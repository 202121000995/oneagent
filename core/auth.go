package core

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionCookieName = "nodetools_session"

type Auth struct {
	db *sql.DB

	mu       sync.RWMutex
	sessions map[string]time.Time
}

func NewAuth(db *sql.DB) *Auth {
	return &Auth{
		db:       db,
		sessions: map[string]time.Time{},
	}
}

func (a *Auth) EnsureAdmin(username, bootstrapPassword string) error {
	if username == "" {
		username = "admin"
	}
	if bootstrapPassword == "" {
		bootstrapPassword = "password123"
	}

	var stored string
	err := a.db.QueryRow(`SELECT password FROM users WHERE username = ?`, username).Scan(&stored)
	if err == sql.ErrNoRows {
		hash, err := hashPassword(bootstrapPassword)
		if err != nil {
			return err
		}
		_, err = a.db.Exec(
			`INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)`,
			username, hash, "admin", time.Now().Format(time.RFC3339),
		)
		return err
	}
	if err != nil {
		return err
	}
	if isBcryptHash(stored) {
		return nil
	}

	plain := stored
	if bootstrapPassword != "" {
		plain = bootstrapPassword
	}
	hash, err := hashPassword(plain)
	if err != nil {
		return err
	}
	_, err = a.db.Exec(`UPDATE users SET password = ? WHERE username = ?`, hash, username)
	return err
}

func (a *Auth) Refresh(user, password string) {
	if user == "" {
		return
	}
	_ = a.EnsureAdmin(user, password)
}

func (a *Auth) Login(w http.ResponseWriter, user, password string) bool {
	if !a.verifyPassword(user, password) {
		return false
	}

	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return false
	}
	value := hex.EncodeToString(token)

	a.mu.Lock()
	a.sessions[value] = time.Now().Add(12 * time.Hour)
	expires := a.sessions[value]
	a.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  expires,
	})
	return true
}

func (a *Auth) ChangePassword(username, currentPassword, nextPassword string) error {
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if len(nextPassword) < 8 {
		return fmt.Errorf("new password must be at least 8 characters")
	}
	if !a.verifyPassword(username, currentPassword) {
		return fmt.Errorf("current password is incorrect")
	}
	hash, err := hashPassword(nextPassword)
	if err != nil {
		return err
	}
	_, err = a.db.Exec(`UPDATE users SET password = ? WHERE username = ?`, hash, username)
	if err == nil {
		a.clearSessions()
	}
	return err
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func (a *Auth) IsAuthenticated(r *http.Request) bool {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	a.mu.RLock()
	expires, ok := a.sessions[cookie.Value]
	a.mu.RUnlock()
	if !ok || time.Now().After(expires) {
		return false
	}
	return true
}

func (a *Auth) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.IsAuthenticated(r) {
			next.ServeHTTP(w, r)
			return
		}
		if r.URL.Path == "/" || r.URL.Path == "/templates/dashboard.html" {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		writeError(w, http.StatusUnauthorized, "authentication required")
	})
}

func (a *Auth) verifyPassword(username, password string) bool {
	var stored string
	err := a.db.QueryRow(`SELECT password FROM users WHERE username = ?`, username).Scan(&stored)
	if err != nil {
		return false
	}
	if isBcryptHash(stored) {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil
	}
	if stored != password {
		return false
	}

	hash, err := hashPassword(password)
	if err == nil {
		_, _ = a.db.Exec(`UPDATE users SET password = ? WHERE username = ?`, hash, username)
	}
	return true
}

func (a *Auth) clearSessions() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions = map[string]time.Time{}
}

func hashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

func isBcryptHash(value string) bool {
	return strings.HasPrefix(value, "$2a$") || strings.HasPrefix(value, "$2b$") || strings.HasPrefix(value, "$2y$")
}
