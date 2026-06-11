package core

import (
	"net/http/httptest"
	"testing"
)

func TestAuthMigratesAndChangesPassword(t *testing.T) {
	db, err := InitDatabase(t.TempDir() + "/test.db")
	if err != nil {
		t.Fatalf("InitDatabase returned error: %v", err)
	}
	defer db.Close()

	auth := NewAuth(db)
	if err := auth.EnsureAdmin("admin", "password123"); err != nil {
		t.Fatalf("EnsureAdmin returned error: %v", err)
	}

	recorder := httptest.NewRecorder()
	if !auth.Login(recorder, "admin", "password123") {
		t.Fatal("expected login with default password")
	}
	if err := auth.ChangePassword("admin", "password123", "new-password"); err != nil {
		t.Fatalf("ChangePassword returned error: %v", err)
	}
	if auth.Login(httptest.NewRecorder(), "admin", "password123") {
		t.Fatal("old password should not work")
	}
	if !auth.Login(httptest.NewRecorder(), "admin", "new-password") {
		t.Fatal("new password should work")
	}
}
