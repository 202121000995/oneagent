package core

import (
	"database/sql"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

func InitDatabase(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;`); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(schemaSQL); err != nil {
		db.Close()
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(
		`INSERT OR IGNORE INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)`,
		"admin", string(hash), "admin", time.Now().Format(time.RFC3339),
	); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS users (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL UNIQUE,
	password TEXT NOT NULL,
	role TEXT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS nodes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	name TEXT NOT NULL UNIQUE,
	type TEXT NOT NULL,
	protocol TEXT NOT NULL,
	address TEXT NOT NULL DEFAULT '',
	port INTEGER NOT NULL,
	status TEXT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS routing_rules (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	inbound TEXT NOT NULL,
	outbound TEXT NOT NULL,
	created_at TEXT NOT NULL,
	UNIQUE(inbound, outbound)
);

CREATE TABLE IF NOT EXISTS traffic_stats (
	node_name TEXT PRIMARY KEY,
	upload_bytes INTEGER NOT NULL DEFAULT 0,
	download_bytes INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS config_history (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	content TEXT NOT NULL,
	created_at TEXT NOT NULL
);
`
