package core

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateBackupPackageIncludesConfigDatabaseAndCerts(t *testing.T) {
	tmpDir := t.TempDir()
	oldDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd returned error: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldDir) })
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Chdir returned error: %v", err)
	}

	if err := os.MkdirAll("database", 0o755); err != nil {
		t.Fatalf("mkdir database: %v", err)
	}
	if err := os.MkdirAll("certs", 0o755); err != nil {
		t.Fatalf("mkdir certs: %v", err)
	}
	if err := os.WriteFile("config.yaml", []byte("server:\n  web_port: 39080\n"), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := os.WriteFile(filepath.Join("database", "nodetools.db"), []byte("db"), 0o644); err != nil {
		t.Fatalf("write database: %v", err)
	}
	if err := os.WriteFile(filepath.Join("certs", "node.crt"), []byte("cert"), 0o644); err != nil {
		t.Fatalf("write cert: %v", err)
	}

	path, err := CreateBackupPackage()
	if err != nil {
		t.Fatalf("CreateBackupPackage returned error: %v", err)
	}
	reader, err := zip.OpenReader(path)
	if err != nil {
		t.Fatalf("OpenReader returned error: %v", err)
	}
	defer reader.Close()
	seen := map[string]bool{}
	for _, item := range reader.File {
		seen[item.Name] = true
	}
	for _, name := range []string{"manifest.json", "config.yaml", "database/nodetools.db", "certs/node.crt"} {
		if !seen[name] {
			t.Fatalf("expected backup to contain %s, got %#v", name, seen)
		}
	}
}
