package core

import (
	"os"
	"strings"
	"testing"
)

func TestOfflineInstallScriptKeepsStateAndSupportsRollback(t *testing.T) {
	data, err := os.ReadFile("../deploy/install-offline.sh")
	if err != nil {
		t.Fatalf("read install script: %v", err)
	}
	script := string(data)
	for _, expected := range []string{
		"releases",
		"backups",
		"current",
		"config.yaml",
		"database",
		"rollback-offline.sh",
		"systemctl stop",
		"ExecStart=${CURRENT_LINK}/${APP_NAME}",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("install script missing %q", expected)
		}
	}
}

func TestOfflinePackageScriptEmbedsVersionAndKernels(t *testing.T) {
	data, err := os.ReadFile("../deploy/package-offline.sh")
	if err != nil {
		t.Fatalf("read package script: %v", err)
	}
	script := string(data)
	for _, expected := range []string{
		"APP_VERSION",
		"BuildTime",
		"VERSION",
		"rollback-offline.sh",
		"copy_kernel \"sing-box\"",
		"copy_kernel \"mihomo\"",
		"ALLOW_MISSING_KERNELS",
	} {
		if !strings.Contains(script, expected) {
			t.Fatalf("package script missing %q", expected)
		}
	}
}
