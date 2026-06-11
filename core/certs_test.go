package core

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaterializeInboundCertificateContent(t *testing.T) {
	previous, err := os.Getwd()
	if err != nil {
		t.Fatalf("get wd: %v", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() {
		_ = os.Chdir(previous)
	}()

	inbound := InboundConfig{
		Name:               "trojan-in",
		Protocol:           "trojan",
		Port:               443,
		Password:           "secret",
		ServerName:         "example.com",
		CertificateContent: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
		KeyContent:         "-----BEGIN PRIVATE KEY-----\nMIIB\n-----END PRIVATE KEY-----",
	}
	if err := materializeInboundCertificateContent(&inbound); err != nil {
		t.Fatalf("materialize returned error: %v", err)
	}
	if inbound.CertificatePath == "" || inbound.KeyPath == "" {
		t.Fatalf("expected certificate paths, got %#v", inbound)
	}
	if inbound.CertificateContent != "" || inbound.KeyContent != "" {
		t.Fatalf("certificate content should not stay in config: %#v", inbound)
	}
	if !inbound.TLS {
		t.Fatal("expected TLS to be enabled")
	}
	if _, err := os.Stat(filepath.Clean(inbound.CertificatePath)); err != nil {
		t.Fatalf("certificate file missing: %v", err)
	}
	if _, err := os.Stat(filepath.Clean(inbound.KeyPath)); err != nil {
		t.Fatalf("key file missing: %v", err)
	}
}
