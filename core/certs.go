package core

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func ensureInboundTLSAssets(inbounds []InboundConfig) ([]InboundConfig, error) {
	next := append([]InboundConfig(nil), inbounds...)
	for i := range next {
		inbound := &next[i]
		if !needsGeneratedCertificate(*inbound) {
			continue
		}
		certPath, keyPath := generatedCertPaths(inbound.Name)
		if err := ensureSelfSignedCertificate(certPath, keyPath, inbound.ServerName); err != nil {
			return nil, err
		}
		inbound.CertificatePath = certPath
		inbound.KeyPath = keyPath
		inbound.TLS = true
	}
	return next, nil
}

func needsGeneratedCertificate(inbound InboundConfig) bool {
	if inbound.Security == "reality" {
		return false
	}
	if inbound.CertificatePath != "" && inbound.KeyPath != "" {
		return false
	}
	return inbound.Protocol == "anytls" || inbound.TLS
}

func generatedCertPaths(name string) (string, string) {
	base := sanitizeFileName(name)
	return filepath.Join("certs", base+".crt"), filepath.Join("certs", base+".key")
}

func ensureSelfSignedCertificate(certPath, keyPath, serverName string) error {
	if fileExists(certPath) && fileExists(keyPath) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	if serverName == "" {
		serverName = "nodetools.local"
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: serverName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{serverName},
	}
	if ip := net.ParseIP(serverName); ip != nil {
		template.IPAddresses = []net.IP{ip}
		template.DNSNames = nil
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	certFile, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: der}); err != nil {
		_ = certFile.Close()
		return err
	}
	if err := certFile.Close(); err != nil {
		return err
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	keyFile, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		_ = keyFile.Close()
		return err
	}
	return keyFile.Close()
}

func sanitizeFileName(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "inbound"
	}
	var builder strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
			builder.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			builder.WriteRune(r)
		case r >= '0' && r <= '9':
			builder.WriteRune(r)
		case r == '-' || r == '_':
			builder.WriteRune(r)
		default:
			builder.WriteRune('-')
		}
	}
	out := strings.Trim(builder.String(), "-")
	if out == "" {
		return fmt.Sprintf("inbound-%d", time.Now().Unix())
	}
	return out
}
