package core

import (
	"encoding/base64"
	"testing"
)

func TestParseYAMLSubscription(t *testing.T) {
	body := []byte(`
proxies:
  - name: HK
    type: vless
    server: hk.example.com
    port: 443
proxy-groups:
  - name: Auto
    type: select
    proxies: [HK]
rules:
  - MATCH,Auto
proxy-providers:
  main:
    type: http
    url: https://example.com/sub.yaml
`)
	preview, err := ParseSubscription("https://example.com/sub.yaml", body)
	if err != nil {
		t.Fatalf("ParseSubscription returned error: %v", err)
	}
	if preview.ProxyCount != 1 || preview.GroupCount != 1 || preview.RuleCount != 1 || preview.ProviderCount != 1 {
		t.Fatalf("unexpected preview: %#v", preview)
	}
}

func TestParseBase64URIListSubscription(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("vless://uuid@example.com:443#HK\nss://method:pass@example.com:8388#SS"))
	preview, err := ParseSubscription("https://example.com/base64", []byte(encoded))
	if err != nil {
		t.Fatalf("ParseSubscription returned error: %v", err)
	}
	if preview.ProxyCount != 2 {
		t.Fatalf("expected 2 proxies, got %#v", preview)
	}
}
