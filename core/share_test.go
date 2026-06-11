package core

import (
	"strings"
	"testing"
)

func TestGenerateRealityKeyPairAndShareLinks(t *testing.T) {
	pair, err := GenerateRealityKeyPair()
	if err != nil {
		t.Fatalf("GenerateRealityKeyPair returned error: %v", err)
	}
	if pair.PrivateKey == "" || pair.PublicKey == "" {
		t.Fatalf("expected key pair, got %#v", pair)
	}

	vless := InboundConfig{
		Name:                   "reality-in",
		Protocol:               "vless",
		Port:                   443,
		UUID:                   "bf000d23-0752-40b4-affe-68f7707a9661",
		Security:               "reality",
		ServerName:             "addons.mozilla.org",
		PrivateKey:             pair.PrivateKey,
		ShortID:                "abcd",
		RealityHandshakeServer: "addons.mozilla.org",
		RealityHandshakePort:   443,
	}
	link, err := inboundShareLink(vless, "node.example.com")
	if err != nil {
		t.Fatalf("inboundShareLink returned error: %v", err)
	}
	if !strings.Contains(link, "vless://") || !strings.Contains(link, "security=reality") || !strings.Contains(link, "pbk=") {
		t.Fatalf("unexpected vless reality link: %s", link)
	}

	anytls := InboundConfig{Name: "anytls-in", Protocol: "anytls", Port: 8443, Password: "secret", ServerName: "example.com", TLS: true}
	link, err = inboundShareLink(anytls, "node.example.com")
	if err != nil {
		t.Fatalf("inboundShareLink returned error: %v", err)
	}
	if !strings.Contains(link, "anytls://") || !strings.Contains(link, "peer=example.com") {
		t.Fatalf("unexpected anytls link: %s", link)
	}
}
