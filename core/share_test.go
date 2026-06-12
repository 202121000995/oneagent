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

	for _, inbound := range []InboundConfig{
		{Name: "trojan-in", Protocol: "trojan", Port: 443, Password: "secret", ServerName: "example.com", TLS: true},
		{Name: "ss-in", Protocol: "shadowsocks", Port: 8388, Method: "2022-blake3-aes-128-gcm", Password: "secret"},
		{Name: "shadowtls-in", Protocol: "shadowtls", Port: 8443, Password: "secret", ServerName: "addons.mozilla.org", RealityHandshakeServer: "addons.mozilla.org", RealityHandshakePort: 443},
	} {
		link, err = inboundShareLink(inbound, "node.example.com")
		if err != nil {
			t.Fatalf("inboundShareLink returned error for %s: %v", inbound.Protocol, err)
		}
		if !strings.Contains(link, inbound.Protocol) && !(inbound.Protocol == "shadowsocks" && strings.Contains(link, "ss://")) {
			t.Fatalf("unexpected %s link: %s", inbound.Protocol, link)
		}
	}
}

func TestOutboundShareLinks(t *testing.T) {
	for _, outbound := range []OutboundConfig{
		{
			Name: "vless-reality", Protocol: "vless", Address: "node.example.com", Port: 443,
			UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Security: "reality",
			ServerName: "addons.mozilla.org", PublicKey: "pubkey", ShortID: "abcd",
		},
		{Name: "vmess-ws", Protocol: "vmess", Address: "node.example.com", Port: 443, UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Transport: "ws", Path: "/ws", Host: "cdn.example.com", TLS: true},
		{Name: "trojan", Protocol: "trojan", Address: "node.example.com", Port: 443, Password: "secret", ServerName: "example.com", TLS: true},
		{Name: "ss", Protocol: "shadowsocks", Address: "node.example.com", Port: 8388, Method: "aes-256-gcm", Password: "secret"},
		{Name: "shadowtls", Protocol: "shadowtls", Address: "node.example.com", Port: 8443, Password: "secret", ServerName: "addons.mozilla.org"},
		{Name: "anytls", Protocol: "anytls", Address: "node.example.com", Port: 8443, Password: "secret", ServerName: "addons.mozilla.org"},
		{Name: "hysteria2", Protocol: "hysteria2", Address: "node.example.com", Port: 8443, Password: "secret", ServerName: "addons.mozilla.org", UpMbps: 100, DownMbps: 500},
		{Name: "tuic", Protocol: "tuic", Address: "node.example.com", Port: 8443, UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Password: "secret", ServerName: "addons.mozilla.org"},
		{Name: "http", Protocol: "http", Address: "node.example.com", Port: 8080, Username: "user", Password: "secret"},
	} {
		link, err := outboundShareLink(outbound)
		if err != nil {
			t.Fatalf("outboundShareLink returned error for %s: %v", outbound.Protocol, err)
		}
		if link == "" || !strings.Contains(link, "://") {
			t.Fatalf("unexpected empty or invalid %s link: %s", outbound.Protocol, link)
		}
	}
}
