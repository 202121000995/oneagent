package core

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSingBoxKernelGenerateConfig(t *testing.T) {
	kernel := NewSingBoxKernel()
	state := RuntimeState{
		Inbounds: []InboundConfig{
			{Name: "local", Protocol: "socks", Listen: "127.0.0.1", Port: 1080},
			{Name: "vless-in", Protocol: "vless", Port: 2080, UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Flow: "xtls-rprx-vision"},
			{Name: "socks-in", Protocol: "socks5", Port: 2081, Username: "in-user", Password: "in-pass"},
			{Name: "reality-in", Protocol: "vless", Port: 2082, UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Security: "reality", ServerName: "addons.mozilla.org", PrivateKey: "private", ShortID: "abcd", RealityHandshakeServer: "addons.mozilla.org", RealityHandshakePort: 443},
			{Name: "anytls-in", Protocol: "anytls", Port: 2083, Password: "secret", TLS: true, ServerName: "example.com", IdleSessionCheck: "30s", IdleSessionTimeout: "30s", MinIdleSession: 5},
			{Name: "shadowtls-in", Protocol: "shadowtls", Port: 2084, Password: "secret", ServerName: "addons.mozilla.org", RealityHandshakeServer: "addons.mozilla.org", RealityHandshakePort: 443},
		},
		Outbounds: []OutboundConfig{
			{Name: "remote", Protocol: "vless", Address: "127.0.0.1", Port: 2080, UUID: "bf000d23-0752-40b4-affe-68f7707a9661", TLS: true, ServerName: "example.com", Transport: "tcp"},
			{Name: "ss", Protocol: "shadowsocks", Address: "127.0.0.1", Port: 2081, Method: "aes-128-gcm", Password: "secret"},
			{Name: "socks-auth", Protocol: "socks5", Address: "127.0.0.1", Port: 2082, Username: "user", Password: "pass"},
		},
		Routing: RoutingConfig{DefaultOutbound: "ss", Rules: []RoutingRule{{Inbound: "local", Outbound: "remote"}}},
	}

	data, err := kernel.GenerateConfig(state)
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}

	var cfg map[string]any
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("generated sing-box config is not json: %v", err)
	}
	inbounds := cfg["inbounds"].([]any)
	if inbounds[0].(map[string]any)["type"] != "socks" {
		t.Fatalf("expected socks inbound, got %#v", inbounds[0])
	}
	if inbounds[0].(map[string]any)["listen"] != "127.0.0.1" {
		t.Fatalf("expected listen override, got %#v", inbounds[0])
	}
	vlessInbound := inbounds[1].(map[string]any)
	if vlessInbound["type"] != "vless" {
		t.Fatalf("expected vless inbound, got %#v", vlessInbound)
	}
	users := vlessInbound["users"].([]any)
	if users[0].(map[string]any)["uuid"] == "" {
		t.Fatalf("expected vless inbound user uuid, got %#v", users)
	}
	socksInbound := inbounds[2].(map[string]any)
	socksUsers := socksInbound["users"].([]any)
	if socksInbound["type"] != "socks" || socksUsers[0].(map[string]any)["username"] != "in-user" {
		t.Fatalf("expected authenticated socks inbound, got %#v", socksInbound)
	}
	realityInbound := inbounds[3].(map[string]any)
	realityTLS := realityInbound["tls"].(map[string]any)
	if realityInbound["type"] != "vless" || realityTLS["reality"] == nil {
		t.Fatalf("expected vless reality inbound, got %#v", realityInbound)
	}
	reality := realityTLS["reality"].(map[string]any)
	shortIDs := reality["short_id"].([]any)
	if len(shortIDs) != 1 || shortIDs[0] != "abcd" {
		t.Fatalf("expected reality short_id array, got %#v", shortIDs)
	}
	anyTLSInbound := inbounds[4].(map[string]any)
	if anyTLSInbound["type"] != "anytls" || anyTLSInbound["tls"] == nil {
		t.Fatalf("expected anytls inbound with tls, got %#v", anyTLSInbound)
	}
	if _, ok := anyTLSInbound["idle_session_check_interval"]; ok {
		t.Fatalf("anytls optional idle fields should be omitted for sing-box compatibility, got %#v", anyTLSInbound)
	}
	shadowTLSInbound := inbounds[5].(map[string]any)
	if shadowTLSInbound["type"] != "shadowtls" || shadowTLSInbound["version"] != float64(3) {
		t.Fatalf("expected shadowtls v3 inbound, got %#v", shadowTLSInbound)
	}
	outbounds := cfg["outbounds"].([]any)
	vless := outbounds[1].(map[string]any)
	if vless["type"] != "vless" || vless["uuid"] == "" {
		t.Fatalf("expected vless outbound with uuid, got %#v", vless)
	}
	if _, ok := vless["transport"]; ok {
		t.Fatalf("tcp transport should be omitted for sing-box outbound, got %#v", vless)
	}
	ss := outbounds[2].(map[string]any)
	if ss["type"] != "shadowsocks" || ss["method"] != "aes-128-gcm" {
		t.Fatalf("expected shadowsocks outbound, got %#v", ss)
	}
	socks := outbounds[3].(map[string]any)
	if socks["type"] != "socks" || socks["username"] != "user" || socks["password"] != "pass" {
		t.Fatalf("expected authenticated socks outbound, got %#v", socks)
	}
	route := cfg["route"].(map[string]any)
	if route["final"] != "ss" {
		t.Fatalf("expected default outbound final ss, got %#v", route)
	}
}

func TestMihomoKernelGenerateConfig(t *testing.T) {
	kernel := NewMihomoKernel()
	state := RuntimeState{
		Inbounds:  []InboundConfig{{Name: "local", Protocol: "mixed", Port: 7890}},
		Outbounds: []OutboundConfig{{Name: "remote", Protocol: "trojan", Address: "127.0.0.1", Port: 443, Password: "secret", TLS: true, ServerName: "example.com"}},
		Mihomo: MihomoConfig{
			Providers:   []ProxyProviderConfig{{Name: "sub", URL: "https://example.com/sub.yaml"}},
			ProxyGroups: []ProxyGroupConfig{{Name: "Auto", Type: "url-test", Use: []string{"sub"}, URL: "http://www.gstatic.com/generate_204", Interval: 300}},
			Rules:       []string{"DOMAIN-SUFFIX,example.com,Auto", "MATCH,DIRECT"},
		},
	}

	data, err := kernel.GenerateConfig(state)
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}

	var cfg map[string]any
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("generated mihomo config is not yaml: %v", err)
	}
	if cfg["mixed-port"] != 7890 {
		t.Fatalf("expected mixed-port 7890, got %#v", cfg["mixed-port"])
	}
	if _, ok := cfg["proxy-providers"]; !ok {
		t.Fatalf("expected proxy-providers in mihomo config")
	}
	groups := cfg["proxy-groups"].([]any)
	if groups[0].(map[string]any)["name"] != "Auto" {
		t.Fatalf("expected Auto proxy group, got %#v", groups[0])
	}
}

func TestNormalizeKernelConfigSwitchesDefaults(t *testing.T) {
	cfg := normalizeKernelConfig(KernelConfig{
		Type:       "mihomo",
		Executable: "/usr/local/bin/sing-box",
		ConfigPath: "sing-box.generated.json",
	})
	if cfg.Executable != "/usr/local/bin/mihomo" || cfg.ConfigPath != "mihomo.generated.yaml" {
		t.Fatalf("expected mihomo defaults, got %#v", cfg)
	}

	cfg = normalizeKernelConfig(KernelConfig{
		Type:       "sing-box",
		Executable: "/usr/local/bin/mihomo",
		ConfigPath: "mihomo.generated.yaml",
	})
	if cfg.Executable != "/usr/local/bin/sing-box" || cfg.ConfigPath != "sing-box.generated.json" {
		t.Fatalf("expected sing-box defaults, got %#v", cfg)
	}
}
