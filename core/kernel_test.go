package core

import (
	"encoding/json"
	"testing"
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
			{Name: "forward-dns", Protocol: "forward-udp", Listen: "0.0.0.0", Port: 5353, TargetHost: "1.1.1.1", TargetPort: 53},
		},
		Outbounds: []OutboundConfig{
			{Name: "remote", Protocol: "vless", Address: "127.0.0.1", Port: 2080, UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Flow: "xtls-rprx-vision", Security: "reality", TLS: true, ServerName: "example.com", PublicKey: "reality-public-key", Transport: "tcp"},
			{Name: "ss", Protocol: "shadowsocks", Address: "127.0.0.1", Port: 2081, Method: "aes-128-gcm", Password: "secret"},
			{Name: "socks-auth", Protocol: "socks5", Address: "127.0.0.1", Port: 2082, Username: "user", Password: "pass"},
			{Name: "hy2", Protocol: "hysteria2", Address: "127.0.0.1", Port: 2083, Password: "hy-pass", TLS: true, ServerName: "example.com", MPort: "2083,30000-30100", UpMbps: 100, DownMbps: 500},
			{Name: "tuic", Protocol: "tuic", Address: "127.0.0.1", Port: 2084, UUID: "bf000d23-0752-40b4-affe-68f7707a9661", Password: "tuic-pass", TLS: true, ServerName: "example.com"},
			{Name: "anytls", Protocol: "anytls", Address: "127.0.0.1", Port: 2085, Password: "any-pass", TLS: true, ServerName: "example.com", IdleSessionCheck: "30s", IdleSessionTimeout: "30s", MinIdleSession: 2},
		},
		Routing: RoutingConfig{
			Mode:            "rule",
			DefaultOutbound: "ss",
			Rules: []RoutingRule{
				{MatchType: "inbound", Value: "local", Inbound: "local", Outbound: "remote", Priority: 10},
				{MatchType: "domain_suffix", Value: "example.com", Outbound: "ss", Priority: 20},
				{MatchType: "ip_cidr", Value: "10.0.0.0/8", Outbound: "direct", Priority: 30},
			},
		},
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
	if shadowTLSInbound["detour"] != "shadowtls-in-shadowsocks" {
		t.Fatalf("expected shadowtls detour to inner shadowsocks inbound, got %#v", shadowTLSInbound)
	}
	shadowTLSInner := inbounds[6].(map[string]any)
	if shadowTLSInner["type"] != "shadowsocks" || shadowTLSInner["tag"] != "shadowtls-in-shadowsocks" {
		t.Fatalf("expected inner shadowsocks inbound for shadowtls, got %#v", shadowTLSInner)
	}
	forwardInbound := inbounds[7].(map[string]any)
	if forwardInbound["type"] != "direct" || forwardInbound["network"] != "udp" || forwardInbound["override_address"] != "1.1.1.1" || forwardInbound["override_port"] != float64(53) {
		t.Fatalf("expected direct udp forward inbound, got %#v", forwardInbound)
	}
	outbounds := cfg["outbounds"].([]any)
	vless := outbounds[1].(map[string]any)
	if vless["type"] != "vless" || vless["uuid"] == "" {
		t.Fatalf("expected vless outbound with uuid, got %#v", vless)
	}
	if vless["flow"] != "xtls-rprx-vision" {
		t.Fatalf("expected vless outbound flow, got %#v", vless)
	}
	vlessTLS := vless["tls"].(map[string]any)
	if vlessTLS["utls"].(map[string]any)["fingerprint"] != "chrome" || vlessTLS["reality"] == nil {
		t.Fatalf("expected reality outbound to default uTLS chrome, got %#v", vlessTLS)
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
	hy2 := outbounds[4].(map[string]any)
	if hy2["server_ports"] == nil || hy2["up_mbps"] != float64(100) || hy2["down_mbps"] != float64(500) {
		t.Fatalf("expected hysteria2 port hopping and bandwidth fields, got %#v", hy2)
	}
	serverPorts := hy2["server_ports"].([]any)
	if serverPorts[1] != "30000:30100" {
		t.Fatalf("expected sing-box port range format, got %#v", serverPorts)
	}
	tuic := outbounds[5].(map[string]any)
	if tuic["congestion_control"] != "bbr" || tuic["udp_relay_mode"] != "native" {
		t.Fatalf("expected tuic defaults, got %#v", tuic)
	}
	anytls := outbounds[6].(map[string]any)
	if anytls["idle_session_check_interval"] != "30s" || anytls["min_idle_session"] != float64(2) {
		t.Fatalf("expected anytls idle session fields, got %#v", anytls)
	}
	route := cfg["route"].(map[string]any)
	if route["final"] != "ss" {
		t.Fatalf("expected default outbound final ss, got %#v", route)
	}
	rules := route["rules"].([]any)
	if len(rules) != 3 {
		t.Fatalf("expected 3 sing-box route rules, got %#v", rules)
	}
	if rules[1].(map[string]any)["domain_suffix"] == nil || rules[2].(map[string]any)["ip_cidr"] == nil {
		t.Fatalf("expected split route rules, got %#v", rules)
	}
}

func TestSingBoxRawProtocolConfigsPassThrough(t *testing.T) {
	cfg := Config{
		Inbounds: []InboundConfig{{
			Name:     "entry-tun",
			Protocol: "custom-inbound",
			ProtocolConfig: map[string]any{
				"type":           "tun",
				"interface_name": "tun0",
				"address":        []string{"172.19.0.1/30"},
				"auto_route":     true,
			},
		}},
		Outbounds: []OutboundConfig{{
			Name:     "node-wg",
			Protocol: "custom-outbound",
			RawConfig: map[string]any{
				"type":        "wireguard",
				"server":      "example.com",
				"server_port": 51820,
				"local_address": []string{
					"10.0.0.2/32",
				},
			},
		}},
	}
	cfg.Server.WebPort = 8080
	cfg.Server.AdminUser = "admin"
	cfg.Server.AdminPass = "password123"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("raw sing-box protocol config should pass validation: %v", err)
	}

	kernel := NewSingBoxKernel()
	data, err := kernel.GenerateConfig(RuntimeState{Inbounds: cfg.Inbounds, Outbounds: cfg.Outbounds})
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}
	var generated map[string]any
	if err := json.Unmarshal(data, &generated); err != nil {
		t.Fatalf("generated sing-box config is not json: %v", err)
	}
	inbound := generated["inbounds"].([]any)[0].(map[string]any)
	if inbound["type"] != "tun" || inbound["tag"] != "entry-tun" || inbound["interface_name"] != "tun0" {
		t.Fatalf("expected raw tun inbound to pass through, got %#v", inbound)
	}
	if _, ok := inbound["listen_port"]; ok {
		t.Fatalf("raw non-port inbound should not receive listen_port, got %#v", inbound)
	}

	var outbound map[string]any
	for _, raw := range generated["outbounds"].([]any) {
		item := raw.(map[string]any)
		if item["tag"] == "node-wg" {
			outbound = item
			break
		}
	}
	if outbound == nil || outbound["type"] != "wireguard" || outbound["server"] != "example.com" {
		t.Fatalf("expected raw wireguard outbound to pass through, got %#v", outbound)
	}
}

func TestSingBoxRawRealityOutboundDefaultsUTLS(t *testing.T) {
	kernel := NewSingBoxKernel()
	data, err := kernel.GenerateConfig(RuntimeState{Outbounds: []OutboundConfig{{
		Name:     "node-reality",
		Protocol: "vless",
		RawConfig: map[string]any{
			"type":        "vless",
			"server":      "example.com",
			"server_port": 443,
			"uuid":        "bf000d23-0752-40b4-affe-68f7707a9661",
			"tls": map[string]any{
				"enabled":     true,
				"server_name": "addons.mozilla.org",
				"reality": map[string]any{
					"enabled":    true,
					"public_key": "pub",
				},
			},
		},
	}}})
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}
	var generated map[string]any
	if err := json.Unmarshal(data, &generated); err != nil {
		t.Fatalf("generated sing-box config is not json: %v", err)
	}
	var outbound map[string]any
	for _, raw := range generated["outbounds"].([]any) {
		item := raw.(map[string]any)
		if item["tag"] == "node-reality" {
			outbound = item
			break
		}
	}
	tls := outbound["tls"].(map[string]any)
	utls := tls["utls"].(map[string]any)
	if utls["fingerprint"] != "chrome" || utls["enabled"] != true {
		t.Fatalf("expected raw reality outbound to default uTLS chrome, got %#v", outbound)
	}
}

func TestNormalizeRoutingConfigRemovesLegacyBypassOverseasDirectRule(t *testing.T) {
	routing := normalizeRoutingConfig(RoutingConfig{
		Mode:   "rule",
		Preset: "bypass_cn",
		Rules: []RoutingRule{
			{MatchType: "geosite", Value: "cn", Outbound: "direct", Priority: 20},
			{MatchType: "domain_suffix", Value: "openai.com,google.com,youtube.com,github.com", Outbound: "direct", Priority: 40},
		},
	})
	if len(routing.Rules) != 1 || routing.Rules[0].MatchType != "geosite" {
		t.Fatalf("expected legacy overseas direct rule removed, got %#v", routing.Rules)
	}
}

func TestNormalizeKernelConfigSwitchesDefaults(t *testing.T) {
	cfg := normalizeKernelConfig(KernelConfig{
		Type:       "mihomo",
		Executable: "/usr/local/bin/sing-box",
		ConfigPath: "sing-box.generated.json",
	})
	if cfg.Type != "sing-box" || cfg.Executable != "/usr/local/bin/sing-box" || cfg.ConfigPath != "sing-box.generated.json" {
		t.Fatalf("expected legacy mihomo config to normalize to sing-box, got %#v", cfg)
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
