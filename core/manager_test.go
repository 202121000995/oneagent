package core

import (
	"path/filepath"
	"testing"
)

func TestUpsertOutboundRenameUpdatesRouting(t *testing.T) {
	db, err := InitDatabase(filepath.Join(t.TempDir(), "nodetools.db"))
	if err != nil {
		t.Fatalf("InitDatabase returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager := NewManager(db, "")
	cfg := Config{
		Inbounds: []InboundConfig{
			{Name: "local", Protocol: "mixed", Listen: "0.0.0.0", Port: 1080},
		},
		Outbounds: []OutboundConfig{
			{Name: "old-out", Protocol: "http", Address: "127.0.0.1", Port: 8081},
		},
		Routing: RoutingConfig{
			DefaultOutbound: "old-out",
			Rules:           []RoutingRule{{Name: "local-route", Inbound: "local", Outbound: "old-out", Priority: 10}},
		},
	}
	cfg.Server.WebPort = 8080
	cfg.Server.AdminUser = "admin"
	cfg.Server.AdminPass = "password123"
	if err := manager.ApplyConfig(cfg); err != nil {
		t.Fatalf("ApplyConfig returned error: %v", err)
	}

	if _, err := manager.UpsertOutbound(OutboundConfig{
		OriginalName: "old-out",
		Name:         "new-out",
		Protocol:     "http",
		Address:      "127.0.0.1",
		Port:         8082,
	}); err != nil {
		t.Fatalf("UpsertOutbound returned error: %v", err)
	}

	snapshot := manager.ConfigSnapshot()
	if snapshot.Routing.DefaultOutbound != "new-out" {
		t.Fatalf("expected default outbound to be renamed, got %q", snapshot.Routing.DefaultOutbound)
	}
	if len(snapshot.Routing.Rules) != 1 || snapshot.Routing.Rules[0].Outbound != "new-out" {
		t.Fatalf("expected routing rule outbound to be renamed, got %#v", snapshot.Routing.Rules)
	}
	if len(snapshot.Outbounds) != 1 || snapshot.Outbounds[0].Name != "new-out" {
		t.Fatalf("expected only renamed outbound, got %#v", snapshot.Outbounds)
	}
}

func TestCreateProxyDoesNotCreateRoutingRule(t *testing.T) {
	db, err := InitDatabase(filepath.Join(t.TempDir(), "nodetools.db"))
	if err != nil {
		t.Fatalf("InitDatabase returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager := NewManager(db, "")
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "proxy", Protocol: "http", Address: "127.0.0.1", Port: 8081},
		},
		Routing: RoutingConfig{Mode: "global", DefaultOutbound: "proxy"},
	}
	cfg.Server.WebPort = 8080
	cfg.Server.AdminUser = "admin"
	cfg.Server.AdminPass = "password123"
	if err := manager.ApplyConfig(cfg); err != nil {
		t.Fatalf("ApplyConfig returned error: %v", err)
	}

	if _, err := manager.CreateProxy(ProxyCreateRequest{
		Name:     "local",
		Protocol: "mixed",
		Listen:   "0.0.0.0",
		Port:     1080,
		Outbound: "proxy",
	}); err != nil {
		t.Fatalf("CreateProxy returned error: %v", err)
	}

	snapshot := manager.ConfigSnapshot()
	if len(snapshot.Routing.Rules) != 0 {
		t.Fatalf("expected inbound creation to leave routing rules unchanged, got %#v", snapshot.Routing.Rules)
	}
}

func TestApplyConfigEnrichesOutboundFromRawFlow(t *testing.T) {
	db, err := InitDatabase(filepath.Join(t.TempDir(), "nodetools.db"))
	if err != nil {
		t.Fatalf("InitDatabase returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager := NewManager(db, "")
	cfg := Config{
		Outbounds: []OutboundConfig{{
			Name:      "raw-reality",
			Protocol:  "vless",
			Address:   "45.139.193.187",
			Port:      8881,
			UUID:      "cbf378ef-bbf8-4539-a564-31c6f0173142",
			Security:  "reality",
			TLS:       true,
			PublicKey: "pub",
			Raw:       "vless://cbf378ef-bbf8-4539-a564-31c6f0173142@45.139.193.187:8881?security=reality&sni=addons.mozilla.org&pbk=pub&type=tcp&flow=xtls-rprx-vision&encryption=none#raw-reality",
		}},
		Routing: RoutingConfig{Mode: "global", DefaultOutbound: "raw-reality"},
	}
	cfg.Server.WebPort = 8080
	cfg.Server.AdminUser = "admin"
	cfg.Server.AdminPass = "password123"
	if err := manager.ApplyConfig(cfg); err != nil {
		t.Fatalf("ApplyConfig returned error: %v", err)
	}

	snapshot := manager.ConfigSnapshot()
	if len(snapshot.Outbounds) != 1 || snapshot.Outbounds[0].Flow != "xtls-rprx-vision" || snapshot.Outbounds[0].ServerName != "addons.mozilla.org" {
		t.Fatalf("expected outbound to be enriched from raw link, got %#v", snapshot.Outbounds)
	}
}

func TestProbeInboundGoogleUnsupportedProtocol(t *testing.T) {
	health := probeHTTPProxyInboundGoogle(InboundConfig{Name: "vless-in", Protocol: "forward-tcp", Port: 443})
	if health.Status != "unsupported" {
		t.Fatalf("expected unsupported status, got %#v", health)
	}
	if health.LastError == "" {
		t.Fatal("expected unsupported reason")
	}
}

func TestInboundProbeOutboundDerivesRealityPublicKey(t *testing.T) {
	pair, err := GenerateRealityKeyPair()
	if err != nil {
		t.Fatalf("GenerateRealityKeyPair returned error: %v", err)
	}
	outbound, err := inboundProbeOutbound(InboundConfig{
		Name:                   "reality-in",
		Protocol:               "vless",
		Listen:                 "0.0.0.0",
		Port:                   443,
		UUID:                   "bf000d23-0752-40b4-affe-68f7707a9661",
		Security:               "reality",
		ServerName:             "addons.mozilla.org",
		PrivateKey:             pair.PrivateKey,
		ShortID:                ",abcd,ef12",
		RealityHandshakeServer: "addons.mozilla.org",
		RealityHandshakePort:   443,
	})
	if err != nil {
		t.Fatalf("inboundProbeOutbound returned error: %v", err)
	}
	if outbound.PublicKey != pair.PublicKey || outbound.ShortID != "abcd" || outbound.Address != "127.0.0.1" || outbound.Fingerprint != "chrome" {
		t.Fatalf("unexpected probe outbound: %#v", outbound)
	}
}

func TestInboundProbeOutboundWrapsShadowTLSWithShadowsocks(t *testing.T) {
	outbound, err := inboundProbeOutbound(InboundConfig{
		Name:                   "shadowtls-in",
		Protocol:               "shadowtls",
		Listen:                 "0.0.0.0",
		Port:                   8443,
		Password:               "secret",
		ServerName:             "addons.mozilla.org",
		RealityHandshakeServer: "addons.mozilla.org",
		RealityHandshakePort:   443,
	})
	if err != nil {
		t.Fatalf("inboundProbeOutbound returned error: %v", err)
	}
	if outbound.Protocol != "shadowsocks" || outbound.Transport != "shadowtls" || outbound.ObfsPassword != "secret" || outbound.Method != "aes-128-gcm" {
		t.Fatalf("unexpected shadowtls probe outbound: %#v", outbound)
	}
}

func TestEnabledRuntimeKeepsSplitRules(t *testing.T) {
	_, _, routing := enabledRuntime(
		[]InboundConfig{{Name: "local", Protocol: "mixed", Port: 7890}},
		[]OutboundConfig{{Name: "proxy", Protocol: "http", Address: "127.0.0.1", Port: 8080}},
		RoutingConfig{
			Mode:            "rule",
			Preset:          "bypass_cn",
			DefaultOutbound: "proxy",
			Rules: []RoutingRule{
				{MatchType: "domain_suffix", Value: "google.com", Outbound: "proxy", Priority: 10},
				{MatchType: "geoip", Value: "cn", Outbound: "direct", Priority: 20},
				{MatchType: "inbound", Value: "missing", Inbound: "missing", Outbound: "proxy", Priority: 30},
			},
		},
	)
	if routing.Mode != "rule" || routing.Preset != "bypass_cn" {
		t.Fatalf("expected routing metadata preserved, got %#v", routing)
	}
	if len(routing.Rules) != 2 {
		t.Fatalf("expected non-inbound split rules kept and missing inbound rule filtered, got %#v", routing.Rules)
	}
}
