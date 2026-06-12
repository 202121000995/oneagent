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
