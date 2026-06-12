package core

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testKernel struct {
	name             string
	stopped          bool
	running          bool
	lastInboundCount int
	failWithInbounds bool
}

func (k *testKernel) Name() string {
	return k.name
}

func (k *testKernel) Configure(KernelConfig) {}

func (k *testKernel) GenerateConfig(state RuntimeState) ([]byte, error) {
	k.lastInboundCount = len(state.Inbounds)
	return []byte(fmt.Sprintf(`{"inbounds":%d}`, k.lastInboundCount)), nil
}

func (k *testKernel) ValidateConfig(string) error {
	return nil
}

func (k *testKernel) Start(string) error {
	if k.failWithInbounds && k.lastInboundCount > 0 {
		return errors.New("kernel start failed")
	}
	k.running = true
	return nil
}

func (k *testKernel) Reload(string) error {
	if k.failWithInbounds && k.lastInboundCount > 0 {
		return errors.New("kernel reload failed")
	}
	return nil
}

func (k *testKernel) Stop() error {
	k.stopped = true
	k.running = false
	return nil
}

func (k *testKernel) Status() KernelStatus {
	return KernelStatus{Name: k.name, Running: k.running}
}

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

func TestApplyConfigStopsOldKernelWhenTypeChanges(t *testing.T) {
	db, err := InitDatabase(filepath.Join(t.TempDir(), "nodetools.db"))
	if err != nil {
		t.Fatalf("InitDatabase returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager := NewManager(db, "")
	oldKernel := &testKernel{name: "sing-box"}
	manager.kernel = oldKernel

	cfg := Config{Kernel: KernelConfig{Type: "placeholder"}}
	cfg.Server.WebPort = 8080
	cfg.Server.AdminUser = "admin"
	cfg.Server.AdminPass = "password123"
	if err := manager.ApplyConfig(cfg); err != nil {
		t.Fatalf("ApplyConfig returned error: %v", err)
	}

	if !oldKernel.stopped {
		t.Fatal("expected ApplyConfig to stop the old kernel before replacing it")
	}
	if manager.kernel == oldKernel {
		t.Fatal("expected ApplyConfig to replace the old kernel")
	}
}

func TestConfigValidateRejectsDuplicateNames(t *testing.T) {
	cfg := Config{
		Inbounds: []InboundConfig{
			{Name: "dup", Protocol: "mixed", Port: 1080},
			{Name: "dup", Protocol: "http", Port: 1081},
		},
	}
	cfg.Server.WebPort = 8080
	cfg.Server.AdminUser = "admin"
	cfg.Server.AdminPass = "password123"
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate inbound name") {
		t.Fatalf("expected duplicate inbound error, got %v", err)
	}

	cfg.Inbounds = nil
	cfg.Outbounds = []OutboundConfig{
		{Name: "dup", Protocol: "http", Address: "127.0.0.1", Port: 8080},
		{Name: "dup", Protocol: "http", Address: "127.0.0.1", Port: 8081},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate outbound name") {
		t.Fatalf("expected duplicate outbound error, got %v", err)
	}

	cfg.Outbounds = []OutboundConfig{{Name: "proxy", Protocol: "http", Address: "127.0.0.1", Port: 8080}}
	cfg.Routing = RoutingConfig{
		Mode:            "rule",
		DefaultOutbound: "proxy",
		Rules: []RoutingRule{
			{Name: "dup-rule", MatchType: "domain", Value: "example.com", Outbound: "proxy"},
			{Name: "dup-rule", MatchType: "domain", Value: "example.org", Outbound: "proxy"},
		},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate routing rule name") {
		t.Fatalf("expected duplicate routing rule error, got %v", err)
	}
}

func TestKernelFailureRollsBackRuntimeAndGeneratedConfig(t *testing.T) {
	tmpDir := t.TempDir()
	generatedPath := filepath.Join(tmpDir, "kernel.generated.json")
	if err := os.WriteFile(generatedPath, []byte(`{"inbounds":0}`), 0o644); err != nil {
		t.Fatalf("write generated config: %v", err)
	}
	db, err := InitDatabase(filepath.Join(tmpDir, "nodetools.db"))
	if err != nil {
		t.Fatalf("InitDatabase returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager := NewManager(db, filepath.Join(tmpDir, "config.yaml"))
	manager.kernel = &testKernel{name: "placeholder", failWithInbounds: true}
	manager.cfg = Config{Kernel: KernelConfig{Type: "placeholder", ConfigPath: generatedPath}}
	manager.cfg.Server.WebPort = 8080
	manager.cfg.Server.AdminUser = "admin"
	manager.cfg.Server.AdminPass = "password123"

	_, err = manager.CreateProxy(ProxyCreateRequest{Name: "local", Protocol: "mixed", Listen: "0.0.0.0", Port: 1080})
	if err == nil {
		t.Fatal("expected kernel failure")
	}
	if _, ok := manager.inbounds["local"]; ok {
		t.Fatal("expected failed create to roll back inbound map")
	}
	if len(manager.ConfigSnapshot().Inbounds) != 0 {
		t.Fatalf("expected failed create to roll back config, got %#v", manager.ConfigSnapshot().Inbounds)
	}
	data, err := os.ReadFile(generatedPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	if string(data) != `{"inbounds":0}` {
		t.Fatalf("expected generated config to roll back, got %s", string(data))
	}
}

func TestBatchEnableIsAtomic(t *testing.T) {
	db, err := InitDatabase(filepath.Join(t.TempDir(), "nodetools.db"))
	if err != nil {
		t.Fatalf("InitDatabase returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager := NewManager(db, "")
	cfg := Config{
		Outbounds: []OutboundConfig{
			{Name: "one", Protocol: "http", Address: "127.0.0.1", Port: 8081},
			{Name: "two", Protocol: "http", Address: "127.0.0.1", Port: 8082},
		},
		Routing: RoutingConfig{Mode: "global", DefaultOutbound: "one"},
	}
	cfg.Server.WebPort = 8080
	cfg.Server.AdminUser = "admin"
	cfg.Server.AdminPass = "password123"
	if err := manager.ApplyConfig(cfg); err != nil {
		t.Fatalf("ApplyConfig returned error: %v", err)
	}

	_, err = manager.SetNodesEnabled([]BatchNodeItem{
		{Type: "outbound", Name: "one"},
		{Type: "outbound", Name: "missing"},
	}, false)
	if err == nil {
		t.Fatal("expected missing node error")
	}
	snapshot := manager.ConfigSnapshot()
	if snapshot.Outbounds[0].Disabled {
		t.Fatalf("expected batch enable failure to leave first outbound enabled, got %#v", snapshot.Outbounds)
	}
}

func TestConfigHistoryRestore(t *testing.T) {
	db, err := InitDatabase(filepath.Join(t.TempDir(), "nodetools.db"))
	if err != nil {
		t.Fatalf("InitDatabase returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager := NewManager(db, "")
	first := Config{
		Outbounds: []OutboundConfig{{Name: "old", Protocol: "http", Address: "127.0.0.1", Port: 8081}},
		Routing:   RoutingConfig{Mode: "global", DefaultOutbound: "old"},
	}
	first.Server.WebPort = 8080
	first.Server.AdminUser = "admin"
	first.Server.AdminPass = "password123"
	if err := manager.ApplyConfig(first); err != nil {
		t.Fatalf("first ApplyConfig returned error: %v", err)
	}
	second := first
	second.Outbounds = []OutboundConfig{{Name: "new", Protocol: "http", Address: "127.0.0.1", Port: 8082}}
	second.Routing.DefaultOutbound = "new"
	if err := manager.ApplyConfig(second); err != nil {
		t.Fatalf("second ApplyConfig returned error: %v", err)
	}

	history, err := manager.ListConfigHistory(10)
	if err != nil {
		t.Fatalf("ListConfigHistory returned error: %v", err)
	}
	if len(history) < 2 {
		t.Fatalf("expected at least two history entries, got %#v", history)
	}
	if err := manager.RestoreConfigHistory(history[1].ID); err != nil {
		t.Fatalf("RestoreConfigHistory returned error: %v", err)
	}
	snapshot := manager.ConfigSnapshot()
	if len(snapshot.Outbounds) != 1 || snapshot.Outbounds[0].Name != "old" || snapshot.Routing.DefaultOutbound != "old" {
		t.Fatalf("expected restored old config, got %#v", snapshot)
	}
	if snapshot.Server.AdminPass != "password123" {
		t.Fatal("expected restore to preserve current admin password")
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

func TestImportOutboundsReportPreservesManualName(t *testing.T) {
	db, err := InitDatabase(filepath.Join(t.TempDir(), "nodetools.db"))
	if err != nil {
		t.Fatalf("InitDatabase returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager := NewManager(db, "")
	cfg := Config{
		Outbounds: []OutboundConfig{{
			Name:       "manual-name",
			Protocol:   "vless",
			Address:    "45.139.193.187",
			Port:       8881,
			UUID:       "cbf378ef-bbf8-4539-a564-31c6f0173142",
			Flow:       "xtls-rprx-vision",
			Security:   "reality",
			TLS:        true,
			ServerName: "addons.mozilla.org",
			PublicKey:  "pub",
		}},
	}
	cfg.Server.WebPort = 8080
	cfg.Server.AdminUser = "admin"
	cfg.Server.AdminPass = "password123"
	if err := manager.ApplyConfig(cfg); err != nil {
		t.Fatalf("ApplyConfig returned error: %v", err)
	}

	report, err := manager.ImportOutboundsReport([]OutboundConfig{{
		Name:       "subscription-name",
		Protocol:   "vless",
		Address:    "45.139.193.187",
		Port:       8881,
		UUID:       "cbf378ef-bbf8-4539-a564-31c6f0173142",
		Flow:       "xtls-rprx-vision",
		Security:   "reality",
		TLS:        true,
		ServerName: "addons.mozilla.org",
		PublicKey:  "pub",
	}})
	if err != nil {
		t.Fatalf("ImportOutboundsReport returned error: %v", err)
	}
	if report.Unchanged != 1 || len(report.Details) != 1 || report.Details[0].Name != "manual-name" || !report.Details[0].PreservedName {
		t.Fatalf("expected manual name preserved, got %#v", report)
	}
}

func TestPreviewRoutingExplainsFinalOutbound(t *testing.T) {
	db, err := InitDatabase(filepath.Join(t.TempDir(), "nodetools.db"))
	if err != nil {
		t.Fatalf("InitDatabase returned error: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	manager := NewManager(db, "")
	cfg := Config{
		Kernel:    KernelConfig{Type: "sing-box"},
		Inbounds:  []InboundConfig{{Name: "local", Protocol: "mixed", Port: 1080}},
		Outbounds: []OutboundConfig{{Name: "proxy", Protocol: "http", Address: "127.0.0.1", Port: 8080}},
		Routing: RoutingConfig{
			Mode:            "rule",
			DefaultOutbound: "proxy",
			Rules: []RoutingRule{
				{Name: "direct-cn", MatchType: "domain_suffix", Value: "cn", Outbound: "direct", Priority: 10},
				{Name: "geo-cn", MatchType: "geosite", Value: "cn", Outbound: "direct", Priority: 20},
			},
		},
	}
	cfg.Server.WebPort = 8080
	cfg.Server.AdminUser = "admin"
	cfg.Server.AdminPass = "password123"
	manager.cfg = cfg
	preview := manager.PreviewRouting(RoutingPreviewRequest{Inbound: "local", Target: "example.cn", Protocol: "tcp", Port: 443})
	if preview.Outbound != "direct" || preview.MatchedRule != "direct-cn" {
		t.Fatalf("expected direct-cn match, got %#v", preview)
	}
	preview = manager.PreviewRouting(RoutingPreviewRequest{Inbound: "local", Target: "google.com", Protocol: "tcp", Port: 443})
	if preview.Outbound != "proxy" || len(preview.Warnings) == 0 {
		t.Fatalf("expected default proxy with geosite warning, got %#v", preview)
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
