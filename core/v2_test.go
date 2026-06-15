package core

import (
	"encoding/json"
	"testing"
)

func TestNormalizeV2ConfigClassifiesLegacyNodes(t *testing.T) {
	cfg := Config{
		Inbounds: []InboundConfig{{Name: "main", Protocol: "socks", Listen: "0.0.0.0", Port: 1080}},
		Outbounds: []OutboundConfig{
			{Name: "新加坡 01", Protocol: "vless", Address: "sg.example.com", Port: 443, UUID: "bf000d23-0752-40b4-affe-68f7707a9661"},
			{Name: "Tokyo 01", Protocol: "trojan", Address: "jp.example.com", Port: 443, Password: "secret"},
		},
	}

	model := V2ModelFromConfig(NormalizeV2Config(cfg))
	if len(model.Entries) != 1 || model.Entries[0].ID != "entry-main" {
		t.Fatalf("expected legacy inbound to become entry, got %#v", model.Entries)
	}
	byID := map[string]OutboundNodeConfig{}
	for _, node := range model.Nodes {
		byID[node.ID] = node
	}
	if byID["node-01"].Region != "sg" {
		t.Fatalf("expected singapore node classified as sg, got %#v", byID["node-01"])
	}
	if byID["node-tokyo01"].Region != "jp" {
		t.Fatalf("expected Tokyo node classified as jp, got %#v", byID["node-tokyo01"])
	}
}

func TestCompileV2RuntimeBuildsPolicyChain(t *testing.T) {
	cfg := NormalizeV2Config(Config{
		Entries: []EntryConfig{{ID: "entry-socks-main", Name: "主入口", Type: "socks", Listen: "0.0.0.0", Port: 1080, Enabled: true}},
		Nodes: []OutboundNodeConfig{{
			ID:      "node-sg-001",
			Name:    "新加坡 01",
			Type:    "vless",
			Region:  "sg",
			Address: "sg.example.com",
			Port:    443,
			Enabled: true,
			RawConfig: map[string]any{
				"type":        "vless",
				"server":      "sg.example.com",
				"server_port": 443,
				"uuid":        "bf000d23-0752-40b4-affe-68f7707a9661",
			},
		}},
	})

	state, err := CompileV2Runtime(cfg)
	if err != nil {
		t.Fatalf("CompileV2Runtime returned error: %v", err)
	}
	kernel := NewSingBoxKernel()
	data, err := kernel.GenerateConfig(state)
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}
	var generated map[string]any
	if err := json.Unmarshal(data, &generated); err != nil {
		t.Fatalf("generated config is not JSON: %v", err)
	}
	outbounds := generated["outbounds"].([]any)
	tags := map[string]map[string]any{}
	for _, raw := range outbounds {
		item := raw.(map[string]any)
		tags[item["tag"].(string)] = item
	}
	if tags["region-sg-auto"]["type"] != "urltest" {
		t.Fatalf("expected region smart urltest, got %#v", tags["region-sg-auto"])
	}
	if tags["region-sg"]["type"] != "selector" || tags["policy-netflix"]["type"] != "selector" {
		t.Fatalf("expected region and netflix selectors, got %#v %#v", tags["region-sg"], tags["policy-netflix"])
	}
	route := generated["route"].(map[string]any)
	if route["final"] != "policy-final" {
		t.Fatalf("expected policy final route, got %#v", route)
	}
	if len(route["rule_set"].([]any)) == 0 {
		t.Fatalf("expected inline rule sets, got %#v", route)
	}
	rules := route["rules"].([]any)
	if rules[0].(map[string]any)["rule_set"] == nil {
		t.Fatalf("expected first-match rule_set rules, got %#v", rules)
	}
}

func TestNormalizeV2ConfigRewritesLegacyRouteRefs(t *testing.T) {
	cfg := NormalizeV2Config(Config{
		Entries: []EntryConfig{{
			ID:      "entry-local-mixed",
			Name:    "Local-Mixed",
			Type:    "mixed",
			Listen:  "127.0.0.1",
			Port:    1080,
			Enabled: true,
		}},
		RouteRules: []RouteRuleConfig{{
			ID:         "rule-example",
			Name:       "Example",
			MatchType:  "domain_suffix",
			MatchValue: "example.com",
			Outbound:   "Direct",
			Enabled:    true,
			Order:      10,
		}},
	})
	cfg.Server.WebPort = 8080
	cfg.Server.AdminUser = "admin"
	cfg.Server.AdminPass = "password123"

	if cfg.RouteRules[0].Outbound != "direct" {
		t.Fatalf("expected legacy Direct outbound to normalize to direct, got %#v", cfg.RouteRules[0])
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected v2 route rule to validate after ref normalization: %v", err)
	}
}

func TestNormalizeV2ConfigReplacesLegacyInboundDirectRoute(t *testing.T) {
	cfg := NormalizeV2Config(Config{
		ModelVersion: "v2",
		Entries: []EntryConfig{{
			ID:      "entry-local-mixed",
			Name:    "Local-Mixed",
			Type:    "mixed",
			Listen:  "127.0.0.1",
			Port:    1080,
			Enabled: true,
		}},
		RouteRules: []RouteRuleConfig{{
			ID:         "rule-local",
			Name:       "Local-Mixed",
			MatchType:  "inbound",
			MatchValue: "entry-local-mixed",
			Inbound:    "entry-local-mixed",
			Outbound:   "direct",
			Enabled:    true,
			Order:      10,
		}},
	})
	cfg.Server.WebPort = 8080
	cfg.Server.AdminUser = "admin"
	cfg.Server.AdminPass = "password123"

	if len(cfg.RouteRules) < 2 || cfg.RouteRules[0].ID != "rule-adblock" || cfg.RouteRules[len(cfg.RouteRules)-1].Outbound != "policy-final" {
		t.Fatalf("expected legacy inbound direct route to be replaced by v2 defaults, got %#v", cfg.RouteRules)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected default v2 route rules to validate: %v", err)
	}
	if len(cfg.Routing.Rules) == 0 || cfg.Routing.Rules[0].Outbound != "policy-adblock" {
		t.Fatalf("expected legacy routing cache to sync to v2 route rules, got %#v", cfg.Routing)
	}
	if cfg.Routing.DefaultOutbound != "policy-final" {
		t.Fatalf("expected legacy routing final to sync to policy-final, got %#v", cfg.Routing)
	}
}

func TestNormalizeV2ConfigAddsUTLSToRealityRawConfig(t *testing.T) {
	cfg := NormalizeV2Config(Config{
		Outbounds: []OutboundConfig{{
			Name:       "Reality",
			Protocol:   "vless",
			Address:    "example.com",
			Port:       443,
			UUID:       "bf000d23-0752-40b4-affe-68f7707a9661",
			Security:   "reality",
			TLS:        true,
			ServerName: "addons.mozilla.org",
			PublicKey:  "pub",
		}},
	})
	if len(cfg.Nodes) != 1 {
		t.Fatalf("expected one v2 node, got %#v", cfg.Nodes)
	}
	tls := cfg.Nodes[0].RawConfig["tls"].(map[string]any)
	utls := tls["utls"].(map[string]any)
	if utls["fingerprint"] != "chrome" || utls["enabled"] != true {
		t.Fatalf("expected v2 raw_config to include uTLS chrome, got %#v", cfg.Nodes[0].RawConfig)
	}
}

func TestNormalizeV2ConfigPreservesEditedRegionMembers(t *testing.T) {
	cfg := NormalizeV2Config(Config{
		Nodes: []OutboundNodeConfig{{
			ID:      "node-hk-001",
			Name:    "香港 01",
			Type:    "vless",
			Region:  "hk",
			Enabled: true,
			RawConfig: map[string]any{
				"type": "vless",
			},
		}},
		RegionGroups: []RegionGroupConfig{{
			ID:      "region-hk",
			Name:    "香港",
			Mode:    "smart",
			NodeIDs: []string{},
			Enabled: true,
		}},
	})
	for _, group := range cfg.RegionGroups {
		if group.ID == "region-hk" && len(group.NodeIDs) != 0 {
			t.Fatalf("expected edited region members to be preserved, got %#v", group.NodeIDs)
		}
	}
}
