package repository

import (
	"context"
	"database/sql"
	"testing"

	"nodetoolsagent/internal/model"

	_ "modernc.org/sqlite"
)

func TestV2RepositorySaveAndLoadModel(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	repo := NewV2Repository(db)
	ctx := context.Background()
	if err := repo.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	input := model.V2Model{
		Entries: []model.EntryConfig{{
			ID:      "entry-socks-main",
			Name:    "SOCKS Main",
			Type:    "socks",
			Listen:  "0.0.0.0",
			Port:    1080,
			Enabled: true,
			Auth:    model.EntryAuthConfig{Enabled: true, Username: "user", Password: "pass"},
		}},
		Subscriptions: []model.SubscriptionConfig{{
			ID:              "sub-main",
			Name:            "Main",
			URL:             "https://example.com/sub",
			Type:            "auto",
			Enabled:         true,
			RefreshInterval: 3600,
		}},
		Nodes: []model.OutboundNodeConfig{{
			ID:             "node-sg-001",
			Name:           "SG 001",
			Type:           "vless",
			Region:         "sg",
			Address:        "sg.example.com",
			Port:           443,
			Enabled:        true,
			Source:         "subscription",
			SubscriptionID: "sub-main",
			ManualGroupIDs: []string{"region-sg"},
			Tags:           []string{"streaming"},
			RawConfig:      map[string]any{"type": "vless", "server": "sg.example.com", "server_port": float64(443)},
		}},
		RegionGroups: []model.RegionGroupConfig{{
			ID:      "region-sg",
			Name:    "新加坡",
			Mode:    "smart",
			Smart:   model.RegionGroupSmartConfig{URL: model.DefaultSmartURL, Interval: model.DefaultSmartInterval, Tolerance: model.DefaultTolerance},
			NodeIDs: []string{"node-sg-001"},
			Enabled: true,
		}},
		AppPolicyGroups: []model.AppPolicyGroupConfig{{
			ID:         "policy-netflix",
			Name:       "奈飞",
			Type:       "selector",
			Selected:   "region-sg",
			Candidates: []string{"region-sg", "direct", "block"},
			Enabled:    true,
			SortOrder:  30,
		}},
		RouteRules: []model.RouteRuleConfig{{
			ID:        "rule-netflix",
			Name:      "奈飞",
			MatchType: "rule_set",
			RuleSet:   "netflix",
			Outbound:  "policy-netflix",
			Enabled:   true,
			Order:     100,
		}},
		RuleSets: []model.RuleSetConfig{{
			Type:         "inline",
			Tag:          "netflix",
			DomainSuffix: []string{"netflix.com"},
		}},
	}

	if err := repo.SaveModel(ctx, input); err != nil {
		t.Fatalf("save model: %v", err)
	}
	output, ok, err := repo.LoadModel(ctx)
	if err != nil {
		t.Fatalf("load model: %v", err)
	}
	if !ok {
		t.Fatal("expected saved model to be present")
	}
	if len(output.Nodes) != 1 || output.Nodes[0].ID != "node-sg-001" || output.Nodes[0].RawConfig["server"] != "sg.example.com" {
		t.Fatalf("unexpected node round trip: %#v", output.Nodes)
	}
	if len(output.AppPolicyGroups) != 1 || output.AppPolicyGroups[0].Candidates[0] != "region-sg" {
		t.Fatalf("unexpected policy round trip: %#v", output.AppPolicyGroups)
	}
	if len(output.RuleSets) != 1 || output.RuleSets[0].DomainSuffix[0] != "netflix.com" {
		t.Fatalf("unexpected ruleset round trip: %#v", output.RuleSets)
	}
}
