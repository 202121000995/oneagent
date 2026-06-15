package service

import (
	"testing"

	"nodetoolsagent/internal/model"
)

func TestUpsertExistingNodeDoesNotReassignRegionGroup(t *testing.T) {
	svc := NewV2ModelService()
	input := model.V2Model{
		Nodes: []model.OutboundNodeConfig{{
			ID:      "node-hk-001",
			Name:    "香港 01",
			Type:    "vless",
			Region:  "hk",
			Enabled: true,
		}},
		RegionGroups: []model.RegionGroupConfig{{
			ID:      "region-hk",
			Name:    "香港",
			Mode:    "smart",
			NodeIDs: []string{},
			Enabled: true,
		}},
	}

	output, _, err := svc.UpsertNode(input, model.OutboundNodeConfig{
		ID:      "node-hk-001",
		Name:    "香港 01",
		Type:    "vless",
		Region:  "hk",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("UpsertNode returned error: %v", err)
	}
	if len(output.RegionGroups) != 1 || len(output.RegionGroups[0].NodeIDs) != 0 {
		t.Fatalf("expected existing node update to preserve edited region members, got %#v", output.RegionGroups)
	}
}

func TestDeleteNodeRemovesPolicyReferences(t *testing.T) {
	svc := NewV2ModelService()
	input := model.V2Model{
		Subscriptions: []model.SubscriptionConfig{{ID: "sub-main", Name: "Main", URL: "https://example.com/sub", Enabled: true}},
		Nodes: []model.OutboundNodeConfig{{
			ID:       "node-hk-001",
			Name:     "香港 01",
			Type:     "vless",
			Source:   "manual",
			Provider: "Main",
			Enabled:  true,
		}},
		RegionGroups:    []model.RegionGroupConfig{{ID: "region-hk", NodeIDs: []string{"node-hk-001"}, SelectedNodeID: "node-hk-001", Enabled: true}},
		AppPolicyGroups: []model.AppPolicyGroupConfig{{ID: "policy-final", Selected: "node-hk-001", Candidates: []string{"node-hk-001"}, Enabled: true}},
	}

	output, err := svc.DeleteNode(input, "node-hk-001")
	if err != nil {
		t.Fatalf("DeleteNode returned error: %v", err)
	}
	if len(output.Nodes) != 0 {
		t.Fatalf("expected node to be deleted, got %#v", output.Nodes)
	}
	if len(output.RegionGroups[0].NodeIDs) != 0 || output.RegionGroups[0].SelectedNodeID != "" {
		t.Fatalf("expected region references to be removed, got %#v", output.RegionGroups)
	}
	if output.AppPolicyGroups[0].Selected != "policy-manual" || len(output.AppPolicyGroups[0].Candidates) != 0 {
		t.Fatalf("expected policy references to be removed, got %#v", output.AppPolicyGroups)
	}
}

func TestDeleteSubscriptionRemovesItsNodes(t *testing.T) {
	svc := NewV2ModelService()
	input := model.V2Model{
		Subscriptions: []model.SubscriptionConfig{{ID: "sub-main", Name: "Main", URL: "https://example.com/sub", Enabled: true}},
		Nodes: []model.OutboundNodeConfig{
			{ID: "node-sub", Name: "Sub", Type: "vless", Source: "subscription", Provider: "Main", SubscriptionID: "sub-main", Enabled: true},
			{ID: "node-manual", Name: "Manual", Type: "vless", Source: "manual", Enabled: true},
		},
		RegionGroups: []model.RegionGroupConfig{{ID: "region-hk", NodeIDs: []string{"node-sub", "node-manual"}, Enabled: true}},
	}

	output, err := svc.DeleteSubscription(input, "sub-main")
	if err != nil {
		t.Fatalf("DeleteSubscription returned error: %v", err)
	}
	if len(output.Subscriptions) != 0 {
		t.Fatalf("expected subscription to be deleted, got %#v", output.Subscriptions)
	}
	if len(output.Nodes) != 1 || output.Nodes[0].ID != "node-manual" {
		t.Fatalf("expected only manual node to remain, got %#v", output.Nodes)
	}
	if len(output.RegionGroups[0].NodeIDs) != 1 || output.RegionGroups[0].NodeIDs[0] != "node-manual" {
		t.Fatalf("expected deleted subscription node to be removed from region, got %#v", output.RegionGroups)
	}
}

func TestReplaceRouteRulesConvertsStaleInboundRuleSet(t *testing.T) {
	svc := NewV2ModelService()
	input := model.V2Model{
		Entries: []model.EntryConfig{{ID: "entry-local-mixed", Name: "Local-Mixed", Type: "mixed", Enabled: true}},
	}

	output, err := svc.ReplaceRouteRules(input, []model.RouteRuleConfig{{
		ID:        "rule-adblock",
		Name:      "广告拦截",
		MatchType: "inbound",
		Inbound:   "adblock",
		Outbound:  "policy-adblock",
		Enabled:   true,
		Order:     10,
	}})
	if err != nil {
		t.Fatalf("ReplaceRouteRules returned error: %v", err)
	}
	if len(output.RouteRules) != 1 {
		t.Fatalf("expected one route rule, got %#v", output.RouteRules)
	}
	rule := output.RouteRules[0]
	if rule.MatchType != "rule_set" || rule.RuleSet != "adblock" || rule.Inbound != "" || rule.MatchValue != "" {
		t.Fatalf("expected stale inbound rule to become rule_set, got %#v", rule)
	}
}
