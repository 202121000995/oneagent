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
