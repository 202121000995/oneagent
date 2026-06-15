package service

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"nodetoolsagent/internal/compiler"
	"nodetoolsagent/internal/model"
)

type V2ModelService struct{}

func NewV2ModelService() V2ModelService {
	return V2ModelService{}
}

func (s V2ModelService) UpsertEntry(m model.V2Model, entry model.EntryConfig) (model.V2Model, model.EntryConfig, error) {
	if entry.ID == "" {
		entry.ID = stableID("entry", firstNonEmpty(entry.Name, entry.Type))
	}
	if entry.Name == "" {
		entry.Name = entry.ID
	}
	if entry.Type == "" {
		entry.Type = "mixed"
	}
	if entry.Listen == "" {
		entry.Listen = "0.0.0.0"
	}
	if entry.Port < 1 || entry.Port > 65535 {
		return m, entry, fmt.Errorf("entry %q requires a valid port", entry.ID)
	}
	if !hasID(m.Entries, entry.ID) && !entry.Enabled {
		entry.Enabled = true
	}
	m.Entries = upsertByID(m.Entries, entry.ID, entry)
	return m, entry, nil
}

func (s V2ModelService) DeleteEntry(m model.V2Model, id string) (model.V2Model, error) {
	next, ok := deleteByID(m.Entries, id)
	if !ok {
		return m, fmt.Errorf("entry %q does not exist", id)
	}
	m.Entries = next
	return m, nil
}

func (s V2ModelService) UpsertSubscription(m model.V2Model, sub model.SubscriptionConfig) (model.V2Model, model.SubscriptionConfig, error) {
	if sub.ID == "" {
		sub.ID = stableID("sub", firstNonEmpty(sub.Name, sub.URL))
	}
	if sub.Name == "" {
		sub.Name = sub.ID
	}
	if sub.URL == "" {
		return m, sub, fmt.Errorf("subscription %q requires url", sub.ID)
	}
	if sub.Type == "" {
		sub.Type = "auto"
	}
	if sub.RefreshInterval == 0 {
		sub.RefreshInterval = 3600
	}
	if !hasID(m.Subscriptions, sub.ID) && !sub.Enabled {
		sub.Enabled = true
	}
	m.Subscriptions = upsertByID(m.Subscriptions, sub.ID, sub)
	return m, sub, nil
}

func (s V2ModelService) DeleteSubscription(m model.V2Model, id string) (model.V2Model, error) {
	next, ok := deleteByID(m.Subscriptions, id)
	if !ok {
		return m, fmt.Errorf("subscription %q does not exist", id)
	}
	m.Subscriptions = next
	for i := range m.Nodes {
		if m.Nodes[i].SubscriptionID == id {
			m.Nodes[i].SubscriptionID = ""
			if m.Nodes[i].Source == "subscription" {
				m.Nodes[i].Source = "manual"
			}
		}
	}
	return m, nil
}

func (s V2ModelService) UpsertNode(m model.V2Model, node model.OutboundNodeConfig) (model.V2Model, model.OutboundNodeConfig, error) {
	if node.ID == "" {
		node.ID = stableID("node", firstNonEmpty(node.Name, node.Address))
	}
	isNew := !hasID(m.Nodes, node.ID)
	if node.Name == "" {
		node.Name = node.ID
	}
	if node.Type == "" {
		return m, node, fmt.Errorf("node %q requires type", node.ID)
	}
	if node.Region == "" {
		node.Region = compiler.DetectNodeRegion(node.Name, node.Address)
	}
	if node.Source == "" {
		node.Source = "manual"
	}
	if node.Enabled == false {
		// Keep explicit false for updates; new nodes are enabled below when absent.
		if !hasID(m.Nodes, node.ID) {
			node.Enabled = true
		}
	}
	m.Nodes = upsertByID(m.Nodes, node.ID, node)
	if isNew {
		m.RegionGroups = assignNodeToRegionGroups(m.RegionGroups, node)
	}
	m.AppPolicyGroups = refreshPolicyCandidates(m.AppPolicyGroups, m.Nodes)
	return m, node, nil
}

func (s V2ModelService) ImportNodes(m model.V2Model, nodes []model.OutboundNodeConfig) (model.V2Model, []model.OutboundNodeConfig, error) {
	imported := make([]model.OutboundNodeConfig, 0, len(nodes))
	for _, node := range nodes {
		var err error
		m, node, err = s.UpsertNode(m, node)
		if err != nil {
			return m, imported, err
		}
		imported = append(imported, node)
	}
	return m, imported, nil
}

func (s V2ModelService) DeleteNode(m model.V2Model, id string) (model.V2Model, error) {
	next, ok := deleteByID(m.Nodes, id)
	if !ok {
		return m, fmt.Errorf("node %q does not exist", id)
	}
	m.Nodes = next
	for i := range m.RegionGroups {
		m.RegionGroups[i].NodeIDs = removeString(m.RegionGroups[i].NodeIDs, id)
		if m.RegionGroups[i].SelectedNodeID == id {
			m.RegionGroups[i].SelectedNodeID = ""
		}
	}
	for i := range m.AppPolicyGroups {
		m.AppPolicyGroups[i].Candidates = removeString(m.AppPolicyGroups[i].Candidates, id)
		if m.AppPolicyGroups[i].Selected == id {
			m.AppPolicyGroups[i].Selected = "policy-manual"
		}
	}
	return m, nil
}

func (s V2ModelService) SetNodeEnabled(m model.V2Model, id string, enabled bool) (model.V2Model, model.OutboundNodeConfig, error) {
	for i := range m.Nodes {
		if m.Nodes[i].ID == id {
			m.Nodes[i].Enabled = enabled
			return m, m.Nodes[i], nil
		}
	}
	return m, model.OutboundNodeConfig{}, fmt.Errorf("node %q does not exist", id)
}

func (s V2ModelService) UpsertRegionGroup(m model.V2Model, group model.RegionGroupConfig) (model.V2Model, model.RegionGroupConfig, error) {
	if group.ID == "" {
		group.ID = stableID("region", group.Name)
	}
	if group.Name == "" {
		group.Name = group.ID
	}
	if group.Mode == "" {
		group.Mode = "smart"
	}
	if group.Smart.URL == "" {
		group.Smart.URL = model.DefaultSmartURL
	}
	if group.Smart.Interval == "" {
		group.Smart.Interval = model.DefaultSmartInterval
	}
	if group.Smart.Tolerance == 0 {
		group.Smart.Tolerance = model.DefaultTolerance
	}
	if !hasID(m.RegionGroups, group.ID) && !group.Enabled {
		group.Enabled = true
	}
	m.RegionGroups = upsertByID(m.RegionGroups, group.ID, group)
	m.AppPolicyGroups = refreshPolicyCandidates(m.AppPolicyGroups, m.Nodes)
	return m, group, nil
}

func (s V2ModelService) DeleteRegionGroup(m model.V2Model, id string) (model.V2Model, error) {
	next, ok := deleteByID(m.RegionGroups, id)
	if !ok {
		return m, fmt.Errorf("region group %q does not exist", id)
	}
	m.RegionGroups = next
	for i := range m.AppPolicyGroups {
		m.AppPolicyGroups[i].Candidates = removeString(m.AppPolicyGroups[i].Candidates, id)
		if m.AppPolicyGroups[i].Selected == id {
			m.AppPolicyGroups[i].Selected = "policy-manual"
		}
	}
	return m, nil
}

func (s V2ModelService) UpsertPolicyGroup(m model.V2Model, policy model.AppPolicyGroupConfig) (model.V2Model, model.AppPolicyGroupConfig, error) {
	if policy.ID == "" {
		policy.ID = stableID("policy", policy.Name)
	}
	if policy.Name == "" {
		policy.Name = policy.ID
	}
	if policy.Type == "" {
		policy.Type = "selector"
	}
	if len(policy.Candidates) == 0 {
		policy.Candidates = policyCandidates(m.RegionGroups, m.Nodes)
	}
	if policy.Selected == "" {
		policy.Selected = firstAvailable(policy.Candidates, "direct")
	}
	if !hasID(m.AppPolicyGroups, policy.ID) && !policy.Enabled {
		policy.Enabled = true
	}
	m.AppPolicyGroups = upsertByID(m.AppPolicyGroups, policy.ID, policy)
	return m, policy, nil
}

func (s V2ModelService) DeletePolicyGroup(m model.V2Model, id string) (model.V2Model, error) {
	next, ok := deleteByID(m.AppPolicyGroups, id)
	if !ok {
		return m, fmt.Errorf("policy group %q does not exist", id)
	}
	m.AppPolicyGroups = next
	for i := range m.RouteRules {
		if m.RouteRules[i].Outbound == id {
			m.RouteRules[i].Outbound = "policy-final"
		}
	}
	return m, nil
}

func (s V2ModelService) UpsertRouteRule(m model.V2Model, rule model.RouteRuleConfig) (model.V2Model, model.RouteRuleConfig, error) {
	if rule.ID == "" {
		rule.ID = stableID("rule", firstNonEmpty(rule.Name, rule.MatchValue, rule.RuleSet, rule.Outbound))
	}
	if rule.Name == "" {
		rule.Name = rule.ID
	}
	if rule.MatchType == "" {
		rule.MatchType = "rule_set"
	}
	if rule.MatchType != "final" && rule.MatchValue == "" && rule.RuleSet == "" && rule.Inbound == "" {
		return m, rule, fmt.Errorf("route rule %q requires match value", rule.ID)
	}
	if rule.Outbound == "" {
		return m, rule, fmt.Errorf("route rule %q requires outbound", rule.ID)
	}
	if rule.Order == 0 {
		rule.Order = nextRuleOrder(m.RouteRules)
	}
	m.RouteRules = upsertByID(m.RouteRules, rule.ID, rule)
	sort.SliceStable(m.RouteRules, func(i, j int) bool {
		if m.RouteRules[i].Order == m.RouteRules[j].Order {
			return m.RouteRules[i].ID < m.RouteRules[j].ID
		}
		return m.RouteRules[i].Order < m.RouteRules[j].Order
	})
	return m, rule, nil
}

func (s V2ModelService) ReplaceRouteRules(m model.V2Model, rules []model.RouteRuleConfig) (model.V2Model, error) {
	m.RouteRules = nil
	for _, rule := range rules {
		var err error
		m, _, err = s.UpsertRouteRule(m, rule)
		if err != nil {
			return m, err
		}
	}
	return m, nil
}

func (s V2ModelService) DeleteRouteRule(m model.V2Model, id string) (model.V2Model, error) {
	next, ok := deleteByID(m.RouteRules, id)
	if !ok {
		return m, fmt.Errorf("route rule %q does not exist", id)
	}
	m.RouteRules = next
	return m, nil
}

type identifiable interface {
	model.EntryConfig | model.SubscriptionConfig | model.OutboundNodeConfig | model.RegionGroupConfig | model.AppPolicyGroupConfig | model.RouteRuleConfig
}

func upsertByID[T identifiable](items []T, id string, next T) []T {
	for i := range items {
		if itemID(items[i]) == id {
			items[i] = next
			return items
		}
	}
	return append(items, next)
}

func deleteByID[T identifiable](items []T, id string) ([]T, bool) {
	for i := range items {
		if itemID(items[i]) == id {
			return append(items[:i], items[i+1:]...), true
		}
	}
	return items, false
}

func hasID[T identifiable](items []T, id string) bool {
	for _, item := range items {
		if itemID(item) == id {
			return true
		}
	}
	return false
}

func itemID(item any) string {
	switch typed := item.(type) {
	case model.EntryConfig:
		return typed.ID
	case model.SubscriptionConfig:
		return typed.ID
	case model.OutboundNodeConfig:
		return typed.ID
	case model.RegionGroupConfig:
		return typed.ID
	case model.AppPolicyGroupConfig:
		return typed.ID
	case model.RouteRuleConfig:
		return typed.ID
	default:
		return ""
	}
}

func assignNodeToRegionGroups(groups []model.RegionGroupConfig, node model.OutboundNodeConfig) []model.RegionGroupConfig {
	targetID := "region-" + firstNonEmpty(node.Region, "other")
	found := false
	for i := range groups {
		if groups[i].ID == targetID {
			groups[i].NodeIDs = uniqueStrings(append(groups[i].NodeIDs, node.ID))
			found = true
			continue
		}
		for _, manualID := range node.ManualGroupIDs {
			if groups[i].ID == manualID {
				groups[i].NodeIDs = uniqueStrings(append(groups[i].NodeIDs, node.ID))
			}
		}
	}
	if found {
		return groups
	}
	groups = append(groups, model.RegionGroupConfig{
		ID:      targetID,
		Name:    targetID,
		Mode:    "smart",
		Smart:   model.RegionGroupSmartConfig{URL: model.DefaultSmartURL, Interval: model.DefaultSmartInterval, Tolerance: model.DefaultTolerance},
		NodeIDs: []string{node.ID},
		Enabled: true,
	})
	return groups
}

func refreshPolicyCandidates(policies []model.AppPolicyGroupConfig, nodes []model.OutboundNodeConfig) []model.AppPolicyGroupConfig {
	candidates := policyCandidates(nil, nodes)
	for i := range policies {
		if len(policies[i].Candidates) == 0 {
			policies[i].Candidates = uniqueStrings(append(policies[i].Candidates, candidates...))
		}
	}
	return policies
}

func policyCandidates(groups []model.RegionGroupConfig, nodes []model.OutboundNodeConfig) []string {
	candidates := []string{"region-hk", "region-sg", "region-jp", "region-us", "region-eu", "region-au", "region-other", "policy-auto", "policy-manual", "direct", "block"}
	for _, group := range groups {
		candidates = append(candidates, group.ID)
	}
	for _, node := range nodes {
		candidates = append(candidates, node.ID)
	}
	return uniqueStrings(candidates)
}

func isDefaultPolicy(id string) bool {
	for _, policy := range model.DefaultPolicyGroups {
		if policy.ID == id {
			return true
		}
	}
	return false
}

func nextRuleOrder(rules []model.RouteRuleConfig) int {
	maxOrder := 0
	for _, rule := range rules {
		if rule.Order > maxOrder && rule.Order < 9000 {
			maxOrder = rule.Order
		}
	}
	return maxOrder + 10
}

func firstAvailable(candidates []string, fallback string) string {
	for _, candidate := range candidates {
		if candidate != "" {
			return candidate
		}
	}
	return fallback
}

func removeString(items []string, value string) []string {
	out := items[:0]
	for _, item := range items {
		if item != value {
			out = append(out, item)
		}
	}
	return out
}

func uniqueStrings(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func stableID(prefix, value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		value = time.Now().Format(time.RFC3339Nano)
	}
	var b strings.Builder
	for _, r := range strings.ToLower(value) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_':
			b.WriteByte('-')
		}
	}
	id := strings.Trim(b.String(), "-")
	if id == "" {
		sum := sha1.Sum([]byte(value))
		id = hex.EncodeToString(sum[:])[:10]
	}
	if prefix != "" && !strings.HasPrefix(id, prefix+"-") {
		id = prefix + "-" + id
	}
	return id
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
