package compiler

import (
	"regexp"
	"sort"
	"strings"

	"nodetoolsagent/internal/model"
)

type RuntimeState struct {
	Inbounds  []InboundConfig  `json:"inbounds"`
	Outbounds []OutboundConfig `json:"outbounds"`
	Routing   RoutingConfig    `json:"routing"`
}

type InboundConfig struct {
	Name           string         `json:"name"`
	Protocol       string         `json:"protocol"`
	Listen         string         `json:"listen,omitempty"`
	Port           int            `json:"port"`
	Username       string         `json:"username,omitempty"`
	Password       string         `json:"password,omitempty"`
	ProtocolConfig map[string]any `json:"protocol_config,omitempty"`
}

type OutboundConfig struct {
	Name              string         `json:"name"`
	Protocol          string         `json:"protocol"`
	Address           string         `json:"address,omitempty"`
	Port              int            `json:"port,omitempty"`
	RawConfig         map[string]any `json:"raw_config,omitempty"`
	SelectorOutbounds []string       `json:"selector_outbounds,omitempty"`
	Default           string         `json:"default,omitempty"`
	URL               string         `json:"url,omitempty"`
	Interval          string         `json:"interval,omitempty"`
	Tolerance         int            `json:"tolerance,omitempty"`
}

type RoutingRule struct {
	Name      string `json:"name,omitempty"`
	MatchType string `json:"match_type,omitempty"`
	Value     string `json:"value,omitempty"`
	Inbound   string `json:"inbound,omitempty"`
	Outbound  string `json:"outbound"`
	Priority  int    `json:"priority,omitempty"`
	Disabled  bool   `json:"disabled,omitempty"`
}

type RoutingConfig struct {
	Mode            string                `json:"mode,omitempty"`
	DefaultOutbound string                `json:"default_outbound,omitempty"`
	Rules           []RoutingRule         `json:"rules"`
	RuleSets        []model.RuleSetConfig `json:"rule_sets,omitempty"`
}

func Compile(input model.V2Model) (RuntimeState, error) {
	nodeTags := enabledNodeTags(input.Nodes)
	viability := newOutboundViability(input)
	outbounds := make([]OutboundConfig, 0, len(input.Nodes)+len(input.RegionGroups)*2+len(input.AppPolicyGroups)+4)
	for _, node := range input.Nodes {
		if !node.Enabled {
			continue
		}
		outbounds = append(outbounds, nodeOutbound(node))
	}

	for _, group := range input.RegionGroups {
		if !group.Enabled {
			continue
		}
		groupNodes := enabledGroupNodeIDs(group, input.Nodes)
		if len(groupNodes) == 0 {
			groupNodes = []string{"block"}
		}
		autoTag := group.ID + "-auto"
		outbounds = append(outbounds, OutboundConfig{
			Name:              autoTag,
			Protocol:          "urltest",
			SelectorOutbounds: groupNodes,
			URL:               firstNonEmpty(group.Smart.URL, model.DefaultSmartURL),
			Interval:          firstNonEmpty(group.Smart.Interval, model.DefaultSmartInterval),
			Tolerance:         firstNonZero(group.Smart.Tolerance, model.DefaultTolerance),
		})
		selectorCandidates := append([]string{autoTag}, groupNodes...)
		selected := autoTag
		if group.Mode == "manual" && group.SelectedNodeID != "" {
			selected = group.SelectedNodeID
		}
		outbounds = append(outbounds, OutboundConfig{
			Name:              group.ID,
			Protocol:          "selector",
			SelectorOutbounds: uniqueStrings(selectorCandidates),
			Default:           selected,
		})
	}

	outbounds = append(outbounds, OutboundConfig{Name: "direct", Protocol: "direct"})
	outbounds = append(outbounds, OutboundConfig{Name: "block", Protocol: "block"})
	outbounds = append(outbounds, OutboundConfig{
		Name:              "policy-auto",
		Protocol:          "urltest",
		SelectorOutbounds: fallbackCandidates(nodeTags, []string{"block"}),
		URL:               model.DefaultSmartURL,
		Interval:          model.DefaultSmartInterval,
		Tolerance:         model.DefaultTolerance,
	})
	manualCandidates := policyManualCandidates(input.RegionGroups, input.Nodes)
	outbounds = append(outbounds, OutboundConfig{
		Name:              "policy-manual",
		Protocol:          "selector",
		SelectorOutbounds: manualCandidates,
		Default:           firstViableOutbound("region-hk", manualCandidates, viability),
	})
	for _, policy := range sortedPolicies(input.AppPolicyGroups) {
		if !policy.Enabled || policy.ID == "policy-auto" || policy.ID == "policy-manual" {
			continue
		}
		candidates := fallbackCandidates(policy.Candidates, []string{"block"})
		outbounds = append(outbounds, OutboundConfig{
			Name:              policy.ID,
			Protocol:          "selector",
			SelectorOutbounds: candidates,
			Default:           firstViableOutbound(policy.Selected, candidates, viability),
		})
	}

	routing := RoutingConfig{Mode: "rule", DefaultOutbound: "policy-final", RuleSets: input.RuleSets}
	for _, rule := range sortedRouteRules(input.RouteRules) {
		if !rule.Enabled {
			continue
		}
		if rule.MatchType == "final" {
			routing.DefaultOutbound = firstNonEmpty(rule.Outbound, routing.DefaultOutbound)
			continue
		}
		routing.Rules = append(routing.Rules, RoutingRule{
			Name:      firstNonEmpty(rule.ID, rule.Name),
			MatchType: firstNonEmpty(rule.MatchType, "rule_set"),
			Value:     firstNonEmpty(rule.MatchValue, rule.RuleSet),
			Inbound:   rule.Inbound,
			Outbound:  rule.Outbound,
			Priority:  rule.Order,
		})
	}

	return RuntimeState{
		Inbounds:  compileEntries(input.Entries),
		Outbounds: outbounds,
		Routing:   routing,
	}, nil
}

func DetectNodeRegion(name, address string) string {
	value := strings.ToLower(name + " " + address)
	for _, preset := range model.DefaultRegionPresets {
		if preset.Code == "other" {
			continue
		}
		for _, keyword := range preset.Keywords {
			kw := strings.ToLower(keyword)
			if len(kw) <= 2 && isASCIIAlpha(kw) {
				if regexp.MustCompile(`(^|[^a-z])` + regexp.QuoteMeta(kw) + `([^a-z]|$)`).MatchString(value) {
					return preset.Code
				}
				continue
			}
			if strings.Contains(value, kw) {
				return preset.Code
			}
		}
	}
	return "other"
}

func compileEntries(entries []model.EntryConfig) []InboundConfig {
	inbounds := make([]InboundConfig, 0, len(entries))
	for _, entry := range entries {
		if !entry.Enabled {
			continue
		}
		inbounds = append(inbounds, InboundConfig{
			Name:           firstNonEmpty(entry.ID, entry.Name),
			Protocol:       entry.Type,
			Listen:         entry.Listen,
			Port:           entry.Port,
			Username:       entry.Auth.Username,
			Password:       entry.Auth.Password,
			ProtocolConfig: entry.ProtocolConfig,
		})
	}
	return inbounds
}

func nodeOutbound(node model.OutboundNodeConfig) OutboundConfig {
	raw := copyMap(node.RawConfig)
	if len(raw) == 0 {
		raw = map[string]any{"type": node.Type, "server": node.Address, "server_port": node.Port}
	}
	raw["type"] = firstNonEmpty(stringValue(raw["type"]), node.Type)
	raw["tag"] = node.ID
	return OutboundConfig{
		Name:      node.ID,
		Protocol:  firstNonEmpty(node.Type, stringValue(raw["type"])),
		Address:   firstNonEmpty(node.Address, stringValue(raw["server"])),
		Port:      firstNonZero(node.Port, intValue(raw["server_port"])),
		RawConfig: raw,
	}
}

func enabledNodeTags(nodes []model.OutboundNodeConfig) []string {
	var out []string
	for _, node := range nodes {
		if node.Enabled {
			out = append(out, node.ID)
		}
	}
	return out
}

func enabledGroupNodeIDs(group model.RegionGroupConfig, nodes []model.OutboundNodeConfig) []string {
	enabled := map[string]struct{}{}
	for _, node := range nodes {
		if node.Enabled {
			enabled[node.ID] = struct{}{}
		}
	}
	var out []string
	for _, id := range group.NodeIDs {
		if _, ok := enabled[id]; ok {
			out = append(out, id)
		}
	}
	return uniqueStrings(out)
}

func policyManualCandidates(groups []model.RegionGroupConfig, nodes []model.OutboundNodeConfig) []string {
	var out []string
	for _, group := range groups {
		if group.Enabled {
			out = append(out, group.ID)
		}
	}
	for _, node := range nodes {
		if node.Enabled {
			out = append(out, node.ID)
		}
	}
	return fallbackCandidates(uniqueStrings(out), []string{"block"})
}

type outboundViability struct {
	nodes       map[string]struct{}
	groupNodes  map[string]int
	hasAnyNodes bool
}

func newOutboundViability(input model.V2Model) outboundViability {
	v := outboundViability{nodes: map[string]struct{}{}, groupNodes: map[string]int{}}
	for _, node := range input.Nodes {
		if !node.Enabled {
			continue
		}
		v.nodes[node.ID] = struct{}{}
		v.hasAnyNodes = true
	}
	for _, group := range input.RegionGroups {
		if !group.Enabled {
			continue
		}
		v.groupNodes[group.ID] = len(enabledGroupNodeIDs(group, input.Nodes))
	}
	return v
}

func firstViableOutbound(preferred string, candidates []string, viability outboundViability) string {
	candidateSet := map[string]struct{}{}
	for _, candidate := range candidates {
		candidateSet[candidate] = struct{}{}
	}
	if _, ok := candidateSet[preferred]; ok && isViableOutbound(preferred, viability) {
		return preferred
	}
	for _, candidate := range candidates {
		if isViableOutbound(candidate, viability) {
			return candidate
		}
	}
	if _, ok := candidateSet["block"]; ok {
		return "block"
	}
	if len(candidates) > 0 {
		return candidates[0]
	}
	return "block"
}

func isViableOutbound(tag string, viability outboundViability) bool {
	switch tag {
	case "":
		return false
	case "direct", "block":
		return true
	case "policy-auto", "policy-manual":
		return viability.hasAnyNodes
	}
	if _, ok := viability.nodes[tag]; ok {
		return true
	}
	return viability.groupNodes[tag] > 0
}

func sortedPolicies(policies []model.AppPolicyGroupConfig) []model.AppPolicyGroupConfig {
	out := append([]model.AppPolicyGroupConfig(nil), policies...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SortOrder == out[j].SortOrder {
			return out[i].ID < out[j].ID
		}
		return out[i].SortOrder < out[j].SortOrder
	})
	return out
}

func sortedRouteRules(rules []model.RouteRuleConfig) []model.RouteRuleConfig {
	out := append([]model.RouteRuleConfig(nil), rules...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Order == out[j].Order {
			return out[i].ID < out[j].ID
		}
		return out[i].Order < out[j].Order
	})
	return out
}

func copyMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func fallbackCandidates(primary, fallback []string) []string {
	if len(primary) > 0 {
		return uniqueStrings(primary)
	}
	return uniqueStrings(fallback)
}

func firstAvailable(preferred string, candidates []string) string {
	if preferred != "" {
		for _, candidate := range candidates {
			if candidate == preferred {
				return preferred
			}
		}
	}
	if len(candidates) == 0 {
		return ""
	}
	return candidates[0]
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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	default:
		return ""
	}
}

func intValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	default:
		return 0
	}
}

func isASCIIAlpha(value string) bool {
	for _, r := range value {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return value != ""
}
