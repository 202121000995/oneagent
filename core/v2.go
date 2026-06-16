package core

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	v2compiler "nodetoolsagent/internal/compiler"
	v2model "nodetoolsagent/internal/model"
)

const (
	defaultSmartURL      = v2model.DefaultSmartURL
	defaultSmartInterval = v2model.DefaultSmartInterval
	defaultTolerance     = v2model.DefaultTolerance
)

type EntryAuthConfig = v2model.EntryAuthConfig
type EntryConfig = v2model.EntryConfig
type SubscriptionConfig = v2model.SubscriptionConfig
type OutboundNodeConfig = v2model.OutboundNodeConfig
type RegionGroupSmartConfig = v2model.RegionGroupSmartConfig
type RegionGroupConfig = v2model.RegionGroupConfig
type AppPolicyGroupConfig = v2model.AppPolicyGroupConfig
type RouteRuleConfig = v2model.RouteRuleConfig
type RuleSetConfig = v2model.RuleSetConfig
type V2Model = v2model.V2Model
type regionPreset = v2model.RegionPreset

var defaultRegionPresets = v2model.DefaultRegionPresets
var policyDefaults = v2model.DefaultPolicyGroups
var defaultRouteRules = v2model.DefaultRouteRules
var defaultRuleSets = v2model.DefaultRuleSets

func HasV2Config(cfg Config) bool {
	return cfg.ModelVersion == "v2" ||
		len(cfg.Entries) > 0 ||
		len(cfg.Nodes) > 0 ||
		len(cfg.RegionGroups) > 0 ||
		len(cfg.AppPolicyGroups) > 0 ||
		len(cfg.RouteRules) > 0 ||
		len(cfg.RuleSets) > 0 ||
		len(cfg.Subscriptions) > 0
}

func NormalizeV2Config(cfg Config) Config {
	if !HasV2Config(cfg) && len(cfg.Inbounds)+len(cfg.Outbounds)+len(cfg.Mihomo.Providers) == 0 {
		return cfg
	}
	cfg.ModelVersion = "v2"
	cfg.Entries = normalizeEntries(cfg.Entries, cfg.Inbounds)
	cfg.Subscriptions = normalizeSubscriptions(cfg.Subscriptions, cfg.Mihomo.Providers)
	cfg.Nodes = normalizeOutboundNodes(cfg.Nodes, cfg.Outbounds, cfg.Subscriptions)
	cfg.RegionGroups = normalizeRegionGroups(cfg.RegionGroups, cfg.Nodes)
	cfg.AppPolicyGroups = normalizeAppPolicyGroups(cfg.AppPolicyGroups, cfg.Nodes)
	cfg.RuleSets = normalizeRuleSets(cfg.RuleSets)
	cfg.RouteRules = normalizeRouteRules(cfg.RouteRules, cfg.Routing)
	cfg.RouteRules = normalizeRouteRuleRefs(cfg.RouteRules, cfg.Entries, cfg.Nodes, cfg.RegionGroups, cfg.AppPolicyGroups)
	cfg = syncV2RuntimeFields(cfg)
	return cfg
}

func syncV2RuntimeFields(cfg Config) Config {
	cfg.Inbounds = make([]InboundConfig, 0, len(cfg.Entries))
	for _, entry := range cfg.Entries {
		cfg.Inbounds = append(cfg.Inbounds, v2EntryToInbound(entry))
	}
	cfg.Outbounds = make([]OutboundConfig, 0, len(cfg.Nodes))
	for _, node := range cfg.Nodes {
		cfg.Outbounds = append(cfg.Outbounds, v2NodeToOutbound(node))
	}
	cfg.Routing = v2RouteRulesToRouting(cfg.RouteRules)
	return cfg
}

func V2ModelFromConfig(cfg Config) V2Model {
	cfg = NormalizeV2Config(cfg)
	return V2Model{
		Entries:         append([]EntryConfig(nil), cfg.Entries...),
		Subscriptions:   append([]SubscriptionConfig(nil), cfg.Subscriptions...),
		Nodes:           append([]OutboundNodeConfig(nil), cfg.Nodes...),
		RegionGroups:    append([]RegionGroupConfig(nil), cfg.RegionGroups...),
		AppPolicyGroups: append([]AppPolicyGroupConfig(nil), cfg.AppPolicyGroups...),
		RouteRules:      append([]RouteRuleConfig(nil), cfg.RouteRules...),
		RuleSets:        append([]RuleSetConfig(nil), cfg.RuleSets...),
	}
}

func CompileV2Runtime(cfg Config) (RuntimeState, error) {
	cfg = NormalizeV2Config(cfg)
	runtime, err := v2compiler.Compile(V2ModelFromConfig(cfg))
	if err != nil {
		return RuntimeState{}, err
	}
	return runtimeFromV2Compiler(runtime), nil
}

func runtimeFromV2Compiler(runtime v2compiler.RuntimeState) RuntimeState {
	inbounds := make([]InboundConfig, 0, len(runtime.Inbounds))
	for _, inbound := range runtime.Inbounds {
		inbounds = append(inbounds, InboundConfig{
			Name:           inbound.Name,
			Protocol:       inbound.Protocol,
			Listen:         inbound.Listen,
			Port:           inbound.Port,
			Sniff:          inbound.Sniff,
			Username:       inbound.Username,
			Password:       inbound.Password,
			ProtocolConfig: inbound.ProtocolConfig,
		})
	}
	outbounds := make([]OutboundConfig, 0, len(runtime.Outbounds))
	for _, outbound := range runtime.Outbounds {
		outbounds = append(outbounds, OutboundConfig{
			Name:              outbound.Name,
			Protocol:          outbound.Protocol,
			Address:           outbound.Address,
			Port:              outbound.Port,
			RawConfig:         outbound.RawConfig,
			SelectorOutbounds: outbound.SelectorOutbounds,
			Default:           outbound.Default,
			URL:               outbound.URL,
			Interval:          outbound.Interval,
			Tolerance:         outbound.Tolerance,
		})
	}
	rules := make([]RoutingRule, 0, len(runtime.Routing.Rules))
	for _, rule := range runtime.Routing.Rules {
		rules = append(rules, RoutingRule{
			Name:      rule.Name,
			MatchType: rule.MatchType,
			Value:     rule.Value,
			Inbound:   rule.Inbound,
			Outbound:  rule.Outbound,
			Priority:  rule.Priority,
			Disabled:  rule.Disabled,
		})
	}
	return RuntimeState{
		Inbounds:  inbounds,
		Outbounds: outbounds,
		Routing: RoutingConfig{
			Mode:            runtime.Routing.Mode,
			DefaultOutbound: runtime.Routing.DefaultOutbound,
			Rules:           rules,
			RuleSets:        runtime.Routing.RuleSets,
		},
	}
}

func normalizeEntries(entries []EntryConfig, legacy []InboundConfig) []EntryConfig {
	byID := map[string]EntryConfig{}
	for _, entry := range entries {
		if entry.ID == "" {
			entry.ID = stableID("entry", entry.Name)
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
		byID[entry.ID] = entry
	}
	for _, inbound := range legacy {
		id := stableID("entry", inbound.Name)
		if _, ok := byID[id]; ok {
			continue
		}
		byID[id] = EntryConfig{
			ID:      id,
			Name:    inbound.Name,
			Type:    inbound.Protocol,
			Listen:  firstNonEmpty(inbound.Listen, "0.0.0.0"),
			Port:    inbound.Port,
			Enabled: !inbound.Disabled,
			Sniff:   true,
			Auth: EntryAuthConfig{
				Enabled:  inbound.Username != "" || inbound.Password != "",
				Username: inbound.Username,
				Password: inbound.Password,
			},
			ProtocolConfig: inbound.ProtocolConfig,
		}
	}
	return sortedEntries(byID)
}

func normalizeSubscriptions(subscriptions []SubscriptionConfig, providers []ProxyProviderConfig) []SubscriptionConfig {
	byID := map[string]SubscriptionConfig{}
	for _, sub := range subscriptions {
		if sub.ID == "" {
			sub.ID = stableID("sub", firstNonEmpty(sub.Name, sub.URL))
		}
		if sub.Type == "" {
			sub.Type = "auto"
		}
		if sub.RefreshInterval == 0 {
			sub.RefreshInterval = 3600
		}
		byID[sub.ID] = sub
	}
	for _, provider := range providers {
		if provider.URL == "" {
			continue
		}
		id := stableID("sub", firstNonEmpty(provider.Name, provider.URL))
		if _, ok := byID[id]; ok {
			continue
		}
		interval := provider.Interval
		if interval == 0 {
			interval = 3600
		}
		byID[id] = SubscriptionConfig{ID: id, Name: firstNonEmpty(provider.Name, id), URL: provider.URL, Type: "auto", Enabled: true, RefreshInterval: interval}
	}
	out := make([]SubscriptionConfig, 0, len(byID))
	for _, sub := range byID {
		out = append(out, sub)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func normalizeOutboundNodes(nodes []OutboundNodeConfig, legacy []OutboundConfig, subscriptions []SubscriptionConfig) []OutboundNodeConfig {
	byID := map[string]OutboundNodeConfig{}
	for _, node := range nodes {
		if node.ID == "" {
			node.ID = stableID("node", node.Name)
		}
		if node.Name == "" {
			node.Name = node.ID
		}
		if node.Region == "" {
			node.Region = DetectNodeRegion(node.Name, node.Address)
		}
		if node.Source == "" {
			node.Source = "manual"
		}
		if subID := subscriptionIDForProvider(node.Provider, subscriptions); subID != "" {
			node.SubscriptionID = firstNonEmpty(node.SubscriptionID, subID)
			node.Source = "subscription"
		}
		byID[node.ID] = node
	}
	for _, outbound := range legacy {
		if outbound.Protocol == "direct" || outbound.Protocol == "block" || outbound.Protocol == "selector" || outbound.Protocol == "urltest" {
			continue
		}
		id := stableID("node", outbound.Name)
		if _, ok := byID[outbound.Name]; ok {
			id = outbound.Name
		}
		raw := outboundToRawConfig(outbound)
		source := "manual"
		if outbound.Subscription != "" {
			source = "subscription"
		}
		next := OutboundNodeConfig{
			ID:             id,
			Name:           outbound.Name,
			Type:           outbound.Protocol,
			Region:         DetectNodeRegion(outbound.Name, outbound.Address),
			Provider:       firstNonEmpty(outbound.Subscription, outbound.Group),
			Address:        outbound.Address,
			Port:           outbound.Port,
			Enabled:        !outbound.Disabled,
			Source:         source,
			SubscriptionID: subscriptionIDForProvider(outbound.Subscription, subscriptions),
			RawConfig:      raw,
		}
		if existing, ok := byID[id]; ok {
			next.Name = firstNonEmpty(existing.Name, next.Name)
			next.Region = firstNonEmpty(existing.Region, next.Region)
			next.Provider = firstNonEmpty(existing.Provider, next.Provider)
			next.Source = firstNonEmpty(existing.Source, next.Source)
			next.SubscriptionID = firstNonEmpty(existing.SubscriptionID, next.SubscriptionID)
			next.Enabled = existing.Enabled
			next.ManualGroupIDs = append([]string(nil), existing.ManualGroupIDs...)
			next.Tags = append([]string(nil), existing.Tags...)
		}
		byID[id] = next
	}
	out := make([]OutboundNodeConfig, 0, len(byID))
	for _, node := range byID {
		out = append(out, node)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func subscriptionIDForProvider(provider string, subscriptions []SubscriptionConfig) string {
	for _, sub := range subscriptions {
		if provider == sub.ID || provider == sub.Name {
			return sub.ID
		}
	}
	return ""
}

func normalizeRegionGroups(groups []RegionGroupConfig, nodes []OutboundNodeConfig) []RegionGroupConfig {
	byID := map[string]RegionGroupConfig{}
	for _, group := range groups {
		if group.ID == "" {
			group.ID = stableID("region", group.Name)
		}
		if group.Mode == "" {
			group.Mode = "smart"
		}
		if group.Smart.URL == "" {
			group.Smart.URL = defaultSmartURL
		}
		if group.Smart.Interval == "" {
			group.Smart.Interval = defaultSmartInterval
		}
		if group.Smart.Tolerance == 0 {
			group.Smart.Tolerance = defaultTolerance
		}
		byID[group.ID] = group
	}
	for _, preset := range defaultRegionPresets {
		group, ok := byID[preset.ID]
		if !ok {
			group = RegionGroupConfig{ID: preset.ID, Name: preset.Name, Mode: "smart", NodeIDs: nodeIDsForRegion(nodes, preset.Code), Enabled: true}
		}
		group.Smart.URL = firstNonEmpty(group.Smart.URL, defaultSmartURL)
		group.Smart.Interval = firstNonEmpty(group.Smart.Interval, defaultSmartInterval)
		group.Smart.Tolerance = firstNonZero(group.Smart.Tolerance, defaultTolerance)
		byID[preset.ID] = group
	}
	out := make([]RegionGroupConfig, 0, len(byID))
	for _, preset := range defaultRegionPresets {
		out = append(out, byID[preset.ID])
	}
	return out
}

func normalizeAppPolicyGroups(policies []AppPolicyGroupConfig, nodes []OutboundNodeConfig) []AppPolicyGroupConfig {
	baseCandidates := []string{"region-hk", "region-sg", "region-jp", "region-us", "region-eu", "region-au", "region-other", "policy-auto", "policy-manual", "direct", "block"}
	for _, node := range nodes {
		baseCandidates = append(baseCandidates, node.ID)
	}
	byID := map[string]AppPolicyGroupConfig{}
	for _, policy := range policyDefaults {
		policy.Type = "selector"
		policy.Enabled = true
		policy.Candidates = append([]string(nil), baseCandidates...)
		byID[policy.ID] = policy
	}
	for _, policy := range policies {
		if policy.ID == "" {
			policy.ID = stableID("policy", policy.Name)
		}
		base := byID[policy.ID]
		if base.ID == "" {
			base = AppPolicyGroupConfig{ID: policy.ID, Type: "selector", Enabled: true, Candidates: append([]string(nil), baseCandidates...)}
		}
		if policy.Name != "" {
			base.Name = policy.Name
		}
		if policy.Type != "" {
			base.Type = policy.Type
		}
		if policy.Selected != "" {
			base.Selected = policy.Selected
		}
		if len(policy.Candidates) > 0 {
			base.Candidates = policy.Candidates
		}
		if policy.RuleSetURL != "" {
			base.RuleSetURL = policy.RuleSetURL
		}
		if policy.SortOrder != 0 {
			base.SortOrder = policy.SortOrder
		}
		base.Enabled = policy.Enabled
		byID[policy.ID] = base
	}
	out := make([]AppPolicyGroupConfig, 0, len(byID))
	for _, policy := range byID {
		out = append(out, policy)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SortOrder == out[j].SortOrder {
			return out[i].ID < out[j].ID
		}
		return out[i].SortOrder < out[j].SortOrder
	})
	return out
}

func normalizeRouteRules(rules []RouteRuleConfig, legacy RoutingConfig) []RouteRuleConfig {
	if len(rules) > 0 {
		for i := range rules {
			if rules[i].ID == "" {
				rules[i].ID = stableID("rule", firstNonEmpty(rules[i].Name, rules[i].MatchValue, rules[i].RuleSet))
			}
		}
		if isLegacyInboundPassthroughRouteSet(rules) {
			return append([]RouteRuleConfig(nil), defaultRouteRules...)
		}
		return rules
	}
	if len(legacy.Rules) > 0 {
		out := make([]RouteRuleConfig, 0, len(legacy.Rules)+1)
		for _, rule := range legacy.Rules {
			out = append(out, RouteRuleConfig{
				ID:         stableID("rule", firstNonEmpty(rule.Name, rule.Inbound, rule.Value)),
				Name:       firstNonEmpty(rule.Name, rule.Inbound),
				MatchType:  routingRuleMatchType(rule),
				MatchValue: routingRuleValue(rule),
				Inbound:    rule.Inbound,
				Outbound:   rule.Outbound,
				Enabled:    !rule.Disabled,
				Order:      rule.Priority,
			})
		}
		if legacy.DefaultOutbound != "" {
			out = append(out, RouteRuleConfig{ID: "rule-final", Name: "Final", MatchType: "final", Outbound: legacy.DefaultOutbound, Enabled: true, Order: 9999})
		}
		if isLegacyInboundPassthroughRouteSet(out) {
			return append([]RouteRuleConfig(nil), defaultRouteRules...)
		}
		return out
	}
	return append([]RouteRuleConfig(nil), defaultRouteRules...)
}

func isLegacyInboundPassthroughRouteSet(rules []RouteRuleConfig) bool {
	if len(rules) == 0 {
		return false
	}
	hasInboundPassthrough := false
	for _, rule := range rules {
		matchType := firstNonEmpty(rule.MatchType, "domain_suffix")
		if matchType == "final" {
			continue
		}
		outbound := strings.ToLower(rule.Outbound)
		if matchType != "inbound" || (outbound != "direct" && outbound != "block") {
			return false
		}
		if rule.Inbound != "" || rule.MatchValue != "" {
			hasInboundPassthrough = true
		}
	}
	return hasInboundPassthrough
}

func normalizeRouteRuleRefs(rules []RouteRuleConfig, entries []EntryConfig, nodes []OutboundNodeConfig, groups []RegionGroupConfig, policies []AppPolicyGroupConfig) []RouteRuleConfig {
	if len(rules) == 0 {
		return rules
	}
	entryByID := map[string]string{}
	entryByName := map[string]string{}
	for _, entry := range entries {
		if entry.ID != "" {
			entryByID[entry.ID] = entry.ID
		}
		if entry.Name != "" && entry.ID != "" {
			entryByName[entry.Name] = entry.ID
		}
	}
	outboundByID := map[string]string{"direct": "direct", "block": "block"}
	outboundByName := map[string]string{
		"Direct": "direct",
		"DIRECT": "direct",
		"direct": "direct",
		"Block":  "block",
		"BLOCK":  "block",
		"block":  "block",
	}
	for _, node := range nodes {
		if node.ID != "" {
			outboundByID[node.ID] = node.ID
		}
		if node.Name != "" && node.ID != "" {
			outboundByName[node.Name] = node.ID
		}
	}
	for _, group := range groups {
		if group.ID != "" {
			outboundByID[group.ID] = group.ID
		}
		if group.Name != "" && group.ID != "" {
			outboundByName[group.Name] = group.ID
		}
	}
	for _, policy := range policies {
		if policy.ID != "" {
			outboundByID[policy.ID] = policy.ID
		}
		if policy.Name != "" && policy.ID != "" {
			outboundByName[policy.Name] = policy.ID
		}
	}
	canonicalEntry := func(value string) string {
		if value == "" {
			return ""
		}
		if id, ok := entryByID[value]; ok {
			return id
		}
		if id, ok := entryByName[value]; ok {
			return id
		}
		if id, ok := entryByID[stableID("entry", value)]; ok {
			return id
		}
		return value
	}
	canonicalOutbound := func(value string) string {
		if value == "" {
			return ""
		}
		if id, ok := outboundByID[value]; ok {
			return id
		}
		if id, ok := outboundByName[value]; ok {
			return id
		}
		if id, ok := outboundByID[stableID("node", value)]; ok {
			return id
		}
		return value
	}
	out := append([]RouteRuleConfig(nil), rules...)
	for i := range out {
		out[i].Inbound = canonicalEntry(out[i].Inbound)
		if out[i].MatchType == "inbound" {
			out[i].MatchValue = canonicalEntry(out[i].MatchValue)
		}
		out[i].Outbound = canonicalOutbound(out[i].Outbound)
	}
	return out
}

func normalizeRuleSets(ruleSets []RuleSetConfig) []RuleSetConfig {
	byTag := map[string]RuleSetConfig{}
	for _, rs := range defaultRuleSets {
		byTag[rs.Tag] = rs
	}
	for _, rs := range ruleSets {
		if rs.Tag == "" {
			continue
		}
		if rs.Type == "" {
			rs.Type = "inline"
		}
		byTag[rs.Tag] = rs
	}
	out := make([]RuleSetConfig, 0, len(byTag))
	for _, rs := range byTag {
		out = append(out, rs)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Tag < out[j].Tag })
	return out
}

func outboundToRawConfig(outbound OutboundConfig) map[string]any {
	raw := map[string]any{
		"type":        outbound.Protocol,
		"tag":         stableID("node", outbound.Name),
		"server":      outbound.Address,
		"server_port": outbound.Port,
	}
	addOptionalAny(raw, "uuid", outbound.UUID)
	addOptionalAny(raw, "password", outbound.Password)
	addOptionalAny(raw, "username", outbound.Username)
	addOptionalAny(raw, "method", outbound.Method)
	addOptionalAny(raw, "flow", outbound.Flow)
	addOptionalAny(raw, "network", outbound.Network)
	if outbound.TLS || outbound.ServerName != "" || outbound.SkipCertVerify || outbound.PublicKey != "" {
		tls := map[string]any{"enabled": outbound.TLS || outbound.ServerName != "" || outbound.PublicKey != ""}
		addOptionalAny(tls, "server_name", outbound.ServerName)
		if outbound.SkipCertVerify {
			tls["insecure"] = true
		}
		if outbound.PublicKey != "" || outbound.Security == "reality" {
			tls["utls"] = map[string]any{"enabled": true, "fingerprint": firstNonEmpty(outbound.Fingerprint, "chrome")}
			reality := map[string]any{"enabled": true}
			addOptionalAny(reality, "public_key", outbound.PublicKey)
			addOptionalAny(reality, "short_id", outbound.ShortID)
			tls["reality"] = reality
		}
		raw["tls"] = tls
	}
	if outbound.Transport != "" && outbound.Transport != "tcp" {
		transport := map[string]any{"type": outbound.Transport}
		addOptionalAny(transport, "path", outbound.Path)
		if outbound.Host != "" {
			transport["headers"] = map[string][]string{"Host": {outbound.Host}}
		}
		raw["transport"] = transport
	}
	return raw
}

func DetectNodeRegion(name, address string) string {
	value := strings.ToLower(name + " " + address)
	for _, preset := range defaultRegionPresets {
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

func nodeIDsForRegion(nodes []OutboundNodeConfig, region string) []string {
	var out []string
	for _, node := range nodes {
		if node.Region == region {
			out = append(out, node.ID)
		}
		for _, groupID := range node.ManualGroupIDs {
			if groupID == "region-"+region {
				out = append(out, node.ID)
			}
		}
	}
	return uniqueStrings(out)
}

func sortedEntries(items map[string]EntryConfig) []EntryConfig {
	out := make([]EntryConfig, 0, len(items))
	for _, item := range items {
		out = append(out, item)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Name < out[j].Name })
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

func addOptionalAny(target map[string]any, key string, value string) {
	if value != "" {
		target[key] = value
	}
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

func fallbackCandidates(items, fallback []string) []string {
	items = uniqueStrings(items)
	if len(items) > 0 {
		return items
	}
	return append([]string(nil), fallback...)
}

func firstAvailable(preferred string, candidates []string) string {
	candidates = fallbackCandidates(candidates, []string{"direct"})
	if preferred != "" {
		for _, candidate := range candidates {
			if candidate == preferred {
				return preferred
			}
		}
	}
	return candidates[0]
}

func isASCIIAlpha(value string) bool {
	for _, r := range value {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return value != ""
}

func marshalV2GeneratedConfig(data []byte) (map[string]any, error) {
	var payload map[string]any
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("generated config is not json: %w", err)
	}
	return payload, nil
}
