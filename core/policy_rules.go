package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type PolicyRuleUpdateResult struct {
	PolicyID    string `json:"policy_id"`
	PolicyName  string `json:"policy_name"`
	RuleSet     string `json:"rule_set"`
	URL         string `json:"url"`
	Path        string `json:"path,omitempty"`
	Status      string `json:"status"`
	Domain      int    `json:"domain"`
	Suffix      int    `json:"domain_suffix"`
	Keyword     int    `json:"domain_keyword"`
	IPCIDR      int    `json:"ip_cidr"`
	Skipped     int    `json:"skipped"`
	Error       string `json:"error,omitempty"`
	UsedProxy   bool   `json:"used_proxy,omitempty"`
	ProxyEntry  string `json:"proxy_entry,omitempty"`
	UpdatedRule string `json:"updated_rule,omitempty"`
}

type clashRulePayload struct {
	Payload []string `yaml:"payload"`
}

type singBoxSourceRuleSet struct {
	Version int             `json:"version"`
	Rules   []RuleSetConfig `json:"rules"`
}

func (m *Manager) UpdateV2PolicyRules(useProxy bool) ([]PolicyRuleUpdateResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	snapshot := m.snapshotLocked()
	model := V2ModelFromConfig(m.cfg)
	results := make([]PolicyRuleUpdateResult, 0)
	changed := false

	for _, policy := range sortedAppPolicies(model.AppPolicyGroups) {
		ruleURL := strings.TrimSpace(policy.RuleSetURL)
		if ruleURL == "" || !policy.Enabled {
			continue
		}
		tag := policyRuleSetTag(model.RouteRules, policy.ID)
		result := PolicyRuleUpdateResult{
			PolicyID:   policy.ID,
			PolicyName: policy.Name,
			RuleSet:    tag,
			URL:        ruleURL,
		}
		raw, proxyEntry, err := m.fetchRuleSetSourceLocked(ruleURL, useProxy, model.Entries)
		result.UsedProxy = useProxy && proxyEntry != ""
		result.ProxyEntry = proxyEntry
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
			results = append(results, result)
			continue
		}
		ruleSet, skipped, err := parseClashRuleSet(tag, raw)
		if err != nil {
			result.Status = "error"
			result.Error = err.Error()
			results = append(results, result)
			continue
		}
		result.Domain = len(ruleSet.Domain)
		result.Suffix = len(ruleSet.DomainSuffix)
		result.Keyword = len(ruleSet.DomainKeyword)
		result.IPCIDR = len(ruleSet.IPCIDR)
		result.Skipped = skipped

		path := filepath.Join("rulesets", tag+".json")
		if err := writeSingBoxSourceRuleSet(path, ruleSet); err != nil {
			result.Status = "error"
			result.Error = err.Error()
			results = append(results, result)
			continue
		}
		ruleSet.Type = "local"
		ruleSet.Format = "source"
		ruleSet.Path = path
		ruleSet.URL = ruleURL
		ruleSet.Domain = nil
		ruleSet.DomainSuffix = nil
		ruleSet.DomainKeyword = nil
		ruleSet.IPCIDR = nil
		model.RuleSets = upsertRuleSet(model.RuleSets, ruleSet)
		var routeID string
		model.RouteRules, routeID = ensurePolicyRouteRule(model.RouteRules, policy, tag)
		result.Path = path
		result.Status = "updated"
		result.UpdatedRule = routeID
		results = append(results, result)
		changed = true
	}

	if !changed {
		return results, nil
	}
	m.applyV2ModelToConfigLocked(model)
	if err := m.commitWithRollbackLocked(snapshot); err != nil {
		return results, err
	}
	return results, nil
}

func parseClashRuleSet(tag string, raw []byte) (RuleSetConfig, int, error) {
	var payload clashRulePayload
	if err := yaml.Unmarshal(raw, &payload); err != nil {
		return RuleSetConfig{}, 0, err
	}
	ruleSet := RuleSetConfig{Tag: tag, Type: "inline"}
	skipped := 0
	for _, line := range payload.Payload {
		kind, value, ok := splitClashRule(line)
		if !ok {
			skipped++
			continue
		}
		switch kind {
		case "DOMAIN":
			ruleSet.Domain = append(ruleSet.Domain, value)
		case "DOMAIN-SUFFIX":
			ruleSet.DomainSuffix = append(ruleSet.DomainSuffix, value)
		case "DOMAIN-KEYWORD":
			ruleSet.DomainKeyword = append(ruleSet.DomainKeyword, value)
		case "IP-CIDR", "IP-CIDR6":
			ruleSet.IPCIDR = append(ruleSet.IPCIDR, value)
		default:
			skipped++
		}
	}
	ruleSet.Domain = uniqueStrings(ruleSet.Domain)
	ruleSet.DomainSuffix = uniqueStrings(ruleSet.DomainSuffix)
	ruleSet.DomainKeyword = uniqueStrings(ruleSet.DomainKeyword)
	ruleSet.IPCIDR = uniqueStrings(ruleSet.IPCIDR)
	if len(ruleSet.Domain)+len(ruleSet.DomainSuffix)+len(ruleSet.DomainKeyword)+len(ruleSet.IPCIDR) == 0 {
		return RuleSetConfig{}, skipped, fmt.Errorf("ruleset %q has no supported rules", tag)
	}
	return ruleSet, skipped, nil
}

func splitClashRule(line string) (string, string, bool) {
	parts := strings.Split(line, ",")
	if len(parts) < 2 {
		return "", "", false
	}
	kind := strings.ToUpper(strings.TrimSpace(parts[0]))
	value := strings.TrimSpace(parts[1])
	if value == "" {
		return "", "", false
	}
	return kind, value, true
}

func writeSingBoxSourceRuleSet(path string, ruleSet RuleSetConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	rule := map[string]any{}
	if len(ruleSet.Domain) > 0 {
		rule["domain"] = ruleSet.Domain
	}
	if len(ruleSet.DomainSuffix) > 0 {
		rule["domain_suffix"] = ruleSet.DomainSuffix
	}
	if len(ruleSet.DomainKeyword) > 0 {
		rule["domain_keyword"] = ruleSet.DomainKeyword
	}
	if len(ruleSet.IPCIDR) > 0 {
		rule["ip_cidr"] = ruleSet.IPCIDR
	}
	payload := map[string]any{
		"version": 4,
		"rules":   []map[string]any{rule},
	}
	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0644)
}

func loadLocalRuleSetForPreview(ruleSet RuleSetConfig) RuleSetConfig {
	if ruleSet.Type != "local" || ruleSet.Path == "" {
		return ruleSet
	}
	data, err := os.ReadFile(ruleSet.Path)
	if err != nil {
		return ruleSet
	}
	var source singBoxSourceRuleSet
	if err := json.Unmarshal(data, &source); err != nil {
		return ruleSet
	}
	for _, rule := range source.Rules {
		ruleSet.Domain = append(ruleSet.Domain, rule.Domain...)
		ruleSet.DomainSuffix = append(ruleSet.DomainSuffix, rule.DomainSuffix...)
		ruleSet.DomainKeyword = append(ruleSet.DomainKeyword, rule.DomainKeyword...)
		ruleSet.IPCIDR = append(ruleSet.IPCIDR, rule.IPCIDR...)
	}
	return ruleSet
}

func upsertRuleSet(ruleSets []RuleSetConfig, next RuleSetConfig) []RuleSetConfig {
	out := append([]RuleSetConfig(nil), ruleSets...)
	for i := range out {
		if out[i].Tag == next.Tag {
			out[i] = next
			return out
		}
	}
	return append(out, next)
}

func ensurePolicyRouteRule(rules []RouteRuleConfig, policy AppPolicyGroupConfig, tag string) ([]RouteRuleConfig, string) {
	out := append([]RouteRuleConfig(nil), rules...)
	for i := range out {
		if out[i].Outbound == policy.ID && out[i].MatchType == "rule_set" {
			out[i].RuleSet = tag
			out[i].MatchValue = ""
			out[i].Enabled = policy.Enabled
			return sortRouteRules(out), out[i].ID
		}
	}
	order := nextPolicyRuleOrder(out)
	id := "rule-" + tag
	out = append(out, RouteRuleConfig{
		ID:        id,
		Name:      firstNonEmpty(policy.Name, policy.ID),
		MatchType: "rule_set",
		RuleSet:   tag,
		Outbound:  policy.ID,
		Enabled:   true,
		Order:     order,
	})
	return sortRouteRules(out), id
}

func policyRuleSetTag(rules []RouteRuleConfig, policyID string) string {
	for _, rule := range rules {
		if rule.Outbound == policyID && rule.MatchType == "rule_set" && rule.RuleSet != "" {
			return rule.RuleSet
		}
	}
	tag := strings.TrimPrefix(policyID, "policy-")
	if tag == "" || tag == policyID {
		tag = stableID("rule", policyID)
	}
	return tag
}

func nextPolicyRuleOrder(rules []RouteRuleConfig) int {
	maxOrder := 0
	finalOrder := 9999
	for _, rule := range rules {
		if rule.MatchType == "final" {
			finalOrder = rule.Order
			continue
		}
		if rule.Order > maxOrder && rule.Order < finalOrder {
			maxOrder = rule.Order
		}
	}
	next := maxOrder + 10
	if next >= finalOrder {
		next = finalOrder - 1
	}
	if next <= 0 {
		next = 10
	}
	return next
}

func sortRouteRules(rules []RouteRuleConfig) []RouteRuleConfig {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Order == rules[j].Order {
			return rules[i].ID < rules[j].ID
		}
		return rules[i].Order < rules[j].Order
	})
	return rules
}

func sortedAppPolicies(policies []AppPolicyGroupConfig) []AppPolicyGroupConfig {
	out := append([]AppPolicyGroupConfig(nil), policies...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SortOrder == out[j].SortOrder {
			return out[i].ID < out[j].ID
		}
		return out[i].SortOrder < out[j].SortOrder
	})
	return out
}

func (m *Manager) fetchRuleSetSourceLocked(rawURL string, useProxy bool, entries []EntryConfig) ([]byte, string, error) {
	if useProxy {
		entry, ok := firstProxyEntry(entries)
		if ok {
			data, err := fetchURLWithEntryProxy(rawURL, entry)
			return data, entry.ID, err
		}
	}
	data, err := fetchURLDirect(rawURL)
	return data, "", err
}

func fetchURLDirect(rawURL string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NodeToolsAgent/0.2")
	client := &http.Client{Timeout: 45 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("download failed: %s", resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024))
}

func fetchURLWithEntryProxy(rawURL string, entry EntryConfig) ([]byte, error) {
	host := entry.Listen
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsUnspecified() {
		host = "127.0.0.1"
	}
	args := []string{"--fail", "--location", "--silent", "--show-error", "--max-time", "60"}
	switch strings.ToLower(entry.Type) {
	case "socks", "socks5":
		args = append(args, "--socks5-hostname", net.JoinHostPort(host, fmt.Sprint(entry.Port)))
	default:
		proxyURL := url.URL{Scheme: "http", Host: net.JoinHostPort(host, fmt.Sprint(entry.Port))}
		args = append(args, "--proxy", proxyURL.String())
	}
	if entry.Auth.Username != "" || entry.Auth.Password != "" {
		args = append(args, "--proxy-user", entry.Auth.Username+":"+entry.Auth.Password)
	}
	args = append(args, rawURL)
	cmd := exec.Command("curl", args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	data, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("proxy download failed: %s", msg)
	}
	if len(data) > 64*1024*1024 {
		return nil, fmt.Errorf("download too large")
	}
	return data, nil
}

func firstProxyEntry(entries []EntryConfig) (EntryConfig, bool) {
	for _, entry := range entries {
		if !entry.Enabled || entry.Port == 0 {
			continue
		}
		switch strings.ToLower(entry.Type) {
		case "mixed", "http", "socks", "socks5":
			return entry, true
		}
	}
	return EntryConfig{}, false
}
