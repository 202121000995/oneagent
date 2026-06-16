package core

import (
	"path/filepath"
	"testing"
)

func TestParseClashRuleSetConvertsSupportedRules(t *testing.T) {
	raw := []byte(`payload:
  - DOMAIN,example.com
  - DOMAIN-SUFFIX,youtube.com
  - DOMAIN-KEYWORD,openai
  - IP-CIDR,1.1.1.0/24
  - IP-CIDR6,2001:db8::/32
  - PROCESS-NAME,Telegram.exe
  - IP-ASN,15169
`)
	ruleSet, skipped, err := parseClashRuleSet("youtube", raw)
	if err != nil {
		t.Fatalf("parseClashRuleSet returned error: %v", err)
	}
	if len(ruleSet.Domain) != 1 || ruleSet.Domain[0] != "example.com" {
		t.Fatalf("expected domain rule, got %#v", ruleSet)
	}
	if len(ruleSet.DomainSuffix) != 1 || ruleSet.DomainSuffix[0] != "youtube.com" {
		t.Fatalf("expected suffix rule, got %#v", ruleSet)
	}
	if len(ruleSet.DomainKeyword) != 1 || ruleSet.DomainKeyword[0] != "openai" {
		t.Fatalf("expected keyword rule, got %#v", ruleSet)
	}
	if len(ruleSet.IPCIDR) != 2 || skipped != 2 {
		t.Fatalf("expected two cidr rules and two skipped rules, got cidr=%#v skipped=%d", ruleSet.IPCIDR, skipped)
	}
}

func TestWriteAndPreviewLocalRuleSet(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "youtube.json")
	ruleSet := RuleSetConfig{
		Tag:          "youtube",
		DomainSuffix: []string{"youtube.com"},
	}
	if err := writeSingBoxSourceRuleSet(path, ruleSet); err != nil {
		t.Fatalf("writeSingBoxSourceRuleSet returned error: %v", err)
	}
	local := RuleSetConfig{Tag: "youtube", Type: "local", Format: "source", Path: path}
	if !ruleSetMatches(local, RoutingPreviewRequest{Target: "www.youtube.com"}) {
		t.Fatalf("expected local source rule set to match preview target")
	}
}

func TestEnsurePolicyRouteRuleForCustomPolicy(t *testing.T) {
	rules, id := ensurePolicyRouteRule([]RouteRuleConfig{{ID: "rule-final", MatchType: "final", Outbound: "policy-final", Enabled: true, Order: 9999}}, AppPolicyGroupConfig{
		ID:      "policy-disney",
		Name:    "Disney",
		Enabled: true,
	}, "disney")
	if id != "rule-disney" || len(rules) != 2 {
		t.Fatalf("expected custom policy route rule, got id=%s rules=%#v", id, rules)
	}
	if rules[0].RuleSet != "disney" || rules[0].Outbound != "policy-disney" || rules[0].Order >= rules[1].Order {
		t.Fatalf("expected custom policy route before final, got %#v", rules)
	}
}
