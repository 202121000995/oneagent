package model

const (
	DefaultSmartURL      = "https://www.gstatic.com/generate_204"
	DefaultSmartInterval = "3m"
	DefaultTolerance     = 50
)

type EntryAuthConfig struct {
	Enabled  bool   `yaml:"enabled,omitempty" json:"enabled,omitempty"`
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`
}

type EntryConfig struct {
	ID             string          `yaml:"id" json:"id"`
	Name           string          `yaml:"name" json:"name"`
	Type           string          `yaml:"type" json:"type"`
	Listen         string          `yaml:"listen,omitempty" json:"listen,omitempty"`
	Port           int             `yaml:"port" json:"port"`
	Enabled        bool            `yaml:"enabled" json:"enabled"`
	Sniff          bool            `yaml:"sniff,omitempty" json:"sniff,omitempty"`
	Auth           EntryAuthConfig `yaml:"auth,omitempty" json:"auth,omitempty"`
	ProtocolConfig map[string]any  `yaml:"protocol_config,omitempty" json:"protocol_config,omitempty"`
}

type SubscriptionConfig struct {
	ID              string `yaml:"id" json:"id"`
	Name            string `yaml:"name" json:"name"`
	URL             string `yaml:"url" json:"url"`
	Type            string `yaml:"type,omitempty" json:"type,omitempty"`
	Enabled         bool   `yaml:"enabled" json:"enabled"`
	RefreshInterval int    `yaml:"refresh_interval,omitempty" json:"refresh_interval,omitempty"`
	LastUpdateAt    string `yaml:"last_update_at,omitempty" json:"last_update_at,omitempty"`
}

type OutboundNodeConfig struct {
	ID             string         `yaml:"id" json:"id"`
	Name           string         `yaml:"name" json:"name"`
	Type           string         `yaml:"type" json:"type"`
	Region         string         `yaml:"region,omitempty" json:"region,omitempty"`
	Provider       string         `yaml:"provider,omitempty" json:"provider,omitempty"`
	Address        string         `yaml:"address,omitempty" json:"address,omitempty"`
	Port           int            `yaml:"port,omitempty" json:"port,omitempty"`
	Enabled        bool           `yaml:"enabled" json:"enabled"`
	Alive          bool           `yaml:"alive,omitempty" json:"alive,omitempty"`
	Latency        int64          `yaml:"latency,omitempty" json:"latency,omitempty"`
	Source         string         `yaml:"source,omitempty" json:"source,omitempty"`
	SubscriptionID string         `yaml:"subscription_id,omitempty" json:"subscription_id,omitempty"`
	ManualGroupIDs []string       `yaml:"manual_group_ids,omitempty" json:"manual_group_ids,omitempty"`
	Tags           []string       `yaml:"tags,omitempty" json:"tags,omitempty"`
	RawConfig      map[string]any `yaml:"raw_config,omitempty" json:"raw_config,omitempty"`
}

type RegionGroupSmartConfig struct {
	URL       string `yaml:"url,omitempty" json:"url,omitempty"`
	Interval  string `yaml:"interval,omitempty" json:"interval,omitempty"`
	Tolerance int    `yaml:"tolerance,omitempty" json:"tolerance,omitempty"`
}

type RegionGroupConfig struct {
	ID             string                 `yaml:"id" json:"id"`
	Name           string                 `yaml:"name" json:"name"`
	Mode           string                 `yaml:"mode,omitempty" json:"mode,omitempty"`
	SelectedNodeID string                 `yaml:"selected_node_id,omitempty" json:"selected_node_id,omitempty"`
	Smart          RegionGroupSmartConfig `yaml:"smart,omitempty" json:"smart,omitempty"`
	NodeIDs        []string               `yaml:"node_ids,omitempty" json:"node_ids,omitempty"`
	Enabled        bool                   `yaml:"enabled" json:"enabled"`
}

type AppPolicyGroupConfig struct {
	ID         string   `yaml:"id" json:"id"`
	Name       string   `yaml:"name" json:"name"`
	Type       string   `yaml:"type,omitempty" json:"type,omitempty"`
	Selected   string   `yaml:"selected,omitempty" json:"selected,omitempty"`
	Candidates []string `yaml:"candidates,omitempty" json:"candidates,omitempty"`
	Enabled    bool     `yaml:"enabled" json:"enabled"`
	SortOrder  int      `yaml:"sort_order,omitempty" json:"sort_order,omitempty"`
}

type RouteRuleConfig struct {
	ID         string `yaml:"id" json:"id"`
	Name       string `yaml:"name" json:"name"`
	MatchType  string `yaml:"match_type,omitempty" json:"match_type,omitempty"`
	MatchValue string `yaml:"match_value,omitempty" json:"match_value,omitempty"`
	Inbound    string `yaml:"inbound,omitempty" json:"inbound,omitempty"`
	RuleSet    string `yaml:"rule_set,omitempty" json:"rule_set,omitempty"`
	Outbound   string `yaml:"outbound" json:"outbound"`
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	Order      int    `yaml:"order,omitempty" json:"order,omitempty"`
}

type RuleSetConfig struct {
	Type           string   `yaml:"type,omitempty" json:"type,omitempty"`
	Tag            string   `yaml:"tag" json:"tag"`
	Format         string   `yaml:"format,omitempty" json:"format,omitempty"`
	Path           string   `yaml:"path,omitempty" json:"path,omitempty"`
	URL            string   `yaml:"url,omitempty" json:"url,omitempty"`
	UpdateInterval string   `yaml:"update_interval,omitempty" json:"update_interval,omitempty"`
	DownloadDetour string   `yaml:"download_detour,omitempty" json:"download_detour,omitempty"`
	Domain         []string `yaml:"domain,omitempty" json:"domain,omitempty"`
	DomainSuffix   []string `yaml:"domain_suffix,omitempty" json:"domain_suffix,omitempty"`
	DomainKeyword  []string `yaml:"domain_keyword,omitempty" json:"domain_keyword,omitempty"`
	IPCIDR         []string `yaml:"ip_cidr,omitempty" json:"ip_cidr,omitempty"`
}

type V2Model struct {
	Entries         []EntryConfig          `json:"entries"`
	Subscriptions   []SubscriptionConfig   `json:"subscriptions"`
	Nodes           []OutboundNodeConfig   `json:"nodes"`
	RegionGroups    []RegionGroupConfig    `json:"region_groups"`
	AppPolicyGroups []AppPolicyGroupConfig `json:"app_policy_groups"`
	RouteRules      []RouteRuleConfig      `json:"route_rules"`
	RuleSets        []RuleSetConfig        `json:"rule_sets"`
}

type RegionPreset struct {
	ID       string
	Code     string
	Name     string
	Keywords []string
}

var DefaultRegionPresets = []RegionPreset{
	{ID: "region-hk", Code: "hk", Name: "香港", Keywords: []string{"香港", "港", "hk", "hong kong", "hkg"}},
	{ID: "region-sg", Code: "sg", Name: "新加坡", Keywords: []string{"新加坡", "狮城", "sg", "singapore", "singa"}},
	{ID: "region-jp", Code: "jp", Name: "日本", Keywords: []string{"日本", "东京", "大阪", "jp", "japan", "tokyo", "osaka"}},
	{ID: "region-us", Code: "us", Name: "美国", Keywords: []string{"美国", "美", "us", "usa", "united states", "los angeles", "la", "san jose"}},
	{ID: "region-eu", Code: "eu", Name: "欧洲", Keywords: []string{"欧洲", "英国", "德国", "法国", "荷兰", "eu", "uk", "de", "fr", "nl"}},
	{ID: "region-au", Code: "au", Name: "澳洲", Keywords: []string{"澳洲", "澳大利亚", "au", "australia", "sydney"}},
	{ID: "region-other", Code: "other", Name: "其他"},
}

var DefaultPolicyGroups = []AppPolicyGroupConfig{
	{ID: "policy-manual", Name: "节点选择", Selected: "region-hk", SortOrder: 10},
	{ID: "policy-auto", Name: "自动选择", Selected: "policy-auto", SortOrder: 20},
	{ID: "policy-netflix", Name: "奈飞", Selected: "region-sg", SortOrder: 30},
	{ID: "policy-tiktok", Name: "TikTok", Selected: "region-us", SortOrder: 40},
	{ID: "policy-openai", Name: "OpenAI", Selected: "region-us", SortOrder: 50},
	{ID: "policy-gemini", Name: "Gemini", Selected: "region-us", SortOrder: 60},
	{ID: "policy-claude", Name: "Claude", Selected: "region-us", SortOrder: 70},
	{ID: "policy-youtube", Name: "YouTube", Selected: "region-hk", SortOrder: 80},
	{ID: "policy-telegram", Name: "Telegram", Selected: "region-sg", SortOrder: 90},
	{ID: "policy-bilibili", Name: "Bilibili", Selected: "direct", SortOrder: 100},
	{ID: "policy-cn-direct", Name: "大陆直连", Selected: "direct", SortOrder: 110},
	{ID: "policy-adblock", Name: "广告拦截", Selected: "block", SortOrder: 120},
	{ID: "policy-final", Name: "Final", Selected: "policy-manual", SortOrder: 130},
}

var DefaultRouteRules = []RouteRuleConfig{
	{ID: "rule-adblock", Name: "广告拦截", MatchType: "rule_set", RuleSet: "adblock", Outbound: "policy-adblock", Enabled: true, Order: 10},
	{ID: "rule-cn-direct", Name: "大陆直连", MatchType: "rule_set", RuleSet: "cn", Outbound: "policy-cn-direct", Enabled: true, Order: 20},
	{ID: "rule-bilibili", Name: "Bilibili", MatchType: "rule_set", RuleSet: "bilibili", Outbound: "policy-bilibili", Enabled: true, Order: 50},
	{ID: "rule-telegram", Name: "Telegram", MatchType: "rule_set", RuleSet: "telegram", Outbound: "policy-telegram", Enabled: true, Order: 60},
	{ID: "rule-openai", Name: "OpenAI", MatchType: "rule_set", RuleSet: "openai", Outbound: "policy-openai", Enabled: true, Order: 70},
	{ID: "rule-gemini", Name: "Gemini", MatchType: "rule_set", RuleSet: "gemini", Outbound: "policy-gemini", Enabled: true, Order: 80},
	{ID: "rule-claude", Name: "Claude", MatchType: "rule_set", RuleSet: "claude", Outbound: "policy-claude", Enabled: true, Order: 90},
	{ID: "rule-netflix", Name: "奈飞", MatchType: "rule_set", RuleSet: "netflix", Outbound: "policy-netflix", Enabled: true, Order: 100},
	{ID: "rule-tiktok", Name: "TikTok", MatchType: "rule_set", RuleSet: "tiktok", Outbound: "policy-tiktok", Enabled: true, Order: 110},
	{ID: "rule-youtube", Name: "YouTube", MatchType: "rule_set", RuleSet: "youtube", Outbound: "policy-youtube", Enabled: true, Order: 120},
	{ID: "rule-final", Name: "Final", MatchType: "final", Outbound: "policy-final", Enabled: true, Order: 9999},
}

var DefaultRuleSets = []RuleSetConfig{
	{Type: "inline", Tag: "adblock", DomainKeyword: []string{"doubleclick", "adservice", "googlesyndication"}},
	{Type: "inline", Tag: "cn", DomainSuffix: []string{"cn", "中国"}, DomainKeyword: []string{"baidu", "bilibili", "qq.com", "taobao", "jd.com"}},
	{Type: "inline", Tag: "bilibili", DomainSuffix: []string{"bilibili.com", "bilibili.tv", "hdslb.com"}},
	{Type: "inline", Tag: "telegram", DomainSuffix: []string{"telegram.org", "t.me", "tdesktop.com"}},
	{Type: "inline", Tag: "openai", DomainSuffix: []string{"openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com"}},
	{Type: "inline", Tag: "gemini", DomainSuffix: []string{"gemini.google.com", "generativelanguage.googleapis.com"}},
	{Type: "inline", Tag: "claude", DomainSuffix: []string{"anthropic.com", "claude.ai"}},
	{Type: "inline", Tag: "netflix", DomainSuffix: []string{"netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net"}},
	{Type: "inline", Tag: "tiktok", DomainSuffix: []string{"tiktok.com", "tiktokv.com", "tiktokcdn.com"}},
	{Type: "inline", Tag: "youtube", DomainSuffix: []string{"youtube.com", "youtu.be", "googlevideo.com", "ytimg.com"}},
}
