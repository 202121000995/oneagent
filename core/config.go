package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		WebPort    int    `yaml:"web_port" json:"web_port"`
		PublicHost string `yaml:"public_host,omitempty" json:"public_host,omitempty"`
		AdminUser  string `yaml:"admin_user" json:"admin_user"`
		AdminPass  string `yaml:"admin_pass" json:"-"`
	} `yaml:"server" json:"server"`
	ModelVersion    string                 `yaml:"model_version,omitempty" json:"model_version,omitempty"`
	Kernel          KernelConfig           `yaml:"kernel" json:"kernel"`
	Entries         []EntryConfig          `yaml:"entries,omitempty" json:"entries,omitempty"`
	Subscriptions   []SubscriptionConfig   `yaml:"subscriptions,omitempty" json:"subscriptions,omitempty"`
	Nodes           []OutboundNodeConfig   `yaml:"nodes,omitempty" json:"nodes,omitempty"`
	RegionGroups    []RegionGroupConfig    `yaml:"region_groups,omitempty" json:"region_groups,omitempty"`
	AppPolicyGroups []AppPolicyGroupConfig `yaml:"app_policy_groups,omitempty" json:"app_policy_groups,omitempty"`
	RouteRules      []RouteRuleConfig      `yaml:"route_rules,omitempty" json:"route_rules,omitempty"`
	RuleSets        []RuleSetConfig        `yaml:"rule_sets,omitempty" json:"rule_sets,omitempty"`
	Inbounds        []InboundConfig        `yaml:"inbounds" json:"inbounds"`
	Outbounds       []OutboundConfig       `yaml:"outbounds" json:"outbounds"`
	Routing         RoutingConfig          `yaml:"routing" json:"routing"`
	Mihomo          MihomoConfig           `yaml:"mihomo" json:"mihomo"`
}

type InboundConfig struct {
	Name                   string         `yaml:"name" json:"name"`
	Protocol               string         `yaml:"protocol" json:"protocol"`
	Listen                 string         `yaml:"listen,omitempty" json:"listen,omitempty"`
	Port                   int            `yaml:"port" json:"port"`
	Outbound               string         `yaml:"-" json:"outbound,omitempty"`
	Disabled               bool           `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	Sniff                  bool           `yaml:"sniff,omitempty" json:"sniff,omitempty"`
	Username               string         `yaml:"username,omitempty" json:"username,omitempty"`
	UUID                   string         `yaml:"uuid,omitempty" json:"uuid,omitempty"`
	Password               string         `yaml:"password,omitempty" json:"password,omitempty"`
	Method                 string         `yaml:"method,omitempty" json:"method,omitempty"`
	Flow                   string         `yaml:"flow,omitempty" json:"flow,omitempty"`
	Security               string         `yaml:"security,omitempty" json:"security,omitempty"`
	AlterID                int            `yaml:"alter_id,omitempty" json:"alter_id,omitempty"`
	TLS                    bool           `yaml:"tls,omitempty" json:"tls,omitempty"`
	ServerName             string         `yaml:"server_name,omitempty" json:"server_name,omitempty"`
	CertificatePath        string         `yaml:"certificate_path,omitempty" json:"certificate_path,omitempty"`
	KeyPath                string         `yaml:"key_path,omitempty" json:"key_path,omitempty"`
	CertificateContent     string         `yaml:"-" json:"certificate_content,omitempty"`
	KeyContent             string         `yaml:"-" json:"key_content,omitempty"`
	Transport              string         `yaml:"transport,omitempty" json:"transport,omitempty"`
	Path                   string         `yaml:"path,omitempty" json:"path,omitempty"`
	Host                   string         `yaml:"host,omitempty" json:"host,omitempty"`
	PrivateKey             string         `yaml:"private_key,omitempty" json:"private_key,omitempty"`
	ShortID                string         `yaml:"short_id,omitempty" json:"short_id,omitempty"`
	RealityHandshakeServer string         `yaml:"reality_handshake_server,omitempty" json:"reality_handshake_server,omitempty"`
	RealityHandshakePort   int            `yaml:"reality_handshake_port,omitempty" json:"reality_handshake_port,omitempty"`
	IdleSessionCheck       string         `yaml:"idle_session_check,omitempty" json:"idle_session_check,omitempty"`
	IdleSessionTimeout     string         `yaml:"idle_session_timeout,omitempty" json:"idle_session_timeout,omitempty"`
	MinIdleSession         int            `yaml:"min_idle_session,omitempty" json:"min_idle_session,omitempty"`
	TargetHost             string         `yaml:"target_host,omitempty" json:"target_host,omitempty"`
	TargetPort             int            `yaml:"target_port,omitempty" json:"target_port,omitempty"`
	ProtocolConfig         map[string]any `yaml:"protocol_config,omitempty" json:"protocol_config,omitempty"`
}

type OutboundConfig struct {
	OriginalName       string         `yaml:"-" json:"original_name,omitempty"`
	Name               string         `yaml:"name" json:"name"`
	Protocol           string         `yaml:"protocol" json:"protocol"`
	Address            string         `yaml:"address" json:"address"`
	Port               int            `yaml:"port" json:"port"`
	Disabled           bool           `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	Username           string         `yaml:"username,omitempty" json:"username,omitempty"`
	UUID               string         `yaml:"uuid,omitempty" json:"uuid,omitempty"`
	Password           string         `yaml:"password,omitempty" json:"password,omitempty"`
	Method             string         `yaml:"method,omitempty" json:"method,omitempty"`
	Flow               string         `yaml:"flow,omitempty" json:"flow,omitempty"`
	Security           string         `yaml:"security,omitempty" json:"security,omitempty"`
	AlterID            int            `yaml:"alter_id,omitempty" json:"alter_id,omitempty"`
	Network            string         `yaml:"network,omitempty" json:"network,omitempty"`
	TLS                bool           `yaml:"tls,omitempty" json:"tls,omitempty"`
	ServerName         string         `yaml:"server_name,omitempty" json:"server_name,omitempty"`
	SkipCertVerify     bool           `yaml:"skip_cert_verify,omitempty" json:"skip_cert_verify,omitempty"`
	Transport          string         `yaml:"transport,omitempty" json:"transport,omitempty"`
	Path               string         `yaml:"path,omitempty" json:"path,omitempty"`
	Host               string         `yaml:"host,omitempty" json:"host,omitempty"`
	PublicKey          string         `yaml:"public_key,omitempty" json:"public_key,omitempty"`
	ShortID            string         `yaml:"short_id,omitempty" json:"short_id,omitempty"`
	Fingerprint        string         `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	ALPN               string         `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	Obfs               string         `yaml:"obfs,omitempty" json:"obfs,omitempty"`
	ObfsPassword       string         `yaml:"obfs_password,omitempty" json:"obfs_password,omitempty"`
	MPort              string         `yaml:"mport,omitempty" json:"mport,omitempty"`
	UpMbps             int            `yaml:"up_mbps,omitempty" json:"up_mbps,omitempty"`
	DownMbps           int            `yaml:"down_mbps,omitempty" json:"down_mbps,omitempty"`
	Congestion         string         `yaml:"congestion,omitempty" json:"congestion,omitempty"`
	UDPRelayMode       string         `yaml:"udp_relay_mode,omitempty" json:"udp_relay_mode,omitempty"`
	Subscription       string         `yaml:"subscription,omitempty" json:"subscription,omitempty"`
	Group              string         `yaml:"group,omitempty" json:"group,omitempty"`
	IdleSessionCheck   string         `yaml:"idle_session_check,omitempty" json:"idle_session_check,omitempty"`
	IdleSessionTimeout string         `yaml:"idle_session_timeout,omitempty" json:"idle_session_timeout,omitempty"`
	MinIdleSession     int            `yaml:"min_idle_session,omitempty" json:"min_idle_session,omitempty"`
	Raw                string         `yaml:"raw,omitempty" json:"raw,omitempty"`
	RawConfig          map[string]any `yaml:"raw_config,omitempty" json:"raw_config,omitempty"`
	SelectorOutbounds  []string       `yaml:"selector_outbounds,omitempty" json:"selector_outbounds,omitempty"`
	Default            string         `yaml:"default,omitempty" json:"default,omitempty"`
	URL                string         `yaml:"url,omitempty" json:"url,omitempty"`
	Interval           string         `yaml:"interval,omitempty" json:"interval,omitempty"`
	Tolerance          int            `yaml:"tolerance,omitempty" json:"tolerance,omitempty"`
}

type RoutingRule struct {
	Name      string `yaml:"name,omitempty" json:"name,omitempty"`
	MatchType string `yaml:"match_type,omitempty" json:"match_type,omitempty"`
	Value     string `yaml:"value,omitempty" json:"value,omitempty"`
	Inbound   string `yaml:"inbound,omitempty" json:"inbound,omitempty"`
	Outbound  string `yaml:"outbound" json:"outbound"`
	Priority  int    `yaml:"priority,omitempty" json:"priority,omitempty"`
	Disabled  bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

type RoutingConfig struct {
	Mode            string          `yaml:"mode,omitempty" json:"mode,omitempty"`
	Preset          string          `yaml:"preset,omitempty" json:"preset,omitempty"`
	DefaultOutbound string          `yaml:"default_outbound,omitempty" json:"default_outbound,omitempty"`
	Rules           []RoutingRule   `yaml:"rules" json:"rules"`
	RuleSets        []RuleSetConfig `yaml:"rule_sets,omitempty" json:"rule_sets,omitempty"`
}

type MihomoConfig struct {
	ProxyGroups []ProxyGroupConfig    `yaml:"proxy_groups,omitempty" json:"proxy_groups,omitempty"`
	Rules       []string              `yaml:"rules,omitempty" json:"rules,omitempty"`
	Providers   []ProxyProviderConfig `yaml:"providers,omitempty" json:"providers,omitempty"`
}

type ProxyGroupConfig struct {
	Name          string   `yaml:"name" json:"name"`
	Type          string   `yaml:"type" json:"type"`
	Proxies       []string `yaml:"proxies,omitempty" json:"proxies,omitempty"`
	Use           []string `yaml:"use,omitempty" json:"use,omitempty"`
	URL           string   `yaml:"url,omitempty" json:"url,omitempty"`
	Interval      int      `yaml:"interval,omitempty" json:"interval,omitempty"`
	Tolerance     int      `yaml:"tolerance,omitempty" json:"tolerance,omitempty"`
	Lazy          bool     `yaml:"lazy,omitempty" json:"lazy,omitempty"`
	Filter        string   `yaml:"filter,omitempty" json:"filter,omitempty"`
	ExcludeFilter string   `yaml:"exclude_filter,omitempty" json:"exclude_filter,omitempty"`
}

type ProxyProviderConfig struct {
	Name                string   `yaml:"name" json:"name"`
	Type                string   `yaml:"type" json:"type"`
	URL                 string   `yaml:"url" json:"url"`
	Path                string   `yaml:"path,omitempty" json:"path,omitempty"`
	Interval            int      `yaml:"interval,omitempty" json:"interval,omitempty"`
	Group               string   `yaml:"group,omitempty" json:"group,omitempty"`
	RenamePrefix        string   `yaml:"rename_prefix,omitempty" json:"rename_prefix,omitempty"`
	RenameSuffix        string   `yaml:"rename_suffix,omitempty" json:"rename_suffix,omitempty"`
	DedupStrategy       string   `yaml:"dedup_strategy,omitempty" json:"dedup_strategy,omitempty"`
	PreserveUserFields  bool     `yaml:"preserve_user_fields,omitempty" json:"preserve_user_fields,omitempty"`
	PreserveFields      []string `yaml:"preserve_fields,omitempty" json:"preserve_fields,omitempty"`
	HealthCheckURL      string   `yaml:"health_check_url,omitempty" json:"health_check_url,omitempty"`
	HealthCheckLazy     bool     `yaml:"health_check_lazy,omitempty" json:"health_check_lazy,omitempty"`
	HealthCheckInterval int      `yaml:"health_check_interval,omitempty" json:"health_check_interval,omitempty"`
	Filter              string   `yaml:"filter,omitempty" json:"filter,omitempty"`
	ExcludeFilter       string   `yaml:"exclude_filter,omitempty" json:"exclude_filter,omitempty"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	if cfg.Server.WebPort == 0 {
		cfg.Server.WebPort = 8080
	}
	if cfg.Kernel.Type == "" {
		cfg.Kernel.Type = "placeholder"
	}
	if cfg.Kernel.ConfigPath == "" {
		cfg.Kernel.ConfigPath = "kernel.generated.json"
	}
	cfg.Kernel = normalizeKernelConfig(cfg.Kernel)
	cfg.Routing = normalizeRoutingConfig(cfg.Routing)
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	cfg = NormalizeV2Config(cfg)
	return cfg, nil
}

func SaveConfig(path string, cfg Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func (c Config) Validate() error {
	if c.Server.WebPort < 1 || c.Server.WebPort > 65535 {
		return fmt.Errorf("invalid web port %d", c.Server.WebPort)
	}
	seenInbound := map[string]struct{}{}
	for _, inbound := range c.Inbounds {
		if inbound.Name == "" {
			return errors.New("inbound name cannot be empty")
		}
		if _, ok := seenInbound[inbound.Name]; ok {
			return fmt.Errorf("duplicate inbound name %q", inbound.Name)
		}
		if inbound.Protocol == "" {
			return fmt.Errorf("inbound %q protocol cannot be empty", inbound.Name)
		}
		if !isSupportedInboundProtocol(inbound.Protocol) && len(inbound.ProtocolConfig) == 0 {
			return fmt.Errorf("inbound %q uses unsupported protocol %q", inbound.Name, inbound.Protocol)
		}
		if len(inbound.ProtocolConfig) == 0 && (inbound.Port < 1 || inbound.Port > 65535) {
			return fmt.Errorf("inbound %q has invalid port %d", inbound.Name, inbound.Port)
		}
		if err := inbound.Validate(); err != nil {
			return err
		}
		seenInbound[inbound.Name] = struct{}{}
	}
	for _, entry := range c.Entries {
		if entry.ID != "" {
			seenInbound[entry.ID] = struct{}{}
		}
		if entry.Name != "" {
			seenInbound[entry.Name] = struct{}{}
		}
	}

	seenOutbound := map[string]struct{}{}
	for _, outbound := range c.Outbounds {
		if outbound.Name == "" {
			return errors.New("outbound name cannot be empty")
		}
		if _, ok := seenOutbound[outbound.Name]; ok {
			return fmt.Errorf("duplicate outbound name %q", outbound.Name)
		}
		if outbound.Protocol == "" {
			return fmt.Errorf("outbound %q protocol cannot be empty", outbound.Name)
		}
		if !isSupportedOutboundProtocol(outbound.Protocol) && len(outbound.RawConfig) == 0 {
			return fmt.Errorf("outbound %q uses unsupported protocol %q", outbound.Name, outbound.Protocol)
		}
		if len(outbound.RawConfig) == 0 && requiresOutboundEndpoint(outbound.Protocol) && (outbound.Port < 1 || outbound.Port > 65535) {
			return fmt.Errorf("outbound %q has invalid port %d", outbound.Name, outbound.Port)
		}
		if err := outbound.Validate(); err != nil {
			return err
		}
		seenOutbound[outbound.Name] = struct{}{}
	}

	mode := routingMode(c.Routing.Mode)
	if mode == "" {
		return fmt.Errorf("routing mode %q is not supported", c.Routing.Mode)
	}
	knownDefaultOutbounds := map[string]struct{}{}
	for name := range seenOutbound {
		knownDefaultOutbounds[name] = struct{}{}
	}
	for _, tag := range v2OutboundTags(c) {
		knownDefaultOutbounds[tag] = struct{}{}
	}
	if c.Routing.DefaultOutbound != "" && c.Routing.DefaultOutbound != "direct" && c.Routing.DefaultOutbound != "block" {
		if _, ok := knownDefaultOutbounds[c.Routing.DefaultOutbound]; !ok {
			return fmt.Errorf("routing default_outbound references missing outbound %q", c.Routing.DefaultOutbound)
		}
	}
	if mode == "rule" {
		knownOutbounds := map[string]struct{}{}
		for name := range seenOutbound {
			knownOutbounds[name] = struct{}{}
		}
		for _, tag := range v2OutboundTags(c) {
			knownOutbounds[tag] = struct{}{}
		}
		seenRuleNames := map[string]struct{}{}
		for _, rule := range c.Routing.Rules {
			if rule.Name != "" {
				if _, ok := seenRuleNames[rule.Name]; ok {
					return fmt.Errorf("duplicate routing rule name %q", rule.Name)
				}
				seenRuleNames[rule.Name] = struct{}{}
			}
			if rule.Disabled {
				continue
			}
			matchType := routingRuleMatchType(rule)
			if !isSupportedRoutingMatchType(matchType) {
				return fmt.Errorf("routing rule %q uses unsupported match type %q", rule.Name, matchType)
			}
			if matchType == "inbound" {
				if _, ok := seenInbound[routingRuleValue(rule)]; !ok {
					return fmt.Errorf("routing rule references missing inbound %q", routingRuleValue(rule))
				}
			} else if routingRuleValue(rule) == "" {
				return fmt.Errorf("routing rule %q requires match value", rule.Name)
			}
			if rule.Outbound == "" {
				return fmt.Errorf("routing rule %q requires outbound", rule.Name)
			}
			if rule.Outbound != "direct" && rule.Outbound != "block" {
				if _, ok := knownOutbounds[rule.Outbound]; !ok {
					return fmt.Errorf("routing rule references missing outbound %q", rule.Outbound)
				}
			}
		}
	}
	return nil
}

func (i InboundConfig) Validate() error {
	if len(i.ProtocolConfig) > 0 {
		return nil
	}
	if !isSupportedInboundProtocol(i.Protocol) {
		return fmt.Errorf("inbound %q uses unsupported protocol %q", i.Name, i.Protocol)
	}
	switch i.Protocol {
	case "vless", "vmess":
		if i.UUID == "" {
			return fmt.Errorf("inbound %q requires uuid for %s", i.Name, i.Protocol)
		}
		if i.Protocol == "vless" && i.Security == "reality" {
			if i.PrivateKey == "" {
				return fmt.Errorf("inbound %q requires private_key for vless reality", i.Name)
			}
			if i.ServerName == "" {
				return fmt.Errorf("inbound %q requires server_name for vless reality", i.Name)
			}
			if i.RealityHandshakeServer == "" {
				return fmt.Errorf("inbound %q requires reality_handshake_server for vless reality", i.Name)
			}
			if i.RealityHandshakePort < 1 || i.RealityHandshakePort > 65535 {
				return fmt.Errorf("inbound %q requires valid reality_handshake_port for vless reality", i.Name)
			}
		}
	case "trojan", "shadowtls":
		if i.Password == "" {
			return fmt.Errorf("inbound %q requires password for %s", i.Name, i.Protocol)
		}
		if i.Protocol == "shadowtls" && i.RealityHandshakeServer == "" {
			return fmt.Errorf("inbound %q requires reality_handshake_server for shadowtls", i.Name)
		}
	case "anytls":
		if i.Password == "" {
			return fmt.Errorf("inbound %q requires password for anytls", i.Name)
		}
		if i.ServerName == "" {
			return fmt.Errorf("inbound %q requires server_name for anytls", i.Name)
		}
	case "shadowsocks", "ss":
		if i.Password == "" {
			return fmt.Errorf("inbound %q requires password for shadowsocks", i.Name)
		}
		if i.Method == "" {
			return fmt.Errorf("inbound %q requires method for shadowsocks", i.Name)
		}
		if !isSupportedSSMethod(i.Method) {
			return fmt.Errorf("inbound %q uses unsupported shadowsocks method %q", i.Name, i.Method)
		}
	case "forward-tcp", "forward-udp":
		if i.TargetHost == "" {
			return fmt.Errorf("inbound %q requires target_host for forwarding", i.Name)
		}
		if i.TargetPort < 1 || i.TargetPort > 65535 {
			return fmt.Errorf("inbound %q requires valid target_port for forwarding", i.Name)
		}
	}
	return nil
}

func (o OutboundConfig) Validate() error {
	if len(o.RawConfig) > 0 {
		return nil
	}
	if !isSupportedOutboundProtocol(o.Protocol) {
		return fmt.Errorf("outbound %q uses unsupported protocol %q", o.Name, o.Protocol)
	}
	if !requiresOutboundEndpoint(o.Protocol) {
		return nil
	}
	switch o.Protocol {
	case "vless", "vmess":
		if o.UUID == "" {
			return fmt.Errorf("outbound %q requires uuid for %s", o.Name, o.Protocol)
		}
	case "trojan":
		if o.Password == "" {
			return fmt.Errorf("outbound %q requires password for trojan", o.Name)
		}
	case "hysteria2", "anytls":
		if o.Password == "" {
			return fmt.Errorf("outbound %q requires password for %s", o.Name, o.Protocol)
		}
	case "shadowtls":
		if o.Password == "" {
			return fmt.Errorf("outbound %q requires password for shadowtls", o.Name)
		}
	case "tuic":
		if o.UUID == "" || o.Password == "" {
			return fmt.Errorf("outbound %q requires uuid and password for tuic", o.Name)
		}
	case "shadowsocks", "ss":
		if o.Password == "" {
			return fmt.Errorf("outbound %q requires password for shadowsocks", o.Name)
		}
		if o.Method == "" {
			return fmt.Errorf("outbound %q requires method for shadowsocks", o.Name)
		}
		if !isSupportedSSMethod(o.Method) {
			return fmt.Errorf("outbound %q uses unsupported shadowsocks method %q", o.Name, o.Method)
		}
		if o.Transport == "shadowtls" && o.ObfsPassword == "" {
			return fmt.Errorf("outbound %q requires obfs_password for shadowtls transport", o.Name)
		}
	}
	return nil
}

func isSupportedInboundProtocol(protocol string) bool {
	switch protocol {
	case "direct", "mixed", "socks", "socks5", "http", "shadowsocks", "ss", "vmess", "trojan", "naive", "hysteria", "shadowtls", "vless", "tuic", "hysteria2", "anytls", "tun", "redirect", "tproxy", "cloudflared", "forward-tcp", "forward-udp":
		return true
	default:
		return false
	}
}

func isSupportedOutboundProtocol(protocol string) bool {
	switch protocol {
	case "direct", "block", "selector", "urltest", "dns", "socks", "socks5", "http", "vless", "vmess", "trojan", "shadowsocks", "ss", "hysteria", "hysteria2", "tuic", "anytls", "naive", "shadowtls", "wireguard", "tor", "ssh", "tcp", "udp":
		return true
	default:
		return false
	}
}

func requiresOutboundEndpoint(protocol string) bool {
	switch protocol {
	case "direct", "block", "selector", "urltest", "dns":
		return false
	default:
		return true
	}
}

func routingMode(mode string) string {
	switch mode {
	case "", "rule":
		return "rule"
	case "global", "direct":
		return mode
	default:
		return ""
	}
}

func routingRuleMatchType(rule RoutingRule) string {
	if rule.MatchType != "" {
		return rule.MatchType
	}
	if rule.Inbound != "" {
		return "inbound"
	}
	return "domain_suffix"
}

func routingRuleValue(rule RoutingRule) string {
	if rule.Value != "" {
		return rule.Value
	}
	if routingRuleMatchType(rule) == "inbound" {
		return rule.Inbound
	}
	return ""
}

func isSupportedRoutingMatchType(matchType string) bool {
	switch matchType {
	case "inbound", "domain", "domain_suffix", "domain_keyword", "domain_regex", "rule_set", "ip_cidr", "geoip", "geosite", "protocol", "port", "network":
		return true
	default:
		return false
	}
}

func v2OutboundTags(c Config) []string {
	if !HasV2Config(c) {
		return nil
	}
	model := V2ModelFromConfig(c)
	var tags []string
	tags = append(tags, "direct", "block", "policy-auto", "policy-manual")
	for _, node := range model.Nodes {
		tags = append(tags, node.ID)
	}
	for _, group := range model.RegionGroups {
		tags = append(tags, group.ID, group.ID+"-auto")
	}
	for _, policy := range model.AppPolicyGroups {
		tags = append(tags, policy.ID)
	}
	return uniqueStrings(tags)
}

func normalizeRoutingConfig(routing RoutingConfig) RoutingConfig {
	if routing.Mode == "" {
		routing.Mode = "rule"
	}
	if routing.Preset == "bypass_cn" {
		rules := routing.Rules[:0]
		for _, rule := range routing.Rules {
			if isLegacyBypassOverseasDirectRule(rule) {
				continue
			}
			rules = append(rules, rule)
		}
		routing.Rules = rules
	}
	return routing
}

func isLegacyBypassOverseasDirectRule(rule RoutingRule) bool {
	if rule.Outbound != "direct" || routingRuleMatchType(rule) != "domain_suffix" {
		return false
	}
	value := strings.ToLower(routingRuleValue(rule))
	return strings.Contains(value, "google.com") &&
		strings.Contains(value, "youtube.com") &&
		strings.Contains(value, "github.com")
}

func isSupportedSSMethod(method string) bool {
	switch method {
	case "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305":
		return true
	default:
		return false
	}
}

func WatchConfig(ctx context.Context, path string, interval time.Duration, apply func(Config)) {
	info, err := os.Stat(path)
	if err != nil {
		log.Printf("watch config disabled: %v", err)
		return
	}
	lastMod := info.ModTime()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := os.Stat(path)
			if err != nil {
				log.Printf("watch config stat failed: %v", err)
				continue
			}
			if !info.ModTime().After(lastMod) {
				continue
			}
			lastMod = info.ModTime()

			cfg, err := LoadConfig(path)
			if err != nil {
				log.Printf("watch config load failed: %v", err)
				continue
			}
			apply(cfg)
		}
	}
}
