package core

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		WebPort   int    `yaml:"web_port" json:"web_port"`
		AdminUser string `yaml:"admin_user" json:"admin_user"`
		AdminPass string `yaml:"admin_pass" json:"-"`
	} `yaml:"server" json:"server"`
	Kernel    KernelConfig     `yaml:"kernel" json:"kernel"`
	Inbounds  []InboundConfig  `yaml:"inbounds" json:"inbounds"`
	Outbounds []OutboundConfig `yaml:"outbounds" json:"outbounds"`
	Routing   RoutingConfig    `yaml:"routing" json:"routing"`
	Mihomo    MihomoConfig     `yaml:"mihomo" json:"mihomo"`
}

type InboundConfig struct {
	Name                   string `yaml:"name" json:"name"`
	Protocol               string `yaml:"protocol" json:"protocol"`
	Listen                 string `yaml:"listen,omitempty" json:"listen,omitempty"`
	Port                   int    `yaml:"port" json:"port"`
	Outbound               string `yaml:"-" json:"outbound,omitempty"`
	Disabled               bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	Username               string `yaml:"username,omitempty" json:"username,omitempty"`
	UUID                   string `yaml:"uuid,omitempty" json:"uuid,omitempty"`
	Password               string `yaml:"password,omitempty" json:"password,omitempty"`
	Method                 string `yaml:"method,omitempty" json:"method,omitempty"`
	Flow                   string `yaml:"flow,omitempty" json:"flow,omitempty"`
	Security               string `yaml:"security,omitempty" json:"security,omitempty"`
	AlterID                int    `yaml:"alter_id,omitempty" json:"alter_id,omitempty"`
	TLS                    bool   `yaml:"tls,omitempty" json:"tls,omitempty"`
	ServerName             string `yaml:"server_name,omitempty" json:"server_name,omitempty"`
	CertificatePath        string `yaml:"certificate_path,omitempty" json:"certificate_path,omitempty"`
	KeyPath                string `yaml:"key_path,omitempty" json:"key_path,omitempty"`
	CertificateContent     string `yaml:"-" json:"certificate_content,omitempty"`
	KeyContent             string `yaml:"-" json:"key_content,omitempty"`
	Transport              string `yaml:"transport,omitempty" json:"transport,omitempty"`
	Path                   string `yaml:"path,omitempty" json:"path,omitempty"`
	Host                   string `yaml:"host,omitempty" json:"host,omitempty"`
	PrivateKey             string `yaml:"private_key,omitempty" json:"private_key,omitempty"`
	ShortID                string `yaml:"short_id,omitempty" json:"short_id,omitempty"`
	RealityHandshakeServer string `yaml:"reality_handshake_server,omitempty" json:"reality_handshake_server,omitempty"`
	RealityHandshakePort   int    `yaml:"reality_handshake_port,omitempty" json:"reality_handshake_port,omitempty"`
	IdleSessionCheck       string `yaml:"idle_session_check,omitempty" json:"idle_session_check,omitempty"`
	IdleSessionTimeout     string `yaml:"idle_session_timeout,omitempty" json:"idle_session_timeout,omitempty"`
	MinIdleSession         int    `yaml:"min_idle_session,omitempty" json:"min_idle_session,omitempty"`
	TargetHost             string `yaml:"target_host,omitempty" json:"target_host,omitempty"`
	TargetPort             int    `yaml:"target_port,omitempty" json:"target_port,omitempty"`
}

type OutboundConfig struct {
	OriginalName   string `yaml:"-" json:"original_name,omitempty"`
	Name           string `yaml:"name" json:"name"`
	Protocol       string `yaml:"protocol" json:"protocol"`
	Address        string `yaml:"address" json:"address"`
	Port           int    `yaml:"port" json:"port"`
	Disabled       bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
	Username       string `yaml:"username,omitempty" json:"username,omitempty"`
	UUID           string `yaml:"uuid,omitempty" json:"uuid,omitempty"`
	Password       string `yaml:"password,omitempty" json:"password,omitempty"`
	Method         string `yaml:"method,omitempty" json:"method,omitempty"`
	Flow           string `yaml:"flow,omitempty" json:"flow,omitempty"`
	Security       string `yaml:"security,omitempty" json:"security,omitempty"`
	AlterID        int    `yaml:"alter_id,omitempty" json:"alter_id,omitempty"`
	Network        string `yaml:"network,omitempty" json:"network,omitempty"`
	TLS            bool   `yaml:"tls,omitempty" json:"tls,omitempty"`
	ServerName     string `yaml:"server_name,omitempty" json:"server_name,omitempty"`
	SkipCertVerify bool   `yaml:"skip_cert_verify,omitempty" json:"skip_cert_verify,omitempty"`
	Transport      string `yaml:"transport,omitempty" json:"transport,omitempty"`
	Path           string `yaml:"path,omitempty" json:"path,omitempty"`
	Host           string `yaml:"host,omitempty" json:"host,omitempty"`
	PublicKey      string `yaml:"public_key,omitempty" json:"public_key,omitempty"`
	ShortID        string `yaml:"short_id,omitempty" json:"short_id,omitempty"`
	Fingerprint    string `yaml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	ALPN           string `yaml:"alpn,omitempty" json:"alpn,omitempty"`
	Obfs           string `yaml:"obfs,omitempty" json:"obfs,omitempty"`
	ObfsPassword   string `yaml:"obfs_password,omitempty" json:"obfs_password,omitempty"`
	MPort          string `yaml:"mport,omitempty" json:"mport,omitempty"`
	UpMbps         int    `yaml:"up_mbps,omitempty" json:"up_mbps,omitempty"`
	DownMbps       int    `yaml:"down_mbps,omitempty" json:"down_mbps,omitempty"`
	Congestion     string `yaml:"congestion,omitempty" json:"congestion,omitempty"`
	UDPRelayMode   string `yaml:"udp_relay_mode,omitempty" json:"udp_relay_mode,omitempty"`
	Raw            string `yaml:"raw,omitempty" json:"raw,omitempty"`
}

type RoutingRule struct {
	Name     string `yaml:"name,omitempty" json:"name,omitempty"`
	Inbound  string `yaml:"inbound" json:"inbound"`
	Outbound string `yaml:"outbound" json:"outbound"`
	Priority int    `yaml:"priority,omitempty" json:"priority,omitempty"`
	Disabled bool   `yaml:"disabled,omitempty" json:"disabled,omitempty"`
}

type RoutingConfig struct {
	DefaultOutbound string        `yaml:"default_outbound,omitempty" json:"default_outbound,omitempty"`
	Rules           []RoutingRule `yaml:"rules" json:"rules"`
}

type MihomoConfig struct {
	ProxyGroups []ProxyGroupConfig    `yaml:"proxy_groups,omitempty" json:"proxy_groups,omitempty"`
	Rules       []string              `yaml:"rules,omitempty" json:"rules,omitempty"`
	Providers   []ProxyProviderConfig `yaml:"providers,omitempty" json:"providers,omitempty"`
}

type ProxyGroupConfig struct {
	Name      string   `yaml:"name" json:"name"`
	Type      string   `yaml:"type" json:"type"`
	Proxies   []string `yaml:"proxies,omitempty" json:"proxies,omitempty"`
	Use       []string `yaml:"use,omitempty" json:"use,omitempty"`
	URL       string   `yaml:"url,omitempty" json:"url,omitempty"`
	Interval  int      `yaml:"interval,omitempty" json:"interval,omitempty"`
	Tolerance int      `yaml:"tolerance,omitempty" json:"tolerance,omitempty"`
}

type ProxyProviderConfig struct {
	Name            string `yaml:"name" json:"name"`
	Type            string `yaml:"type" json:"type"`
	URL             string `yaml:"url" json:"url"`
	Path            string `yaml:"path,omitempty" json:"path,omitempty"`
	Interval        int    `yaml:"interval,omitempty" json:"interval,omitempty"`
	HealthCheckURL  string `yaml:"health_check_url,omitempty" json:"health_check_url,omitempty"`
	HealthCheckLazy bool   `yaml:"health_check_lazy,omitempty" json:"health_check_lazy,omitempty"`
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
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
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
		if inbound.Protocol == "" {
			return fmt.Errorf("inbound %q protocol cannot be empty", inbound.Name)
		}
		if !isSupportedInboundProtocol(inbound.Protocol) {
			return fmt.Errorf("inbound %q uses unsupported protocol %q", inbound.Name, inbound.Protocol)
		}
		if inbound.Port < 1 || inbound.Port > 65535 {
			return fmt.Errorf("inbound %q has invalid port %d", inbound.Name, inbound.Port)
		}
		if err := inbound.Validate(); err != nil {
			return err
		}
		seenInbound[inbound.Name] = struct{}{}
	}

	seenOutbound := map[string]struct{}{}
	for _, outbound := range c.Outbounds {
		if outbound.Name == "" {
			return errors.New("outbound name cannot be empty")
		}
		if outbound.Protocol == "" {
			return fmt.Errorf("outbound %q protocol cannot be empty", outbound.Name)
		}
		if !isSupportedOutboundProtocol(outbound.Protocol) {
			return fmt.Errorf("outbound %q uses unsupported protocol %q", outbound.Name, outbound.Protocol)
		}
		if outbound.Port < 1 || outbound.Port > 65535 {
			return fmt.Errorf("outbound %q has invalid port %d", outbound.Name, outbound.Port)
		}
		if err := outbound.Validate(); err != nil {
			return err
		}
		seenOutbound[outbound.Name] = struct{}{}
	}

	if c.Routing.DefaultOutbound != "" {
		if c.Routing.DefaultOutbound != "direct" {
			if _, ok := seenOutbound[c.Routing.DefaultOutbound]; !ok {
				return fmt.Errorf("routing default_outbound references missing outbound %q", c.Routing.DefaultOutbound)
			}
		}
	}
	for _, rule := range c.Routing.Rules {
		if rule.Disabled {
			continue
		}
		if _, ok := seenInbound[rule.Inbound]; !ok {
			return fmt.Errorf("routing rule references missing inbound %q", rule.Inbound)
		}
		if rule.Outbound != "direct" {
			if _, ok := seenOutbound[rule.Outbound]; !ok {
				return fmt.Errorf("routing rule references missing outbound %q", rule.Outbound)
			}
		}
	}
	return nil
}

func (i InboundConfig) Validate() error {
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
	if !isSupportedOutboundProtocol(o.Protocol) {
		return fmt.Errorf("outbound %q uses unsupported protocol %q", o.Name, o.Protocol)
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
	case "mixed", "socks", "socks5", "http", "vless", "anytls", "vmess", "trojan", "shadowtls", "shadowsocks", "ss", "forward-tcp", "forward-udp":
		return true
	default:
		return false
	}
}

func isSupportedOutboundProtocol(protocol string) bool {
	switch protocol {
	case "direct", "socks", "socks5", "http", "vless", "vmess", "trojan", "shadowsocks", "ss", "hysteria2", "tuic", "anytls", "naive", "shadowtls", "tcp", "udp":
		return true
	default:
		return false
	}
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
