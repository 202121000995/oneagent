package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RuntimeState struct {
	Inbounds  []InboundConfig  `json:"inbounds"`
	Outbounds []OutboundConfig `json:"outbounds"`
	Routing   RoutingConfig    `json:"routing"`
}

type Kernel interface {
	Name() string
	Configure(KernelConfig)
	GenerateConfig(RuntimeState) ([]byte, error)
	ValidateConfig(string) error
	Start(string) error
	Reload(string) error
	Stop() error
	Status() KernelStatus
}

type KernelConfig struct {
	Type       string `yaml:"type" json:"type"`
	Executable string `yaml:"executable" json:"executable"`
	ConfigPath string `yaml:"config_path" json:"config_path"`
}

type KernelStatus struct {
	Name       string `json:"name"`
	Mode       string `json:"mode"`
	Running    bool   `json:"running"`
	PID        int    `json:"pid,omitempty"`
	ConfigPath string `json:"config_path"`
	LastApply  string `json:"last_apply"`
	LastError  string `json:"last_error,omitempty"`
}

func NewKernel(cfg KernelConfig) Kernel {
	switch cfg.Type {
	case "", "placeholder":
		kernel := NewPlaceholderKernel()
		kernel.Configure(cfg)
		return kernel
	case "sing-box":
		kernel := NewSingBoxKernel()
		kernel.Configure(cfg)
		return kernel
	default:
		kernel := NewPlaceholderKernel()
		kernel.Configure(cfg)
		return kernel
	}
}

type baseKernel struct {
	mu       sync.RWMutex
	cfg      KernelConfig
	cmd      *exec.Cmd
	waitDone chan struct{}
	running  bool
	pid      int
	lastTime time.Time
	lastErr  string
	mode     string
	name     string
}

func (b *baseKernel) Configure(cfg KernelConfig) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = "kernel.generated.json"
	}
	b.cfg = cfg
}

func (b *baseKernel) executable() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.cfg.Executable
}

func (b *baseKernel) setApplied(running bool, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.running = running
	if !running {
		b.pid = 0
	}
	b.lastTime = time.Now()
	if err != nil {
		b.lastErr = err.Error()
	} else {
		b.lastErr = ""
	}
}

func (b *baseKernel) status() KernelStatus {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return KernelStatus{
		Name:       b.name,
		Mode:       b.mode,
		Running:    b.running,
		PID:        b.pid,
		ConfigPath: b.cfg.ConfigPath,
		LastApply:  b.lastTime.Format(time.RFC3339),
		LastError:  b.lastErr,
	}
}

func (b *baseKernel) startProcess(args ...string) error {
	executable := b.executable()
	if executable == "" {
		err := fmt.Errorf("%s executable is required", b.name)
		b.setApplied(false, err)
		return err
	}
	if err := b.stopProcess(); err != nil {
		return err
	}

	cmd := exec.Command(executable, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		b.setApplied(false, err)
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		b.setApplied(false, err)
		return err
	}
	if err := cmd.Start(); err != nil {
		b.setApplied(false, err)
		return err
	}

	b.mu.Lock()
	b.cmd = cmd
	b.waitDone = make(chan struct{})
	b.running = true
	b.pid = cmd.Process.Pid
	b.lastTime = time.Now()
	b.lastErr = ""
	b.mu.Unlock()

	go pipeKernelLog(b.name, stdout)
	go pipeKernelLog(b.name, stderr)
	go func() {
		err := cmd.Wait()
		b.mu.Lock()
		defer b.mu.Unlock()
		if b.waitDone != nil {
			close(b.waitDone)
			b.waitDone = nil
		}
		if b.cmd == cmd {
			b.cmd = nil
			b.running = false
			b.pid = 0
			if err != nil {
				b.lastErr = err.Error()
				log.Printf("%s exited: %v", b.name, err)
			}
		}
	}()
	return nil
}

func (b *baseKernel) stopProcess() error {
	b.mu.RLock()
	cmd := b.cmd
	waitDone := b.waitDone
	b.mu.RUnlock()
	if cmd == nil || cmd.Process == nil {
		b.setApplied(false, nil)
		return nil
	}

	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		log.Printf("%s interrupt failed: %v", b.name, err)
	}
	select {
	case <-waitDone:
	case <-time.After(3 * time.Second):
		if err := cmd.Process.Kill(); err != nil {
			b.setApplied(false, err)
			return err
		}
		if waitDone != nil {
			<-waitDone
		}
	}
	b.mu.Lock()
	if b.cmd == cmd {
		b.cmd = nil
	}
	b.waitDone = nil
	b.running = false
	b.pid = 0
	b.lastTime = time.Now()
	b.lastErr = ""
	b.mu.Unlock()
	return nil
}

func pipeKernelLog(name string, reader io.Reader) {
	buf := make([]byte, 4096)
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			log.Printf("%s: %s", name, string(bytes.TrimSpace(buf[:n])))
		}
		if err != nil {
			return
		}
	}
}

type PlaceholderKernel struct {
	baseKernel
}

func NewPlaceholderKernel() *PlaceholderKernel {
	return &PlaceholderKernel{baseKernel: baseKernel{name: "placeholder", mode: "dry-run"}}
}

func (k *PlaceholderKernel) Name() string {
	return k.name
}

func (k *PlaceholderKernel) GenerateConfig(state RuntimeState) ([]byte, error) {
	payload := map[string]any{
		"kernel":    k.Name(),
		"log":       map[string]string{"level": "info"},
		"inbounds":  state.Inbounds,
		"outbounds": state.Outbounds,
		"route":     state.Routing,
	}
	return json.MarshalIndent(payload, "", "  ")
}

func (k *PlaceholderKernel) ValidateConfig(path string) error {
	return nil
}

func (k *PlaceholderKernel) Start(path string) error {
	k.setApplied(true, nil)
	log.Printf("placeholder kernel started with %s", path)
	return nil
}

func (k *PlaceholderKernel) Reload(path string) error {
	k.setApplied(true, nil)
	log.Printf("placeholder kernel reloaded with %s", path)
	return nil
}

func (k *PlaceholderKernel) Stop() error {
	k.setApplied(false, nil)
	return nil
}

func (k *PlaceholderKernel) Status() KernelStatus {
	return k.status()
}

type SingBoxKernel struct {
	baseKernel
}

func NewSingBoxKernel() *SingBoxKernel {
	return &SingBoxKernel{baseKernel: baseKernel{name: "sing-box", mode: "external"}}
}

func (k *SingBoxKernel) Name() string {
	return "sing-box"
}

func (k *SingBoxKernel) GenerateConfig(state RuntimeState) ([]byte, error) {
	final := routeFinal(state.Routing)
	rules := append(singBoxSniffRules(state.Inbounds), singBoxRules(state.Routing)...)
	route := map[string]any{"rules": rules, "final": final}
	if ruleSets := singBoxRuleSets(state.Routing.RuleSets); len(ruleSets) > 0 {
		route["rule_set"] = ruleSets
	}
	payload := map[string]any{
		"log":       map[string]any{"level": "debug", "timestamp": true, "output": "logs/sing-box.log"},
		"inbounds":  singBoxInbounds(state.Inbounds),
		"outbounds": singBoxOutbounds(state.Outbounds),
		"route":     route,
		"experimental": map[string]any{
			"clash_api": map[string]any{"external_controller": singBoxClashAPIAddress},
		},
	}
	return json.MarshalIndent(payload, "", "  ")
}

func (k *SingBoxKernel) ValidateConfig(path string) error {
	executable := k.executable()
	if executable == "" {
		return fmt.Errorf("sing-box executable is required")
	}
	output, err := exec.Command(executable, "check", "-c", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

func (k *SingBoxKernel) Start(path string) error {
	if err := k.ValidateConfig(path); err != nil {
		k.setApplied(false, err)
		return err
	}
	if err := k.startProcess("run", "-c", path); err != nil {
		return err
	}
	log.Printf("sing-box started with %s", path)
	return nil
}

func (k *SingBoxKernel) Reload(path string) error {
	return k.Start(path)
}

func (k *SingBoxKernel) Stop() error {
	return k.stopProcess()
}

func (k *SingBoxKernel) Status() KernelStatus {
	return k.status()
}

func singBoxInbounds(inbounds []InboundConfig) []map[string]any {
	items := make([]map[string]any, 0, len(inbounds))
	for _, inbound := range inbounds {
		if len(inbound.ProtocolConfig) > 0 {
			item := copyMap(inbound.ProtocolConfig)
			finalizeSingBoxInbound(item, inbound)
			items = append(items, item)
			continue
		}
		base := map[string]any{"tag": inbound.Name, "listen": firstNonEmpty(inbound.Listen, "::")}
		if inbound.Port > 0 {
			base["listen_port"] = inbound.Port
		}
		switch inbound.Protocol {
		case "mixed":
			base["type"] = "mixed"
			addSingBoxInboundAuth(base, inbound)
		case "socks", "socks5":
			base["type"] = "socks"
			addSingBoxInboundAuth(base, inbound)
		case "http":
			base["type"] = "http"
			addSingBoxInboundAuth(base, inbound)
		case "vless":
			base["type"] = "vless"
			user := map[string]any{"uuid": inbound.UUID}
			addOptional(user, "flow", inbound.Flow)
			base["users"] = []map[string]any{user}
			addSingBoxInboundTLS(base, inbound)
			addSingBoxInboundTransport(base, inbound)
		case "vmess":
			base["type"] = "vmess"
			base["users"] = []map[string]any{{"uuid": inbound.UUID, "alter_id": inbound.AlterID}}
			addSingBoxInboundTLS(base, inbound)
			addSingBoxInboundTransport(base, inbound)
		case "trojan":
			base["type"] = "trojan"
			base["users"] = []map[string]any{{"password": inbound.Password}}
			addSingBoxInboundTLS(base, inbound)
			addSingBoxInboundTransport(base, inbound)
		case "shadowtls":
			base["type"] = "shadowtls"
			base["version"] = 3
			innerTag := inbound.Name + "-shadowsocks"
			base["users"] = []map[string]any{{
				"name":     firstNonEmpty(inbound.Username, inbound.Name),
				"password": inbound.Password,
			}}
			base["handshake"] = map[string]any{
				"server":      firstNonEmpty(inbound.RealityHandshakeServer, inbound.ServerName),
				"server_port": firstNonZero(inbound.RealityHandshakePort, 443),
			}
			base["detour"] = innerTag
			items = append(items, base)
			items = append(items, map[string]any{
				"type":     "shadowsocks",
				"tag":      innerTag,
				"method":   firstNonEmpty(inbound.Method, "aes-128-gcm"),
				"password": inbound.Password,
				"network":  "tcp",
			})
			continue
		case "anytls":
			base["type"] = "anytls"
			base["users"] = []map[string]any{{"password": inbound.Password}}
			addSingBoxInboundTLS(base, inbound)
		case "shadowsocks", "ss":
			base["type"] = "shadowsocks"
			base["method"] = inbound.Method
			base["password"] = inbound.Password
		case "forward-tcp", "forward-udp":
			base["type"] = "direct"
			base["network"] = strings.TrimPrefix(inbound.Protocol, "forward-")
			base["override_address"] = inbound.TargetHost
			base["override_port"] = inbound.TargetPort
		default:
			base["type"] = firstNonEmpty(inbound.Protocol, "mixed")
		}
		finalizeSingBoxInbound(base, inbound)
		items = append(items, base)
	}
	return items
}

func finalizeSingBoxInbound(item map[string]any, inbound InboundConfig) {
	item["tag"] = inbound.Name
	if stringValue(item["type"]) == "" {
		item["type"] = firstNonEmpty(inbound.Protocol, "mixed")
	}
	if stringValue(item["listen"]) == "" {
		listen := inbound.Listen
		if listen == "" && len(inbound.ProtocolConfig) == 0 {
			listen = "::"
		}
		if listen != "" {
			item["listen"] = listen
		}
	}
	if _, ok := item["listen_port"]; !ok && inbound.Port > 0 {
		item["listen_port"] = inbound.Port
	}
}

func addSingBoxInboundTLS(target map[string]any, inbound InboundConfig) {
	if !inbound.TLS && inbound.Security != "reality" && inbound.ServerName == "" {
		return
	}
	tls := map[string]any{"enabled": inbound.TLS || inbound.Security == "reality" || inbound.ServerName != ""}
	addOptional(tls, "server_name", inbound.ServerName)
	addOptional(tls, "certificate_path", inbound.CertificatePath)
	addOptional(tls, "key_path", inbound.KeyPath)
	if inbound.Security == "reality" {
		reality := map[string]any{
			"enabled": true,
			"handshake": map[string]any{
				"server":      inbound.RealityHandshakeServer,
				"server_port": inbound.RealityHandshakePort,
			},
			"private_key": inbound.PrivateKey,
		}
		if inbound.ShortID != "" {
			reality["short_id"] = splitCSV(inbound.ShortID)
		}
		tls["reality"] = reality
	}
	target["tls"] = tls
}

func addSingBoxInboundAuth(target map[string]any, inbound InboundConfig) {
	if inbound.Username == "" && inbound.Password == "" {
		return
	}
	target["users"] = []map[string]any{{
		"username": inbound.Username,
		"password": inbound.Password,
	}}
}

func addSingBoxInboundTransport(target map[string]any, inbound InboundConfig) {
	if inbound.Transport == "" || inbound.Transport == "tcp" {
		return
	}
	transport := map[string]any{"type": inbound.Transport}
	addOptional(transport, "path", inbound.Path)
	if inbound.Host != "" {
		transport["headers"] = map[string][]string{"Host": {inbound.Host}}
	}
	target["transport"] = transport
}

func singBoxOutbounds(outbounds []OutboundConfig) []map[string]any {
	items := make([]map[string]any, 0, len(outbounds)+1)
	hasDirect := false
	for _, outbound := range outbounds {
		if outbound.Name == "direct" {
			hasDirect = true
		}
		if len(outbound.RawConfig) > 0 {
			item := copyMap(outbound.RawConfig)
			item["tag"] = firstNonEmpty(outbound.Name, stringValue(item["tag"]))
			item["type"] = firstNonEmpty(stringValue(item["type"]), outbound.Protocol)
			ensureSingBoxRealityUTLS(item)
			items = append(items, item)
			continue
		}
		if outbound.Address == "" || outbound.Protocol == "direct" {
			if outbound.Protocol == "block" {
				items = append(items, map[string]any{"type": "block", "tag": outbound.Name})
				continue
			}
			if outbound.Protocol == "selector" {
				candidates := fallbackCandidates(outbound.SelectorOutbounds, []string{"direct"})
				items = append(items, map[string]any{"type": "selector", "tag": outbound.Name, "outbounds": candidates, "default": firstAvailable(outbound.Default, candidates)})
				continue
			}
			if outbound.Protocol == "urltest" {
				candidates := fallbackCandidates(outbound.SelectorOutbounds, []string{"direct"})
				item := map[string]any{
					"type":      "urltest",
					"tag":       outbound.Name,
					"outbounds": candidates,
					"url":       firstNonEmpty(outbound.URL, defaultSmartURL),
					"interval":  firstNonEmpty(outbound.Interval, defaultSmartInterval),
				}
				if outbound.Tolerance > 0 {
					item["tolerance"] = outbound.Tolerance
				}
				items = append(items, item)
				continue
			}
			items = append(items, map[string]any{"type": "direct", "tag": outbound.Name})
			continue
		}
		base := map[string]any{"type": outbound.Protocol, "tag": outbound.Name, "server": outbound.Address, "server_port": outbound.Port}
		switch outbound.Protocol {
		case "socks", "socks5":
			item := map[string]any{"type": "socks", "tag": outbound.Name, "server": outbound.Address, "server_port": outbound.Port, "version": "5"}
			addOptional(item, "username", outbound.Username)
			addOptional(item, "password", outbound.Password)
			items = append(items, item)
		case "http":
			item := map[string]any{"type": "http", "tag": outbound.Name, "server": outbound.Address, "server_port": outbound.Port}
			addOptional(item, "username", outbound.Username)
			addOptional(item, "password", outbound.Password)
			items = append(items, item)
		case "vless":
			base["uuid"] = outbound.UUID
			addOptional(base, "flow", outbound.Flow)
			addOptional(base, "network", outbound.Network)
			addTLS(base, outbound)
			addSingBoxTransport(base, outbound)
			items = append(items, base)
		case "vmess":
			base["uuid"] = outbound.UUID
			if outbound.Security == "" {
				base["security"] = "auto"
			} else {
				base["security"] = outbound.Security
			}
			base["alter_id"] = outbound.AlterID
			addOptional(base, "network", outbound.Network)
			addTLS(base, outbound)
			addSingBoxTransport(base, outbound)
			items = append(items, base)
		case "trojan":
			base["password"] = outbound.Password
			addOptional(base, "network", outbound.Network)
			addTLS(base, outbound)
			addSingBoxTransport(base, outbound)
			items = append(items, base)
		case "shadowsocks", "ss":
			if outbound.Transport == "shadowtls" {
				shadowTag := outbound.Name + "-shadowtls"
				shadow := map[string]any{
					"type":        "shadowtls",
					"tag":         shadowTag,
					"server":      outbound.Address,
					"server_port": outbound.Port,
					"version":     3,
					"password":    outbound.ObfsPassword,
				}
				addTLS(shadow, outbound)
				items = append(items, shadow)
				base["detour"] = shadowTag
			}
			base["type"] = "shadowsocks"
			base["method"] = outbound.Method
			base["password"] = outbound.Password
			addOptional(base, "network", outbound.Network)
			items = append(items, base)
		case "hysteria2":
			base["type"] = "hysteria2"
			base["password"] = outbound.Password
			if outbound.MPort != "" {
				base["server_ports"] = singBoxPortRanges(outbound.MPort)
			}
			if outbound.UpMbps > 0 {
				base["up_mbps"] = outbound.UpMbps
			}
			if outbound.DownMbps > 0 {
				base["down_mbps"] = outbound.DownMbps
			}
			if outbound.Obfs != "" && outbound.Obfs != "none" {
				base["obfs"] = map[string]any{"type": outbound.Obfs, "password": outbound.ObfsPassword}
			}
			addTLS(base, outbound)
			items = append(items, base)
		case "tuic":
			base["type"] = "tuic"
			base["uuid"] = outbound.UUID
			base["password"] = outbound.Password
			addOptional(base, "congestion_control", firstNonEmpty(outbound.Congestion, "bbr"))
			addOptional(base, "udp_relay_mode", firstNonEmpty(outbound.UDPRelayMode, "native"))
			addTLS(base, outbound)
			items = append(items, base)
		case "anytls":
			base["type"] = "anytls"
			base["password"] = outbound.Password
			addAnyTLSIdleFields(base, outbound)
			addTLS(base, outbound)
			items = append(items, base)
		case "naive":
			base["type"] = "naive"
			base["username"] = firstNonEmpty(outbound.Username, outbound.UUID)
			base["password"] = outbound.Password
			addOptional(base, "network", outbound.Transport)
			addTLS(base, outbound)
			items = append(items, base)
		case "shadowtls":
			base["type"] = "shadowtls"
			base["version"] = 3
			base["password"] = outbound.Password
			addTLS(base, outbound)
			items = append(items, base)
		default:
			items = append(items, map[string]any{"type": "direct", "tag": outbound.Name})
		}
	}
	if !hasDirect {
		items = append([]map[string]any{{"type": "direct", "tag": "direct"}}, items...)
	}
	return items
}

func ensureSingBoxRealityUTLS(item map[string]any) {
	tls, ok := item["tls"].(map[string]any)
	if !ok {
		return
	}
	if _, ok := tls["reality"].(map[string]any); !ok {
		return
	}
	utls, ok := tls["utls"].(map[string]any)
	if !ok {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": "chrome"}
		return
	}
	utls["enabled"] = true
	if stringValue(utls["fingerprint"]) == "" {
		utls["fingerprint"] = "chrome"
	}
}

func singBoxRules(routing RoutingConfig) []map[string]any {
	if routingMode(routing.Mode) != "rule" {
		return nil
	}
	rules := sortedRoutingRules(routing.Rules)
	items := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		if rule.Disabled {
			continue
		}
		item := map[string]any{"outbound": rule.Outbound}
		value := routingRuleValue(rule)
		switch routingRuleMatchType(rule) {
		case "inbound":
			item["inbound"] = splitCSV(value)
		case "domain":
			item["domain"] = splitCSV(value)
		case "domain_suffix":
			item["domain_suffix"] = splitCSV(value)
		case "domain_keyword":
			item["domain_keyword"] = splitCSV(value)
		case "domain_regex":
			item["domain_regex"] = splitCSV(value)
		case "rule_set":
			item["rule_set"] = splitCSV(value)
		case "ip_cidr":
			item["ip_cidr"] = splitCSV(value)
		case "geoip":
			continue
		case "geosite":
			continue
		case "protocol":
			item["protocol"] = splitCSV(value)
		case "port":
			item["port"] = splitInts(value)
		case "network":
			item["network"] = splitCSV(value)
		default:
			continue
		}
		items = append(items, item)
	}
	return items
}

func singBoxSniffRules(inbounds []InboundConfig) []map[string]any {
	items := make([]map[string]any, 0)
	for _, inbound := range inbounds {
		if inbound.Disabled || !inbound.Sniff || inbound.Name == "" {
			continue
		}
		items = append(items, map[string]any{
			"inbound": []string{inbound.Name},
			"action":  "sniff",
			"timeout": "1s",
		})
	}
	return items
}

func singBoxRuleSets(ruleSets []RuleSetConfig) []map[string]any {
	items := make([]map[string]any, 0, len(ruleSets))
	for _, ruleSet := range ruleSets {
		if ruleSet.Tag == "" {
			continue
		}
		item := map[string]any{"type": firstNonEmpty(ruleSet.Type, "inline"), "tag": ruleSet.Tag}
		switch item["type"] {
		case "local":
			item["format"] = firstNonEmpty(ruleSet.Format, "source")
			item["path"] = ruleSet.Path
		case "remote":
			item["format"] = firstNonEmpty(ruleSet.Format, "source")
			item["url"] = ruleSet.URL
			addOptional(item, "download_detour", ruleSet.DownloadDetour)
			addOptional(item, "update_interval", ruleSet.UpdateInterval)
		default:
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
			if len(rule) == 0 {
				continue
			}
			item["rules"] = []map[string]any{rule}
		}
		items = append(items, item)
	}
	return items
}

func addOptional(target map[string]any, key string, value string) {
	if value != "" {
		target[key] = value
	}
}

func mergeMap(target map[string]any, values map[string]any) {
	for key, value := range values {
		target[key] = value
	}
}

func addAnyTLSIdleFields(target map[string]any, outbound OutboundConfig) {
	addOptional(target, "idle_session_check_interval", outbound.IdleSessionCheck)
	addOptional(target, "idle_session_timeout", outbound.IdleSessionTimeout)
	if outbound.MinIdleSession > 0 {
		target["min_idle_session"] = outbound.MinIdleSession
	}
}

func firstNonZero(values ...int) int {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func addTLS(target map[string]any, outbound OutboundConfig) {
	if !outbound.TLS && outbound.ServerName == "" && !outbound.SkipCertVerify {
		return
	}
	tls := map[string]any{"enabled": outbound.TLS || outbound.ServerName != "" || outbound.Security == "reality" || outbound.PublicKey != ""}
	addOptional(tls, "server_name", outbound.ServerName)
	if outbound.ALPN != "" {
		tls["alpn"] = splitCSV(outbound.ALPN)
	}
	if outbound.SkipCertVerify {
		tls["insecure"] = true
	}
	if outbound.Security == "reality" || outbound.PublicKey != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": firstNonEmpty(outbound.Fingerprint, "chrome")}
		reality := map[string]any{"enabled": true}
		addOptional(reality, "public_key", outbound.PublicKey)
		addOptional(reality, "short_id", outbound.ShortID)
		tls["reality"] = reality
	} else if outbound.Fingerprint != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": outbound.Fingerprint}
	}
	target["tls"] = tls
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitInts(value string) []int {
	parts := splitCSV(value)
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		number, err := strconv.Atoi(part)
		if err == nil && number > 0 && number <= 65535 {
			out = append(out, number)
		}
	}
	return out
}

func singBoxPortRanges(value string) []string {
	parts := splitCSV(value)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			left, leftErr := strconv.Atoi(strings.TrimSpace(bounds[0]))
			right, rightErr := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if leftErr == nil && rightErr == nil && left > 0 && right > 0 && left <= right && right <= 65535 {
				out = append(out, fmt.Sprintf("%d:%d", left, right))
				continue
			}
		}
		out = append(out, part)
	}
	return out
}

func addSingBoxTransport(target map[string]any, outbound OutboundConfig) {
	if outbound.Transport == "" || outbound.Transport == "tcp" {
		return
	}
	transport := map[string]any{"type": outbound.Transport}
	if outbound.Transport == "grpc" {
		addOptional(transport, "service_name", strings.TrimPrefix(outbound.Path, "/"))
	} else {
		addOptional(transport, "path", outbound.Path)
	}
	if outbound.Host != "" {
		transport["headers"] = map[string][]string{"Host": {outbound.Host}}
	}
	target["transport"] = transport
}

func routeFinal(routing RoutingConfig) string {
	mode := routingMode(routing.Mode)
	if mode == "direct" {
		return "direct"
	}
	final := routing.DefaultOutbound
	if final == "" {
		final = "direct"
	}
	return final
}

func sortedRoutingRules(rules []RoutingRule) []RoutingRule {
	next := append([]RoutingRule(nil), rules...)
	sort.SliceStable(next, func(i, j int) bool {
		if next[i].Priority == next[j].Priority {
			return next[i].Inbound < next[j].Inbound
		}
		return next[i].Priority < next[j].Priority
	})
	return next
}
