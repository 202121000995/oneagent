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
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

type RuntimeState struct {
	Inbounds  []InboundConfig  `json:"inbounds"`
	Outbounds []OutboundConfig `json:"outbounds"`
	Routing   RoutingConfig    `json:"routing"`
	Mihomo    MihomoConfig     `json:"mihomo"`
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
	case "mihomo":
		kernel := NewMihomoKernel()
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
	final := state.Routing.DefaultOutbound
	if final == "" {
		final = "direct"
	}
	payload := map[string]any{
		"log":       map[string]any{"level": "info", "timestamp": true},
		"inbounds":  singBoxInbounds(state.Inbounds),
		"outbounds": singBoxOutbounds(state.Outbounds),
		"route":     map[string]any{"rules": singBoxRules(state.Routing.Rules), "final": final},
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

type MihomoKernel struct {
	baseKernel
}

func NewMihomoKernel() *MihomoKernel {
	return &MihomoKernel{baseKernel: baseKernel{name: "mihomo", mode: "external"}}
}

func (k *MihomoKernel) Name() string {
	return "mihomo"
}

func (k *MihomoKernel) GenerateConfig(state RuntimeState) ([]byte, error) {
	proxies := mihomoProxies(state.Outbounds)
	proxyNames := []string{"DIRECT"}
	for _, proxy := range proxies {
		if name, ok := proxy["name"].(string); ok {
			proxyNames = append(proxyNames, name)
		}
	}

	proxyGroups := mihomoProxyGroups(state.Mihomo, proxyNames)
	payload := map[string]any{
		"mixed-port":                mihomoMixedPort(state.Inbounds),
		"allow-lan":                 true,
		"mode":                      "rule",
		"log-level":                 "info",
		"external-controller":       "127.0.0.1:9090",
		"global-client-fingerprint": "chrome",
		"unified-delay":             true,
		"tcp-concurrent":            true,
		"profile":                   map[string]bool{"store-selected": true},
		"proxies":                   proxies,
		"proxy-groups":              proxyGroups,
		"rules":                     mihomoRules(state.Routing, state.Mihomo, proxyGroups, state.Inbounds),
	}
	if providers := mihomoProviders(state.Mihomo); len(providers) > 0 {
		payload["proxy-providers"] = providers
	}
	return yaml.Marshal(payload)
}

func (k *MihomoKernel) ValidateConfig(path string) error {
	executable := k.executable()
	if executable == "" {
		return fmt.Errorf("mihomo executable is required")
	}
	output, err := exec.Command(executable, "-t", "-f", path).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, string(output))
	}
	return nil
}

func (k *MihomoKernel) Start(path string) error {
	if err := k.ValidateConfig(path); err != nil {
		k.setApplied(false, err)
		return err
	}
	if err := k.startProcess("-f", path); err != nil {
		return err
	}
	log.Printf("mihomo started with %s", path)
	return nil
}

func (k *MihomoKernel) Reload(path string) error {
	return k.Start(path)
}

func (k *MihomoKernel) Stop() error {
	return k.stopProcess()
}

func (k *MihomoKernel) Status() KernelStatus {
	return k.status()
}

func singBoxInbounds(inbounds []InboundConfig) []map[string]any {
	items := make([]map[string]any, 0, len(inbounds))
	for _, inbound := range inbounds {
		base := map[string]any{"tag": inbound.Name, "listen": firstNonEmpty(inbound.Listen, "::"), "listen_port": inbound.Port}
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
			base["users"] = []map[string]any{{
				"name":     firstNonEmpty(inbound.Username, inbound.Name),
				"password": inbound.Password,
			}}
			base["handshake"] = map[string]any{
				"server":      firstNonEmpty(inbound.RealityHandshakeServer, inbound.ServerName),
				"server_port": firstNonZero(inbound.RealityHandshakePort, 443),
			}
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
			base["type"] = "mixed"
		}
		items = append(items, base)
	}
	return items
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
	items := []map[string]any{{"type": "direct", "tag": "direct"}}
	for _, outbound := range outbounds {
		if outbound.Address == "" || outbound.Protocol == "direct" {
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
			addOptional(base, "congestion_control", outbound.Congestion)
			addOptional(base, "udp_relay_mode", outbound.UDPRelayMode)
			addTLS(base, outbound)
			items = append(items, base)
		case "anytls":
			base["type"] = "anytls"
			base["password"] = outbound.Password
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
	return items
}

func singBoxRules(rules []RoutingRule) []map[string]any {
	rules = sortedRoutingRules(rules)
	items := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		if rule.Disabled {
			continue
		}
		items = append(items, map[string]any{"inbound": []string{rule.Inbound}, "outbound": rule.Outbound})
	}
	return items
}

func mihomoMixedPort(inbounds []InboundConfig) int {
	for _, inbound := range inbounds {
		switch inbound.Protocol {
		case "mixed", "socks", "socks5", "http":
			return inbound.Port
		}
	}
	if len(inbounds) > 0 {
		return inbounds[0].Port
	}
	return 7890
}

func mihomoProxies(outbounds []OutboundConfig) []map[string]any {
	items := make([]map[string]any, 0, len(outbounds))
	for _, outbound := range outbounds {
		if outbound.Address == "" {
			continue
		}
		base := map[string]any{"name": outbound.Name, "server": outbound.Address, "port": outbound.Port}
		switch outbound.Protocol {
		case "socks", "socks5":
			item := map[string]any{"name": outbound.Name, "type": "socks5", "server": outbound.Address, "port": outbound.Port}
			addOptional(item, "username", outbound.Username)
			addOptional(item, "password", outbound.Password)
			items = append(items, item)
		case "http":
			item := map[string]any{"name": outbound.Name, "type": "http", "server": outbound.Address, "port": outbound.Port}
			addOptional(item, "username", outbound.Username)
			addOptional(item, "password", outbound.Password)
			items = append(items, item)
		case "vless":
			base["type"] = "vless"
			base["uuid"] = outbound.UUID
			addMihomoTLS(base, outbound)
			addMihomoNetwork(base, outbound)
			items = append(items, base)
		case "vmess":
			base["type"] = "vmess"
			base["uuid"] = outbound.UUID
			base["alterId"] = outbound.AlterID
			if outbound.Security == "" {
				base["cipher"] = "auto"
			} else {
				base["cipher"] = outbound.Security
			}
			addMihomoTLS(base, outbound)
			addMihomoNetwork(base, outbound)
			items = append(items, base)
		case "trojan":
			base["type"] = "trojan"
			base["password"] = outbound.Password
			addMihomoTLS(base, outbound)
			addMihomoNetwork(base, outbound)
			items = append(items, base)
		case "shadowsocks", "ss":
			base["type"] = "ss"
			base["cipher"] = outbound.Method
			base["password"] = outbound.Password
			items = append(items, base)
		case "hysteria2":
			base["type"] = "hysteria2"
			base["password"] = outbound.Password
			if outbound.UpMbps > 0 {
				base["up"] = outbound.UpMbps
			}
			if outbound.DownMbps > 0 {
				base["down"] = outbound.DownMbps
			}
			if outbound.Obfs != "" && outbound.Obfs != "none" {
				base["obfs"] = outbound.Obfs
				addOptional(base, "obfs-password", outbound.ObfsPassword)
			}
			addMihomoTLS(base, outbound)
			items = append(items, base)
		case "tuic":
			base["type"] = "tuic"
			base["uuid"] = outbound.UUID
			base["password"] = outbound.Password
			addOptional(base, "congestion-controller", outbound.Congestion)
			addOptional(base, "udp-relay-mode", outbound.UDPRelayMode)
			addMihomoTLS(base, outbound)
			items = append(items, base)
		case "anytls":
			base["type"] = "anytls"
			base["password"] = outbound.Password
			addMihomoTLS(base, outbound)
			items = append(items, base)
		case "naive":
			base["type"] = "http"
			base["username"] = firstNonEmpty(outbound.Username, outbound.UUID)
			base["password"] = outbound.Password
			addMihomoTLS(base, outbound)
			items = append(items, base)
		case "shadowtls":
			base["type"] = "shadowtls"
			base["password"] = outbound.Password
			base["version"] = 3
			addMihomoTLS(base, outbound)
			items = append(items, base)
		}
	}
	return items
}

func addOptional(target map[string]any, key string, value string) {
	if value != "" {
		target[key] = value
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
	if outbound.Fingerprint != "" {
		tls["utls"] = map[string]any{"enabled": true, "fingerprint": outbound.Fingerprint}
	}
	if outbound.SkipCertVerify {
		tls["insecure"] = true
	}
	if outbound.Security == "reality" || outbound.PublicKey != "" {
		reality := map[string]any{"enabled": true}
		addOptional(reality, "public_key", outbound.PublicKey)
		addOptional(reality, "short_id", outbound.ShortID)
		tls["reality"] = reality
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

func addMihomoTLS(target map[string]any, outbound OutboundConfig) {
	if outbound.TLS {
		target["tls"] = true
	}
	if outbound.ServerName != "" {
		target["servername"] = outbound.ServerName
	}
	if outbound.SkipCertVerify {
		target["skip-cert-verify"] = true
	}
	if outbound.Security == "reality" || outbound.PublicKey != "" {
		target["reality-opts"] = map[string]any{"public-key": outbound.PublicKey, "short-id": outbound.ShortID}
	}
}

func addMihomoNetwork(target map[string]any, outbound OutboundConfig) {
	if outbound.Transport == "" && outbound.Network == "" {
		return
	}
	network := outbound.Transport
	if network == "" {
		network = outbound.Network
	}
	target["network"] = network
	if network == "ws" {
		opts := map[string]any{}
		addOptional(opts, "path", outbound.Path)
		if outbound.Host != "" {
			opts["headers"] = map[string]string{"Host": outbound.Host}
		}
		target["ws-opts"] = opts
	}
}

func mihomoProviders(cfg MihomoConfig) map[string]any {
	providers := map[string]any{}
	for _, provider := range cfg.Providers {
		if provider.Name == "" || provider.URL == "" {
			continue
		}
		interval := provider.Interval
		if interval == 0 {
			interval = 3600
		}
		providerType := provider.Type
		if providerType == "" {
			providerType = "http"
		}
		path := provider.Path
		if path == "" {
			path = "./providers/" + provider.Name + ".yaml"
		}
		item := map[string]any{"type": providerType, "url": provider.URL, "path": path, "interval": interval}
		if provider.HealthCheckURL != "" {
			item["health-check"] = map[string]any{"enable": true, "url": provider.HealthCheckURL, "lazy": provider.HealthCheckLazy}
		}
		providers[provider.Name] = item
	}
	return providers
}

func mihomoProxyGroups(cfg MihomoConfig, defaultProxies []string) []map[string]any {
	if len(cfg.ProxyGroups) == 0 {
		return []map[string]any{{"name": "NodeTools", "type": "select", "proxies": defaultProxies}}
	}
	groups := make([]map[string]any, 0, len(cfg.ProxyGroups))
	for _, group := range cfg.ProxyGroups {
		if group.Name == "" {
			continue
		}
		groupType := group.Type
		if groupType == "" {
			groupType = "select"
		}
		proxies := group.Proxies
		if len(proxies) == 0 && len(group.Use) == 0 {
			proxies = defaultProxies
		}
		item := map[string]any{"name": group.Name, "type": groupType}
		if len(proxies) > 0 {
			item["proxies"] = proxies
		}
		if len(group.Use) > 0 {
			item["use"] = group.Use
		}
		addOptional(item, "url", group.URL)
		if group.Interval > 0 {
			item["interval"] = group.Interval
		}
		if group.Tolerance > 0 {
			item["tolerance"] = group.Tolerance
		}
		groups = append(groups, item)
	}
	return groups
}

func mihomoRules(routing RoutingConfig, cfg MihomoConfig, groups []map[string]any, inbounds []InboundConfig) []string {
	if len(cfg.Rules) > 0 {
		return cfg.Rules
	}
	target := "DIRECT"
	if routing.DefaultOutbound != "" {
		target = routing.DefaultOutbound
	} else if len(groups) > 0 {
		if name, ok := groups[0]["name"].(string); ok {
			target = name
		}
	}
	rules := sortedRoutingRules(routing.Rules)
	items := make([]string, 0, len(rules)+1)
	inboundPorts := map[string]int{}
	for _, inbound := range inbounds {
		inboundPorts[inbound.Name] = inbound.Port
	}
	for _, rule := range rules {
		if rule.Disabled {
			continue
		}
		if port := inboundPorts[rule.Inbound]; port > 0 {
			items = append(items, fmt.Sprintf("IN-PORT,%d,%s", port, rule.Outbound))
		}
	}
	items = append(items, "MATCH,"+target)
	return items
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
