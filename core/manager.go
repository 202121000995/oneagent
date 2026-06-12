package core

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Node struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Protocol      string `json:"protocol"`
	Address       string `json:"address"`
	Port          int    `json:"port"`
	Enabled       bool   `json:"enabled"`
	Status        string `json:"status"`
	LatencyMS     int64  `json:"latency_ms"`
	LastError     string `json:"last_error,omitempty"`
	UploadBytes   int64  `json:"upload_bytes"`
	DownloadBytes int64  `json:"download_bytes"`
	UpdatedAt     string `json:"updated_at"`
}

type Status struct {
	Version          string       `json:"version"`
	BuildTime        string       `json:"build_time"`
	Commit           string       `json:"commit"`
	StartedAt        string       `json:"started_at"`
	UptimeSeconds    int64        `json:"uptime_seconds"`
	InboundCount     int          `json:"inbound_count"`
	OutboundCount    int          `json:"outbound_count"`
	RoutingRuleCount int          `json:"routing_rule_count"`
	TotalUpload      int64        `json:"total_upload_bytes"`
	TotalDownload    int64        `json:"total_download_bytes"`
	Kernel           KernelStatus `json:"kernel"`
}

type Manager struct {
	db         *sql.DB
	kernel     Kernel
	configPath string
	startedAt  time.Time
	stopCh     chan struct{}

	mu        sync.RWMutex
	cfg       Config
	inbounds  map[string]InboundConfig
	outbounds map[string]OutboundConfig
	rules     []RoutingRule
	traffic   map[string]*Traffic
	health    map[string]Health
}

type Traffic struct {
	UploadBytes   int64
	DownloadBytes int64
	UpdatedAt     time.Time
}

type Health struct {
	Status    string
	LatencyMS int64
	LastError string
	UpdatedAt time.Time
}

type NodeTestResult struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Status    string `json:"status"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
	UpdatedAt string `json:"updated_at"`
}

type SubscriptionUpdateResult struct {
	Provider      string   `json:"provider"`
	URL           string   `json:"url"`
	Parsed        int      `json:"parsed"`
	Imported      int      `json:"imported"`
	ImportedNodes []string `json:"imported_nodes,omitempty"`
	Errors        []string `json:"errors,omitempty"`
}

func NewManager(db *sql.DB, configPath string) *Manager {
	return &Manager{
		db:         db,
		kernel:     NewPlaceholderKernel(),
		configPath: configPath,
		startedAt:  time.Now(),
		stopCh:     make(chan struct{}),
		inbounds:   map[string]InboundConfig{},
		outbounds:  map[string]OutboundConfig{},
		traffic:    map[string]*Traffic{},
		health:     map[string]Health{},
	}
}

func (m *Manager) ApplyConfig(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.cfg = cfg
	m.inbounds = map[string]InboundConfig{}
	for _, inbound := range cfg.Inbounds {
		m.inbounds[inbound.Name] = inbound
		m.ensureTrafficLocked(inbound.Name)
		m.ensureHealthLocked(inbound.Name, inbound.Disabled)
	}
	m.outbounds = map[string]OutboundConfig{}
	for _, outbound := range cfg.Outbounds {
		m.outbounds[outbound.Name] = outbound
		m.ensureTrafficLocked(outbound.Name)
		m.ensureHealthLocked(outbound.Name, outbound.Disabled)
	}
	m.rules = append([]RoutingRule(nil), cfg.Routing.Rules...)
	if m.kernel == nil || m.kernel.Name() != kernelName(cfg.Kernel) {
		m.kernel = NewKernel(cfg.Kernel)
	} else {
		m.kernel.Configure(cfg.Kernel)
	}

	if err := m.persistConfigLocked(cfg); err != nil {
		return err
	}
	if err := m.persistRuntimeLocked(); err != nil {
		return err
	}
	if err := m.applyKernelLocked(); err != nil {
		return err
	}
	InitInbounds(cfg.Inbounds)
	InitOutbounds(cfg.Outbounds)
	InitRoutes(cfg.Routing.Rules)
	return nil
}

func (m *Manager) Stop() {
	close(m.stopCh)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.kernel != nil {
		if err := m.kernel.Stop(); err != nil {
			log.Printf("kernel stop failed: %v", err)
		}
	}
}

func (m *Manager) StartTrafficSampler() {
	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		m.probeAllNodes()
		for {
			select {
			case <-m.stopCh:
				return
			case <-ticker.C:
				m.probeAllNodes()
			}
		}
	}()
}

func (m *Manager) ListNodes() []Node {
	m.mu.RLock()
	defer m.mu.RUnlock()

	nodes := make([]Node, 0, len(m.inbounds)+len(m.outbounds))
	inboundNames := make([]string, 0, len(m.inbounds))
	for name := range m.inbounds {
		inboundNames = append(inboundNames, name)
	}
	sort.Strings(inboundNames)
	for _, name := range inboundNames {
		inbound := m.inbounds[name]
		traffic := m.traffic[inbound.Name]
		health := m.health[inbound.Name]
		nodes = append(nodes, Node{
			Name:          inbound.Name,
			Type:          "inbound",
			Protocol:      inbound.Protocol,
			Address:       firstNonEmpty(inbound.Listen, "::"),
			Port:          inbound.Port,
			Enabled:       !inbound.Disabled,
			Status:        health.Status,
			LatencyMS:     health.LatencyMS,
			LastError:     health.LastError,
			UploadBytes:   traffic.UploadBytes,
			DownloadBytes: traffic.DownloadBytes,
			UpdatedAt:     traffic.UpdatedAt.Format(time.RFC3339),
		})
	}
	outboundNames := make([]string, 0, len(m.outbounds))
	for name := range m.outbounds {
		outboundNames = append(outboundNames, name)
	}
	sort.Strings(outboundNames)
	for _, name := range outboundNames {
		outbound := m.outbounds[name]
		traffic := m.traffic[outbound.Name]
		health := m.health[outbound.Name]
		nodes = append(nodes, Node{
			Name:          outbound.Name,
			Type:          "outbound",
			Protocol:      outbound.Protocol,
			Address:       outbound.Address,
			Port:          outbound.Port,
			Enabled:       !outbound.Disabled,
			Status:        health.Status,
			LatencyMS:     health.LatencyMS,
			LastError:     health.LastError,
			UploadBytes:   traffic.UploadBytes,
			DownloadBytes: traffic.DownloadBytes,
			UpdatedAt:     traffic.UpdatedAt.Format(time.RFC3339),
		})
	}
	return nodes
}

func (m *Manager) Status() Status {
	nodes := m.ListNodes()
	var upload, download int64
	for _, node := range nodes {
		upload += node.UploadBytes
		download += node.DownloadBytes
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	return Status{
		Version:          Version,
		BuildTime:        BuildTime,
		Commit:           Commit,
		StartedAt:        m.startedAt.Format(time.RFC3339),
		UptimeSeconds:    int64(time.Since(m.startedAt).Seconds()),
		InboundCount:     len(m.inbounds),
		OutboundCount:    len(m.outbounds),
		RoutingRuleCount: len(m.rules),
		TotalUpload:      upload,
		TotalDownload:    download,
		Kernel:           m.kernel.Status(),
	}
}

func (m *Manager) ConfigSnapshot() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

func (m *Manager) ReloadKernel() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.applyKernelLocked()
}

func (m *Manager) StopKernel() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.kernel == nil {
		return nil
	}
	return m.kernel.Stop()
}

func (m *Manager) UpdateKernelConfig(cfg KernelConfig) error {
	if cfg.Type == "" {
		cfg.Type = "placeholder"
	}
	cfg = normalizeKernelConfig(cfg)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.kernel != nil && m.kernel.Name() != kernelName(cfg) {
		if err := m.kernel.Stop(); err != nil {
			return err
		}
		m.kernel = NewKernel(cfg)
	} else if m.kernel == nil {
		m.kernel = NewKernel(cfg)
	} else {
		m.kernel.Configure(cfg)
	}
	m.cfg.Kernel = cfg
	return m.commitLocked()
}

func normalizeKernelConfig(cfg KernelConfig) KernelConfig {
	if cfg.Type == "" {
		cfg.Type = "placeholder"
	}
	if cfg.ConfigPath == "" {
		cfg.ConfigPath = "kernel.generated.json"
	}
	switch cfg.Type {
	case "sing-box":
		if cfg.Executable == "" || cfg.Executable == "/usr/local/bin/mihomo" {
			cfg.Executable = "/usr/local/bin/sing-box"
		}
		if cfg.ConfigPath == "" || cfg.ConfigPath == "kernel.generated.json" || cfg.ConfigPath == "mihomo.generated.yaml" {
			cfg.ConfigPath = "sing-box.generated.json"
		}
	case "mihomo":
		if cfg.Executable == "" || cfg.Executable == "/usr/local/bin/sing-box" {
			cfg.Executable = "/usr/local/bin/mihomo"
		}
		if cfg.ConfigPath == "" || cfg.ConfigPath == "kernel.generated.json" || cfg.ConfigPath == "sing-box.generated.json" {
			cfg.ConfigPath = "mihomo.generated.yaml"
		}
	}
	return cfg
}

func (m *Manager) UpdateMihomoConfig(cfg MihomoConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.Mihomo = cfg
	return m.commitLocked()
}

func (m *Manager) CreateProxy(req ProxyCreateRequest) (Node, error) {
	if req.Name == "" {
		return Node{}, fmt.Errorf("name is required")
	}
	if req.Protocol == "" {
		req.Protocol = "socks"
	}
	if req.Port < 1 || req.Port > 65535 {
		return Node{}, fmt.Errorf("valid port is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.inbounds[req.Name]; exists {
		return Node{}, fmt.Errorf("inbound %q already exists", req.Name)
	}

	inbound := InboundConfig{
		Name:                   req.Name,
		Protocol:               req.Protocol,
		Listen:                 req.Listen,
		Port:                   req.Port,
		Username:               req.Username,
		UUID:                   req.UUID,
		Password:               req.Password,
		Method:                 req.Method,
		Flow:                   req.Flow,
		Security:               req.Security,
		AlterID:                req.AlterID,
		TLS:                    req.TLS,
		ServerName:             req.ServerName,
		CertificatePath:        req.CertificatePath,
		KeyPath:                req.KeyPath,
		CertificateContent:     req.CertificateContent,
		KeyContent:             req.KeyContent,
		Transport:              req.Transport,
		Path:                   req.Path,
		Host:                   req.Host,
		PrivateKey:             req.PrivateKey,
		ShortID:                req.ShortID,
		RealityHandshakeServer: req.RealityHandshakeServer,
		RealityHandshakePort:   req.RealityHandshakePort,
		IdleSessionCheck:       req.IdleSessionCheck,
		IdleSessionTimeout:     req.IdleSessionTimeout,
		MinIdleSession:         req.MinIdleSession,
	}
	if err := materializeInboundCertificateContent(&inbound); err != nil {
		return Node{}, err
	}
	if err := inbound.Validate(); err != nil {
		return Node{}, err
	}
	m.inbounds[inbound.Name] = inbound
	m.cfg.Inbounds = append(m.cfg.Inbounds, inbound)
	m.ensureTrafficLocked(req.Name)
	m.ensureHealthLocked(req.Name, inbound.Disabled)
	if err := m.commitLocked(); err != nil {
		return Node{}, err
	}
	return m.nodeLocked(req.Name, "inbound"), nil
}

func (m *Manager) CreateForward(req ForwardCreateRequest) (Node, error) {
	if req.Name == "" {
		return Node{}, fmt.Errorf("name is required")
	}
	if req.ListenPort < 1 || req.ListenPort > 65535 {
		return Node{}, fmt.Errorf("valid listen_port is required")
	}
	if req.TargetHost == "" {
		return Node{}, fmt.Errorf("target_host is required")
	}
	if req.TargetPort < 1 || req.TargetPort > 65535 {
		return Node{}, fmt.Errorf("valid target_port is required")
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	if req.Protocol != "tcp" && req.Protocol != "udp" {
		return Node{}, fmt.Errorf("forward protocol must be tcp or udp")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.inbounds[req.Name]; exists {
		return Node{}, fmt.Errorf("inbound %q already exists", req.Name)
	}

	inbound := InboundConfig{
		Name:       req.Name,
		Protocol:   "forward-" + req.Protocol,
		Listen:     "0.0.0.0",
		Port:       req.ListenPort,
		TargetHost: req.TargetHost,
		TargetPort: req.TargetPort,
	}
	if err := inbound.Validate(); err != nil {
		return Node{}, err
	}
	rule := RoutingRule{Name: inbound.Name + "-route", Inbound: inbound.Name, Outbound: "direct", Priority: nextRulePriority(m.rules)}
	m.inbounds[inbound.Name] = inbound
	m.rules = append(m.rules, rule)
	m.cfg.Inbounds = append(m.cfg.Inbounds, inbound)
	m.cfg.Routing.Rules = append(m.cfg.Routing.Rules, rule)
	m.ensureTrafficLocked(inbound.Name)
	m.ensureHealthLocked(inbound.Name, inbound.Disabled)
	if err := m.commitLocked(); err != nil {
		return Node{}, err
	}
	return m.nodeLocked(inbound.Name, "inbound"), nil
}

func (m *Manager) UpsertInbound(inbound InboundConfig) (Node, error) {
	if inbound.Name == "" {
		return Node{}, fmt.Errorf("name is required")
	}
	if inbound.Protocol == "" {
		return Node{}, fmt.Errorf("protocol is required")
	}
	if inbound.Port < 1 || inbound.Port > 65535 {
		return Node{}, fmt.Errorf("valid port is required")
	}
	if err := materializeInboundCertificateContent(&inbound); err != nil {
		return Node{}, err
	}
	if err := inbound.Validate(); err != nil {
		return Node{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.inbounds[inbound.Name] = inbound
	m.cfg.Inbounds = upsertInboundConfig(m.cfg.Inbounds, inbound)
	m.ensureTrafficLocked(inbound.Name)
	m.ensureHealthLocked(inbound.Name, inbound.Disabled)
	if err := m.commitLocked(); err != nil {
		return Node{}, err
	}
	return m.nodeLocked(inbound.Name, "inbound"), nil
}

func (m *Manager) UpsertOutbound(outbound OutboundConfig) (Node, error) {
	originalName := outbound.OriginalName
	outbound.OriginalName = ""
	if outbound.Name == "" {
		return Node{}, fmt.Errorf("name is required")
	}
	if outbound.Protocol == "" {
		return Node{}, fmt.Errorf("protocol is required")
	}
	if outbound.Address == "" {
		return Node{}, fmt.Errorf("address is required")
	}
	if outbound.Port < 1 || outbound.Port > 65535 {
		return Node{}, fmt.Errorf("valid port is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if originalName != "" && originalName != outbound.Name {
		if _, ok := m.outbounds[originalName]; !ok {
			return Node{}, fmt.Errorf("outbound %q does not exist", originalName)
		}
		if _, exists := m.outbounds[outbound.Name]; exists {
			return Node{}, fmt.Errorf("outbound %q already exists", outbound.Name)
		}
		delete(m.outbounds, originalName)
		m.cfg.Outbounds = deleteOutboundConfig(m.cfg.Outbounds, originalName)
		m.rules = renameRoutingOutbound(m.rules, originalName, outbound.Name)
		m.cfg.Routing.Rules = renameRoutingOutbound(m.cfg.Routing.Rules, originalName, outbound.Name)
		if m.cfg.Routing.DefaultOutbound == originalName {
			m.cfg.Routing.DefaultOutbound = outbound.Name
		}
		if traffic, ok := m.traffic[originalName]; ok {
			m.traffic[outbound.Name] = traffic
			delete(m.traffic, originalName)
		}
		if health, ok := m.health[originalName]; ok {
			m.health[outbound.Name] = health
			delete(m.health, originalName)
		}
	}
	m.outbounds[outbound.Name] = outbound
	m.cfg.Outbounds = upsertOutboundConfig(m.cfg.Outbounds, outbound)
	m.ensureTrafficLocked(outbound.Name)
	m.ensureHealthLocked(outbound.Name, outbound.Disabled)
	if err := m.commitLocked(); err != nil {
		return Node{}, err
	}
	return m.nodeLocked(outbound.Name, "outbound"), nil
}

func (m *Manager) ImportOutbounds(outbounds []OutboundConfig) ([]Node, error) {
	if len(outbounds) == 0 {
		return nil, fmt.Errorf("no outbounds to import")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	imported := make([]Node, 0, len(outbounds))
	for _, outbound := range outbounds {
		if outbound.Name == "" {
			outbound.Name = outbound.Protocol + "-" + outbound.Address
		}
		if existing := m.findEquivalentOutboundLocked(outbound); existing != "" {
			outbound.Name = existing
		} else {
			outbound.Name = m.uniqueOutboundNameLocked(outbound.Name)
		}
		if outbound.Protocol == "" {
			return nil, fmt.Errorf("protocol is required for %q", outbound.Name)
		}
		if outbound.Address == "" {
			return nil, fmt.Errorf("address is required for %q", outbound.Name)
		}
		if outbound.Port < 1 || outbound.Port > 65535 {
			return nil, fmt.Errorf("valid port is required for %q", outbound.Name)
		}
		if err := outbound.Validate(); err != nil {
			return nil, err
		}
		m.outbounds[outbound.Name] = outbound
		m.cfg.Outbounds = upsertOutboundConfig(m.cfg.Outbounds, outbound)
		m.ensureTrafficLocked(outbound.Name)
		m.ensureHealthLocked(outbound.Name, outbound.Disabled)
		imported = append(imported, m.nodeLocked(outbound.Name, "outbound"))
	}
	if err := m.commitLocked(); err != nil {
		return nil, err
	}
	return imported, nil
}

func (m *Manager) UpdateSubscriptions() ([]SubscriptionUpdateResult, error) {
	m.mu.RLock()
	providers := append([]ProxyProviderConfig(nil), m.cfg.Mihomo.Providers...)
	m.mu.RUnlock()
	if len(providers) == 0 {
		return nil, fmt.Errorf("no subscription providers configured")
	}

	results := make([]SubscriptionUpdateResult, 0, len(providers))
	for _, provider := range providers {
		if provider.URL == "" {
			continue
		}
		result := SubscriptionUpdateResult{Provider: provider.Name, URL: provider.URL}
		body, err := fetchSubscription(provider.URL)
		if err != nil {
			result.Errors = append(result.Errors, err.Error())
			results = append(results, result)
			continue
		}
		outbounds, parseErrors := ParseOutboundLinks(string(body))
		result.Parsed = len(outbounds)
		result.Errors = append(result.Errors, parseErrors...)
		if len(outbounds) > 0 {
			nodes, importErr := m.ImportOutbounds(outbounds)
			if importErr != nil {
				result.Errors = append(result.Errors, importErr.Error())
			} else {
				result.Imported = len(nodes)
				for _, node := range nodes {
					result.ImportedNodes = append(result.ImportedNodes, node.Name)
				}
			}
		}
		results = append(results, result)
	}
	return results, nil
}

func (m *Manager) UpdateRoutingConfig(routing RoutingConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg.Routing = routing
	m.rules = append([]RoutingRule(nil), routing.Rules...)
	return m.commitLocked()
}

func (m *Manager) DeleteNode(nodeType, name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	switch nodeType {
	case "inbound":
		if _, ok := m.inbounds[name]; !ok {
			return fmt.Errorf("inbound %q does not exist", name)
		}
		delete(m.inbounds, name)
		m.cfg.Inbounds = deleteInboundConfig(m.cfg.Inbounds, name)
		m.rules = deleteRulesForNode(m.rules, "inbound", name)
		m.cfg.Routing.Rules = deleteRulesForNode(m.cfg.Routing.Rules, "inbound", name)
	case "outbound":
		if _, ok := m.outbounds[name]; !ok {
			return fmt.Errorf("outbound %q does not exist", name)
		}
		delete(m.outbounds, name)
		m.cfg.Outbounds = deleteOutboundConfig(m.cfg.Outbounds, name)
		m.rules = deleteRulesForNode(m.rules, "outbound", name)
		m.cfg.Routing.Rules = deleteRulesForNode(m.cfg.Routing.Rules, "outbound", name)
	default:
		return fmt.Errorf("node type must be inbound or outbound")
	}
	if err := m.commitLocked(); err != nil {
		return err
	}
	return nil
}

func (m *Manager) SetNodeEnabled(nodeType, name string, enabled bool) (Node, error) {
	if name == "" {
		return Node{}, fmt.Errorf("name is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	switch nodeType {
	case "inbound":
		inbound, ok := m.inbounds[name]
		if !ok {
			return Node{}, fmt.Errorf("inbound %q does not exist", name)
		}
		inbound.Disabled = !enabled
		m.inbounds[name] = inbound
		m.cfg.Inbounds = upsertInboundConfig(m.cfg.Inbounds, inbound)
	case "outbound":
		outbound, ok := m.outbounds[name]
		if !ok {
			return Node{}, fmt.Errorf("outbound %q does not exist", name)
		}
		outbound.Disabled = !enabled
		m.outbounds[name] = outbound
		m.cfg.Outbounds = upsertOutboundConfig(m.cfg.Outbounds, outbound)
	default:
		return Node{}, fmt.Errorf("node type must be inbound or outbound")
	}
	m.ensureHealthLocked(name, !enabled)
	if err := m.commitLocked(); err != nil {
		return Node{}, err
	}
	return m.nodeLocked(name, nodeType), nil
}

func (m *Manager) TestNode(nodeType, name string) (NodeTestResult, error) {
	m.mu.RLock()
	cfg := m.cfg
	var health Health
	switch nodeType {
	case "inbound":
		inbound, ok := m.inbounds[name]
		m.mu.RUnlock()
		if !ok {
			return NodeTestResult{}, fmt.Errorf("inbound %q does not exist", name)
		}
		health = m.probeInboundGoogle(inbound, cfg)
	case "outbound":
		_, disabled, outbound, err := m.probeTargetLocked(nodeType, name)
		m.mu.RUnlock()
		if err != nil {
			return NodeTestResult{}, err
		}
		health = m.probeOutbound(outbound, cfg, disabled)
	default:
		m.mu.RUnlock()
		return NodeTestResult{}, fmt.Errorf("node type must be inbound or outbound")
	}
	m.mu.Lock()
	m.health[name] = health
	m.mu.Unlock()
	return NodeTestResult{
		Name:      name,
		Type:      nodeType,
		Status:    health.Status,
		LatencyMS: health.LatencyMS,
		Error:     health.LastError,
		UpdatedAt: health.UpdatedAt.Format(time.RFC3339),
	}, nil
}

func (m *Manager) probeInboundGoogle(inbound InboundConfig, cfg Config) Health {
	if cfg.Kernel.Type == "sing-box" {
		if executable := firstNonEmpty(cfg.Kernel.Executable, findExecutable("sing-box")); executable != "" {
			return probeInboundWithSingBox(executable, inbound)
		}
	}
	return probeHTTPProxyInboundGoogle(inbound)
}

func probeHTTPProxyInboundGoogle(inbound InboundConfig) Health {
	now := time.Now()
	if inbound.Disabled {
		return Health{Status: "disabled", LastError: "node disabled", UpdatedAt: now}
	}
	switch inbound.Protocol {
	case "mixed", "http":
	default:
		return Health{
			Status:    "unsupported",
			LastError: fmt.Sprintf("%s 入站需要对应客户端协议握手；当前仅支持 mixed/http 入站做 Google 链路测试", inbound.Protocol),
			UpdatedAt: now,
		}
	}
	proxyURL := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", inbound.Port)),
	}
	if inbound.Username != "" || inbound.Password != "" {
		proxyURL.User = url.UserPassword(inbound.Username, inbound.Password)
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	start := time.Now()
	resp, err := client.Get("http://www.google.com/generate_204")
	if err != nil {
		return Health{Status: "offline", LastError: "Google 链路测试失败: " + compactError(err.Error()), UpdatedAt: now}
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return Health{Status: "offline", LastError: fmt.Sprintf("Google 链路测试 HTTP 状态异常: %d", resp.StatusCode), UpdatedAt: now}
	}
	return Health{Status: "online", LatencyMS: time.Since(start).Milliseconds(), LastError: "Google 链路测试通过", UpdatedAt: now}
}

func probeInboundWithSingBox(executable string, inbound InboundConfig) Health {
	now := time.Now()
	if inbound.Disabled {
		return Health{Status: "disabled", LastError: "node disabled", UpdatedAt: now}
	}
	if inbound.Protocol == "mixed" || inbound.Protocol == "http" {
		return probeHTTPProxyInboundGoogle(inbound)
	}
	outbound, err := inboundProbeOutbound(inbound)
	if err != nil {
		return Health{Status: "unsupported", LastError: err.Error(), UpdatedAt: now}
	}
	if err := outbound.Validate(); err != nil {
		return Health{Status: "offline", LastError: "入口客户端参数无效: " + err.Error(), UpdatedAt: now}
	}
	port, err := freeLocalPort()
	if err != nil {
		return Health{Status: "offline", LastError: "分配本地测试端口失败: " + err.Error(), UpdatedAt: now}
	}
	tmpDir, err := os.MkdirTemp("", "nodetools-inbound-test-*")
	if err != nil {
		return Health{Status: "offline", LastError: "创建测试目录失败: " + err.Error(), UpdatedAt: now}
	}
	defer os.RemoveAll(tmpDir)

	kernel := NewSingBoxKernel()
	kernel.Configure(KernelConfig{Type: "sing-box", Executable: executable, ConfigPath: filepath.Join(tmpDir, "config.json")})
	data, err := kernel.GenerateConfig(RuntimeState{
		Inbounds: []InboundConfig{{
			Name:     "probe-in",
			Protocol: "mixed",
			Listen:   "127.0.0.1",
			Port:     port,
		}},
		Outbounds: []OutboundConfig{outbound},
		Routing: RoutingConfig{
			DefaultOutbound: outbound.Name,
			Rules:           []RoutingRule{{Inbound: "probe-in", Outbound: outbound.Name}},
		},
	})
	if err != nil {
		return Health{Status: "offline", LastError: "生成入口测试配置失败: " + err.Error(), UpdatedAt: now}
	}
	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		return Health{Status: "offline", LastError: "写入入口测试配置失败: " + err.Error(), UpdatedAt: now}
	}
	if err := kernel.ValidateConfig(configPath); err != nil {
		return Health{Status: "offline", LastError: "入口测试 sing-box 配置校验失败: " + compactError(err.Error()), UpdatedAt: now}
	}

	cmd := exec.Command(executable, "run", "-c", configPath)
	var output strings.Builder
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return Health{Status: "offline", LastError: "启动入口测试进程失败: " + err.Error(), UpdatedAt: now}
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	if err := waitTCP(net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)), 2*time.Second); err != nil {
		return Health{Status: "offline", LastError: "入口测试代理未启动: " + compactError(output.String()+" "+err.Error()), UpdatedAt: now}
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	start := time.Now()
	resp, err := client.Get("http://www.google.com/generate_204")
	if err != nil {
		return Health{Status: "offline", LastError: "入口到 Google 链路测试失败: " + compactError(err.Error()+" "+output.String()), UpdatedAt: now}
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return Health{Status: "offline", LastError: fmt.Sprintf("入口到 Google 链路测试 HTTP 状态异常: %d", resp.StatusCode), UpdatedAt: now}
	}
	return Health{Status: "online", LatencyMS: time.Since(start).Milliseconds(), LastError: "入口到 Google 链路测试通过", UpdatedAt: now}
}

func inboundProbeOutbound(inbound InboundConfig) (OutboundConfig, error) {
	outbound := OutboundConfig{
		Name:           "probe-out",
		Protocol:       inbound.Protocol,
		Address:        inboundProbeHost(inbound.Listen),
		Port:           inbound.Port,
		Username:       inbound.Username,
		UUID:           inbound.UUID,
		Password:       inbound.Password,
		Method:         inbound.Method,
		Flow:           inbound.Flow,
		Security:       inbound.Security,
		AlterID:        inbound.AlterID,
		Network:        inbound.Transport,
		TLS:            inbound.TLS || inbound.Security == "reality" || inbound.ServerName != "",
		ServerName:     inbound.ServerName,
		SkipCertVerify: true,
		Transport:      inbound.Transport,
		Path:           inbound.Path,
		Host:           inbound.Host,
		ShortID:        firstNonEmpty(splitCSV(inbound.ShortID)...),
	}
	if outbound.Protocol == "ss" {
		outbound.Protocol = "shadowsocks"
	}
	if outbound.Protocol == "socks5" {
		outbound.Protocol = "socks"
	}
	if outbound.Protocol == "vless" && inbound.Security == "reality" {
		publicKey, err := publicKeyFromRealityPrivate(inbound.PrivateKey)
		if err != nil {
			return OutboundConfig{}, fmt.Errorf("无法从 Reality 私钥推导 public key: %w", err)
		}
		outbound.PublicKey = publicKey
	}
	switch outbound.Protocol {
	case "socks", "http", "vless", "vmess", "trojan", "shadowsocks", "shadowtls", "anytls":
		return outbound, nil
	default:
		return OutboundConfig{}, fmt.Errorf("%s 入站暂不支持从入口到 Google 的自动链路测试", inbound.Protocol)
	}
}

func inboundProbeHost(listen string) string {
	host := strings.TrimSpace(listen)
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return "127.0.0.1"
	default:
		return strings.Trim(host, "[]")
	}
}

func (m *Manager) probeAllNodes() {
	type target struct {
		name     string
		nodeType string
		address  string
		disabled bool
	}
	m.mu.RLock()
	targets := make([]target, 0, len(m.inbounds)+len(m.outbounds))
	for _, inbound := range m.inbounds {
		targets = append(targets, target{
			name:     inbound.Name,
			nodeType: "inbound",
			address:  fmt.Sprintf("127.0.0.1:%d", inbound.Port),
			disabled: inbound.Disabled,
		})
	}
	for _, outbound := range m.outbounds {
		targets = append(targets, target{
			name:     outbound.Name,
			nodeType: "outbound",
			address:  net.JoinHostPort(outbound.Address, fmt.Sprintf("%d", outbound.Port)),
			disabled: outbound.Disabled,
		})
	}
	m.mu.RUnlock()

	for _, target := range targets {
		health := probeTCP(target.address, target.disabled)
		m.mu.Lock()
		m.health[target.name] = health
		m.mu.Unlock()
	}
}

func (m *Manager) probeTargetLocked(nodeType, name string) (string, bool, OutboundConfig, error) {
	switch nodeType {
	case "inbound":
		inbound, ok := m.inbounds[name]
		if !ok {
			return "", false, OutboundConfig{}, fmt.Errorf("inbound %q does not exist", name)
		}
		return fmt.Sprintf("127.0.0.1:%d", inbound.Port), inbound.Disabled, OutboundConfig{}, nil
	case "outbound":
		outbound, ok := m.outbounds[name]
		if !ok {
			return "", false, OutboundConfig{}, fmt.Errorf("outbound %q does not exist", name)
		}
		return net.JoinHostPort(outbound.Address, fmt.Sprintf("%d", outbound.Port)), outbound.Disabled, outbound, nil
	default:
		return "", false, OutboundConfig{}, fmt.Errorf("node type must be inbound or outbound")
	}
}

func (m *Manager) probeOutbound(outbound OutboundConfig, cfg Config, disabled bool) Health {
	now := time.Now()
	if disabled {
		return Health{Status: "disabled", LastError: "node disabled", UpdatedAt: now}
	}
	if err := outbound.Validate(); err != nil {
		return Health{Status: "offline", LastError: "字段校验失败: " + err.Error(), UpdatedAt: now}
	}
	if cfg.Kernel.Type == "sing-box" {
		if executable := firstNonEmpty(cfg.Kernel.Executable, findExecutable("sing-box")); executable != "" {
			return probeOutboundWithSingBox(executable, outbound)
		}
	}
	target := net.JoinHostPort(outbound.Address, fmt.Sprintf("%d", outbound.Port))
	health := probeTCP(target, false)
	if health.Status == "online" {
		health.LastError = "仅完成 TCP 端口探测；配置 sing-box 后可进行真实代理链路测试"
	}
	return health
}

func probeOutboundWithSingBox(executable string, outbound OutboundConfig) Health {
	now := time.Now()
	port, err := freeLocalPort()
	if err != nil {
		return Health{Status: "offline", LastError: "分配本地测试端口失败: " + err.Error(), UpdatedAt: now}
	}
	tmpDir, err := os.MkdirTemp("", "nodetools-outbound-test-*")
	if err != nil {
		return Health{Status: "offline", LastError: "创建测试目录失败: " + err.Error(), UpdatedAt: now}
	}
	defer os.RemoveAll(tmpDir)

	kernel := NewSingBoxKernel()
	kernel.Configure(KernelConfig{Type: "sing-box", Executable: executable, ConfigPath: filepath.Join(tmpDir, "config.json")})
	data, err := kernel.GenerateConfig(RuntimeState{
		Inbounds: []InboundConfig{{
			Name:     "probe-in",
			Protocol: "mixed",
			Port:     port,
		}},
		Outbounds: []OutboundConfig{outbound},
		Routing: RoutingConfig{
			DefaultOutbound: outbound.Name,
			Rules:           []RoutingRule{{Inbound: "probe-in", Outbound: outbound.Name}},
		},
	})
	if err != nil {
		return Health{Status: "offline", LastError: "生成测试配置失败: " + err.Error(), UpdatedAt: now}
	}
	configPath := filepath.Join(tmpDir, "config.json")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		return Health{Status: "offline", LastError: "写入测试配置失败: " + err.Error(), UpdatedAt: now}
	}
	if err := kernel.ValidateConfig(configPath); err != nil {
		return Health{Status: "offline", LastError: "sing-box 配置校验失败: " + compactError(err.Error()), UpdatedAt: now}
	}

	cmd := exec.Command(executable, "run", "-c", configPath)
	var output strings.Builder
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Start(); err != nil {
		return Health{Status: "offline", LastError: "启动 sing-box 测试进程失败: " + err.Error(), UpdatedAt: now}
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	if err := waitTCP(net.JoinHostPort("127.0.0.1", fmt.Sprintf("%d", port)), 2*time.Second); err != nil {
		return Health{Status: "offline", LastError: "测试代理入口未启动: " + compactError(output.String()+" "+err.Error()), UpdatedAt: now}
	}

	proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	client := &http.Client{
		Timeout: 8 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
	}
	start := time.Now()
	resp, err := client.Get("http://www.gstatic.com/generate_204")
	if err != nil {
		return Health{Status: "offline", LastError: "真实代理测试失败: " + compactError(err.Error()+" "+output.String()), UpdatedAt: now}
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return Health{Status: "offline", LastError: fmt.Sprintf("真实代理测试 HTTP 状态异常: %d", resp.StatusCode), UpdatedAt: now}
	}
	return Health{Status: "online", LatencyMS: time.Since(start).Milliseconds(), UpdatedAt: now}
}

func freeLocalPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func waitTCP(address string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timeout")
	}
	return lastErr
}

func findExecutable(name string) string {
	path, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return path
}

func compactError(value string) string {
	value = strings.Join(strings.Fields(value), " ")
	if len(value) > 500 {
		return value[:500] + "..."
	}
	return value
}

func probeTCP(address string, disabled bool) Health {
	now := time.Now()
	if disabled {
		return Health{Status: "disabled", LastError: "node disabled", UpdatedAt: now}
	}
	start := time.Now()
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return Health{Status: "offline", LastError: err.Error(), UpdatedAt: now}
	}
	_ = conn.Close()
	return Health{Status: "online", LatencyMS: time.Since(start).Milliseconds(), UpdatedAt: now}
}

func (m *Manager) sampleTraffic() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for name, traffic := range m.traffic {
		traffic.UpdatedAt = time.Now()
		_, err := m.db.Exec(
			`INSERT INTO traffic_stats (node_name, upload_bytes, download_bytes, updated_at)
			 VALUES (?, ?, ?, ?)
			 ON CONFLICT(node_name) DO UPDATE SET upload_bytes = excluded.upload_bytes, download_bytes = excluded.download_bytes, updated_at = excluded.updated_at`,
			name, traffic.UploadBytes, traffic.DownloadBytes, traffic.UpdatedAt.Format(time.RFC3339),
		)
		if err != nil {
			log.Printf("persist traffic failed: %v", err)
		}
	}
}

func (m *Manager) persistConfigLocked(cfg Config) error {
	content, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	_, err = m.db.Exec(`INSERT INTO config_history (content, created_at) VALUES (?, ?)`, string(content), time.Now().Format(time.RFC3339))
	return err
}

func (m *Manager) saveConfigLocked() error {
	if m.configPath == "" {
		return nil
	}
	return SaveConfig(m.configPath, m.cfg)
}

func (m *Manager) commitLocked() error {
	if err := m.cfg.Validate(); err != nil {
		return err
	}
	if err := m.saveConfigLocked(); err != nil {
		return err
	}
	if err := m.persistConfigLocked(m.cfg); err != nil {
		return err
	}
	if err := m.persistRuntimeLocked(); err != nil {
		return err
	}
	return m.applyKernelLocked()
}

func (m *Manager) applyKernelLocked() error {
	inbounds, outbounds, routing := enabledRuntime(m.cfg.Inbounds, m.cfg.Outbounds, m.cfg.Routing)
	var err error
	inbounds, err = ensureInboundTLSAssets(inbounds)
	if err != nil {
		return err
	}
	state := RuntimeState{
		Inbounds:  inbounds,
		Outbounds: outbounds,
		Routing:   routing,
		Mihomo:    m.cfg.Mihomo,
	}
	data, err := m.kernel.GenerateConfig(state)
	if err != nil {
		return err
	}
	path := m.cfg.Kernel.ConfigPath
	if err := saveGeneratedFile(path, data); err != nil {
		return err
	}
	status := m.kernel.Status()
	if status.Running {
		return m.kernel.Reload(path)
	}
	return m.kernel.Start(path)
}

func (m *Manager) persistRuntimeLocked() error {
	now := time.Now().Format(time.RFC3339)
	tx, err := m.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM nodes`); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM routing_rules`); err != nil {
		return err
	}

	for _, inbound := range m.inbounds {
		health := m.health[inbound.Name]
		status := health.Status
		if status == "" {
			status = "unknown"
		}
		if _, err := tx.Exec(
			`INSERT INTO nodes (name, type, protocol, address, port, status, created_at, updated_at)
			 VALUES (?, 'inbound', ?, '', ?, ?, ?, ?)
			 ON CONFLICT(name) DO UPDATE SET protocol = excluded.protocol, port = excluded.port, status = excluded.status, updated_at = excluded.updated_at`,
			inbound.Name, inbound.Protocol, inbound.Port, status, now, now,
		); err != nil {
			return err
		}
	}
	for _, outbound := range m.outbounds {
		health := m.health[outbound.Name]
		status := health.Status
		if status == "" {
			status = "unknown"
		}
		if _, err := tx.Exec(
			`INSERT INTO nodes (name, type, protocol, address, port, status, created_at, updated_at)
			 VALUES (?, 'outbound', ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(name) DO UPDATE SET protocol = excluded.protocol, address = excluded.address, port = excluded.port, status = excluded.status, updated_at = excluded.updated_at`,
			outbound.Name, outbound.Protocol, outbound.Address, outbound.Port, status, now, now,
		); err != nil {
			return err
		}
	}
	for _, rule := range m.rules {
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO routing_rules (inbound, outbound, created_at) VALUES (?, ?, ?)`,
			rule.Inbound, rule.Outbound, now,
		); err != nil {
			return err
		}
	}
	for name, traffic := range m.traffic {
		if _, err := tx.Exec(
			`INSERT OR IGNORE INTO traffic_stats (node_name, upload_bytes, download_bytes, updated_at) VALUES (?, ?, ?, ?)`,
			name, traffic.UploadBytes, traffic.DownloadBytes, traffic.UpdatedAt.Format(time.RFC3339),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (m *Manager) ensureTrafficLocked(name string) {
	if _, ok := m.traffic[name]; !ok {
		m.traffic[name] = &Traffic{UpdatedAt: time.Now()}
	}
}

func (m *Manager) ensureHealthLocked(name string, disabled bool) {
	if _, ok := m.health[name]; ok {
		return
	}
	status := "unknown"
	errText := ""
	if disabled {
		status = "disabled"
		errText = "node disabled"
	}
	m.health[name] = Health{Status: status, LastError: errText, UpdatedAt: time.Now()}
}

func (m *Manager) nodeLocked(name string, nodeType string) Node {
	traffic := m.traffic[name]
	if nodeType == "inbound" {
		inbound := m.inbounds[name]
		return Node{
			Name:          inbound.Name,
			Type:          "inbound",
			Protocol:      inbound.Protocol,
			Address:       firstNonEmpty(inbound.Listen, "::"),
			Port:          inbound.Port,
			Enabled:       !inbound.Disabled,
			Status:        m.health[name].Status,
			LatencyMS:     m.health[name].LatencyMS,
			LastError:     m.health[name].LastError,
			UploadBytes:   traffic.UploadBytes,
			DownloadBytes: traffic.DownloadBytes,
			UpdatedAt:     traffic.UpdatedAt.Format(time.RFC3339),
		}
	}
	outbound := m.outbounds[name]
	return Node{
		Name:          outbound.Name,
		Type:          "outbound",
		Protocol:      outbound.Protocol,
		Address:       outbound.Address,
		Port:          outbound.Port,
		Enabled:       !outbound.Disabled,
		Status:        m.health[name].Status,
		LatencyMS:     m.health[name].LatencyMS,
		LastError:     m.health[name].LastError,
		UploadBytes:   traffic.UploadBytes,
		DownloadBytes: traffic.DownloadBytes,
		UpdatedAt:     traffic.UpdatedAt.Format(time.RFC3339),
	}
}

func saveGeneratedFile(path string, payload []byte) error {
	if path == "" {
		return nil
	}
	return os.WriteFile(path, payload, 0o644)
}

func kernelName(cfg KernelConfig) string {
	switch cfg.Type {
	case "sing-box":
		return "sing-box"
	case "mihomo":
		return "mihomo"
	default:
		return "placeholder"
	}
}

func upsertInboundConfig(items []InboundConfig, next InboundConfig) []InboundConfig {
	for i, item := range items {
		if item.Name == next.Name {
			items[i] = next
			return items
		}
	}
	return append(items, next)
}

func upsertOutboundConfig(items []OutboundConfig, next OutboundConfig) []OutboundConfig {
	for i, item := range items {
		if item.Name == next.Name {
			items[i] = next
			return items
		}
	}
	return append(items, next)
}

func deleteInboundConfig(items []InboundConfig, name string) []InboundConfig {
	next := items[:0]
	for _, item := range items {
		if item.Name != name {
			next = append(next, item)
		}
	}
	return next
}

func deleteOutboundConfig(items []OutboundConfig, name string) []OutboundConfig {
	next := items[:0]
	for _, item := range items {
		if item.Name != name {
			next = append(next, item)
		}
	}
	return next
}

func deleteRulesForNode(items []RoutingRule, nodeType, name string) []RoutingRule {
	next := items[:0]
	for _, item := range items {
		if nodeType == "inbound" && routingRuleMatchType(item) == "inbound" && routingRuleValue(item) == name {
			continue
		}
		if nodeType == "outbound" && item.Outbound == name {
			continue
		}
		next = append(next, item)
	}
	return next
}

func renameRoutingOutbound(items []RoutingRule, oldName, newName string) []RoutingRule {
	next := append([]RoutingRule(nil), items...)
	for i := range next {
		if next[i].Outbound == oldName {
			next[i].Outbound = newName
		}
	}
	return next
}

func (m *Manager) uniqueOutboundNameLocked(name string) string {
	name = sanitizeNodeName(name)
	if _, ok := m.outbounds[name]; !ok {
		return name
	}
	for i := 2; ; i++ {
		candidate := fmt.Sprintf("%s-%d", name, i)
		if _, ok := m.outbounds[candidate]; !ok {
			return candidate
		}
	}
}

func (m *Manager) findEquivalentOutboundLocked(outbound OutboundConfig) string {
	next := outboundSignature(outbound)
	for _, existing := range m.outbounds {
		if outboundSignature(existing) == next {
			return existing.Name
		}
	}
	return ""
}

func outboundSignature(outbound OutboundConfig) string {
	return fmt.Sprintf("%s|%s|%d|%s|%s|%s|%s|%s|%s|%s|%s",
		outbound.Protocol,
		outbound.Address,
		outbound.Port,
		outbound.Username,
		outbound.UUID,
		outbound.Password,
		outbound.Method,
		outbound.ServerName,
		outbound.PublicKey,
		outbound.ShortID,
		outbound.Transport,
	)
}

func nextRulePriority(rules []RoutingRule) int {
	maxPriority := 0
	for _, rule := range rules {
		if rule.Priority > maxPriority {
			maxPriority = rule.Priority
		}
	}
	return maxPriority + 10
}

func enabledRuntime(inbounds []InboundConfig, outbounds []OutboundConfig, routing RoutingConfig) ([]InboundConfig, []OutboundConfig, RoutingConfig) {
	enabledInbounds := make([]InboundConfig, 0, len(inbounds))
	enabledInboundNames := map[string]struct{}{}
	for _, inbound := range inbounds {
		if inbound.Disabled {
			continue
		}
		enabledInbounds = append(enabledInbounds, inbound)
		enabledInboundNames[inbound.Name] = struct{}{}
	}

	enabledOutbounds := make([]OutboundConfig, 0, len(outbounds))
	enabledOutboundNames := map[string]struct{}{}
	for _, outbound := range outbounds {
		if outbound.Disabled {
			continue
		}
		enabledOutbounds = append(enabledOutbounds, outbound)
		enabledOutboundNames[outbound.Name] = struct{}{}
	}

	enabledRules := make([]RoutingRule, 0, len(routing.Rules))
	for _, rule := range routing.Rules {
		if rule.Disabled {
			continue
		}
		if routingRuleMatchType(rule) == "inbound" {
			if _, ok := enabledInboundNames[routingRuleValue(rule)]; !ok {
				continue
			}
		}
		if rule.Outbound != "direct" {
			if _, ok := enabledOutboundNames[rule.Outbound]; !ok {
				continue
			}
		}
		enabledRules = append(enabledRules, rule)
	}
	defaultOutbound := routing.DefaultOutbound
	if defaultOutbound != "" && defaultOutbound != "direct" {
		if _, ok := enabledOutboundNames[defaultOutbound]; !ok {
			defaultOutbound = "direct"
		}
	}
	if defaultOutbound == "" {
		defaultOutbound = "direct"
	}
	return enabledInbounds, enabledOutbounds, RoutingConfig{
		Mode:            routing.Mode,
		Preset:          routing.Preset,
		DefaultOutbound: defaultOutbound,
		Rules:           enabledRules,
	}
}
