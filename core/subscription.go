package core

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const maxSubscriptionBytes = 2 << 20

type SubscriptionPreviewRequest struct {
	URL string `json:"url"`
}

type SubscriptionPreview struct {
	URL           string   `json:"url"`
	Format        string   `json:"format"`
	ProxyCount    int      `json:"proxy_count"`
	GroupCount    int      `json:"group_count"`
	RuleCount     int      `json:"rule_count"`
	ProviderCount int      `json:"provider_count"`
	ProxyNames    []string `json:"proxy_names"`
	GroupNames    []string `json:"group_names"`
	Warnings      []string `json:"warnings,omitempty"`
}

func PreviewSubscription(url string) (SubscriptionPreview, error) {
	url = strings.TrimSpace(url)
	if url == "" {
		return SubscriptionPreview{}, fmt.Errorf("url is required")
	}
	body, err := fetchSubscription(url)
	if err != nil {
		return SubscriptionPreview{}, err
	}
	return ParseSubscription(url, body)
}

func ParseSubscription(url string, body []byte) (SubscriptionPreview, error) {
	text := strings.TrimSpace(string(body))
	if text == "" {
		return SubscriptionPreview{}, fmt.Errorf("subscription is empty")
	}

	preview, err := parseYAMLSubscription(url, []byte(text))
	if err == nil && (preview.ProxyCount > 0 || preview.GroupCount > 0 || preview.RuleCount > 0 || preview.ProviderCount > 0) {
		return preview, nil
	}

	decoded, decodeErr := base64.StdEncoding.DecodeString(normalizeBase64(text))
	if decodeErr == nil {
		if preview, err := parseYAMLSubscription(url, decoded); err == nil && (preview.ProxyCount > 0 || preview.GroupCount > 0 || preview.RuleCount > 0 || preview.ProviderCount > 0) {
			preview.Format = "base64-yaml"
			return preview, nil
		}
		return parseURIList(url, string(decoded)), nil
	}
	return parseURIList(url, text), nil
}

func fetchSubscription(url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "NodeToolsAgent/1.0")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("subscription returned status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxSubscriptionBytes))
}

func parseYAMLSubscription(url string, body []byte) (SubscriptionPreview, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(body, &raw); err != nil {
		return SubscriptionPreview{}, err
	}
	preview := SubscriptionPreview{URL: url, Format: "yaml"}
	preview.ProxyNames = namesFromList(raw["proxies"])
	preview.GroupNames = namesFromList(raw["proxy-groups"])
	preview.ProxyCount = len(preview.ProxyNames)
	preview.GroupCount = len(preview.GroupNames)
	preview.RuleCount = len(stringList(raw["rules"]))
	if providers, ok := raw["proxy-providers"].(map[string]any); ok {
		preview.ProviderCount = len(providers)
	}
	if preview.ProxyCount == 0 && preview.ProviderCount == 0 {
		preview.Warnings = append(preview.Warnings, "未发现 proxies 或 proxy-providers")
	}
	return preview, nil
}

func parseURIList(url, body string) SubscriptionPreview {
	preview := SubscriptionPreview{URL: url, Format: "uri-list"}
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		switch {
		case strings.HasPrefix(line, "ss://"),
			strings.HasPrefix(line, "ssr://"),
			strings.HasPrefix(line, "vmess://"),
			strings.HasPrefix(line, "vless://"),
			strings.HasPrefix(line, "trojan://"),
			strings.HasPrefix(line, "hysteria2://"),
			strings.HasPrefix(line, "hy2://"):
			preview.ProxyCount++
			preview.ProxyNames = append(preview.ProxyNames, uriDisplayName(line))
		}
	}
	if preview.ProxyCount == 0 {
		preview.Warnings = append(preview.Warnings, "未识别到 YAML 订阅或 URI 节点")
	}
	return preview
}

func normalizeBase64(value string) string {
	value = strings.ReplaceAll(value, "\n", "")
	value = strings.ReplaceAll(value, "\r", "")
	if padding := len(value) % 4; padding != 0 {
		value += strings.Repeat("=", 4-padding)
	}
	return value
}

func namesFromList(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(items))
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		if name != "" {
			names = append(names, name)
		}
	}
	return names
}

func stringList(value any) []string {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if value, ok := item.(string); ok {
			out = append(out, value)
		}
	}
	return out
}

func uriDisplayName(line string) string {
	if idx := strings.LastIndex(line, "#"); idx >= 0 && idx+1 < len(line) {
		name := strings.TrimSpace(line[idx+1:])
		if name != "" {
			return name
		}
	}
	if idx := strings.Index(line, "://"); idx >= 0 {
		return line[:idx]
	}
	return "node"
}
