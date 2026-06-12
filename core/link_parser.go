package core

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type ImportLinksRequest struct {
	Text string `json:"text"`
}

type ImportLinksResponse struct {
	Imported []Node   `json:"imported"`
	Parsed   int      `json:"parsed"`
	Errors   []string `json:"errors,omitempty"`
}

func ParseOutboundLinks(text string) ([]OutboundConfig, []string) {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil, []string{"empty input"}
	}

	var outbounds []OutboundConfig
	var errors []string
	if yamlOutbounds := parseOutboundYAML(text); len(yamlOutbounds) > 0 {
		return uniqueOutbounds(yamlOutbounds), nil
	}
	for _, item := range extractLinkCandidates(text) {
		parsed, err := parseOutboundLink(item)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		outbounds = append(outbounds, parsed)
	}
	if len(outbounds) == 0 {
		if decoded, ok := decodeBase64String(text); ok {
			return ParseOutboundLinks(decoded)
		}
	}
	return uniqueOutbounds(outbounds), errors
}

func extractLinkCandidates(text string) []string {
	var candidates []string
	for _, line := range strings.Fields(text) {
		line = strings.TrimSpace(strings.Trim(line, `"'`))
		if strings.Contains(line, "://") {
			candidates = append(candidates, line)
		}
	}
	if len(candidates) > 0 {
		return candidates
	}
	if decoded, ok := decodeBase64String(text); ok {
		return extractLinkCandidates(decoded)
	}
	return nil
}

func parseOutboundYAML(text string) []OutboundConfig {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(text), &root); err != nil {
		var list []any
		if listErr := yaml.Unmarshal([]byte(text), &list); listErr != nil {
			return nil
		}
		return parseYAMLProxyList(list)
	}
	rawProxies, ok := root["proxies"].([]any)
	if ok {
		return parseYAMLProxyList(rawProxies)
	}
	rawOutbounds, ok := root["outbounds"].([]any)
	if ok {
		return parseSingBoxOutboundList(rawOutbounds)
	}
	return nil
}

func parseYAMLProxyList(rawProxies []any) []OutboundConfig {
	outbounds := make([]OutboundConfig, 0, len(rawProxies))
	for _, rawProxy := range rawProxies {
		proxy, ok := rawProxy.(map[string]any)
		if !ok {
			continue
		}
		out := OutboundConfig{
			Name:           stringValue(proxy["name"]),
			Protocol:       normalizeYAMLProtocol(stringValue(proxy["type"])),
			Address:        stringValue(proxy["server"]),
			Port:           intValue(proxy["port"]),
			Username:       stringValue(proxy["username"]),
			UUID:           stringValue(proxy["uuid"]),
			Password:       firstNonEmpty(stringValue(proxy["password"]), stringValue(proxy["passwd"])),
			Method:         firstNonEmpty(stringValue(proxy["cipher"]), stringValue(proxy["method"])),
			Flow:           stringValue(proxy["flow"]),
			Security:       firstNonEmpty(stringValue(proxy["security"]), stringValue(proxy["cipher"])),
			AlterID:        intValue(firstNonEmptyAny(proxy["alterId"], proxy["alter_id"], proxy["aid"])),
			Network:        stringValue(proxy["network"]),
			TLS:            boolValue(proxy["tls"]),
			ServerName:     firstNonEmpty(stringValue(proxy["servername"]), stringValue(proxy["sni"]), stringValue(proxy["peer"])),
			SkipCertVerify: boolValue(firstNonEmptyAny(proxy["skip-cert-verify"], proxy["skip_cert_verify"])),
			PublicKey:      firstNonEmpty(stringValue(proxy["public-key"]), stringValue(proxy["public_key"]), stringValue(proxy["pbk"])),
			ShortID:        firstNonEmpty(stringValue(proxy["short-id"]), stringValue(proxy["short_id"]), stringValue(proxy["sid"])),
			Fingerprint:    firstNonEmpty(stringValue(proxy["client-fingerprint"]), stringValue(proxy["fingerprint"]), stringValue(proxy["fp"])),
			ALPN:           stringListValue(proxy["alpn"]),
			Obfs:           stringValue(proxy["obfs"]),
			MPort:          firstNonEmpty(stringValue(proxy["mport"]), stringValue(proxy["ports"])),
			UpMbps:         intValue(firstNonEmptyAny(proxy["up"], proxy["upmbps"])),
			DownMbps:       intValue(firstNonEmptyAny(proxy["down"], proxy["downmbps"])),
			Congestion:     firstNonEmpty(stringValue(proxy["congestion-controller"]), stringValue(proxy["congestion_control"])),
			UDPRelayMode:   firstNonEmpty(stringValue(proxy["udp-relay-mode"]), stringValue(proxy["udp_relay_mode"])),
		}
		if out.Protocol == "shadowsocks" && out.Method == "" {
			out.Method = stringValue(proxy["cipher"])
		}
		if out.Network == "ws" {
			out.Transport = "ws"
			if opts, ok := proxy["ws-opts"].(map[string]any); ok {
				out.Path = stringValue(opts["path"])
				if headers, ok := opts["headers"].(map[string]any); ok {
					out.Host = stringValue(headers["Host"])
				}
			}
		}
		if opts, ok := proxy["reality-opts"].(map[string]any); ok {
			out.Security = "reality"
			out.TLS = true
			out.PublicKey = firstNonEmpty(out.PublicKey, stringValue(opts["public-key"]), stringValue(opts["public_key"]))
			out.ShortID = firstNonEmpty(out.ShortID, stringValue(opts["short-id"]), stringValue(opts["short_id"]))
		}
		if plugin := stringValue(proxy["plugin"]); plugin == "shadow-tls" {
			out.Transport = "shadowtls"
			if opts, ok := proxy["plugin-opts"].(map[string]any); ok {
				out.ObfsPassword = stringValue(opts["password"])
				out.ServerName = firstNonEmpty(out.ServerName, stringValue(opts["host"]))
			}
		}
		if out.Name != "" && out.Address != "" && out.Port > 0 {
			outbounds = append(outbounds, out)
		}
	}
	return outbounds
}

func parseSingBoxOutboundList(rawOutbounds []any) []OutboundConfig {
	outbounds := make([]OutboundConfig, 0, len(rawOutbounds))
	for _, rawOutbound := range rawOutbounds {
		item, ok := rawOutbound.(map[string]any)
		if !ok {
			continue
		}
		out := OutboundConfig{
			Name:         firstNonEmpty(stringValue(item["tag"]), stringValue(item["name"])),
			Protocol:     normalizeLinkProtocol(stringValue(item["type"])),
			Address:      stringValue(item["server"]),
			Port:         intValue(item["server_port"]),
			Username:     stringValue(item["username"]),
			UUID:         stringValue(item["uuid"]),
			Password:     stringValue(item["password"]),
			Method:       stringValue(item["method"]),
			Flow:         stringValue(item["flow"]),
			Security:     stringValue(item["security"]),
			AlterID:      intValue(item["alter_id"]),
			Network:      stringValue(item["network"]),
			Transport:    stringValue(item["network"]),
			UpMbps:       intValue(item["up_mbps"]),
			DownMbps:     intValue(item["down_mbps"]),
			Congestion:   stringValue(item["congestion_control"]),
			UDPRelayMode: stringValue(item["udp_relay_mode"]),
		}
		if transport, ok := item["transport"].(map[string]any); ok {
			out.Transport = stringValue(transport["type"])
			out.Path = stringValue(transport["path"])
			if headers, ok := transport["headers"].(map[string]any); ok {
				out.Host = firstNonEmpty(stringValue(headers["Host"]), stringListValue(headers["Host"]))
			}
		}
		if tls, ok := item["tls"].(map[string]any); ok {
			out.TLS = boolValue(tls["enabled"])
			out.ServerName = stringValue(tls["server_name"])
			if utls, ok := tls["utls"].(map[string]any); ok {
				out.Fingerprint = stringValue(utls["fingerprint"])
			}
			if reality, ok := tls["reality"].(map[string]any); ok {
				out.Security = "reality"
				out.TLS = true
				out.PublicKey = stringValue(reality["public_key"])
				out.ShortID = stringValue(reality["short_id"])
			}
		}
		if out.Name != "" && out.Address != "" && out.Port > 0 && out.Protocol != "direct" {
			outbounds = append(outbounds, out)
		}
	}
	return outbounds
}

func parseOutboundLink(raw string) (OutboundConfig, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return OutboundConfig{}, err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme == "" {
		return OutboundConfig{}, fmt.Errorf("missing scheme in %q", raw)
	}

	if u.Host == "" && u.Opaque != "" {
		decoded, ok := decodeBase64String(u.Opaque)
		if ok {
			if strings.HasPrefix(strings.TrimSpace(decoded), "{") {
				return parseJSONShare(scheme, decoded, raw)
			}
			return parseOutboundLink(scheme + "://" + decoded + "?" + u.RawQuery + "#" + u.RawFragment)
		}
	}
	if scheme == "v2rayn" {
		protocol := u.Host
		payload := strings.TrimPrefix(u.Path, "/")
		decoded, ok := decodeBase64String(payload)
		if !ok {
			return OutboundConfig{}, fmt.Errorf("invalid v2rayn payload in %q", raw)
		}
		return parseJSONShare(protocol, decoded, raw)
	}
	if decoded, ok := decodeBase64String(u.Host); ok {
		if strings.Contains(decoded, "@") {
			return parseOutboundLink(scheme + "://" + decoded + "?" + u.RawQuery + "#" + u.RawFragment)
		}
		if strings.HasPrefix(strings.TrimSpace(decoded), "{") {
			return parseJSONShare(scheme, decoded, raw)
		}
	}

	query := u.Query()
	name := linkName(u, scheme)
	host := u.Hostname()
	port := parsePort(u.Port())
	user := ""
	password := ""
	if u.User != nil {
		user = u.User.Username()
		password, _ = u.User.Password()
	}

	out := OutboundConfig{
		Name:         name,
		Protocol:     normalizeLinkProtocol(scheme),
		Address:      host,
		Port:         port,
		Raw:          raw,
		Flow:         firstNonEmpty(query.Get("flow"), xtlsFlow(query.Get("xtls"))),
		ServerName:   firstNonEmpty(query.Get("peer"), query.Get("sni"), query.Get("servername"), query.Get("host")),
		PublicKey:    firstNonEmpty(query.Get("pbk"), query.Get("public-key"), query.Get("public_key")),
		ShortID:      firstNonEmpty(query.Get("sid"), query.Get("short-id"), query.Get("short_id")),
		Fingerprint:  firstNonEmpty(query.Get("fp"), query.Get("fingerprint")),
		ALPN:         query.Get("alpn"),
		Path:         firstNonEmpty(query.Get("path"), query.Get("serviceName"), query.Get("service_name")),
		Host:         firstNonEmpty(query.Get("obfsParam"), query.Get("host")),
		Obfs:         query.Get("obfs"),
		ObfsPassword: firstNonEmpty(query.Get("obfs-password"), query.Get("obfs_password")),
		MPort:        query.Get("mport"),
		UpMbps:       atoiDefault(firstNonEmpty(query.Get("upmbps"), query.Get("up")), 0),
		DownMbps:     atoiDefault(firstNonEmpty(query.Get("downmbps"), query.Get("down")), 0),
		Congestion:   query.Get("congestion_control"),
		UDPRelayMode: query.Get("udp_relay_mode"),
	}
	if query.Get("tls") == "1" || strings.EqualFold(query.Get("security"), "tls") || strings.EqualFold(query.Get("security"), "reality") || out.ServerName != "" {
		out.TLS = true
	}
	if query.Get("allowInsecure") == "1" || query.Get("allow_insecure") == "1" || query.Get("insecure") == "1" {
		out.SkipCertVerify = true
	}
	if strings.EqualFold(query.Get("security"), "reality") || out.PublicKey != "" {
		out.Security = "reality"
		out.TLS = true
	}
	switch out.Obfs {
	case "websocket":
		out.Transport = "ws"
	case "h2":
		out.Transport = "http"
	case "grpc":
		out.Transport = "grpc"
	default:
		out.Transport = query.Get("type")
	}

	switch scheme {
	case "vless", "vmess":
		out.UUID = firstNonEmpty(password, user)
		out.Security = firstNonEmpty(out.Security, query.Get("security"), query.Get("encryption"), query.Get("cipher"), "auto")
		out.AlterID = atoiDefault(firstNonEmpty(query.Get("alterId"), query.Get("alterid"), query.Get("aid")), 0)
	case "trojan", "hysteria2", "hy2", "anytls", "shadowtls":
		out.Password = user
		if password != "" {
			out.Password = password
		}
	case "tuic":
		out.UUID = user
		out.Password = password
	case "ss":
		method, pass := parseSSUserinfo(user, password)
		out.Method = method
		out.Password = pass
		if shadowTLS := query.Get("shadow-tls"); shadowTLS != "" {
			out.Transport = "shadowtls"
			if decoded, ok := decodeBase64String(shadowTLS); ok {
				var shadow map[string]any
				if err := json.Unmarshal([]byte(decoded), &shadow); err == nil {
					out.ObfsPassword = stringValue(shadow["password"])
					out.ServerName = firstNonEmpty(out.ServerName, stringValue(shadow["host"]))
					out.TLS = true
				} else {
					out.ObfsPassword = decoded
				}
			}
		}
	case "http2", "http3", "naive", "https", "naive+https", "naive+quic":
		out.Protocol = "naive"
		out.Username = user
		out.Password = password
		out.Transport = scheme
	}
	if out.Port == 0 {
		return OutboundConfig{}, fmt.Errorf("missing port in %q", raw)
	}
	if out.Address == "" {
		return OutboundConfig{}, fmt.Errorf("missing server in %q", raw)
	}
	return out, nil
}

func parseJSONShare(protocol string, payload string, raw string) (OutboundConfig, error) {
	var data map[string]any
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		return OutboundConfig{}, err
	}
	protocol = normalizeLinkProtocol(protocol)
	name := firstNonEmpty(stringValue(data["Remarks"]), stringValue(data["remarks"]), stringValue(data["ps"]), protocol+"-"+stringValue(data["Address"]), protocol+"-"+stringValue(data["add"]))
	address := firstNonEmpty(stringValue(data["Address"]), stringValue(data["add"]), stringValue(data["server"]))
	port := intValue(firstNonEmptyAny(data["Port"], data["port"]))
	out := OutboundConfig{
		Name:        name,
		Protocol:    protocol,
		Address:     address,
		Port:        port,
		Username:    stringValue(data["Username"]),
		UUID:        firstNonEmpty(stringValue(data["id"]), stringValue(data["uuid"])),
		Password:    firstNonEmpty(stringValue(data["Password"]), stringValue(data["password"])),
		Flow:        firstNonEmpty(stringValue(data["Flow"]), stringValue(data["flow"])),
		Security:    firstNonEmpty(stringValue(data["StreamSecurity"]), stringValue(data["security"]), stringValue(data["scy"])),
		ServerName:  firstNonEmpty(stringValue(data["Sni"]), stringValue(data["sni"]), stringValue(data["servername"])),
		Fingerprint: firstNonEmpty(stringValue(data["Fingerprint"]), stringValue(data["fp"])),
		PublicKey:   firstNonEmpty(stringValue(data["PublicKey"]), stringValue(data["pbk"])),
		ShortID:     firstNonEmpty(stringValue(data["ShortId"]), stringValue(data["sid"])),
		Network:     firstNonEmpty(stringValue(data["Network"]), stringValue(data["net"])),
		Transport:   firstNonEmpty(stringValue(data["Network"]), stringValue(data["net"])),
		Path:        stringValue(data["path"]),
		Host:        stringValue(data["host"]),
		AlterID:     intValue(firstNonEmptyAny(data["alterId"], data["aid"])),
		Raw:         raw,
	}
	if out.Protocol == "vless" || out.Protocol == "vmess" {
		out.UUID = firstNonEmpty(out.UUID, out.Username, out.Password)
	}
	if out.Protocol == "tuic" {
		out.UUID = firstNonEmpty(out.UUID, out.Username)
	}
	if out.Security == "tls" || out.Security == "reality" || out.ServerName != "" {
		out.TLS = true
	}
	if extra, ok := data["ProtoExtraObj"].(map[string]any); ok {
		out.UpMbps = intValue(extra["UpMbps"])
		out.DownMbps = intValue(extra["DownMbps"])
		out.MPort = stringValue(extra["Ports"])
		out.Congestion = stringValue(extra["CongestionControl"])
		if boolValue(extra["NaiveQuic"]) {
			out.Transport = "naive+quic"
		}
	}
	if out.Address == "" || out.Port == 0 {
		return OutboundConfig{}, fmt.Errorf("incomplete json share %q", raw)
	}
	return out, nil
}

func parseSSUserinfo(user, password string) (string, string) {
	if decoded, ok := decodeBase64String(user); ok && strings.Contains(decoded, ":") {
		user = decoded
	}
	if password != "" {
		return user, password
	}
	parts := strings.SplitN(user, ":", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return user, password
}

func linkName(u *url.URL, fallback string) string {
	for _, key := range []string{"remarks", "name"} {
		if value := strings.TrimSpace(u.Query().Get(key)); value != "" {
			return value
		}
	}
	if fragment := strings.TrimSpace(u.Fragment); fragment != "" {
		if decoded, err := url.QueryUnescape(fragment); err == nil {
			return decoded
		}
		return fragment
	}
	host := u.Hostname()
	if host == "" {
		host = fallback
	}
	return fallback + "-" + host
}

func normalizeLinkProtocol(scheme string) string {
	switch scheme {
	case "hy2":
		return "hysteria2"
	case "ss":
		return "shadowsocks"
	case "http2", "http3", "https", "naive":
		return "naive"
	case "naive+https", "naive+quic":
		return "naive"
	case "shadowtls":
		return "shadowtls"
	default:
		return scheme
	}
}

func normalizeYAMLProtocol(value string) string {
	switch value {
	case "ss":
		return "shadowsocks"
	case "socks5":
		return "socks"
	default:
		return value
	}
}

func xtlsFlow(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "2", "vision", "xtls-rprx-vision":
		return "xtls-rprx-vision"
	case "1", "direct", "xtls-rprx-direct":
		return "xtls-rprx-direct"
	default:
		return strings.TrimSpace(value)
	}
}

func parsePort(port string) int {
	if port == "" {
		return 0
	}
	value, _ := strconv.Atoi(port)
	return value
}

func atoiDefault(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func decodeBase64String(value string) (string, bool) {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "\n", "")
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.TrimRight(value, "=")
	encodings := []*base64.Encoding{base64.RawURLEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.StdEncoding}
	for _, encoding := range encodings {
		decoded, err := encoding.DecodeString(value)
		if err == nil && len(decoded) > 0 {
			return string(decoded), true
		}
	}
	return "", false
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case fmt.Stringer:
		return typed.String()
	default:
		return ""
	}
}

func stringListValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case []string:
		return strings.Join(typed, ",")
	case []any:
		parts := make([]string, 0, len(typed))
		for _, item := range typed {
			if part := stringValue(item); part != "" {
				parts = append(parts, part)
			}
		}
		return strings.Join(parts, ",")
	default:
		return ""
	}
}

func intValue(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case string:
		return atoiDefault(leadingNumber(typed), 0)
	default:
		return 0
	}
}

func leadingNumber(value string) string {
	value = strings.TrimSpace(value)
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	return value[:end]
}

func boolValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return typed == "1" || strings.EqualFold(typed, "true")
	default:
		return false
	}
}

func firstNonEmptyAny(values ...any) any {
	for _, value := range values {
		switch typed := value.(type) {
		case string:
			if typed != "" {
				return typed
			}
		case nil:
		default:
			return typed
		}
	}
	return nil
}

func uniqueOutbounds(items []OutboundConfig) []OutboundConfig {
	seen := map[string]int{}
	for i := range items {
		name := strings.TrimSpace(items[i].Name)
		if name == "" {
			name = items[i].Protocol + "-" + items[i].Address
		}
		if count := seen[name]; count > 0 {
			seen[name] = count + 1
			items[i].Name = fmt.Sprintf("%s-%d", name, count+1)
		} else {
			seen[name] = 1
			items[i].Name = name
		}
		items[i].Name = sanitizeNodeName(items[i].Name)
	}
	return items
}

func sanitizeNodeName(name string) string {
	name = strings.TrimSpace(name)
	name = strings.ReplaceAll(name, "\n", " ")
	if len(name) > 80 {
		return name[:80]
	}
	return name
}

func splitHostPortLoose(value string) (string, int) {
	host, portText, err := net.SplitHostPort(value)
	if err == nil {
		return host, parsePort(portText)
	}
	idx := strings.LastIndex(value, ":")
	if idx <= 0 {
		return value, 0
	}
	return value[:idx], parsePort(value[idx+1:])
}
