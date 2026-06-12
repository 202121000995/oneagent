package core

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

type RealityKeyPair struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

type InboundShareResponse struct {
	Name string `json:"name"`
	Link string `json:"link"`
}

func GenerateRealityKeyPair() (RealityKeyPair, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return RealityKeyPair{}, err
	}
	return RealityKeyPair{
		PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()),
		PublicKey:  base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
	}, nil
}

func publicKeyFromRealityPrivate(privateKey string) (string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(privateKey))
	if err != nil {
		return "", err
	}
	key, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

func (m *Manager) ShareInbound(name, publicHost string) (InboundShareResponse, error) {
	m.mu.RLock()
	inbound, ok := m.inbounds[name]
	m.mu.RUnlock()
	if !ok {
		return InboundShareResponse{}, fmt.Errorf("inbound %q does not exist", name)
	}
	link, err := inboundShareLink(inbound, publicHost)
	if err != nil {
		return InboundShareResponse{}, err
	}
	return InboundShareResponse{Name: name, Link: link}, nil
}

func (m *Manager) ShareOutbound(name string) (InboundShareResponse, error) {
	m.mu.RLock()
	outbound, ok := m.outbounds[name]
	m.mu.RUnlock()
	if !ok {
		return InboundShareResponse{}, fmt.Errorf("outbound %q does not exist", name)
	}
	link, err := outboundShareLink(outbound)
	if err != nil {
		return InboundShareResponse{}, err
	}
	return InboundShareResponse{Name: name, Link: link}, nil
}

func inboundShareLink(inbound InboundConfig, publicHost string) (string, error) {
	host := strings.TrimSpace(publicHost)
	if host == "" {
		host = "127.0.0.1"
	}
	hostPort := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		hostPort = net.JoinHostPort(host, strconv.Itoa(inbound.Port))
	}
	fragment := url.QueryEscape(inbound.Name)

	switch inbound.Protocol {
	case "vless":
		values := url.Values{}
		values.Set("encryption", "none")
		if inbound.Security == "reality" {
			publicKey, err := publicKeyFromRealityPrivate(inbound.PrivateKey)
			if err != nil {
				return "", fmt.Errorf("derive reality public key: %w", err)
			}
			values.Set("security", "reality")
			values.Set("sni", inbound.ServerName)
			values.Set("pbk", publicKey)
			if inbound.ShortID != "" {
				values.Set("sid", inbound.ShortID)
			}
		} else if inbound.TLS || inbound.ServerName != "" {
			values.Set("security", "tls")
			values.Set("sni", inbound.ServerName)
		} else {
			values.Set("security", "none")
		}
		if inbound.Flow != "" {
			values.Set("flow", inbound.Flow)
		}
		if inbound.Transport != "" && inbound.Transport != "tcp" {
			values.Set("type", inbound.Transport)
		} else {
			values.Set("type", "tcp")
		}
		if inbound.Path != "" {
			values.Set("path", inbound.Path)
		}
		if inbound.Host != "" {
			values.Set("host", inbound.Host)
		}
		return "vless://" + inbound.UUID + "@" + hostPort + "?" + values.Encode() + "#" + fragment, nil
	case "anytls":
		values := url.Values{}
		values.Set("peer", inbound.ServerName)
		if inbound.TLS || inbound.ServerName != "" {
			values.Set("security", "tls")
		}
		return "anytls://" + url.QueryEscape(inbound.Password) + "@" + hostPort + "?" + values.Encode() + "#" + fragment, nil
	case "trojan":
		values := url.Values{}
		if inbound.TLS || inbound.ServerName != "" {
			values.Set("security", "tls")
			values.Set("sni", inbound.ServerName)
		}
		if inbound.Transport != "" && inbound.Transport != "tcp" {
			values.Set("type", inbound.Transport)
		}
		addQueryValue(values, "path", inbound.Path)
		addQueryValue(values, "host", inbound.Host)
		return "trojan://" + url.QueryEscape(inbound.Password) + "@" + hostPort + "?" + values.Encode() + "#" + fragment, nil
	case "vmess":
		values := url.Values{}
		values.Set("encryption", "auto")
		if inbound.TLS || inbound.ServerName != "" {
			values.Set("security", "tls")
			values.Set("sni", inbound.ServerName)
		}
		if inbound.Transport != "" && inbound.Transport != "tcp" {
			values.Set("type", inbound.Transport)
		}
		addQueryValue(values, "path", inbound.Path)
		addQueryValue(values, "host", inbound.Host)
		return "vmess://" + inbound.UUID + "@" + hostPort + "?" + values.Encode() + "#" + fragment, nil
	case "shadowsocks", "ss":
		userInfo := base64.RawURLEncoding.EncodeToString([]byte(inbound.Method + ":" + inbound.Password))
		return "ss://" + userInfo + "@" + hostPort + "#" + fragment, nil
	case "shadowtls":
		values := url.Values{}
		values.Set("version", "3")
		values.Set("security", "tls")
		values.Set("sni", inbound.ServerName)
		addQueryValue(values, "handshake", inbound.RealityHandshakeServer)
		if inbound.RealityHandshakePort > 0 {
			values.Set("handshake_port", strconv.Itoa(inbound.RealityHandshakePort))
		}
		return "shadowtls://:" + url.QueryEscape(inbound.Password) + "@" + hostPort + "?" + values.Encode() + "#" + fragment, nil
	default:
		return "", fmt.Errorf("share link is not supported for inbound protocol %s", inbound.Protocol)
	}
}

func outboundShareLink(outbound OutboundConfig) (string, error) {
	if strings.TrimSpace(outbound.Raw) != "" && strings.Contains(outbound.Raw, "://") {
		return strings.TrimSpace(outbound.Raw), nil
	}
	if outbound.Address == "" || outbound.Port <= 0 {
		return "", fmt.Errorf("outbound %s has no server address or port", outbound.Name)
	}

	hostPort := net.JoinHostPort(outbound.Address, strconv.Itoa(outbound.Port))
	fragment := url.QueryEscape(outbound.Name)

	switch outbound.Protocol {
	case "vless":
		values := url.Values{}
		values.Set("encryption", "none")
		if outbound.Security == "reality" {
			values.Set("security", "reality")
			addQueryValue(values, "sni", outbound.ServerName)
			addQueryValue(values, "pbk", outbound.PublicKey)
			addQueryValue(values, "sid", outbound.ShortID)
			addQueryValue(values, "fp", outbound.Fingerprint)
		} else if outbound.TLS || outbound.ServerName != "" {
			values.Set("security", "tls")
			addQueryValue(values, "sni", outbound.ServerName)
		} else {
			values.Set("security", "none")
		}
		addQueryValue(values, "flow", outbound.Flow)
		addTransportQuery(values, outbound.Transport, outbound.Path, outbound.Host)
		return "vless://" + url.QueryEscape(outbound.UUID) + "@" + hostPort + "?" + values.Encode() + "#" + fragment, nil
	case "vmess":
		payload := map[string]string{
			"v":    "2",
			"ps":   outbound.Name,
			"add":  outbound.Address,
			"port": strconv.Itoa(outbound.Port),
			"id":   outbound.UUID,
			"aid":  strconv.Itoa(outbound.AlterID),
			"scy":  outbound.Security,
			"net":  outbound.Transport,
			"type": "none",
			"host": outbound.Host,
			"path": outbound.Path,
			"tls":  "",
			"sni":  outbound.ServerName,
		}
		if payload["scy"] == "" {
			payload["scy"] = "auto"
		}
		if payload["net"] == "" {
			payload["net"] = "tcp"
		}
		if outbound.TLS || outbound.ServerName != "" {
			payload["tls"] = "tls"
		}
		raw, err := json.Marshal(payload)
		if err != nil {
			return "", err
		}
		return "vmess://" + base64.StdEncoding.EncodeToString(raw), nil
	case "trojan":
		values := url.Values{}
		if outbound.TLS || outbound.ServerName != "" {
			values.Set("security", "tls")
			addQueryValue(values, "sni", outbound.ServerName)
		}
		addTransportQuery(values, outbound.Transport, outbound.Path, outbound.Host)
		return "trojan://" + url.QueryEscape(outbound.Password) + "@" + hostPort + "?" + values.Encode() + "#" + fragment, nil
	case "shadowsocks", "ss":
		userInfo := base64.RawURLEncoding.EncodeToString([]byte(outbound.Method + ":" + outbound.Password))
		return "ss://" + userInfo + "@" + hostPort + "#" + fragment, nil
	case "shadowtls":
		values := url.Values{}
		values.Set("version", "3")
		values.Set("security", "tls")
		addQueryValue(values, "sni", outbound.ServerName)
		return "shadowtls://:" + url.QueryEscape(outbound.Password) + "@" + hostPort + "?" + values.Encode() + "#" + fragment, nil
	case "anytls":
		values := url.Values{}
		addQueryValue(values, "peer", outbound.ServerName)
		return "anytls://" + url.QueryEscape(outbound.Password) + "@" + hostPort + "?" + values.Encode() + "#" + fragment, nil
	case "hysteria2", "hy2":
		values := url.Values{}
		addQueryValue(values, "peer", outbound.ServerName)
		addQueryValue(values, "obfs", outbound.Obfs)
		addQueryValue(values, "obfs-password", outbound.ObfsPassword)
		addQueryValue(values, "mport", outbound.MPort)
		if outbound.UpMbps > 0 {
			values.Set("upmbps", strconv.Itoa(outbound.UpMbps))
		}
		if outbound.DownMbps > 0 {
			values.Set("downmbps", strconv.Itoa(outbound.DownMbps))
		}
		return "hysteria2://" + url.QueryEscape(outbound.Password) + "@" + hostPort + "?" + values.Encode() + "#" + fragment, nil
	case "tuic":
		values := url.Values{}
		addQueryValue(values, "peer", outbound.ServerName)
		addQueryValue(values, "congestion_control", outbound.Congestion)
		addQueryValue(values, "udp_relay_mode", outbound.UDPRelayMode)
		addQueryValue(values, "alpn", outbound.ALPN)
		return "tuic://" + url.QueryEscape(outbound.UUID) + ":" + url.QueryEscape(outbound.Password) + "@" + hostPort + "?" + values.Encode() + "#" + fragment, nil
	case "http", "socks", "socks5":
		scheme := outbound.Protocol
		if scheme == "socks" {
			scheme = "socks5"
		}
		u := url.URL{Scheme: scheme, Host: hostPort, Fragment: outbound.Name}
		if outbound.Username != "" || outbound.Password != "" {
			u.User = url.UserPassword(outbound.Username, outbound.Password)
		}
		return u.String(), nil
	default:
		return "", fmt.Errorf("share link is not supported for outbound protocol %s", outbound.Protocol)
	}
}

func addTransportQuery(values url.Values, transport, path, host string) {
	if transport != "" && transport != "tcp" {
		values.Set("type", transport)
	}
	addQueryValue(values, "path", path)
	addQueryValue(values, "host", host)
}

func addQueryValue(values url.Values, key, value string) {
	if value != "" {
		values.Set(key, value)
	}
}
