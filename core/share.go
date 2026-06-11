package core

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
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
	default:
		return "", fmt.Errorf("share link is not supported for inbound protocol %s", inbound.Protocol)
	}
}
