package core

import "testing"

func TestParseOutboundLinksSupportsCommonShareLinks(t *testing.T) {
	input := `
vless://YXV0bzpjYmYzNzhlZi1iYmY4LTQ1MzktYTU2NC0zMWM2ZjAxNzMxNDJANDUuMTM5LjE5My4xODc6ODg4MQ==?remarks=US%20xtls-reality&tls=1&peer=addons.mozilla.org&xtls=2&pbk=qgjFWDDlYP2DZJpWSp8SZ7wefup7LVRT4dYFxIK9LQs
hysteria2://cbf378ef-bbf8-4539-a564-31c6f0173142@45.139.193.187:8882?peer=addons.mozilla.org&obfs=none&upmbps=200&downmbps=1000&mport=8882,50000-51000#US%20hysteria2
tuic://cbf378ef-bbf8-4539-a564-31c6f0173142:cbf378ef-bbf8-4539-a564-31c6f0173142@45.139.193.187:8883?peer=addons.mozilla.org&congestion_control=bbr&udp_relay_mode=native&alpn=h3#US%20tuic
ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206bWRyMFZxb3JWaXdiTzlkUDZSM3o0QT09QDQ1LjEzOS4xOTMuMTg3Ojg4ODU=#US%20shadowsocks
trojan://cbf378ef-bbf8-4539-a564-31c6f0173142@45.139.193.187:8886?peer=addons.mozilla.org#US%20trojan
vmess://YXV0bzpjYmYzNzhlZi1iYmY4LTQ1MzktYTU2NC0zMWM2ZjAxNzMxNDJAc2trLm1vZTo4MA==?remarks=US%20vmess-ws&obfsParam=cdn.example.com&path=/vmess&obfs=websocket&alterId=0
anytls://cbf378ef-bbf8-4539-a564-31c6f0173142@45.139.193.187:8891?peer=addons.mozilla.org&udp=1#US%20anytls
http2://Y2JmMzc4ZWYtYmJmOC00NTM5LWE1NjQtMzFjNmYwMTczMTQyOmNiZjM3OGVmLWJiZjgtNDUzOS1hNTY0LTMxYzZmMDE3MzE0MkA0NS4xMzkuMTkzLjE4Nzo4ODky?peer=addons.mozilla.org&alpn=h2,http/1.1#US%20naive%20http2
`
	outbounds, errors := ParseOutboundLinks(input)
	if len(errors) != 0 {
		t.Fatalf("unexpected parse errors: %#v", errors)
	}
	if len(outbounds) != 8 {
		t.Fatalf("expected 8 outbounds, got %d: %#v", len(outbounds), outbounds)
	}
	byProtocol := map[string]bool{}
	for _, outbound := range outbounds {
		byProtocol[outbound.Protocol] = true
	}
	for _, protocol := range []string{"vless", "hysteria2", "tuic", "shadowsocks", "trojan", "vmess", "anytls", "naive"} {
		if !byProtocol[protocol] {
			t.Fatalf("missing protocol %s in %#v", protocol, outbounds)
		}
	}
}

func TestParseOutboundLinksSupportsV2rayNJSON(t *testing.T) {
	input := `v2rayn://tuic/eyJDb25maWdUeXBlIjo4LCJSZW1hcmtzIjoiVVMgdHVpYyIsIkFkZHJlc3MiOiI0NS4xMzkuMTkzLjE4NyIsIlBvcnQiOjg4ODMsIlBhc3N3b3JkIjoiY2JmMzc4ZWYtYmJmOC00NTM5LWE1NjQtMzFjNmYwMTczMTQyIiwiVXNlcm5hbWUiOiJjYmYzNzhlZi1iYmY4LTQ1MzktYTU2NC0zMWM2ZjAxNzMxNDIiLCJTdHJlYW1TZWN1cml0eSI6InRscyIsIlNuaSI6ImFkZG9ucy5tb3ppbGxhLm9yZyIsIlByb3RvRXh0cmFPYmoiOnsiQ29uZ2VzdGlvbkNvbnRyb2wiOiJiYnIifX0`
	outbounds, errors := ParseOutboundLinks(input)
	if len(errors) != 0 {
		t.Fatalf("unexpected parse errors: %#v", errors)
	}
	if len(outbounds) != 1 || outbounds[0].Protocol != "tuic" || outbounds[0].Congestion != "bbr" {
		t.Fatalf("unexpected outbounds: %#v", outbounds)
	}
}

func TestParseOutboundLinksSupportsClashListYAML(t *testing.T) {
	input := `
- {name: "US reality", type: vless, server: 45.139.193.187, port: 8881, uuid: cbf378ef-bbf8-4539-a564-31c6f0173142, network: tcp, tls: true, servername: addons.mozilla.org, reality-opts: {public-key: abc, short-id: ""}}
- {name: "US shadowsocks", type: ss, server: 45.139.193.187, port: 8885, cipher: 2022-blake3-aes-128-gcm, password: secret}
`
	outbounds, errors := ParseOutboundLinks(input)
	if len(errors) != 0 {
		t.Fatalf("unexpected parse errors: %#v", errors)
	}
	if len(outbounds) != 2 {
		t.Fatalf("expected 2 outbounds, got %#v", outbounds)
	}
	if outbounds[0].Security != "reality" || outbounds[0].PublicKey != "abc" {
		t.Fatalf("expected reality opts, got %#v", outbounds[0])
	}
	if outbounds[1].Protocol != "shadowsocks" || outbounds[1].Method == "" {
		t.Fatalf("expected shadowsocks, got %#v", outbounds[1])
	}
}

func TestParseOutboundLinksSupportsSingBoxJSON(t *testing.T) {
	input := `{
  "outbounds": [
    {"type": "direct", "tag": "direct"},
    {
      "type": "shadowtls",
      "tag": "shadowtls-out",
      "server": "45.139.193.187",
      "server_port": 8884,
      "password": "secret",
      "tls": {
        "enabled": true,
        "server_name": "addons.mozilla.org",
        "utls": {"enabled": true, "fingerprint": "firefox"}
      }
    }
  ]
}`
	outbounds, errors := ParseOutboundLinks(input)
	if len(errors) != 0 {
		t.Fatalf("unexpected parse errors: %#v", errors)
	}
	if len(outbounds) != 1 {
		t.Fatalf("expected 1 outbound, got %#v", outbounds)
	}
	if outbounds[0].Protocol != "shadowtls" || outbounds[0].ServerName != "addons.mozilla.org" || !outbounds[0].TLS {
		t.Fatalf("unexpected sing-box outbound: %#v", outbounds[0])
	}
}

func TestParseOutboundLinksSupportsShadowTLSLink(t *testing.T) {
	input := `shadowtls://:secret@45.139.193.187:8884?version=3&security=tls&sni=addons.mozilla.org&fp=chrome#shadowtls`
	outbounds, errors := ParseOutboundLinks(input)
	if len(errors) != 0 {
		t.Fatalf("unexpected parse errors: %#v", errors)
	}
	if len(outbounds) != 1 {
		t.Fatalf("expected 1 outbound, got %#v", outbounds)
	}
	if outbounds[0].Protocol != "shadowtls" || outbounds[0].Password != "secret" {
		t.Fatalf("unexpected shadowtls outbound: %#v", outbounds[0])
	}
}
