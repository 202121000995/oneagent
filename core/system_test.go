package core

import (
	"strings"
	"testing"
)

func TestAgentServiceInfoContainsUnitAndCommands(t *testing.T) {
	info := AgentServiceInfo()
	if info.ServiceName != "nodetools-agent.service" {
		t.Fatalf("unexpected service name: %s", info.ServiceName)
	}
	if info.Unit == "" {
		t.Fatal("expected service unit content")
	}
	if !strings.Contains(info.Unit, "/opt/nodetools-agent/current/nodetools-agent") {
		t.Fatalf("expected versioned current symlink in unit, got %s", info.Unit)
	}
	if len(info.Commands) == 0 {
		t.Fatal("expected service install commands")
	}
}

func TestDetectKernelsReturnsKnownKernelNames(t *testing.T) {
	kernels := DetectKernels(Config{})
	if len(kernels) != 2 {
		t.Fatalf("expected two kernel probes, got %d", len(kernels))
	}
	if kernels[0].Name != "sing-box" || kernels[1].Name != "mihomo" {
		t.Fatalf("unexpected kernel probes: %#v", kernels)
	}
}

func TestParsePortListenersSupportsSSOutput(t *testing.T) {
	output := `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
tcp   LISTEN 0      4096               *:39080            *:*    users:(("nodetools-agent",pid=1222,fd=7))
tcp   LISTEN 0      4096       127.0.0.1:1080             *:*    users:(("sing-box",pid=1234,fd=9))`
	ports := parsePortListeners("ss", output)
	if len(ports) != 2 {
		t.Fatalf("expected 2 listeners, got %#v", ports)
	}
	if ports[0].LocalAddress != "*:39080" || !strings.Contains(ports[0].Process, "nodetools-agent") {
		t.Fatalf("unexpected first listener: %#v", ports[0])
	}
}
