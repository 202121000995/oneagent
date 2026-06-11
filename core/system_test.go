package core

import "testing"

func TestAgentServiceInfoContainsUnitAndCommands(t *testing.T) {
	info := AgentServiceInfo()
	if info.ServiceName != "nodetools-agent.service" {
		t.Fatalf("unexpected service name: %s", info.ServiceName)
	}
	if info.Unit == "" {
		t.Fatal("expected service unit content")
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
