package core

import "testing"

func TestCurrentConfigGeneratesKernelConfig(t *testing.T) {
	cfg, err := LoadConfig("../config.yaml")
	if err != nil {
		t.Fatalf("LoadConfig returned error: %v", err)
	}
	kernel := NewKernel(cfg.Kernel)
	_, err = kernel.GenerateConfig(RuntimeState{
		Inbounds:  cfg.Inbounds,
		Outbounds: cfg.Outbounds,
		Routing:   cfg.Routing,
		Mihomo:    cfg.Mihomo,
	})
	if err != nil {
		t.Fatalf("GenerateConfig returned error: %v", err)
	}
}
