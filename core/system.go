package core

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type KernelProbe struct {
	Name       string   `json:"name"`
	Installed  bool     `json:"installed"`
	Path       string   `json:"path,omitempty"`
	Version    string   `json:"version,omitempty"`
	Error      string   `json:"error,omitempty"`
	Candidates []string `json:"candidates,omitempty"`
}

type ServiceInfo struct {
	Supported   bool     `json:"supported"`
	Systemd     bool     `json:"systemd"`
	ServiceName string   `json:"service_name"`
	ServicePath string   `json:"service_path"`
	Installed   bool     `json:"installed"`
	Active      string   `json:"active,omitempty"`
	Enabled     string   `json:"enabled,omitempty"`
	Unit        string   `json:"unit"`
	Commands    []string `json:"commands"`
	Notes       []string `json:"notes"`
}

func DetectKernels(cfg Config) []KernelProbe {
	return []KernelProbe{
		detectKernel("sing-box", cfg.Kernel),
		detectKernel("mihomo", cfg.Kernel),
	}
}

func detectKernel(name string, cfg KernelConfig) KernelProbe {
	candidates := []string{name}
	if cfg.Type == name && cfg.Executable != "" {
		candidates = append([]string{cfg.Executable}, candidates...)
	}
	if name == "sing-box" {
		candidates = append(candidates, "/usr/local/bin/sing-box", "/usr/bin/sing-box")
	} else {
		candidates = append(candidates, "/usr/local/bin/mihomo", "/usr/bin/mihomo")
	}

	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}

		path, err := resolveExecutable(candidate)
		if err != nil {
			continue
		}
		version, versionErr := kernelVersion(path, name)
		probe := KernelProbe{Name: name, Installed: true, Path: path, Version: version}
		if versionErr != nil {
			probe.Error = versionErr.Error()
		}
		return probe
	}
	return KernelProbe{Name: name, Installed: false, Candidates: candidates}
}

func resolveExecutable(candidate string) (string, error) {
	if strings.Contains(candidate, "/") {
		info, err := os.Stat(candidate)
		if err != nil {
			return "", err
		}
		if info.IsDir() {
			return "", fmt.Errorf("%s is a directory", candidate)
		}
		if info.Mode()&0o111 == 0 {
			return "", fmt.Errorf("%s is not executable", candidate)
		}
		return candidate, nil
	}
	return exec.LookPath(candidate)
}

func kernelVersion(path, name string) (string, error) {
	argSets := [][]string{{"version"}, {"--version"}, {"-v"}}
	if name == "mihomo" {
		argSets = [][]string{{"-v"}, {"-version"}, {"--version"}, {"version"}}
	}
	for _, args := range argSets {
		output, err := runShortCommand(path, args...)
		if err == nil && strings.TrimSpace(output) != "" {
			return firstLine(output), nil
		}
	}
	return "", fmt.Errorf("version command failed")
}

func runShortCommand(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	data, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	return string(data), err
}

func firstLine(value string) string {
	value = strings.TrimSpace(value)
	if idx := strings.IndexByte(value, '\n'); idx >= 0 {
		return strings.TrimSpace(value[:idx])
	}
	return value
}

func AgentServiceInfo() ServiceInfo {
	const serviceName = "nodetools-agent.service"
	servicePath := "/etc/systemd/system/" + serviceName
	workDir := "/opt/nodetools-agent"
	execPath := filepath.Join(workDir, "nodetools-agent")
	unit := agentServiceUnit(workDir, execPath)

	info := ServiceInfo{
		Supported:   runtime.GOOS == "linux",
		Systemd:     hasSystemctl(),
		ServiceName: serviceName,
		ServicePath: servicePath,
		Installed:   fileExists(servicePath),
		Unit:        unit,
		Commands: []string{
			"mkdir -p kernels",
			"# 下载 sing-box 和 mihomo 的 Linux amd64 发布文件到 kernels/",
			"DEPLOY_WEB_PORT=39080 GO_BIN=/Users/apple/Library/Go/sdk/go1.26.3/bin/go ARCH=amd64 ./deploy/package-offline.sh",
			"unzip nodetools-agent-offline-linux-amd64.zip",
			"cd nodetools-agent-offline",
			"sudo sh install-offline.sh",
			"sudo journalctl -u nodetools-agent -f",
		},
		Notes: []string{
			"推荐先在本机生成带 sing-box / mihomo 的离线 zip，再上传到 VPS 解压安装。",
			"默认缺少内核时 package-offline.sh 会停止，避免生成半成品离线包。",
			"install-offline.sh 会安装 systemd 服务、检查本机端口，并提示云安全组放行。",
		},
	}
	if info.Systemd {
		info.Active = systemctlValue("is-active", "nodetools-agent")
		info.Enabled = systemctlValue("is-enabled", "nodetools-agent")
	}
	return info
}

func agentServiceUnit(workDir, execPath string) string {
	return `[Unit]
Description=NodeTools Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=` + workDir + `
ExecStart=` + execPath + `
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`
}

func hasSystemctl() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	_, err := exec.LookPath("systemctl")
	return err == nil
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func systemctlValue(args ...string) string {
	output, err := runShortCommand("systemctl", args...)
	if strings.TrimSpace(output) != "" {
		return firstLine(output)
	}
	if err != nil {
		return "unknown"
	}
	return firstLine(output)
}
