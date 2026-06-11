package core

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
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

type EnvironmentInfo struct {
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	Hostname       string `json:"hostname"`
	User           string `json:"user"`
	WorkingDir     string `json:"working_dir"`
	Release        string `json:"release,omitempty"`
	Systemd        bool   `json:"systemd"`
	HasSS          bool   `json:"has_ss"`
	HasNetstat     bool   `json:"has_netstat"`
	HasCurl        bool   `json:"has_curl"`
	HasUnzip       bool   `json:"has_unzip"`
	InstallDir     string `json:"install_dir"`
	ServiceName    string `json:"service_name"`
	AgentVersion   string `json:"agent_version"`
	AgentBuildTime string `json:"agent_build_time"`
}

type PortListener struct {
	Protocol     string `json:"protocol"`
	LocalAddress string `json:"local_address"`
	Process      string `json:"process,omitempty"`
	Raw          string `json:"raw"`
}

type PortListenerResult struct {
	Command string         `json:"command"`
	Ports   []PortListener `json:"ports"`
	Error   string         `json:"error,omitempty"`
}

type ServiceActionResult struct {
	Status  string `json:"status"`
	Action  string `json:"action"`
	Message string `json:"message"`
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
	execPath := filepath.Join(workDir, "current", "nodetools-agent")
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
			"升级安装会保留 database、logs 和现有 config.yaml，并在 backups/ 下备份配置。",
		},
	}
	if info.Systemd {
		info.Active = systemctlValue("is-active", "nodetools-agent")
		info.Enabled = systemctlValue("is-enabled", "nodetools-agent")
	}
	return info
}

func DetectEnvironment() EnvironmentInfo {
	hostname, _ := os.Hostname()
	workingDir, _ := os.Getwd()
	currentUser := ""
	if u, err := user.Current(); err == nil {
		currentUser = u.Username
	}
	return EnvironmentInfo{
		OS:             runtime.GOOS,
		Arch:           runtime.GOARCH,
		Hostname:       hostname,
		User:           currentUser,
		WorkingDir:     workingDir,
		Release:        linuxRelease(),
		Systemd:        hasSystemctl(),
		HasSS:          commandExists("ss"),
		HasNetstat:     commandExists("netstat"),
		HasCurl:        commandExists("curl"),
		HasUnzip:       commandExists("unzip"),
		InstallDir:     "/opt/nodetools-agent",
		ServiceName:    "nodetools-agent.service",
		AgentVersion:   Version,
		AgentBuildTime: BuildTime,
	}
}

func ListListeningPorts() PortListenerResult {
	commands := [][]string{
		{"ss", "-lntup"},
		{"netstat", "-lntup"},
		{"lsof", "-nP", "-iTCP", "-sTCP:LISTEN"},
	}
	for _, command := range commands {
		if !commandExists(command[0]) {
			continue
		}
		output, err := runShortCommand(command[0], command[1:]...)
		result := PortListenerResult{Command: strings.Join(command, " ")}
		if strings.TrimSpace(output) != "" {
			result.Ports = parsePortListeners(command[0], output)
		}
		if err != nil {
			result.Error = firstLine(output)
			if result.Error == "" {
				result.Error = err.Error()
			}
		}
		return result
	}
	return PortListenerResult{Error: "未找到 ss、netstat 或 lsof，无法读取监听端口"}
}

func RunServiceAction(action string) (ServiceActionResult, error) {
	if !hasSystemctl() {
		return ServiceActionResult{Action: action, Status: "unsupported", Message: "当前系统没有 systemctl"}, fmt.Errorf("systemctl is unavailable")
	}
	switch action {
	case "restart":
		go func() {
			time.Sleep(300 * time.Millisecond)
			output, err := exec.Command("systemctl", "restart", "nodetools-agent").CombinedOutput()
			if err != nil {
				fmt.Fprintf(os.Stderr, "restart nodetools-agent failed: %v: %s\n", err, strings.TrimSpace(string(output)))
			}
		}()
		return ServiceActionResult{Action: action, Status: "accepted", Message: "已提交重启 Agent 服务"}, nil
	case "daemon-reload":
		output, err := runShortCommand("systemctl", "daemon-reload")
		if err != nil {
			message := strings.TrimSpace(output)
			if message == "" {
				message = err.Error()
			}
			return ServiceActionResult{Action: action, Status: "failed", Message: message}, err
		}
		return ServiceActionResult{Action: action, Status: "ok", Message: "systemd 配置已重载"}, nil
	default:
		return ServiceActionResult{Action: action, Status: "invalid", Message: "不支持的服务动作"}, fmt.Errorf("unsupported service action %q", action)
	}
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
	return commandExists("systemctl")
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

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func linuxRelease() string {
	data, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
		}
	}
	return ""
}

func parsePortListeners(command, output string) []PortListener {
	var ports []PortListener
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "netid") || strings.HasPrefix(strings.ToLower(line), "proto") || strings.HasPrefix(strings.ToLower(line), "command") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		listener := PortListener{Protocol: fields[0], Raw: line}
		switch command {
		case "ss":
			if len(fields) >= 5 {
				listener.LocalAddress = fields[4]
			}
			if len(fields) >= 7 {
				listener.Process = strings.Join(fields[6:], " ")
			}
		case "netstat":
			if len(fields) >= 4 {
				listener.LocalAddress = fields[3]
			}
			if len(fields) >= 7 {
				listener.Process = fields[6]
			}
		case "lsof":
			if len(fields) >= 9 {
				listener.Protocol = fields[7]
				listener.LocalAddress = fields[8]
				listener.Process = fields[0]
			}
		}
		ports = append(ports, listener)
	}
	return ports
}
