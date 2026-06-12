package core

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type BackupManifest struct {
	Type      string   `json:"type"`
	Version   string   `json:"version"`
	CreatedAt string   `json:"created_at"`
	Files     []string `json:"files"`
	SHA256    string   `json:"sha256,omitempty"`
}

type RestoreResult struct {
	Status         string `json:"status"`
	BackupPath     string `json:"backup_path"`
	RestoredConfig bool   `json:"restored_config"`
	RestoredDB     bool   `json:"restored_database"`
	RestoredCerts  bool   `json:"restored_certs"`
	Message        string `json:"message"`
}

func CreateBackupPackage() (string, error) {
	if err := os.MkdirAll("backups", 0o755); err != nil {
		return "", err
	}
	path := filepath.Join("backups", "nodetools-backup-"+time.Now().Format("20060102-150405")+".zip")
	if err := writeBackupZip(path, false); err != nil {
		return "", err
	}
	return path, nil
}

func CreateDiagnosticPackage(manager *Manager) (string, error) {
	if err := os.MkdirAll("backups", 0o755); err != nil {
		return "", err
	}
	path := filepath.Join("backups", "nodetools-diagnostics-"+time.Now().Format("20060102-150405")+".zip")
	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer file.Close()

	zw := zip.NewWriter(file)
	defer zw.Close()

	manifest := BackupManifest{Type: "diagnostics", Version: Version, CreatedAt: time.Now().Format(time.RFC3339)}
	addJSONToZip(zw, &manifest.Files, "status.json", manager.Status())
	addJSONToZip(zw, &manifest.Files, "environment.json", DetectEnvironment())
	addJSONToZip(zw, &manifest.Files, "service.json", AgentServiceInfo())
	addJSONToZip(zw, &manifest.Files, "ports.json", ListListeningPorts())
	addJSONToZip(zw, &manifest.Files, "kernels.json", DetectKernels(manager.ConfigSnapshot()))
	addJSONToZip(zw, &manifest.Files, "config.redacted.json", redactConfig(manager.ConfigSnapshot()))
	addTextToZip(zw, &manifest.Files, "logs/agent.tail.log", tailLog("logs/agent.log", 200000))
	addFileIfExists(zw, &manifest.Files, "sing-box.generated.json", "generated/sing-box.generated.json")
	addFileIfExists(zw, &manifest.Files, "mihomo.generated.yaml", "generated/mihomo.generated.yaml")
	addFileIfExists(zw, &manifest.Files, "kernel.generated.json", "generated/kernel.generated.json")
	addTextToZip(zw, &manifest.Files, "runtime.txt", runtime.GOOS+"/"+runtime.GOARCH)
	addJSONToZip(zw, &manifest.Files, "manifest.json", manifest)
	return path, nil
}

func writeBackupZip(path string, includeDiagnostics bool) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	zw := zip.NewWriter(file)
	defer zw.Close()

	manifest := BackupManifest{Type: "backup", Version: Version, CreatedAt: time.Now().Format(time.RFC3339)}
	addFileIfExists(zw, &manifest.Files, "config.yaml", "config.yaml")
	addFileIfExists(zw, &manifest.Files, filepath.Join("database", "nodetools.db"), filepath.Join("database", "nodetools.db"))
	addDirIfExists(zw, &manifest.Files, "certs", "certs")
	if includeDiagnostics {
		addFileIfExists(zw, &manifest.Files, "logs/agent.log", "logs/agent.log")
	}
	addJSONToZip(zw, &manifest.Files, "manifest.json", manifest)
	return nil
}

func RestoreBackupPackage(r *http.Request, manager *Manager) (RestoreResult, error) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		return RestoreResult{}, err
	}
	file, header, err := r.FormFile("backup")
	if err != nil {
		return RestoreResult{}, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, 128<<20))
	if err != nil {
		return RestoreResult{}, err
	}
	if len(data) == 0 {
		return RestoreResult{}, fmt.Errorf("backup file is empty")
	}
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return RestoreResult{}, err
	}
	currentBackup, err := CreateBackupPackage()
	if err != nil {
		return RestoreResult{}, fmt.Errorf("backup current state before restore: %w", err)
	}

	result := RestoreResult{Status: "restored", BackupPath: currentBackup}
	allowed := map[string]bool{
		"manifest.json":         true,
		"config.yaml":           true,
		"database/nodetools.db": true,
	}
	for _, item := range reader.File {
		name := filepath.ToSlash(filepath.Clean(item.Name))
		if strings.HasPrefix(name, "../") || strings.HasPrefix(name, "/") || name == "." {
			return RestoreResult{}, fmt.Errorf("backup contains unsafe path %q", item.Name)
		}
		if !allowed[name] && !strings.HasPrefix(name, "certs/") {
			continue
		}
		if item.FileInfo().IsDir() || name == "manifest.json" {
			continue
		}
		switch name {
		case "config.yaml":
			if err := restoreZipFile(item, name, 0o644); err != nil {
				return RestoreResult{}, err
			}
			result.RestoredConfig = true
		case "database/nodetools.db":
			if err := restoreZipFile(item, name, 0o644); err != nil {
				return RestoreResult{}, err
			}
			result.RestoredDB = true
		default:
			if strings.HasPrefix(name, "certs/") {
				if err := restoreZipFile(item, name, 0o600); err != nil {
					return RestoreResult{}, err
				}
				result.RestoredCerts = true
			}
		}
	}
	if result.RestoredConfig {
		cfg, err := LoadConfig("config.yaml")
		if err != nil {
			return RestoreResult{}, fmt.Errorf("restored config validation failed: %w", err)
		}
		if err := manager.ApplyConfig(cfg); err != nil {
			return RestoreResult{}, fmt.Errorf("apply restored config failed: %w", err)
		}
	}
	result.Message = "恢复完成；如果恢复了数据库，建议重启 Agent 服务让所有连接重新打开。来源文件：" + header.Filename
	return result, nil
}

func restoreZipFile(item *zip.File, target string, perm os.FileMode) error {
	source, err := item.Open()
	if err != nil {
		return err
	}
	defer source.Close()
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	tmp := target + ".restore.tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, source); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, target)
}

func addDirIfExists(zw *zip.Writer, files *[]string, sourceDir, targetDir string) {
	info, err := os.Stat(sourceDir)
	if err != nil || !info.IsDir() {
		return
	}
	_ = filepath.WalkDir(sourceDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return nil
		}
		addFileIfExists(zw, files, path, filepath.ToSlash(filepath.Join(targetDir, rel)))
		return nil
	})
}

func addFileIfExists(zw *zip.Writer, files *[]string, source, target string) {
	data, err := os.ReadFile(source)
	if err != nil {
		return
	}
	addBytesToZip(zw, files, target, data)
}

func addTextToZip(zw *zip.Writer, files *[]string, target, value string) {
	addBytesToZip(zw, files, target, []byte(value))
}

func addJSONToZip(zw *zip.Writer, files *[]string, target string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return
	}
	addBytesToZip(zw, files, target, data)
}

func addBytesToZip(zw *zip.Writer, files *[]string, target string, data []byte) {
	writer, err := zw.Create(filepath.ToSlash(target))
	if err != nil {
		return
	}
	if _, err := writer.Write(data); err != nil {
		return
	}
	*files = append(*files, filepath.ToSlash(target))
}

func backupChecksum(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func redactConfig(cfg Config) Config {
	cfg.Server.AdminPass = ""
	for i := range cfg.Inbounds {
		cfg.Inbounds[i].Password = redactSecret(cfg.Inbounds[i].Password)
		cfg.Inbounds[i].PrivateKey = redactSecret(cfg.Inbounds[i].PrivateKey)
		cfg.Inbounds[i].KeyContent = ""
		cfg.Inbounds[i].CertificateContent = ""
	}
	for i := range cfg.Outbounds {
		cfg.Outbounds[i].Password = redactSecret(cfg.Outbounds[i].Password)
		cfg.Outbounds[i].UUID = redactSecret(cfg.Outbounds[i].UUID)
		cfg.Outbounds[i].ObfsPassword = redactSecret(cfg.Outbounds[i].ObfsPassword)
		cfg.Outbounds[i].Raw = ""
	}
	for i := range cfg.Mihomo.Providers {
		cfg.Mihomo.Providers[i].URL = redactURL(cfg.Mihomo.Providers[i].URL)
	}
	return cfg
}

func redactSecret(value string) string {
	if value == "" {
		return ""
	}
	return "<redacted>"
}

func redactURL(value string) string {
	if value == "" {
		return ""
	}
	if idx := strings.Index(value, "?"); idx >= 0 {
		return value[:idx] + "?<redacted>"
	}
	return value
}

func ServePackage(w http.ResponseWriter, r *http.Request, path string) {
	name := filepath.Base(path)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	w.Header().Set("X-Content-SHA256", backupChecksum(path))
	http.ServeFile(w, r, path)
}
