package core

import (
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
)

type ProxyCreateRequest struct {
	Name                   string `json:"name"`
	Protocol               string `json:"protocol"`
	Listen                 string `json:"listen,omitempty"`
	Port                   int    `json:"port"`
	Outbound               string `json:"outbound"`
	Username               string `json:"username,omitempty"`
	UUID                   string `json:"uuid,omitempty"`
	Password               string `json:"password,omitempty"`
	Method                 string `json:"method,omitempty"`
	Flow                   string `json:"flow,omitempty"`
	Security               string `json:"security,omitempty"`
	AlterID                int    `json:"alter_id,omitempty"`
	TLS                    bool   `json:"tls,omitempty"`
	ServerName             string `json:"server_name,omitempty"`
	CertificatePath        string `json:"certificate_path,omitempty"`
	KeyPath                string `json:"key_path,omitempty"`
	CertificateContent     string `json:"certificate_content,omitempty"`
	KeyContent             string `json:"key_content,omitempty"`
	Transport              string `json:"transport,omitempty"`
	Path                   string `json:"path,omitempty"`
	Host                   string `json:"host,omitempty"`
	PrivateKey             string `json:"private_key,omitempty"`
	ShortID                string `json:"short_id,omitempty"`
	RealityHandshakeServer string `json:"reality_handshake_server,omitempty"`
	RealityHandshakePort   int    `json:"reality_handshake_port,omitempty"`
	IdleSessionCheck       string `json:"idle_session_check,omitempty"`
	IdleSessionTimeout     string `json:"idle_session_timeout,omitempty"`
	MinIdleSession         int    `json:"min_idle_session,omitempty"`
}

type ForwardCreateRequest struct {
	Name       string `json:"name"`
	Protocol   string `json:"protocol"`
	ListenPort int    `json:"listen_port"`
	TargetHost string `json:"target_host"`
	TargetPort int    `json:"target_port"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ChangePasswordRequest struct {
	Username        string `json:"username"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type NodeEnableRequest struct {
	Enabled bool `json:"enabled"`
}

type BatchNodesRequest struct {
	Items []BatchNodeItem `json:"items"`
}

type BatchNodeItem struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

func RegisterAPI(mux *http.ServeMux, manager *Manager, auth *Auth) {
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		var req LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		if !auth.Login(w, req.Username, req.Password) {
			writeError(w, http.StatusUnauthorized, "invalid username or password")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		auth.Logout(w, r)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.Handle("GET /api/me", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]bool{"authenticated": true})
	})))
	mux.Handle("POST /api/password/change", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ChangePasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		if err := auth.ChangePassword(req.Username, req.CurrentPassword, req.NewPassword); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "password_changed"})
	})))
	mux.Handle("GET /api/status", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, manager.Status())
	})))
	mux.Handle("GET /api/nodes", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"nodes": manager.ListNodes()})
	})))
	mux.Handle("GET /api/config", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, manager.ConfigSnapshot())
	})))
	mux.Handle("GET /api/system/kernels", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"kernels": DetectKernels(manager.ConfigSnapshot())})
	})))
	mux.Handle("GET /api/system/service", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, AgentServiceInfo())
	})))
	mux.Handle("GET /api/system/environment", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, DetectEnvironment())
	})))
	mux.Handle("GET /api/system/ports", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, ListListeningPorts())
	})))
	mux.Handle("POST /api/system/service/restart", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, err := RunServiceAction("restart")
		if err != nil {
			writeError(w, http.StatusBadRequest, result.Message)
			return
		}
		writeJSON(w, http.StatusAccepted, result)
	})))
	mux.Handle("POST /api/reality/keypair", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keyPair, err := GenerateRealityKeyPair()
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, keyPair)
	})))
	mux.Handle("PUT /api/kernel/config", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req KernelConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		if err := manager.UpdateKernelConfig(req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "saved", "kernel": manager.Status().Kernel})
	})))
	mux.Handle("PUT /api/mihomo/config", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req MihomoConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		if err := manager.UpdateMihomoConfig(req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "saved", "mihomo": manager.ConfigSnapshot().Mihomo})
	})))
	mux.Handle("PUT /api/routing/config", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req RoutingConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		if err := manager.UpdateRoutingConfig(req); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "saved", "routing": manager.ConfigSnapshot().Routing})
	})))
	mux.Handle("POST /api/subscription/preview", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req SubscriptionPreviewRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		preview, err := PreviewSubscription(req.URL)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, preview)
	})))
	mux.Handle("POST /api/subscriptions/update", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		results, err := manager.UpdateSubscriptions()
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": results})
	})))
	mux.Handle("POST /api/kernel/reload", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := manager.ReloadKernel(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "reloaded", "kernel": manager.Status().Kernel})
	})))
	mux.Handle("POST /api/kernel/stop", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := manager.StopKernel(); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "stopped", "kernel": manager.Status().Kernel})
	})))
	mux.Handle("GET /api/logs", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		logs := tailLog("logs/agent.log", 120000)
		logs = filterLogLines(logs, query.Get("q"))
		writeJSON(w, http.StatusOK, map[string]string{"logs": limitLogLines(logs, parsePositiveInt(query.Get("lines"), 300))})
	})))
	mux.Handle("POST /api/proxy/create", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ProxyCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		node, err := manager.CreateProxy(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"node":   node,
			"socks5": "127.0.0.1:12001",
		})
	})))
	mux.Handle("POST /api/forward/create", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ForwardCreateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		node, err := manager.CreateForward(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"node": node})
	})))
	mux.Handle("PUT /api/inbounds", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req InboundConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		node, err := manager.UpsertInbound(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"node": node})
	})))
	mux.Handle("PUT /api/outbounds", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req OutboundConfig
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		node, err := manager.UpsertOutbound(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"node": node})
	})))
	mux.Handle("POST /api/outbounds/import", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ImportLinksRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		outbounds, parseErrors := ParseOutboundLinks(req.Text)
		nodes, err := manager.ImportOutbounds(outbounds)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, ImportLinksResponse{Imported: nodes, Parsed: len(outbounds), Errors: parseErrors})
	})))
	mux.Handle("POST /api/nodes/{type}/{name}/test", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, err := manager.TestNode(r.PathValue("type"), r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
	})))
	mux.Handle("POST /api/inbounds/{name}/share", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Host string `json:"host"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		result, err := manager.ShareInbound(r.PathValue("name"), req.Host)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
	})))
	mux.Handle("POST /api/outbounds/{name}/share", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		result, err := manager.ShareOutbound(r.PathValue("name"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
	})))
	mux.Handle("PATCH /api/nodes/{type}/{name}/enabled", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req NodeEnableRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		node, err := manager.SetNodeEnabled(r.PathValue("type"), r.PathValue("name"), req.Enabled)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"node": node})
	})))
	mux.Handle("POST /api/nodes/batch/test", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req BatchNodesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		results := make([]NodeTestResult, 0, len(req.Items))
		for _, item := range req.Items {
			result, err := manager.TestNode(item.Type, item.Name)
			if err != nil {
				results = append(results, NodeTestResult{Name: item.Name, Type: item.Type, Status: "error", Error: err.Error()})
				continue
			}
			results = append(results, result)
		}
		writeJSON(w, http.StatusOK, map[string]any{"results": results})
	})))
	mux.Handle("PATCH /api/nodes/batch/enabled", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Items   []BatchNodeItem `json:"items"`
			Enabled bool            `json:"enabled"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		nodes := make([]Node, 0, len(req.Items))
		for _, item := range req.Items {
			node, err := manager.SetNodeEnabled(item.Type, item.Name, req.Enabled)
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			nodes = append(nodes, node)
		}
		writeJSON(w, http.StatusOK, map[string]any{"nodes": nodes})
	})))
	mux.Handle("POST /api/nodes/batch/delete", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req BatchNodesRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid json body")
			return
		}
		for _, item := range req.Items {
			if err := manager.DeleteNode(item.Type, item.Name); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": len(req.Items)})
	})))
	mux.Handle("DELETE /api/nodes/{type}/{name}", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := manager.DeleteNode(r.PathValue("type"), r.PathValue("name")); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
	})))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func tailLog(path string, maxBytes int) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	if len(data) > maxBytes {
		data = data[len(data)-maxBytes:]
		if idx := strings.IndexByte(string(data), '\n'); idx >= 0 && idx+1 < len(data) {
			data = data[idx+1:]
		}
	}
	return string(data)
}

func filterLogLines(logs, query string) string {
	query = strings.TrimSpace(query)
	if query == "" {
		return logs
	}
	lines := strings.Split(logs, "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), strings.ToLower(query)) {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func limitLogLines(logs string, maxLines int) string {
	lines := strings.Split(logs, "\n")
	if len(lines) <= maxLines {
		return logs
	}
	return strings.Join(lines[len(lines)-maxLines:], "\n")
}

func parsePositiveInt(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 1 {
		return fallback
	}
	return parsed
}
