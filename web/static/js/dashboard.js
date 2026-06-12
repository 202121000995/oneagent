const pageTitles = {
  overview: "系统状态",
  inbounds: "入站列表",
  outbounds: "出站节点",
  routing: "路由策略",
  kernel: "内核管理",
  subscriptions: "订阅管理",
  system: "系统服务",
  logs: "运行日志",
  security: "安全设置",
};

const state = {
  page: "overview",
  nodes: [],
  config: {},
  status: {},
  configLoaded: false,
  selected: {
    inbound: new Set(),
    outbound: new Set(),
  },
};

const outboundProtocols = [
  "vless",
  "vmess",
  "trojan",
  "shadowsocks",
  "hysteria2",
  "tuic",
  "anytls",
  "naive",
  "shadowtls",
  "socks5",
  "http",
];

const ssMethods = [
  "2022-blake3-aes-128-gcm",
  "2022-blake3-aes-256-gcm",
  "aes-128-gcm",
  "aes-256-gcm",
  "chacha20-ietf-poly1305",
  "xchacha20-ietf-poly1305",
];

const fingerprints = ["chrome", "firefox", "safari", "ios", "android", "edge", "randomized"];
const alpnOptions = ["", "h2", "http/1.1", "h2,http/1.1", "h3"];
const transportOptions = ["tcp", "ws", "http", "grpc"];
const inboundListenOptions = ["0.0.0.0", "::", "127.0.0.1"];
const localListenOptions = ["0.0.0.0", "::", "127.0.0.1"];
const routingMatchTypes = [
  ["inbound", "入站"],
  ["domain", "完整域名"],
  ["domain_suffix", "域名后缀"],
  ["domain_keyword", "域名关键词"],
  ["ip_cidr", "IP/CIDR"],
  ["geoip", "GeoIP（mihomo/规则集）"],
  ["geosite", "Geosite（mihomo/规则集）"],
  ["protocol", "协议"],
  ["port", "目标端口"],
];
const tlsCertificateFields = [
  ["certificate_path", "TLS 证书路径", ""],
  ["key_path", "TLS 私钥路径", ""],
  ["certificate_content", "TLS 证书内容", "", "textarea"],
  ["key_content", "TLS 私钥内容", "", "textarea"],
];

const inboundSchemas = {
  mixed: [
    ["listen", "监听地址", "0.0.0.0", "select", localListenOptions],
    ["username", "用户名", ""],
    ["password", "密码", "", "password"],
  ],
  socks: [
    ["listen", "监听地址", "0.0.0.0", "select", localListenOptions],
    ["username", "用户名", ""],
    ["password", "密码", "", "password"],
  ],
  socks5: [
    ["listen", "监听地址", "0.0.0.0", "select", localListenOptions],
    ["username", "用户名", ""],
    ["password", "密码", "", "password"],
  ],
  http: [
    ["listen", "监听地址", "0.0.0.0", "select", localListenOptions],
    ["username", "用户名", ""],
    ["password", "密码", "", "password"],
  ],
  vless: [
    ["listen", "监听地址", "0.0.0.0", "select", inboundListenOptions],
    ["uuid", "UUID", ""],
    ["flow", "Flow", "", "select", ["", "xtls-rprx-vision"]],
    ["security", "安全", "none", "select", ["none", "reality"]],
    ["tls", "TLS", "", "checkbox"],
    ["server_name", "Server Name", "addons.mozilla.org"],
    ["private_key", "Reality Private Key", ""],
    ["short_id", "Reality Short IDs", ""],
    ["reality_handshake_server", "Reality Handshake Server", "addons.mozilla.org"],
    ["reality_handshake_port", "Reality Handshake Port", "443", "number"],
    ...tlsCertificateFields,
    ["transport", "传输", "tcp", "select", transportOptions],
    ["path", "路径 / Service Name", "/"],
    ["host", "Host", ""],
  ],
  vmess: [
    ["listen", "监听地址", "0.0.0.0", "select", inboundListenOptions],
    ["uuid", "UUID", ""],
    ["alter_id", "Alter ID", "0", "number"],
    ["tls", "TLS", "", "checkbox"],
    ["server_name", "Server Name", "example.com"],
    ...tlsCertificateFields,
    ["transport", "传输", "tcp", "select", transportOptions],
    ["path", "路径", "/ws"],
    ["host", "Host", ""],
  ],
  trojan: [
    ["listen", "监听地址", "0.0.0.0", "select", inboundListenOptions],
    ["password", "密码", "", "password"],
    ["tls", "TLS", "true", "checkbox"],
    ["server_name", "Server Name", "example.com"],
    ...tlsCertificateFields,
    ["transport", "传输", "tcp", "select", transportOptions],
    ["path", "路径", "/"],
    ["host", "Host", ""],
  ],
  anytls: [
    ["listen", "监听地址", "0.0.0.0", "select", inboundListenOptions],
    ["password", "密码", "", "password"],
    ["tls", "TLS", "true", "checkbox"],
    ["server_name", "Server Name", "example.com"],
    ...tlsCertificateFields,
  ],
  shadowsocks: [
    ["listen", "监听地址", "0.0.0.0", "select", inboundListenOptions],
    ["method", "加密方法", "", "select", ssMethods],
    ["password", "密码", "", "password"],
  ],
  shadowtls: [
    ["listen", "监听地址", "0.0.0.0", "select", inboundListenOptions],
    ["password", "ShadowTLS 密码", "", "password"],
    ["server_name", "SNI / Server Name", "addons.mozilla.org"],
    ["reality_handshake_server", "握手目标", "addons.mozilla.org"],
    ["reality_handshake_port", "握手端口", "443", "number"],
  ],
};

const outboundSchemas = {
  vless: [
    ["name", "名称", "HK-VLESS"],
    ["address", "服务器地址", "example.com"],
    ["port", "端口", "443", "number"],
    ["uuid", "UUID", ""],
    ["flow", "Flow", "", "select", ["", "xtls-rprx-vision"]],
    ["security", "安全", "auto", "select", ["auto", "none", "tls", "reality"]],
    ["transport", "传输", "tcp", "select", transportOptions],
    ["path", "路径 / Service Name", "/"],
    ["host", "Host", "cdn.example.com"],
    ["tls", "TLS", "", "checkbox"],
    ["server_name", "SNI / Server Name", "example.com"],
    ["public_key", "Reality Public Key", ""],
    ["short_id", "Reality Short ID", ""],
    ["fingerprint", "Fingerprint", "chrome", "select", fingerprints],
    ["alpn", "ALPN", "", "select", alpnOptions],
  ],
  vmess: [
    ["name", "名称", "HK-VMess"],
    ["address", "服务器地址", "example.com"],
    ["port", "端口", "443", "number"],
    ["uuid", "UUID", ""],
    ["alter_id", "Alter ID", "0", "number"],
    ["security", "加密", "auto", "select", ["auto", "none", "zero", "aes-128-gcm", "chacha20-poly1305"]],
    ["transport", "传输", "tcp", "select", transportOptions],
    ["path", "路径", "/ws"],
    ["host", "Host", "cdn.example.com"],
    ["tls", "TLS", "", "checkbox"],
    ["server_name", "SNI / Server Name", "example.com"],
    ["alpn", "ALPN", "", "select", alpnOptions],
  ],
  trojan: [
    ["name", "名称", "HK-Trojan"],
    ["address", "服务器地址", "example.com"],
    ["port", "端口", "443", "number"],
    ["password", "密码", "", "password"],
    ["transport", "传输", "tcp", "select", transportOptions],
    ["path", "路径", "/"],
    ["host", "Host", ""],
    ["tls", "TLS", "", "checkbox"],
    ["server_name", "SNI / Server Name", "example.com"],
    ["skip_cert_verify", "跳过证书校验", "", "checkbox"],
  ],
  shadowsocks: [
    ["name", "名称", "HK-SS"],
    ["address", "服务器地址", "example.com"],
    ["port", "端口", "8388", "number"],
    ["method", "加密方法", "", "select", ssMethods],
    ["password", "密码", "", "password"],
  ],
  hysteria2: [
    ["name", "名称", "HK-Hysteria2"],
    ["address", "服务器地址", "example.com"],
    ["port", "端口", "443", "number"],
    ["password", "密码", "", "password"],
    ["server_name", "SNI / Server Name", "example.com"],
    ["skip_cert_verify", "跳过证书校验", "", "checkbox"],
    ["up_mbps", "上传 Mbps", "100", "number"],
    ["down_mbps", "下载 Mbps", "100", "number"],
    ["obfs", "Obfs", "none", "select", ["none", "salamander"]],
    ["obfs_password", "Obfs 密码", "", "password"],
    ["mport", "端口跳跃", "50000-51000"],
  ],
  tuic: [
    ["name", "名称", "HK-TUIC"],
    ["address", "服务器地址", "example.com"],
    ["port", "端口", "443", "number"],
    ["uuid", "UUID", ""],
    ["password", "密码", "", "password"],
    ["server_name", "SNI / Server Name", "example.com"],
    ["congestion", "拥塞控制", "bbr", "select", ["bbr", "cubic", "new_reno"]],
    ["udp_relay_mode", "UDP Relay Mode", "native", "select", ["native", "quic"]],
    ["alpn", "ALPN", "h3", "select", ["h3"]],
    ["skip_cert_verify", "跳过证书校验", "", "checkbox"],
  ],
  anytls: [
    ["name", "名称", "HK-AnyTLS"],
    ["address", "服务器地址", "example.com"],
    ["port", "端口", "443", "number"],
    ["password", "密码", "", "password"],
    ["server_name", "SNI / Server Name", "example.com"],
    ["skip_cert_verify", "跳过证书校验", "", "checkbox"],
  ],
  naive: [
    ["name", "名称", "HK-Naive"],
    ["address", "服务器地址", "example.com"],
    ["port", "端口", "443", "number"],
    ["username", "用户名", ""],
    ["password", "密码", "", "password"],
    ["transport", "模式", "naive+https", "select", ["naive+https", "naive+quic", "http2", "http3"]],
    ["server_name", "SNI / Server Name", "example.com"],
    ["tls", "TLS", "", "checkbox"],
  ],
  shadowtls: [
    ["name", "名称", "HK-ShadowTLS"],
    ["address", "服务器地址", "example.com"],
    ["port", "端口", "443", "number"],
    ["password", "ShadowTLS 密码", "", "password"],
    ["server_name", "SNI / Server Name", "example.com"],
    ["fingerprint", "Fingerprint", "chrome", "select", fingerprints],
  ],
  socks5: [
    ["name", "名称", "Remote-SOCKS"],
    ["address", "服务器地址", "127.0.0.1"],
    ["port", "端口", "1080", "number"],
    ["username", "用户名", ""],
    ["password", "密码", "", "password"],
  ],
  http: [
    ["name", "名称", "Remote-HTTP"],
    ["address", "服务器地址", "127.0.0.1"],
    ["port", "端口", "8080", "number"],
    ["username", "用户名", ""],
    ["password", "密码", "", "password"],
  ],
};

const formatBytes = (value) => {
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Number(value || 0);
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
};

const formatLatency = (node) => {
  if (node.latency_ms) return `${node.latency_ms} ms`;
  if (["offline", "error", "timeout"].includes(node.status)) return "timeout";
  return "--";
};

const nodeHint = (node) => {
  const diagnosis = node.diagnosis || "";
  const detail = node.last_error || node.diagnosis_hint || "";
  if (!diagnosis && !detail) return "";
  return [diagnosis, detail].filter(Boolean).join("：");
};

const statusBadgeClass = (node) => {
  if (node.status === "online") return "badge";
  if (node.status === "offline" || node.status === "error" || node.status === "timeout") return "badge badge-danger";
  return "badge badge-muted";
};

const escapeHTML = (value) => String(value ?? "")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");

const shareHost = () => {
  const host = location.hostname;
  if (!host || host === "localhost" || host === "::1" || host === "0.0.0.0" || host.startsWith("127.")) return "";
  return host;
};

const randomHex = (bytes) => {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  return Array.from(data, (item) => item.toString(16).padStart(2, "0")).join("");
};

const randomPassword = (length = 18) => {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const data = new Uint8Array(length);
  crypto.getRandomValues(data);
  return Array.from(data, (item) => alphabet[item % alphabet.length]).join("");
};

const randomBase64 = (bytes) => {
  const data = new Uint8Array(bytes);
  crypto.getRandomValues(data);
  let binary = "";
  data.forEach((item) => { binary += String.fromCharCode(item); });
  return btoa(binary);
};

const randomUUID = () => {
  if (crypto.randomUUID) return crypto.randomUUID();
  const data = new Uint8Array(16);
  crypto.getRandomValues(data);
  data[6] = (data[6] & 0x0f) | 0x40;
  data[8] = (data[8] & 0x3f) | 0x80;
  const hex = Array.from(data, (item) => item.toString(16).padStart(2, "0"));
  return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10).join("")}`;
};

const postJSON = async (url, body) => {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || "请求失败");
  return payload;
};

const sendJSON = async (url, method, body) => {
  const response = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || "请求失败");
  return payload;
};

const formToObject = (form) => {
  const data = Object.fromEntries(new FormData(form).entries());
  for (const key of ["port", "start_port", "listen_port", "target_port", "alter_id", "up_mbps", "down_mbps", "reality_handshake_port", "min_idle_session"]) {
    if (key in data && data[key] !== "") data[key] = Number(data[key]);
  }
  for (const checkbox of form.querySelectorAll('input[type="checkbox"]')) {
    data[checkbox.name] = checkbox.checked;
  }
  delete data.enabled;
  return data;
};

const fillForm = (form, values) => {
  if (!form || !values) return;
  for (const [key, value] of Object.entries(values)) {
    const field = form.elements[key];
    if (!field) continue;
    if (field.type === "checkbox") {
      field.checked = Boolean(value);
    } else {
      field.value = value ?? "";
    }
  }
};

const setText = (id, value) => {
  const element = document.getElementById(id);
  if (element) element.textContent = value;
};

const getRules = () => state.config?.routing?.rules || [];
const getOutbounds = () => state.nodes.filter((node) => node.type === "outbound");
const getInbounds = () => state.nodes.filter((node) => node.type === "inbound");
const getInboundConfig = (name) => (state.config?.inbounds || []).find((item) => item.name === name);
const getOutboundConfig = (name) => (state.config?.outbounds || []).find((item) => item.name === name);

async function refresh() {
  const [statusRes, nodeRes, configRes, kernelsRes, serviceRes, envRes, portsRes, securityRes] = await Promise.all([
    fetch("/api/status"),
    fetch("/api/nodes"),
    fetch("/api/config"),
    fetch("/api/system/kernels"),
    fetch("/api/system/service"),
    fetch("/api/system/environment"),
    fetch("/api/system/ports"),
    fetch("/api/security/status"),
  ]);
  if ([statusRes, nodeRes, configRes, kernelsRes, serviceRes, envRes, portsRes, securityRes].some((res) => res.status === 401)) {
    location.href = "/login";
    return;
  }

  state.status = await statusRes.json();
  const nodePayload = await nodeRes.json();
  state.nodes = nodePayload.nodes || [];
  state.config = await configRes.json();
  const { kernels } = await kernelsRes.json();
  const service = await serviceRes.json();
  const environment = await envRes.json();
  const ports = await portsRes.json();
  const security = await securityRes.json();

  renderMetrics();
  renderInbounds();
  renderOutbounds();
  renderSystem(kernels, service, environment, ports);
  renderSecurity(security);
  renderOutboundOptions();
  renderRoutingPreviewOptions();

  if (!state.configLoaded) {
    fillForm(document.getElementById("kernelForm"), state.config.kernel);
    fillMihomoForm(state.config.mihomo || {});
    fillRoutingForm(state.config.routing || {});
    state.configLoaded = true;
  }

  const logOutput = document.getElementById("logOutput");
  if (logOutput) {
    await refreshLogs();
  }
}

const renderMetrics = () => {
  const status = state.status;
  const pidText = status.kernel?.pid ? ` #${status.kernel.pid}` : "";
  setText("inboundCount", status.inbound_count || 0);
  setText("outboundCount", status.outbound_count || 0);
  setText("uploadTotal", formatBytes(status.total_upload_bytes));
  setText("downloadTotal", formatBytes(status.total_download_bytes));
  setText("routingRuleCount", status.routing_rule_count || 0);
  setText("uptimeText", `${status.uptime_seconds || 0} 秒`);
  setText("kernelStatus", `${status.kernel?.name || "--"} / ${status.kernel?.running ? "运行中" : "未运行"}${pidText}`);
  setText("overviewKernel", `${status.kernel?.name || "--"} ${status.kernel?.running ? "运行中" : "未运行"}`);
  setText("envVersion", `${status.version || "--"} / ${status.commit || "dev"}`);
  setText("overviewUpdated", new Date().toLocaleTimeString());
  setText("lastUpdated", new Date().toLocaleTimeString());
};

const renderInbounds = () => {
  const rows = document.getElementById("inboundRows");
  if (!rows) return;
  const query = (document.getElementById("inboundSearch")?.value || "").toLowerCase();
  const items = getInbounds().filter((node) => {
    const text = `${node.name} ${node.protocol}`.toLowerCase();
    return text.includes(query);
  });
  rows.innerHTML = items.map((node) => {
    const hint = nodeHint(node);
    return `
      <tr>
        <td><div class="node-name">${escapeHTML(node.name)}</div>${hint ? `<div class="node-hint">${escapeHTML(hint)}</div>` : ""}</td>
        <td>${escapeHTML(node.protocol)}</td>
        <td>${escapeHTML(node.address || "::")}:${node.port}</td>
        <td>${formatBytes(node.upload_bytes)}</td>
        <td>${formatBytes(node.download_bytes)}</td>
        <td>${formatLatency(node)}</td>
        <td><span class="${statusBadgeClass(node)}" title="${escapeHTML(hint)}">${escapeHTML(node.status)}</span></td>
        <td>
          <div class="row-actions">
            <button class="icon-button" data-test-type="inbound" data-test-name="${escapeHTML(node.name)}" type="button">Google 测试</button>
            <button class="icon-button" data-edit-inbound="${escapeHTML(node.name)}" type="button">编辑</button>
            <button class="icon-button" data-share-inbound="${escapeHTML(node.name)}" type="button">分享</button>
            <button class="icon-button" data-toggle-type="inbound" data-toggle-name="${escapeHTML(node.name)}" data-toggle-enabled="${node.enabled ? "false" : "true"}" type="button">${node.enabled ? "停用" : "启用"}</button>
            <button class="icon-button" data-delete-type="inbound" data-delete-name="${escapeHTML(node.name)}" type="button">删除</button>
          </div>
        </td>
        <td><input type="checkbox" data-node-check="inbound" value="${escapeHTML(node.name)}"${state.selected.inbound.has(node.name) ? " checked" : ""}></td>
      </tr>
    `;
  }).join("") || `<tr><td colspan="9" class="empty-cell">还没有入站，点击“添加入站”创建本地代理端口。</td></tr>`;
};

const renderOutbounds = () => {
  const rows = document.getElementById("outboundRows");
  if (!rows) return;
  const query = (document.getElementById("outboundSearch")?.value || "").toLowerCase();
  const items = getOutbounds().filter((node) => {
    const text = `${node.name} ${node.protocol} ${node.address}`.toLowerCase();
    return text.includes(query);
  });
  rows.innerHTML = items.map((node) => {
    const hint = nodeHint(node);
    return `
    <tr>
      <td><div class="node-name">${escapeHTML(node.name)}</div>${hint ? `<div class="node-hint">${escapeHTML(hint)}</div>` : ""}</td>
      <td>${escapeHTML(node.protocol)}</td>
      <td>${escapeHTML(node.address || "--")}</td>
      <td>${node.port || "--"}</td>
      <td>${formatBytes(node.upload_bytes)}</td>
      <td>${formatBytes(node.download_bytes)}</td>
      <td>${formatLatency(node)}</td>
      <td><span class="${statusBadgeClass(node)}" title="${escapeHTML(hint)}">${escapeHTML(node.status)}</span></td>
      <td>
        <div class="row-actions">
          <button class="icon-button" data-test-type="outbound" data-test-name="${escapeHTML(node.name)}" type="button">连通测试</button>
          <button class="icon-button" data-edit-outbound="${escapeHTML(node.name)}" type="button">编辑</button>
          <button class="icon-button" data-inspect-outbound="${escapeHTML(node.name)}" type="button">检查</button>
          <button class="icon-button" data-share-outbound="${escapeHTML(node.name)}" type="button">分享</button>
          <button class="icon-button" data-toggle-type="outbound" data-toggle-name="${escapeHTML(node.name)}" data-toggle-enabled="${node.enabled ? "false" : "true"}" type="button">${node.enabled ? "停用" : "启用"}</button>
          <button class="icon-button" data-delete-type="outbound" data-delete-name="${escapeHTML(node.name)}" type="button">删除</button>
        </div>
      </td>
      <td><input type="checkbox" data-node-check="outbound" value="${escapeHTML(node.name)}"${state.selected.outbound.has(node.name) ? " checked" : ""}></td>
    </tr>
  `;
  }).join("") || `<tr><td colspan="10" class="empty-cell">还没有出站节点，可以导入链接或手动添加。</td></tr>`;
};

const refreshLogs = async () => {
  const logOutput = document.getElementById("logOutput");
  if (!logOutput) return;
  const query = new URLSearchParams({
    q: document.getElementById("logSearch")?.value || "",
    lines: document.getElementById("logLines")?.value || "200",
  });
  const logRes = await fetch(`/api/logs?${query.toString()}`);
  if (logRes.ok) {
    const payload = await logRes.json();
    logOutput.textContent = payload.logs || "";
    setText("logUpdated", new Date().toLocaleTimeString());
  }
};

const renderOutboundOptions = () => {
  const outbounds = getOutbounds();
  const defaultSelect = document.getElementById("defaultOutboundSelect");
  if (defaultSelect) {
    const current = defaultSelect.value || state.config?.routing?.default_outbound || "direct";
    defaultSelect.innerHTML = `<option value="direct">direct</option>` + outbounds
      .map((node) => `<option value="${escapeHTML(node.name)}">${escapeHTML(node.name)} / ${escapeHTML(node.protocol)}</option>`)
      .join("");
    defaultSelect.value = current;
  }
};

const renderRoutingPreviewOptions = () => {
  const inboundSelect = document.getElementById("routingPreviewInbound");
  if (!inboundSelect) return;
  const current = inboundSelect.value;
  inboundSelect.innerHTML = getInbounds()
    .map((node) => `<option value="${escapeHTML(node.name)}">${escapeHTML(node.name)} / ${escapeHTML(node.protocol)}</option>`)
    .join("") || `<option value="">无入站</option>`;
  if (current) inboundSelect.value = current;
};

const renderSecurity = (security) => {
  setText("securityUser", security.username || "--");
  setText("securityDefaultPassword", security.default_password ? "存在风险" : "未检测到");
  setText("securitySessions", String(security.active_sessions ?? "--"));
  setText("securityLoginLimit", `${security.login_failure_limit || 6} 次 / ${security.login_failure_window || "15 分钟"}`);
  const warnings = document.getElementById("securityWarnings");
  if (warnings) {
    warnings.textContent = (security.warnings || []).length > 0
      ? security.warnings.map((item) => `风险: ${item}`).join("\n")
      : "未发现默认密码风险。仍建议定期更换强密码，并只在可信网络开放面板。";
  }
};

const formValues = (form) => {
  const values = {};
  if (!form) return values;
  for (const element of Array.from(form.elements)) {
    if (!element.name || element.name === "enabled") continue;
    values[element.name] = element.type === "checkbox" ? element.checked : element.value;
  }
  return values;
};

const applyValues = (container, values) => {
  if (!container) return;
  for (const element of Array.from(container.querySelectorAll("input, select, textarea"))) {
    if (!element.name || !(element.name in values)) continue;
    if (element.type === "checkbox") {
      element.checked = Boolean(values[element.name]);
    } else {
      element.value = values[element.name] ?? "";
    }
  }
};

const usesTLS = (values, defaultOn = false) => values.tls === true || values.tls === "true" || values.tls === "on" || (values.tls === undefined && defaultOn);
const usesTransportFields = (values) => ["ws", "http", "grpc"].includes(values.transport || "tcp");

const inboundFieldsFor = (protocol, values = {}) => {
  if (protocol === "vless") {
    const security = values.security || "none";
    const fields = [
      ["listen", "监听地址", "0.0.0.0", "select", inboundListenOptions],
      ["uuid", "UUID", ""],
      ["flow", "Flow", "", "select", ["", "xtls-rprx-vision"]],
      ["security", "安全", "none", "select", ["none", "reality"]],
    ];
    if (security === "reality") {
      fields.push(
        ["server_name", "可选域名 / SNI", "addons.mozilla.org"],
        ["private_key", "Reality 私钥", ""],
        ["short_id", "Short IDs", ""],
        ["reality_handshake_server", "目标网站", "addons.mozilla.org"],
        ["reality_handshake_port", "目标端口", "443", "number"],
      );
    } else {
      fields.push(["tls", "TLS", "", "checkbox"]);
      if (usesTLS(values)) {
        fields.push(["server_name", "Server Name", "example.com"], ...tlsCertificateFields);
      }
    }
    fields.push(["transport", "传输", "tcp", "select", transportOptions]);
    if (usesTransportFields(values)) fields.push(["path", "路径 / Service Name", "/"], ["host", "Host", ""]);
    return fields;
  }
  if (protocol === "vmess") {
    const fields = [
      ["listen", "监听地址", "0.0.0.0", "select", inboundListenOptions],
      ["uuid", "UUID", ""],
      ["alter_id", "Alter ID", "0", "number"],
      ["tls", "TLS", "", "checkbox"],
    ];
    if (usesTLS(values)) fields.push(["server_name", "Server Name", "example.com"], ...tlsCertificateFields);
    fields.push(["transport", "传输", "tcp", "select", transportOptions]);
    if (usesTransportFields(values)) fields.push(["path", "路径", "/ws"], ["host", "Host", ""]);
    return fields;
  }
  if (protocol === "trojan") {
    const fields = [
      ["listen", "监听地址", "0.0.0.0", "select", inboundListenOptions],
      ["password", "密码", "", "password"],
      ["tls", "TLS", "true", "checkbox"],
    ];
    if (usesTLS(values, true)) fields.push(["server_name", "Server Name", "example.com"], ...tlsCertificateFields);
    fields.push(["transport", "传输", "tcp", "select", transportOptions]);
    if (usesTransportFields(values)) fields.push(["path", "路径", "/"], ["host", "Host", ""]);
    return fields;
  }
  if (protocol === "anytls") {
    return [
      ["listen", "监听地址", "0.0.0.0", "select", inboundListenOptions],
      ["password", "密码", "", "password"],
      ["server_name", "Server Name", "example.com"],
      ...tlsCertificateFields,
    ];
  }
  return inboundSchemas[protocol] || inboundSchemas.mixed;
};

const renderInboundFields = () => {
  const select = document.getElementById("inboundProtocolSelect");
  const container = document.getElementById("inboundDynamicFields");
  if (!select || !container) return;
  const form = document.getElementById("inboundForm");
  const values = formValues(form);
  const protocol = select.value || "mixed";
  container.innerHTML = inboundFieldsFor(protocol, values).map((field) => fieldControl(field, values)).join("");
  applyValues(container, values);
};

const renderSystem = (kernels, service, environment, ports) => {
  const rows = document.getElementById("kernelProbeRows");
  if (rows) {
    rows.innerHTML = (kernels || []).map((kernel) => `
      <tr>
        <td>${escapeHTML(kernel.name)}</td>
        <td><span class="badge ${kernel.installed ? "" : "badge-muted"}">${kernel.installed ? "已安装" : "未安装"}</span></td>
        <td>${escapeHTML(kernel.path || "--")}</td>
        <td>${escapeHTML(kernel.version || kernel.error || "--")}</td>
      </tr>
    `).join("");
  }
  setText("serviceSystemd", service.systemd ? "可用" : "不可用");
  setText("serviceInstalled", service.installed ? "已安装" : "未安装");
  setText("serviceActive", service.active || "--");
  setText("serviceEnabled", service.enabled || "--");
  setText("envVersion", `${environment.agent_version || state.status.version || "--"} / ${state.status.commit || environment.agent_build_time || "dev"}`);
  setText("envOS", `${environment.release || environment.os || "--"} ${environment.arch || ""}`.trim());
  setText("envHost", environment.hostname || "--");
  setText("envUser", environment.user || "--");
  setText("envTools", [
    environment.systemd ? "systemd" : "",
    environment.has_ss ? "ss" : "",
    environment.has_netstat ? "netstat" : "",
    environment.has_curl ? "curl" : "",
    environment.has_unzip ? "unzip" : "",
  ].filter(Boolean).join(" / ") || "--");
  const portRows = document.getElementById("portRows");
  if (portRows) {
    portRows.innerHTML = (ports.ports || []).map((port) => `
      <tr title="${escapeHTML(port.raw || "")}">
        <td>${escapeHTML(port.protocol || "--")}</td>
        <td>${escapeHTML(port.local_address || "--")}</td>
        <td>${escapeHTML(port.process || "--")}</td>
      </tr>
    `).join("") || `<tr><td colspan="3" class="empty-cell">${escapeHTML(ports.error || "没有读取到监听端口")}</td></tr>`;
  }
  setText("systemUpdated", new Date().toLocaleTimeString());
  const commands = document.getElementById("serviceCommands");
  if (commands) commands.value = (service.commands || []).join("\n");
  const unit = document.getElementById("serviceUnit");
  if (unit) unit.value = service.unit || "";
};

const fillMihomoForm = (mihomo) => {
  const form = document.getElementById("mihomoForm");
  if (!form) return;
  const provider = mihomo.providers?.[0] || {};
  const group = mihomo.proxy_groups?.[0] || {};
  form.elements.provider_name.value = provider.name || "";
  form.elements.provider_url.value = provider.url || "";
  form.elements.group_name.value = group.name || "NodeTools";
  form.elements.group_type.value = group.type || "select";
  form.elements.rules.value = (mihomo.rules || ["MATCH,NodeTools"]).join("\n");
};

const fillRoutingForm = (routing) => {
  const form = document.getElementById("routingForm");
  if (!form) return;
  renderOutboundOptions();
  form.elements.mode.value = routing.mode || "rule";
  form.elements.preset.value = routing.preset || "custom";
  form.elements.default_outbound.value = routing.default_outbound || "direct";
  renderRoutingRules(routing.rules || []);
  updateRoutingModeUI();
};

const routingValuePlaceholder = (matchType) => ({
  inbound: "选择入站",
  domain: "example.com",
  domain_suffix: "google.com",
  domain_keyword: "google",
  ip_cidr: "8.8.8.0/24",
  geoip: "cn",
  geosite: "cn",
  protocol: "tcp 或 udp",
  port: "443",
}[matchType] || "");

const routingRuleValue = (rule) => rule.value || rule.inbound || "";

const routingRuleMatchType = (rule) => rule.match_type || (rule.inbound ? "inbound" : "domain_suffix");

const routingOutboundOptionsHTML = (current = "") => [
  `<option value="direct"${current === "direct" ? " selected" : ""}>direct</option>`,
  ...getOutbounds().map((node) => `<option value="${escapeHTML(node.name)}"${node.name === current ? " selected" : ""}>${escapeHTML(node.name)} / ${escapeHTML(node.protocol)}</option>`),
].join("");

const routingInboundOptionsHTML = (current = "") => getInbounds()
  .map((node) => `<option value="${escapeHTML(node.name)}"${node.name === current ? " selected" : ""}>${escapeHTML(node.name)} / ${escapeHTML(node.protocol)}</option>`)
  .join("");

const routingValueControl = (matchType, value) => {
  if (matchType === "inbound") {
    const options = routingInboundOptionsHTML(value);
    return `<select name="value">${options || `<option value="">请先添加入站</option>`}</select>`;
  }
  return `<input name="value" value="${escapeHTML(value)}" placeholder="${escapeHTML(routingValuePlaceholder(matchType))}">`;
};

const renderRoutingRules = (rules = []) => {
  const rows = document.getElementById("routingRuleRows");
  if (!rows) return;
  rows.innerHTML = rules.map((rule, index) => {
    const matchType = routingRuleMatchType(rule);
    const value = routingRuleValue(rule);
    const priority = rule.priority || (index + 1) * 10;
    return `
      <tr data-routing-rule>
        <td><input name="priority" type="number" min="1" value="${priority}"></td>
        <td>
          <select name="match_type">
            ${routingMatchTypes.map(([key, label]) => `<option value="${key}"${key === matchType ? " selected" : ""}>${label}</option>`).join("")}
          </select>
        </td>
        <td data-routing-value>${routingValueControl(matchType, value)}</td>
        <td><select name="outbound">${routingOutboundOptionsHTML(rule.outbound || "direct")}</select></td>
        <td>
          <select name="enabled">
            <option value="true"${rule.disabled ? "" : " selected"}>启用</option>
            <option value="false"${rule.disabled ? " selected" : ""}>停用</option>
          </select>
        </td>
        <td><button type="button" class="icon-button" data-delete-routing-rule>删除</button></td>
      </tr>
    `;
  }).join("") || `<tr><td colspan="6" class="empty-cell">还没有分流规则；未命中流量会走默认出站。</td></tr>`;
};

const collectRoutingRules = () => Array.from(document.querySelectorAll("[data-routing-rule]"))
  .map((row, index) => {
    const matchType = row.querySelector('[name="match_type"]')?.value || "domain_suffix";
    const value = row.querySelector('[name="value"]')?.value || "";
    const outbound = row.querySelector('[name="outbound"]')?.value || "direct";
    const priority = Number(row.querySelector('[name="priority"]')?.value || (index + 1) * 10);
    const rule = {
      name: `${matchType}-${index + 1}`,
      match_type: matchType,
      value,
      outbound,
      priority,
      disabled: row.querySelector('[name="enabled"]')?.value === "false",
    };
    if (matchType === "inbound") rule.inbound = value;
    return rule;
  })
  .filter((rule) => rule.value && rule.outbound);

const addRoutingRule = (rule = {}) => {
  const preset = document.getElementById("routingPresetInput");
  if (preset) preset.value = "custom";
  const current = collectRoutingRules();
  current.push({
    match_type: rule.match_type || "domain_suffix",
    value: rule.value || "",
    inbound: rule.inbound || "",
    outbound: rule.outbound || document.getElementById("defaultOutboundSelect")?.value || "direct",
    priority: rule.priority || (current.length + 1) * 10,
    disabled: Boolean(rule.disabled),
  });
  renderRoutingRules(current);
};

const applyBypassChinaPreset = () => {
  const defaultSelect = document.getElementById("defaultOutboundSelect");
  if (defaultSelect?.value === "direct") {
    const firstOutbound = getOutbounds()[0]?.name;
    if (firstOutbound) defaultSelect.value = firstOutbound;
  }
  document.getElementById("routingModeSelect").value = "rule";
  document.getElementById("routingPresetInput").value = "bypass_cn";
  renderRoutingRules([
    { match_type: "ip_cidr", value: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,127.0.0.0/8,100.64.0.0/10", outbound: "direct", priority: 10 },
    { match_type: "geosite", value: "cn", outbound: "direct", priority: 20 },
    { match_type: "geoip", value: "cn", outbound: "direct", priority: 30 },
  ]);
  updateRoutingModeUI();
};

const updateRoutingModeUI = () => {
  const mode = document.getElementById("routingModeSelect")?.value || "rule";
  const defaultSelect = document.getElementById("defaultOutboundSelect");
  const rulesPanel = document.getElementById("routingRulesPanel");
  const addButton = document.getElementById("addRoutingRuleButton");
  const presetButton = document.getElementById("bypassChinaPresetButton");
  const hint = document.getElementById("routingModeHint");

  const ruleMode = mode === "rule";
  const globalMode = mode === "global";
  if (defaultSelect) {
    defaultSelect.disabled = mode === "direct";
    defaultSelect.closest("label")?.classList.toggle("routing-disabled", mode === "direct");
  }
  if (rulesPanel) rulesPanel.hidden = !ruleMode;
  if (addButton) addButton.hidden = !ruleMode;
  if (presetButton) presetButton.hidden = !ruleMode;
  if (hint) {
    hint.textContent = {
      direct: "全部直连：所有流量直接从 VPS 出口访问，不使用默认出站，分流规则不会生效。",
      global: "全局代理：所有流量都走默认出站，下面的分流规则不会生效。",
      rule: "规则分流：先按下方规则匹配，未命中流量走默认出站。sing-box 1.12+ 不再支持旧 GeoIP/Geosite 字段，相关规则不会写入 sing-box，mihomo 可用。",
    }[mode] || "";
  }
  if (globalMode) document.getElementById("routingPresetInput").value = "custom";
};

const mihomoPayloadFromForm = (form) => {
  const data = formToObject(form);
  const provider = data.provider_name && data.provider_url ? [{
    name: data.provider_name,
    type: "http",
    url: data.provider_url,
    interval: 3600,
    health_check_url: "http://www.gstatic.com/generate_204",
    health_check_lazy: true,
  }] : [];
  const groupName = data.group_name || "NodeTools";
  return {
    providers: provider,
    proxy_groups: [{
      name: groupName,
      type: data.group_type || "select",
      proxies: ["DIRECT"],
      use: provider.map((item) => item.name),
    }],
    rules: String(data.rules || "MATCH," + groupName)
      .split(/\r?\n/)
      .map((line) => line.trim())
      .filter(Boolean),
  };
};

const saveMihomoConfig = async () => {
  const form = document.getElementById("mihomoForm");
  if (!form) return;
  await sendJSON("/api/mihomo/config", "PUT", mihomoPayloadFromForm(form));
  state.configLoaded = false;
};

const renderSubscriptionUpdateResult = (payload) => {
  const output = document.getElementById("subscriptionPreview");
  const lines = subscriptionResultLines(payload);
  if (output) output.textContent = lines.join("\n") || "没有可更新的订阅";
};

const subscriptionResultLines = (payload) => (payload.results || []).flatMap((item) => [
  `订阅: ${item.provider || item.url}`,
  `解析: ${item.parsed} / 导入: ${item.imported} / 新增: ${item.added || 0} / 更新: ${item.updated || 0} / 未变化: ${item.unchanged || 0}`,
  `节点: ${(item.imported_nodes || []).slice(0, 20).join(", ") || "--"}`,
  ...((item.warnings || []).slice(0, 10).map((warning) => `提示: ${warning}`)),
  ...((item.errors || []).map((error) => `错误: ${error}`)),
]);

const importResultLines = (payload) => {
  const lines = [
    `解析节点: ${payload.parsed}`,
    `导入节点: ${(payload.imported || []).length}`,
    `新增: ${payload.added || 0} / 更新: ${payload.updated || 0} / 未变化: ${payload.unchanged || 0}`,
  ];
  const details = payload.details || [];
  if (details.length > 0) {
    lines.push("明细:");
    lines.push(...details.slice(0, 30).map((item) => {
      const preserved = item.preserved_name ? "，保留原名称" : "";
      const warnings = (item.warnings || []).length ? `，提示: ${item.warnings.join("；")}` : "";
      return `- ${item.action}: ${item.name} / ${item.protocol} / ${item.address}:${item.port}${preserved}${warnings}`;
    }));
  }
  if ((payload.errors || []).length > 0) {
    lines.push("部分错误:");
    lines.push(...payload.errors.slice(0, 8));
  }
  return lines;
};

const showPage = (page) => {
  state.page = page;
  document.querySelectorAll("[data-page]").forEach((view) => {
    view.classList.toggle("active", view.dataset.page === page);
  });
  document.querySelectorAll("[data-page-target]").forEach((button) => {
    button.classList.toggle("active", button.dataset.pageTarget === page);
  });
  setText("pageTitle", pageTitles[page] || "NodeTools");
};

const openModal = (id) => {
  const backdrop = document.getElementById("modalBackdrop");
  const modal = document.getElementById(id);
  if (!backdrop || !modal) return;
  backdrop.hidden = false;
  document.querySelectorAll(".modal").forEach((item) => {
    item.hidden = item.id !== id;
  });
  document.body.classList.add("modal-open");
  if (id === "inboundModal") {
    renderInboundFields();
  }
  if (id === "outboundModal") renderOutboundFields();
};

const openInboundEditor = (name) => {
  const form = document.getElementById("inboundForm");
  const inbound = getInboundConfig(name);
  if (!form || !inbound) return;
  form.reset();
  form.elements.original_name.value = inbound.name;
  fillForm(form, inbound);
  document.getElementById("inboundProtocolSelect").value = inbound.protocol;
  renderInboundFields();
  fillForm(form, inbound);
  openModal("inboundModal");
};

const openOutboundEditor = (name) => {
  const form = document.getElementById("outboundForm");
  const outbound = getOutboundConfig(name);
  if (!form || !outbound) return;
  form.reset();
  form.elements.original_name.value = outbound.name;
  const title = document.getElementById("outboundModalTitle");
  if (title) title.textContent = "编辑出站";
  document.getElementById("outboundProtocolSelect").value = outbound.protocol;
  openModal("outboundModal");
  renderOutboundFields(outbound);
  fillForm(form, outbound);
};

const closeModal = () => {
  document.getElementById("modalBackdrop")?.setAttribute("hidden", "");
  document.querySelectorAll(".modal").forEach((item) => item.hidden = true);
  document.body.classList.remove("modal-open");
};

const fieldControl = ([name, label, placeholder, type = "text", options = []], values = {}) => {
  const current = values[name] ?? "";
  if (type === "checkbox") {
    const checked = current === true || current === "true" || current === "on" || (current === "" && placeholder === "true") ? " checked" : "";
    return `
      <label class="check-label">
        <input name="${name}" type="checkbox"${checked}>
        ${label}
      </label>
    `;
  }
  if (type === "select") {
    return `
      <label>${label}
        <select name="${name}">
          ${options.map((option) => `<option value="${option}"${option === (current || placeholder) ? " selected" : ""}>${option || "无"}</option>`).join("")}
        </select>
      </label>
    `;
  }
  if (type === "textarea") {
    return `
      <label class="full-width">${label}
        <textarea name="${name}" rows="4" placeholder="${escapeHTML(placeholder)}">${escapeHTML(current)}</textarea>
      </label>
    `;
  }
  return `
    <label>${label}
      <input name="${name}" type="${type}" value="${escapeHTML(current)}" placeholder="${escapeHTML(placeholder)}">
    </label>
  `;
};

const renderOutboundProtocolOptions = () => {
  const select = document.getElementById("outboundProtocolSelect");
  if (!select) return;
  select.innerHTML = outboundProtocols.map((protocol) => `<option value="${protocol}">${protocol}</option>`).join("");
};

const renderOutboundFields = (values = {}) => {
  const select = document.getElementById("outboundProtocolSelect");
  const container = document.getElementById("outboundDynamicFields");
  if (!select || !container) return;
  const protocol = values.protocol || select.value || "vless";
  select.value = protocol;
  container.innerHTML = (outboundSchemas[protocol] || outboundSchemas.vless).map((field) => fieldControl(field, values)).join("");
};

const showShareLink = async (name, link) => {
  const text = document.getElementById("shareLinkText");
  const qr = document.getElementById("shareQRCode");
  if (text) text.value = link;
  if (qr) {
    qr.src = `https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(link)}`;
  }
  openModal("shareModal");
  await navigator.clipboard?.writeText(link);
};

const inspectionLines = (inspection) => {
  const lines = [
    `节点: ${inspection.name}`,
    `协议: ${inspection.protocol}`,
  ];
  if ((inspection.missing || []).length > 0) {
    lines.push(`缺失字段: ${inspection.missing.join(", ")}`);
  } else {
    lines.push("缺失字段: 无");
  }
  if ((inspection.warnings || []).length > 0) {
    lines.push(...inspection.warnings.map((warning) => `提示: ${warning}`));
  }
  lines.push("保存字段:");
  Object.entries(inspection.saved || {}).forEach(([key, value]) => {
    if (value) lines.push(`  ${key}: ${value}`);
  });
  if (inspection.raw) {
    lines.push("原始链接解析字段:");
    Object.entries(inspection.raw || {}).forEach(([key, value]) => {
      if (value) lines.push(`  ${key}: ${value}`);
    });
  }
  return lines;
};

const selectedBatchProtocols = (form) => [
  ["vless_reality", "vless-reality"],
  ["shadowtls", "shadowtls"],
  ["shadowsocks", "shadowsocks"],
  ["trojan", "trojan"],
  ["anytls", "anytls"],
].filter(([field]) => form.elements[field]?.checked).map(([, protocol]) => protocol);

const buildBatchInboundPayload = async (protocol, base) => {
  const name = `${base.prefix}-${protocol}`;
  const common = {
    name,
    listen: base.listen,
    port: base.port,
  };
  switch (protocol) {
  case "vless-reality": {
    const keyPair = await postJSON("/api/reality/keypair", {});
    return {
      ...common,
      name: `${base.prefix}-VLESS-Reality`,
      protocol: "vless",
      uuid: randomUUID(),
      flow: "xtls-rprx-vision",
      security: "reality",
      tls: true,
      server_name: base.serverName,
      private_key: keyPair.private_key,
      short_id: ["", randomHex(4), randomHex(6), randomHex(8)].join(","),
      reality_handshake_server: base.realityServer,
      reality_handshake_port: 443,
      transport: "tcp",
    };
  }
  case "shadowtls":
    return {
      ...common,
      name: `${base.prefix}-ShadowTLS-v3`,
      protocol: "shadowtls",
      method: "aes-128-gcm",
      password: randomPassword(),
      server_name: base.serverName,
      reality_handshake_server: base.realityServer,
      reality_handshake_port: 443,
    };
  case "shadowsocks":
    return {
      ...common,
      name: `${base.prefix}-Shadowsocks`,
      protocol: "shadowsocks",
      method: "2022-blake3-aes-128-gcm",
      password: randomBase64(16),
    };
  case "trojan":
    return {
      ...common,
      name: `${base.prefix}-Trojan`,
      protocol: "trojan",
      password: randomPassword(),
      tls: true,
      server_name: base.serverName,
      transport: "tcp",
    };
  case "anytls":
    return {
      ...common,
      name: `${base.prefix}-AnyTLS`,
      protocol: "anytls",
      password: randomPassword(),
      tls: true,
      server_name: base.serverName,
    };
  default:
    throw new Error(`不支持的批量协议: ${protocol}`);
  }
};

document.querySelectorAll("[data-page-target]").forEach((button) => {
  button.addEventListener("click", () => showPage(button.dataset.pageTarget));
});

document.getElementById("inboundSearch")?.addEventListener("input", renderInbounds);
document.getElementById("outboundSearch")?.addEventListener("input", renderOutbounds);
document.getElementById("logSearch")?.addEventListener("input", refreshLogs);
document.getElementById("logLines")?.addEventListener("change", refreshLogs);
document.getElementById("refreshLogsButton")?.addEventListener("click", refreshLogs);
document.getElementById("refreshSystemButton")?.addEventListener("click", refresh);

document.getElementById("openInboundModalButton")?.addEventListener("click", () => {
  const form = document.getElementById("inboundForm");
  form?.reset();
  if (form?.elements.original_name) form.elements.original_name.value = "";
  renderInboundFields();
  openModal("inboundModal");
});
document.getElementById("openBatchInboundModalButton")?.addEventListener("click", () => {
  const form = document.getElementById("batchInboundForm");
  form?.reset();
  const result = document.getElementById("batchInboundResult");
  if (result) result.textContent = "";
  openModal("batchInboundModal");
});
document.getElementById("openOutboundModalButton")?.addEventListener("click", () => {
  const form = document.getElementById("outboundForm");
  form?.reset();
  if (form?.elements.original_name) form.elements.original_name.value = "";
  const title = document.getElementById("outboundModalTitle");
  if (title) title.textContent = "手动添加出站";
  renderOutboundFields();
  openModal("outboundModal");
});
document.querySelectorAll("[data-close-modal]").forEach((button) => button.addEventListener("click", closeModal));
document.getElementById("modalBackdrop")?.addEventListener("click", (event) => {
  if (event.target.id === "modalBackdrop") closeModal();
});

renderOutboundProtocolOptions();
document.getElementById("inboundProtocolSelect")?.addEventListener("change", renderInboundFields);
document.getElementById("inboundDynamicFields")?.addEventListener("change", (event) => {
  if (["security", "tls", "transport"].includes(event.target.name)) renderInboundFields();
});
document.getElementById("outboundProtocolSelect")?.addEventListener("change", renderOutboundFields);
document.getElementById("routingModeSelect")?.addEventListener("change", updateRoutingModeUI);
document.getElementById("addRoutingRuleButton")?.addEventListener("click", () => addRoutingRule());
document.getElementById("bypassChinaPresetButton")?.addEventListener("click", applyBypassChinaPreset);
document.getElementById("routingRuleRows")?.addEventListener("change", (event) => {
  const preset = document.getElementById("routingPresetInput");
  if (preset) preset.value = "custom";
  const matchSelect = event.target.closest('[name="match_type"]');
  if (!matchSelect) return;
  const row = matchSelect.closest("[data-routing-rule]");
  const cell = row?.querySelector("[data-routing-value]");
  if (cell) cell.innerHTML = routingValueControl(matchSelect.value, "");
});
document.getElementById("routingRuleRows")?.addEventListener("click", (event) => {
  const button = event.target.closest("[data-delete-routing-rule]");
  if (!button) return;
  const preset = document.getElementById("routingPresetInput");
  if (preset) preset.value = "custom";
  button.closest("[data-routing-rule]")?.remove();
  if (!document.querySelector("[data-routing-rule]")) renderRoutingRules([]);
});
renderInboundFields();
renderOutboundFields();

document.addEventListener("change", (event) => {
  const nodeCheck = event.target.closest("[data-node-check]");
  if (nodeCheck) {
    const scope = nodeCheck.dataset.nodeCheck;
    if (nodeCheck.checked) {
      state.selected[scope]?.add(nodeCheck.value);
    } else {
      state.selected[scope]?.delete(nodeCheck.value);
    }
    return;
  }
  const selectAll = event.target.closest("[data-select-all]");
  if (!selectAll) return;
  document.querySelectorAll(`[data-node-check="${selectAll.dataset.selectAll}"]`).forEach((checkbox) => {
    checkbox.checked = selectAll.checked;
    if (checkbox.checked) {
      state.selected[selectAll.dataset.selectAll]?.add(checkbox.value);
    } else {
      state.selected[selectAll.dataset.selectAll]?.delete(checkbox.value);
    }
  });
});

const checkedNodes = (scope) => Array.from(document.querySelectorAll(`[data-node-check="${scope}"]:checked`))
  .map((item) => ({ type: scope, name: item.value }));

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-batch-action]");
  if (!button) return;
  const scope = button.dataset.batchScope;
  const items = checkedNodes(scope);
  if (items.length === 0) {
    alert("请先选择节点");
    return;
  }
  try {
    if (button.dataset.batchAction === "test") {
      await postJSON("/api/nodes/batch/test", { items });
    }
    if (button.dataset.batchAction === "disable") {
      await sendJSON("/api/nodes/batch/enabled", "PATCH", { items, enabled: false });
    }
    await refresh();
  } catch (error) {
    if (button.dataset.batchAction === "test") {
      button.textContent = "timeout";
      return;
    }
    alert(error.message);
  }
});

const loginForm = document.getElementById("loginForm");
if (loginForm) {
  loginForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const error = document.getElementById("loginError");
    if (error) error.textContent = "";
    try {
      await postJSON("/api/login", formToObject(loginForm));
      location.href = "/";
    } catch (err) {
      if (error) error.textContent = err.message;
    }
  });
}

document.getElementById("logoutButton")?.addEventListener("click", async () => {
  await fetch("/api/logout", { method: "POST" });
  location.href = "/login";
});

document.getElementById("reloadKernelButton")?.addEventListener("click", async () => {
  try {
    await postJSON("/api/kernel/reload", {});
    await refresh();
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById("stopKernelButton")?.addEventListener("click", async () => {
  try {
    await postJSON("/api/kernel/stop", {});
    await refresh();
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById("copyShareLinkButton")?.addEventListener("click", async () => {
  const link = document.getElementById("shareLinkText")?.value || "";
  if (!link) return;
  await navigator.clipboard?.writeText(link);
  alert("分享链接已复制");
});

document.getElementById("restartServiceButton")?.addEventListener("click", async () => {
  if (!confirm("确定要重启 Agent 服务吗？面板会短暂断开。")) return;
  try {
    await postJSON("/api/system/service/restart", {});
    alert("已提交重启，几秒后页面会自动刷新。");
    setTimeout(refresh, 4000);
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById("clearImportButton")?.addEventListener("click", () => {
  const text = document.getElementById("importLinksText");
  const result = document.getElementById("importResult");
  if (text) text.value = "";
  if (result) result.textContent = "";
});

document.getElementById("importOutboundsButton")?.addEventListener("click", async () => {
  const text = document.getElementById("importLinksText")?.value || "";
  const result = document.getElementById("importResult");
  if (result) result.textContent = "解析中...";
  try {
    const payload = await postJSON("/api/outbounds/import", { text });
    if (result) result.textContent = importResultLines(payload).join("\n");
    state.configLoaded = false;
    await refresh();
  } catch (error) {
    if (result) result.textContent = error.message;
  }
});

document.getElementById("updateSubscriptionsButton")?.addEventListener("click", async () => {
  const result = document.getElementById("importResult");
  if (result) result.textContent = "更新订阅中...";
  try {
    const payload = await postJSON("/api/subscriptions/update", {});
    const lines = subscriptionResultLines(payload);
    if (result) result.textContent = lines.join("\n") || "没有可更新的订阅";
    state.configLoaded = false;
    await refresh();
  } catch (error) {
    if (result) result.textContent = error.message;
  }
});

document.getElementById("generateRealityKeyButton")?.addEventListener("click", async () => {
  const form = document.getElementById("inboundForm");
  try {
    const protocol = document.getElementById("inboundProtocolSelect");
    if (protocol) {
      protocol.value = "vless";
      renderInboundFields();
    }
    const keyPair = await postJSON("/api/reality/keypair", {});
    const uuid = randomUUID();
    const shortIds = ["", randomHex(4), randomHex(6), randomHex(8)].join(",");
    if (form?.elements.uuid) form.elements.uuid.value = uuid;
    if (form?.elements.flow) form.elements.flow.value = "xtls-rprx-vision";
    if (form?.elements.security) form.elements.security.value = "reality";
    if (form?.elements.tls) form.elements.tls.checked = true;
    if (form?.elements.server_name) form.elements.server_name.value = "addons.mozilla.org";
    if (form?.elements.private_key) form.elements.private_key.value = keyPair.private_key;
    if (form?.elements.short_id) form.elements.short_id.value = shortIds;
    if (form?.elements.reality_handshake_server) form.elements.reality_handshake_server.value = "addons.mozilla.org";
    if (form?.elements.reality_handshake_port) form.elements.reality_handshake_port.value = 443;
    await navigator.clipboard?.writeText(keyPair.public_key);
    alert(`Reality 参数已生成。\nPublic Key 已复制：\n${keyPair.public_key}`);
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById("inboundForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formToObject(form);
  const editing = Boolean(data.original_name);
  delete data.original_name;
  delete data.share_host;
  delete data.outbound;
  try {
    if (editing) {
      await sendJSON("/api/inbounds", "PUT", data);
    } else {
      await postJSON("/api/proxy/create", data);
    }
    form.reset();
    closeModal();
    await refresh();
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById("batchInboundForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const protocols = selectedBatchProtocols(form);
  const output = document.getElementById("batchInboundResult");
  if (protocols.length === 0) {
    if (output) output.textContent = "请至少选择一个协议";
    return;
  }
  const data = formToObject(form);
  const base = {
    prefix: data.prefix || "NodeTools",
    listen: data.listen || "0.0.0.0",
    port: Number(data.start_port || 30000),
    realityServer: data.reality_server || "addons.mozilla.org",
    serverName: data.server_name || "addons.mozilla.org",
  };
  const lines = [];
  try {
    for (let index = 0; index < protocols.length; index += 1) {
      const payload = await buildBatchInboundPayload(protocols[index], { ...base, port: base.port + index });
      await postJSON("/api/proxy/create", payload);
      lines.push(`${payload.name}: ${payload.protocol} / ${payload.listen}:${payload.port}`);
      if (output) output.textContent = lines.join("\n");
    }
    state.configLoaded = false;
    await refresh();
    if (output) output.textContent = `${lines.join("\n")}\n\n批量搭建完成。可在入站列表逐个点击分享查看链接和二维码。`;
  } catch (error) {
    if (output) output.textContent = `${lines.join("\n")}\n错误: ${error.message}`;
  }
});

document.getElementById("outboundForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = formToObject(form);
  try {
    await sendJSON("/api/outbounds", "PUT", data);
    form.reset();
    renderOutboundFields();
    closeModal();
    await refresh();
  } catch (error) {
    alert(error.message);
  }
});

const applyKernelDefaults = (form) => {
  if (!form) return;
  const type = form.elements.type?.value || "placeholder";
  const defaults = {
    "sing-box": ["/usr/local/bin/sing-box", "sing-box.generated.json"],
    mihomo: ["/usr/local/bin/mihomo", "mihomo.generated.yaml"],
    placeholder: ["", "kernel.generated.json"],
  };
  const [executable, configPath] = defaults[type] || defaults.placeholder;
  if (form.elements.executable) form.elements.executable.value = executable;
  if (form.elements.config_path) form.elements.config_path.value = configPath;
};

document.getElementById("kernelForm")?.elements.type?.addEventListener("change", (event) => {
  applyKernelDefaults(event.currentTarget.form);
});

document.getElementById("kernelForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await sendJSON("/api/kernel/config", "PUT", formToObject(event.currentTarget));
    state.configLoaded = false;
    await refresh();
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById("mihomoForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await saveMihomoConfig();
    const output = document.getElementById("subscriptionPreview");
    if (output) output.textContent = "订阅设置已保存。需要导入节点时点击“保存并拉取节点”。";
    await refresh();
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById("saveAndUpdateSubscriptionButton")?.addEventListener("click", async () => {
  const output = document.getElementById("subscriptionPreview");
  if (output) output.textContent = "保存并拉取节点中...";
  try {
    await saveMihomoConfig();
    const payload = await postJSON("/api/subscriptions/update", {});
    renderSubscriptionUpdateResult(payload);
    await refresh();
    showPage("outbounds");
    const result = document.getElementById("importResult");
    if (result) result.textContent = subscriptionResultLines(payload).join("\n") || "没有可更新的订阅";
  } catch (error) {
    if (output) output.textContent = error.message;
  }
});

document.getElementById("routingForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = formToObject(event.currentTarget);
  const payload = {
    mode: data.mode || "rule",
    preset: data.preset || "custom",
    default_outbound: data.default_outbound || "direct",
    rules: collectRoutingRules(),
  };
  try {
    await sendJSON("/api/routing/config", "PUT", payload);
    state.configLoaded = false;
    await refresh();
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById("previewRoutingButton")?.addEventListener("click", async () => {
  const output = document.getElementById("routingPreviewOutput");
  if (output) output.textContent = "预览中...";
  try {
    const payload = await postJSON("/api/routing/preview", {
      inbound: document.getElementById("routingPreviewInbound")?.value || "",
      target: document.getElementById("routingPreviewTarget")?.value || "",
      protocol: document.getElementById("routingPreviewProtocol")?.value || "tcp",
      port: Number(document.getElementById("routingPreviewPort")?.value || 443),
    });
    if (output) {
      output.textContent = [
        `模式: ${payload.mode}`,
        `最终出站: ${payload.outbound}`,
        `原因: ${payload.reason}`,
        payload.matched_rule ? `命中规则: ${payload.matched_rule} / ${payload.match_type}=${payload.value} / 优先级 ${payload.priority}` : "",
        ...((payload.warnings || []).map((warning) => `提示: ${warning}`)),
      ].filter(Boolean).join("\n");
    }
  } catch (error) {
    if (output) output.textContent = error.message;
  }
});

document.getElementById("previewSubscriptionButton")?.addEventListener("click", async () => {
  const output = document.getElementById("subscriptionPreview");
  const url = document.getElementById("mihomoForm")?.elements.provider_url.value || "";
  if (output) output.textContent = "解析中...";
  try {
    const preview = await postJSON("/api/subscription/preview", { url });
    if (output) {
      output.textContent = [
        `格式: ${preview.format}`,
        `节点: ${preview.proxy_count}`,
        `代理组: ${preview.group_count}`,
        `规则: ${preview.rule_count}`,
        `Provider: ${preview.provider_count}`,
        `节点名称: ${(preview.proxy_names || []).slice(0, 12).join(", ") || "--"}`,
        `代理组名称: ${(preview.group_names || []).join(", ") || "--"}`,
        ...(preview.warnings || []).map((item) => `提示: ${item}`),
      ].join("\n");
    }
  } catch (error) {
    if (output) output.textContent = error.message;
  }
});

document.getElementById("passwordForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await postJSON("/api/password/change", formToObject(event.currentTarget));
    alert("密码已修改，请重新登录");
    location.href = "/login";
  } catch (error) {
    alert(error.message);
  }
});

document.addEventListener("click", async (event) => {
  const editInboundButton = event.target.closest("[data-edit-inbound]");
  if (editInboundButton) {
    openInboundEditor(editInboundButton.dataset.editInbound);
    return;
  }

  const editOutboundButton = event.target.closest("[data-edit-outbound]");
  if (editOutboundButton) {
    openOutboundEditor(editOutboundButton.dataset.editOutbound);
    return;
  }

  const inspectOutboundButton = event.target.closest("[data-inspect-outbound]");
  if (inspectOutboundButton) {
    const output = document.getElementById("outboundDiagnostics");
    if (output) output.textContent = "检查中...";
    try {
      const response = await fetch(`/api/outbounds/${encodeURIComponent(inspectOutboundButton.dataset.inspectOutbound)}/inspect`);
      const payload = await response.json();
      if (!response.ok) throw new Error(payload.error || "检查失败");
      if (output) output.textContent = inspectionLines(payload).join("\n");
    } catch (error) {
      if (output) output.textContent = error.message;
    }
    return;
  }

  const shareInboundButton = event.target.closest("[data-share-inbound]");
  if (shareInboundButton) {
    try {
      const result = await postJSON(`/api/inbounds/${encodeURIComponent(shareInboundButton.dataset.shareInbound)}/share`, { host: shareHost() });
      await showShareLink(result.name, result.link);
    } catch (error) {
      alert(error.message);
    }
    return;
  }

  const shareOutboundButton = event.target.closest("[data-share-outbound]");
  if (shareOutboundButton) {
    try {
      const result = await postJSON(`/api/outbounds/${encodeURIComponent(shareOutboundButton.dataset.shareOutbound)}/share`, {});
      await showShareLink(result.name, result.link);
    } catch (error) {
      alert(error.message);
    }
    return;
  }

  const testButton = event.target.closest("[data-test-type]");
  if (testButton) {
    const originalText = testButton.textContent;
    try {
      testButton.textContent = "测试中";
      const result = await postJSON(`/api/nodes/${encodeURIComponent(testButton.dataset.testType)}/${encodeURIComponent(testButton.dataset.testName)}/test`, {});
      testButton.textContent = result.status === "online" && result.latency_ms ? `${result.latency_ms} ms` : (result.diagnosis || "timeout");
      testButton.title = [result.error, result.hint].filter(Boolean).join("\n");
      await refresh();
    } catch (error) {
      testButton.textContent = "timeout";
      testButton.title = error.message;
      setTimeout(() => {
        testButton.textContent = originalText;
      }, 1200);
    }
    return;
  }

  const toggleButton = event.target.closest("[data-toggle-type]");
  if (toggleButton) {
    try {
      await sendJSON(
        `/api/nodes/${encodeURIComponent(toggleButton.dataset.toggleType)}/${encodeURIComponent(toggleButton.dataset.toggleName)}/enabled`,
        "PATCH",
        { enabled: toggleButton.dataset.toggleEnabled === "true" },
      );
      state.configLoaded = false;
      await refresh();
    } catch (error) {
      alert(error.message);
    }
    return;
  }

  const button = event.target.closest("[data-delete-type]");
  if (!button) return;
  try {
    await fetch(`/api/nodes/${encodeURIComponent(button.dataset.deleteType)}/${encodeURIComponent(button.dataset.deleteName)}`, {
      method: "DELETE",
    });
    state.configLoaded = false;
    await refresh();
  } catch (error) {
    alert(error.message);
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeModal();
});

if (!loginForm) {
  refresh();
  setInterval(refresh, 3000);
}
