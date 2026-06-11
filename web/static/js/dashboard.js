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

const inboundSchemas = {
  mixed: [
    ["listen", "监听地址", "127.0.0.1", "select", ["127.0.0.1", "::", "0.0.0.0"]],
    ["username", "用户名", ""],
    ["password", "密码", "", "password"],
  ],
  socks: [
    ["listen", "监听地址", "127.0.0.1", "select", ["127.0.0.1", "::", "0.0.0.0"]],
    ["username", "用户名", ""],
    ["password", "密码", "", "password"],
  ],
  socks5: [
    ["listen", "监听地址", "127.0.0.1", "select", ["127.0.0.1", "::", "0.0.0.0"]],
    ["username", "用户名", ""],
    ["password", "密码", "", "password"],
  ],
  http: [
    ["listen", "监听地址", "127.0.0.1", "select", ["127.0.0.1", "::", "0.0.0.0"]],
    ["username", "用户名", ""],
    ["password", "密码", "", "password"],
  ],
  vless: [
    ["listen", "监听地址", "0.0.0.0", "select", ["0.0.0.0", "::", "127.0.0.1"]],
    ["uuid", "UUID", ""],
    ["flow", "Flow", "", "select", ["", "xtls-rprx-vision"]],
    ["security", "安全", "none", "select", ["none", "reality"]],
    ["tls", "TLS", "", "checkbox"],
    ["server_name", "Server Name", "addons.mozilla.org"],
    ["private_key", "Reality Private Key", ""],
    ["short_id", "Reality Short ID", ""],
    ["reality_handshake_server", "Reality Handshake Server", "addons.mozilla.org"],
    ["reality_handshake_port", "Reality Handshake Port", "443", "number"],
    ["certificate_path", "TLS 证书路径", ""],
    ["key_path", "TLS 私钥路径", ""],
    ["transport", "传输", "tcp", "select", transportOptions],
    ["path", "路径 / Service Name", "/"],
    ["host", "Host", ""],
  ],
  vmess: [
    ["uuid", "UUID", ""],
    ["alter_id", "Alter ID", "0", "number"],
    ["transport", "传输", "tcp", "select", transportOptions],
    ["path", "路径", "/ws"],
    ["host", "Host", ""],
  ],
  trojan: [
    ["password", "密码", "", "password"],
    ["tls", "TLS", "", "checkbox"],
    ["server_name", "Server Name", "example.com"],
    ["transport", "传输", "tcp", "select", transportOptions],
    ["path", "路径", "/"],
    ["host", "Host", ""],
  ],
  anytls: [
    ["listen", "监听地址", "0.0.0.0", "select", ["0.0.0.0", "::", "127.0.0.1"]],
    ["password", "密码", "", "password"],
    ["tls", "TLS", "true", "checkbox"],
    ["server_name", "Server Name", "example.com"],
    ["certificate_path", "TLS 证书路径", ""],
    ["key_path", "TLS 私钥路径", ""],
    ["idle_session_check", "空闲检查间隔", "30s"],
    ["idle_session_timeout", "空闲超时", "30s"],
    ["min_idle_session", "最小空闲会话", "5", "number"],
  ],
  shadowsocks: [
    ["method", "加密方法", "", "select", ssMethods],
    ["password", "密码", "", "password"],
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

const escapeHTML = (value) => String(value ?? "")
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");

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
  for (const key of ["port", "listen_port", "target_port", "alter_id", "up_mbps", "down_mbps", "reality_handshake_port", "min_idle_session"]) {
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

async function refresh() {
  const [statusRes, nodeRes, configRes, kernelsRes, serviceRes, envRes, portsRes] = await Promise.all([
    fetch("/api/status"),
    fetch("/api/nodes"),
    fetch("/api/config"),
    fetch("/api/system/kernels"),
    fetch("/api/system/service"),
    fetch("/api/system/environment"),
    fetch("/api/system/ports"),
  ]);
  if ([statusRes, nodeRes, configRes, kernelsRes, serviceRes, envRes, portsRes].some((res) => res.status === 401)) {
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

  renderMetrics();
  renderInbounds();
  renderOutbounds();
  renderSystem(kernels, service, environment, ports);
  renderOutboundOptions();

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
  const rules = getRules();
  const items = getInbounds().filter((node) => {
    const text = `${node.name} ${node.protocol}`.toLowerCase();
    return text.includes(query);
  });
  rows.innerHTML = items.map((node) => {
    const rule = rules.find((item) => item.inbound === node.name);
    return `
      <tr>
        <td>${escapeHTML(node.name)}</td>
        <td>${escapeHTML(node.protocol)}</td>
        <td>${escapeHTML(node.address || "::")}:${node.port}</td>
        <td>${escapeHTML(rule?.outbound || "未选择")}</td>
        <td>${formatBytes(node.upload_bytes)}</td>
        <td>${formatBytes(node.download_bytes)}</td>
        <td>${node.latency_ms ? `${node.latency_ms} ms` : "--"}</td>
        <td><span class="badge" title="${escapeHTML(node.last_error || "")}">${escapeHTML(node.status)}</span></td>
        <td>
          <div class="row-actions">
            <button class="icon-button" data-test-type="inbound" data-test-name="${escapeHTML(node.name)}" type="button">测速</button>
            <button class="icon-button" data-edit-inbound="${escapeHTML(node.name)}" type="button">编辑</button>
            <button class="icon-button" data-share-inbound="${escapeHTML(node.name)}" type="button">分享</button>
            <button class="icon-button" data-toggle-type="inbound" data-toggle-name="${escapeHTML(node.name)}" data-toggle-enabled="${node.enabled ? "false" : "true"}" type="button">${node.enabled ? "停用" : "启用"}</button>
            <button class="icon-button" data-delete-type="inbound" data-delete-name="${escapeHTML(node.name)}" type="button">删除</button>
          </div>
        </td>
        <td><input type="checkbox" data-node-check="inbound" value="${escapeHTML(node.name)}"></td>
      </tr>
    `;
  }).join("") || `<tr><td colspan="10" class="empty-cell">还没有入站，点击“添加入站”创建本地代理端口。</td></tr>`;
};

const renderOutbounds = () => {
  const rows = document.getElementById("outboundRows");
  if (!rows) return;
  const query = (document.getElementById("outboundSearch")?.value || "").toLowerCase();
  const items = getOutbounds().filter((node) => {
    const text = `${node.name} ${node.protocol} ${node.address}`.toLowerCase();
    return text.includes(query);
  });
  rows.innerHTML = items.map((node) => `
    <tr>
      <td>${escapeHTML(node.name)}</td>
      <td>${escapeHTML(node.protocol)}</td>
      <td>${escapeHTML(node.address || "--")}</td>
      <td>${node.port || "--"}</td>
      <td>${formatBytes(node.upload_bytes)}</td>
      <td>${formatBytes(node.download_bytes)}</td>
      <td>${node.latency_ms ? `${node.latency_ms} ms` : "--"}</td>
      <td><span class="badge" title="${escapeHTML(node.last_error || "")}">${escapeHTML(node.status)}</span></td>
      <td>
        <div class="row-actions">
          <button class="icon-button" data-test-type="outbound" data-test-name="${escapeHTML(node.name)}" type="button">测速</button>
          <button class="icon-button" data-toggle-type="outbound" data-toggle-name="${escapeHTML(node.name)}" data-toggle-enabled="${node.enabled ? "false" : "true"}" type="button">${node.enabled ? "停用" : "启用"}</button>
          <button class="icon-button" data-delete-type="outbound" data-delete-name="${escapeHTML(node.name)}" type="button">删除</button>
        </div>
      </td>
      <td><input type="checkbox" data-node-check="outbound" value="${escapeHTML(node.name)}"></td>
    </tr>
  `).join("") || `<tr><td colspan="10" class="empty-cell">还没有出站节点，可以导入链接或手动添加。</td></tr>`;
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
  const select = document.getElementById("inboundOutboundSelect");
  const outbounds = getOutbounds();
  if (select) {
    select.innerHTML = outbounds.length
      ? outbounds.map((node) => `<option value="${escapeHTML(node.name)}">${escapeHTML(node.name)} / ${escapeHTML(node.protocol)}</option>`).join("")
      : `<option value="">请先添加出站节点</option>`;
  }
  const defaultSelect = document.getElementById("defaultOutboundSelect");
  if (defaultSelect) {
    const current = defaultSelect.value || state.config?.routing?.default_outbound || "direct";
    defaultSelect.innerHTML = `<option value="direct">direct</option>` + outbounds
      .map((node) => `<option value="${escapeHTML(node.name)}">${escapeHTML(node.name)} / ${escapeHTML(node.protocol)}</option>`)
      .join("");
    defaultSelect.value = current;
  }
};

const renderInboundFields = () => {
  const select = document.getElementById("inboundProtocolSelect");
  const container = document.getElementById("inboundDynamicFields");
  if (!select || !container) return;
  const protocol = select.value || "mixed";
  container.innerHTML = (inboundSchemas[protocol] || []).map(fieldControl).join("");
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
  form.elements.default_outbound.value = routing.default_outbound || "direct";
  form.elements.rules.value = (routing.rules || [])
    .map((rule, index) => [
      rule.priority || (index + 1) * 10,
      rule.inbound || "",
      rule.outbound || "",
      rule.disabled ? "false" : "true",
    ].join(","))
    .join("\n");
};

const parseRoutingRules = (text) => String(text || "")
  .split(/\r?\n/)
  .map((line) => line.trim())
  .filter(Boolean)
  .map((line, index) => {
    const parts = line.split(",").map((item) => item.trim());
    const [priority, inbound, outbound, enabled = "true"] = parts;
    return {
      name: `${inbound || "rule"}-route`,
      priority: Number(priority || (index + 1) * 10),
      inbound,
      outbound,
      disabled: ["false", "0", "no", "停用"].includes(enabled.toLowerCase()),
    };
  });

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
    renderOutboundOptions();
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
  const rule = getRules().find((item) => item.inbound === inbound.name);
  renderOutboundOptions();
  if (rule?.outbound) form.elements.outbound.value = rule.outbound;
  openModal("inboundModal");
};

const closeModal = () => {
  document.getElementById("modalBackdrop")?.setAttribute("hidden", "");
  document.querySelectorAll(".modal").forEach((item) => item.hidden = true);
  document.body.classList.remove("modal-open");
};

const fieldControl = ([name, label, placeholder, type = "text", options = []]) => {
  if (type === "checkbox") {
    const checked = placeholder === "true" ? " checked" : "";
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
          ${options.map((option) => `<option value="${option}"${option === placeholder ? " selected" : ""}>${option || "无"}</option>`).join("")}
        </select>
      </label>
    `;
  }
  return `
    <label>${label}
      <input name="${name}" type="${type}" placeholder="${escapeHTML(placeholder)}">
    </label>
  `;
};

const renderOutboundProtocolOptions = () => {
  const select = document.getElementById("outboundProtocolSelect");
  if (!select) return;
  select.innerHTML = outboundProtocols.map((protocol) => `<option value="${protocol}">${protocol}</option>`).join("");
};

const renderOutboundFields = () => {
  const select = document.getElementById("outboundProtocolSelect");
  const container = document.getElementById("outboundDynamicFields");
  if (!select || !container) return;
  const protocol = select.value || "vless";
  container.innerHTML = (outboundSchemas[protocol] || outboundSchemas.vless).map(fieldControl).join("");
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
  renderOutboundOptions();
  openModal("inboundModal");
});
document.getElementById("openOutboundModalButton")?.addEventListener("click", () => openModal("outboundModal"));
document.querySelectorAll("[data-close-modal]").forEach((button) => button.addEventListener("click", closeModal));
document.getElementById("modalBackdrop")?.addEventListener("click", (event) => {
  if (event.target.id === "modalBackdrop") closeModal();
});

renderOutboundProtocolOptions();
document.getElementById("inboundProtocolSelect")?.addEventListener("change", renderInboundFields);
document.getElementById("outboundProtocolSelect")?.addEventListener("change", renderOutboundFields);
renderInboundFields();
renderOutboundFields();

document.addEventListener("change", (event) => {
  const selectAll = event.target.closest("[data-select-all]");
  if (!selectAll) return;
  document.querySelectorAll(`[data-node-check="${selectAll.dataset.selectAll}"]`).forEach((checkbox) => {
    checkbox.checked = selectAll.checked;
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
    const names = (payload.imported || []).map((node) => `${node.name} (${node.protocol})`);
    const lines = [
      `解析节点: ${payload.parsed}`,
      `导入节点: ${(payload.imported || []).length}`,
      `名称: ${names.join(", ") || "--"}`,
    ];
    if ((payload.errors || []).length > 0) {
      lines.push("部分错误:");
      lines.push(...payload.errors.slice(0, 8));
    }
    if (result) result.textContent = lines.join("\n");
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
    const lines = (payload.results || []).flatMap((item) => [
      `订阅: ${item.provider || item.url}`,
      `解析: ${item.parsed} / 导入: ${item.imported}`,
      ...((item.errors || []).map((error) => `错误: ${error}`)),
    ]);
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
    const keyPair = await postJSON("/api/reality/keypair", {});
    if (form?.elements.private_key) form.elements.private_key.value = keyPair.private_key;
    alert(`Reality 密钥已生成。\nPublic Key: ${keyPair.public_key}`);
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById("inboundForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = formToObject(event.currentTarget);
  const editing = Boolean(data.original_name);
  delete data.original_name;
  delete data.share_host;
  if (!data.outbound) {
    alert("请先添加一个出站节点，再创建入站。");
    return;
  }
  try {
    if (editing) {
      await sendJSON("/api/inbounds", "PUT", data);
    } else {
      await postJSON("/api/proxy/create", data);
    }
    event.currentTarget.reset();
    closeModal();
    await refresh();
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById("outboundForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = formToObject(event.currentTarget);
  try {
    await sendJSON("/api/outbounds", "PUT", data);
    event.currentTarget.reset();
    renderOutboundFields();
    closeModal();
    await refresh();
  } catch (error) {
    alert(error.message);
  }
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
  const data = formToObject(event.currentTarget);
  const provider = data.provider_name && data.provider_url ? [{
    name: data.provider_name,
    type: "http",
    url: data.provider_url,
    interval: 3600,
    health_check_url: "http://www.gstatic.com/generate_204",
    health_check_lazy: true,
  }] : [];
  const groupName = data.group_name || "NodeTools";
  const payload = {
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
  try {
    await sendJSON("/api/mihomo/config", "PUT", payload);
    state.configLoaded = false;
    await refresh();
  } catch (error) {
    alert(error.message);
  }
});

document.getElementById("routingForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = formToObject(event.currentTarget);
  const payload = {
    default_outbound: data.default_outbound || "direct",
    rules: parseRoutingRules(data.rules),
  };
  try {
    await sendJSON("/api/routing/config", "PUT", payload);
    state.configLoaded = false;
    await refresh();
  } catch (error) {
    alert(error.message);
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

  const shareInboundButton = event.target.closest("[data-share-inbound]");
  if (shareInboundButton) {
    const form = document.getElementById("inboundForm");
    const host = form?.elements.share_host?.value || location.hostname;
    try {
      const result = await postJSON(`/api/inbounds/${encodeURIComponent(shareInboundButton.dataset.shareInbound)}/share`, { host });
      await navigator.clipboard?.writeText(result.link);
      alert(`分享链接已生成并复制：\n${result.link}`);
    } catch (error) {
      alert(error.message);
    }
    return;
  }

  const testButton = event.target.closest("[data-test-type]");
  if (testButton) {
    try {
      testButton.textContent = "测试中";
      const result = await postJSON(`/api/nodes/${encodeURIComponent(testButton.dataset.testType)}/${encodeURIComponent(testButton.dataset.testName)}/test`, {});
      if (result.error) alert(result.error);
      await refresh();
    } catch (error) {
      alert(error.message);
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
