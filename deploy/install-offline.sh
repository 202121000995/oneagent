#!/usr/bin/env sh
set -eu

APP_NAME="nodetools-agent"
INSTALL_DIR="${INSTALL_DIR:-/opt/nodetools-agent}"
SERVICE_PATH="/etc/systemd/system/${APP_NAME}.service"
OPEN_FIREWALL="${OPEN_FIREWALL:-1}"
KEEP_CONFIG="${KEEP_CONFIG:-0}"
PACKAGE_VERSION="$(cat ./VERSION 2>/dev/null || date +%Y%m%d%H%M%S)"
RELEASE_ID="${PACKAGE_VERSION}-$(date +%Y%m%d%H%M%S)"
RELEASES_DIR="${INSTALL_DIR}/releases"
RELEASE_DIR="${RELEASES_DIR}/${RELEASE_ID}"
BACKUP_DIR="${INSTALL_DIR}/backups"
CURRENT_LINK="${INSTALL_DIR}/current"

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行：sudo sh install-offline.sh"
  exit 1
fi

if [ ! -f "./${APP_NAME}" ]; then
  echo "当前目录缺少 ${APP_NAME} 二进制。请在离线包解压后的 nodetools-agent-offline 目录运行。"
  exit 1
fi

if ! command -v systemctl >/dev/null 2>&1; then
  echo "当前系统没有 systemd/systemctl，离线脚本暂不支持自动安装服务。"
  exit 1
fi

if systemctl list-unit-files "${APP_NAME}.service" >/dev/null 2>&1; then
  systemctl stop "${APP_NAME}" >/dev/null 2>&1 || true
fi

mkdir -p "${INSTALL_DIR}/database" "${INSTALL_DIR}/logs" "${RELEASE_DIR}/web" "${RELEASE_DIR}/deploy" "${BACKUP_DIR}"
cp "./${APP_NAME}" "${RELEASE_DIR}/${APP_NAME}"
chmod 0755 "${RELEASE_DIR}/${APP_NAME}"
printf "%s\n" "${PACKAGE_VERSION}" > "${RELEASE_DIR}/VERSION"

package_web_port() {
  if [ -f "./config.yaml" ]; then
    awk '/web_port:/ {print $2; exit}' "./config.yaml" 2>/dev/null || true
  fi
}

WEB_PORT="${WEB_PORT:-$(package_web_port)}"
WEB_PORT="${WEB_PORT:-39080}"

update_config_port() {
  path="$1"
  port="$2"
  tmp_path="${path}.tmp"
  awk -v port="${port}" '
    /web_port:/ && done == 0 {
      sub(/web_port:.*/, "web_port: " port)
      done = 1
    }
    { print }
    END {
      if (done == 0) {
        print "server:"
        print "  web_port: " port
      }
    }
  ' "${path}" > "${tmp_path}"
  mv "${tmp_path}" "${path}"
}

if [ -f "./config.yaml" ] && [ ! -f "${INSTALL_DIR}/config.yaml" ]; then
  cp "./config.yaml" "${INSTALL_DIR}/config.yaml"
elif [ -f "./config.yaml" ]; then
  cp "./config.yaml" "${INSTALL_DIR}/config.yaml.example"
  if [ "${KEEP_CONFIG}" != "1" ]; then
    backup_path="${BACKUP_DIR}/config.yaml.$(date +%Y%m%d%H%M%S)"
    cp "${INSTALL_DIR}/config.yaml" "${backup_path}"
    update_config_port "${INSTALL_DIR}/config.yaml" "${WEB_PORT}"
    echo "已保留现有配置并更新 web_port=${WEB_PORT}，备份：${backup_path}"
  fi
fi

if [ -f "${INSTALL_DIR}/config.yaml" ] && [ "${KEEP_CONFIG}" != "1" ]; then
  update_config_port "${INSTALL_DIR}/config.yaml" "${WEB_PORT}"
fi

cp -R "./web/." "${RELEASE_DIR}/web/"
if [ -d "./deploy" ]; then
  cp -R "./deploy/." "${RELEASE_DIR}/deploy/"
fi
if [ -f "./rollback-offline.sh" ]; then
  cp "./rollback-offline.sh" "${RELEASE_DIR}/rollback-offline.sh"
fi

if [ -d "${INSTALL_DIR}/web" ] && [ ! -L "${INSTALL_DIR}/web" ]; then
  mv "${INSTALL_DIR}/web" "${BACKUP_DIR}/web.$(date +%Y%m%d%H%M%S)"
fi
if [ -d "${INSTALL_DIR}/deploy" ] && [ ! -L "${INSTALL_DIR}/deploy" ]; then
  mv "${INSTALL_DIR}/deploy" "${BACKUP_DIR}/deploy.$(date +%Y%m%d%H%M%S)"
fi

ln -sfn "${RELEASE_DIR}" "${CURRENT_LINK}"
ln -sfn "${CURRENT_LINK}/web" "${INSTALL_DIR}/web"
ln -sfn "${CURRENT_LINK}/deploy" "${INSTALL_DIR}/deploy"

install_kernel() {
  name="$1"
  source_path="./kernels/${name}"
  target_path="/usr/local/bin/${name}"
  if [ -f "${source_path}" ]; then
    install -m 0755 "${source_path}" "${target_path}"
    echo "已安装内核：${target_path}"
  else
    echo "离线包未包含 ${name}，跳过。"
  fi
}

install_kernel "sing-box"
install_kernel "mihomo"

cat > "${SERVICE_PATH}" <<EOF
[Unit]
Description=NodeTools Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${CURRENT_LINK}/${APP_NAME}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${APP_NAME}"
systemctl restart "${APP_NAME}"

if ! systemctl is-active --quiet "${APP_NAME}"; then
  echo "服务启动失败，最近日志如下："
  journalctl -u "${APP_NAME}" -n 80 --no-pager || true
  exit 1
fi

open_firewall_port() {
  port="$1"
  [ "${OPEN_FIREWALL}" = "1" ] || return 0

  if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi "Status: active"; then
    ufw allow "${port}/tcp" || true
    echo "已尝试通过 ufw 放行 ${port}/tcp"
  fi

  if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
    firewall-cmd --permanent --add-port="${port}/tcp" || true
    firewall-cmd --reload || true
    echo "已尝试通过 firewalld 放行 ${port}/tcp"
  fi
}

open_firewall_port "${WEB_PORT}"

check_http() {
  port="$1"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS "http://127.0.0.1:${port}/login" >/dev/null
    return $?
  fi
  if command -v wget >/dev/null 2>&1; then
    wget -q -O /dev/null "http://127.0.0.1:${port}/login"
    return $?
  fi
  return 0
}

wait_http() {
  port="$1"
  tries=20
  while [ "${tries}" -gt 0 ]; do
    if check_http "${port}"; then
      return 0
    fi
    tries=$((tries - 1))
    sleep 1
  done
  return 1
}

if ! wait_http "${WEB_PORT}"; then
  echo "服务已启动，但本机访问 http://127.0.0.1:${WEB_PORT}/login 失败。最近日志如下："
  journalctl -u "${APP_NAME}" -n 80 --no-pager || true
  exit 1
fi

echo "服务已启动："
systemctl --no-pager status "${APP_NAME}" || true

if command -v ss >/dev/null 2>&1; then
  ss -lntp | grep ":${WEB_PORT} " || true
elif command -v netstat >/dev/null 2>&1; then
  netstat -lntp 2>/dev/null | grep ":${WEB_PORT} " || true
fi

echo "安装完成：访问 http://服务器IP:${WEB_PORT}"
echo "当前版本：${PACKAGE_VERSION}"
echo "如需回滚：sudo sh ${CURRENT_LINK}/rollback-offline.sh"
echo "如果外网仍打不开，请在 VPS 云厂商安全组/防火墙放行 TCP ${WEB_PORT}。"
