#!/usr/bin/env sh
set -eu

APP_NAME="nodetools-agent"
INSTALL_DIR="${INSTALL_DIR:-/opt/nodetools-agent}"
SERVICE_PATH="/etc/systemd/system/${APP_NAME}.service"

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行：sudo sh deploy/install.sh"
  exit 1
fi

if [ ! -f "./${APP_NAME}" ]; then
  echo "当前目录缺少 ${APP_NAME} 二进制，请先构建：go build -o ${APP_NAME} ./cmd"
  exit 1
fi

mkdir -p "${INSTALL_DIR}/database" "${INSTALL_DIR}/logs" "${INSTALL_DIR}/web" "${INSTALL_DIR}/deploy"
cp "./${APP_NAME}" "${INSTALL_DIR}/${APP_NAME}"
cp "./config.yaml" "${INSTALL_DIR}/config.yaml"
cp -R "./web/"* "${INSTALL_DIR}/web/"
cp -R "./deploy/"* "${INSTALL_DIR}/deploy/"

cat > "${SERVICE_PATH}" <<EOF
[Unit]
Description=NodeTools Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${INSTALL_DIR}/${APP_NAME}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${APP_NAME}"
systemctl restart "${APP_NAME}"
systemctl --no-pager status "${APP_NAME}" || true
