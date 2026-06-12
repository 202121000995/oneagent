#!/usr/bin/env sh
set -eu

APP_NAME="nodetools-agent"
ARCH="${ARCH:-amd64}"
GO_BIN="${GO_BIN:-}"
OUT_DIR="${OUT_DIR:-dist}"
PACKAGE_NAME="${PACKAGE_NAME:-nodetools-agent-offline-linux-${ARCH}}"
APP_VERSION="${APP_VERSION:-0.2.0}"
BUILD_TIME="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}"
KERNEL_SOURCE_DIR="${KERNEL_SOURCE_DIR:-kernels}"
ALLOW_MISSING_KERNELS="${ALLOW_MISSING_KERNELS:-0}"
DEPLOY_WEB_PORT="${DEPLOY_WEB_PORT:-39080}"
DEPLOY_PUBLIC_HOST="${DEPLOY_PUBLIC_HOST:-}"
DEPLOY_PROXY_USER="${DEPLOY_PROXY_USER:-nodetools}"
DEPLOY_PROXY_PASS="${DEPLOY_PROXY_PASS:-}"

if [ -z "${GO_BIN}" ]; then
  if command -v go >/dev/null 2>&1; then
    GO_BIN="go"
  elif [ -x "/Users/apple/Library/Go/sdk/go1.26.3/bin/go" ]; then
    GO_BIN="/Users/apple/Library/Go/sdk/go1.26.3/bin/go"
  else
    echo "未找到 Go。请设置 GO_BIN=/path/to/go 后重试。"
    exit 1
  fi
fi

if ! command -v zip >/dev/null 2>&1; then
  echo "未找到 zip 命令，请先在本机安装 zip。"
  exit 1
fi

if [ -z "${DEPLOY_PROXY_PASS}" ]; then
  DEPLOY_PROXY_PASS="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 18)"
fi

make_deploy_config() {
  path="$1"
  cat > "${path}" <<EOF
server:
  web_port: ${DEPLOY_WEB_PORT}
EOF
  if [ -n "${DEPLOY_PUBLIC_HOST}" ]; then
    printf "  public_host: %s\n" "${DEPLOY_PUBLIC_HOST}" >> "${path}"
  fi
  cat >> "${path}" <<EOF
  admin_user: admin
  admin_pass: password123
kernel:
  type: sing-box
  executable: /usr/local/bin/sing-box
  config_path: sing-box.generated.json
inbounds:
  - name: Local-Mixed
    protocol: mixed
    listen: 127.0.0.1
    port: 1080
    username: ${DEPLOY_PROXY_USER}
    password: ${DEPLOY_PROXY_PASS}
outbounds:
  - name: Direct
    protocol: direct
    address: direct
    port: 1
routing:
  rules:
    - inbound: Local-Mixed
      outbound: Direct
EOF
}

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

BUNDLE_DIR="${TMP_DIR}/nodetools-agent-offline"
mkdir -p "${BUNDLE_DIR}/deploy" "${BUNDLE_DIR}/web" "${BUNDLE_DIR}/kernels" "${OUT_DIR}"

echo "构建 Linux ${ARCH} 版本 Agent..."
CGO_ENABLED=0 GOOS=linux GOARCH="${ARCH}" "${GO_BIN}" build \
  -ldflags "-X nodetoolsagent/core.Version=${APP_VERSION} -X nodetoolsagent/core.BuildTime=${BUILD_TIME} -X nodetoolsagent/core.Commit=${COMMIT}" \
  -o "${BUNDLE_DIR}/${APP_NAME}" ./cmd

make_deploy_config "${BUNDLE_DIR}/config.yaml"
printf "%s\n" "${APP_VERSION}" > "${BUNDLE_DIR}/VERSION"
cp README.md "${BUNDLE_DIR}/README.md"
cp -R web/. "${BUNDLE_DIR}/web/"
cp deploy/install-offline.sh "${BUNDLE_DIR}/install-offline.sh"
cp deploy/rollback-offline.sh "${BUNDLE_DIR}/rollback-offline.sh"
cp deploy/nodetools-agent.service "${BUNDLE_DIR}/deploy/nodetools-agent.service"

copy_kernel() {
  name="$1"
  env_path="$2"
  target="${BUNDLE_DIR}/kernels/${name}"

  if [ -n "${env_path}" ] && [ -f "${env_path}" ]; then
    install_kernel_source "${name}" "${env_path}" "${target}"
    return 0
  fi

  source_path="$(find_kernel_source "${name}")"
  if [ -n "${source_path}" ]; then
    install_kernel_source "${name}" "${source_path}" "${target}"
    return 0
  fi

  if command -v "${name}" >/dev/null 2>&1; then
    found_path="$(command -v "${name}")"
    if is_linux_binary "${found_path}"; then
      cp "${found_path}" "${target}"
      chmod 0755 "${target}"
      echo "已加入内核：${name} <- ${found_path}"
      return 0
    fi
    echo "跳过 ${found_path}：不是 Linux 可执行文件。"
    return 0
  fi

  if [ -f "/usr/local/bin/${name}" ]; then
    if is_linux_binary "/usr/local/bin/${name}"; then
      cp "/usr/local/bin/${name}" "${target}"
      chmod 0755 "${target}"
      echo "已加入内核：${name} <- /usr/local/bin/${name}"
      return 0
    fi
    echo "跳过 /usr/local/bin/${name}：不是 Linux 可执行文件。"
    return 0
  fi

  if [ "${name}" = "sing-box" ]; then
    echo "未找到 ${name}。请下载 Linux ${ARCH} 版本到 ${KERNEL_SOURCE_DIR}/，或设置 SING_BOX_BIN=/path/to/sing-box。"
  else
    echo "未找到 ${name}。请下载 Linux ${ARCH} 版本到 ${KERNEL_SOURCE_DIR}/，或设置 MIHOMO_BIN=/path/to/mihomo。"
  fi
  return 1
}

install_kernel_source() {
  name="$1"
  source_path="$2"
  target="$3"
  extracted="${TMP_DIR}/${name}-extract"
  mkdir -p "${extracted}"

  case "${source_path}" in
    *.tar.gz|*.tgz)
      tar -xzf "${source_path}" -C "${extracted}"
      binary_path="$(find "${extracted}" -type f -name "${name}" -perm -111 | head -n 1)"
      if [ -z "${binary_path}" ]; then
        binary_path="$(find "${extracted}" -type f -name "${name}" | head -n 1)"
      fi
      ;;
    *.gz)
      binary_path="${extracted}/${name}"
      gzip -dc "${source_path}" > "${binary_path}"
      chmod 0755 "${binary_path}"
      ;;
    *)
      binary_path="${source_path}"
      ;;
  esac

  if [ -z "${binary_path}" ] || [ ! -f "${binary_path}" ]; then
    echo "无法从 ${source_path} 找到 ${name} 可执行文件。"
    exit 1
  fi
  if ! is_linux_binary "${binary_path}"; then
    echo "${source_path} 不是 Linux 可执行文件或不含 Linux 可执行文件，请换 Linux ${ARCH} 版本。"
    exit 1
  fi
  cp "${binary_path}" "${target}"
  chmod 0755 "${target}"
  echo "已加入内核：${name} <- ${source_path}"
}

find_kernel_source() {
  name="$1"
  [ -d "${KERNEL_SOURCE_DIR}" ] || return 0
  case "${name}" in
    sing-box)
      find "${KERNEL_SOURCE_DIR}" -maxdepth 1 -type f \( -name "sing-box" -o -name "sing-box-*linux-${ARCH}*.tar.gz" -o -name "sing-box-*linux-${ARCH}*.tgz" \) | head -n 1
      ;;
    mihomo)
      find "${KERNEL_SOURCE_DIR}" -maxdepth 1 -type f \( -name "mihomo" -o -name "mihomo-linux-${ARCH}*.gz" \) | head -n 1
      ;;
  esac
}

is_linux_binary() {
  path="$1"
  if command -v file >/dev/null 2>&1; then
    file "${path}" | grep -qi "ELF"
    return $?
  fi
  echo "未找到 file 命令，无法校验 ${path} 是否为 Linux 可执行文件，默认接受。"
  return 0
}

missing_kernels=0
copy_kernel "sing-box" "${SING_BOX_BIN:-}" || missing_kernels=$((missing_kernels + 1))
copy_kernel "mihomo" "${MIHOMO_BIN:-}" || missing_kernels=$((missing_kernels + 1))

if [ "${missing_kernels}" -gt 0 ] && [ "${ALLOW_MISSING_KERNELS}" != "1" ]; then
  echo "离线包要求内置 sing-box 和 mihomo。缺少内核时已停止打包。"
  echo "临时生成纯 Agent 包可设置 ALLOW_MISSING_KERNELS=1，但不推荐用于 VPS 测试。"
  exit 1
fi

(
  cd "${TMP_DIR}"
  zip -qr "package.zip" "nodetools-agent-offline"
)

cp "${TMP_DIR}/package.zip" "${OUT_DIR}/${PACKAGE_NAME}.zip"
echo "离线包已生成：${OUT_DIR}/${PACKAGE_NAME}.zip"
echo "VPS 上传后执行：unzip ${PACKAGE_NAME}.zip && cd nodetools-agent-offline && sudo sh install-offline.sh"
echo "版本：${APP_VERSION} (${COMMIT}, ${BUILD_TIME})"
echo "Web 面板端口：${DEPLOY_WEB_PORT}"
echo "默认 mixed 入站认证：${DEPLOY_PROXY_USER} / ${DEPLOY_PROXY_PASS}"
