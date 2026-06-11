#!/usr/bin/env sh
set -eu

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
KERNEL="${KERNEL:-all}"

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行：sudo sh deploy/install-kernels.sh"
  exit 1
fi

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "缺少命令：$1"
    exit 1
  }
}

need_cmd curl
need_cmd tar
need_cmd gzip

case "$(uname -m)" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "暂不支持架构：$(uname -m)"; exit 1 ;;
esac

latest_asset_url() {
  repo="$1"
  pattern="$2"
  curl -fsSL "https://api.github.com/repos/${repo}/releases/latest" \
    | awk -F '"' '/browser_download_url/ {print $4}' \
    | grep "$pattern" \
    | head -n 1
}

install_sing_box() {
  url="$(latest_asset_url "SagerNet/sing-box" "linux-${ARCH}.*\\.tar\\.gz")"
  if [ -z "$url" ]; then
    echo "没有找到 sing-box linux-${ARCH} 发布包"
    exit 1
  fi
  tmp="$(mktemp -d)"
  curl -fL "$url" -o "${tmp}/sing-box.tar.gz"
  tar -xzf "${tmp}/sing-box.tar.gz" -C "$tmp"
  bin="$(find "$tmp" -type f -name sing-box | head -n 1)"
  if [ -z "$bin" ]; then
    echo "sing-box 发布包里没有找到可执行文件"
    exit 1
  fi
  install -m 0755 "$bin" "${INSTALL_DIR}/sing-box"
  "${INSTALL_DIR}/sing-box" version || true
  rm -rf "$tmp"
}

install_mihomo() {
  url="$(latest_asset_url "MetaCubeX/mihomo" "linux-${ARCH}.*\\.gz")"
  if [ -z "$url" ]; then
    echo "没有找到 mihomo linux-${ARCH} 发布包"
    exit 1
  fi
  tmp="$(mktemp -d)"
  curl -fL "$url" -o "${tmp}/mihomo.gz"
  gzip -dc "${tmp}/mihomo.gz" > "${tmp}/mihomo"
  install -m 0755 "${tmp}/mihomo" "${INSTALL_DIR}/mihomo"
  "${INSTALL_DIR}/mihomo" -v || true
  rm -rf "$tmp"
}

mkdir -p "$INSTALL_DIR"

case "$KERNEL" in
  all)
    install_sing_box
    install_mihomo
    ;;
  sing-box)
    install_sing_box
    ;;
  mihomo)
    install_mihomo
    ;;
  *)
    echo "KERNEL 只能是 all、sing-box 或 mihomo"
    exit 1
    ;;
esac
