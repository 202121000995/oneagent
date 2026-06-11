#!/usr/bin/env sh
set -eu

APP_NAME="nodetools-agent"
INSTALL_DIR="${INSTALL_DIR:-/opt/nodetools-agent}"
CURRENT_LINK="${INSTALL_DIR}/current"
RELEASES_DIR="${INSTALL_DIR}/releases"

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行：sudo sh rollback-offline.sh"
  exit 1
fi

if [ ! -d "${RELEASES_DIR}" ]; then
  echo "没有找到版本目录：${RELEASES_DIR}"
  exit 1
fi

current_target=""
if [ -L "${CURRENT_LINK}" ]; then
  current_target="$(readlink -f "${CURRENT_LINK}")"
fi

previous=""
for release in $(ls -1dt "${RELEASES_DIR}"/* 2>/dev/null); do
  [ -d "${release}" ] || continue
  if [ -n "${current_target}" ] && [ "$(readlink -f "${release}")" = "${current_target}" ]; then
    continue
  fi
  previous="${release}"
  break
done

if [ -z "${previous}" ]; then
  echo "没有可回滚的上一版本。"
  exit 1
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl stop "${APP_NAME}" >/dev/null 2>&1 || true
fi

ln -sfn "${previous}" "${CURRENT_LINK}"
ln -sfn "${CURRENT_LINK}/web" "${INSTALL_DIR}/web"
ln -sfn "${CURRENT_LINK}/deploy" "${INSTALL_DIR}/deploy"

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl restart "${APP_NAME}"
  systemctl --no-pager status "${APP_NAME}" || true
fi

echo "已回滚到：${previous}"
