#!/bin/bash
# ensure-our-deps.sh — 非 uv 依赖管理器（二进制下载 + 校验）
# 由 auto-update Phase 3 在 uv sync 后执行
set -euo pipefail

DEPLOY_FAILED=0

# ─── codebase-memory-mcp ─────────────────────────────────────────
# 静态二进制，curl 下载 + SHA-256 校验 + 安装到 /usr/local/bin
CBM_VERSION="v0.8.1"
CBM_SHA256="6ab87a6c05d049dde57700803ca0ab4199fcf25973a0606618af0fcee73f5abd"
CBM_URL="https://github.com/DeusData/codebase-memory-mcp/releases/download/${CBM_VERSION}/codebase-memory-mcp-linux-amd64-portable.tar.gz"
CBM_BIN="/usr/local/bin/codebase-memory-mcp"

if [ ! -x "$CBM_BIN" ] || [ "$("$CBM_BIN" --version 2>/dev/null | head -1)" != "codebase-memory-mcp 0.8.1" ]; then
  echo "codebase-memory-mcp: downloading ${CBM_VERSION} ..."
  TMPDIR=$(mktemp -d)
  curl -fSL -o "$TMPDIR/cbm.tar.gz" "$CBM_URL" 2>&1 | tail -1 || {
    echo "codebase-memory-mcp: ❌ 下载失败"
    DEPLOY_FAILED=1
    rm -rf "$TMPDIR"
  }
  if [ $DEPLOY_FAILED -eq 0 ]; then
    echo "$CBM_SHA256  $TMPDIR/cbm.tar.gz" | sha256sum -c - 2>&1 || {
      echo "codebase-memory-mcp: ❌ SHA-256 校验失败"
      DEPLOY_FAILED=1
      rm -rf "$TMPDIR"
    }
  fi
  if [ $DEPLOY_FAILED -eq 0 ]; then
    tar -xzf "$TMPDIR/cbm.tar.gz" -C "$TMPDIR"
    cp "$TMPDIR/codebase-memory-mcp" "$CBM_BIN"
    chmod 755 "$CBM_BIN"
    rm -rf "$TMPDIR"
    echo "codebase-memory-mcp: ✅ 已安装到 $CBM_BIN"
  fi
else
  echo "codebase-memory-mcp: ✅ $(codebase-memory-mcp --version 2>&1 | head -1)"
fi

exit $DEPLOY_FAILED
