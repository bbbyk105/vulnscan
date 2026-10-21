#!/bin/bash
# Projects 配下の各ディレクトリを順にスキャンし、Markdown レポートを保存する。
#
#   ./scripts/scan-all.sh                    # ~/Projects の直下を全部
#   ./scripts/scan-all.sh ~/Projects/foo     # 指定したものだけ
#
set -euo pipefail

here=$(cd -- "$(dirname -- "$0")" && pwd)
tool="$here/../vulnscan"
projects=$(cd -- "$here/../.." && pwd)
out="${OUT_DIR:-$here/../reports}"
stamp=$(date +%Y%m%d-%H%M%S)

mkdir -p "$out"

scan_one() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  local name
  name=$(basename -- "$dir")
  case "$name" in
    vulnscan|reports|node_modules|_backup|.git|.pnpm-store) return 0 ;;
  esac
  printf '\n== %s\n' "$name"
  "$tool" scan "$dir" --format md -o "$out/$name-$stamp.md" --no-color --fail-on never || true
}

if [ "$#" -gt 0 ]; then
  for dir in "$@"; do
    scan_one "$dir"
  done
else
  while IFS= read -r -d '' dir; do
    scan_one "$dir"
  done < <(find "$projects" -maxdepth 1 -mindepth 1 -type d ! -name '.*' -print0)
fi

printf '\nレポート: %s\n' "$out"
