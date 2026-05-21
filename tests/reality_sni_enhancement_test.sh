#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() { echo "TEST FAILED: $1" >&2; exit 1; }

C_RED="" C_GREEN="" C_YELLOW="" C_CYAN="" C_RESET=""
print_info() { echo "[i] $1"; }
print_success() { echo "[ok] $1"; }
print_warn() { echo "[!] $1"; }
print_error() { echo "[x] $1"; }
confirm() { return 0; }

REALITY_CANDIDATE_SNI=("fallback.example.com")
source modules/enhancements/reality-sni-speedtest-interactive.sh

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
REALITY_SNI_CACHE_DIR="$tmp_dir"
REALITY_SNI_POOL_FILE="$tmp_dir/pool.txt"
printf '%s\n' "sni-one.example.com" "sni-two.example.com" > "$REALITY_SNI_POOL_FILE"

stdout_file="$tmp_dir/stdout.txt"
stderr_file="$tmp_dir/stderr.txt"
printf '5\n1\n' | reality_prompt_sni >"$stdout_file" 2>"$stderr_file"
stdout_value="$(cat "$stdout_file")"

if [[ "$stdout_value" != "sni-one.example.com" && "$stdout_value" != "sni-two.example.com" ]]; then
    echo "stdout was:" >&2
    sed -n '1,80p' "$stdout_file" >&2
    echo "stderr was:" >&2
    sed -n '1,80p' "$stderr_file" >&2
    fail "enhanced SNI prompt stdout should contain only the selected domain"
fi

if grep -Eq '\[i\]|\[ok\]|\[!\]|\[x\]|REALITY|候选|测速|模式|bulianglin|v2ray-agent' "$stdout_file"; then
    fail "enhanced SNI prompt leaked UI text to stdout"
fi

echo "reality_sni_enhancement_test: PASS"
