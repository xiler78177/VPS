#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() { echo "TEST FAILED: $1" >&2; exit 1; }

C_RESET='\033[0m'
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_CYAN='\033[0;36m'
print_info() { echo "[i] $1"; }
print_success() { echo "[ok] $1"; }
print_warn() { echo "[!] $1"; }
print_error() { echo "[x] $1"; }
confirm() { return 0; }

REALITY_CANDIDATE_SNI=("fallback.example.com")
source modules/enhancements/reality-sni-speedtest-interactive.sh

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

standalone_out="$tmp_dir/standalone-exit.out"
standalone_err="$tmp_dir/standalone-exit.err"
if ! printf '0\n' | TERM=dumb bash modules/enhancements/test-reality-sni-speedtest.sh >"$standalone_out" 2>"$standalone_err"; then
    sed -n '1,80p' "$standalone_out" >&2
    sed -n '1,80p' "$standalone_err" >&2
    fail "standalone Reality SNI speedtest script should support noninteractive exit"
fi
if grep -Eq '\(\([[:space:]]*(qualified_count|batch_num)\+\+[[:space:]]*\)\)' modules/enhancements/test-reality-sni-speedtest.sh; then
    fail "standalone Reality SNI speedtest script should not use post-increment under set -e"
fi

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

if grep -Fq '\033' "$stderr_file"; then
    echo "stderr was:" >&2
    sed -n '1,80p' "$stderr_file" >&2
    fail "enhanced SNI prompt should render ANSI colors, not print literal \\033 text"
fi

rm -f /tmp/v2ray-agent-install.sh /tmp/reality-fallback-pool.txt

mock_bin="$tmp_dir/bin"
mkdir -p "$mock_bin"
cat > "$mock_bin/curl" <<'CURLMOCK'
#!/usr/bin/env bash
out=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -o)
            out="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done
[[ -n "$out" ]] || exit 1
{
    echo '_realityDomainList() {'
    for i in $(seq 1 12); do
        printf '    "agent-%02d.example.com"\n' "$i"
    done
    echo '}'
} > "$out"
CURLMOCK
chmod +x "$mock_bin/curl"
old_path="$PATH"
PATH="$mock_bin:$PATH"

REALITY_SNI_POOL_FILE="$tmp_dir/agent-pool.txt"
REALITY_SNI_CACHE_DIR="$tmp_dir/cache-agent"
REALITY_SNI_FALLBACK_POOL_FILE="$REALITY_SNI_CACHE_DIR/fallback-sni-pool.txt"
if ! reality_fetch_v2ray_agent_pool >/dev/null 2>"$tmp_dir/agent.err"; then
    PATH="$old_path"
    sed -n '1,80p' "$tmp_dir/agent.err" >&2
    fail "v2ray-agent fallback pool fetch should succeed with mocked curl"
fi
PATH="$old_path"

if [[ -e /tmp/v2ray-agent-install.sh ]]; then
    fail "v2ray-agent pool fetch created fixed /tmp/v2ray-agent-install.sh"
fi
agent_count=$(wc -l < "$REALITY_SNI_POOL_FILE")
if [[ "$agent_count" -ne 12 ]]; then
    fail "v2ray-agent pool fetch wrote unexpected domain count: $agent_count"
fi

bad_bulianglin_pool="$tmp_dir/bad-bulianglin-pool.txt"
printf '%s\n' "existing-good.example.com" > "$bad_bulianglin_pool"
curl() {
    printf 'const domains = ["too-short-one.example.com", "too-short-two.example.com"];'
}
REALITY_SNI_POOL_FILE="$bad_bulianglin_pool"
REALITY_SNI_CACHE_DIR="$tmp_dir/cache-bad-bulianglin"
if reality_fetch_bulianglin_pool >/dev/null 2>"$tmp_dir/bad-bulianglin.err"; then
    unset -f curl
    fail "bulianglin pool fetch should reject undersized candidate set"
fi
unset -f curl
if ! grep -Fxq "existing-good.example.com" "$bad_bulianglin_pool" \
   || grep -q "too-short" "$bad_bulianglin_pool"; then
    fail "bulianglin undersized fetch should not overwrite existing pool"
fi

bad_agent_pool="$tmp_dir/bad-agent-pool.txt"
printf '%s\n' "existing-agent-good.example.com" > "$bad_agent_pool"
curl() {
    local out=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -o)
                out="$2"
                shift 2
                ;;
            *)
                shift
                ;;
        esac
    done
    [[ -n "$out" ]] || return 1
    {
        echo '_realityDomainList() {'
        echo '    "agent-too-short-one.example.com"'
        echo '    "agent-too-short-two.example.com"'
        echo '}'
    } > "$out"
}
REALITY_SNI_POOL_FILE="$bad_agent_pool"
REALITY_SNI_CACHE_DIR="$tmp_dir/cache-bad-agent"
if reality_fetch_v2ray_agent_pool >/dev/null 2>"$tmp_dir/bad-agent.err"; then
    unset -f curl
    fail "v2ray-agent pool fetch should reject undersized candidate set"
fi
unset -f curl
if ! grep -Fxq "existing-agent-good.example.com" "$bad_agent_pool" \
   || grep -q "agent-too-short" "$bad_agent_pool"; then
    fail "v2ray-agent undersized fetch should not overwrite existing pool"
fi

reality_fetch_bulianglin_pool() { return 1; }
reality_fetch_v2ray_agent_pool() { return 1; }
REALITY_CANDIDATE_SNI=(
    fallback-one.example.com
    fallback-two.example.com
)
REALITY_SNI_CACHE_DIR="$tmp_dir/cache-fallback"
REALITY_SNI_POOL_FILE="$REALITY_SNI_CACHE_DIR/primary.txt"
mkdir -p "$REALITY_SNI_CACHE_DIR"
: > "$REALITY_SNI_POOL_FILE"
REALITY_SNI_FALLBACK_POOL_FILE="$REALITY_SNI_CACHE_DIR/fallback-sni-pool.txt"
if ! reality_update_sni_pool >/dev/null 2>"$tmp_dir/fallback.err"; then
    sed -n '1,80p' "$tmp_dir/fallback.err" >&2
    fail "fallback SNI pool should be written when remote pools fail or cache is empty"
fi
if [[ -e /tmp/reality-fallback-pool.txt ]]; then
    fail "fallback SNI pool created fixed /tmp/reality-fallback-pool.txt"
fi
if [[ "$REALITY_SNI_POOL_FILE" != "$REALITY_SNI_FALLBACK_POOL_FILE" || ! -f "$REALITY_SNI_FALLBACK_POOL_FILE" ]]; then
    fail "fallback SNI pool should use managed cache file"
fi

echo "reality_sni_enhancement_test: PASS"
