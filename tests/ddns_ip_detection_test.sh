#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

assert_eq() {
    local expected="$1" actual="$2" message="$3"
    if [[ "$expected" != "$actual" ]]; then
        echo "ASSERTION FAILED: $message" >&2
        echo "  expected: $expected" >&2
        echo "  actual:   $actual" >&2
        exit 1
    fi
}

make_mock_curl() {
    local scenario="$1" mock_dir="$2"
    cat > "${mock_dir}/curl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

scenario="${MOCK_SCENARIO:-}"
url="${@: -1}"

case "$scenario:$url" in
    module_json:https://4.ipw.cn)
        exit 35
        ;;
    module_json:https://myip.ipip.net/ip)
        printf '{"ip":"203.0.113.42"}'
        ;;
    module_json:https://ip.3322.net|module_json:https://ifconfig.me|module_json:https://ifconfig.me/ip)
        exit 35
        ;;

    ddns_fallback:https://4.ipw.cn)
        printf 'blocked-by-middlebox'
        ;;
    ddns_fallback:https://myip.ipip.net/ip)
        printf '203.0.113.42'
        ;;
    ddns_fallback:https://ip.3322.net|ddns_fallback:https://ifconfig.me|ddns_fallback:https://ifconfig.me/ip)
        printf '198.51.100.10'
        ;;

    *)
        echo "unexpected curl call: scenario=${scenario} url=${url}" >&2
        exit 99
        ;;
esac
EOF
    chmod +x "${mock_dir}/curl"
}

run_module_json_test() {
    local mock_dir actual rc
    mock_dir="$(mktemp -d)"
    trap 'rm -rf "$mock_dir"' RETURN
    make_mock_curl module_json "$mock_dir"

    set +e
    actual="$(
        PATH="${mock_dir}:$PATH" \
        MOCK_SCENARIO=module_json \
        bash -c '
            source modules/00-constants.sh
            source modules/01-utils.sh
            source modules/02-network.sh
            get_public_ipv4
        '
    )"
    rc=$?
    set -e
    assert_eq "0" "$rc" "get_public_ipv4 should exit successfully when JSON endpoint contains IPv4"
    assert_eq "203.0.113.42" "$actual" "get_public_ipv4 should extract IPv4 from JSON endpoint response"
    trap - RETURN
    rm -rf "$mock_dir"
}

run_ddns_fallback_test() {
    local mock_dir ddns_script actual rc
    mock_dir="$(mktemp -d)"
    trap 'rm -rf "$mock_dir"' RETURN
    make_mock_curl ddns_fallback "$mock_dir"

    ddns_script="$(
        bash -lc '
            source modules/00-constants.sh
            source modules/01-utils.sh
            source modules/02-network.sh
            ddns_create_script >/dev/null 2>&1
            cat /usr/local/bin/ddns-update.sh
        '
    )"

    set +e
    actual="$(
        PATH="${mock_dir}:$PATH" \
        MOCK_SCENARIO=ddns_fallback \
        bash -c "
            source <(printf '%s\n' \"\$DDNS_SCRIPT_CONTENT\")
            get_ip 4
        " 2>/dev/null
    )"
    rc=$?
    set -e
    assert_eq "0" "$rc" "generated ddns-update.sh should exit successfully after skipping invalid endpoint response"
    assert_eq "203.0.113.42" "$actual" "generated ddns-update.sh should continue fallback after invalid non-IP response"
    trap - RETURN
    rm -rf "$mock_dir"
}

export DDNS_SCRIPT_CONTENT=""
DDNS_SCRIPT_CONTENT="$(printf '%s' "$(
    bash -lc '
        cd "'"$ROOT_DIR"'"
        source modules/00-constants.sh
        source modules/01-utils.sh
        source modules/02-network.sh
        ddns_create_script >/dev/null 2>&1
        cat /usr/local/bin/ddns-update.sh
    '
)")"

run_module_json_test
run_ddns_fallback_test

echo "ddns_ip_detection_test: PASS"
