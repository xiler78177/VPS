#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

fail() { echo "TEST FAILED: $1" >&2; exit 1; }
assert_match() {
    local pattern="$1" value="$2" message="$3"
    [[ "$value" =~ $pattern ]] || fail "$message (value=$value)"
}
assert_contains() {
    local needle="$1" haystack="$2" message="$3"
    grep -Fq -- "$needle" <<< "$haystack" || fail "$message"
}
assert_mode_600() {
    local file="$1" message="$2" mode
    case "$(uname -s 2>/dev/null || echo unknown)" in
        MINGW*|MSYS*|CYGWIN*) return 0 ;;
    esac
    mode="$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null || true)"
    [[ "$mode" == "600" ]] || fail "$message (mode=${mode:-unknown})"
}
assert_mode_644() {
    local file="$1" message="$2" mode
    case "$(uname -s 2>/dev/null || echo unknown)" in
        MINGW*|MSYS*|CYGWIN*) return 0 ;;
    esac
    mode="$(stat -c '%a' "$file" 2>/dev/null || stat -f '%Lp' "$file" 2>/dev/null || true)"
    [[ "$mode" == "644" ]] || fail "$message (mode=${mode:-unknown})"
}

source modules/00-constants.sh
source modules/01-utils.sh
source modules/15-singbox-reality.sh

# review #14 / audit H10-H11: Reality 轮换必须先写临时文件并 check，失败不覆盖 config/state；中转重装必须先读取既有 state。
declare -F reality_apply_singbox_config >/dev/null || fail "Reality should define checked sing-box config apply helper"
rotate_user_body="$(declare -f reality_rotate_user)"
rotate_key_body="$(declare -f reality_rotate_key)"
relay_body="$(declare -f reality_install_relay)"
assert_contains 'reality_apply_singbox_config' "$rotate_user_body" "UUID rotation should use checked apply helper"
assert_contains 'reality_apply_singbox_config' "$rotate_key_body" "key rotation should use checked apply helper"
if grep -Fq '> "$REALITY_SINGBOX_CONFIG"' <<< "$rotate_user_body$rotate_key_body"; then
    fail "Reality rotation should not write directly to final sing-box config"
fi
assert_contains 'old_uuid' "$rotate_user_body" "UUID rotation should keep old UUID for rollback"
assert_contains 'old_private_key' "$rotate_key_body" "key rotation should keep old key for rollback"
assert_contains 'validate_port "$REALITY_PORT"' "$rotate_key_body" "key rotation should validate REALITY_PORT before rendering JSON numeric port"
if ! awk '/reality_install_relay\(\)/{infn=1} infn && /reality_load_state \|\| true/{load=NR} infn && /REALITY_ROLE=/{role=NR} infn && /^}/{exit !(load && role && load < role)}' modules/15-singbox-reality.sh; then
    fail "relay install should load existing state before writing relay fields"
fi

reality_test_tmp="$(mktemp -d)"
reality_old_path="$PATH"
realm_tmp=""
trap 'PATH="$reality_old_path"; rm -rf "$reality_test_tmp" "$realm_tmp"' EXIT
REALITY_SINGBOX_CONFIG="$reality_test_tmp/config.json"
printf '%s\n' 'old-config' > "$REALITY_SINGBOX_CONFIG"
mkdir -p "$reality_test_tmp/bin"
cat > "$reality_test_tmp/bin/sing-box" <<'EOF_MOCK_SINGBOX_FAIL'
#!/usr/bin/env bash
exit 1
EOF_MOCK_SINGBOX_FAIL
cat > "$reality_test_tmp/bin/systemctl" <<'EOF_MOCK_SYSTEMCTL_OK'
#!/usr/bin/env bash
exit 0
EOF_MOCK_SYSTEMCTL_OK
chmod +x "$reality_test_tmp/bin/sing-box" "$reality_test_tmp/bin/systemctl"
PATH="$reality_test_tmp/bin:$PATH"
sha_file="$reality_test_tmp/sing-box-linux-amd64.tar.gz"
printf '%s' 'payload' > "$sha_file"
sha_hash="$(sha256sum "$sha_file" | awk '{print $1}')"
printf '%s  sing-box-linux-amd64.tar.gz\n' "$sha_hash" > "$reality_test_tmp/checksums.txt"
reality_verify_sha256_file "$sha_file" "$reality_test_tmp/checksums.txt" >/dev/null 2>&1 || \
    fail "sha256 verification should default asset_name from file basename when third argument is omitted"
if reality_apply_singbox_config '{"new":"bad"}' >/dev/null 2>&1; then
    fail "checked apply helper should fail when sing-box check fails"
fi
[[ "$(cat "$REALITY_SINGBOX_CONFIG")" == 'old-config' ]] || fail "failed sing-box check should leave existing config untouched"
cat > "$reality_test_tmp/bin/sing-box" <<'EOF_MOCK_SINGBOX_OK'
#!/usr/bin/env bash
exit 0
EOF_MOCK_SINGBOX_OK
cat > "$reality_test_tmp/bin/systemctl" <<'EOF_MOCK_SYSTEMCTL_FAIL'
#!/usr/bin/env bash
exit 1
EOF_MOCK_SYSTEMCTL_FAIL
chmod +x "$reality_test_tmp/bin/sing-box" "$reality_test_tmp/bin/systemctl"
if reality_apply_singbox_config '{"new":"restart-fail"}' >/dev/null 2>&1; then
    fail "checked apply helper should fail when sing-box restart fails"
fi
[[ "$(cat "$REALITY_SINGBOX_CONFIG")" == 'old-config' ]] || fail "failed restart should restore previous config"

selftest_tmp="$reality_test_tmp/selftest-tmp"
mkdir -p "$selftest_tmp"
cat > "$reality_test_tmp/bin/sing-box" <<'EOF_MOCK_SELFTEST_SINGBOX'
#!/usr/bin/env bash
echo "mock sing-box exited" >&2
exit 0
EOF_MOCK_SELFTEST_SINGBOX
cat > "$reality_test_tmp/bin/ss" <<'EOF_MOCK_SELFTEST_SS'
#!/usr/bin/env bash
echo "LISTEN 0 0 127.0.0.1:19090 0.0.0.0:*"
EOF_MOCK_SELFTEST_SS
cat > "$reality_test_tmp/bin/curl" <<'EOF_MOCK_SELFTEST_CURL'
#!/usr/bin/env bash
echo "mock curl failure" >&2
exit 7
EOF_MOCK_SELFTEST_CURL
chmod +x "$reality_test_tmp/bin/sing-box" "$reality_test_tmp/bin/ss" "$reality_test_tmp/bin/curl"
(
    TMPDIR="$selftest_tmp"
    REALITY_PORT=443
    REALITY_UUID=11111111-1111-1111-1111-111111111111
    REALITY_SNI=www.example.com
    REALITY_PUBLIC_KEY=pubkey
    REALITY_SHORT_ID=abcd
    REALITY_FINGERPRINT=chrome
    reality_load_state(){ return 0; }
    if reality_local_client_self_test >/dev/null 2>&1; then
        fail "Reality self-test should fail with mocked curl"
    fi
)
if find "$selftest_tmp" -maxdepth 1 -name 'reality-client-test.*' -print -quit | grep -q .; then
    fail "Reality self-test should clean private temp directory on failure"
fi

prompt_sni_body="$(declare -f reality_prompt_sni)"
assert_contains 'reality_smart_sni_selection' "$prompt_sni_body" "sourcing Reality module should keep enhanced SNI prompt active"
if grep -Fq 'REALITY SNI/handshake 目标' <<< "$prompt_sni_body"; then
    fail "enhanced SNI prompt should not be overwritten by legacy prompt when sourcing modules"
fi

prompt_marker="$reality_test_tmp/noninteractive-prompts.log"
landing_args="$reality_test_tmp/noninteractive-landing.args"
(
    reality_prompt_cf_token(){ echo "cf-token" >> "$prompt_marker"; return 1; }
    reality_prompt_landing_dns_mode(){ echo "dns-mode" >> "$prompt_marker"; return 1; }
    reality_prompt_domain_with_zones(){ echo "domain" >> "$prompt_marker"; return 1; }
    reality_prompt_node_name(){ echo "node-name" >> "$prompt_marker"; return 1; }
    reality_prompt_sni(){ echo "sni" >> "$prompt_marker"; return 1; }
    reality_prompt_port(){ echo "port" >> "$prompt_marker"; return 1; }
    reality_prompt_split_ports(){ echo "split-ports" >> "$prompt_marker"; return 1; }
    reality_install_landing(){ printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$@" > "$landing_args"; return 0; }
    reality_install_relay(){ echo "relay" >> "$prompt_marker"; return 1; }
    reality_install_wizard --landing --cf-token tok --dns-mode split \
        --node-v4 v4.example.com --node-v6 v6.example.com \
        --name node --name-v4 node-v4 --name-v6 node-v6 \
        --sni www.example.com --port 443 --port-v6 443 >/dev/null 2>&1
) || fail "non-interactive Reality landing CLI args should complete without prompts"
[[ ! -s "$prompt_marker" ]] || fail "non-interactive Reality landing unexpectedly called prompt/install fallback: $(cat "$prompt_marker")"
[[ "$(cat "$landing_args")" == "v4.example.com|www.example.com|443|tok|node|split|v4.example.com|v6.example.com|443|node-v4|node-v6" ]] \
    || fail "non-interactive Reality landing passed wrong args: $(cat "$landing_args")"

prompt_marker="$reality_test_tmp/noninteractive-both-prompts.log"
landing_args="$reality_test_tmp/noninteractive-both-landing.args"
relay_args="$reality_test_tmp/noninteractive-both-relay.args"
(
    confirm(){ echo "confirm" >> "$prompt_marker"; return 1; }
    reality_prompt_cf_token(){ echo "cf-token" >> "$prompt_marker"; return 1; }
    reality_prompt_landing_dns_mode(){ echo "dns-mode" >> "$prompt_marker"; return 1; }
    reality_prompt_domain_with_zones(){ echo "domain" >> "$prompt_marker"; return 1; }
    reality_prompt_node_name(){ echo "node-name" >> "$prompt_marker"; return 1; }
    reality_prompt_sni(){ echo "sni" >> "$prompt_marker"; return 1; }
    reality_prompt_port(){ echo "port" >> "$prompt_marker"; return 1; }
    reality_install_landing(){ printf '%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n' "$@" > "$landing_args"; return 0; }
    reality_install_relay(){ printf '%s|%s|%s|%s|%s|%s\n' "$@" > "$relay_args"; return 0; }
    reality_load_state(){ return 1; }
    reality_install_wizard --both --cf-token tok --dns-mode auto \
        --node node.example.com --name combo --sni www.example.com --port 443 \
        --relay-domain relay.example.com --relay-port 2443 >/dev/null 2>&1
) || fail "non-interactive Reality both CLI args should complete without prompts"
[[ ! -s "$prompt_marker" ]] || fail "non-interactive Reality both unexpectedly called prompt/confirm: $(cat "$prompt_marker")"
[[ "$(cat "$landing_args")" == "node.example.com|www.example.com|443|tok|combo|auto|||||" ]] \
    || fail "non-interactive Reality both landing args wrong: $(cat "$landing_args")"
[[ "$(cat "$relay_args")" == "relay.example.com|2443|127.0.0.1|443|tok|combo" ]] \
    || fail "non-interactive Reality both relay args wrong: $(cat "$relay_args")"

candidate_count="$(grep -A80 '^REALITY_CANDIDATE_SNI=(' modules/15-singbox-reality.sh | sed -n '/^)/q;p' | grep -c '\"')"
[[ "$candidate_count" -ge 20 ]] || fail "SNI candidate pool should contain at least 20 domains"
if grep -q 'source /etc/os-release' modules/15-singbox-reality.sh; then
    fail "Reality module should not source /etc/os-release because VERSION is readonly in this project"
fi

port="$(REALITY_TEST_PORT_CANDIDATES="19999 20000 60000 60001" reality_random_port)"
[[ "$port" == "20000" || "$port" == "60000" ]] || fail "random port should stay in 20000-60000 range, got $port"

short_id="$(reality_generate_short_id)"
assert_match '^[0-9a-f]{16}$' "$short_id" "short_id should be non-empty 8-byte hex"

(
    get_public_ipv4(){ echo "217.142.138.63"; }
    get_public_ipv6(){ return 1; }
    ip(){
        case "$*" in
            "-o -4 addr show scope global") echo "2: eth0    inet 10.0.0.111/24 brd 10.0.0.255 scope global eth0" ;;
            "-o link show") echo "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500" ;;
        esac
    }
    REALITY_IPV4=""; REALITY_IPV6=""
    reality_detect_ips
    [[ "$REALITY_IPV4" == "217.142.138.63" ]] || fail "cloud NAT public IPv4 should be kept even when not bound to local NIC"
    [[ -z "$REALITY_IPV6" ]] || fail "cloud NAT fixture should not invent IPv6"
)

(
    get_public_ipv4(){ echo "104.28.200.1"; }
    get_public_ipv6(){ return 1; }
    ip(){
        case "$*" in
            "-o -4 addr show scope global") echo "3: CloudflareWARP    inet 172.16.0.2/32 scope global CloudflareWARP" ;;
            "-o link show") echo "3: CloudflareWARP: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1280" ;;
        esac
    }
    REALITY_IPV4=""; REALITY_IPV6=""
    reality_detect_ips
    [[ -z "$REALITY_IPV4" ]] || fail "WARP IPv4 egress should be cleared when no local public IPv4 exists"
)

config="$(REALITY_LISTEN_HOST=0.0.0.0 reality_render_singbox_config '11111111-1111-4111-8111-111111111111' 'priv-key' '23456' 'www.example.com' 'a1b2c3d4e5f60708')"
assert_contains '"log":{"disabled":true}' "$config" "config should disable sing-box logs"
assert_contains '"type":"vless"' "$config" "config should use VLESS inbound"
assert_contains '"listen_port":23456' "$config" "config should include selected high port"
assert_contains '"listen":"0.0.0.0"' "$config" "config should bind 0.0.0.0 when listen host is IPv4"
assert_contains '"flow":"xtls-rprx-vision"' "$config" "config should enable Vision flow"
assert_contains '"reality":{"enabled":true' "$config" "config should enable REALITY"
assert_contains '"short_id":["a1b2c3d4e5f60708"]' "$config" "config should include non-empty short_id"

config6="$(REALITY_LISTEN_HOST=:: reality_render_singbox_config '11111111-1111-4111-8111-111111111111' 'priv-key' '23456' 'www.example.com' 'a1b2c3d4e5f60708')"
assert_contains '"listen":"::"' "$config6" "config should bind :: for dual-stack/IPv6-only"

split_config="$(REALITY_DNS_MODE=split REALITY_PORT_V6=34567 REALITY_LISTEN_HOST_V4=0.0.0.0 REALITY_LISTEN_HOST_V6=:: reality_render_singbox_config '11111111-1111-4111-8111-111111111111' 'priv-key' '23456' 'www.example.com' 'a1b2c3d4e5f60708')"
assert_contains '"tag":"vless-reality-ipv4"' "$split_config" "split mode should render an IPv4 Reality inbound"
assert_contains '"listen":"0.0.0.0","listen_port":23456' "$split_config" "split mode IPv4 inbound should bind 0.0.0.0 on IPv4 port"
assert_contains '"tag":"vless-reality-ipv6"' "$split_config" "split mode should render an IPv6 Reality inbound"
assert_contains '"listen":"::","listen_port":34567' "$split_config" "split mode IPv6 inbound should bind :: on IPv6 port"

REALITY_LISTEN_HOST_V4=""
REALITY_LISTEN_HOST_V6="2001:db8::10"
REALITY_LISTEN_HOST=""
reality_prepare_split_listen_hosts 443 443
[[ "$REALITY_LISTEN_HOST_V4" == "0.0.0.0" ]] || fail "split same-port should keep IPv4 inbound on 0.0.0.0"
[[ "$REALITY_LISTEN_HOST_V6" == "2001:db8::10" ]] || fail "split same-port should bind IPv6 inbound to concrete IPv6"
split_443_config="$(REALITY_DNS_MODE=split REALITY_PORT_V6=443 REALITY_LISTEN_HOST_V4="$REALITY_LISTEN_HOST_V4" REALITY_LISTEN_HOST_V6="$REALITY_LISTEN_HOST_V6" reality_render_singbox_config '11111111-1111-4111-8111-111111111111' 'priv-key' '443' 'www.example.com' 'a1b2c3d4e5f60708')"
assert_contains '"listen":"0.0.0.0","listen_port":443' "$split_443_config" "split same-port IPv4 inbound should use 443"
assert_contains '"listen":"2001:db8::10","listen_port":443' "$split_443_config" "split same-port IPv6 inbound should bind concrete IPv6 on 443"
REALITY_LISTEN_HOST_V4=""
REALITY_LISTEN_HOST_V6=""
REALITY_LISTEN_HOST=""

link="$(reality_build_vless_link '11111111-1111-4111-8111-111111111111' 'node.example.com' '23456' 'www.example.com' 'pub-key' 'a1b2c3d4e5f60708' 'node-01')"
assert_contains 'vless://11111111-1111-4111-8111-111111111111@node.example.com:23456?' "$link" "link should use node host and port"
assert_contains 'security=reality' "$link" "link should use reality security"
assert_contains 'sni=www.example.com' "$link" "link should include SNI"
assert_contains 'pbk=pub-key' "$link" "link should include public key"
assert_contains 'sid=a1b2c3d4e5f60708' "$link" "link should include short id"
assert_contains 'flow=xtls-rprx-vision' "$link" "link should include Vision flow"

REALITY_NODE_NAME="us-nat-01"
REALITY_NODE_DOMAIN="node.example.com"
assert_contains 'us-nat-01' "$(reality_effective_node_name)" "custom node name should be used for link/client tag"
REALITY_NODE_NAME=""
assert_contains 'node-reality' "$(reality_effective_node_name)" "missing custom node name should fall back to node domain prefix"

reality_parse_vless_link "$link"
relay_link="$(reality_build_vless_link "$REALITY_UUID" 'relay.example.com' '25000' "$REALITY_SNI" "$REALITY_PUBLIC_KEY" "$REALITY_SHORT_ID" 'relay-01')"
assert_contains 'vless://11111111-1111-4111-8111-111111111111@relay.example.com:25000?' "$relay_link" "relay link should replace host/port only"
assert_contains 'sni=www.example.com' "$relay_link" "relay link should preserve landing SNI"
assert_contains 'pbk=pub-key' "$relay_link" "relay link should preserve landing public key"
assert_contains 'sid=a1b2c3d4e5f60708' "$relay_link" "relay link should preserve landing short id"

REALITY_CONFIG_DIR="$reality_test_tmp/reality"
REALITY_LINK_FILE="${REALITY_CONFIG_DIR}/client-link.txt"
REALITY_CLIENT_JSON="${REALITY_CONFIG_DIR}/client.json"
REALITY_LINK_FILE_V4="${REALITY_CONFIG_DIR}/client-link-v4.txt"
REALITY_LINK_FILE_V6="${REALITY_CONFIG_DIR}/client-link-v6.txt"
REALITY_CLIENT_JSON_V4="${REALITY_CONFIG_DIR}/client-v4.json"
REALITY_CLIENT_JSON_V6="${REALITY_CONFIG_DIR}/client-v6.json"
REALITY_DNS_MODE="split"
REALITY_NODE_DOMAIN_V4="v4.example.com"
REALITY_NODE_DOMAIN_V6="v6.example.com"
REALITY_PORT="23456"
REALITY_PORT_V6="34567"
REALITY_UUID="11111111-1111-4111-8111-111111111111"
REALITY_SNI="www.example.com"
REALITY_PUBLIC_KEY="pub-key"
REALITY_SHORT_ID="a1b2c3d4e5f60708"
REALITY_NODE_NAME="node"
reality_write_client_artifacts
assert_contains '@v4.example.com:23456?' "$(cat "$REALITY_LINK_FILE_V4")" "split mode should write IPv4-only client link"
assert_contains '@v6.example.com:34567?' "$(cat "$REALITY_LINK_FILE_V6")" "split mode should write IPv6-only client link"
assert_contains '@v4.example.com:23456?' "$(cat "$REALITY_LINK_FILE")" "combined split link file should include IPv4 node"
assert_contains '@v6.example.com:34567?' "$(cat "$REALITY_LINK_FILE")" "combined split link file should include IPv6 node"
assert_contains '"server":"v6.example.com","server_port":34567' "$(cat "$REALITY_CLIENT_JSON_V6")" "split mode should write IPv6 client JSON"
assert_mode_600 "$REALITY_LINK_FILE_V4" "split IPv4 link artifact should be private"
assert_mode_600 "$REALITY_LINK_FILE_V6" "split IPv6 link artifact should be private"
assert_mode_600 "$REALITY_LINK_FILE" "combined split link artifact should be private"
assert_mode_600 "$REALITY_CLIENT_JSON_V4" "split IPv4 JSON artifact should be private"
assert_mode_600 "$REALITY_CLIENT_JSON_V6" "split IPv6 JSON artifact should be private"
assert_mode_600 "$REALITY_CLIENT_JSON" "combined split JSON artifact should be private"
REALITY_DNS_MODE=""
REALITY_PORT_V6=""

REALITY_CDN_LINK_FILE="${REALITY_CONFIG_DIR}/cdn-link.txt"
REALITY_CDN_CLIENT_JSON="${REALITY_CONFIG_DIR}/cdn-client.json"
REALITY_CDN_DOMAIN="cdn.example.com"
REALITY_CDN_UUID="22222222-2222-4222-8222-222222222222"
REALITY_CDN_WS_PATH="/secretpath00"
REALITY_CDN_INNER_PORT="58999"
REALITY_CDN_PREFER_IP="1.2.3.4"
REALITY_CDN_NODE_NAME="cdn-test"
reality_cdn_write_client_artifacts
assert_contains '@1.2.3.4:443?' "$(cat "$REALITY_CDN_LINK_FILE")" "CDN client link should use preferred IP"
assert_contains '"transport":{"type":"ws","path":"/secretpath00"' "$(cat "$REALITY_CDN_CLIENT_JSON")" "CDN client JSON should include WS path"
assert_mode_600 "$REALITY_CDN_LINK_FILE" "CDN link artifact should be private"
assert_mode_600 "$REALITY_CDN_CLIENT_JSON" "CDN JSON artifact should be private"

REALITY_RELAY_DIR="${REALITY_CONFIG_DIR}/relays"
RLY_NAME="relay-test"
RLY_LISTEN_PORT="25000"
RLY_CONNECT_HOST="relay.example.com"
RLY_UUID="33333333-3333-4333-8333-333333333333"
RLY_SNI="www.example.com"
RLY_PUBLIC_KEY="relay-pub-key"
RLY_SHORT_ID="0011223344556677"
RLY_FINGERPRINT="chrome"
reality_relay_write_client_artifacts
assert_contains '@relay.example.com:25000?' "$(cat "$REALITY_RELAY_DIR/relay-25000.link.txt")" "relay link artifact should use relay host and port"
assert_contains '"server":"relay.example.com","server_port":25000' "$(cat "$REALITY_RELAY_DIR/relay-25000.client.json")" "relay JSON artifact should use relay host and port"
assert_mode_600 "$REALITY_RELAY_DIR/relay-25000.link.txt" "relay link artifact should be private"
assert_mode_600 "$REALITY_RELAY_DIR/relay-25000.client.json" "relay JSON artifact should be private"

payload="$(reality_cf_dns_payload 'A' 'node.example.com' '203.0.113.10')"
assert_contains '"proxied":false' "$payload" "Cloudflare node DNS payload must force grey-cloud"
assert_contains '"ttl":1' "$payload" "Cloudflare DNS payload should use auto TTL"

realm_cfg="$(REALITY_LISTEN_HOST=0.0.0.0 reality_render_realm_config '25000' 'landing.example.com' '23456')"
assert_contains 'listen = "0.0.0.0:25000"' "$realm_cfg" "Realm config should listen on relay port"
assert_contains 'remote = "landing.example.com:23456"' "$realm_cfg" "Realm config should forward to landing host and port"
assert_contains 'log.level = "warn"' "$realm_cfg" "Realm config should use warn logs"

realm_cfg6="$(REALITY_LISTEN_HOST=:: reality_render_realm_config '25000' 'landing.example.com' '23456')"
assert_contains 'listen = "[::]:25000"' "$realm_cfg6" "Realm config should bracket-bind [::] for dual-stack/IPv6-only"

realm_api_json='{"assets":[{"browser_download_url":"https://github.com/zhboner/realm/releases/download/v2.9.4/realm-slim-x86_64-unknown-linux-gnu.tar.gz"},{"browser_download_url":"https://github.com/zhboner/realm/releases/download/v2.9.4/realm-x86_64-unknown-linux-gnu.tar.gz"}]}'
realm_url="$(reality_select_realm_asset_url "$realm_api_json" 'x86_64-unknown-linux-gnu')"
[[ "$realm_url" == 'https://github.com/zhboner/realm/releases/download/v2.9.4/realm-x86_64-unknown-linux-gnu.tar.gz' ]] || fail "Realm asset selector should prefer non-slim exact asset, got: $realm_url"
realm_api_slim_only='{"assets":[{"browser_download_url":"https://github.com/zhboner/realm/releases/download/v2.9.4/realm-slim-x86_64-unknown-linux-gnu.tar.gz"}]}'
realm_slim_url="$(reality_select_realm_asset_url "$realm_api_slim_only" 'x86_64-unknown-linux-gnu')"
[[ "$realm_slim_url" == 'https://github.com/zhboner/realm/releases/download/v2.9.4/realm-slim-x86_64-unknown-linux-gnu.tar.gz' ]] || fail "Realm asset selector should fall back to slim asset"
realm_tmp="$(mktemp -d)"
touch "$realm_tmp/realm-slim"
realm_bin="$(reality_find_realm_binary "$realm_tmp")"
[[ "$realm_bin" == "$realm_tmp/realm-slim" ]] || fail "Realm binary finder should accept realm-slim extracted binary, got: $realm_bin"

sagernet_keyring="$reality_test_tmp/apt/keyrings/sagernet.asc"
sagernet_source="$reality_test_tmp/apt/sources/sagernet.sources"
REALITY_SAGERNET_KEYRING_FILE="$sagernet_keyring"
REALITY_SAGERNET_SOURCE_FILE="$sagernet_source"
_reality_write_sagernet_source || fail "SagerNet apt source helper should write to redirected candidate path"
sagernet_source_body="$(cat "$sagernet_source")"
assert_contains 'URIs: https://deb.sagernet.org/' "$sagernet_source_body" "SagerNet source should use official repo URI"
assert_contains "Signed-By: $sagernet_keyring" "$sagernet_source_body" "SagerNet source should reference redirected keyring path"
assert_mode_644 "$sagernet_source" "SagerNet source candidate should be public-readable"
if ( REALITY_SAGERNET_KEYRING_FILE="relative/keyring.asc"; _reality_write_sagernet_source >/dev/null 2>&1 ); then
    fail "SagerNet source helper should reject non-absolute keyring path"
fi
unset REALITY_SAGERNET_KEYRING_FILE REALITY_SAGERNET_SOURCE_FILE

realm_service="$reality_test_tmp/systemd/realm.service"
realm_config="$reality_test_tmp/realm/config.toml"
orig_reality_realm_config="${REALITY_REALM_CONFIG:-}"
mkdir -p "$(dirname "$realm_config")" "$reality_test_tmp/realm-bin"
printf '#!/usr/bin/env bash\nexit 0\n' > "$reality_test_tmp/realm-bin/realm"
chmod +x "$reality_test_tmp/realm-bin/realm"
printf 'log.level = "warn"\n' > "$realm_config"
REALITY_REALM_SERVICE_FILE="$realm_service"
REALITY_REALM_BIN="$reality_test_tmp/realm-bin/realm"
REALITY_REALM_CONFIG="$realm_config"
_reality_install_realm_service_unit || fail "Realm service helper should write to redirected candidate path"
realm_service_body="$(cat "$realm_service")"
assert_contains "ExecStart=$REALITY_REALM_BIN -c $realm_config" "$realm_service_body" "Realm service should use resolved binary and redirected config path"
assert_mode_644 "$realm_service" "Realm service candidate should be public-readable"
if ( REALITY_REALM_SERVICE_FILE="relative.service"; _reality_install_realm_service_unit >/dev/null 2>&1 ); then
    fail "Realm service helper should reject non-absolute service path"
fi
unset REALITY_REALM_SERVICE_FILE REALITY_REALM_BIN
REALITY_REALM_CONFIG="$orig_reality_realm_config"

firewall_helper_body="$(awk '/^firewall_allow_tcp_port\(\)/,/^}/' modules/04-firewall.sh)"
assert_contains 'ufw allow "${port}/tcp"' "$firewall_helper_body" "Reality firewall helper should add only the requested TCP port"
if grep -Eq 'ufw default|ufw .*enable|CURRENT_SSH_PORT|refresh_ssh_port' <<< "$firewall_helper_body"; then
    fail "Reality firewall helper should not enable/reset UFW or touch existing SSH/old ports"
fi

grep -q '15-singbox-reality.sh' build.sh || fail "build.sh should include Reality module"
grep -q -- '--reality' modules/13-menus.sh || fail "main menu should expose --reality CLI"
grep -q 'Sing-box Reality' modules/13-menus.sh || fail "main menu should expose Reality menu"
assert_contains '11. Sing-box Reality 节点' "$(cat modules/13-menus.sh)" "main menu should move Reality to option 11"
assert_contains '12. 查看操作日志' "$(cat modules/13-menus.sh)" "main menu should move logs to option 12"
# 备份模块已删除（见 P0-1 / README 维护工具区块），不再断言菜单 13. 备份与恢复
if grep -Fq '"13. Sing-box Reality 节点"' modules/13-menus.sh; then
    fail "main menu should not keep Reality as option 13"
fi
if grep -Fq '13. 备份与恢复' modules/13-menus.sh; then
    fail "backup menu item should be removed (module deleted)"
fi
grep -q 'systemctl restart sing-box' modules/15-singbox-reality.sh || fail "landing reinstall should restart sing-box after writing new config"
grep -q 'reality_diagnose' modules/15-singbox-reality.sh || fail "Reality module should provide a diagnose/self-check command"
grep -q '诊断/自检' modules/15-singbox-reality.sh || fail "Reality menu should expose diagnose/self-check"
grep -q 'tcpdump' modules/15-singbox-reality.sh || fail "diagnose should guide packet-level external reachability checks"
grep -q 'reality_verify_sni "$REALITY_SNI"' modules/15-singbox-reality.sh || fail "diagnose should call the existing SNI verification helper"
grep -Fq '[[ -t 0 ]]' modules/15-singbox-reality.sh || fail "diagnose should not prompt for tcpdump in non-interactive CLI runs"
assert_contains 'REALITY_NODE_NAME=' "$(cat modules/15-singbox-reality.sh)" "Reality state should persist custom node name"
assert_contains '节点名称/备注' "$(cat modules/15-singbox-reality.sh)" "Reality install wizard should prompt for custom node name"
assert_contains '使用 443（推荐' "$(cat modules/15-singbox-reality.sh)" "Reality port prompt should recommend 443"
assert_contains '非 443 监听可能增加 IP 被封锁风险' "$(cat modules/15-singbox-reality.sh)" "Reality module should warn about non-443 Reality ports"
assert_contains 'Apple/iCloud' "$(cat modules/15-singbox-reality.sh)" "Reality module should warn about Apple/iCloud SNI risk"
assert_contains '3. 查看/修改节点信息' "$(cat modules/15-singbox-reality.sh)" "Reality menu should combine info/link management"
assert_contains '删除节点信息' "$(cat modules/15-singbox-reality.sh)" "Reality info submenu should expose delete node info"
reality_menu_body="$(awk '/^reality_menu\(\)/,/^}/' modules/15-singbox-reality.sh)"
if grep -Fq '输出客户端链接' <<< "$reality_menu_body"; then
    fail "Reality top-level menu should not keep duplicate output-link entry"
fi
if grep -Fq '卸载 Reality/Realm 配置' <<< "$reality_menu_body"; then
    fail "Reality top-level menu should not expose uninstall entry"
fi
delete_body="$(awk '/^reality_delete_node_info\(\)/,/^reality_uninstall\(\)/' modules/15-singbox-reality.sh)"
assert_contains 'systemctl disable --now sing-box' "$delete_body" "deleting Reality node info should stop the managed sing-box service"
assert_contains 'rm -f "$REALITY_SINGBOX_CONFIG"' "$delete_body" "deleting Reality node info should remove the managed sing-box config after backup"

zones_json='{"success":true,"result":[{"name":"example.com"},{"name":"gpt.xx.kg"}]}'
zones="$(reality_cf_zone_names_from_json "$zones_json")"
assert_contains 'example.com' "$zones" "should parse Cloudflare zone list"
assert_contains 'gpt.xx.kg' "$zones" "should parse second Cloudflare zone"
full_domain="$(reality_join_subdomain 'node-us-01' 'gpt.xx.kg')"
[[ "$full_domain" == 'node-us-01.gpt.xx.kg' ]] || fail "subdomain prefix should join with selected zone"
full_domain2="$(reality_join_subdomain 'already.example.com' 'gpt.xx.kg')"
[[ "$full_domain2" == 'already.example.com' ]] || fail "full domain input should be preserved"

curl() { printf '%s\n' '{"Status":0,"Answer":[{"name":"node.example.com","type":1,"TTL":300,"data": "203.0.113.10"}]}'; }
resolved_public_a="$(reality_resolve_public_a 'node.example.com')"
unset -f curl
[[ "$resolved_public_a" == '203.0.113.10' ]] || fail "public DoH resolver should parse IPv4 from JSON with optional spacing"

cf_token_out="$(printf 'secret-token\n' | reality_prompt_cf_token 2>"$reality_test_tmp/reality-token-prompt.err")"
[[ "$cf_token_out" == 'secret-token' ]] || fail "Cloudflare token prompt should return only token on stdout"

_cf_api() {
    printf '%s\n' '{"success":true,"result":[{"name":"example.com"},{"name":"gpt.xx.kg"}]}'
}
_cf_api_ok() { [[ "$(grep -o '"success":true' <<< "$1")" == '"success":true' ]]; }
_cf_list_zones() {
    printf '%s\n' '{"success":true,"result":[{"name":"example.com"},{"name":"gpt.xx.kg"}]}'
}
prompt_domain_out="$(printf '2\ntest\n' | reality_prompt_domain_with_zones '节点连接' 'secret-token' 2>"$reality_test_tmp/reality-domain-prompt.err")"
[[ "$prompt_domain_out" == 'test.gpt.xx.kg' ]] || fail "zone-aware domain prompt should return only joined full domain on stdout, got: $prompt_domain_out"
unset -f _cf_api _cf_api_ok _cf_list_zones

prompts_text="$(grep -E '节点连接域名|SNI 域名|REALITY SNI|候选|Cloudflare 灰云|Cloudflare API Token|自动创建/更新|不是让你手动|只需要填写自定义前缀|实际连接|成品网站|校验 TLS|请选择一个 SNI' modules/15-singbox-reality.sh)"
assert_contains 'Cloudflare 灰云' "$prompts_text" "node-domain prompt should explain Cloudflare grey-cloud requirement"
assert_contains 'Cloudflare API Token' "$prompts_text" "node-domain prompt should ask for token before DNS domain"
assert_contains '自动创建/更新' "$prompts_text" "node-domain prompt should explain DNS is automated"
assert_contains '不是让你手动去 Cloudflare 添加记录' "$prompts_text" "node-domain prompt should avoid manual CF workflow"
assert_contains '只需要填写自定义前缀' "$prompts_text" "node-domain prompt should prefer subdomain prefix when token provides zones"
assert_contains '客户端实际连接' "$prompts_text" "node-domain prompt should explain this is the client connection domain"
assert_contains '成品网站' "$prompts_text" "SNI prompt should explain ready-made domain choices"
assert_contains '请选择一个 SNI' "$prompts_text" "SNI prompt should explicitly say it is asking for SNI, not node domain"
assert_contains '校验 TLS/SAN' "$prompts_text" "SNI prompt should tell user domains are tested"
assert_contains '换一批' "$(cat modules/15-singbox-reality.sh)" "SNI prompt should support refreshing candidate domains"
assert_contains 'REALITY_CANDIDATE_SNI=(' "$(cat modules/15-singbox-reality.sh)" "SNI candidate pool should exist"

if [[ -f dist/v4-built.sh ]]; then
    dist_prompt_count="$(grep -c '^reality_prompt_sni()' dist/v4-built.sh || true)"
    [[ "$dist_prompt_count" == "1" ]] || fail "dist should contain exactly one reality_prompt_sni definition, got $dist_prompt_count"
    dist_prompt_body="$(awk '/^reality_prompt_sni\(\)/,/^}/' dist/v4-built.sh)"
    assert_contains 'reality_smart_sni_selection' "$dist_prompt_body" "dist should use enhanced SNI prompt"
fi
echo "reality_module_static_test: PASS"
