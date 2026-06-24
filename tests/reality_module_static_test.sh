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

prompt_sni_body="$(declare -f reality_prompt_sni)"
assert_contains 'reality_smart_sni_selection' "$prompt_sni_body" "sourcing Reality module should keep enhanced SNI prompt active"
if grep -Fq 'REALITY SNI/handshake 目标' <<< "$prompt_sni_body"; then
    fail "enhanced SNI prompt should not be overwritten by legacy prompt when sourcing modules"
fi

candidate_count="$(grep -A80 '^REALITY_CANDIDATE_SNI=(' modules/15-singbox-reality.sh | sed -n '/^)/q;p' | grep -c '\"')"
[[ "$candidate_count" -ge 20 ]] || fail "SNI candidate pool should contain at least 20 domains"
if grep -q 'source /etc/os-release' modules/15-singbox-reality.sh; then
    fail "Reality module should not source /etc/os-release because VERSION is readonly in this project"
fi

port="$(REALITY_TEST_PORT_CANDIDATES="19999 20000 60000 60001" reality_random_port)"
[[ "$port" == "20000" || "$port" == "60000" ]] || fail "random port should stay in 20000-60000 range, got $port"

short_id="$(reality_generate_short_id)"
assert_match '^[0-9a-f]{16}$' "$short_id" "short_id should be non-empty 8-byte hex"

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
REALITY_DNS_MODE=""
REALITY_PORT_V6=""

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
assert_contains '3. 查看/修改节点信息' "$(cat modules/15-singbox-reality.sh)" "Reality menu should combine info/link management"
assert_contains '删除节点信息' "$(cat modules/15-singbox-reality.sh)" "Reality info submenu should expose delete node info"
reality_menu_body="$(awk '/^reality_menu\(\)/,/^}/' modules/15-singbox-reality.sh)"
if grep -Fq '输出客户端链接' <<< "$reality_menu_body"; then
    fail "Reality top-level menu should not keep duplicate output-link entry"
fi
if grep -Fq '卸载 Reality/Realm 配置' <<< "$reality_menu_body"; then
    fail "Reality top-level menu should not expose uninstall entry"
fi

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

cf_token_out="$(printf 'secret-token\n' | reality_prompt_cf_token 2>/tmp/reality-token-prompt.err)"
[[ "$cf_token_out" == 'secret-token' ]] || fail "Cloudflare token prompt should return only token on stdout"

_cf_api() {
    printf '%s\n' '{"success":true,"result":[{"name":"example.com"},{"name":"gpt.xx.kg"}]}'
}
_cf_api_ok() { [[ "$(grep -o '"success":true' <<< "$1")" == '"success":true' ]]; }
prompt_domain_out="$(printf '2\ntest\n' | reality_prompt_domain_with_zones '节点连接' 'secret-token' 2>/tmp/reality-domain-prompt.err)"
[[ "$prompt_domain_out" == 'test.gpt.xx.kg' ]] || fail "zone-aware domain prompt should return only joined full domain on stdout, got: $prompt_domain_out"

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
