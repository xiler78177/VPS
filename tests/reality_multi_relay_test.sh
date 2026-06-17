#!/bin/bash
# tests/reality_multi_relay_test.sh
# 行为测试：单落地 + 多路中转（每路独立身份/独立链接）。
# 直接 source 模块真实函数，mock 掉系统依赖（systemctl/ufw/realm 安装/校验等）。
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

pass=0; fail=0
ck(){ if eval "$2"; then echo "  PASS: $1"; pass=$((pass+1)); else echo "  FAIL: $1"; fail=$((fail+1)); fi; }

# ---- 跨模块依赖 mock（模块自身不定义这些，故不会被覆盖）----
validate_port(){ [[ "${1:-}" =~ ^[0-9]+$ ]] && [[ "$1" -ge 1 && "$1" -le 65535 ]]; }
validate_domain(){ [[ "${1:-}" == *.* ]]; }
validate_ip(){ [[ "${1:-}" =~ ^[0-9]+\.[0-9.]+$ ]]; }
command_exists(){ return 1; }
systemctl(){ return 0; }
confirm(){ return 0; }
pause(){ :; }
fix_terminal(){ :; }
print_title(){ :; }; print_success(){ :; }; print_warn(){ :; }; print_info(){ :; }
print_error(){ echo "ERR: $*" >&2; }
draw_line(){ :; }
log_action(){ :; }
firewall_apply_realm_port(){ return 0; }
ufw_is_active(){ return 1; }
ufw_setup(){ :; }
install_package(){ return 0; }
C_GREEN=""; C_RESET=""; C_CYAN=""; C_RED=""; C_YELLOW=""; C_BLUE=""

# 让常量指向临时目录
export REALITY_CONFIG_DIR="$TMP/reality"
export REALITY_STATE_FILE="$REALITY_CONFIG_DIR/state.conf"
export REALITY_LINK_FILE="$REALITY_CONFIG_DIR/client-link.txt"
export REALITY_CLIENT_JSON="$REALITY_CONFIG_DIR/client.json"
export REALITY_BACKUP_DIR="$REALITY_CONFIG_DIR/backups"
export REALITY_RELAY_DIR="$REALITY_CONFIG_DIR/relays"
export REALITY_REALM_CONFIG="$TMP/realm.toml"
mkdir -p "$REALITY_CONFIG_DIR" "$REALITY_RELAY_DIR"

# 避免 source 时拉起 SNI 增强模块
export REALITY_ENHANCEMENT_MODULE="/nonexistent-$$"

# shellcheck disable=SC1090
source "$ROOT/modules/15-singbox-reality.sh"

# ---- 覆盖模块内重函数为 stub（source 之后才能覆盖）----
reality_install_realm_binary(){ return 0; }
reality_require_supported_os(){ return 0; }
reality_relay_ensure_service(){ :; }
reality_sync_cloudflare_dns(){ return 0; }
validate_conf_file(){ return 0; }   # 临时目录文件非 root:600，测试中放行

echo "[T1] 两条线路各自独立身份 → 渲染多端点 + 每路链接互不串扰"
RLY_NAME="lineB"; RLY_LISTEN_PORT="51882"; RLY_CONNECT_HOST="a.example.com"
RLY_TARGET_HOST="b.land.com"; RLY_TARGET_PORT="33964"
RLY_UUID="uuid-B"; RLY_SNI="sniB.com"; RLY_PUBLIC_KEY="PBK_B"; RLY_SHORT_ID="SIDB"; RLY_FLOW="xtls-rprx-vision"
reality_relay_write_route 51882; reality_relay_write_client_artifacts
RLY_NAME="lineC"; RLY_LISTEN_PORT="51883"; RLY_CONNECT_HOST="a.example.com"
RLY_TARGET_HOST="c.land.com"; RLY_TARGET_PORT="443"
RLY_UUID="uuid-C"; RLY_SNI="sniC.com"; RLY_PUBLIC_KEY="PBK_C"; RLY_SHORT_ID="SIDC"; RLY_FLOW="xtls-rprx-vision"
reality_relay_write_route 51883; reality_relay_write_client_artifacts

cfg="$(reality_render_realm_config_multi)"
ck "渲染恰好 2 个 [[endpoints]]" '[[ $(grep -c "\[\[endpoints\]\]" <<< "$cfg") -eq 2 ]]'
ck "渲染恰好 1 行 log.level" '[[ $(grep -c "log.level" <<< "$cfg") -eq 1 ]]'
ck "含 B 端点 listen/remote" 'grep -q "listen = \"0.0.0.0:51882\"" <<< "$cfg" && grep -q "remote = \"b.land.com:33964\"" <<< "$cfg"'
ck "含 C 端点 listen/remote" 'grep -q "listen = \"0.0.0.0:51883\"" <<< "$cfg" && grep -q "remote = \"c.land.com:443\"" <<< "$cfg"'

lb="$(cat "$REALITY_RELAY_DIR/relay-51882.link.txt")"
lc="$(cat "$REALITY_RELAY_DIR/relay-51883.link.txt")"
ck "B 链接=B身份@A域名:51882" '[[ "$lb" == "vless://uuid-B@a.example.com:51882?"*"sni=sniB.com"*"pbk=PBK_B"*"sid=SIDB"* ]]'
ck "C 链接=C身份@A域名:51883" '[[ "$lc" == "vless://uuid-C@a.example.com:51883?"*"sni=sniC.com"*"pbk=PBK_C"*"sid=SIDC"* ]]'
ck "B 链接不含 C 身份(无串扰)" '! grep -q "PBK_C\|uuid-C\|SIDC" <<< "$lb"'

echo "[T2] regenerate 写出 realm 配置 + 刷新所有线路产物"
reality_relay_regenerate
ck "realm 配置文件含 2 端点" '[[ $(grep -c "\[\[endpoints\]\]" "$REALITY_REALM_CONFIG") -eq 2 ]]'
ck "两路 client.json 都在" '[[ -f "$REALITY_RELAY_DIR/relay-51882.client.json" && -f "$REALITY_RELAY_DIR/relay-51883.client.json" ]]'

echo "[T3] 删除一条线路 → 配置剩 1 端点，产物清理"
rm -f "$REALITY_RELAY_DIR"/relay-51882.*
reality_relay_regenerate
ck "删除后剩 1 端点" '[[ $(grep -c "\[\[endpoints\]\]" "$REALITY_REALM_CONFIG") -eq 1 ]]'
ck "剩余端点为 C" 'grep -q "remote = \"c.land.com:443\"" "$REALITY_REALM_CONFIG"'

echo "[T4] install_relay 导入身份 → 路由用导入身份(不串本机落地身份)"
# 模拟解析导入链接后 REALITY_* 为导入身份
REALITY_UUID="imp-uuid"; REALITY_SNI="imp.sni"; REALITY_PUBLIC_KEY="IMP_PBK"; REALITY_SHORT_ID="IMP_SID"
REALITY_NODE_DOMAIN="land.imp.com"; REALITY_PORT="33964"; REALITY_PRIVATE_KEY=""; REALITY_FLOW="xtls-rprx-vision"
REALITY_ROLE="landing"   # 本机本是落地
reality_install_relay "a.example.com" 51999 "land.imp.com" 33964 "" "impline" >/dev/null 2>&1
rl="$(cat "$REALITY_RELAY_DIR/relay-51999.link.txt" 2>/dev/null)"
ck "导入线路链接用导入身份@A域名:51999" '[[ "$rl" == "vless://imp-uuid@a.example.com:51999?"*"pbk=IMP_PBK"*"sid=IMP_SID"* ]]'
ck "install_relay 复合角色 landing+relay" 'reality_load_state && [[ "${REALITY_ROLE}" == "landing+relay" ]]'

echo "[T5] both 场景：目标 127.0.0.1 用本机落地身份"
RLY_NAME="self"; RLY_LISTEN_PORT="52000"; RLY_CONNECT_HOST="a.example.com"
RLY_TARGET_HOST="127.0.0.1"; RLY_TARGET_PORT="58853"
RLY_UUID="box-uuid"; RLY_SNI="box.sni"; RLY_PUBLIC_KEY="BOX_PBK"; RLY_SHORT_ID="BOX_SID"; RLY_FLOW="xtls-rprx-vision"
reality_relay_write_route 52000; reality_relay_write_client_artifacts
rself="$(cat "$REALITY_RELAY_DIR/relay-52000.link.txt")"
ck "本机自转链接用本机身份@A域名:52000" '[[ "$rself" == "vless://box-uuid@a.example.com:52000?"*"pbk=BOX_PBK"* ]]'

echo "[T6] 旧版单中转字段迁移为一条线路并清空旧字段"
rm -rf "$REALITY_RELAY_DIR"; mkdir -p "$REALITY_RELAY_DIR"
REALITY_UUID="leg-uuid"; REALITY_SNI="leg.sni"; REALITY_PUBLIC_KEY="LEG_PBK"; REALITY_SHORT_ID="LEG_SID"
REALITY_NODE_DOMAIN="a.example.com"; REALITY_NODE_NAME="legacy"
REALITY_RELAY_DOMAIN="a.example.com"; REALITY_RELAY_PORT="53000"
REALITY_RELAY_TARGET_HOST="old.land.com"; REALITY_RELAY_TARGET_PORT="33964"
reality_relay_migrate_legacy
ck "迁移生成 relay-53000.conf" '[[ -f "$REALITY_RELAY_DIR/relay-53000.conf" ]]'
ck "迁移后旧字段已清空" '[[ -z "$REALITY_RELAY_TARGET_HOST" && -z "$REALITY_RELAY_PORT" ]]'
reality_relay_load_route "$REALITY_RELAY_DIR/relay-53000.conf"
ck "迁移线路携带原身份+目标" '[[ "$RLY_UUID" == "leg-uuid" && "$RLY_TARGET_HOST" == "old.land.com" && "$RLY_TARGET_PORT" == "33964" ]]'

echo ""
echo "==== reality_multi_relay_test: PASS=$pass FAIL=$fail ===="
[[ $fail -eq 0 ]] && echo "reality_multi_relay_test: PASS" || { echo "reality_multi_relay_test: FAIL"; exit 1; }
