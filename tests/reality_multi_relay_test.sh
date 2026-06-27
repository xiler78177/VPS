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
export REALITY_LISTEN_HOST="0.0.0.0"   # 固定监听地址，使渲染断言不受测试机 IPv6 影响
# CDN 链路常量（构建产物里由 00-constants.sh 提供；测试不 source 它，需手动指向临时目录，
# 否则 set -u 下 reality_show_info 等引用未绑定的 CDN 常量会直接终止脚本）
export REALITY_CDN_STATE_FILE="$REALITY_CONFIG_DIR/cdn.conf"
export REALITY_CDN_LINK_FILE="$REALITY_CONFIG_DIR/cdn-link.txt"
export REALITY_CDN_CLIENT_JSON="$REALITY_CONFIG_DIR/cdn-client.json"
export REALITY_CDN_ORIGIN_PORT="8443"
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

cfg6="$(REALITY_LISTEN_HOST=:: reality_render_realm_config_multi)"
ck "IPv6 监听渲染为 [::]:port" 'grep -q "listen = \"\[::\]:51882\"" <<< "$cfg6"'

# 回归：split 双节点落地的哨兵值 REALITY_LISTEN_HOST=split 不得当作 realm bind 地址泄漏，
# 否则会渲染出非法的 listen = "split:<port>" 致 realm 无法启动（split 必有 IPv6→应回落 ::）。
cfg_split="$(REALITY_LISTEN_HOST=split reality_render_realm_config_multi)"
ck "split 哨兵不泄漏为 listen=split:port" '! grep -q "listen = \"split:" <<< "$cfg_split"'
cfg_split_single="$(REALITY_LISTEN_HOST=split reality_render_realm_config 51999 land.example.com 443)"
ck "单端点渲染同样不泄漏 split 哨兵" '! grep -q "listen = \"split:" <<< "$cfg_split_single"'

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

echo "[T7] 细节优化：脱敏/链接视图/回滚/诊断中转段"
MOD="$ROOT/modules/15-singbox-reality.sh"
ck "mask_secret 长串脱敏" '[[ "$(reality_mask_secret 0123456789abcdef0123)" == "012345…0123" ]]'
ck "mask_secret 短串原样" '[[ "$(reality_mask_secret short)" == "short" ]]'
ck "已移除冗余 reality_show_links" '! grep -q "reality_show_links" "$MOD"'
info_body="$(awk "/^reality_info_menu\\(\\)/,/^}/" "$MOD")"
ck "info 菜单不再有独立输出链接项" '! grep -q "输出客户端链接" <<< "$info_body"'
list_body="$(awk "/^reality_relay_list\\(\\)/,/^}/" "$MOD")"
ck "中转线路列表只显示清单(不 dump 链接)" '! grep -q "link.txt" <<< "$list_body"'
ck "中转线路列表显示监听状态" 'grep -q "监听中" <<< "$list_body"'
ck "relay_add 含解析核对/确认" 'grep -q "以上落地参数是否正确" "$MOD"'
add_body="$(awk "/^reality_relay_add\\(\\)/,/^}/" "$MOD")"
ck "relay_add 含失败回滚" 'grep -q "正在回滚本条线路" <<< "$add_body"'
ck "relay_add 多处可取消(0/q)" 'grep -q "0=取消" <<< "$add_body"'
diag_body="$(awk "/^reality_diagnose\\(\\)/,/^}/" "$MOD")"
ck "diagnose 含 realm 服务检查" 'grep -q "realm 中转服务" <<< "$diag_body"'
ck "diagnose 含每线路监听检查" 'grep -q "中转线路 .* 监听" <<< "$diag_body"'

echo "[T8] 回归：添加线路后报告/回滚必须用 local，不被 regenerate 遍历覆盖 RLY_*"
# relay_add 必须把新线路标识固定为 local，再在 regenerate 之后引用
ck "relay_add 捕获 local new_port" 'grep -q "local new_port=" <<< "$add_body"'
ck "relay_add 成功提示用 new_* 而非 RLY_*" 'grep -q "本机 \${new_chost}:\${new_port}" <<< "$add_body"'
ck "relay_add 链接展示用 relay-\${new_port}" 'grep -q "relay-\${new_port}.link.txt" <<< "$add_body"'
ck "relay_add 回滚 rm 用 new_port" 'grep -q "relay-\${new_port}.conf" <<< "$add_body"'
# 行为：证实 regenerate 会覆盖 RLY_*（故调用方必须先存 local）；且各线路文件本身正确
rm -rf "$REALITY_RELAY_DIR"; mkdir -p "$REALITY_RELAY_DIR"
RLY_NAME="A"; RLY_LISTEN_PORT="22222"; RLY_CONNECT_HOST="a.example.com"
RLY_TARGET_HOST="sanjose.land"; RLY_TARGET_PORT="44231"
RLY_UUID="uuid-A"; RLY_SNI="a.sni"; RLY_PUBLIC_KEY="PBK_A"; RLY_SHORT_ID="SIDA"; RLY_FLOW="xtls-rprx-vision"
reality_relay_write_route 22222; reality_relay_write_client_artifacts
RLY_NAME="B"; RLY_LISTEN_PORT="99999"; RLY_CONNECT_HOST="a.example.com"
RLY_TARGET_HOST="mcdool.land"; RLY_TARGET_PORT="53487"
RLY_UUID="uuid-B"; RLY_SNI="b.sni"; RLY_PUBLIC_KEY="PBK_B"; RLY_SHORT_ID="SIDB"; RLY_FLOW="xtls-rprx-vision"
reality_relay_write_route 99999; reality_relay_write_client_artifacts
# 模拟“刚添加 A”，捕获 local，再 regenerate
new_port="22222"; new_thost="sanjose.land"
RLY_NAME="A"; RLY_LISTEN_PORT="22222"; RLY_TARGET_HOST="sanjose.land"
reality_relay_regenerate >/dev/null 2>&1 || true
ck "regenerate 之后 RLY_* 被覆盖(印证 bug 成因)" '[[ "$RLY_LISTEN_PORT" != "22222" ]]'
ck "用 local new_port 仍能取到 A 的链接(修复点)" 'grep -q "@a.example.com:22222?" "$REALITY_RELAY_DIR/relay-${new_port}.link.txt" && grep -q "pbk=PBK_A" "$REALITY_RELAY_DIR/relay-${new_port}.link.txt"'


echo "[T9] CDN 链路 WS 入站：合并渲染 + rotate 后存活（最高风险点）"
# CDN state 文件常量在测试顶部未导出，这里单独指向临时目录
export REALITY_CDN_STATE_FILE="$REALITY_CONFIG_DIR/cdn.conf"
# 落地身份（render 必需）
REALITY_DNS_MODE="auto"; REALITY_PORT="443"; REALITY_PORT_V6=""
# 未启用 CDN 时：渲染不得含 WS 入站
rm -f "$REALITY_CDN_STATE_FILE"
cfg_nocdn="$(reality_render_singbox_config uid-x pk-x 443 sni.x sid-x)"
ck "未装 CDN → 无 vless-cdn-ws 入站" '! grep -q "vless-cdn-ws" <<< "$cfg_nocdn"'
ck "未装 CDN → 渲染为合法单 reality 入站" 'grep -q "vless-reality-in" <<< "$cfg_nocdn"'

# 写 CDN state（复用模块函数），再渲染
REALITY_CDN_DOMAIN="cdn.example.com"; REALITY_CDN_UUID="cdn-uuid-123"
REALITY_CDN_WS_PATH="/secretpath00"; REALITY_CDN_INNER_PORT="58999"
REALITY_CDN_ORIGIN_PORT="8443"; REALITY_CDN_PREFER_IP=""; REALITY_CDN_NODE_NAME="cdn-test"
reality_cdn_write_state
ck "reality_cdn_enabled 识别已启用" 'reality_cdn_enabled'
cfg_cdn="$(reality_render_singbox_config uid-x pk-x 443 sni.x sid-x)"
ck "装 CDN → 含 vless-cdn-ws 入站" 'grep -q "vless-cdn-ws" <<< "$cfg_cdn"'
ck "WS 入站绑 127.0.0.1:内部端口" 'grep -q "\"listen\":\"127.0.0.1\",\"listen_port\":58999" <<< "$cfg_cdn"'
ck "WS 入站含 ws path" 'grep -q "\"path\":\"/secretpath00\"" <<< "$cfg_cdn"'
ck "WS 入站仍保留 reality 入站(并存非替换)" 'grep -q "vless-reality-in" <<< "$cfg_cdn"'
# rotate key/user 模拟：换 uuid/key 重渲，WS 入站必须仍在（核心回归）
cfg_rot="$(reality_render_singbox_config new-uuid new-pk 443 sni.x new-sid)"
ck "rotate 重渲后 WS 入站仍存活" 'grep -q "vless-cdn-ws" <<< "$cfg_rot"'
ck "rotate 重渲后 reality 入站换了新 uuid" 'grep -q "new-uuid" <<< "$cfg_rot"'
# split 双节点 + CDN：两个 reality 入站 + 1 个 WS 入站
cfg_split_cdn="$(REALITY_DNS_MODE=split REALITY_PORT_V6=443 reality_render_singbox_config uid-x pk-x 443 sni.x sid-x)"
ck "split+CDN → 含 WS 入站" 'grep -q "vless-cdn-ws" <<< "$cfg_split_cdn"'
ck "split+CDN → 含 IPv4+IPv6 两个 reality 入站" 'grep -q "vless-reality-ipv4" <<< "$cfg_split_cdn" && grep -q "vless-reality-ipv6" <<< "$cfg_split_cdn"'
# CDN 客户端链接：server=优选IP，host/sni=真实域名
REALITY_CDN_PREFER_IP="1.2.3.4"
link_cdn="$(reality_cdn_build_link "$REALITY_CDN_PREFER_IP" "cdn-test")"
ck "CDN 链接 server=优选IP" '[[ "$link_cdn" == "vless://cdn-uuid-123@1.2.3.4:443?"* ]]'
ck "CDN 链接 host/sni=真实域名" 'grep -q "sni=cdn.example.com" <<< "$link_cdn" && grep -q "host=cdn.example.com" <<< "$link_cdn"'
ck "CDN 链接 type=ws + path" 'grep -q "type=ws" <<< "$link_cdn" && grep -q "path=%2Fsecretpath00" <<< "$link_cdn"'
# 卸载语义：删 state 后渲染回到无 WS 入站
rm -f "$REALITY_CDN_STATE_FILE"
ck "删 state → reality_cdn_enabled 为否" '! reality_cdn_enabled'
cfg_after="$(reality_render_singbox_config uid-x pk-x 443 sni.x sid-x)"
ck "卸载后渲染无 WS 入站" '! grep -q "vless-cdn-ws" <<< "$cfg_after"'

echo ""
echo "==== reality_multi_relay_test: PASS=$pass FAIL=$fail ===="
[[ $fail -eq 0 ]] && echo "reality_multi_relay_test: PASS" || { echo "reality_multi_relay_test: FAIL"; exit 1; }
