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
write_file_atomic(){ mkdir -p "$(dirname "$1")"; printf '%s' "$2" > "$1"; }
copy_cert_pair_atomic(){
    mkdir -p "$3" || return 1
    cp "$1" "$3/fullchain.pem" || return 1
    cp "$2" "$3/privkey.pem" || return 1
    chmod 644 "$3/fullchain.pem" 2>/dev/null || true
    chmod 600 "$3/privkey.pem" 2>/dev/null || true
}
render_cert_pair_hook_helper(){ printf 'copy_cert_pair_atomic(){ cp "$1" "$3/fullchain.pem"; cp "$2" "$3/privkey.pem"; }\n'; }

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
# 真实落地机：本机落地身份必已写盘（含私钥）。install_relay 会清空内存 REALITY_* 再 load_state 回填本机身份。
REALITY_UUID="self-land-uuid"; REALITY_SNI="self.land.com"; REALITY_PUBLIC_KEY="SELF_PBK"; REALITY_SHORT_ID="SELF_SID"
REALITY_NODE_DOMAIN="self.land.com"; REALITY_PORT="443"; REALITY_PRIVATE_KEY="self-priv"; REALITY_FLOW="xtls-rprx-vision"
REALITY_ROLE="landing"
reality_write_state   # 落地身份写盘（模拟真实落地机磁盘状态）
# 模拟 wizard 解析导入链接后 REALITY_* 被覆盖为下游身份（内存态；install_relay 内部会清空再回填）
REALITY_UUID="imp-uuid"; REALITY_SNI="imp.sni"; REALITY_PUBLIC_KEY="IMP_PBK"; REALITY_SHORT_ID="IMP_SID"
REALITY_NODE_DOMAIN="land.imp.com"; REALITY_PORT="33964"; REALITY_PRIVATE_KEY=""; REALITY_FLOW="xtls-rprx-vision"
reality_install_relay "a.example.com" 51999 "land.imp.com" 33964 "" "impline" >/dev/null 2>&1
rl="$(cat "$REALITY_RELAY_DIR/relay-51999.link.txt" 2>/dev/null)"
ck "导入线路链接用导入身份@A域名:51999" '[[ "$rl" == "vless://imp-uuid@a.example.com:51999?"*"pbk=IMP_PBK"*"sid=IMP_SID"* ]]'
ck "install_relay 复合角色 landing+relay" 'reality_load_state && [[ "${REALITY_ROLE}" == "landing+relay" ]]'
# HIGH-1 回归：导入下游身份绝不污染本机落地 state（私钥/UUID 必须仍是本机的）
ck "HIGH-1 本机落地私钥未被抹掉" 'reality_load_state && [[ "${REALITY_PRIVATE_KEY}" == "self-priv" ]]'
ck "HIGH-1 本机落地UUID未被下游覆盖" 'reality_load_state && [[ "${REALITY_UUID}" == "self-land-uuid" ]]'
ck "HIGH-1 本机落地SNI未被下游覆盖" 'reality_load_state && [[ "${REALITY_SNI}" == "self.land.com" ]]'

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
link_cdn6="$(reality_cdn_build_link "2606:4700::1111" "cdn-v6")"
ck "CDN 链接 IPv6 server 自动加方括号" '[[ "$link_cdn6" == "vless://cdn-uuid-123@[2606:4700::1111]:443?"* ]]'
link_reality6="$(reality_build_vless_link "uid6" "2001:db8::1" "443" "sni.x" "pbk6" "sid6" "node-v6")"
ck "Reality 链接 IPv6 server 自动加方括号" '[[ "$link_reality6" == "vless://uid6@[2001:db8::1]:443?"* ]]'
reality_parse_vless_link "$link_reality6"
ck "解析 bracket IPv6 vless 链接不截断 host/port" '[[ "$REALITY_NODE_DOMAIN" == "2001:db8::1" && "$REALITY_PORT" == "443" ]]'
# 卸载语义：删 state 后渲染回到无 WS 入站
rm -f "$REALITY_CDN_STATE_FILE"
ck "删 state → reality_cdn_enabled 为否" '! reality_cdn_enabled'
cfg_after="$(reality_render_singbox_config uid-x pk-x 443 sni.x sid-x)"
ck "卸载后渲染无 WS 入站" '! grep -q "vless-cdn-ws" <<< "$cfg_after"'

# 卸载回归：sing-box 重渲失败时必须恢复 CDN state，避免旧 config 仍有 WS 入站但 state 丢失。
REALITY_CDN_DOMAIN="cdn.example.com"; REALITY_CDN_UUID="cdn-uuid-123"
REALITY_CDN_WS_PATH="/secretpath00"; REALITY_CDN_INNER_PORT="58999"
REALITY_CDN_ORIGIN_PORT="8443"; REALITY_CDN_PREFER_IP=""; REALITY_CDN_NODE_NAME="cdn-test"
reality_cdn_write_state
REALITY_ROLE="landing"; REALITY_NODE_DOMAIN="node.example.com"; REALITY_DNS_MODE="auto"
REALITY_PORT="443"; REALITY_UUID="uid-x"; REALITY_PRIVATE_KEY="pk-x"; REALITY_PUBLIC_KEY="pbk-x"; REALITY_SNI="sni.x"; REALITY_SHORT_ID="sid-x"
reality_write_state
reality_apply_singbox_config(){ return 1; }
reality_cdn_uninstall >/dev/null 2>&1 || true
ck "CDN 卸载失败回滚会恢复 state" '[[ -f "$REALITY_CDN_STATE_FILE" ]] && grep -q "REALITY_CDN_DOMAIN" "$REALITY_CDN_STATE_FILE"'

# 安装回归：UFW active 但回源端口放行失败时不得继续报安装完成。
# 这里把前置步骤全部 stub 成成功，只让 firewall_allow_tcp_port 失败，验证失败会被传播。
(
    export REALITY_CONFIG_DIR="$TMP/cdn-install-fw"
    export REALITY_STATE_FILE="$REALITY_CONFIG_DIR/state.conf"
    export REALITY_CDN_STATE_FILE="$REALITY_CONFIG_DIR/cdn.conf"
    export REALITY_CDN_LINK_FILE="$REALITY_CONFIG_DIR/cdn-link.txt"
    export REALITY_CDN_CLIENT_JSON="$REALITY_CONFIG_DIR/cdn-client.json"
    export REALITY_CDN_ORIGIN_PORT="8443"
	    export CERT_PATH_PREFIX="$REALITY_CONFIG_DIR/cert"
	    export CERT_HOOKS_DIR="$REALITY_CONFIG_DIR/hooks"
	    export REALITY_CDN_CF_CRED_DIR="$REALITY_CONFIG_DIR/root"
	    export REALITY_CDN_LE_LIVE_DIR="$REALITY_CONFIG_DIR/le-live"
	    export EMAIL="audit@example.com"
	    mkdir -p "$REALITY_CONFIG_DIR" "$CERT_HOOKS_DIR" "$REALITY_CDN_CF_CRED_DIR" "$REALITY_CDN_LE_LIVE_DIR"
    REALITY_ROLE="landing"; REALITY_UUID="uid-fw"; REALITY_PRIVATE_KEY="pk-fw"; REALITY_PUBLIC_KEY="pbk-fw"
    REALITY_PORT="443"; REALITY_SNI="sni.example.com"; REALITY_SHORT_ID="sidfw"; REALITY_DNS_MODE="auto"
    reality_write_state
    command_exists(){ case "${1:-}" in nginx|certbot) return 0 ;; *) return 1 ;; esac; }
    reality_require_supported_os(){ return 0; }
    reality_prompt_cf_token(){ printf 'token-fw\n'; }
    reality_prompt_domain_with_zones(){ printf 'cdn.example.com\n'; }
    reality_prompt_node_name(){ printf 'cdn-fw\n'; }
    reality_cdn_pick_inner_port(){ printf '58999\n'; }
    reality_cdn_gen_ws_path(){ printf '/secretpath00\n'; }
	    write_private_file_atomic(){ mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; chmod 600 "$1"; return 0; }
	    certbot(){
	        case "$*" in
	            certonly*) mkdir -p "$REALITY_CDN_LE_LIVE_DIR/cdn.example.com"; printf 'cert\n' > "$REALITY_CDN_LE_LIVE_DIR/cdn.example.com/fullchain.pem"; printf 'key\n' > "$REALITY_CDN_LE_LIVE_DIR/cdn.example.com/privkey.pem" ;;
	            delete*) rm -rf "$REALITY_CDN_LE_LIVE_DIR/cdn.example.com" ;;
	        esac
	        return 0
	    }
	    cron_add_job(){ printf '%s\n' "$1" > "$REALITY_CONFIG_DIR/cron-added"; return 0; }
	    cron_remove_job(){ printf '%s\n' "$1" > "$REALITY_CONFIG_DIR/cron-removed"; return 0; }
    _ensure_ssl_params(){ return 0; }
    _nginx_deploy_conf(){ return 0; }
    reality_render_singbox_config(){ printf '{"ok":true}\n'; }
    reality_apply_singbox_config(){ return 0; }
    reality_cdn_sync_dns_orange(){ return 0; }
    reality_cdn_apply_origin_rule(){ return 0; }
    firewall_allow_tcp_port(){ return 1; }
    reality_cdn_install >/dev/null 2>&1
)
	cdn_fw_rc=$?
	ck "CDN 安装在 UFW active 放行失败时返回非 0" '[[ "$cdn_fw_rc" -ne 0 ]]'
	ck "CDN 防火墙失败不会继续写客户端完成产物" '[[ ! -f "$TMP/cdn-install-fw/cdn-link.txt" && ! -f "$TMP/cdn-install-fw/cdn-client.json" ]]'

# 安装回归：CF 橙云 DNS 同步失败时必须 fail-closed，不能留下本机 CDN 半成品。
(
    export REALITY_CONFIG_DIR="$TMP/cdn-install-dns"
    export REALITY_STATE_FILE="$REALITY_CONFIG_DIR/state.conf"
    export REALITY_CDN_STATE_FILE="$REALITY_CONFIG_DIR/cdn.conf"
    export REALITY_CDN_LINK_FILE="$REALITY_CONFIG_DIR/cdn-link.txt"
    export REALITY_CDN_CLIENT_JSON="$REALITY_CONFIG_DIR/cdn-client.json"
    export REALITY_CDN_ORIGIN_PORT="8443"
	    export CERT_PATH_PREFIX="$REALITY_CONFIG_DIR/cert"
	    export CERT_HOOKS_DIR="$REALITY_CONFIG_DIR/hooks"
	    export REALITY_CDN_CF_CRED_DIR="$REALITY_CONFIG_DIR/root"
	    export REALITY_CDN_LE_LIVE_DIR="$REALITY_CONFIG_DIR/le-live"
	    export EMAIL="audit@example.com"
	    mkdir -p "$REALITY_CONFIG_DIR" "$CERT_HOOKS_DIR" "$REALITY_CDN_CF_CRED_DIR" "$REALITY_CDN_LE_LIVE_DIR"
    REALITY_ROLE="landing"; REALITY_UUID="uid-dns"; REALITY_PRIVATE_KEY="pk-dns"; REALITY_PUBLIC_KEY="pbk-dns"
    REALITY_PORT="443"; REALITY_SNI="sni.example.com"; REALITY_SHORT_ID="siddns"; REALITY_DNS_MODE="auto"
    reality_write_state
    command_exists(){ case "${1:-}" in nginx|certbot) return 0 ;; *) return 1 ;; esac; }
    reality_require_supported_os(){ return 0; }
    reality_prompt_cf_token(){ printf 'token-dns\n'; }
    reality_prompt_domain_with_zones(){ printf 'cdn.example.com\n'; }
    reality_prompt_node_name(){ printf 'cdn-dns\n'; }
    reality_cdn_pick_inner_port(){ printf '58999\n'; }
    reality_cdn_gen_ws_path(){ printf '/secretpath00\n'; }
	    write_private_file_atomic(){ mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; chmod 600 "$1"; return 0; }
	    certbot(){
	        case "$*" in
	            certonly*) mkdir -p "$REALITY_CDN_LE_LIVE_DIR/cdn.example.com"; printf 'cert\n' > "$REALITY_CDN_LE_LIVE_DIR/cdn.example.com/fullchain.pem"; printf 'key\n' > "$REALITY_CDN_LE_LIVE_DIR/cdn.example.com/privkey.pem" ;;
	            delete*) rm -rf "$REALITY_CDN_LE_LIVE_DIR/cdn.example.com" ;;
	        esac
	        return 0
	    }
	    cron_add_job(){ printf '%s\n' "$1" > "$REALITY_CONFIG_DIR/cron-added"; return 0; }
	    cron_remove_job(){ printf '%s\n' "$1" > "$REALITY_CONFIG_DIR/cron-removed"; return 0; }
    _ensure_ssl_params(){ return 0; }
    _nginx_deploy_conf(){ mkdir -p "$REALITY_CONFIG_DIR/nginx"; : > "$REALITY_CONFIG_DIR/nginx/deployed"; return 0; }
    reality_cdn_remove_nginx_conf(){ rm -f "$REALITY_CONFIG_DIR/nginx/deployed"; }
    reality_render_singbox_config(){ printf '{"ok":true}\n'; }
    reality_apply_singbox_config(){ return 0; }
    reality_cdn_sync_dns_orange(){ return 1; }
    reality_cdn_apply_origin_rule(){ return 0; }
    firewall_allow_tcp_port(){ return 0; }
    reality_cdn_install >/dev/null 2>&1
)
	cdn_dns_rc=$?
	ck "CDN 安装在橙云 DNS 同步失败时返回非 0" '[[ "$cdn_dns_rc" -ne 0 ]]'
	ck "CDN DNS 失败会回滚 state/nginx/客户端产物" '[[ ! -f "$TMP/cdn-install-dns/cdn.conf" && ! -e "$TMP/cdn-install-dns/nginx/deployed" && ! -f "$TMP/cdn-install-dns/cdn-link.txt" && ! -f "$TMP/cdn-install-dns/cdn-client.json" ]]'
	ck "CDN DNS 失败会清理本次新建证书凭据 hook cron" '[[ ! -e "$TMP/cdn-install-dns/cert/cdn.example.com" && ! -e "$TMP/cdn-install-dns/root/.cloudflare-cdn.example.com.ini" && ! -e "$TMP/cdn-install-dns/hooks/renew-cdn.example.com.sh" && ! -e "$TMP/cdn-install-dns/le-live/cdn.example.com" && -f "$TMP/cdn-install-dns/cron-removed" ]]'

# 安装回归：Origin Rule 写入失败时回滚新链路，并恢复覆盖前的旧 state/产物。
(
    export REALITY_CONFIG_DIR="$TMP/cdn-install-origin"
    export REALITY_STATE_FILE="$REALITY_CONFIG_DIR/state.conf"
    export REALITY_CDN_STATE_FILE="$REALITY_CONFIG_DIR/cdn.conf"
    export REALITY_CDN_LINK_FILE="$REALITY_CONFIG_DIR/cdn-link.txt"
    export REALITY_CDN_CLIENT_JSON="$REALITY_CONFIG_DIR/cdn-client.json"
    export REALITY_CDN_ORIGIN_PORT="8443"
	    export CERT_PATH_PREFIX="$REALITY_CONFIG_DIR/cert"
	    export CERT_HOOKS_DIR="$REALITY_CONFIG_DIR/hooks"
	    export REALITY_CDN_CF_CRED_DIR="$REALITY_CONFIG_DIR/root"
	    export REALITY_CDN_LE_LIVE_DIR="$REALITY_CONFIG_DIR/le-live"
	    export EMAIL="audit@example.com"
	    mkdir -p "$REALITY_CONFIG_DIR" "$CERT_HOOKS_DIR" "$REALITY_CDN_CF_CRED_DIR" "$REALITY_CDN_LE_LIVE_DIR" "$CERT_PATH_PREFIX/new.example.com" "$REALITY_CDN_LE_LIVE_DIR/new.example.com"
	    printf 'old-cert\n' > "$CERT_PATH_PREFIX/new.example.com/fullchain.pem"
	    printf 'old-key\n' > "$CERT_PATH_PREFIX/new.example.com/privkey.pem"
	    printf 'old-live-cert\n' > "$REALITY_CDN_LE_LIVE_DIR/new.example.com/fullchain.pem"
	    printf 'old-live-key\n' > "$REALITY_CDN_LE_LIVE_DIR/new.example.com/privkey.pem"
	    printf 'old-token\n' > "$REALITY_CDN_CF_CRED_DIR/.cloudflare-new.example.com.ini"
	    printf '#!/bin/sh\nold-hook\n' > "$CERT_HOOKS_DIR/renew-new.example.com.sh"
    REALITY_ROLE="landing"; REALITY_UUID="uid-origin"; REALITY_PRIVATE_KEY="pk-origin"; REALITY_PUBLIC_KEY="pbk-origin"
    REALITY_PORT="443"; REALITY_SNI="sni.example.com"; REALITY_SHORT_ID="sidorigin"; REALITY_DNS_MODE="auto"
    reality_write_state
    REALITY_CDN_DOMAIN="old.example.com"; REALITY_CDN_UUID="old-uuid"; REALITY_CDN_WS_PATH="/oldpath00"
    REALITY_CDN_INNER_PORT="58888"; REALITY_CDN_ORIGIN_PORT="8443"; REALITY_CDN_PREFER_IP=""; REALITY_CDN_NODE_NAME="old-cdn"
    reality_cdn_write_state
    reality_write_secure_file "$REALITY_CDN_LINK_FILE" "old-link"
    reality_write_secure_file "$REALITY_CDN_CLIENT_JSON" '{"old":true}'
    command_exists(){ case "${1:-}" in nginx|certbot) return 0 ;; *) return 1 ;; esac; }
    reality_require_supported_os(){ return 0; }
    reality_prompt_cf_token(){ printf 'token-origin\n'; }
    reality_prompt_domain_with_zones(){ printf 'new.example.com\n'; }
    reality_prompt_node_name(){ printf 'cdn-origin\n'; }
    reality_cdn_pick_inner_port(){ printf '58999\n'; }
    reality_cdn_gen_ws_path(){ printf '/secretpath00\n'; }
	    write_private_file_atomic(){ mkdir -p "$(dirname "$1")"; printf '%s\n' "$2" > "$1"; chmod 600 "$1"; return 0; }
	    certbot(){
	        case "$*" in
	            certonly*) printf 'new-live-cert\n' > "$REALITY_CDN_LE_LIVE_DIR/new.example.com/fullchain.pem"; printf 'new-live-key\n' > "$REALITY_CDN_LE_LIVE_DIR/new.example.com/privkey.pem" ;;
	            delete*) rm -rf "$REALITY_CDN_LE_LIVE_DIR/new.example.com" ;;
	        esac
	        return 0
	    }
	    cron_add_job(){ printf '%s\n' "$1" > "$REALITY_CONFIG_DIR/cron-added"; return 0; }
	    cron_remove_job(){ printf '%s\n' "$1" > "$REALITY_CONFIG_DIR/cron-removed"; return 0; }
    _ensure_ssl_params(){ return 0; }
    _nginx_deploy_conf(){ mkdir -p "$REALITY_CONFIG_DIR/nginx"; : > "$REALITY_CONFIG_DIR/nginx/${1:-site}"; return 0; }
    reality_cdn_remove_nginx_conf(){ rm -f "$REALITY_CONFIG_DIR/nginx/reality-cdn-${1:-}.conf" "$REALITY_CONFIG_DIR/nginx/deployed" "$REALITY_CONFIG_DIR/nginx/reality-cdn-new.example.com"; }
    reality_render_singbox_config(){ printf '{"ok":true}\n'; }
    reality_apply_singbox_config(){ return 0; }
    reality_cdn_sync_dns_orange(){ return 0; }
    reality_cdn_apply_origin_rule(){ return 1; }
    firewall_allow_tcp_port(){ return 0; }
    reality_cdn_install >/dev/null 2>&1
)
	cdn_origin_rc=$?
	ck "CDN 安装在 Origin Rule 写入失败时返回非 0" '[[ "$cdn_origin_rc" -ne 0 ]]'
	ck "CDN Origin Rule 失败会恢复旧 state/产物" 'grep -q "old.example.com" "$TMP/cdn-install-origin/cdn.conf" && grep -q "old-link" "$TMP/cdn-install-origin/cdn-link.txt" && grep -q "\"old\":true" "$TMP/cdn-install-origin/cdn-client.json"'
	ck "CDN Origin Rule 失败会恢复安装前证书凭据 hook" 'grep -q "old-cert" "$TMP/cdn-install-origin/cert/new.example.com/fullchain.pem" && grep -q "old-token" "$TMP/cdn-install-origin/root/.cloudflare-new.example.com.ini" && grep -q "old-hook" "$TMP/cdn-install-origin/hooks/renew-new.example.com.sh" && grep -q "old-live-cert" "$TMP/cdn-install-origin/le-live/new.example.com/fullchain.pem" && [[ ! -f "$TMP/cdn-install-origin/cron-removed" ]]'

echo "[FP] 客户端指纹随机化（fp=chrome 特征分散）"
# 随机指纹只落在真实浏览器池内（不含 randomized/360/q）
fp_ok=1
for _i in $(seq 1 30); do
    f=$(reality_random_fingerprint)
    case "$f" in chrome|firefox|edge|safari|ios|android) : ;; *) fp_ok=0; break ;; esac
done
ck "reality_random_fingerprint 只产出真实浏览器指纹池成员" '[[ "$fp_ok" == "1" ]]'
# 30 次抽样至少见到 2 种（几乎不可能恒定单值；概率上验证「确实随机」）
uniq_n=$(for _i in $(seq 1 30); do reality_random_fingerprint; echo; done | sort -u | wc -l)
ck "随机指纹有分散性（≥2 种）" '[[ "$uniq_n" -ge 2 ]]'
# sanitize：合法值透传，非法/空回退 chrome
ck "sanitize 合法 firefox 透传" '[[ "$(reality_sanitize_fingerprint firefox)" == "firefox" ]]'
ck "sanitize 非法值回退 chrome" '[[ "$(reality_sanitize_fingerprint bogusfp)" == "chrome" ]]'
ck "sanitize 空值回退 chrome" '[[ "$(reality_sanitize_fingerprint "")" == "chrome" ]]'
# effective：读 state 的 REALITY_FINGERPRINT；旧版无该字段→chrome
REALITY_FINGERPRINT="safari"
ck "effective 读 state 指纹" '[[ "$(reality_effective_fingerprint)" == "safari" ]]'
REALITY_FINGERPRINT=""
ck "effective 空 state 回退 chrome（老节点兼容）" '[[ "$(reality_effective_fingerprint)" == "chrome" ]]'
# 链接携带 fp，且 parse 能回读为 REALITY_FINGERPRINT（中转导入沿用落地真实指纹）
link_fp="$(reality_build_vless_link uidF nodeF.example.com 443 sniF pbkF sidF nameF edge)"
ck "build_vless_link 写入 fp=edge" 'grep -q "fp=edge" <<< "$link_fp"'
REALITY_FINGERPRINT=""
reality_parse_vless_link "$link_fp"
ck "parse 回读 fp→REALITY_FINGERPRINT" '[[ "$REALITY_FINGERPRINT" == "edge" ]]'
# build 未传 fp → 回退 chrome（旧调用不破坏）
link_nofp="$(reality_build_vless_link uidG nodeG.example.com 443 sniG pbkG sidG nameG)"
ck "build_vless_link 缺省 fp 回退 chrome" 'grep -q "fp=chrome" <<< "$link_nofp"'
# 相邻两次全新安装身份的指纹独立（分散全网特征的核心目的）——用 relay 路由持久化验证 RLY_FINGERPRINT 落盘
RLY_NAME="r1"; RLY_LISTEN_PORT="41001"; RLY_CONNECT_HOST="h1.example.com"
RLY_TARGET_HOST="t1.example.com"; RLY_TARGET_PORT="443"
RLY_UUID="u1"; RLY_SNI="s1.example.com"; RLY_PUBLIC_KEY="p1"; RLY_SHORT_ID="sid1"; RLY_FLOW="xtls-rprx-vision"; RLY_FINGERPRINT="firefox"
reality_relay_write_route 41001
ck "RLY_FINGERPRINT 落盘到路由文件" 'grep -q "RLY_FINGERPRINT=\"firefox\"" "$REALITY_RELAY_DIR/relay-41001.conf"'
RLY_FINGERPRINT=""
reality_relay_load_route "$REALITY_RELAY_DIR/relay-41001.conf"
ck "路由回读 RLY_FINGERPRINT" '[[ "$RLY_FINGERPRINT" == "firefox" ]]'
reality_relay_write_client_artifacts
ck "中转客户端链接用 RLY_FINGERPRINT(firefox)" 'grep -q "fp=firefox" "$REALITY_RELAY_DIR/relay-41001.link.txt"'
ck "中转客户端 JSON 用 RLY_FINGERPRINT(firefox)" 'grep -q "\"fingerprint\":\"firefox\"" "$REALITY_RELAY_DIR/relay-41001.client.json"'

echo "[T7] MED-4 统一保留端口集合：relay 监听端口即使 realm 停止也不被复用"
# 清空 relays，写两条已知监听端口的路由；不依赖运行时 ss（command_exists→false 使 reality_port_in_use 恒 false）
rm -rf "$REALITY_RELAY_DIR"; mkdir -p "$REALITY_RELAY_DIR"
RLY_NAME="rA"; RLY_LISTEN_PORT="45001"; RLY_CONNECT_HOST="h.example.com"
RLY_TARGET_HOST="t.example.com"; RLY_TARGET_PORT="443"
RLY_UUID="uA"; RLY_SNI="sA.example.com"; RLY_PUBLIC_KEY="pA"; RLY_SHORT_ID="sidA"; RLY_FLOW="xtls-rprx-vision"; RLY_FINGERPRINT="chrome"
reality_relay_write_route 45001
RLY_LISTEN_PORT="45002"; RLY_UUID="uB"; RLY_SNI="sB.example.com"; RLY_PUBLIC_KEY="pB"; RLY_SHORT_ID="sidB"
reality_relay_write_route 45002
# 落地/共存/CDN 也各占一个逻辑端口
REALITY_PORT="443"; REALITY_CDN_ORIGIN_PORT="8443"; REALITY_CDN_INNER_PORT="47777"
ck "reserved 含 relay 监听 45001" 'reality_reserved_ports | grep -qx 45001'
ck "reserved 含 relay 监听 45002" 'reality_reserved_ports | grep -qx 45002'
ck "reserved 含落地 443" 'reality_reserved_ports | grep -qx 443'
ck "reserved 含 CDN origin 8443" 'reality_reserved_ports | grep -qx 8443'
ck "reserved 含 CDN inner 47777" 'reality_reserved_ports | grep -qx 47777'
ck "reserved 含共存默认内部端口 18443" 'reality_reserved_ports | grep -qx 18443'
ck "reserved 含 web 默认内部端口 12443" 'reality_reserved_ports | grep -qx 12443'
ck "port_reserved 命中 relay 端口(realm 停止仍算占用)" 'reality_port_reserved 45001'
ck "port_reserved 未命中随机空闲端口" '! reality_port_reserved 39511'
ck "port_reserved exclude 自身可排除" '! reality_port_reserved 45001 45001'
# 读 RLY_LISTEN_PORT 用 grep 而非 source：不得污染当前 RLY_* 全局
RLY_LISTEN_PORT="OWNER_MARKER"
reality_reserved_ports >/dev/null
ck "reserved_ports 不污染 RLY_LISTEN_PORT 全局" '[[ "$RLY_LISTEN_PORT" == "OWNER_MARKER" ]]'
prompt_port="$(printf '2\n45001\n2\n39511\n' | reality_prompt_port "Reality 监听" 2>/dev/null)"
ck "prompt_port 拒绝已保留 relay 端口并继续读取" '[[ "$prompt_port" == "39511" ]]'
REALITY_PORT="39511"; REALITY_PORT_V6=""
ck "except_current_landing 允许复用当前落地端口" '! reality_port_reserved_except_current_landing 39511'
REALITY_CDN_INNER_PORT="39511"
ck "except_current_landing 仍拦截同号的其他保留来源" 'reality_port_reserved_except_current_landing 39511'
REALITY_CDN_INNER_PORT="47777"
install_reserved_rc=0
reality_install_relay "relay.example.com" 47777 "land.example.com" 443 "" "reserved" >/dev/null 2>&1 || install_reserved_rc=$?
ck "install_relay 拒绝 CDN inner 已保留端口" '[[ "$install_reserved_rc" -ne 0 && ! -f "$REALITY_RELAY_DIR/relay-47777.conf" ]]'

echo "[T8] LOW-1 realm 0 端点守卫：全部路由文件无效时不得拿空配置重启"
rm -rf "$REALITY_RELAY_DIR"; mkdir -p "$REALITY_RELAY_DIR"
# 写一条“存在但无效”的路由文件：validate_conf_file 此测试恒真，但缺 RLY_TARGET_* → 渲染时被 continue
printf 'RLY_NAME="x"\nRLY_LISTEN_PORT="46001"\nRLY_CONNECT_HOST="h.example.com"\nRLY_TARGET_HOST=""\nRLY_TARGET_PORT=""\nRLY_UUID="u"\nRLY_SNI="s.example.com"\nRLY_PUBLIC_KEY="p"\nRLY_SHORT_ID="sid"\nRLY_FLOW="xtls-rprx-vision"\n' > "$REALITY_RELAY_DIR/relay-46001.conf"
# 预置一份“上一版好配置”，验证 0 端点时它被保留（不被空配置覆盖）
printf 'log.level = "warn"\n\n[[endpoints]]\nlisten = "0.0.0.0:99999"\nremote = "old.good:443"\n' > "$REALITY_REALM_CONFIG"
reality_relay_regenerate; rc_zero=$?
ck "0 有效端点 → regenerate 返回失败(非0)" '[[ "$rc_zero" -ne 0 ]]'
ck "0 有效端点 → 旧 realm 配置被保留(未被空配置覆盖)" 'grep -q "old.good:443" "$REALITY_REALM_CONFIG"'
# 反证：加入一条有效路由后 regenerate 成功且配置更新
RLY_NAME="ok"; RLY_LISTEN_PORT="46002"; RLY_CONNECT_HOST="h.example.com"
RLY_TARGET_HOST="good.land.com"; RLY_TARGET_PORT="443"
RLY_UUID="u2"; RLY_SNI="s2.example.com"; RLY_PUBLIC_KEY="p2"; RLY_SHORT_ID="sid2"; RLY_FLOW="xtls-rprx-vision"; RLY_FINGERPRINT="chrome"
reality_relay_write_route 46002
reality_relay_regenerate; rc_ok=$?
ck "含 1 有效端点 → regenerate 成功(0)" '[[ "$rc_ok" -eq 0 ]]'
ck "有效端点写入新配置" 'grep -q "remote = \"good.land.com:443\"" "$REALITY_REALM_CONFIG"'

echo ""
echo "==== reality_multi_relay_test: PASS=$pass FAIL=$fail ===="
[[ $fail -eq 0 ]] && echo "reality_multi_relay_test: PASS" || { echo "reality_multi_relay_test: FAIL"; exit 1; }
