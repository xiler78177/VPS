# modules/15-singbox-reality.sh - Sing-box VLESS REALITY / Realm 中转

# Source SNI 测速增强模块（纯交互式）
REALITY_MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REALITY_ENHANCEMENT_MODULE="${REALITY_MODULE_DIR}/enhancements/reality-sni-speedtest-interactive.sh"
if [[ -f "$REALITY_ENHANCEMENT_MODULE" ]]; then
    source "$REALITY_ENHANCEMENT_MODULE"
    # reality_prompt_sni() 会被增强模块自动替换
fi

REALITY_CANDIDATE_SNI=(
    "c.6sc.co"
    "j.6sc.co"
    "b.6sc.co"
    "ipv6.6sc.co"
    "rum.hlx.page"
    "c.marsflag.com"
    "snap.licdn.com"
    "s.go-mpulse.net"
    "tags.tiqcdn.com"
    "cdn.bizibly.com"
    "cdn.bizible.com"
    "ocsp2.apple.com"
    "s0.awsstatic.com"
    "a0.awsstatic.com"
    "apps.mzstatic.com"
    "sisu.xboxlive.com"
    "s.mp.marsflag.com"
    "c.s-microsoft.com"
    "statici.icloud.com"
    "beacon.gtv-pub.com"
    "ts1.tc.mm.bing.net"
    "ts2.tc.mm.bing.net"
    "ts3.tc.mm.bing.net"
    "ts4.tc.mm.bing.net"
    "ce.mf.marsflag.com"
    "d0.m.awsstatic.com"
    "t0.m.awsstatic.com"
    "tag.demandbase.com"
    "assets-www.xbox.com"
    "assets-xbxweb.xbox.com"
    "logx.optimizely.com"
    "aadcdn.msftauth.net"
    "acctcdn.msftauth.net"
    "d.oracleinfinity.io"
    "assets.adobedtm.com"
    "lpcdn.lpsnmedia.net"
    "res-1.cdn.office.net"
    "is1-ssl.mzstatic.com"
    "intelcorp.scene7.com"
    "cdnssl.clicktale.net"
    "catalog.gamepass.com"
    "consent.trustarc.com"
    "gsp-ssl.ls.apple.com"
    "munchkin.marketo.net"
    "cdn77.api.userway.org"
    "cua-chat-ui.tesla.com"
    "ds-aksb-a.akamaihd.net"
    "static.cloud.coveo.com"
    "devblogs.microsoft.com"
    "s7mbrstream.scene7.com"
    "fpinit.itunes.apple.com"
    "digitalassets.tesla.com"
    "d.impactradius-event.com"
    "downloadmirror.intel.com"
    "iosapps.itunes.apple.com"
    "se-edge.itunes.apple.com"
    "publisher.liveperson.net"
    "tag-logger.demandbase.com"
    "services.digitaleast.mobi"
    "configuration.ls.apple.com"
    "gray-wowt-prod.gtv-cdn.com"
    "visualstudio.microsoft.com"
    "amp-api-edge.apps.apple.com"
    "store-images.s-microsoft.com"
    "github.gallerycdn.vsassets.io"
    "vscjava.gallerycdn.vsassets.io"
    "ms-vscode.gallerycdn.vsassets.io"
    "ms-python.gallerycdn.vsassets.io"
    "gray-config-prod.api.arc-cdn.net"
    "gray.video-player.arcpublishing.com"
    "i7158c100-ds-aksb-a.akamaihd.net"
    "downloaddispatch.itunes.apple.com"
    "img-prod-cms-rt-microsoft-com.akamaized.net"
)

reality_urlencode() {
    local s="$1" out="" i c
    for ((i=0; i<${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            ' ') out+="%20" ;;
            *) printf -v c '%%%02X' "'${c}"; out+="$c" ;;
        esac
    done
    printf '%s' "$out"
}

reality_json_escape() {
    local s="$1"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    printf '%s' "$s"
}

reality_port_in_use() {
    local port="$1"
    if command_exists ss; then
        ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$" && return 0
    elif command_exists netstat; then
        netstat -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${port}$" && return 0
    elif command_exists lsof; then
        lsof -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1 && return 0
    fi
    return 1
}

reality_random_port() {
    local min="${REALITY_PORT_MIN:-20000}" max="${REALITY_PORT_MAX:-60000}" port try
    if [[ -n "${REALITY_TEST_PORT_CANDIDATES:-}" ]]; then
        for port in $REALITY_TEST_PORT_CANDIDATES; do
            [[ "$port" =~ ^[0-9]+$ ]] || continue
            [[ "$port" -ge "$min" && "$port" -le "$max" ]] || continue
            reality_port_in_use "$port" || { echo "$port"; return 0; }
        done
    fi
    for try in $(seq 1 200); do
        if command_exists shuf; then
            port=$(shuf -i "${min}-${max}" -n 1)
        else
            port=$(( RANDOM % (max - min + 1) + min ))
        fi
        reality_port_in_use "$port" || { echo "$port"; return 0; }
    done
    return 1
}

reality_generate_short_id() {
    if command_exists openssl; then
        openssl rand -hex 8
    else
        tr -dc '0-9a-f' < /dev/urandom | head -c 16
        echo
    fi
}

reality_generate_uuid() {
    if command_exists sing-box; then
        sing-box generate uuid 2>/dev/null && return 0
    fi
    [[ -r /proc/sys/kernel/random/uuid ]] && { cat /proc/sys/kernel/random/uuid; return 0; }
    command_exists uuidgen && { uuidgen | tr 'A-Z' 'a-z'; return 0; }
    return 1
}

reality_generate_keypair() {
    local out private public
    out=$(sing-box generate reality-keypair 2>/dev/null) || return 1
    private=$(awk -F': *' '/PrivateKey|Private key|private_key/{print $2; exit}' <<< "$out")
    public=$(awk -F': *' '/PublicKey|Public key|public_key/{print $2; exit}' <<< "$out")
    if [[ -z "$private" || -z "$public" ]]; then
        private=$(sed -n '1p' <<< "$out" | awk '{print $NF}')
        public=$(sed -n '2p' <<< "$out" | awk '{print $NF}')
    fi
    [[ -n "$private" && -n "$public" ]] || return 1
    printf '%s\n%s\n' "$private" "$public"
}

reality_render_singbox_config() {
    local uuid="$1" private_key="$2" port="$3" sni="$4" short_id="$5"
    uuid=$(reality_json_escape "$uuid")
    private_key=$(reality_json_escape "$private_key")
    sni=$(reality_json_escape "$sni")
    short_id=$(reality_json_escape "$short_id")
    cat <<EOF
{"log":{"disabled":true},"inbounds":[{"type":"vless","tag":"vless-reality-in","listen":"0.0.0.0","listen_port":${port},"users":[{"name":"main","uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"],"max_time_difference":"1m"}}}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
EOF
}

reality_build_vless_link() {
    local uuid="$1" node="$2" port="$3" sni="$4" public_key="$5" short_id="$6" name="${7:-singbox-reality}"
    local encoded_name
    encoded_name=$(reality_urlencode "$name")
    printf 'vless://%s@%s:%s?encryption=none&security=reality&sni=%s&fp=chrome&pbk=%s&sid=%s&type=tcp&flow=xtls-rprx-vision#%s\n' \
        "$uuid" "$node" "$port" "$sni" "$public_key" "$short_id" "$encoded_name"
}

reality_parse_vless_link() {
    local link="$1" body user hostport query param key value
    [[ "$link" == vless://* ]] || return 1
    body="${link#vless://}"
    user="${body%@*}"
    body="${body#*@}"
    hostport="${body%%\?*}"
    query="${body#*\?}"
    query="${query%%#*}"
    REALITY_UUID="$user"
    REALITY_NODE_DOMAIN="${hostport%:*}"
    REALITY_PORT="${hostport##*:}"
    while IFS= read -r param; do
        key="${param%%=*}"
        value="${param#*=}"
        case "$key" in
            sni|serverName) REALITY_SNI="$value" ;;
            pbk|publicKey) REALITY_PUBLIC_KEY="$value" ;;
            sid|shortId) REALITY_SHORT_ID="$value" ;;
            flow) REALITY_FLOW="$value" ;;
        esac
    done < <(tr '&' '\n' <<< "$query")
    [[ -n "${REALITY_UUID:-}" && -n "${REALITY_SNI:-}" && -n "${REALITY_PUBLIC_KEY:-}" && -n "${REALITY_SHORT_ID:-}" ]]
}

reality_cf_dns_payload() {
    local type="$1" name="$2" content="$3"
    type=$(reality_json_escape "$type")
    name=$(reality_json_escape "$name")
    content=$(reality_json_escape "$content")
    printf '{"type":"%s","name":"%s","content":"%s","ttl":1,"proxied":false}\n' "$type" "$name" "$content"
}

reality_render_realm_config() {
    local listen_port="$1" target_host="$2" target_port="$3"
    cat <<EOF
log.level = "warn"

[[endpoints]]
listen = "0.0.0.0:${listen_port}"
remote = "${target_host}:${target_port}"
EOF
}

reality_resolve_public_a() {
    local domain="$1" resp ip
    command_exists curl || return 1
    resp=$(curl -fsS --max-time 8 -H 'accept: application/dns-json' \
        "https://cloudflare-dns.com/dns-query?name=${domain}&type=A" 2>/dev/null) || return 1
    if command_exists _extract_ipv4_from_text; then
        ip=$(_extract_ipv4_from_text "$resp") || return 1
    else
        ip=$(printf '%s' "$resp" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)
        [[ -n "$ip" ]] || return 1
    fi
    printf '%s\n' "$ip"
}

reality_local_client_self_test() {
    reality_load_state || return 1
    command_exists sing-box || { print_warn "sing-box 不存在，跳过本机协议自测"; return 1; }
    command_exists curl || { print_warn "curl 不存在，跳过本机协议自测"; return 1; }
    local test_port="${REALITY_SELFTEST_PORT:-19090}" cfg log pid i
    cfg=$(mktemp /tmp/reality-client-test.XXXXXX.json) || return 1
    log=$(mktemp /tmp/reality-client-test.XXXXXX.log) || { rm -f "$cfg"; return 1; }
    chmod 600 "$cfg" "$log" 2>/dev/null || true
    cat > "$cfg" <<EOF
{"log":{"level":"info","timestamp":true},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":${test_port}}],"outbounds":[{"type":"vless","tag":"self-test","server":"127.0.0.1","server_port":${REALITY_PORT},"uuid":"${REALITY_UUID}","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"${REALITY_SNI}","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"${REALITY_PUBLIC_KEY}","short_id":"${REALITY_SHORT_ID}"}}}],"route":{"final":"self-test"}}
EOF
    ( sing-box run -c "$cfg" > "$log" 2>&1 & echo $! > "${cfg}.pid" )
    pid=$(cat "${cfg}.pid" 2>/dev/null || true)
    for i in $(seq 1 30); do
        ss -ltn 2>/dev/null | grep -q ":${test_port} " && break
        sleep 0.2
    done
    if curl -x "socks5h://127.0.0.1:${test_port}" -fsS --max-time 15 https://www.cloudflare.com/cdn-cgi/trace >/tmp/reality-selftest-curl.log 2>&1; then
        print_success "本机协议自测通过: sing-box client -> 127.0.0.1:${REALITY_PORT} -> 外网"
        rm -f "$cfg" "$log" "${cfg}.pid" /tmp/reality-selftest-curl.log
        [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
        return 0
    fi
    print_warn "本机协议自测失败，最近日志:"
    tail -n 20 /tmp/reality-selftest-curl.log 2>/dev/null || true
    sed -E 's/[0-9a-fA-F-]{36}/<uuid>/g' "$log" 2>/dev/null | tail -n 20 || true
    [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
    rm -f "$cfg" "$log" "${cfg}.pid" /tmp/reality-selftest-curl.log
    return 1
}

reality_require_supported_os() {
    [[ "$PLATFORM" != "openwrt" ]] || { print_error "Reality 节点模块暂不支持 OpenWrt"; return 1; }
    is_systemd || { print_error "Reality 节点模块需要 systemd"; return 1; }
    local os_id="" ver=""
    if [[ -f /etc/os-release ]]; then
        os_id=$(grep '^ID=' /etc/os-release | head -1 | cut -d= -f2- | tr -d '"')
        ver=$(grep '^VERSION_ID=' /etc/os-release | head -1 | cut -d= -f2- | tr -d '"')
    fi
    case "$os_id:$ver" in
        debian:12|debian:13|ubuntu:20.04|ubuntu:22.04|ubuntu:24.04) ;;
        *) print_warn "未在支持列表中的系统: ${os_id:-unknown} ${ver:-unknown}，将尝试继续" ;;
    esac
    case "$(uname -m)" in
        x86_64|amd64|aarch64|arm64) return 0 ;;
        *) print_error "仅支持 amd64/arm64 架构"; return 1 ;;
    esac
}

reality_install_singbox_official() {
    reality_require_supported_os || return 1
    install_package "curl" "silent" || return 1
    install_package "ca-certificates" "silent" || return 1
    install_package "gnupg" "silent" || return 1
    install_package "openssl" "silent" || return 1
    install_package "jq" "silent" || true
    if ! command_exists sing-box; then
        print_info "添加 sing-box 官方 APT 源..."
        mkdir -p /etc/apt/keyrings
        curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc || return 1
        chmod a+r /etc/apt/keyrings/sagernet.asc
        cat > /etc/apt/sources.list.d/sagernet.sources <<'EOF'
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
EOF
        APT_UPDATED=0
        update_apt_cache
        DEBIAN_FRONTEND=noninteractive apt-get install -y sing-box >/dev/null || return 1
    fi
    command_exists sing-box || { print_error "sing-box 安装失败"; return 1; }
}

reality_verify_sni() {
    local domain="$1"
    validate_domain "$domain" || return 1
    command_exists openssl || install_package "openssl" "silent" || return 1
    local timeout_cmd=""
    command_exists timeout && timeout_cmd="timeout 12"
    $timeout_cmd openssl s_client -connect "${domain}:443" -servername "$domain" -verify_hostname "$domain" -brief </dev/null >/tmp/reality-sni-check.log 2>&1
}

reality_pick_sni_candidates() {
    local count="${1:-12}"
    if command_exists shuf; then
        printf '%s\n' "${REALITY_CANDIDATE_SNI[@]}" | shuf | head -n "$count"
    else
        printf '%s\n' "${REALITY_CANDIDATE_SNI[@]}" | awk 'BEGIN{srand()} {print rand() "\t" $0}' | sort -n | cut -f2- | head -n "$count"
    fi
}

reality_prompt_sni_legacy() {
    local choice sni i shown=()
    while true; do
        mapfile -t shown < <(reality_pick_sni_candidates 12)
        echo -e "${C_CYAN}REALITY SNI/handshake 目标:${C_RESET}" >&2
        echo "  这个域名不是你的节点连接域名，而是 REALITY 握手时模拟访问的 HTTPS 成品网站或自建网站。" >&2
        echo "  下面随机提供一批较小众的成品网站候选；脚本会对所选域名进行校验 TLS/SAN 和 443 连通性测试。" >&2
        echo "  请选择一个 SNI 候选编号，或输入 c 自定义 SNI；这里不是节点连接域名。" >&2
        echo "  如果你使用自建网站，请确保它是正常 HTTPS 站点，且不要填写 Cloudflare 灰云节点域名本身。" >&2
        i=1
        for sni in "${shown[@]}"; do echo "  ${i}. ${sni}" >&2; ((i++)); done
        echo "  r. 换一批候选域名" >&2
        echo "  c. 自定义域名" >&2
        read -e -r -p "请选择一个 SNI 候选编号，或输入 c 自定义 [c]: " choice
        choice=${choice:-c}
        if [[ "${choice,,}" == "r" ]]; then
            continue
        elif [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#shown[@]} ]]; then
            sni="${shown[$((choice-1))]}"
        elif [[ "${choice,,}" == "c" ]]; then
            read -e -r -p "SNI 域名: " sni
        else
            sni="$choice"
        fi
        validate_domain "$sni" || { print_error "域名格式无效" >&2; continue; }
        print_info "校验 TLS/SAN: $sni" >&2
        if reality_verify_sni "$sni"; then
            print_success "SNI 校验通过: $sni" >&2
            echo "$sni"; return 0
        fi
        print_warn "SNI 校验未通过或网络不可达: $sni" >&2
        tail -n 3 /tmp/reality-sni-check.log >&2 2>/dev/null || true
        confirm "仍然使用该 SNI?" && { echo "$sni"; return 0; }
    done
}

if ! declare -F reality_prompt_sni >/dev/null; then
    reality_prompt_sni() {
        reality_prompt_sni_legacy "$@"
    }
fi

reality_backup_file() {
    local file="$1"
    [[ -f "$file" ]] || return 0
    mkdir -p "$REALITY_BACKUP_DIR"
    cp -a "$file" "$REALITY_BACKUP_DIR/$(basename "$file").$(date +%Y%m%d-%H%M%S).bak"
}

reality_state_quote() {
    local s="${1:-}"
    s=${s//$'\r'/ }
    s=${s//$'\n'/ }
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//\$/\\\$}
    s=${s//\`/\\\`}
    printf '"%s"' "$s"
}

reality_write_state() {
    mkdir -p "$REALITY_CONFIG_DIR"
    cat > "$REALITY_STATE_FILE" <<EOF
REALITY_ROLE=$(reality_state_quote "${REALITY_ROLE:-}")
REALITY_NODE_NAME=$(reality_state_quote "${REALITY_NODE_NAME:-}")
REALITY_NODE_DOMAIN=$(reality_state_quote "${REALITY_NODE_DOMAIN:-}")
REALITY_SNI=$(reality_state_quote "${REALITY_SNI:-}")
REALITY_PORT=$(reality_state_quote "${REALITY_PORT:-}")
REALITY_UUID=$(reality_state_quote "${REALITY_UUID:-}")
REALITY_PRIVATE_KEY=$(reality_state_quote "${REALITY_PRIVATE_KEY:-}")
REALITY_PUBLIC_KEY=$(reality_state_quote "${REALITY_PUBLIC_KEY:-}")
REALITY_SHORT_ID=$(reality_state_quote "${REALITY_SHORT_ID:-}")
REALITY_RELAY_DOMAIN=$(reality_state_quote "${REALITY_RELAY_DOMAIN:-}")
REALITY_RELAY_PORT=$(reality_state_quote "${REALITY_RELAY_PORT:-}")
REALITY_RELAY_TARGET_HOST=$(reality_state_quote "${REALITY_RELAY_TARGET_HOST:-}")
REALITY_RELAY_TARGET_PORT=$(reality_state_quote "${REALITY_RELAY_TARGET_PORT:-}")
EOF
    chmod 600 "$REALITY_STATE_FILE"
}

reality_load_state() {
    [[ -f "$REALITY_STATE_FILE" ]] || return 1
    validate_conf_file "$REALITY_STATE_FILE" || return 1
    source "$REALITY_STATE_FILE"
}

reality_validate_node_name() {
    local name="$1"
    [[ -n "$name" && ${#name} -le 64 ]] || return 1
    [[ "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._[:space:]-]{0,63}$ ]]
}

reality_default_node_name() {
    local host="${REALITY_RELAY_DOMAIN:-${REALITY_NODE_DOMAIN:-singbox}}"
    host="${host%%.*}"
    [[ -n "$host" ]] || host="singbox"
    printf '%s-reality' "$host"
}

reality_effective_node_name() {
    if [[ -n "${REALITY_NODE_NAME:-}" ]]; then
        printf '%s' "$REALITY_NODE_NAME"
    else
        reality_default_node_name
    fi
}

reality_prompt_node_name() {
    local default_name="${1:-}" name=""
    [[ -n "$default_name" ]] || default_name="$(reality_default_node_name)"
    echo -e "${C_CYAN}节点名称/备注说明:${C_RESET}" >&2
    echo "  这个名称只用于本机状态展示、vless:// 链接 #备注、sing-box 客户端 tag，方便区分几十台 VPS。" >&2
    echo "  不影响 Reality 协议参数，不会写入 Cloudflare DNS。" >&2
    echo "  建议使用英文/数字/短横线，示例: us-nat-01、jp-relay-02。" >&2
    while true; do
        read -e -r -p "节点名称/备注 [${default_name}]: " name
        name="${name:-$default_name}"
        if reality_validate_node_name "$name"; then
            printf '%s' "$name"
            return 0
        fi
        print_error "节点名称无效：请使用 1-64 位英文、数字、空格、点、下划线或短横线" >&2
    done
}

reality_write_client_artifacts() {
    local link_host="${REALITY_RELAY_DOMAIN:-$REALITY_NODE_DOMAIN}" link_port="${REALITY_RELAY_PORT:-$REALITY_PORT}" name
    [[ -n "$link_host" && -n "$link_port" ]] || return 1
    name="$(reality_effective_node_name)"
    local json_name
    json_name=$(reality_json_escape "$name")
    mkdir -p "$REALITY_CONFIG_DIR"
    reality_build_vless_link "$REALITY_UUID" "$link_host" "$link_port" "$REALITY_SNI" "$REALITY_PUBLIC_KEY" "$REALITY_SHORT_ID" "$name" > "$REALITY_LINK_FILE"
    cat > "$REALITY_CLIENT_JSON" <<EOF
{"type":"vless","tag":"${json_name}","server":"${link_host}","server_port":${link_port},"uuid":"${REALITY_UUID}","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"${REALITY_SNI}","utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":"${REALITY_PUBLIC_KEY}","short_id":"${REALITY_SHORT_ID}"}}}
EOF
    chmod 600 "$REALITY_LINK_FILE" "$REALITY_CLIENT_JSON"
}

reality_detect_ips() {
    REALITY_IPV4="$(get_public_ipv4 2>/dev/null || true)"
    REALITY_IPV6="$(get_public_ipv6 2>/dev/null || true)"
    [[ -n "$REALITY_IPV6" && "$REALITY_IPV6" != *:* ]] && REALITY_IPV6=""
}

reality_sync_cloudflare_dns() {
    local domain="$1" token="$2"
    [[ -z "$domain" || -z "$token" ]] && return 1
    reality_detect_ips
    [[ -n "$REALITY_IPV4" || -n "$REALITY_IPV6" ]] || { print_error "未检测到公网 IP"; return 1; }
    cf_dns_sync_node_grey "$token" "$domain" "$REALITY_IPV4" "$REALITY_IPV6" "true" "5"
}

reality_cf_zone_names_from_json() {
    local json="$1"
    if command_exists jq; then
        jq -r '.result[].name // empty' <<< "$json"
    else
        grep -oE '"name"[[:space:]]*:[[:space:]]*"[^"]+"' <<< "$json" | sed -E 's/.*"name"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'
    fi
}

reality_cf_list_zones() {
    local token="$1" resp
    [[ -z "$token" ]] && return 1
    resp=$(_cf_api GET "/zones?per_page=50" "$token") || return 1
    _cf_api_ok "$resp" || return 1
    reality_cf_zone_names_from_json "$resp"
}

reality_join_subdomain() {
    local prefix="$1" zone="$2"
    prefix="${prefix#.}"
    prefix="${prefix%.}"
    if [[ "$prefix" == *.* ]]; then
        printf '%s\n' "$prefix"
    else
        printf '%s.%s\n' "$prefix" "$zone"
    fi
}

reality_prompt_domain_with_zones() {
    local purpose="$1" token="$2" zone="" prefix="" zones=() i choice domain
    if [[ -n "$token" ]]; then
        mapfile -t zones < <(reality_cf_list_zones "$token" 2>/dev/null || true)
    fi
    if [[ ${#zones[@]} -gt 0 ]]; then
        echo -e "${C_CYAN}${purpose}域名后缀:${C_RESET}" >&2
        echo "  已通过 Cloudflare API Token 获取到你的域名后缀，请选择一个 zone。" >&2
        i=1
        for zone in "${zones[@]}"; do echo "  ${i}. ${zone}" >&2; ((i++)); done
        while true; do
            read -e -r -p "请选择域名后缀 [1]: " choice
            choice=${choice:-1}
            [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#zones[@]} ]] && { zone="${zones[$((choice-1))]}"; break; }
            print_error "无效选择" >&2
        done
        while true; do
            echo "  只需要填写自定义前缀，脚本会拼接为完整域名并自动创建/更新 Cloudflare 灰云 DNS。" >&2
            read -e -r -p "${purpose}自定义前缀 [$(hostname)-reality]: " prefix
            prefix=${prefix:-$(hostname)-reality}
            domain=$(reality_join_subdomain "$prefix" "$zone")
            validate_domain "$domain" && { echo "$domain"; return 0; }
            print_error "域名前缀无效" >&2
        done
    fi
    while true; do
        read -e -r -p "${purpose}完整域名(Cloudflare 灰云): " domain
        validate_domain "$domain" && { echo "$domain"; return 0; }
        print_error "域名无效" >&2
    done
}

reality_prompt_cf_token() {
    local token=""
    echo -e "${C_CYAN}Cloudflare 自动 DNS 说明:${C_RESET}" >&2
    echo "  本脚本会使用 Cloudflare API Token 自动创建/更新节点域名 DNS，并强制设置为 DNS only / 灰云。" >&2
    echo "  如果 Token 能读取 zone，后续只需要选择域名后缀并填写自定义前缀。" >&2
    echo "  这不是让你手动去 Cloudflare 添加记录；脚本会自动 upsert A/AAAA 并配置 DDNS。" >&2
    echo "  Token 建议使用最小权限: Zone:Read + DNS:Edit。Token 仅用于本机 DNS/DDNS 配置。" >&2
    read -s -r -p "Cloudflare API Token (留空则跳过自动 DNS/DDNS): " token
    echo "" >&2
    printf '%s' "$token"
}

reality_install_landing() {
    local node_domain="$1" sni="$2" port="$3" cf_token="${4:-}" node_name="${5:-}"
    validate_domain "$node_domain" || { print_error "节点域名无效"; return 1; }
    validate_domain "$sni" || { print_error "SNI 域名无效"; return 1; }
    validate_port "$port" || { print_error "端口无效"; return 1; }
    [[ -z "$node_name" ]] || reality_validate_node_name "$node_name" || { print_error "节点名称无效"; return 1; }
    reality_install_singbox_official || return 1
    REALITY_UUID=$(reality_generate_uuid) || return 1
    local keys
    keys=$(reality_generate_keypair) || { print_error "生成 Reality keypair 失败"; return 1; }
    REALITY_PRIVATE_KEY=$(sed -n '1p' <<< "$keys")
    REALITY_PUBLIC_KEY=$(sed -n '2p' <<< "$keys")
    REALITY_SHORT_ID=$(reality_generate_short_id)
    REALITY_ROLE="landing"
    REALITY_NODE_NAME="$node_name"
    REALITY_NODE_DOMAIN="$node_domain"
    REALITY_SNI="$sni"
    REALITY_PORT="$port"
    reality_backup_file "$REALITY_SINGBOX_CONFIG"
    mkdir -p /etc/sing-box
    reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID" > "$REALITY_SINGBOX_CONFIG"
    chmod 600 "$REALITY_SINGBOX_CONFIG"
    sing-box check -c "$REALITY_SINGBOX_CONFIG" || return 1
    firewall_apply_reality_port "$REALITY_PORT" || return 1
    systemctl enable sing-box >/dev/null || return 1
    systemctl restart sing-box || return 1
    [[ -n "$cf_token" ]] && reality_sync_cloudflare_dns "$REALITY_NODE_DOMAIN" "$cf_token"
    reality_write_state
    reality_write_client_artifacts
    print_success "Sing-box Reality 落地机安装完成"
    reality_show_info
}

reality_realm_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) return 1 ;;
    esac
}

reality_install_realm_binary() {
    command_exists curl || install_package "curl" "silent" || return 1
    command_exists tar || install_package "tar" "silent" || true
    if command_exists realm; then return 0; fi
    local arch api url tmp
    arch=$(reality_realm_arch) || { print_error "Realm 不支持当前架构"; return 1; }
    api=$(curl -fsSL https://api.github.com/repos/zhboner/realm/releases/latest) || return 1
    url=$(grep -Eo 'https://[^" ]+' <<< "$api" | grep "$arch" | grep -E 'tar\.gz|tgz|gz' | head -n 1)
    [[ -n "$url" ]] || { print_error "未找到 Realm ${arch} 发布包"; return 1; }
    tmp=$(mktemp -d)
    curl -fsSL "$url" -o "$tmp/realm.tgz" || return 1
    tar -xzf "$tmp/realm.tgz" -C "$tmp" || return 1
    install -m 0755 "$(find "$tmp" -type f -name realm | head -n 1)" /usr/local/bin/realm || return 1
    rm -rf "$tmp"
}

reality_install_relay() {
    local relay_domain="$1" listen_port="$2" target_host="$3" target_port="$4" cf_token="${5:-}" node_name="${6:-}"
    validate_domain "$relay_domain" || { print_error "中转域名无效"; return 1; }
    validate_port "$listen_port" || { print_error "中转端口无效"; return 1; }
    validate_domain "$target_host" || validate_ip "$target_host" || { print_error "落地地址无效"; return 1; }
    validate_port "$target_port" || { print_error "落地端口无效"; return 1; }
    [[ -z "$node_name" ]] || reality_validate_node_name "$node_name" || { print_error "节点名称无效"; return 1; }
    reality_require_supported_os || return 1
    reality_install_realm_binary || return 1
    mkdir -p /etc/realm "$REALITY_CONFIG_DIR"
    reality_backup_file "$REALITY_REALM_CONFIG"
    reality_render_realm_config "$listen_port" "$target_host" "$target_port" > "$REALITY_REALM_CONFIG"
    chmod 600 "$REALITY_REALM_CONFIG"
    cat > /etc/systemd/system/realm.service <<'EOF'
[Unit]
Description=Realm TCP Relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/realm -c /etc/realm/config.toml
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    firewall_apply_realm_port "$listen_port" || return 1
    systemctl daemon-reload
    systemctl enable realm >/dev/null || return 1
    systemctl restart realm || return 1
    REALITY_ROLE="relay"
    REALITY_NODE_NAME="$node_name"
    REALITY_RELAY_DOMAIN="$relay_domain"
    REALITY_RELAY_PORT="$listen_port"
    REALITY_RELAY_TARGET_HOST="$target_host"
    REALITY_RELAY_TARGET_PORT="$target_port"
    if [[ -n "$cf_token" ]]; then reality_sync_cloudflare_dns "$REALITY_RELAY_DOMAIN" "$cf_token"; fi
    reality_write_state
    if [[ -n "${REALITY_UUID:-}" && -n "${REALITY_SNI:-}" && -n "${REALITY_PUBLIC_KEY:-}" && -n "${REALITY_SHORT_ID:-}" ]]; then
        reality_write_client_artifacts
    fi
    print_success "Realm 单跳中转安装完成"
    reality_show_info
}

reality_prompt_port() {
    local prompt="$1" port
    port=$(reality_random_port) || { print_error "无法生成可用随机端口"; return 1; }
    read -e -r -p "${prompt} [${port}]: " input_port
    input_port=${input_port:-$port}
    validate_port "$input_port" || { print_error "端口无效"; return 1; }
    echo "$input_port"
}

reality_install_wizard() {
    local role="" node="" sni="" port="" cf_token="" relay_domain="" relay_port="" target_host="" target_port="" landing_link="" node_name=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --landing) role="landing"; shift ;;
            --relay) role="relay"; shift ;;
            --both) role="both"; shift ;;
            --name|--node-name) node_name="$2"; shift 2 ;;
            --node) node="$2"; shift 2 ;;
            --sni) sni="$2"; shift 2 ;;
            --port) port="$2"; shift 2 ;;
            --cf-token) cf_token="$2"; shift 2 ;;
            --relay-domain) relay_domain="$2"; shift 2 ;;
            --relay-port) relay_port="$2"; shift 2 ;;
            --target-host) target_host="$2"; shift 2 ;;
            --target-port) target_port="$2"; shift 2 ;;
            --landing-link) landing_link="$2"; shift 2 ;;
            *) print_warn "忽略未知参数: $1"; shift ;;
        esac
    done
    print_title "Sing-box Reality 节点安装向导"
    if [[ -z "$role" ]]; then
        echo "1. 落地机 (sing-box VLESS REALITY)"
        echo "2. 中转机 (Realm TCP 单跳转发)"
        echo "3. 落地 + 本机中转"
        read -e -r -p "请选择 [1]: " role_choice
        case "${role_choice:-1}" in
            1) role="landing" ;; 2) role="relay" ;; 3) role="both" ;; *) print_error "无效选择"; return 1 ;;
        esac
    fi
    if [[ "$role" == "landing" || "$role" == "both" ]]; then
        if [[ -z "$cf_token" ]]; then
            cf_token=$(reality_prompt_cf_token)
        fi
        while [[ -z "$node" ]]; do
            echo -e "${C_CYAN}节点连接域名说明:${C_RESET}"
            echo "  这是客户端实际连接的节点域名，会写入 vless:// 链接的 @host 部分。"
            echo "  脚本会通过 Cloudflare API 自动创建/更新此域名到当前 VPS 公网 IP，并强制 Cloudflare 灰云。"
            echo "  这里不是让你手动去 Cloudflare 添加记录；如果 Token 能列出 zone，只需要填写自定义前缀。"
            echo "  示例: 选择 example.com 后输入 node-us-01，脚本会生成 node-us-01.example.com -> 当前 VPS 公网 IP"
            node=$(reality_prompt_domain_with_zones "节点连接" "$cf_token")
            validate_domain "$node" || { print_error "域名无效"; node=""; }
        done
        if [[ -z "$node_name" ]]; then
            REALITY_NODE_DOMAIN="$node"
            node_name=$(reality_prompt_node_name "$(reality_default_node_name)")
        fi
        [[ -z "$sni" ]] && sni=$(reality_prompt_sni)
        [[ -z "$port" ]] && port=$(reality_prompt_port "Reality 监听端口")
        reality_install_landing "$node" "$sni" "$port" "$cf_token" "$node_name" || return 1
    fi
    if [[ "$role" == "relay" || "$role" == "both" ]]; then
        if [[ -n "$landing_link" ]]; then
            reality_parse_vless_link "$landing_link" || { print_error "落地机 VLESS 链接解析失败"; return 1; }
            [[ -z "$target_host" ]] && target_host="$REALITY_NODE_DOMAIN"
            [[ -z "$target_port" ]] && target_port="$REALITY_PORT"
        elif [[ "$role" == "relay" ]] && confirm "是否导入落地机 VLESS 链接以生成中转客户端链接?"; then
            read -e -r -p "粘贴落地机 vless:// 链接: " landing_link
            reality_parse_vless_link "$landing_link" || { print_error "落地机 VLESS 链接解析失败"; return 1; }
            [[ -z "$target_host" ]] && target_host="$REALITY_NODE_DOMAIN"
            [[ -z "$target_port" ]] && target_port="$REALITY_PORT"
        fi
        if [[ -z "$cf_token" ]]; then
            cf_token=$(reality_prompt_cf_token)
        fi
        while [[ -z "$relay_domain" ]]; do
            echo -e "${C_CYAN}中转机连接域名说明:${C_RESET}"
            echo "  这是客户端实际连接的中转机域名，会替换客户端链接里的 @host。"
            echo "  脚本会通过 Cloudflare API 自动创建/更新此域名到当前中转机公网 IP，并强制 Cloudflare 灰云。"
            echo "  这里不是让你手动去 Cloudflare 添加记录；如果 Token 能列出 zone，只需要填写自定义前缀。"
            echo "  Realm 会把该端口的 TCP 流量转发到落地机 Reality 端口。"
            relay_domain=$(reality_prompt_domain_with_zones "中转机连接" "$cf_token")
            validate_domain "$relay_domain" || { print_error "域名无效"; relay_domain=""; }
        done
        if [[ -z "$node_name" ]]; then
            REALITY_RELAY_DOMAIN="$relay_domain"
            node_name=$(reality_prompt_node_name "$(reality_default_node_name)")
        fi
        [[ -z "$relay_port" ]] && relay_port=$(reality_prompt_port "Realm 中转监听端口")
        if [[ "$role" == "both" ]]; then
            target_host="127.0.0.1"; target_port="$port"
        else
            while [[ -z "$target_host" ]]; do read -e -r -p "落地机域名/IP: " target_host; validate_domain "$target_host" || validate_ip "$target_host" || { print_error "地址无效"; target_host=""; }; done
            while [[ -z "$target_port" ]]; do read -e -r -p "落地机 Reality 端口: " target_port; validate_port "$target_port" || { print_error "端口无效"; target_port=""; }; done
        fi
        reality_install_relay "$relay_domain" "$relay_port" "$target_host" "$target_port" "$cf_token" "$node_name" || return 1
        if reality_load_state && [[ -n "${REALITY_UUID:-}" ]]; then reality_write_client_artifacts; fi
    fi
}

reality_show_info() {
    print_title "Sing-box Reality 节点信息"
    reality_load_state || { print_warn "未发现 Reality 状态文件"; pause; return 0; }
    echo -e "角色: ${C_GREEN}${REALITY_ROLE:-未知}${C_RESET}"
    echo "节点名称: $(reality_effective_node_name)"
    [[ -n "${REALITY_NODE_DOMAIN:-}" ]] && echo "落地域名: $REALITY_NODE_DOMAIN"
    [[ -n "${REALITY_PORT:-}" ]] && echo "Reality端口: $REALITY_PORT"
    [[ -n "${REALITY_SNI:-}" ]] && echo "SNI: $REALITY_SNI"
    [[ -n "${REALITY_RELAY_DOMAIN:-}" ]] && echo "中转域名: $REALITY_RELAY_DOMAIN"
    [[ -n "${REALITY_RELAY_PORT:-}" ]] && echo "中转端口: $REALITY_RELAY_PORT"
    [[ -n "${REALITY_RELAY_TARGET_HOST:-}" ]] && echo "中转目标: ${REALITY_RELAY_TARGET_HOST}:${REALITY_RELAY_TARGET_PORT}"
    if [[ -f "$REALITY_LINK_FILE" ]]; then
        draw_line
        cat "$REALITY_LINK_FILE"
    fi
    pause
}

reality_status() {
    print_title "Reality 服务状态"
    command_exists systemctl || { print_warn "systemctl 不可用"; pause; return; }
    systemctl --no-pager --full status sing-box 2>/dev/null | sed -n '1,12p' || print_warn "sing-box 未运行"
    echo ""
    systemctl --no-pager --full status realm 2>/dev/null | sed -n '1,12p' || true
    pause
}

reality_diagnose() {
    print_title "Reality 诊断/自检"
    reality_load_state || { print_error "未发现状态文件: $REALITY_STATE_FILE"; pause; return 1; }

    local connect_domain="${REALITY_RELAY_DOMAIN:-$REALITY_NODE_DOMAIN}"
    local connect_port="${REALITY_RELAY_PORT:-$REALITY_PORT}"
    local public_ip="" dns_ip="" system_dns=""

    echo "节点角色: ${REALITY_ROLE:-unknown}"
    echo "客户端连接: ${connect_domain}:${connect_port}"
    echo "落地端口: ${REALITY_PORT:-unknown}"
    echo "REALITY SNI: ${REALITY_SNI:-unknown}"
    echo ""

    if command_exists sing-box; then
        sing-box version 2>/dev/null | head -n 1 || true
        if [[ -f "$REALITY_SINGBOX_CONFIG" ]]; then
            sing-box check -c "$REALITY_SINGBOX_CONFIG" >/dev/null 2>&1 \
                && print_success "sing-box 配置检查通过" \
                || print_error "sing-box 配置检查失败"
        fi
    else
        print_warn "sing-box 未安装"
    fi

    if command_exists systemctl; then
        systemctl is-active --quiet sing-box \
            && print_success "sing-box 服务 active" \
            || print_error "sing-box 服务未运行"
    fi

    if command_exists ss; then
        if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${REALITY_PORT}$"; then
            print_success "本机正在监听 Reality 端口: ${REALITY_PORT}/tcp"
        else
            print_error "本机未监听 Reality 端口: ${REALITY_PORT}/tcp"
        fi
    fi

    if command_exists ufw; then
        if ufw status 2>/dev/null | grep -q "${REALITY_PORT}/tcp"; then
            print_success "UFW 已放行 Reality 端口: ${REALITY_PORT}/tcp"
        else
            print_warn "UFW 状态中未看到 ${REALITY_PORT}/tcp 放行规则"
        fi
    fi

    public_ip=$(get_public_ipv4 2>/dev/null || true)
    [[ -n "$public_ip" ]] && echo "本机公网 IPv4: $public_ip" || print_warn "未能获取本机公网 IPv4"

    system_dns=$(getent ahostsv4 "$connect_domain" 2>/dev/null | awk '{print $1; exit}' || true)
    [[ -n "$system_dns" ]] && echo "系统 DNS 解析: ${connect_domain} -> ${system_dns}" || print_warn "系统 DNS 未解析到 IPv4"

    dns_ip=$(reality_resolve_public_a "$connect_domain" 2>/dev/null || true)
    [[ -n "$dns_ip" ]] && echo "Cloudflare DoH: ${connect_domain} -> ${dns_ip}" || print_warn "Cloudflare DoH 未解析到 IPv4"
    if [[ -n "$public_ip" && -n "$dns_ip" ]]; then
        [[ "$public_ip" == "$dns_ip" ]] \
            && print_success "DNS 公网解析与本机公网 IP 一致" \
            || print_warn "DNS 公网解析与本机公网 IP 不一致，可能是 DDNS 未同步或当前机器在 NAT/转发环境"
    fi

    if reality_verify_sni "$REALITY_SNI"; then
        print_success "SNI TLS/SAN 校验通过: $REALITY_SNI"
    else
        print_warn "SNI TLS/SAN 校验失败或当前网络不可达: $REALITY_SNI"
        tail -n 5 /tmp/reality-sni-check.log 2>/dev/null || true
    fi

    if [[ "${REALITY_ROLE:-}" == "landing" ]]; then
        reality_local_client_self_test || true
    fi

    echo ""
    print_info "外部连通性抓包诊断:"
    echo "  如果本机自测通过但客户端仍不通，通常是云厂商安全组/NAT/端口映射、客户端 DNS Fake-IP、或本地网络路由问题。"
    echo "  可在 VPS 上执行抓包，同时从客户端连接节点，看是否有包到达本机:"
    echo "    sudo timeout 30 tcpdump -nni any tcp port ${connect_port}"
    if command_exists tcpdump && [[ -t 0 ]] && confirm "现在启动 30 秒 tcpdump 抓包? 请同时在客户端发起连接"; then
        timeout 30 tcpdump -nni any "tcp port ${connect_port}" 2>/dev/null | sed -n '1,80p' || true
    elif command_exists tcpdump; then
        print_info "当前为非交互运行或已跳过抓包；需要时可手动执行上面的 tcpdump 命令"
    else
        print_warn "tcpdump 未安装；如需抓包可安装 tcpdump 后重试"
    fi
    pause
}

reality_restart() {
    systemctl restart sing-box 2>/dev/null || true
    systemctl restart realm 2>/dev/null || true
    print_success "已发送重启命令"
    pause
}

reality_rotate_user() {
    reality_load_state || { print_error "未安装落地机配置"; pause; return 1; }
    [[ -n "${REALITY_PRIVATE_KEY:-}" && -n "${REALITY_PORT:-}" ]] || { print_error "状态文件缺少落地机参数"; pause; return 1; }
    REALITY_UUID=$(reality_generate_uuid) || return 1
    reality_backup_file "$REALITY_SINGBOX_CONFIG"
    reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID" > "$REALITY_SINGBOX_CONFIG"
    sing-box check -c "$REALITY_SINGBOX_CONFIG" && systemctl restart sing-box
    reality_write_state; reality_write_client_artifacts
    print_success "UUID 已轮换"
    reality_show_info
}

reality_rotate_key() {
    reality_load_state || { print_error "未安装落地机配置"; pause; return 1; }
    local keys
    keys=$(reality_generate_keypair) || return 1
    REALITY_PRIVATE_KEY=$(sed -n '1p' <<< "$keys")
    REALITY_PUBLIC_KEY=$(sed -n '2p' <<< "$keys")
    REALITY_SHORT_ID=$(reality_generate_short_id)
    reality_backup_file "$REALITY_SINGBOX_CONFIG"
    reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID" > "$REALITY_SINGBOX_CONFIG"
    sing-box check -c "$REALITY_SINGBOX_CONFIG" && systemctl restart sing-box
    reality_write_state; reality_write_client_artifacts
    print_success "Reality Key/ShortID 已轮换"
    reality_show_info
}

reality_cf_sync_menu() {
    reality_load_state || { print_error "未发现状态文件"; pause; return 1; }
    local domain="${REALITY_RELAY_DOMAIN:-$REALITY_NODE_DOMAIN}" token=""
    [[ -n "$domain" ]] || { print_error "状态文件缺少域名"; pause; return 1; }
    read -s -r -p "Cloudflare API Token: " token; echo ""
    reality_sync_cloudflare_dns "$domain" "$token"
    pause
}

reality_update_node_name() {
    reality_load_state || { print_error "未发现状态文件"; pause; return 1; }
    local old_name new_name
    old_name="$(reality_effective_node_name)"
    new_name=$(reality_prompt_node_name "$old_name") || return 1
    REALITY_NODE_NAME="$new_name"
    reality_write_state
    if [[ -n "${REALITY_UUID:-}" && -n "${REALITY_SNI:-}" && -n "${REALITY_PUBLIC_KEY:-}" && -n "${REALITY_SHORT_ID:-}" ]]; then
        reality_write_client_artifacts || true
    fi
    print_success "节点名称已更新: $new_name"
    pause
}

reality_delete_node_info() {
    print_title "删除 Reality 节点信息"
    confirm "确认删除本机 Reality/Realm 管理信息? 不会卸载 sing-box 软件包" || return 0
    systemctl disable --now realm 2>/dev/null || true
    rm -f /etc/systemd/system/realm.service
    systemctl daemon-reload 2>/dev/null || true
    reality_backup_file "$REALITY_SINGBOX_CONFIG"
    rm -f "$REALITY_REALM_CONFIG"
    rm -rf "$REALITY_CONFIG_DIR"
    print_success "Reality/Realm 节点信息已删除"
    pause
}

reality_uninstall() {
    reality_delete_node_info
}

reality_info_menu() {
    fix_terminal
    while true; do
        print_title "查看/修改节点信息"
        echo "1. 查看节点信息"
        echo "2. 输出客户端链接"
        echo "3. 修改节点名称/备注"
        echo "4. 删除节点信息"
        echo "0. 返回"
        read -e -r -p "请选择: " c
        case "$c" in
            1) reality_show_info ;;
            2) reality_show_info ;;
            3) reality_update_node_name ;;
            4) reality_delete_node_info ;;
            0|q|Q) break ;;
            *) print_error "无效选项"; sleep 1 ;;
        esac
    done
}

reality_menu() {
    fix_terminal
    while true; do
        print_title "Sing-box Reality 节点"
        echo "1. 安装/重装落地机"
        echo "2. 安装/重装中转机"
        echo "3. 查看/修改节点信息"
        echo "4. 检查服务状态"
        echo "5. 重启服务"
        echo "6. 同步 Cloudflare DNS/DDNS"
        echo "7. 轮换 UUID"
        echo "8. 轮换 Reality Key"
        echo "9. 诊断/自检"
        echo "0. 返回"
        read -e -r -p "请选择: " c
        case "$c" in
            1) reality_install_wizard --landing ;;
            2) reality_install_wizard --relay ;;
            3) reality_info_menu ;;
            4) reality_status ;;
            5) reality_restart ;;
            6) reality_cf_sync_menu ;;
            7) reality_rotate_user ;;
            8) reality_rotate_key ;;
            9) reality_diagnose ;;
            0|q|Q) break ;;
            *) print_error "无效选项"; sleep 1 ;;
        esac
    done
}

reality_cli() {
    local cmd="${1:-install}"; shift || true
    case "$cmd" in
        install) reality_install_wizard "$@" ;;
        info|link) reality_show_info ;;
        status) reality_status ;;
        diagnose|check) reality_diagnose ;;
        restart) reality_restart ;;
        cf-sync) reality_cf_sync_menu ;;
        rotate-user) reality_rotate_user ;;
        rotate-key) reality_rotate_key ;;
        delete|uninstall) reality_delete_node_info ;;
        *) print_error "未知 Reality 命令: $cmd"; return 1 ;;
    esac
}
