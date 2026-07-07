# modules/15-singbox-reality.sh - Sing-box VLESS REALITY / Realm 中转

# BEGIN BUILD-OMIT reality-sni-runtime-source
# Source SNI 测速增强模块（纯交互式）
REALITY_MODULE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REALITY_ENHANCEMENT_MODULE="${REALITY_MODULE_DIR}/enhancements/reality-sni-speedtest-interactive.sh"
if [[ -f "$REALITY_ENHANCEMENT_MODULE" ]]; then
    source "$REALITY_ENHANCEMENT_MODULE"
    # reality_prompt_sni() 会被增强模块自动替换
fi
# END BUILD-OMIT reality-sni-runtime-source

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
    "s0.awsstatic.com"
    "a0.awsstatic.com"
    "sisu.xboxlive.com"
    "s.mp.marsflag.com"
    "c.s-microsoft.com"
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
    "intelcorp.scene7.com"
    "cdnssl.clicktale.net"
    "catalog.gamepass.com"
    "consent.trustarc.com"
    "munchkin.marketo.net"
    "cdn77.api.userway.org"
    "cua-chat-ui.tesla.com"
    "ds-aksb-a.akamaihd.net"
    "static.cloud.coveo.com"
    "devblogs.microsoft.com"
    "s7mbrstream.scene7.com"
    "digitalassets.tesla.com"
    "d.impactradius-event.com"
    "downloadmirror.intel.com"
    "publisher.liveperson.net"
    "tag-logger.demandbase.com"
    "services.digitaleast.mobi"
    "gray-wowt-prod.gtv-cdn.com"
    "visualstudio.microsoft.com"
    "store-images.s-microsoft.com"
    "github.gallerycdn.vsassets.io"
    "vscjava.gallerycdn.vsassets.io"
    "ms-vscode.gallerycdn.vsassets.io"
    "ms-python.gallerycdn.vsassets.io"
    "gray-config-prod.api.arc-cdn.net"
    "gray.video-player.arcpublishing.com"
    "i7158c100-ds-aksb-a.akamaihd.net"
    "img-prod-cms-rt-microsoft-com.akamaized.net"
)

reality_urlencode() {
    local s="$1" out="" i c
    local LC_ALL=C
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

reality_uri_host() {
    # vless:// URI 中 IPv6 literal 必须加 []，否则 host:port 无法可靠解析。
    local host="${1:-}"
    if [[ "$host" == \[*\] ]]; then
        printf '%s' "$host"
    elif [[ "$host" == *:* ]]; then
        printf '[%s]' "$host"
    else
        printf '%s' "$host"
    fi
}

reality_validate_ws_path() {
    local path="${1:-}"
    [[ "$path" == /* ]] || return 1
    [[ ${#path} -ge 2 && ${#path} -le 128 ]] || return 1
    # 仅允许对 nginx location / sing-box WS path 都安全的可见字符。
    [[ "$path" =~ ^/[A-Za-z0-9._~/-]+$ ]]
}

reality_mask_secret() {
    local s="${1:-}" n=${#1}
    if (( n <= 12 )); then printf '%s' "$s"; else printf '%s…%s' "${s:0:6}" "${s: -4}"; fi
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

# 有界等待某端口“释放”（不再有 LISTEN）。用于消除异步 reload 竞态：
# nginx reload 释放 443 是异步的（旧 worker 优雅退出需时间），若紧接着 restart
# sing-box 抢绑 443，旧 worker 仍占用 → bind 失败 → systemd 重试前中断约 10 秒。
# 默认最多等 ${2:-50} 次 × 0.1s ≈ 5s；到点即返回（不阻断流程，restart 仍会兜底重试）。
reality_wait_port_free() {
    local port="$1" tries="${2:-50}" i=0
    validate_port "$port" || return 0
    while (( i < tries )); do
        reality_port_in_use "$port" || return 0
        sleep 0.1
        i=$((i+1))
    done
    return 1
}

# MED-4：统一“已保留端口”集合。各 feature 选内部端口时，除运行时 ss 检查外还要查此集合，
# 避免某服务当前停止(端口空闲) → 其保留端口被另一 feature 选走 → 服务重启后 bind 冲突。
# 汇总：落地 REALITY_PORT(_V6)、共存内部端口(reality/web)、CDN origin、所有 relay 监听端口。
# 逐行输出端口号（可能含重复/空行，调用方用 grep -qx 精确匹配即可）。
reality_reserved_ports() {
    [[ -n "${REALITY_PORT:-}" ]] && echo "$REALITY_PORT"
    [[ -n "${REALITY_PORT_V6:-}" ]] && echo "$REALITY_PORT_V6"
    # 共存内部端口（从 coexist state 读，未启用则回退常量默认值）
    local _cr _cw
    _cr="$(reality_coexist_reality_port 2>/dev/null || true)"; [[ -n "$_cr" ]] && echo "$_cr"
    _cw="$(reality_coexist_web_port 2>/dev/null || true)"; [[ -n "$_cw" ]] && echo "$_cw"
    echo "${REALITY_COEXIST_INNER_PORT:-18443}"
    echo "${REALITY_WEB_INNER_PORT:-12443}"
    [[ -n "${REALITY_CDN_ORIGIN_PORT:-}" ]] && echo "$REALITY_CDN_ORIGIN_PORT"
    [[ -n "${REALITY_CDN_INNER_PORT:-}" ]] && echo "$REALITY_CDN_INNER_PORT"
    # 所有已配置的 relay 监听端口（realm 可能当前停止，ss 查不到，故必须从磁盘枚举）
    local f
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        # 只读 RLY_LISTEN_PORT 行，避免 source 污染当前 RLY_* 全局
        local _p
        _p="$(grep -E '^RLY_LISTEN_PORT=' "$f" 2>/dev/null | head -n1 | sed -E 's/^RLY_LISTEN_PORT=["'\'']?([0-9]+)["'\'']?.*/\1/')"
        [[ -n "$_p" ]] && echo "$_p"
    done < <(reality_relay_route_files 2>/dev/null)
}

# 某端口是否已被本项目其他 feature 保留（逻辑占用，独立于运行时 ss 检查）。
reality_port_reserved() {
    local port="$1" exclude="${2:-}"
    [[ -n "$port" ]] || return 1
    reality_reserved_ports 2>/dev/null | grep -vxF "${exclude:-__none__}" | grep -qxF "$port"
}

reality_port_reserved_except_current_landing() {
    local port="$1" _old_p="${REALITY_PORT:-}" _old_p6="${REALITY_PORT_V6:-}"
    local _save_p="${REALITY_PORT:-}" _save_p6="${REALITY_PORT_V6:-}" _rc
    if [[ "$port" == "$_old_p" ]]; then
        REALITY_PORT=""
    fi
    if [[ "$port" == "$_old_p6" ]]; then
        REALITY_PORT_V6=""
    fi
    if reality_port_reserved "$port"; then
        _rc=0
    else
        _rc=$?
    fi
    REALITY_PORT="$_save_p"
    REALITY_PORT_V6="$_save_p6"
    return "$_rc"
}

reality_detect_local_ipv6_addr() {
    # 用于 split 双节点“IPv4/IPv6 共用 443”场景：
    #   IPv4 入站继续绑定 0.0.0.0:443；
    #   IPv6 入站必须绑定具体本机公网 IPv6:443，避免 [::]:443 与 0.0.0.0:443 在 bindv6only=0 下冲突。
    # 只接受公网可路由地址，跳过 fe80::/10 与 fc00::/7。
    if [[ -n "${REALITY_LISTEN_HOST_V6:-}" && "${REALITY_LISTEN_HOST_V6}" != "::" ]]; then
        printf '%s' "$REALITY_LISTEN_HOST_V6"
        return 0
    fi
    command_exists ip || return 1
    ip -o -6 addr show scope global 2>/dev/null | awk '
        {
            for (i = 1; i <= NF; i++) {
                if ($i == "inet6") {
                    split($(i + 1), a, "/")
                    addr = tolower(a[1])
                    if (addr !~ /^fe80:/ && addr !~ /^fc/ && addr !~ /^fd/) {
                        if ($0 !~ / temporary / && $0 !~ / deprecated /) {
                            found = 1
                            print a[1]
                            exit
                        }
                        if (fallback == "") fallback = a[1]
                    }
                }
            }
        }
        END { if (!found && fallback != "") print fallback }'
}

reality_prepare_split_listen_hosts() {
    local port_v4="$1" port_v6="$2" v6_addr
    REALITY_LISTEN_HOST="split"
    REALITY_LISTEN_HOST_V4="${REALITY_LISTEN_HOST_V4:-0.0.0.0}"
    if [[ "$port_v4" == "$port_v6" ]]; then
        v6_addr="$(reality_detect_local_ipv6_addr 2>/dev/null || true)"
        if [[ -z "$v6_addr" || "$v6_addr" == "::" ]]; then
            print_error "IPv4/IPv6 双节点共用 ${port_v4}/tcp 需要绑定具体本机公网 IPv6，未检测到可用 IPv6。"
            print_error "请改用不同端口，或确认系统已有全局 IPv6 地址后重试。"
            return 1
        fi
        REALITY_LISTEN_HOST_V6="$v6_addr"
    else
        REALITY_LISTEN_HOST_V6="${REALITY_LISTEN_HOST_V6:-::}"
    fi
}

reality_warn_sni_risk() {
    local sni="${1,,}"
    [[ -n "$sni" ]] || return 0
    if [[ "$sni" == *apple* || "$sni" == *icloud* || "$sni" == *itunes* || "$sni" == *mzstatic* ]]; then
        print_warn "REALITY SNI/handshake 目标疑似 Apple/iCloud 系域名；Xray v26.3.27 已提示这类目标可能增加 IP 被封锁风险。"
    fi
}

reality_warn_port_risk() {
    local port="$1" label="${2:-Reality}"
    validate_port "$port" || return 0
    if [[ "$port" != "443" ]]; then
        print_warn "${label} 监听端口为 ${port}，不是 443；Xray v26.3.27 已提示 REALITY 非 443 监听可能增加 IP 被封锁风险。"
    fi
}

reality_random_port() {
    local min="${REALITY_PORT_MIN:-20000}" max="${REALITY_PORT_MAX:-60000}" port try range rand
    range=$((max - min + 1))
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
        elif command_exists od && [[ -r /dev/urandom ]]; then
            rand=$(od -An -N4 -tu4 /dev/urandom 2>/dev/null | tr -d ' ')
            port=$(( rand % range + min ))
        else
            port=$(( (((RANDOM << 15) ^ RANDOM) % range) + min ))
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

# 随机挑一个「真实浏览器」uTLS 指纹（客户端 fp）。
# 目的：全网节点默认都填 chrome 会形成同一特征（fp=chrome 指纹画像），改为按节点随机分散。
# 关键取舍：不用 uTLS 的 "randomized"（每次连接换指纹反而异常——真实浏览器指纹是稳定的），
# 而是「装机时定一个真实浏览器指纹并持久化」→ 单节点稳定像真浏览器、节点之间彼此不同。
# 池仅取主流真实浏览器（sing-box uTLS 合法值），不含 360/q（地域性强、易反成特征）与 randomized。
reality_random_fingerprint() {
    local fps=(chrome firefox edge safari ios android)
    local n=${#fps[@]} idx
    if command_exists openssl; then
        idx=$(( 0x$(openssl rand -hex 2) % n ))
    else
        idx=$(( RANDOM % n ))
    fi
    printf '%s' "${fps[$idx]}"
}

# 校验是否为合法 uTLS 指纹（用于导入/回读兜底）。非法或空 → 回退 chrome。
reality_sanitize_fingerprint() {
    local fp="${1:-}"
    case "$fp" in
        chrome|firefox|edge|safari|ios|android|360|q|randomized) printf '%s' "$fp" ;;
        *) printf '%s' "chrome" ;;
    esac
}

# 当前落地机的有效客户端指纹：读 state 的 REALITY_FINGERPRINT，经 sanitize；
# 旧版 state 无该字段（空）→ 回退 chrome（保持老节点链接不变）。
reality_effective_fingerprint() {
    reality_sanitize_fingerprint "${REALITY_FINGERPRINT:-}"
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

reality_public_key_from_private() {
    # sing-box 目前没有可靠的 "private -> public" 子命令；不要调用
    # `sing-box generate reality-keypair --private-key ...`，实测会生成新 keypair。
    # 这里按 RFC8410 包装 X25519 raw private key，再由 openssl 导出 raw public key。
    local private="$1" tmp_dir raw der spki pub b64 len
    [[ -n "$private" ]] || return 1
    command_exists openssl || return 1
    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/reality-x25519.XXXXXX") || return 1
    raw="$tmp_dir/private.raw"
    der="$tmp_dir/private.der"
    spki="$tmp_dir/public.spki.der"
    pub="$tmp_dir/public.raw"
    b64="${private//-/+}"
    b64="${b64//_//}"
    case $(( ${#b64} % 4 )) in
        2) b64="${b64}==" ;;
        3) b64="${b64}=" ;;
        1) rm -rf "$tmp_dir"; return 1 ;;
    esac
    if ! printf '%s' "$b64" | openssl base64 -d -A > "$raw" 2>/dev/null; then
        rm -rf "$tmp_dir"; return 1
    fi
    len=$(wc -c < "$raw" | tr -d '[:space:]')
    if [[ "$len" != "32" ]]; then rm -rf "$tmp_dir"; return 1; fi
    printf '%b' '\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20' > "$der"
    cat "$raw" >> "$der"
    if ! openssl pkey -inform DER -in "$der" -pubout -outform DER > "$spki" 2>/dev/null; then
        rm -rf "$tmp_dir"; return 1
    fi
    tail -c 32 "$spki" > "$pub"
    openssl base64 -A -in "$pub" 2>/dev/null | tr '+/' '-_' | sed 's/=*$//'
    rm -rf "$tmp_dir"
}

reality_detect_listen_host() {
    # 决定 sing-box / realm 应绑定的本机地址：
    #   本机存在全局 IPv6 地址 → "::"（双栈监听；bindv6only=0 默认下经 IPv4-mapped 同时覆盖 IPv4），
    #   否则 → "0.0.0.0"（纯 IPv4）。
    # 用本地接口判断而非公网探测，避免网络抖动导致 IPv6-only 机器误绑 0.0.0.0 而对外不可达。
    # 可用 REALITY_LISTEN_HOST 覆盖（测试/特殊网络）。
    # "split" 是双节点模式的哨兵值（sing-box 入站走 REALITY_LISTEN_HOST_V4/V6，不用此变量），
    # 不是合法 bind 地址；realm 等消费者遇到它时必须回落到接口探测（split 必有 IPv6→绑 ::），
    # 否则会渲染出 listen = "split:<port>" 致 realm 无法启动。
    if [[ -n "${REALITY_LISTEN_HOST:-}" && "${REALITY_LISTEN_HOST}" != "split" ]]; then printf '%s' "$REALITY_LISTEN_HOST"; return 0; fi
    if command_exists ip && ip -6 addr show scope global 2>/dev/null | grep -q 'inet6'; then
        printf '%s' "::"
    else
        printf '%s' "0.0.0.0"
    fi
}

# 把 host+port 组装为监听串：IPv6 字面量加方括号
reality_listen_endpoint() {
    local host="$1" port="$2"
    if [[ "$host" == *:* ]]; then printf '[%s]:%s' "$host" "$port"; else printf '%s:%s' "$host" "$port"; fi
}

# ============================================================================
# 443 共存模式（nginx stream + ssl_preread 分流）
# 开启后：443 由 nginx stream 独占，按 SNI 分流——真站域名→web(127.0.0.1:WEB_PORT)，
# default(借用SNI/未知/无SNI)→reality(127.0.0.1:REALITY_PORT)。sing-box reality 入站
# 从公网 443 改绑 127.0.0.1:<内部端口>；客户端链接仍是 443（连的是 nginx stream）。
# 关键：Reality 客户端 ClientHello 的 SNI 是借用大站域名（非节点域名），故必须 default→reality。
# ============================================================================

# 共存是否已启用（state 文件存在且 ENABLED=1、内部端口合法）
reality_coexist_enabled() {
    [[ -f "$REALITY_COEXIST_STATE_FILE" ]] || return 1
    (
        # shellcheck disable=SC1090
        validate_conf_file "$REALITY_COEXIST_STATE_FILE" 2>/dev/null && source "$REALITY_COEXIST_STATE_FILE" 2>/dev/null || exit 1
        [[ "${REALITY_COEXIST_ENABLED:-0}" == "1" ]] || exit 1
        validate_port "${REALITY_COEXIST_REALITY_PORT:-}" 2>/dev/null || exit 1
        validate_port "${REALITY_COEXIST_WEB_PORT:-}" 2>/dev/null || exit 1
    )
}

# 加载共存 state 到全局（渲染/菜单/诊断用；渲染入站走子 shell 读取时不调它）
reality_coexist_load_state() {
    [[ -f "$REALITY_COEXIST_STATE_FILE" ]] || return 1
    validate_conf_file "$REALITY_COEXIST_STATE_FILE" || return 1
    # shellcheck disable=SC1090
    source "$REALITY_COEXIST_STATE_FILE"
}

# 写共存 state（值经 reality_state_quote，满足 validate_conf_file 的 owner/600/字面量校验）
reality_coexist_write_state() {
    mkdir -p "$REALITY_CONFIG_DIR"
    chmod 700 "$REALITY_CONFIG_DIR" 2>/dev/null || true
    validate_port "${REALITY_COEXIST_REALITY_PORT:-}" || { print_error "共存 reality 内部端口无效: ${REALITY_COEXIST_REALITY_PORT:-空}"; return 1; }
    validate_port "${REALITY_COEXIST_WEB_PORT:-}" || { print_error "共存 web 内部端口无效: ${REALITY_COEXIST_WEB_PORT:-空}"; return 1; }
    local content
    content=$(cat <<EOF
REALITY_COEXIST_ENABLED=$(reality_state_quote "${REALITY_COEXIST_ENABLED:-0}")
REALITY_COEXIST_REALITY_PORT=$(reality_state_quote "${REALITY_COEXIST_REALITY_PORT:-}")
REALITY_COEXIST_WEB_PORT=$(reality_state_quote "${REALITY_COEXIST_WEB_PORT:-}")
EOF
)
    reality_write_secure_file "$REALITY_COEXIST_STATE_FILE" "$content"
}

# 取共存 reality 内部端口（供 web 模块/诊断复用）；未启用返回非 0
reality_coexist_reality_port() {
    reality_coexist_enabled || return 1
    (
        # shellcheck disable=SC1090
        validate_conf_file "$REALITY_COEXIST_STATE_FILE" 2>/dev/null && source "$REALITY_COEXIST_STATE_FILE" 2>/dev/null || exit 1
        validate_port "${REALITY_COEXIST_REALITY_PORT:-}" 2>/dev/null || exit 1
        printf '%s' "${REALITY_COEXIST_REALITY_PORT}"
    )
}

# 取共存 web 内部端口（供 web 模块建站下沉复用）；未启用返回非 0
reality_coexist_web_port() {
    reality_coexist_enabled || return 1
    (
        # shellcheck disable=SC1090
        validate_conf_file "$REALITY_COEXIST_STATE_FILE" 2>/dev/null && source "$REALITY_COEXIST_STATE_FILE" 2>/dev/null || exit 1
        validate_port "${REALITY_COEXIST_WEB_PORT:-}" 2>/dev/null || exit 1
        printf '%s' "${REALITY_COEXIST_WEB_PORT}"
    )
}

# 收集需要走 443 stream SNI 白名单的真站域名。
# 真相源：/etc/nginx/sites-available/*.conf。关键：只收录“实际监听 web 内部端口”的站点，
# 从其 server_name 取域名——因为只有经 _web_coexist_https_port 下沉到 web_port 的站才真在该端口。
# 09e 家宽暴露（默认 8443）、用户自定义非 443 端口的站不会下沉，故不监听 web_port，
# 不应进白名单（否则会被 stream 路由到无人监听的 web_port 而连不上）。
# 排除 CDN 回源站（reality-cdn-*，走 8443 橙云回源，不经 443 stream）。
# 每域一行；无则输出空。
reality_coexist_collect_web_domains() {
    local f base web_port sn sites_dir="${REALITY_NGINX_SITES_DIR:-/etc/nginx/sites-available}"
    web_port="$(reality_coexist_web_port 2>/dev/null || true)"
    validate_port "$web_port" 2>/dev/null || return 0
    [[ -d "$sites_dir" ]] || return 0
    for f in "$sites_dir"/*.conf; do
        [[ -f "$f" ]] || continue
        base=$(basename "$f" .conf)
        # CDN 回源站不经 443 stream（独立回源端口 + 橙云），跳过
        [[ "$base" == reality-cdn-* ]] && continue
        # 该站必须真实监听 web 内部端口，否则不路由到 web。
        # 共存下真站由 _nginx_tls_http2_block 渲染成 loopback 绑定：
        #   listen 127.0.0.1:<port> ssl;  /  listen [::1]:<port> ssl;
        # 故 listen 行可能带 IPv4/IPv6 主机前缀（127.0.0.1: 或 [..]:），也可能是裸端口
        # （listen <port> / listen [::]:<port>）。全部需匹配，否则真站永不入白名单，
        # 所有 SNI 都落到 default→reality，web 侧共存静默失效。
        grep -Eq "^\s*listen\s+([0-9.]+:|\[[0-9a-fA-F:]+\]:)?${web_port}(\s|;)" "$f" 2>/dev/null || continue
        # 从 server_name 行取第一个域名（比文件名更准：文件名可能与 server_name 不一致）
        sn=$(grep -E '^\s*server_name\s+' "$f" 2>/dev/null | head -n1 \
             | sed -E 's/^\s*server_name\s+//; s/;.*$//' | awk '{print $1}')
        [[ -n "$sn" ]] || sn="$base"
        validate_domain "$sn" 2>/dev/null || continue
        printf '%s\n' "$sn"
    done | sort -u
}

# 渲染 stream 分流配置片段（写入独立文件，由 nginx.conf 的 stream{} include 引入）。
# map $ssl_preread_server_name：真站域名 → web upstream；default → reality upstream。
# 关键：default 必须指向 reality（Reality 客户端 SNI 是借用大站域名，非节点域名）。
reality_coexist_render_stream_conf() {
    local reality_port web_port
    reality_port="$(reality_coexist_reality_port 2>/dev/null || true)"
    web_port="$(reality_coexist_web_port 2>/dev/null || true)"
    validate_port "$reality_port" || { print_error "共存 reality 内部端口无效"; return 1; }
    validate_port "$web_port" || { print_error "共存 web 内部端口无效"; return 1; }
    local -a domains=()
    local d
    while IFS= read -r d; do [[ -n "$d" ]] && domains+=("$d"); done < <(reality_coexist_collect_web_domains)
    {
        echo "# Reality 443 共存分流 (nginx stream + ssl_preread)"
        echo "# Generated by ${SCRIPT_NAME} ${VERSION}"
        echo "# 443 由本 stream 独占；真站域名(白名单)→127.0.0.1:${web_port}，default→127.0.0.1:${reality_port}(reality)。"
        echo "map \$ssl_preread_server_name \$reality_coexist_backend {"
        for d in "${domains[@]}"; do
            printf '    %s reality_coexist_web;\n' "$d"
        done
        echo "    default reality_coexist_reality;"
        echo "}"
        echo "upstream reality_coexist_reality { server 127.0.0.1:${reality_port}; }"
        echo "upstream reality_coexist_web { server 127.0.0.1:${web_port}; }"
        echo "server {"
        echo "    listen 443;"
        echo "    listen [::]:443;"
        echo "    proxy_pass \$reality_coexist_backend;"
        echo "    ssl_preread on;"
        echo "}"
    }
}

# nginx.conf 是否已有顶层 stream{} 块（外部/发行版自带）。有则注入策略需谨慎。
# 除 nginx.conf 正文外，还展开其中 include 引入的文件——发行版常把 stream{} 放在
# include 进来的独立片段里（如 /etc/nginx/conf.d/*.conf、modules 等），只查正文会漏检，
# 导致我们再注入一个 stream{} 造成两个顶层 stream 块、nginx 启动失败。
# 排除我们自己的标记块与 stream-enabled 目录（那是本功能产物，非“外部已有”）。
reality_coexist_nginx_has_stream_block() {
    local main_conf="${1:-/etc/nginx/nginx.conf}"
    [[ -f "$main_conf" ]] || return 1
    local uncommented inc_line inc_glob g conf_dir
    conf_dir="$(dirname "$main_conf")"
    # 1) 正文（去注释）直接含 stream{ —— 但排除我们自己注入的标记块
    if ! grep -q 'reality-coexist-stream-include' "$main_conf" 2>/dev/null; then
        if grep -vE '^\s*#' "$main_conf" 2>/dev/null | grep -qE '(^|\s)stream\s*\{'; then
            return 0
        fi
    fi
    # 2) 展开 include 的文件再查（仅顶层 include；一层展开足以覆盖发行版默认布局）
    while IFS= read -r inc_line; do
        inc_glob=$(sed -E 's/^\s*include\s+//; s/;\s*$//' <<< "$inc_line")
        [[ -n "$inc_glob" ]] || continue
        # 相对路径按 nginx.conf 所在目录展开
        [[ "$inc_glob" != /* ]] && inc_glob="${conf_dir}/${inc_glob}"
        for g in $inc_glob; do
            [[ -f "$g" ]] || continue
            # 跳过我们自己的 stream-enabled 产物目录
            [[ "$g" == "$REALITY_STREAM_ENABLED_DIR"/* ]] && continue
            grep -vE '^\s*#' "$g" 2>/dev/null | grep -qE '(^|\s)stream\s*\{' && return 0
        done
    done < <(grep -vE '^\s*#' "$main_conf" 2>/dev/null | grep -E '^\s*include\s+')
    return 1
}

# 幂等地把 stream include 注入 nginx.conf 顶层。
# 用独立 stream{} 块 include 我们的 stream-enabled 目录；带唯一标记便于回滚移除。
reality_coexist_inject_nginx_include() {
    local main_conf="${1:-/etc/nginx/nginx.conf}" tmp
    [[ -f "$main_conf" ]] || { print_error "未找到 nginx.conf: $main_conf"; return 1; }
    mkdir -p "$REALITY_STREAM_ENABLED_DIR"
    # 已注入过（含标记）→ 幂等返回
    if grep -q 'reality-coexist-stream-include' "$main_conf" 2>/dev/null; then
        return 0
    fi
    if reality_coexist_nginx_has_stream_block "$main_conf"; then
        # 外部已有 stream{}：不改它，改为把 include 加进已有块——风险较高，交由调用方提示手动处理。
        print_warn "nginx.conf 已存在 stream{} 块；为避免破坏，请手动在其中加入: include ${REALITY_STREAM_ENABLED_DIR}/*.conf;"
        return 2
    fi
    reality_backup_file "$main_conf" || return 1
    tmp=$(mktemp "$(dirname "$main_conf")/.tmp.server-manage.nginx-stream-include.XXXXXX") || return 1
    declare -F _tmp_register >/dev/null 2>&1 && _tmp_register "$tmp"
    # 追加独立 stream 块到文件末尾（顶层合法），先写同目录候选文件，避免中断/写满磁盘污染 nginx.conf。
    if ! cat "$main_conf" > "$tmp"; then
        rm -f "$tmp" 2>/dev/null || true
        declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$tmp"
        return 1
    fi
    if ! cat >> "$tmp" <<EOF

# reality-coexist-stream-include (由 ${SCRIPT_NAME} 注入，可经菜单关闭共存自动移除)
stream {
    include ${REALITY_STREAM_ENABLED_DIR}/*.conf;
}
EOF
    then
        rm -f "$tmp" 2>/dev/null || true
        declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$tmp"
        return 1
    fi
    chmod --reference="$main_conf" "$tmp" 2>/dev/null || true
    chown --reference="$main_conf" "$tmp" 2>/dev/null || true
    if ! mv "$tmp" "$main_conf"; then
        rm -f "$tmp" 2>/dev/null || true
        declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$tmp"
        return 1
    fi
    declare -F _tmp_unregister >/dev/null 2>&1 && _tmp_unregister "$tmp"
}

# 移除注入的 stream include 块（回滚用）。仅删带唯一标记的块，不动外部 stream。
reality_coexist_remove_nginx_include() {
    local main_conf="${1:-/etc/nginx/nginx.conf}"
    [[ -f "$main_conf" ]] || return 0
    grep -q 'reality-coexist-stream-include' "$main_conf" 2>/dev/null || return 0
    reality_backup_file "$main_conf"
    # 删除从标记注释行起、到其后第一个单独成行的 '}' 为止的整块
    local tmp
    tmp=$(mktemp "$(dirname "$main_conf")/.tmp.nginxconf.XXXXXX") || return 1
    awk '
        /# reality-coexist-stream-include/ { skip=1; next }
        skip && /^\}/ { skip=0; next }
        skip { next }
        { print }
    ' "$main_conf" > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod --reference="$main_conf" "$tmp" 2>/dev/null || true
    mv "$tmp" "$main_conf" || { rm -f "$tmp"; return 1; }
}

# 刷新 stream 分流配置（web 模块增删域名后调用；仅在共存启用时生效）。
# 重写 stream 片段 → nginx -t → reload。失败保留旧片段并回滚。
reality_coexist_refresh() {
    reality_coexist_enabled || return 0
    command_exists nginx || return 0
    # stream 模块必须在场：refresh 也被 web 建站路径调用，若此时 nginx 无 stream 模块
    # （被外部改动卸载/换版本），我们注入的 stream{} 会让 nginx -t 整体失败，进而误伤
    # 刚部署的站点配置。此时告警并跳过刷新（不动 nginx），把 stream 恢复留给用户重开共存。
    if declare -F _check_nginx_stream >/dev/null 2>&1 && ! _check_nginx_stream; then
        print_warn "nginx 当前无 stream 模块，跳过 443 共存分流刷新；请重新启用共存或修复 stream 模块。"
        return 0
    fi
    mkdir -p "$REALITY_STREAM_ENABLED_DIR"
    local new_conf backup=""
    new_conf="$(reality_coexist_render_stream_conf)" || return 1
    if [[ -f "$REALITY_STREAM_CONF" ]]; then
        backup=$(mktemp "${REALITY_STREAM_ENABLED_DIR}/.reality-coexist.bak.XXXXXX") || return 1
        cp -a "$REALITY_STREAM_CONF" "$backup" || { rm -f "$backup"; return 1; }
    fi
    write_file_atomic "$REALITY_STREAM_CONF" "$new_conf" || {
        print_error "写入 stream 分流配置失败"
        [[ -n "$backup" ]] && rm -f "$backup"
        return 1
    }
    if nginx -t >/dev/null 2>&1 && _nginx_reload >/dev/null 2>&1; then
        [[ -n "$backup" ]] && rm -f "$backup"
        return 0
    fi
    print_error "nginx 测试/重载失败，回滚 stream 分流配置"
    if [[ -n "$backup" && -e "$backup" ]]; then
        mv "$backup" "$REALITY_STREAM_CONF"
    else
        rm -f "$REALITY_STREAM_CONF"
    fi
    nginx -t >/dev/null 2>&1 && _nginx_reload >/dev/null 2>&1 || true
    return 1
}

# 选一个未占用的 loopback 内部端口：优先用建议值，被占用则回落随机高位。
reality_coexist_pick_inner_port() {
    local prefer="$1" forbidden="${2:-}" p
    # 建议值(prefer)本身是共存常量，会出现在 reserved 集里，故检查保留时把 prefer 自身排除。
    if validate_port "$prefer" && [[ "$prefer" != "$forbidden" ]] \
        && ! reality_port_in_use "$prefer" && ! reality_port_reserved "$prefer" "$prefer"; then
        echo "$prefer"; return 0
    fi
    for _ in $(seq 1 200); do
        p=$(reality_random_port) || return 1
        [[ "$p" == "$forbidden" || "$p" == "${REALITY_PORT:-}" || "$p" == "${REALITY_CDN_ORIGIN_PORT:-8443}" ]] && continue
        # MED-4：除运行时占用，还要避开本项目其他 feature 已保留(可能当前停止)的端口。
        reality_port_reserved "$p" "$forbidden" && continue
        reality_port_in_use "$p" && continue
        echo "$p"; return 0
    done
    return 1
}

# 启用 443 共存模式：sing-box reality 入站下沉到 loopback，443 交给 nginx stream 分流。
# 顺序关键：先重渲 sing-box 释放公网 443，再让 nginx stream 抢 443，避免端口冲突。
reality_coexist_enable() {
    print_title "启用 Reality 443 共存模式（nginx stream + ssl_preread）"
    reality_require_supported_os || { pause; return 1; }
    if ! reality_load_state || [[ -z "${REALITY_UUID:-}" || -z "${REALITY_PORT:-}" || -z "${REALITY_SNI:-}" ]]; then
        print_error "本机尚未安装 Reality 落地机，请先用菜单 1 安装落地机。"
        pause; return 1
    fi
    if reality_coexist_enabled; then
        print_warn "443 共存模式已启用。"
        pause; return 0
    fi
    # split 双栈：共存分支只渲染单入站（用 REALITY_PORT），会丢掉 IPv6 节点，故明确拒绝。
    local _mode; _mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo auto)
    if [[ "$_mode" == "split" ]]; then
        print_error "IPv4/IPv6 双节点(split)模式暂不支持 443 共存：stream 分流与双入站需另行设计。"
        print_info "如需共存，请改用单节点(auto/ipv4/ipv6)模式重装落地机后再启用。"
        pause; return 1
    fi
    # 共存要求 Reality 对外走 443（由 nginx stream 持有）。若落地端口非 443，
    # 启用后客户端链接端口(REALITY_PORT)与实际对外端口(443)不一致，且 ufw/安全组未放行 443，
    # 会静默不可达。强制要求落地端口为 443。
    if [[ "${REALITY_PORT:-}" != "443" ]]; then
        print_error "当前 Reality 落地端口为 ${REALITY_PORT:-未知}，非 443。443 共存要求落地端口为 443。"
        print_info "请用菜单 1 以「443」端口重装落地机后再启用共存。"
        pause; return 1
    fi
    command_exists nginx || { print_error "Nginx 未安装。请先用 Web 菜单「添加域名」安装 nginx/certbot 依赖。"; pause; return 1; }
    echo "  说明：开启后 443 由 nginx stream 独占，按 SNI 分流——真站域名→web 内部端口，"
    echo "  default（Reality 借用大站 SNI/未知/无 SNI）→ sing-box reality loopback 入站。"
    echo "  Reality 直连伪装、借 SNI 轮换保持不变；客户端链接仍是 443（连的是 nginx stream）。"
    echo "  注意：此后每次 reload nginx（加站/改站）会让 Reality 连接瞬断重连。"
    echo "  注意：真站经 stream 透传后，其访问日志/按 IP 的限流/geo 会看到 127.0.0.1（非真实客户端 IP）；"
    echo "        因 stream 与 Reality 直连共用一个入口、无法只对真站启用 PROXY 协议，故不取真实 IP。"
    echo ""
    confirm "确认启用 443 共存模式?" || { print_info "已取消"; pause; return 0; }

    # 1) 确保 nginx 具备 stream 模块（缺失则装 libnginx-mod-stream 或换官方源）
    echo -e "\n${C_CYAN}=== [1] 检查/安装 nginx stream 模块 ===${C_RESET}"
    if ! _ensure_nginx_stream; then
        print_error "无法为 nginx 启用 stream 模块，已中止。可手动安装官方 nginx.org 源（含 stream）后重试。"
        pause; return 1
    fi
    print_success "nginx stream 模块可用"

    # 2) 选内部端口（loopback，仅本机 nginx 连接）
    local reality_inner web_inner
    reality_inner=$(reality_coexist_pick_inner_port "$REALITY_COEXIST_INNER_PORT") || { print_error "无法分配 reality 内部端口"; pause; return 1; }
    web_inner=$(reality_coexist_pick_inner_port "$REALITY_WEB_INNER_PORT" "$reality_inner") || { print_error "无法分配 web 内部端口"; pause; return 1; }

    # 3) 写共存 state（ENABLED=1 使 render 走 loopback 分支）
    REALITY_COEXIST_ENABLED=1
    REALITY_COEXIST_REALITY_PORT="$reality_inner"
    REALITY_COEXIST_WEB_PORT="$web_inner"
    reality_coexist_write_state || { print_error "写入共存 state 失败"; rm -f "$REALITY_COEXIST_STATE_FILE"; pause; return 1; }

    # 4) 重渲 sing-box：入站改绑 127.0.0.1:reality_inner，释放公网 443
    echo -e "\n${C_CYAN}=== [2] 重渲 sing-box（reality 入站下沉到 127.0.0.1:${reality_inner}）===${C_RESET}"
    local new_config
    if ! new_config=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") \
       || ! reality_apply_singbox_config "$new_config"; then
        print_error "sing-box 重渲失败，回滚共存 state。"
        rm -f "$REALITY_COEXIST_STATE_FILE"
        pause; return 1
    fi
    print_success "sing-box reality 入站已下沉到 loopback，公网 443 已释放"

    # 5) 生成 stream 分流配置 + 注入 nginx.conf include + reload
    echo -e "\n${C_CYAN}=== [3] 部署 nginx stream 443 分流 ===${C_RESET}"
    local inject_rc
    reality_coexist_inject_nginx_include; inject_rc=$?
    # rc==0 注入成功；rc==2 外部已有 stream{} 块（我们未注入 include，若继续会导致分流配置成为
    # 死文件、公网 443 无人监听而节点全废且误报成功）；rc==1 写入失败。非 0 一律中止回滚。
    if [[ $inject_rc -ne 0 ]]; then
        if [[ $inject_rc -eq 2 ]]; then
            print_error "nginx.conf 已存在 stream{} 块，为避免破坏未自动注入。请手动在该 stream{} 内加入："
            print_error "    include ${REALITY_STREAM_ENABLED_DIR}/*.conf;"
            print_error "然后重新启用共存。已回滚（sing-box 改回直绑 443）。"
        else
            print_error "注入 nginx.conf stream include 失败，回滚。"
        fi
        reality_coexist_disable_internal
        pause; return 1
    fi
    if ! reality_coexist_refresh; then
        print_error "nginx stream 分流部署失败，回滚（sing-box 改回直绑 443）。"
        reality_coexist_disable_internal
        pause; return 1
    fi
    print_success "nginx stream 已接管 443 分流"
    # 确保对外 443 已放行（nginx stream 现在持有 443；落地端口原为 443 通常已放行，此处兜底）。
    # 内部端口 reality_inner/web_inner 仅 loopback，不放行、外部不可见。
    firewall_apply_reality_port 443 >/dev/null 2>&1 || \
        print_warn "未能自动放行 443/tcp，请确认 ufw/云安全组已放行 443（stream 分流对外入口）。"
    echo ""
    print_success "443 共存模式已启用！reality 内部端口 ${reality_inner}，web 内部端口 ${web_inner}。"
    print_info "此后用 Web 菜单新建的站点会自动使用 ${web_inner} 端口，由 443 stream 统一对外。"
    log_action "reality coexist enabled: reality=${reality_inner} web=${web_inner}"
    pause
}

# 内部回滚/关闭：不含交互确认，供 enable 失败回滚与 disable 菜单共用。
# 顺序：先移除 nginx stream（释放 443）→ 删共存 state → 重渲 sing-box 直绑 443。
reality_coexist_disable_internal() {
    rm -f "$REALITY_STREAM_CONF"
    reality_coexist_remove_nginx_include
    rm -f "$REALITY_COEXIST_STATE_FILE"
    if command_exists nginx && nginx -t >/dev/null 2>&1; then _nginx_reload >/dev/null 2>&1 || true; fi
    # nginx reload 释放 443 是异步的（旧 worker 优雅退出需时间）。若紧接着 restart sing-box
    # 抢绑 443，旧 worker 可能仍持有 443 → bind 失败 → systemd 重试期间对外中断约 10s。
    # 故先有界等待 443 真正释放（最多 ~5s），再重渲 sing-box 直绑 443，消除竞态中断。
    reality_wait_port_free 443 50 || print_warn "443 释放等待超时，sing-box 直绑可能需 systemd 重试后生效。"
    if reality_load_state && [[ -n "${REALITY_UUID:-}" && -n "${REALITY_PORT:-}" ]]; then
        local cfg
        cfg=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") \
            && reality_apply_singbox_config "$cfg" || true
    fi
}

# 关闭 443 共存模式（菜单入口，带确认）。
reality_coexist_disable() {
    print_title "关闭 Reality 443 共存模式"
    if ! reality_coexist_enabled; then
        print_warn "当前未启用 443 共存模式。"
        pause; return 0
    fi
    echo "  关闭后：nginx stream 443 分流移除，sing-box reality 入站改回直绑公网 443。"
    echo "  已建的真站若仍监听内部端口（如 12443），需你自行改回 443 或重建（脚本不自动改回）。"
    echo ""
    confirm "确认关闭 443 共存模式?" || { print_info "已取消"; pause; return 0; }
    reality_coexist_disable_internal
    print_success "443 共存模式已关闭，Reality 已改回直绑 443。"
    print_info "如有站点仍监听内部端口，请手动改回 443 后 reload nginx，或用 Web 菜单重建。"
    log_action "reality coexist disabled"
    pause
}

reality_render_singbox_config() {
    local uuid="$1" private_key="$2" port="$3" sni="$4" short_id="$5"
    local listen_host; listen_host="${REALITY_LISTEN_HOST:-$(reality_detect_listen_host)}"
    uuid=$(reality_json_escape "$uuid")
    private_key=$(reality_json_escape "$private_key")
    sni=$(reality_json_escape "$sni")
    short_id=$(reality_json_escape "$short_id")
    # CDN 链路（VLESS+WS）入站：若已启用则作为额外 inbound 一并渲染。
    # 关键：必须在“整体重渲染”里合并（不能事后追加），否则 rotate key/user、改名、重装
    # 等任何触发重渲染的操作都会把 WS 入站冲掉。子 shell 读取，避免污染本函数全局。
    local cdn_inbound; cdn_inbound="$(reality_cdn_inbound_json)"
    # 共存模式：sing-box reality 入站改绑 127.0.0.1:<内部端口>，443 由 nginx stream 对外分流。
    # 共存下单入站即可（v4/v6 都由 nginx stream 统一对外），故优先于 split 分支处理。
    local coexist_port; coexist_port="$(reality_coexist_reality_port 2>/dev/null || true)"
    if [[ -n "$coexist_port" ]]; then
        cat <<EOF
{"log":{"disabled":true},"inbounds":[{"type":"vless","tag":"vless-reality-in","listen":"127.0.0.1","listen_port":${coexist_port},"users":[{"name":"main","uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"],"max_time_difference":"1m"}}}${cdn_inbound}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
EOF
        return 0
    fi
    if [[ "${REALITY_DNS_MODE:-auto}" == "split" && -n "${REALITY_PORT_V6:-}" ]]; then
        local listen_host_v4="${REALITY_LISTEN_HOST_V4:-0.0.0.0}" listen_host_v6="${REALITY_LISTEN_HOST_V6:-::}" port_v6="${REALITY_PORT_V6}"
        cat <<EOF
{"log":{"disabled":true},"inbounds":[{"type":"vless","tag":"vless-reality-ipv4","listen":"${listen_host_v4}","listen_port":${port},"users":[{"name":"main","uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"],"max_time_difference":"1m"}}},{"type":"vless","tag":"vless-reality-ipv6","listen":"${listen_host_v6}","listen_port":${port_v6},"users":[{"name":"main","uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"],"max_time_difference":"1m"}}}${cdn_inbound}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
EOF
        return 0
    fi
    cat <<EOF
{"log":{"disabled":true},"inbounds":[{"type":"vless","tag":"vless-reality-in","listen":"${listen_host}","listen_port":${port},"users":[{"name":"main","uuid":"${uuid}","flow":"xtls-rprx-vision"}],"tls":{"enabled":true,"server_name":"${sni}","reality":{"enabled":true,"handshake":{"server":"${sni}","server_port":443},"private_key":"${private_key}","short_id":["${short_id}"],"max_time_difference":"1m"}}}${cdn_inbound}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
EOF
}

# ============================================================================
# CDN 链路（VLESS + WebSocket + TLS，CF 橙云 + 优选 IP）
# 与 Reality 直连链路并存：Reality 仍绑 443 灰云直连；CDN 的 WS 入站只绑
# 127.0.0.1:<内部端口>（明文），由 nginx 在 REALITY_CDN_ORIGIN_PORT 上做 TLS 终止
# + 反代到该内部端口，CF 橙云 Full(strict) 回源。客户端把 server 字段填优选 IP、
# host/sni 填真实 cdn 域名，CF 靠 Host 头路由回源。
# 优选 IP 时效仅几天，由国内机定时跑 CloudflareSpeedTest（B）+ 本地渲染/入口 DNS 同步（C）刷新。
# ============================================================================

# CDN 是否已启用（state 文件存在且关键字段齐全）
reality_cdn_enabled() {
    [[ -f "$REALITY_CDN_STATE_FILE" ]] || return 1
    (
        # shellcheck disable=SC1090
        validate_conf_file "$REALITY_CDN_STATE_FILE" 2>/dev/null && source "$REALITY_CDN_STATE_FILE" 2>/dev/null
        [[ -n "${REALITY_CDN_UUID:-}" && -n "${REALITY_CDN_WS_PATH:-}" && -n "${REALITY_CDN_INNER_PORT:-}" ]] && \
        validate_port "${REALITY_CDN_INNER_PORT:-}" 2>/dev/null && \
        reality_validate_ws_path "${REALITY_CDN_WS_PATH:-}" 2>/dev/null
    )
}

# 写 CDN state（值经 reality_state_quote，满足 validate_conf_file 的 owner/600/字面量校验）
reality_cdn_write_state() {
    mkdir -p "$REALITY_CONFIG_DIR"
    chmod 700 "$REALITY_CONFIG_DIR" 2>/dev/null || true
    validate_domain "${REALITY_CDN_DOMAIN:-}" || { print_error "CDN 域名无效: ${REALITY_CDN_DOMAIN:-空}"; return 1; }
    [[ -n "${REALITY_CDN_UUID:-}" ]] || { print_error "CDN UUID 为空"; return 1; }
    reality_validate_ws_path "${REALITY_CDN_WS_PATH:-}" || { print_error "CDN WS path 无效: ${REALITY_CDN_WS_PATH:-空}"; return 1; }
    validate_port "${REALITY_CDN_INNER_PORT:-}" || { print_error "CDN 内部端口无效: ${REALITY_CDN_INNER_PORT:-空}"; return 1; }
    validate_port "${REALITY_CDN_ORIGIN_PORT:-}" || { print_error "CDN 回源端口无效: ${REALITY_CDN_ORIGIN_PORT:-空}"; return 1; }
    local content
    content=$(cat <<EOF
REALITY_CDN_DOMAIN=$(reality_state_quote "${REALITY_CDN_DOMAIN:-}")
REALITY_CDN_UUID=$(reality_state_quote "${REALITY_CDN_UUID:-}")
REALITY_CDN_WS_PATH=$(reality_state_quote "${REALITY_CDN_WS_PATH:-}")
REALITY_CDN_INNER_PORT=$(reality_state_quote "${REALITY_CDN_INNER_PORT:-}")
REALITY_CDN_ORIGIN_PORT=$(reality_state_quote "${REALITY_CDN_ORIGIN_PORT:-}")
REALITY_CDN_PREFER_IP=$(reality_state_quote "${REALITY_CDN_PREFER_IP:-}")
REALITY_CDN_NODE_NAME=$(reality_state_quote "${REALITY_CDN_NODE_NAME:-}")
EOF
)
    reality_write_secure_file "$REALITY_CDN_STATE_FILE" "$content"
}

# 加载 CDN state 到全局（供向导/卸载/产物使用；渲染入站走子 shell 不调它）
reality_cdn_load_state() {
    [[ -f "$REALITY_CDN_STATE_FILE" ]] || return 1
    validate_conf_file "$REALITY_CDN_STATE_FILE" || return 1
    # shellcheck disable=SC1090
    source "$REALITY_CDN_STATE_FILE"
}

# 生成 CDN 的 WS 入站 JSON 片段（带前导逗号，拼到 reality 入站之后）。
# 子 shell 读取 state，避免污染调用方（reality_render_singbox_config）的全局变量。
# 未启用 / 字段不全 → 输出空串（即不渲染该入站）。
reality_cdn_inbound_json() {
    [[ -f "$REALITY_CDN_STATE_FILE" ]] || return 0
    (
        # shellcheck disable=SC1090
        validate_conf_file "$REALITY_CDN_STATE_FILE" 2>/dev/null && source "$REALITY_CDN_STATE_FILE" 2>/dev/null || exit 0
        [[ -n "${REALITY_CDN_UUID:-}" && -n "${REALITY_CDN_WS_PATH:-}" && -n "${REALITY_CDN_INNER_PORT:-}" ]] || exit 0
        validate_port "${REALITY_CDN_INNER_PORT}" 2>/dev/null || exit 0
        reality_validate_ws_path "${REALITY_CDN_WS_PATH}" 2>/dev/null || exit 0
        local u p path
        u=$(reality_json_escape "$REALITY_CDN_UUID")
        path=$(reality_json_escape "$REALITY_CDN_WS_PATH")
        p="$REALITY_CDN_INNER_PORT"
        printf ',{"type":"vless","tag":"vless-cdn-ws","listen":"127.0.0.1","listen_port":%s,"users":[{"name":"cdn","uuid":"%s"}],"transport":{"type":"ws","path":"%s"}}' \
            "$p" "$u" "$path"
    )
}

# 生成 CDN 客户端 vless 链接（WS+TLS）。server=优选IP(默认=域名)，host/sni=真实 cdn 域名。
# fp 复用落地机的有效指纹（CDN 与落地共用 UUID，同属一台机器的客户端身份）。
reality_cdn_build_link() {
    local server="$1" name="$2" encoded_name encoded_path server_uri fp
    fp=$(reality_effective_fingerprint)
    encoded_name=$(reality_urlencode "$name")
    encoded_path=$(reality_urlencode "$REALITY_CDN_WS_PATH")
    server_uri=$(reality_uri_host "$server")
    printf 'vless://%s@%s:443?encryption=none&security=tls&sni=%s&fp=%s&type=ws&host=%s&path=%s#%s\n' \
        "$REALITY_CDN_UUID" "$server_uri" "$REALITY_CDN_DOMAIN" "$fp" "$REALITY_CDN_DOMAIN" "$encoded_path" "$encoded_name"
}

# 写 CDN 客户端产物（链接 + sing-box JSON）。server 优先用优选 IP，无则回落域名。
reality_cdn_write_client_artifacts() {
    mkdir -p "$REALITY_CONFIG_DIR"
    local server="${REALITY_CDN_PREFER_IP:-$REALITY_CDN_DOMAIN}"
    local name="${REALITY_CDN_NODE_NAME:-cdn-$( printf '%s' "$REALITY_CDN_DOMAIN" | cut -d. -f1 )}"
    [[ -n "$REALITY_CDN_UUID" && -n "$REALITY_CDN_DOMAIN" && -n "$REALITY_CDN_WS_PATH" ]] || return 1
    reality_validate_ws_path "$REALITY_CDN_WS_PATH" || return 1
    local json_name; json_name=$(reality_json_escape "$name")
    local json_path; json_path=$(reality_json_escape "$REALITY_CDN_WS_PATH")
    local json_host; json_host=$(reality_json_escape "$REALITY_CDN_DOMAIN")
    local json_server; json_server=$(reality_json_escape "$server")
    local json_uuid; json_uuid=$(reality_json_escape "$REALITY_CDN_UUID")
    local cdn_fp; cdn_fp=$(reality_effective_fingerprint)
    local link_content json_content
    link_content="$(reality_cdn_build_link "$server" "$name")" || return 1
    json_content=$(cat <<EOF
{"type":"vless","tag":"${json_name}","server":"${json_server}","server_port":443,"uuid":"${json_uuid}","tls":{"enabled":true,"server_name":"${json_host}","utls":{"enabled":true,"fingerprint":"${cdn_fp}"}},"transport":{"type":"ws","path":"${json_path}","headers":{"Host":"${json_host}"}}}
EOF
)
    reality_write_secure_file "$REALITY_CDN_LINK_FILE" "$link_content" || return 1
    reality_write_secure_file "$REALITY_CDN_CLIENT_JSON" "$json_content" || return 1
}

reality_cdn_nginx_site_name() {
    local domain="${1:-}"
    printf 'reality-cdn-%s' "$domain"
}

reality_cdn_cf_cred_path() {
    local domain="${1:-}" dir="${REALITY_CDN_CF_CRED_DIR:-/root}"
    [[ -n "$domain" ]] || return 1
    printf '%s/.cloudflare-%s.ini' "${dir%/}" "$domain"
}

reality_cdn_le_live_dir() {
    local domain="${1:-}" dir="${REALITY_CDN_LE_LIVE_DIR:-/etc/letsencrypt/live}"
    [[ -n "$domain" ]] || return 1
    printf '%s/%s' "${dir%/}" "$domain"
}

reality_cdn_cleanup_cert_resources() {
    local domain="$1" clean_cert_dir="${2:-0}" clean_cred="${3:-0}" clean_hook="${4:-0}" clean_cron="${5:-0}" clean_le="${6:-0}" snapshot_dir="${7:-}"
    [[ -n "$domain" ]] || return 0
    validate_domain "$domain" || return 1
    local cert_prefix="${CERT_PATH_PREFIX%/}" cert_dir="" cred_path="" hook_path="${CERT_HOOKS_DIR}/renew-${domain}.sh" le_dir=""
    [[ -n "$cert_prefix" && "$cert_prefix" != "/" ]] && cert_dir="${cert_prefix}/${domain}"
    cred_path="$(reality_cdn_cf_cred_path "$domain")" || cred_path=""
    le_dir="$(reality_cdn_le_live_dir "$domain")" || le_dir=""

    if [[ "$clean_cron" -eq 1 ]]; then
        if [[ -n "$snapshot_dir" && -f "$snapshot_dir/crontab" ]] && command_exists crontab; then
            crontab "$snapshot_dir/crontab" 2>/dev/null || cron_remove_job "CertRenew_${domain}" 2>/dev/null || true
        else
            cron_remove_job "CertRenew_${domain}" 2>/dev/null || true
        fi
    fi
    if [[ -n "$snapshot_dir" && -e "$snapshot_dir/hook" && -n "$hook_path" ]]; then
        mkdir -p "$(dirname "$hook_path")" 2>/dev/null || true
        rm -f "$hook_path" 2>/dev/null || true
        cp -a "$snapshot_dir/hook" "$hook_path" 2>/dev/null || true
    elif [[ "$clean_hook" -eq 1 ]]; then
        rm -f "$hook_path" 2>/dev/null || true
    fi
    if [[ -n "$snapshot_dir" && -e "$snapshot_dir/cf-cred" && -n "$cred_path" ]]; then
        mkdir -p "$(dirname "$cred_path")" 2>/dev/null || true
        rm -f "$cred_path" 2>/dev/null || true
        cp -a "$snapshot_dir/cf-cred" "$cred_path" 2>/dev/null || true
    elif [[ "$clean_cred" -eq 1 && -n "$cred_path" ]]; then
        rm -f "$cred_path" 2>/dev/null || true
    fi
    if [[ -n "$snapshot_dir" && -e "$snapshot_dir/cert-dir" && -n "$cert_dir" ]]; then
        rm -rf "$cert_dir" 2>/dev/null || true
        mkdir -p "$(dirname "$cert_dir")" 2>/dev/null || true
        cp -a "$snapshot_dir/cert-dir" "$cert_dir" 2>/dev/null || true
    elif [[ "$clean_cert_dir" -eq 1 && -n "$cert_dir" ]]; then
        rm -rf "$cert_dir" 2>/dev/null || true
    fi
    if [[ -n "$snapshot_dir" && -e "$snapshot_dir/le-live" && -n "$le_dir" ]]; then
        rm -rf "$le_dir" 2>/dev/null || true
        mkdir -p "$(dirname "$le_dir")" 2>/dev/null || true
        cp -a "$snapshot_dir/le-live" "$le_dir" 2>/dev/null || true
    elif [[ "$clean_le" -eq 1 && -n "$le_dir" ]]; then
        command_exists certbot && certbot delete --cert-name "$domain" --non-interactive 2>/dev/null || true
        rm -rf "$le_dir" 2>/dev/null || true
    fi
    [[ -n "$snapshot_dir" ]] && rm -rf -- "$snapshot_dir" 2>/dev/null || true
}

reality_cdn_remove_nginx_conf() {
    local domain="$1" site legacy_av legacy_en f
    [[ -n "$domain" ]] || return 0
    site="$(reality_cdn_nginx_site_name "$domain")"
    rm -f "/etc/nginx/sites-enabled/${site}.conf" "/etc/nginx/sites-available/${site}.conf"
    # 兼容旧版本曾使用 ${domain}.conf 的 CDN 回源站点；只删除带 CDN 生成标记的文件，
    # 避免误删 Web 菜单托管的同名站点。
    legacy_av="/etc/nginx/sites-available/${domain}.conf"
    legacy_en="/etc/nginx/sites-enabled/${domain}.conf"
    for f in "$legacy_en" "$legacy_av"; do
        [[ -f "$f" ]] || continue
        if grep -q "CDN 回源站点 (VLESS+WS+TLS) for ${domain}" "$f" 2>/dev/null; then
            rm -f "$f"
        fi
    done
}

reality_cdn_restore_state_snapshot() {
    local had_state="${1:-0}" state_snapshot="${2:-}"
    if [[ "$had_state" -eq 1 ]]; then
        reality_write_secure_file "$REALITY_CDN_STATE_FILE" "$state_snapshot" || return 1
    else
        rm -f "$REALITY_CDN_STATE_FILE"
    fi
}

reality_cdn_reapply_current_singbox() {
    reality_load_state || return 1
    [[ -n "${REALITY_UUID:-}" && -n "${REALITY_PRIVATE_KEY:-}" && -n "${REALITY_PORT:-}" && -n "${REALITY_SNI:-}" && -n "${REALITY_SHORT_ID:-}" ]] || return 1
    local rollback_config
    rollback_config=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") || return 1
    reality_apply_singbox_config "$rollback_config"
}

reality_cdn_install_rollback() {
    local had_state="${1:-0}" state_snapshot="${2:-}" cdn_domain="${3:-}" nginx_deployed="${4:-0}" reapply_singbox="${5:-0}"
    local had_link="${6:-0}" link_snapshot="${7-}" had_client_json="${8:-0}" client_json_snapshot="${9-}"
    local clean_cert_dir="${10:-0}" clean_cred="${11:-0}" clean_hook="${12:-0}" clean_cron="${13:-0}" clean_le="${14:-0}" cert_snapshot_dir="${15:-}"
    if ! reality_cdn_restore_state_snapshot "$had_state" "$state_snapshot"; then
        print_warn "恢复安装前 CDN state 失败，请手动检查 ${REALITY_CDN_STATE_FILE}"
    fi
    if [[ "$had_link" -eq 1 ]]; then
        reality_write_secure_file "$REALITY_CDN_LINK_FILE" "$link_snapshot" || print_warn "恢复旧 CDN 链接产物失败，请手动检查 ${REALITY_CDN_LINK_FILE}"
    else
        rm -f "$REALITY_CDN_LINK_FILE"
    fi
    if [[ "$had_client_json" -eq 1 ]]; then
        reality_write_secure_file "$REALITY_CDN_CLIENT_JSON" "$client_json_snapshot" || print_warn "恢复旧 CDN JSON 产物失败，请手动检查 ${REALITY_CDN_CLIENT_JSON}"
    else
        rm -f "$REALITY_CDN_CLIENT_JSON"
    fi
    if [[ "$nginx_deployed" -eq 1 && -n "$cdn_domain" ]]; then
        local restored_old_nginx=0 old_nginx_conf old_cert_dir
        if [[ "$had_state" -eq 1 ]] && reality_cdn_load_state 2>/dev/null && [[ "${REALITY_CDN_DOMAIN:-}" == "$cdn_domain" ]]; then
            old_cert_dir="${CERT_PATH_PREFIX}/${REALITY_CDN_DOMAIN}"
            if old_nginx_conf=$(reality_cdn_render_nginx_conf "$REALITY_CDN_DOMAIN" "${REALITY_CDN_ORIGIN_PORT:-8443}" "$REALITY_CDN_WS_PATH" "$REALITY_CDN_INNER_PORT" "$old_cert_dir") \
                && _nginx_deploy_conf "$(reality_cdn_nginx_site_name "$REALITY_CDN_DOMAIN")" "$old_nginx_conf"; then
                restored_old_nginx=1
            else
                print_warn "恢复旧 CDN nginx 回源站失败，请手动检查 ${cdn_domain}"
            fi
        fi
        if [[ "$restored_old_nginx" -ne 1 ]]; then
            reality_cdn_remove_nginx_conf "$cdn_domain"
            if command_exists nginx && nginx -t >/dev/null 2>&1; then _nginx_reload >/dev/null 2>&1 || true; fi
        fi
    fi
    if [[ "$reapply_singbox" -eq 1 ]]; then
        reality_cdn_reapply_current_singbox >/dev/null 2>&1 || print_warn "回滚后重载 sing-box 失败，请手动检查 ${REALITY_SINGBOX_CONFIG}"
    fi
    reality_cdn_cleanup_cert_resources "$cdn_domain" "$clean_cert_dir" "$clean_cred" "$clean_hook" "$clean_cron" "$clean_le" "$cert_snapshot_dir"
}

# 渲染 CDN 回源 nginx 站点：TLS 终止 + 隐秘 WS path 反代到内部端口；其余路径 444 断开。
reality_cdn_render_nginx_conf() {
    local domain="$1" origin_port="$2" ws_path="$3" inner_port="$4" cert_dir="$5"
    validate_domain "$domain" || return 1
    validate_port "$origin_port" || return 1
    validate_port "$inner_port" || return 1
    reality_validate_ws_path "$ws_path" || return 1
    cat <<EOF
# CDN 回源站点 (VLESS+WS+TLS) for ${domain}
# Generated by ${SCRIPT_NAME} ${VERSION}
# CF 橙云 Full(strict) 回源到本机 ${origin_port}；仅隐秘 path 反代到 sing-box WS 入站，其余 444。
server {
    # WebSocket 反代必须走 HTTP/1.1(Upgrade 机制),不能启用 HTTP/2,否则 CF 回源协商 h2 时 WS 握手 400。
    # 故 CDN 回源站用纯 ssl listen(不接 http2);web 模块的 _nginx_tls_http2_block 是普通 HTTPS 反代,不受影响。
    listen ${origin_port} ssl;
    listen [::]:${origin_port} ssl;
    server_name ${domain};
    ssl_certificate ${cert_dir}/fullchain.pem;
    ssl_certificate_key ${cert_dir}/privkey.pem;
    ssl_trusted_certificate ${cert_dir}/fullchain.pem;
    include snippets/ssl-params.conf;
    location ${ws_path} {
        proxy_pass http://127.0.0.1:${inner_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
    location / {
        return 444;
    }
}
EOF
}

# 同步 cdn 域名为 CF 橙云 A/AAAA（proxied=true）。复用通用 DNS upsert。
reality_cdn_sync_dns_orange() {
    local domain="$1" token="$2" zone_id ipv4 ipv6
    [[ -n "$domain" && -n "$token" ]] || return 1
    command_exists jq || install_package "jq" "silent" || return 1
    _cf_verify_token "$token" || return 1
    zone_id=$(_cf_get_zone_id "$domain" "$token") || return 1
    [[ -n "$zone_id" ]] || { print_error "无法获取 Zone ID: $domain"; return 1; }
    reality_detect_ips
    ipv4="$REALITY_IPV4"; ipv6="$REALITY_IPV6"
    [[ -n "$ipv4" || -n "$ipv6" ]] || { print_error "未检测到本机公网 IP，无法同步 CDN 域名"; return 1; }
    if [[ -n "$ipv4" ]]; then
        _cf_update_dns_record "$zone_id" "$token" "$domain" "A" "$ipv4" "true" || return 1
    else
        reality_cf_delete_dns_type "$domain" "$token" "A" "$zone_id" || { print_error "清理 ${domain} 的旧 A 记录失败"; return 1; }
    fi
    if [[ -n "$ipv6" ]]; then
        _cf_update_dns_record "$zone_id" "$token" "$domain" "AAAA" "$ipv6" "true" || return 1
    else
        reality_cf_delete_dns_type "$domain" "$token" "AAAA" "$zone_id" || { print_error "清理 ${domain} 的旧 AAAA 记录失败"; return 1; }
    fi
    log_action "CDN orange-cloud DNS synced: $domain proxied=true"
}

# 建/更新 CF Origin Rule：把 cdn 域名的回源端口改写到 origin_port（解决与 Reality 抢 443）。
reality_cdn_apply_origin_rule() {
    local domain="$1" token="$2" origin_port="$3" zone_id existing existing_rules filtered new_rule final err
    command_exists jq || install_package "jq" "silent" || return 1
    validate_domain "$domain" || { print_error "Origin Rule: 域名无效"; return 1; }
    validate_port "$origin_port" || { print_error "Origin Rule: 回源端口无效"; return 1; }
    zone_id=$(_cf_get_zone_id "$domain" "$token") || return 1
    [[ -n "$zone_id" ]] || { print_error "Origin Rule: 无法获取 Zone ID"; return 1; }
    if ! existing=$(_cf_get_origin_ruleset "$token" "$zone_id"); then
        print_error "Origin Rule: 读取现有规则失败，已中止以避免覆盖既有规则。"
        return 1
    fi
    if [[ -n "$existing" ]]; then
        existing_rules=$(jq '.result.rules // []' <<< "$existing" 2>/dev/null) || {
            print_error "Origin Rule: 解析现有规则失败，已中止。"
            return 1
        }
    else
        existing_rules="[]"
    fi
    filtered=$(jq --arg d "$domain" '[.[] | select(.expression != ("http.host eq \"" + $d + "\""))]' <<< "$existing_rules") || {
        print_error "Origin Rule: 过滤现有规则失败，已中止。"
        return 1
    }
    new_rule=$(jq -n --arg expr "http.host eq \"${domain}\"" --arg desc "Script-CDN-${domain}-${origin_port}" --argjson port "$origin_port" \
        '{action:"route", action_parameters:{origin:{port:$port}}, expression:$expr, description:$desc, enabled:true}') || {
        print_error "Origin Rule: 构造新规则失败。"
        return 1
    }
    final=$(jq --argjson new "$new_rule" '. + [$new]' <<< "$filtered") || {
        print_error "Origin Rule: 合并规则失败。"
        return 1
    }
    if ! err=$(_cf_put_origin_ruleset "$token" "$zone_id" "$final"); then
        print_error "Origin Rule 写入失败: $err"; return 1
    fi
    log_action "CDN origin rule set: $domain -> origin port $origin_port"
}

reality_build_vless_link() {
    local uuid="$1" node="$2" port="$3" sni="$4" public_key="$5" short_id="$6" name="${7:-singbox-reality}" fp="${8:-}" flow="${9:-xtls-rprx-vision}"
    local encoded_name node_uri
    encoded_name=$(reality_urlencode "$name")
    node_uri=$(reality_uri_host "$node")
    # fp 未显式传入时回退 chrome（保持旧调用/旧节点链接不变）；经 sanitize 防非法值。
    fp=$(reality_sanitize_fingerprint "${fp:-chrome}")
    flow="${flow:-xtls-rprx-vision}"
    printf 'vless://%s@%s:%s?encryption=none&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&type=tcp&flow=%s#%s\n' \
        "$uuid" "$node_uri" "$port" "$sni" "$fp" "$public_key" "$short_id" "$flow" "$encoded_name"
}

reality_parse_vless_link() {
    local link="$1" body user hostport query param key value host port
    [[ "$link" == vless://* ]] || return 1
    body="${link#vless://}"
    user="${body%@*}"
    body="${body#*@}"
    hostport="${body%%\?*}"
    query="${body#*\?}"
    query="${query%%#*}"
    REALITY_UUID="$user"
    if [[ "$hostport" == \[*\]:* ]]; then
        host="${hostport#\[}"
        host="${host%%\]*}"
        port="${hostport##*\]:}"
    else
        host="${hostport%:*}"
        port="${hostport##*:}"
    fi
    REALITY_NODE_DOMAIN="$host"
    REALITY_PORT="$port"
    # 关键：先把可选字段清空，再逐项解析。否则调用前若 reality_load_state 已把本机
    # 落地身份写进这些全局，链接里缺失的参数会"继承"本机旧值 —— 缺 sni 会用本机 sni
    # 通过非空守卫（烘进错误 SNI → 下游握手不匹配、静默不通）；缺 fp 会用本机指纹（破坏
    # 每节点 fp 分散设计）。清空后，缺失即为空，末尾的非空守卫才能真正拦住残缺链接。
    REALITY_SNI=""; REALITY_PUBLIC_KEY=""; REALITY_SHORT_ID=""; REALITY_FLOW=""; REALITY_FINGERPRINT=""
    while IFS= read -r param; do
        key="${param%%=*}"
        value="${param#*=}"
        case "$key" in
            sni|serverName) REALITY_SNI="$value" ;;
            pbk|publicKey) REALITY_PUBLIC_KEY="$value" ;;
            sid|shortId) REALITY_SHORT_ID="$value" ;;
            flow) REALITY_FLOW="$value" ;;
            fp|fingerprint) REALITY_FINGERPRINT="$value" ;;
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
    # 经 reality_detect_listen_host 解析，以处理 split 哨兵值（直接读 REALITY_LISTEN_HOST 会把 "split" 当 bind 地址）。
    local listen_host; listen_host="$(reality_detect_listen_host)"
    cat <<EOF
log.level = "warn"

[[endpoints]]
listen = "$(reality_listen_endpoint "$listen_host" "$listen_port")"
remote = "$(reality_listen_endpoint "$target_host" "$target_port")"
EOF
}

reality_resolve_public_a() {
    local domain="$1" resp ip
    [[ -n "$domain" ]] || return 1
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

reality_resolve_public_aaaa() {
    local domain="$1" resp ip
    [[ -n "$domain" ]] || return 1
    command_exists curl || return 1
    resp=$(curl -fsS --max-time 8 -H 'accept: application/dns-json' \
        "https://cloudflare-dns.com/dns-query?name=${domain}&type=AAAA" 2>/dev/null) || return 1
    ip=$(printf '%s' "$resp" | grep -Eo '"data":"[0-9a-fA-F:]+"' | head -n 1 | sed -E 's/"data":"([0-9a-fA-F:]+)"/\1/')
    [[ -n "$ip" && "$ip" == *:* ]] || return 1
    printf '%s\n' "$ip"
}

reality_local_client_self_test() {
    reality_load_state || return 1
    command_exists sing-box || { print_warn "sing-box 不存在，跳过本机协议自测"; return 1; }
    command_exists curl || { print_warn "curl 不存在，跳过本机协议自测"; return 1; }
    local test_port="${REALITY_SELFTEST_PORT:-19090}" tmp_dir cfg log curl_log pid_file pid i
    local old_umask
    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/reality-client-test.XXXXXX") || return 1
    chmod 700 "$tmp_dir" 2>/dev/null || true
    cfg="$tmp_dir/client.json"
    log="$tmp_dir/sing-box.log"
    curl_log="$tmp_dir/curl.log"
    pid_file="$tmp_dir/sing-box.pid"
    local st_fp; st_fp=$(reality_effective_fingerprint)
    old_umask=$(umask)
    umask 077
    if ! cat > "$cfg" <<EOF
{"log":{"level":"info","timestamp":true},"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":${test_port}}],"outbounds":[{"type":"vless","tag":"self-test","server":"127.0.0.1","server_port":${REALITY_PORT},"uuid":"${REALITY_UUID}","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"${REALITY_SNI}","utls":{"enabled":true,"fingerprint":"${st_fp}"},"reality":{"enabled":true,"public_key":"${REALITY_PUBLIC_KEY}","short_id":"${REALITY_SHORT_ID}"}}}],"route":{"final":"self-test"}}
EOF
    then
        umask "$old_umask"
        rm -rf "$tmp_dir"
        return 1
    fi
    umask "$old_umask"
    ( sing-box run -c "$cfg" > "$log" 2>&1 & echo $! > "$pid_file" )
    pid=$(cat "$pid_file" 2>/dev/null || true)
    for i in $(seq 1 30); do
        ss -ltn 2>/dev/null | grep -q ":${test_port} " && break
        sleep 0.2
    done
    if curl -x "socks5h://127.0.0.1:${test_port}" -fsS --max-time 15 https://www.cloudflare.com/cdn-cgi/trace >"$curl_log" 2>&1; then
        print_success "本机协议自测通过: sing-box client -> 127.0.0.1:${REALITY_PORT} -> 外网"
        [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
        rm -rf "$tmp_dir"
        return 0
    fi
    print_warn "本机协议自测失败，最近日志:"
    tail -n 20 "$curl_log" 2>/dev/null || true
    sed -E 's/[0-9a-fA-F-]{36}/<uuid>/g' "$log" 2>/dev/null | tail -n 20 || true
    [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
    rm -rf "$tmp_dir"
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

_reality_abs_system_path() {
    local path="${1:-}"
    [[ -n "$path" && "$path" == /* ]] || return 1
    [[ "$path" != *[[:space:]]* ]]
}

_reality_sagernet_keyring_path() {
    printf '%s' "${REALITY_SAGERNET_KEYRING_FILE:-/etc/apt/keyrings/sagernet.asc}"
}

_reality_sagernet_source_path() {
    printf '%s' "${REALITY_SAGERNET_SOURCE_FILE:-/etc/apt/sources.list.d/sagernet.sources}"
}

_reality_realm_service_path() {
    printf '%s' "${REALITY_REALM_SERVICE_FILE:-/etc/systemd/system/realm.service}"
}

_reality_realm_bin_path() {
    if [[ -n "${REALITY_REALM_BIN:-}" ]]; then
        printf '%s' "$REALITY_REALM_BIN"
        return 0
    fi
    local bin
    bin="$(type -P realm 2>/dev/null || true)"
    printf '%s' "${bin:-/usr/local/bin/realm}"
}

_reality_realm_config_path() {
    printf '%s' "${REALITY_REALM_CONFIG:-/etc/realm/config.toml}"
}

_reality_render_sagernet_source() {
    local keyring="$1"
    _reality_abs_system_path "$keyring" || return 1
    cat <<EOF
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: $keyring
EOF
}

_reality_install_sagernet_keyring() {
    local keyring dir tmp_key
    command_exists curl || return 1
    keyring="$(_reality_sagernet_keyring_path)"
    _reality_abs_system_path "$keyring" || return 1
    dir="$(dirname "$keyring")"
    mkdir -p "$dir" || return 1
    tmp_key=$(mktemp "${dir}/.tmp.server-manage.sagernet-key.XXXXXX") || return 1
    _tmp_register "$tmp_key"
    if ! curl -fsSL https://sing-box.app/gpg.key -o "$tmp_key"; then
        rm -f "$tmp_key" 2>/dev/null || true
        _tmp_unregister "$tmp_key"
        return 1
    fi
    chmod 644 "$tmp_key" 2>/dev/null || true
    chown root:root "$tmp_key" 2>/dev/null || true
    if ! mv "$tmp_key" "$keyring"; then
        rm -f "$tmp_key" 2>/dev/null || true
        _tmp_unregister "$tmp_key"
        return 1
    fi
    _tmp_unregister "$tmp_key"
    return 0
}

_reality_write_sagernet_source() {
    local keyring source_file content
    keyring="$(_reality_sagernet_keyring_path)"
    source_file="$(_reality_sagernet_source_path)"
    _reality_abs_system_path "$source_file" || return 1
    content="$(_reality_render_sagernet_source "$keyring")" || return 1
    write_file_atomic "$source_file" "$content" || return 1
    chmod 644 "$source_file" 2>/dev/null || true
}

_reality_render_realm_service_unit() {
    local realm_bin="${1:-$(_reality_realm_bin_path)}" realm_config="${2:-$(_reality_realm_config_path)}"
    _reality_abs_system_path "$realm_bin" || return 1
    _reality_abs_system_path "$realm_config" || return 1
    cat <<EOF
[Unit]
Description=Realm TCP Relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$realm_bin -c $realm_config
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
}

_reality_install_realm_service_unit() {
    local service_file content
    service_file="$(_reality_realm_service_path)"
    _reality_abs_system_path "$service_file" || return 1
    content="$(_reality_render_realm_service_unit)" || return 1
    write_file_atomic "$service_file" "$content" || return 1
    chmod 644 "$service_file" 2>/dev/null || true
}

_reality_install_realm_binary_file() {
    local src="$1" target="${2:-$(_reality_realm_bin_path)}" dir tmp_bin
    [[ -f "$src" ]] || return 1
    _reality_abs_system_path "$target" || return 1
    dir="$(dirname "$target")"
    mkdir -p "$dir" || return 1
    tmp_bin=$(mktemp "${dir}/.tmp.server-manage.realm.XXXXXX") || return 1
    _tmp_register "$tmp_bin"
    if ! cp "$src" "$tmp_bin"; then
        rm -f "$tmp_bin" 2>/dev/null || true
        _tmp_unregister "$tmp_bin"
        return 1
    fi
    chmod 0755 "$tmp_bin" 2>/dev/null || true
    chown root:root "$tmp_bin" 2>/dev/null || true
    if ! mv "$tmp_bin" "$target"; then
        rm -f "$tmp_bin" 2>/dev/null || true
        _tmp_unregister "$tmp_bin"
        return 1
    fi
    _tmp_unregister "$tmp_bin"
    return 0
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
        _reality_install_sagernet_keyring || return 1
        _reality_write_sagernet_source || return 1
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
    local timeout_cmd="" tmp_dir old_umask rc
    command_exists timeout && timeout_cmd="timeout 12"
    reality_cleanup_sni_check_log
    old_umask=$(umask)
    umask 077
    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/reality-sni-check.XXXXXX")
    rc=$?
    umask "$old_umask"
    [[ "$rc" -eq 0 ]] || return 1
    chmod 700 "$tmp_dir" 2>/dev/null || true
    REALITY_SNI_CHECK_DIR="$tmp_dir"
    REALITY_SNI_CHECK_LOG="$tmp_dir/sni-check.log"
    : > "$REALITY_SNI_CHECK_LOG" || { reality_cleanup_sni_check_log; return 1; }
    chmod 600 "$REALITY_SNI_CHECK_LOG" 2>/dev/null || true
    $timeout_cmd openssl s_client -connect "${domain}:443" -servername "$domain" -verify_hostname "$domain" -verify_return_error -brief </dev/null >"$REALITY_SNI_CHECK_LOG" 2>&1
}

reality_cleanup_sni_check_log() {
    if [[ -n "${REALITY_SNI_CHECK_DIR:-}" ]]; then
        rm -rf -- "$REALITY_SNI_CHECK_DIR" 2>/dev/null || true
    elif [[ -n "${REALITY_SNI_CHECK_LOG:-}" ]]; then
        rm -f -- "$REALITY_SNI_CHECK_LOG" 2>/dev/null || true
    fi
    REALITY_SNI_CHECK_DIR=""
    REALITY_SNI_CHECK_LOG=""
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
            reality_cleanup_sni_check_log
            echo "$sni"; return 0
        fi
        print_warn "SNI 校验未通过或网络不可达: $sni" >&2
        tail -n 3 "${REALITY_SNI_CHECK_LOG:-/dev/null}" >&2 2>/dev/null || true
        reality_cleanup_sni_check_log
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
    chmod 700 "$REALITY_BACKUP_DIR" 2>/dev/null || true
    cp -a "$file" "$REALITY_BACKUP_DIR/$(basename "$file").$(date +%Y%m%d-%H%M%S).bak"
}

reality_write_secure_file() {
    # 原子写入含密钥/UUID/path 的状态文件，避免 “cat > file; chmod 600”
    # 在宽 umask 下出现短暂 0644 暴露窗口。
    local file="$1" content="$2" dir tmp
    dir="$(dirname "$file")"
    mkdir -p "$dir" || return 1
    chmod 700 "$dir" 2>/dev/null || true
    tmp=$(mktemp "${dir}/.tmp.server-manage.reality.XXXXXX") || return 1
    if declare -F _tmp_register >/dev/null 2>&1; then _tmp_register "$tmp"; fi
    if ! printf '%s\n' "$content" > "$tmp"; then
        rm -f -- "$tmp" 2>/dev/null || true
        if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
        return 1
    fi
    chmod 600 "$tmp" 2>/dev/null || true
    if ! mv "$tmp" "$file"; then
        rm -f -- "$tmp" 2>/dev/null || true
        if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
        return 1
    fi
    if declare -F _tmp_unregister >/dev/null 2>&1; then _tmp_unregister "$tmp"; fi
    return 0
}

reality_apply_singbox_config() {
    local content="$1" target="${2:-$REALITY_SINGBOX_CONFIG}"
    [[ -n "$content" ]] || { print_error "sing-box 配置内容为空"; return 1; }
    command_exists sing-box || { print_error "sing-box 未安装"; return 1; }
    mkdir -p "$(dirname "$target")"
    local tmp backup="" had_old=0
    tmp=$(mktemp "$(dirname "$target")/.tmp.server-manage.singbox.XXXXXX") || return 1
    _tmp_register "$tmp"
    printf '%s\n' "$content" > "$tmp" || { rm -f "$tmp"; _tmp_unregister "$tmp"; return 1; }
    chmod 600 "$tmp" 2>/dev/null || true

    if ! sing-box check -c "$tmp" >/dev/null 2>&1; then
        print_error "sing-box 新配置校验失败，已保留原配置。"
        rm -f "$tmp"
        _tmp_unregister "$tmp"
        return 1
    fi

    if [[ -f "$target" ]]; then
        backup=$(mktemp "$(dirname "$target")/.bak.server-manage.singbox.XXXXXX") || { rm -f "$tmp"; _tmp_unregister "$tmp"; return 1; }
        _tmp_register "$backup"
        cp -a "$target" "$backup" || { rm -f "$tmp" "$backup"; _tmp_unregister "$tmp"; _tmp_unregister "$backup"; return 1; }
        had_old=1
    fi

    if ! mv "$tmp" "$target"; then
        print_error "写入 sing-box 配置失败，已保留原配置。"
        rm -f "$tmp"
        [[ -n "$backup" ]] && rm -f "$backup"
        _tmp_unregister "$tmp"
        [[ -n "$backup" ]] && _tmp_unregister "$backup"
        return 1
    fi
    _tmp_unregister "$tmp"

    if ! systemctl restart sing-box >/dev/null 2>&1; then
        print_error "sing-box 重启失败，正在回滚原配置。"
        if [[ $had_old -eq 1 && -n "$backup" ]]; then
            mv "$backup" "$target" 2>/dev/null || true
            _tmp_unregister "$backup"
        else
            rm -f "$target"
        fi
        systemctl restart sing-box >/dev/null 2>&1 || true
        return 1
    fi

    [[ -n "$backup" ]] && rm -f "$backup"
    [[ -n "$backup" ]] && _tmp_unregister "$backup"
    return 0
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
    chmod 700 "$REALITY_CONFIG_DIR" 2>/dev/null || true
    local content
    content=$(cat <<EOF
REALITY_ROLE=$(reality_state_quote "${REALITY_ROLE:-}")
REALITY_NODE_NAME=$(reality_state_quote "${REALITY_NODE_NAME:-}")
REALITY_NODE_DOMAIN=$(reality_state_quote "${REALITY_NODE_DOMAIN:-}")
REALITY_DNS_MODE=$(reality_state_quote "${REALITY_DNS_MODE:-}")
REALITY_NODE_DOMAIN_V4=$(reality_state_quote "${REALITY_NODE_DOMAIN_V4:-}")
REALITY_NODE_DOMAIN_V6=$(reality_state_quote "${REALITY_NODE_DOMAIN_V6:-}")
REALITY_NODE_NAME_V4=$(reality_state_quote "${REALITY_NODE_NAME_V4:-}")
REALITY_NODE_NAME_V6=$(reality_state_quote "${REALITY_NODE_NAME_V6:-}")
REALITY_SNI=$(reality_state_quote "${REALITY_SNI:-}")
REALITY_PORT=$(reality_state_quote "${REALITY_PORT:-}")
REALITY_PORT_V6=$(reality_state_quote "${REALITY_PORT_V6:-}")
REALITY_UUID=$(reality_state_quote "${REALITY_UUID:-}")
REALITY_PRIVATE_KEY=$(reality_state_quote "${REALITY_PRIVATE_KEY:-}")
REALITY_PUBLIC_KEY=$(reality_state_quote "${REALITY_PUBLIC_KEY:-}")
REALITY_SHORT_ID=$(reality_state_quote "${REALITY_SHORT_ID:-}")
REALITY_FINGERPRINT=$(reality_state_quote "${REALITY_FINGERPRINT:-}")
REALITY_LISTEN_HOST=$(reality_state_quote "${REALITY_LISTEN_HOST:-}")
REALITY_LISTEN_HOST_V4=$(reality_state_quote "${REALITY_LISTEN_HOST_V4:-}")
REALITY_LISTEN_HOST_V6=$(reality_state_quote "${REALITY_LISTEN_HOST_V6:-}")
REALITY_RELAY_DOMAIN=$(reality_state_quote "${REALITY_RELAY_DOMAIN:-}")
REALITY_RELAY_PORT=$(reality_state_quote "${REALITY_RELAY_PORT:-}")
REALITY_RELAY_TARGET_HOST=$(reality_state_quote "${REALITY_RELAY_TARGET_HOST:-}")
REALITY_RELAY_TARGET_PORT=$(reality_state_quote "${REALITY_RELAY_TARGET_PORT:-}")
EOF
)
    reality_write_secure_file "$REALITY_STATE_FILE" "$content"
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

reality_normalize_dns_mode() {
    local mode="${1:-auto}"
    mode="${mode,,}"
    case "$mode" in
        auto|dual|both|same|same-domain|"") echo "auto" ;;
        ipv4|ip4|v4|4) echo "ipv4" ;;
        ipv6|ip6|v6|6) echo "ipv6" ;;
        split|dual-node|dual-nodes|split-dual|v4v6|ipv4-ipv6) echo "split" ;;
        *) return 1 ;;
    esac
}

reality_dns_mode_label() {
    case "${1:-auto}" in
        ipv4) echo "IPv4-only 单节点（仅 A 记录）" ;;
        ipv6) echo "IPv6-only 单节点（仅 AAAA 记录）" ;;
        split) echo "IPv4+IPv6 双节点（A-only + AAAA-only，独立链接，优先共用 443）" ;;
        *) echo "自动/双栈单节点（同域名 A/AAAA）" ;;
    esac
}

reality_node_name_with_suffix() {
    local base="${1:-singbox-reality}" suffix="$2" max
    max=$((64 - ${#suffix}))
    (( max < 1 )) && max=1
    printf '%s%s' "${base:0:max}" "$suffix"
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

reality_write_one_client_artifact() {
    local link_path="$1" json_path="$2" link_host="$3" link_port="$4" name="$5" json_name
    [[ -n "$link_path" && -n "$json_path" && -n "$link_host" && -n "$link_port" ]] || return 1
    validate_port "$link_port" || return 1
    json_name=$(reality_json_escape "$name")
    local json_host; json_host=$(reality_json_escape "$link_host")
    local json_uuid; json_uuid=$(reality_json_escape "$REALITY_UUID")
    local json_sni; json_sni=$(reality_json_escape "$REALITY_SNI")
    local json_public_key; json_public_key=$(reality_json_escape "$REALITY_PUBLIC_KEY")
    local json_short_id; json_short_id=$(reality_json_escape "$REALITY_SHORT_ID")
    local fp; fp=$(reality_effective_fingerprint)
    local link_content json_content
    link_content="$(reality_build_vless_link "$REALITY_UUID" "$link_host" "$link_port" "$REALITY_SNI" "$REALITY_PUBLIC_KEY" "$REALITY_SHORT_ID" "$name" "$fp")" || return 1
    json_content=$(cat <<EOF
{"type":"vless","tag":"${json_name}","server":"${json_host}","server_port":${link_port},"uuid":"${json_uuid}","flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"${json_sni}","utls":{"enabled":true,"fingerprint":"${fp}"},"reality":{"enabled":true,"public_key":"${json_public_key}","short_id":"${json_short_id}"}}}
EOF
)
    reality_write_secure_file "$link_path" "$link_content" || return 1
    reality_write_secure_file "$json_path" "$json_content" || return 1
}

reality_write_client_artifacts() {
    mkdir -p "$REALITY_CONFIG_DIR"
    local mode="${REALITY_DNS_MODE:-auto}"
    mode=$(reality_normalize_dns_mode "$mode" 2>/dev/null || echo "auto")
    if [[ "$mode" == "split" ]]; then
        local host_v4="${REALITY_NODE_DOMAIN_V4:-$REALITY_NODE_DOMAIN}" host_v6="${REALITY_NODE_DOMAIN_V6:-}"
        local port_v4="${REALITY_PORT}" port_v6="${REALITY_PORT_V6:-}"
        local name_v4="${REALITY_NODE_NAME_V4:-}" name_v6="${REALITY_NODE_NAME_V6:-}"
        [[ -n "$host_v4" && -n "$host_v6" && -n "$port_v4" && -n "$port_v6" ]] || return 1
        [[ -n "$name_v4" ]] || name_v4="$(reality_node_name_with_suffix "$(reality_effective_node_name)" "-ipv4")"
        [[ -n "$name_v6" ]] || name_v6="$(reality_node_name_with_suffix "$(reality_effective_node_name)" "-ipv6")"
        reality_write_one_client_artifact "$REALITY_LINK_FILE_V4" "$REALITY_CLIENT_JSON_V4" "$host_v4" "$port_v4" "$name_v4" || return 1
        reality_write_one_client_artifact "$REALITY_LINK_FILE_V6" "$REALITY_CLIENT_JSON_V6" "$host_v6" "$port_v6" "$name_v6" || return 1
        local combined_links combined_json
        combined_links="$(cat "$REALITY_LINK_FILE_V4" "$REALITY_LINK_FILE_V6")" || return 1
        combined_json="$(cat "$REALITY_CLIENT_JSON_V4")" || return 1
        reality_write_secure_file "$REALITY_LINK_FILE" "$combined_links" || return 1
        reality_write_secure_file "$REALITY_CLIENT_JSON" "$combined_json" || return 1
        return 0
    fi

    local link_host="${REALITY_RELAY_DOMAIN:-$REALITY_NODE_DOMAIN}" link_port="${REALITY_RELAY_PORT:-$REALITY_PORT}" name
    [[ -n "$link_host" && -n "$link_port" ]] || return 1
    name="$(reality_effective_node_name)"
    reality_write_one_client_artifact "$REALITY_LINK_FILE" "$REALITY_CLIENT_JSON" "$link_host" "$link_port" "$name"
    rm -f "$REALITY_LINK_FILE_V4" "$REALITY_LINK_FILE_V6" "$REALITY_CLIENT_JSON_V4" "$REALITY_CLIENT_JSON_V6" 2>/dev/null || true
}

# 本机网卡是否真实绑定了全局公网 IPv4(排除私有/CGNAT/WARP 172.16.0.x/链路本地)。有=返回0。
reality_has_local_public_ipv4() {
    command_exists ip || return 0   # 无 ip 命令无法判断,则不拦,保持原行为
    ip -o -4 addr show scope global 2>/dev/null | awk '
        { for(i=1;i<=NF;i++) if($i=="inet"){ split($(i+1),a,"/"); p=a[1]
            if(p ~ /^10\./)                                 continue
            if(p ~ /^192\.168\./)                           continue
            if(p ~ /^172\.(1[6-9]|2[0-9]|3[01])\./)         continue
            if(p ~ /^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./) continue
            if(p ~ /^127\./ || p ~ /^169\.254\./)           continue
            found=1 } }
        END { exit (found?0:1) }'
}

reality_ipv4_is_likely_warp_egress() {
    local ip="${1:-}"
    # Cloudflare WARP 常见 IPv4 出口段。若本机网卡没有公网 IPv4 且探测到这些出口，
    # 不能把它写进 CF 回源 A 记录，否则 CF 会回源到 WARP 出口而不是本机。
    case "$ip" in
        104.28.*|104.29.*) return 0 ;;
    esac
    return 1
}

reality_has_warp_interface() {
    command_exists ip || return 1
    ip -o link show 2>/dev/null | grep -Eiq '(warp|wgcf|cloudflare)'
}

reality_should_clear_detected_ipv4() {
    local ip="${1:-}"
    [[ -n "$ip" ]] || return 1
    reality_has_local_public_ipv4 && return 1
    # 没有本地公网 IPv4 有两种常见情况：
    # 1) IPv6-only + WARP：公网 IPv4 是 WARP 出口，必须清空；
    # 2) OCI/云厂商 1:1 NAT：公网 IPv4 不绑在网卡上，但仍可入站回源，必须保留。
    # 因此只在明确像 WARP 时清空；普通云 NAT IPv4 保留。
    reality_ipv4_is_likely_warp_egress "$ip" && return 0
    reality_has_warp_interface && return 0
    return 1
}

reality_detect_ips() {
    REALITY_IPV4="$(get_public_ipv4 2>/dev/null || true)"
    REALITY_IPV6="$(get_public_ipv6 2>/dev/null || true)"
    [[ -n "$REALITY_IPV6" && "$REALITY_IPV6" != *:* ]] && REALITY_IPV6=""
    # 防 WARP/NAT64 幽灵 IPv4，同时兼容 OCI/云厂商 1:1 NAT 公网 IPv4 不绑定到客机网卡的场景。
    if [[ -n "$REALITY_IPV4" ]] && reality_should_clear_detected_ipv4 "$REALITY_IPV4"; then
        REALITY_IPV4=""
    fi
}

reality_cf_delete_dns_type() {
    local domain="$1" token="$2" type="$3" zone_id="${4:-}" resp id ids=() page=1 per_page=100 total_pages count del_resp
    [[ -z "$domain" || -z "$token" || -z "$type" ]] && return 1
    command_exists jq || install_package "jq" "silent" || return 1
    [[ -n "$zone_id" ]] || zone_id=$(_cf_get_zone_id "$domain" "$token") || return 1
    [[ -n "$zone_id" ]] || return 1
    while true; do
        resp=$(_cf_api GET "/zones/$zone_id/dns_records?type=$type&name=$domain&per_page=$per_page&page=$page" "$token") || return 1
        _cf_api_ok "$resp" || return 1
        while IFS= read -r id; do
            [[ -n "$id" ]] && ids+=("$id")
        done < <(jq -r '.result[].id // empty' <<< "$resp" 2>/dev/null)
        total_pages=$(jq -r '.result_info.total_pages // empty' <<< "$resp" 2>/dev/null)
        count=$(jq -r '.result | length' <<< "$resp" 2>/dev/null)
        if [[ "$total_pages" =~ ^[0-9]+$ ]]; then
            (( page >= total_pages )) && break
        else
            [[ "$count" =~ ^[0-9]+$ ]] || count=0
            (( count < per_page )) && break
        fi
        page=$((page + 1))
    done
    for id in "${ids[@]}"; do
        [[ -n "$id" ]] || continue
        del_resp=$(_cf_api DELETE "/zones/$zone_id/dns_records/$id" "$token") || return 1
        _cf_api_ok "$del_resp" || return 1
    done
}

reality_sync_cloudflare_dns() {
    local domain="$1" token="$2" mode="${3:-auto}"
    [[ -z "$domain" || -z "$token" ]] && return 1
    mode=$(reality_normalize_dns_mode "$mode" 2>/dev/null || echo "auto")
    reality_detect_ips
    case "$mode" in
        ipv4)
            [[ -n "$REALITY_IPV4" ]] || { print_error "未检测到公网 IPv4，无法同步 IPv4-only 节点"; return 1; }
            cf_dns_sync_node_grey "$token" "$domain" "$REALITY_IPV4" "" "true" "5" || return 1
            reality_cf_delete_dns_type "$domain" "$token" "AAAA" || { print_error "清理 ${domain} 的 AAAA 记录失败；IPv4-only 节点可能仍被解析到 IPv6"; return 1; }
            ;;
        ipv6)
            [[ -n "$REALITY_IPV6" ]] || { print_error "未检测到公网 IPv6，无法同步 IPv6-only 节点"; return 1; }
            cf_dns_sync_node_grey "$token" "$domain" "" "$REALITY_IPV6" "true" "5" || return 1
            reality_cf_delete_dns_type "$domain" "$token" "A" || { print_error "清理 ${domain} 的 A 记录失败；IPv6-only 节点可能仍被解析到 IPv4"; return 1; }
            ;;
        *)
            [[ -n "$REALITY_IPV4" || -n "$REALITY_IPV6" ]] || { print_error "未检测到公网 IP"; return 1; }
            cf_dns_sync_node_grey "$token" "$domain" "$REALITY_IPV4" "$REALITY_IPV6" "true" "5"
            ;;
    esac
}

reality_sync_cloudflare_dns_by_state() {
    local token="$1" mode
    [[ -n "$token" ]] || return 1
    mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo "auto")
    if [[ "$mode" == "split" ]]; then
        [[ -n "${REALITY_NODE_DOMAIN_V4:-}" && -n "${REALITY_NODE_DOMAIN_V6:-}" ]] || { print_error "双节点模式缺少 IPv4/IPv6 域名"; return 1; }
        reality_sync_cloudflare_dns "$REALITY_NODE_DOMAIN_V4" "$token" "ipv4" || return 1
        reality_sync_cloudflare_dns "$REALITY_NODE_DOMAIN_V6" "$token" "ipv6" || return 1
    else
        reality_sync_cloudflare_dns "$REALITY_NODE_DOMAIN" "$token" "$mode"
    fi
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
    local token="$1" resp page=1 per_page=50 all='[]' total_pages count
    [[ -z "$token" ]] && return 1
    if declare -F _cf_list_zones >/dev/null 2>&1; then
        resp=$(_cf_list_zones "$token") || return 1
        _cf_api_ok "$resp" || return 1
        reality_cf_zone_names_from_json "$resp"
        return 0
    fi
    while true; do
        resp=$(_cf_api GET "/zones?per_page=$per_page&page=$page" "$token") || return 1
        _cf_api_ok "$resp" || return 1
        all=$(jq -c --argjson acc "$all" '$acc + (.result // [])' <<< "$resp" 2>/dev/null) || return 1
        total_pages=$(jq -r '.result_info.total_pages // empty' <<< "$resp" 2>/dev/null)
        count=$(jq -r '.result | length' <<< "$resp" 2>/dev/null)
        if [[ "$total_pages" =~ ^[0-9]+$ ]]; then
            (( page >= total_pages )) && break
        else
            [[ "$count" =~ ^[0-9]+$ ]] || count=0
            (( count < per_page )) && break
        fi
        page=$((page + 1))
    done
    resp=$(jq -n --argjson result "$all" '{success:true, errors:[], messages:[], result:$result}') || return 1
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
    local purpose="$1" token="$2" default_prefix="${3:-$(hostname)-reality}" zone="" prefix="" zones=() i choice domain
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
            read -e -r -p "${purpose}自定义前缀 [${default_prefix}]: " prefix
            prefix=${prefix:-$default_prefix}
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
    local dns_mode="${6:-auto}" node_domain_v4="${7:-}" node_domain_v6="${8:-}" port_v6="${9:-}"
    local node_name_v4="${10:-}" node_name_v6="${11:-}"
    dns_mode=$(reality_normalize_dns_mode "$dns_mode") || { print_error "网络/DNS 模式无效"; return 1; }
    validate_domain "$sni" || { print_error "SNI 域名无效"; return 1; }
    validate_port "$port" || { print_error "端口无效"; return 1; }
    reality_warn_sni_risk "$sni"
    reality_warn_port_risk "$port" "Reality"
    [[ -z "$node_name" ]] || reality_validate_node_name "$node_name" || { print_error "节点名称无效"; return 1; }
    # 443 共存已开时的重装防护：render 会走 loopback 分支（reality_coexist_reality_port 有值即触发），
    # 此时若本次端口非 443，客户端链接会指向一个既不监听、也不被 stream 覆盖的端口 → 静默不可达；
    # 若本次是 split，coexist 分支优先于 split 分支渲染，只出单入站会丢掉 IPv6 节点。故一律拦下。
    if reality_coexist_enabled 2>/dev/null; then
        if [[ "$dns_mode" == "split" ]]; then
            print_error "当前已启用 443 共存模式，暂不支持以 split 双节点模式重装落地机。"
            print_info "请先用菜单「关闭 443 共存模式」再重装，或改用单节点模式。"
            return 1
        fi
        if [[ "$port" != "443" ]]; then
            print_error "当前已启用 443 共存模式，重装落地机的端口必须为 443（对外由 nginx stream 持有）。"
            print_info "本次端口为 ${port}，非 443。请以 443 重装，或先关闭 443 共存模式再用其他端口。"
            return 1
        fi
    fi
    if [[ "$dns_mode" == "split" ]]; then
        node_domain_v4="${node_domain_v4:-$node_domain}"
        validate_domain "$node_domain_v4" || { print_error "IPv4 节点域名无效"; return 1; }
        validate_domain "$node_domain_v6" || { print_error "IPv6 节点域名无效"; return 1; }
        [[ "$node_domain_v4" != "$node_domain_v6" ]] || { print_error "双节点模式下 IPv4/IPv6 域名不能相同"; return 1; }
        validate_port "$port_v6" || { print_error "IPv6 端口无效"; return 1; }
        reality_warn_port_risk "$port_v6" "IPv6 Reality"
        [[ -z "$node_name_v4" ]] || reality_validate_node_name "$node_name_v4" || { print_error "IPv4 节点名称无效"; return 1; }
        [[ -z "$node_name_v6" ]] || reality_validate_node_name "$node_name_v6" || { print_error "IPv6 节点名称无效"; return 1; }
    else
        validate_domain "$node_domain" || { print_error "节点域名无效"; return 1; }
    fi
    reality_load_state || true
    if reality_port_reserved_except_current_landing "$port"; then
        print_error "Reality 端口已被本项目其他功能保留: ${port}"
        return 1
    fi
    if [[ "$dns_mode" == "split" ]]; then
        if reality_port_reserved_except_current_landing "$port_v6"; then
            print_error "IPv6 Reality 端口已被本项目其他功能保留: ${port_v6}"
            return 1
        fi
    fi
    local had_relay=0
    [[ "${REALITY_ROLE:-}" == *"relay"* ]] && had_relay=1
    reality_install_singbox_official || return 1
    REALITY_UUID=$(reality_generate_uuid) || return 1
    local keys
    keys=$(reality_generate_keypair) || { print_error "生成 Reality keypair 失败"; return 1; }
    REALITY_PRIVATE_KEY=$(sed -n '1p' <<< "$keys")
    REALITY_PUBLIC_KEY=$(sed -n '2p' <<< "$keys")
    REALITY_SHORT_ID=$(reality_generate_short_id)
    # 客户端指纹：重装保留旧节点已定的指纹（reality_load_state 已回读），
    # 全新安装则随机挑一个真实浏览器指纹并持久化（分散全网 fp=chrome 特征）。
    if [[ -z "${REALITY_FINGERPRINT:-}" ]]; then
        REALITY_FINGERPRINT=$(reality_random_fingerprint)
    else
        REALITY_FINGERPRINT=$(reality_sanitize_fingerprint "$REALITY_FINGERPRINT")
    fi
    if [[ "$had_relay" -eq 1 ]]; then
        REALITY_ROLE="landing+relay"
    else
        REALITY_ROLE="landing"
    fi
    REALITY_NODE_NAME="$node_name"
    REALITY_DNS_MODE="$dns_mode"
    REALITY_SNI="$sni"
    REALITY_PORT="$port"
    REALITY_PORT_V6=""
    REALITY_NODE_DOMAIN_V4=""
    REALITY_NODE_DOMAIN_V6=""
    REALITY_NODE_NAME_V4=""
    REALITY_NODE_NAME_V6=""
    REALITY_LISTEN_HOST_V4=""
    REALITY_LISTEN_HOST_V6=""
    if [[ "$dns_mode" == "split" ]]; then
        REALITY_NODE_DOMAIN="$node_domain_v4"
        REALITY_NODE_DOMAIN_V4="$node_domain_v4"
        REALITY_NODE_DOMAIN_V6="$node_domain_v6"
        REALITY_PORT_V6="$port_v6"
        REALITY_NODE_NAME_V4="${node_name_v4:-$(reality_node_name_with_suffix "${node_name:-$(reality_default_node_name)}" "-ipv4")}"
        REALITY_NODE_NAME_V6="${node_name_v6:-$(reality_node_name_with_suffix "${node_name:-$(reality_default_node_name)}" "-ipv6")}"
        REALITY_LISTEN_HOST_V4=""
        REALITY_LISTEN_HOST_V6=""
        reality_prepare_split_listen_hosts "$REALITY_PORT" "$REALITY_PORT_V6" || return 1
    else
        REALITY_NODE_DOMAIN="$node_domain"
        case "$dns_mode" in
            ipv4) REALITY_LISTEN_HOST="0.0.0.0" ;;
            ipv6) REALITY_LISTEN_HOST="::" ;;
            *)
                # 重新探测监听地址：IPv6-only / 双栈机器绑定 ::，纯 IPv4 机器绑定 0.0.0.0。
                # 每次安装都重新探测，使旧节点重装即自愈为正确的绑定地址。
                REALITY_LISTEN_HOST="$(reality_detect_listen_host)"
                ;;
        esac
    fi
    local new_config
    new_config=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") || return 1
    local _fw_rc _fw_need_setup=0 _fw_port
    for _fw_port in "$REALITY_PORT" "${REALITY_PORT_V6:-}"; do
        [[ -n "$_fw_port" ]] || continue
        firewall_apply_reality_port "$_fw_port"
        _fw_rc=$?
        if [[ $_fw_rc -eq 1 ]]; then
            return 1
        elif [[ $_fw_rc -eq 2 ]]; then
            _fw_need_setup=1
        fi
    done
    if [[ $_fw_need_setup -eq 1 ]]; then
        if [[ -t 0 ]] && confirm "UFW 未启用，是否现在跳转防火墙菜单启用并放行 Reality 端口?"; then
            ufw_setup
            for _fw_port in "$REALITY_PORT" "${REALITY_PORT_V6:-}"; do
                [[ -n "$_fw_port" ]] || continue
                firewall_apply_reality_port "$_fw_port" || \
                    print_warn "UFW 仍未生效，请确认云安全组已放行 ${_fw_port}/tcp"
            done
        else
            print_warn "已跳过本地防火墙配置，请确认云安全组已放行 Reality 端口: ${REALITY_PORT}${REALITY_PORT_V6:+/${REALITY_PORT_V6}}/tcp"
        fi
    fi
    systemctl enable sing-box >/dev/null || return 1
    reality_apply_singbox_config "$new_config" || return 1
    [[ -n "$cf_token" ]] && reality_sync_cloudflare_dns_by_state "$cf_token"
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

reality_select_realm_asset_url() {
    local api="$1" arch="$2" url=""
    url=$(grep -Eo "https://[^\" ]+/realm-${arch}\.tar\.gz" <<< "$api" | head -n 1)
    if [[ -z "$url" ]]; then
        url=$(grep -Eo "https://[^\" ]+/realm-slim-${arch}\.tar\.gz" <<< "$api" | head -n 1)
    fi
    [[ -n "$url" ]] || return 1
    printf '%s\n' "$url"
}

reality_select_realm_checksum_url() {
    local api="$1" asset_url="$2" asset_name checksum_url=""
    asset_name="$(basename "$asset_url")"
    checksum_url=$(grep -Eo "https://[^\" ]+/${asset_name}\.(sha256|sha256sum|sha256.txt)" <<< "$api" | head -n 1)
    if [[ -z "$checksum_url" ]]; then
        checksum_url=$(grep -Eo 'https://[^" ]+/(SHA256SUMS|sha256sums\.txt|checksums\.txt|checksum\.txt)' <<< "$api" | head -n 1)
    fi
    [[ -n "$checksum_url" ]] || return 1
    printf '%s\n' "$checksum_url"
}

reality_verify_sha256_file() {
    local file="$1" checksum_file="$2" asset_name hash line
    asset_name="${3:-$(basename "$file")}"
    command_exists sha256sum || { print_error "缺少 sha256sum，无法校验下载文件"; return 1; }
    line=$(grep -F "$asset_name" "$checksum_file" 2>/dev/null | head -n 1 || true)
    if [[ -n "$line" ]]; then
        hash=$(awk '{print $1}' <<< "$line")
    else
        hash=$(grep -Eo '^[a-fA-F0-9]{64}' "$checksum_file" | head -n 1)
    fi
    [[ "$hash" =~ ^[a-fA-F0-9]{64}$ ]] || { print_error "无法解析 sha256 校验文件"; return 1; }
    printf '%s  %s\n' "$hash" "$file" | sha256sum -c - >/dev/null
}

reality_find_realm_binary() {
    local dir="$1" bin=""
    bin=$(find "$dir" -type f -name realm -print -quit 2>/dev/null)
    if [[ -z "$bin" ]]; then
        bin=$(find "$dir" -type f \( -name 'realm-*' -o -name 'realm' \) ! -name '*.sha*' ! -name '*.txt' -print 2>/dev/null | sort | head -n 1)
    fi
    [[ -n "$bin" ]] || return 1
    printf '%s\n' "$bin"
}

# 上游 zhboner/realm 发布包不附带任何 sha256/SHA256SUMS 校验文件，
# 因此固定 Realm 版本并内置各架构校验值，既保留"下载后强制 sha256 校验"，
# 又避免"校验文件缺失即拒绝安装"导致中转链路永远装不上。
# 升级版本时需同步更新此处版本号与对应 sha256（来自官方发布包）。
REALITY_REALM_VERSION="${REALITY_REALM_VERSION:-v2.9.4}"

reality_realm_pinned_sha256() {
    case "$1" in
        x86_64-unknown-linux-gnu)  echo "9dec109386b8abc828b452d0d1cecde35b7a2f8cfa93eae757fe9c248ad07ddd" ;;
        aarch64-unknown-linux-gnu) echo "1f7f06e82fe0ea798b5c8e8e32906ee212a7085629a1c5cef9957ca270fcad99" ;;
        *) return 1 ;;
    esac
}

reality_install_realm_binary() {
    command_exists curl || install_package "curl" "silent" || return 1
    command_exists tar || install_package "tar" "silent" || true
    if command_exists realm; then return 0; fi
    local arch expected url tmp bin asset_name old_umask rc
    arch=$(reality_realm_arch) || { print_error "Realm 不支持当前架构"; return 1; }
    expected=$(reality_realm_pinned_sha256 "$arch") || { print_error "无内置 Realm ${arch} 校验值，已拒绝安装"; return 1; }
    asset_name="realm-${arch}.tar.gz"
    url="https://github.com/zhboner/realm/releases/download/${REALITY_REALM_VERSION}/${asset_name}"
    old_umask=$(umask)
    umask 077
    tmp=$(mktemp -d "${TMPDIR:-/tmp}/server-manage-realm.XXXXXX")
    rc=$?
    umask "$old_umask"
    [[ "$rc" -eq 0 ]] || return 1
    chmod 700 "$tmp" 2>/dev/null || true
    curl -fsSL "$url" -o "$tmp/realm.tgz" || { print_error "Realm 发布包下载失败"; rm -rf "$tmp"; return 1; }
    # 用内置校验值生成本地 checksum 文件，复用统一校验 helper（含 sha256sum -c）。
    printf '%s  %s\n' "$expected" "$asset_name" > "$tmp/realm.sha256"
    reality_verify_sha256_file "$tmp/realm.tgz" "$tmp/realm.sha256" "$asset_name" || {
        print_error "Realm 发布包 sha256 校验失败，已拒绝安装"; rm -rf "$tmp"; return 1
    }
    tar -xzf "$tmp/realm.tgz" -C "$tmp" || { rm -rf "$tmp"; return 1; }
    bin=$(reality_find_realm_binary "$tmp") || { print_error "Realm 发布包中未找到可安装二进制"; rm -rf "$tmp"; return 1; }
    _reality_install_realm_binary_file "$bin" "$(_reality_realm_bin_path)" || { rm -rf "$tmp"; return 1; }
    rm -rf "$tmp"
}

# ============================================================================
# 多路中转（A 既做落地、又同时给多台落地机 B/C/D… 做 Realm TCP 中转）
# 每条线路独立存储自己的落地 Reality 身份，互不串扰；relays 目录是 realm 配置的
# 唯一真相源。客户端复用本机域名、用不同监听端口区分各条线路。
# ============================================================================

# 列出全部中转线路文件（稳定排序）
reality_relay_route_files() {
    [[ -d "$REALITY_RELAY_DIR" ]] || return 0
    find "$REALITY_RELAY_DIR" -maxdepth 1 -type f -name 'relay-*.conf' 2>/dev/null | sort
}

reality_relay_next_port() {
    local base="${REALITY_RELAY_PORT_BASE:-35101}" max port f start
    validate_port "$base" || base="35101"
    max=$((base - 1))
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        port="$(grep -E '^RLY_LISTEN_PORT=' "$f" 2>/dev/null | head -n1 | sed -E 's/^RLY_LISTEN_PORT=["'\'']?([0-9]+)["'\'']?.*/\1/')"
        validate_port "$port" || continue
        (( port > max )) && max="$port"
    done < <(reality_relay_route_files)
    start=$((max + 1))
    (( start < base )) && start="$base"
    for port in $(seq "$start" 65535); do
        reality_port_reserved "$port" && continue
        reality_port_in_use "$port" && continue
        printf '%s\n' "$port"
        return 0
    done
    return 1
}

# 校验并加载一条线路到 RLY_* 全局；校验失败跳过
reality_relay_load_route() {
    local file="$1"
    [[ -f "$file" ]] || return 1
    validate_conf_file "$file" || { print_warn "中转线路文件校验失败，已跳过: $file"; return 1; }
    RLY_NAME=""; RLY_LISTEN_PORT=""; RLY_CONNECT_HOST=""; RLY_TARGET_HOST=""; RLY_TARGET_PORT=""
    RLY_UUID=""; RLY_SNI=""; RLY_PUBLIC_KEY=""; RLY_SHORT_ID=""; RLY_FLOW=""; RLY_FINGERPRINT=""
    # shellcheck disable=SC1090
    source "$file"
}

reality_host_resolves() {
    local host="$1"
    [[ -n "$host" ]] || return 1
    validate_ip "$host" 2>/dev/null && return 0
    [[ "$host" == *:* ]] && return 0
    if command_exists getent; then
        getent ahosts "$host" >/dev/null 2>&1 && return 0
        return 1
    fi
    if command_exists python3; then
        python3 - "$host" <<'PY' >/dev/null 2>&1
import socket
import sys
socket.getaddrinfo(sys.argv[1], None)
PY
        return $?
    fi
    return 2
}

reality_tcp_connect_check() {
    local host="$1" port="$2" timeout_s="${3:-5}"
    [[ -n "$host" ]] && validate_port "$port" || return 1
    if command_exists nc; then
        if command_exists timeout; then
            timeout "$((timeout_s + 2))" nc -z -w "$timeout_s" "$host" "$port" >/dev/null 2>&1
        else
            nc -z -w "$timeout_s" "$host" "$port" >/dev/null 2>&1
        fi
        return $?
    fi
    if command_exists python3; then
        python3 - "$host" "$port" "$timeout_s" <<'PY' >/dev/null 2>&1
import socket
import sys
host = sys.argv[1]
port = int(sys.argv[2])
timeout_s = float(sys.argv[3])
with socket.create_connection((host, port), timeout_s):
    pass
PY
        return $?
    fi
    return 2
}

reality_relay_preflight_route() {
    local mode="${1:-new}" rc=0 dns_rc tcp_rc public_ip dns_ip
    validate_port "${RLY_LISTEN_PORT:-}" || { print_error "中转监听端口无效: ${RLY_LISTEN_PORT:-空}"; return 1; }
    validate_domain "${RLY_CONNECT_HOST:-}" || validate_ip "${RLY_CONNECT_HOST:-}" || { print_error "中转连接域名/IP 无效: ${RLY_CONNECT_HOST:-空}"; return 1; }
    validate_domain "${RLY_TARGET_HOST:-}" || validate_ip "${RLY_TARGET_HOST:-}" || { print_error "落地地址无效: ${RLY_TARGET_HOST:-空}"; return 1; }
    validate_port "${RLY_TARGET_PORT:-}" || { print_error "落地端口无效: ${RLY_TARGET_PORT:-空}"; return 1; }
    [[ -n "${RLY_UUID:-}" && -n "${RLY_SNI:-}" && -n "${RLY_PUBLIC_KEY:-}" && -n "${RLY_SHORT_ID:-}" ]] || {
        print_error "中转线路缺少 Reality 客户端身份(uuid/sni/pbk/sid)"
        return 1
    }
    if [[ "$mode" != "existing" && -f "$REALITY_RELAY_DIR/relay-${RLY_LISTEN_PORT}.conf" ]]; then
        print_error "该端口已有中转线路: ${RLY_LISTEN_PORT}"
        return 1
    fi
    if [[ "$mode" != "existing" ]] && reality_port_reserved "$RLY_LISTEN_PORT"; then
        print_error "中转端口已被本项目其他功能保留: ${RLY_LISTEN_PORT}"
        return 1
    fi
    if [[ "$mode" != "existing" ]] && reality_port_in_use "$RLY_LISTEN_PORT"; then
        print_error "中转端口已被占用: ${RLY_LISTEN_PORT}"
        return 1
    fi

    if validate_domain "$RLY_TARGET_HOST"; then
        reality_host_resolves "$RLY_TARGET_HOST"; dns_rc=$?
        if [[ "$dns_rc" -eq 1 ]]; then
            print_error "落地域名无法解析: ${RLY_TARGET_HOST}"
            rc=1
        elif [[ "$dns_rc" -eq 2 ]]; then
            print_warn "缺少 DNS 检查工具(getent/python3)，已跳过落地域名解析预检"
        fi
    fi
    reality_tcp_connect_check "$RLY_TARGET_HOST" "$RLY_TARGET_PORT" "${REALITY_RELAY_PREFLIGHT_TIMEOUT:-5}"; tcp_rc=$?
    if [[ "$tcp_rc" -eq 1 ]]; then
        print_error "中转机无法 TCP 连接落地: ${RLY_TARGET_HOST}:${RLY_TARGET_PORT}"
        rc=1
    elif [[ "$tcp_rc" -eq 2 ]]; then
        print_warn "缺少 TCP 检查工具(nc/python3)，已跳过落地端口预检"
    fi

    if validate_domain "$RLY_CONNECT_HOST"; then
        if declare -F get_public_ipv4 >/dev/null 2>&1; then
            public_ip="$(get_public_ipv4 2>/dev/null || true)"
        else
            public_ip=""
        fi
        dns_ip="$(reality_resolve_public_a "$RLY_CONNECT_HOST" 2>/dev/null || true)"
        if [[ -n "$public_ip" && -n "$dns_ip" && "$public_ip" != "$dns_ip" ]]; then
            if [[ "${REALITY_RELAY_STRICT_CONNECT_DNS:-0}" == "1" ]]; then
                print_error "中转域名 A 记录(${dns_ip})与本机公网 IPv4(${public_ip})不一致: ${RLY_CONNECT_HOST}"
                rc=1
            else
                print_warn "中转域名 A 记录(${dns_ip})与本机公网 IPv4(${public_ip})不一致: ${RLY_CONNECT_HOST}"
            fi
        fi
    fi
    return "$rc"
}

# 用当前 RLY_* 写出一条线路文件（值经 reality_state_quote，满足 validate_conf_file）
reality_relay_write_route() {
    local port="$1" file
    file="$REALITY_RELAY_DIR/relay-${port}.conf"
    mkdir -p "$REALITY_RELAY_DIR"
    chmod 700 "$REALITY_RELAY_DIR" 2>/dev/null || true
    local content
    content=$(cat <<EOF
RLY_NAME=$(reality_state_quote "${RLY_NAME:-}")
RLY_LISTEN_PORT=$(reality_state_quote "${RLY_LISTEN_PORT:-}")
RLY_CONNECT_HOST=$(reality_state_quote "${RLY_CONNECT_HOST:-}")
RLY_TARGET_HOST=$(reality_state_quote "${RLY_TARGET_HOST:-}")
RLY_TARGET_PORT=$(reality_state_quote "${RLY_TARGET_PORT:-}")
RLY_UUID=$(reality_state_quote "${RLY_UUID:-}")
RLY_SNI=$(reality_state_quote "${RLY_SNI:-}")
RLY_PUBLIC_KEY=$(reality_state_quote "${RLY_PUBLIC_KEY:-}")
RLY_SHORT_ID=$(reality_state_quote "${RLY_SHORT_ID:-}")
RLY_FLOW=$(reality_state_quote "${RLY_FLOW:-}")
RLY_FINGERPRINT=$(reality_state_quote "${RLY_FINGERPRINT:-}")
EOF
)
    reality_write_secure_file "$file" "$content"
}

# 用当前 RLY_* 写该线路客户端链接/JSON（身份=落地机，host:port=本机中转入口）
reality_relay_write_client_artifacts() {
    local port="${RLY_LISTEN_PORT:-}" host="${RLY_CONNECT_HOST:-}" name="${RLY_NAME:-relay-${RLY_LISTEN_PORT:-0}}" json_name
    [[ -n "$host" && -n "$port" && -n "${RLY_UUID:-}" && -n "${RLY_SNI:-}" && -n "${RLY_PUBLIC_KEY:-}" && -n "${RLY_SHORT_ID:-}" ]] || return 1
    validate_port "$port" || return 1
    mkdir -p "$REALITY_RELAY_DIR"
    chmod 700 "$REALITY_RELAY_DIR" 2>/dev/null || true
    json_name=$(reality_json_escape "$name")
    local json_host; json_host=$(reality_json_escape "$host")
    local json_uuid; json_uuid=$(reality_json_escape "$RLY_UUID")
    local json_sni; json_sni=$(reality_json_escape "$RLY_SNI")
    local json_public_key; json_public_key=$(reality_json_escape "$RLY_PUBLIC_KEY")
    local json_short_id; json_short_id=$(reality_json_escape "$RLY_SHORT_ID")
    local rly_fp rly_flow; rly_fp=$(reality_sanitize_fingerprint "${RLY_FINGERPRINT:-}")
    rly_flow="${RLY_FLOW:-xtls-rprx-vision}"
    local link_path="${REALITY_RELAY_DIR}/relay-${port}.link.txt"
    local json_path="${REALITY_RELAY_DIR}/relay-${port}.client.json"
    local link_content json_content
    link_content="$(reality_build_vless_link "$RLY_UUID" "$host" "$port" "$RLY_SNI" "$RLY_PUBLIC_KEY" "$RLY_SHORT_ID" "$name" "$rly_fp" "$rly_flow")" || return 1
    json_content=$(cat <<EOF
{"type":"vless","tag":"${json_name}","server":"${json_host}","server_port":${port},"uuid":"${json_uuid}","flow":"${rly_flow}","tls":{"enabled":true,"server_name":"${json_sni}","utls":{"enabled":true,"fingerprint":"${rly_fp}"},"reality":{"enabled":true,"public_key":"${json_public_key}","short_id":"${json_short_id}"}}}
EOF
)
    reality_write_secure_file "$link_path" "$link_content" || return 1
    reality_write_secure_file "$json_path" "$json_content" || return 1
}

reality_relay_validate_route() {
    local expected_exit_ip="${1:-}" test_url="${REALITY_RELAY_TEST_URL:-https://api.ipify.org}" tmp_dir cfg log curl_log pid_file pid test_port i out rc status="failed" json_path
    command_exists sing-box || { print_warn "sing-box 不存在，跳过中转端到端验证"; return 2; }
    command_exists curl || { print_warn "curl 不存在，跳过中转端到端验证"; return 2; }
    test_port="${REALITY_RELAY_SELFTEST_PORT:-}"
    if [[ -z "$test_port" ]]; then
        for i in $(seq 1 100); do
            test_port=$((19090 + i))
            reality_port_in_use "$test_port" || break
        done
    fi
    validate_port "$test_port" || return 1
    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/reality-relay-test.XXXXXX") || return 1
    chmod 700 "$tmp_dir" 2>/dev/null || true
    cfg="$tmp_dir/client.json"
    log="$tmp_dir/sing-box.log"
    curl_log="$tmp_dir/curl.log"
    pid_file="$tmp_dir/sing-box.pid"
    json_path="${REALITY_RELAY_DIR}/relay-${RLY_LISTEN_PORT}.health.json"
    local rly_fp rly_flow json_name json_host json_uuid json_sni json_public_key json_short_id
    rly_fp=$(reality_sanitize_fingerprint "${RLY_FINGERPRINT:-}")
    rly_flow="${RLY_FLOW:-xtls-rprx-vision}"
    json_name=$(reality_json_escape "${RLY_NAME:-relay-${RLY_LISTEN_PORT:-0}}")
    json_host=$(reality_json_escape "$RLY_CONNECT_HOST")
    json_uuid=$(reality_json_escape "$RLY_UUID")
    json_sni=$(reality_json_escape "$RLY_SNI")
    json_public_key=$(reality_json_escape "$RLY_PUBLIC_KEY")
    json_short_id=$(reality_json_escape "$RLY_SHORT_ID")
    cat > "$cfg" <<EOF
{"log":{"level":"warn","timestamp":true},"inbounds":[{"type":"mixed","tag":"mixed-in","listen":"127.0.0.1","listen_port":${test_port}}],"outbounds":[{"type":"vless","tag":"${json_name}","server":"${json_host}","server_port":${RLY_LISTEN_PORT},"uuid":"${json_uuid}","flow":"${rly_flow}","tls":{"enabled":true,"server_name":"${json_sni}","utls":{"enabled":true,"fingerprint":"${rly_fp}"},"reality":{"enabled":true,"public_key":"${json_public_key}","short_id":"${json_short_id}"}}},{"type":"direct","tag":"direct"}],"route":{"final":"${json_name}"}}
EOF
    if ! sing-box check -c "$cfg" > "$log" 2>&1; then
        print_warn "中转客户端配置自检失败"
        sed -E 's/[0-9a-fA-F-]{36}/<uuid>/g' "$log" 2>/dev/null | tail -n 20 || true
        rm -rf "$tmp_dir"
        return 1
    fi
    ( sing-box run -c "$cfg" >> "$log" 2>&1 & echo $! > "$pid_file" )
    pid=$(cat "$pid_file" 2>/dev/null || true)
    for i in $(seq 1 30); do
        ss -ltn 2>/dev/null | grep -q ":${test_port} " && break
        sleep 0.2
    done
    if out=$(curl -4 -sS --max-time "${REALITY_RELAY_VALIDATE_TIMEOUT:-25}" --socks5-hostname "127.0.0.1:${test_port}" "$test_url" 2>"$curl_log"); then
        rc=0
    else
        rc=$?
    fi
    [[ -n "$pid" ]] && kill "$pid" >/dev/null 2>&1 || true
    [[ -n "$pid" ]] && wait "$pid" >/dev/null 2>&1 || true
    mkdir -p "$REALITY_RELAY_DIR"
    if [[ "$rc" -eq 0 && ( -z "$expected_exit_ip" || "$out" == "$expected_exit_ip" ) ]]; then
        status="ok"
        print_success "中转端到端验证通过: ${RLY_CONNECT_HOST}:${RLY_LISTEN_PORT} 出口 ${out}"
    elif [[ "$rc" -eq 0 ]]; then
        status="mismatch"
        print_warn "中转端到端验证出口不符: got=${out} expected=${expected_exit_ip}"
    else
        status="failed"
        print_warn "中转端到端验证失败，最近日志:"
        tail -n 10 "$curl_log" 2>/dev/null || true
        sed -E 's/[0-9a-fA-F-]{36}/<uuid>/g' "$log" 2>/dev/null | tail -n 20 || true
    fi
    cat > "$json_path" <<EOF
{"route":"${json_name}","listen_port":${RLY_LISTEN_PORT},"connect_host":"${json_host}","target_host":"$(reality_json_escape "${RLY_TARGET_HOST:-}")","target_port":${RLY_TARGET_PORT:-0},"status":"${status}","exit_ip":"$(reality_json_escape "$out")","expected_exit_ip":"$(reality_json_escape "$expected_exit_ip")","checked_at":"$(date -Is 2>/dev/null || date)"}
EOF
    chmod 600 "$json_path" 2>/dev/null || true
    rm -rf "$tmp_dir"
    [[ "$status" == "ok" ]]
}

# 由全部线路渲染 realm 多端点配置（保持单端点格式：log.level + [[endpoints]]）
reality_render_realm_config_multi() {
    local f listen_host
    # 经 reality_detect_listen_host 解析，避免 split 哨兵值直接当 bind 地址渲染出 listen = "split:<port>"
    listen_host="$(reality_detect_listen_host)"
    echo 'log.level = "warn"'
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        reality_relay_load_route "$f" || continue
        validate_port "$RLY_LISTEN_PORT" || continue
        [[ -n "$RLY_TARGET_HOST" && -n "$RLY_TARGET_PORT" ]] || continue
        cat <<EOF

[[endpoints]]
listen = "$(reality_listen_endpoint "$listen_host" "$RLY_LISTEN_PORT")"
remote = "$(reality_listen_endpoint "$RLY_TARGET_HOST" "$RLY_TARGET_PORT")"
EOF
    done < <(reality_relay_route_files)
}

# 写 realm systemd 单元
reality_relay_ensure_service() {
    _reality_install_realm_service_unit || return 1
    systemctl daemon-reload
}

# 旧版单中转字段（REALITY_RELAY_*）一次性迁移为一条线路
reality_relay_migrate_legacy() {
    [[ -n "${REALITY_RELAY_TARGET_HOST:-}" && -n "${REALITY_RELAY_PORT:-}" ]] || return 0
    [[ -z "$(reality_relay_route_files)" ]] || return 0
    validate_port "$REALITY_RELAY_PORT" || return 0
    RLY_NAME="$(reality_effective_node_name)"
    RLY_LISTEN_PORT="$REALITY_RELAY_PORT"
    RLY_CONNECT_HOST="${REALITY_RELAY_DOMAIN:-${REALITY_NODE_DOMAIN:-}}"
    RLY_TARGET_HOST="$REALITY_RELAY_TARGET_HOST"
    RLY_TARGET_PORT="${REALITY_RELAY_TARGET_PORT:-}"
    RLY_UUID="${REALITY_UUID:-}"; RLY_SNI="${REALITY_SNI:-}"
    RLY_PUBLIC_KEY="${REALITY_PUBLIC_KEY:-}"; RLY_SHORT_ID="${REALITY_SHORT_ID:-}"
    RLY_FLOW="${REALITY_FLOW:-xtls-rprx-vision}"
    RLY_FINGERPRINT="${REALITY_FINGERPRINT:-}"
    reality_relay_write_route "$RLY_LISTEN_PORT"
    reality_relay_write_client_artifacts || true
    REALITY_RELAY_DOMAIN=""; REALITY_RELAY_PORT=""
    REALITY_RELAY_TARGET_HOST=""; REALITY_RELAY_TARGET_PORT=""
    reality_write_state
}

# 根据 relays 目录重建 realm 配置、放行端口、刷新各线路客户端产物并重启 realm
reality_relay_regenerate() {
    local realm_config
    realm_config="$(_reality_realm_config_path)"
    _reality_abs_system_path "$realm_config" || return 1
    mkdir -p "$(dirname "$realm_config")" "$REALITY_CONFIG_DIR" "$REALITY_RELAY_DIR"
    reality_relay_migrate_legacy
    if [[ -z "$(reality_relay_route_files)" ]]; then
        systemctl disable --now realm >/dev/null 2>&1 || true
        rm -f "$realm_config"
        return 0
    fi
    reality_install_realm_binary || return 1
    reality_backup_file "$realm_config"
    # 临时文件落在目标目录(/etc/realm)内，确保下方 mv 是同文件系统的原子 rename
    # （mktemp 默认落 /tmp 会跨文件系统退化为 copy+delete 且受目标 umask 影响）。
    mkdir -p "$(dirname "$realm_config")"
    local _tmp_cfg; _tmp_cfg="$(mktemp "$(dirname "$realm_config")/.realm.XXXXXX")" || return 1
    reality_render_realm_config_multi > "$_tmp_cfg"
    # LOW-1：只数有效端点。若路由文件都校验失败→0 端点，不能拿空配置 restart realm
    # （会启动一个空转/或静默“成功”的服务，且旧转发被静默丢弃）。此时保留旧配置并报错。
    # grep -c 匹配 0 次时输出 "0" 但退出码为 1；不要在后面追加 echo 0（会变成 "0\n0"
    # 触发算术比较语法错误）。改用 grep -o | wc -l，始终单行数字、退出码无关。
    local _ep_count; _ep_count="$(grep -o '^\[\[endpoints\]\]' "$_tmp_cfg" 2>/dev/null | wc -l | tr -d '[:space:]')"
    if [[ "${_ep_count:-0}" -eq 0 ]]; then
        rm -f "$_tmp_cfg"
        print_error "所有中转线路文件校验失败，渲染出 0 个端点；已保留原 realm 配置，未重启。"
        return 1
    fi
    mv -f "$_tmp_cfg" "$realm_config"
    chmod 600 "$realm_config"
    reality_relay_ensure_service
    local f
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        reality_relay_load_route "$f" || continue
        validate_port "$RLY_LISTEN_PORT" || continue
        firewall_apply_realm_port "$RLY_LISTEN_PORT" >/dev/null 2>&1 || true
        reality_relay_write_client_artifacts || true
    done < <(reality_relay_route_files)
    systemctl enable realm >/dev/null 2>&1 || true
    if ! systemctl restart realm; then
        # restart 失败：恢复最近一次备份配置（若有），避免留下坏配置继续对外。
        local _bak
        _bak="$(ls -1t "$REALITY_BACKUP_DIR/$(basename "$realm_config")".*.bak 2>/dev/null | head -n1)"
        if [[ -n "$_bak" && -f "$_bak" ]]; then
            cp -a "$_bak" "$realm_config" 2>/dev/null || true
            systemctl restart realm >/dev/null 2>&1 || true
        fi
        print_error "realm 重启失败，已尝试恢复上一版配置。"
        return 1
    fi
    return 0
}

# 交互：添加一条中转线路（导入下游落地 vless 链接）
reality_relay_add() {
    print_title "添加中转线路（导入落地 vless 链接）"
    reality_require_supported_os || return 1
    reality_load_state || true
    local link=""
    read -e -r -p "粘贴落地机 vless:// 链接 (留空取消): " link
    [[ -n "$link" ]] || { print_info "已取消"; pause; return 0; }
    # 快照本机落地身份，避免被链接解析覆盖
    local _s_uuid="${REALITY_UUID:-}" _s_node="${REALITY_NODE_DOMAIN:-}" _s_port="${REALITY_PORT:-}" \
          _s_sni="${REALITY_SNI:-}" _s_pbk="${REALITY_PUBLIC_KEY:-}" _s_sid="${REALITY_SHORT_ID:-}" _s_flow="${REALITY_FLOW:-}" \
          _s_fp="${REALITY_FINGERPRINT:-}"
    reality_parse_vless_link "$link" || { print_error "落地机 vless 链接解析失败"; pause; return 1; }
    RLY_TARGET_HOST="$REALITY_NODE_DOMAIN"; RLY_TARGET_PORT="$REALITY_PORT"
    RLY_UUID="$REALITY_UUID"; RLY_SNI="$REALITY_SNI"; RLY_PUBLIC_KEY="$REALITY_PUBLIC_KEY"
    RLY_SHORT_ID="$REALITY_SHORT_ID"; RLY_FLOW="${REALITY_FLOW:-xtls-rprx-vision}"
    # 中转客户端指纹沿用导入链接里的 fp（真实落地机身份的一部分）；链接无 fp 时留空→回退 chrome。
    RLY_FINGERPRINT="${REALITY_FINGERPRINT:-}"
    # 恢复本机落地身份
    REALITY_UUID="$_s_uuid"; REALITY_NODE_DOMAIN="$_s_node"; REALITY_PORT="$_s_port"
    REALITY_SNI="$_s_sni"; REALITY_PUBLIC_KEY="$_s_pbk"; REALITY_SHORT_ID="$_s_sid"; REALITY_FLOW="$_s_flow"
    REALITY_FINGERPRINT="$_s_fp"
    validate_domain "$RLY_TARGET_HOST" || validate_ip "$RLY_TARGET_HOST" || { print_error "落地地址无效"; pause; return 1; }
    validate_port "$RLY_TARGET_PORT" || { print_error "落地端口无效"; pause; return 1; }
    [[ -n "$RLY_PUBLIC_KEY" && -n "$RLY_UUID" && -n "$RLY_SHORT_ID" ]] || { print_error "链接缺少 Reality 参数(pbk/uuid/sid)"; pause; return 1; }
    # 解析结果核对页（任意 read 处输入 0/q 可取消返回）
    draw_line
    echo "已解析落地机参数，请核对:"
    echo "  转发目标 : ${RLY_TARGET_HOST}:${RLY_TARGET_PORT}"
    echo "  SNI      : ${RLY_SNI}"
    echo "  UUID     : $(reality_mask_secret "$RLY_UUID")"
    echo "  公钥(pbk): $(reality_mask_secret "$RLY_PUBLIC_KEY")"
    echo "  ShortID  : ${RLY_SHORT_ID}"
    draw_line
    confirm "以上落地参数是否正确?" || { print_info "已取消"; pause; return 0; }
    # 客户端连接域名：默认复用本机落地/中转域名，可覆盖
    local connect_default="${REALITY_NODE_DOMAIN:-${REALITY_RELAY_DOMAIN:-}}" in_host=""
    RLY_CONNECT_HOST=""
    while [[ -z "$RLY_CONNECT_HOST" ]]; do
        read -e -r -p "客户端连接本机的域名/IP [${connect_default:-必填}] (0=取消): " in_host
        in_host="${in_host:-$connect_default}"
        [[ "$in_host" == "0" || "$in_host" == "q" ]] && { print_info "已取消"; pause; return 0; }
        validate_domain "$in_host" || validate_ip "$in_host" || { print_error "地址无效"; continue; }
        RLY_CONNECT_HOST="$in_host"
    done
    [[ "$RLY_CONNECT_HOST" == "$connect_default" && -n "$connect_default" ]] && echo "（复用本机域名，按端口区分线路）"
    # 监听端口：唯一、未占用、不等于本机落地端口；优先推荐 443，无法使用时按已有 relay 最大端口递增。
    local def_port="443"
    if [[ "${REALITY_PORT:-}" == "443" || -f "$REALITY_RELAY_DIR/relay-443.conf" ]] || reality_port_in_use 443 || reality_port_reserved 443; then
        local candidate_port=""
        def_port="$(reality_relay_next_port 2>/dev/null || true)"
        for _ in $(seq 1 200); do
            [[ -n "$def_port" ]] && break
            candidate_port=$(reality_random_port 2>/dev/null || echo "")
            [[ -n "$candidate_port" ]] || continue
            reality_port_reserved "$candidate_port" && continue
            reality_port_in_use "$candidate_port" && continue
            def_port="$candidate_port"
            break
        done
        [[ -n "$def_port" ]] || { print_error "无法生成可用随机端口"; pause; return 1; }
        print_warn "本机 443/tcp 已被占用或已用于落地/其他中转，本条线路默认回落到随机端口；非 443 入口伪装弱于 443。"
    fi
    RLY_LISTEN_PORT=""
    while true; do
        read -e -r -p "本机中转监听端口 [${def_port}] (0=取消): " RLY_LISTEN_PORT
        RLY_LISTEN_PORT="${RLY_LISTEN_PORT:-$def_port}"
        [[ "$RLY_LISTEN_PORT" == "0" || "$RLY_LISTEN_PORT" == "q" ]] && { print_info "已取消"; pause; return 0; }
        validate_port "$RLY_LISTEN_PORT" || { print_error "端口无效"; continue; }
        if [[ -n "${REALITY_PORT:-}" && "$RLY_LISTEN_PORT" == "${REALITY_PORT}" ]]; then print_error "不能与本机落地端口相同"; continue; fi
        [[ -f "$REALITY_RELAY_DIR/relay-${RLY_LISTEN_PORT}.conf" ]] && { print_error "该端口已有中转线路"; continue; }
        if reality_port_reserved "$RLY_LISTEN_PORT"; then print_error "端口已被本项目其他功能保留"; continue; fi
        if reality_port_in_use "$RLY_LISTEN_PORT"; then print_error "端口已被占用"; continue; fi
        reality_warn_port_risk "$RLY_LISTEN_PORT" "Realm 中转入口"
        if [[ "$RLY_LISTEN_PORT" != "443" && -t 0 ]] && ! confirm "确认使用非 443 中转入口端口?"; then
            continue
        fi
        break
    done
    # 线路名称
    local def_name="relay-${RLY_LISTEN_PORT}"
    read -e -r -p "线路名称/备注 [${def_name}]: " RLY_NAME
    RLY_NAME="${RLY_NAME:-$def_name}"
    reality_validate_node_name "$RLY_NAME" || { print_error "名称无效：1-64 位英文/数字/空格/点/下划线/短横线"; pause; return 1; }
    # 固定本条新线路标识：reality_relay_regenerate 内部会遍历所有线路并复用 RLY_* 全局，
    # 返回后 RLY_* 已是“最后一条线路”的值；后续引用必须用这些 local，否则报错/回滚会指向别的线路。
    local new_port="$RLY_LISTEN_PORT" new_name="$RLY_NAME" new_chost="$RLY_CONNECT_HOST" \
          new_thost="$RLY_TARGET_HOST" new_tport="$RLY_TARGET_PORT"
    reality_relay_preflight_route new || { pause; return 1; }
    reality_relay_write_route "$new_port"
    # 应用失败时回滚刚加的线路，避免把 realm 留在半残/停止状态
    if ! reality_relay_regenerate; then
        print_error "Realm 配置应用失败，正在回滚本条线路"
        rm -f "$REALITY_RELAY_DIR/relay-${new_port}.conf" \
              "$REALITY_RELAY_DIR/relay-${new_port}.link.txt" \
              "$REALITY_RELAY_DIR/relay-${new_port}.client.json"
        reality_relay_regenerate || true   # 用剩余线路恢复到原先可用状态
        pause; return 1
    fi
    # 防火墙：regenerate 已对所有线路放行；此处仅在 UFW 未启用时给交互引导
    if command_exists ufw && ! ufw_is_active; then
        if [[ -t 0 ]] && confirm "UFW 未启用，是否现在跳转防火墙菜单启用并放行中转端口?"; then
            ufw_setup
            firewall_apply_realm_port "$new_port" || print_warn "UFW 仍未生效，请确认云安全组已放行 ${new_port}/tcp"
        else
            print_warn "已跳过本地防火墙配置，请确认云安全组已放行 ${new_port}/tcp"
        fi
    fi
    # 角色刷新
    reality_load_state || true
    if [[ "${REALITY_ROLE:-}" == *"landing"* ]]; then REALITY_ROLE="landing+relay"; else REALITY_ROLE="relay"; fi
    reality_write_state
    print_success "中转线路已添加: ${new_name} (本机 ${new_chost}:${new_port} -> ${new_thost}:${new_tport})"
    echo ""
    [[ -f "$REALITY_RELAY_DIR/relay-${new_port}.link.txt" ]] && cat "$REALITY_RELAY_DIR/relay-${new_port}.link.txt"
    pause
}

# 列出全部中转线路及客户端链接
reality_relay_list() {
    print_title "中转线路列表"
    local f n=0 st health status exit_ip
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        reality_relay_load_route "$f" || continue
        n=$((n+1))
        st="[未监听]"
        if command_exists ss && ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${RLY_LISTEN_PORT}$"; then st="[监听中]"; fi
        health=""
        if [[ -f "$REALITY_RELAY_DIR/relay-${RLY_LISTEN_PORT}.health.json" ]]; then
            status="$(grep -Eo '"status":"[^"]+"' "$REALITY_RELAY_DIR/relay-${RLY_LISTEN_PORT}.health.json" 2>/dev/null | head -n1 | cut -d'"' -f4)"
            exit_ip="$(grep -Eo '"exit_ip":"[^"]*"' "$REALITY_RELAY_DIR/relay-${RLY_LISTEN_PORT}.health.json" 2>/dev/null | head -n1 | cut -d'"' -f4)"
            [[ -n "$status" ]] && health="  [验证:${status}${exit_ip:+/$exit_ip}]"
        fi
        echo "${n}. ${RLY_NAME}  本机:${RLY_LISTEN_PORT} -> ${RLY_TARGET_HOST}:${RLY_TARGET_PORT}  ${st}${health}"
    done < <(reality_relay_route_files)
    if [[ $n -eq 0 ]]; then
        print_warn "暂无中转线路"
    else
        echo ""
        print_info "完整客户端链接请到「查看/修改节点信息 → 查看节点信息」获取"
    fi
    pause
}

# 删除一条中转线路
reality_relay_remove() {
    print_title "删除中转线路"
    local files=() f
    while IFS= read -r f; do [[ -n "$f" ]] && files+=("$f"); done < <(reality_relay_route_files)
    [[ ${#files[@]} -gt 0 ]] || { print_warn "暂无中转线路"; pause; return 0; }
    local i=1
    for f in "${files[@]}"; do
        reality_relay_load_route "$f" && echo "  ${i}. ${RLY_NAME} (${RLY_CONNECT_HOST}:${RLY_LISTEN_PORT} -> ${RLY_TARGET_HOST}:${RLY_TARGET_PORT})"
        i=$((i+1))
    done
    local sel; read -e -r -p "选择要删除的线路序号 [0=取消]: " sel
    [[ "$sel" =~ ^[0-9]+$ ]] || { print_error "无效序号"; pause; return 1; }
    [[ "$sel" -ge 1 && "$sel" -le ${#files[@]} ]] || return 0
    f="${files[$((sel-1))]}"
    reality_relay_load_route "$f" || { print_error "读取失败"; pause; return 1; }
    confirm "确认删除中转线路 ${RLY_NAME} (端口 ${RLY_LISTEN_PORT})?" || return 0
    local port="$RLY_LISTEN_PORT"
    rm -f "$f" "$REALITY_RELAY_DIR/relay-${port}.link.txt" "$REALITY_RELAY_DIR/relay-${port}.client.json"
    if command_exists ufw && ufw_is_active; then ufw delete allow "${port}/tcp" >/dev/null 2>&1 || true; fi
    reality_relay_regenerate || true
    reality_load_state || true
    if [[ -z "$(reality_relay_route_files)" ]]; then
        if [[ "${REALITY_ROLE:-}" == *"landing"* ]]; then REALITY_ROLE="landing"; else REALITY_ROLE=""; fi
        reality_write_state
    fi
    print_success "已删除中转线路 (端口 ${port})"
    pause
}

# 中转线路管理子菜单
reality_relay_menu() {
    # 旧版单中转安装首次进入本菜单时，自动把 REALITY_RELAY_* 迁移为一条线路，
    # 使其在列表中可见、可管理（仅转换表示，不重启 realm）。
    reality_load_state 2>/dev/null && reality_relay_migrate_legacy 2>/dev/null || true
    while true; do
        print_title "中转线路管理（A 给多台落地机做中转）"
        echo "1. 添加中转线路（导入落地链接）"
        echo "2. 查看中转线路（清单/状态）"
        echo "3. 删除中转线路"
        echo "0. 返回"
        read -e -r -p "请选择: " c
        case "$c" in
            1) reality_relay_add ;;
            2) reality_relay_list ;;
            3) reality_relay_remove ;;
            0|q|Q) break ;;
            *) print_error "无效选项"; sleep 1 ;;
        esac
    done
}

firewall_remove_reality_ports() {
    command_exists ufw || return 0
    ufw_is_active || return 0
    local port f
    for port in "${REALITY_PORT:-}" "${REALITY_PORT_V6:-}" "${REALITY_RELAY_PORT:-}"; do
        validate_port "$port" || continue
        ufw delete allow "${port}/tcp" >/dev/null 2>&1 || true
    done
    # 回收所有中转线路监听端口
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        reality_relay_load_route "$f" || continue
        validate_port "$RLY_LISTEN_PORT" || continue
        ufw delete allow "${RLY_LISTEN_PORT}/tcp" >/dev/null 2>&1 || true
    done < <(reality_relay_route_files)
}

reality_install_relay() {
    local relay_domain="$1" listen_port="$2" target_host="$3" target_port="$4" cf_token="${5:-}" node_name="${6:-}"
    validate_domain "$relay_domain" || { print_error "中转域名无效"; return 1; }
    validate_port "$listen_port" || { print_error "中转端口无效"; return 1; }
    validate_domain "$target_host" || validate_ip "$target_host" || { print_error "落地地址无效"; return 1; }
    validate_port "$target_port" || { print_error "落地端口无效"; return 1; }
    reality_warn_port_risk "$listen_port" "Realm 中转入口"
    [[ -z "$node_name" ]] || reality_validate_node_name "$node_name" || { print_error "节点名称无效"; return 1; }
    # 导入落地 vless 链接带入的客户端 Reality 身份(公钥/UUID/SNI/ShortID/flow/fp)只进 RLY_*
    # （中转线路的独立身份），绝不写入会被 reality_write_state 持久化的 REALITY_*。
    # 教训(HIGH-1)：曾把导入值经 REALITY_* 中转再赋给 RLY_*，导致本机 state.conf 被下游身份污染、
    # 甚至私钥被抹空(链接无私钥)——本机落地节点不可逆损坏。故此处快照后不再触碰 REALITY_*。
    local _imp_uuid="${REALITY_UUID:-}" _imp_sni="${REALITY_SNI:-}" \
          _imp_pbk="${REALITY_PUBLIC_KEY:-}" _imp_sid="${REALITY_SHORT_ID:-}" \
          _imp_node="${REALITY_NODE_DOMAIN:-}" _imp_port="${REALITY_PORT:-}" \
          _imp_flow="${REALITY_FLOW:-}" _imp_fp="${REALITY_FINGERPRINT:-}"
    # 先清空 REALITY_* 身份字段：否则 relay-only 全新机上 reality_load_state 失败时，
    # 这些字段会残留上面 parse 出的下游值，被 reality_write_state 误持久化成"伪落地"state
    # （UUID=下游、私钥空），日后误跑 rotate-key 会崩。清空后 load_state 只会填回本机真落地身份。
    REALITY_UUID=""; REALITY_SNI=""; REALITY_PUBLIC_KEY=""; REALITY_SHORT_ID=""
    REALITY_NODE_DOMAIN=""; REALITY_PORT=""; REALITY_PRIVATE_KEY=""; REALITY_FLOW=""; REALITY_FINGERPRINT=""
    # 加载本机落地 state（若有）以便保留本机落地身份 + 判断 landing 角色；导入值不覆盖它。
    reality_load_state || true
    if reality_port_reserved "$listen_port"; then
        print_error "中转端口已被本项目其他功能保留: ${listen_port}"
        return 1
    fi
    reality_warn_sni_risk "${_imp_sni:-${REALITY_SNI:-}}"
    reality_require_supported_os || return 1
    # 写为一条独立身份的中转线路（relays 目录是 realm 配置的唯一真相源）。
    # RLY_* 优先取导入的下游身份(_imp_*)；未导入链接时回退本机落地身份(REALITY_*)。
    RLY_NAME="${node_name:-$(reality_effective_node_name)}"
    RLY_LISTEN_PORT="$listen_port"
    RLY_CONNECT_HOST="$relay_domain"
    RLY_TARGET_HOST="$target_host"
    RLY_TARGET_PORT="$target_port"
    if [[ -n "$_imp_pbk" ]]; then
        RLY_UUID="$_imp_uuid"; RLY_SNI="$_imp_sni"
        RLY_PUBLIC_KEY="$_imp_pbk"; RLY_SHORT_ID="$_imp_sid"
        RLY_FLOW="${_imp_flow:-xtls-rprx-vision}"; RLY_FINGERPRINT="$_imp_fp"
    else
        RLY_UUID="${REALITY_UUID:-}"; RLY_SNI="${REALITY_SNI:-}"
        RLY_PUBLIC_KEY="${REALITY_PUBLIC_KEY:-}"; RLY_SHORT_ID="${REALITY_SHORT_ID:-}"
        RLY_FLOW="${REALITY_FLOW:-xtls-rprx-vision}"; RLY_FINGERPRINT="${REALITY_FINGERPRINT:-}"
    fi
    # MED-2：先迁移老版单中转字段（REALITY_RELAY_*）为一条独立线路，再写本次新线路。
    # 否则本次 write_route 会让 relays 目录非空 → regenerate 里的 migrate 提前 return →
    # 老线路永远不被渲染，升级用户原有中转静默失效。菜单路径已先迁移，这里对齐。
    reality_relay_migrate_legacy
    reality_relay_preflight_route new || return 1
    reality_relay_write_route "$listen_port"
    if [[ -n "$cf_token" ]]; then reality_sync_cloudflare_dns "$relay_domain" "$cf_token"; fi
    # MED-3：regenerate 失败时回滚本次新写的线路文件并重建，避免残留半配置线路
    # （下次 regenerate 会把它渲染进 realm，复活一条坏线路）。对齐 reality_relay_add 的回滚。
    if ! reality_relay_regenerate; then
        rm -f "${REALITY_RELAY_DIR}/relay-${listen_port}.conf" \
              "${REALITY_RELAY_DIR}/relay-${listen_port}.link.txt" \
              "${REALITY_RELAY_DIR}/relay-${listen_port}.client.json" 2>/dev/null || true
        reality_relay_regenerate || true
        print_error "Realm 中转重建失败，已回滚本次新增线路"
        return 1
    fi
    firewall_apply_realm_port "$listen_port"
    local _fw_rc=$?
    if [[ $_fw_rc -eq 1 ]]; then
        return 1
    elif [[ $_fw_rc -eq 2 ]]; then
        if [[ -t 0 ]] && confirm "UFW 未启用，是否现在跳转防火墙菜单启用并放行 Realm 中转端口?"; then
            ufw_setup
            firewall_apply_realm_port "$listen_port" || \
                print_warn "UFW 仍未生效，请确认云安全组已放行 ${listen_port}/tcp"
        else
            print_warn "已跳过本地防火墙配置，请确认云安全组已放行 ${listen_port}/tcp"
        fi
    fi
    if [[ -n "${REALITY_UUID:-}" && "${REALITY_ROLE:-}" == *"landing"* ]]; then
        REALITY_ROLE="landing+relay"
    else
        REALITY_ROLE="relay"
    fi
    [[ -n "$node_name" ]] && REALITY_NODE_NAME="$node_name"
    reality_write_state
    print_success "Realm 中转线路安装完成"
    reality_show_info
}

reality_prompt_port() {
    local prompt="$1" forbidden="${2:-}" allow_current_landing="${3:-0}" choice port input_port
    while true; do
        echo -e "${C_CYAN}${prompt} 端口策略:${C_RESET}" >&2
        echo "  1. 使用 443（推荐：最符合正常 HTTPS/REALITY 伪装）" >&2
        echo "  2. 自定义端口（非 443 会提示风险）" >&2
        echo "  3. 随机高位端口（仅备用；非 443 伪装弱于 443）" >&2
        read -e -r -p "请选择端口策略 [1]: " choice
        case "${choice:-1}" in
            1)
                input_port="443"
                ;;
            2)
                read -e -r -p "${prompt} 自定义端口: " input_port
                ;;
            3)
                input_port=""
                for _ in $(seq 1 200); do
                    port=$(reality_random_port) || { print_error "无法生成可用随机端口"; return 1; }
                    [[ -n "$forbidden" && "$port" == "$forbidden" ]] && continue
                    if [[ "$allow_current_landing" == "1" ]]; then
                        reality_port_reserved_except_current_landing "$port" && continue
                    else
                        reality_port_reserved "$port" && continue
                    fi
                    input_port="$port"
                    break
                done
                [[ -n "$input_port" ]] || { print_error "无法生成可用随机端口"; return 1; }
                ;;
            *) print_error "无效选择"; continue ;;
        esac
        validate_port "$input_port" || { print_error "端口无效"; continue; }
        if [[ -n "$forbidden" && "$input_port" == "$forbidden" ]]; then
            print_error "端口不能与 ${forbidden} 相同"
            continue
        fi
        if [[ "$allow_current_landing" == "1" ]]; then
            if reality_port_reserved_except_current_landing "$input_port"; then
                print_error "端口 ${input_port} 已被本项目其他功能保留"
                continue
            fi
        elif reality_port_reserved "$input_port"; then
            print_error "端口 ${input_port} 已被本项目其他功能保留"
            continue
        fi
        if reality_port_in_use "$input_port"; then
            print_warn "端口 ${input_port}/tcp 当前已被监听。若这是重装同一个 sing-box/realm 服务通常可以继续；否则启动可能失败。"
            if [[ -t 0 ]] && ! confirm "仍继续使用 ${input_port}/tcp?"; then
                continue
            fi
        fi
        reality_warn_port_risk "$input_port" "$prompt"
        if [[ "$input_port" != "443" && -t 0 ]] && ! confirm "确认使用非 443 Reality/Realm 入口端口?"; then
            continue
        fi
        echo "$input_port"
        return 0
    done
}

reality_prompt_split_ports() {
    local choice p4="" p6=""
    while true; do
        echo -e "${C_CYAN}IPv4/IPv6 双 Reality 端口策略:${C_RESET}" >&2
        echo "  1. IPv4 与 IPv6 均使用 443（推荐；脚本会让 IPv6 入站绑定具体 IPv6，避免端口冲突）" >&2
        echo "  2. IPv4 使用 443，IPv6 单独选择端口" >&2
        echo "  3. IPv6 使用 443，IPv4 单独选择端口" >&2
        echo "  4. IPv4/IPv6 分别选择端口（非 443 会提示风险）" >&2
        read -e -r -p "请选择端口策略 [1]: " choice
        case "${choice:-1}" in
            1) p4="443"; p6="443" ;;
            2) p4="443"; p6=$(reality_prompt_port "IPv6 Reality 监听" "" 1) || return 1 ;;
            3) p6="443"; p4=$(reality_prompt_port "IPv4 Reality 监听" "" 1) || return 1 ;;
            4)
                p4=$(reality_prompt_port "IPv4 Reality 监听" "" 1) || return 1
                p6=$(reality_prompt_port "IPv6 Reality 监听" "" 1) || return 1
                ;;
            *) print_error "无效选择"; continue ;;
        esac
        validate_port "$p4" && validate_port "$p6" || { print_error "端口无效"; continue; }
        printf '%s %s\n' "$p4" "$p6"
        return 0
    done
}

reality_prompt_landing_dns_mode() {
    local choice
    reality_detect_ips
    echo -e "${C_CYAN}节点网络/DNS 模式:${C_RESET}" >&2
    echo "  当前检测: IPv4=${REALITY_IPV4:-N/A}  IPv6=${REALITY_IPV6:-N/A}" >&2
    echo "  1. 自动/双栈单节点：同一域名写入可用的 A/AAAA（保持旧行为）" >&2
    echo "  2. IPv4-only 单节点：域名仅保留 A 记录" >&2
    echo "  3. IPv6-only 单节点：域名仅保留 AAAA 记录" >&2
    echo "  4. IPv4+IPv6 双节点：两个域名、两条客户端链接，端口优先共用 443（推荐双栈线路对比）" >&2
    while true; do
        read -e -r -p "请选择网络模式 [1]: " choice
        case "${choice:-1}" in
            1) echo "auto"; return 0 ;;
            2) echo "ipv4"; return 0 ;;
            3) echo "ipv6"; return 0 ;;
            4) echo "split"; return 0 ;;
            *) print_error "无效选择" >&2 ;;
        esac
    done
}

reality_install_wizard() {
    local role="" node="" node_v4="" node_v6="" dns_mode="" sni="" port="" port_v6="" cf_token="" relay_domain="" relay_port="" target_host="" target_port="" landing_link="" node_name="" node_name_v4="" node_name_v6="" _split_ports=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --landing) role="landing"; shift ;;
            --relay) role="relay"; shift ;;
            --both) role="both"; shift ;;
            --name|--node-name) node_name="$2"; shift 2 ;;
            --name-v4|--node-name-v4) node_name_v4="$2"; shift 2 ;;
            --name-v6|--node-name-v6) node_name_v6="$2"; shift 2 ;;
            --node) node="$2"; shift 2 ;;
            --node-v4|--ipv4-node) node_v4="$2"; shift 2 ;;
            --node-v6|--ipv6-node) node_v6="$2"; shift 2 ;;
            --dns-mode|--network-mode) dns_mode="$2"; shift 2 ;;
            --split|--dual-node|--dual-nodes) dns_mode="split"; shift ;;
            --sni) sni="$2"; shift 2 ;;
            --port) port="$2"; shift 2 ;;
            --port-v6|--ipv6-port) port_v6="$2"; shift 2 ;;
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
        echo "0. 返回上一级"
        read -e -r -p "请选择 [1, 0=返回]: " role_choice
        case "${role_choice:-1}" in
            1) role="landing" ;;
            2) role="relay" ;;
            3) role="both" ;;
            0|q|Q) return 0 ;;
            *) print_error "无效选择"; return 1 ;;
        esac
    fi
    if [[ "$role" == "landing" || "$role" == "both" ]]; then
        if [[ -z "$cf_token" ]]; then
            cf_token=$(reality_prompt_cf_token)
        fi
        if [[ -z "$dns_mode" ]]; then
            dns_mode=$(reality_prompt_landing_dns_mode)
        fi
        dns_mode=$(reality_normalize_dns_mode "$dns_mode") || { print_error "网络/DNS 模式无效: $dns_mode"; return 1; }
        if [[ "$dns_mode" == "split" ]]; then
            [[ -n "$node_v4" || -z "$node" ]] || node_v4="$node"
            while [[ -z "$node_v4" ]]; do
                echo -e "${C_CYAN}IPv4 节点连接域名说明:${C_RESET}"
                echo "  该域名会被同步为 A-only，用于客户端强制走 IPv4 线路。"
                node_v4=$(reality_prompt_domain_with_zones "IPv4 节点连接" "$cf_token" "$(hostname)-reality-v4")
                validate_domain "$node_v4" || { print_error "IPv4 节点域名无效"; node_v4=""; }
            done
            while [[ -z "$node_v6" ]]; do
                echo -e "${C_CYAN}IPv6 节点连接域名说明:${C_RESET}"
                echo "  该域名会被同步为 AAAA-only，用于客户端强制走 IPv6 线路。"
                node_v6=$(reality_prompt_domain_with_zones "IPv6 节点连接" "$cf_token" "$(hostname)-reality-v6")
                validate_domain "$node_v6" || { print_error "IPv6 节点域名无效"; node_v6=""; }
            done
            [[ "$node_v4" != "$node_v6" ]] || { print_error "双节点模式下 IPv4/IPv6 域名不能相同"; return 1; }
            node="$node_v4"
        else
            while [[ -z "$node" ]]; do
                echo -e "${C_CYAN}节点连接域名说明:${C_RESET}"
                echo "  这是客户端实际连接的节点域名，会写入 vless:// 链接的 @host 部分。"
                echo "  脚本会通过 Cloudflare API 自动创建/更新此域名到当前 VPS 公网 IP，并强制 Cloudflare 灰云。"
                echo "  这里不是让你手动去 Cloudflare 添加记录；如果 Token 能列出 zone，只需要填写自定义前缀。"
                echo "  示例: 选择 example.com 后输入 node-us-01，脚本会生成 node-us-01.example.com -> 当前 VPS 公网 IP"
                node=$(reality_prompt_domain_with_zones "节点连接" "$cf_token")
                validate_domain "$node" || { print_error "域名无效"; node=""; }
            done
        fi
        if [[ -z "$node_name" ]]; then
            REALITY_NODE_DOMAIN="$node"
            node_name=$(reality_prompt_node_name "$(reality_default_node_name)")
        fi
        if [[ "$dns_mode" == "split" ]]; then
            [[ -n "$node_name_v4" ]] || node_name_v4=$(reality_node_name_with_suffix "$node_name" "-ipv4")
            [[ -n "$node_name_v6" ]] || node_name_v6=$(reality_node_name_with_suffix "$node_name" "-ipv6")
        fi
        [[ -z "$sni" ]] && sni=$(reality_prompt_sni)
        if [[ "$dns_mode" == "split" ]]; then
            if [[ -z "$port" && -z "$port_v6" ]]; then
                _split_ports="$(reality_prompt_split_ports)" || return 1
                read -r port port_v6 <<< "$_split_ports"
            elif [[ -z "$port" && "$port_v6" == "443" ]]; then
                port="443"
            elif [[ -z "$port_v6" && "$port" == "443" ]]; then
                port_v6="443"
            else
                [[ -z "$port" ]] && port=$(reality_prompt_port "IPv4 Reality 监听" "" 1)
                [[ -z "$port_v6" ]] && port_v6=$(reality_prompt_port "IPv6 Reality 监听" "" 1)
            fi
        else
            [[ -z "$port" ]] && port=$(reality_prompt_port "Reality 监听" "" 1)
        fi
        reality_install_landing "$node" "$sni" "$port" "$cf_token" "$node_name" "$dns_mode" "$node_v4" "$node_v6" "$port_v6" "$node_name_v4" "$node_name_v6" || return 1
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
        local _relay_forbidden_port=""
        [[ "$role" == "both" ]] && _relay_forbidden_port="$port"
        [[ -z "$relay_port" ]] && relay_port=$(reality_prompt_port "Realm 中转监听" "$_relay_forbidden_port")
        if [[ "$role" == "both" ]]; then
            target_host="127.0.0.1"; target_port="$port"
            [[ "$relay_port" != "$port" ]] || { print_error "本机中转端口不能与本机落地 Reality 端口相同"; return 1; }
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
    local mode; mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo "auto")
    echo -e "角色: ${C_GREEN}${REALITY_ROLE:-未知}${C_RESET}"
    echo "节点名称: $(reality_effective_node_name)"
    echo "网络模式: $(reality_dns_mode_label "$mode")"
    if [[ "$mode" == "split" ]]; then
        [[ -n "${REALITY_NODE_DOMAIN_V4:-}" ]] && echo "IPv4节点: ${REALITY_NODE_DOMAIN_V4}:${REALITY_PORT} (${REALITY_NODE_NAME_V4:-IPv4})"
        [[ -n "${REALITY_NODE_DOMAIN_V6:-}" ]] && echo "IPv6节点: ${REALITY_NODE_DOMAIN_V6}:${REALITY_PORT_V6} (${REALITY_NODE_NAME_V6:-IPv6})"
    else
        [[ -n "${REALITY_NODE_DOMAIN:-}" ]] && echo "落地域名: $REALITY_NODE_DOMAIN"
        [[ -n "${REALITY_PORT:-}" ]] && echo "Reality端口: $REALITY_PORT"
    fi
    [[ -n "${REALITY_SNI:-}" ]] && echo "SNI: $REALITY_SNI"
    [[ -n "${REALITY_RELAY_DOMAIN:-}" ]] && echo "中转域名: $REALITY_RELAY_DOMAIN"
    [[ -n "${REALITY_RELAY_PORT:-}" ]] && echo "中转端口: $REALITY_RELAY_PORT"
    [[ -n "${REALITY_RELAY_TARGET_HOST:-}" ]] && echo "中转目标: ${REALITY_RELAY_TARGET_HOST}:${REALITY_RELAY_TARGET_PORT}"
    if [[ -f "$REALITY_LINK_FILE" ]]; then
        draw_line
        echo "落地客户端链接:"
        cat "$REALITY_LINK_FILE"
    fi
    # 多路中转线路：每条独立身份、独立客户端链接
    local _f _n=0
    while IFS= read -r _f; do
        [[ -n "$_f" ]] || continue
        reality_relay_load_route "$_f" || continue
        _n=$((_n+1))
        draw_line
        echo "中转线路 ${_n}: ${RLY_NAME}  本机 ${RLY_CONNECT_HOST}:${RLY_LISTEN_PORT} -> ${RLY_TARGET_HOST}:${RLY_TARGET_PORT}"
        local _lf="$REALITY_RELAY_DIR/relay-${RLY_LISTEN_PORT}.link.txt"
        [[ -f "$_lf" ]] && cat "$_lf"
    done < <(reality_relay_route_files)
    # CDN 链路（橙云 + 优选 IP）：与 Reality 直连并存，单独展示
    if reality_cdn_load_state 2>/dev/null && [[ -n "${REALITY_CDN_DOMAIN:-}" ]]; then
        draw_line
        echo "CDN 链路 (VLESS+WS+TLS 橙云): ${REALITY_CDN_NODE_NAME:-cdn}"
        echo "  CDN 域名: ${REALITY_CDN_DOMAIN}  回源端口: ${REALITY_CDN_ORIGIN_PORT:-8443}  WS path: ${REALITY_CDN_WS_PATH:-}"
        echo "  当前优选 IP: ${REALITY_CDN_PREFER_IP:-（未设置，server 暂用域名；由国内机 B+C 自动刷新）}"
        [[ -f "$REALITY_CDN_LINK_FILE" ]] && cat "$REALITY_CDN_LINK_FILE"
    fi
    pause
}

reality_status() {
    print_title "Reality 服务状态"
    command_exists systemctl || { print_warn "systemctl 不可用"; pause; return; }
    local status_out
    if status_out=$(systemctl --no-pager --full status sing-box 2>&1); then
        printf '%s\n' "$status_out" | sed -n '1,12p'
    else
        print_warn "sing-box 未运行"
        printf '%s\n' "$status_out" | sed -n '1,6p'
    fi
    echo ""
    if status_out=$(systemctl --no-pager --full status realm 2>&1); then
        printf '%s\n' "$status_out" | sed -n '1,12p'
    fi
    pause
}

reality_diagnose() {
    print_title "Reality 诊断/自检"
    reality_load_state || { print_error "未发现状态文件: $REALITY_STATE_FILE"; pause; return 1; }

    local mode; mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo "auto")
    local has_landing=0; [[ -n "${REALITY_PORT:-}" && -n "${REALITY_NODE_DOMAIN:-}" ]] && has_landing=1
    # 连接核对目标：优先落地域名；纯中转机回落到首条线路的连接域名
    local connect_domain="${REALITY_NODE_DOMAIN:-}" connect_port="${REALITY_PORT:-}"
    if [[ -z "$connect_domain" ]]; then
        local _first; _first=$(reality_relay_route_files | head -n1)
        if [[ -n "$_first" ]] && reality_relay_load_route "$_first"; then
            connect_domain="$RLY_CONNECT_HOST"; connect_port="$RLY_LISTEN_PORT"
        fi
    fi
    local public_ip="" dns_ip="" system_dns=""

    echo "节点角色: ${REALITY_ROLE:-unknown}"
    echo "网络模式: $(reality_dns_mode_label "$mode")"
    echo "客户端连接: ${connect_domain:-未设置}:${connect_port:-未设置}"
    if [[ "$has_landing" -eq 1 && "$mode" == "split" ]]; then
        echo "IPv4节点: ${REALITY_NODE_DOMAIN_V4:-未设置}:${REALITY_PORT:-未设置}"
        echo "IPv6节点: ${REALITY_NODE_DOMAIN_V6:-未设置}:${REALITY_PORT_V6:-未设置}"
    elif [[ "$has_landing" -eq 1 ]]; then
        echo "落地端口: ${REALITY_PORT}"
    fi
    [[ -n "${REALITY_SNI:-}" ]] && echo "落地 SNI: ${REALITY_SNI}"
    echo ""

    if [[ "$has_landing" -eq 1 ]]; then
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
            local _co_rport=""
            _co_rport="$(reality_coexist_reality_port 2>/dev/null || true)"
            if [[ -n "$_co_rport" ]]; then
                # 共存模式：sing-box 绑 127.0.0.1:<内部端口>，公网 443 由 nginx stream 持有。
                if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${_co_rport}$"; then
                    print_success "本机正在监听 Reality 内部端口(loopback): ${_co_rport}/tcp（443 共存模式）"
                else
                    print_error "本机未监听 Reality 内部端口: ${_co_rport}/tcp（443 共存模式，sing-box 可能未起）"
                fi
            else
                local _rp
                for _rp in "${REALITY_PORT:-}" "${REALITY_PORT_V6:-}"; do
                    validate_port "$_rp" || continue
                    if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${_rp}$"; then
                        print_success "本机正在监听 Reality 端口: ${_rp}/tcp"
                    else
                        print_error "本机未监听 Reality 端口: ${_rp}/tcp"
                    fi
                done
            fi
        fi

        if command_exists ufw; then
            local _up
            for _up in "${REALITY_PORT:-}" "${REALITY_PORT_V6:-}"; do
                validate_port "$_up" || continue
                if ufw status 2>/dev/null | grep -q "${_up}/tcp"; then
                    print_success "UFW 已放行 Reality 端口: ${_up}/tcp"
                else
                    print_warn "UFW 状态中未看到 ${_up}/tcp 放行规则"
                fi
            done
        fi
    fi

    # 443 共存模式诊断：stream 模块 / 443 归属 / 内部端口 / SNI 白名单
    if reality_coexist_enabled 2>/dev/null; then
        echo ""
        print_info "443 共存模式（nginx stream + ssl_preread）诊断:"
        local _co_rport _co_wport
        _co_rport="$(reality_coexist_reality_port 2>/dev/null || true)"
        _co_wport="$(reality_coexist_web_port 2>/dev/null || true)"
        echo "  reality 内部端口: ${_co_rport:-未知}   web 内部端口: ${_co_wport:-未知}"
        if declare -F _check_nginx_stream >/dev/null && _check_nginx_stream; then
            print_success "nginx stream 模块可用"
        else
            print_error "nginx stream 模块不可用（443 分流无法工作）"
        fi
        if command_exists ss; then
            if ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)443$"; then
                print_success "本机正在监听 443/tcp（应为 nginx stream 持有）"
            else
                print_error "本机未监听 443/tcp（nginx stream 未接管，Reality 对外不可达）"
            fi
        fi
        if [[ -f "$REALITY_STREAM_CONF" ]]; then
            print_success "stream 分流配置存在: $REALITY_STREAM_CONF"
            local _wl_count
            _wl_count=$(reality_coexist_collect_web_domains 2>/dev/null | wc -l | tr -d ' ')
            echo "  真站 SNI 白名单: ${_wl_count} 个域名 → web(${_co_wport:-?})，其余 default → reality(${_co_rport:-?})"
        else
            print_error "stream 分流配置缺失: $REALITY_STREAM_CONF"
        fi
        if command_exists nginx; then
            nginx -t >/dev/null 2>&1 \
                && print_success "nginx 配置校验通过" \
                || print_error "nginx 配置校验失败（run: nginx -t 查看详情）"
        fi
    fi

    # 中转线路诊断：realm 服务 + 各线路监听端口
    if [[ -n "$(reality_relay_route_files)" ]]; then
        echo ""
        if command_exists systemctl; then
            systemctl is-active --quiet realm \
                && print_success "realm 中转服务 active" \
                || print_error "realm 中转服务未运行"
        fi
        local _rf
        while IFS= read -r _rf; do
            [[ -n "$_rf" ]] || continue
            reality_relay_load_route "$_rf" || continue
            validate_port "$RLY_LISTEN_PORT" || continue
            if command_exists ss && ss -ltn 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)${RLY_LISTEN_PORT}$"; then
                print_success "中转线路 ${RLY_NAME}: 监听 ${RLY_LISTEN_PORT}/tcp -> ${RLY_TARGET_HOST}:${RLY_TARGET_PORT}"
            else
                print_error "中转线路 ${RLY_NAME}: 未监听 ${RLY_LISTEN_PORT}/tcp（realm 可能未启动或端口冲突）"
            fi
        done < <(reality_relay_route_files)
    fi

    echo ""
    if [[ "$mode" == "split" ]]; then
        echo "监听地址: IPv4=${REALITY_LISTEN_HOST_V4:-0.0.0.0}:${REALITY_PORT:-?}  IPv6=[${REALITY_LISTEN_HOST_V6:-::}]:${REALITY_PORT_V6:-?}"
    else
        echo "监听地址: ${REALITY_LISTEN_HOST:-0.0.0.0}$([[ "${REALITY_LISTEN_HOST:-}" == "::" ]] && echo '（双栈 IPv4+IPv6）')"
    fi

    local public_ip6 dns_ip6 has_v4_path=0 has_v6_path=0
    public_ip=$(get_public_ipv4 2>/dev/null || true)
    public_ip6=$(get_public_ipv6 2>/dev/null || true)
    [[ -n "$public_ip" ]] && { echo "本机公网 IPv4: $public_ip"; has_v4_path=1; }
    [[ -n "$public_ip6" ]] && { echo "本机公网 IPv6: $public_ip6"; has_v6_path=1; }
    [[ -z "$public_ip" && -z "$public_ip6" ]] && print_warn "未能获取本机公网 IPv4/IPv6"

    system_dns=$(getent ahostsv4 "$connect_domain" 2>/dev/null | awk '{print $1; exit}' || true)
    local system_dns6; system_dns6=$(getent ahostsv6 "$connect_domain" 2>/dev/null | awk '{print $1; exit}' || true)
    [[ -n "$system_dns" ]] && echo "系统 DNS(A): ${connect_domain} -> ${system_dns}"
    [[ -n "$system_dns6" ]] && echo "系统 DNS(AAAA): ${connect_domain} -> ${system_dns6}"

    dns_ip=$(reality_resolve_public_a "$connect_domain" 2>/dev/null || true)
    dns_ip6=$(reality_resolve_public_aaaa "$connect_domain" 2>/dev/null || true)
    [[ -n "$dns_ip" ]] && echo "Cloudflare DoH(A): ${connect_domain} -> ${dns_ip}"
    [[ -n "$dns_ip6" ]] && echo "Cloudflare DoH(AAAA): ${connect_domain} -> ${dns_ip6}"
    if [[ -z "$dns_ip" && -z "$dns_ip6" ]]; then
        print_warn "公网 DNS 未解析到 ${connect_domain} 的 A/AAAA 记录（DNS 未同步或未创建）"
    fi
    # 一致性：优先按本机可用的协议栈核对
    if [[ -n "$public_ip" && -n "$dns_ip" ]]; then
        [[ "$public_ip" == "$dns_ip" ]] \
            && print_success "IPv4 DNS 解析与本机公网一致" \
            || print_warn "IPv4 DNS 解析与本机公网不一致（DDNS 未同步或处于 NAT/转发环境）"
    fi
    if [[ -n "$public_ip6" && -n "$dns_ip6" ]]; then
        [[ "$public_ip6" == "$dns_ip6" ]] \
            && print_success "IPv6 DNS 解析与本机公网一致" \
            || print_warn "IPv6 DNS 解析与本机公网不一致（DDNS 未同步）"
    fi
    if [[ "$mode" == "split" ]]; then
        local v4_a="" v4_aaaa="" v6_a="" v6_aaaa=""
        v4_a=$(reality_resolve_public_a "${REALITY_NODE_DOMAIN_V4:-}" 2>/dev/null || true)
        v4_aaaa=$(reality_resolve_public_aaaa "${REALITY_NODE_DOMAIN_V4:-}" 2>/dev/null || true)
        v6_a=$(reality_resolve_public_a "${REALITY_NODE_DOMAIN_V6:-}" 2>/dev/null || true)
        v6_aaaa=$(reality_resolve_public_aaaa "${REALITY_NODE_DOMAIN_V6:-}" 2>/dev/null || true)
        [[ -n "$v4_a" ]] && print_success "IPv4 节点 A 记录存在: ${REALITY_NODE_DOMAIN_V4} -> ${v4_a}" || print_warn "IPv4 节点缺少 A 记录: ${REALITY_NODE_DOMAIN_V4}"
        [[ -z "$v4_aaaa" ]] && print_success "IPv4 节点未发现 AAAA 记录（符合 A-only）" || print_warn "IPv4 节点仍存在 AAAA 记录: ${v4_aaaa}"
        [[ -n "$v6_aaaa" ]] && print_success "IPv6 节点 AAAA 记录存在: ${REALITY_NODE_DOMAIN_V6} -> ${v6_aaaa}" || print_warn "IPv6 节点缺少 AAAA 记录: ${REALITY_NODE_DOMAIN_V6}"
        [[ -z "$v6_a" ]] && print_success "IPv6 节点未发现 A 记录（符合 AAAA-only）" || print_warn "IPv6 节点仍存在 A 记录: ${v6_a}"
    fi
    if [[ "$has_v6_path" -eq 1 && "$has_v4_path" -eq 0 ]]; then
        print_info "本机为 IPv6-only：请确认节点域名已有 AAAA 记录、监听地址为 ::、且客户端网络支持 IPv6。"
        [[ "${REALITY_LISTEN_HOST:-}" != "::" ]] && print_warn "当前监听地址非 :: —— IPv6-only 机器需重装落地机(菜单 11→1)使其绑定 ::，否则 IPv6 客户端无法连接。"
    fi

    if [[ -n "${REALITY_SNI:-}" ]]; then
        if reality_verify_sni "$REALITY_SNI"; then
            print_success "SNI TLS/SAN 校验通过: $REALITY_SNI"
            reality_cleanup_sni_check_log
        else
            print_warn "SNI TLS/SAN 校验失败或当前网络不可达: $REALITY_SNI"
            tail -n 5 "${REALITY_SNI_CHECK_LOG:-/dev/null}" 2>/dev/null || true
            reality_cleanup_sni_check_log
        fi
    fi

    if [[ "${REALITY_ROLE:-}" == *"landing"* ]]; then
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
    [[ -n "${REALITY_PRIVATE_KEY:-}" && -n "${REALITY_PORT:-}" && -n "${REALITY_SNI:-}" && -n "${REALITY_SHORT_ID:-}" ]] || { print_error "状态文件缺少落地机参数"; pause; return 1; }
    validate_port "$REALITY_PORT" || { print_error "状态文件端口无效: ${REALITY_PORT:-空}"; pause; return 1; }
    local mode; mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo "auto")
    [[ "$mode" != "split" ]] || validate_port "${REALITY_PORT_V6:-}" || { print_error "双节点状态文件 IPv6 端口无效: ${REALITY_PORT_V6:-空}"; pause; return 1; }
    local old_uuid="$REALITY_UUID" new_uuid new_config
    new_uuid=$(reality_generate_uuid) || return 1
    new_config=$(reality_render_singbox_config "$new_uuid" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") || return 1
    REALITY_UUID="$new_uuid"
    if ! reality_apply_singbox_config "$new_config"; then
        REALITY_UUID="$old_uuid"
        pause; return 1
    fi
    reality_write_state; reality_write_client_artifacts
    print_success "UUID 已轮换"
    reality_show_info
}

reality_rotate_key() {
    reality_load_state || { print_error "未安装落地机配置"; pause; return 1; }
    [[ -n "${REALITY_UUID:-}" && -n "${REALITY_PORT:-}" && -n "${REALITY_SNI:-}" ]] || { print_error "状态文件缺少落地机参数"; pause; return 1; }
    validate_port "$REALITY_PORT" || { print_error "状态文件端口无效: ${REALITY_PORT:-空}"; pause; return 1; }
    local mode; mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo "auto")
    [[ "$mode" != "split" ]] || validate_port "${REALITY_PORT_V6:-}" || { print_error "双节点状态文件 IPv6 端口无效: ${REALITY_PORT_V6:-空}"; pause; return 1; }
    local old_private_key="$REALITY_PRIVATE_KEY" old_public_key="$REALITY_PUBLIC_KEY" old_short_id="$REALITY_SHORT_ID" keys new_config
    keys=$(reality_generate_keypair) || return 1
    REALITY_PRIVATE_KEY=$(sed -n '1p' <<< "$keys")
    REALITY_PUBLIC_KEY=$(sed -n '2p' <<< "$keys")
    REALITY_SHORT_ID=$(reality_generate_short_id)
    new_config=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") || return 1
    if ! reality_apply_singbox_config "$new_config"; then
        REALITY_PRIVATE_KEY="$old_private_key"
        REALITY_PUBLIC_KEY="$old_public_key"
        REALITY_SHORT_ID="$old_short_id"
        pause; return 1
    fi
    reality_write_state; reality_write_client_artifacts
    print_success "Reality Key/ShortID 已轮换"
    reality_show_info
}

reality_cf_sync_menu() {
    reality_load_state || { print_error "未发现状态文件"; pause; return 1; }
    local domain="${REALITY_RELAY_DOMAIN:-$REALITY_NODE_DOMAIN}" token="" mode
    mode=$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo "auto")
    if [[ "$mode" != "split" ]]; then
        [[ -n "$domain" ]] || { print_error "状态文件缺少域名"; pause; return 1; }
    fi
    read -s -r -p "Cloudflare API Token: " token; echo ""
    if [[ "$mode" == "split" ]]; then
        reality_sync_cloudflare_dns_by_state "$token"
    else
        reality_sync_cloudflare_dns "$domain" "$token" "$mode"
    fi
    pause
}

reality_update_node_name() {
    reality_load_state || { print_error "未发现状态文件"; pause; return 1; }
    local old_name new_name
    old_name="$(reality_effective_node_name)"
    new_name=$(reality_prompt_node_name "$old_name") || return 1
    REALITY_NODE_NAME="$new_name"
    if [[ "$(reality_normalize_dns_mode "${REALITY_DNS_MODE:-auto}" 2>/dev/null || echo auto)" == "split" ]]; then
        REALITY_NODE_NAME_V4="$(reality_node_name_with_suffix "$new_name" "-ipv4")"
        REALITY_NODE_NAME_V6="$(reality_node_name_with_suffix "$new_name" "-ipv6")"
    fi
    reality_write_state
    if [[ -n "${REALITY_UUID:-}" && -n "${REALITY_SNI:-}" && -n "${REALITY_PUBLIC_KEY:-}" && -n "${REALITY_SHORT_ID:-}" ]]; then
        reality_write_client_artifacts || true
    fi
    print_success "节点名称已更新: $new_name"
    pause
}

# ── CDN 链路安装/卸载/信息 向导 ──

# 选一个未占用的内部 WS 端口（127.0.0.1，高位随机）
reality_cdn_pick_inner_port() {
    local p
    validate_port "${REALITY_CDN_ORIGIN_PORT:-8443}" || return 1
    for _ in $(seq 1 200); do
        p=$(reality_random_port) || return 1
        [[ "$p" == "${REALITY_PORT:-}" || "$p" == "${REALITY_PORT_V6:-}" ]] && continue
        [[ "$p" == "${REALITY_CDN_ORIGIN_PORT:-8443}" ]] && continue
        # MED-4：避开本项目其他 feature 已保留(含当前停止的 relay/共存)的端口，避免重启后 bind 冲突。
        reality_port_reserved "$p" && continue
        reality_port_in_use "$p" && continue
        echo "$p"; return 0
    done
    return 1
}

# 生成隐秘 WS path（/ + 16 位 hex）
reality_cdn_gen_ws_path() {
    if command_exists openssl; then
        printf '/%s' "$(openssl rand -hex 8)"
    else
        printf '/%s' "$(tr -dc '0-9a-f' < /dev/urandom 2>/dev/null | head -c 16)"
    fi
}

# 为 Reality 节点加挂 CDN 链路（VLESS+WS+TLS 橙云 + 优选 IP）。
# 前置：本机已是 Reality 落地机（有 state、sing-box 在跑）。
reality_cdn_install() {
    print_title "为 Reality 节点加挂 CDN 链路（橙云 + 优选 IP，主打晚高峰）"
    reality_require_supported_os || { pause; return 1; }
    if ! reality_load_state || [[ -z "${REALITY_UUID:-}" || -z "${REALITY_PORT:-}" ]]; then
        print_error "本机尚未安装 Reality 落地机，请先用菜单 1 安装落地机再加挂 CDN 链路。"
        pause; return 1
    fi
    command_exists nginx || { print_error "Nginx 未安装。请先用 Web 菜单「添加域名」安装 nginx/certbot 依赖。"; pause; return 1; }
    command_exists certbot || { print_error "certbot 未安装。请先用 Web 菜单「添加域名」安装依赖。"; pause; return 1; }

    local had_cdn_state=0 old_cdn_state=""
    if [[ -f "$REALITY_CDN_STATE_FILE" ]]; then
        had_cdn_state=1
        old_cdn_state=$(cat "$REALITY_CDN_STATE_FILE" 2>/dev/null || true)
        if reality_cdn_load_state 2>/dev/null && [[ -n "${REALITY_CDN_DOMAIN:-}" ]]; then
            print_warn "检测到已存在 CDN 链路: ${REALITY_CDN_DOMAIN}（覆盖前会保留旧 state，失败自动恢复）"
            confirm "是否覆盖重建 CDN 链路?" || { print_info "已取消"; pause; return 0; }
        else
            print_warn "检测到旧 CDN state 但校验失败；继续会覆盖它。"
            confirm "是否覆盖旧 CDN state?" || { print_info "已取消"; pause; return 0; }
        fi
    fi
    local had_cdn_link=0 old_cdn_link="" had_cdn_client_json=0 old_cdn_client_json=""
    if [[ -f "$REALITY_CDN_LINK_FILE" ]]; then
        had_cdn_link=1
        old_cdn_link=$(cat "$REALITY_CDN_LINK_FILE" 2>/dev/null || true)
    fi
    if [[ -f "$REALITY_CDN_CLIENT_JSON" ]]; then
        had_cdn_client_json=1
        old_cdn_client_json=$(cat "$REALITY_CDN_CLIENT_JSON" 2>/dev/null || true)
    fi

    echo "  说明：Reality 直连链路（灰云）原样保留；这里新增一条 CDN 链路并存。"
    echo "  CDN 链路用 CF 橙云 + 优选 IP，把「国内→落地IP」被干扰的那跳换成「国内→CF边缘→回源」。"
    echo "  回源用真实证书 Full(strict)；因 Reality 已占 443，CDN 回源走独立端口 ${REALITY_CDN_ORIGIN_PORT}（自动建 CF Origin Rule 改写回源端口）。"
    echo ""

    # CF Token
    local cf_token; cf_token=$(reality_prompt_cf_token)
    [[ -n "$cf_token" ]] || { print_error "CDN 链路需要 CF Token（签证书=DNS-01、橙云 DNS、Origin Rule 都要）。"; pause; return 1; }

    # CDN 域名
    local cdn_domain=""
    while [[ -z "$cdn_domain" ]]; do
        echo -e "${C_CYAN}CDN 链路域名说明:${C_RESET}"
        echo "  这是开启橙云（小云朵）的域名，客户端 host/sni 都填它；server 字段后续由优选 IP 替换。"
        echo "  建议用与 Reality 节点不同的新子域，例如 cdn-us-01。"
        cdn_domain=$(reality_prompt_domain_with_zones "CDN 链路" "$cf_token" "$(hostname)-cdn")
        validate_domain "$cdn_domain" || { print_error "域名无效"; cdn_domain=""; }
    done

    local cdn_name; cdn_name=$(reality_prompt_node_name "cdn-${cdn_domain%%.*}")

    # 内部端口 / WS path
    local inner_port ws_path
    inner_port=$(reality_cdn_pick_inner_port) || { print_error "无法分配内部 WS 端口"; pause; return 1; }
    ws_path=$(reality_cdn_gen_ws_path)
    local origin_port="${REALITY_CDN_ORIGIN_PORT:-8443}"
    validate_port "$origin_port" || { print_error "CDN 回源端口无效: ${origin_port}"; pause; return 1; }
    reality_validate_ws_path "$ws_path" || { print_error "生成的 WS path 无效: ${ws_path}"; pause; return 1; }

    draw_line
    echo "CDN 链路配置确认:"
    echo "  CDN 域名      : ${cdn_domain}（CF 橙云 proxied=true）"
    echo "  回源端口      : ${origin_port}（nginx TLS 终止；CF Origin Rule 改写回源到此端口）"
    echo "  WS 隐秘 path  : ${ws_path}"
    echo "  内部 WS 端口  : 127.0.0.1:${inner_port}（sing-box vless-ws 入站，明文）"
    echo "  节点名称      : ${cdn_name}"
    echo "  将自动执行    : DNS-01 签证书 → 渲染 nginx 回源站 → 合并 WS 入站重渲 sing-box → 橙云 DNS → Origin Rule → 放行 ${origin_port}/tcp"
    draw_line
    confirm "确认开始为该节点加挂 CDN 链路?" || { print_info "已取消"; pause; return 0; }

    # 1) DNS-01 签证书（橙云后面必须 DNS-01，HTTP-01 被橙云拦）
    echo -e "\n${C_CYAN}=== [1] 签发证书 (DNS-01) ===${C_RESET}"
    local cert_dir="${CERT_PATH_PREFIX}/${cdn_domain}"
    local cert_snapshot_dir
    cert_snapshot_dir=$(mktemp -d "${REALITY_CONFIG_DIR%/}/.cdn-cert-rollback.XXXXXX") || { print_error "创建证书回滚快照目录失败"; pause; return 1; }
    chmod 700 "$cert_snapshot_dir" 2>/dev/null || true
    local cert_dir_preexisting=0 cf_cred_preexisting=0 hook_preexisting=0 le_live_preexisting=0 cron_preexisting=0
    if [[ -e "$cert_dir" || -L "$cert_dir" ]]; then
        cert_dir_preexisting=1
        cp -a "$cert_dir" "$cert_snapshot_dir/cert-dir" 2>/dev/null || true
    fi
    local cf_cred hook le_live_dir
    cf_cred="$(reality_cdn_cf_cred_path "$cdn_domain")"
    hook="${CERT_HOOKS_DIR}/renew-${cdn_domain}.sh"
    le_live_dir="$(reality_cdn_le_live_dir "$cdn_domain")"
    if [[ -e "$cf_cred" || -L "$cf_cred" ]]; then
        cf_cred_preexisting=1
        cp -a "$cf_cred" "$cert_snapshot_dir/cf-cred" 2>/dev/null || true
    fi
    if [[ -e "$hook" || -L "$hook" ]]; then
        hook_preexisting=1
        cp -a "$hook" "$cert_snapshot_dir/hook" 2>/dev/null || true
    fi
    if [[ -e "$le_live_dir" || -L "$le_live_dir" ]]; then
        le_live_preexisting=1
        cp -a "$le_live_dir" "$cert_snapshot_dir/le-live" 2>/dev/null || true
    fi
    if command_exists crontab && crontab -l 2>/dev/null | grep -Fq "CertRenew_${cdn_domain}"; then
        cron_preexisting=1
        crontab -l 2>/dev/null > "$cert_snapshot_dir/crontab" || true
    fi
    local cleanup_cert_dir=0 cleanup_cred=0 cleanup_hook=0 cleanup_cron=0 cleanup_le=0
    [[ "$cert_dir_preexisting" -eq 0 ]] && cleanup_cert_dir=1
    [[ "$cf_cred_preexisting" -eq 0 ]] && cleanup_cred=1
    [[ "$hook_preexisting" -eq 0 ]] && cleanup_hook=1
    [[ "$le_live_preexisting" -eq 0 ]] && cleanup_le=1
    mkdir -p "$cert_dir" || { print_error "证书目录创建失败"; pause; return 1; }
    write_private_file_atomic "$cf_cred" "dns_cloudflare_api_token = $cf_token" || { print_error "Cloudflare 凭据写入失败"; reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" 0 0 0 0 "$cert_snapshot_dir"; pause; return 1; }
    if [[ -f "${cert_dir}/fullchain.pem" && -f "${cert_dir}/privkey.pem" ]]; then
        print_info "检测到已有证书，复用: ${cert_dir}"
    else
        print_info "正在申请证书 (DNS 验证，可能 1-2 分钟)..."
        if certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$cf_cred" \
            --dns-cloudflare-propagation-seconds 60 -d "$cdn_domain" \
            --email "$EMAIL" --agree-tos --no-eff-email --non-interactive; then
            copy_cert_pair_atomic "${le_live_dir}/fullchain.pem" "${le_live_dir}/privkey.pem" "$cert_dir" || {
                print_error "证书复制失败"
                reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" 0 0 "$cleanup_le" "$cert_snapshot_dir"
                pause; return 1
            }
            print_success "证书签发成功"
            # 续签 hook：复制证书 + reload nginx
            mkdir -p "$CERT_HOOKS_DIR" || { print_error "续签 Hook 目录创建失败"; reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" 0 0 "$cleanup_le" "$cert_snapshot_dir"; pause; return 1; }
            write_file_atomic "$hook" "#!/bin/bash
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LIVE=${le_live_dir}
CERT_DIR=\"${cert_dir}\"
$(render_cert_pair_hook_helper)
copy_cert_pair_atomic \"\$LIVE/fullchain.pem\" \"\$LIVE/privkey.pem\" \"\$CERT_DIR\" || exit 1
systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null || true
"
            chmod +x "$hook" || { print_error "续签 Hook 授权失败"; reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" 0 "$cleanup_le" "$cert_snapshot_dir"; pause; return 1; }
            cron_add_job "CertRenew_${cdn_domain}" "$(( $(echo "$cdn_domain" | cksum | cut -d' ' -f1) % 60 )) 3 * * * certbot renew --quiet --cert-name '${cdn_domain}' --deploy-hook '${hook}' # CertRenew_${cdn_domain}" || {
                print_error "自动续签 cron 配置失败"
                reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
                pause; return 1
            }
            cleanup_cron=1
        else
            print_error "证书申请失败，已中止 CDN 安装。请检查 Token 权限(Zone:DNS Edit)与域名。"
            reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" 0 0 "$cleanup_le" "$cert_snapshot_dir"
            pause; return 1
        fi
    fi

    # 2) nginx 回源站
    echo -e "\n${C_CYAN}=== [2] 部署 nginx 回源站 (端口 ${origin_port}) ===${C_RESET}"
    _ensure_ssl_params
    local nginx_conf
    nginx_conf=$(reality_cdn_render_nginx_conf "$cdn_domain" "$origin_port" "$ws_path" "$inner_port" "$cert_dir") || {
        print_error "渲染 nginx 回源站失败，请检查域名/端口/path。"
        reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        pause; return 1
    }
    local nginx_site
    nginx_site="$(reality_cdn_nginx_site_name "$cdn_domain")"
    if ! _nginx_deploy_conf "$nginx_site" "$nginx_conf"; then
        print_error "nginx 回源站部署失败，已中止。"
        reality_cdn_cleanup_cert_resources "$cdn_domain" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        pause; return 1
    fi
    local nginx_deployed=1
    print_success "nginx 回源站已生效"

    # 3) 写 CDN state 并合并重渲 sing-box（WS 入站随 Reality 一并渲染）
    echo -e "\n${C_CYAN}=== [3] 合并渲染 sing-box（Reality + CDN WS 入站）===${C_RESET}"
    REALITY_CDN_DOMAIN="$cdn_domain"
    REALITY_CDN_UUID="$REALITY_UUID"   # 复用落地 UUID，少记一套；WS 入站无 reality/flow
    REALITY_CDN_WS_PATH="$ws_path"
    REALITY_CDN_INNER_PORT="$inner_port"
    REALITY_CDN_ORIGIN_PORT="$origin_port"
    REALITY_CDN_PREFER_IP=""
    REALITY_CDN_NODE_NAME="$cdn_name"
    if ! reality_cdn_write_state; then
        print_error "写入 CDN state 失败，已中止。"
        reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 0 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        pause; return 1
    fi
    local new_config
    if ! new_config=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID"); then
        print_error "渲染 sing-box 配置失败，已回滚 CDN state/nginx。"
        reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 1 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        pause; return 1
    fi
    if ! reality_apply_singbox_config "$new_config"; then
        reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 1 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        print_error "sing-box 应用失败（已回滚原配置）。已恢复安装前 CDN state，避免后续重渲染误带半成品 WS 入站。"
        pause; return 1
    fi
    print_success "sing-box 已合并 CDN WS 入站"

    # 4) 橙云 DNS
    echo -e "\n${C_CYAN}=== [4] 同步 CF 橙云 DNS ===${C_RESET}"
    if ! reality_cdn_sync_dns_orange "$cdn_domain" "$cf_token"; then
        reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 1 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        print_error "橙云 DNS 同步失败，已回滚 CDN 本机配置。请修复 Cloudflare DNS 权限或网络后重试。"
        pause; return 1
    fi

    # 5) Origin Rule：回源端口改写到 origin_port
    echo -e "\n${C_CYAN}=== [5] 设置 CF Origin Rule（回源端口 ${origin_port}）===${C_RESET}"
    if ! reality_cdn_apply_origin_rule "$cdn_domain" "$cf_token" "$origin_port"; then
        reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 1 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        print_error "Origin Rule 设置失败，已回滚 CDN 本机配置。未设置时 CF 默认回源 443 会撞到 Reality。"
        pause; return 1
    fi

    # 6) 放行回源端口
    echo -e "\n${C_CYAN}=== [6] 防火墙放行 ${origin_port}/tcp ===${C_RESET}"
    local fw_rc=0
    if declare -F firewall_allow_tcp_port >/dev/null 2>&1; then
        firewall_allow_tcp_port "$origin_port" "CDN-origin"
        fw_rc=$?
        case "$fw_rc" in
            0)
                print_success "已放行 ${origin_port}/tcp"
                ;;
            2)
                print_warn "请确认云安全组已放行 ${origin_port}/tcp（CF 回源需要）。"
                ;;
            *)
                reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 1 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
                print_error "防火墙放行 ${origin_port}/tcp 失败，已回滚 CDN 本机配置。"
                print_info "请修复 UFW 后重新执行 CDN 安装。"
                pause; return 1
                ;;
        esac
    else
        print_warn "未找到防火墙放行 helper，请手动确认 ${origin_port}/tcp 已放行。"
    fi

    if ! reality_cdn_write_client_artifacts; then
        reality_cdn_install_rollback "$had_cdn_state" "$old_cdn_state" "$cdn_domain" "$nginx_deployed" 1 "$had_cdn_link" "$old_cdn_link" "$had_cdn_client_json" "$old_cdn_client_json" "$cleanup_cert_dir" "$cleanup_cred" "$cleanup_hook" "$cleanup_cron" "$cleanup_le" "$cert_snapshot_dir"
        print_error "写入 CDN 客户端产物失败，已回滚 CDN 本机配置。"
        pause; return 1
    fi
    # 不要删 $cf_cred —— certbot 续签(renewal conf 的 dns_cloudflare_credentials)长期依赖它;
    # 它已 chmod 600。仅签发失败分支才删,成功后必须保留,否则证书到期无法自动续签。
    rm -rf -- "$cert_snapshot_dir" 2>/dev/null || true
    draw_line
    print_success "CDN 链路加挂完成！"
    echo "  客户端链接（server 暂为域名，优选后由国内机 B+C 自动替换为优选 IP）:"
    [[ -f "$REALITY_CDN_LINK_FILE" ]] && cat "$REALITY_CDN_LINK_FILE"
    echo ""
    echo "  下一步（B/C，在国内机执行）:"
    echo "   - B: 跑 CloudflareSpeedTest 优选 CF 边缘 IP（必须国内侧跑）"
    echo "   - C: 生成本地节点文件；如启用固定入口模式，则只更新独立 entry 域名的 DNS（host/sni 保留 ${cdn_domain}）"
    echo "   仓库已提供脚本：scripts/cdn-preferip/（见同目录 README）"
    draw_line
    log_action "CDN link installed: domain=$cdn_domain origin_port=$origin_port inner=$inner_port"
    pause
}

# 卸载 CDN 链路：移除 WS 入站（重渲 sing-box）、nginx 回源站、state/产物。
# 不动 Reality 直连链路；CF 橙云 DNS/Origin Rule 提示用户手动清理（避免误删）。
reality_cdn_uninstall() {
    print_title "卸载 CDN 链路"
    reality_cdn_load_state || { print_warn "未发现 CDN 链路配置"; pause; return 0; }
    confirm "确认卸载 CDN 链路 ${REALITY_CDN_DOMAIN:-}? Reality 直连链路不受影响。" || return 0
    local cdn_domain="${REALITY_CDN_DOMAIN:-}" origin_port="${REALITY_CDN_ORIGIN_PORT:-8443}"
    local old_cdn_state
    old_cdn_state=$(cat "$REALITY_CDN_STATE_FILE" 2>/dev/null || true)
    # 先删 state，使重渲不再带 WS 入站
    rm -f "$REALITY_CDN_STATE_FILE"
    if reality_load_state && [[ -n "${REALITY_UUID:-}" && -n "${REALITY_PORT:-}" ]]; then
        local cfg
        if ! cfg=$(reality_render_singbox_config "$REALITY_UUID" "$REALITY_PRIVATE_KEY" "$REALITY_PORT" "$REALITY_SNI" "$REALITY_SHORT_ID") || \
           ! reality_apply_singbox_config "$cfg"; then
            reality_write_secure_file "$REALITY_CDN_STATE_FILE" "$old_cdn_state" || true
            print_error "sing-box 重渲失败，已恢复 CDN state；未删除 nginx 回源站/产物，避免出现“配置仍生效但 state 丢失”。"
            pause; return 1
        fi
    fi
    # 删 nginx 回源站
    if [[ -n "$cdn_domain" ]]; then
        reality_cdn_remove_nginx_conf "$cdn_domain"
        if command_exists nginx && nginx -t >/dev/null 2>&1; then _nginx_reload >/dev/null 2>&1 || true; fi
    fi
    # 回收端口
    if command_exists ufw && ufw_is_active; then ufw delete allow "${origin_port}/tcp" >/dev/null 2>&1 || true; fi
    rm -f "$REALITY_CDN_LINK_FILE" "$REALITY_CDN_CLIENT_JSON"
    print_success "CDN 链路已卸载（WS 入站已移除、nginx 回源站已删）。"
    [[ -n "$cdn_domain" ]] && print_info "如不再使用，请到 CF 后台手动删除 ${cdn_domain} 的橙云 DNS 与 Origin Rule（脚本不自动删，避免误删其它规则）。"
    pause
}

reality_delete_node_info() {
    print_title "删除 Reality 节点信息"
    confirm "确认删除本机 Reality/Realm 管理信息? 不会卸载 sing-box 软件包" || return 0
    reality_load_state || true
    firewall_remove_reality_ports
    systemctl disable --now realm 2>/dev/null || true
    rm -f "$(_reality_realm_service_path)"
    systemctl daemon-reload 2>/dev/null || true
    reality_backup_file "$REALITY_SINGBOX_CONFIG"
    if [[ -f "$REALITY_SINGBOX_CONFIG" ]]; then
        systemctl disable --now sing-box 2>/dev/null || true
        rm -f "$REALITY_SINGBOX_CONFIG"
    fi
    rm -f "$(_reality_realm_config_path)"
    rm -f "$REALITY_STATE_FILE" "$REALITY_LINK_FILE" "$REALITY_CLIENT_JSON" \
          "$REALITY_LINK_FILE_V4" "$REALITY_LINK_FILE_V6" "$REALITY_CLIENT_JSON_V4" "$REALITY_CLIENT_JSON_V6"
    # CDN 链路 state/产物（nginx 回源站与 CF 规则由 reality_cdn_uninstall 处理；此处只清本机管理信息）
    rm -f "$REALITY_CDN_STATE_FILE" "$REALITY_CDN_LINK_FILE" "$REALITY_CDN_CLIENT_JSON"
    # 443 共存：移除 stream 分流配置 + nginx.conf include + coexist state，并 reload nginx 释放 443。
    # 复用 disable_internal（它还会尝试把 sing-box 改回直绑，但下面随即删 state/停服，无副作用）。
    if reality_coexist_enabled 2>/dev/null; then
        reality_coexist_disable_internal
    fi
    # 清理多路中转线路（保留 backups 目录，不 rm -rf 整个配置目录）
    rm -f "$REALITY_RELAY_DIR"/relay-*.conf "$REALITY_RELAY_DIR"/relay-*.link.txt "$REALITY_RELAY_DIR"/relay-*.client.json 2>/dev/null || true
    rmdir "$REALITY_RELAY_DIR" 2>/dev/null || true
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
        echo "1. 查看节点信息（含客户端链接）"
        echo "2. 修改节点名称/备注"
        echo "3. 删除节点信息"
        echo "0. 返回"
        read -e -r -p "请选择: " c
        case "$c" in
            1) reality_show_info ;;
            2) reality_update_node_name ;;
            3) reality_delete_node_info ;;
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
        echo "2. 中转线路管理（多落地中转）"
        echo "3. 查看/修改节点信息"
        echo "4. 检查服务状态"
        echo "5. 重启服务"
        echo "6. 同步 Cloudflare DNS/DDNS"
        echo "7. 轮换 UUID"
        echo "8. 轮换 Reality Key"
        echo "9. 诊断/自检"
        echo "10. 加挂 CDN 链路（橙云+优选IP，治晚高峰）"
        echo "11. 卸载 CDN 链路"
        if reality_coexist_enabled 2>/dev/null; then
            echo "12. 关闭 443 共存模式（nginx stream 分流）★ 已启用"
        else
            echo "12. 启用 443 共存模式（nginx stream 分流，Reality 与真站共用 443）"
        fi
        echo "0. 返回"
        read -e -r -p "请选择: " c
        case "$c" in
            1) reality_install_wizard --landing ;;
            2) reality_relay_menu ;;
            3) reality_info_menu ;;
            4) reality_status ;;
            5) reality_restart ;;
            6) reality_cf_sync_menu ;;
            7) reality_rotate_user ;;
            8) reality_rotate_key ;;
            9) reality_diagnose ;;
            10) reality_cdn_install ;;
            11) reality_cdn_uninstall ;;
            12) if reality_coexist_enabled 2>/dev/null; then reality_coexist_disable; else reality_coexist_enable; fi ;;
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
        cdn-install|cdn) reality_cdn_install ;;
        cdn-uninstall) reality_cdn_uninstall ;;
        coexist-enable|coexist-on) reality_coexist_enable ;;
        coexist-disable|coexist-off) reality_coexist_disable ;;
        delete|uninstall) reality_delete_node_info ;;
        *) print_error "未知 Reality 命令: $cmd"; return 1 ;;
    esac
}
