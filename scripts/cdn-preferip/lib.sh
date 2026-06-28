#!/usr/bin/env bash
# scripts/cdn-preferip/lib.sh
# B/C 共享：配置加载、日志、节点串拼装、sub-store API 封装。
# 不进 v4-built.sh；在【国内机】独立运行。

set -u

CDN_PREFERIP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CDN_PREFERIP_CONF="${CDN_PREFERIP_CONF:-$CDN_PREFERIP_DIR/cdn-preferip.conf}"

log() { printf '[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

require_cmd() { command -v "$1" >/dev/null 2>&1 || die "缺少依赖命令: $1"; }

load_conf() {
    [[ -f "$CDN_PREFERIP_CONF" ]] || die "配置文件不存在: $CDN_PREFERIP_CONF（请 cp cdn-preferip.conf.example cdn-preferip.conf 后填写）"
    # shellcheck disable=SC1090
    source "$CDN_PREFERIP_CONF"
    : "${SUBSTORE_BASE:?配置缺少 SUBSTORE_BASE}"
    : "${SUBSTORE_SUB_NAME:?配置缺少 SUBSTORE_SUB_NAME}"
    SUBSTORE_BASE="${SUBSTORE_BASE%/}"
    if [[ "$SUBSTORE_BASE" == */api ]]; then
        SUBSTORE_BASE="${SUBSTORE_BASE%/api}"
        log "提示: SUBSTORE_BASE 已自动去掉末尾 /api，脚本会自行拼接 /api"
    fi
    # CDN_UUID/DOMAIN/WS_PATH 仅旧「单节点」模式需要;新「多节点」(nodes.txt)模式从链接里读,故改可选
    CDN_UUID="${CDN_UUID:-}"; CDN_DOMAIN="${CDN_DOMAIN:-}"; CDN_WS_PATH="${CDN_WS_PATH:-}"
    CDN_NODE_NAME="${CDN_NODE_NAME:-cdn-${CDN_DOMAIN%%.*}}"
    CFST_TOP_N="${CFST_TOP_N:-1}"
    [[ "$CFST_TOP_N" =~ ^[0-9]+$ && "$CFST_TOP_N" -ge 1 ]] || die "CFST_TOP_N 必须是 >=1 的整数"
    DEFAULT_CF_COLO="${DEFAULT_CF_COLO:-}"
    CFST_COLO_MODE="${CFST_COLO_MODE:-auto}"  # auto=nodes.txt 有地区码就按地区优选; off=全局优选
    CFST_COLO_MODE="${CFST_COLO_MODE,,}"
    case "$CFST_COLO_MODE" in
        auto|off) ;;
        *) die "CFST_COLO_MODE 只能是 auto / off" ;;
    esac
    # 某节点所需地区没有结果时：
    #   keep   = 保留 nodes.txt 原链接里的 server，仅更新有结果的节点（推荐）
    #   abort  = 中止整次 PATCH，完全保留 sub-store 现状
    #   global = 回退到全局优选 IP（仅在明确接受跨地区覆盖时使用）
    MISSING_COLO_POLICY="${MISSING_COLO_POLICY:-keep}"
    MISSING_COLO_POLICY="${MISSING_COLO_POLICY,,}"
    case "$MISSING_COLO_POLICY" in
        keep|abort|global) ;;
        *) die "MISSING_COLO_POLICY 只能是 keep / abort / global" ;;
    esac
    KEEP_ON_EMPTY="${KEEP_ON_EMPTY:-true}"
    # 公网 https 务必加密传输 secret
    [[ "$SUBSTORE_BASE" == https://* ]] || log "警告: SUBSTORE_BASE 非 https，secret 前缀会明文暴露在链路上"
}

trim() {
    local s="${1:-}"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}

normalize_colo_key() {
    # 支持 HKG / NRT,KIX 这类 CF colo/IATA 码；去空白并转大写。
    local key="${1:-}"
    key="${key//[[:space:]]/}"
    key="${key^^}"
    [[ "$key" =~ ^[A-Z0-9]+(,[A-Z0-9]+)*$ ]] || return 1
    printf '%s' "$key"
}

result_key_for_colo() {
    local colo="${1:-}" key=""
    if [[ -n "$colo" ]] && key=$(normalize_colo_key "$colo" 2>/dev/null); then
        printf '%s' "$key"
    else
        printf 'GLOBAL'
    fi
}

NODE_NOTE=""; NODE_COLO=""; NODE_LINK=""
parse_node_line() {
    # 兼容两种格式：
    #   旧: 备注|vless链接
    #   新: 备注|CF地区码|vless链接       例如: 香港-01|HKG|vless://...
    # 地区码可填多个逗号分隔候选，例如: 日本-01|NRT,KIX|vless://...
    local raw="${1:-}" trimmed f1 f2 f3 rest
    NODE_NOTE=""; NODE_COLO=""; NODE_LINK=""
    [[ -n "${raw//[[:space:]]/}" ]] || return 1
    trimmed="$(trim "$raw")"
    [[ "$trimmed" == \#* ]] && return 1
    IFS='|' read -r f1 f2 f3 rest <<< "$raw"
    f1="$(trim "$f1")"; f2="$(trim "$f2")"; f3="$(trim "$f3")"
    if [[ "$f2" == vless://* ]]; then
        NODE_NOTE="$f1"
        NODE_COLO="${DEFAULT_CF_COLO:-}"
        NODE_LINK="$f2"
    elif [[ "$f3" == vless://* ]]; then
        NODE_NOTE="$f1"
        NODE_COLO="$f2"
        NODE_LINK="$f3"
    else
        return 1
    fi
    [[ -n "$NODE_NOTE" && "$NODE_LINK" == vless://* ]] || return 1
    if [[ -n "$NODE_COLO" ]]; then
        NODE_COLO="$(normalize_colo_key "$NODE_COLO")" || return 1
    fi
    return 0
}

uri_host() {
    local host="${1:-}"
    if [[ "$host" == \[*\] ]]; then
        printf '%s' "$host"
    elif [[ "$host" == *:* ]]; then
        printf '[%s]' "$host"
    else
        printf '%s' "$host"
    fi
}

is_ip_literal() {
    local ip="${1:-}"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ || ( "$ip" == *:* && "$ip" =~ ^[0-9A-Fa-f:.]+$ ) ]]
}

vless_hostport() {
    local link="${1:-}" body after hostport
    [[ "$link" == vless://* && "$link" == *"@"* ]] || return 1
    body="${link#vless://}"
    body="${body%%#*}"
    after="${body#*@}"
    hostport="${after%%\?*}"
    [[ -n "$hostport" ]] || return 1
    printf '%s' "$hostport"
}

vless_server() {
    local hostport
    hostport="$(vless_hostport "$1")" || return 1
    if [[ "$hostport" =~ ^\[([^]]+)\](:[0-9]+)?$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    elif [[ "$hostport" =~ ^([^:]+):[0-9]+$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    else
        # 无端口域名 / IPv4 / 未加括号 IPv6（兼容旧数据）
        printf '%s' "$hostport"
    fi
}

vless_port() {
    local hostport
    hostport="$(vless_hostport "$1")" || return 1
    if [[ "$hostport" =~ ^\[[^]]+\]:([0-9]+)$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    elif [[ "$hostport" =~ ^[^:]+:([0-9]+)$ ]]; then
        printf '%s' "${BASH_REMATCH[1]}"
    else
        printf '443'
    fi
}

# URL-encode（用于 ws path 等）
urlencode() {
    local s="$1" out="" i c
    local LC_ALL=C   # 关键:按字节处理,正确编码中文等多字节 UTF-8(否则会编成 Unicode 码点)
    for ((i=0; i<${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in
            [a-zA-Z0-9.~_-]) out+="$c" ;;
            *) printf -v c '%%%02X' "'${c}"; out+="$c" ;;
        esac
    done
    printf '%s' "$out"
}

# 拼一条 CDN 客户端 vless 链接：server=优选IP，host/sni=真实域名。
# 与落地机 reality_cdn_build_link 完全一致的格式。
build_cdn_link() {
    local server="$1" name="${2:-$CDN_NODE_NAME}"
    printf 'vless://%s@%s:443?encryption=none&security=tls&sni=%s&fp=chrome&type=ws&host=%s&path=%s#%s' \
        "$CDN_UUID" "$(uri_host "$server")" "$CDN_DOMAIN" "$CDN_DOMAIN" "$(urlencode "$CDN_WS_PATH")" "$(urlencode "$name")"
}

# 多节点模式:把一条现成 vless 链接的 server 换成优选IP、备注换成指定名,其余(uuid/port/host/sni/path)原样保留。
# 用法: rewrite_vless "<原链接>" "<优选IP>" "<新备注名>"  →  stdout 新链接
rewrite_vless() {
    local link="$1" newip="$2" newname="$3"
    [[ "$link" == vless://* ]] || return 1
    local body="${link#vless://}"
    body="${body%%#*}"                          # 去掉原 #备注
    local uuid="${body%%@*}"                     # UUID(@前)
    local after="${body#*@}"                     # HOST:PORT?QUERY
    local query=""; [[ "$after" == *\?* ]] && query="${after#*\?}"
    local port; port="$(vless_port "$link")" || port="443"
    local out="vless://${uuid}@$(uri_host "$newip"):${port}"
    [[ -n "$query" ]] && out="${out}?${query}"
    printf '%s#%s' "$out" "$(urlencode "$newname")"
}

# ── sub-store API ──
# 真实路由（已实测）：GET /api/subs、GET/PATCH/DELETE /api/sub/:name、PUT /api/subs
substore_api() {
    local method="$1" path="$2"; shift 2
    curl -fsS --max-time 30 -X "$method" "${SUBSTORE_BASE}/api${path}" \
        -H "Content-Type: application/json" "$@"
}

# 取单条订阅 JSON（.data）；不存在返回非 0
substore_get_sub() {
    local name="$1" resp
    resp=$(substore_api GET "/sub/$(urlencode "$name")") || return 1
    [[ "$(jq -r '.status // empty' <<< "$resp")" == "success" ]] || return 1
    jq -c '.data' <<< "$resp"
}

# 该专用订阅是否已存在
substore_sub_exists() {
    substore_get_sub "$1" >/dev/null 2>&1
}
