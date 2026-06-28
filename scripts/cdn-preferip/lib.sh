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
    # CDN_UUID/DOMAIN/WS_PATH 仅旧「单节点」模式需要;新「多节点」(nodes.txt)模式从链接里读,故改可选
    CDN_UUID="${CDN_UUID:-}"; CDN_DOMAIN="${CDN_DOMAIN:-}"; CDN_WS_PATH="${CDN_WS_PATH:-}"
    CDN_NODE_NAME="${CDN_NODE_NAME:-cdn-${CDN_DOMAIN%%.*}}"
    CFST_TOP_N="${CFST_TOP_N:-1}"
    KEEP_ON_EMPTY="${KEEP_ON_EMPTY:-true}"
    # 公网 https 务必加密传输 secret
    [[ "$SUBSTORE_BASE" == https://* ]] || log "警告: SUBSTORE_BASE 非 https，secret 前缀会明文暴露在链路上"
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
        "$CDN_UUID" "$server" "$CDN_DOMAIN" "$CDN_DOMAIN" "$(urlencode "$CDN_WS_PATH")" "$(urlencode "$name")"
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
    local hostport="${after%%\?*}"               # HOST:PORT
    local query=""; [[ "$after" == *\?* ]] && query="${after#*\?}"
    local port="${hostport##*:}"; [[ "$port" == "$hostport" ]] && port="443"
    local out="vless://${uuid}@${newip}:${port}"
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
