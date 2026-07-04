#!/usr/bin/env bash
# scripts/cdn-preferip/preferip-push.sh  (C 块：生成本地节点文件 + 可选同步 DNS)
#
# 多节点模式(推荐)：读 nodes.txt，每行可写：
#   旧格式: 区域备注|vless链接
#   新格式: 区域备注|CF地区码|vless链接    例如 香港-01|HKG|vless://...
#   混合池: 区域备注|CF地区码|ipv6|vless链接 或 区域备注|HKG@ipv6|vless://...
#   C 会按每个节点的 CF 地区码选择对应优选 IP；host/sni/uuid/path 全保留，输出到本地渲染文件。
# 单节点模式(旧/兼容)：若无 nodes.txt 但 conf 填了 CDN_UUID/DOMAIN/WS_PATH，则按单节点拼。
#
# 安全：只写本地输出文件和可选 DNS，不依赖任何订阅后端。
# 兜底：优选结果为空则不写新文件(KEEP_ON_EMPTY=true)，避免把客户端刷成空 server。
# 缺地区结果策略：MISSING_COLO_POLICY=keep/abort/global；默认 keep，仅更新有结果的节点。

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
load_conf
require_cmd curl

RESULT_FILE="${RESULT_FILE:-$HERE/preferip.result}"
NODES_FILE="${NODES_FILE:-$HERE/nodes.txt}"

is_true() { [[ "${1:-}" =~ ^([Tt][Rr][Uu][Ee]|1|yes|YES|on|ON)$ ]]; }
is_number() { [[ "${1:-}" =~ ^[0-9]+([.][0-9]+)?$ ]]; }

append_history_event() {
    local key="$1" ip="$2" lat="${3:-}" speed="${4:-}" count="${5:-}" event="${6:-applied}" note="${7:-}"
    [[ -n "${PREFERIP_HISTORY_FILE:-}" ]] || return 0
    mkdir -p "$(dirname "$PREFERIP_HISTORY_FILE")" 2>/dev/null || true
    if [[ ! -s "$PREFERIP_HISTORY_FILE" ]]; then
        printf 'timestamp,key,ip,avg_latency_ms,avg_speed_mbps,rounds_hit,event,note\n' >> "$PREFERIP_HISTORY_FILE" 2>/dev/null || return 0
    fi
    printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$(date '+%F %T')" "$key" "$ip" "$lat" "$speed" "$count" "$event" "$note" >> "$PREFERIP_HISTORY_FILE" 2>/dev/null || true
}

declare -A candidates_by_key=()
append_candidate() {
    local key="$1" ip="$2" lat="${3:-}" speed="${4:-}" count="${5:-}"
    is_ip_literal "$ip" || return 0
    candidates_by_key["$key"]+="${ip}|${lat}|${speed}|${count}"$'\n'
}

candidate_entries() {
    local key="$1"
    printf '%s' "${candidates_by_key[$key]:-}" | sed '/^[[:space:]]*$/d'
}

candidate_count() {
    local key="$1"
    candidate_entries "$key" | wc -l | tr -d '[:space:]'
}

entry_ip() { local e="$1"; printf '%s' "${e%%|*}"; }
entry_lat() { local e="$1" _ip b c d; IFS='|' read -r _ip b c d <<< "$e"; printf '%s' "$b"; }
entry_speed() { local e="$1" _ip b c d; IFS='|' read -r _ip b c d <<< "$e"; printf '%s' "$c"; }
entry_count() { local e="$1" _ip b c d; IFS='|' read -r _ip b c d <<< "$e"; printf '%s' "$d"; }

first_ip_for_key() {
    local key="$1" e
    e="$(candidate_entries "$key" | head -n 1)"
    [[ -n "$e" ]] || return 1
    entry_ip "$e"
}

# 1) 读优选 IP（B 的产出，兼容 v1/v2/v3）
if [[ ! -s "$RESULT_FILE" ]]; then
    log "优选结果文件不存在或为空: $RESULT_FILE"
    [[ "${KEEP_ON_EMPTY}" == "true" ]] && { log "KEEP_ON_EMPTY=true：不覆盖上次输出文件。"; exit 1; }
    die "无优选 IP 可推送"
fi
while IFS= read -r raw || [[ -n "$raw" ]]; do
    [[ -z "${raw//[[:space:]]/}" ]] && continue
    raw="$(trim "$raw")"
    [[ "$raw" == \#* ]] && continue
    if [[ "$raw" == *"|"* ]]; then
        IFS='|' read -r f1 f2 f3 f4 f5 _rest <<< "$raw"
        f1="$(trim "$f1")"; f2="$(trim "$f2")"; f3="$(trim "$f3")"; f4="$(trim "$f4")"; f5="$(trim "$f5")"
        if is_ip_literal "$f1"; then
            # 全局 v3: IP|lat|speed|rounds；也兼容误写成 IP|...
            append_candidate "GLOBAL" "$f1" "$f2" "$f3" "$f4"
        else
            key="$(normalize_result_key "$f1" 2>/dev/null || true)"
            [[ -n "$key" ]] || continue
            append_candidate "$key" "$f2" "$f3" "$f4" "$f5"
        fi
    else
        ip="$raw"
        append_candidate "GLOBAL" "$ip" "" "" ""
    fi
done < "$RESULT_FILE"
global_best="$(first_ip_for_key GLOBAL 2>/dev/null || true)"
group_keys="${!candidates_by_key[*]}"
[[ -n "$global_best" || -n "$group_keys" ]] || { log "结果文件无有效 IP"; exit 1; }
[[ -n "$group_keys" ]] || group_keys="无"
log "已读取优选结果：全局=${global_best:-无}，地区分组=${group_keys}"

# 2) 读取状态/黑名单工具
declare -A state_ip=()
if [[ -s "${PREFERIP_STATE_FILE:-}" ]]; then
    while IFS=$'\t' read -r note key ip lat speed count ts _rest || [[ -n "${note:-}" ]]; do
        [[ -z "${note//[[:space:]]/}" || "$note" == \#* ]] && continue
        : "$key" "$lat" "$speed" "$count" "$ts"
        state_ip["$note"]="$ip"
    done < "$PREFERIP_STATE_FILE"
fi

is_blacklisted() {
    local key="$1" ip="$2" now line f1 f2 f3 bkey bip until
    [[ -s "${PREFERIP_BAD_FILE:-}" ]] || return 1
    now="$(date +%s)"
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="$(trim "$line")"
        [[ -z "$line" || "$line" == \#* ]] && continue
        IFS='|' read -r f1 f2 f3 _rest <<< "$line"
        f1="$(trim "$f1")"; f2="$(trim "$f2")"; f3="$(trim "$f3")"
        bkey=""; bip=""; until=""
        if is_ip_literal "$f1"; then
            bip="$f1"; until="$f2"
        else
            bkey="$(normalize_result_key "$f1" 2>/dev/null || true)"
            bip="$f2"; until="$f3"
        fi
        [[ "$bip" == "$ip" ]] || continue
        [[ -n "$bkey" && "$bkey" != "$key" && "$bkey" != "GLOBAL" ]] && continue
        if [[ -n "$until" && "$until" =~ ^[0-9]+$ && "$until" -lt "$now" ]]; then
            continue
        fi
        return 0
    done < "$PREFERIP_BAD_FILE"
    return 1
}

blacklist_ip() {
    local key="$1" ip="$2" reason="${3:-probe_failed}" ttl="${PREFERIP_BAD_TTL_HOURS:-24}" until
    is_ip_literal "$ip" || return 0
    mkdir -p "$(dirname "$PREFERIP_BAD_FILE")" 2>/dev/null || true
    until="$(awk -v now="$(date +%s)" -v ttl="$ttl" 'BEGIN{printf "%d", now + ttl * 3600}')"
    printf '%s|%s|%s|%s\n' "$key" "$ip" "$until" "$reason" >> "$PREFERIP_BAD_FILE" 2>/dev/null || true
}

find_candidate_by_ip() {
    local key="$1" ip="$2" entry eip
    while IFS= read -r entry; do
        eip="$(entry_ip "$entry")"
        [[ "$eip" == "$ip" ]] && { printf '%s' "$entry"; return 0; }
    done < <(candidate_entries "$key")
    return 1
}

declare -A key_cursor=()
PICKED_ENTRY=""
pick_candidate() {
    local key="$1" idx start len off pos entry ip
    local -a entries=()
    PICKED_ENTRY=""
    mapfile -t entries < <(candidate_entries "$key")
    len="${#entries[@]}"
    [[ "$len" -gt 0 ]] || return 1
    idx="${key_cursor[$key]:-0}"
    if [[ "$PREFERIP_ASSIGN_MODE" == "first" ]]; then
        start=0
    else
        start=$((idx % len))
    fi
    for ((off=0; off<len; off++)); do
        pos=$(((start + off) % len))
        entry="${entries[$pos]}"
        ip="$(entry_ip "$entry")"
        if is_blacklisted "$key" "$ip"; then
            log "候选 ${key}/${ip} 在黑名单内，跳过"
            continue
        fi
        [[ "$PREFERIP_ASSIGN_MODE" == "round_robin" ]] && key_cursor["$key"]=$((pos + 1))
        PICKED_ENTRY="$entry"
        return 0
    done
    return 1
}

should_keep_current() {
    local cur="$1" new="$2" cur_ip new_ip cur_lat cur_speed new_lat new_speed
    cur_ip="$(entry_ip "$cur")"; new_ip="$(entry_ip "$new")"
    [[ "$cur_ip" == "$new_ip" ]] && return 0
    cur_lat="$(entry_lat "$cur")"; cur_speed="$(entry_speed "$cur")"
    new_lat="$(entry_lat "$new")"; new_speed="$(entry_speed "$new")"
    is_number "$cur_lat" && is_number "$cur_speed" && is_number "$new_lat" && is_number "$new_speed" || return 1
    awk -v cur_lat="$cur_lat" -v cur_speed="$cur_speed" \
        -v new_lat="$new_lat" -v new_speed="$new_speed" \
        -v min_speed="$PREFERIP_STICKY_MIN_SPEED" -v max_lat="$PREFERIP_STICKY_MAX_LATENCY" \
        -v min_speed_gain="$PREFERIP_SWITCH_MIN_SPEED_GAIN_PERCENT" \
        -v min_lat_gain="$PREFERIP_SWITCH_MIN_LATENCY_GAIN_MS" '
        BEGIN {
            if (cur_speed < min_speed || cur_lat > max_lat) exit 1
            speed_gain = (cur_speed > 0) ? ((new_speed - cur_speed) * 100 / cur_speed) : ((new_speed > cur_speed) ? 999 : 0)
            lat_gain = cur_lat - new_lat
            # 新 IP 没有明显更好，则保持当前 IP；明显更好才允许切换。
            if (speed_gain >= min_speed_gain || lat_gain >= min_lat_gain) exit 1
            exit 0
        }'
}

code_is_accepted() {
    local code="$1" list=",${PREFERIP_PROBE_ACCEPT_CODES//[[:space:]]/},"
    [[ "$code" =~ ^[0-9][0-9][0-9]$ ]] || return 1
    [[ "$list" == *",$code,"* ]]
}

probe_candidate() {
    local link="$1" ip="$2" note="$3" key="$4" domain path security scheme port resolve_ip code url
    is_true "$PREFERIP_PROBE_ENABLE" || return 0
    domain="$(vless_query_param "$link" sni 2>/dev/null || true)"
    [[ -n "$domain" ]] || domain="$(vless_query_param "$link" host 2>/dev/null || true)"
    if [[ -z "$domain" ]]; then
        log "节点 ${note}: 未找到 sni/host，跳过真实链路探活"
        return 0
    fi
    path="$(vless_query_param "$link" path 2>/dev/null || true)"
    [[ -n "$path" ]] || path="/"
    [[ "$path" == /* ]] || path="/$path"
    security="$(vless_query_param "$link" security 2>/dev/null || true)"
    if [[ "${security,,}" == "tls" ]]; then scheme="https"; else scheme="http"; fi
    port="$(vless_port "$link" 2>/dev/null || printf '443')"
    resolve_ip="$ip"
    [[ "$resolve_ip" == *:* ]] && resolve_ip="[$resolve_ip]"
    url="${scheme}://${domain}:${port}${path}"
    code="$(curl -sk --connect-timeout "$PREFERIP_PROBE_TIMEOUT" --max-time "$PREFERIP_PROBE_TIMEOUT" \
        --resolve "${domain}:${port}:${resolve_ip}" -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || printf '000')"
    if code_is_accepted "$code"; then
        log "节点 ${note}: 探活通过 ${ip} code=${code}"
        return 0
    fi
    log "节点 ${note}: 探活失败 ${ip} code=${code}，临时拉黑 ${PREFERIP_BAD_TTL_HOURS}h"
    blacklist_ip "$key" "$ip" "probe_failed_${code}"
    append_history_event "$key" "$ip" "" "" "" "probe_failed_${code}" "$note"
    return 1
}

SELECTED_ENTRY=""
select_entry_for_node() {
    local key="$1" note="$2" link="$3" selected current_ip current_entry ip entry pool_count
    SELECTED_ENTRY=""
    if pick_candidate "$key"; then
        selected="$PICKED_ENTRY"
    else
        return 1
    fi

    current_ip="${state_ip[$note]:-}"
    if [[ -z "$current_ip" ]]; then
        current_ip="$(vless_server "$link" 2>/dev/null || true)"
    fi
    pool_count="$(candidate_count "$key")"
    if is_true "$PREFERIP_STICKY" && [[ -n "$current_ip" ]] \
        && ! [[ "$PREFERIP_ASSIGN_MODE" == "round_robin" && "$pool_count" -gt 1 ]]; then
        current_entry="$(find_candidate_by_ip "$key" "$current_ip" 2>/dev/null || true)"
        if [[ -n "$current_entry" ]] && ! is_blacklisted "$key" "$current_ip"; then
            if should_keep_current "$current_entry" "$selected"; then
                log "节点 ${note}: 当前 IP ${current_ip} 仍在候选池且未被新候选明显超越，保持不切换"
                selected="$current_entry"
            fi
        fi
    fi

    if probe_candidate "$link" "$(entry_ip "$selected")" "$note" "$key"; then
        SELECTED_ENTRY="$selected"
        return 0
    fi

    # 探活失败时，顺序尝试同组其它候选。
    while IFS= read -r entry; do
        ip="$(entry_ip "$entry")"
        [[ "$ip" == "$(entry_ip "$selected")" ]] && continue
        is_blacklisted "$key" "$ip" && continue
        if probe_candidate "$link" "$ip" "$note" "$key"; then
            SELECTED_ENTRY="$entry"
            return 0
        fi
    done < <(candidate_entries "$key")
    return 1
}

DNS_DOMAIN_FOR_NODE=""
DNS_DOMAIN_ERROR=""
dns_domain_for_node() {
    local domain="${NODE_ENTRY_DOMAIN:-}" origin_sni origin_host origin_server
    DNS_DOMAIN_FOR_NODE=""
    DNS_DOMAIN_ERROR=""
    [[ -n "$domain" ]] || return 1
    origin_sni="$(vless_query_param "$NODE_LINK" sni 2>/dev/null || true)"
    origin_host="$(vless_query_param "$NODE_LINK" host 2>/dev/null || true)"
    origin_server="$(vless_server "$NODE_LINK" 2>/dev/null || true)"
    origin_sni="${origin_sni,,}"; origin_host="${origin_host,,}"; origin_server="${origin_server,,}"
    # DNS 固定入口必须是“独立入口域名”。如果把原 CDN 回源域名/Host/SNI 当 entry，
    # 程序会把它改成 DNS-only 优选 IP，等于破坏 Cloudflare 橙云回源记录。
    if [[ -n "$origin_sni" && "$domain" == "$origin_sni" ]] \
        || [[ -n "$origin_host" && "$domain" == "$origin_host" ]] \
        || { [[ -n "$origin_server" && "$domain" == "$origin_server" ]] && ! is_ip_literal "$origin_server"; }; then
        DNS_DOMAIN_ERROR="节点 ${NODE_NOTE} 的 entry=${domain} 与原 CDN 域名/Host/SNI 相同；请改用独立入口域名（如 prefer-xxx.example.com），禁止修改原橙云回源记录"
        return 2
    fi
    DNS_DOMAIN_FOR_NODE="$domain"
    return 0
}

should_use_dns_mode() {
    local domain="${1:-}"
    case "$PREFERIP_SERVER_MODE" in
        ip) return 1 ;;
        dns)
            [[ -n "$domain" && -n "$PREFERIP_CF_API_TOKEN" ]] || return 1
            return 0
            ;;
        auto)
            [[ -n "$domain" && -n "$PREFERIP_CF_API_TOKEN" ]] || return 1
            return 0
            ;;
        *) return 1 ;;
    esac
}

planned_dns_family_for_node() {
    local key ip
    case "${NODE_IP_VERSION:-}" in
        ipv4) printf 'A'; return 0 ;;
        ipv6) printf 'AAAA'; return 0 ;;
    esac
    key="$(result_key_for_node "${NODE_COLO:-}" "${NODE_IP_VERSION:-}")"
    [[ "$CFST_COLO_MODE" == "off" ]] && key="GLOBAL"
    ip="$(first_ip_for_key "$key" 2>/dev/null || true)"
    if [[ -z "$ip" && "$key" != "GLOBAL" && "$MISSING_COLO_POLICY" == "global" ]]; then
        ip="$(first_ip_for_key "GLOBAL" 2>/dev/null || true)"
    fi
    [[ -z "$ip" ]] && ip="${state_ip[$NODE_NOTE]:-}"
    [[ -z "$ip" ]] && ip="$(vless_server "$NODE_LINK" 2>/dev/null || true)"
    if is_ip_literal "$ip"; then
        cf_ip_family "$ip"
        return 0
    fi
    return 1
}

add_dns_family_plan() {
    local domain="$1" family="$2" cur
    [[ -n "$domain" && -n "$family" ]] || return 0
    cur="${dns_domain_family_plan[$domain]:-}"
    [[ " $cur " == *" $family "* ]] && return 0
    dns_domain_family_plan["$domain"]="${cur:+$cur }$family"
}

dns_domain_has_dual_family_plan() {
    local plan="${dns_domain_family_plan[$1]:-}"
    [[ " $plan " == *" A "* && " $plan " == *" AAAA "* ]]
}

build_dns_family_plan() {
    local raw domain family
    [[ "$PREFERIP_SERVER_MODE" == "ip" ]] && return 0
    [[ -f "$NODES_FILE" ]] || return 0
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        parse_node_line "$raw" || continue
        domain="${NODE_ENTRY_DOMAIN:-}"
        [[ -n "$domain" ]] || continue
        family="$(planned_dns_family_for_node 2>/dev/null || true)"
        [[ -n "$family" ]] && add_dns_family_plan "$domain" "$family"
    done < "$NODES_FILE"
}

state_payload=""
content=""
n=0
kept=0
fallback_global=0
now_epoch="$(date +%s)"
declare -A dns_domain_seen=()
declare -A dns_domain_family_plan=()

if [[ -f "$NODES_FILE" ]]; then
    build_dns_family_plan
    # ── 多节点模式：nodes.txt 每行「备注|vless链接」或「备注|CF地区码|vless链接」 ──
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        if ! parse_node_line "$raw"; then
            [[ -n "${raw//[[:space:]]/}" && "$(trim "$raw")" != \#* ]] && log "跳过无效行（需「备注|链接」或「备注|CF地区码|链接」）: $raw"
            continue
        fi
        key="$(result_key_for_node "${NODE_COLO:-}" "${NODE_IP_VERSION:-}")"
        [[ "$CFST_COLO_MODE" == "off" ]] && key="GLOBAL"

        selected=""
        if select_entry_for_node "$key" "$NODE_NOTE" "$NODE_LINK"; then
            selected="$SELECTED_ENTRY"
        fi

        dns_domain=""
        if [[ "$PREFERIP_SERVER_MODE" != "ip" ]]; then
            if [[ "$PREFERIP_SERVER_MODE" == "dns" && -z "${NODE_ENTRY_DOMAIN:-}" ]]; then
                die "PREFERIP_SERVER_MODE=dns 时，节点 ${NODE_NOTE} 必须显式配置 entry=独立入口域名；不会再隐式使用原链接 server，避免误改原 CDN 橙云记录"
            fi
            dns_rc=0
            if dns_domain_for_node; then
                dns_domain="$DNS_DOMAIN_FOR_NODE"
            else
                dns_rc=$?
                [[ "$dns_rc" -eq 2 ]] && die "$DNS_DOMAIN_ERROR"
            fi
        fi
        if should_use_dns_mode "$dns_domain"; then
            if [[ -n "${dns_domain_seen[$dns_domain]:-}" && "${dns_domain_seen[$dns_domain]}" != "$NODE_NOTE" ]]; then
                if dns_domain_has_dual_family_plan "$dns_domain"; then
                    log "提示: DNS 域名 ${dns_domain} 被多个节点复用为双栈入口（${dns_domain_seen[$dns_domain]} / ${NODE_NOTE}），本轮将同时维护 A+AAAA"
                else
                    log "警告: DNS 域名 ${dns_domain} 被多个节点复用（${dns_domain_seen[$dns_domain]} / ${NODE_NOTE}），同 family 后写入者会覆盖前者"
                fi
            else
                dns_domain_seen["$dns_domain"]="$NODE_NOTE"
            fi
        fi

        if [[ -z "$selected" && "$key" != "GLOBAL" && "$MISSING_COLO_POLICY" == "global" ]]; then
            if select_entry_for_node "GLOBAL" "$NODE_NOTE" "$NODE_LINK"; then
                selected="$SELECTED_ENTRY"
            fi
            [[ -n "$selected" ]] && { fallback_global=$((fallback_global+1)); log "节点 ${NODE_NOTE}: colo=${key} 无本地区可用候选，回退 GLOBAL"; key="GLOBAL"; }
        fi

        if [[ -z "$selected" ]]; then
            case "$MISSING_COLO_POLICY" in
                keep)
                    state_ip_value="${state_ip[$NODE_NOTE]:-}"
                    if [[ -z "$state_ip_value" && "$PREFERIP_SERVER_MODE" != "dns" ]]; then
                        state_ip_value="$(vless_server "$NODE_LINK" 2>/dev/null || true)"
                    fi
                    [[ -n "$state_ip_value" || "$PREFERIP_SERVER_MODE" == "dns" ]] || die "节点 ${NODE_NOTE} 需要地区 ${key} 的优选 IP，但结果文件缺失，且无法从原链接提取 server"
                    best="$state_ip_value"
                    kept=$((kept+1))
                    if [[ -n "$best" ]]; then
                        log "节点 ${NODE_NOTE}: colo=${key} 无可用候选，按 MISSING_COLO_POLICY=keep 保留原 server=${best}"
                    else
                        log "节点 ${NODE_NOTE}: colo=${key} 无可用候选，按 MISSING_COLO_POLICY=keep 保留入口域名 ${dns_domain:-<none>}，等待下次有 IP 再同步"
                    fi
                    lat=""; speed=""; count=""; event="kept"
                    ;;
                abort|*)
                    die "节点 ${NODE_NOTE} 需要地区 ${key} 的可用优选 IP，但结果缺失/探活失败；MISSING_COLO_POLICY=abort，已中止生成"
                    ;;
            esac
        else
            best="$(entry_ip "$selected")"
            lat="$(entry_lat "$selected")"; speed="$(entry_speed "$selected")"; count="$(entry_count "$selected")"
            event="applied"
            log "节点 ${NODE_NOTE}: colo=${key} server=${best} latency=${lat:-?}ms speed=${speed:-?}MB/s rounds=${count:-?} assign=${PREFERIP_ASSIGN_MODE} sticky=${PREFERIP_STICKY}"
        fi

        server_value="$best"
        state_ip_value="$best"
        if should_use_dns_mode "${dns_domain:-}" && [[ -n "${dns_domain:-}" ]]; then
            dns_delete_stale="${PREFERIP_DNS_DELETE_STALE:-true}"
            if dns_domain_has_dual_family_plan "$dns_domain"; then
                dns_delete_stale="false"
                log "节点 ${NODE_NOTE}: DNS 入口 ${dns_domain} 计划同时维护 A+AAAA，跳过 stale family 删除"
            fi
            server_value="$dns_domain"
            if is_ip_literal "$state_ip_value"; then
                require_cmd jq
                if ! cf_dns_sync_entry_domain "$dns_domain" "$state_ip_value" "$PREFERIP_CF_API_TOKEN" "$PREFERIP_CF_ZONE_ID" "$dns_delete_stale" >/dev/null; then
                    die "节点 ${NODE_NOTE} 的 DNS 解析同步失败（${dns_domain} -> ${state_ip_value}）"
                fi
            else
                log "节点 ${NODE_NOTE}: DNS 入口 ${dns_domain} 暂未拿到可同步的 IP，保留现有 DNS 记录"
            fi
            log "节点 ${NODE_NOTE}: colo=${key} dns=${dns_domain} -> ${state_ip_value} latency=${lat:-?}ms speed=${speed:-?}MB/s rounds=${count:-?} assign=${PREFERIP_ASSIGN_MODE} sticky=${PREFERIP_STICKY}"
        fi
        new="$(rewrite_vless "$NODE_LINK" "$server_value" "$NODE_NOTE")" || { log "解析失败，跳过: $NODE_NOTE"; continue; }
        content+="${new}"$'\n'
        state_payload+="${NODE_NOTE}"$'\t'"${key}"$'\t'"${state_ip_value}"$'\t'"${lat:-}"$'\t'"${speed:-}"$'\t'"${count:-}"$'\t'"${now_epoch}"$'\n'
        append_history_event "$key" "$state_ip_value" "${lat:-}" "${speed:-}" "${count:-}" "$event" "$NODE_NOTE"
        n=$((n+1))
    done < "$NODES_FILE"
    log "多节点模式：从 nodes.txt 生成 ${n} 个节点（保留原 server=${kept}，全局回退=${fallback_global}）"
    [[ $n -gt 0 ]] || die "nodes.txt 里没有有效节点（每行格式：备注|链接 或 备注|CF地区码|链接）"
else
    # ── 单节点模式（兼容旧 conf）──
    if [[ -z "$CDN_UUID" || -z "$CDN_DOMAIN" || -z "$CDN_WS_PATH" ]]; then
        die "未找到 nodes.txt，且 conf 也没填 CDN_UUID/DOMAIN/WS_PATH。请创建 nodes.txt（每行：区域备注|链接）"
    fi
    keys=()
    if [[ -n "${DEFAULT_CF_COLO:-}" ]]; then
        keys+=("$(result_key_for_node "$DEFAULT_CF_COLO" "${DEFAULT_CF_IP_VERSION:-}")")
    fi
    keys+=("GLOBAL")
    for key in "${keys[@]}"; do
        while IFS= read -r entry; do
            ip="$(entry_ip "$entry")"
            is_blacklisted "$key" "$ip" && continue
            nm="$CDN_NODE_NAME"
            [[ $n -gt 0 ]] && nm="${CDN_NODE_NAME}-$((n+1))"
            content+="$(build_cdn_link "$ip" "$nm")"$'\n'
            state_payload+="${nm}"$'\t'"${key}"$'\t'"${ip}"$'\t'"$(entry_lat "$entry")"$'\t'"$(entry_speed "$entry")"$'\t'"$(entry_count "$entry")"$'\t'"${now_epoch}"$'\n'
            append_history_event "$key" "$ip" "$(entry_lat "$entry")" "$(entry_speed "$entry")" "$(entry_count "$entry")" "applied" "$nm"
            n=$((n+1))
        done < <(candidate_entries "$key")
        [[ $n -gt 0 ]] && break
    done
    log "单节点模式：生成 ${n} 个节点"
fi

# 3) 写出本地渲染文件（供客户端/其他自动化拉取）
rendered_file="${PREFERIP_OUTPUT_FILE:-$HERE/preferip.rendered.txt}"
{
    printf '# generated: %s\n' "$(date '+%F %T')"
    printf '%s' "$content"
} | preferip_atomic_write "$rendered_file" 600 || die "写入本地节点文件失败: $rendered_file"
log "已生成本地节点文件 → $rendered_file"

if [[ -n "${PREFERIP_STATE_FILE:-}" ]]; then
    {
        printf '# note\tkey\tserver\tavg_latency_ms\tavg_speed_mbps\trounds_hit\tupdated_at_epoch\n'
        printf '%s' "$state_payload"
    } | preferip_atomic_write "$PREFERIP_STATE_FILE" 600 || die "写入 preferip state 失败: $PREFERIP_STATE_FILE"
fi
log "完成：已更新 ${n} 个 CDN 节点。客户端获取本地节点文件或入口 DNS 即生效。"
