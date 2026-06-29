#!/usr/bin/env bash
# scripts/cdn-preferip/preferip-push.sh  (C 块：回写 sub-store)
#
# 多节点模式(推荐)：读 nodes.txt，每行可写：
#   旧格式: 区域备注|vless链接
#   新格式: 区域备注|CF地区码|vless链接    例如 香港-01|HKG|vless://...
#   混合池: 区域备注|CF地区码|ipv6|vless链接 或 区域备注|HKG@ipv6|vless://...
#   C 会按每个节点的 CF 地区码选择对应优选 IP；host/sni/uuid/path 全保留，一次性 PATCH 到专用订阅。
# 单节点模式(旧/兼容)：若无 nodes.txt 但 conf 填了 CDN_UUID/DOMAIN/WS_PATH，则按单节点拼。
#
# 安全：只动 SUBSTORE_SUB_NAME 这一条专用订阅。secret 不入日志。
# 兜底：优选结果为空则不推(KEEP_ON_EMPTY=true)，避免把订阅刷成空 server。
# 缺地区结果策略：MISSING_COLO_POLICY=keep/abort/global；默认 keep，仅更新有结果的节点。

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
load_conf
require_cmd curl
require_cmd jq

RESULT_FILE="${RESULT_FILE:-$HERE/preferip.result}"
NODES_FILE="${NODES_FILE:-$HERE/nodes.txt}"

# 1) 读优选 IP（B 的产出）
if [[ ! -s "$RESULT_FILE" ]]; then
    log "优选结果文件不存在或为空: $RESULT_FILE"
    [[ "${KEEP_ON_EMPTY}" == "true" ]] && { log "KEEP_ON_EMPTY=true：不推空值，保留 sub-store 现状。"; exit 1; }
    die "无优选 IP 可推送"
fi
declare -A best_by_key=()
ips=()
while IFS= read -r raw || [[ -n "$raw" ]]; do
    [[ -z "${raw//[[:space:]]/}" ]] && continue
    raw="$(trim "$raw")"
    [[ "$raw" == \#* ]] && continue
    if [[ "$raw" == *"|"* ]]; then
        key="${raw%%|*}"
        ip="${raw#*|}"
        key="$(normalize_result_key "$key")"
        ip="$(trim "$ip")"
        is_ip_literal "$ip" || continue
        [[ -z "${best_by_key[$key]:-}" ]] && best_by_key[$key]="$ip"
    else
        ip="$raw"
        is_ip_literal "$ip" || continue
        ips+=("$ip")
    fi
done < "$RESULT_FILE"
global_best="${best_by_key[GLOBAL]:-${ips[0]:-}}"
[[ -n "$global_best" || ${#best_by_key[@]} -gt 0 ]] || { log "结果文件无有效 IP"; exit 1; }
group_keys="${!best_by_key[*]}"
[[ -n "$group_keys" ]] || group_keys="无"
log "已读取优选结果：全局=${global_best:-无}，地区分组=${group_keys}"

# 2) 拼装节点内容
content=""
n=0
kept=0
fallback_global=0
if [[ -f "$NODES_FILE" ]]; then
    # ── 多节点模式：nodes.txt 每行「备注|vless链接」或「备注|CF地区码|vless链接」 ──
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        if ! parse_node_line "$raw"; then
            [[ -n "${raw//[[:space:]]/}" && "$(trim "$raw")" != \#* ]] && log "跳过无效行（需「备注|链接」或「备注|CF地区码|链接」）: $raw"
            continue
        fi
        key="$(result_key_for_node "${NODE_COLO:-}" "${NODE_IP_VERSION:-}")"
        [[ "$CFST_COLO_MODE" == "off" ]] && key="GLOBAL"

        best=""
        if [[ "$key" == "GLOBAL" ]]; then
            best="${global_best:-}"
        else
            best="${best_by_key[$key]:-}"
        fi

        if [[ -z "$best" ]]; then
            case "$MISSING_COLO_POLICY" in
                keep)
                    best="$(vless_server "$NODE_LINK" 2>/dev/null || true)"
                    [[ -n "$best" ]] || die "节点 ${NODE_NOTE} 需要地区 ${key} 的优选 IP，但结果文件缺失，且无法从原链接提取 server"
                    kept=$((kept+1))
                    log "节点 ${NODE_NOTE}: colo=${key} 无本地区结果，按 MISSING_COLO_POLICY=keep 保留原 server=${best}"
                    ;;
                global)
                    best="${global_best:-}"
                    [[ -n "$best" ]] || die "节点 ${NODE_NOTE} 需要地区 ${key} 的优选 IP，但结果文件缺失，且没有全局优选 IP 可回退"
                    fallback_global=$((fallback_global+1))
                    log "节点 ${NODE_NOTE}: colo=${key} 无本地区结果，按 MISSING_COLO_POLICY=global 回退 server=${best}"
                    ;;
                abort|*)
                    die "节点 ${NODE_NOTE} 需要地区 ${key} 的优选 IP，但结果文件缺失；MISSING_COLO_POLICY=abort，已中止 PATCH"
                    ;;
            esac
        else
            log "节点 ${NODE_NOTE}: colo=${key} server=${best}"
        fi
        new="$(rewrite_vless "$NODE_LINK" "$best" "$NODE_NOTE")" || { log "解析失败，跳过: $NODE_NOTE"; continue; }
        content+="${new}"$'\n'
        n=$((n+1))
    done < "$NODES_FILE"
    log "多节点模式：从 nodes.txt 生成 ${n} 个节点（保留原 server=${kept}，全局回退=${fallback_global}）"
    [[ $n -gt 0 ]] || die "nodes.txt 里没有有效节点（每行格式：备注|链接 或 备注|CF地区码|链接）"
else
    # ── 单节点模式（兼容旧 conf）──
    if [[ -z "$CDN_UUID" || -z "$CDN_DOMAIN" || -z "$CDN_WS_PATH" ]]; then
        die "未找到 nodes.txt，且 conf 也没填 CDN_UUID/DOMAIN/WS_PATH。请创建 nodes.txt（每行：区域备注|链接）"
    fi
    mapfile -t single_ips < <(
        if [[ -n "${DEFAULT_CF_COLO:-}" ]]; then
            key="$(result_key_for_node "$DEFAULT_CF_COLO" "${DEFAULT_CF_IP_VERSION:-}")"
            [[ -n "${best_by_key[$key]:-}" ]] && printf '%s\n' "${best_by_key[$key]}"
        fi
        [[ -n "$global_best" ]] && printf '%s\n' "$global_best"
        printf '%s\n' "${ips[@]:-}"
    )
    for ip in "${single_ips[@]}"; do
        is_ip_literal "$ip" || continue
        nm="$CDN_NODE_NAME"
        [[ ${#ips[@]} -gt 1 ]] && nm="${CDN_NODE_NAME}-$((n+1))"
        content+="$(build_cdn_link "$ip" "$nm")"$'\n'
        n=$((n+1))
    done
    log "单节点模式：生成 ${n} 个节点"
fi

# 3) PATCH 专用订阅（不存在则 POST 新建 local 订阅）
sub_json="$(substore_get_sub "$SUBSTORE_SUB_NAME" 2>/dev/null || true)"
if [[ -n "$sub_json" && "$sub_json" != "null" ]]; then
    payload="$(jq -c --arg c "$content" '.content=$c' <<< "$sub_json")"
    log "专用订阅已存在，PATCH 更新 content"
    if resp="$(substore_api PATCH "/sub/$(urlencode "$SUBSTORE_SUB_NAME")" --data "$payload")"; then
        [[ "$(jq -r '.status // empty' <<< "$resp")" == "success" ]] \
            && log "PATCH 成功" || { log "PATCH 返回非 success: $(jq -c '.' <<< "$resp" 2>/dev/null)"; exit 1; }
    else
        die "PATCH 请求失败（网络/secret/路径？）"
    fi
else
    payload="$(jq -nc --arg n "$SUBSTORE_SUB_NAME" --arg c "$content" \
        '{name:$n, displayName:$n, source:"local", content:$c}')"
    log "专用订阅不存在，POST 新建 local 订阅 ${SUBSTORE_SUB_NAME}"
    if resp="$(substore_api POST "/subs" --data "$payload")"; then
        [[ "$(jq -r '.status // empty' <<< "$resp")" == "success" ]] \
            && log "新建成功" || { log "新建返回非 success: $(jq -c '.' <<< "$resp" 2>/dev/null)"; exit 1; }
    else
        die "新建请求失败"
    fi
fi
log "完成：${SUBSTORE_SUB_NAME} 已更新 ${n} 个 CDN 节点。客户端刷新订阅即生效。"
