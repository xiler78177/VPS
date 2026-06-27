#!/usr/bin/env bash
# scripts/cdn-preferip/preferip-push.sh  (C 块：回写 sub-store)
# 在【国内机】运行：读 B 产出的优选 IP，PATCH 一条【专用 local 订阅】，
# 把节点 server 字段替换为优选 IP（host/sni 保留真实 CDN 域名，CF 靠 Host 头回源）。
#
# 安全：只动 SUBSTORE_SUB_NAME 这一条专用订阅，绝不碰用户现有 19 条。
#       公网 https + secret 前缀即事实鉴权；secret 不入日志。
# 兜底：优选结果为空/文件缺失则不推（KEEP_ON_EMPTY=true），避免把订阅刷成空 server。
#
# 真实路由（已实测）：GET /api/sub/:name、PATCH /api/sub/:name、POST /api/subs（新建）

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
load_conf
require_cmd curl
require_cmd jq

RESULT_FILE="${RESULT_FILE:-$HERE/preferip.result}"

# 1) 读优选 IP（B 的产出）
if [[ ! -s "$RESULT_FILE" ]]; then
    log "优选结果文件不存在或为空: $RESULT_FILE"
    [[ "${KEEP_ON_EMPTY}" == "true" ]] && { log "KEEP_ON_EMPTY=true：不推空值，保留 sub-store 现状。"; exit 1; }
    die "无优选 IP 可推送"
fi
mapfile -t ips < <(grep -E '^[0-9a-fA-F:.]+$' "$RESULT_FILE")
[[ ${#ips[@]} -gt 0 ]] || { log "结果文件无有效 IP"; exit 1; }
log "读取到 ${#ips[@]} 个优选 IP，将写入专用订阅 ${SUBSTORE_SUB_NAME}"

# 2) 拼装节点内容（每个优选 IP 一条；多条时名字加序号区分）
content=""
i=1
for ip in "${ips[@]}"; do
    name="$CDN_NODE_NAME"
    [[ ${#ips[@]} -gt 1 ]] && name="${CDN_NODE_NAME}-${i}"
    line="$(build_cdn_link "$ip" "$name")"
    content+="${line}"$'\n'
    i=$((i+1))
done

# 3) 取专用订阅当前 JSON（保留其它字段，只换 content）；不存在则新建一条 local 订阅。
sub_json="$(substore_get_sub "$SUBSTORE_SUB_NAME" 2>/dev/null || true)"

if [[ -n "$sub_json" && "$sub_json" != "null" ]]; then
    # 仅替换 content；保留 name/displayName/icon/process 等既有字段
    payload="$(jq -c --arg c "$content" '.content=$c' <<< "$sub_json")"
    log "专用订阅已存在，PATCH 更新 content"
    if resp="$(substore_api PATCH "/sub/$(urlencode "$SUBSTORE_SUB_NAME")" --data "$payload")"; then
        [[ "$(jq -r '.status // empty' <<< "$resp")" == "success" ]] \
            && log "PATCH 成功" || { log "PATCH 返回非 success: $(jq -c '.' <<< "$resp" 2>/dev/null)"; exit 1; }
    else
        die "PATCH 请求失败（网络/secret/路径？）"
    fi
else
    # 新建一条 local 订阅（content 为内联节点）
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

log "完成：${SUBSTORE_SUB_NAME} 的 server 已更新为优选 IP（host/sni=${CDN_DOMAIN} 不变）。客户端刷新订阅即生效。"
