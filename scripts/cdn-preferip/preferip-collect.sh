#!/usr/bin/env bash
# scripts/cdn-preferip/preferip-collect.sh  (B 块：优选 IP 采集)
# 在【国内机】运行：跑 XIU2/CloudflareSpeedTest 选出最优 CF 边缘 IP，写结果文件。
# 必须国内侧跑——它测的是「本机→各 CF 边缘」延迟/速度，海外机结果作废。
#
# 产出：
#   旧全局模式：$RESULT_FILE 每行一个 IP。
#   分地区模式：$RESULT_FILE 每行「地区码|IP」，例如 HKG|1.2.3.4、NRT,KIX|1.2.3.5。
# 兜底：测速无结果/超时则保留旧结果文件、退出非 0，绝不写空（避免把订阅刷成空 server）。
#
# 依赖：CloudflareSpeedTest 二进制（cfst / CloudflareST），可用 CFST_BIN 指定路径。

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
load_conf
require_cmd awk

RESULT_FILE="${RESULT_FILE:-$HERE/preferip.result}"
NODES_FILE="${NODES_FILE:-$HERE/nodes.txt}"
CFST_BIN="${CFST_BIN:-}"
CFST_EXTRA_ARGS="${CFST_EXTRA_ARGS:-}"
CFST_IP_FILE="${CFST_IP_FILE:-}"
CFST_ROUNDS="${CFST_ROUNDS:-1}"
CFST_PICK_MODE="${CFST_PICK_MODE:-cfst}"
[[ "$CFST_ROUNDS" =~ ^[0-9]+$ && "$CFST_ROUNDS" -ge 1 ]] || die "CFST_ROUNDS 必须是 >=1 的整数"
case "${CFST_PICK_MODE,,}" in
    cfst|latency|speed|balanced) CFST_PICK_MODE="${CFST_PICK_MODE,,}" ;;
    *) die "CFST_PICK_MODE 只能是 cfst / latency / speed / balanced" ;;
esac

# 定位 CloudflareSpeedTest 二进制
if [[ -z "$CFST_BIN" ]]; then
    for c in cfst CloudflareST cloudflarespeedtest; do
        command -v "$c" >/dev/null 2>&1 && { CFST_BIN="$c"; break; }
    done
fi
[[ -n "$CFST_BIN" ]] || die "未找到 CloudflareSpeedTest。请安装并把二进制加入 PATH，或设 CFST_BIN=/path/to/cfst（项目: https://github.com/XIU2/CloudflareSpeedTest）"

# 自定义 IP 段文件（-f）；留空则用 CloudflareSpeedTest 自带 ip.txt。
ipfile_args=()
[[ -n "$CFST_IP_FILE" ]] && { [[ -f "$CFST_IP_FILE" ]] || die "CFST_IP_FILE 不存在: $CFST_IP_FILE"; ipfile_args=(-f "$CFST_IP_FILE"); }

tmp_files=()
cleanup(){ rm -f "${tmp_files[@]}" 2>/dev/null || true; }
trap cleanup EXIT

collect_one_group() {
    local key="$1" csv out rows ranked ip ips=() round ok=0
    local -a sort_args=()
    rows="$(mktemp)"; ranked="$(mktemp)"
    tmp_files+=("$rows" "$ranked")

    for ((round=1; round<=CFST_ROUNDS; round++)); do
        csv="$(mktemp)"; out="$(mktemp)"
        tmp_files+=("$csv" "$out")
        if [[ "$key" == "GLOBAL" ]]; then
            log "开始全局优选（$CFST_BIN），轮次 ${round}/${CFST_ROUNDS}；输出 CSV → $csv"
            # shellcheck disable=SC2086
            "$CFST_BIN" $CFST_EXTRA_ARGS "${ipfile_args[@]}" -o "$csv" >"$out" 2>&1 || {
                log "CloudflareSpeedTest 全局优选失败，日志末尾:"; tail -n 15 "$out" >&2 || true; continue
            }
        else
            log "开始按地区优选 ${key}（HTTPing + -cfcolo），轮次 ${round}/${CFST_ROUNDS}；输出 CSV → $csv"
            # CloudflareSpeedTest 官方限制：-cfcolo 仅 HTTPing 模式可用。
            # shellcheck disable=SC2086
            "$CFST_BIN" $CFST_EXTRA_ARGS "${ipfile_args[@]}" -httping -cfcolo "$key" -o "$csv" >"$out" 2>&1 || {
                log "CloudflareSpeedTest 地区 ${key} 优选失败，日志末尾:"; tail -n 15 "$out" >&2 || true; continue
            }
        fi
        if awk -F, -v round="$round" '
            NR > 1 {
                gsub(/^\xef\xbb\xbf/, "", $1)
                if ($1 != "") {
                    # 输出: ip,latency,speed,loss,round,original_rank
                    printf "%s,%.6f,%.6f,%.6f,%d,%d\n", $1, $5 + 0, $6 + 0, $4 + 0, round, NR - 1
                    found = 1
                }
            }
            END { exit(found ? 0 : 1) }
        ' "$csv" >> "$rows"; then
            ok=1
        else
            log "地区 ${key} 第 ${round}/${CFST_ROUNDS} 轮无有效 CSV 结果"
        fi
    done
    [[ "$ok" -eq 1 && -s "$rows" ]] || { log "地区 ${key} 无有效结果"; return 1; }

    awk -F, -v mode="$CFST_PICK_MODE" '
        {
            ip=$1; lat=$2+0; speed=$3+0; rank=$6+0
            if (!(ip in seen)) {
                seen[ip]=1
                order[ip]=++n
                min_rank[ip]=rank
            }
            cnt[ip]++
            sum_lat[ip]+=lat
            sum_speed[ip]+=speed
            if (rank < min_rank[ip]) min_rank[ip]=rank
        }
        END {
            for (ip in cnt) {
                avg_lat=sum_lat[ip]/cnt[ip]
                avg_speed=sum_speed[ip]/cnt[ip]
                if (mode == "speed") {
                    printf "%.6f,%.6f,%06d,%s,%.2f,%.2f,%d\n", avg_speed, avg_lat, cnt[ip], ip, avg_lat, avg_speed, cnt[ip]
                } else if (mode == "latency") {
                    printf "%.6f,%.6f,%06d,%s,%.2f,%.2f,%d\n", avg_lat, avg_speed, cnt[ip], ip, avg_lat, avg_speed, cnt[ip]
                } else if (mode == "balanced") {
                    printf "%06d,%.6f,%.6f,%s,%.2f,%.2f,%d\n", cnt[ip], avg_lat, avg_speed, ip, avg_lat, avg_speed, cnt[ip]
                } else {
                    printf "%06d,%.6f,%06d,%s,%.2f,%.2f,%d\n", min_rank[ip], order[ip], cnt[ip], ip, avg_lat, avg_speed, cnt[ip]
                }
            }
        }
    ' "$rows" > "$ranked"

    case "$CFST_PICK_MODE" in
        speed) sort_args=(-t, -k1,1nr -k2,2n -k3,3nr) ;;
        latency) sort_args=(-t, -k1,1n -k2,2nr -k3,3nr) ;;
        balanced) sort_args=(-t, -k1,1nr -k2,2n -k3,3nr) ;;
        *) sort_args=(-t, -k1,1n -k2,2n -k3,3nr) ;;
    esac

    while IFS=, read -r _s1 _s2 _s3 ip avg_lat avg_speed count; do
        is_ip_literal "$ip" || continue
        log "候选 ${key}: ${ip} avg_latency=${avg_lat}ms avg_speed=${avg_speed}MB/s rounds_hit=${count} pick_mode=${CFST_PICK_MODE}"
        ips+=("$ip")
        [[ ${#ips[@]} -ge "$CFST_TOP_N" ]] && break
    done < <(sort "${sort_args[@]}" "$ranked")

    [[ ${#ips[@]} -gt 0 ]] || { log "地区 ${key} 无有效结果"; return 1; }
    printf '%s\n' "${ips[@]}"
}

groups=()
add_group() {
    local key="$1" g
    for g in "${groups[@]}"; do [[ "$g" == "$key" ]] && return 0; done
    groups+=("$key")
}

collect_group_or_fail() {
    local key="$1" outfile="$2"
    if collect_one_group "$key" > "$outfile"; then
        [[ -s "$outfile" ]] || { log "地区 ${key} 无有效结果"; return 1; }
        return 0
    fi
    return 1
}

if [[ "${CFST_COLO_MODE,,}" != "off" && -f "$NODES_FILE" ]]; then
    while IFS= read -r raw || [[ -n "$raw" ]]; do
        if parse_node_line "$raw"; then
            add_group "$(result_key_for_colo "${NODE_COLO:-}")"
        fi
    done < "$NODES_FILE"
fi
[[ ${#groups[@]} -gt 0 ]] || groups=("GLOBAL")

tmp_result="$(mktemp)"
tmp_files+=("$tmp_result")
if [[ ${#groups[@]} -eq 1 && "${groups[0]}" == "GLOBAL" ]]; then
    group_out="$(mktemp)"; tmp_files+=("$group_out")
    collect_group_or_fail "GLOBAL" "$group_out" || {
        [[ "${KEEP_ON_EMPTY}" == "true" ]] && log "保留旧结果文件 $RESULT_FILE，不写空。"
        exit 1
    }
    mapfile -t ips < "$group_out"
    printf '%s\n' "${ips[@]}" > "$tmp_result"
else
    printf '# cdn-preferip result v2: colo|ip\n' > "$tmp_result"
    for key in "${groups[@]}"; do
        group_out="$(mktemp)"; tmp_files+=("$group_out")
        collect_group_or_fail "$key" "$group_out" || {
            [[ "${KEEP_ON_EMPTY}" == "true" ]] && log "保留旧结果文件 $RESULT_FILE，不写空。"
            exit 1
        }
        mapfile -t ips < "$group_out"
        for ip in "${ips[@]}"; do
            printf '%s|%s\n' "$key" "$ip" >> "$tmp_result"
        done
    done
fi

mv "$tmp_result" "$RESULT_FILE"
log "优选完成，分组=${groups[*]}，TopN=$CFST_TOP_N，写入 $RESULT_FILE:"
sed -n '1,40p' "$RESULT_FILE" >&2
