#!/usr/bin/env bash
# scripts/cdn-preferip/preferip-collect.sh  (B 块：优选 IP 采集)
# 在【国内机】运行：跑 XIU2/CloudflareSpeedTest 选出最优 CF 边缘 IP，写结果文件。
# 必须国内侧跑——它测的是「本机→各 CF 边缘」延迟/速度，海外机结果作废。
#
# 产出：$RESULT_FILE（每行一个 IP，按优劣排序，取 TopN）。
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
CFST_BIN="${CFST_BIN:-}"
CFST_EXTRA_ARGS="${CFST_EXTRA_ARGS:-}"
CFST_IP_FILE="${CFST_IP_FILE:-}"

# 定位 CloudflareSpeedTest 二进制
if [[ -z "$CFST_BIN" ]]; then
    for c in cfst CloudflareST cloudflarespeedtest; do
        command -v "$c" >/dev/null 2>&1 && { CFST_BIN="$c"; break; }
    done
fi
[[ -n "$CFST_BIN" ]] || die "未找到 CloudflareSpeedTest。请安装并把二进制加入 PATH，或设 CFST_BIN=/path/to/cfst（项目: https://github.com/XIU2/CloudflareSpeedTest）"

tmp_csv="$(mktemp)"; tmp_out="$(mktemp)"
trap 'rm -f "$tmp_csv" "$tmp_out"' EXIT

# 自定义 IP 段文件（-f）；留空则用 CloudflareSpeedTest 自带 ip.txt。
ipfile_args=()
[[ -n "$CFST_IP_FILE" ]] && { [[ -f "$CFST_IP_FILE" ]] || die "CFST_IP_FILE 不存在: $CFST_IP_FILE"; ipfile_args=(-f "$CFST_IP_FILE"); }

log "开始优选（$CFST_BIN）；输出 CSV → $tmp_csv"
# -o 输出 CSV；其余参数（-dd 关测速 / -tl -sl 等）由 CFST_EXTRA_ARGS 透传。
# shellcheck disable=SC2086
if ! "$CFST_BIN" $CFST_EXTRA_ARGS "${ipfile_args[@]}" -o "$tmp_csv" >"$tmp_out" 2>&1; then
    log "CloudflareSpeedTest 运行失败，日志末尾:"; tail -n 15 "$tmp_out" >&2 || true
    [[ "${KEEP_ON_EMPTY}" == "true" ]] && { log "保留旧结果文件 $RESULT_FILE，不写空。"; exit 1; }
    exit 1
fi

# CSV 首行为表头，第 1 列是 IP。按文件给出的顺序（已按优劣排序）取 TopN。
mapfile -t ips < <(awk -F, 'NR>1 && $1 ~ /^[0-9a-fA-F:.]+$/ {print $1}' "$tmp_csv" | head -n "$CFST_TOP_N")

if [[ ${#ips[@]} -eq 0 ]]; then
    log "测速无有效结果（可能本机网络异常或全部超时）。"
    [[ "${KEEP_ON_EMPTY}" == "true" ]] && { log "保留旧结果文件，不写空。"; exit 1; }
    exit 1
fi

printf '%s\n' "${ips[@]}" > "$RESULT_FILE"
log "优选完成，TopN=$CFST_TOP_N，写入 $RESULT_FILE:"
printf '  %s\n' "${ips[@]}" >&2
