#!/usr/bin/env bash
# scripts/cdn-preferip/preferip-cron.sh
# B→C 串联入口（给国内机 cron 用）：先优选，再生成本地节点文件并可选同步 DNS。
# 优选失败（无结果）则不覆盖上次输出文件。
#
# crontab 示例（国内机，每天晚高峰前 20:30 刷新一次；优选 IP 时效约几天）：
#   30 20 * * * /path/to/scripts/cdn-preferip/preferip-cron.sh >> /var/log/cdn-preferip.log 2>&1

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=lib.sh
source "$HERE/lib.sh"
load_conf

if command -v flock >/dev/null 2>&1; then
    exec 9>"$PREFERIP_LOCK_FILE"
    if ! flock -n 9; then
        echo "==== [$(date '+%F %T')] 已有 cdn-preferip 任务在运行，跳过本次 ===="
        exit 0
    fi
fi

echo "==== [$(date '+%F %T')] cdn-preferip 优选+回写 开始 ===="
if "$HERE/preferip-collect.sh"; then
    "$HERE/preferip-push.sh"
    rc=$?
else
    echo "优选未产出有效结果，跳过输出更新。"
    rc=1
fi
echo "==== [$(date '+%F %T')] 结束 (rc=$rc) ===="
exit "$rc"
