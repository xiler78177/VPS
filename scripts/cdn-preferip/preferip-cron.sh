#!/usr/bin/env bash
# scripts/cdn-preferip/preferip-cron.sh
# B→C 串联入口（给国内机 cron 用）：先优选，成功再回写 sub-store。
# 优选失败（无结果）则不回写，保留 sub-store 现状（不推空值）。
#
# crontab 示例（国内机，每天晚高峰前 20:30 刷新一次；优选 IP 时效约几天）：
#   30 20 * * * /path/to/scripts/cdn-preferip/preferip-cron.sh >> /var/log/cdn-preferip.log 2>&1

set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "==== [$(date '+%F %T')] cdn-preferip 优选+回写 开始 ===="
if "$HERE/preferip-collect.sh"; then
    "$HERE/preferip-push.sh"
    rc=$?
else
    echo "优选未产出有效结果，跳过回写（保留 sub-store 现状）。"
    rc=1
fi
echo "==== [$(date '+%F %T')] 结束 (rc=$rc) ===="
exit "$rc"
