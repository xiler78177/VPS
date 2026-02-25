#!/bin/bash
# build.sh - 将 modules/ 下所有模块合并为单文件部署产物
# 用法: bash build.sh [输出文件路径]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
DIST_DIR="$SCRIPT_DIR/dist"
OUTPUT="${1:-$DIST_DIR/v4-built.sh}"

# 模块加载顺序（与 v4.sh 中 source 顺序一致）
MODULES=(
    "00-constants.sh"
    "01-utils.sh"
    "02-network.sh"
    "03-sysinfo.sh"
    "04-firewall.sh"
    "05-fail2ban.sh"
    "06-ssh.sh"
    "07-system.sh"
    "08-network-tools.sh"
    "09-web.sh"
    "09a-web-helpers.sh"
    "09b-web-cloudflare.sh"
    "09c-web-domain.sh"
    "09d-web-proxy.sh"
    "10-docker.sh"
    "11a-wireguard-netcheck.sh"
    "11-wireguard.sh"
    "11c-wireguard-server.sh"
    "11d-wireguard-peers.sh"
    "11e-wireguard-clash.sh"
    "11f-wireguard-portfwd.sh"
    "11g-wireguard-extra.sh"
    "11b-wireguard-udp2raw.sh"
    "12-backup.sh"
    "13-menus.sh"
)

mkdir -p "$(dirname "$OUTPUT")"

# 写入 shebang
echo '#!/bin/bash' > "$OUTPUT"
echo '' >> "$OUTPUT"

# 按顺序拼接各模块（跳过模块文件的注释头）
for mod in "${MODULES[@]}"; do
    mod_path="$MODULES_DIR/$mod"
    if [[ ! -f "$mod_path" ]]; then
        echo "错误: 模块文件不存在 - $mod_path" >&2
        exit 1
    fi
    # 跳过第一行（模块注释头 # modules/xx-xxx.sh - ...）
    tail -n +2 "$mod_path" >> "$OUTPUT"
done

# 末尾追加入口调用
echo 'main "$@"' >> "$OUTPUT"

chmod +x "$OUTPUT"

# 统计信息
TOTAL_LINES=$(wc -l < "$OUTPUT")
echo "构建完成: $OUTPUT"
echo "总行数: $TOTAL_LINES"
echo ""
echo "模块统计:"
for mod in "${MODULES[@]}"; do
    lines=$(wc -l < "$MODULES_DIR/$mod")
    printf "  %-25s %5d 行\n" "$mod" "$lines"
done
