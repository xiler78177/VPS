#!/bin/bash
# build.sh - 将 modules/ 下所有模块合并为单文件部署产物
# 用法: bash build.sh [输出文件路径]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SCRIPT_DIR/modules"
DIST_DIR="$SCRIPT_DIR/dist"
OUTPUT="${1:-$DIST_DIR/v4-built.sh}"

# 模块加载顺序（运行时按此顺序拼接，main 由 13-menus.sh 提供）
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
    "09e-web-home-expose.sh"
    "10-docker.sh"
    "11a-wireguard-netcheck.sh"
    "11-wireguard.sh"
    "11c-wireguard-server.sh"
    "11d-wireguard-peers.sh"
    "11e-wireguard-clash.sh"
    "11g-wireguard-extra.sh"
    "12a-wireguard-deb-netcheck.sh"
    "12b-wireguard-deb.sh"
    "12c-wireguard-deb-server.sh"
    "12d-wireguard-deb-peers.sh"
    "12e-wireguard-deb-extra.sh"
    "14a-email-state.sh"
    "14b-email-cf.sh"
    "14c-email-deploy.sh"
    "14d-email-manage.sh"
    "14e-email-uninstall.sh"
    "14-email.sh"
    "15-singbox-reality.sh"
    "13-menus.sh"
)

mkdir -p "$(dirname "$OUTPUT")"
OUTPUT_DIR="$(dirname "$OUTPUT")"
OUTPUT_BASE="$(basename "$OUTPUT")"
TMP_OUTPUT="$(mktemp "${OUTPUT_DIR}/.${OUTPUT_BASE}.tmp.XXXXXX")"
cleanup_tmp_output() {
    rm -f "$TMP_OUTPUT"
}
trap cleanup_tmp_output EXIT

# 写入 shebang
echo '#!/bin/bash' > "$TMP_OUTPUT"
echo '' >> "$TMP_OUTPUT"

# 按顺序拼接各模块（跳过模块文件的注释头）
for mod in "${MODULES[@]}"; do
    mod_path="$MODULES_DIR/$mod"
    if [[ ! -f "$mod_path" ]]; then
        echo "错误: 模块文件不存在 - $mod_path" >&2
        exit 1
    fi

    # 特殊处理：在拼接 15-singbox-reality.sh 之前，先内联增强模块
    if [[ "$mod" == "15-singbox-reality.sh" ]]; then
        enhancement_path="$MODULES_DIR/enhancements/reality-sni-speedtest-interactive.sh"
        if [[ -f "$enhancement_path" ]]; then
            echo "# ============================================================================" >> "$TMP_OUTPUT"
            echo "# Reality SNI 自动测速增强模块（内联）" >> "$TMP_OUTPUT"
            echo "# ============================================================================" >> "$TMP_OUTPUT"
            tail -n +2 "$enhancement_path" | tr -d '\r' >> "$TMP_OUTPUT"
            echo "" >> "$TMP_OUTPUT"
        fi
    fi

    # 跳过第一行（模块注释头 # modules/xx-xxx.sh - ...），并去除 Windows 换行符 \r
    # 对于 15-singbox-reality.sh，仅删除显式 BUILD-OMIT 包裹的运行时 source 块；
    # 增强模块已内联，legacy SNI 函数保留为兜底且不会覆盖增强入口。
    if [[ "$mod" == "15-singbox-reality.sh" ]]; then
        tail -n +2 "$mod_path" | tr -d '\r' | sed '/^# BEGIN BUILD-OMIT reality-sni-runtime-source$/,/^# END BUILD-OMIT reality-sni-runtime-source$/d' >> "$TMP_OUTPUT"
    else
        tail -n +2 "$mod_path" | tr -d '\r' >> "$TMP_OUTPUT"
    fi
done

# 末尾追加入口调用
echo 'main "$@"' >> "$TMP_OUTPUT"

# 确保整个文件使用 LF 换行符（防止 Windows 环境污染）
if command -v sed &>/dev/null; then
    sed -i 's/\r$//' "$TMP_OUTPUT"
fi

chmod +x "$TMP_OUTPUT"
mv -f "$TMP_OUTPUT" "$OUTPUT"
trap - EXIT

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
