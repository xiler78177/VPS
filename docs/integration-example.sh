#!/bin/bash
# 集成示例：如何将 reality-sni-speedtest-enhancement.sh 整合到 15-singbox-reality.sh

# ============================================================================
# 方案 1：完全替换（推荐）
# ============================================================================

# 在 15-singbox-reality.sh 的开头（REALITY_CANDIDATE_SNI 数组定义之后）添加：

# --- 开始插入 ---

# Source SNI 测速增强模块
REALITY_ENHANCEMENT_MODULE="/path/to/reality-sni-speedtest-enhancement.sh"
if [[ -f "$REALITY_ENHANCEMENT_MODULE" ]]; then
    source "$REALITY_ENHANCEMENT_MODULE"
    REALITY_SNI_ENHANCEMENT_ENABLED=true
else
    REALITY_SNI_ENHANCEMENT_ENABLED=false
fi

# 增强版 SNI 选择函数（兼容原有接口）
reality_prompt_sni() {
    if [[ "$REALITY_SNI_ENHANCEMENT_ENABLED" == "true" ]]; then
        # 使用增强模块
        clear
        print_title "REALITY SNI 选择"
        echo ""
        echo "${C_CYAN}选择模式：${C_RESET}"
        echo ""
        echo "  1. 智能测速（推荐）"
        echo "     - 从 bulianglin.com 拉取 117+ 个大厂域名"
        echo "     - 自动 TLS 握手测速，筛选低延迟域名"
        echo "     - 延迟阈值: ${REALITY_SNI_LATENCY_THRESHOLD}ms"
        echo ""
        echo "  2. 快速选择"
        echo "     - 从候选池随机展示，不测速"
        echo "     - 适合网络环境稳定的场景"
        echo ""
        echo "  3. 内置列表"
        echo "     - 使用脚本内置的 77 个域名"
        echo "     - 兼容模式，无需联网"
        echo ""

        read -e -r -p "请选择模式 [1]: " mode_choice
        mode_choice=${mode_choice:-1}

        case "$mode_choice" in
            1)
                reality_prompt_sni_enhanced "smart"
                ;;
            2)
                reality_prompt_sni_enhanced "manual"
                ;;
            3)
                reality_prompt_sni_enhanced "legacy"
                ;;
            *)
                print_error "无效选择，使用智能测速模式"
                reality_prompt_sni_enhanced "smart"
                ;;
        esac
    else
        # Fallback 到原有逻辑（如果增强模块不可用）
        reality_prompt_sni_legacy
    fi
}

# 保留原有的 SNI 选择逻辑作为 fallback
reality_prompt_sni_legacy() {
    local choice sni i shown=()

    while true; do
        mapfile -t shown < <(printf '%s\n' "${REALITY_CANDIDATE_SNI[@]}" | shuf | head -n 12)

        clear
        print_title "REALITY SNI 伪装目标"
        echo ""
        echo "${C_CYAN}候选域名（内置列表）:${C_RESET}"
        echo ""

        i=1
        for sni in "${shown[@]}"; do
            printf "  %2d. %s\n" "$i" "$sni"
            ((i++))
        done

        echo ""
        echo "  r. 换一批"
        echo "  c. 自定义域名"
        echo ""

        read -e -r -p "请选择 [1]: " choice
        choice=${choice:-1}

        if [[ "${choice,,}" == "r" ]]; then
            continue
        elif [[ "${choice,,}" == "c" ]]; then
            read -e -r -p "自定义 SNI 域名: " sni
            if [[ -n "$sni" ]]; then
                echo "$sni"
                return 0
            fi
        elif [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#shown[@]} ]]; then
            sni="${shown[$((choice-1))]}"
            echo "$sni"
            return 0
        else
            print_error "无效选择"
            sleep 1
        fi
    done
}

# --- 结束插入 ---

# ============================================================================
# 方案 2：最小化集成（仅在需要时调用）
# ============================================================================

# 在 Reality 安装函数中，SNI 选择部分改为：

reality_install() {
    # ... 前面的代码 ...

    # SNI 选择
    print_info "选择 Reality 伪装目标域名..."

    # 询问是否使用智能测速
    if confirm "是否使用智能测速选择 SNI?（推荐）"; then
        # 临时下载增强模块
        local enhancement_script="/tmp/reality-sni-enhancement.sh"

        if curl -fsSL "https://raw.githubusercontent.com/xiler78177/VPS/main/reality-sni-speedtest-enhancement.sh" \
            -o "$enhancement_script" 2>/dev/null; then

            source "$enhancement_script"
            REALITY_SNI=$(reality_smart_sni_selection false)
        else
            print_warn "无法下载增强模块，使用内置列表"
            REALITY_SNI=$(reality_prompt_sni_legacy)
        fi
    else
        # 使用原有逻辑
        REALITY_SNI=$(reality_prompt_sni_legacy)
    fi

    # ... 后面的代码 ...
}

# ============================================================================
# 方案 3：独立命令行工具（用于测试和维护）
# ============================================================================

# 在脚本末尾添加命令行接口：

if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # 脚本被直接执行（非 source）

    case "${1:-}" in
        --sni-test)
            # 测试 SNI 工具
            source /path/to/reality-sni-speedtest-enhancement.sh
            reality_sni_tool "${2:-help}"
            ;;

        --sni-select)
            # 独立运行 SNI 选择
            source /path/to/reality-sni-speedtest-enhancement.sh
            selected_sni=$(reality_smart_sni_selection false)
            echo ""
            echo "选择的 SNI: $selected_sni"
            ;;

        --sni-validate)
            # 验证候选池质量
            source /path/to/reality-sni-speedtest-enhancement.sh
            reality_sni_tool validate "${2:-20}"
            ;;

        *)
            # 正常的菜单流程
            # ... 原有代码 ...
            ;;
    esac
fi

# ============================================================================
# 使用示例
# ============================================================================

# 1. 在 VPS 上直接测试 SNI 工具：
#    bash 15-singbox-reality.sh --sni-test help
#    bash 15-singbox-reality.sh --sni-test fetch
#    bash 15-singbox-reality.sh --sni-test batch 15 500
#    bash 15-singbox-reality.sh --sni-test validate 30

# 2. 独立运行 SNI 选择（不安装 Reality）：
#    bash 15-singbox-reality.sh --sni-select

# 3. 验证候选池质量（抽样 50 个域名）：
#    bash 15-singbox-reality.sh --sni-validate 50

# 4. 正常安装流程（会自动调用增强模块）：
#    bash 15-singbox-reality.sh

# ============================================================================
# 配置文件示例
# ============================================================================

# 创建 /etc/vps-mgr/reality/config 文件，自定义参数：

cat > /etc/vps-mgr/reality/config <<'EOF'
# Reality SNI 测速配置

# 延迟阈值（毫秒），超过此值视为不合格
REALITY_SNI_LATENCY_THRESHOLD=500

# 每批测试的域名数量
REALITY_SNI_BATCH_SIZE=15

# 最多测试批次数
REALITY_SNI_MAX_BATCHES=8

# 是否自动选择延迟最低的（true=自动，false=用户选择）
REALITY_SNI_AUTO_SELECT=false

# 单个域名测试超时（秒）
REALITY_SNI_TEST_TIMEOUT=5

# 候选池缓存 TTL（秒）
REALITY_SNI_CACHE_TTL=43200  # 12 小时
EOF

# ============================================================================
# 完整的工作流程示例
# ============================================================================

# 用户执行安装脚本：
# bash <(curl -sSL https://raw.githubusercontent.com/xiler78177/VPS/dist/v4-built.sh)

# 进入 Reality 安装菜单 → 选择 SNI：

# [系统输出]
# ========================================
# REALITY SNI 选择
# ========================================
#
# 选择模式：
#
#   1. 智能测速（推荐）
#      - 从 bulianglin.com 拉取 117+ 个大厂域名
#      - 自动 TLS 握手测速，筛选低延迟域名
#      - 延迟阈值: 800ms
#
#   2. 快速选择
#      - 从候选池随机展示，不测速
#      - 适合网络环境稳定的场景
#
#   3. 内置列表
#      - 使用脚本内置的 77 个域名
#      - 兼容模式，无需联网
#
# 请选择模式 [1]: 1

# [系统输出]
# ========================================
# REALITY SNI 智能选择（自动测速）
# ========================================
#
# 说明：
#   1. 脚本将从 bulianglin.com 拉取最新的 SNI 候选池（117+ 个大厂域名）
#   2. 自动进行 TLS 握手测速，筛选延迟低于 800ms 的域名
#   3. 如果当前批次没有合格域名，自动拉取下一批继续测试
#   4. 最多测试 5 批，或直到找到合格域名
#
# 正在从 bulianglin.com 拉取最新 SNI 候选池...
# ✓ 成功拉取 117 个 SNI 候选域名
#
# 开始自动测速? [Y/n]: y
#
# ========== 第 1/5 批测速 ==========
#
# 开始测速（批次大小: 10，延迟阈值: 800ms）...
#
#   测试 apps.apple.com ... 245ms ✓
#   测试 s0.awsstatic.com ... 312ms ✓
#   测试 github.gallerycdn.vsassets.io ... 189ms ✓
#   测试 statici.icloud.com ... 267ms ✓
#   测试 www.microsoft.com ... 423ms ✓
#   测试 azure.microsoft.com ... 398ms ✓
#   测试 cdn.bizible.com ... 超时 ✗
#   测试 tags.tiqcdn.com ... 756ms ✓
#   测试 gsp-ssl.ls.apple.com ... 234ms ✓
#   测试 store-images.s-microsoft.com ... 445ms ✓
#
# 测速完成: 9/10 个域名符合要求
#
# ✓ 找到 9 个合格域名：
#
#   1. github.gallerycdn.vsassets.io              [ 189ms]
#   2. gsp-ssl.ls.apple.com                       [ 234ms]
#   3. apps.apple.com                             [ 245ms]
#   4. statici.icloud.com                         [ 267ms]
#   5. s0.awsstatic.com                           [ 312ms]
#   6. azure.microsoft.com                        [ 398ms]
#   7. www.microsoft.com                          [ 423ms]
#   8. store-images.s-microsoft.com               [ 445ms]
#   9. tags.tiqcdn.com                            [ 756ms]
#
#   a. 自动选择延迟最低的（推荐）
#   r. 重新测速
#   c. 手动输入域名
#
# 请选择 [a]: a
#
# ✓ 已选择: github.gallerycdn.vsassets.io (189ms)

# ============================================================================
# 注意事项
# ============================================================================

# 1. 依赖检查：
#    - curl（必需，用于拉取候选池）
#    - openssl（必需，用于 TLS 握手测速）
#    - shuf（推荐，用于随机选择；若无则用 RANDOM）
#    - date +%s%3N（推荐，用于毫秒级计时；若不支持则用秒级）

# 2. 网络要求：
#    - VPS 需要能访问 bulianglin.com（HTTPS）
#    - VPS 需要能访问候选域名的 443 端口（TLS 握手）

# 3. 性能考虑：
#    - 每批测速约需 10-30 秒（取决于网络和批次大小）
#    - 建议在 VPS 网络空闲时进行测速
#    - 可通过配置文件调整批次大小和超时时间

# 4. 兼容性：
#    - 完全兼容原有的 15-singbox-reality.sh
#    - 如果增强模块不可用，自动 fallback 到内置列表
#    - 不影响已安装的 Reality 节点

# 5. 维护建议：
#    - 定期运行 --sni-validate 验证候选池质量
#    - 如果发现大量超时或 Cloudflare 代理，手动更新候选池
#    - 可通过 GitHub Issue 向 bulianglin.com 反馈失效域名
