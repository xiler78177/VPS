#!/bin/bash
# Reality SNI 自动测速选择增强模块（纯交互式版本）
# 所有配置通过菜单选择，无需编辑配置文件

# ============================================================================
# 默认参数（用户通过交互式菜单修改，不需要编辑此文件）
# ============================================================================

# bulianglin.com 候选池 URL
BULIANGLIN_SNI_POOL_URL="https://bulianglin.com/archives/nicename.html"

# 本地缓存文件
REALITY_SNI_CACHE_DIR="/etc/vps-mgr/reality"
REALITY_SNI_POOL_FILE="${REALITY_SNI_CACHE_DIR}/bulianglin-sni-pool.txt"
REALITY_SNI_CACHE_TTL=86400  # 24 小时

# 三级阈值（默认值，用户可在交互菜单中选择）
REALITY_SNI_LATENCY_THRESHOLD_STRICT=50
REALITY_SNI_LATENCY_THRESHOLD_NORMAL=200
REALITY_SNI_LATENCY_THRESHOLD_RELAXED=500

# 测速参数
REALITY_SNI_BATCH_SIZE=15
REALITY_SNI_TEST_TIMEOUT=3

# ============================================================================
# 核心函数：从 bulianglin.com 拉取候选池
# ============================================================================

reality_fetch_bulianglin_pool() {
    local html_content domains_json

    print_info "正在从 bulianglin.com 拉取最新 SNI 候选池..."

    html_content=$(curl -fsSL --max-time 15 "$BULIANGLIN_SNI_POOL_URL" 2>/dev/null)
    if [[ -z "$html_content" ]]; then
        return 1
    fi

    domains_json=$(echo "$html_content" | grep -o 'const domains = \[.*\];' | sed 's/const domains = \[//; s/\];//')

    if [[ -z "$domains_json" ]]; then
        return 1
    fi

    mkdir -p "$REALITY_SNI_CACHE_DIR"
    echo "$domains_json" | sed 's/"//g; s/, /\n/g' | sed 's/^ *//; s/ *$//' | sort -u > "$REALITY_SNI_POOL_FILE"

    local count
    count=$(wc -l < "$REALITY_SNI_POOL_FILE")

    if [[ $count -lt 10 ]]; then
        return 1
    fi

    print_success "成功拉取 $count 个 SNI 候选域名"
    return 0
}

# ============================================================================
# 核心函数：从 v2ray-agent 拉取备用候选池
# ============================================================================

reality_fetch_v2ray_agent_pool() {
    local v2ray_agent_url="https://raw.githubusercontent.com/mack-a/v2ray-agent/master/install.sh"
    local temp_file="/tmp/v2ray-agent-install.sh"

    print_info "正在从 v2ray-agent 拉取备用候选池..."

    if ! curl -fsSL --max-time 15 "$v2ray_agent_url" -o "$temp_file" 2>/dev/null; then
        return 1
    fi

    local domains_content
    domains_content=$(grep -A 100 '_realityDomainList()' "$temp_file" | grep -E '^\s*"[^"]+"\s*$' | sed 's/[" ]//g' | sort -u)

    if [[ -z "$domains_content" ]]; then
        rm -f "$temp_file"
        return 1
    fi

    mkdir -p "$REALITY_SNI_CACHE_DIR"
    echo "$domains_content" > "$REALITY_SNI_POOL_FILE"

    local count
    count=$(wc -l < "$REALITY_SNI_POOL_FILE")

    if [[ $count -lt 10 ]]; then
        rm -f "$temp_file"
        return 1
    fi

    print_success "成功从 v2ray-agent 拉取 $count 个备用域名"
    rm -f "$temp_file"
    return 0
}

# ============================================================================
# 核心函数：更新候选池（三级降级）
# ============================================================================

reality_update_sni_pool() {
    # 检查缓存
    if [[ -f "$REALITY_SNI_POOL_FILE" ]]; then
        local age
        age=$(( $(date +%s) - $(stat -c %Y "$REALITY_SNI_POOL_FILE" 2>/dev/null || echo 0) ))

        if [[ $age -lt $REALITY_SNI_CACHE_TTL ]]; then
            local count
            count=$(wc -l < "$REALITY_SNI_POOL_FILE")
            print_info "使用缓存的候选池（$count 个域名，${age}s 前更新）"
            return 0
        fi
    fi

    # 三级降级：bulianglin.com → v2ray-agent → 内置列表
    if reality_fetch_bulianglin_pool; then
        return 0
    fi

    print_warn "bulianglin.com 不可用，尝试 v2ray-agent 备用池..."
    if reality_fetch_v2ray_agent_pool; then
        return 0
    fi

    print_warn "v2ray-agent 也不可用，使用内置列表"
    printf '%s\n' "${REALITY_CANDIDATE_SNI[@]}" > /tmp/reality-fallback-pool.txt
    REALITY_SNI_POOL_FILE="/tmp/reality-fallback-pool.txt"
    return 0
}

# ============================================================================
# 核心函数：TLS 握手测速
# ============================================================================

reality_test_sni_latency() {
    local domain="$1"
    local timeout="${2:-$REALITY_SNI_TEST_TIMEOUT}"
    local start_ms end_ms latency_ms

    start_ms=$(date +%s%3N 2>/dev/null || echo $(($(date +%s) * 1000)))

    if timeout "$timeout" openssl s_client -connect "${domain}:443" \
        -servername "$domain" -brief </dev/null >/dev/null 2>&1; then

        end_ms=$(date +%s%3N 2>/dev/null || echo $(($(date +%s) * 1000)))
        latency_ms=$((end_ms - start_ms))

        echo "$latency_ms"
        return 0
    else
        echo "timeout"
        return 1
    fi
}

# ============================================================================
# 核心函数：批量测速
# ============================================================================

reality_batch_speedtest() {
    local batch_size="${1:-$REALITY_SNI_BATCH_SIZE}"
    local threshold="${2:-$REALITY_SNI_LATENCY_THRESHOLD_NORMAL}"
    local pool_file="${3:-$REALITY_SNI_POOL_FILE}"

    if [[ ! -f "$pool_file" ]]; then
        print_error "候选池文件不存在"
        return 1
    fi

    local -a batch_domains
    mapfile -t batch_domains < <(shuf -n "$batch_size" "$pool_file")

    if [[ ${#batch_domains[@]} -eq 0 ]]; then
        print_error "候选池为空"
        return 1
    fi

    print_info "开始测速（批次大小: ${#batch_domains[@]}，延迟阈值: ${threshold}ms）..." >&2
    echo "" >&2

    local -a results=()
    local domain latency status
    local qualified_count=0

    for domain in "${batch_domains[@]}"; do
        echo -n "  测试 ${domain} ... " >&2

        latency=$(reality_test_sni_latency "$domain")
        status=$?

        if [[ $status -eq 0 && "$latency" != "timeout" ]]; then
            if [[ $latency -le $threshold ]]; then
                echo -e "${C_GREEN}${latency}ms ✓${C_RESET}" >&2
                results+=("${latency}|${domain}")
                ((qualified_count++))
            else
                echo -e "${C_YELLOW}${latency}ms (超过阈值)${C_RESET}" >&2
            fi
        else
            echo -e "${C_RED}超时 ✗${C_RESET}" >&2
        fi
    done

    echo "" >&2
    print_info "测速完成: ${qualified_count}/${#batch_domains[@]} 个域名符合要求" >&2

    if [[ ${#results[@]} -gt 0 ]]; then
        printf '%s\n' "${results[@]}" | sort -t'|' -k1 -n
        return 0
    else
        return 1
    fi
}

# ============================================================================
# 核心函数：智能 SNI 选择（纯交互式，三级阈值）
# ============================================================================

reality_smart_sni_selection() {
    echo "" >&2
    echo "========================================" >&2
    echo "REALITY SNI 智能选择" >&2
    echo "========================================" >&2
    echo "" >&2
    echo "${C_CYAN}说明：${C_RESET}" >&2
    echo "  脚本将从 bulianglin.com 拉取 117+ 个大厂域名候选池" >&2
    echo "  自动进行 TLS 握手测速，筛选低延迟域名" >&2
    echo "" >&2

    # 更新候选池（自动三级降级）
    reality_update_sni_pool

    echo "" >&2
    echo "${C_CYAN}选择测速模式：${C_RESET}" >&2
    echo "" >&2
    echo "  1. 严格模式（延迟 < 50ms）" >&2
    echo "     适合：VPS 与 CDN 在同一地区（如美西 VPS 访问美西 CloudFront）" >&2
    echo "" >&2
    echo "  2. 正常模式（延迟 < 200ms）" >&2
    echo "     适合：大部分场景（如亚洲 VPS 访问全球 CDN）" >&2
    echo "" >&2
    echo "  3. 宽松模式（延迟 < 500ms）" >&2
    echo "     适合：跨洲访问或网络较慢的场景" >&2
    echo "" >&2
    echo "  4. 自动模式（智能三级降级）★ 推荐" >&2
    echo "     先尝试严格模式，无合格域名则自动降级到正常/宽松模式" >&2
    echo "" >&2
    echo "  5. 跳过测速（从候选池随机选择，不测速）" >&2
    echo "" >&2

    local mode_choice
    read -e -r -p "请选择模式 [4]: " mode_choice
    mode_choice=${mode_choice:-4}

    local threshold
    case "$mode_choice" in
        1) threshold=$REALITY_SNI_LATENCY_THRESHOLD_STRICT ;;
        2) threshold=$REALITY_SNI_LATENCY_THRESHOLD_NORMAL ;;
        3) threshold=$REALITY_SNI_LATENCY_THRESHOLD_RELAXED ;;
        4)
            # 自动模式（三级降级）
            reality_smart_sni_selection_auto
            return $?
            ;;
        5)
            # 跳过测速
            reality_select_from_pool_no_test
            return $?
            ;;
        *)
            print_error "无效选择，使用自动模式"
            reality_smart_sni_selection_auto
            return $?
            ;;
    esac

    # 单一阈值模式
    echo "" >&2
    confirm "开始测速?" || return 1

    echo "" >&2
    local batch_output
    batch_output=$(reality_batch_speedtest "$REALITY_SNI_BATCH_SIZE" "$threshold" "$REALITY_SNI_POOL_FILE")

    if [[ -z "$batch_output" ]]; then
        print_error "未找到符合要求的域名" >&2
        echo "" >&2
        echo "建议：" >&2
        echo "  1. 选择更宽松的模式" >&2
        echo "  2. 检查 VPS 网络连接" >&2
        echo "  3. 手动输入 SNI 域名" >&2
        echo "" >&2

        if confirm "是否手动输入 SNI?"; then
            read -e -r -p "请输入 SNI 域名: " manual_sni
            if [[ -n "$manual_sni" ]]; then
                echo "$manual_sni"
                return 0
            fi
        fi

        return 1
    fi

    # 显示结果并让用户选择
    reality_display_and_select_sni "$batch_output"
}

# ============================================================================
# 辅助函数：自动模式（三级阈值降级）
# ============================================================================

reality_smart_sni_selection_auto() {
    echo "" >&2
    print_info "自动模式：将依次尝试严格（50ms）→ 正常（200ms）→ 宽松（500ms）阈值" >&2
    echo "" >&2
    confirm "开始测速?" || return 1

    local -a thresholds=(
        "$REALITY_SNI_LATENCY_THRESHOLD_STRICT:严格（< 50ms）"
        "$REALITY_SNI_LATENCY_THRESHOLD_NORMAL:正常（< 200ms）"
        "$REALITY_SNI_LATENCY_THRESHOLD_RELAXED:宽松（< 500ms）"
    )

    local -a all_results=()

    for tier in "${thresholds[@]}"; do
        local threshold="${tier%%:*}"
        local tier_name="${tier##*:}"

        echo "" >&2
        print_info "========== 尝试 ${tier_name} ==========" >&2
        echo "" >&2

        local batch_output
        batch_output=$(reality_batch_speedtest "$REALITY_SNI_BATCH_SIZE" "$threshold" "$REALITY_SNI_POOL_FILE")

        if [[ -n "$batch_output" ]]; then
            mapfile -t all_results < <(echo "$batch_output")
            print_success "在 ${tier_name} 下找到 ${#all_results[@]} 个合格域名"
            break
        else
            print_warn "${tier_name} 下无合格域名，自动降级..."
            sleep 1
        fi
    done

    if [[ ${#all_results[@]} -eq 0 ]]; then
        print_error "所有阈值级别均未找到合格域名" >&2
        echo "" >&2
        echo "建议：" >&2
        echo "  1. 检查 VPS 网络连接" >&2
        echo "  2. 手动输入 SNI 域名" >&2
        echo "" >&2

        if confirm "是否手动输入 SNI?"; then
            read -e -r -p "请输入 SNI 域名: " manual_sni
            if [[ -n "$manual_sni" ]]; then
                echo "$manual_sni"
                return 0
            fi
        fi

        return 1
    fi

    # 显示结果并让用户选择
    reality_display_and_select_sni "$(printf '%s\n' "${all_results[@]}")"
}

# ============================================================================
# 辅助函数：跳过测速，从候选池随机选择
# ============================================================================

reality_select_from_pool_no_test() {
    echo "" >&2
    print_info "从候选池中随机选择（不测速）" >&2
    echo "" >&2

    local -a shown
    mapfile -t shown < <(shuf -n 12 "$REALITY_SNI_POOL_FILE")

    while true; do
        echo "" >&2
        echo "========================================" >&2
        echo "REALITY SNI 候选域名" >&2
        echo "========================================" >&2
        echo "" >&2

        local i=1
        for domain in "${shown[@]}"; do
            printf "  %2d. %s\n" "$i" "$domain" >&2
            ((i++))
        done

        echo "" >&2
        echo "  ${C_CYAN}r${C_RESET}. 换一批" >&2
        echo "  ${C_CYAN}c${C_RESET}. 手动输入域名" >&2
        echo "  ${C_CYAN}s${C_RESET}. 切换到测速模式" >&2
        echo "" >&2

        local choice
        read -e -r -p "请选择 [1]: " choice
        choice=${choice:-1}

        if [[ "${choice,,}" == "r" ]]; then
            mapfile -t shown < <(shuf -n 12 "$REALITY_SNI_POOL_FILE")
            continue
        elif [[ "${choice,,}" == "s" ]]; then
            reality_smart_sni_selection
            return $?
        elif [[ "${choice,,}" == "c" ]]; then
            read -e -r -p "请输入 SNI 域名: " manual_sni
            if [[ -n "$manual_sni" ]]; then
                echo "$manual_sni"
                return 0
            fi
        elif [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#shown[@]} ]]; then
            echo "${shown[$((choice-1))]}"
            return 0
        else
            print_error "无效选择" >&2
            sleep 1
        fi
    done
}

# ============================================================================
# 辅助函数：显示测速结果并让用户选择
# ============================================================================

reality_display_and_select_sni() {
    local results_text="$1"

    if [[ -z "$results_text" ]]; then
        return 1
    fi

    local -a results
    mapfile -t results < <(echo "$results_text")

    echo "" >&2
    print_success "找到 ${#results[@]} 个合格域名：" >&2
    echo "" >&2

    local i=1
    local -a display_list=()

    for result in "${results[@]}"; do
        local latency="${result%%|*}"
        local domain="${result##*|}"
        display_list+=("$domain")
        printf "  %2d. %-50s [%4dms]\n" "$i" "$domain" "$latency" >&2
        ((i++))
    done

    echo "" >&2
    echo "  ${C_CYAN}a${C_RESET}. 自动选择延迟最低的（推荐）" >&2
    echo "  ${C_CYAN}r${C_RESET}. 重新测速" >&2
    echo "  ${C_CYAN}c${C_RESET}. 手动输入域名" >&2
    echo "" >&2

    while true; do
        local choice
        read -e -r -p "请选择 [a]: " choice
        choice=${choice:-a}

        if [[ "${choice,,}" == "a" ]]; then
            local best_domain="${results[0]##*|}"
            local best_latency="${results[0]%%|*}"
            print_success "已选择: $best_domain (${best_latency}ms)" >&2
            echo "$best_domain"
            return 0

        elif [[ "${choice,,}" == "r" ]]; then
            reality_smart_sni_selection
            return $?

        elif [[ "${choice,,}" == "c" ]]; then
            read -e -r -p "请输入 SNI 域名: " manual_sni
            if [[ -n "$manual_sni" ]]; then
                echo "$manual_sni"
                return 0
            fi

        elif [[ "$choice" =~ ^[0-9]+$ && "$choice" -ge 1 && "$choice" -le ${#display_list[@]} ]]; then
            local selected_domain="${display_list[$((choice-1))]}"
            print_success "已选择: $selected_domain" >&2
            echo "$selected_domain"
            return 0
        else
            print_error "无效选择" >&2
        fi
    done
}

# ============================================================================
# 主入口函数（替换原有的 reality_prompt_sni）
# ============================================================================

reality_prompt_sni() {
    # 直接调用智能选择（纯交互式）
    reality_smart_sni_selection
}

# ============================================================================
# 使用说明
# ============================================================================

# 在 15-singbox-reality.sh 中集成此模块的方法：
#
# 1. 在文件开头 source 此脚本：
#    source /path/to/reality-sni-speedtest-interactive.sh
#
# 2. 原有的 reality_prompt_sni() 函数会被自动替换
#
# 3. 用户体验：
#    - 进入 Reality 安装流程
#    - 选择 SNI 时，自动弹出交互式菜单
#    - 用户选择测速模式（严格/正常/宽松/自动/跳过）
#    - 自动测速并展示结果
#    - 用户选择域名或自动选择最优
#    - 无需编辑任何配置文件

# ============================================================================
# 完整工作流程示例
# ============================================================================

# [用户执行安装脚本]
# bash <(curl -sSL https://raw.githubusercontent.com/xiler78177/VPS/dist/v4-built.sh)
#
# [进入 Reality 安装菜单]
# → 选择 SNI
#
# [系统输出]
# ========================================
# REALITY SNI 智能选择
# ========================================
#
# 说明：
#   脚本将从 bulianglin.com 拉取 117+ 个大厂域名候选池
#   自动进行 TLS 握手测速，筛选低延迟域名
#
# [INFO] 正在从 bulianglin.com 拉取最新 SNI 候选池...
# [SUCCESS] 成功拉取 117 个 SNI 候选域名
#
# 选择测速模式：
#
#   1. 严格模式（推荐，延迟 < 50ms）
#      适合：VPS 与 CDN 在同一地区（如美西 VPS 访问美西 CloudFront）
#
#   2. 正常模式（推荐，延迟 < 200ms）
#      适合：大部分场景（如亚洲 VPS 访问全球 CDN）
#
#   3. 宽松模式（兜底，延迟 < 500ms）
#      适合：跨洲访问或网络较慢的场景
#
#   4. 自动模式（智能，三级阈值自动降级）
#      先尝试严格模式，无合格域名则自动降级到正常/宽松模式
#
#   5. 跳过测速（从候选池随机选择，不测速）
#
# 请选择模式 [4]: 4
#
# [INFO] 自动模式：将依次尝试严格（50ms）→ 正常（200ms）→ 宽松（500ms）阈值
#
# 开始测速? [Y/n]: y
#
# ========== 尝试 严格（< 50ms）==========
#
# [INFO] 开始测速（批次大小: 15，延迟阈值: 50ms）...
#
#   测试 apps.apple.com ... 245ms (超过阈值)
#   测试 s0.awsstatic.com ... 312ms (超过阈值)
#   ...
#
# [INFO] 测速完成: 0/15 个域名符合要求
# [WARN] 严格（< 50ms）下无合格域名，自动降级...
#
# ========== 尝试 正常（< 200ms）==========
#
# [INFO] 开始测速（批次大小: 15，延迟阈值: 200ms）...
#
#   测试 github.gallerycdn.vsassets.io ... 189ms ✓
#   测试 gsp-ssl.ls.apple.com ... 134ms ✓
#   测试 statici.icloud.com ... 167ms ✓
#   ...
#
# [INFO] 测速完成: 5/15 个域名符合要求
# [SUCCESS] 在 正常（< 200ms）下找到 5 个合格域名
#
# [SUCCESS] 找到 5 个合格域名：
#
#   1. gsp-ssl.ls.apple.com                       [ 134ms]
#   2. statici.icloud.com                         [ 167ms]
#   3. github.gallerycdn.vsassets.io              [ 189ms]
#   4. apps.apple.com                             [ 195ms]
#   5. store-images.s-microsoft.com               [ 198ms]
#
#   a. 自动选择延迟最低的（推荐）
#   r. 重新测速
#   c. 手动输入域名
#
# 请选择 [a]: a
#
# [SUCCESS] 已选择: gsp-ssl.ls.apple.com (134ms)
#
# [继续 Reality 安装流程...]

