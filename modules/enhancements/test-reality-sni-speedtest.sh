#!/bin/bash
# Reality SNI 测速方案完整测试脚本
# 用途：验证从 bulianglin.com 拉取候选池 + 自动测速的完整流程

set -e

# 颜色定义
C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[1;33m'
C_CYAN='\033[0;36m'
C_RESET='\033[0m'

print_info() { echo -e "${C_CYAN}[INFO]${C_RESET} $*"; }
print_success() { echo -e "${C_GREEN}[SUCCESS]${C_RESET} $*"; }
print_warn() { echo -e "${C_YELLOW}[WARN]${C_RESET} $*"; }
print_error() { echo -e "${C_RED}[ERROR]${C_RESET} $*"; }
print_title() { echo -e "\n${C_CYAN}========== $* ==========${C_RESET}\n"; }

# ============================================================================
# 测试 1：拉取 bulianglin.com 候选池
# ============================================================================

test_fetch_pool() {
    print_title "测试 1: 拉取 bulianglin.com 候选池"

    local url="https://bulianglin.com/archives/nicename.html"
    local output_file="/tmp/bulianglin-sni-pool.txt"

    print_info "正在下载网页..."
    local html_content
    html_content=$(curl -fsSL --max-time 15 "$url" 2>/dev/null)

    if [[ -z "$html_content" ]]; then
        print_error "无法连接到 bulianglin.com"
        return 1
    fi

    print_success "网页下载成功"

    print_info "正在解析候选池..."
    local domains_json
    domains_json=$(echo "$html_content" | grep -o 'const domains = \[.*\];' | sed 's/const domains = \[//; s/\];//')

    if [[ -z "$domains_json" ]]; then
        print_error "无法解析候选池数据"
        return 1
    fi

    echo "$domains_json" | sed 's/"//g; s/, /\n/g' | sed 's/^ *//; s/ *$//' | sort -u > "$output_file"

    local count
    count=$(wc -l < "$output_file")

    print_success "成功提取 $count 个域名"
    echo ""
    print_info "前 10 个域名："
    head -10 "$output_file" | sed 's/^/  /'
    echo ""
    print_info "候选池已保存到: $output_file"

    return 0
}

# ============================================================================
# 测试 2：TLS 握手测速（单个域名）
# ============================================================================

test_single_speedtest() {
    print_title "测试 2: TLS 握手测速（单个域名）"

    local test_domains=(
        "apps.apple.com"
        "s0.awsstatic.com"
        "github.gallerycdn.vsassets.io"
        "www.microsoft.com"
        "statici.icloud.com"
    )

    print_info "测试 ${#test_domains[@]} 个域名..."
    echo ""

    for domain in "${test_domains[@]}"; do
        echo -n "  $domain ... "

        local start_ms end_ms latency_ms
        start_ms=$(date +%s%3N 2>/dev/null || echo $(($(date +%s) * 1000)))

        if timeout 5 openssl s_client -connect "${domain}:443" \
            -servername "$domain" -brief </dev/null >/dev/null 2>&1; then

            end_ms=$(date +%s%3N 2>/dev/null || echo $(($(date +%s) * 1000)))
            latency_ms=$((end_ms - start_ms))

            echo -e "${C_GREEN}${latency_ms}ms ✓${C_RESET}"
        else
            echo -e "${C_RED}超时 ✗${C_RESET}"
        fi
    done

    echo ""
    return 0
}

# ============================================================================
# 测试 3：批量测速（从候选池随机选择）
# ============================================================================

test_batch_speedtest() {
    print_title "测试 3: 批量测速（从候选池随机选择）"

    local pool_file="/tmp/bulianglin-sni-pool.txt"

    if [[ ! -f "$pool_file" ]]; then
        print_error "候选池文件不存在，请先运行测试 1"
        return 1
    fi

    local batch_size=10
    local threshold=800

    print_info "从候选池中随机选择 $batch_size 个域名进行测速..."
    print_info "延迟阈值: ${threshold}ms"
    echo ""

    local -a batch_domains results=()
    mapfile -t batch_domains < <(shuf -n "$batch_size" "$pool_file")

    local qualified_count=0

    for domain in "${batch_domains[@]}"; do
        echo -n "  测试 ${domain} ... "

        local start_ms end_ms latency_ms
        start_ms=$(date +%s%3N 2>/dev/null || echo $(($(date +%s) * 1000)))

        if timeout 3 openssl s_client -connect "${domain}:443" \
            -servername "$domain" -brief </dev/null >/dev/null 2>&1; then

            end_ms=$(date +%s%3N 2>/dev/null || echo $(($(date +%s) * 1000)))
            latency_ms=$((end_ms - start_ms))

            if [[ $latency_ms -le $threshold ]]; then
                echo -e "${C_GREEN}${latency_ms}ms ✓${C_RESET}"
                results+=("${latency_ms}|${domain}")
                ((qualified_count++))
            else
                echo -e "${C_YELLOW}${latency_ms}ms (超过阈值)${C_RESET}"
            fi
        else
            echo -e "${C_RED}超时 ✗${C_RESET}"
        fi
    done

    echo ""
    print_info "测速完成: ${qualified_count}/${batch_size} 个域名符合要求"

    if [[ ${#results[@]} -gt 0 ]]; then
        echo ""
        print_success "合格域名（按延迟排序）："
        printf '%s\n' "${results[@]}" | sort -t'|' -k1 -n | while IFS='|' read -r latency domain; do
            printf "  %-50s [%4dms]\n" "$domain" "$latency"
        done
    fi

    echo ""
    return 0
}

# ============================================================================
# 测试 4：Cloudflare 代理检测
# ============================================================================

test_cloudflare_detection() {
    print_title "测试 4: Cloudflare 代理检测"

    local test_domains=(
        "apps.apple.com"
        "s0.awsstatic.com"
        "www.cloudflare.com"
        "dash.cloudflare.com"
    )

    print_info "测试 ${#test_domains[@]} 个域名的 Cloudflare 状态..."
    echo ""

    for domain in "${test_domains[@]}"; do
        echo -n "  $domain ... "

        local resp headers
        resp=$(curl -sI --max-time 5 "https://$domain" 2>/dev/null)

        if [[ -z "$resp" ]]; then
            echo -e "${C_YELLOW}无法连接${C_RESET}"
            continue
        fi

        headers=$(echo "$resp" | tr -d '\r')

        if echo "$headers" | grep -iq 'cf-ray\|server:.*cloudflare'; then
            echo -e "${C_RED}Cloudflare 代理 ✗${C_RESET}"
        else
            echo -e "${C_GREEN}无 CF 代理 ✓${C_RESET}"
        fi
    done

    echo ""
    return 0
}

# ============================================================================
# 测试 5：完整流程模拟（多批次测速）
# ============================================================================

test_full_workflow() {
    print_title "测试 5: 完整流程模拟（多批次测速）"

    local pool_file="/tmp/bulianglin-sni-pool.txt"

    if [[ ! -f "$pool_file" ]]; then
        print_error "候选池文件不存在，请先运行测试 1"
        return 1
    fi

    local batch_size=8
    local threshold=600
    local max_batches=3

    print_info "模拟智能 SNI 选择流程："
    print_info "  - 批次大小: $batch_size"
    print_info "  - 延迟阈值: ${threshold}ms"
    print_info "  - 最多批次: $max_batches"
    echo ""

    local batch_num=0
    local -a all_results=()

    while [[ $batch_num -lt $max_batches ]]; do
        ((batch_num++))

        print_info "========== 第 ${batch_num}/${max_batches} 批测速 =========="
        echo ""

        local -a batch_domains batch_results=()
        mapfile -t batch_domains < <(shuf -n "$batch_size" "$pool_file")

        local qualified_count=0

        for domain in "${batch_domains[@]}"; do
            echo -n "  测试 ${domain} ... "

            local start_ms end_ms latency_ms
            start_ms=$(date +%s%3N 2>/dev/null || echo $(($(date +%s) * 1000)))

            if timeout 3 openssl s_client -connect "${domain}:443" \
                -servername "$domain" -brief </dev/null >/dev/null 2>&1; then

                end_ms=$(date +%s%3N 2>/dev/null || echo $(($(date +%s) * 1000)))
                latency_ms=$((end_ms - start_ms))

                if [[ $latency_ms -le $threshold ]]; then
                    echo -e "${C_GREEN}${latency_ms}ms ✓${C_RESET}"
                    batch_results+=("${latency_ms}|${domain}")
                    ((qualified_count++))
                else
                    echo -e "${C_YELLOW}${latency_ms}ms (超过阈值)${C_RESET}"
                fi
            else
                echo -e "${C_RED}超时 ✗${C_RESET}"
            fi
        done

        echo ""
        print_info "本批次: ${qualified_count}/${batch_size} 个域名符合要求"

        if [[ ${#batch_results[@]} -gt 0 ]]; then
            all_results+=("${batch_results[@]}")
            break
        else
            print_warn "本批次无合格域名"

            if [[ $batch_num -lt $max_batches ]]; then
                echo ""
                print_info "继续测试下一批..."
                echo ""
                sleep 1
            fi
        fi
    done

    echo ""

    if [[ ${#all_results[@]} -eq 0 ]]; then
        print_error "未找到符合要求的 SNI 域名"
        return 1
    fi

    print_success "找到 ${#all_results[@]} 个合格域名："
    echo ""

    printf '%s\n' "${all_results[@]}" | sort -t'|' -k1 -n | head -10 | while IFS='|' read -r latency domain; do
        printf "  %-50s [%4dms]\n" "$domain" "$latency"
    done

    echo ""

    local best_domain best_latency
    best_domain=$(printf '%s\n' "${all_results[@]}" | sort -t'|' -k1 -n | head -1 | cut -d'|' -f2)
    best_latency=$(printf '%s\n' "${all_results[@]}" | sort -t'|' -k1 -n | head -1 | cut -d'|' -f1)

    print_success "推荐选择: $best_domain (${best_latency}ms)"

    return 0
}

# ============================================================================
# 主菜单
# ============================================================================

main() {
    clear
    print_title "Reality SNI 测速方案完整测试"

    echo "本脚本将测试以下功能："
    echo ""
    echo "  1. 从 bulianglin.com 拉取候选池"
    echo "  2. TLS 握手测速（单个域名）"
    echo "  3. 批量测速（从候选池随机选择）"
    echo "  4. Cloudflare 代理检测"
    echo "  5. 完整流程模拟（多批次测速）"
    echo "  6. 运行所有测试"
    echo "  0. 退出"
    echo ""

    read -e -r -p "请选择测试项 [6]: " choice
    choice=${choice:-6}

    echo ""

    case "$choice" in
        1) test_fetch_pool ;;
        2) test_single_speedtest ;;
        3) test_batch_speedtest ;;
        4) test_cloudflare_detection ;;
        5) test_full_workflow ;;
        6)
            test_fetch_pool && \
            test_single_speedtest && \
            test_batch_speedtest && \
            test_cloudflare_detection && \
            test_full_workflow
            ;;
        0) exit 0 ;;
        *)
            print_error "无效选择"
            exit 1
            ;;
    esac

    echo ""
    print_success "测试完成！"
    echo ""
    echo "下一步："
    echo "  1. 将 reality-sni-speedtest-enhancement.sh 集成到你的脚本中"
    echo "  2. 参考 integration-example.sh 中的集成方案"
    echo "  3. 在 VPS 上实际测试完整安装流程"
}

# 运行主程序
main "$@"
