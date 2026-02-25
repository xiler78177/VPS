# modules/03-sysinfo.sh - 系统信息缓存与展示
load_cache() {
    if [[ -f "$CACHE_FILE" ]]; then
        local file_mtime
        file_mtime=$(stat -c %Y "$CACHE_FILE" 2>/dev/null || stat -f %m "$CACHE_FILE" 2>/dev/null || echo 0)
        local cache_age=$(($(date +%s) - file_mtime))
        if [[ $cache_age -lt $CACHE_TTL ]]; then
            # 安全检查：仅允许合法的变量赋值格式
            if validate_conf_file "$CACHE_FILE" 2>/dev/null; then
                source "$CACHE_FILE" 2>/dev/null || return 1
                return 0
            fi
            return 1
        fi
    fi
    return 1
}

refresh_network_cache() {
    CACHED_IPV4=$(get_public_ipv4 || echo "N/A")
    CACHED_IPV6=$(get_public_ipv6 || echo "")
    [[ -z "$CACHED_IPV6" ]] && CACHED_IPV6="未配置"
    local ipinfo=$(curl -s --connect-timeout 3 --max-time 5 https://ipinfo.io/json 2>/dev/null || echo "{}")
    CACHED_ISP=$(echo "$ipinfo" | grep -o '"org"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    [[ -z "$CACHED_ISP" ]] && CACHED_ISP="N/A"
    local country=$(echo "$ipinfo" | grep -o '"country"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    local city=$(echo "$ipinfo" | grep -o '"city"[[:space:]]*:[[:space:]]*"[^"]*"' | cut -d'"' -f4)
    CACHED_LOCATION="${country:-N/A} ${city:-}"
    mkdir -p "$CACHE_DIR"
    cat > "$CACHE_FILE" << EOF
CACHED_IPV4="$CACHED_IPV4"
CACHED_IPV6="$CACHED_IPV6"
CACHED_ISP="$CACHED_ISP"
CACHED_LOCATION="$CACHED_LOCATION"
EOF
    chmod 600 "$CACHE_FILE"
}
get_ip_location() {
    local ip="$1"
    if [[ "$ip" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|fe80:|::1|fc00:|fd00:) ]]; then
        echo "本地网络"
        return
    fi
    local result
    if command_exists timeout; then
        result=$(timeout 3 curl -s "http://ip-api.com/json/${ip}?lang=zh-CN&fields=status,country,regionName,city,isp" 2>/dev/null)
    else
        result=$(curl -s --max-time 3 "http://ip-api.com/json/${ip}?lang=zh-CN&fields=status,country,regionName,city,isp" 2>/dev/null)
    fi
    if [[ -n "$result" ]] && echo "$result" | grep -q '"status":"success"'; then
        local country=$(echo "$result" | grep -o '"country":"[^"]*"' | cut -d'"' -f4)
        local region=$(echo "$result" | grep -o '"regionName":"[^"]*"' | cut -d'"' -f4)
        local city=$(echo "$result" | grep -o '"city":"[^"]*"' | cut -d'"' -f4)
        local isp=$(echo "$result" | grep -o '"isp":"[^"]*"' | cut -d'"' -f4)
        local location=""
        [[ -n "$country" ]] && location="$country"
        [[ -n "$region" && "$region" != "$country" ]] && location="${location} ${region}"
        [[ -n "$city" && "$city" != "$region" ]] && location="${location} ${city}"
        [[ -n "$isp" ]] && location="${location} (${isp})"
        echo "${location:-未知}"
        return
    fi
    echo "查询失败"
}

show_dual_column_sysinfo() {
    load_cache || refresh_network_cache
    local hostname=$(cat /proc/sys/kernel/hostname 2>/dev/null || echo "unknown")
    local os_info=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2 | head -c 35)
    local kernel=$(uname -r | head -c 20)
    local arch=$(uname -m)
    local cpu_model=$(grep "model name" /proc/cpuinfo 2>/dev/null | head -1 | cut -d: -f2 | xargs | head -c 25)
    local cpu_cores=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo 2>/dev/null || echo "1")
    local cpu_freq=$(awk '/MHz/ {printf "%.1fGHz", $4/1000; exit}' /proc/cpuinfo 2>/dev/null || echo "N/A")

    # 使用 /proc/stat 计算 CPU 使用率（比 top -bn1 快 5-10 倍）
    local cpu_usage="0%"
    if [[ -f /proc/stat ]]; then
        local c1 c2
        c1=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5}' /proc/stat)
        sleep 0.2
        c2=$(awk '/^cpu /{print $2+$3+$4+$5+$6+$7+$8, $5}' /proc/stat)
        cpu_usage=$(awk -v a="$c1" -v b="$c2" 'BEGIN{
            split(a,x," "); split(b,y," ");
            dt=y[1]-x[1]; di=y[2]-x[2];
            if(dt>0) printf "%.0f%%", 100*(1-di/dt); else print "0%"}')
    fi
    local load_avg=$(awk '{printf "%.2f %.2f %.2f", $1, $2, $3}' /proc/loadavg 2>/dev/null)
    local tcp_conn=0 udp_conn=0
    if command -v ss >/dev/null 2>&1; then
        tcp_conn=$(ss -tn state established 2>/dev/null | tail -n +2 | wc -l)
        udp_conn=$(ss -un 2>/dev/null | tail -n +2 | wc -l)
    elif [[ -f /proc/net/tcp ]]; then
        tcp_conn=$(awk 'NR>1 && $4=="01"{n++}END{print n+0}' /proc/net/tcp 2>/dev/null)
        udp_conn=$(awk 'NR>1{n++}END{print n+0}' /proc/net/udp 2>/dev/null)
    fi
    local mem_info swap_info
    if command -v free >/dev/null 2>&1; then
        mem_info=$(free -m | awk '/^Mem:/ {printf "%d/%dM %.0f%%", $3, $2, ($2>0)?$3/$2*100:0}')
        swap_info=$(free -m | awk '/^Swap:/ {if($2>0) printf "%d/%dM %.0f%%", $3, $2, $3/$2*100; else print "未启用"}')
    else
        local mt=$(awk '/^MemTotal/{print int($2/1024)}' /proc/meminfo)
        local mf=$(awk '/^MemAvailable/{print int($2/1024)}' /proc/meminfo)
        local mu=$((mt - mf))
        mem_info="${mu}/${mt}M $(( mt>0 ? mu*100/mt : 0 ))%"
        swap_info="未启用"
    fi
    local disk_info=$(df -h / | awk 'NR==2 {printf "%s/%s %s", $3, $2, $5}')
    local main_if=$(ip route 2>/dev/null | awk '/default/{print $5; exit}')
    local rx_total="0B" tx_total="0B"
    if [[ -n "$main_if" ]]; then
        read -r rx_total tx_total <<< "$(awk -v iface="$main_if:" '
            function fmt(b) {
                if(b>=1073741824) return sprintf("%.2fG",b/1073741824)
                if(b>=1048576) return sprintf("%.0fM",b/1048576)
                if(b>=1024) return sprintf("%.0fK",b/1024)
                return sprintf("%dB",b)
            }
            $1==iface {print fmt($2), fmt($10)}
        ' /proc/net/dev 2>/dev/null)"
        rx_total=${rx_total:-0B}; tx_total=${tx_total:-0B}
    fi
    local tcp_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
    local qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "N/A")
    local uptime_str=$(awk '{d=int($1/86400);h=int($1%86400/3600);m=int($1%3600/60);
        if(d>0)printf "%d天%d时%d分",d,h,m;else if(h>0)printf "%d时%d分",h,m;else printf "%d分",m}' /proc/uptime)
    local sys_time=$(date "+%m-%d %H:%M")
    local timezone=$(timedatectl 2>/dev/null | awk '/Time zone/{print $3}' || echo "UTC")
    local ssh_port=$(grep -E "^Port\s" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    [[ -z "$ssh_port" ]] && ssh_port="22"
    local ufw_st="○"; command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active" && ufw_st="●"
    local f2b_st="○"; systemctl is-active fail2ban &>/dev/null && f2b_st="●"
    local nginx_st="○"; systemctl is-active nginx &>/dev/null && nginx_st="●"
    local docker_st="○"; systemctl is-active docker &>/dev/null && docker_st="●"
    local wg_st="○"; ip link show wg0 &>/dev/null && wg_st="●"
    local W=76  # 总宽度
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "主机:" "$hostname" "IPv4:" "$CACHED_IPV4"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "系统:" "${os_info:0:17}" "IPv6:" "${CACHED_IPV6:0:20}"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "内核:" "$kernel" "运营商:" "${CACHED_ISP:0:18}"
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "CPU:" "${cpu_model:0:17}" "内存:" "$mem_info"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "核心:" "${cpu_cores}核 @ $cpu_freq" "交换:" "$swap_info"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "负载:" "$load_avg" "硬盘:" "$disk_info"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "占用:" "$cpu_usage 连接:${tcp_conn}t/${udp_conn}u" "流量:" "↓${rx_total} ↑${tx_total}"
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "算法:" "$tcp_cc + $qdisc" "位置:" "${CACHED_LOCATION:0:18}"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "运行:" "$uptime_str" "时区:" "$timezone"
    printf " ${C_CYAN}%-18s${C_RESET}%-17s │ ${C_CYAN}%-8s${C_RESET}%s\n" \
        "SSH:" "端口 $ssh_port" "时间:" "$sys_time"
    printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
    printf " 服务: UFW[${C_GREEN}%s${C_RESET}] F2B[${C_GREEN}%s${C_RESET}] Nginx[${C_GREEN}%s${C_RESET}] Docker[${C_GREEN}%s${C_RESET}] WG[${C_GREEN}%s${C_RESET}]\n" \
        "$ufw_st" "$f2b_st" "$nginx_st" "$docker_st" "$wg_st"

    # 展示最近 3 条登录记录
    local login_count=0
    if command -v last >/dev/null 2>&1; then
        local login_lines
        login_lines=$(last -n 20 -a -w 2>/dev/null | grep -E "^[a-zA-Z]" | grep -v -E "wtmp begins|^reboot" | head -3)
        if [[ -n "$login_lines" ]]; then
            printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
            while IFS= read -r login_line; do
                [[ -z "$login_line" ]] && continue
                login_count=$((login_count + 1))
                local login_user=$(echo "$login_line" | awk '{print $1}')
                local login_ip=$(echo "$login_line" | awk '{print $NF}')
                local login_time=$(echo "$login_line" | awk '{print $4, $5, $6}')
                local login_display=""
                if [[ -n "$login_ip" && "$login_ip" =~ ^[0-9a-f.:]+$ ]]; then
                    local ip_loc=$(get_ip_location "$login_ip")
                    login_display="${login_user}@${login_ip} (${ip_loc}) ${login_time}"
                else
                    login_display="${login_user} ${login_time}"
                fi
                printf " ${C_CYAN}%-8s${C_RESET}%s\n" "登录${login_count}:" "${login_display:0:65}"
            done <<< "$login_lines"
        fi
    fi
    if [[ "$login_count" -eq 0 ]]; then
        printf "${C_DIM}%${W}s${C_RESET}\n" | tr ' ' '-'
        printf " ${C_CYAN}%-8s${C_RESET}%s\n" "登录:" "无记录"
    fi
}
