# modules/10-docker.sh - Docker 管理
docker_install() {
    print_title "Docker 安装"
    if command_exists docker; then
        print_warn "Docker 已安装。"
        docker --version
        pause; return
    fi
    print_info "正在安装 Docker..."
    update_apt_cache
    install_package "ca-certificates" "silent"
    install_package "curl" "silent"
    install_package "gnupg" "silent"
    local keyring_dir="/etc/apt/keyrings"
    mkdir -p "$keyring_dir"
    local docker_gpg="$keyring_dir/docker.gpg"
    local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    if [[ ! -f "$docker_gpg" ]]; then
        print_info "添加 Docker GPG 密钥..."
        # 根据实际系统选择正确的 GPG URL
        local gpg_os="${os_id}"
        [[ "$gpg_os" != "ubuntu" && "$gpg_os" != "debian" ]] && gpg_os="debian"
        if ! curl -fsSL "https://download.docker.com/linux/${gpg_os}/gpg" | gpg --dearmor -o "$docker_gpg" 2>/dev/null; then
            print_error "GPG 密钥下载失败。"
            pause; return
        fi
        chmod a+r "$docker_gpg"
    fi
    local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    local version_codename=$(grep 'VERSION_CODENAME' /etc/os-release | cut -d= -f2)
    if [[ -z "$version_codename" ]]; then
        version_codename=$(grep 'UBUNTU_CODENAME' /etc/os-release | cut -d= -f2)
    fi
    if [[ -z "$version_codename" ]]; then
        print_error "无法检测系统版本代号，Docker 源配置可能失败。"
        print_info "请手动安装 Docker: https://docs.docker.com/engine/install/"
        pause; return
    fi
    local docker_list="/etc/apt/sources.list.d/docker.list"
    if [[ ! -f "$docker_list" ]]; then
        print_info "添加 Docker 软件源..."
        echo "deb [arch=$(dpkg --print-architecture) signed-by=$docker_gpg] https://download.docker.com/linux/$os_id $version_codename stable" > "$docker_list"
    fi
    apt-get update -qq 2>/dev/null || true
    if apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1; then
        print_success "Docker 安装成功。"
        if is_systemd; then
            systemctl enable docker >/dev/null 2>&1 || true
            systemctl start docker || true
        fi
        docker --version
        log_action "Docker installed"
    else
        print_error "Docker 安装失败。"
    fi
    pause
}

docker_uninstall() {
    print_title "Docker 卸载"
    if ! command_exists docker; then
        print_warn "Docker 未安装。"
        pause; return
    fi
    echo -e "${C_RED}警告: 这将删除 Docker 及所有容器、镜像、卷！${C_RESET}"
    if ! confirm "确认卸载？"; then return; fi
    print_info "正在停止服务..."
    if is_systemd; then
        systemctl stop docker docker.socket containerd 2>/dev/null || true
        systemctl disable docker docker.socket containerd 2>/dev/null || true
    fi
    print_info "正在卸载软件包..."
    apt-get purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1 || true
    apt-get autoremove -y >/dev/null 2>&1 || true
    if confirm "是否删除所有 Docker 数据 (/var/lib/docker)?"; then
        rm -rf /var/lib/docker /var/lib/containerd
        print_success "数据已删除。"
    fi
    rm -f /etc/apt/sources.list.d/docker.list
    rm -f /etc/apt/keyrings/docker.gpg
    print_success "Docker 已卸载。"
    log_action "Docker uninstalled"
    pause
}

docker_compose_install() {
    print_title "Docker Compose 独立安装"
    if command_exists docker && docker compose version >/dev/null 2>&1; then
        print_warn "Docker Compose (Plugin) 已安装。"
        docker compose version
        pause; return
    fi
    if command_exists docker-compose; then
        print_warn "Docker Compose (Standalone) 已安装。"
        docker-compose --version
        pause; return
    fi
    print_info "正在安装 Docker Compose..."
    
    # 自动获取最新版本，失败时使用固定版本作为 fallback
    local compose_version
    compose_version=$(curl -s --max-time 10 https://api.github.com/repos/docker/compose/releases/latest 2>/dev/null | jq -r '.tag_name // empty' 2>/dev/null)
    [[ -z "$compose_version" ]] && compose_version="v2.24.5"
    print_info "版本: $compose_version"
    local compose_url="https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-linux-$(uname -m)"
    if curl -L "$compose_url" -o /usr/local/bin/docker-compose 2>/dev/null; then
        chmod +x /usr/local/bin/docker-compose
        print_success "Docker Compose 安装成功。"
        docker-compose --version
        log_action "Docker Compose installed"
    else
        print_error "下载失败。"
    fi
    pause
}

docker_proxy_config() {
    print_title "Docker 代理配置"
    if ! command_exists docker; then
        print_error "Docker 未安装。"
        pause; return
    fi
    echo "1. 配置 Docker 守护进程代理 (拉取镜像用)
2. 清除代理配置
0. 返回"
    read -e -r -p "选择: " c
    case $c in
        1)
            read -e -r -p "代理地址 (如 http://proxy.example.com:3128): " proxy
            if [[ -z "$proxy" ]]; then return; fi
            # 校验代理地址格式，防止注入 systemd 指令
            if [[ ! "$proxy" =~ ^https?://[a-zA-Z0-9._-]+(:[0-9]+)?(/.*)?$ ]] && \
               [[ ! "$proxy" =~ ^socks5?://[a-zA-Z0-9._-]+(:[0-9]+)?$ ]]; then
                print_error "代理地址格式无效 (应为 http(s)://host:port 或 socks5://host:port)"
                pause; return
            fi
            mkdir -p "$DOCKER_PROXY_DIR"
            local proxy_conf="[Service]
Environment=\"HTTP_PROXY=$proxy\"
Environment=\"HTTPS_PROXY=$proxy\"
Environment=\"NO_PROXY=localhost,127.0.0.1,::1\"
Environment=\"http_proxy=$proxy\"
Environment=\"https_proxy=$proxy\"
Environment=\"no_proxy=localhost,127.0.0.1,::1\""
            write_file_atomic "$DOCKER_PROXY_CONF" "$proxy_conf"
            if is_systemd; then
                systemctl daemon-reload || true
                systemctl restart docker || true
            fi
            print_success "Docker 代理已配置。"
            log_action "Docker proxy configured: $proxy"
            ;;
        2)
            rm -f "$DOCKER_PROXY_CONF"
            if is_systemd; then
                systemctl daemon-reload || true
                systemctl restart docker || true
            fi
            print_success "代理配置已清除。"
            log_action "Docker proxy removed"
            ;;
        0|q) return ;;
    esac
    pause
}

docker_images_manage() {
    print_title "Docker 镜像管理"
    if ! command_exists docker; then
        print_error "Docker 未安装。"
        pause; return
    fi
    echo "1. 列出所有镜像
2. 删除未使用的镜像
3. 删除所有镜像 (危险)
0. 返回"
    read -e -r -p "选择: " c
    case $c in
        1)
            docker images
            ;;
        2)
            if confirm "删除未使用的镜像？"; then
                docker image prune -a -f
                print_success "清理完成。"
                log_action "Docker unused images pruned"
            fi
            ;;
        3)
            if confirm "删除所有镜像？这将影响所有容器！"; then
                local all_images=$(docker images -q)
                if [[ -n "$all_images" ]]; then
                    docker rmi -f $all_images
                    print_success "所有镜像已删除。"
                    log_action "Docker all images removed"
                else
                    print_warn "没有镜像可删除。"
                fi
            fi
            ;;
        0|q) return ;;
    esac
    pause
}

docker_containers_manage() {
    if ! command_exists docker; then
        print_error "Docker 未安装。"; pause; return
    fi
    while true; do
        print_title "Docker 容器管理"
        # Build container table
        local containers=()
        local fmt='{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'
        while IFS=$'\t' read -r id name image status ports; do
            [[ -z "$id" ]] && continue
            containers+=("$id|$name|$image|$status|$ports")
        done < <(docker ps -a --format "$fmt" 2>/dev/null)
        if [[ ${#containers[@]} -eq 0 ]]; then
            print_warn "没有容器。"
        else
            printf "  ${C_CYAN}%-3s %-4s %-20s %-25s %-30s${C_RESET}\n" "#" "状态" "名称" "镜像" "端口"
            local idx=1
            for entry in "${containers[@]}"; do
                IFS='|' read -r id name image status ports <<< "$entry"
                local icon="${C_RED}○${C_RESET}"
                [[ "$status" == Up* ]] && icon="${C_GREEN}●${C_RESET}"
                [[ ${#image} -gt 25 ]] && image="${image:0:22}..."
                [[ ${#ports} -gt 30 ]] && ports="${ports:0:27}..."
                printf "  %-3s %b  %-20s %-25s %-30s\n" "$idx" "$icon" "$name" "$image" "$ports"
                ((idx++)) || true
            done
        fi
        local running_ids=$(docker ps -q 2>/dev/null)
        if [[ -n "$running_ids" ]]; then
            echo ""
            echo -e "${C_CYAN}[资源占用]${C_RESET}"
            docker stats --no-stream --format "  {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null | column -t -s $'\t'
        fi
        echo ""
        echo -e "${C_CYAN}操作:${C_RESET} 1.启动 2.停止 3.重启 4.日志 5.删除  6.停止所有 7.删除所有  0.返回"
        read -e -r -p "操作 [如 '3 2' 表示重启第2个容器]: " action_input
        [[ -z "$action_input" || "$action_input" == "0" || "$action_input" == "q" ]] && break
        local action=$(echo "$action_input" | awk '{print $1}')
        local target_idx=$(echo "$action_input" | awk '{print $2}')
        if [[ "$action" == "6" ]]; then
            if confirm "停止所有容器?"; then
                local rq=$(docker ps -q)
                [[ -n "$rq" ]] && docker stop $rq && print_success "已停止" || print_warn "无运行中容器"
                log_action "Docker all containers stopped"
            fi
            pause; continue
        fi
        if [[ "$action" == "7" ]]; then
            if confirm "删除所有容器? (危险)"; then
                local aq=$(docker ps -aq)
                [[ -n "$aq" ]] && docker rm -f $aq && print_success "已删除" || print_warn "无容器"
                log_action "Docker all containers removed"
            fi
            pause; continue
        fi
        if [[ -z "$target_idx" || ! "$target_idx" =~ ^[0-9]+$ ]]; then
            print_error "格式: 操作编号 容器序号 (如 '3 2')"; pause; continue
        fi
        if [[ "$target_idx" -lt 1 || "$target_idx" -gt ${#containers[@]} ]]; then
            print_error "容器序号超出范围"; pause; continue
        fi
        local target_entry="${containers[$((target_idx-1))]}"
        local target_id=$(echo "$target_entry" | cut -d'|' -f1)
        local target_name=$(echo "$target_entry" | cut -d'|' -f2)
        case $action in
            1) docker start "$target_id" && print_success "已启动: $target_name" || print_error "启动失败" ;;
            2) docker stop "$target_id" && print_success "已停止: $target_name" || print_error "停止失败" ;;
            3) docker restart "$target_id" && print_success "已重启: $target_name" || print_error "重启失败" ;;
            4) print_info "按 Ctrl+C 退出日志..."; docker logs --tail 50 -f "$target_id" ;;
            5)
                if confirm "确认删除容器 $target_name?"; then
                    docker rm -f "$target_id" && print_success "已删除: $target_name" || print_error "删除失败"
                    log_action "Docker container removed: $target_name"
                fi
                ;;
            *) print_error "无效操作" ;;
        esac
        pause
    done
}

menu_docker() {
    fix_terminal
    while true; do
        print_title "Docker 管理"
        if command_exists docker; then
            local dver=$(docker --version 2>/dev/null | grep -oP '[\d.]+' | head -1)
            local cver=$(docker compose version 2>/dev/null | grep -oP '[\d.]+' | head -1)
            local running=$(docker ps -q 2>/dev/null | wc -l)
            local total=$(docker ps -aq 2>/dev/null | wc -l)
            echo -e "${C_GREEN}Docker $dver${C_RESET}${cver:+ | Compose $cver} | 容器: ${running}/${total} 运行中"
        else
            echo -e "${C_YELLOW}Docker 未安装${C_RESET}"
        fi
        echo "1. 安装 Docker
2. 卸载 Docker
3. 安装 Docker Compose
4. 配置 Docker 代理
5. 镜像管理
6. 容器管理 (一览式)
7. 系统清理 (prune)
0. 返回主菜单
"
        read -e -r -p "请选择: " c
        case $c in
            1) docker_install ;;
            2) docker_uninstall ;;
            3) docker_compose_install ;;
            4) docker_proxy_config ;;
            5) docker_images_manage ;;
            6) docker_containers_manage ;;
            7)
                if command_exists docker; then
                    if confirm "清理未使用的容器、网络、镜像、构建缓存？"; then
                        docker system prune -a -f --volumes
                        print_success "清理完成。"
                        log_action "Docker system pruned"
                    fi
                else
                    print_error "Docker 未安装。"
                fi
                pause
                ;;
            0|q) break ;;
            *) print_error "无效选项" ;;
        esac
    done
}
