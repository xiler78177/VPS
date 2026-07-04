# modules/10-docker.sh - Docker 管理
docker_remove_conflicting_packages() {
    # Docker 官方 Debian/Ubuntu 安装文档要求先移除这些可能冲突的发行版包。
    # 失败不阻断：部分精简系统未安装 apt 包数据库或包名不存在。
    local conflicts=(docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc)
    print_info "移除可能冲突的旧 Docker/Compose 包..."
    apt-get remove -y "${conflicts[@]}" >/dev/null 2>&1 || true
}

_docker_keyring_path() {
    printf '%s' "${DOCKER_KEYRING_FILE:-/etc/apt/keyrings/docker.gpg}"
}

_docker_source_list_path() {
    printf '%s' "${DOCKER_SOURCE_LIST_FILE:-/etc/apt/sources.list.d/docker.list}"
}

_docker_compose_bin_path() {
    printf '%s' "${DOCKER_COMPOSE_BIN:-/usr/local/bin/docker-compose}"
}

_docker_render_apt_source() {
    local arch="$1" docker_gpg="$2" docker_repo_os="$3" version_codename="$4"
    printf 'deb [arch=%s signed-by=%s] https://download.docker.com/linux/%s %s stable\n' \
        "$arch" "$docker_gpg" "$docker_repo_os" "$version_codename"
}

_docker_install_keyring() {
    local docker_repo_os="$1" docker_gpg="$2" dir tmp_armored tmp_gpg
    [[ "$docker_gpg" == /* ]] || return 1
    dir="$(dirname "$docker_gpg")"
    mkdir -p "$dir" || return 1
    tmp_armored=$(mktemp "${dir}/.tmp.server-manage.docker-gpg.asc.XXXXXX") || return 1
    _tmp_register "$tmp_armored"
    tmp_gpg=$(mktemp "${dir}/.tmp.server-manage.docker-gpg.XXXXXX") || {
        rm -f -- "$tmp_armored" 2>/dev/null || true
        _tmp_unregister "$tmp_armored"
        return 1
    }
    _tmp_register "$tmp_gpg"
    if curl -fsSL "https://download.docker.com/linux/${docker_repo_os}/gpg" -o "$tmp_armored" 2>/dev/null \
        && gpg --dearmor < "$tmp_armored" > "$tmp_gpg" 2>/dev/null; then
        chmod 0644 "$tmp_gpg" 2>/dev/null || true
        chown root:root "$tmp_gpg" 2>/dev/null || true
        if mv "$tmp_gpg" "$docker_gpg"; then
            rm -f -- "$tmp_armored" 2>/dev/null || true
            _tmp_unregister "$tmp_armored"
            _tmp_unregister "$tmp_gpg"
            return 0
        fi
    fi
    rm -f -- "$tmp_armored" "$tmp_gpg" 2>/dev/null || true
    _tmp_unregister "$tmp_armored"
    _tmp_unregister "$tmp_gpg"
    return 1
}

_docker_write_apt_source() {
    local docker_list="$1" arch="$2" docker_gpg="$3" docker_repo_os="$4" version_codename="$5" content
    [[ "$docker_list" == /* && "$docker_gpg" == /* ]] || return 1
    content="$(_docker_render_apt_source "$arch" "$docker_gpg" "$docker_repo_os" "$version_codename")"
    write_file_atomic "$docker_list" "$content" || return 1
    chmod 0644 "$docker_list" 2>/dev/null || true
}

docker_install() {
    print_title "Docker 安装"
    if command_exists docker; then
        print_warn "Docker 已安装。"
        docker --version
        pause; return
    fi
    print_info "正在安装 Docker..."
    update_apt_cache
    # 官方冲突包列表：docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc
    docker_remove_conflicting_packages
    install_package "ca-certificates" "silent"
    install_package "curl" "silent"
    install_package "gnupg" "silent"
    local docker_gpg="$(_docker_keyring_path)"
    local keyring_dir
    keyring_dir="$(dirname "$docker_gpg")"
    if ! mkdir -p "$keyring_dir"; then
        print_error "Docker keyring 目录创建失败。"
        pause; return 1
    fi
    local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
    local docker_repo_os="${os_id}"
    [[ "$docker_repo_os" != "ubuntu" && "$docker_repo_os" != "debian" ]] && docker_repo_os="debian"
    if [[ ! -f "$docker_gpg" ]]; then
        print_info "添加 Docker GPG 密钥..."
        # 根据实际系统选择正确的官方仓库 OS；非 Debian/Ubuntu 系回退到 debian 时，
        # GPG URL 与 apt source 必须保持一致。
        if ! _docker_install_keyring "$docker_repo_os" "$docker_gpg"; then
            print_error "GPG 密钥下载失败。"
            pause; return 1
        fi
    fi
    local version_codename=$(grep 'VERSION_CODENAME' /etc/os-release | cut -d= -f2)
    if [[ -z "$version_codename" ]]; then
        version_codename=$(grep 'UBUNTU_CODENAME' /etc/os-release | cut -d= -f2)
    fi
    if [[ -z "$version_codename" ]]; then
        print_error "无法检测系统版本代号，Docker 源配置可能失败。"
        print_info "请手动安装 Docker: https://docs.docker.com/engine/install/"
        pause; return 1
    fi
    local docker_list="$(_docker_source_list_path)"
    if [[ ! -f "$docker_list" ]]; then
        print_info "添加 Docker 软件源..."
        if ! _docker_write_apt_source "$docker_list" "$(dpkg --print-architecture)" "$docker_gpg" "$docker_repo_os" "$version_codename"; then
            print_error "Docker 软件源写入失败。"
            pause; return 1
        fi
    fi
    if ! apt-get update -qq >/dev/null 2>&1; then
        print_error "Docker 软件源更新失败。"
        pause; return 1
    fi
    if apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null 2>&1; then
        if is_systemd; then
            if ! systemctl enable docker >/dev/null 2>&1 || ! systemctl start docker >/dev/null 2>&1; then
                print_error "Docker 已安装但服务启动失败。"
                pause; return 1
            fi
        fi
        print_success "Docker 安装成功。"
        docker --version
        log_action "Docker installed"
    else
        print_error "Docker 安装失败。"
        pause; return 1
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
    rm -f "$DOCKER_PROXY_CONF"
    rm -rf "$DOCKER_PROXY_DIR"
    if confirm "是否删除所有 Docker 数据 (/var/lib/docker)?"; then
        rm -rf /var/lib/docker /var/lib/containerd /etc/docker
        print_success "数据已删除。"
    else
        rm -rf /etc/docker
    fi
    rm -f /etc/apt/sources.list.d/docker.list
    rm -f /etc/apt/keyrings/docker.gpg
    hash -r 2>/dev/null || true
    print_success "Docker 已卸载。"
    log_action "Docker uninstalled"
    pause
}

_docker_compose_standalone_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64" ;;
        aarch64|arm64) echo "aarch64" ;;
        armv7l|armv7*) echo "armv7" ;;
        *) uname -m ;;
    esac
}

_docker_compose_install_standalone() {
    local compose_url="$1" target_bin="$(_docker_compose_bin_path)" target_dir tmp_bin tmp_sha hash
    [[ "$target_bin" == /* ]] || return 1
    target_dir="$(dirname "$target_bin")"
    mkdir -p "$target_dir" || return 1
    tmp_bin=$(mktemp "${target_dir}/.tmp.server-manage.docker-compose.XXXXXX") || return 1
    _tmp_register "$tmp_bin"
    tmp_sha=$(mktemp "${target_dir}/.tmp.server-manage.docker-compose.sha256.XXXXXX") || {
        rm -f -- "$tmp_bin" 2>/dev/null || true
        _tmp_unregister "$tmp_bin"
        return 1
    }
    _tmp_register "$tmp_sha"
    if curl -fL --retry 3 "$compose_url" -o "$tmp_bin" 2>/dev/null \
        && curl -fL --retry 3 "${compose_url}.sha256" -o "$tmp_sha" 2>/dev/null \
        && hash=$(awk '{print $1; exit}' "$tmp_sha") \
        && [[ "$hash" =~ ^[a-fA-F0-9]{64}$ ]] \
        && printf '%s  %s\n' "$hash" "$tmp_bin" | sha256sum -c - >/dev/null; then
        chmod 0755 "$tmp_bin" 2>/dev/null || true
        chown root:root "$tmp_bin" 2>/dev/null || true
        if mv "$tmp_bin" "$target_bin"; then
            rm -f -- "$tmp_sha" 2>/dev/null || true
            _tmp_unregister "$tmp_bin"
            _tmp_unregister "$tmp_sha"
            return 0
        fi
    fi
    rm -f -- "$tmp_bin" "$tmp_sha" 2>/dev/null || true
    _tmp_unregister "$tmp_bin"
    _tmp_unregister "$tmp_sha"
    return 1
}

_docker_systemd_reload_restart() {
    is_systemd || return 0
    systemctl daemon-reload >/dev/null || return 1
    systemctl restart docker >/dev/null || return 1
}

_docker_restore_proxy_conf() {
    local backup="$1" had_old="$2"
    if [[ "$had_old" -eq 1 && -f "$backup" ]]; then
        mkdir -p "$DOCKER_PROXY_DIR" 2>/dev/null || true
        cp -a "$backup" "$DOCKER_PROXY_CONF" 2>/dev/null || true
    else
        rm -f "$DOCKER_PROXY_CONF" 2>/dev/null || true
    fi
}

_docker_apply_proxy_conf() {
    local proxy_conf="$1" backup="" had_old=0
    mkdir -p "$DOCKER_PROXY_DIR" || return 1
    if [[ -f "$DOCKER_PROXY_CONF" ]]; then
        backup=$(mktemp "${DOCKER_PROXY_DIR}/.http-proxy.conf.bak.XXXXXX") || return 1
        cp -a "$DOCKER_PROXY_CONF" "$backup" || { rm -f "$backup"; return 1; }
        had_old=1
    fi
    if ! write_file_atomic "$DOCKER_PROXY_CONF" "$proxy_conf"; then
        rm -f "$backup" 2>/dev/null || true
        return 1
    fi
    if ! _docker_systemd_reload_restart; then
        _docker_restore_proxy_conf "$backup" "$had_old"
        _docker_systemd_reload_restart >/dev/null 2>&1 || true
        rm -f "$backup" 2>/dev/null || true
        return 1
    fi
    rm -f "$backup" 2>/dev/null || true
    return 0
}

_docker_clear_proxy_conf() {
    local backup="" had_old=0
    if [[ -f "$DOCKER_PROXY_CONF" ]]; then
        mkdir -p "$DOCKER_PROXY_DIR" || return 1
        backup=$(mktemp "${DOCKER_PROXY_DIR}/.http-proxy.conf.bak.XXXXXX") || return 1
        cp -a "$DOCKER_PROXY_CONF" "$backup" || { rm -f "$backup"; return 1; }
        had_old=1
    fi
    rm -f "$DOCKER_PROXY_CONF" || { rm -f "$backup" 2>/dev/null || true; return 1; }
    if ! _docker_systemd_reload_restart; then
        _docker_restore_proxy_conf "$backup" "$had_old"
        _docker_systemd_reload_restart >/dev/null 2>&1 || true
        rm -f "$backup" 2>/dev/null || true
        return 1
    fi
    rm -f "$backup" 2>/dev/null || true
    return 0
}

docker_compose_install() {
    print_title "Docker Compose 安装"
    if command_exists docker && docker compose version >/dev/null 2>&1; then
        print_warn "Docker Compose (Plugin) 已安装。"
        docker compose version
        pause; return
    fi
    if command_exists docker-compose && ! command_exists docker; then
        print_warn "Docker Compose (Standalone) 已安装。"
        docker-compose --version
        pause; return
    fi
    if command_exists docker-compose; then
        print_warn "检测到旧 standalone docker-compose，但当前官方推荐 Compose Plugin；将优先安装 plugin。"
    fi

    print_info "正在安装 Docker Compose Plugin..."
    update_apt_cache
    if apt-get install -y docker-compose-plugin >/dev/null 2>&1 && command_exists docker && docker compose version >/dev/null 2>&1; then
        print_success "Docker Compose Plugin 安装成功。"
        docker compose version
        log_action "Docker Compose plugin installed"
        pause; return
    fi

    print_warn "Compose Plugin 安装失败，尝试 standalone fallback。"
    
    # 自动获取最新版本，失败时使用固定版本作为 fallback
    local compose_version
    if command_exists jq; then
        compose_version=$(curl -s --max-time 10 https://api.github.com/repos/docker/compose/releases/latest 2>/dev/null | jq -r '.tag_name // empty' 2>/dev/null)
    else
        compose_version=$(curl -s --max-time 10 https://api.github.com/repos/docker/compose/releases/latest 2>/dev/null | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | cut -d'"' -f4)
    fi
    [[ -z "$compose_version" ]] && compose_version="v2.24.5"
    print_info "版本: $compose_version"
    local compose_arch
    compose_arch=$(_docker_compose_standalone_arch)
    local compose_url="https://github.com/docker/compose/releases/download/${compose_version}/docker-compose-linux-${compose_arch}"
    if _docker_compose_install_standalone "$compose_url"; then
        print_success "Docker Compose Standalone 安装成功。"
        docker-compose --version
        log_action "Docker Compose standalone installed"
    else
        print_error "下载失败。"
        pause; return 1
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
            local proxy_conf="[Service]
Environment=\"HTTP_PROXY=$proxy\"
Environment=\"HTTPS_PROXY=$proxy\"
Environment=\"NO_PROXY=localhost,127.0.0.1,::1\"
Environment=\"http_proxy=$proxy\"
Environment=\"https_proxy=$proxy\"
Environment=\"no_proxy=localhost,127.0.0.1,::1\""
            if ! _docker_apply_proxy_conf "$proxy_conf"; then
                print_error "Docker 代理配置失败，已回滚。"
                pause; return 1
            fi
            print_success "Docker 代理已配置。"
            log_action "Docker proxy configured: $proxy"
            ;;
        2)
            if ! _docker_clear_proxy_conf; then
                print_error "代理配置清除失败，已回滚。"
                pause; return 1
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
                if docker image prune -a -f; then
                    print_success "清理完成。"
                    log_action "Docker unused images pruned"
                else
                    print_error "镜像清理失败。"
                    pause; return 1
                fi
            fi
            ;;
        3)
            if confirm "删除所有镜像？这将影响所有容器！"; then
                local all_images=$(docker images -q)
                if [[ -n "$all_images" ]]; then
                    if docker rmi -f $all_images; then
                        print_success "所有镜像已删除。"
                        log_action "Docker all images removed"
                    else
                        print_error "镜像删除失败。"
                        pause; return 1
                    fi
                else
                    print_warn "没有镜像可删除。"
                fi
            fi
            ;;
        0|q) return ;;
    esac
    pause
}

docker_print_stats_table() {
    local stats_output=""
    stats_output=$(docker stats --no-stream --format "{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null || true)
    [[ -z "$stats_output" ]] && { print_warn "暂无资源占用数据"; return; }

    if command_exists column; then
        printf '%s\n' "$stats_output" | column -t -s $'\t'
        return
    fi

    printf "  %-24s %-10s %s\n" "名称" "CPU" "内存"
    while IFS=$'\t' read -r name cpu mem; do
        [[ -z "$name" ]] && continue
        printf "  %-24s %-10s %s\n" "$name" "$cpu" "$mem"
    done <<< "$stats_output"
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
            docker_print_stats_table
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
                if [[ -z "$rq" ]]; then
                    print_warn "无运行中容器"
                elif docker stop $rq >/dev/null; then
                    print_success "已停止"
                    log_action "Docker all containers stopped"
                else
                    print_error "停止失败"
                fi
            fi
            pause; continue
        fi
        if [[ "$action" == "7" ]]; then
            if confirm "删除所有容器? (危险)"; then
                local aq=$(docker ps -aq)
                if [[ -z "$aq" ]]; then
                    print_warn "无容器"
                elif docker rm -f $aq >/dev/null; then
                    print_success "已删除"
                    log_action "Docker all containers removed"
                else
                    print_error "删除失败"
                fi
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
            4)
                print_info "按 Ctrl+C 退出日志并返回菜单..."
                trap - INT
                docker logs --tail 50 -f "$target_id" || true
                trap 'handle_interrupt' INT
                ;;
            5)
                if confirm "确认删除容器 $target_name?"; then
                    if docker rm -f "$target_id"; then
                        print_success "已删除: $target_name"
                        log_action "Docker container removed: $target_name"
                    else
                        print_error "删除失败"
                    fi
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
                        if docker system prune -a -f --volumes; then
                            print_success "清理完成。"
                            log_action "Docker system pruned"
                        else
                            print_error "清理失败。"
                        fi
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
