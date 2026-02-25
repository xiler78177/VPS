#!/bin/bash
# server-manage 主入口
# 多文件模式：source 各功能模块

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# 按依赖顺序加载模块
source "$SCRIPT_DIR/modules/00-constants.sh"
source "$SCRIPT_DIR/modules/01-utils.sh"
source "$SCRIPT_DIR/modules/02-network.sh"
source "$SCRIPT_DIR/modules/03-sysinfo.sh"
source "$SCRIPT_DIR/modules/04-firewall.sh"
source "$SCRIPT_DIR/modules/05-fail2ban.sh"
source "$SCRIPT_DIR/modules/06-ssh.sh"
source "$SCRIPT_DIR/modules/07-system.sh"
source "$SCRIPT_DIR/modules/08-network-tools.sh"
source "$SCRIPT_DIR/modules/09-web.sh"
source "$SCRIPT_DIR/modules/10-docker.sh"
source "$SCRIPT_DIR/modules/11a-wireguard-netcheck.sh"
source "$SCRIPT_DIR/modules/11-wireguard.sh"
source "$SCRIPT_DIR/modules/11b-wireguard-udp2raw.sh"
source "$SCRIPT_DIR/modules/12-backup.sh"
source "$SCRIPT_DIR/modules/13-menus.sh"

main "$@"
