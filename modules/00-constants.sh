# modules/00-constants.sh - 全局常量、变量、平台检测
readonly VERSION="v14.0"
readonly SCRIPT_NAME="server-manage"
readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"
readonly CONFIG_FILE="/etc/${SCRIPT_NAME}.conf"
readonly CACHE_DIR="/var/cache/${SCRIPT_NAME}"
readonly CACHE_FILE="${CACHE_DIR}/sysinfo.cache"
readonly CACHE_TTL=300 
readonly CERT_HOOKS_DIR="/root/cert-hooks"
readonly WG_DEFAULT_PORT=50000
readonly BACKUP_LOCAL_DIR="/root/${SCRIPT_NAME}-backups"
readonly BACKUP_CONFIG_FILE="/etc/${SCRIPT_NAME}-backup.conf"
PLATFORM="debian"

detect_platform() {
    if [[ -f /etc/openwrt_release ]]; then
        PLATFORM="openwrt"
    elif [[ -f /etc/os-release ]]; then
        local os_id=$(grep '^ID=' /etc/os-release | cut -d= -f2 | tr -d '"')
        case "$os_id" in
            ubuntu|debian) PLATFORM="debian" ;;
            *) command -v opkg &>/dev/null && PLATFORM="openwrt" ;;
        esac
    elif command -v opkg &>/dev/null; then
        PLATFORM="openwrt"
    fi
}
detect_platform

feature_blocked() {
    echo -e "${C_YELLOW}[!] 功能不可用: $1${C_RESET}"
    echo -e "${C_YELLOW}    当前系统: OpenWrt (仅支持 Web/DNS/DDNS/BBR/基础信息)${C_RESET}"
    read -n 1 -s -r -p "按任意键继续..."
    echo ""
}

readonly C_RESET='\033[0m'
readonly C_RED='\033[0;31m'
readonly C_GREEN='\033[0;32m'
readonly C_YELLOW='\033[1;33m'
readonly C_BLUE='\033[0;34m'
readonly C_CYAN='\033[0;36m'
readonly C_GRAY='\033[0;90m'
readonly C_DIM='\033[2m'

CF_API_TOKEN=""
DOMAIN=""
EMAIL="your@mail.com"
CERT_PATH_PREFIX="/root/cert"
CONFIG_DIR="${CERT_PATH_PREFIX}/.managed_domains"
DEFAULT_SSH_PORT=22
SSHD_CONFIG="/etc/ssh/sshd_config"
FAIL2BAN_JAIL_LOCAL="/etc/fail2ban/jail.local"
DOCKER_PROXY_DIR="/etc/systemd/system/docker.service.d"
DOCKER_PROXY_CONF="${DOCKER_PROXY_DIR}/http-proxy.conf"

[[ -f "$CONFIG_FILE" ]] && source "$CONFIG_FILE"

CURRENT_SSH_PORT=""
APT_UPDATED=0

CACHED_IPV4=""
CACHED_IPV6=""
CACHED_ISP=""
CACHED_LOCATION=""
DDNS_CONFIG_DIR="/etc/ddns"
DDNS_LOG="/var/log/ddns.log"
SAAS_CONFIG_DIR="/etc/saas-cdn"
SAAS_PREFERRED_DOMAINS="saas.sin.fan cdn.anycast.eu.org cdn-all.xn--b6gac.eu.org www.freedidi.com"

