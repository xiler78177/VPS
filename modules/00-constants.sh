# modules/00-constants.sh - 全局常量、变量、平台检测
readonly VERSION="v14.4"
readonly SCRIPT_NAME="server-manage"
readonly CONFIG_FILE="/etc/${SCRIPT_NAME}.conf"
readonly CACHE_DIR="/var/cache/${SCRIPT_NAME}"
readonly CACHE_FILE="${CACHE_DIR}/sysinfo.cache"
readonly CACHE_TTL=300 
readonly CERT_HOOKS_DIR="/root/cert-hooks"
readonly WG_SHARED_DB_DIR="/etc/wireguard/db"
readonly WG_SHARED_DB_FILE="${WG_SHARED_DB_DIR}/wg-data.json"
readonly WG_SHARED_ROLE_FILE="/etc/wireguard/.role"
readonly WG_DEFAULT_PORT=50000
readonly WG_MTU_DIRECT=1420
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

if [[ "$PLATFORM" == "openwrt" ]]; then
    readonly LOG_FILE="/root/.server-manage/log/${SCRIPT_NAME}.log"
else
    readonly LOG_FILE="/var/log/${SCRIPT_NAME}.log"
fi

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

# 注意：$CONFIG_FILE 的安全加载在 01-utils.sh 末尾完成（需依赖 validate_conf_file）

CURRENT_SSH_PORT=""
CURRENT_SSH_PORTS=""
APT_UPDATED=0

CACHED_IPV4=""
CACHED_IPV6=""
CACHED_ISP=""
CACHED_LOCATION=""
DDNS_CONFIG_DIR="/etc/ddns"
DDNS_LOG="/var/log/ddns.log"
DDNS_UPDATE_SCRIPT="${DDNS_UPDATE_SCRIPT:-/usr/local/bin/ddns-update.sh}"
SAAS_CONFIG_DIR="/etc/saas-cdn"
SAAS_PREFERRED_DOMAINS="saas.sin.fan cdn.anycast.eu.org cdn-all.xn--b6gac.eu.org www.freedidi.com"
REALITY_CONFIG_DIR="/etc/server-manage/reality"
REALITY_STATE_FILE="${REALITY_CONFIG_DIR}/state.conf"
REALITY_LINK_FILE="${REALITY_CONFIG_DIR}/client-link.txt"
REALITY_CLIENT_JSON="${REALITY_CONFIG_DIR}/client.json"
REALITY_BACKUP_DIR="${REALITY_CONFIG_DIR}/backups"
REALITY_RELAY_DIR="${REALITY_CONFIG_DIR}/relays"
REALITY_SINGBOX_CONFIG="/etc/sing-box/config.json"
REALITY_REALM_CONFIG="/etc/realm/config.toml"
REALITY_PORT_MIN=20000
REALITY_PORT_MAX=60000
