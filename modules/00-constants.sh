# modules/00-constants.sh - 全局常量、变量、平台检测
readonly VERSION="v14.5"
readonly SCRIPT_NAME="server-manage"
readonly CONFIG_FILE="/etc/${SCRIPT_NAME}.conf"
readonly CACHE_DIR="/var/cache/${SCRIPT_NAME}"
readonly CACHE_FILE="${CACHE_DIR}/sysinfo.cache"
readonly CACHE_TTL=300 
readonly CERT_HOOKS_DIR="/root/cert-hooks"
# 证书续签共享 cron（单条 certbot renew 覆盖所有证书，各证书 hook 存于其 renewal conf 的 renew_hook）
readonly CERT_RENEW_SHARED_CRON_TAG="CertRenewShared"
CERT_RENEW_SHARED_CRON_MINUTE="${CERT_RENEW_SHARED_CRON_MINUTE:-17}"
readonly WG_SHARED_DB_DIR="/etc/wireguard/db"
readonly WG_SHARED_DB_FILE="${WG_SHARED_DB_DIR}/wg-data.json"
readonly WG_SHARED_ROLE_FILE="/etc/wireguard/.role"
readonly WG_SHARED_ROUTE_STATE_FILE="${WG_SHARED_DB_DIR}/managed-routes.state"
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
REALITY_LINK_FILE_V4="${REALITY_CONFIG_DIR}/client-link-v4.txt"
REALITY_LINK_FILE_V6="${REALITY_CONFIG_DIR}/client-link-v6.txt"
REALITY_CLIENT_JSON_V4="${REALITY_CONFIG_DIR}/client-v4.json"
REALITY_CLIENT_JSON_V6="${REALITY_CONFIG_DIR}/client-v6.json"
REALITY_BACKUP_DIR="${REALITY_CONFIG_DIR}/backups"
REALITY_RELAY_DIR="${REALITY_CONFIG_DIR}/relays"
# CDN 链路（VLESS+WS+TLS 橙云 + 优选 IP）状态/产物。与 Reality 直连链路并存：
# Reality 仍绑 0.0.0.0:443 灰云直连；CDN 的 WS 入站只绑 127.0.0.1:<内部端口>，
# 由 nginx 在独立回源端口(REALITY_CDN_ORIGIN_PORT)做 TLS 终止 + 反代，CF 橙云回源。
REALITY_CDN_STATE_FILE="${REALITY_CONFIG_DIR}/cdn.conf"
REALITY_CDN_LINK_FILE="${REALITY_CONFIG_DIR}/cdn-link.txt"
REALITY_CDN_CLIENT_JSON="${REALITY_CONFIG_DIR}/cdn-client.json"
REALITY_CDN_ORIGIN_PORT="${REALITY_CDN_ORIGIN_PORT:-8443}"
# 443 共存模式（nginx stream + ssl_preread 分流）：443 由 nginx stream 独占，
# 按 SNI 分流——真站域名(白名单) → REALITY_WEB_INNER_PORT；default(借用SNI/未知/无SNI)
# → REALITY_COEXIST_INNER_PORT(sing-box reality 入站)。所有后端仅绑 127.0.0.1，外部不可见。
# reality 内部端口选 18443，明确避开 CDN 回源用的 8443（CF 橙云支持端口，不可改）。
REALITY_COEXIST_STATE_FILE="${REALITY_CONFIG_DIR}/coexist.conf"
REALITY_COEXIST_INNER_PORT="${REALITY_COEXIST_INNER_PORT:-18443}"
REALITY_WEB_INNER_PORT="${REALITY_WEB_INNER_PORT:-12443}"
REALITY_STREAM_ENABLED_DIR="/etc/nginx/stream-enabled"
REALITY_STREAM_CONF="${REALITY_STREAM_ENABLED_DIR}/reality-coexist.conf"
REALITY_SINGBOX_CONFIG="/etc/sing-box/config.json"
REALITY_REALM_CONFIG="/etc/realm/config.toml"
REALITY_PORT_MIN=20000
REALITY_PORT_MAX=60000
