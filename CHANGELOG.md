# Changelog

本项目所有重要变更记录于此。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

### Added
- **Reality 节点新增「加挂 CDN 链路」（CF 橙云 + 优选 IP，治晚高峰）**：在不动现有 Reality 直连链路（灰云）的前提下，为节点并存一条 **VLESS+WS+TLS** 橙云链路，把「国内→落地 IP」被运营商干扰的那一跳换成「国内→CF 优选边缘→CF 骨干→回源」。Reality 菜单新增「10. 加挂 CDN 链路 / 11. 卸载 CDN 链路」，对应 CLI `cdn-install` / `cdn-uninstall`。
  - **合并渲染（关键约束）**：CDN 的 VLESS-WS 入站作为额外 inbound **合并进 `reality_render_singbox_config` 的每条渲染路径**（读独立 CDN state），而非事后追加——确保 rotate UUID / rotate key / 改名 / 重装等任何触发整体重渲染的操作都不会把 WS 入站冲掉。split 双节点模式下同样并存。
  - **443 冲突处理**：Reality 仍独占 `0.0.0.0:443` 灰云直连；CDN 回源 nginx 监听独立端口（默认 `8443`，`REALITY_CDN_ORIGIN_PORT`），并自动建一条 **CF Origin Rule** 把 CDN 域名的回源端口改写到该端口。WS 入站只绑 `127.0.0.1:<随机内部端口>`（明文），由 nginx 做 TLS 终止 + 隐秘 path 反代，其余路径返回 444。
  - **证书/DNS**：复用 certbot **DNS-01**（橙云后面 HTTP-01 会被拦）签发 `cdn.<域名>` 证书并配置续签 hook；CF DNS 同步为**橙云 A/AAAA**（proxied=true）。
  - **优选 IP 自动化（国内机侧脚本，不进 v4-built.sh）**：新增 `scripts/cdn-preferip/` —— **B** `preferip-collect.sh` 封装 [XIU2/CloudflareSpeedTest](https://github.com/XIU2/CloudflareSpeedTest) 在国内机优选 CF 边缘 IP（必须国内侧跑，海外结果作废；无结果不写空值）；**C** `preferip-push.sh` 经公网 https + secret 前缀 `PATCH /api/sub/:name` 把优选 IP 刷进一条 **sub-store 专用 local 订阅**的 server 字段（host/sni 保留真实 CDN 域名，CF 靠 Host 头回源；绝不碰用户现有订阅）；`preferip-cron.sh` 串联两者供国内机 cron 调用。客户端订阅该专用订阅，刷新即换 IP。
  - 新增针对最高风险点的回归断言（`tests/reality_multi_relay_test.sh` T9）：装 CDN 后含 `vless-cdn-ws` 入站且 rotate key 重渲后仍存活、与 Reality 入站并存（含 split）、卸载后干净移除；合并配置经 `sing-box check` 校验通过。
- **优选脚本支持多节点（一份 `nodes.txt` 管 N 台 VPS）**：`scripts/cdn-preferip/` 重构为读 `nodes.txt`（每行「区域备注\|vless链接」），新增 `lib.sh:rewrite_vless` 把每条链接的 server 换成当天优选 IP、备注换成指定区域名（host/sni/uuid/path 全保留）。**优选 IP 所有节点共用**——它优化的是「客户端→CF 边缘」那一跳，对所有落地机完全相同，故 N 台 VPS 只需 1 份脚本 + 1 个 cron，加机器 = 往 `nodes.txt` 粘一行链接。同时修复 `urlencode` 对中文按字节编码（原按 Unicode 码点导致备注乱码）；新增 `运维手册.md` 与 `nodes.txt.example`。

### Fixed
- **[P1] CDN 回源 nginx 启用 HTTP/2 致 WebSocket 握手 400（客户端连不上）**：`reality_cdn_render_nginx_conf` 原经 `_nginx_tls_http2_block` 渲染出 `listen <port> ssl http2;`。WebSocket 依赖 HTTP/1.1 的 `Upgrade` 机制，与 HTTP/2 不兼容，CF 回源协商 h2 时 WS 握手被 nginx 拒为 400，导致客户端（OpenClash/NekoBox 等）无法建立 VLESS+WS 连接。修复：CDN 回源站改用纯 `listen <port> ssl;`（不接 http2），WS 反代回到 HTTP/1.1。web 模块共用的 `_nginx_tls_http2_block`（普通 HTTPS 反代）不受影响。
- **[P1] IPv6-only + WARP 落地机误建 A 记录致 CDN 回源超时 20s**：IPv6-only 机若装了 WARP，`get_public_ipv4`（`curl -4` 走 WARP 出口）会探到 WARP 的 IPv4（如 `104.28.x`），而 `reality_detect_ips` 只校验 IPv6、不校验 IPv4，于是 `reality_cdn_sync_dns_orange` 据此建出一条 A 记录。但本机网卡并无真实公网 IPv4，CF 回源优先尝试该 A 记录会连超时（约 20s）才回落 AAAA，WS 12s 超时下客户端不可用。修复：新增 `reality_has_local_public_ipv4`（`ip -4 addr show scope global` 校验，排除私有/CGNAT/WARP `172.16.0.x`/链路本地），`reality_detect_ips` 在本机无真实公网 IPv4 时清空 `REALITY_IPV4`，只建 AAAA、IPv6 回源（0.4s）。
- **[P1] 加挂 CDN 成功后误删 certbot 续签凭据致证书到期无法续签**：`reality_cdn_install` 末尾无条件 `rm -f "$cf_cred"` 删除了 `/root/.cloudflare-<域名>.ini`，而该文件正是 certbot renewal conf 的 `dns_cloudflare_credentials` 指向、DNS-01 自动续签长期依赖。删除后证书到期续签会失败、CDN 回源 TLS(Full strict) 中断。修复：成功分支不再删凭据（已 chmod 600 保留），仅证书签发失败分支才清理。
- **[P1] split 双节点落地机无法再叠加 Realm 中转线路**：split（IPv4+IPv6 双节点）落地安装会把 `REALITY_LISTEN_HOST` 持久化为哨兵值 `"split"`（真正的 IPv4/IPv6 监听地址走 `REALITY_LISTEN_HOST_V4/V6`，sing-box 入站不读此变量）。但 realm 渲染器 `reality_render_realm_config` / `reality_render_realm_config_multi` 当时以 `${REALITY_LISTEN_HOST:-…}` 解析 bind 地址——非空的 `"split"` 直接短路、被当成字面 bind host，渲染出非法的 `listen = "split:<port>"`，realm 无法启动；该机再添加任何中转线路都会触发 `reality_relay_add` 的应用失败回滚（机器不至于半残，但 split 落地机就是加不了中转）。修复：`reality_detect_listen_host` 显式把 `"split"` 当作未设置处理并回落接口探测（split 必有全局 IPv6 → 绑 `::` 双栈），两个 realm 渲染器改为统一经它解析、不再直接读裸变量。新增 2 条回归断言（单/多端点渲染均不得泄漏 `split:` 哨兵）。

## [v14.5] — 2026-06-24

### Added
- **Reality 落地机新增 IPv4/IPv6 网络模式选择**：安装/重装落地机时可选择“自动/双栈单节点”“IPv4-only”“IPv6-only”或“IPv4+IPv6 双节点”。双节点模式会在同一台 VPS 上渲染两个 sing-box Reality 入站：IPv4 入站绑定 `0.0.0.0:<port>`、IPv6 入站在共用端口时绑定具体本机 IPv6（不同端口时绑定 `[::]:<port-v6>`），并生成两条客户端链接，分别使用 A-only 与 AAAA-only 域名，方便双栈机器按线路质量在客户端手动选择 IPv4/IPv6。
  - 新增 `--dns-mode/--network-mode split|ipv4|ipv6|auto`、`--node-v4`、`--node-v6`、`--port-v6` 等 CLI 参数；菜单模式下会分别提示 IPv4/IPv6 域名，并把 Reality/Realm 入口端口策略调整为优先推荐 `443`。
  - 双节点模式允许 IPv4/IPv6 两条 Reality 入站共用 `443/tcp`：脚本会让 IPv4 监听 `0.0.0.0:443`、IPv6 监听具体本机公网 IPv6 `:443`，避免 Linux 默认 IPv6 wildcard 监听抢占 IPv4 端口。
  - 选择或传入非 `443` Reality/Realm 入口端口时输出风险提示；内置 SNI 候选池移除 Apple/iCloud 系域名，手动填写类似目标时也会提示风险。
  - Cloudflare 同步支持按节点模式写入 DNS：IPv4-only 会清理同名 AAAA，IPv6-only 会清理同名 A；双节点模式分别同步 IPv4 域名 A 记录与 IPv6 域名 AAAA 记录，并写入独立 DDNS 配置。
  - 客户端产物新增 `client-link-v4.txt` / `client-link-v6.txt` 与 `client-v4.json` / `client-v6.json`；兼容的 `client-link.txt` 在双节点模式下同时包含两条链接。

## [v14.4] — 2026-06-23

### Fixed
- **[P0] Oracle/Ubuntu 修改 SSH 端口后仍无法远程连接**：修复两类锁外场景。其一，Oracle Cloud 默认镜像常见 `iptables`/`nftables` INPUT 链仅放行 22 且尾部 `REJECT`，但 UFW 处于 inactive；`ssh_change_port` 现在会在 UFW 未启用时检测 `iptables`/`ip6tables`/`firewalld`，先放行新 SSH 端口并尽量持久化，失败或用户取消则拒绝继续改端口。其二，systemd `ssh.socket` 在 `BindIPv6Only=ipv6-only` 下写裸 `ListenStream=<port>` 会只监听 IPv6；socket drop-in 改为同时写 `0.0.0.0:<port>` 与 `[::]:<port>`，确保 IPv4/IPv6 都真实监听。
- **（测试）`smoke_p0p1p2.sh` 4 条 SSH/版本断言改为 hermetic**，消除在真实服务器上的误报（仅改测试，未动产品代码）：`P2-7`/`S2` 改走新增的 `run_set_directive` 包装——临时令 `confirm` 自动接受，绕开"宿主机 `/etc/ssh/sshd_config.d/` 存在同名 drop-in 时触发 confirm、而非交互终端下 `confirm` 直接拒绝→函数不改文件"导致的假失败；`S7` 临时 stub `sshd` 强制走 `refresh_ssh_port` 的 `SSHD_CONFIG` 多端口回退路径（原先在装有 sshd 的机器上会因优先 `sshd -T` 读到真实系统端口而误报）；`P3` 版本断言由钉死 `v14.1` 改为 `v<主>.<次>` 格式校验，不再随发布版本漂移。
- **DDNS 配置列表/删除菜单报 `parse_ddns_conf: command not found`**：`parse_ddns_conf` 仅定义在 `ddns_create_script` 生成的 `ddns-update.sh`（heredoc `<< 'EOF' … EOF`，行 50–200）内部，是那个独立 cron 脚本的私有函数；而交互菜单的 `ddns_list` / `ddns_delete` 在主脚本**顶层**调用它，顶层并无此函数 → 列表/删除菜单报 `command not found` 且无法显示已配置域名（cron 自动更新因生成脚本自带副本，不受影响）。修复：在主脚本顶层补一份 `parse_ddns_conf`（逻辑与 heredoc 内副本一致，诊断改走顶层 `log_action`），与本文件 `get_public_ipv4`(顶层)/`get_ip`(生成脚本) 既有的“双份”模式一致。
- **添加中转线路后提示/回滚指向错误线路**：`reality_relay_add` 在 `reality_relay_regenerate` 之后继续引用 `RLY_*` 全局，而 regenerate 内部遍历所有线路会把 `RLY_*` 覆盖为“最后一条线路”，导致成功提示、展示链接、UFW 端口、失败回滚 `rm` 全部指向另一条已存在的线路（如添加 sanjose 却显示/可能误删 mcdool）。新线路实际写入是正确的，仅事后引用错乱。修复：写入前把端口/名称/目标/连接域名固定为 local，regenerate 之后一律用 local 引用。

### Changed
- **Reality 中转/信息流程细节打磨**（基于实测反馈）：
  - 消除三处视图链接重复：完整 `vless://` 客户端链接**只在「查看节点信息」一处**展示（含落地 + 各中转线路）。「查看/修改节点信息」去掉单独的「输出客户端链接」项（移除 `reality_show_links`）；「中转线路列表」改为只显示清单与监听状态（名称/本机端口→目标/[监听中]），不再 dump 链接，并提示去「查看节点信息」取链接。
  - 添加中转线路新增「解析核对页」：写入前展示导入落地的 目标/SNI/UUID/公钥(脱敏)/ShortID 供确认，并允许覆盖默认连接域名；链接、端口等输入支持留空或 `0/q` 取消返回，不再只能 Ctrl+C。
  - 添加线路若 realm 配置应用/重启失败，自动回滚刚加的线路并用剩余线路恢复到原可用状态，不再留下半残/停止的 realm。
  - 清理 `reality_relay_add` 中对同一端口的重复防火墙放行（`reality_relay_regenerate` 已统一放行）。
  - `reality_diagnose` 覆盖中转：报告 realm 服务状态与每条线路监听端口是否在听；纯中转机不再因无落地参数而显示空目标/误报。

## [v14.3] — 2026-06-17

### Added
- **Reality 中转支持「单落地 + 多路中转」拓扑**：A 机可同时作为自己的 sing-box Reality 落地，并为多台线路较差的落地机 B/C/D… 做 Realm TCP 中转。每条线路独立存储自己的落地 Reality 身份（UUID/SNI/公钥/ShortID），互不串扰，各自生成一条客户端链接；客户端复用本机域名、按监听端口区分各线路。
  - 新增 `${REALITY_CONFIG_DIR}/relays/` 目录作为 realm 配置的唯一真相源，每条线路一个 `relay-<port>.conf`（经 `reality_state_quote`，满足 `validate_conf_file` 的 owner/mode/字面量校验）。
  - 菜单「2. 中转线路管理（多落地中转）」：添加（导入落地链接）/查看链接/删除；`reality_render_realm_config_multi` 渲染多 `[[endpoints]]`，`reality_relay_regenerate` 统一重建配置、放行端口、刷新各线路客户端产物并重启 realm。
  - 删除节点信息与 `firewall_remove_reality_ports` 同步回收所有中转线路监听端口；删除仅清理 relays 路由/链接，保留 backups、不 `rm -rf` 配置目录。
  - 旧版单中转字段（`REALITY_RELAY_*`）首次操作时自动迁移为一条线路并清空旧字段，既有安装平滑过渡。

### Fixed
- **[P0] IPv6-only / 双栈机器无法对外建立节点**：sing-box Reality 入站与 realm 中转此前固定绑定 `0.0.0.0`（仅 IPv4），IPv6-only 机器虽本地监听、IPv4 环回自测通过，但 IPv6 客户端无法连接。新增 `reality_detect_listen_host`（按本机是否存在全局 IPv6 地址决定绑 `::` 双栈或 `0.0.0.0`），sing-box/realm 渲染据此绑定（IPv6 监听串自动加方括号 `[::]:port`），并持久化 `REALITY_LISTEN_HOST`；重装落地机即自愈为正确绑定。诊断新增 IPv6 公网/AAAA 解析与一致性检查，IPv6-only 不再误报全失败，并在监听地址非 `::` 时提示重装。
- **[P0] 中转机安装 Realm 必失败**：上游 `zhboner/realm` 发布包不附带任何 sha256/SHA256SUMS 校验文件，原「校验文件缺失即拒绝安装」逻辑导致中转链路永远装不上。改为固定 `REALITY_REALM_VERSION` + 内置各架构 sha256，下载后仍强制 `sha256sum -c` 校验，既可安装又保留供应链校验，且不再依赖 `releases/latest` API。
- **[P0] 中转导入落地链接时客户端链接错用本机旧落地身份**：同机已有自身落地 state 时，`reality_install_relay` 在 `reality_load_state` 处用本机旧身份覆盖了刚解析出的导入身份，致使客户端 Reality 握手参数与真实落地机不匹配、节点不通。新多路模型按线路隔离身份，从架构上根除该类问题。

## [v14.2] — 2026-06-12

### Fixed
- **[P1/P2] 第二轮审计剩余 WireGuard/基础稳定性修复**（review #36）：
  - Debian WireGuard watchdog 生成脚本内写入固定 `WG_DEB_INTERFACE`，接口检测与 `wg-quick@...` unit 均使用常量，不再因单引号 heredoc 留下运行期未定义变量。
  - DDNS cron 改为每分钟唤醒，由 `ddns-update.sh` 按每份配置的 `DDNS_INTERVAL` 节流，修正 `*/59` 在 cron 中不是“每 59 分钟”的语义偏差。
  - OpenWrt `install_package` 不再把包名前缀当命令检测；sysctl 调优块改用显式 begin/end 标记删除；OpenWrt 主日志改用持久化路径。
  - WireGuard 清理不再粗暴删除全部 `prio 100` 策略路由；OpenWrt/Debian 下一可用 IP 查重改为固定字符串精确匹配。
  - Debian 添加 peer 不再在 DB 写入前冗余初写客户端配置；OpenWrt/Debian 卸载不再删除外部 `/etc/wireguard/*.key`；清理未调用的迁移/list/upsert 死函数。
  - OpenWrt/Debian peer 增删启停/导入路径新增热应用 helper，使用 `wg syncconf` 更新运行配置，避免整隧道 restart 造成在线 peer 集体断流。
  - Debian WireGuard Clash 配置生成改为 `wg_deb_generate_clash_config` wrapper，OpenWrt/Debian 共用 `_wg_generate_clash_config_impl`，不再隐式跨线调用 OpenWrt 函数。
  - WireGuard 11/12 的 DB/role 路径与读写/锁实现收敛到 `WG_SHARED_*` 和 `wg_shared_db_*`，把原先“同路径但假隔离”的共享状态改为显式共享。
  - DDNS 管理端列表/删除不再 `source "$conf"`，统一复用白名单解析器；Web 公网 IP 缓存复用全局 `CACHED_IPV4/CACHED_IPV6`。
  - 邮箱管理修复低危细节：`ADMIN_PASSWORDS` 普通变量保留反斜杠字面量，`DOMAINS` 解析失败时拒绝覆盖，Resend 状态颜色正确输出，升级日志记录旧版本→新版本。
  - Docker 安装时 GPG URL 与 apt source 使用同一官方 repo OS，停止/删除所有容器改为显式分支；Reality/Web 去除固定 `/tmp` 日志文件并修复 `reality_status` 管道退出码遮蔽；OpenWrt DNS uci 写入/提交失败会中止并提示。

- **[P2] 第二轮审计剩余低/中危修复**（review #35）：
  - DDNS cron 的 Cloudflare DNS POST/PUT 请求补齐 `--connect-timeout` / `--max-time` 并引用 method，避免更新请求长期阻塞或 shell 展开异常。
  - UFW 删除规则菜单真实过滤 Fail2ban/f2b 规则，并在删除前校验端口范围；SSH 公钥删除改为整行固定字符串过滤，不再用 `sed` 分隔符拼接 key。
  - OpenWrt `rc.local` 插入 helper 与网关部署命令支持带空格/注释的 `exit 0` 锚点，避免规则被追加到 `exit 0` 后而开机不生效。
  - GeoIP cron IPv4 下载失败路径同步清理已创建的 IPv6 临时文件。
  - `_sshd_set_directive` 与 Reality sing-box 配置 apply 的临时文件接入统一中断清理，并使用 `.tmp/.bak.server-manage.*` 命名。
  - Debian WireGuard systemd unit 名统一使用 `WG_DEB_INTERFACE` 常量，不再硬编码 `wg-quick@wg0`。

- **[P1] 第二轮审计剩余安全/稳定性修复**（review #34）：
  - `geoip_update` 对 `_geoip_apply` 失败改为 fail-closed，避免下载成功但规则加载失败时仍写入更新时间并提示“完成”。
  - `refresh_ssh_port` 支持保留多个 OpenSSH `Port`，UFW 初始化/重置会放行全部 SSH 监听端口；系统信息也复用统一解析结果。
  - `menu_update` 补齐本次新装 `fail2ban` 跟踪，手动依赖修复不会引用未赋值变量，也会停掉安装后默认启动的 jail。
  - `_fail2ban_set_sshd_port` 未命中 `[sshd]` jail 时返回失败，不再静默假成功。
  - OpenWrt/Debian WireGuard 服务端配置写入前收紧 `umask 077`，减少 `wg0.conf` 私钥文件创建权限窗口。
  - 新增 `validate_wg_allowed_ips`，自定义 WireGuard AllowedIPs 支持裸 IP 与 CIDR 混合；非法输入回退为仅 VPN 内网，不再回退全局代理。
  - Debian WireGuard 安装仅在 DB 写入成功后设置 server role，并补齐服务端修改、peer 启停/删除、路由联动的 DB 写入失败检查。
  - iPerf3 清理不再用 `pkill -f` 子串匹配；OpenWrt DNS 设置不再硬编码 `network.wan`；Reality 无 `shuf` 时的随机端口 fallback 不再受 `$RANDOM` 32767 上限截断。

- **[P1] 第二轮审计 Reality/Docker 剩余修复**（review #33）：
  - 删除 Reality/Realm 节点信息时回收已放行的 Reality/Realm UFW 端口规则，并保留 `REALITY_BACKUP_DIR`，不再 `rm -rf` 整个配置目录导致备份自删。
  - Reality SNI 校验增加 `openssl s_client -verify_return_error`，证书校验失败会真实返回失败。
  - Realm 与 Docker Compose standalone 下载后增加 sha256 校验，校验缺失或失败时拒绝安装，避免截断/篡改二进制落盘。
  - Docker 容器日志跟随时临时接管 `Ctrl+C`，退出日志后返回菜单，不再触发全局中断退出整个脚本。
  - Docker 卸载同步清理脚本写入的 systemd proxy drop-in 与 `/etc/docker`，避免重装后旧代理配置静默复活。

- **[P1] 第二轮审计邮箱剩余高优先修复**（review #32）：
  - 邮箱部署、卸载和管理入口设置敏感环境变量 RETURN 清理，统一清除 `CF_*` 与 `CLOUDFLARE_*`，避免 Cloudflare 凭据被后续子进程继承。
  - NodeSource 安装链路去掉裸 `curl | bash`，改为下载脚本后在 `bash -o pipefail` 环境中执行，curl/setup 失败不会被后续 `apt-get install` 掩盖。
  - 首次 Worker 部署前在 `wrangler.toml` 写入 `ADMIN_PASSWORDS` 兜底变量，随后再写 secret，避免 secret 写入失败时公网 Worker 出现无管理员密码窗口。
  - Pages service binding patch 改为临时修改后恢复 `pages/wrangler.toml`，不再用 `sed -i` 长期 dirty git tracked 文件，避免后续 `git checkout` 升级冲突。
  - 已安装状态下禁止直接覆盖部署，改为提示使用管理菜单升级/重部署或先完整卸载，避免生成新随机 D1/Pages 后丢失旧资源 ID。

- **[P1] 第二轮审计邮箱高优先修复**（review #31）：
  - 临时邮箱卸载时如 Worker/Pages/D1/DNS/Catch-all 任一远端资源删除失败，不再删除本地项目、管理员密码文件或清空 state；保留资源 ID 供用户修复权限/网络后重试卸载。
  - D1 patch 升级每成功应用一个 migration 即立即写回 `EMAIL_PATCHES_APPLIED`，后续 patch 失败时可安全重跑，不会重复执行已成功的 ALTER TABLE。
  - `_email_cf_worker_exists` 改为三态返回：存在/不存在/未知；Worker 名选择在存在性未知时 fail-closed，避免 Cloudflare API 失败或权限不足时误用默认名覆盖生产 Worker。

- **[P1] 第二轮审计剩余高优先修复**（review #30）：
  - Reality 初次安装路径改为先渲染到内存，再复用 `reality_apply_singbox_config` 做临时文件校验、原子替换与失败回滚，不再直写最终 `sing-box` 配置。
  - OpenWrt WireGuard 网关部署命令中的 `/etc/rc.local` 持久化块改为 `awk` + 临时文件插入，避免 BusyBox `sed i\` 多行插入兼容性问题。
  - Web/Cloudflare DNS 公网 IP 探测改用统一 `get_public_ipv4/get_public_ipv6` helper，并在写入 DNS 前用 `validate_ip` 区分 IPv4/IPv6，避免劫持页或错误页被当作 A/AAAA 记录。

- **[P1] 第二轮审计 Web 反代替换修复**（review #29）：
  - 新增 `_replace_proxy_pass_backend`，通过 `match` + `substr` 拼接替换 `proxy_pass` 后端，避免 gawk `sub()` replacement 中 `&` 展开为整段匹配。
  - 修改反向代理后端时改用安全 helper，`&` 等字符按字面量写入，并继续保留临时文件 + `nginx -t` 回滚链路。

- **[P2] 第二轮审计测试/工作区可靠性修复**（review #28）：
  - `tests/smoke_p0p1p2.sh` 开头强制使用 UTF-8 locale，避免 C/POSIX locale 下中文 UTF-8 字节被线框字符 grep 误判。
  - `.gitattributes` 增加 Markdown LF 规则，并统一关键 `sh/md` 工作区文件为 LF，避免直接 scp 到 VPS 执行脚本时触发 `$'\r': command not found`。

- **[P1] 第二轮审计 WireGuard 导入修复**（review #27）：
  - OpenWrt / Debian 两条 WireGuard 导入链路保留 `route_mode` 字段，跨机迁移 custom peer 后不会被后续自动路由刷新覆盖。
  - 新增 WireGuard key 字面量校验，导入时校验 private/public/PSK、`client_allowed_ips`、`lan_subnets`、peer 类型与路由模式；Debian 导入同步补齐 name/IP 校验，拒绝恶意 JSON 字段进入配置、UCI/nft/部署命令。

- **[P1] 第二轮审计行级安全修复**（review #26）：
  - SSH 端口监听检测只匹配 `:port` 结尾，避免 `1022/2022/8022` 被误判为 `22`，降低改 SSH 端口后误删旧防火墙规则的锁外风险。
  - 家宽公网暴露的路由器 DNS 劫持流程新增 `nginx_ip` IP 校验，并把 `router_ssh` 作为单个 SSH 目标参数传递，避免输入拼入远程 root 命令。
  - Reality 落地/中转重复安装时按包含关系合并 `landing+relay` 角色；落地安装会先读取已有 relay 状态，中转安装不再把一体机降级为纯 relay。

- **[P0] 第二轮审计 fix_broken 回归修复**（review #25）：
  - GeoIP weekly update 写回 `GEOIP_LAST_UPDATE` 时保留 `KEY="value"` 格式，避免首次 cron 更新后 `geoip-apply.sh` 因安全解析失败而静默跳过所有 GeoIP 规则。
  - DDNS 交互/非交互创建配置时恢复所有字段的双引号输出，确保新建配置能被 `ddns-update.sh` 白名单解析器接受，自动更新不再退化为无效配置。

- **[P1] 审计报告 WireGuard 运行时修复**（review #24）：
  - Debian 修改 WireGuard 出口网卡后会清理旧网卡上的 NAT MASQUERADE 规则，避免 `wg-quick restart` 使用新配置 PostDown 时遗留旧出口 NAT。
  - OpenWrt watchdog 不再只用 `wg_bypass` 子串判断 bypass 是否完整；改为分别自愈 `wg_bypass_iface` 与各 VPN/LAN 子网 `wg_bypass_subnet` 规则。
  - OpenWrt Mihomo bypass/端口放行的 `/etc/rc.local` 持久化新增块插入 helper，不再依赖 BusyBox `sed i\` 多行插入兼容性。

- **[P1] 审计报告 WireGuard Clash 注入修复**（review #23）：
  - Clash YAML 自动注入在原配置缺少 `proxy-groups:` 时会补齐顶级 `proxy-groups:` key，再插入 WireGuard 分组，避免把分组条目追加到 `rules:` 下生成损坏 YAML。
  - `proxy-providers` 订阅域名提取改为显式 awk 状态机，不再使用起止都匹配顶级 key 的范围表达式，避免起始行即终止导致 DNS 直连策略从未注入。
  - 含 WireGuard 私钥/PSK 的 Clash YAML 输出使用 `umask 077` 创建并 `chmod 600` 收紧，避免 `/tmp` 默认 644 泄露敏感配置。

- **[P1] 审计报告 WireGuard 路由与状态修复**（review #22）：
  - 新增通用 CIDR / CIDR 列表校验，OpenWrt 与 Debian 修改服务端 LAN 子网时会先校验格式，并在变更后联动刷新 peer `AllowedIPs`。
  - 标准 peer 的自定义路由会持久化 `route_mode=custom`，网关增删或 LAN 变更触发的自动路由刷新会跳过自定义路由 peer，避免覆盖用户手工路由。
  - OpenWrt `wg_setup_watchdog "true"` 支持非交互自动安装，不再进入已启用管理界面、确认提示或 pause。
  - Debian WireGuard 服务端安装、添加 peer、导入 peer 对数据库写入失败显式 fail-closed；添加 peer 失败会清理已生成客户端配置，导入失败计入跳过而非虚增成功数。
  - WireGuard 导出 peer 的 `mktemp` 模板改为 BusyBox 兼容格式，不再使用 `XXXXXX.json` 这类非尾部 X 模板。
  - OpenWrt / Debian 主菜单不再仅凭 `wg0.conf` 存在强制把角色改为 server，需存在 server state 私钥才自动识别服务端。

- **[P1] 审计报告 Web 剩余项修复**（review #21）：
  - Cloudflare Zone 列表新增 `_cf_list_zones` 分页 helper，添加域名、家宽暴露、Zone ID fallback 均改为读取全量分页，避免 Token 可管理域名超过 50 个时漏选。
  - 反向代理复用父域证书前新增 SAN 覆盖校验，仅当证书精确覆盖目标域名或通配符覆盖单级子域时才自动复用。
  - 子域反代不再把任意父域证书提示为“可用主域证书”；未覆盖目标域名时明确提示用户先申请匹配证书或手动指定证书。

- **[P1] 审计报告 Web 安全回归修复**（review #20）：
  - Nginx reload 失败不再自动 fallback 到 restart，避免端口/配置异常时把全站 stop 后无法拉起。
  - `_nginx_deploy_conf` 覆盖部署新增旧配置备份与失败恢复；`nginx -t` 或 reload 失败时恢复原 `sites-available` / `sites-enabled`，不再删除正常站点配置。
  - Web 域名查看/删除序号校验补齐 `< 1` 判断，拒绝 `00` 等会被 bash 当成负索引的输入。
  - 覆盖重配域名时同步更新既有 DDNS 配置，避免新 Token/新解析参数不落盘导致后续 DDNS 静默失败。
  - 修改反向代理后端地址改为安全替换 `proxy_pass` 行，正确处理 `&` / `|` 等替换特殊字符。

- **[P1] 审计报告 GeoIP IPv6 防绕过修复**（review #19）：
  - GeoIP 国家白/黑名单新增 IPv6 数据源与 `.zone6` 数据下载，自动更新脚本同步下载 IPv4/IPv6，任一失败即中止应用，避免半更新导致策略漂移。
  - `_geoip_apply` 新增 `family inet6` 的 IPv6 ipset 与 `ip6tables` 链；IPv6 可用但缺少 `ip6tables` 时拒绝应用规则，避免 IPv6 绕过白/黑名单。
  - 白名单模式下 IPv6 链与 IPv4 一样默认 DROP，仅对匹配国家集合放行；黑名单模式下匹配国家集合 DROP。
  - GeoIP 清理与开机持久化 apply 脚本同步覆盖 IPv6 链和集合，重启后不会退回 IPv4-only。

- **[P2] 审计报告 OpenWrt 系统优化修复**（review #18）：
  - OpenWrt 修改主机名改为通过 `uci set system.@system[0].hostname` + `uci commit system` 持久化，并检查写入失败；不再只写 `/etc/hostname` 后提示成功。
  - OpenWrt 修改时区改为同时写入 `zonename` 与 POSIX `timezone`，并提交 `system` 配置；非 OpenWrt 的软链接回退路径会先检查 `/usr/share/zoneinfo/$z` 是否存在，避免创建悬空 `/etc/localtime`。
  - BBR 开启流程检查 `sysctl -p` 返回值，并在应用后复验 `net.ipv4.tcp_congestion_control` 是否实际为 `bbr`；失败时明确报错，不再假报成功。

- **[P1] 审计报告安全防护修复**（review #17）：
  - Fail2ban 旧 UFW 规则迁移不再直接 `sed` 修改 `/etc/ufw/user.rules` / `user6.rules`，改为通过 `ufw status numbered` 定位并用 `ufw delete` 删除，且不再吞掉 `ufw reload` 失败。
  - `auto_deps` 新安装 `fail2ban` 且安装前未运行时，会立即 `disable --now`/stop，避免发行版默认 `sshd` jail 静默启用后误封 SSH。
  - `ufw_setup` 与 `ufw_safe_reset` 在放行 SSH 前强制 `refresh_ssh_port` 并校验端口，避免使用过期 `CURRENT_SSH_PORT` 导致锁外。
  - Fail2ban 解封菜单新增活跃 jail 枚举，展示和解封遍历所有 jail，不再只处理 `sshd`，可恢复 nginx 等 jail 的误封。

- **[P1] 审计报告核心基础剩余修复**（review #16）：
  - 主菜单系统信息不再在前台串行刷新公网 IPv4/IPv6 与 ipinfo；缓存缺失或过期时先用旧缓存/占位值渲染菜单，再后台刷新，避免无网环境主菜单卡顿。
  - 最近登录记录的公网 IP 归属地改为 24 小时缓存 + 后台查询；首次缺缓存时显示“待查询”，不再在菜单渲染路径实时访问 `ip-api.com`。
  - `write_file_atomic` 新增临时文件注册/注销；`handle_interrupt` 统一清理本进程登记的 `.tmp.server-manage.*` 临时文件，避免中断后在任意目标目录残留。
  - DNS 修改的 `/etc/resolv.conf` 写入改走 `write_file_atomic`，不再创建未注册的 `/etc/resolv.conf.tmp.*`。
  - `build.sh` 删除 Reality 运行时 source 块时改用显式 `BUILD-OMIT` 起止边界，不再依赖“注释标记到首个顶格 `fi`”的脆弱 sed 范围。

- **[P1] 审计报告核心基础修复**（review #15）：
  - `confirm()` 在非交互 stdin / EOF 场景下不再把空输入当作默认确认，避免管道、cron、远程批处理误触发破坏性操作。
  - `--reality` CLI 入口补齐与菜单一致的 OpenWrt 平台拦截，在 OpenWrt 上通过 `feature_blocked` 明确拒绝 Sing-box Reality 节点功能。
  - `cron_add_job` / `cron_remove_job` 改用固定字符串匹配删除任务，并检查 `crontab` 安装失败返回码，避免正则误删相似任务或把安装失败误判为成功。
  - DDNS cron 的 Cloudflare `proxied` 字段补齐默认值与布尔归一化；配置缺省、空值或非法值时统一写入 JSON `false`，避免生成非法请求体。

- **[P1] 审计报告 Reality 高风险修复**（review #14）：
  - Reality UUID / Key 轮换改为先渲染到临时配置并执行 `sing-box check`，通过后再替换最终配置并重启；`check` 或 `restart` 失败均回滚/保留旧配置，且不写入新 state 或客户端链接。
  - `rotate_key` 增加落地机参数完整性与 `REALITY_PORT` 校验，避免空端口渲染出非法 JSON 并覆盖好配置。
  - Realm 中转安装/重装前先 `reality_load_state`，同机已有落地机时保留 UUID、私钥、公钥、SNI、ShortID 等落地机参数，避免中转 state 覆盖清空落地配置。

- **[P2] 审计报告第三批安全细节修复**（review #13）：
  - `_sshd_set_directive` 改为只修改首个 `Match` 块之前的全局指令；无全局指令时插入到首个 `Match` 前，避免破坏用户例外规则。
  - SSH 改端口同步 Fail2ban 时新增 `_fail2ban_set_sshd_port`，仅更新 `[sshd]` jail 的 `port`，不再误改 nginx/http 等其他 jail。
  - 网络诊断端口测试新增 `validate_host`，并改为通过 `bash -c` 参数传递 host/port，避免把 host 拼进 `/dev/tcp` 命令字符串。
  - `validate_ip` 加强 IPv6 校验，拒绝多个 `::` 的非法地址。
  - DDNS 配置文件改走 `write_file_atomic` 后再 `chmod 600`，避免 token 文件先以默认 umask 创建再收紧权限的窗口；DDNS cron 的 Cloudflare GET 失败会返回失败，不再误判记录不存在。

- **[P1] 审计报告第二批锁外/Cloudflare 高风险问题修复**（review #12）：
  - SSH 改端口新增 `ssh.socket` / `sshd.socket` socket activation 检测；socket 模式下同步写入 systemd socket drop-in，并在删除旧 UFW 端口规则前用真实监听端口检测确认新端口已可用。
  - 禁用密码登录前检查至少一个可登录用户存在 `authorized_keys`；禁用 Root 登录前检查存在非 root sudo 用户；两条流程均用 `sshd -T` 复验 `PasswordAuthentication` / `PermitRootLogin` 的最终有效值，失败即回滚。
  - GeoIP 下载改为 `curl -f` + 临时文件 + 非空内容校验，任一国家下载失败不再继续应用；`_geoip_apply` 拒绝空集合并检查 `ipset restore/swap`，cron 更新失败会中止且保留旧集合。
  - Cloudflare Origin Rules GET 增加超时、重试、curl 返回码和 `success` 校验；家宽一键流程在读取失败时跳过自动 PUT，避免把全量 entrypoint ruleset 误替换为空/单条规则。
  - DNS/Origin Rules 的 Cloudflare GET 读取失败与“不存在”分离，DNS 更新不会在 GET 失败时误判记录不存在并创建重复记录。

- **[P1] 审计报告第一批高风险问题修复**（review #11）：
  - 修复 `email_run` 失败命令返回码被 `if` 复合语句吞掉的问题；失败时现在返回真实退出码，避免部署/升级/卸载链路把失败误判为成功。
  - 新增通用 `validate_dns_label`，并在 Web「添加域名」与「家宽公网暴露」入口校验子域名前缀，阻断路径、Nginx、crontab 等后续注入面；临时邮箱 `_email_validate_dns_label` 改为复用通用 helper。
  - 修复 OpenWrt WireGuard `wg_add_peer` 添加网关后展示部署命令时未定义 `target_idx` 的问题，改为使用新增 peer 的真实索引。
  - 导入 OpenWrt WireGuard peer 时新增 name 白名单与 IP 格式校验，避免篡改 JSON 触发路径穿越或脏数据入库。
  - `print_warn` / `print_error` 改为输出到 stderr，避免命令替换吞掉诊断文本或污染 stdout 返回值。
  - 新增 `ufw_is_active` 并统一替换 `ufw status | grep "Status: active"`，避免 locale 导致 UFW active 检测失真。
  - 清理 `grep -c ... || echo 0` 反模式，避免无匹配时得到 `0\n0` 触发算术错误。

### Tests
- 新增 review #24 WireGuard 运行时回归：覆盖 Debian 出口网卡变更清理旧 NAT、OpenWrt watchdog 分别检查 iface/subnet bypass、rc.local 持久化不再使用 BusyBox 不兼容 sed 多行插入。
- 新增 review #23 WireGuard Clash 回归：覆盖缺少 `proxy-groups:` 时补顶级 key、`proxy-providers` 显式状态机提取、Clash YAML 输出权限 0600。
- 新增 review #22 WireGuard 回归：覆盖 CIDR 校验、服务端 LAN 变更联动刷新 peer routes、自定义路由不被覆盖、OpenWrt watchdog auto mode、Debian DB 写入失败处理、BusyBox `mktemp` 模板、主菜单 server 角色识别条件。
- 新增 review #21 Web 剩余回归：覆盖 Zone 分页 helper、添加域名/家宽暴露/Zone fallback 使用分页列表、通配符证书只匹配单级子域、反代复用父域证书前校验 SAN。
- 新增 review #20 Web 回归：覆盖 `_nginx_reload` 不 restart、`_nginx_deploy_conf` 失败恢复旧配置、`00` 序号拒绝、覆盖重配 DDNS 配置更新、反代后端安全替换特殊字符。
- 新增 review #19 GeoIP IPv6 回归：覆盖 IPv6 数据源、`.zone6` 下载、`family inet6` ipset、`ip6tables` 链、IPv6 清理与持久化 apply 脚本。
- 新增 review #18 OpenWrt 系统优化回归：覆盖主机名/时区通过 UCI 持久化、非 OpenWrt zoneinfo 存在性检查、BBR `sysctl -p` 返回值与应用后复验。
- 新增 review #17 安全防护回归：覆盖 Fail2ban UFW 旧规则迁移不直接改规则文件、`ufw reload` 失败不吞、`auto_deps` 新装 fail2ban 后停用、UFW setup/reset 刷新 SSH 端口、Fail2ban 多 jail 解封。
- 新增 review #16 核心基础剩余回归：覆盖主菜单异步网络缓存、登录 IP 归属地缓存/后台查询、临时文件注册清理、DNS resolv.conf 原子写、Reality source 块显式构建省略边界。
- 新增 review #15 核心基础回归：覆盖非 tty `confirm` 不自动确认、`--reality` CLI OpenWrt guard、cron 固定字符串删除与 crontab 失败返回、DDNS `proxied` 缺省/非法值归一化。
- 新增 review #14 Reality 回归：覆盖轮换函数必须使用临时配置 + checked apply helper、失败不覆盖旧配置、restart 失败回滚、`rotate_key` 端口校验、Realm 中转安装先加载既有 state。
- 新增 review #13 回归：覆盖 `Match` 块保护、Fail2ban `[sshd]` 定向更新、端口测试 host 校验/命令注入防护、非法 IPv6、多处 DDNS token 原子写与 Cloudflare GET success 判定。
- 新增 review #12 回归：覆盖 SSH socket activation 监听校验、禁用密码/root 登录前置校验与 `sshd -T` 复验、GeoIP fail-closed 自动更新、Origin Rules 读取失败保护、Cloudflare DNS GET success 判定。
- 新增 review #11 回归：覆盖 `email_run` 真实失败码、Web DNS label 校验、WG 新增 peer 索引、WG 导入 name/ip 校验、stderr 输出、UFW locale helper、`grep -c` 反模式清理。

### Changed
- **[P1] Nginx HTTP/2 配置改为版本感知生成**（review #10）：Nginx 1.25.1+ 已将 `listen ... http2` 标记为 deprecated，推荐独立 `http2 on;`；但 Debian/Ubuntu 稳定仓库仍可能是旧版 Nginx，旧版不识别 `http2 on;`。修复：新增 `_nginx_tls_http2_block <port>`，运行时按 `nginx -v` 选择新/旧语法；`添加域名`、`反向代理网站`、`家宽公网暴露` 三类生成模板统一调用该 helper，Cloudflare Origin Rules 的手工提示也更新为新语法说明。
- **[P1] Docker 安装流程对齐官方 Debian/Ubuntu 文档**（review #10）：安装 Docker CE 前先移除官方列出的冲突包 `docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc`；Docker Compose 菜单改为优先安装官方 `docker-compose-plugin`，仅在 plugin 安装失败时 fallback 到 standalone 二进制；standalone fallback 增加 `uname -m` 到 Compose release 资产名的架构映射。
- **[P1] 临时邮箱 Wrangler/Node 链路对齐 Cloudflare 与上游项目**（review #10）：环境检查不再全局 `npm install -g wrangler`，改为使用上游 `worker/pages/frontend` 子项目内的 `node_modules/.bin/wrangler`；NodeSource 安装脚本从固定 `setup_22.x` 改为 `setup_lts.x`；Worker 依赖安装从 `npm install` 改为 `pnpm install --no-frozen-lockfile`，与上游 `packageManager: pnpm@10.10.0` 和 `wrangler` devDependency 保持一致。首次部署、D1 migration、改管理员密码 fallback、改 DOMAINS、升级、重部署均统一走 `_email_wrangler` helper。

### Tests
- **新增 review #10 官方兼容性回归**：覆盖 Nginx HTTP/2 版本感知 helper、dist 不再硬编码 deprecated `listen ... http2`、Docker 冲突包移除、Compose plugin 优先、standalone 架构映射、NodeSource LTS、临时邮箱项目本地 Wrangler。
- **本地测试脚本隔离增强**：`smoke_email.sh` / `smoke_remote.sh` 在非 root Git Bash 环境下自动使用临时 state/log/admin/install 路径并 mock 必要的 root/UFW 条件；远端 root 环境仍保留原 owner/mode/UFW 严格路径，便于同一套测试同时覆盖本地开发与服务器冒烟。
- 本轮本地验证（Windows Git Bash，`/tmp/v4-built.sh`）：`smoke_p0p1p2.sh` 109/109 PASS、`smoke_email.sh` 14/14 PASS、`smoke_remote.sh` 13/13 PASS、`reality_module_static_test.sh` PASS、`reality_sni_enhancement_test.sh` PASS、`ddns_ip_detection_test.sh` PASS、`nginx_body_size_defaults_test.sh` PASS；`dist/v4-built.sh` 已重建并通过 `bash -n`。

### Fixed
- **[P2] 子域名引导文案误导用户走到失败路径**（review #8）：review #7 的 MX 替换警告里推荐"使用专用子域名（如 `tmp.example.com`），重启脚本时填入子域名即可避免影响主域邮件"，但脚本随后用用户输入的 `EMAIL_DOMAIN` 直接精确查 Cloudflare Zone (`zones?name=$EMAIL_DOMAIN`)；多数用户的 Cloudflare 上只有 `example.com` 一个 Zone，没有把 `tmp.example.com` 独立托管 → 部署会在"获取 Zone ID"阶段失败。修复：(a) 文案改为"使用一个未托管邮件的专用域名作为 EMAIL_DOMAIN（例如新购的 .top/.xyz 等便宜域名）"；(b) 显式说明"如需用子域名，必须先在 Cloudflare 控制台把该子域名独立托管/委派为新 Zone，否则脚本会在获取 Zone ID 时失败"。不改代码流程（单 EMAIL_DOMAIN 模型与上游 dreamhunter2333 一致；拆分 Zone/收信域名会引入 catch-all → 收件规则的复杂度，工程代价远高于文案修复）。

### Docs
- **[P3] `build.sh` 注释引用已不存在的 `v4.sh`**（review #8）：build.sh 第 12 行注释 `# 模块加载顺序（与 v4.sh 中 source 顺序一致）`，但 `v4.sh` 已在 v14.1 重构里淘汰（只剩 `build.sh` + `dist/v4-built.sh`）。修复：注释改为 `# 模块加载顺序（运行时按此顺序拼接，main 由 13-menus.sh 提供）`。

### Tests
- **从 `smoke_p0p1p2.sh` 移除 review #7 加入的 P3-CHANGELOG / P3-README 4 项 docs 静态断言**（review #8）：这 4 项依赖兄弟文件 `../CHANGELOG.md` 和 `../README.md` 存在；远端只 `scp tests/*.sh /tmp/` 时它们走 SKIP，使同一份测试在不同执行路径上 PASS 计数不一致（远端少 4 项），CHANGELOG 引用的数字也跟着对不上。判定：docs 一致性是构建期元数据问题，不属于 dist 行为回归 — 移到 review 时人工检查或后续单独的 docs lint 脚本。移除后本地与远程跑出的数字一致，便于作为发布证据。
- 远程冒烟 (Debian 12 HK-Alice-2, hostname `mcdool`) 经 review #8 后实测：
  - `tests/smoke_p0p1p2.sh`: 79/79 PASS（含 review #1-#7 全部 79 项断言；review #7 经文案修订后净 6 项；review #8 无新增 dist 断言）
  - `tests/smoke_email.sh`: 14/14 PASS（state roundtrip / mask / API guard / 40 个函数齐备）
  - `tests/smoke_remote.sh`: 15/15 PASS（validate_conf_file / SSH 数组防注入 / UFW active 路径 / 菜单字面）
  - **合计 108/108 PASS**
- 之前 CHANGELOG 写 "110/110 PASS" 是 review #7 时数字（其中 4 项是临时上传 CHANGELOG/README 到 `/tmp/vpsroot/` 让 docs 断言能跑），用户标准远端路径只跑 78（4 项 SKIP）；本轮移除 docs 断言后路径稳定，108/108 为新基线。
- 历史 v14.1 段 review #1-#4 的远程测试在另一台机 (HK-Alice-1) 上跑，主机名差异保留原记录。

### Fixed (review #7 — 历史保留)
- **[P2] 临时邮箱部署会无二次提醒地接管整域 MX**（review #7）：原配置确认页只列域名/API/前端/邮箱格式，没有提示部署会执行 `_email_cf_dns_purge "$zid" MX "$EMAIL_DOMAIN"` 清空根域所有 MX。如域名已有 Google Workspace / Microsoft 365 / 自建邮件服务器，部署后立即停止收信，且 partial 卸载流程也无法还原原 MX 记录（只能凭用户记忆手工补回）。修复：(a) 配置确认页加红色高亮警告，明确列出要写入的 3 条 cloudflare MX 与 priority，并显式提醒已有的常见企业邮箱会被中断；(b) 引导改用专用域名（review #8 又把"子域名"措辞修正为"独立托管的子域名 Zone"，避免误导）；(c) 第一道 `confirm "确认以上配置开始部署?"` 后追加独立的 MX 替换二次确认 `confirm "再次确认：${EMAIL_DOMAIN} 没有正在使用的企业邮箱或其他 MX 服务?"`，二次未确认则取消并提示改用专用域名。

### Docs (review #7 — 历史保留)
- **[P3] CHANGELOG 主机名与本轮实测一致化**（review #7）：本轮 review #6 远程冒烟实际在 HK-Alice-2（hostname `mcdool`）跑，CHANGELOG 原写 HK-Alice-1 不准确。修复：Tests 段写明 HK-Alice-2 (mcdool)；历史 v14.1 段保留原 HK-Alice-1 记录（那一轮确实是另一台机）。
- **[P3] README 项目结构去掉幻影文件**（review #7）：README 原列 `v4.sh`（主入口多文件模式）与 `install.sh`（安装引导脚本），但工作区和 git 跟踪文件里这两个文件都不存在。修复：删除这两行；同时补上 `CHANGELOG.md` 的项目结构条目，并把 `build.sh` / `dist/v4-built.sh` 的注释改成与实际使用方式一致（`bash <(curl …)/v4-built.sh`）。
- **[P3] 清理误生成的根目录 `%q` 0 字节文件**（review #7）：疑似某次本地交互输入 `printf '%q'` 被重定向到文件名 `%q` 的残留，0 字节、未跟踪。修复：`rm -f %q`，避免被 `git add -A` 误入仓库。

### Fixed (review #6 — 历史保留)
- **[P1] DNS / MX / Catch-all 失败仍标记部署完成**（review #6）：原 `_email_deploy_dns` 把 CNAME/MX 失败 `print_warn` 后吞掉，`_email_deploy_email_routing` 失败也 `return 0`，主流程一路走到 `EMAIL_INSTALLED=1`，结果"部署完成"但临时邮箱实际收不到信。修复：(a) `_email_deploy_dns` 累计 `_dns_fail` — 前端 CNAME 失败或 MX 3 条全失败 → return 1（Resend 相关 DNS 仍仅 warn，不阻断主链路）；(b) `_email_deploy_email_routing` 任一阶段失败 → return 1；(c) 两个函数失败前都先 `email_state_write` 落盘 partial 状态（EMAIL_INSTALLED=0，已创建的 record_id 保留供后续【强制卸载】回收）；主流程的 `|| { pause; return 1; }` 即可正确阻断 `EMAIL_INSTALLED=1`。
- **[P1] 自定义 Worker 名的升级/重部署链路未同步 Pages service binding**（review #6）：首次部署里 `_email_deploy_pages` 已 sed 修补 `pages/wrangler.toml` 的 `service = "$EMAIL_WORKER_NAME"`，但 `email_manage_upgrade`（拉新 tag 后）与 `email_manage_redeploy` 直接 `wrangler pages deploy`，未复用修补逻辑。结果：升级后 `pages/wrangler.toml` 可能被新版上游覆盖回 `service = "cloudflare_temp_email"`，Pages Functions 的 `/api` 找不到自定义 Worker。修复：抽 helper `_email_patch_pages_service_binding <pages_dir>`（14a），幂等（已是正确 worker 则 noop，无 services section 也 noop），在 14c deploy / 14d upgrade / 14d redeploy 三处复用。
- **[P2] 管理员密码输入仍明文回显**（review #6）：`14c:193`（部署时设密码）和 `14d:53`（管理菜单改密码）用 `read -e -r -p`，输入会显示在终端上。修复：改为 `read -r -s -p`（隐藏输入），允许留空走自动生成；输入非空时只显示 `已收到密码（不回显）`，避免在最终汇总前任何位置泄露明文。最终汇总仍单次展示并保存到 `/root/.email-admin.txt` mode 600。
- **[P2] "查看部署日志"菜单绕过脱敏**（review #6）：`email_run` 失败尾部已走 `_email_redact_secrets`，但 `email_view_log` 菜单直接 `tail -n 80 "$EMAIL_LOG_FILE"`，日志里旧版本残留的 `secret_text` / `Bearer xxx` / `TOKEN=xxx` 形式会原样打出。修复：菜单 tail 改为 `tail | _email_redact_secrets`，与 `email_run` 一致。
- **[P3] `smoke_p0p1p2.sh` 仍会被注释行误判**（review #6）：原 `grep -q "echo 0 | timeout" smoke_remote.sh` 会命中 smoke_remote 第 125 行那条描述旧写法的注释，导致 P3 测试在已修复脚本上仍 FAIL。修复：(a) grep 前加 `grep -v '^[[:space:]]*#'` 排除注释行；(b) smoke_remote 注释里有意拆分 `"echo 0"` 与 `"timeout"` 字面，避免被回归测试误命中（双保险）。

### Fixed (review #5 — 历史保留)
- **[P1] CF API 失败日志可能泄露 secret**：`_email_cf_api` 失败分支把完整请求 body 写入 `/var/log/server-manage-email.log`；`_email_cf_worker_secret_put` 的 body 含 `text:"<密码>"` / `text:"<resend_token>"`。修复：(a) `_email_cf_api` 检测 path 含 `/secrets` 时 body 替换为 `<redacted: secret payload>`；(b) `email_run` tail 日志前过滤 `secret_text` JSON 字段、`ADMIN_PASSWORDS=/RESEND_TOKEN=/CF_API_TOKEN=` 形式、`Bearer xxx` Authorization 头，统一替换为 `<redacted>`（新增 `_email_redact_secrets` helper）。
- **[P1] Cloudflare `send_email` binding 默认启用导致首次 Worker 部署失败**：`wrangler.toml` 模板原无条件写入 `send_email = [{ name = "SEND_MAIL" }]`，但部署此 binding 要求 Email Routing 已启用且发件地址已验证；本流程 Worker 部署发生在 Email Routing 启用之前 → `wrangler deploy` 失败。修复：默认注释掉 `send_email` binding（与上游模板对齐），Resend 用户走 `RESEND_TOKEN` secret 不需要该 binding；如确需 Cloudflare 原生 SEND_MAIL，TOML 注释说明手动取消注释步骤。
- **[P2] Wrangler 仅使用 deprecated `CF_*` 环境变量**：Cloudflare 当前文档推荐 `CLOUDFLARE_API_TOKEN` / `CLOUDFLARE_ACCOUNT_ID`，`CF_*` 已被 Wrangler 4.x 标记为 deprecated。修复：新增 `_email_export_wrangler_env` helper 同步双导两套变量；`14c` collect / `14d` prepare / `14e` uninstall 三处调用。`CF_*` 保留给内部 `_email_cf_api` 使用，对外（wrangler 命令）走新版。
- **[P2] 邮箱地址前缀展示与上游实际行为不一致**：上游 Worker 直接把 PREFIX 拼到 local-part 前面（如 `tmpfoo@example.com`），脚本却展示成 `tmp.foo@example.com`。修复：`_email_deploy_render_toml` 写入 `wrangler.toml` 时自动给 `PREFIX` 末尾补 `.`（用户已带点则不重复），最终行为与展示一致。
- **[P3] `tests/smoke_remote.sh` Test 4 假阴性**：原写法用非交互管道抓 `read -p` prompt，但 Bash 非交互模式不输出 prompt，菜单实际已正确显示却报 FAIL。修复：改为静态 `grep '请选择功能 \[0-12\]:' dist/v4-built.sh` 和反断言 `"13\. 备份与恢复"` 不存在。

### Changed (review #3 — 历史保留)
- **Reality / Realm 安装链路在 UFW 未启用时新增交互引导**（选项 C）。`firewall_apply_reality_port` / `firewall_apply_realm_port` 返回 `2`（UFW 未安装/未启用）时，安装流程会询问用户是否跳转 `ufw_setup` 完成 UFW 安装与启用，启用成功后自动重试端口放行；用户拒绝或仍未生效时仅 `print_warn` 不中断安装。仅 reality 路径走此交互，`firewall_allow_tcp_port` 通用 helper 仍保持"只追加规则、不启用 UFW"的安全默认（review #3 行为）。
  非交互终端（无 tty）下完全跳过 confirm，保留 print_warn 行为，便于自动化部署。
  影响文件：`modules/15-singbox-reality.sh`（两处 `firewall_apply_*_port` 调用点）。

### Fixed (review #4 历史保留)
- **[P1] ADMIN_PASSWORDS secret 双重 JSON 化导致后台登录失败**：`14c-email-deploy.sh:377` 和 `14d-email-manage.sh:61` 原写法 `jq -nc --arg p "$pw" '[$p] | tostring'` 输出字符串字面量 `"[\"abc\"]"`，写入 Worker secret 后上游 `JSON.parse(c.env.ADMIN_PASSWORDS)` 得到的是**字符串**而非数组，`.filter()` 不可用 → `/admin` 永远登录失败。修复：去掉 `| tostring`，secret 直接写 JSON 数组字面量 `["abc"]`。
- **[P1] 自定义 Worker 名时 Pages Functions 仍指默认 worker**：上游 `pages/wrangler.toml` 中 `[[services]] service = "cloudflare_temp_email"` 硬编码，自定义 Worker 名时前端 `/api`、`/admin` 等请求会打到不存在的 Worker。修复：`_email_deploy_pages` 在 `pnpm install` 前 sed 同步 `service = "$EMAIL_WORKER_NAME"`。
- **[P1] partial 状态下"重新部署"覆盖旧 state，永久丢失可回收资源 ID**：半成品菜单原"1. 重新部署（覆盖现有 state）"会重新生成 D1/Pages 名并写新 state，旧 D1_ID / DNS record_id 全丢，事后无法精准回收。修复：(a) `menu_email` partial 分支把"强制卸载"提到第 1 项（默认推荐），"重新部署"降为第 2 项并明确警告"会生成新资源名"；(b) `email_deploy` 入口检测 partial 时打印旧资源清单 + 强警告，确认覆盖后**自动备份**旧 state 到 `${EMAIL_STATE_FILE}.bak.<YYYYMMDD-HHMMSS>`（mode 600）；(c) 新增 `email_state_backup` helper（`14a-email-state.sh`）。
- **[P2] Cloudflare API query 参数未 URL encode**：`zones?name=$domain`、`dns_records?type=$type&name=$name` 直接拼接，IDN/特殊字符场景不稳。修复：新增 `_email_cf_urlencode`（基于 `jq @uri`，无 jq 时裸值回退）；`_email_cf_zone_id_by_name` 与 `_email_cf_dns_find_ids` 调用点改走 encode。
- **[P2] 卸载成功日志里的域名被清空**：`email_state_clear` 会重置 `EMAIL_DOMAIN`，随后 `log_action "fully uninstalled: $EMAIL_DOMAIN"` 写入空值。修复：先 `local _log_domain="${EMAIL_DOMAIN:-unknown}"`，清 state 后再用该副本写日志。

---

## [v14.1] — 2026-05-24

本版本完成一次大规模重构，跨多轮 code review 修正 22 个问题。下列按问题类型分类。

### Removed
- **备份模块整体删除**（`modules/12-backup.sh`、`13-menus.sh` 菜单项 `13. 备份与恢复`、`--backup` CLI 入口、`BACKUP_*` 常量、`build.sh` 数组、README 备份章节）。原因：实测发现脚本无法对大部分功能做有效备份，删除避免误导用户。

### Added
- **临时邮箱模块（14-email）重构为 6 文件子模块**：
  - `14a-email-state.sh` — state 持久化 + Token 隐藏输入 + 日志包装 + admin 密码落盘
  - `14b-email-cf.sh` — Cloudflare API 封装（jq 解析、统一错误处理）
  - `14c-email-deploy.sh` — 部署主流程
  - `14d-email-manage.sh` — 改管理员密码 / 改 DOMAINS / 配置 Resend / 升级 / 重新部署
  - `14e-email-uninstall.sh` — 按 state 精准回收 Worker/Pages/D1/DNS/Catch-all
  - `14-email.sh` — 三态菜单（未部署 / 部署未完成 / 已部署）
- **state 文件** `/etc/server-manage/email/state.conf`（mode 600 root:root）— 持久化全部 27 个字段（含 `EMAIL_CF_ACCOUNT_ID`、`EMAIL_D1_ID`、各 DNS record_id 等），用于精准升级与卸载。
- **`firewall_ensure_active` 引导（已被 review #3 撤销）** — 详见下方"撤销/调整"。
- **`_sshd_set_directive`**（`01-utils.sh`）— 统一处理 sshd_config 配置项：drop-in 冲突警告 + 注释行替换 + 未命中追加。
- **D1 数据库随机后缀** `temp-email-$(openssl rand -hex 3)` 避免账户内多次部署撞名。
- **D1 全量 migration**：除 `schema.sql` 外按字母序应用 `db/*-patch.sql`，state 记录已应用列表，升级时仅跑新增 patch。
- **Email Routing catch-all 自动配置**：`_email_cf_email_routing_enable` + `_email_cf_catch_all_to_worker`，无需 Dashboard 手动操作。
- **多 Cloudflare Account 选择**（`_email_deploy_pick_account`）：Token 可见多个账户时强制让用户选编号，绝不取第一个；唯一账户时静默选用。
- **Pages 项目名随机后缀** `temp-email-pages-$(openssl rand -hex 3)` 彻底避免撞名。
- **Worker 名冲突检测**（`_email_cf_worker_exists` + `_email_deploy_pick_worker_name`）：同名存在时三选项交互（取消/换名/覆盖），不再静默覆盖。
- **DNS label 严格校验**（`_email_validate_dns_label`）：邮箱 API/前端/地址前缀循环校验直到合法。
- **部署中途失败的回收入口**：`menu_email` 新增 `partial` 状态分支，state 文件存在但 `EMAIL_INSTALLED=0` 时显示"强制卸载"入口，可回收已创建的 D1/Worker/Pages/DNS 残留。

### Fixed
- **[P0] `_cf_api` / `_cf_dns_delete` 命名冲突**：邮箱模块 14b 与已有 09b Web 模块同名定义，build 拼接后邮箱版覆盖 Web 版，导致 Web/Reality 的 Cloudflare 调用全废。修复：14b/14c/14d/14e 内全部 `_cf_*` 改名为 `_email_cf_*`。
- **[P0] 邮箱固定资源名误覆盖**：原 `cloudflare_temp_email` / `temp-email-pages` 全账户唯一名硬编码，可能覆盖用户已有同名 Worker。修复：Worker 检测+交互、Pages 随机后缀。
- **[P0] cron 路径失效**：定时备份用 `$0` 解析路径，`bash <(curl ...)` 场景下指向 `/dev/fd/63`，定时任务必失效。修复：随备份模块删除。
- **[P1] 主配置文件 source 前未校验**：`/etc/${SCRIPT_NAME}.conf` 直接 `source`，能写入该文件的进程可 root RCE。修复：source 移到 01-utils.sh 末尾，先经新版 `validate_conf_file`（owner=root + mode≤755 + 严格 value 格式，禁未转义 `$(`/`${`/`` ` ``）校验。
- **[P1] `validate_conf_file` 校验不足**：原版仅检查行首 `KEY=`，`KEY="$(cmd)"` 仍通过。修复：禁止双引号内未转义命令替换/变量扩展；新增 owner/mode 检查。
- **[P1] UFW 安装/重置可能放行错 SSH 端口**：`refresh_ssh_port` 只读 `/etc/ssh/sshd_config`，未读 `sshd_config.d/*.conf`。修复：优先 `sshd -T` 解析；回退时也合并 drop-in。
- **[P1] ddns/geoip cron 脚本裸 `source`**：生成的 root cron 脚本直接 source 用户配置，配置被替换可 RCE。修复：嵌入白名单 KEY + 严格双引号字面量正则 + stat owner/mode 校验。
- **[P1] Web 域名清理 glob 越界**：`origin.*.conf` 通配会删除其他域名的 DDNS 配置。修复：精确匹配 `origin.${domain}.conf` 与 `origin.${root_part}.conf`，root_part 与 domain 不同才删。
- **[P1] 临时邮箱部署中途失败遗留 D1**：原卸载入口仅在 `EMAIL_INSTALLED=1` 时显示，半成品状态无法精准回收。修复：`email_uninstall` 入口改为 state 文件存在即可清理；菜单新增 `partial` 三态显示"强制卸载"入口。
- **[P1] CF_ACCOUNT_ID 未持久化**：原管理/卸载在环境变量缺失时取第一个 Account，多账户场景可能误操作其他账户。修复：state 新增 `EMAIL_CF_ACCOUNT_ID` 字段；管理/卸载优先读 state，缺失时强制让用户选。
- **[P1] `ssh_change_port` 不读 drop-in**：sed 改主配可能被 drop-in 覆盖，但脚本仍删旧 UFW 规则。修复：改前 `refresh_ssh_port` 拿真实端口 + 检测 drop-in 让用户选；改后用 `sshd -T` 比对 `effective_port` 是否生效，不一致则回滚且不动 UFW。
- **[P2] SSH `eval $cmd` 命令注入**：密钥生成时备注 `comment` 走 `eval`，可注入。修复：改数组调用 `"${args[@]}"`。
- **[P2] SSH 禁用密码/Root 登录 sed 不追加**：原文件没有对应行时显示成功但未生效。修复：用新增的 `_sshd_set_directive`（替换或追加 + drop-in 冲突警告）。
- **[P2] `$NGINX_CONF_PATH` 未定义引用**：反代完成页打印未定义变量。修复：改为字面路径 `/etc/nginx/sites-available/${DOMAIN}.conf`。
- **[P2] 临时邮箱密码三次明文回显**：原 admin password 在生成时 + 确认页 + 汇总打印 3 次。修复：仅最终汇总打印 1 次，并保存到 `/root/.email-admin.txt` mode 600。
- **[P2] CF Token / Resend Token 输入回显**：原 `read -e`。修复：`read -s` 隐藏，反馈仅显 `email_mask_token` 首尾 4 位掩码。
- **[P2] 邮箱前缀字符未校验**：API/前端/地址前缀直接拼域名和 wrangler.toml。修复：循环校验直到匹配 DNS label 正则 `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`。

### Changed
- **UFW 联动行为变更**（review #3 决策）：`firewall_allow_tcp_port` 改回"只追加规则"——UFW 缺/未启用时返回 `2` + 提示"请进【防火墙管理】菜单"，**不再**在业务流程里自动 `install_package ufw`、`ufw default deny`、`ufw enable`。设计原则：业务模块不重置/启用本地防火墙，避免与云安全组、用户已有规则、SSH 端口产生冲突。
- 邮箱模块 `ADMIN_PASSWORDS` 从 `wrangler.toml` 的 `[vars]` 改为通过 CF API 直接 `_email_cf_worker_secret_put` 写入 secret。改密码不再需要重新部署整个 Worker。
- 临时邮箱使用 `jq` 替换原 7 处 `python3 -c "import json"`，统一依赖路径。
- 部署日志统一写入 `/var/log/server-manage-email.log`，菜单新增"查看部署日志"项；`email_run` 包装失败时自动 `tail -n 30`。

### Tests
- 新增 `tests/smoke_email.sh`（14 项 PASS）：state 写读 roundtrip、危险字符不触发命令、token mask、`_email_cf_api` 缺 token 安全返回、40 个新函数齐备等。
- 新增 `tests/smoke_p0p1p2.sh`（35 项 PASS）：覆盖本次所有 P0/P1/P2 修复点的回归断言。
- `tests/reality_module_static_test.sh` 同步：移除"`13. 备份与恢复`"断言，新增反断言（备份菜单已删）。
- 远程冒烟测试在 Debian 12 实机（HK-Alice-1）跑通：35 + 14 = **49/49 PASS**。

---

## 历史版本

早期版本未维护 CHANGELOG。后续如需归档可补充。
