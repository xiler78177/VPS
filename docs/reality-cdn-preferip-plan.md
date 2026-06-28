# Reality 节点 + CDN 优选 IP 提速方案（设计文档）

> 状态：**已实现并持续优化**。A 块已集成到 `modules/15-singbox-reality.sh`，B/C 块在 `scripts/cdn-preferip/` 独立运行。
> 目标读者：本仓库维护者（复盘设计取舍、继续做回归优化）。

## 1. 背景与问题定位

现网节点为 **sing-box Reality（VLESS + xtls-rprx-vision，直连，CF 灰云 DNS-only）**，
晚高峰速度不稳定。经确认，瓶颈在 **「国内 → 落地机公网 IP」这一跳被运营商干扰/QoS**，
而非落地机本身带宽或国际出口拥塞。拓扑为**单机直连落地**。

针对这个瓶颈，调研过两条路：

1. **CDN + 优选 IP**：域名开 CF 橙云，用 `CloudflareSpeedTest` 选出当前国内到 CF 边缘最快的 IP，
   客户端连这个优选 IP，流量经 CF Anycast 边缘 → CF 骨干 → 回源到落地机。
2. **改用 Hysteria 2（QUIC/UDP）**。

### 1.1 结论：选方案 1，排除方案 2

- **方案 1 对症**。它的作用恰好是**把那条被干扰的「国内→落地IP」直连路径整段换掉**：
  国内 → CF 边缘（优选 IP，走 Anycast，海量边缘可选）→ CF 骨干（通常不被运营商 QoS）→ 回源。
  被干扰的那一跳被绕开了。
- **方案 2 逆向**。Hy2 走 UDP，国内晚高峰对国际 UDP 的 QoS/限速通常比 TCP 更狠（UDP 易被当
  视频/游戏流量降级），且 UDP 大流量更容易触发 IP 封锁。Hy2 也**无法套 CF 免费版橙云**
  （CF 免费/Pro/Biz 不代理任意 UDP，UDP 代理是企业版 Spectrum），与「优选 IP」方案天然冲突。
  故排除。

### 1.2 关键认知（避免走弯路）

- **Reality 不能套 CF 橙云**，必须保持灰云直连。原因：Reality 依赖客户端 TCP 流**原样直达**
  落地机以完成「偷证书指纹」的 TLS 握手；CF 橙云是 TLS 终止代理，会解包并丢弃非 HTTP 的
  Reality 流量。所以 `CloudflareSpeedTest` 优选的 CF 边缘 IP 对现有 Reality 节点**完全无效**
  （流量根本不经过 CF 边缘）。**要吃到优选 IP 的红利，必须新增一条能套橙云的协议链路。**
- **本方案是「并存」而非「替换」**：Reality 链路原样保留（直连，适合不被干扰时段 / 备用），
  新增一条 **CDN 链路**（VLESS-WS-TLS，橙云，优选 IP，主打晚高峰）。客户端两条都装，按需切换。
- **优选 IP 不改 DNS**。域名 A 记录继续指向 CF（橙云）即可。优选的做法是：
  **客户端节点的「服务器地址」字段填优选出的 CF 边缘 IP，而 SNI / Host 头继续填真实域名**，
  CF 靠 Host 头路由回你的源站。所以「自动更新」更新的是**订阅里节点的 server 字段**，不是 DNS。
- **`CloudflareSpeedTest` 必须在国内侧机器跑**。它测的是「测试发起方 → 各 CF 边缘 IP」的延迟/速度。
  在海外落地机上跑，测出来是「海外→边缘」，与国内客户端的最优边缘无关，结果作废。
  已确认：**有国内侧机器可跑**，自动化以此为前提。

## 2. 目标架构（Reality 与 CDN 链路并存）

```
                        ┌─ [保留] Reality 链路（直连，灰云 DNS-only）
                        │     客户端 → 落地IP:443  (VLESS xtls-rprx-vision)
   落地 VPS（海外）─────┤
                        └─ [新增] CDN 链路（橙云 + 优选 IP）
                              客户端 → CF优选IP:443 → CF边缘 → CF骨干 → 回源
                              回源落点：nginx :8443（cdn.域名 真实证书，DNS-01 签发；CF Origin Rule 改写回源端口）
                                        └ location /<隐秘路径>  →反代→ 127.0.0.1:<内部端口>
                                                                         (sing-box VLESS-WS 入站)
                                        └ location /            → 444 直接断开（避免异常路径落到代理）

   国内侧机器：CloudflareSpeedTest 定时优选 → 取最优 IP → 经 sub-store API 刷进订阅 → 客户端拉取即换 IP
```

### 2.1 协议选型：VLESS + WebSocket + TLS（**不用 VMess**）

| 维度 | VMess+WS+TLS（常见旧教程） | **VLESS+WS+TLS（本方案采用）** |
|---|---|---|
| 自带加密 | 有（外层已 TLS，**冗余**） | 无，靠外层 TLS，更轻 |
| 性能 | 双重加密，CPU 略高 | 单层，延迟/CPU 更低 |
| 时钟依赖 | 依赖客户端时钟，偏差会握手失败 | 无时钟依赖 |
| 与本仓库栈 | 需引入 v2ray/xray 二进制 | **sing-box 原生支持，零新增二进制** |

为什么是 WS 而非 gRPC：WS 在 CF 橙云上兼容性/稳定性最成熟，gRPC 在部分 CF 线路上有兼容坑。
WS 足够。

### 2.2 为什么回源要走 nginx（而不是 sing-box 直接监听 443）

复用现有 09 web 栈（已确认决策）。Reality 直连继续占用 443；CDN 回源由 CF Origin Rule 改写到 nginx 的独立 TLS 端口（默认 8443）：
- 用真实域名证书做 TLS（CF 橙云 ↔ 源站这一段是「Full (strict)」加密，需要有效证书）。
- 把隐秘 WS 路径反代到 sing-box 内部端口，其余路径 `return 444`。
- 与现有 Emby/Alist 等反代站、Origin Rules（菜单 10-12，解决 443 被封）共存。

## 3. 与现有代码的接口与约束（已核对源码）

落地落点都已在仓库里核对过，实现时直接复用：

- **sing-box 配置是「整体重渲染」**——这是最关键的约束。
  `reality_render_singbox_config()`（`modules/15-singbox-reality.sh:257`）每次都把
  `REALITY_SINGBOX_CONFIG=/etc/sing-box/config.json`（`00-constants.sh:89`）整个重写成
  「仅 Reality 入站 + direct 出站」。`reality_rotate_user` / `reality_rotate_key` / 改名 / 重装
  都会触发重渲染。
  **因此 CDN 的 VLESS-WS 入站不能简单追加进同一个 config.json**，否则任意 Reality 操作都会把它冲掉。
  **设计决定**：让渲染函数在「CDN 链路已启用」时，把 WS 入站作为**额外 inbound 一并渲染进去**
  （读取一份独立的 CDN state，渲染时合并），而不是事后追加。这样 Reality 的任何重渲染都会
  带上 WS 入站，不会互相冲掉。`reality_apply_singbox_config()`（:502，带 `sing-box check` +
  备份 + 重启回滚）原样复用。
- **证书签发：DNS-01 已就绪**。`web_add_domain`（`09c-web-domain.sh:3`）用
  `certbot certonly --dns-cloudflare --dns-cloudflare-credentials "$CLOUDFLARE_CREDENTIALS"`（:222）
  签发，证书落 `CERT_PATH_PREFIX=/root/cert/<域名>`（`00-constants.sh:56`）。
  **DNS-01 是橙云后面签证书的正确方式**（HTTP-01 会被橙云拦截）。`cdn.域名` 直接复用此流程。
- **反代：复用 09d**。`web_reverse_proxy_site`（`09d-web-proxy.sh:55`，「通用反代」模板）已含
  `Upgrade/Connection "upgrade"` 的 WebSocket 头，可作为 CDN 站点 nginx 配置的基底
  （需要再加一个 `location /<隐秘路径>` 指向内部端口，`location /` 指向伪装站/返回 444）。
  TLS 块走 `_nginx_tls_http2_block` + `snippets/ssl-params.conf`，部署走 `_nginx_deploy_conf`
  （`nginx -t` 通过才 reload）。
- **CF DNS 橙云**。现有 `cf_dns_sync_node_grey` 是**灰云**（proxied=false，给 Reality 用）。
  CDN 域名需要**橙云**（proxied=true）。需新增一个橙云同步调用 / 参数；
  CF token 输入复用 `reality_prompt_cf_token`。
- **Origin Rules 可选叠加**。若客户端所在网络 443 被运营商封，菜单 10（`web_cf_origin_rule_create`，
  `09b-web-cloudflare.sh:334`）可让客户端用 2053/2083/2087/2096 等 CF 支持的备用端口连边缘，
  CF 仍回源到 443。与本方案正交，可叠加。

## 4. 分块交付状态

三块**可独立交付、独立验证**。A 已进入主菜单；B/C 作为独立脚本给国内机使用。

### A. 源站向导（落地机，本仓库主体）

`15-singbox-reality.sh` 已新增「为 Reality 节点加挂 CDN 链路」向导：

1. 输入 `cdn.域名` 与 CF token → `web_add_domain` 式 DNS-01 签证书。
2. 选定隐秘 WS path（随机生成，如 `/<16位随机>`）与内部端口（127.0.0.1，随机高位端口）。
3. 渲染 nginx 站点：`location /<path>` 反代到内部端口（带 WS 头）；`location /` 伪装站。
4. **改造 `reality_render_singbox_config`**：当 CDN state 存在时，额外渲染一个
   `vless` + `transport:{type:"ws", path}` 入站，listen `127.0.0.1:<内部端口>`。
   经 `reality_apply_singbox_config` 应用（自带校验/回滚）。
5. CF DNS：`cdn.域名` 同步为**橙云 A/AAAA**。
6. 产出客户端链接/JSON（`vless://...?type=ws&path=...&host=cdn.域名&sni=cdn.域名`，
   server 字段先填 `cdn.域名`，优选后由 C 替换为优选 IP）。
7. 落一份 CDN state（path/端口/域名/uuid 等），供重渲染与 C 读取。

**验证**：`sing-box check` 通过、`nginx -t` 通过、本机 `curl --resolve` 打 WS 握手、
Reality 链路不受影响（rotate key 后 WS 入站仍在）。新增对应 smoke 用例。

### B. 优选 IP 采集（国内机，独立子脚本）

封装 `XIU2/CloudflareSpeedTest`：定时跑 → 输出 TopN 最优 IP（含延迟/速度）→ 写出结果文件。
可作为本仓库独立脚本（不进 v4-built.sh 主菜单，或单列一个轻量入口），在国内机 cron 执行。

**验证**：能产出稳定的 IP 列表；异常（无结果/超时）有兜底，不推空值。

### C. sub-store 自动更新对接（自托管，已实测）

**部署实测记录**（已脱敏，Debian 12 aarch64）：

- sub-store 跑在 Docker（`xream/sub-store:latest`），后端 3000 → 宿主 **`127.0.0.1:3001`**、
  前端 3001 → 宿主 `127.0.0.1:3002`，**仅回环监听**，由 nginx `sub.example.com.conf` 反代
  （`location /` → `127.0.0.1:3002`）。
- **API secret 前缀**：`SUB_STORE_BACKEND_PREFIX=/<secret>`（即 URL 里的密钥段）。
  真实 API base = `http://127.0.0.1:3001/<secret>/api`（本机直连）或
  `https://sub.example.com/<secret>/api`（公网）。
- 已实测 `GET …/api/subs` → **HTTP 200**，返回 19 条订阅，绝大多数 `source=local`
  （节点内联在订阅里，`url_len=0`），4 条 `source=remote`。
- 容器自带 `SUB_STORE_BACKEND_SYNC_CRON=*/30 * * * *`（每 30 min sync remote 订阅）
  与 `SUB_STORE_BACKEND_UPLOAD_CRON=55 23 * * *`。

已核对 sub-store 后端真实路由（`backend/src/restful/`，已与上面实测对齐）：

- `GET  /api/subs`            列出全部订阅
- `GET  /api/sub/:name`       取单条订阅
- **`PATCH /api/sub/:name`**  更新单条订阅 ← **着力点**
- `DELETE /api/sub/:name`
- 路由全在 secret 前缀 + `/api` 下；`SUB_STORE_CORS_ALLOWED_ORIGINS` 是 CORS 来源过滤（非鉴权）。

**设计（已定）**：**新建一条专用 local 订阅**（不动现有 19 条），内容为 CDN 节点（VLESS-WS-TLS）。
B 产出最优 IP 后，脚本对这条订阅 `PATCH /api/sub/<name>`，把节点 server 字段替换为优选 IP
（保留 host/sni = 真实域名 `cdn.域名`）。客户端订阅该专用订阅的下载链接，刷新即得新 IP。

- **C 脚本的落点**：跑在 sub-store 所在机器上最省事——直连 `127.0.0.1:3001` + secret 前缀，
  无需公网、无需穿透。但**优选 IP 必须来自国内机（B）**，所以 B→C 之间要把 IP 列表
  从国内机送到 sub-store 所在机器（或 C 直接在国内机跑、走公网 `https://sub.example.com/<secret>/api` PATCH）。
  二选一在实现 C 前定（见下）。
- **鉴权**：secret 前缀即事实鉴权；走公网 PATCH 时务必全程 HTTPS，secret 不入日志。

## 5. 风险与取舍

- **多一跳延迟**：客户端→CF边缘→回源，比直连多一跳。但你的瓶颈是直连那跳被干扰，
  绕开后**晚高峰净收益为正**；非高峰时段直连的 Reality 可能更快，故两条并存、客户端按需切。
- **CF 免费线路晚高峰也可能拥堵**：优选 IP 缓解但非根治；TopN + 定时刷新是应对手段。
- **优选 IP 时效**：通常几天，故必须有 B+C 的自动化，否则手动维护成本高。
- **回源端口/伪装**：源站 `location /` 必须像个正常站点（或 444 直接断开），
  避免裸 IP/异常路径被主动探测识别出代理特征。
- **安全**：sub-store API 默认无强鉴权（CORS 仅来源过滤）。C 的脚本与 sub-store 之间
  应走内网/localhost 或加反代鉴权，避免订阅接口公网裸奔。

## 6. 下一步

本文档定稿后，按 A → B → C 顺序实现，每块独立提交 + 验证。

- **A 落地前需确认**：CDN state 的字段设计、`reality_render_singbox_config` 的改造方式（合并渲染）
  是否如 §3、§4.A 所述。
- **C 落地前需定**：B→C 的 IP 传输路径——C 跑在 sub-store 所在机器直连 `127.0.0.1:3001`（需把国内机 B 的
  优选结果送过来），还是 C 直接在国内机跑、走公网 `https://sub.example.com/<secret>/api` PATCH。
