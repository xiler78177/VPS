# Reality 节点 + CDN 优选 IP 提速 —— 完整使用步骤

给现有 sing-box Reality 节点**加挂一条 CDN+优选 IP 链路**，专治晚高峰「国内→落地 IP」那一跳被运营商干扰。
Reality 直连链路（灰云）原样保留，CDN 链路（橙云+优选 IP）并存，客户端两条都装、按需切。

整个方案分三块，按 **A → B → C** 顺序做一次，之后由 cron 全自动轮换：

| 块 | 跑在哪 | 干什么 | 频率 |
|---|---|---|---|
| **A** 源站向导 | 落地 VPS（海外） | 加挂 CDN 回源链路（签证书+nginx+合并 WS 入站+橙云 DNS+Origin Rule） | 一次 |
| **B** 优选 IP 采集 | **国内机** | 跑 CloudflareSpeedTest 选当前最优 CF 边缘 IP | 定时 |
| **C** 回写 sub-store | **国内机** | 把优选 IP PATCH 进一条专用订阅的 server 字段 | 定时（紧跟 B） |

> 为什么 B/C 必须在国内机：CloudflareSpeedTest 测的是「本机→各 CF 边缘」的延迟/速度，
> 海外落地机测出来的最优 IP 对国内客户端无意义。这是方案成立的前提。

---

## 前置条件

- 一台已经装好 Reality 落地机的海外 VPS（本仓库菜单 `Reality 节点 → 1. 安装/重装落地机`）。
- 一个托管在 Cloudflare 的域名 + 一个 CF API Token（权限：`Zone:Read` + `DNS:Edit`；
  Origin Rules 需要 `Zone:Edit` 或在面板手动加）。
- 一台能跑脚本的**国内**机器（软路由/NAS/国内小鸡都行），装有 `bash` `curl` `jq` `awk`。
- 一个自托管的 sub-store（本方案以公网 `https://<域名>/<secret前缀>` 直连为例）。

---

## A. 落地机：加挂 CDN 链路（在海外 VPS 上，一次）

1. 跑主脚本，进入 `Reality 节点` 菜单，选 **`10. 加挂 CDN 链路（橙云+优选IP，治晚高峰）`**。

2. 按提示操作：
   - **CF API Token**：粘贴（输入不回显）。
   - **CDN 链路域名**：建议用与 Reality 节点不同的新子域，例如 `cdn-us-01`。Token 能列出 zone 时只需填前缀。
   - **节点名称**：默认 `cdn-<域名前缀>`，回车即可。
   - 确认配置概要后回车开始。

3. 向导自动完成 6 步（全自动，无需干预）：
   1. **DNS-01 签证书**（橙云后面必须 DNS-01，HTTP-01 会被橙云拦）。证书落 `/root/cert/<域名>/`，并装好自动续签 hook。
   2. **部署 nginx 回源站**：在回源端口（默认 `8443`）做 TLS 终止；隐秘 WS path 反代到内部端口，其余路径回 444。
   3. **合并重渲 sing-box**：把 VLESS-WS 入站作为额外 inbound 渲染进 `config.json`，与 Reality 入站并存。
   4. **CF 橙云 DNS**：把 CDN 域名同步为橙云 A/AAAA（proxied=true）。
   5. **CF Origin Rule**：因 Reality 已占 443，自动建规则让 CF 回源到 `8443`。
   6. **放行** `8443/tcp`。

4. 完成后屏幕打印 CDN 客户端链接（此时 server 暂为域名）。记下这三个值，B/C 配置要用：
   - `CDN_UUID`（= 链接里 `vless://` 后、`@` 前那段）
   - `CDN_DOMAIN`（你填的 CDN 域名）
   - `CDN_WS_PATH`（链接 `path=` 的值）

   也可随时在 `Reality 节点 → 3. 查看/修改节点信息 → 1. 查看节点信息` 里重新看到 CDN 段。

> ⚠️ 若 Token 没有 Origin Rule 权限，向导会提示你手动到 CF 面板 `规则 → Origin Rules`
> 把该域名回源端口改为 `8443`。不设置的话 CF 默认回源 443 会撞到 Reality。

---

## B + C. 国内机：定时优选 + 自动回写（一次配置，长期自动）

1. **装 CloudflareSpeedTest**（XIU2/CloudflareSpeedTest），把二进制放进 PATH（叫 `CloudflareST` 或 `cfst`），
   或稍后在配置里用 `CFST_BIN` 指定路径。项目地址：<https://github.com/XIU2/CloudflareSpeedTest>

2. **把本目录 `scripts/cdn-preferip/` 拷到国内机**（整个目录即可），然后：

   ```bash
   cd cdn-preferip
   cp cdn-preferip.conf.example cdn-preferip.conf
   chmod +x preferip-collect.sh preferip-push.sh preferip-cron.sh
   ```

3. **编辑 `cdn-preferip.conf`**，填 A 步记下的值：

   ```ini
   SUBSTORE_BASE="https://sub.你的域名/你的secret前缀"   # 不含 /api
   SUBSTORE_SUB_NAME="cdn-preferip"                      # 专用订阅名（C 只动这一条）
   CDN_UUID="<A 步的 UUID>"
   CDN_DOMAIN="<A 步的 CDN 域名>"
   CDN_WS_PATH="<A 步的 path>"
   CDN_NODE_NAME="cdn-us-01"
   CFST_TOP_N="1"                 # 取前 N 个最优 IP
   CFST_EXTRA_ARGS="-dn 10 -tl 200"
   KEEP_ON_EMPTY="true"           # 优选无结果时不推空值（强烈建议 true）
   ```

4. **先手动跑一次串联脚本**，确认全链路通：

   ```bash
   ./preferip-cron.sh
   ```

   - 第一次跑：C 发现专用订阅不存在 → 自动 `POST` 新建一条 local 订阅。
   - 之后每次：C `PATCH` 这条订阅，只替换 server 为最新优选 IP（host/sni 永远是真实域名）。
   - 成功后到 sub-store 面板能看到名为 `cdn-preferip` 的订阅，里面是 CDN 节点。

5. **把客户端订阅这条专用订阅的下载链接**。以后客户端刷新订阅，就会自动拿到最新优选 IP。

6. **配置 cron 定期轮换**（优选 IP 时效约几天，建议每天晚高峰前刷一次）：

   ```bash
   crontab -e
   ```
   加一行（路径换成实际路径）：
   ```cron
   30 20 * * * /path/to/cdn-preferip/preferip-cron.sh >> /var/log/cdn-preferip.log 2>&1
   ```
   每天 20:30 自动优选并回写；优选无结果时保留现状、不推空值。

---

## 数据流总览

```
[国内机] 20:30 cron
   │  B: CloudflareSpeedTest 选最优 CF 边缘 IP
   ▼
   │  C: PATCH 专用订阅 → server=优选IP, host/sni=cdn域名
   ▼
[sub-store]  专用订阅 cdn-preferip 内容更新
   │
   ▼
[客户端] 刷新订阅 → 拿到新优选 IP
   │  连 优选IP:443 (VLESS-WS-TLS, Host=cdn域名)
   ▼
[CF 橙云边缘] ──CF骨干──▶ [落地 VPS nginx :8443 TLS终止] ──▶ [sing-box WS 入站 127.0.0.1:inner] ──▶ 出网
```

Reality 直连链路（`落地IP:443` 灰云）始终并存，不受影响；晚高峰走 CDN，平峰可切回直连。

---

## 故障排查

| 现象 | 排查 |
|---|---|
| `preferip-collect.sh` 报找不到 CloudflareSpeedTest | 装好二进制并加进 PATH，或在 conf 里设 `CFST_BIN=/full/path` |
| C 报 `PATCH 请求失败` | 检查 `SUBSTORE_BASE`（含 secret 前缀、不含 `/api`）、网络、HTTPS |
| 客户端连不上 CDN 节点 | CF 面板确认域名橙云已开 + Origin Rule 回源端口=8443；落地机确认 `8443/tcp` 已放行 |
| 优选总是空 | 国内机网络问题或 `CFST_EXTRA_ARGS` 阈值太严（放宽 `-tl`/`-sl`） |
| 想暂时停掉 CDN | 落地机菜单 `11. 卸载 CDN 链路`（不影响 Reality 直连） |

---

## 安全说明

- sub-store 的 secret 前缀即事实鉴权，**务必全程 HTTPS**，脚本不会把 secret 写进日志。
- C 只操作 `SUBSTORE_SUB_NAME` 这一条专用订阅，不会碰你已有的其它订阅。
- CDN 回源用真实证书走 Full(strict)，CF↔源站这一段是加密的。
