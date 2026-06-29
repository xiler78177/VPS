# Reality 节点 + CDN 优选 IP 提速 —— 完整使用步骤

给现有 sing-box Reality 节点**加挂一条 CDN+优选 IP 链路**，专治晚高峰「国内→落地 IP」那一跳被运营商干扰。
Reality 直连链路（灰云）原样保留，CDN 链路（橙云+优选 IP）并存，客户端两条都装、按需切。

整个方案分三块，按 **A → B → C** 顺序做一次，之后由 cron 全自动轮换：

| 块 | 跑在哪 | 干什么 | 频率 |
|---|---|---|---|
| **A** 源站向导 | 落地 VPS（海外） | 加挂 CDN 回源链路（签证书+nginx+合并 WS 入站+橙云 DNS+Origin Rule） | 一次 |
| **B** 优选 IP 采集 | **国内机** | 跑 CloudflareSpeedTest 选当前最优 CF 边缘 IP | 定时 |
| **C** 生成节点文件 | **国内机** | 把优选 IP 生成到本地节点文件（可选同步入口域名 DNS） | 定时（紧跟 B） |

> 为什么 B/C 必须在国内机：CloudflareSpeedTest 测的是「本机→各 CF 边缘」的延迟/速度，
> 海外落地机测出来的最优 IP 对国内客户端无意义。这是方案成立的前提。

---

## 前置条件

- 一台已经装好 Reality 落地机的海外 VPS（本仓库菜单 `Reality 节点 → 1. 安装/重装落地机`）。
- 一个托管在 Cloudflare 的域名 + 一个 CF API Token（权限：`Zone:Read` + `DNS:Edit`；
  Origin Rules 需要 `Zone:Edit` 或在面板手动加）。
- 一台能跑脚本的**国内**机器（软路由/NAS/国内小鸡都行），装有 `bash` `curl` `jq` `awk`。
- 一份本地节点输出文件，或由你自己的分发方式读取该文件。

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
   CDN_UUID="<A 步的 UUID>"
   CDN_DOMAIN="<A 步的 CDN 域名>"
   CDN_WS_PATH="<A 步的 path>"
   CDN_NODE_NAME="cdn-us-01"
   CFST_TOP_N="3"                 # 每个地区取前 N 个最优 IP；>1 时可给同地区多节点做 IP 池化
   CFST_COLO_MODE="auto"          # nodes.txt 写了地区码时，按地区码分组优选
   DEFAULT_CF_COLO=""             # 旧格式节点没有地区码时可填默认值，如 HKG；留空=全局优选
   DEFAULT_CF_IP_VERSION=""       # 旧格式节点默认 IP 池；留空/auto=沿用 CFST_IP_FILE，也可填 ipv4/ipv6
   CFST_EXTRA_ARGS="-n 100 -dn 5 -dt 10 -tl 180 -tlr 0 -sl 1"
   CFST_ROUNDS="3"                # 多轮测速次数；>1 可降低单次随机抽样/网络抖动影响
   CFST_PICK_MODE="speed"         # cfst/latency/speed/balanced
   CFST_STAGE2_ENABLE="false"     # true=粗筛后对候选 IP 二阶段复测，更稳但更慢
   CFST_STAGE2_TOP_N="20"
   CFST_STAGE2_ROUNDS="2"
   CFST_IPV6_FILE="/opt/cfst/ipv6.txt"  # 节点写 ipv6 时使用；留空时会尝试从 CFST_IP_FILE 同目录推导
   KEEP_ON_EMPTY="true"           # 优选无结果时不推空值（强烈建议 true）
   MISSING_COLO_POLICY="keep"     # 某地区无结果时：keep保留原server / abort中止 / global回退全局
   PREFERIP_ASSIGN_MODE="round_robin"   # CFST_TOP_N>1 时，同地区节点轮询分配候选池
   PREFERIP_STICKY="true"         # 当前 IP 仍达标且新 IP 没明显更好时，不频繁切换
   PREFERIP_PROBE_ENABLE="false"  # 可选：回写前用 curl --resolve 做真实链路探活
   ```

   如果实际测试发现亚洲方向只有 HKG 稳定，可把亚洲节点的地区码都写成 `HKG`，并用更严格的筛选参数兼顾低延迟和带宽，例如：

   ```ini
   CFST_EXTRA_ARGS="-n 100 -dn 5 -dt 10 -tl 180 -tlr 0 -sl 1"
   CFST_TOP_N="3"
   CFST_ROUNDS="3"
   CFST_PICK_MODE="speed"
   PREFERIP_ASSIGN_MODE="round_robin"
   PREFERIP_STICKY="true"
   ```

   其中 `-tlr 0` 要求零丢包，`-sl 1` 要求下载速度至少 1 MB/s；`CFST_TOP_N=3`
   会保留同地区前 3 个候选 IP，多个同地区节点会轮询分配，避免所有节点压在一个 IP 上。
   当 `PREFERIP_ASSIGN_MODE=round_robin` 且同地区候选 IP 超过 1 个时，轮询分配优先于 sticky，
   这样不会因为历史状态把所有节点继续粘在同一个 IP。
   如果你希望“满足带宽门槛后尽量低延迟”，也可以把 `CFST_PICK_MODE` 改成 `latency`。

   如果你不想依赖客户端及时读取新文件，可以把每个节点再加一个入口域名：

   ```ini
   PREFERIP_SERVER_MODE="dns"   # 或 auto：有 entry 域名就走 DNS 模式
   PREFERIP_CF_API_TOKEN="..."   # Cloudflare API Token
   PREFERIP_DNS_PROXIED="false"  # 入口域名通常保持 DNS only
   ```

   然后把 `nodes.txt` 写成：

   ```text
   香港-example-1-CDN|HKG|entry=prefer-hkg.example.com|vless://...
   ```

   **注意：`entry=` 必须是独立入口域名，不能等于原节点里的 `server` / `host` / `sni` CDN 回源域名。**
   原 CDN 域名要继续保持 Cloudflare 橙云并指向真实源站；入口域名才会被脚本改成 DNS-only 优选 IP。
   `PREFERIP_SERVER_MODE=dns` 下缺少 `entry=` 会直接中止，防止误改原橙云记录。
   如果一个 IPv4 节点和一个 IPv6 节点共用同一个 `entry=`，脚本会同时维护 A + AAAA，
   不会让默认的 `PREFERIP_DNS_DELETE_STALE=true` 互删另一种记录类型。

   这样脚本会把输出文件里的 `server` 写成 `prefer-hkg.example.com`，同时把这条 DNS 记录同步到当前优选 IP。
   客户端即使短时间没读取新文件，也会在 DNS 过期后跟随新 IP。
   `auto` 模式会在节点写了 `entry=` 时自动走这条逻辑，没写则继续走纯 IP 模式。

4. **编辑 `nodes.txt`（多节点推荐）**，给每个节点标注实际落地区域对应的 CF colo/IATA 码：

   ```text
   香港-example-1-CDN|HKG|vless://...
   韩国-example-2-CDN|ICN|vless://...
   日本-example-3-CDN|NRT,KIX|vless://...
   香港-ipv6-example-CDN|HKG|ipv6|vless://...
   ```

   格式为 `备注|CF地区码|vless链接`；如果某台节点要走 IPv6 优选池，写成 `备注|CF地区码|ipv6|vless链接`（也支持紧凑写法 `备注|HKG@ipv6|vless链接`）。地区码用于 B 阶段按组执行 `CloudflareSpeedTest -httping -cfcolo`；C 阶段回写时，每个节点只使用自己地区组/IP 池的优选 IP。旧格式 `备注|vless链接` 仍兼容，但会走 `DEFAULT_CF_COLO` 或全局优选。

5. **先手动跑一次串联脚本**，确认全链路通：

   ```bash
   ./preferip-cron.sh
   ```

   - 每次跑完会生成本地 `preferip.rendered.txt`（可用 `PREFERIP_OUTPUT_FILE` 改名）。
   - 若启用 DNS 入口模式，则会同时同步入口域名的 A/AAAA（host/sni 永远是真实域名）。
   - 脚本会维护本地 `preferip.state.tsv`、`preferip.history.csv` 和 `bad-ip.txt`：
     用于稳态切换、历史追踪和临时黑名单。

6. **把客户端或你的分发程序指向这个本地输出文件**。以后重新生成后，客户端按你的分发方式读取即可；若启用了 DNS 入口模式，短时间不刷新也会在 DNS TTL 后跟上新 IP。

7. **配置 cron 定期轮换**（优选 IP 时效约几天，建议每天晚高峰前刷一次）：

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
   │  B: 按 nodes.txt 的 HKG/ICN/NRT... 分组优选 CF 边缘 IP，可粗筛+二阶段复测
   ▼
   │  C: 候选池分配/稳态切换/可选探活 → 生成本地节点文件
   ▼
[本地文件]  preferip.rendered.txt 内容更新
   │
   ▼
[客户端/分发程序] 读取新文件 → 拿到新优选 IP
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
| C 没有生成输出文件 | 检查 `PREFERIP_OUTPUT_FILE`、目录权限、以及 `preferip.result` 是否为空 |
| 客户端连不上 CDN 节点 | CF 面板确认域名橙云已开 + Origin Rule 回源端口=8443；落地机确认 `8443/tcp` 已放行 |
| 某地区优选为空 | 该 colo 当前无可用结果或阈值太严；先放宽 `-tl`，或把节点地区码写成多个候选如 `NRT,KIX`；`MISSING_COLO_POLICY=keep` 时该节点保留原 server，其它节点照常更新 |
| 优选总是空 | 国内机网络问题或 `CFST_EXTRA_ARGS` 阈值太严（放宽 `-tl`/`-sl`） |
| 单次优选结果波动大 | 设置 `CFST_ROUNDS=3` 多跑几轮；开启 `PREFERIP_STICKY=true` 减少无收益切换；需要更稳时开启 `CFST_STAGE2_ENABLE=true` 二阶段复测 |
| 多个节点都被同一个 IP 拖慢 | 设置 `CFST_TOP_N=3` 或更高，并保持 `PREFERIP_ASSIGN_MODE=round_robin`，同地区多节点会轮询使用候选池 |
| CFST 看起来快但客户端不通 | 可临时开启 `PREFERIP_PROBE_ENABLE=true`，脚本会用 `curl --resolve` 验证“优选IP + SNI/Host + path”，失败 IP 会写入 `bad-ip.txt` 临时跳过 |
| 需要 IPv6 优选池 | XIU2/CloudflareSpeedTest 自带 `ipv6.txt`；混合 IPv4/IPv6 节点时推荐设置 `CFST_IPV6_FILE="/opt/cfst/ipv6.txt"`，并在对应节点写 `备注|HKG|ipv6|vless://...`；脚本会自动给 IPv6 server 加 `[]` |
| 想让客户端不依赖订阅刷新 | 用 `PREFERIP_SERVER_MODE="dns"` 或 `auto`，并在节点里写 `entry=你的入口域名`；脚本会同步更新该入口域名的 A/AAAA 记录 |
| 想暂时停掉 CDN | 落地机菜单 `11. 卸载 CDN 链路`（不影响 Reality 直连） |

---

## 安全说明

- CDN 回源用真实证书走 Full(strict)，CF↔源站这一段是加密的。
