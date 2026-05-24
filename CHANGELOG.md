# Changelog

本项目所有重要变更记录于此。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)。

## [Unreleased]

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
