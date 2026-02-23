# VPS Server Manage

一站式 Linux 服务器管理脚本，集成安全防护、Web 服务、WireGuard VPN、Docker 管理等常用运维功能。

支持 **Debian/Ubuntu** 和 **OpenWrt**（精简模式）。

## 一键运行

```bash
bash <(curl -sSL https://raw.githubusercontent.com/xiler78177/VPS/main/dist/v4-built.sh)
```

> 需要 root 权限。脚本会自动检测系统环境并安装必要依赖。

## 功能概览

### 安全防护

| 功能 | 说明 |
|------|------|
| 基础依赖安装 | 一键安装常用软件包 |
| UFW 防火墙 | 安装/启用/管理端口规则（增删查） |
| Fail2ban 入侵防御 | SSH 暴力破解防护，支持 ipset 模式，日志查看与封禁管理 |
| SSH 安全配置 | 修改端口、密钥管理、禁用密码登录 |

### 系统优化

| 功能 | 说明 |
|------|------|
| BBR 加速 | 一键开启 TCP BBR 拥塞控制 |
| Swap 虚拟内存 | 创建/调整 Swap 分区 |
| 系统清理 | 自动清理软件包缓存 |
| 主机名/时区 | 修改主机名和系统时区 |

### 网络工具

| 功能 | 说明 |
|------|------|
| DNS 配置 | 切换公共 DNS（支持多家服务商） |
| iPerf3 测速 | 服务端/客户端带宽测试 |

### Web 服务

| 功能 | 说明 |
|------|------|
| SSL 证书 | Let's Encrypt 证书自动申请（Cloudflare DNS 验证），自动续期 |
| Nginx 反向代理 | 自动配置反代站点，支持 HTTP/HTTPS 后端、自定义端口 |
| Cloudflare 管理 | DNS 记录增删改查（A/AAAA/CNAME） |
| SaaS 回源加速 | Cloudflare SaaS 自定义主机名 + 优选 IP 配置 |
| Origin Rules | Cloudflare 源站规则管理 |
| DDNS 动态域名 | 自动更新 Cloudflare DNS 记录（支持 IPv4/IPv6） |

### WireGuard VPN

| 功能 | 说明 |
|------|------|
| 服务端部署 | 一键安装配置 WireGuard 服务端 |
| 客户端管理 | 添加/删除/启用/禁用设备，二维码配置导出 |
| 集群高可用 | 多节点集群同步，自动故障转移 |
| Mesh 全互联 | 全互联组网，节点间自动发现与连接 |
| Clash 配置 | 自动生成 Clash 代理配置 |
| 端口转发 | 通过 WireGuard 隧道转发端口 |
| Watchdog | 连接监控与自动恢复 |
| 导入/导出 | 批量导入导出设备配置 |

### Docker 管理

| 功能 | 说明 |
|------|------|
| 安装/卸载 | Docker 与 Docker Compose 一键安装 |
| 代理配置 | 配置 Docker 拉取镜像代理 |
| 镜像/容器 | 镜像清理、容器批量管理 |

### 维护工具

| 功能 | 说明 |
|------|------|
| 操作日志 | 查看脚本操作记录（自动轮转） |
| 备份与恢复 | 本地备份 + WebDAV 远程上传，定时自动备份，一键恢复 |

## 项目结构

```
VPS/
├── v4.sh                   # 主入口（多文件模式）
├── build.sh                # 构建脚本（合并为单文件）
├── install.sh              # 安装引导脚本
├── dist/
│   └── v4-built.sh         # 构建产物（可直接部署）
└── modules/
    ├── 00-constants.sh     # 全局常量与平台检测
    ├── 01-utils.sh         # 通用工具函数
    ├── 02-network.sh       # 公网IP获取、DDNS
    ├── 03-sysinfo.sh       # 系统信息展示
    ├── 04-firewall.sh      # UFW 防火墙
    ├── 05-fail2ban.sh      # Fail2ban 防护
    ├── 06-ssh.sh           # SSH 管理
    ├── 07-system.sh        # 系统优化与包管理
    ├── 08-network-tools.sh # 网络测试工具
    ├── 09-web.sh           # Web 服务（SSL/Nginx/Cloudflare）
    ├── 10-docker.sh        # Docker 管理
    ├── 11-wireguard.sh     # WireGuard VPN
    ├── 12-backup.sh        # 备份与恢复
    └── 13-menus.sh         # 菜单与主入口
```

## 开发与构建

修改 `modules/` 下的模块文件后，运行构建脚本生成单文件部署产物：

```bash
bash build.sh
```

产物输出到 `dist/v4-built.sh`，可直接上传到服务器运行。

也可指定输出路径：

```bash
bash build.sh /path/to/output.sh
```

## 定时备份

脚本支持通过命令行参数触发非交互式备份，适用于 cron 定时任务：

```bash
bash /path/to/v4.sh --backup
```

## 系统要求

- **Debian / Ubuntu**（完整功能）
- **OpenWrt**（精简模式：Web/DNS/DDNS/BBR/WireGuard/备份可用）
- root 权限
- bash, curl（脚本会自动检测并安装）
