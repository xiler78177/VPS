# Reality 节点 + CDN 优选 IP 方案

> 状态：已落地并继续优化。

## 1. 目标

保留 Reality 直连链路，同时增加一条 CDN 链路，专门解决晚高峰国内到落地 IP 这一跳的干扰。

## 2. 架构

```
客户端 → CF 优选 IP → CF 边缘 → CF 骨干 → 落地机 nginx :8443 → sing-box WS 入站
客户端 → 落地机 Reality 直连
```

核心点：

1. 优选必须在国内机跑。
2. 优选结果直接生成本地节点文件。
3. 需要时再同步入口域名 DNS，减少对客户端刷新频率的依赖。

## 3. 已实现约束

- `preferip-collect.sh` 负责跑 CloudflareSpeedTest。
- `preferip-push.sh` 负责生成 `preferip.rendered.txt`。
- `PREFERIP_SERVER_MODE=dns` 时，脚本只同步显式 `entry=` 入口域名；`entry=` 必须独立于原节点 `server` / `host` / `sni`，原 CDN 回源域名继续保持橙云。
- 节点按 `CF 地区码` 分组，避免香港 IP 直接拿去给首尔或日本节点造成负优化。

## 4. 节点格式

推荐：

```text
香港-1|HKG|vless://...
韩国-1|ICN|vless://...
日本-1|NRT,KIX|vless://...
香港-ipv6|HKG|ipv6|vless://...
```

也支持：

```text
香港-1|HKG|entry=prefer-hkg.example.com|vless://...
```

`prefer-hkg.example.com` 是 DNS-only 入口域名，不能写成原 CDN 回源域名。

## 5. 策略

- `CFST_TOP_N` 控制候选池大小。
- `PREFERIP_ASSIGN_MODE=round_robin` 避免多个节点压在同一个 IP 上。
- `PREFERIP_STICKY=true` 减少无收益切换。
- `MISSING_COLO_POLICY=keep` 让缺结果的地区保留原 server。
- `KEEP_ON_EMPTY=true` 避免空结果覆盖现状。

## 6. 后续优化方向

1. 继续提高带宽门槛，优先低延迟但不能牺牲速度。
2. 对可疑 IP 开启 `PREFERIP_PROBE_ENABLE=true` 做真实链路探活。
3. 对 IPv6 节点单独维护 `CFST_IPV6_FILE`。
