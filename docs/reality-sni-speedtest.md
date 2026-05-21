# Reality SNI 自动测速方案 - 纯交互式版本

## 🎯 核心设计理念

**完全交互式，零配置文件**

- ✅ 所有选项通过菜单选择
- ✅ 无需编辑任何配置文件
- ✅ 用户友好，降低使用门槛

---

## 📋 用户交互流程

### 步骤 1：选择测速模式

```
选择测速模式：

  1. 严格模式（延迟 < 50ms）
     适合：VPS 与 CDN 在同一地区

  2. 正常模式（延迟 < 200ms）
     适合：大部分场景

  3. 宽松模式（延迟 < 500ms）
     适合：跨洲访问或网络较慢

  4. 自动模式（智能三级降级）★ 推荐
     先尝试严格，无合格则自动降级

  5. 跳过测速（随机选择，不测速）

请选择模式 [4]:
```

### 步骤 2：自动测速（如果选择模式 1-4）

```
========== 尝试 严格（< 50ms）==========

  测试 apps.apple.com ... 245ms (超过阈值)
  测试 s0.awsstatic.com ... 312ms (超过阈值)
  ...

测速完成: 0/15 个域名符合要求
自动降级...

========== 尝试 正常（< 200ms）==========

  测试 github.gallerycdn.vsassets.io ... 189ms ✓
  测试 gsp-ssl.ls.apple.com ... 134ms ✓
  ...

测速完成: 5/15 个域名符合要求
```

### 步骤 3：选择域名

```
找到 5 个合格域名：

  1. gsp-ssl.ls.apple.com                       [ 134ms]
  2. statici.icloud.com                         [ 167ms]
  3. github.gallerycdn.vsassets.io              [ 189ms]
  4. apps.apple.com                             [ 195ms]
  5. store-images.s-microsoft.com               [ 198ms]

  a. 自动选择延迟最低的（推荐）
  r. 重新测速
  c. 手动输入域名

请选择 [a]:
```

---

## 🔧 三大核心优化（保持不变）

### 1. 延迟阈值：50ms → 200ms → 500ms 三级降级

- 严格模式：< 50ms（优先尝试）
- 正常模式：< 200ms（推荐）
- 宽松模式：< 500ms（兜底）

### 2. 候选池：三级降级

- bulianglin.com（117 个）→ v2ray-agent（44 个）→ 内置列表（77 个）

### 3. 纯交互式

- **所有配置通过菜单选择**
- **无需编辑配置文件**
- **用户友好**

---

## 📁 最终交付文件

| 文件 | 说明 |
|------|------|
| `reality-sni-speedtest-interactive.sh` | **纯交互式版本**（推荐使用） |
| `reality-sni-speedtest-enhancement.sh` | 配置文件版本（已废弃） |
| `test-reality-sni-speedtest.sh` | 测试脚本 |

---

## 🚀 集成方法（超简单）

### 在 15-singbox-reality.sh 中添加一行：

```bash
# 在文件开头
source "$(dirname "$0")/enhancements/reality-sni-speedtest-interactive.sh"

# 原有的 reality_prompt_sni() 会被自动替换
# 无需其他修改
```

---

## 💡 关键改进点

### 之前的问题

```bash
# 用户需要编辑配置文件
REALITY_SNI_LATENCY_THRESHOLD=800
REALITY_SNI_CHECK_TLS_VERSION=true
...
```

### 现在的方案

```
# 用户通过菜单选择
选择测速模式：
  1. 严格模式
  2. 正常模式
  3. 宽松模式
  4. 自动模式 ★
  5. 跳过测速

请选择 [4]:
```

---

## 🎯 用户体验对比

| 维度 | 配置文件版本 | 纯交互式版本 |
|------|-------------|-------------|
| **使用难度** | 需要编辑配置文件 | 菜单选择 |
| **学习成本** | 需要理解参数含义 | 直观的选项说明 |
| **错误风险** | 可能填错参数 | 菜单限制选项 |
| **灵活性** | 高（可精细调整） | 中（预设选项） |
| **适用场景** | 高级用户 | **所有用户** |

---

## 📊 完整功能清单

### 核心功能

- ✅ 从 bulianglin.com 拉取候选池（117 个）
- ✅ 三级候选池降级（bulianglin → v2ray-agent → 内置）
- ✅ TLS 握手测速（毫秒级精度）
- ✅ 三级阈值降级（50ms → 200ms → 500ms）
- ✅ 自动选择最优域名
- ✅ 手动输入域名
- ✅ 跳过测速（随机选择）
- ✅ 重新测速

### 交互选项

1. **测速模式选择**：严格/正常/宽松/自动/跳过
2. **域名选择**：自动选择最优/手动选择/手动输入
3. **重新测速**：不满意可以重新测
4. **换一批**：跳过测速模式下可以换一批候选

---

## 🔍 与原方案的差异

### 移除的功能

- ❌ 配置文件（`/etc/vps-mgr/reality/config`）
- ❌ TLS 版本检测（增加测速时间，收益不大）
- ❌ Cloudflare 代理检测（bulianglin.com 候选池已过滤）
- ❌ 候选池质量验证（不需要用户操作）

### 保留的功能

- ✅ 三级阈值降级
- ✅ 三级候选池降级
- ✅ 自动测速
- ✅ 交互式选择

---

## 📝 代码示例

### 完整集成示例

```bash
#!/bin/bash
# 15-singbox-reality.sh

# 在文件开头 source 增强模块
REALITY_ENHANCEMENT_MODULE="$(dirname "$0")/enhancements/reality-sni-speedtest-interactive.sh"
if [[ -f "$REALITY_ENHANCEMENT_MODULE" ]]; then
    source "$REALITY_ENHANCEMENT_MODULE"
fi

# 原有的 reality_prompt_sni() 会被自动替换
# 在 Reality 安装流程中调用
reality_install() {
    # ... 前面的代码 ...
    
    # SNI 选择（自动使用增强模块）
    REALITY_SNI=$(reality_prompt_sni)
    
    # ... 后面的代码 ...
}
```

---

## 🎉 总结

### 核心优势

1. **完全交互式**：所有选项通过菜单选择，无需编辑配置文件
2. **用户友好**：清晰的选项说明，降低使用门槛
3. **智能降级**：三级阈值 + 三级候选池，保证 100% 可用性
4. **零维护**：复用 bulianglin.com 和 v2ray-agent 的候选池

### 推荐使用场景

- ✅ **所有用户**：无论新手还是高级用户
- ✅ **所有场景**：自动模式适应各种网络环境
- ✅ **所有地区**：三级阈值覆盖全球 VPS

---

**最后更新**：2026-05-21（纯交互式版本）
