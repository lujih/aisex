# 秘密花园 (Secret Garden) - 极乐统计

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/lujih/aisex)
[![Version](https://img.shields.io/badge/version-v7.7-d946ef.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](#)

> 一个基于 Cloudflare Workers + D1（SQLite）的私密个人生活记录与统计工具。
> 
> **Secret Garden** 提供了一个安全、极速且完全私有的空间，用于记录亲密生活。支持全文检索、可视化报表、沉浸式计时与多维度的私密日记。

## ✨ 主要特性

- **⚡ 极致架构**：后端基于 Cloudflare Workers + D1 (SQLite)，全球边缘节点毫秒级响应。
- **🔍 全文检索 (FTS5)**：基于 SQLite FTS5 引擎，支持对心情、地点、备注、体位等进行毫秒级全文搜索（支持组合查询）。
- **📊 深度可视化**：内置 Chart.js，自动生成频率趋势、类型占比、满意度分布等图表。
- **🛡️ 隐私优先**：
  - 密码使用 **PBKDF2** (SHA-256) + 随机盐 (Salt) 进行高强度哈希存储。
  - 数据仅存储在你个人的 D1 数据库中。
  - 前端支持“安全抽屉”模式修改密码。
- **🧩 丰富记录**：支持时长、满意度、高潮/射精计数、助兴素材、玩具、体位 (69/传教士等)、玩法标签等详细维度。
- **⏱️ 沉浸体验**：前端内置“沉浸式计时器”，专注当下，结束后自动填入时长。
- **🔧 管理后台**：内置隐藏的 Admin Dashboard，可查看系统统计、管理用户及清理数据。
- **📱 移动端适配**：类 App 的 Dock 导航栏与手势交互，完美适配手机浏览器。

## 🏗 架构概览

- **单文件全栈**：`worker.js` 包含后端 API 路由与服务端渲染 (SSR) 的前端 HTML，无需额外部署前端。
- **数据库**：Cloudflare D1 (SQLite)，利用 `schema.sql` 定义了包括 FTS5 虚拟表在内的完整结构。
- **认证**：基于 JWT (JSON Web Token) 的无状态认证。

## 🚀 快速部署

### 1. 准备工作
确保你已经安装了 [Node.js](https://nodejs.org/) 和 Wrangler CLI：
```bash
npm install -g wrangler
wrangler login
```

### 2. 克隆项目
```bash
git clone https://github.com/lujih/aisex.git
cd aisex
```

### 3. 创建 D1 数据库
```bash
npx wrangler d1 create aisex
```
*执行后，请复制控制台返回的 `database_id`，下一步要用到。*

### 4. 配置 `wrangler.toml`
复制以下内容到项目根目录的 `wrangler.toml` 文件中，并填入你的 `database_id`：

```toml
name = "aisex"
main = "worker.js"
compatibility_date = "2026-01-29"
keep_vars = true

# [重要] 开启 Node.js 兼容模式
compatibility_flags = ["nodejs_compat"]

# 部署按钮会自动覆盖这里的配置，或者提示用户创建
[[d1_databases]]
binding = "DB"
database_name = "aisex"
database_id = "这里填入上一步生成的 ID"

```

### 5. 初始化数据库表结构 (Schema)
这是最关键的一步，用于创建用户表、记录表和**搜索索引**：

```bash
# 远程执行 (部署到线上)
npx wrangler d1 execute aisex --remote --file=schema.sql

# 本地预览 (可选)
# npx wrangler d1 execute aisex --local --file=schema.sql
```

### 6. 设置敏感密钥
项目运行需要两个核心密钥，请务必设置：

```bash
# 1. JWT 签名密钥 (建议 32 位以上随机字符串)
npx wrangler secret put JWT_SECRET

# 2. 管理员密码 (用于访问 /api/admin 接口和管理后台)
npx wrangler secret put ADMIN_PASSWORD
```

### 7. 部署上线
```bash
npx wrangler deploy
```
部署完成后，访问 Worker 给出的 URL 即可开始使用。

---

## 🛠️ 管理后台 (Admin)

项目内置了一个隐藏的管理界面。
1. 在已登录的用户界面中，点击 **"我的" -> "管理后台"**。
2. 输入你在 secrets 中设置的 `ADMIN_PASSWORD`。
3. 验证通过后，你可以：
   - 查看系统总用户数、总记录数、数据库体积估算。
   - 查看所有注册用户列表。
   - 删除违规用户及其所有数据。

## 📂 数据库说明 (Schema)

核心表结构位于 `schema.sql`：
- **`users`**: 存储用户凭证 (PBKDF2 Hash) 和注册信息。
- **`records`**: 主记录表，存储所有活动数据。
- **`records_fts`**: **虚拟表**，由 SQLite FTS5 驱动，通过 Trigger 自动同步，实现高性能全文搜索。
- **`record_acts`**: 标签关联表。

> **注意**：如果你修改了 `records` 表结构，请务必同步更新 `schema.sql` 中的 Trigger 逻辑，否则搜索功能可能失效。

## ❓ 常见问题

**Q: 部署后打开页面点击“登录/注册”没反应？**
A: 请检查：
1. 是否已执行 `npx wrangler d1 execute ... --file=schema.sql` 初始化数据库？
2. 是否已设置 `JWT_SECRET`？
3. `wrangler.toml` 中的 binding 是否为 `DB`？(旧版本可能是 AIS_DB，请修正)。

**Q: 搜索功能报错或无结果？**
A: 搜索依赖 `records_fts` 虚拟表。如果是旧数据库升级上来，可能缺少该表。请重新运行 schema 中的 FTS 相关创建语句，或者手动对旧数据触发一次 update 以重建索引。

**Q: 如何修改前端界面？**
A: 前端代码内嵌在 `worker.js`底部的 `serveFrontend()` 函数中。修改 HTML/CSS/JS 后，重新运行 `npx wrangler deploy` 即可更新。

**Q: 安全性如何？**
A: 
- 通信层：Cloudflare 强制 HTTPS。
- 数据层：数据库隔离，开发者无法直接查看内容（除非拥有 Cloudflare 账号权限）。
- 密码层：使用 PBKDF2 + Salt 存储，抗彩虹表攻击。
- **建议**：不要泄露 `wrangler.toml` 中的 `database_id` 和你的 `JWT_SECRET`。

## 📜 许可证

MIT License. 
Designed with Passion by [lujih](https://github.com/lujih).