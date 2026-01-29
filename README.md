# 秘密花园 (Secret Garden) - 极乐统计

[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/lujih/aisex)
[![Version](https://img.shields.io/badge/version-v6.0-blue.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)](#)

> 一个基于 Cloudflare Workers + D1（SQLite）的私密个人生活记录与统计工具。零成本托管、极速响应、可视化报表，适合用于个人日记/私密记录场景。

目录
- [主要特性](#主要特性)
- [架构概览](#架构概览)
- [快速部署（推荐）](#快速部署推荐)
  - [一键部署到 Cloudflare Workers](#一键部署到-cloudflare-workers)
  - [部署后必须设置的密钥（JWT）](#部署后必须设置的密钥jwt)
  - [初始化数据库（重要）](#初始化数据库重要)
- [本地开发与手动部署](#本地开发与手动部署)
- [配置示例（wrangler.toml）](#配置示例wranglertoml)
- [数据库与表结构](#数据库与表结构)
- [项目文件结构说明](#项目文件结构说明)
- [安全与隐私建议](#安全与隐私建议)
- [常见问题与排错](#常见问题与排错)
- [贡献 & 许可证](#贡献--许可证)
- [作者](#作者)

## 主要特性

- ⚡ 极致性能：后端基于 Cloudflare Workers + D1（SQLite），查询与写入延迟极低。  
- 📊 数据可视化：内置 Chart.js，自动生成趋势、分布与满意度等图表。  
- 📝 丰富记录字段：支持时长、分类、心情、地点、助兴材料、玩具、备注等。  
- 🔄 完整交互：支持编辑回显、无限滚动、修改密码等功能。  
- 🌍 时区支持：自动处理时区，记录时间与本地时间一致。  
- 🏆 匿名排行榜：可选的匿名全局 Top 50 排行（可关闭）。  
- ⏱️ 内置计时器：在前端提供沉浸式计时并便捷保存 session 时长。

## 架构概览

- 前后端：单文件部署（worker.js）把后端 API 与前端静态页面打包在一起，方便 Cloudflare Workers 托管。  
- 数据库：Cloudflare D1（SQLite）负责持久化，schema 位于项目根的 `schema.sql`。  
- 部署工具：推荐使用 Cloudflare + Wrangler。

## 快速部署（推荐）

### 一键部署到 Cloudflare Workers
1. 点击上方的 "Deploy to Cloudflare Workers" 按钮。  
2. Cloudflare 会引导授权 GitHub 并创建项目。  
3. 在部署配置页面会提示创建 D1 数据库，请允许创建（或手动输入已有 D1 数据库）。  
4. 点击 "Save and Deploy" 完成部署（此时数据库尚为空，需要初始化表结构，见下文）。

### 部署后必须设置的密钥（JWT）
为保证账号安全，请在部署完成后设置 `JWT_SECRET`：
1. 登录 Cloudflare Dashboard -> Workers & Pages -> 选择项目 (aisex) -> Settings -> Variables and Secrets。  
2. 新增 Secret：
   - 名称: `JWT_SECRET`
   - 值: 建议使用至少 32 字节随机字符串（例如由密码管理器或 `openssl rand -hex 32` 生成）。  
3. 保存并重新部署使配置生效。

注意：定期更换密钥并记录备份；更换密钥将使已有 JWT 无效。

### 初始化数据库（重要）
部署仅会创建空的 D1 实例，需要手动导入表结构：
1. Cloudflare Dashboard -> D1 SQL Database -> 选择你创建的数据库。  
2. 点击 Console（控制台）标签页。  
3. 打开项目根目录的 `schema.sql`，将其内容复制并粘贴到控制台中。  
4. 执行并确认返回 Success。  
完成后，访问 Worker 域名开始注册与使用。

---

## 本地开发与手动部署

1. 克隆项目
```bash
git clone https://github.com/lujih/aisex.git
cd aisex
```

2. 创建本地/远程 D1（示例）
```bash
# 在本地创建一个 D1（示例命令）
npx wrangler d1 create aisex
# 记录返回的 database_id 并填入 wrangler.toml（见下）
```

3. 初始化表结构
```bash
# 本地执行（如果支持本地 D1）
npx wrangler d1 execute aisex --local --file=./schema.sql

# 远程执行（如果要初始化远程 D1）
npx wrangler d1 execute aisex --remote --file=./schema.sql
```

4. 本地运行开发服务器
```bash
npx wrangler dev
```

5. 上传/部署到 Cloudflare
```bash
# 设置 secret（交互式）
npx wrangler secret put JWT_SECRET

# 发布
npx wrangler deploy
```

## 配置示例（wrangler.toml）
下面给出一个最小示例，请根据实际 `account_id`、`database_id` 与 `route` 修改：

```toml
name = "aisex"
main = "worker.js"
compatibility_date = "2026-01-01"

account_id = "your_account_id"
workers_dev = true

[[d1_databases]]
binding = "AIS_DB"
database_name = "aisex"
database_id = "your_database_id"
```

在 Worker 代码中，D1 的绑定名需与 `binding` 一致（例如 `AIS_DB`）。

## 数据库与表结构

- 表结构位于 `schema.sql`，含主要的 `users` 与 `records`（或根据实际 schema 命名）表。部署后请务必执行该脚本以初始化表结构。
- 推荐设置索引以优化按日期或用户查询的性能（若未在 schema 中包含，可考虑添加）。

## 项目文件结构说明

- `worker.js`：后端路由 + 内嵌前端静态页面（HTML/JS），处理 API 请求与 D1 操作。  
- `schema.sql`：数据库初始化脚本（表与索引）。  
- `wrangler.toml`：Cloudflare Wrangler 配置与 D1 绑定信息。  
- 其余文件：如 README、LICENSE、静态资源等（具体请查看仓库目录）。

## 安全与隐私建议

- 强烈建议使用强随机的 `JWT_SECRET` 并保存在 Cloudflare Secrets 中，而不是写入仓库。  
- 本项目设计为将所有数据保存在你的 D1 数据库中，开发者无法访问数据库内容——仍需确保 Cloudflare 账户与 API keys 的安全。  
- 若需要公开部署，建议关闭匿名排行或对排行数据进行额外脱敏处理。  
- 做好备份：D1 虽然稳定，但请定期导出数据或使用自己的备份策略。

## 常见问题与排错

Q: 部署后访问页面为空或 404？  
A: 检查 Cloudflare Worker 是否已成功部署，确认 `workers_dev` 或自定义域配置正确；检查 `worker.js` 是否在项目根并在 `wrangler.toml` 中被正确引用。

Q: 报错找不到 D1 绑定？  
A: 确认 `wrangler.toml` 中的 `[[d1_databases]]` binding 名称与 Worker 代码中使用的一致，并且 `database_id` 已填写正确。

Q: 初始化 schema 后仍然无法写入/查询？  
A: 检查 schema 执行是否成功；在 D1 Console 中运行简单 SELECT 测试；确认 Worker 使用正确的 D1 绑定。

## 贡献 & 许可证

欢迎 PR、Issue 与功能建议。请遵循常规贡献流程：
1. Fork -> 创建分支 -> 提交 -> 发起 PR。  
2. 说明变更目的与影响范围。  

许可证：MIT（仓库根目录 LICENSE 为准）。

## 作者

Created by [lujih](https://github.com/lujih)

---
