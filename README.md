# 秘密花园 (Secret Garden) - 极乐统计

**秘密花园 (Secret Garden)** 是一个基于 Cloudflare Workers 和 D1 数据库构建的私密个人生活记录与统计工具。它无需购买服务器，完全免费托管在 Cloudflare 的边缘网络上，拥有极致的性能和安全性。

> **当前版本**: v6.0 (D1 极速版)

## ✨ 主要特性

*   **⚡ 极致性能**: 后端迁移至 Cloudflare D1 (SQLite)，查询速度毫秒级响应。
*   **📊 数据可视化**: 内置 Chart.js 图表，自动生成月度趋势、类型分布、满意度分析。
*   **📝 详尽记录**: 支持记录时长、体位、心情、地点、助兴材料、玩具使用及详细体验备注。
*   **🔄 完整交互**: 支持**编辑回显**、**无限滚动加载**、**修改密码**。
*   **🌍 时区支持**: 自动处理时区问题，无论身在何处，记录的时间永远准确。
*   **🏆 极乐排行榜**: 匿名的全局排行榜系统 (Top 50)。
*   **⏱️ 内置计时器**: 沉浸式计时工具，方便记录 session 时长。

## 🚀 快速部署 (推荐)

### 第一步：一键部署
[![Deploy to Cloudflare Workers](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/lujih/aisex)

点击上方的 **Deploy to Cloudflare Workers** 按钮。

1.  Cloudflare 会引导你授权 GitHub 账号。
2.  在部署配置页面，Cloudflare 会自动检测到需要 D1 数据库。
3.  **关键步骤**：请确保允许 Cloudflare 创建一个新的 D1 数据库（通常会自动命名或让你输入名称）。
4.  点击 "Save and Deploy"。

### 第二步：设置密钥 (安全必选)
部署完成后，为了保证账户安全，请修改 JWT 密钥：

1.  进入 [Cloudflare Dashboard](https://dash.cloudflare.com/)。
2.  进入 **Workers & Pages** -> 选择刚部署的项目 (aisex)。
3.  点击 **Settings** -> **Variables and Secrets**。
4.  添加一个变量：
    *   变量名: `JWT_SECRET`
    *   值: 输入一串随机且复杂的字符串 (例如: `my-super-secret-key-999`)。
5.  点击 **Deploy** (或 Redeploy) 使配置生效。

### 第三步：初始化数据库 (重要)
一键部署只会创建空数据库，你需要手动导入表结构：

1.  在 Cloudflare Dashboard 左侧菜单点击 **D1 SQL Database**。
2.  点击刚才创建的数据库名称。
3.  点击 **Console** (控制台) 标签页。
4.  复制本项目根目录下的 `schema.sql` 文件内容。
5.  粘贴到控制台输入框中，点击 **Execute**。
6.  看到 "Success" 即表示完成！现在可以访问你的 Workers 域名进行注册和使用了。

---

## 🛠️ 本地开发与手动部署

如果你更喜欢使用命令行工具 (CLI)：

1.  **克隆项目**
    ```bash
    git clone https://github.com/lujih/aisex.git
    cd aisex
    ```

2.  **创建 D1 数据库**
    ```bash
    npx wrangler d1 create aisex
    ```
    *复制终端返回的 `database_id`，填入 `wrangler.toml` 文件中。*

3.  **初始化表结构**
    ```bash
    npx wrangler d1 execute aisex --local --file=./schema.sql
    ```

4.  **本地运行**
    ```bash
    npx wrangler dev
    ```

5.  **部署上线**
    ```bash
    # 先初始化远程数据库表结构
    npx wrangler d1 execute aisex --remote --file=./schema.sql
    
    # 设置密钥
    npx wrangler secret put JWT_SECRET
    
    # 发布
    npx wrangler deploy
    ```

## 📂 项目结构

*   `worker.js`: 核心逻辑文件。包含了后端 API 路由、数据库操作逻辑以及内嵌的前端 HTML/JS 代码。
*   `schema.sql`: 数据库初始化脚本，定义了 `users` 和 `records` 表结构。
*   `wrangler.toml`: Cloudflare 配置文件，定义了 D1 数据库绑定。

## ⚠️ 免责声明

本项目仅供个人学习和记录使用。所有数据存储在您自己的 Cloudflare D1 数据库中，开发者无法查看任何数据。请妥善保管您的 Cloudflare 账号和 JWT 密钥。

---
*Created by [lujih](https://github.com/lujih)*
