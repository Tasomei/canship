# canship

面向 JavaScript / TypeScript Web 应用的本地静态扫描器，检查凭据暴露、访问控制配置及请求输入风险。扫描不执行项目代码、不上传文件、不联网。

[English](./README.md)

> 本文对应 `0.6.0`。使用 `npx canship --version` 确认已安装版本。

## 快速开始

```powershell
npx canship
```

默认扫描当前目录，也可指定路径。要求 Node.js ≥18，无运行时依赖，安装可能联网。Git 检查覆盖本地跟踪文件及提交历史，不访问远程仓库；历史无法读取时标记扫描不完整。

以下报告来自发布前开发构建，使用示例数据。

![终端报告](https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/terminal.png)

## 检测范围

| 类别 | 级别 | 范围 |
|---|:---:|---|
| 凭据 | `P0` | 硬编码密钥、私钥、含密码的数据库连接串、公开变量中的私密值、Supabase 管理员密钥、Git 跟踪或历史中的非模板 `.env` 文件 |
| API 访问 | `P0/P1` | 未识别到鉴权的数据库操作、服务端信任 Supabase `getSession()`、未验证的 Stripe webhook |
| 数据库规则 | `P1/P2` | Supabase 表未启用 RLS、无条件放行策略、允许公开列出对象的存储桶；Firebase 开放规则及限时测试规则 |
| CORS | `P1/P2` | 携带凭据的来源回显或通配符配置 |
| 请求输入 | `P1/P2` | 请求输入参与 SQL 或命令构造、调用方可控的请求主机和重定向目标 |

凭据格式包括 OpenAI、Anthropic、AWS、Stripe、GitHub、npm 等。Firebase 覆盖 Firestore、Storage、Realtime Database。`--list-rules` 列出规则 ID、范围及局限。

### 服务端入口

| 框架 | 入口 |
|---|---|
| Next.js | App Router 处理函数、Pages Router `/api`、`'use server'` 函数 |
| SvelteKit | `+server` 端点、`+page.server` 表单 action |
| Nuxt | `server/api`、`server/routes` |
| Remix / React Router | `app/routes` 中的 `loader`、`action` 导出 |
| Astro | `src/pages` 中的端点 |
| Express | `app`/`Router` 路由，含 `.route()` 链、挂载的子路由和其他文件中的控制器 |
| Hono | `app.get()` 等路由、链式调用、`basePath`，以及 `app.route()` 挂载的子应用 |
| Fastify | 简写与 `route()` 声明、`register()` 前缀与封装作用域、`@fastify/autoload` 目录 |

已识别的 Next.js/Astro 中间件可抑制覆盖范围内的鉴权结果；Server Function 需在函数内检查。Express、Hono、Fastify 的中间件与钩子只有解析到拒绝未认证请求的代码或已知鉴权库时才抑制鉴权结果；名称像鉴权但无法解析的中间件降低置信度。本地辅助函数、SvelteKit hooks、Nuxt 中间件可降低置信度，但保留结果。输入分析追踪可见的赋值、解构和字符串构造，不以辅助函数名称证明安全。

Express、Hono、Fastify 路由会跟进被调项目函数中的写入，最多两层（处理函数 → service → model）；文件约定路由只报告路由文件内的写入。路由分析不覆盖 SvelteKit 页面 load、remote function 和 Hono 的 `app.openapi()` 路由；凭据、CORS 等内容规则仍适用。

## 结果

报告正文为英文。终端按文件分组，`--verbose` 展开摘录、说明、证据和修复步骤。HTML 为自包含离线报告，支持筛选、分组、人工操作清单及修复提示复制。

![HTML 报告](https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/report.png)

`certain` 表示静态证据充分，`likely` 需人工审阅；测试和示例中的结果降为 `likely`。默认仅展示 `certain`，`--all` 显示全部。置信度仅反映静态证据，不代表凭据有效或风险已在运行时验证。

| 退出码 | 含义 |
|---|---|
| `0` | 无结果，且扫描完整或由 `--best-effort` 接受 |
| `1` | 至少一条 `certain` 的 P0/P1 结果 |
| `2` | 其他结果，包括隐藏的 `likely` |
| `3` | 参数错误、工具错误或未被接受的不完整扫描 |

退出码基于规则筛选、忽略注释和基线处理后的结果。有结果时优先于扫描不完整；`--best-effort` 不改变 `1` 或 `2`。

## 命令行

`npx canship [path] [options]`

| 参数 | 作用 |
|---|---|
| `-a`、`--all` | 包含 `likely` 结果 |
| `--verbose` | 展开终端结果 |
| `--report[=file]` | 写入 HTML，默认 `canship-report.html` |
| `--open` | 打开 `--report` 输出；CI 和非交互终端中禁用 |
| `--json` | 输出 JSON |
| `--sarif[=file]` | 写入 SARIF 2.1.0，默认 `canship.sarif` |
| `--fix-prompt` | 输出修复指令及独立的人工操作清单 |
| `--no-excerpts` | 移除所有报告中的摘录 |
| `--changed-since=ref` | 展示变更文件结果，保留全量扫描退出码 |
| `--only=ids` / `--skip=ids` | 选择或排除规则及命名空间，逗号分隔，可重复 |
| `--list-rules` | 列出规则而不扫描，支持 `--json` |
| `--baseline[=file]` / `--baseline-write[=file]` | 抑制或记录结果，默认 `canship-baseline.json` |
| `--no-config` / `--no-ignore-markers` | 忽略项目配置或源码抑制注释 |
| `--best-effort` | 允许没有结果的不完整扫描退出 `0` |
| `-h`、`--help` / `-v`、`--version` | 显示帮助或版本 |

`--json` 与 `--fix-prompt` 互斥，均可同时输出 HTML 和 SARIF。

`--changed-since` 比较本地共同祖先与工作区，包含未被忽略的新文件，不拉取远程、不缩小扫描范围。缺少 Git、引用或共同历史时退出 `3`；不能与 `--baseline-write` 组合。

## 配置

`canship.config.json` 支持 `baseline`、`only`、`skip`、`all`。命令行参数优先，`only` 与 `skip` 互斥。

```json
{ "skip": ["cors/wildcard-with-credentials"], "all": false }
```

独占行注释 `canship-ignore-file` 排除整个文件；`canship-ignore-next-line [rule]` 抑制下一行，可限定单条规则。报告披露排除项；主动抑制不标记扫描不完整，可能使退出码降为 `0`。扫描不可信项目时使用 `--no-config --no-ignore-markers`。

基线表示接受已有结果，不代表问题已修复。v2 格式不受行号移动影响，但凭据变化会重新报告。

默认路径相对扫描目录，显式路径相对工作目录；读取与写入互斥。缺失、无效或 v1 基线退出 `3`。写入成功退出 `0`，不完整或选择性扫描会提示。

## GitHub Action

保存为 `.github/workflows/canship.yml`：

```yaml
name: canship
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: Tasomei/canship@7dfebc9502b786edd5c7fd71266e4926d0ad764b
        with:
          version: '0.6.0'
          honor-ignore-markers: false
```

提交哈希固定 Action 实现，`version` 指定 npm 扫描器版本，不使用开发分支源码。Action 使用 Node.js 22，不安装或运行项目依赖，仅输出统计摘要。

| 输入 | 默认值 | 含义 |
|---|---|---|
| `version` | `0.6.0` | 精确 npm 扫描器版本 |
| `fail-on` | `blocking` | `blocking`：确定的 P0/P1；`any`：全部结果；`none`：仅报告 |

扫描不完整或工具错误始终失败。默认不读取项目配置、不上传 SARIF。输入输出见 [action.yml](./action.yml)。

上传 SARIF 需 `security-events: write` 及代码扫描支持，fork PR 可能权限不足；上传前应审阅报告。不可信 PR 使用 `pull_request`，不要使用 `pull_request_target`。

## API 与结构化输出

```js
import { scan, summarize } from 'canship'

const result = await scan('./my-app', { noExcerpts: true })
console.log(summarize(result))
```

`scan()` 返回全部置信度结果，支持 `only`、`skip`、`honorIgnoreMarkers`（默认 `true`）、`noExcerpts`（默认 `false`）。不加载配置、不应用基线、不写报告、不设置进程退出码；无效参数抛出异常。`listRules()` 返回规则目录。

JSON 使用 [schemaVersion 1](./schemas/scan-report-v1.schema.json)。须独立于退出码检查 `partial`、`errors`、`skipped`、`filesScanned`。SARIF 包含证据位置和执行诊断。

## 隐私与限制

- 静态检查可能误报或漏报，不验证业务授权、限流、依赖漏洞或线上配置。
- 脱敏仅覆盖已识别格式，未知敏感值可能保留在摘录中；`--no-excerpts` 可移除摘录。路径、名称和基线描述仍可见。
- Google/Firebase/Maps 的 `AIza…` 密钥按公开标识符处理，不单凭其值判定泄露。Supabase 检查依据本地迁移及支持的存储桶配置。
- 评估快照获取和可选的 SARIF 上传可能联网。
- 不跟随符号链接；嵌套仓库与子模块需单独扫描。范围内跳过项及分析超限标记扫描不完整；鉴权辅助函数解析超限不会隐藏结果，改为在受影响的结果上注明。默认排除的依赖和构建目录不计为扫描缺口。

| 项目 | 上限 |
|---|---|
| 文件读取 | 单文件 2 MiB；单次 128 MiB、10,000 个文件，含探测 |
| 目录遍历 | 50,000 个条目；16 层 |
| 结果 | 每文件 100 条，优先保留高严重度、高置信度结果 |
| Git 历史 | 每文件 100 个相关版本；单条命令 30 秒 |
| 鉴权辅助函数解析 | 8 跳；每个辅助函数 64 个符号，每个路由文件共 1,024 个 |
| 委托写入 | 调用 2 层；每个文件 256 个被调函数；超出部分的写入不报告 |
| 身份/控制流 | 值解析 8 步；表达式 4,000 字符；每函数 512 个赋值/区域；区域嵌套 8 层 |
| 请求输入追踪 | 值解析 8 步；512 个赋值/区域；单条表达式 64 KiB；URL 分析 8 层、静态前缀 200 字符 |
| Supabase 策略/存储桶解析 | 单条语句 4,000 字符 |

证据链最多 24 步，截断时提示。

## 开发

```powershell
npm ci
```

```powershell
npm run prepublishOnly
```

```powershell
npm run test:package
```

```powershell
npm run evaluate
```

新增规则需包含应检出和不应检出的 [夹具](./test/fixtures/)。固定项目评估见 [清单](./test/evaluation/projects.json)、[获取脚本](./scripts/fetch-evaluation-projects.mjs)、[评估器](./scripts/evaluate-projects.ts)。样本通过不代表真实检出率。

## 许可

[MIT](./LICENSE)。Supabase/Firebase 夹具保留 Apache-2.0，Next.js/`cors` 夹具保留 MIT。
