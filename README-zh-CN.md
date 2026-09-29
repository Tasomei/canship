# canship

面向 JavaScript / TypeScript 项目的本地静态扫描器，检测凭据暴露与访问控制配置错误。扫描不执行项目代码、不上传文件、不联网。

[English](./README.md)

## 快速开始

```powershell
npx canship .
```

要求 Node.js ≥18，无运行时依赖。安装可能联网；Git 检查仅读取本地历史，仓库中无法调用 Git 时标记扫描未完成。

> 本文对应 0.5.0。`npx canship` 运行 npm 默认版本；其他版本的文档请查阅对应 Git 标签。

## 检测范围

| 检查项 | 级别 |
|---|---|
| 硬编码凭据、私钥及含密码的数据库连接串 | P0 |
| 公开环境变量中的私密值 | P0 |
| 源码或公开环境变量中的 Supabase 管理员凭据 | P0 |
| Git 跟踪或历史提交的 `.env` 文件，模板除外 | P0 |
| Supabase 未启用 RLS 的表及条件恒真的策略 | P1 |
| 内容可被列举的 Supabase 公开存储桶 | P2 |
| Firebase 无条件访问及固定日期测试规则 | P1 |
| 服务端数据操作未识别到鉴权 | P0 / P1 |
| 携带凭据的 CORS 来源回显或通配符配置 | P1 / P2 |

识别 OpenAI、Anthropic、AWS、Stripe、GitHub、npm 等凭据格式。Firebase 检查覆盖 Firestore、Storage、Realtime Database。规则 ID 与范围见 `--list-rules`。

### 鉴权检查

| 框架 | 检查入口 |
|---|---|
| Next.js | `app/` 路由处理函数、Pages Router `/api`、`'use server'` 函数 |
| SvelteKit | `+server` 端点及 `+page.server` 表单 action |
| Nuxt | `server/api`、`server/routes` |
| Remix / React Router | `app/routes` 中的 `loader`、`action` 导出 |
| Astro | `src/pages` 中的端点 |

支持路由组、工作区应用、本地辅助函数链、身份别名与解构、实参约束及有界分支/异常分析。原始请求输入、常量、未等待的 Promise 或辅助函数名称本身，不构成本地鉴权依据。

已识别的 Next.js/Astro 中间件可抑制覆盖范围内的结果；Server Function 需在函数内检查。本地辅助函数、SvelteKit hooks、Nuxt 中间件可降低置信度，但保留结果。不检查 SvelteKit 页面 load 与 remote function。

`certain`（确定）与 `likely`（疑似）描述静态证据，不验证凭据有效性或运行时安全。默认只展示 `certain`，隐藏的 `likely` 仍影响退出码。管理员客户端结果附带操作、导入、构造及鉴权函数位置。

## 命令行

省略路径时扫描当前目录。报告正文为英文。

| 参数 | 作用 |
|---|---|
| `-a`、`--all` | 包含 `likely` 结果 |
| `--json` | 输出 JSON |
| `--fix-prompt` | 输出修复指令及独立的人工操作清单 |
| `--report[=file]` | 写入 HTML，默认 `canship-report.html` |
| `--sarif[=file]` | 写入 SARIF 2.1.0，默认 `canship.sarif` |
| `--no-excerpts` | 省略源码摘录，保留结果和退出码 |
| `--changed-since=ref` | 展示与变更文件相关的结果，退出码仍基于全量扫描 |
| `--only=ids` / `--skip=ids` | 选择或排除规则，支持逗号分隔及重复参数 |
| `--list-rules` | 列出规则而不扫描，支持 `--json` |
| `--baseline[=file]` | 抑制已有结果，默认 `canship-baseline.json` |
| `--baseline-write[=file]` | 记录结果后退出，默认路径同上 |
| `--no-config` | 忽略项目配置 |
| `--no-ignore-markers` | 不遵从源码忽略注释 |
| `--best-effort` | 允许没有结果的不完整扫描退出 `0` |
| `-h`、`--help` / `-v`、`--version` | 显示帮助或版本 |

`--json` 与 `--fix-prompt` 互斥；HTML、SARIF 可与任一模式组合。

### 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 无结果，且扫描完整或已由 `--best-effort` 接受不完整状态 |
| `1` | 至少一条 `certain` 的 P0/P1 结果 |
| `2` | 其他结果，包括隐藏的 `likely` |
| `3` | 参数错误、工具错误或未被接受的不完整扫描 |

退出码基于规则筛选、忽略标记及基线处理后的结果。结果优先于不完整状态；`--best-effort` 不改变 `1` 或 `2`。

### 变更视图与报告

`--changed-since=origin/main` 比较本地共同祖先与工作区，包含未被 Git 忽略的新文件，不拉取远程。仍扫描全项目，仅展示主位置或证据位置发生变更的结果；仓库级结果及证据链截断的结果保留。隐藏结果仍影响退出码。缺少 Git、引用或共同历史时退出 `3`，`--best-effort` 不豁免。不能与 `--baseline-write` 组合。

JSON 使用 `schemaVersion: 1`；字段及筛选统计见 [结构定义](./schemas/scan-report-v1.schema.json)。须独立于退出码检查 `partial`、`errors`、`skipped`、`filesScanned`。兼容新增字段，拒绝不支持的结构版本。

SARIF 包含执行诊断与证据位置。`--list-rules --json` 返回独立的 `kind: "rule-catalog"` 文档。

## 配置

扫描目录中的 `canship.config.json` 支持 `baseline`、`only`、`skip`、`all`：

```json
{
  "skip": ["cors/wildcard-with-credentials"],
  "all": false
}
```

命令行参数优先。`only`、`skip` 互斥，接受规则 ID 或命名空间。`--best-effort` 仅限命令行。不可信项目使用 `--no-config --no-ignore-markers`。

### 忽略注释

独占注释行的 `canship-ignore-file` 排除整个文件；`canship-ignore-next-line` 抑制下一行，可限定规则：

```ts
// canship-ignore-next-line cors/wildcard-with-credentials
const corsOptions = { origin: '*', credentials: true }
```

报告披露排除信息。主动抑制不标记扫描未完成，可使退出码降为 `0`。`--no-config` 不禁用这些注释。

### 基线

记录已有结果，后续扫描再抑制：

```powershell
npx canship --baseline-write
```

```powershell
npx canship --baseline
```

默认路径相对扫描目录，显式路径相对工作目录；读取与写入模式互斥。写入成功退出 `0`，不代表扫描无问题；扫描不完整或启用规则筛选时会提示。

v2 指纹不受行号移动影响，凭据变化会改变指纹。缺失、损坏及 v1 基线均退出 `3`。基线不含摘录，但保留路径、规则和描述，提交前需审阅。

## API

提供 Node.js ESM 入口与 TypeScript 类型：

```js
import { scan, summarize, listRules } from 'canship'

const result = await scan('./my-app', { noExcerpts: true })
console.log(summarize(result))
console.log(listRules())
```

`scan()` 返回全部置信度结果，支持 `only`、`skip`、`honorIgnoreMarkers`（默认 `true`）、`noExcerpts`（默认 `false`）。不加载配置、不应用基线、不写报告、不设置退出码。无效参数或根目录抛出异常；扫描缺口保留在结果中。

`summarize()` 返回结果统计、`partial` 及默认 CLI 退出码。`listRules()` 返回独立的规则目录副本。

## GitHub Action

保存为 `.github/workflows/canship.yml`。Action 安装指定 npm 扫描器并输出统计摘要，不安装或运行项目依赖；SARIF 需显式启用上传。

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
      - uses: Tasomei/canship@97c14d1f1e494a49adf716c455b597edf6ae1d88
        with:
          version: '0.5.0'
          honor-ignore-markers: false
```

提交号固定 Action 实现；`version` 选择 npm 扫描器，不使用仓库源码。该固定实现默认安装 0.5.0。

| 输入 | 默认值 | 说明 |
|---|---|---|
| `version` | `0.5.0` | 精确 npm 版本，不接受范围或标签 |
| `fail-on` | `blocking` | `blocking`：确定的 P0/P1；`any`：全部结果；`none`：仅报告 |
| `use-config` | `false` | 启用项目配置 |
| `honor-ignore-markers` | `true` | 遵从整文件及逐行忽略注释 |
| `upload-sarif` | `false` | 上传至 GitHub 代码扫描 |

路径、规则筛选、基线及分类输入见 [action.yml](./action.yml)。

输出：`exit-code`、`findings`、`blocking`、`partial`。统计包含抑制后的疑似结果。扫描不完整、工具错误或报告不兼容始终失败，`fail-on: none` 也不例外。

上传 SARIF 需 `security-events: write` 及代码扫描支持；Fork PR 可能权限不足。上传前需审阅报告。不可信 PR 使用 `pull_request`，不要使用 `pull_request_target`。Action 设置 Node.js 22，必要时使用独立扫描任务。

## 隐私与限制

- 静态检查可能漏报或将预期配置报为问题，不验证线上行为、业务授权、限流、注入或依赖漏洞。无结果不等于安全。
- 脱敏仅覆盖已识别格式。未知敏感值可能保留在摘录中；`--no-excerpts` 移除摘录并设置 JSON `excerptsOmitted`。路径、名称、描述和基线不匿名化。
- Google/Firebase/Maps 的 `AIza...` 密钥按公开标识符处理，不单凭其值判定泄露。
- Supabase 检查依据本地迁移及支持的存储桶配置，不检查控制台专属改动或省略子句隐含的策略条件。
- 不跟随符号链接；嵌套仓库与子模块需单独扫描。范围内跳过项使扫描未完成，内置依赖/构建目录排除除外。

| 限制 | 上限 |
|---|---|
| 文件读取，含探测 | 单文件 2 MiB；单次 128 MiB、10,000 个文件 |
| 目录遍历 | 50,000 个条目、16 层 |
| 结果数量 | 每文件 100 条，优先保留高严重度、高置信度结果 |
| Git 历史 | 每文件 100 个相关版本；单条命令 30 秒 |
| 鉴权解析 | 8 跳；每个路由文件 128 个符号 |
| 身份/控制流 | 值解析 8 步；表达式 4,000 字符；每函数 512 个赋值/条件区域；分支/异常区域嵌套 8 层 |
| Supabase 策略/存储桶解析 | 单条语句 4,000 字符 |

扫描或分析超限会报告未完成。证据链最多 24 步，截断时提示。身份获取函数名及导入关系仍属语法证据，不验证运行时实现。

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

新增规则须包含应检出与不应检出的 [夹具](./test/fixtures/)。运行离线评估：

```powershell
npm run evaluate
```

应用评估见 [快照清单](./test/evaluation/projects.json)、[获取脚本](./scripts/fetch-evaluation-projects.mjs) 及 [离线评估器](./scripts/evaluate-projects.ts)。测试在临时副本中比较原项目与成对变体，不运行样本依赖；不衡量真实检出率、Git 历史覆盖率或线上行为。

## 许可

[MIT](./LICENSE)。Supabase/Firebase 夹具保留 Apache-2.0，Next.js/`cors` 夹具保留 MIT；来源与许可证随夹具保存。
