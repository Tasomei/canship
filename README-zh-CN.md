# canship

面向 JavaScript / TypeScript 项目的本地静态扫描器，检测凭据暴露与访问控制配置错误。扫描不执行项目代码、不上传文件、不联网。

[English](./README.md)

## 快速开始

```powershell
npx canship .
```

要求 Node.js ≥18，无运行时依赖。安装软件包可能联网；Git 检查仅使用本地历史。仓库中无法调用 Git 时，扫描标记为未完成。

> 本文对应 0.4.0，较早的 [npm 版本](https://www.npmjs.com/package/canship) 可能不包含下述全部功能。

## 检测范围

| 检查项 | 级别 |
|---|---|
| 硬编码凭据、私钥及含密码的数据库连接串 | P0 |
| 公开环境变量中的私密值 | P0 |
| 源码或公开环境变量中的 Supabase 管理员凭据 | P0 |
| Git 跟踪及历史 `.env` 文件中的凭据或疑似私密值 | P0 |
| Supabase 迁移中未启用行级安全（RLS）的表 | P1 |
| Supabase 条件恒为真的 RLS 策略 | P1 |
| 内容可被列举的 Supabase 公开存储桶 | P2 |
| Firebase 无条件访问及固定日期测试规则（Firestore、Storage、Realtime Database） | P1 |
| 服务端数据操作未识别到鉴权 | P0 / P1 |
| 携带凭据的 CORS 来源回显或通配符配置 | P1 / P2 |

识别 OpenAI、Anthropic、AWS、Stripe、GitHub、npm 等凭据格式及常见前端公开环境变量前缀。规则 ID、范围与限制见 `--list-rules`。

### 鉴权检查范围

| 框架 | 检查入口 |
|---|---|
| Next.js | `app/` 下的 route 处理函数、Pages Router `/api`、`'use server'` 函数 |
| SvelteKit | `+server` 端点及 `+page.server` 表单 action |
| Nuxt | `server/api`、`server/routes` |
| Remix / React Router | `app/routes` 中导出的 `loader`、`action` |
| Astro | `src/pages` 中的端点 |

支持路由组和工作区应用，不检查 SvelteKit 页面 load 与 remote function。已识别的 Next.js、Astro 中间件鉴权可抑制覆盖路由的结果；Server Function 需在函数内鉴权。SvelteKit hooks、Nuxt 中间件及本地鉴权函数可降低置信度，但不抑制结果。

Supabase 检查重放本地迁移并读取支持的存储桶配置，不检查仅在控制台修改的配置或省略子句隐含的策略条件。

### 置信度与证据

`certain`（确定）与 `likely`（疑似）描述静态证据，不验证凭据有效性或线上状态。默认仅展示 `certain`；隐藏的 `likely` 仍影响退出码。

管理员客户端相关结果附带数据操作、导入和客户端构造位置。支持限定语法内的 Supabase 构造器别名、本地鉴权导入、重导出及返回函数的封装。鉴权解析最多 8 跳，证据链最多 24 步，截断时提示。间接鉴权证据仅降低置信度；导入关系不证明运行时数据流。

## 命令行

省略路径时扫描当前目录。报告正文为英文。

| 参数 | 作用 |
|---|---|
| `-a`, `--all` | 所有格式包含 `likely` 结果 |
| `--json` | 输出 JSON |
| `--fix-prompt` | 输出修复指令及独立的人工操作清单 |
| `--report[=file]` | 写入 HTML，默认 `canship-report.html` |
| `--sarif[=file]` | 写入 SARIF 2.1.0，默认 `canship.sarif` |
| `--no-excerpts` | 省略源码摘录，不改变结果和退出码 |
| `--changed-since=ref` | 按变更文件筛选报告，不改变扫描范围和退出码 |
| `--only=ids` / `--skip=ids` | 选择或排除规则，支持逗号分隔及重复参数 |
| `--list-rules` | 列出规则，不扫描；支持 `--json` |
| `--baseline[=file]` | 抑制基线结果，默认 `canship-baseline.json` |
| `--baseline-write[=file]` | 记录结果后退出，默认路径同上 |
| `--no-config` | 忽略项目配置 |
| `--no-ignore-markers` | 不遵从源码忽略标记 |
| `--best-effort` | 无结果时，允许不完整扫描退出 `0` |
| `-h`, `--help` / `-v`, `--version` | 显示帮助或版本 |

`--json` 与 `--fix-prompt` 互斥；HTML、SARIF 可与任一模式组合。

### 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 无结果；扫描完整，或由 `--best-effort` 接受不完整状态 |
| `1` | 存在 `certain` 的 P0/P1 结果 |
| `2` | 存在其他结果，包括隐藏的 `likely` |
| `3` | 参数或工具错误，或未被接受的不完整扫描 |

统计以规则筛选、忽略标记和基线处理后的结果为准。结果退出码优先于不完整状态；`--best-effort` 不改变 `1` 或 `2`。

### 变更文件视图

`--changed-since=origin/main` 比较本地共同祖先与工作区，包含未被 Git 忽略的新文件，不拉取远程。仍扫描全项目，仅展示主位置或证据位置发生变更的结果；仓库级结果及证据链截断的结果保留。

隐藏结果仍影响退出码：此功能用于审阅，不是“仅新增问题阻断 CI”的策略。缺少 Git、引用或共同历史时退出 `3`，`--best-effort` 不豁免。不能与 `--baseline-write` 组合。

### 结构化报告

JSON 使用 `schemaVersion: 1`，包内附带 [结构定义](./schemas/scan-report-v1.schema.json)。调用方应兼容新增字段，拒绝不支持的结构版本。

- `findings`：抑制及展示筛选后的结果。
- `hiddenLikely`、`baselineSuppressed`、`baselineStale`：筛选与基线统计。
- `partial`、`errors`、`skipped`、`filesScanned`：扫描完整性，须独立于退出码检查。
- `changeView`：启用变更视图时的筛选统计及全量扫描统计。

SARIF 包含执行诊断与证据关联位置。`--list-rules --json` 返回独立的 `kind: "rule-catalog"` 文档。

## 程序化 API

提供 Node.js ESM 入口及 TypeScript 类型：

```js
import { scan, summarize, listRules } from 'canship'

const result = await scan('./my-app', { noExcerpts: true })
console.log(summarize(result))
console.log(listRules())
```

`scan()` 返回全部置信度结果，支持 `only`、`skip`、`honorIgnoreMarkers`（默认 `true`）、`noExcerpts`（默认 `false`）。不读取项目配置、不应用基线、不写报告、不设置进程退出码。无效参数或根目录抛出异常；扫描缺口保留在结果中。

`summarize()` 返回结果数、阻断数、疑似数、`partial` 及默认 CLI 退出码。`listRules()` 返回独立的规则目录副本。

## GitHub Action

保存为 `.github/workflows/canship.yml`。Action 安装指定 npm 版本，扫描检出目录并生成统计摘要；不安装或执行项目依赖，SARIF 需显式启用上传。

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
      - uses: Tasomei/canship@b4cbbfe6b5c4c88164b9388d121f7651032259a4
        with:
          version: '0.4.0'
```

提交号固定 Action 实现；`version` 选择 npm 扫描器，不使用仓库源码。该固定提交默认安装 0.3.2；示例显式选择 0.4.0。

| 输入 | 默认值 | 说明 |
|---|---|---|
| `path` | `.` | 检出目录内的扫描路径 |
| `version` | `0.3.2` | 精确 npm 版本，不接受范围或标签 |
| `fail-on` | `blocking` | `blocking`：确定的 P0/P1；`any`：全部结果；`none`：仅报告 |
| `only` / `skip` | 未设置 | 互斥的规则选择器 |
| `baseline` | 未设置 | 相对扫描目录的已有基线 |
| `use-config` | `false` | 启用项目配置 |
| `upload-sarif` | `false` | 上传至 GitHub 代码扫描 |
| `category` | `canship` | 扫描目标的 SARIF 分类 |

输出：`exit-code`、`findings`、`blocking`、`partial`。统计包含基线与排除处理后的疑似结果。扫描不完整、工具错误或报告不兼容始终失败，`fail-on: none` 也不例外。

上传 SARIF 需 `security-events: write` 及 [代码扫描支持](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)，Fork PR 可能权限不足。上传前需审阅报告。不可信 PR 使用 `pull_request`，不要使用 `pull_request_target`。Action 为后续步骤设置 Node.js 22；需要其他版本时使用独立扫描任务。

## 配置与基线

扫描目录中的 `canship.config.json` 支持 `baseline`、`only`、`skip`、`all`：

```json
{
  "skip": ["cors/wildcard-with-credentials"],
  "all": false
}
```

命令行参数优先。`only`、`skip` 互斥，接受规则 ID 或命名空间。`--best-effort` 仅限命令行。扫描不可信项目时使用 `--no-config --no-ignore-markers`。

### 忽略标记

独占注释行的 `canship-ignore-file` 排除整个文件；`canship-ignore-next-line` 抑制下一行，可限定规则：

```ts
// canship-ignore-next-line cors/wildcard-with-credentials
const corsOptions = { origin: '*', credentials: true }
```

报告披露排除与抑制信息。主动排除不标记为未完成，可使退出码降为 `0`。`--no-config` 不禁用标记，`--no-ignore-markers` 才会禁用。

### 基线

记录已有结果：

```powershell
npx canship --baseline-write
```

后续扫描抑制这些结果：

```powershell
npx canship --baseline
```

默认路径相对扫描目录，显式路径相对工作目录；读取与写入模式互斥。写入成功退出 `0`，不表示无问题；扫描不完整或启用规则筛选时会提示。

基线格式为 v2，移动行号不改变指纹，替换凭据会改变。缺失、损坏及 v1 基线均退出 `3`。基线不含源码摘录，但包含路径、规则和问题描述，提交前需审阅。

## 隐私与限制

- 静态检查可能漏报或将预期配置报为问题，不验证线上行为，不覆盖限流、注入、依赖漏洞或业务授权。无结果不等于安全。
- 脱敏仅覆盖已识别格式。未识别的敏感值可能保留在摘录中；`--no-excerpts` 移除摘录，并设置 JSON `excerptsOmitted`。路径、名称、说明和基线不匿名化。
- Google/Firebase/Maps 的 `AIza...` 密钥按公开标识符处理，不单凭其值判定泄露。
- 读取上限：单文件 2 MiB，单次 128 MiB、10,000 个文件，目录 16 层。每文件跨规则最多 100 条结果，优先保留高严重度、高置信度结果。
- Git 历史每文件最多 100 个相关版本，单条命令超时 30 秒；Supabase 策略及存储桶语句最多解析 4,000 个字符。超限报告扫描未完成。
- 不跟随符号链接；嵌套仓库、子模块需单独扫描。范围内跳过项使扫描未完成，内置排除的依赖和构建目录除外。

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

新增规则需包含应检出与不应检出的 [夹具](./test/fixtures/)。运行离线 [评估集](./test/fixtures/evaluation/)：

```powershell
npm run evaluate
```

[应用快照](./test/evaluation/projects.json) 需先联网获取并校验来源，目标为 Git 仓库外的新目录：

```powershell
node scripts/fetch-evaluation-projects.mjs "$env:TEMP/canship-evaluation"
```

随后离线评估：

```powershell
npm run evaluate:projects -- "$env:TEMP/canship-evaluation"
```

项目评估使用临时副本，比较原项目及开放、受限测试变体的全部结果，不安装或运行样本依赖。这些测试不衡量真实项目检出率、Git 历史覆盖率或线上行为。

## 许可

[MIT](./LICENSE)。Supabase、Firebase 夹具保留 Apache-2.0，Next.js、`cors` 夹具保留 MIT；来源与许可证随夹具保存。
