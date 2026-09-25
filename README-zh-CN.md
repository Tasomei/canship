# canship

面向 JavaScript / TypeScript 项目的本地静态扫描器，检测凭据暴露与访问控制配置错误。扫描不执行项目代码、不上传文件、不联网。

本文档对应 0.3.x，适用于匹配的 [npm 版本](https://www.npmjs.com/package/canship) 或本地构建。

```powershell
npx canship .
```

要求 Node.js ≥18，无运行时依赖。`npx` 可能联网下载软件包；扫描仅使用本地文件与 Git 历史。Git 仓库中无法调用 Git 时，扫描标记为未完成。

[English](./README.md)

## 检测范围

| 检查项 | 级别 |
|---|---|
| 硬编码凭据、私钥及含密码的数据库连接串 | P0 |
| 公开环境变量中的私密值 | P0 |
| Supabase 管理员密钥暴露至客户端 | P0 |
| Git 跟踪及历史 `.env` 文件中的凭据或疑似私密值 | P0 |
| Supabase 迁移记录中未启用行级安全（RLS）的表 | P1 |
| Firebase 无条件访问及固定日期测试规则 | P1 |
| 服务端路由数据操作未识别到鉴权 | P0 / P1 |
| 携带凭据的 CORS 来源回显或通配符配置 | P1 / P2 |

支持 OpenAI、Anthropic、AWS、Stripe、GitHub、npm、Slack、SendGrid 等凭据格式及常见前端公开环境变量前缀。API 鉴权检查覆盖以下框架的服务端路由：Next.js（App Router 与 Pages Router 的 `/api`）、SvelteKit（`+server` 端点）、Nuxt（`server/api` 与 `server/routes`）、Remix 与 React Router（`app/routes` 中导出 `loader` 或 `action` 的模块）、Astro（`src/pages` 中的端点），支持路由组和工作区应用。不检查 SvelteKit 的页面 load 与表单 action。SvelteKit `hooks.server` 或 Nuxt `server/middleware` 中的鉴权会降低结果置信度而不是直接隐藏结果，因为它覆盖哪些路由由代码决定。

置信度分为确定（`certain`）和疑似（`likely`），仅描述静态证据，不验证凭据有效性或线上状态。默认只展示确定结果；隐藏的疑似结果仍影响退出码。

## 用法

省略路径时扫描当前目录。

| 参数 | 说明 |
|---|---|
| `-a`, `--all` | 展示疑似结果 |
| `--json` | 输出 JSON |
| `--fix-prompt` | 输出修复指令及独立的人工操作清单 |
| `--report[=file]` | 写入 HTML，默认 `canship-report.html` |
| `--sarif[=file]` | 写入 SARIF 2.1.0，默认 `canship.sarif` |
| `--best-effort` | 无结果时，允许不完整扫描退出 `0` |
| `--baseline[=file]` | 应用基线，默认 `canship-baseline.json` |
| `--baseline-write[=file]` | 写入当前结果为基线后退出，同上默认路径 |
| `--only=ids` | 仅执行匹配规则，支持逗号分隔及重复参数 |
| `--skip=ids` | 排除匹配规则，支持逗号分隔及重复参数 |
| `--no-config` | 忽略项目配置 |
| `--no-ignore-markers` | 不遵从被扫描源码中的忽略标记 |
| `--list-rules` | 列出规则及限制，不扫描；支持 `--json` |
| `--no-excerpts` | 所有报告省略源码摘录，不改变结果和退出码 |
| `-h`, `--help` | 显示帮助 |
| `-v`, `--version` | 显示版本 |

`--json` 与 `--fix-prompt` 互斥；HTML、SARIF 可与任一模式组合。报告正文为英文，`--all` 对所有格式生效。

### 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 无结果，且扫描完整或由 `--best-effort` 接受不完整扫描 |
| `1` | 存在 `certain` 的 P0/P1 结果 |
| `2` | 存在其他结果，包括被隐藏的 `likely` |
| `3` | 参数或工具错误，或未被接受的不完整扫描 |

结果退出码优先于不完整状态；`--best-effort` 不改变 `1` 或 `2`。

### 机器可读输出

JSON 使用独立于包版本的 `schemaVersion: 1`，npm 包附带 [结构定义](./schemas/scan-report-v1.schema.json)。调用方应兼容新增字段、拒绝不支持的结构版本；`--list-rules --json` 为独立的 `kind: "rule-catalog"` 文档。

`findings` 为抑制和筛选后的结果；`hiddenLikely`、`baselineSuppressed`、`baselineStale` 提供相关统计。完整性需另查 `partial`、`errors`、`skipped`、`filesScanned`；SARIF 提供执行状态与诊断通知。

## GitHub Action

保存为 `.github/workflows/canship.yml`，在推送和 PR 时扫描并生成统计摘要。安装扫描器需要联网，扫描不联网；不安装或执行项目依赖，默认不上传 SARIF。

示例固定 Action 提交，显式安装 npm 版 `0.3.1`；`version` 不使用仓库中的未发布源码。Action 兼容 0.2.1 无 `schemaVersion` 的报告。

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
      - uses: Tasomei/canship@2d33cce0ad8439e34f01f5218fdaaf4657215e3d
        with:
          version: '0.3.1'
```

| 输入 | 默认值 | 说明 |
|---|---|---|
| `path` | `.` | 检出目录内的扫描路径 |
| `version` | `0.3.1` | 精确 npm 版本，不接受范围或标签 |
| `fail-on` | `blocking` | `blocking`：确定的 P0/P1；`any`：全部结果；`none`：仅报告结果 |
| `only` / `skip` | 未设置 | 互斥，逗号分隔的规则选择器 |
| `baseline` | 未设置 | 相对扫描目录的已有基线 |
| `use-config` | `false` | 启用项目配置 |
| `upload-sarif` | `false` | 上传 SARIF 至 GitHub 代码扫描 |
| `category` | `canship` | 每个扫描目标使用独立分类 |

输出：`exit-code`、`findings`、`blocking`、`partial`。策略统计包含疑似结果，基线与忽略仍生效；扫描不完整、工具错误或报告不兼容始终失败，包括 `fail-on: none`。

上传 SARIF 需 `security-events: write` 及 [GitHub 代码扫描支持](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)，Fork PR 可能无权限。上传前审阅报告中的路径与详情；不可信 PR 使用 `pull_request`，不要使用 `pull_request_target`。Action 为后续步骤设置 Node.js 22，需要其他版本时应使用独立扫描任务。

## 配置与基线

扫描目录中的 `canship.config.json` 支持 `baseline`、`only`、`skip`、`all`：

```json
{
  "skip": ["cors/wildcard-with-credentials"],
  "all": false
}
```

命令行参数优先；`only`、`skip` 互斥，接受规则 ID 或命名空间。未选规则不执行，`ruleSelection.removed` 仅统计已执行规则中被过滤的结果。扫描不可信项目时同时使用 `--no-config --no-ignore-markers`，二者均由被扫描项目控制；`bestEffort` 仅限命令行设置。

### 忽略标记

独占注释行的 `canship-ignore-file` 排除整个文件；`canship-ignore-next-line` 忽略下一行，可附规则 ID：

```ts
// canship-ignore-next-line cors/wildcard-with-credentials
const corsOptions = { origin: '*', credentials: true }
```

报告披露忽略、规则筛选和基线抑制信息；主动排除不标记为未完成。标记可使退出码降为 `0`；`--no-config` 不影响标记，`--no-ignore-markers` 使两种标记均失效。

### 基线

记录已有结果：

```powershell
npx canship --baseline-write
```

仅报告新增结果：

```powershell
npx canship --baseline
```

默认基线位于扫描目录，显式路径相对工作目录。写入成功退出 `0`，不代表无问题；扫描不完整或启用规则筛选时会提示。

基线格式为 v2，移动行号不改变指纹，替换凭据会改变。缺失、损坏及 v1 基线均退出 `3`。基线不含源码，但包含路径、规则和问题描述，提交前需审阅。

## 隐私与限制

- 静态分析可能误报或漏报，不验证线上行为，不覆盖限流、注入、依赖漏洞或业务授权。无结果不等于安全。
- 脱敏仅覆盖已识别格式，未知秘密可能出现在源码摘录中。`--no-excerpts` 省略摘录，JSON 以 `excerptsOmitted` 标明；路径、名称、说明及基线不匿名化，分享前仍需审阅。
- Google/Firebase/Maps 的 `AIza...` 值按公开标识符处理，不单凭其值判定泄露。
- 读取上限：单文件 2 MiB，单次 128 MiB、10,000 个文件，目录 16 层。每文件跨规则最多 100 条结果，优先保留高严重度、高置信度结果。
- Git 历史每文件最多 100 个相关版本，单条 Git 命令超时 30 秒。超限、超时均报告检查缺口。
- 不跟随符号链接；嵌套仓库、子模块需单独扫描。范围内跳过项使扫描未完成，内置排除的构建和依赖目录除外。

## 开发

新增规则需包含应检出与不应检出的 [测试用例](./test/fixtures/)。

```powershell
npm ci
```

```powershell
npm run prepublishOnly
```

离线评估：

```powershell
npm run evaluate
```

评估集含 10 个构造用例、9 个固定版本上游示例及变体，同时纳入 `npm test`；[来源与许可](./test/fixtures/evaluation/) 随样本保存。断言覆盖规则、文件、严重度、置信度与扫描完整性，不代表真实项目检出率。

另有 5 个 [应用目录快照](./test/evaluation/projects.json)。准备阶段联网并校验 Git 对象摘要，目标须为 Git 仓库外的新目录：

```powershell
node scripts/fetch-evaluation-projects.mjs "$env:TEMP/canship-evaluation"
```

随后离线评估，不安装或运行样本依赖：

```powershell
npm run evaluate:projects -- "$env:TEMP/canship-evaluation"
```

CI 使用同一评估集，不验证 Git 历史或线上行为。

## 许可

[MIT](./LICENSE)。Supabase、Firebase 样本保留 Apache-2.0，Next.js、`cors` 样本保留 MIT；各样本附来源及许可证。
