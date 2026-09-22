# canship

面向 JavaScript / TypeScript 项目的本地静态扫描器，检测凭据暴露和访问控制配置错误。不执行项目代码，不上传文件，扫描过程不联网。

```powershell
npx canship .
```

要求 Node.js ≥18，无运行时依赖。Git 用于读取本地历史；仓库中无法使用 Git 时，扫描标记为未完成。首次使用 `npx` 可能需要从 npm 下载软件包。

[English](./README.md)

## 检测范围

| 检查项 | 级别 |
|---|---|
| 硬编码凭据、私钥及含密码的数据库连接串 | P0 |
| 公开环境变量中的私密值 | P0 |
| 客户端可访问的 Supabase 管理员密钥 | P0 |
| Git 跟踪及历史 `.env` 文件中的凭据或疑似私密值 | P0 |
| Supabase 表未启用行级安全（RLS） | P1 |
| Firebase 无条件访问及固定日期测试规则 | P1 |
| Next.js API 数据操作缺少鉴权 | P0 / P1 |
| 携带凭据的 CORS 来源回显或通配符配置 | P1 / P2 |

识别 OpenAI、Anthropic、AWS、Stripe、GitHub、npm、Slack、SendGrid 等凭据格式及常见前端框架的公开环境变量前缀。API 鉴权检查限于 Next.js 的 `/api` 处理函数，支持 App Router、Pages Router、路由组和工作区应用。

置信度分为确定（`certain`）和疑似（`likely`）。默认只展示确定结果；隐藏的疑似结果仍影响退出码。

## 参数

省略路径时扫描当前目录。

| 参数 | 说明 |
|---|---|
| `-a`, `--all` | 展示疑似结果 |
| `--json` | 输出 JSON |
| `--fix-prompt` | 输出编程助手修复指令及独立的人工操作清单 |
| `--report[=文件]` | 写入 HTML 报告，默认 `canship-report.html` |
| `--sarif[=文件]` | 写入 SARIF 2.1.0 报告，默认 `canship.sarif` |
| `--best-effort` | 无结果时，允许不完整扫描退出 `0` |
| `--baseline[=文件]` | 应用基线，默认 `canship-baseline.json` |
| `--baseline-write[=文件]` | 记录当前结果为基线后退出 |
| `--only=规则` | 仅执行匹配规则，支持逗号分隔及重复参数 |
| `--skip=规则` | 排除匹配规则，支持逗号分隔及重复参数 |
| `--no-config` | 忽略项目配置 |
| `-h`, `--help` | 显示帮助 |
| `-v`, `--version` | 显示版本 |

`--json` 与 `--fix-prompt` 互斥；HTML 和 SARIF 可与任一输出模式组合。报告正文为英文，各格式均用 `--all` 包含疑似结果。

### 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 无结果且扫描完整，或由 `--best-effort` 接受不完整扫描 |
| `1` | 存在 `certain` 的 P0/P1 结果 |
| `2` | 存在其他结果，包括被隐藏的 `likely` |
| `3` | 参数或工具错误，或未被接受的不完整扫描 |

结果对应的退出码优先于不完整状态；`--best-effort` 不改变 `1` 或 `2`。JSON 用 `partial`、`errors`、`skipped` 保留完整性信息，SARIF 提供执行状态和诊断通知。

### JSON 契约

JSON 包含独立于软件包 `version` 的 `schemaVersion: 1`。调用方应兼容新增字段，拒绝不支持的结构版本。已发布的 0.2.1 不含此字段，Action 同时兼容该旧格式。

`findings` 为抑制和可见性筛选后的结果；`hiddenLikely`、`baselineSuppressed`、`baselineStale` 保留筛选统计。应单独检查 `partial`、`errors`、`skipped` 和 `filesScanned`，不能仅凭结果或退出码判断完整性。

## GitHub Action

将以下配置保存为 `.github/workflows/canship.yml`，在推送和 PR 时自动扫描仓库，生成仅含统计的摘要。不安装或执行项目依赖；安装扫描器需要联网，扫描不联网，默认不上传 SARIF。

示例将 Action 固定到已通过测试的提交，并安装已发布的扫描器 `0.2.1`。`version` 指定 npm 包版本，不包含尚未发布的源码改动。

```yaml
name: canship
on: [push, pull_request]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: Tasomei/canship@f10ba0d2d08d79ee354907fff0c0f646995b8c1f
        with:
          version: '0.2.1'
```

| 输入 | 默认值 | 说明 |
|---|---|---|
| `path` | `.` | 检出目录内的扫描路径 |
| `version` | `0.2.1` | 精确 npm 版本，不接受范围或标签 |
| `fail-on` | `blocking` | `blocking`：确定的 P0/P1；`any`：全部结果；`none`：仅报告结果 |
| `only` / `skip` | 未设置 | 互斥，逗号分隔的规则选择器 |
| `baseline` | 未设置 | 相对扫描目录的已有基线 |
| `use-config` | `false` | 启用项目配置 |
| `upload-sarif` | `false` | 上传 SARIF 至 GitHub 代码扫描 |
| `category` | `canship` | 每个扫描目标使用独立分类 |

扫描不完整、工具错误或报告不兼容始终失败，`fail-on: none` 也不例外。输出为 `exit-code`、`findings`、`blocking`、`partial`，所有置信度均参与策略判定。基线、源码忽略标记和内置排除仍然生效，需一并审阅扫描范围。

上传 SARIF 需要 `security-events: write`，且仓库须支持 [GitHub 代码扫描](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file)。Fork PR 可能没有上传权限。报告含路径及发现详情，启用上传前需评估披露风险。不可信贡献使用 `pull_request`，不要使用 `pull_request_target`。Action 会将后续步骤的 Node.js 设为 22；项目需要其他版本时，使用独立扫描任务。

## 配置与忽略

扫描目录中的 `canship.config.json` 支持 `baseline`、`only`、`skip`、`all`：

```json
{
  "skip": ["cors/wildcard-with-credentials"],
  "all": false
}
```

命令行参数优先；`only` 与 `skip` 互斥，接受完整规则 ID 或命名空间。无关规则不执行；`ruleSelection.removed` 仅统计已执行规则中被过滤的结果。扫描不可信项目时使用 `--no-config`；`bestEffort` 仅支持命令行设置。

以独占注释行的 `canship-ignore-file` 排除整个文件，或用 `canship-ignore-next-line` 忽略下一行。后者可附加规则 ID：

```ts
// canship-ignore-next-line cors/wildcard-with-credentials
const corsOptions = { origin: '*', credentials: true }
```

报告披露忽略、筛选和基线抑制信息。主动忽略不使扫描标记为未完成。

## 基线

记录已有结果：

```powershell
npx canship --baseline-write
```

仅报告新增结果：

```powershell
npx canship --baseline
```

裸参数使用扫描目录，显式路径相对工作目录。写入成功退出 `0`；扫描不完整或启用规则筛选时会提示。

基线格式为第 2 版，不含源码摘录，但披露路径、规则、标题和问题类型，提交前需审阅。指纹不含行号，移动行号不会产生新结果，替换凭据会。缺失、损坏及第 1 版基线均退出 `3`。

## 限制

- 静态启发式分析可能误报或漏报，不验证运行时行为、限流、注入、依赖漏洞及业务授权。无发现不代表项目安全。
- 脱敏仅覆盖已识别格式；未知秘密可能出现在证据行中，报告应作为内部材料。Google/Firebase/Maps 的 `AIza...` 值按公开标识符处理。
- 单文件最多读取 2 MiB；单次累计读取最多 128 MiB、10,000 个文件；目录最多 16 层。跨规则每文件最多输出 100 条结果，优先保留高严重度、高置信度结果。
- Git 历史每文件最多检查 100 个相关版本，单条 Git 命令超时为 30 秒。超限或超时均披露检查缺口。
- 不跟随符号链接；嵌套仓库及子模块需分别扫描。扫描范围内的跳过项使扫描未完成，已排除的构建和依赖目录除外。

## 开发

检测规则需同时包含应检出和不应检出的用例，参见 [测试夹具](./test/fixtures/)。

```powershell
npm ci
```

```powershell
npm run prepublishOnly
```

运行离线初始评估集：

```powershell
npm run evaluate
```

12 个用例覆盖跨文件 API 鉴权、工作区路由、RLS 迁移重放、Firebase 规则、CORS 及扫描完整性。其中 10 个为人工构造，2 个基于同一份 Supabase 迁移文件改编，固定提交及许可证保存在 `test/fixtures/evaluation/`。评估比较规则、文件、严重度、置信度和完整性，列出漏报及额外结果；不代表真实项目检出率。用例同时纳入 `npm test`。

## 许可

[MIT](./LICENSE)。Supabase 测试样本保留 [Apache-2.0 许可](./test/fixtures/evaluation/supabase-profiles/LICENSE)。
