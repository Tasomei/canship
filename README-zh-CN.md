# canship

面向 JavaScript / TypeScript Web 应用的本地静态扫描器，检查凭据暴露、访问控制配置及请求输入风险。扫描不执行项目代码、不上传文件、不联网。

[English](./README.md)

> 本文对应开发分支。npm `0.7.1` 请参阅[发行版文档](https://github.com/Tasomei/canship/blob/v0.7.1/README-zh-CN.md)。使用 `npx canship --version` 确认版本。

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
| Hono | 方法路由、`OpenAPIHono.openapi()` / `openapiRoutes()`、链式调用、`basePath`、`app.route()` 子应用 |
| Fastify | 简写与 `route()` 声明、`register()` 前缀与封装作用域、`@fastify/autoload` 目录 |

已识别的 Next.js/Astro 中间件可抑制匹配路由的鉴权结果；Server Function 需在函数内检查。Express/Hono/Fastify 仅接受已解析的拒绝逻辑或已知鉴权库。Fastify 装饰器和插件的保护证据限定于当前实例。

会话校验及 webhook 验签（Stripe、Polar、Clerk、Svix、QStash）须在失败时拒绝请求，异步调用须等待或返回。项目辅助函数与包装器、SvelteKit hooks、Nuxt 中间件的间接证据可降低置信度；未解析的鉴权来源不能消除结果。

输入追踪支持赋值、解构、字符串构造及可解析的跨文件透传函数，不以辅助函数名称证明输入已净化。

Express、Hono、Fastify 路由会跟进被调项目函数中的写入，最多两层（处理函数 → service → model）；文件约定路由只报告路由文件内的写入。路由分析不覆盖 SvelteKit 页面 load 和 remote function；凭据、CORS 等内容规则仍适用。

OpenAPI 配置支持内联对象、常量及静态 ESM 导入与重导出，路径须为字面量，最多解析八步。中间件按定义文件解析。动态配置、已检测到的修改及多源 `export *` 不提供保护证明；不分析任意模块副作用。`security` 声明和校验回调不等于鉴权。

`openapiRoutes()` 支持静态数组、展开项和 `defineOpenAPIRoute()` 条目，仅字面量 `addRoute: false` 跳过该项。启用路由相关检查时，无法解析的条目或处理函数标记扫描不完整。

## 结果

报告正文为英文。终端按文件分组，`--verbose` 展开摘录、说明、证据和修复步骤；常见规则附带前后示例及适用限制，也可通过 `--list-rules` 查看。后续命令保留扫描目标与隐私选项。离线 HTML 支持严重度及置信度筛选、分组、稳定定位、引用及修复提示复制。打印包含报告内全部结果，结束后恢复视图。筛选不能恢复生成时省略的结果，纳入疑似结果须使用 `--all`。

![HTML 报告](https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/report.png)

`certain` 表示静态证据充分，`likely` 需人工审阅；测试和示例中的结果降为 `likely`。默认仅展示 `certain`，`--all` 显示全部。置信度仅反映静态证据，不代表凭据有效或风险已在运行时验证。

| 退出码 | 含义 |
|---|---|
| `0` | 无结果，且扫描完整或由 `--best-effort` 接受 |
| `1` | 至少一条 `certain` 的 P0/P1 结果 |
| `2` | 其他结果，包括隐藏的 `likely` |
| `3` | 参数错误、工具错误或未被接受的不完整扫描 |
| `130` / `143` | 扫描期间收到 SIGINT / SIGTERM，不生成报告 |

退出码基于规则筛选、忽略注释和基线处理后的结果。有结果时优先于扫描不完整；`--best-effort` 不改变 `1` 或 `2`。

## 命令行

`npx canship [path] [options]`

| 参数 | 作用 |
|---|---|
| `-a`、`--all` | 包含 `likely` 结果 |
| `--verbose` | 展开终端结果 |
| `--no-progress` | 关闭交互终端的标准错误进度；结构化输出及重定向流不显示进度 |
| `--report[=file]` | 写入 HTML，默认 `canship-report.html` |
| `--open` | 打开 `--report` 输出；CI 和非交互终端中禁用 |
| `--json` | 输出 JSON |
| `--workspace=path` | 独立扫描指定子项目，可重复，最多 32 项；输出终端或 JSON 报告 |
| `--compare=before.json` + `--with=after.json` | 比较已保存的扫描报告，不执行扫描，支持 `--json` |
| `--share-summary` | 仅输出计数及范围标记，不含项目文本，支持 `--json`，不上传 |
| `--sarif[=file]` | 写入 SARIF 2.1.0，默认 `canship.sarif` |
| `--fix-prompt` | 输出修复指令及独立的人工操作清单 |
| `--no-excerpts` | 移除所有报告中的摘录 |
| `--changed-since=ref` | 展示变更文件结果，保留全量扫描退出码 |
| `--only=ids` / `--skip=ids` | 选择或排除规则及命名空间，逗号分隔，可重复 |
| `--exclude=path` | 排除项目相对文件或目录，按字面值匹配，可重复 |
| `--list-rules` | 列出规则而不扫描，支持 `--only` / `--skip` 筛选及 `--json` |
| `--explain-config` | 展示生效设置、来源及规则选择，不执行扫描，支持 `--json` |
| `--doctor` | 只读环境诊断，支持 `--json`、`--no-config`、`--baseline` 及输出路径预检 |
| `--init[=config\|ci\|ci-workspaces\|pre-commit]` | 预览配置、CI 或钩子模板，不修改文件 |
| `--baseline[=file]` / `--baseline-write[=file]` | 抑制或记录结果，默认 `canship-baseline.json` |
| `--baseline-migrate[=file]` | 输出迁移后的基线 JSON，保留原文件 |
| `--baseline-review` | 对照基线与当前结果，支持 `--baseline[=file]` 及 `--json` |
| `--baseline-prune` | 输出仅保留有效且匹配记录的 v4 候选基线，保留原文件 |
| `--baseline-accept=ids` | 输出接受所选 `fingerprint[:count]` 的候选基线，数量默认 `1`，逗号分隔，可重复 |
| `--baseline-reason=text` / `--baseline-expires=UTC` | 配合 `--baseline-accept` 记录理由或 UTC 到期时间 |
| `--no-config` / `--no-ignore-markers` | 忽略项目配置或源码抑制注释 |
| `--best-effort` | 允许没有结果的不完整扫描退出 `0` |
| `-h`、`--help` / `-v`、`--version` | 显示帮助或版本 |
| `--build-info` | 显示构建渠道、提交摘要、修改状态和能力边界，支持 `--json` |

`--json` 与 `--fix-prompt` 互斥，均可同时输出 HTML 和 SARIF。

重复使用 `--workspace=apps/web --workspace=apps/admin` 独立扫描所选目录。路径须为字面相对路径，不得重叠或经过符号链接。各项目使用独立配置和基线，不继承父目录配置、不读取未选择的源码。命令行规则、排除、可见性及隐私选项覆盖各项目设置；裸 `--baseline` 读取各项目的默认基线。结果分别披露配置来源、覆盖状态及全部置信度计数。任一项目执行失败时整批退出 `3`，否则沿用扫描结果优先级。仅支持终端与 JSON（`kind: "workspace-report"`）；HTML/SARIF 及基线维护使用单项目扫描。

`--compare` 读取两份本地 v1 JSON 报告，每份最多 10 MiB、50,000 条结果。按稳定身份与数量列出新增、持续存在和本次未再出现的记录；缺少来源摘要的记录不配对。覆盖缺口、筛选、基线、根目录差异及扫描器构建变更或不明均限制比较结论。退出 `0` 表示未发现已知比较限制，`2` 表示比较受限，`3` 表示输入无效，不沿用扫描的发布阻断策略。记录消失不等于已修复。不扫描、不写文件；输出省略标题、摘录和扫描根目录，但保留结果路径。此独立模式仅可搭配 `--json`，JSON 使用 `kind: "report-comparison"`。

`--share-summary` 统计规则筛选、源码抑制及基线处理后的全部置信度结果，保留正常扫描退出码。不包含路径、标题、标识、摘录及诊断详情；受控错误仅显示代码与本地排查提示。不能同时输出详细报告或使用变更视图。JSON 使用 `kind: "share-summary"`，不属于扫描报告格式。数量本身仍可能敏感，分享前须审阅。

`--init` 为独立预览模式：标准输出为模板，标准错误提示保存位置，审阅后自行保存。CI 模板使用扫描器的包版本，启用前须确认该版本已发布，并审阅固定的 Action 提交。

`--init=ci-workspaces` 预览多项目矩阵，各任务独立运行，使用 `fail-fast: false` 和不同的 SARIF 类别。使用前替换示例目录与名称。项目配置和 SARIF 上传默认关闭，启用上传还需配置相应权限。

`--init=pre-commit` 仅预览 Node 钩子，不安装、不修改 Git 设置。审阅后保存到 [Git 钩子目录](https://git-scm.com/docs/githooks)的 `pre-commit`，按平台要求赋予执行权限。将 `CANSHIP_CLI` 指向工作区之外、独立安装且可信的 `dist/cli.js`，版本须与模板一致。钩子扫描完整工作区（含未暂存修改），显示全部结果并禁用项目抑制设置；不验证暂存区快照，须另行审阅仅存在于暂存区的内容。任意非零退出码均阻止提交；不下载依赖，扫描超过两分钟即失败。

`--changed-since` 比较本地共同祖先与工作区，包含未被忽略的新文件，不拉取远程、不缩小扫描范围。缺少 Git、引用或共同历史时退出 `3`；不能与 `--baseline-write` 组合。

`--doctor` 检查 Node.js、目录访问、配置、基线结构及本地 Git 元数据。此模式下，`--report` / `--sarif` 仅预检目标，不写报告或测试文件。预检错误退出 `3`；退出 `0` 仍可能含警告，不代表扫描完整、基线匹配或后续写入成功。JSON 使用 `kind: "doctor"`；诊断不输出项目内容、基线条目、环境变量或远程地址。

## 配置

`canship.config.json` 支持 `baseline`、`only`、`skip`、`exclude`、`all`。命令行参数优先，`only` 与 `skip` 互斥。

将 `$schema` 指向随包提供的[配置 Schema](./schemas/config-v1.schema.json)可启用编辑器补全；本地安装后可用 `./node_modules/canship/schemas/config-v1.schema.json`。Canship 不请求该地址。字段错误显示字段路径及行列；JSON 语法错误在可定位时显示位置。Schema 不验证基线文件及路径边界。

```json
{ "skip": ["cors/wildcard-with-credentials"], "all": false }
```

`--explain-config` 与扫描使用相同的配置解析逻辑，不读取源码或基线内容、不检查 Git 历史、不写文件。退出 `0` 仅表示配置解析成功，不代表扫描完整或基线有效。JSON 使用 `kind: "effective-config"`，不属于扫描报告格式。输出保留路径，分享前须审阅；不能与报告输出、基线写入或迁移、`--changed-since` 组合。

独占行注释 `canship-ignore-file` 排除整个文件；`canship-ignore-next-line [rule]` 抑制下一行，可限定单条规则。报告披露排除项；主动抑制不标记扫描不完整，可能使退出码降为 `0`。扫描不可信项目时使用 `--no-config --no-ignore-markers`。

`exclude` 按区分大小写的字面路径匹配，如 `generated/`、`test/fixtures/`，不支持通配符或目录越界；最多 64 项，每项 512 字符。命令行列表覆盖配置列表，`--no-config` 禁用项目提供的排除项。匹配文件的正文及环境文件历史对象不读取，配置、基线和 Git 元数据读取不受此设置控制。报告披露请求及匹配的排除路径，不将其当作文件数量；限制范围时拒绝基线维护。

基线表示接受已有结果，不代表问题已修复。新基线使用 v4，支持可选理由和有效期，仍可读取 v2/v3。v3 指纹算法不变：标题、语言及行号移动不改变身份，来源证据变化仍会重新报告。SARIF 保留 v2/v3 指纹；旧扫描器会拒绝 v4，而非忽略有效期。

`--baseline-review` 列出保留、未匹配、未接受及已到期记录；未匹配不等于已修复。仅隐式默认基线缺失时，预览与接受从空记录开始；显式或配置路径缺失仍报错。清理与接受要求扫描完整、未筛选规则且无源码抑制项，均只输出候选内容：清理不接受新结果，接受只增加所选数量并保留旧 v3/v4 记录。从预览中选取完整指纹，审阅候选后另存文件。v2 接受操作要求原条目全部匹配。这些命令按操作状态退出，不按问题级别退出；不完整预览退出 `3`。

理由可选，限 500 字符，不应包含凭据或个人信息。有效期须为未来的 UTC 时间，如 `2030-01-01T00:00:00Z`，到时停止抑制。同一指纹的不同接受决定独立计数、独立到期。报告披露到期数量，预览展示理由和期限；不设置期限表示永久接受。

`--baseline-migrate` 要求扫描完整、未筛选规则，且原条目全部匹配并未到期；不接受新发现，只输出 v4 JSON，不修改原文件。未匹配或到期记录须先预览及清理。报告与基线采用原子写入，不覆盖无关的已有文件或符号链接目标。

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
      - uses: Tasomei/canship@7465c9560b8b3692777af080e8cc67b4be2335d7
        with:
          version: '0.7.1'
          honor-ignore-markers: false
```

提交哈希固定 Action 实现，`version` 指定 npm 扫描器版本，不使用开发分支源码。Action 使用 Node.js 22，不安装或运行项目依赖，仅输出统计摘要。

| 输入 | 默认值 | 含义 |
|---|---|---|
| `version` | `0.7.0` | 精确 npm 扫描器版本 |
| `fail-on` | `blocking` | `blocking`：确定的 P0/P1；`any`：全部结果；`none`：仅报告 |

扫描不完整或工具错误始终失败。默认不读取项目配置、不上传 SARIF。输入输出见 [action.yml](./action.yml)。

上传 SARIF 需 `security-events: write` 及代码扫描支持，fork PR 可能权限不足；上传前应审阅报告。不可信 PR 使用 `pull_request`，不要使用 `pull_request_target`。

## API 与结构化输出

```js
import { scan, summarize } from 'canship'

const result = await scan('./my-app', { noExcerpts: true })
console.log(summarize(result))
```

`scan()` 返回全部置信度结果，支持 `only`、`skip`、`exclude`、`honorIgnoreMarkers`（默认 `true`）、`noExcerpts`（默认 `false`）、`signal` 和 `onProgress`。不加载配置、不应用基线、不写报告、不设置进程退出码；无效参数抛出异常。`listRules()` 返回规则目录，`getBuildInfo()` 和 `getCapabilities()` 提供构建身份与权限边界。

`signal` 接受 AbortSignal。取消时抛出 `ScanCancelledError`（`name: "AbortError"`、`code: "SCAN_CANCELLED"`），不返回成功或部分结果。`onProgress` 提供不可变的阶段与计数快照，等待异步回调，回调失败抛出 `ScanProgressError`。阶段结束不代表覆盖完整，应检查返回结果。取消在文件批次及规则边界检查，不会立即中断执行中的同步文件或 Git 调用。CLI Ctrl+C 使用相同边界，进度不包含文件名。

JSON 使用 [schemaVersion 1](./schemas/scan-report-v1.schema.json)。须独立于退出码检查 `partial`、`errors`、`skipped`、`filesScanned`。新报告提供稳定的 `errors[].code`，旧报告可能缺少该字段。CLI 失败通过标准错误输出 `[CODE]`，不破坏 JSON 标准输出。SARIF 包含证据位置和执行诊断。

构建身份区分开发版、候选版和正式版；只有工作区干净且匹配版本标签时才标为发行构建，该标签不等同于发布者认证。JSON 可包含 `build` 元数据，调用方须兼容缺失元数据和未知诊断代码。`--version` 保持包版本格式。

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
| OpenAPI 批量入口 | 每次调用 256 项，含展开项；数组 8 层 |
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
