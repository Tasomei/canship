# canship

canship 是面向 JavaScript/TypeScript Web 项目的只读静态扫描工具，用于发现凭据泄露、公开环境变量误用和访问控制配置错误。支持 Next.js、Vite、Nuxt、Create React App、Expo，以及使用 Supabase 或 Firebase 的项目。

扫描过程不会执行被扫描项目的代码，不会上传内容或主动访问网络，也没有运行时 npm 依赖。扫描 Git 仓库时，只读取本地工作区和本地提交历史。

```bash
npx canship
```

要求 Node.js 18 或更高版本。项目无需使用 Git；只有提交历史检查依赖本机 Git 和可读取的本地仓库。npm 缓存中没有 canship 时，`npx` 可能先从 npm registry 下载软件包，这一步由 npm 执行，不属于扫描过程。

[English](./README.md)

## 检测范围

| 检查项 | 风险 | 级别 |
|---|---|---|
| 硬编码凭据 | 当前扫描文件中包含已识别的 OpenAI、Anthropic、AWS、Stripe、GitHub、npm、Slack、SendGrid、私钥或数据库连接凭据 | P0 |
| 公开环境变量中的私密值 | 私密值可能被打包进浏览器代码 | P0 |
| 客户端可访问 Supabase `service_role` key | `service_role` 可绕过 Row Level Security（RLS）策略 | P0 |
| Git 跟踪的 `.env` 文件 | 已识别凭据会留在仓库历史中；未识别但内容仍像真实配置的文件也可能产生低置信度结果 | P0 |
| Supabase 表未启用 RLS | 表经 Supabase Data API 暴露时缺少行级访问控制 | P1 |
| Firebase 规则允许无条件访问 | 未经授权的客户端可能读取或写入数据 | P1 |
| Next.js API route 访问数据但未鉴权 | 未验证调用方即可访问数据或执行管理操作 | P0 / P1 |
| CORS 回显 `Origin` 且允许凭据 | 其他站点可能携带用户凭据访问接口并读取响应 | P1 |

严重度（P0、P1、P2）表示潜在影响，置信度（`certain`、`likely`）表示规则对结论的确定程度。两者相互独立：`certain` 的 P0/P1 结果会阻止发布并返回退出码 `1`；其他结果返回退出码 `2`。

`Access-Control-Allow-Origin: *` 与凭据同时出现时报告为 P2，因为浏览器会拒绝该组合；单独使用 `*` 不报告。

对于 Git 跟踪的 `.env` 文件，已识别凭据按 `certain` 报告；未识别但值较长且不像公开值或占位符时按 `likely` 报告。环境变量模板、公开值、占位符和短设置不会仅因文件进入 Git 而触发这条规则。

## 使用方式

```bash
npx canship [路径]
```

未提供路径时扫描当前目录。

| 参数 | 说明 |
|---|---|
| `-a`, `--all` | 显示 `likely` 结果 |
| `--json` | 输出机器可读的 JSON |
| `--fix-prompt` | 输出可交给编程助手的修复说明 |
| `--report[=文件]` | 生成自包含的 HTML 报告；默认写入 `canship-report.html` |
| `--best-effort` | 扫描不完整且没有任何结果时允许退出 `0`；不会改变已有结果对应的退出码 |
| `--baseline[=文件]` | 隐藏基线中已记录的结果，只报告新增项；默认读取 `canship-baseline.json` |
| `--baseline-write[=文件]` | 将当前结果记录为基线后退出；默认写入 `canship-baseline.json` |
| `--only=规则` | 只报告这些规则；逗号分隔，可重复传入 |
| `--skip=规则` | 报告除这些规则以外的全部；逗号分隔，可重复传入 |
| `--sarif[=文件]` | 生成 SARIF 2.1.0 日志供 CI 代码扫描使用；默认写入 `canship.sarif` |
| `--no-config` | 忽略被扫描目录下的 `canship.config.json` |
| `-h`, `--help` | 显示帮助 |
| `-v`, `--version` | 显示版本 |

`--json` 与 `--fix-prompt` 互斥。`--report` 写入独立文件，可以与其中任意一种组合。

### 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 没有任何置信度的结果，且扫描完整；使用 `--best-effort` 时也可能表示接受了不完整扫描 |
| `1` | 至少有一条 `certain` 的 P0/P1 结果 |
| `2` | 存在结果，但没有已确认的 P0/P1 阻断项 |
| `3` | 参数或工具错误，或者扫描不完整且未使用 `--best-effort` |

如果结果与不完整扫描同时存在，退出码 `1` 或 `2` 优先。JSON 中的 `partial`、`errors` 和 `skipped` 字段仍会保留扫描不完整的信息。

默认视图只展开 `certain` 结果。被隐藏的 `likely` 结果仍会使进程返回 `2`；终端和 HTML 报告会显示警告，JSON 通过 `hiddenLikely` 给出数量。使用 `--all` 可查看完整结果。

### 排除文件

在文件中单独添加一行 `canship-ignore-file` 可以排除整个文件。标记前后只允许出现 `//`、`#`、`--`、`*`、`/* */` 或 `<!-- -->` 注释符。被主动排除的文件会列入报告，但不会使扫描标记为不完整。

### 排除单行

在某条结果所在行的上一行添加 `canship-ignore-next-line` 可以只抑制该行。注释符规则与上面相同，且标记必须独占整行——同时含有代码或说明文字的行不会产生任何抑制作用。

```ts
// canship-ignore-next-line
const documentedExample = "sk-proj-not-a-real-key"
```

不带参数的标记会抑制下一行上的所有规则。在标记后写出规则 id 可将抑制范围收窄到该规则，使得一行上已知的误报不会同时让另一条规则失明：

```ts
// canship-ignore-next-line secrets/hardcoded/openai
const key = process.env.OPENAI_KEY
```

规则 id 可从 `--json` 输出中获得；终端与 HTML 报告不显示规则 id，不带参数的形式正是为此保留的。

标记只作用于紧接其后的那一行，不会跳过空行。被抑制的结果会在终端、HTML 报告以及 `--json` 的 `ignoredFindings` 字段中按文件、行号和规则列出。它们不会使扫描标记为不完整，报告也会声明该结果并非"没有任何问题"。

### 配置文件

项目一次性确定的设置可以提交到被扫描目录下的 `canship.config.json`。命令行参数始终覆盖配置文件。

```json
{
  "baseline": "canship-baseline.json",
  "skip": ["cors/wildcard-with-credentials"],
  "all": false
}
```

| 设置项 | 等价参数 |
|---|---|
| `baseline` | `--baseline=文件` |
| `only` | `--only=规则` |
| `skip` | `--skip=规则` |
| `all` | `--all` |

格式是 JSON 而非 JavaScript。`canship.config.js` 属于项目代码，而扫描不执行项目代码。

未知设置项、类型错误、指向不存在规则的 id，以及同时设置 `only` 和 `skip`，都会报错并以 `3` 退出。配置文件不存在不算错误。`baseline` 路径必须位于被扫描项目之内；`--baseline` 参数不受此限制。

**配置文件来自被扫描的目录本身。** 当该目录是你自己的代码时，这正是这个功能的意义；当它不是——某个依赖、某个 fork、某个尚未审阅的合并请求——项目就可以用它关掉本会报告它的规则。`--no-config` 会完全忽略该文件。

`bestEffort` 被刻意排除在设置项之外。它会把不完整扫描的退出码从 `3` 变成 `0`，而这是运行 canship 的人对自身容忍度的判断，不是被扫描项目的属性。在配置文件中写出该键会直接报错，而不是被悄悄忽略。请改用 `--best-effort`。

### 选择规则

`--only` 和 `--skip` 接受 `--json` 输出中出现的规则 id，逗号分隔，可重复传入。选择器可精确匹配某个 id，也可按 `/` 边界匹配其下的全部 id——`secrets` 覆盖所有凭据格式，`secrets/hardcoded/openai` 只覆盖一种。像 `secrets/hardcoded/open` 这样的半截 id 不匹配任何规则并会被拒绝，因此拼错的 id 不会悄悄关掉一条规则。

`--only` 与 `--skip` 不能同时使用。规则选择过滤的是结果而非跳过规则本身，因此不会缩短扫描时间。每个报告都会说明当前生效的选择以及它隐藏了多少条结果。

### 基线

已有项目首次扫描通常会产生若干结果。基线记录这些结果，使后续扫描只报告此后新增的问题——这是让 canship 能够接入一个并非从零开始使用它的项目的持续集成的前提。

```bash
npx canship --baseline-write   # 接受当前结果
npx canship --baseline         # 只报告新增项
```

`--baseline-write` 写入 `canship-baseline.json` 后以 `0` 退出，不再继续输出扫描结果。该文件应当提交：它是"接受了哪些问题"的记录，本身就是供人在引入它的合并请求中审阅的。

**但要先想清楚提交它意味着公开什么。** 每个条目都记录了文件路径、规则 id 和结果标题，而每个条目按定义都是尚未修复的问题。canship 会有意搜索被 gitignore 的凭据文件，因此某个条目可能描述的是仓库中并不存在的文件——例如 `.env.local` 以及其中某个变量的名字。该文件不包含任何凭据值。在私有仓库中这正是预期用法；在公开仓库中，提交前需自行权衡这部分信息的披露。

路径按其来源解析：命令行上输入的路径相对当前工作目录；不带参数的 `--baseline` 或 `--baseline-write` 使用被扫描项目自己的 `canship-baseline.json`；`canship.config.json` 中的路径相对该配置文件所在目录。因此 `npx canship ./app --baseline-write` 会写入 `./app`，而 `npx canship ./app --baseline` 正是去那里读取。

基线条目按规则、文件、标题以及摘录的哈希匹配。行号被刻意排除在外，因此在某条结果上方编辑文件不会使其被报告为新增项。每个条目记录出现次数；超出该次数的额外出现会被报告。

基线保存的是 SHA-256 哈希而非摘录原文，因为该文件应当被提交，而 canship 无法保证它无法识别的凭据一定被遮蔽。

基线会隐藏真实结果，因此每个输出都会说明隐藏了多少：

- 基线正在隐藏结果时，终端与 HTML 报告不会显示"干净"结论，并会给出数量和基线文件路径
- `--json` 通过 `baselineSuppressed` 给出数量
- 不再匹配任何结果的基线条目通过 `baselineStale` 报告，不影响退出码

所有置信度的结果都会被记录。基线文件无法读取时——缺失、格式损坏，或由不同格式版本写入——以 `3` 退出，而不是在不做任何抑制的情况下继续。`--baseline` 与 `--baseline-write` 不能同时使用。

### 修复说明

`--fix-prompt` 将输出分为两部分：可以交给编程助手执行的代码修改，以及必须由项目维护者完成的操作，例如轮换密钥、修改服务端控制台配置或重写 Git 历史。

当前扫描结果、HTML 报告和修复说明正文使用英文，JSON 字段名也使用英文。

## 规则生效条件

| 规则 | 生效条件 |
|---|---|
| 公开环境变量 | 变量名以 `NEXT_PUBLIC_`、`VITE_`、`REACT_APP_`、`EXPO_PUBLIC_`、`NUXT_PUBLIC_`、`GATSBY_`、`VUE_APP_` 或 `PUBLIC_` 开头 |
| Git 凭据历史 | 目标位于可读取的本地 Git 仓库中，且 `.git` 元数据位于工作区内、或其目标反向指认本工作区；模板、公开值、占位符和短设置除外；每个文件最多检查最近 100 个相关版本 |
| Next.js API 鉴权 | 仅检查 `app/api/**` 和 `pages/api/**`；识别明确的鉴权调用、控制拒绝响应的身份条件，以及覆盖该路由的 middleware `matcher` |
| Supabase RLS | 当前子项目存在 `supabase/`、`@supabase/supabase-js`/`@supabase/ssr` 导入或 `SUPABASE_URL`；按子项目重放 migration 中与表相关的 DDL |
| 其他凭据和配置规则 | 按已知文件格式和内容模式匹配，不要求特定前端框架 |

## 已知限制

- canship 是静态启发式扫描器，不验证运行时行为。自定义鉴权封装、动态配置和非标准语法可能产生误报或漏报。
- 检测和脱敏使用同一套凭据特征。无法识别的凭据也无法保证脱敏；如果其所在行因其他规则被引用，原始值可能出现在报告中。因此报告应视为内部材料。
- 工具不使用熵值检测，避免将随机 ID、哈希或普通 Base64 文本误判为凭据。
- 单个文件最大读取 2 MiB，目录最大扫描深度为 16 层，单文件最多报告 100 条结果，Git 历史中单文件最多检查最近 100 个版本。触及上限时扫描会明确记录。
- 符号链接不会被跟随，并会使扫描标记为不完整。
- 嵌套 Git 仓库和子模块不会由父项目展开扫描。父项目会记录跳过项并标记扫描不完整。
- `.git` 文件可能指向工作区之外。canship 只在目标反过来指认本工作区时才跟随——这正是 git 为链接工作树和子模块记录的形式；其余情况按"重定向到无关仓库"处理：文件扫描继续，历史检查标记为不完整。
- Google/Firebase/Maps 的 `AIza...` key 被视为公开标识符。其应用和 API 限制保存在 Google Cloud，无法仅从本地源码判断，因此不会仅凭该值报告凭据泄露。
- 不检查限流、注入、依赖漏洞，也不验证“调用方是否已登录”之外的业务授权逻辑。

扫描结果只表示已实现规则在已读取文件中观察到的情况，不能证明项目不存在其他安全问题。

## 计划

`--probe` 尚未实现。计划在用户显式确认后，对项目本地配置中的服务地址发起只读验证请求。当前版本不会联网。

## 参与开发

新增或修改检测规则时，至少提供两个测试夹具：一个应当被检出，一个不应被检出。参见 [`test/fixtures/`](./test/fixtures/)。

```bash
npm ci
npm run prepublishOnly
```

## 许可

[MIT](./LICENSE)
