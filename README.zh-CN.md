# canship

面向 JavaScript 和 TypeScript Web 项目的本地静态安全扫描工具。canship 检测暴露的凭据和常见访问控制错误，不执行项目代码，不上传源码，也不主动访问网络。

```bash
npx canship .
```

要求 Node.js 18 或更高版本。npm 包没有运行时依赖。Git 仅用于读取本地提交历史，不是必需依赖。如果本机尚未缓存 canship，`npx` 可能在扫描前从 npm 下载软件包。

[English](./README.md)

## 检测范围

| 检查项 | 典型影响 | 级别 |
|---|---|---|
| 硬编码凭据 | 暴露已识别的 OpenAI、Anthropic、AWS、Stripe、GitHub、npm、Slack、SendGrid、私钥或数据库凭据 | P0 |
| 公开环境变量中的私密值 | 将私密值打包进浏览器代码 | P0 |
| 客户端可访问 Supabase `service_role` key | 绕过 Row Level Security 策略 | P0 |
| Git 跟踪的 `.env` 文件中存在凭据 | 凭据留在本地仓库历史中 | P0 |
| Supabase 表未启用 RLS | 通过 Supabase Data API 暴露缺少行级控制的数据 | P1 |
| Firebase 规则允许无条件访问 | 允许未经授权的读取或写入 | P1 |
| Next.js API route 未鉴权 | 未验证调用方即可访问数据或管理操作 | P0 / P1 |
| 携带凭据的 CORS 回显来源 | 其他站点可能读取已认证响应 | P1 |

API 鉴权检查仅覆盖 `app/api/**` 和 `pages/api/**` 下的处理函数。其他检查不依赖具体框架，并识别 Next.js、Vite、Nuxt、Create React App、Expo、Gatsby、Vue CLI 和 SvelteKit 使用的公开环境变量前缀。

严重度表示潜在影响，置信度（`certain` 或 `likely`）表示证据强度。`certain` 的 P0/P1 结果会阻止发布并返回退出码 `1`；其他结果返回退出码 `2`。

## 使用方式

```bash
npx canship [路径] [参数]
```

省略路径时扫描当前目录。

| 参数 | 说明 |
|---|---|
| `-a`, `--all` | 显示 `likely` 结果 |
| `--json` | 向标准输出写入机器可读的 JSON |
| `--fix-prompt` | 输出可交给编程助手的修复说明 |
| `--report[=文件]` | 生成自包含 HTML 报告；默认：`canship-report.html` |
| `--sarif[=文件]` | 生成 SARIF 2.1.0 日志；默认：`canship.sarif` |
| `--best-effort` | 扫描不完整且没有结果时允许退出 `0` |
| `--baseline[=文件]` | 隐藏基线中已有结果；默认：`canship-baseline.json` |
| `--baseline-write[=文件]` | 将当前结果记录为基线后退出 |
| `--only=规则` | 只报告匹配的规则 ID；逗号分隔，可重复传入 |
| `--skip=规则` | 排除匹配的规则 ID；逗号分隔，可重复传入 |
| `--no-config` | 忽略被扫描目录下的 `canship.config.json` |
| `-h`, `--help` | 显示帮助 |
| `-v`, `--version` | 显示版本 |

`--json` 和 `--fix-prompt` 是两种互斥的标准输出模式。`--report` 可以与其中任意一种组合。

### 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 扫描完整且没有结果，或通过 `--best-effort` 接受了不完整且无结果的扫描 |
| `1` | 至少有一条 `certain` 的 P0/P1 结果 |
| `2` | 存在结果，但没有 `certain` 的 P0/P1 阻断项 |
| `3` | 参数错误、工具错误，或扫描不完整且未使用 `--best-effort` |

结果对应的退出码优先于扫描不完整状态。机器可读输出仍通过 `partial`、`errors` 和 `skipped` 保留不完整信息。

终端默认只展开 `certain` 结果。被隐藏的 `likely` 结果仍会返回退出码 `2`；使用 `--all` 查看完整内容。

## 配置

项目设置可以保存在被扫描目录下的 `canship.config.json`：

```json
{
  "baseline": "canship-baseline.json",
  "skip": ["cors/wildcard-with-credentials"],
  "all": false
}
```

支持 `baseline`、`only`、`skip` 和 `all`。命令行参数优先于配置文件。`only` 和 `skip` 不能同时使用；选择器必须匹配完整规则 ID 或规则命名空间。规则 ID 可从 JSON 输出中获取。

配置采用 JSON，因为 canship 不执行项目代码。扫描不可信代码时应使用 `--no-config`，避免目标项目修改规则选择。`bestEffort` 只能由运行者通过命令行启用。

## 抑制结果

用只包含 `canship-ignore-file` 的注释排除整个文件。用 `canship-ignore-next-line` 抑制下一行的结果：

```ts
// canship-ignore-next-line
const documentedExample = "sk-proj-not-a-real-key"
```

在标记后添加规则 ID，可以缩小抑制范围：

```ts
// canship-ignore-next-line secrets/hardcoded/openai
const key = process.env.OPENAI_KEY
```

标记必须独占注释行。报告仍会列出被抑制的结果和被排除的文件；它们不会使扫描标记为不完整。

## 基线

基线适合在已有项目中接入 canship：

```bash
npx canship --baseline-write
npx canship --baseline
```

第一条命令记录当前结果，第二条命令只报告新增结果。基线保存哈希而非源码摘录，但仍会披露文件路径、规则 ID、结果标题和尚未解决的问题类型。提交前应审阅基线，公开仓库尤其如此。

第 2 版基线在脱敏前对原始来源内容生成指纹，并排除行号。因此，移动已有问题不会产生新结果，替换凭据则会。第 1 版基线会以退出码 `3` 被拒绝；请重新审阅结果后使用 `--baseline-write` 生成新文件。

所有输出都会说明基线抑制了多少结果。基线缺失、损坏或版本不兼容时，canship 会以退出码 `3` 失败，不会静默跳过。

## 范围与限制

- canship 使用静态启发式规则，无法验证运行时行为。自定义鉴权、动态配置和不支持的语法可能产生误报或漏报。
- 检测和脱敏使用同一套凭据特征。无法识别的密钥也无法保证被遮蔽，因此报告应视为内部材料。
- 单个文件最大读取 2 MiB，目录最大深度为 16 层，单文件最多输出 100 条结果，Git 历史中每个文件最多检查最近 100 个相关版本。触及限制时会明确报告。
- 不跟随符号链接。嵌套 Git 仓库和子模块会列为跳过项；这些情况会使扫描标记为不完整。
- Google、Firebase 和 Maps 的 `AIza...` 值被视为公开标识符，因为仅凭源码无法验证其服务端限制。
- 不检查限流、注入、依赖漏洞，也不验证调用方身份之外的业务授权。

扫描干净只表示已实现规则在实际读取的文件中没有发现问题，不能证明项目安全。

## 参与开发

修改检测规则时，应在 [`test/fixtures/`](./test/fixtures/) 中同时提供一个应检出和一个不应检出的夹具。

```bash
npm ci
npm run prepublishOnly
```

## 许可

[MIT](./LICENSE)
