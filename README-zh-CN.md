# canship

面向 JavaScript / TypeScript Web 应用的本地静态扫描器，检测凭据暴露、访问控制配置错误及请求输入风险。

静态扫描离线、只读，不执行项目代码。部署校验为独立功能，须显式确认请求计划。

[English](./README.md) · [使用参考](./docs/reference-zh-CN.md) · [npm](https://www.npmjs.com/package/canship)

> 候选版本 `0.8.0-rc.1` 使用 npm `next` 渠道。下方示例固定此预发布版本；稳定版 `0.7.1` 请参阅[发行版文档](https://github.com/Tasomei/canship/blob/v0.7.1/README-zh-CN.md)。

## 扫描项目

要求 Node.js ≥18，无运行时依赖；安装可能联网。

```powershell
npx canship@0.8.0-rc.1
```

扫描其他目录：

```powershell
npx canship@0.8.0-rc.1 "./my-app"
```

Git 检查读取本地跟踪文件及提交历史，不访问远程仓库；历史无法读取时标记覆盖不完整。

以下截图使用开发构建及合成数据。

![终端报告](https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/terminal.png)

## 检测范围

| 类别 | 级别 | 范围 |
|---|:---:|---|
| 凭据 | `P0` | 硬编码凭据、公开环境变量暴露、Supabase 管理员密钥、Git 跟踪或历史中的非模板 `.env` 文件 |
| API 访问 | `P0/P1` | 未识别到鉴权的数据库操作、服务端信任 Supabase `getSession()`、未验证的 Stripe webhook |
| 数据库规则 | `P1/P2` | Supabase RLS、无条件放行策略及公开对象列表；Firebase 开放规则及测试模式到期时间 |
| CORS | `P1/P2` | 携带凭据的来源回显或通配符配置 |
| 请求输入 | `P1/P2` | SQL 和命令构造、调用方可控的请求主机及重定向目标 |

路由分析覆盖 Next.js、SvelteKit、Nuxt、Remix / React Router、Astro、Express、Hono、Fastify 的指定入口，不支持任意框架行为。详见[入口及限制](./docs/reference-zh-CN.md#服务端入口)。

```powershell
npx canship@0.8.0-rc.1 --list-rules
```

## 审阅结果

报告正文为英文。`certain` 表示静态证据充分，`likely` 需人工审阅。测试和示例中的结果降为 `likely`；置信度不代表凭据有效或风险可被利用。

显示全部置信度及详细证据：

```powershell
npx canship@0.8.0-rc.1 --all --verbose
```

生成离线 HTML 报告：

```powershell
npx canship@0.8.0-rc.1 --all --report
```

![HTML 报告](https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/report.png)

[合成 HTML 示例](https://github.com/Tasomei/canship/blob/main/docs/demo.html)：下载文件后在本地打开，无需安装扫描器。

HTML 支持严重度及置信度筛选、稳定定位和修复提示复制。`--no-excerpts` 移除摘录，但保留路径等项目文本。`--share-summary` 仅输出计数及范围标记，分享前仍须审阅。

| 退出码 | 静态扫描结果 |
|---|---|
| `0` | 无结果，且扫描完整或由 `--best-effort` 接受 |
| `1` | 至少一条 `certain` 的 P0/P1 结果 |
| `2` | 其他结果，包括隐藏的 `likely` |
| `3` | 参数错误、工具错误或未被接受的不完整扫描 |
| `130` / `143` | 收到 SIGINT / SIGTERM，不生成扫描报告 |

退出码基于规则选择、源码抑制及基线处理后的结果。有结果时优先于覆盖不完整；`--best-effort` 不改变 `1` 或 `2`。须另行检查 JSON 的 `partial`、`errors`、`skipped` 和 `filesScanned`。

基线表示接受结果，不代表问题已修复。[基线管理](./docs/reference-zh-CN.md#配置)支持审阅已有记录、选择性接受、理由及到期时间。[报告比较](./docs/reference-zh-CN.md#命令行)提供终端、JSON 和离线 HTML 视图，区分新增、持续存在及本次未再出现，不将结果消失视为修复证明。

## 接入 CI

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
          version: '0.8.0-rc.1'
          honor-ignore-markers: false
```

提交哈希固定 Action 实现；`version` 指定此 npm 候选版本，须在候选包公开后启用工作流。Action 使用 Node.js 22，不安装或运行项目依赖，仅输出统计摘要。

| 输入 | 固定 Action 的默认值 | 含义 |
|---|---|---|
| `version` | `0.7.0` | 精确 npm 版本；上例已覆盖 |
| `fail-on` | `blocking` | `blocking`：确定的 P0/P1；`any`：全部结果；`none`：仅报告 |

扫描不完整或工具错误始终失败。默认不读取项目配置、不上传 SARIF。上传需 `security-events: write` 及代码扫描支持，操作前须审阅报告。不可信 PR 使用 `pull_request`，不要使用 `pull_request_target`。详见 [Action 输入](https://github.com/Tasomei/canship/blob/main/action.yml)。

## 进阶用法

[完整命令参考](./docs/reference-zh-CN.md#命令行)涵盖 JSON/SARIF、规则选择、配置、排除项、独立工作区、诊断及模板预览。[API](./docs/reference-zh-CN.md#api-与结构化输出)返回结构化结果，不加载项目配置、不写文件。

pre-commit 模板扫描**工作区，而非暂存区快照**。部署校验默认关闭，仅支持无认证的 HTTPS 请求；使用前须审阅[范围与隐私限制](./docs/reference-zh-CN.md#部署校验)。

[VS Code 插件](https://github.com/Tasomei/canship/tree/main/extensions/vscode#readme)为独立开发预览，本地 VSIX 打包及已验证宿主范围见插件 README；尚未发布到 Marketplace。

## 隐私与限制

- 静态分析可能误报或漏报，不验证业务授权、限流或依赖漏洞。
- 脱敏仅覆盖已识别格式，未知敏感值可能保留在摘录中；详细报告及基线应按内部材料处理。
- Google/Firebase/Maps 的 `AIza…` 密钥按公开标识符处理，不单凭其值判定泄露。
- 不跟随符号链接；嵌套仓库及子模块须单独扫描。范围内跳过项及分析上限会披露；默认排除的依赖和构建目录不计为覆盖缺口。
- 显式部署校验会访问已确认目标；安装、评估下载及可选 SARIF 上传也可能联网。静态扫描保持离线。

详见[资源上限与覆盖边界](./docs/reference-zh-CN.md#隐私与限制)。

## 开发与许可

分别运行 `npm ci`、`npm run prepublishOnly`、`npm run test:package`、`npm run evaluate`。新增规则须包含应检出和不应检出的夹具；样本通过不代表真实检出率。详见[开发参考](./docs/reference-zh-CN.md#开发)。

[MIT](./LICENSE)。Supabase/Firebase 夹具保留 Apache-2.0，Next.js/`cors` 夹具保留 MIT。
