# canship

面向 JavaScript / TypeScript Web 应用的发布前安全检查工具。Canship 在源码中查找凭据泄露、缺失的访问控制及不安全的请求输入处理，并可选择对你拥有的部署进行校验。

静态扫描在本地运行：只读、不执行项目代码、不发起网络请求。部署校验是独立的可选模式，只访问经你确认的目标。

[English](./README.md) · [使用参考](./docs/reference-zh-CN.md) · [发布说明](https://github.com/Tasomei/canship/releases) · [npm](https://www.npmjs.com/package/canship)

> 本文对应 npm `latest` 渠道的 `0.8.1`。其他版本见[发布说明](https://github.com/Tasomei/canship/releases)。

## 快速开始

要求 Node.js 18 及以上，无运行时依赖。

```powershell
npx canship@0.8.1
```

扫描指定目录：

```powershell
npx canship@0.8.1 "./my-app"
```

合成项目的输出示例：

![终端报告](https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/terminal.png)

## 检测范围

| 类别 | 级别 | 内容 |
|---|:---:|---|
| 凭据 | `P0` | 硬编码密钥、公开环境变量中的密钥、Supabase 服务密钥、被 Git 跟踪或存在于历史中的 `.env` 文件 |
| API 访问 | `P0/P1` | 未识别到鉴权的数据库操作、服务端信任 Supabase `getSession()`、未验签的 Stripe webhook |
| 数据库规则 | `P1/P2` | 未启用 Supabase RLS、过宽的策略、公开存储列表、开放的 Firebase 规则 |
| CORS | `P1/P2` | 携带凭据时回显来源或使用通配符 |
| 代码（Code） | `P1/P2` | 由请求输入拼接的 SQL 与 shell 命令；向调用方指定地址发起的服务端请求和重定向 |

路由分析覆盖 Next.js、SvelteKit、Nuxt、Remix / React Router、Astro、Express、Hono、Fastify 的指定入口，详见[入口及限制](./docs/reference-zh-CN.md#服务端入口)。

```powershell
npx canship@0.8.1 --list-rules
```

## 审阅结果

每条结果标为 `certain`（静态证据充分）或 `likely`（需人工审阅），默认只显示 `certain`。两者都不代表凭据有效或问题可被利用。

```powershell
npx canship@0.8.1 --all --verbose
```

```powershell
npx canship@0.8.1 --all --report
```

![HTML 报告](https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/report.png)

离线 HTML 报告支持筛选和复制修复提示；`--fix-prompt` 在终端输出同样的说明。报告包含文件路径，也可能包含源码摘录：`--no-excerpts` 去除摘录，`--share-summary` 仅输出计数。可下载[合成示例报告](https://github.com/Tasomei/canship/blob/main/docs/demo.html)查看。

| 退出码 | 含义 |
|---|---|
| `0` | 无结果，且覆盖完整（或经 `--best-effort` 接受不完整覆盖） |
| `1` | 至少一条 `certain` 的 P0/P1 结果 |
| `2` | 其他结果，包括被隐藏的 `likely` |
| `3` | 输入无效、工具错误或覆盖不完整 |

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
      - uses: Tasomei/canship@8f09ad58fca369060e5333b325765ff7870aa92f
        with:
          version: '0.8.1'
          honor-ignore-markers: false
```

提交哈希固定 Action 实现，`version` 固定 npm 扫描器版本。Action 不安装项目依赖，只输出计数摘要；扫描不完整或工具出错时始终失败。SARIF 上传需显式开启。

| 输入 | 固定 Action 的默认值 | 含义 |
|---|---|---|
| `version` | `0.8.1` | 精确的 npm 扫描器版本；请如上例显式设置 |
| `fail-on` | `blocking` | `blocking`：`certain` 的 P0/P1；`any`：全部结果；`none`：仅报告 |

完整说明见 [Action 输入](https://github.com/Tasomei/canship/blob/main/action.yml)。

## 扫描之外

- **基线**：接受已审阅的结果，可附理由和到期时间，见[基线管理](./docs/reference-zh-CN.md#配置)。
- **报告比较**：比较两份已保存的 JSON 报告，列出新增、持续存在和不再出现的结果，见[命令参考](./docs/reference-zh-CN.md#命令行)。
- **工作区与配置**：独立扫描 monorepo 子项目、排除路径，并用 `--explain-config` 或 `--doctor` 查看生效设置。
- **模板**：用 `--init` 预览 CI 与 pre-commit 配置。pre-commit 钩子扫描工作区，而非暂存区快照。
- **部署校验**：`--probe=https://…` 预览少量无认证的 HTTPS 请求，确认计划前不会发出任何请求。使用前请阅读[范围与隐私说明](./docs/reference-zh-CN.md#部署校验)。
- **API 与编辑器**：[编程接口](./docs/reference-zh-CN.md#api-与结构化输出)及 [VS Code 插件预览版](https://github.com/Tasomei/canship/tree/main/extensions/vscode#readme)。

## 限制

- 静态分析可能漏报或误报有意为之的配置，不评估业务授权、限流或依赖漏洞。
- 脱敏仅覆盖已识别的密钥格式。详细报告和基线应作为内部资料处理。
- Google 与 Firebase 的 `AIza…` 密钥属于公开标识符，不单独作为泄露报告。

详见[隐私与覆盖限制](./docs/reference-zh-CN.md#隐私与限制)。

## 开发与许可

见[开发参考](./docs/reference-zh-CN.md#开发)。采用 [MIT](./LICENSE) 许可；Supabase 与 Firebase 测试夹具保留 Apache-2.0，Next.js 与 `cors` 夹具保留 MIT。
