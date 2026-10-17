# Canship for VS Code

[English](https://github.com/Tasomei/canship/blob/main/extensions/vscode/README.md) · [命令行工具](https://github.com/Tasomei/canship/blob/main/README-zh-CN.md) · [规则参考](https://github.com/Tasomei/canship/blob/main/docs/reference-zh-CN.md)

在编辑器中对 JavaScript / TypeScript Web 应用做上线前安全检查：泄露的凭据、缺失的访问控制、不安全的请求输入处理。与 `canship` 命令行工具使用同一扫描器。

预览版。要求 VS Code 1.95 及以上，并使用已信任的本地工作区。

## 使用

在命令面板运行 **Canship: Scan Workspace**，结果显示在问题面板。

| 命令 | 作用 |
| --- | --- |
| Scan Workspace | 扫描所选目录中已保存的文件 |
| Cancel Scan | 停止当前扫描，不保留部分结果 |
| Clear Results | 清除 Canship 诊断 |
| Show Scan Summary | 列出隐藏结果、基线、排除项和覆盖缺口 |
| Copy Finding Fix Prompt | 复制单条结果的修复提示，供编码助手使用 |
| Review Line Suppression | 预览特定规则的抑制注释，确认后才修改编辑缓冲区 |

## 设置

| 设置 | 默认值 | 说明 |
| --- | --- | --- |
| `canship.scanOnSave` | `false` | 保存后扫描 |
| `canship.saveDelay` | `750` | 保存后触发扫描前的延迟（毫秒） |
| `canship.includeLikely` | `false` | 同时显示疑似结果 |
| `canship.useProjectConfig` | `true` | 使用所选目录的 Canship 配置与基线 |
| `canship.honorIgnoreMarkers` | `true` | 遵循源码中的抑制注释 |

## 说明

- 仅扫描已保存文件；未保存内容或外部修改需重新扫描。
- 使用内置扫描器，不运行工作区中的 `npx`、脚本或可执行文件。
- 多根工作区不得重叠，每次扫描一个项目。
- 不在 JSX、JSON 或含义不明的字符串中插入抑制注释。
- 每次最多显示 5,000 条结果，并报告省略数量。
- 结果是静态证据，不证明部署或授权逻辑正确。

## 隐私

无遥测、无上传、无网络请求。诊断不含源码摘录；文件路径、说明和复制的提示仍可能敏感。

## 开发

在仓库根目录运行：

```powershell
npm run build:extension
```

构建两个入口，供 Extension Development Host 使用。

```powershell
npm run package:extension
```

构建并校验 VSIX，输出到 `.scratch/vsix/`（需要 Node.js 22 及以上），不发布。编辑器宿主测试使用 `scripts/run-editor-host.mjs` 和隔离配置，已在 Windows / VS Code 1.141.0 上验证。
