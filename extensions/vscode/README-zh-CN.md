# Canship for VS Code

[English](./README.md)

开发预览，尚未发布到 Marketplace。要求 VS Code 1.95 及以上，并使用已信任的本地文件系统工作区。

运行 **Canship: Scan Workspace** 检查已保存文件。多根工作区不得重叠，每次独立选择一个项目。结果显示在问题面板和悬浮提示中；**Show Scan Summary** 披露隐藏结果、基线、排除项和覆盖缺口。

- 使用随插件打包的扫描器，不调用工作区中的 `npx`、脚本或同名程序。
- 读取所选目录的 Canship 配置及配置的基线；应用级设置可禁用这些配置或显示疑似结果。
- 保存后扫描默认关闭，并合并短时间内的重复请求。取消、源码编辑及设置变化会使旧结果失效。
- **Copy Finding Fix Prompt** 复制单条结果的修复提示。**Review Line Suppression** 先预览特定规则的抑制注释，确认后仅修改编辑缓冲区，不自动保存。语法不支持或源码已变化时，须人工审阅或使用 CLI 基线。
- 仅扫描已保存文件。未保存内容及外部修改需重新扫描；不自动编辑 JSX、JSON 或字符串内的歧义位置。

无遥测、项目上传或扫描网络请求。默认省略摘录；路径、说明和复制的提示仍可能敏感。结果仅表示静态证据，不证明部署或授权逻辑正确。每次最多展示 5,000 条结果，并披露省略数量。

## 开发

在仓库根目录运行：

```powershell
npm run build:extension
```

使用独立的 Extension Development Host，将本目录作为 `--extensionDevelopmentPath`。测试不得改动正常编辑器配置；Marketplace 发布及发布者注册分别验收。

真实宿主测试使用 `scripts/run-editor-host.mjs`，参数为已安装 VS Code 可执行文件的绝对路径。驱动器创建隔离配置与合成工作区，不关闭工作区信任；需要人工授权时报告 `blocked`。真实宿主验收尚未完成，自动化交互测试不能替代该验收。
