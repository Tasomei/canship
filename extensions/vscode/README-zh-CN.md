# Canship for VS Code

[English](https://github.com/Tasomei/canship/blob/main/extensions/vscode/README.md)

开发预览，尚未发布到 Marketplace。要求 VS Code 1.95 及以上，并使用已信任的本地文件系统工作区。

运行 **Canship: Scan Workspace** 检查已保存文件。多根工作区不得重叠，每次独立选择一个项目。结果显示在问题面板和悬浮提示中；**Show Scan Summary** 披露隐藏结果、基线、排除项和覆盖缺口。

- 使用随插件打包的扫描器，不调用工作区中的 `npx`、脚本或同名程序。
- 读取所选目录的 Canship 配置及配置的基线；应用级设置可禁用这些配置或显示疑似结果。
- 保存后扫描默认关闭，并合并短时间内的重复请求。取消、源码编辑及设置变化会使旧结果失效。
- **Copy Finding Fix Prompt** 复制单条结果的修复提示。**Review Line Suppression** 先预览特定规则的抑制注释，确认后仅修改编辑缓冲区，不自动保存。语法不支持或源码已变化时，须人工审阅或使用 CLI 基线。
- 仅扫描已保存文件。未保存内容及外部修改需重新扫描；不自动编辑 JSX、JSON 或字符串内的歧义位置。

无遥测、项目上传或扫描网络请求。默认省略摘录；路径、说明和复制的提示仍可能敏感。结果仅表示静态证据，不证明部署或授权逻辑正确。每次最多展示 5,000 条结果，并披露省略数量。

## 开发

### 本地安装包

打包工具要求 Node.js 22 及以上，不改变扫描器的运行版本要求。在仓库根目录运行：

```powershell
npm run package:extension
```

命令在项目内安装锁定的开发工具，构建两个入口并验证 VSIX 清单及文件字节。工具安装可能联网。产物使用唯一名称写入 `.scratch/vsix/`，不覆盖已有包，不登录或发布 Marketplace。

VSIX 仅含插件配置、两个运行文件、中英文 README、许可证及两个格式元数据文件，不包含源码、测试、日志或本地配置。`npm run test:extension-package` 另行验证拒绝场景，并在源码目录外运行包内 worker。

在目标 VS Code 窗口运行 **Extensions: Install from VSIX**，选择生成的文件。已在隔离的 Windows / VS Code 1.141.0 配置中验证安装、激活、扫描和源码定位，未使用开发宿主参数；这不代表已发布扩展或验证其他编辑器版本。

### 开发宿主

在仓库根目录运行：

```powershell
npm run build:extension
```

使用独立的 Extension Development Host，将本目录作为 `--extensionDevelopmentPath`。测试不得改动正常编辑器配置；Marketplace 发布及发布者注册分别验收。

宿主测试使用 `scripts/run-editor-host.mjs`，参数为已安装 VS Code 可执行文件的绝对路径。测试使用隔离配置和合成工作区，不关闭工作区信任。Windows / VS Code 1.141.0 已通过八项基础检查及九项工作流检查：保存扫描默认关闭、启用后触发、连续保存后的最终结果、关闭后停止、项目选择、独立配置、兄弟项目结果保留、取消不产生成功结果，以及清除诊断。VS Code 1.95 及其他版本、平台尚未验收。

`--workflows` 检查保存、取消及多根交互，按提示按钮选择指定项目。`--prepare` 打开手动检查；`--session=<测试目录绝对路径>` 复用经校验的会话，不覆盖结果。须在当前窗口确认信任。信任超时、未完成选择或未观察到取消时序均报告 `blocked`，不记为通过。失败显示具体步骤，通过后自动关闭；结束时恢复临时设置并删除生成的负载文件，会话结果仅保留在本地。
