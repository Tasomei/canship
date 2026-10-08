/** 真实宿主测试仅使用驱动器创建的合成工作区，不更改信任设置或系统剪贴板。 */
const assert = require('node:assert/strict')
const { readFileSync, writeFileSync, realpathSync } = require('node:fs')
const { join, resolve, relative } = require('node:path')
const vscode = require('vscode')

/** 等待用户在真实界面授予信任；超时不执行扫描，也不更改信任设置。 */
exports.waitForTrust = (workspace, timeoutMs = 300_000) => {
  if (workspace.isTrusted) return Promise.resolve(true)
  return new Promise(resolve => {
    let finished = false
    const finish = accepted => {
      if (finished) return
      finished = true; clearTimeout(timer); subscription.dispose(); resolve(accepted)
    }
    const subscription = workspace.onDidGrantWorkspaceTrust(() => finish(workspace.isTrusted === true))
    const timer = setTimeout(() => finish(false), timeoutMs)
    if (workspace.isTrusted) finish(true)
  })
}

exports.run = async () => {
  const directory = process.env.CANSHIP_EDITOR_TEST_DIR
  const marker = JSON.parse(readFileSync(join(directory, 'marker.json'), 'utf8'))
  assert.equal(marker.kind, 'canship-editor-host-test')
  const output = data => writeFileSync(join(directory, 'result.json'), JSON.stringify(data), { flag: 'wx' })
  let stage = 'trust'
  let actionState
  let workflowState
  try {
    if (!vscode.workspace.isTrusted) {
      writeFileSync(join(directory, 'waiting.json'), JSON.stringify({ stage: 'trust' }), { flag: 'wx' })
      if (!await exports.waitForTrust(vscode.workspace)) {
        output({ status: 'blocked', stage, reason: 'workspace_trust_required' })
        await vscode.window.showWarningMessage('Canship acceptance blocked: Workspace Trust was not granted.',
          { modal: true, detail: 'No scan was run. The result is saved locally. Dismiss this message to close only this test window.' }, 'Close Test Window')
        return
      }
    }
    if (marker.suite === 'workflows') {
      const { runWorkflows } = require('./workflows.cjs')
      const checks = await runWorkflows(directory, process.env.CANSHIP_EDITOR_EXTENSION, (next, details) => {
        stage = next
        if (details) workflowState = details
        writeFileSync(join(directory, 'progress.json'), JSON.stringify({ stage, workflowState }))
      })
      output({ status: 'passed', vscode: vscode.version, suite: 'workflows', checks })
      return
    }
    stage = 'workspace'
    assert.equal(vscode.workspace.workspaceFolders.length, 1)
    const folder = vscode.workspace.workspaceFolders[0]
    // Windows 的盘符大小写可能被宿主规范化，仍须严格指向同一真实目录。
    assert.equal(relative(realpathSync(folder.uri.fsPath), realpathSync(join(directory, 'project'))), '')
    stage = 'activation'
    const expected = resolve(process.env.CANSHIP_EDITOR_EXTENSION)
    const extension = vscode.extensions.all.find(item => relative(resolve(item.extensionPath), expected) === '')
    assert.ok(extension)
    await extension.activate()
    stage = 'scan'
    await vscode.commands.executeCommand('canship.scanWorkspace')
    const uri = vscode.Uri.joinPath(folder.uri, 'server.ts')
    const findings = vscode.languages.getDiagnostics(uri).filter(item => item.source === 'canship')
    assert.equal(findings.length, 1)
    assert.equal(findings[0].code, 'cors/reflected-origin-with-credentials')
    stage = 'document'
    // 代码操作命令要求已加载的编辑器模型；悬浮提供器的临时模型不能替代它。
    await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(uri), { preview: true })
    stage = 'hover'
    const hovers = await vscode.commands.executeCommand('vscode.executeHoverProvider', uri, new vscode.Position(0, 0))
    assert.ok(hovers.some(item => item.contents.some(content => content.value?.includes('cors/reflected-origin-with-credentials') && content.isTrusted !== true)))
    stage = 'actions'
    const actions = await vscode.commands.executeCommand('vscode.executeCodeActionProvider', uri, findings[0].range)
    assert.ok(Array.isArray(actions), 'Code actions must be returned as an array')
    // 失败诊断仅记录结构和预期命令匹配，不输出参数、路径或源码。
    actionState = { count: actions.length, entries: actions.slice(0, 20).map(action => ({
      titleMatches: action.title === 'Canship: Review line suppression',
      commandShape: typeof action.command,
      commandMatches: action.command?.command === 'canship.previewIgnore' || action.command === 'canship.previewIgnore',
    })) }
    assert.ok(actions.some(action => action.command?.command === 'canship.previewIgnore'))
    stage = 'summary'
    await vscode.commands.executeCommand('canship.showSummary')
    assert.match(vscode.window.activeTextEditor.document.getText(), /1 findings; 1 blocking/)
    stage = 'clear'
    await vscode.commands.executeCommand('canship.clearResults')
    assert.equal(vscode.languages.getDiagnostics(uri).filter(item => item.source === 'canship').length, 0)
    output({ status: 'passed', vscode: vscode.version, checks: ['activation', 'scan', 'diagnostics', 'document', 'hover', 'actions', 'summary', 'clear'] })
  } catch (error) {
    if (error?.code === 'ACCEPTANCE_PROJECT_NOT_SELECTED') {
      output({ status: 'blocked', stage, reason: 'project_selection_not_completed' })
      await vscode.window.showWarningMessage('Canship acceptance blocked: the requested project was not selected.',
        { modal: true, detail: 'No multi-root pass is claimed. Keep the picker open until the requested synthetic project is chosen. Dismiss this message to close only this test window.' }, 'Close Test Window')
      return
    }
    if (error?.code === 'ACCEPTANCE_CANCEL_WINDOW_MISSED') {
      output({ status: 'blocked', stage, reason: 'cancellation_window_not_observed' })
      await vscode.window.showWarningMessage('Canship acceptance blocked: cancellation timing was not observed.',
        { modal: true, detail: 'No cancellation pass is claimed. The result is saved locally. Dismiss this message to close only this test window.' }, 'Close Test Window')
      return
    }
    const message = String(error?.message ?? '')
    const failure = { assertion: error?.code === 'ERR_ASSERTION', typeError: error instanceof TypeError,
      rangeArgument: /rangeOrSelection|range|Range/.test(message),
      uriArgument: /uri|URI|Uri/.test(message), commandError: /command/i.test(message),
      disposed: /disposed|cancel/i.test(message), undefinedValue: /undefined/.test(message),
      unknown: /unknown|not found|not registered/i.test(message) }
    output({ status: 'failed', stage, ...(stage === 'actions' ? { failure, actionState } : {}), ...(workflowState ? { workflowState } : {}) })
    // 先保存脱敏结果并展示失败步骤，用户确认后才让测试宿主退出。
    await vscode.window.showErrorMessage(`Canship acceptance failed at: ${stage}.`,
      { modal: true, detail: 'The failure result is saved locally. This is not a passed acceptance test. Dismiss this message to close only this test window.' }, 'Close Test Window')
    throw new Error('Editor host smoke failed at ' + stage)
  }
}
