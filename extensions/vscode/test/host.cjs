/** 真实宿主测试仅使用驱动器创建的合成工作区，不更改信任设置或系统剪贴板。 */
const assert = require('node:assert/strict')
const { readFileSync, writeFileSync, realpathSync } = require('node:fs')
const { join, resolve } = require('node:path')
const vscode = require('vscode')

exports.run = async () => {
  const directory = process.env.CANSHIP_EDITOR_TEST_DIR
  const marker = JSON.parse(readFileSync(join(directory, 'marker.json'), 'utf8'))
  assert.equal(marker.kind, 'canship-editor-host-test')
  const output = data => writeFileSync(join(directory, 'result.json'), JSON.stringify(data), { flag: 'wx' })
  let stage = 'trust'
  try {
    if (!vscode.workspace.isTrusted) { output({ status: 'blocked', stage, reason: 'workspace_trust_required' }); return }
    stage = 'workspace'
    assert.equal(vscode.workspace.workspaceFolders.length, 1)
    const folder = vscode.workspace.workspaceFolders[0]
    assert.equal(realpathSync(folder.uri.fsPath), realpathSync(join(directory, 'project')))
    stage = 'activation'
    const expected = resolve(process.env.CANSHIP_EDITOR_EXTENSION)
    const extension = vscode.extensions.all.find(item => resolve(item.extensionPath) === expected)
    assert.ok(extension)
    await extension.activate()
    stage = 'scan'
    await vscode.commands.executeCommand('canship.scanWorkspace')
    const uri = vscode.Uri.joinPath(folder.uri, 'server.ts')
    const findings = vscode.languages.getDiagnostics(uri).filter(item => item.source === 'canship')
    assert.equal(findings.length, 1)
    assert.equal(findings[0].code, 'cors/reflected-origin-with-credentials')
    stage = 'hover'
    const hovers = await vscode.commands.executeCommand('vscode.executeHoverProvider', uri, new vscode.Position(0, 0))
    assert.ok(hovers.some(item => item.contents.some(content => content.value?.includes('cors/reflected-origin-with-credentials') && content.isTrusted !== true)))
    stage = 'actions'
    const actions = await vscode.commands.executeCommand('vscode.executeCodeActionProvider', uri, findings[0].range)
    assert.ok(actions.some(action => action.command?.command === 'canship.previewIgnore'))
    stage = 'summary'
    await vscode.commands.executeCommand('canship.showSummary')
    assert.match(vscode.window.activeTextEditor.document.getText(), /1 findings; 1 blocking/)
    stage = 'clear'
    await vscode.commands.executeCommand('canship.clearResults')
    assert.equal(vscode.languages.getDiagnostics(uri).filter(item => item.source === 'canship').length, 0)
    output({ status: 'passed', vscode: vscode.version, checks: ['activation', 'scan', 'diagnostics', 'hover', 'actions', 'summary', 'clear'] })
  } catch {
    output({ status: 'failed', stage })
    throw new Error('Editor host smoke failed at ' + stage)
  }
}
