/** 真实宿主工作流验收；只操作驱动器生成的合成项目及隔离配置。 */
const assert = require('node:assert/strict')
const { readFileSync, realpathSync, mkdirSync, writeFileSync, unlinkSync, rmdirSync } = require('node:fs')
const { join, resolve, relative } = require('node:path')
const vscode = require('vscode')

const unsafe = 'app.use(cors({origin:true,credentials:true}));'
const safe = "app.use(cors({origin:'https://app.example.com',credentials:true}));"
const delay = ms => new Promise(resolve => setTimeout(resolve, ms))
const samePath = (left, right) => relative(realpathSync(left), realpathSync(right)) === ''
async function until(check, timeout = 15_000) {
  const end = Date.now() + timeout
  while (!await check()) { if (Date.now() >= end) throw new Error('Workflow state timed out.'); await delay(50) }
}

exports.runWorkflows = async (directory, extensionPath, stage) => {
  stage('workflow-workspace')
  assert.equal(vscode.workspace.isTrusted, true)
  const folders = vscode.workspace.workspaceFolders
  assert.equal(folders.length, 2)
  const one = folders.find(folder => samePath(folder.uri.fsPath, join(directory, 'project', 'one')))
  const two = folders.find(folder => samePath(folder.uri.fsPath, join(directory, 'project', 'two')))
  assert.ok(one && two)
  assert.equal(one.name, 'Synthetic One'); assert.equal(two.name, 'Synthetic Two')
  const extension = vscode.extensions.all.find(item => relative(resolve(item.extensionPath), resolve(extensionPath)) === '')
  assert.ok(extension); await extension.activate()
  const uri = vscode.Uri.joinPath(one.uri, 'server.ts')
  const rulesUri = vscode.Uri.joinPath(two.uri, 'firestore.rules')
  const secondCode = vscode.Uri.joinPath(two.uri, 'server.ts')
  const findings = target => vscode.languages.getDiagnostics(target).filter(item => item.source === 'canship')
  const document = await vscode.workspace.openTextDocument(uri)
  await vscode.window.showTextDocument(document, { preview: false })
  assert.equal(document.getText().trim(), unsafe)
  const config = vscode.workspace.getConfiguration('canship')
  const keys = ['scanOnSave', 'saveDelay']
  const previous = new Map(keys.map(key => [key, config.inspect(key)?.globalValue]))
  const generated = []
  const bulk = join(one.uri.fsPath, 'acceptance-load')
  let bulkCreated = false
  async function replace(text) {
    const edit = new vscode.WorkspaceEdit()
    edit.replace(uri, new vscode.Range(document.positionAt(0), document.positionAt(document.getText().length)), text)
    assert.equal(await vscode.workspace.applyEdit(edit), true)
    assert.equal(await document.save(), true)
  }
  async function summary(folder) {
    await vscode.commands.executeCommand('canship.showSummary')
    const value = vscode.window.activeTextEditor.document.getText()
    return value.split('\n\n').find(part => part.startsWith(folder.uri.fsPath + '\n')) ?? ''
  }
  async function choose(name, key) {
    // 用户切回聊天确认信任时会使 QuickPick 失焦；先等待显式开始按钮。
    stage('ready-' + key)
    const button = 'Choose ' + name
    if (await vscode.window.showInformationMessage('Canship acceptance: select ' + name + ' in the next project picker.', button) !== button) {
      const error = new Error('The requested project selection was not completed.')
      error.code = 'ACCEPTANCE_PROJECT_NOT_SELECTED'; throw error
    }
    stage('choose-' + key)
    await vscode.commands.executeCommand('canship.scanWorkspace')
  }
  try {
    stage('save-default-off')
    assert.notEqual(config.get('scanOnSave'), true)
    assert.equal(await summary(one), '')
    await replace(safe); await delay(500)
    assert.equal(findings(uri).length, 0)
    assert.match(await summary(one), /Source changed; results are stale/)
    assert.doesNotMatch(await summary(one), /Coverage:|\d+ findings;/)

    stage('save-enabled')
    await config.update('saveDelay', 250, vscode.ConfigurationTarget.Global)
    await config.update('scanOnSave', true, vscode.ConfigurationTarget.Global)
    await replace(unsafe)
    await until(() => findings(uri).some(item => item.code === 'cors/reflected-origin-with-credentials'))
    assert.equal(findings(uri).length, 1)

    // 使用真实项目选择器，由界面验收选择指定条目，不替换宿主 API。
    await choose('Synthetic Two', 'two')
    const secondSummary = await summary(two)
    if (!/Coverage:|Scan failed|Scan cancelled|Scan pending/.test(secondSummary)) {
      const error = new Error('The requested project selection was not completed.')
      error.code = 'ACCEPTANCE_PROJECT_NOT_SELECTED'; throw error
    }
    stage('verify-two-rules', { rulesCount: findings(rulesUri).length, secondCodeCount: findings(secondCode).length,
      oneCount: findings(uri).length,
      globalFirebaseCount: vscode.languages.getDiagnostics().flatMap(([, values]) => values).filter(item => item.source === 'canship' && item.code === 'firebase/open-rules').length,
      summaryFailed: /Scan failed/.test(secondSummary), summaryComplete: /Coverage: complete/.test(secondSummary),
      summaryFindings: Number(/(\d+) findings;/.exec(secondSummary)?.[1] ?? -1),
      hiddenLikely: Number(/(\d+) hidden likely/.exec(secondSummary)?.[1] ?? -1),
      unlocated: Number(/(\d+) findings without a current file location/.exec(secondSummary)?.[1] ?? -1) })
    assert.equal(findings(rulesUri).length, 1)
    stage('verify-two-rule-id')
    assert.equal(findings(rulesUri)[0].code, 'firebase/open-rules')
    stage('verify-two-exclusions')
    assert.equal(findings(secondCode).length, 0)
    stage('verify-one-retained')
    assert.equal(findings(uri).length, 1)
    await choose('Synthetic One', 'one')
    stage('verify-both-results')
    assert.equal(findings(uri).length, 1)
    assert.equal(findings(rulesUri).length, 1)

    stage('cancel-load')
    mkdirSync(bulk); bulkCreated = true
    let cancelled = false
    for (let attempt = 0; attempt < 2 && !cancelled; attempt++) {
      // 固定且有界的安全 CORS 文本只作扫描输入，不执行其中代码。
      for (let index = generated.length; index < (attempt + 1) * 1000; index++) {
        const path = join(bulk, `sample-${index}.ts`)
        writeFileSync(path, safe + '\n' + '// synthetic workload\n'.repeat(80), { flag: 'wx' }); generated.push(path)
      }
      assert.equal(findings(uri).length, 1)
      let observed = false, cancellation
      const listener = vscode.languages.onDidChangeDiagnostics(event => {
        if (observed || !event.uris.some(changed => changed.scheme === 'file' && relative(changed.fsPath, uri.fsPath) === '') || findings(uri).length !== 0) return
        observed = true
        cancellation = vscode.commands.executeCommand('canship.cancelScan')
      })
      try { await choose('Synthetic One', 'cancel-one') } finally { listener.dispose() }
      if (cancellation) await cancellation
      const result = await summary(one)
      cancelled = observed && /Scan cancelled; no clean result was produced/.test(result)
      if (observed) assert.equal(cancelled, true, 'A cancelled request must not publish success')
    }
    if (!cancelled) {
      const error = new Error('Cancellation timing was not observed.')
      error.code = 'ACCEPTANCE_CANCEL_WINDOW_MISSED'; throw error
    }
    assert.equal(findings(uri).length, 0)
    assert.equal(findings(rulesUri).length, 1)
    await delay(300)
    assert.equal(findings(uri).length, 0)

    stage('save-burst-and-isolation')
    for (const text of [safe, unsafe, safe]) await replace(text)
    await until(async () => /0 findings; 0 blocking/.test(await summary(one)))
    assert.equal(findings(uri).length, 0)
    assert.equal(findings(rulesUri).length, 1)

    stage('save-disabled')
    await config.update('scanOnSave', false, vscode.ConfigurationTarget.Global)
    await replace(unsafe); await delay(600)
    assert.equal(findings(uri).length, 0)
    assert.doesNotMatch(await summary(one), /Coverage: complete/)

    stage('workflow-clear')
    await vscode.commands.executeCommand('canship.clearResults')
    assert.equal(findings(uri).length + findings(rulesUri).length, 0)
    return ['save-default-off', 'save-enabled', 'save-burst-final-state', 'save-disabled',
      'project-selection', 'project-config-isolation', 'sibling-results-retained', 'cancel-no-success', 'clear']
  } finally {
    // 只恢复隔离配置中的原值，不修改正常用户配置或工作区信任。
    const failures = []
    const cleanup = async (label, action) => { try { await action() } catch { failures.push(label) } }
    await cleanup('cancel', () => vscode.commands.executeCommand('canship.cancelScan'))
    for (const key of keys) await cleanup(key, () => config.update(key, previous.get(key), vscode.ConfigurationTarget.Global))
    await cleanup('source', async () => {
      if (document.getText().trim() !== unsafe || document.isDirty) await replace(unsafe)
      assert.equal(readFileSync(uri.fsPath, 'utf8').trim(), unsafe)
    })
    for (const path of generated) await cleanup('fixture', () => unlinkSync(path))
    if (bulkCreated) await cleanup('directory', () => rmdirSync(bulk))
    if (failures.length) { stage('workflow-cleanup-failed'); throw new Error('Workflow cleanup failed: ' + [...new Set(failures)].join(', ')) }
  }
}
