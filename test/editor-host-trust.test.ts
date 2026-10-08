/** 验证真实宿主驱动的授权等待，不把模拟测试当作界面验收。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { runInNewContext } from 'node:vm'
import { createRequire } from 'node:module'
import { win32 } from 'node:path'

const source = readFileSync(new URL('../extensions/vscode/test/host.cjs', import.meta.url), 'utf8')
const require = createRequire(import.meta.url)
function setup(trusted = false) {
  let callback: (() => void) | undefined, disposed = 0, subscribed = 0
  const workspace = { isTrusted: trusted, onDidGrantWorkspaceTrust(fn: () => void) {
    callback = fn; subscribed++; return { dispose() { disposed++ } }
  } }
  const exports: { waitForTrust?: (workspace: unknown, ms: number) => Promise<boolean> } = {}
  runInNewContext(source, { exports, require: (name: string) => name === 'vscode' ? {} : require(name), setTimeout, clearTimeout })
  return { workspace, wait: (ms = 1000) => exports.waitForTrust!(workspace, ms),
    grant() { workspace.isTrusted = true; callback?.() }, signal() { callback?.() },
    counters: () => ({ subscribed, disposed }) }
}
test('trusted workspaces proceed without subscribing or changing settings', async () => {
  const host = setup(true)
  assert.equal(await host.wait(), true)
  assert.deepEqual(host.counters(), { subscribed: 0, disposed: 0 })
})
test('untrusted workspaces wait for the real grant event and dispose the listener', async () => {
  const host = setup(); let settled = false
  const result = host.wait().then(value => { settled = true; return value })
  await Promise.resolve(); assert.equal(settled, false)
  assert.equal(host.workspace.isTrusted, false)
  host.grant(); assert.equal(await result, true)
  assert.deepEqual(host.counters(), { subscribed: 1, disposed: 1 })
})
test('trust timeout stays blocked and a late grant cannot change the result', async () => {
  const host = setup()
  assert.equal(await host.wait(1), false)
  assert.equal(host.workspace.isTrusted, false)
  host.grant(); assert.deepEqual(host.counters(), { subscribed: 1, disposed: 1 })
})
test('an event without actual trust cannot authorize scanning', async () => {
  const host = setup(); const result = host.wait()
  host.signal(); assert.equal(await result, false)
  assert.equal(host.workspace.isTrusted, false)
  assert.deepEqual(host.counters(), { subscribed: 1, disposed: 1 })
})

test('Windows host paths accept drive-case normalization but reject a different workspace', async () => {
  for (const valid of [true, false]) {
    const reports: Array<{ status: string; stage?: string }> = []
    const exports: { run?: () => Promise<void> } = {}
    let cleared = false, opened = false, shown = false
    const rule = 'cors/reflected-origin-with-credentials'
    const vscode = {
      version: 'synthetic', workspace: { isTrusted: true, workspaceFolders: [{ uri: { fsPath: valid ? 'c:\\test\\project' : 'c:\\other\\project' } }],
        openTextDocument: async () => { opened = true; return { uri: {} } } },
      extensions: { all: [{ extensionPath: 'c:\\extension', activate: async () => {} }] },
      Uri: { joinPath: () => ({ fsPath: 'c:\\test\\project\\server.ts' }) }, Position: class {},
      languages: { getDiagnostics: () => cleared ? [] : [{ source: 'canship', code: rule, range: {} }] },
      window: { activeTextEditor: { document: { getText: () => '1 findings; 1 blocking' } },
        showTextDocument: async () => { assert.equal(opened, true); shown = true }, showErrorMessage: async () => {} },
      commands: { executeCommand: async (name: string) => {
        if (name === 'vscode.executeHoverProvider') return [{ contents: [{ value: rule, isTrusted: false }] }]
        if (name === 'vscode.executeCodeActionProvider') { assert.equal(shown, true); return [{ command: { command: 'canship.previewIgnore' } }] }
        if (name === 'canship.clearResults') cleared = true
      } },
    }
    runInNewContext(source, { exports, setTimeout, clearTimeout,
      process: { env: { CANSHIP_EDITOR_TEST_DIR: 'C:\\test', CANSHIP_EDITOR_EXTENSION: 'C:\\extension' } },
      require: (name: string) => name === 'vscode' ? vscode : name === 'node:path' ? win32 : name === 'node:fs' ? {
        realpathSync: (path: string) => path, readFileSync: () => '{"kind":"canship-editor-host-test"}',
        writeFileSync: (_path: string, json: string) => reports.push(JSON.parse(json)),
      } : require(name) })
    if (valid) { await exports.run!(); assert.equal(reports[0]?.status, 'passed') }
    else { await assert.rejects(exports.run!(), /workspace/); assert.deepEqual(reports, [{ status: 'failed', stage: 'workspace' }]) }
  }
})

test('failed action checks preserve a private-safe result and wait for acknowledgement before throwing', async () => {
  for (const throws of [false, true]) {
    const reports: unknown[] = [], dialogs: unknown[] = []
    let acknowledge: (() => void) | undefined, settled = false
    const exports: { run?: () => Promise<void> } = {}
    const rule = 'cors/reflected-origin-with-credentials'
    const vscode = {
      workspace: { isTrusted: true, workspaceFolders: [{ uri: { fsPath: 'C:\\test\\project' } }], openTextDocument: async () => ({}) },
      extensions: { all: [{ extensionPath: 'C:\\extension', activate: async () => {} }] },
      Uri: { joinPath: () => ({}) }, Position: class {},
      languages: { getDiagnostics: () => [{ source: 'canship', code: rule, range: {} }] },
      window: { showTextDocument: async () => {}, showErrorMessage: (...args: unknown[]) => {
        dialogs.push(args); return new Promise<void>(resolve => { acknowledge = resolve })
      } },
      commands: { executeCommand: async (name: string) => {
        if (name === 'vscode.executeHoverProvider') return [{ contents: [{ value: rule, isTrusted: false }] }]
        if (name === 'vscode.executeCodeActionProvider') {
          if (throws) throw new Error('SYNTHETIC_PRIVATE_FAILURE must not appear in reports')
          return []
        }
      } },
    }
    runInNewContext(source, { exports, setTimeout, clearTimeout,
      process: { env: { CANSHIP_EDITOR_TEST_DIR: 'C:\\test', CANSHIP_EDITOR_EXTENSION: 'C:\\extension' } },
      require: (name: string) => name === 'vscode' ? vscode : name === 'node:path' ? win32 : name === 'node:fs' ? {
        realpathSync: (path: string) => path, readFileSync: () => '{"kind":"canship-editor-host-test"}',
        writeFileSync: (_path: string, json: string) => reports.push(JSON.parse(json)),
      } : require(name) })
    const completed = assert.rejects(exports.run!(), /Editor host smoke failed at actions/).then(() => { settled = true })
    await new Promise(resolve => setImmediate(resolve))
    assert.equal(settled, false)
    assert.equal((reports[0] as { status: string }).status, 'failed')
    assert.equal(dialogs.length, 1)
    assert.match(JSON.stringify(dialogs), /Close Test Window/)
    assert.doesNotMatch(JSON.stringify([reports, dialogs]), /SYNTHETIC_PRIVATE_FAILURE/)
    assert.equal(typeof acknowledge, 'function')
    acknowledge!(); await completed
    assert.equal(settled, true)
  }
})
