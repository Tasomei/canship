/** 使用打包入口验证宿主交互和竞态；此测试不等同于真实编辑器界面验收。 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import { mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { createRequire } from 'node:module'
import { runInNewContext } from 'node:vm'
import { createHash } from 'node:crypto'
import { build } from 'tsup'

const temporary = mkdtempSync(join(tmpdir(), 'canship-editor-controller-'))
after(() => rmSync(temporary, { recursive: true, force: true }))
let bundle = ''
before(async () => {
  const output = join(temporary, 'bundle')
  await build({ config: false, entry: { extension: 'extensions/vscode/src/extension.ts' }, outDir: output,
    format: ['cjs'], platform: 'node', target: 'node18', bundle: true, external: ['vscode'], silent: true })
  bundle = readFileSync(join(output, 'extension.cjs'), 'utf8')
})
const source = 'app.use(cors({origin:true,credentials:true}));'
const disposable = () => ({ dispose() {} })
class Uri {
  constructor(readonly value: string) {}
  static file(path: string) { return new Uri(pathToFileURL(path).href) }
  static parse(value: string) { return new Uri(value) }
  static from(value: { scheme: string; path: string }) { return new Uri(`${value.scheme}:${value.path}`) }
  get scheme() { return this.value.split(':')[0] }
  get fsPath() { return this.scheme === 'file' ? fileURLToPath(this.value) : this.value }
  toString() { return this.value }
}
class Range {
  start: { line: number; character: number }
  end: { line: number; character: number }
  constructor(a: number, b: number, c: number, d: number) { this.start = { line: a, character: b }; this.end = { line: c, character: d } }
}
class Diagnostic {
  source = ''; code = ''
  constructor(readonly range: Range, readonly message: string, readonly severity: number) {}
}
class CodeAction {
  command?: { command: string; arguments: unknown[] }
  diagnostics?: Diagnostic[]
  constructor(readonly title: string) {}
}
class MarkdownString {
  isTrusted = false; supportHtml = false; value = ''
  appendText(text: string) { this.value += text; return this }
  appendCodeblock(text: string) { this.value += text; return this }
}

function setup(trusted = true) {
  const root = mkdtempSync(join(temporary, 'project-')), uri = Uri.file(join(root, 'server.ts'))
  writeFileSync(uri.fsPath, source)
  const folder = { name: 'sample', uri: Uri.file(root), index: 0 }
  const settings: Record<string, unknown> = {}
  const commands = new Map<string, (...args: any[]) => any>()
  const callbacks: Record<string, (...args: any[]) => any> = {}
  const collection = new Map<string, Diagnostic[]>()
  const providers: Record<string, any> = {}
  const workers: FakeWorker[] = []
  let clipboard = '', shown = '', answer: string | undefined, currentText = source
  const warnings: any[][] = []
  const document = { uri, version: 1, isDirty: false, getText: () => currentText }
  const textDocuments = [document]
  const status = { text: '', tooltip: '', command: '', show() {}, dispose() {} }
  class FakeWorker extends EventEmitter {
    stdout = new EventEmitter(); stderr = new EventEmitter(); terminated = false
    constructor(readonly path: string, readonly options: any) { super(); workers.push(this) }
    async terminate() { this.terminated = true; this.emit('exit', 1); return 1 }
    result(title = 'Sample CORS finding') {
      this.emit('message', { type: 'result', version: '0.0.0-dev', displayOmitted: 0, result: {
        exitCode: 1, error: null, summary: { findings: 1, blocking: 1, likely: 0, partial: false, exitCode: 1 },
        report: { findings: [{ ruleId: 'cors/reflected-origin-with-credentials', title, file: 'server.ts', line: 1,
          sourceFingerprint: createHash('sha256').update(source).digest('hex'), severity: 'P1', confidence: 'certain', excerpt: null,
          why: ['[untrusted](command:run)'], fix: ['Use an explicit origin'],
          evidence: [{ kind: 'operation', file: 'server.ts', line: 1, description: 'Sample static operation' }] }], filesScanned: 1, hiddenLikely: 0, baselineSuppressed: 0,
          baselineExpired: 0, ignored: [], ignoredFindings: [], ruleSelection: null },
      } })
    }
  }
  const register = (name: string) => (callback: (...args: any[]) => any) => { callbacks[name] = callback; return disposable() }
  const vscode = {
    Uri, Range, Diagnostic, CodeAction, MarkdownString,
    Position: class { constructor(readonly line: number, readonly character: number) {} },
    WorkspaceEdit: class { inserts: any[] = []; insert(...args: any[]) { this.inserts.push(args) } },
    Hover: class { constructor(readonly contents: MarkdownString) {} },
    DiagnosticSeverity: { Error: 0, Warning: 1, Information: 2 }, StatusBarAlignment: { Left: 1 },
    ProgressLocation: { Notification: 1 }, CodeActionKind: { QuickFix: 'quickfix' },
    env: { clipboard: { writeText: async (value: string) => { clipboard = value } } },
    commands: { registerCommand: (name: string, action: (...args: any[]) => any) => { commands.set(name, action); return disposable() } },
    window: {
      createStatusBarItem: () => status,
      showWarningMessage: async (...args: any[]) => { warnings.push(args); return answer },
      showErrorMessage: async (...args: any[]) => { warnings.push(args) },
      showInformationMessage: async (...args: any[]) => { warnings.push(args) },
      showQuickPick: async (items: any[]) => items[0],
      showTextDocument: async (value: any) => { shown = value.getText(); return value },
      withProgress: async (_options: unknown, callback: any) => callback({ report() {} }, { isCancellationRequested: false, onCancellationRequested: () => disposable() }),
    },
    workspace: {
      isTrusted: trusted, workspaceFolders: [folder], textDocuments,
      getConfiguration: () => ({ inspect: (key: string) => ({ globalValue: settings[key] }) }),
      getWorkspaceFolder: (value: Uri) => value.scheme === 'file' && value.fsPath.startsWith(root) ? folder : undefined,
      openTextDocument: async (value: Uri) => value.scheme === 'file' ? document : { uri: value, getText: () => providers.summary.provideTextDocumentContent(value) },
      registerTextDocumentContentProvider: (_scheme: string, provider: unknown) => { providers.summary = provider; return disposable() },
      applyEdit: async (edit: any) => {
        for (const [_uri, position, text] of edit.inserts) {
          assert.equal(position.line, 0); currentText = text + currentText
        }
        document.isDirty = true; document.version++
        callbacks.change!({ document, contentChanges: [{}] })
        return true
      },
      onDidChangeTextDocument: register('change'), onDidSaveTextDocument: register('save'),
      onDidChangeWorkspaceFolders: register('folders'), onDidChangeConfiguration: register('config'),
    },
    languages: {
      createDiagnosticCollection: () => ({ clear: () => collection.clear(), set: (value: Uri, entries: Diagnostic[]) => collection.set(value.toString(), entries),
        get: (value: Uri) => collection.get(value.toString()), dispose() {} }),
      registerCodeActionsProvider: (_selector: unknown, provider: unknown) => { providers.actions = provider; return disposable() },
      registerHoverProvider: (_selector: unknown, provider: unknown) => { providers.hover = provider; return disposable() },
    },
  }
  const module = { exports: {} as any }, require = createRequire(import.meta.url)
  runInNewContext(bundle, { module, exports: module.exports, Buffer, process, console, setTimeout, clearTimeout, URL,
    require: (id: string) => id === 'vscode' ? vscode : ['node:worker_threads', 'worker_threads'].includes(id) ? { Worker: FakeWorker } : require(id) })
  const context = { extensionPath: join(root, 'trusted-extension'), subscriptions: [] as { dispose(): void }[] }
  module.exports.activate(context)
  return { root, uri, settings, commands, callbacks, collection, providers, workers, document, status, warnings,
    clipboard: () => clipboard, shown: () => shown, setAnswer: (value: string | undefined) => { answer = value },
    close: () => { module.exports.deactivate(); for (const item of context.subscriptions) item.dispose() } }
}
const settled = () => new Promise<void>(resolve => setImmediate(resolve))

test('startup and untrusted commands never scan or enable save-triggered execution', async () => {
  const app = setup(false)
  try {
    await app.commands.get('canship.scanWorkspace')!()
    app.callbacks.save!(app.document)
    assert.equal(app.workers.length, 0)
    assert.ok(app.warnings.length > 0)
  } finally { app.close() }
})
test('manual scan publishes diagnostics, safe hover and a scoped fix prompt', async () => {
  const app = setup()
  try {
    assert.equal(app.workers.length, 0)
    const pending = app.commands.get('canship.scanWorkspace')!()
    await settled(); assert.equal(app.workers.length, 1)
    assert.ok(app.workers[0]!.path.endsWith(join('dist', 'worker.cjs')))
    app.workers[0]!.result(); await pending
    const values = app.collection.get(app.uri.toString())!
    assert.equal(values.length, 1)
    const hover = app.providers.hover.provideHover(app.document, { line: 0 })
    assert.equal(hover.contents.isTrusted, false)
    assert.equal(hover.contents.supportHtml, false)
    assert.match(hover.contents.value, /Static evidence:/)
    assert.match(hover.contents.value, /Sample static operation/)
    const actions = app.providers.actions.provideCodeActions(app.document, null, { diagnostics: values })
    await app.commands.get(actions[0].command.command)!(...actions[0].command.arguments)
    assert.match(app.clipboard(), /only selected findings/)
    assert.doesNotMatch(app.clipboard(), /scanned zero files|scan did not finish|rules were selected/)
    assert.match(app.clipboard(), /cors\/reflected-origin-with-credentials/)
    await app.commands.get('canship.showSummary')!()
    assert.match(app.shown(), /1 findings; 1 blocking/)
  } finally { app.close() }
})
test('source changes cancel work and prevent stale responses from restoring diagnostics', async () => {
  const app = setup()
  try {
    const pending = app.commands.get('canship.scanWorkspace')!(); await settled()
    app.callbacks.change!({ document: app.document, contentChanges: [{}] })
    app.workers[0]!.result('STALE_RESULT'); await pending
    assert.equal(app.collection.size, 0)
    assert.ok(app.workers[0]!.terminated)
    assert.match(app.status.text, /stale/)
  } finally { app.close() }
})
test('save scanning is opt-in, debounced and cancelled by settings changes', async () => {
  const app = setup()
  try {
    app.callbacks.save!(app.document); assert.equal(app.workers.length, 0)
    app.settings.scanOnSave = true; app.settings.saveDelay = 250
    for (let i = 0; i < 3; i++) app.callbacks.save!(app.document)
    await new Promise(resolve => setTimeout(resolve, 320))
    assert.equal(app.workers.length, 1)
    app.callbacks.config!({ affectsConfiguration: () => true })
    await settled(); assert.ok(app.workers[0]!.terminated)
    assert.equal(app.collection.size, 0)
  } finally { app.close() }
})
test('suppression requires preview confirmation and leaves a minimal unsaved edit', async () => {
  const app = setup()
  try {
    const pending = app.commands.get('canship.scanWorkspace')!(); await settled(); app.workers[0]!.result(); await pending
    const actions = app.providers.actions.provideCodeActions(app.document, null, { diagnostics: app.collection.get(app.uri.toString())! })
    const action = actions[1].command
    await app.commands.get(action.command)!(...action.arguments)
    assert.equal(app.document.isDirty, false)
    assert.match(app.warnings.at(-1)![1].detail, /one rule on the next line only/)
    app.setAnswer('Insert Comment')
    await app.commands.get(action.command)!(...action.arguments)
    assert.equal(app.document.isDirty, true)
    assert.match(app.document.getText(), /^\/\/ canship-ignore-next-line cors\/reflected-origin-with-credentials\n/)
    assert.equal(readFileSync(app.uri.fsPath, 'utf8'), source)
    assert.equal(app.collection.size, 0)
  } finally { app.close() }
})
