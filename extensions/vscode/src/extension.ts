/** 编辑器只调用随插件打包的扫描器；默认手动扫描，不上传项目内容。 */
import * as vscode from 'vscode'
import { join } from 'node:path'
import { randomUUID } from 'node:crypto'
import { VERSION, buildLabel } from '../../../src/build-info.js'
import { cleanForOutput } from '../../../src/engine.js'
import { renderFixPrompt } from '../../../src/report/prompt.js'
import type { PromptContext } from '../../../src/report/prompt.js'
import { fixExampleFor } from '../../../src/rules/examples.js'
import type { Finding } from '../../../src/types.js'
import { findingPath, independentRoots, Revisions, suppressionPreview } from './model.js'
import { EditorCancelled, startWorker } from './runner.js'
import type { WorkerResult } from './runner.js'

interface RecordEntry { finding: Finding; root: string; revision: number; uri: vscode.Uri; promptContext: PromptContext }
interface Request { folder: vscode.WorkspaceFolder; revision: number; done: () => void }
let cleanup: (() => void) | undefined

export function activate(context: vscode.ExtensionContext): void {
  const diagnostics = vscode.languages.createDiagnosticCollection('canship')
  const status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 20)
  status.text = '$(shield) Canship'; status.command = 'canship.scanWorkspace'; status.show()
  const revisions = new Revisions(), records = new Map<string, RecordEntry>()
  const diagnosticTokens = new WeakMap<vscode.Diagnostic, string>()
  const byRoot = new Map<string, Map<string, vscode.Diagnostic[]>>()
  const summaries = new Map<string, string>(), documents = new Map<string, string>()
  const queue = new Map<string, Request>(), timers = new Map<string, ReturnType<typeof setTimeout>>()
  let active: { root: string; cancelled: boolean; cancel: () => void } | null = null
  let disposed = false
  const settings = () => {
    const config = vscode.workspace.getConfiguration('canship')
    // 应用级用户设置不会被仓库中的 .vscode 配置静默覆盖。
    const get = <T>(key: string, fallback: T): T => config.inspect<T>(key)?.globalValue ?? fallback
    return { auto: get<boolean>('scanOnSave', false) === true, all: get<boolean>('includeLikely', false) === true,
      noConfig: get<boolean>('useProjectConfig', true) !== true, noIgnoreMarkers: get<boolean>('honorIgnoreMarkers', true) !== true,
      delay: Math.max(250, Math.min(10000, Number(get<number>('saveDelay', 750)) || 750)) }
  }
  const repaint = () => {
    diagnostics.clear()
    const merged = new Map<string, vscode.Diagnostic[]>()
    for (const group of byRoot.values()) for (const [uri, values] of group) merged.set(uri, [...(merged.get(uri) ?? []), ...values])
    for (const [uri, values] of merged) diagnostics.set(vscode.Uri.parse(uri), values)
  }
  const invalidate = (root: string) => {
    const revision = revisions.next(root)
    if (active?.root === root) active.cancel()
    const queued = queue.get(root); if (queued) { queue.delete(root); queued.done() }
    const timer = timers.get(root); if (timer) { clearTimeout(timer); timers.delete(root) }
    byRoot.delete(root)
    for (const [id, entry] of records) if (entry.root === root) records.delete(id)
    repaint()
    return revision
  }
  const eligible = (folder: vscode.WorkspaceFolder) => vscode.workspace.isTrusted && folder.uri.scheme === 'file' &&
    vscode.workspace.workspaceFolders?.some(item => item.uri.toString() === folder.uri.toString()) === true &&
    independentRoots((vscode.workspace.workspaceFolders ?? []).filter(item => item.uri.scheme === 'file').map(item => item.uri.fsPath))
  const showSummary = async () => {
    const uri = vscode.Uri.from({ scheme: 'canship-summary', path: '/' + randomUUID() })
    documents.clear()
    documents.set(uri.toString(), [...summaries.entries()].map(([root, summary]) => `${cleanForOutput(root)}\n${summary}`).join('\n\n') || 'No completed scan. Run Canship: Scan Workspace.')
    await vscode.window.showTextDocument(await vscode.workspace.openTextDocument(uri), { preview: true })
  }
  const publish = (request: Request, response: WorkerResult) => {
    const root = request.folder.uri.fsPath, project = response.result, report = project.report
    if (!eligible(request.folder) || !revisions.current(root, request.revision)) return
    if (!report || !project.summary) {
      summaries.set(root, `Scan failed (${project.error?.code ?? 'EDITOR_SCAN_FAILED'}). No clean result was produced.`)
      status.text = '$(warning) Canship: failed'
      void vscode.window.showErrorMessage('Canship could not complete this scan. Run the CLI locally for details.')
      return
    }
    const group = new Map<string, vscode.Diagnostic[]>()
    const promptContext: PromptContext = { selectedFindings: true, partial: project.summary.partial,
      filesScanned: report.filesScanned, hiddenLikely: report.hiddenLikely, baselineSuppressed: report.baselineSuppressed,
      baselineExpired: report.baselineExpired, excludedPaths: report.exclusions?.requested ?? [], ignoredFiles: report.ignored,
      silenced: report.ignoredFindings.map(f => `${f.file}:${f.line} (${f.ruleId})`),
      ruleSelection: report.ruleSelection === null ? null : 'a rule filter was applied; consult the original report for its scope' }
    let unlocated = 0
    for (const finding of report.findings) {
      const path = findingPath(root, finding.file)
      if (!path) { unlocated++; continue }
      const uri = vscode.Uri.file(path)
      const open = vscode.workspace.textDocuments.find(document => document.uri.toString() === uri.toString())
      if (open?.isDirty) { unlocated++; continue }
      const line = Math.max(0, (finding.line ?? 1) - 1)
      const diagnostic = new vscode.Diagnostic(new vscode.Range(line, 0, line, 1),
        `${finding.title} [${finding.severity}, ${finding.confidence}]`, finding.confidence === 'likely' ? vscode.DiagnosticSeverity.Information
          : finding.severity === 'P0' ? vscode.DiagnosticSeverity.Error : finding.severity === 'P1' ? vscode.DiagnosticSeverity.Warning : vscode.DiagnosticSeverity.Information)
      diagnostic.source = 'canship'; diagnostic.code = finding.ruleId
      const id = randomUUID()
      records.set(id, { finding, root, revision: request.revision, uri, promptContext }); diagnosticTokens.set(diagnostic, id)
      const key = uri.toString(), values = group.get(key) ?? []; values.push(diagnostic); group.set(key, values)
    }
    byRoot.set(root, group); repaint()
    summaries.set(root, [
      `Canship ${buildLabel()} — saved files only; no project code executed or uploaded.`,
      'This is a scan snapshot. Reopen the summary after editing or rescanning.',
      `${project.summary.findings} findings; ${project.summary.blocking} blocking; ${report.hiddenLikely} hidden likely.`,
      `Coverage: ${project.summary.partial ? 'incomplete' : 'complete within selected scope'}; ${report.filesScanned} files scanned.`,
      `${report.baselineSuppressed} baseline-suppressed; ${report.baselineExpired} expired; ${report.ignored.length} ignored files; ${report.ignoredFindings.length} ignored findings.`,
      `${report.exclusions?.requested.length ?? 0} path exclusions; rule selection ${report.ruleSelection ? 'active' : 'none'}.`,
      `${response.displayOmitted} findings omitted by the editor display limit; ${unlocated} findings without a current file location.`,
      'Findings are static evidence, not verification of deployed security. Paths and descriptions may be sensitive.',
      ...report.findings.filter(finding => !findingPath(root, finding.file)).map(finding => `${finding.ruleId}: ${finding.title}`),
    ].join('\n'))
    status.text = project.summary.partial ? '$(warning) Canship: incomplete' : `$(shield) Canship: ${project.summary.findings}`
    status.tooltip = 'Saved-file results. Run Canship: Show Scan Summary for scope and hidden counts.'
  }
  const pump = async () => {
    if (active || disposed || !queue.size) return
    const [root, request] = queue.entries().next().value!
    queue.delete(root)
    active = { root, cancelled: false, cancel: () => {} }
    try {
      if (!eligible(request.folder)) return
      const config = settings()
      status.text = '$(sync~spin) Canship: scanning'
      await vscode.window.withProgress({ location: vscode.ProgressLocation.Notification, title: 'Canship: scanning saved files', cancellable: true }, async (progress, token) => {
        // 进度回调可能延后启动；已取消的请求不能再创建扫描线程。
        if (active?.cancelled || token.isCancellationRequested || !revisions.current(root, request.revision)) throw new EditorCancelled('Editor scan cancelled.')
        const job = startWorker(join(context.extensionPath, 'dist', 'worker.cjs'), { root, all: config.all,
          noConfig: config.noConfig, noIgnoreMarkers: config.noIgnoreMarkers }, VERSION,
        value => progress.report({ message: `${value.phase}: ${value.filesCompleted} files, ${value.projectRulesCompleted} project checks` }))
        active!.cancel = job.cancel
        const cancel = token.onCancellationRequested(job.cancel)
        if (token.isCancellationRequested || !revisions.current(root, request.revision)) job.cancel()
        try {
          const response = await job.promise
          // 线程清理期间仍可能取消；结果已生成不代表可以继续发布。
          if (active?.cancelled || token.isCancellationRequested) throw new EditorCancelled('Editor scan cancelled.')
          publish(request, response)
        } finally { cancel.dispose() }
      })
    } catch (error) {
      if (revisions.current(root, request.revision)) {
        const cancelled = error instanceof EditorCancelled
        summaries.set(root, cancelled ? 'Scan cancelled; no clean result was produced.' : 'Scan failed; run the CLI locally for diagnostics.')
        status.text = cancelled ? '$(circle-slash) Canship: cancelled' : '$(warning) Canship: failed'
      }
    } finally { active = null; request.done(); void pump() }
  }
  const requestScan = (folder: vscode.WorkspaceFolder): Promise<void> => {
    if (!eligible(folder) || disposed) return Promise.resolve()
    const root = folder.uri.fsPath, revision = invalidate(root)
    summaries.set(root, 'Scan pending; previous results were invalidated.')
    return new Promise(resolve => { queue.set(root, { folder, revision, done: resolve }); void pump() })
  }
  const currentEntry = (id: unknown) => {
    if (typeof id !== 'string' || !vscode.workspace.isTrusted) return null
    const entry = records.get(id)
    return entry && revisions.current(entry.root, entry.revision) ? entry : null
  }
  const scanCommand = async () => {
    if (!vscode.workspace.isTrusted) { void vscode.window.showWarningMessage('Canship requires Workspace Trust before scanning.'); return }
    const folders = vscode.workspace.workspaceFolders?.filter(folder => folder.uri.scheme === 'file') ?? []
    if (!folders.length || folders.length > 32) { void vscode.window.showWarningMessage('Open 1–32 local workspace folders before scanning.'); return }
    if (!independentRoots(folders.map(folder => folder.uri.fsPath))) { void vscode.window.showWarningMessage('Canship requires accessible, non-overlapping workspace roots. Scan nested projects separately.'); return }
    const picked = folders.length === 1 ? folders[0] : (await vscode.window.showQuickPick(folders.map(folder => ({ label: cleanForOutput(folder.name), description: cleanForOutput(folder.uri.fsPath), folder })), { placeHolder: 'Choose the project to scan independently' }))?.folder
    if (!picked) return
    if (vscode.workspace.textDocuments.some(document => document.isDirty && vscode.workspace.getWorkspaceFolder(document.uri)?.uri.toString() === picked.uri.toString())) {
      if (await vscode.window.showWarningMessage('Unsaved changes are not scanned. Scan the saved files?', { modal: true }, 'Scan Saved Files') !== 'Scan Saved Files') return
    }
    await requestScan(picked)
  }
  context.subscriptions.push(diagnostics, status,
    vscode.workspace.registerTextDocumentContentProvider('canship-summary', { provideTextDocumentContent: uri => documents.get(uri.toString()) ?? 'This summary has expired. Run Canship: Show Scan Summary again.' }),
    vscode.commands.registerCommand('canship.scanWorkspace', scanCommand),
    vscode.commands.registerCommand('canship.showSummary', showSummary),
    vscode.commands.registerCommand('canship.cancelScan', () => {
      if (active) { active.cancelled = true; active.cancel() }
      for (const [root, request] of queue) { revisions.next(root); summaries.set(root, 'Queued scan cancelled.'); request.done() }
      queue.clear(); for (const timer of timers.values()) clearTimeout(timer); timers.clear()
      status.text = '$(circle-slash) Canship: cancelled'
    }),
    vscode.commands.registerCommand('canship.clearResults', () => { for (const folder of vscode.workspace.workspaceFolders ?? []) invalidate(folder.uri.fsPath); summaries.clear(); documents.clear(); status.text = '$(shield) Canship' }),
    vscode.commands.registerCommand('canship.copyFixPrompt', async (id: unknown) => {
      const entry = currentEntry(id)
      if (!entry) { void vscode.window.showInformationMessage('Select a current Canship finding in the Problems panel or code actions.'); return }
      const prompt = renderFixPrompt([entry.finding], entry.promptContext)
      if (prompt) await vscode.env.clipboard.writeText(prompt)
    }),
    vscode.commands.registerCommand('canship.previewIgnore', async (id: unknown) => {
      const entry = currentEntry(id)
      if (!entry) return
      const currentPath = findingPath(entry.root, entry.finding.file)
      if (!currentPath || vscode.Uri.file(currentPath).toString() !== entry.uri.toString()) return
      const document = await vscode.workspace.openTextDocument(entry.uri), version = document.version
      const preview = suppressionPreview(entry.uri.fsPath, document.getText(), entry.finding)
      if (!preview) { void vscode.window.showWarningMessage('This location changed or does not support a safe line comment. Review the CLI baseline instead.'); return }
      const accepted = await vscode.window.showWarningMessage('Suppress this rule on the next source line?', { modal: true,
        detail: `Insert before line ${preview.line + 1}:\n${preview.text}\nScope: one rule on the next line only. This accepts a finding, not a fix. The edit is not saved automatically.` }, 'Insert Comment')
      if (accepted !== 'Insert Comment' || !currentEntry(id) || document.version !== version || !vscode.workspace.isTrusted) return
      const edit = new vscode.WorkspaceEdit(); edit.insert(entry.uri, new vscode.Position(preview.line, 0), preview.text)
      if (await vscode.workspace.applyEdit(edit)) { invalidate(entry.root); summaries.set(entry.root, 'Source suppression edited; save and rescan to update results.') }
    }),
    vscode.languages.registerCodeActionsProvider({ scheme: 'file' }, { provideCodeActions: (_document, _range, ctx) => ctx.diagnostics.flatMap(diagnostic => {
      const id = diagnosticTokens.get(diagnostic)
      if (!id || !currentEntry(id)) return []
      return [new vscode.CodeAction('Canship: Copy finding fix prompt', vscode.CodeActionKind.QuickFix), new vscode.CodeAction('Canship: Review line suppression', vscode.CodeActionKind.QuickFix)].map((action, index) => {
        action.command = { command: index ? 'canship.previewIgnore' : 'canship.copyFixPrompt', title: action.title, arguments: [id] }; action.diagnostics = [diagnostic]; return action
      })
    }) }),
    vscode.languages.registerHoverProvider({ scheme: 'file' }, { provideHover: (document, position) => {
      const values = diagnostics.get(document.uri) ?? []
      const diagnostic = values.find(value => value.range.start.line === position.line)
      const entry = diagnostic ? currentEntry(diagnosticTokens.get(diagnostic)) : null
      if (!entry) return null
      const text = new vscode.MarkdownString(); text.isTrusted = false; text.supportHtml = false
      text.appendText(`${entry.finding.ruleId} — ${entry.finding.severity}, ${entry.finding.confidence}\n\n${entry.finding.why.join('\n\n')}\n\n${entry.finding.fix.join('\n')}`)
      if (entry.finding.evidence?.length) text.appendText('\n\nStatic evidence:\n' + entry.finding.evidence.map(step => `${step.kind}: ${step.file}${step.line === null ? '' : `:${step.line}`} — ${step.description}`).join('\n'))
      if (entry.finding.evidenceTruncated) text.appendText('\nAdditional evidence steps were omitted.')
      const example = fixExampleFor(entry.finding.ruleId)
      if (example) { text.appendText(`\n\nIllustrative example: ${example.context}\nBefore:`); text.appendCodeblock(example.before); text.appendText('After:'); text.appendCodeblock(example.after); text.appendText(example.limitation) }
      return new vscode.Hover(text, diagnostic!.range)
    } }),
    vscode.workspace.onDidChangeTextDocument(event => {
      if (!event.contentChanges.length) return
      const folder = vscode.workspace.getWorkspaceFolder(event.document.uri)
      if (folder) { invalidate(folder.uri.fsPath); summaries.set(folder.uri.fsPath, 'Source changed; results are stale. Save and rescan.'); status.text = '$(clock) Canship: stale' }
    }),
    vscode.workspace.onDidSaveTextDocument(document => {
      const folder = vscode.workspace.getWorkspaceFolder(document.uri), config = settings()
      if (!folder || !eligible(folder) || !config.auto) return
      invalidate(folder.uri.fsPath)
      timers.set(folder.uri.fsPath, setTimeout(() => { timers.delete(folder.uri.fsPath); void requestScan(folder) }, config.delay))
    }),
    vscode.workspace.onDidChangeWorkspaceFolders(event => {
      for (const folder of [...event.removed, ...(vscode.workspace.workspaceFolders ?? [])]) { invalidate(folder.uri.fsPath); summaries.delete(folder.uri.fsPath) }
      status.text = '$(clock) Canship: workspace changed'
    }),
    vscode.workspace.onDidChangeConfiguration(event => {
      if (event.affectsConfiguration('canship')) {
        for (const folder of vscode.workspace.workspaceFolders ?? []) { invalidate(folder.uri.fsPath); summaries.set(folder.uri.fsPath, 'Scan settings changed; rescan to update results.') }
        status.text = '$(clock) Canship: stale'
      }
    }),
  )
  const dispose = () => { if (disposed) return; disposed = true; active?.cancel(); for (const request of queue.values()) request.done(); queue.clear(); for (const timer of timers.values()) clearTimeout(timer); timers.clear(); revisions.clear(); records.clear(); byRoot.clear(); documents.clear(); summaries.clear(); diagnostics.clear() }
  cleanup = dispose
  context.subscriptions.unshift({ dispose })
}

export function deactivate(): void { cleanup?.(); cleanup = undefined }
