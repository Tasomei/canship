/** 比较视图仅使用比较结果白名单，不嵌入原报告、摘录或扫描根目录。 */
import { resolve } from 'node:path'
import { realpathSync, statSync } from 'node:fs'
import { inspectOutput, writeOutput } from '../output.js'
import type { compareReports } from './compare.js'

type Comparison = ReturnType<typeof compareReports>
export const MAX_COMPARISON_ROWS = 2000
const MAX_REFERENCE_CHARACTERS = 512
const escape = (value: string): string => value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#39;')

export function renderComparisonHtml(report: Comparison): string {
  let clipped = false
  const reference = (value: string): string => {
    if (value.length <= MAX_REFERENCE_CHARACTERS) return escape(value)
    clipped = true
    let prefix = value.slice(0, MAX_REFERENCE_CHARACTERS)
    if (/[\ud800-\udbff]$/.test(prefix)) prefix = prefix.slice(0, -1)
    return escape(prefix) + '… [truncated]'
  }
  const levels = (value: Comparison['entries'][number]['before']): string => value.count === 0 ? 'none' :
    value.levels.map(level => `${level.severity}/${level.confidence} ×${level.count}`).join('<br>') +
      (value.firstLine === null ? '' : `<br>first line ${value.firstLine}`)
  const totalRows = report.entries.length + report.unpaired.before.length + report.unpaired.after.length
  const rows: string[] = []
  for (const entry of report.entries.slice(0, MAX_COMPARISON_ROWS)) {
    rows.push(`<tr><th scope="row"><code>${reference(entry.ruleId)}</code><br>${reference(entry.file ?? '(project)')}<br><small>${escape(entry.fingerprint)}</small></th>` +
      `<td data-label="Earlier"><span>${levels(entry.before)}</span></td><td data-label="Later"><span>${levels(entry.after)}</span></td><td data-label="Change"><span>${entry.added} added<br>${entry.persisting} persisting<br>${entry.notObserved} not observed</span></td></tr>`)
  }
  for (const side of ['before', 'after'] as const) {
    for (const entry of report.unpaired[side].slice(0, MAX_COMPARISON_ROWS - rows.length)) {
      const text = `${entry.severity}/${entry.confidence}${entry.line === null ? '' : `<br>line ${entry.line}`}`
      rows.push(`<tr><th scope="row"><code>${reference(entry.ruleId)}</code><br>${reference(entry.file ?? '(project)')}</th>` +
        `<td data-label="Earlier"><span>${side === 'before' ? text : 'none'}</span></td><td data-label="Later"><span>${side === 'after' ? text : 'none'}</span></td><td data-label="Change"><span>Unpaired: no stable source identity</span></td></tr>`)
    }
  }
  const summary = Object.entries(report.counts).map(([key, count]) => `<dt>${({ before: 'Earlier findings', after: 'Later findings', added: 'Added',
    persisting: 'Persisting', notObserved: 'Not observed later', unpairedBefore: 'Unpaired earlier', unpairedAfter: 'Unpaired later' } as Record<string, string>)[key]}</dt><dd>${count}</dd>`).join('')
  const view = { schemaVersion: 1, kind: 'report-comparison-view', totalRows, shownRows: rows.length, truncatedReferences: clipped }
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="referrer" content="no-referrer"><title>canship report comparison</title>
<style>
:root{color-scheme:light dark;--paper:#fcfcfa;--ink:#1b1b18;--muted:#5c5b56;--rule:#bdbab0}
@media(prefers-color-scheme:dark){:root{--paper:#171715;--ink:#e9e7e0;--muted:#aaa79c;--rule:#4a4843}}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 Georgia,serif}
main{max-width:1040px;margin:auto;padding:24px}h1{line-height:1.2}p{max-width:80ch}small{color:var(--muted)}
dl{display:grid;grid-template-columns:minmax(0,1fr) auto;max-width:32rem}dd{margin:0;text-align:right}
table{width:100%;border-collapse:collapse;table-layout:fixed}th,td{padding:10px 8px;border-bottom:1px solid var(--rule);text-align:left;vertical-align:top;overflow-wrap:anywhere}
th{font-weight:normal}th:first-child{width:40%}code,small{font:12px/1.6 ui-monospace,monospace}.limits{border-left:3px solid var(--rule);padding-left:16px}
@media screen and (max-width:600px){main{padding:16px}table,tbody,tr,th,td{display:block;width:100%}th:first-child{width:100%}
thead{position:absolute;width:1px;height:1px;clip-path:inset(50%);overflow:hidden}tbody tr{border:1px solid var(--rule);margin:16px 0;padding:12px}
th,td{padding:8px 0;font-size:14px}td{display:grid;grid-template-columns:80px minmax(0,1fr);gap:12px}td::before{content:attr(data-label);color:var(--muted)}td:last-child{border:0}}
@media print{:root{color-scheme:light;--paper:#fff;--ink:#000;--muted:#444;--rule:#999}main{padding:0;max-width:none}tr{break-inside:avoid-page}thead{display:table-header-group}}
</style></head><body><main><h1>Saved report comparison</h1>
<p>No scan performed. ${escape(report.notice)}</p><dl>${summary}</dl>
<section class="limits"><h2>${report.limited ? 'Comparison limitations' : 'Comparison scope'}</h2>
${report.warnings.length ? `<ul>${report.warnings.map(warning => `<li><code>${escape(warning.code)}</code>: ${escape(warning.message)}</li>`).join('')}</ul>` : '<p>No known comparison limitation was detected. This is not a scan verdict.</p>'}
<p>Comparison exit ${report.exitCode}. A missing record does not establish remediation.</p></section>
<h2>Details</h2><p>Showing ${rows.length} of ${totalRows} detail rows. Counts above include all records.</p>
${totalRows > rows.length || clipped ? '<p>Display limit reached. Use comparison JSON for complete references; this HTML view does not change comparison counts or exit status.</p>' : ''}
${rows.length ? `<table><thead><tr><th scope="col">Rule / location</th><th scope="col">Earlier</th><th scope="col">Later</th><th scope="col">Change</th></tr></thead><tbody>${rows.join('')}</tbody></table>` : '<p>No detail records.</p>'}
</main><script type="application/json" id="canship-data">${JSON.stringify(view)}</script></body></html>
`
}

/** 输出不能覆盖任一输入，包括目录别名与硬链接。 */
export function writeComparisonHtml(path: string, inputs: readonly string[], report: Comparison): void {
  if (/^(?:\\\\|\/\/)/.test(resolve(path))) throw new Error('Comparison output must be local.')
  const { target, before } = inspectOutput(path, 'html')
  const key = (value: string) => process.platform === 'win32' ? value.toLowerCase() : value
  for (const input of inputs) {
    if (key(target) === key(realpathSync(input))) throw new Error('Comparison output cannot replace an input.')
    const source = statSync(input)
    if (before && before.dev === source.dev && before.ino === source.ino) throw new Error('Comparison output cannot alias an input.')
  }
  writeOutput(target, renderComparisonHtml(report), 'html')
}
