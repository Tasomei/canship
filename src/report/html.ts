/**
 * Self-contained HTML report.
 *
 * One file, no external requests, no fonts or scripts from a CDN — it has to
 * work offline, from a file:// URL, and inside a corporate network that blocks
 * everything. The whole point is that it can be handed to someone else.
 *
 * Which is also the risk: a report names your files, your table names and the
 * shape of your project. Recognised secrets are masked the same way as
 * everywhere else, and the ones redaction cannot recognise are the reason the
 * report carries a banner saying what it holds: "shareable" and "safe to post
 * publicly" are not the same thing.
 */

import type { Finding, ScanResult } from '../types.js'
import { locationOf, plural, skipPhrase, verdictOf } from './shared.js'

/** Escape text for safe interpolation into HTML */
function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
}

/** Turn plain paragraphs into HTML, preserving blank-line breaks */
function paragraphs(parts: string[]): string {
  return parts.map((p) => `<p>${esc(p.trim())}</p>`).join('')
}

/** Linkify bare URLs so rotation links are clickable */
function linkify(html: string): string {
  return html.replace(
    /https?:\/\/[^\s<>"')]+/g,
    (url) => `<a href="${url}" target="_blank" rel="noreferrer noopener">${url}</a>`,
  )
}

function renderFinding(f: Finding, index: number): string {
  const location = locationOf(f)
  const cls = f.confidence === 'certain' ? 'certain' : 'likely'

  const fixList =
    f.fix.length > 0
      ? `<h4>How to fix</h4><ol>${f.fix.map((s) => `<li>${linkify(esc(s))}</li>`).join('')}</ol>`
      : ''

  const humanList =
    f.humanOnly && f.humanOnly.length > 0
      ? `<div class="human"><h4>Only you can do this</h4><ul>${f.humanOnly
          .map((s) => `<li>${linkify(esc(s))}</li>`)
          .join('')}</ul></div>`
      : ''

  return `
<article class="finding ${cls}">
  <header>
    <span class="num">${index}</span>
    <h3>${esc(f.title)}</h3>
  </header>
  <div class="loc">${esc(location)}${f.confidence === 'likely' ? ' <span class="tag">lower confidence</span>' : ''}</div>
  ${f.excerpt ? `<pre><code>${esc(f.excerpt)}</code></pre>` : ''}
  <div class="why">${linkify(paragraphs(f.why))}</div>
  ${fixList}
  ${humanList}
</article>`
}

export interface HtmlOptions {
  root: string
  /** ISO timestamp for the report header */
  generatedAt: string
  /** How many lower-confidence findings the default report does not expand */
  hiddenLikely?: number
}

export function renderHtml(result: ScanResult, opts: HtmlOptions): string {
  const { findings } = result
  const hiddenLikely = opts.hiddenLikely ?? 0
  // Severity decides the verdict; confidence decides how sure it is. See the
  // note on Severity in types.ts for why those were once the same number.
  const { blocking: certain, minor, unsure } = verdictOf(findings)

  const verdict =
    findings.length === 0
      ? result.filesScanned === 0
        ? // Examined nothing, so there is nothing to report either way.
          `<div class="verdict warn">No files were scanned &mdash; nothing was checked</div>`
        : result.partial
          ? // Never the green banner on a partial scan: it reads as a guarantee,
            // and a scan that skipped files cannot make one.
            hiddenLikely > 0
              ? `<div class="verdict warn">No certain findings &mdash; ${hiddenLikely} lower-confidence ${plural(hiddenLikely, 'finding')} hidden, and not everything was checked</div>`
              : `<div class="verdict warn">No findings &mdash; but not everything was checked</div>`
          : hiddenLikely > 0
            ? `<div class="verdict warn">No certain findings &mdash; ${hiddenLikely} lower-confidence ${plural(hiddenLikely, 'finding')} hidden</div>`
            : `<div class="verdict clean">No exposed credentials found</div>`
      : certain > 0
        ? `<div class="verdict bad">${certain} critical ${plural(certain, 'issue')} &mdash; do not deploy</div>`
        : minor > 0
          ? `<div class="verdict warn">${minor} ${plural(minor, 'thing')} to fix &mdash; nothing exposed</div>`
          : `<div class="verdict warn">${unsure} possible ${plural(unsure, 'issue')} to review</div>`

  const body =
    findings.length === 0
      ? result.filesScanned === 0
        ? // The checklist below would be a false statement here: none of those
          // checks had any input to run against.
          `<div class="clean-note">
           <p>canship found no files it could read at this path, so none of its checks ran.
           <strong>This is not a clean result &mdash; it is an empty one.</strong></p>
           <p>Most likely this is not the directory you meant to scan, or everything in it is
           gitignored or build output that canship skips. If the project lives in a
           subdirectory, point canship at it: <code>npx canship ./app</code>.</p>
         </div>`
        : hiddenLikely > 0
          ? `<div class="clean-note">
             <p><strong>This is not a finding-free result.</strong> The default report hides
             ${hiddenLikely} lower-confidence ${plural(hiddenLikely, 'finding')}.</p>
             <p>Re-run with <code>--all --report</code> to include ${hiddenLikely === 1 ? 'it' : 'them'} in the report.</p>
           </div>`
          : `<div class="clean-note">
           <p>canship checked for hardcoded API keys, server secrets exposed to the browser,
            Supabase tables without Row Level Security, open Firebase rules, API routes that reach
            the database with no sign-in check, CORS that lets other sites use your visitors&rsquo;
           sessions, and <code>.env</code> files committed to git.</p>
           <p><strong>A clean result means those checks passed &mdash; not that your app is secure.</strong>
           Rate limiting and injection are not covered, and neither is whether the authorisation
           checks it did find are the right ones.</p>
         </div>`
      : findings.map((f, i) => renderFinding(f, i + 1)).join('\n')

  const optedOut =
    result.ignored.length > 0
      ? `<p class="opted-out">${result.ignored.length} ${plural(result.ignored.length, 'file')} excluded by <code>canship-ignore-file</code>: ${result.ignored.map((f) => `<code>${esc(f)}</code>`).join(', ')}</p>`
      : ''

  const hiddenNotice =
    hiddenLikely > 0 && findings.length > 0
      ? `<p class="opted-out">${hiddenLikely} lower-confidence ${plural(hiddenLikely, 'finding')} hidden. Re-run with <code>--all --report</code> to include ${hiddenLikely === 1 ? 'it' : 'them'}.</p>`
      : ''

  // Shown whether or not there were findings: "we did not look at these" is
  // information the reader needs in both cases.
  const incomplete = result.partial
    ? `<div class="incomplete">
         <h2>Not everything was checked</h2>
         <ul>
           ${
             // Reachable with findings present: a repository whose working
             // tree is entirely gitignored still has a git history, and the
             // history rule reads it. The findings are real; the file-based
             // checks simply never ran.
             result.filesScanned === 0
               ? `<li>no files could be read at this path, so every file-based check was skipped</li>`
               : ''
           }
           ${result.errors
             .map(
               (e) =>
                 `<li>the <code>${esc(e.ruleId)}</code> check ${
                   e.kind === 'incomplete' ? 'did not finish' : 'failed'
                 }${e.file ? ` on <code>${esc(e.file)}</code>` : ''} &mdash; ${esc(e.message)}</li>`,
             )
             .join('\n           ')}
           ${result.skipped
             .map((s) => `<li><code>${esc(s.path)}</code> &mdash; ${esc(skipPhrase(s.reason))}${s.detail ? ` (${esc(s.detail)})` : ''}</li>`)
             .join('\n           ')}
         </ul>
         <p>Anything could be in what was skipped. Re-run once it is readable.</p>
       </div>`
    : ''

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>canship report</title>
<style>
  :root {
    --bg: #ffffff; --fg: #1a1a1a; --muted: #666; --line: #e3e3e3;
    --card: #fafafa; --bad: #c0392b; --warn: #b8860b; --good: #1e7e34;
    --code-bg: #f4f4f4; --human-bg: #fff8e6; --human-line: #e6c35c;
  }
  @media (prefers-color-scheme: dark) {
    :root {
      --bg: #16181c; --fg: #e6e6e6; --muted: #9aa0a6; --line: #2c3036;
      --card: #1c1f24; --bad: #ff6b5e; --warn: #e8b339; --good: #4ade80;
      --code-bg: #22262c; --human-bg: #2a2418; --human-line: #6b5a2a;
    }
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 2rem 1rem 4rem; background: var(--bg); color: var(--fg);
    font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }
  main { max-width: 46rem; margin: 0 auto; }
  h1 { font-size: 1.4rem; margin: 0 0 .25rem; }
  .meta { color: var(--muted); font-size: .85rem; margin-bottom: 1.5rem; word-break: break-all; }
  .verdict { font-weight: 600; padding: .75rem 1rem; border-radius: 6px; margin-bottom: 1.5rem; }
  .verdict.bad { background: var(--bad); color: #fff; }
  .verdict.warn { background: var(--warn); color: #000; }
  .verdict.clean { background: var(--good); color: #fff; }
  .notice {
    border: 1px solid var(--line); border-left: 3px solid var(--muted);
    padding: .75rem 1rem; margin-bottom: 2rem; font-size: .85rem; color: var(--muted);
  }
  .finding {
    border: 1px solid var(--line); border-radius: 6px; background: var(--card);
    padding: 1.25rem; margin-bottom: 1.25rem;
  }
  .finding.certain { border-left: 3px solid var(--bad); }
  .finding.likely { border-left: 3px solid var(--warn); }
  .finding header { display: flex; gap: .6rem; align-items: baseline; }
  .num { color: var(--muted); font-variant-numeric: tabular-nums; font-size: .9rem; }
  .finding h3 { font-size: 1.05rem; margin: 0 0 .35rem; }
  .loc { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .82rem; color: var(--muted); margin-bottom: .75rem; word-break: break-all; }
  .tag { background: var(--warn); color: #000; padding: 0 .35rem; border-radius: 3px; font-size: .72rem; }
  pre {
    background: var(--code-bg); padding: .7rem .9rem; border-radius: 4px;
    overflow-x: auto; font-size: .82rem; margin: 0 0 .9rem;
  }
  code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
  .why p { margin: 0 0 .7rem; }
  h4 { font-size: .82rem; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); margin: 1.1rem 0 .4rem; }
  ol, ul { margin: 0; padding-left: 1.3rem; }
  li { margin-bottom: .45rem; }
  .human {
    background: var(--human-bg); border-left: 3px solid var(--human-line);
    padding: .1rem 1rem .8rem; margin-top: 1rem; border-radius: 0 4px 4px 0;
  }
  .human h4 { color: var(--fg); }
  .opted-out { color: var(--muted); font-size: .85rem; margin-top: 1.5rem; }
  .clean-note { border: 1px solid var(--line); border-radius: 6px; padding: 1.25rem; }
  .incomplete { border: 1px solid var(--warn); border-radius: 6px; padding: 1rem 1.25rem; margin-top: 1.5rem; }
  .incomplete h2 { font-size: 1rem; margin: 0 0 .5rem; }
  .incomplete ul { margin: 0 0 .75rem; padding-left: 1.25rem; }
  .incomplete li { margin-bottom: .25rem; }
  .incomplete p:last-child { margin-bottom: 0; }
  .clean-note p:last-child { margin-bottom: 0; }
  footer { margin-top: 2.5rem; padding-top: 1.25rem; border-top: 1px solid var(--line); color: var(--muted); font-size: .82rem; }
  a { color: inherit; }
</style>
</head>
<body>
<main>
  <h1>canship report</h1>
  <div class="meta">${esc(opts.root)}<br>${esc(opts.generatedAt)} &middot; ${result.filesScanned} ${plural(result.filesScanned, 'file')} scanned in ${result.durationMs}ms</div>
  ${verdict}
  <div class="notice">
    Credential values canship recognises are masked in this report. One in a format it has no
    pattern for can still appear inside a quoted line, and this report lists your
    file paths and project structure either way &mdash; so treat it as internal,
    shareable with your team rather than something to post publicly.
  </div>
  ${body}
  ${incomplete}
  ${hiddenNotice}
  ${optedOut}
  <footer>
    Generated by canship. Everything ran locally; nothing was uploaded.
  </footer>
</main>
</body>
</html>
`
}
