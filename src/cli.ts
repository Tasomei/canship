/**
 * canship CLI entry point.
 *
 * Exit codes, chosen so this drops straight into CI or a git hook:
 *   0 — nothing found, and the whole project was examined
 *   1 — a confirmed issue serious enough not to ship: severity decides this,
 *       not confidence. A P2 that browsers reject on your behalf is a bug
 *       worth fixing, not a reason to stop a deploy.
 *   2 — findings exist, but none is a certain P0/P1. Lower-confidence details
 *       may still be hidden unless --all is present.
 *   3 — the tool failed, or could not finish: a rule crashed, a file was
 *       unreadable, something was skipped, or there was nothing to scan at
 *       all. "Found nothing" and "checked nothing" must not share an exit
 *       code, or a broken scan passes CI looking exactly like a clean one.
 *       Scanning zero files is the sharpest case of that, and the easiest to
 *       hit: the headline command takes no argument, so the wrong working
 *       directory is the ordinary mistake. --best-effort opts out.
 */

import { resolve } from 'node:path'
import { existsSync, statSync, writeFileSync } from 'node:fs'
import { scan, cleanForOutput } from './engine.js'
import { renderReport } from './report/terminal.js'
import { renderFixPrompt } from './report/prompt.js'
import { renderHtml } from './report/html.js'
import { bold, cyan, dim, red } from './colors.js'
import { verdictOf } from './report/shared.js'

/**
 * Injected from package.json at build time, so the project holds one version
 * number rather than two that agree right up until a release.
 *
 * The fallback covers running from source with tsx, where nothing defines it.
 */
declare const __CANSHIP_VERSION__: string | undefined
const VERSION = typeof __CANSHIP_VERSION__ === 'string' ? __CANSHIP_VERSION__ : '0.0.0-dev'

interface Args {
  root: string
  showAll: boolean
  json: boolean
  fixPrompt: boolean
  /** Path to write the HTML report to, or null when not requested */
  report: string | null
  /** Treat an incomplete scan as acceptable and exit on the findings alone */
  bestEffort: boolean
  help: boolean
  version: boolean
}

/** One place to clean the user input inside an argument error, and exit as a tool error */
function argumentError(message: string): never {
  process.stderr.write(`canship: ${cleanForOutput(message)}\n`)
  process.exit(3)
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    root: process.cwd(),
    showAll: false,
    json: false,
    fixPrompt: false,
    report: null,
    bestEffort: false,
    help: false,
    version: false,
  }
  const positional: string[] = []

  for (const arg of argv) {
    // --report=path, or bare --report which defaults to canship-report.html
    if (arg === '--report') {
      args.report = 'canship-report.html'
      continue
    }
    if (arg.startsWith('--report=')) {
      const value = arg.slice('--report='.length)
      if (!value) {
        argumentError('--report= needs a file path')
      }
      args.report = value
      continue
    }

    switch (arg) {
      case '--all':
      case '-a':
        args.showAll = true
        break
      case '--json':
        args.json = true
        break
      case '--fix-prompt':
        args.fixPrompt = true
        break
      case '--best-effort':
        args.bestEffort = true
        break
      case '--help':
      case '-h':
        args.help = true
        break
      case '--version':
      case '-v':
        args.version = true
        break
      default:
        if (arg.startsWith('-')) {
          argumentError(`unknown option ${arg}`)
        }
        positional.push(arg)
    }
  }

  if (positional.length > 1) {
    argumentError(`expected at most one path, received ${positional.length}`)
  }
  if (positional[0]) args.root = resolve(positional[0])
  return args
}

const HELP = `
  ${bold('canship')} — static scanner for exposed credentials and open access rules in JS/TS apps

  ${bold('Usage')}
    npx canship [path]

  ${bold('Options')}
    -a, --all         Show likely findings
        --fix-prompt  Output instructions to paste into a coding assistant
        --report[=F]  Write a self-contained HTML report (default canship-report.html)
        --json        Output raw JSON (for CI or tooling)
        --best-effort Allow exit 0 for an incomplete scan with no findings;
                      findings still exit 1 or 2
    -h, --help        Show this help
    -v, --version     Show version

  ${bold('Exit codes')}
    0  no findings; scan complete, or partial accepted with --best-effort
    1  at least one certain P0/P1 finding
    2  findings exist, but no certain P0/P1 blocker
    3  invalid arguments, tool error, or incomplete scan without --best-effort

  ${dim('--json and --fix-prompt are alternative stdout modes; --report may be combined with either.')}

  ${dim('Scanned files stay local: no project-code execution, network requests, or uploads.')}
`

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2))

  if (args.help) {
    process.stdout.write(`${HELP}\n`)
    return process.exit(0)
  }
  if (args.version) {
    process.stdout.write(`${VERSION}\n`)
    return process.exit(0)
  }

  if (args.json && args.fixPrompt) {
    argumentError('--json and --fix-prompt are mutually exclusive')
  }

  if (!existsSync(args.root) || !statSync(args.root).isDirectory()) {
    process.stderr.write(`${red('canship:')} not a directory: ${cleanForOutput(args.root)}\n`)
    return process.exit(3)
  }

  const result = await scan(args.root)

  // Redacted once, here, because every renderer prints it. The scan itself is
  // still run against the real path — this is only what gets shown.
  const displayRoot = cleanForOutput(args.root)

  const shown = args.showAll ? result.findings : result.findings.filter((f) => f.confidence === 'certain')
  const hiddenLikely = args.showAll ? 0 : result.findings.filter((f) => f.confidence === 'likely').length

  if (args.fixPrompt) {
    const prompt = renderFixPrompt(shown, {
      partial: result.partial,
      filesScanned: result.filesScanned,
      hiddenLikely,
    })
    process.stdout.write(
      prompt === null ? 'Nothing to fix — no findings.\n' : `${prompt}\n`,
    )
  } else if (args.json) {
    process.stdout.write(
      `${JSON.stringify(
        {
          version: VERSION,
          root: displayRoot,
          filesScanned: result.filesScanned,
          durationMs: result.durationMs,
          // Machine consumers need the same distinction humans get: an empty
          // findings array from a partial scan is not a pass.
          partial: result.partial,
          errors: result.errors,
          skipped: result.skipped,
          ignored: result.ignored,
          vendored: result.vendored,
          // The default view hides the detail, never the fact. A machine reading this
          // must not see "no findings" while lower-confidence ones exist.
          hiddenLikely,
          findings: shown,
        },
        null,
        2,
      )}\n`,
    )
  } else {
    process.stdout.write(
      `${renderReport(
        { ...result, findings: shown },
        { root: displayRoot, showingLikely: args.showAll, hiddenLikely },
      )}\n`,
    )
  }

  // The HTML report is written in addition to whatever went to stdout, so
  // `--report` composes with the other output modes.
  if (args.report) {
    const target = resolve(args.report)
    try {
      writeFileSync(
        target,
        renderHtml(
          { ...result, findings: shown },
          { root: displayRoot, generatedAt: new Date().toISOString(), hiddenLikely },
        ),
        'utf8',
      )
      if (!args.json && !args.fixPrompt) {
        process.stdout.write(`  ${dim('Report written to')} ${cyan(cleanForOutput(target))}\n\n`)
      }
    } catch (err) {
      process.stderr.write(
        `${red('canship:')} could not write report to ${cleanForOutput(target)}\n${cleanForOutput(String(err))}\n`,
      )
      return process.exit(3)
    }
  }

  // Precedence, stated rather than left to the order of these lines: a finding
  // outranks an incomplete scan. Exit 3 means "I could not tell you", and
  // answering "your admin key is in the browser bundle" with that would be a
  // worse misstatement than the imprecision it fixes. Nothing is lost by it —
  // the report prints what went unchecked above the findings either way, and
  // --json carries `partial` next to them, so a machine that needs the
  // distinction has it. Only the single exit code cannot hold both, and the
  // more urgent one wins.
  // The same count the banner uses. Three separate re-derivations of "is this
  // blocking" meant the terminal could say "do not deploy" while the process
  // exited 2; this was the last of them, and the one with teeth.
  if (verdictOf(result.findings).blocking > 0) return process.exit(1)
  if (result.findings.length > 0) return process.exit(2)
  // Nothing was found. Whether that means "clean" depends on whether the scan
  // actually finished.
  if (result.partial && !args.bestEffort) return process.exit(3)
  return process.exit(0)
}

main().catch((err: unknown) => {
  process.stderr.write(`${red('canship: unexpected error')}\n${cleanForOutput(String(err))}\n`)
  process.exit(3)
})
