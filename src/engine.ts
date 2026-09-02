/**
 * Scan engine: schedules rules, deduplicates and sorts the results.
 */

import type { Finding, ScanContext, ScanError, ScanFile, ScanResult, SkippedFile } from './types.js'
import { FILE_RULES, PROJECT_RULES } from './rules/index.js'
import { collectFiles, detectGitRepo } from './walker.js'
import { resolveGitExecutable } from './git.js'
import { redactAll, truncate } from './redact.js'

const SEVERITY_ORDER: Record<Finding['severity'], number> = { P0: 0, P1: 1, P2: 2 }
const CONFIDENCE_ORDER: Record<Finding['confidence'], number> = { certain: 0, likely: 1 }

/**
 * The same underlying problem can be matched by several rules (a service_role
 * key sitting in .env and also referenced from source, say). Deduplicate so one
 * mistake is not reported three times.
 *
 * The excerpt is part of the key, and has to be. Rule + file + line alone is a
 * proxy for identity rather than identity itself, and it was wrong in the
 * direction that loses findings: two different OpenAI keys declared on one line
 * share a ruleId — `secrets/hardcoded/openai` — so the second was dropped
 * silently, with nothing in `errors` and no effect on `partial`. Two live
 * credentials, two rotations needed, one of them never named. The existing
 * multi-secret fixture happened to use two *different* providers, whose rule
 * ids differ, so it walked straight past this.
 *
 * Rules that redact per match give those two findings different excerpts, which
 * is exactly the distinction wanted here. A rule reporting the same line twice
 * for genuinely the same reason still produces one entry, because its excerpt
 * is then the same string.
 *
 * The title is in the key for the same reason and because the excerpt cannot
 * carry the distinction alone: a rule may have no excerpt to give. The RLS rule
 * sets `excerpt: null` on every finding, so two tables declared on one line of
 * SQL — which a generated or minified migration does — collapsed to the same
 * key and the second table went unreported, silently, with `errors` empty and
 * `partial` still false.
 */
function dedupe(findings: Finding[]): Finding[] {
  const seen = new Set<string>()
  const out: Finding[] = []
  for (const f of findings) {
    const key = `${f.ruleId}|${f.file ?? ''}|${f.line ?? ''}|${f.excerpt ?? ''}|${f.title}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(f)
  }
  return out
}

/**
 * Terminal escape sequences and other control characters.
 *
 * A path is attacker-influenced in exactly the way a file's contents are:
 * anyone who can add a file to a repository chooses its name. A name carrying
 * ANSI escapes can repaint the report around it, and one carrying a credential
 * puts that credential into every output.
 */
const CONTROL_CHARS = /[\u0000-\u001f\u007f-\u009f]/g

/**
 * Bidirectional and invisible formatting characters.
 *
 * These are not noise, they are a technique. A right-to-left override in a
 * comment reorders everything after it *at display time only*, so a line can
 * read as one thing in canship's report and mean another to the compiler —
 * the Trojan Source attack. Stripping them the way the control characters
 * above are stripped would defeat the deception and destroy the evidence at
 * the same time: the reader would be shown a clean-looking line, no longer
 * matching the file, with nothing to say why it had been touched.
 *
 * So they are made visible instead. `<U+202E>` cannot reorder anything, it
 * survives being pasted back into an editor, and it tells a reader the thing
 * they most need to know about that line — that someone put an invisible
 * character in it on purpose.
 *
 * ZWNJ and ZWJ (U+200C, U+200D) are deliberately absent: they carry real
 * meaning in Persian, in several Indic scripts and in every emoji sequence,
 * so marking them would fire constantly on ordinary text.
 */
const DECEPTIVE_CHARS = /[\u061c\u200b\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g

/** U+202E arrives as one character and leaves as the eight that name it */
function nameOf(ch: string): string {
  return `<U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}>`
}

/**
 * The output boundary.
 *
 * canship promises it never prints a complete secret, and that promise is only
 * as good as the last rule that remembered to keep it. Enforcing it here means
 * a rule cannot leak a credential by forgetting to redact one, or by redacting
 * the wrong one of the two on a line. Every renderer reads what this produces.
 *
 * Which strings reach a reader is a list, and it has been wrong twice: once
 * for the excerpt, once for the path. Being a list, it will be wrong again —
 * the only real defence is that it lives in one place.
 */
function clean(text: string): string {
  return redactAll(text)
    // A tab is a control character and was being deleted with the rest of them,
    // which closed up the gap it was holding: an indented `return\ttrue` became
    // `returntrue`, so an excerpt could show code that does not exist. Turned
    // into a space rather than kept, because a real tab still lets a crafted
    // line push text around in a terminal.
    .replace(/\t/g, ' ')
    .replace(CONTROL_CHARS, '')
    .replace(DECEPTIVE_CHARS, nameOf)
}

/**
 * The same boundary, for text the CLI adds after the scan.
 *
 * Exported for exactly one caller and one reason: the scanned path itself.
 * Every field of a Finding goes through `clean`, but the root is attached by
 * the CLI afterwards and reached the JSON, the terminal header and the HTML
 * report untouched — so a project in a directory named after a credential
 * printed that credential in full, three times over, under a README promising
 * everything is redacted. A directory name is attacker-influenced in exactly
 * the way the note above describes, and it is also the one string a user can
 * put a secret in entirely by accident.
 */
export function cleanForOutput(text: string): string {
  return clean(text)
}

function sanitize(findings: Finding[]): Finding[] {
  return findings.map((f) => ({
    ...f,
    title: clean(f.title),
    // Per paragraph, so the breaks between them survive a cleaner that removes
    // every newline inside them. See Finding.why.
    why: f.why.map(clean),
    // The path was left out of this list once, and a filename holding a
    // credential put it straight back into the JSON, the terminal, the HTML
    // and the prompt meant for pasting into an assistant.
    file: f.file === null ? null : clean(f.file),
    // Redacted first, cut second, and both of them here.
    //
    // A rule that trimmed its own excerpt to length before this ran could
    // defeat the redaction entirely: cutting at 120 characters through the
    // middle of a key leaves a fragment that matches no pattern, so `clean`
    // waved it past and nineteen characters of a live OpenAI key reached the
    // terminal, the JSON, the HTML report and the prompt meant for pasting
    // into an assistant. The rule was not doing anything unreasonable — it
    // truncated, which every other rule also does. The order was simply not
    // its decision to make.
    //
    // So rules hand over the whole line and the boundary does both jobs, in
    // the only order that is safe. Rules that redact per match still may:
    // masking a known secret before this point is additive, and truncating an
    // already-truncated string is a no-op.
    excerpt: f.excerpt === null ? null : truncate(clean(f.excerpt)),
    fix: f.fix.map(clean),
    ...(f.humanOnly ? { humanOnly: f.humanOnly.map(clean) } : {}),
  }))
}

/**
 * Every piece of variable text in a skip record goes through the same boundary.
 *
 * A system error message usually repeats the full path, so cleaning `path`
 * alone still let a credential in a filename reach the JSON and the HTML
 * through `detail`.
 */
export function sanitizeSkippedForOutput(items: SkippedFile[]): SkippedFile[] {
  return items.map((item) => ({
    ...item,
    path: clean(item.path),
    ...(item.detail === undefined ? {} : { detail: clean(item.detail) }),
  }))
}

/**
 * Findings from test fixtures, examples and documentation are held at lower
 * confidence — never dropped.
 *
 * Enforced here because leaving it to each rule produced two incompatible
 * policies at once: secrets and gitleak downgraded, while exposure, cors,
 * firebase, supabase and apiauth refused to look at all. The same
 * unauthenticated service_role route was reported under `app/` and completely
 * absent under `examples/demo/` — no finding, no `skipped` entry, nothing in
 * `partial`, on a directory layout that ships a deployable demo in half the
 * repositories that have one.
 *
 * gitleak's own header already recorded this lesson, having watched `e2e/.env`
 * vanish from a report, but the conclusion stayed inside that one rule. A
 * policy every rule has to remember is a policy some rule will forget, so the
 * engine applies it once and rules no longer get the choice.
 *
 * Downgraded rather than shown in full because the flood is real: v0.1 pointed
 * canship at its own repository and drowned in its own fixtures. `likely` is
 * hidden without --all, so the default report stays quiet while the finding
 * still exists for anyone who looks.
 */
function downgradeExampleContext(findings: Finding[], files: ScanFile[]): Finding[] {
  const examples = new Set(files.filter((f) => f.isExampleContext).map((f) => f.path))
  return findings.map((f) =>
    f.file !== null && examples.has(f.file) ? { ...f, confidence: 'likely' as const } : f,
  )
}

/** Most severe and most certain first — people often read only the first few */
function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const bySeverity = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    if (bySeverity !== 0) return bySeverity
    const byConfidence = CONFIDENCE_ORDER[a.confidence] - CONFIDENCE_ORDER[b.confidence]
    if (byConfidence !== 0) return byConfidence
    return (a.file ?? '').localeCompare(b.file ?? '') || (a.line ?? 0) - (b.line ?? 0)
  })
}

/**
 * Run a full scan and return **all** findings, including likely ones.
 * Deciding what to display is the caller's job — we scan once and never repeat
 * the work just to produce a count.
 */
export async function scan(root: string): Promise<ScanResult> {
  const started = Date.now()

  const gitExecutable = resolveGitExecutable(root)
  const git = detectGitRepo(root, gitExecutable)
  const { files, skipped, ignored, vendored } = collectFiles(root, git === 'repo', gitExecutable)

  const findings: Finding[] = []
  const errors: ScanError[] = []
  /** ruleId + message pairs already recorded, so a ceiling is reported once */
  const incompleteSeen = new Set<string>()

  // A rule reporting a ceiling it hit lands in the same list as a rule that
  // crashed, because the consequence for the reader is identical: part of this
  // scan did not happen, so "found nothing" is not "there is nothing".
  const ctx: ScanContext = {
    root,
    files,
    git,
    gitExecutable,
    // Deduplicated here rather than by each rule remembering to report once.
    // A rule that reaches the same ceiling from two loops over the same file —
    // firebase does, once for open rules and once for test-mode rules — said
    // the identical sentence twice, in the terminal's incomplete section and in
    // the JSON. Saying "part of this did not happen" twice does not make it
    // twice as true, and a once-flag per rule is the kind of bookkeeping every
    // new rule would have to remember.
    reportIncomplete: (ruleId, message) => {
      if (incompleteSeen.has(`${ruleId} ${message}`)) return
      incompleteSeen.add(`${ruleId} ${message}`)
      errors.push({ ruleId, file: null, message, kind: 'incomplete' })
    },
  }

  // Per-file rules
  for (const file of files) {
    for (const rule of FILE_RULES) {
      if (!rule.appliesTo(file)) continue
      try {
        findings.push(...rule.check(file, ctx))
      } catch (err) {
        // One broken rule must not fail the whole scan — the rest of the
        // results are still worth showing. But the check did not run, and
        // saying nothing about that is how a scanner reports "clean" for a
        // repository it never finished examining.
        errors.push({ ruleId: rule.id, file: file.path, message: messageOf(err), kind: 'crashed' })
      }
    }
  }

  // Project-wide rules
  for (const rule of PROJECT_RULES) {
    try {
      findings.push(...(await rule.check(ctx)))
    } catch (err) {
      errors.push({ ruleId: rule.id, file: null, message: messageOf(err), kind: 'crashed' })
    }
  }

  return {
    findings: sanitize(sortFindings(dedupe(downgradeExampleContext(findings, files)))),
    filesScanned: files.length,
    durationMs: Date.now() - started,
    errors: errors.map((e) => ({
      ...e,
      file: e.file === null ? null : clean(e.file),
      message: clean(e.message),
    })),
    skipped: sanitizeSkippedForOutput(skipped),
    ignored: ignored.map(clean),
    vendored,
    // A deliberate opt-out is not an incomplete scan: the user made that call
    // knowingly. It is listed in the report, not treated as a failure.
    //
    // Examining no files at all, however, is the purest form of an incomplete
    // scan, and it used to print a green tick and exit 0 — the exact outcome
    // the README says must never share an exit code with "clean". It is also
    // the most likely way to be wrong in practice: the headline command is
    // `npx canship` with no argument, so running it from the wrong directory
    // is the ordinary user error, and a directory holding nothing but a
    // build/ folder (every entry of which the walker skips by design) reaches
    // zero without looking empty to a human.
    partial: errors.length > 0 || skipped.length > 0 || files.length === 0,
  }
}

/** Readable one-liner from whatever a rule decided to throw */
function messageOf(err: unknown): string {
  if (err instanceof Error) return err.message
  return String(err)
}
