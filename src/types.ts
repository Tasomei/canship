/**
 * Core types for canship.
 *
 * See the README for the design principles. Confidence is a first-class part of
 * the type system on purpose: every rule is forced to state how sure it is,
 * because the cost of a false positive here is losing the user's trust for good.
 */

/**
 * How bad a finding is.
 * P0 — burns money or leaks the whole database. Must be fixed before shipping.
 * P1 — database or endpoints left open, leads to data exposure.
 * P2 — broken or abusable, but nothing catches fire.
 *
 * Severity and confidence answer different questions, and the reports used to
 * conflate them: the verdict counted certain findings and called every one of
 * them critical, so a P2 CORS pairing that browsers simply reject rendered as
 * "do not deploy". Severity decides whether shipping is a mistake; confidence
 * decides how sure canship is and whether the finding shows without --all.
 */
export type Severity = 'P0' | 'P1' | 'P2'

/** Severities that mean "do not ship this" rather than "fix this soon" */
export const BLOCKING: ReadonlySet<Severity> = new Set<Severity>(['P0', 'P1'])

/**
 * Confidence in a finding.
 * certain — backed by hard evidence (e.g. the JWT payload literally says
 *           service_role). Shown by default.
 * likely  — based on a heuristic and can be wrong. Hidden unless --all.
 */
export type Confidence = 'certain' | 'likely'

/** A single file being scanned. */
export interface ScanFile {
  /** Path relative to the project root, always with / separators (Windows too) */
  path: string
  /** Full file contents */
  content: string
  /** Contents split into lines; rules use this to resolve line numbers */
  lines: string[]
  /**
   * Whether secret-shaped strings are expected in this file — test fixtures,
   * examples, documentation.
   *
   * This lives on ScanFile rather than being decided inside each rule because
   * scattering the exemption across rules guarantees one of them forgets it.
   * That is exactly what happened the first time v0.1 was run against its own
   * repository: the fixtures flooded the report. Rules should respect this flag
   * unless they genuinely need to inspect test code.
   */
  isExampleContext: boolean
}

/** A single finding. Written for people who are not security engineers. */
export interface Finding {
  /** Rule id, e.g. 'exposure/supabase-service-role-in-client' */
  ruleId: string
  severity: Severity
  confidence: Confidence
  /**
   * One sentence saying what went wrong, in the second person.
   * Good: Your Supabase admin key is exposed to the browser
   * Bad:  Potential credential exposure detected
   */
  title: string
  /** Relative path, or null when the finding is not tied to a file (e.g. git history) */
  file: string | null
  /** 1-based line number, or null when it cannot be located */
  line: number | null
  /** The offending snippet. Must already be redacted. */
  excerpt: string | null
  /**
   * Why this matters — state the consequence, not the category.
   *
   * One paragraph per element. It is a list rather than a string with `\n\n`
   * in it because the output boundary strips every control character from what
   * a rule produces, newlines included, and it has to: `why` interpolates file
   * paths and file contents, and a path may legally contain a newline. A rule
   * that spelled its paragraph breaks as `\n\n` had them stripped along with
   * everything else — the README's own example output showed breaks the tool
   * could no longer produce — and simply exempting `\n` would have handed
   * anyone who can add a file to the repository the ability to forge report
   * lines. Keeping the breaks *between* elements puts them where only the rule
   * can place them, and leaves the boundary free to keep stripping everything.
   */
  why: string[]
  /** How to fix it — steps that can be followed as-is */
  fix: string[]
  /**
   * Steps only a person can carry out: rotating a credential, flipping a
   * dashboard setting, rewriting git history.
   *
   * Kept separate from `fix` because of how this output actually gets used.
   * People paste the report into a coding assistant and let it apply the
   * changes. An assistant can rename a variable; it cannot rotate your Stripe
   * key. If both kinds of step were in one list, the assistant would report
   * success and the user would believe the leak was closed while the key is
   * still live. `--fix-prompt` relies on this split.
   */
  humanOnly?: string[]
}

/** A rule that runs against a single file. */
export interface Rule {
  id: string
  severity: Severity
  /**
   * Whether this rule cares about the file at all. A cheap pre-filter, so we do
   * not run every regex against every file.
   */
  appliesTo(file: ScanFile): boolean
  /** Run the check. An empty array means nothing was found. */
  check(file: ScanFile, ctx: ScanContext): Finding[]
}

/**
 * A rule that is not tied to a single file (for example, one that reads git
 * history). Runs once per scan.
 */
export interface ProjectRule {
  id: string
  severity: Severity
  check(ctx: ScanContext): Finding[] | Promise<Finding[]>
}

/**
 * What asking git about this directory produced.
 *
 * Three states rather than a boolean, because two of them used to be the same
 * one. `unavailable` means the question could not be answered — git missing,
 * a repository git refuses to read, a permission problem. Treating that as
 * `not-a-repo` let the history rule skip itself in silence over a repository
 * whose history held a live credential.
 */
export type GitStatus = 'repo' | 'not-a-repo' | 'unavailable'

/** Context for one scan. */
export interface ScanContext {
  /** Absolute path to the project root */
  root: string
  /** Every file included in this scan */
  files: ScanFile[]
  /** Whether the project is a git repository, or whether git could say */
  git: GitStatus
  gitExecutable: string | null
  /**
   * How a rule says "I could not finish" without throwing away what it did find.
   *
   * Throwing is the right move when a rule cannot run at all — the engine
   * records it and the scan goes partial. But a rule that examined most of
   * something and hit a ceiling has real findings to hand back *and* an
   * incomplete answer to admit, and it could previously do only one or the
   * other. It chose to hand back findings, so the ceiling was silent: the
   * history check stopped at twenty revisions and still reported a complete
   * scan, which made "checks your git history" mean "checks the last twenty
   * versions" without ever saying so.
   */
  reportIncomplete(ruleId: string, message: string): void
}

/** Why a file that was found never got read */
export type SkipReason =
  /** Above the size cap */
  | 'too-large'
  /** Permission denied, a device error, or vanished mid-scan */
  | 'unreadable'
  /** A whole directory could not be listed, so its contents are unknown */
  | 'directory-unreadable'
  /** Scannable extension but binary content */
  | 'binary'
  /** A symbolic link, not followed, so the scan stays inside the project root */
  | 'symlink'
  /** A nested worktree or submodule, which git reports as one opaque entry */
  | 'nested-repository'

/** A file or directory that was found but not examined */
export interface SkippedFile {
  path: string
  reason: SkipReason
  /** Human-readable extra context, e.g. the file size */
  detail?: string
}

/** A rule that threw. The check it performs did not run. */
export interface ScanError {
  /** Rule id, or 'walker' for traversal failures */
  ruleId: string
  /** The file being checked, when it was a per-file rule */
  file: string | null
  message: string
  /**
   * What went wrong, so the report can use the right word.
   *
   * `crashed` is a rule that threw; `incomplete` is a rule that ran, returned
   * real findings, and reached a ceiling before it was done. Both make the scan
   * partial, and the reader needs the same warning from both — but calling a
   * revision limit a failure sends someone hunting a bug that is not there.
   */
  kind: 'crashed' | 'incomplete'
}

/**
 * Summary of a scan.
 *
 * `errors`, `skipped` and `partial` exist because of the worst failure mode a
 * security scanner has: printing "nothing found" when the answer is "nothing
 * was looked at". A rule that throws, a file too large to read, a directory
 * that returns EACCES — all of them used to end in silence, and the report was
 * indistinguishable from a genuinely clean one.
 */
export interface ScanResult {
  findings: Finding[]
  /** How many files were actually read, so the report can say what it covered */
  filesScanned: number
  /** Duration in milliseconds */
  durationMs: number
  /** Rules that crashed. Their checks did not run. */
  errors: ScanError[]
  /** Files and directories that were found but never examined */
  skipped: SkippedFile[]
  /**
   * Files excluded on purpose, by a canship-ignore-file marker the user wrote.
   * Not a failure — but still reported, because a file silently dropping out of
   * a security scan is the same problem in a friendlier costume.
   */
  ignored: string[]
  /**
   * How many listed paths were dropped for running through a dependency tree.
   *
   * Not a failure either, and not the user's decision — canship makes this one
   * on their behalf, on the grounds that a third-party test fixture's example
   * key is a false positive. That is a defensible call and still owes the
   * reader a sentence, so it is counted rather than passed over.
   */
  vendored: number
  /**
   * Whether anything stopped this from being a complete scan.
   * When true, a clean result means "nothing was found in what was checked",
   * which is a much weaker statement — and the report has to say so.
   */
  partial: boolean
}
