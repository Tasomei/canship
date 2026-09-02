/**
 * Reading a `.env` file the way the runtime does.
 *
 * Extracted because two rules need it and only one of them had it. The
 * exposure rule parsed values properly — quotes, escapes, trailing comments —
 * while the git-history rule kept its own three-line version that stopped at
 * `line.indexOf('=')` and stripped nothing but the outer quotes.
 *
 * That difference was not cosmetic. `MY_API_TOKEN=ghp_… # production` left the
 * comment glued to the value, `matchesKnownSecret` requires the whole value to
 * be the match, and so a committed .env holding a live token dropped from a
 * certain-grade P0 that exits 1 to a lower-confidence finding that is hidden by
 * default and exits 0. Annotating the variable that matters is the most
 * ordinary thing a person does in one of these files, and it turned the
 * scanner green.
 *
 * The fix belongs here rather than in either rule: the parsing was already
 * correct once, and a second copy is what let the two answers drift apart.
 */

/** One `KEY=value` assignment read out of a .env file */
export interface EnvAssignment {
  key: string
  value: string
}

/**
 * Read the value half of a `KEY=...` line the way dotenv does.
 *
 * The previous version only stripped matching quotes from the ends, which
 * meant a trailing comment stayed glued to the value:
 *
 *   NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_… # production
 *
 * The value became "sk_live_… # production", matched no known key format, and
 * the most dangerous line in the file was reported as nothing at all. Comments
 * on config lines are not an edge case; they are how people annotate exactly
 * the variables that matter.
 */
export function parseEnvValue(raw: string): string {
  const value = raw.trim()
  const quote = value[0]

  if (quote === '"' || quote === "'" || quote === '`') {
    // Read to the matching close quote. Anything after it is a comment or
    // stray text, and a `#` inside the quotes is part of the value.
    let out = ''
    for (let i = 1; i < value.length; i++) {
      const ch = value[i]!
      if (ch === '\\' && quote === '"' && i + 1 < value.length) {
        // Double quotes take escapes. Private keys in .env are usually one
        // long line with \n escapes, so this is the difference between
        // recognising a key and seeing gibberish.
        const next = value[++i]!
        out += next === 'n' ? '\n' : next === 'r' ? '\r' : next === 't' ? '\t' : next
        continue
      }
      if (ch === quote) break
      out += ch
    }
    return out
  }

  // Unquoted: the value ends at the first #, whitespace before it or not.
  //
  // This follows dotenv, whose unquoted branch stops at the first hash.
  // Requiring whitespace looked kinder to a password containing one, but it
  // disagreed
  // with the runtime — and it disagreed in the direction that hides things:
  // KEY=sk_live_...#production kept the comment glued on, matched no known
  // format, and went unreported. A # in an unquoted value is unreliable in
  // real dotenv too; the answer there is to quote it, which this respects.
  const comment = value.indexOf('#')
  return (comment === -1 ? value : value.slice(0, comment)).trim()
}

/**
 * Parse one line of a .env file.
 *
 * Returns null when the line is blank, a whole-line comment, or not an
 * assignment at all.
 *
 * The key shape is dotenv's own — `[\w.-]+` — and it has to be. A stricter
 * `[A-Za-z_][A-Za-z0-9_]*` reads like the shell-exportable identifier rule and
 * is wrong for a file dotenv loads: `my-api-token`, `app.api.token` and
 * `2FA_SECRET` are all real variables it will happily read, and all three were
 * silently dropped. In the git-history rule that meant a committed .env holding
 * a live GitHub token produced no finding at all, where the older
 * `indexOf('=')` parser it replaced had graded every one of them `proof`.
 */
export function parseEnvLine(raw: string): EnvAssignment | null {
  const line = raw.trim()
  if (!line || line.startsWith('#')) return null
  const m = /^(?:export\s+)?([\w.-]+)\s*=\s*(.*)$/.exec(line)
  if (!m) return null
  return { key: m[1]!, value: parseEnvValue(m[2] ?? '') }
}
