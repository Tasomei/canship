/**
 * Secret redaction.
 *
 * The rule canship works to: **mask every secret it can recognise, everywhere.**
 *
 * Phrased that way on purpose. The obvious wording — "canship never prints a
 * complete secret" — is a promise this cannot keep, and a security tool that
 * overstates its own guarantee is worse than one that is plain about the edge.
 * Redaction is pattern-based, so a value in a format there is no pattern for —
 * a database password, an internally issued token, a key from a provider not
 * on the list — is not masked, and if a rule quotes the line it sits on for
 * some unrelated reason, it is printed in full. The README says so under
 * "Where it gets things wrong". A canship report is sensitive, not sanitised.
 *
 * Within that limit the guarantee is worth having, and the reason is practical.
 * When someone discovers they have leaked a key, the first thing they do is
 * screenshot the output and paste it into a group chat or a forum asking what
 * it means. If canship's output held the full key, we would be the second leak.
 *
 * It could not be kept rule by rule. It was, once, and it failed exactly the
 * way per-rule invariants always fail: `redactLine` masks the one secret its
 * caller happened to match, so a line holding an OpenAI key *and* a GitHub
 * token produced a finding with the OpenAI key masked and the GitHub token
 * printed in full — in the terminal, the JSON, the HTML report, and the prompt
 * meant for pasting into an assistant.
 *
 * So redaction is enforced at the output boundary instead: `redactAll` runs the
 * whole pattern set over the text, and the engine runs it over every finding
 * before anything is rendered. A rule cannot forget to call it, because rules
 * no longer decide.
 */

import { JWT_SOURCE, SECRET_PATTERNS } from './rules/patterns.js'

/** How many leading/trailing characters survive redaction */
const KEEP_HEAD = 6
const KEEP_TAIL = 2

/**
 * Mask a secret, keeping just enough at each end for the user to recognise
 * which one it is.
 * e.g. sk-proj-abc123...xyz789  ->  sk-pro…(41 chars)…89
 */
export function redactSecret(secret: string): string {
  if (secret.length <= KEEP_HEAD + KEEP_TAIL + 4) {
    // Too short — mask it entirely, otherwise "redacting" would leave the
    // original value intact.
    return '•'.repeat(Math.max(secret.length, 8))
  }
  const head = secret.slice(0, KEEP_HEAD)
  const tail = secret.slice(-KEEP_TAIL)
  return `${head}…(${secret.length} chars)…${tail}`
}

/**
 * Redact a whole line of code: replace the matched secret with its masked form
 * while keeping the rest, so the user can still see which variable is at fault.
 *
 * @param line   the original full line
 * @param secret the substring within it that was identified as a secret
 */
export function redactLine(line: string, secret: string): string {
  const trimmed = line.trim()
  if (!secret) return truncate(trimmed)
  return truncate(trimmed.split(secret).join(redactSecret(secret)))
}

/**
 * Anything shaped like a JSON Web Token.
 *
 * Masked wholesale rather than decoded, because the boundary's job is to be
 * unconditional. A Supabase service_role key is a JWT, and whether a given one
 * is the admin key or the public anon key takes a base64 decode that the
 * detection rules do — not this. Masking an anon key that was already safe to
 * print costs a reader nothing; missing the other kind costs them the database.
 */
const JWT_SHAPED = new RegExp(String.raw`\b${JWT_SOURCE}\b`, 'g')

/**
 * Mask every recognisable credential anywhere in a piece of text.
 *
 * Unlike `redactLine`, this does not need to be told what the secret is: it
 * runs the whole detection pattern set over the text and masks each hit. That
 * is what makes it safe to apply at the output boundary, where the caller has
 * no idea what a string might contain.
 *
 * A value that has already been masked stays masked — the placeholder form
 * matches no pattern, so a second pass is a no-op.
 */
export function redactAll(text: string): string {
  let out = text
  for (const pat of SECRET_PATTERNS) {
    // A fresh RegExp each time: the shared ones carry lastIndex state.
    const re = new RegExp(pat.pattern.source, pat.pattern.flags)
    out = out.replace(re, (match) => redactSecret(match))
  }
  return out.replace(new RegExp(JWT_SHAPED.source, JWT_SHAPED.flags), (m) => redactSecret(m))
}

/**
 * Cut off very long lines so the terminal output does not blow up.
 *
 * Exported because the number and the ellipsis were being re-derived: apiauth
 * wrote the same `length <= 120 ? … : slice(0, 120) + '…'` by hand, and
 * exposure wrote `slice(0, 120)` with no ellipsis at all — an excerpt that had
 * been cut giving the reader no sign of it.
 */
export function truncate(s: string, max = 120): string {
  return s.length <= max ? s : `${s.slice(0, max)}…`
}
