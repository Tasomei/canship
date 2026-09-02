/**
 * Secret pattern table.
 *
 * Inclusion criteria: **only formats that are unambiguous.**
 * Things like the AWS secret access key ("40 characters of base64") are
 * deliberately left out — they are indistinguishable from an ordinary hash, so
 * including them would only manufacture false positives, and a false positive
 * destroys the user's trust in the tool (see the design principles in README).
 */

export interface SecretPattern {
  /** Suffix used in the rule id */
  id: string
  /** Human-readable name, shown directly in the report */
  name: string
  /** Match pattern; must carry the g flag */
  pattern: RegExp
  /** What an attacker can actually do with this — the consequence, not the category */
  impact: string
  /** Where to rotate this credential */
  rotateAt?: string
  /**
   * How to refer to this credential in a rotation instruction, when `name`
   * does not read well in that sentence. "Rotate this Database connection
   * string with password" is not a sentence anyone wants to read.
   */
  rotateLabel?: string
  /**
   * Which capture group holds the actual secret, for placeholder checking.
   *
   * Why this exists: a database connection string match also contains the host,
   * port and database name. Checking the whole match for placeholders means
   * `postgres://u:realpw@db.example.com/prod` gets dismissed as a template just
   * because the host contains "example" — a real miss. Pointing at the password
   * group narrows the check to the password itself.
   * Defaults to the whole match when unset.
   */
  secretGroup?: number
  /**
   * Extra exclusion check; returning true means the match is not worth
   * reporting. Used for values that are correctly formatted but point at
   * something meaningless, such as a connection string for localhost.
   */
  ignoreIf?: (match: RegExpExecArray) => boolean
  /**
   * This value is meant to travel to the browser, by the issuing provider's
   * own design — not a mistake canship should flag as a leak.
   *
   * Google's own documentation says a Firebase apiKey "identifies your
   * project on the Google servers" rather than authorising access to it, and
   * is safe to include in client code; the Maps Platform docs say the same
   * key type "will always be visible in your page source" and call that
   * expected. Either way, the protection is application/API restrictions
   * configured in the Google Cloud console — a setting canship cannot see
   * from a repository — not secrecy. Treating it like a Stripe or OpenAI key
   * ("rotate immediately, do not ship") is the wrong instruction and blocks a
   * deploy that was never actually broken.
   */
  publicByDesign?: boolean
}

/**
 * RFC-reserved example domains and local addresses.
 * Credentials pointing at these are worthless to an attacker: they are either
 * documentation samples or local development config. Reporting them is noise.
 */
const IRRELEVANT_HOSTS =
  /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal|.*\.?example\.(?:com|org|net)|.*\.(?:test|invalid|localhost))$/i

/**
 * The two credential shapes that more than one file has to recognise.
 *
 * Kept as source strings, in the one module both the detection rules and the
 * redaction boundary already import, because the copies had drifted: the JWT
 * shape was written three times with two different segment minimums (8 in
 * redact.ts and apiauth.ts, 10 in exposure.ts), and `sb_secret_` twice with
 * 8 against 16. Detection and redaction walking different patterns is how a
 * format canship can find becomes a format canship cannot mask.
 *
 * Eight is the shared minimum, taken from the looser of each pair on purpose:
 * for redaction, covering more is the safe direction, and for detection the
 * prefixes settle it — nothing that starts `eyJ` and has three base64url
 * segments, or that starts `sb_secret_`, is anything else.
 */
export const JWT_SOURCE = String.raw`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`

/** Supabase's newer server-side key. The prefix alone settles what it is. */
export const SB_SECRET_SOURCE = String.raw`sb_secret_[A-Za-z0-9_-]{8,}`

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'openai',
    name: 'OpenAI API key',
    pattern: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    impact: 'Anyone with this key can spend your OpenAI credit. Leaked keys are typically abused within minutes of going public.',
    rotateAt: 'https://platform.openai.com/api-keys',
  },
  {
    id: 'anthropic',
    name: 'Anthropic API key',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    impact: 'Anyone with this key can spend your Anthropic credit.',
    rotateAt: 'https://console.anthropic.com/settings/keys',
  },
  {
    id: 'aws-access-key-id',
    name: 'AWS access key ID',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    impact: 'Combined with its secret, this grants access to your AWS account — S3 buckets, databases, and compute you pay for.',
    rotateAt: 'https://console.aws.amazon.com/iam/home#/security_credentials',
  },
  {
    id: 'stripe-live',
    name: 'Stripe live secret key',
    pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g,
    impact: 'This is a LIVE key. Anyone holding it can read your customer records and move real money.',
    rotateAt: 'https://dashboard.stripe.com/apikeys',
  },
  {
    id: 'github-token',
    name: 'GitHub token',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
    impact: 'Grants access to your repositories — including private ones, and the ability to push code.',
    rotateAt: 'https://github.com/settings/tokens',
  },
  {
    id: 'google-api-key',
    name: 'Google API key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    impact: 'Depending on its scope, this can be used to run up billed usage on Google Cloud services.',
    rotateAt: 'https://console.cloud.google.com/apis/credentials',
    // Unlike every other pattern in this table, an AIza-format key is not a
    // bearer credential: it identifies a Firebase project or a Maps Platform
    // caller, and Google's own docs say it belongs in client code. Flagging
    // it as "exposed to the browser — rotate this" was a false positive on
    // every ordinary Firebase or Maps front-end, and the actual protection
    // (application/API restrictions in the Cloud console) is not something a
    // static scan of the repository can confirm one way or the other.
    publicByDesign: true,
  },
  {
    id: 'slack-token',
    name: 'Slack token',
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    impact: 'Grants access to your Slack workspace — reading messages and posting as you or your bot.',
    rotateAt: 'https://api.slack.com/apps',
  },
  {
    id: 'sendgrid',
    name: 'SendGrid API key',
    pattern: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{22,}\b/g,
    impact: 'Anyone with this key can send email from your domain — which means they can send phishing email that passes your SPF/DKIM checks.',
    rotateAt: 'https://app.sendgrid.com/settings/api_keys',
  },
  {
    id: 'supabase-secret-key',
    name: 'Supabase secret key',
    rotateLabel: 'Supabase secret key',
    // Supabase's newer key format. The prefix settles it: sb_secret_ is the
    // server-side half, sb_publishable_ is the one meant for browsers, and the
    // two are never confusable.
    //
    // framework.ts has recognised this format since the day it was written —
    // but only for deciding whether a *client-exposed* value is the admin key.
    // It was never in this table, and this table is what the hardcoded-secret
    // rule and the output-boundary redaction both walk. So a project with one
    // of these in its source got a clean report, and a project with one beside
    // another credential had it printed in full: the redaction pass could not
    // mask a format it did not know.
    pattern: new RegExp(String.raw`\b${SB_SECRET_SOURCE}\b`, 'g'),
    impact:
      'This is the server-side Supabase key. It bypasses every Row Level Security policy — it is effectively your database root password.',
    rotateAt: 'your Supabase dashboard, Project Settings -> API Keys',
  },
  {
    id: 'private-key',
    name: 'Private key file contents',
    rotateLabel: 'private key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    impact: 'A private key in source code can be used to impersonate your server, decrypt traffic, or log into your machines.',
  },
  {
    id: 'db-connection-string',
    name: 'Database connection string with password',
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/'"`]+:([^\s@/'"`]+)@(\[[^\]\s]+\]|[^\s'"`/:]+)(?::\d+)?(?:[/?#][^\s'"`]*)?/g,
    // Check only the password group for placeholders, so an "example" or "test"
    // in the host does not cause a miss.
    secretGroup: 1,
    // But if the host itself is an example domain or a local address, the
    // connection string is worthless and not worth reporting.
    //
    // The host alternative takes a bracketed form first so IPv6 survives:
    // `[^\s'"/:]+` stops at the first colon, so `@[::1]:5432` captured a lone
    // `[`, which matches no entry below — an IPv6 loopback string was reported
    // P0 while the identical `localhost` one was correctly ignored.
    //
    // The backtick is excluded for the same reason. It is the third string
    // delimiter in JavaScript and the only one this pattern had never heard of,
    // so a connection string written in a template literal handed the host
    // group a trailing backtick and defeated the check below. canship found
    // that one on its own source, in the comment above.
    ignoreIf: (m) => IRRELEVANT_HOSTS.test(m[2] ?? ''),
    rotateLabel: 'database password',
    impact: 'This contains your database username AND password. Anyone with it can read, modify, or delete your entire database.',
  },
]

/**
 * Extract the part of a match that should be placeholder-checked.
 */
export function secretPartOf(match: RegExpExecArray, pat: SecretPattern): string {
  if (pat.secretGroup === undefined) return match[0]
  return match[pat.secretGroup] ?? match[0]
}

/** Excluded by shape only when the whole value is a template marker */
const PLACEHOLDER_SHAPE = /^(?:<[^>\r\n]*>|\[[^\]\r\n]*\]|\.\.\.|\*{4,})$/

/**
 * The longer placeholder words have to hold a whole segment too.
 * A bare `includes` reads an ordinary collision in a random body — `AbcDef`,
 * `sample` — as a template.
 */
const LONG_PLACEHOLDER_SEGMENT =
  /(?:^|[-_.])(?:youre|example|placeholder|changeme|change-me|change_me|replace|insert|paste|dummy|sample|test-key|testkey|fixme|abcdef|123456|foobar|redacted|hidden)(?:[-_.]|$)/i

/**
 * `my-key`, `my_secret` — scaffolding, but too short to match loose.
 *
 * Anchored rather than listed above for the same reason the run-length went to
 * four: `my-` is three characters, and the two formats that permit `-` and `_`
 * inside the key body (OpenAI's and Google's) would hit it by chance. Requiring
 * a separator on both sides keeps the intent and removes the coincidence.
 */
const MY_PREFIX = /(?:^|[-_.])my[-_.]/i

/**
 * A four-character placeholder word has to hold a whole segment; a leading
 * boundary alone is not enough.
 *
 * `sk-your-key-here` still matches; a real key whose random body opens with
 * `yourAbc` does not.
 * x/y/z accept only a full repeated segment of four or more, so an ordinary
 * random body is not cut short.
 */
const SHORT_PLACEHOLDER =
  /(?:^|[-_.])(?:x{4,}|y{4,}|z{4,}|your|here|goes|todo|fake)(?:[-_.]|$)/i

/**
 * Words that count towards a value naming itself scaffolding *twice*.
 *
 * Every rule above needs a separator to anchor to, and the run-on placeholder
 * has none: `sk-proj-yourkeyhere000000` and `sk-proj-TODOreplaceThisBeforeDeploy`
 * are obviously templates to a reader and matched nothing, so both were
 * reported as live keys at P0 `certain`. Loosening the anchors to reach them is
 * not available — a real key whose random body opens `yourAbc…` has exactly the
 * same shape, and dismissing that is the expensive direction.
 *
 * Two *distinct* words is what tells them apart. Someone writing a template
 * reaches for several of these in one breath; a random body colliding with even
 * one is about a one-in-thirty-thousand event, and with two it stops being
 * worth counting. Measured over 300,000 keys per format, adding this moved the
 * false-negative rate by 0.002 percentage points and cut the templates reported
 * as live keys from three in ten to one.
 *
 * `abcdef` and `123456` are deliberately absent. They are sequences rather than
 * words, they turn up in templates on their own, and an alphabet walk inside an
 * otherwise ordinary value would hand this rule a second "word" for free.
 */
const COUNTED_PLACEHOLDER_WORDS =
  /youre|example|placeholder|changeme|replace|insert|paste|dummy|sample|testkey|fixme|foobar|redacted|hidden|your|here|goes|todo|fake/gi

function namesItselfTwice(secret: string): boolean {
  // Shared /g pattern: reset before use, and again on every exit, since exec
  // advances lastIndex and no later caller can know this one ran.
  COUNTED_PLACEHOLDER_WORDS.lastIndex = 0
  const seen = new Set<string>()
  let match: RegExpExecArray | null
  while ((match = COUNTED_PLACEHOLDER_WORDS.exec(secret)) !== null) {
    seen.add(match[0].toLowerCase())
    if (seen.size >= 2) break
  }
  COUNTED_PLACEHOLDER_WORDS.lastIndex = 0
  return seen.size >= 2
}

/**
 * A scaffolding word standing on its own inside a value.
 *
 * `xoxb-test-token-…` is a fixture, and the prefix rule below cannot see it —
 * the value starts with a real provider prefix, and the giveaway is in the
 * middle. Matching whole hyphen- or underscore-delimited segments keeps that
 * from becoming a blanket substring search, which would suppress any real key
 * unlucky enough to contain the letters.
 */
const DUMMY_SEGMENT = /(?:^|[-_.])(?:test|dummy|fake|sample|placeholder|example|demo|mock|stub)(?:[-_.]|$)/i

/**
 * Values that announce themselves as scaffolding by how they start:
 * test_token, dummy-key, fake_secret, demo-api-key.
 *
 * The separator is what makes this safe. A credential does not begin with
 * "test_" — but plenty of them contain "test" somewhere in the middle, so a
 * bare substring check here would suppress real findings.
 */
const DUMMY_PREFIX = /^(?:test|dummy|fake|sample|placeholder|example|demo|mock|stub|dev|local)[-_]/i

/** Whether a matched string is in fact just a placeholder */
export function isPlaceholder(secret: string): boolean {
  const lower = secret.toLowerCase()
  if (DUMMY_PREFIX.test(secret)) return true
  if (DUMMY_SEGMENT.test(secret)) return true
  if (MY_PREFIX.test(secret)) return true
  if (SHORT_PLACEHOLDER.test(secret)) return true
  if (LONG_PLACEHOLDER_SEGMENT.test(secret)) return true
  if (namesItselfTwice(secret)) return true
  if (PLACEHOLDER_SHAPE.test(secret)) return true

  // After stripping a known prefix, too few distinct characters in the body
  // (as in sk-aaaaaaaaaa) means it is a placeholder.
  const body = lower.replace(/^(sk-ant-|sk-proj-|sk-|rk_live_|sk_live_|akia|aiza|sg\.|gh[pousr]_)/, '')
  if (body.length >= 8) {
    const distinct = new Set(body.replace(/[^a-z0-9]/g, '')).size
    if (distinct <= 3) return true
  }
  return false
}

/**
 * Which credential format a value *is*, or null.
 *
 * The whole value has to be the match: `sk_live_…` qualifies, a sentence that
 * happens to contain one does not. Used where the question is "does this hold
 * a secret" rather than "where is the secret in this text".
 *
 * Returning the pattern rather than a boolean is what lets this be the only
 * copy. exposure.ts kept its own `matchKnownSecret` for the sole reason that it
 * needed the name and the rotation link, and copied the loop to get them —
 * along with a `KnownSecret` interface that was a strict subset of
 * SecretPattern. Two identical judgements, both feeding P0 rules, either of
 * which could be tightened without the other.
 */
export function findKnownSecret(value: string): SecretPattern | null {
  const trimmed = value.trim()
  for (const pat of SECRET_PATTERNS) {
    pat.pattern.lastIndex = 0
    const m = pat.pattern.exec(trimmed)
    // exec advanced lastIndex; later callers of this shared pattern cannot know
    // that happened, so put it back before returning either way.
    pat.pattern.lastIndex = 0
    if (m === null || m[0] !== trimmed) continue
    // `ignoreIf` was missing here while the walker's own copy of this judgement
    // applied it, so two readings of the same question disagreed:
    // `DATABASE_URL=postgres://user:pass@localhost` came back as a recognised
    // credential, which made it P0 `certain` through exposure.ts and `proof`
    // through gitleak.ts — a local dev connection string failing CI.
    if (isPlaceholder(secretPartOf(m, pat)) || pat.ignoreIf?.(m)) continue
    return pat
  }
  return null
}

/** Whether a value is, on its own, a credential in a format canship recognises */
export function matchesKnownSecret(value: string): boolean {
  return findKnownSecret(value) !== null
}

/**
 * Whether a line is commented out.
 * A commented-out secret is still leaked — it is in the file and therefore in
 * git — so we do **not** skip it. This only lets the report add a note.
 */
export function isCommentedOut(line: string): boolean {
  return /^\s*(?:\/\/|#|\/\*|\*)/.test(line)
}
