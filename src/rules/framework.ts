/**
 * Shared frontend-framework knowledge.
 *
 * Extracted because "does this code get shipped to the browser?" is a question
 * both the secrets and exposure rules need to ask, and the answer directly sets
 * the severity: the same OpenAI key hardcoded in a server file means "it is in
 * your git history", while in a 'use client' component it means "every visitor
 * can read it right now".
 */

import type { ScanContext, ScanFile } from '../types.js'
import { isEnvFile } from '../walker.js'
import { parseEnvLine } from './envfile.js'
import { commentsMaskedOf, noiseMaskedOf } from '../mask.js'

/**
 * Environment variable prefixes that get bundled into the frontend.
 * A variable with one of these prefixes always ends up in JavaScript the
 * browser can download.
 */
export const PUBLIC_PREFIXES = [
  'NEXT_PUBLIC_',
  'VITE_',
  'REACT_APP_',
  'EXPO_PUBLIC_',
  'NUXT_PUBLIC_',
  'GATSBY_',
  'VUE_APP_',
  'PUBLIC_',
]

/**
 * Split a variable name into its words.
 *
 * This exists because `\b` does not do what it looks like it does here.
 * A word boundary sits between a word character and a non-word character, and
 * `_` **is** a word character — so `/\bSECRET\b/` does not match
 * `STRIPE_SECRET_KEY`, and `/\bSERVICE_ROLE\b/` does not match
 * `SUPABASE_SERVICE_ROLE_KEY`. Both patterns read as if they work. Neither
 * matched a single realistic environment variable name, which made the two
 * lists below dead code for as long as they existed.
 *
 *   SUPABASE_SERVICE_ROLE_KEY -> SUPABASE SERVICE ROLE KEY
 *   nextPublicApiKey          -> NEXT PUBLIC API KEY
 *   sentry-dsn                -> SENTRY DSN
 */
export function nameWords(key: string): string[] {
  return key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .split(/[^A-Za-z0-9]+/)
    .filter(Boolean)
    .map((w) => w.toUpperCase())
}

/**
 * The name as a phrase that can be searched exactly.
 * Sentinels at both ends so `_SECRET_` matches STRIPE_SECRET_KEY but not
 * SECRETARY_EMAIL.
 */
function namePhrase(key: string): string {
  return `_${nameWords(key).join('_')}_`
}

/**
 * Phrases that mark a value as meant for the browser.
 * NEXT_PUBLIC_SUPABASE_ANON_KEY and NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY are
 * public **by design**; flagging them is a false positive.
 */
const PUBLIC_PHRASES = [
  'ANON',
  'PUBLISHABLE',
  'PUBLIC',
  'CLIENT_ID',
  'MEASUREMENT',
  'TRACKING',
  'ANALYTICS',
  'SENTRY_DSN',
  'MAPBOX',
]

/**
 * Phrases that must never be public.
 * Kept deliberately narrow — no generic KEY / TOKEN / AUTH, since those appear
 * in legitimately public variables all the time.
 */
const PRIVATE_PHRASES = [
  'SECRET',
  'SERVICE_ROLE',
  'SERVICE_KEY',
  'PRIVATE_KEY',
  'PASSWORD',
  'PASSWD',
  'CREDENTIAL',
  'CREDENTIALS',
]

/** Whether the name says this value is meant for the browser */
export function looksIntentionallyPublic(key: string): boolean {
  const phrase = namePhrase(key)
  return PUBLIC_PHRASES.some((p) => phrase.includes(`_${p}_`))
}

/** Whether the name says this value is a credential */
export function looksClearlyPrivate(key: string): boolean {
  const phrase = namePhrase(key)
  return PRIVATE_PHRASES.some((p) => phrase.includes(`_${p}_`))
}

/** Whether the name carries a public prefix; returns the matched prefix */
export function publicPrefixOf(key: string): string | null {
  return PUBLIC_PREFIXES.find((p) => key.startsWith(p)) ?? null
}

/**
 * Whether this file is shipped to the browser in full.
 *
 * v0.1 only trusts the unambiguous signals: the Next.js / React 'use client'
 * directive, and file types that are inherently client components. It does not
 * try to infer things like "server components under app/ run on the server" —
 * guessing wrong would invert the severity, and it is better to be conservative.
 */
export function isClientCode(file: ScanFile): boolean {
  if (/\.(svelte|vue)$/.test(file.path)) return true
  // Read to the first statement rather than to a fixed line count. The
  // directive has to come before any code, but a licence header may come before
  // *it* — and the previous five-line window meant a seven-line copyright
  // banner turned a client component into a server one, which inverts the
  // severity of everything the exposure and secrets rules then say about it.
  let inBlockComment = false
  for (const line of file.lines) {
    let rest = line
    if (inBlockComment) {
      const close = rest.indexOf('*/')
      if (close === -1) continue
      inBlockComment = false
      rest = rest.slice(close + 2)
    }
    // What follows a closed comment on the same line is code, and skipping the
    // whole line lost it: `/* licence */ 'use client'` is a legal first line,
    // and treating it as a comment graded every credential in the file as
    // server-side — the opposite severity, with the opposite advice attached.
    rest = rest.replace(/\/\*[\s\S]*?\*\//g, ' ')
    const opens = rest.indexOf('/*')
    if (opens !== -1) {
      inBlockComment = true
      rest = rest.slice(0, opens)
    }
    const trimmed = rest.trim()
    if (trimmed === '' || trimmed.startsWith('//')) continue
    // First real line. The directive is here or it is nowhere.
    return /^['"]use client['"]/.test(trimmed)
  }
  return false
}

/**
 * Whether this project actually uses Supabase.
 *
 * This gate matters more than it looks. Row Level Security is only *required*
 * in architectures where the database is exposed directly to the browser —
 * Supabase and PostgREST. A conventional backend talking to Postgres does not
 * need RLS at all, and flagging those projects would be a serious false
 * positive. So the RLS rule must not run until we are confident Supabase is in
 * play.
 */
export function isSupabaseProject(ctx: ScanContext): boolean {
  const isSupabaseUrlName = (name: string): boolean =>
    name === 'SUPABASE_URL' || name.endsWith('_SUPABASE_URL')

  for (const file of ctx.files) {
    if (file.path === 'supabase' || file.path.startsWith('supabase/')) return true
    if (file.path.includes('/supabase/migrations/')) return true

    const name = file.path.slice(file.path.lastIndexOf('/') + 1)
    if (isEnvFile(name)) {
      for (const line of file.lines) {
        const entry = parseEnvLine(line)
        if (entry && isSupabaseUrlName(entry.key)) return true
      }
      continue
    }

    if (name === 'package.json') {
      try {
        const pkg = JSON.parse(file.content) as Record<string, unknown>
        for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
          const dependencies = pkg[field]
          if (
            typeof dependencies === 'object' &&
            dependencies !== null &&
            '@supabase/supabase-js' in dependencies
          ) {
            return true
          }
        }
      } catch {
        // Invalid JSON is somebody else's problem. What it must not do here is let
        // a comment or a line of prose count as evidence about the project.
      }
      continue
    }

    const commentsRemoved = commentsMaskedOf(file)
    const code = noiseMaskedOf(file)
    const supabaseImport =
      /(?:\bfrom\s*|\bimport\s*\(\s*|\brequire\s*\(\s*|\bimport\s*)['"]@supabase\/(?:supabase-js|ssr)(?:\/[^'"]*)?['"]/g
    for (const match of commentsRemoved.matchAll(supabaseImport)) {
      // The keyword has to sit in real code: an import quoted inside prose must
      // not switch on a project-wide rule.
      const start = match.index
      if (start !== undefined && /\b(?:from|import|require)\b/.test(code.slice(start, start + 10))) {
        return true
      }
    }

    if (/\b(?:[A-Z][A-Z0-9_]*_)?SUPABASE_URL\b/.test(code)) return true

    // The variable name in a bracket access lives inside a string, which
    // noiseMaskedOf blanks — so the access is confirmed against real code as
    // well, keeping a documentation string from switching on the whole rule.
    const bracketAccess = /(?:process\.env|import\.meta\.env)\s*\[\s*['"]([^'"]+)['"]\s*\]/g
    for (const match of commentsRemoved.matchAll(bracketAccess)) {
      const start = match.index
      if (
        start !== undefined &&
        /(?:process\.env|import\.meta\.env)/.test(code.slice(start, start + 20)) &&
        isSupabaseUrlName(match[1] ?? '')
      ) {
        return true
      }
    }
    if (/\bcreateServerClient\s*\(/.test(code) && /\bsupabase\b/i.test(code)) return true
  }
  return false
}

/** Decode a JWT payload. Returns null when the input is not a valid JWT. */
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const payload = Buffer.from(parts[1]!, 'base64url').toString('utf8')
    const parsed: unknown = JSON.parse(payload)
    return typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>) : null
  } catch {
    return null
  }
}

/**
 * Whether a string is a Supabase service_role key.
 *
 * This is the hardest evidence canship produces: decode the JWT payload, and if
 * the role field says service_role, it is the database root password. There is
 * nothing to argue about. Handles both the legacy JWT format and the newer
 * sb_secret_ format.
 */
export function isSupabaseServiceRole(value: string): boolean {
  if (value.startsWith('sb_secret_')) return true
  if (!value.startsWith('eyJ')) return false
  return decodeJwtPayload(value)?.['role'] === 'service_role'
}
