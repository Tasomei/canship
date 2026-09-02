/**
 * P0-2 / P0-3: server-side secrets exposed to the browser.
 *
 * This is canship's flagship rule, and the classic way vibe-coded apps die:
 * to make the code work, the assistant adds a NEXT_PUBLIC_ prefix to an
 * environment variable — because that is what makes the browser able to read
 * it. And then the whole world can read it too.
 *
 * The Supabase service_role check inside is the zero-false-positive part:
 * that key is a JWT, so decoding the payload and reading the role field
 * settles it. If it says service_role, it is the database root password, and
 * there is nothing to argue about.
 */

import type { Finding, Rule, ScanContext, ScanFile } from '../types.js'
import { redactLine, redactSecret } from '../redact.js'
import { basename } from 'node:path'
import { isEnvFile } from '../walker.js'
import { MAX_FINDINGS_PER_FILE } from './limits.js'
import { JWT_SOURCE, findKnownSecret, isPlaceholder } from './patterns.js'
import { parseEnvLine } from './envfile.js'
import { commentsMaskedOf } from '../mask.js'
import {
  looksClearlyPrivate,
  isClientCode,
  isSupabaseServiceRole,
  publicPrefixOf,
} from './framework.js'

/**
 * Built from the shared source rather than written out again.
 *
 * The copy that used to live here required ten characters per segment where
 * redact.ts and apiauth.ts required eight — three spellings of one shape, free
 * to drift apart, and one of the three is the redaction boundary.
 */
const JWT_SHAPED = new RegExp(String.raw`\b${JWT_SOURCE}\b`, 'g')

interface EnvEntry {
  key: string
  value: string
  line: number
}

/** Parse a .env file, tolerating an export prefix and quoted values */
function parseEnv(file: ScanFile): EnvEntry[] {
  const entries: EnvEntry[] = []
  file.lines.forEach((raw, i) => {
    const assignment = parseEnvLine(raw)
    if (assignment) entries.push({ ...assignment, line: i + 1 })
  })
  return entries
}

export const exposureRule: Rule = {
  id: 'exposure/public-env',
  severity: 'P0',

  appliesTo(file: ScanFile): boolean {
    // Fixtures and examples are no longer refused here. Dogfooding once drowned
    // this rule's report in canship's own fixtures, and skipping them outright
    // was the first answer — but it also made a deployable app under examples/
    // invisible. The engine now holds whatever they produce at lower confidence
    // instead, which keeps the default report quiet without losing the finding.
    // See downgradeExampleContext.
    const name = basename(file.path)
    if (isEnvFile(name)) return true
    return /\.(ts|tsx|js|jsx|mjs|cjs|svelte|vue|astro)$/.test(name)
  },

  /**
   * The ceiling, applied here rather than inside each branch.
   *
   * This rule was the last one without one. secrets.ts, firebase.ts and
   * supabase.ts all cap and all say so — the constant was pulled into limits.ts
   * precisely so the reasoning would not have to be rediscovered — and exposure
   * never adopted it. A `.env` holding 3,000 public-prefixed credential names
   * produced 3,000 findings, 2.36 MB of JSON and 48,046 lines of terminal
   * output, with `partial` false and `errors` empty: the identical shape of the
   * bug firebase.ts records in its own comment.
   *
   * At the entry point because there are two branches and a future third would
   * have to remember. Truncating after the fact rather than stopping the loop
   * keeps that single place honest: the input is already bounded by
   * MAX_FILE_BYTES, so what this protects is the report, not the scan.
   */
  check(file: ScanFile, ctx: ScanContext): Finding[] {
    const name = basename(file.path)
    const findings = isEnvFile(name) ? checkEnvFile(file) : checkSourceFile(file)
    if (findings.length <= MAX_FINDINGS_PER_FILE) return findings

    ctx.reportIncomplete(
      'exposure/public-env',
      `${file.path} holds more than ${MAX_FINDINGS_PER_FILE} values exposed to the browser; ` +
        `the rest were not reported`,
    )
    return findings.slice(0, MAX_FINDINGS_PER_FILE)
  },
}

/** Check a .env file */
function checkEnvFile(file: ScanFile): Finding[] {
  const findings: Finding[] = []

  for (const entry of parseEnv(file)) {
    const prefix = publicPrefixOf(entry.key)
    if (!prefix) continue
    if (!entry.value || isPlaceholder(entry.value)) continue

    const rawLine = file.lines[entry.line - 1] ?? ''

    // ── Case A: the value is a Supabase service_role key — worst case, and proven ──
    if (isSupabaseServiceRole(entry.value)) {
      findings.push({
        ruleId: 'exposure/supabase-service-role-in-client',
        severity: 'P0',
        confidence: 'certain',
        title: 'Your Supabase admin key is exposed to the browser',
        file: file.path,
        line: entry.line,
        excerpt: `${entry.key}=${redactSecret(entry.value)}`,
        why: [
          `This is the service_role key. It bypasses every Row Level Security policy in your database — ` +
            `it is effectively your database root password.`,
          `Because the variable name starts with ${prefix}, its value is compiled into your website's ` +
            `JavaScript bundle. Anyone who opens your site can read it from their browser's dev tools and ` +
            `then read, modify, or delete every row in your database.`,
        ],
        fix: [
          `Rename this variable to SUPABASE_SERVICE_ROLE_KEY (drop the ${prefix} prefix).`,
          `Only reference it from server-side code — API routes, server actions, or server components. Never from a component with 'use client'.`,
          `For anything the browser needs, use the anon key (NEXT_PUBLIC_SUPABASE_ANON_KEY) together with Row Level Security policies.`,
        ],
        humanOnly: [
          `Rotate the service_role key in your Supabase dashboard (Project Settings -> API). If your site has ever been deployed with this key, assume it is already compromised — renaming the variable does not revoke it.`,
        ],
      })
      continue
    }

    // ── Case B: the value matches a known high-risk secret format — also proven ──
    const known = findKnownSecret(entry.value)
    if (known) {
      // A Firebase/Maps key is meant to reach the browser by the provider's
      // own design — see SecretPattern.publicByDesign. Reporting it here
      // would say "your secret is exposed" about a value that was never a
      // secret in the first place.
      if (known.publicByDesign) continue
      findings.push({
        ruleId: 'exposure/secret-in-public-env',
        severity: 'P0',
        confidence: 'certain',
        title: `Your ${known.name} is exposed to the browser`,
        file: file.path,
        line: entry.line,
        excerpt: `${entry.key}=${redactSecret(entry.value)}`,
        why: [
          `Variables prefixed with ${prefix} are compiled into the JavaScript your website sends to every ` +
            `visitor. This one is not a public identifier — it is a real credential.`,
          known.impact,
        ],
        fix: [
          `Rename this variable to drop the ${prefix} prefix, so it stays on the server.`,
          `Move any code that uses it into an API route or server action.`,
        ],
        humanOnly: [
          `Rotate this ${known.rotateLabel ?? known.name}${known.rotateAt ? ` at ${known.rotateAt}` : ''} — the current one must be considered public.`,
        ],
      })
      continue
    }

    // ── Case C: the name says it is private — heuristic, marked likely ──
    //
    // Asked about the name *after* the prefix. Every NEXT_PUBLIC_ variable
    // contains the word PUBLIC by construction, so testing the whole name
    // would mark all of them intentionally public and silence this branch
    // entirely — the one place it is meant to fire.
    // A credential word wins over a public one. NEXT_PUBLIC_ANALYTICS_PASSWORD
    // contains both, and letting "analytics" excuse "password" is how a name
    // that says exactly what it holds goes unreported.
    const rest = entry.key.slice(prefix.length)
    if (looksClearlyPrivate(rest)) {
      findings.push({
        ruleId: 'exposure/private-name-in-public-env',
        severity: 'P0',
        confidence: 'likely',
        title: `"${entry.key}" looks like a secret but is exposed to the browser`,
        file: file.path,
        line: entry.line,
        excerpt: redactLine(rawLine, entry.value),
        why: [
          `The name contains a word that usually marks a private credential, but the ${prefix} prefix ` +
            `means its value ships to every visitor's browser.`,
          `If this value really is meant to be public, you can ignore this.`,
        ],
        fix: [
          `If it is a secret: drop the ${prefix} prefix and use it only from server-side code.`,
          `If it is genuinely public: rename it so the name does not say "secret" — future you will thank you.`,
        ],
      })
    }
  }

  return findings
}

/** Check a source file */
function checkSourceFile(file: ScanFile): Finding[] {
  const findings: Finding[] = []

  // A service_role key or known secret inlined directly into a client component
  const clientSide = isClientCode(file)

  // Comments blanked by the shared lexer, offsets preserved so line numbers and
  // match positions still line up. The hand-rolled predicate this replaces got
  // two ordinary lines wrong, both in the direction that loses findings: a `//`
  // inside a string literal — `const p = "a//b"` — started a comment, and a
  // block comment that closed before the code on its own line swallowed the
  // whole line. Every other rule that has to tell code from prose already calls
  // this; exposure.ts was the one hand-rolling it.
  const commentless = commentsMaskedOf(file).split(/\r?\n/)

  file.lines.forEach((line, i) => {
    // Find JWT-shaped strings on this line
    // The shared shape; the local copy asked for ten characters a segment.
    JWT_SHAPED.lastIndex = 0
    const jwtMatches = line.match(JWT_SHAPED)
    if (jwtMatches) {
      for (const jwt of jwtMatches) {
        if (!isSupabaseServiceRole(jwt)) continue
        findings.push({
          ruleId: 'exposure/supabase-service-role-in-client',
          severity: 'P0',
          confidence: 'certain',
          title: clientSide
            ? 'Your Supabase admin key is hardcoded in a client component'
            : 'Your Supabase admin key is hardcoded in source code',
          file: file.path,
          line: i + 1,
          excerpt: redactLine(line, jwt),
          why: [
            `This is the service_role key — it bypasses every Row Level Security policy and is effectively ` +
              `your database root password.`,
            clientSide
              ? `This file starts with 'use client', so it is shipped to the browser in full. Any visitor can read this key.`
              : `Hardcoding it in source means it is in your git history, and it will be bundled anywhere this file is imported from client code.`,
          ],
          fix: [
            `Remove the key from the source file entirely.`,
            `Put it in .env as SUPABASE_SERVICE_ROLE_KEY (no public prefix) and read it via process.env on the server only.`,
          ],
          humanOnly: [
            `Rotate the key in your Supabase dashboard (Project Settings -> API) — the current one must be treated as compromised.`,
          ],
        })
      }
    }

    // Client code referencing a public-prefixed variable whose name says it is
    // a credential.
    // Matched against the comment-blanked copy. Inside a comment there is no
    // value going anywhere, so the name proves nothing — this branch judges a
    // name rather than a value, which is the difference from the
    // hardcoded-secret rule: a commented-out *key* is still in the file and
    // still leaked, a commented-out *name* is prose. canship found this on its
    // own source, where a comment gave an example of the very pattern matched
    // here.
    // `import.meta.env` as well as `process.env`: it is how Vite, Astro and
    // SvelteKit read these, and `VITE_`, `PUBLIC_` and `GATSBY_` are already in
    // PUBLIC_PREFIXES — so canship knew those prefixes ship to the browser
    // while being unable to see a single line of code that used one.
    //
    // Bracket access as well as dot access. `process.env['NEXT_PUBLIC_X']` is
    // the same read written differently — required, in fact, for any name a
    // dotted identifier cannot hold — and matching only the dotted form meant
    // the choice of syntax decided whether the line was examined. A dynamic
    // index stays unmatched on purpose: there is no name to judge.
    const envRef =
      /(?:process\.env|import\.meta\.env)(?:\.([A-Z_][A-Z0-9_]*)|\[\s*['"]([A-Z_][A-Z0-9_]*)['"]\s*\])/g
    let m: RegExpExecArray | null
    while ((m = envRef.exec(commentless[i] ?? '')) !== null) {
      const varName = (m[1] ?? m[2])!

      const varPrefix = publicPrefixOf(varName)
      if (!varPrefix) continue
      // Judged on the name minus its prefix — see the note in checkEnvFile.
      const varRest = varName.slice(varPrefix.length)
      // A credential word wins over a public one, exactly as in checkEnvFile.
      // This branch used to let `looksIntentionallyPublic` overrule it, so
      // NEXT_PUBLIC_ANALYTICS_PASSWORD went unreported: "analytics" excused
      // "password". The note in checkEnvFile named that very variable as the
      // thing not to do, while this branch did it — an exemption the sibling
      // rule had already learned to refuse.
      //
      // Safe to drop because PRIVATE_PHRASES holds only unambiguous words —
      // SECRET, PASSWORD, SERVICE_ROLE, PRIVATE_KEY and the like, never a bare
      // KEY. A publishable key does not match it and is still not reported.
      if (!looksClearlyPrivate(varRest)) continue
      findings.push({
        ruleId: 'exposure/private-name-in-public-env',
        severity: 'P0',
        confidence: 'likely',
        title: `"${varName}" looks like a secret but is readable in the browser`,
        file: file.path,
        line: i + 1,
        excerpt: line.trim(),
        why: [
          `This variable has a public prefix, so its value is embedded in the JavaScript bundle that every ` +
            `visitor downloads — but its name suggests it holds a credential.`,
        ],
        fix: [
          `Drop the public prefix and move the code that uses it to the server.`,
          `If the value really is public, rename it so it does not read as a secret.`,
        ],
      })
    }
  })

  return findings
}
