/** 规则目录说明检测范围与证据边界，不执行扫描。 */
import type { Severity } from '../types.js'
import { SECRET_PATTERNS } from './patterns.js'

export interface RuleDescription {
  id: string
  name: string
  severity: Severity
  confidence: 'certain' | 'likely' | 'varies'
  scope: string
  limitation: string
  reportsFindings: boolean
}

const rule = (id: string, name: string, severity: Severity, confidence: RuleDescription['confidence'],
  scope: string, limitation: string): RuleDescription => ({ id, name, severity, confidence, scope, limitation, reportsFindings: true })

export const RULE_CATALOG: readonly RuleDescription[] = [
  rule('api/admin-db-access-without-auth', 'Admin database access without a recognized auth guard', 'P0', 'certain',
    'Server routes and Next.js Server Functions in Next.js, SvelteKit (endpoints and form actions), Nuxt, Remix/React Router, and Astro, including workspace applications.', 'Syntactic guards only; runtime authentication and business authorization are not verified. Local calls, identity arguments, branches and exception paths are analysed within documented limits. Local auth evidence, SvelteKit hooks and Nuxt middleware may lower confidence without removing findings; exceeded limits disclose incomplete coverage.'),
  rule('api/db-write-without-auth', 'Database write without a recognized auth guard', 'P1', 'likely',
    'Server routes and Next.js Server Functions in Next.js, SvelteKit (endpoints and form actions), Nuxt, Remix/React Router, and Astro.', 'Session-scoped clients and indirect guards may need manual review.'),
  rule('auth/unverified-session', 'Server code trusting supabase.auth.getSession()', 'P1', 'varies',
    'Server routes, Server Functions, middleware and proxy modules, Next.js server components, *.server modules, and server directories that call supabase.auth.getSession(): a result used in a condition is certain; reading its user is reported for review. Exemption requires a checked, awaited identity from the same client before trusted session use.',
    'Only the receiving variable in the same function is followed; results passed to helpers are not tracked.'),
  rule('cors/reflected-origin-with-credentials', 'Reflected origin with credentials', 'P1', 'certain',
    'Response headers and cors middleware options.', 'Static pairing does not prove the deployed policy or cookie behavior.'),
  rule('cors/wildcard-with-credentials', 'Wildcard origin with credentials', 'P2', 'certain',
    'Response headers and cors middleware options.', 'Browsers reject this combination; it is not proof of data exposure.'),
  rule('exposure/private-name-in-public-env', 'Private-looking name with a public env prefix', 'P0', 'likely',
    'Environment files and source references using recognized public prefixes.', 'A variable name is not proof that its value is a secret.'),
  rule('exposure/secret-in-public-env', 'Recognized secret in a public env variable', 'P0', 'certain',
    'Environment files using recognized public prefixes.', 'Credential validity and actual deployment are not verified.'),
  rule('exposure/supabase-service-role-in-client', 'Supabase admin credential exposed in source or public env', 'P0', 'certain',
    'Recognized service_role JWTs in scanned text files, including configuration and non-JavaScript source; Supabase admin credentials in public environment variables.', 'Source presence is observable; actual browser delivery and key validity are not verified.'),
  rule('firebase/open-rules', 'Unconditional Firebase access', 'P1', 'varies',
    'Firebase .rules files and Realtime Database JSON rules: unconditional writes are certain; public reads require review.', 'Public reads may be intentional; runtime rules and business authorization are not verified.'),
  rule('firebase/test-mode-rules', 'Date-based Firebase test rules', 'P1', 'certain',
    'Firebase .rules files using a fixed timestamp cutoff.', 'Expired rules may deny access; deployment state is not verified.'),
  rule('gitleak/env-in-history', 'Private env values in local Git history', 'P0', 'varies',
    'Relevant historical versions of environment files in the local repository.', 'History and resource limits apply; remote refs not available locally are not checked.'),
  rule('gitleak/env-tracked', 'Private env values tracked by Git', 'P0', 'varies',
    'Tracked environment files; templates and public-only values are treated separately.', 'Unrecognized private values are heuristic findings, not verified credentials.'),
  rule('injection/command', 'Shell command built from request input', 'P1', 'varies',
    'exec, execSync, and spawn/execFile with shell: true in supported server handlers. Execa command strings are checked for a caller-chosen executable, or shell interpolation when shell is enabled. Direct request input is certain; values passing through other calls or content checks require review.',
    'Only flows inside one function are followed; values passed to helpers, other files, or validated elsewhere are not tracked.'),
  rule('injection/sql', 'SQL query built from request input', 'P1', 'varies',
    'Untagged template or string concatenation in Prisma $queryRawUnsafe/$executeRawUnsafe, Prisma.raw, sql.raw/sql.unsafe, knex *Raw methods, driver query/execute calls, and query-builder where clauses, in server routes and Next.js Server Functions. Tagged templates and placeholders are not reported.',
    'Only flows inside one function are followed; values passed to helpers, other files, or validated elsewhere are not tracked. Driver calls are reported only when the text looks like SQL.'),
  rule('redirect/open', 'Redirect to an address taken from the request', 'P2', 'varies',
    'redirect, permanentRedirect, NextResponse.redirect, Response.redirect, res.redirect, and sendRedirect in server routes and Next.js Server Functions, when request input decides the start of the target (a whole value, a leading /, or the host). Request input used directly is certain; values that pass through other calls or checks require review.',
    'Only flows inside one function are followed. The request\'s own URL and fixed paths followed by input are not reported; helper-built targets are not tracked.'),
  rule('supabase/permissive-policy', 'Row Level Security policy with an always-true condition', 'P1', 'varies',
    'Supabase SQL migrations, replayed by application scope: permissive policies whose USING or WITH CHECK is always true (true, 1=1, \'a\'=\'a\'). Changing or deleting any row is certain; reading or inserting any row requires review.',
    'Missing clauses and dashboard changes are not checked; matching restrictive policies and nontrivial WITH CHECK conditions lower confidence.'),
  rule('supabase/public-bucket-listing', 'Public storage bucket whose contents can be listed', 'P2', 'varies',
    'Public buckets declared in migrations or supabase/config.toml, paired with a SELECT policy on storage.objects that is always true or filters only by that bucket.',
    'Buckets created from the dashboard or at runtime are not visible; restrictive policies may limit listing and lower confidence.'),
  rule('ssrf/request-url', 'Server request to an address the caller chooses', 'P1', 'likely',
    'fetch, $fetch/ofetch, axios, got, ky, needle, and Node http(s) calls in server routes and Next.js Server Functions, when request input decides the scheme or host of the address.',
    'Only flows inside one function are followed. Fetching caller-supplied URLs can be intended, and allowlists or network controls are not verified.'),
  rule('supabase/rls-not-enabled', 'Table without RLS in migrations', 'P1', 'certain',
    'Supabase SQL migrations, replayed by application scope.', 'Migration state is not deployed database state; grants and policy correctness are outside this check.'),
  rule('webhook/unverified-signature', 'Stripe webhook events handled without signature verification', 'P1', 'varies',
    'Server routes that branch on Stripe event types without an enforced constructEvent or awaited event-retrieval result for the handled value. Request-body handling is certain; custom signature checks remain likely.',
    'Only Stripe is recognized. Unused calls do not verify events; custom HMAC and shared-helper verification require review.'),
  ...SECRET_PATTERNS.map(pattern => ({
    ...rule(`secrets/hardcoded/${pattern.id}`, pattern.name, 'P0', 'certain',
      'Recognized credential formats in scanned text files.', 'Validity, revocation, and use are not checked; example contexts lower confidence.'),
    reportsFindings: !pattern.publicByDesign,
    ...(pattern.publicByDesign ? { limitation: 'Treated as a public identifier; this format alone does not produce a finding.' } : {}),
  })),
]

export function renderRuleCatalog(): string {
  return 'canship rules\n\n' + RULE_CATALOG.map(item =>
    `${item.id}\n  ${item.name}\n  ${item.reportsFindings ? `${item.severity}; ${item.confidence}` : 'Public identifier; not reported'}\n  Scope: ${item.scope}\n  Limit: ${item.limitation}`,
  ).join('\n\n') + '\n\nExample and fixture contexts may lower confidence. No credential validity or deployed configuration is verified.\n'
}
