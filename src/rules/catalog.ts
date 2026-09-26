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
    'Server routes and Next.js Server Functions in Next.js, SvelteKit (endpoints and form actions), Nuxt, Remix/React Router, and Astro, including workspace applications.', 'Syntactic guards only; runtime authentication and business authorization are not verified. Guards in SvelteKit hooks or Nuxt server middleware lower confidence.'),
  rule('api/db-write-without-auth', 'Database write without a recognized auth guard', 'P1', 'likely',
    'Server routes and Next.js Server Functions in Next.js, SvelteKit (endpoints and form actions), Nuxt, Remix/React Router, and Astro.', 'Session-scoped clients and indirect guards may need manual review.'),
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
  rule('supabase/permissive-policy', 'Row Level Security policy with an always-true condition', 'P1', 'varies',
    'Supabase SQL migrations, replayed by application scope: permissive policies whose USING or WITH CHECK is always true (true, 1=1, \'a\'=\'a\'). Changing or deleting any row is certain; reading or inserting any row requires review.',
    'Policies missing a USING or WITH CHECK clause are not checked; dashboard changes and restrictive policies elsewhere are not visible.'),
  rule('supabase/public-bucket-listing', 'Public storage bucket whose contents can be listed', 'P2', 'certain',
    'Public buckets declared in migrations or supabase/config.toml, paired with a SELECT policy on storage.objects that is always true or filters only by that bucket.',
    'Buckets created from the dashboard or at runtime are not visible.'),
  rule('supabase/rls-not-enabled', 'Table without RLS in migrations', 'P1', 'certain',
    'Supabase SQL migrations, replayed by application scope.', 'Migration state is not deployed database state; grants and policy correctness are outside this check.'),
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
