/**
 * Rule registry.
 *
 * The bar for adding a rule is accuracy, not coverage. Few and precise beats
 * many and noisy: a single false positive is enough to make someone stop
 * trusting the tool, and they will tell other people it is unreliable.
 *
 * P0 — burns money or exposes the whole database (secrets, exposure, gitleak,
 *      unauthenticated admin-level API routes)
 * P1 — the database is left open to anyone (Supabase RLS, Firebase rules,
 *      unauthenticated writes, credentialed cross-origin access)
 * P2 — broken rather than dangerous, but the obvious fix makes it dangerous
 */

import type { Rule, ProjectRule } from '../types.js'
import { SECRET_PATTERNS } from './patterns.js'
import { secretsRule } from './secrets.js'
import { exposureRule } from './exposure.js'
import { gitleakRule } from './gitleak.js'
import { supabaseRlsRule } from './supabase.js'
import { firebaseRulesRule } from './firebase.js'
import { apiAuthRule } from './apiauth.js'
import { corsRule } from './cors.js'

/** Rules that run per file */
export const FILE_RULES: Rule[] = [secretsRule, exposureRule, firebaseRulesRule, corsRule]

/**
 * Rules that run once per project.
 * These need to see every file before deciding — a table can be created in one
 * migration and secured in another, and an API route can be protected by
 * middleware that lives nowhere near it.
 */
export const PROJECT_RULES: ProjectRule[] = [gitleakRule, supabaseRlsRule, apiAuthRule]

/**
 * Every rule id a finding can carry.
 *
 * Not the same thing as the `id` on the rules above, which is the surprise
 * here: a rule's registry id and the ids of the findings it emits are two
 * different naming schemes that agree only on their first segment.
 * `exposure/public-env` produces `exposure/secret-in-public-env`;
 * `gitleak/env-in-git` produces `gitleak/env-tracked`; `api/db-access-without-auth`
 * produces `api/db-write-without-auth`. None of the registry ids is a prefix
 * of what it emits.
 *
 * That matters because the ids in this list are the ones a *user* can see —
 * they are what `--json` prints and what a canship-ignore-next-line marker or
 * a config file names. Selecting rules by the registry ids would mean asking
 * people to type strings that appear in no output.
 *
 * The list is written out rather than derived because it cannot be derived:
 * the ids are string literals scattered across the rule bodies. What keeps it
 * honest is the test that scans the fixtures and asserts every id a real scan
 * produces is a member — so a new finding id that nobody added here fails the
 * suite rather than becoming an id that config validation rejects.
 */
export const RULE_IDS: readonly string[] = [
  'api/admin-db-access-without-auth',
  'api/db-write-without-auth',
  'cors/reflected-origin-with-credentials',
  'cors/wildcard-with-credentials',
  'exposure/private-name-in-public-env',
  'exposure/secret-in-public-env',
  'exposure/supabase-service-role-in-client',
  'firebase/open-rules',
  'firebase/test-mode-rules',
  'gitleak/env-in-history',
  'gitleak/env-tracked',
  'supabase/rls-not-enabled',
  // One per credential format, built the same way secrets.ts builds them, so
  // adding a pattern cannot leave a finding id this list has never heard of.
  ...SECRET_PATTERNS.map((p) => `secrets/hardcoded/${p.id}`),
]

/**
 * Whether `selector` names `ruleId`, exactly or as a path prefix.
 *
 * The boundary is the slash, so `secrets` covers every credential format and
 * `secrets/hardcoded/openai` covers one. Without the boundary, `cors/w` would
 * select `cors/wildcard-with-credentials`, and a half-typed id silently
 * turning off a rule is the failure mode this whole area has to avoid.
 */
export function ruleMatches(selector: string, ruleId: string): boolean {
  return ruleId === selector || ruleId.startsWith(`${selector}/`)
}

/** Whether a selector names at least one real rule, for rejecting typos */
export function isKnownSelector(selector: string): boolean {
  return RULE_IDS.some((id) => ruleMatches(selector, id))
}
