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
