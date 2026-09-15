/** 注册单文件和跨文件规则，并维护对外可选择的规则 ID。 */

import type { Rule, ProjectRule } from '../types.js'
import { SECRET_PATTERNS } from './patterns.js'
import { secretsRule } from './secrets.js'
import { exposureRule } from './exposure.js'
import { gitleakRule } from './gitleak.js'
import { supabaseRlsRule } from './supabase.js'
import { firebaseRulesRule } from './firebase.js'
import { apiAuthRule } from './apiauth.js'
import { corsRule } from './cors.js'

/** 按文件执行的规则。 */
export const FILE_RULES: Rule[] = [secretsRule, exposureRule, firebaseRulesRule, corsRule]

/** 每次扫描执行一次的跨文件规则。 */
export const PROJECT_RULES: ProjectRule[] = [gitleakRule, supabaseRlsRule, apiAuthRule]

/** 所有可能输出的规则 ID，用于参数校验和执行筛选。 */
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
  // 凭据规则 ID 从共享格式表生成。
  ...SECRET_PATTERNS.map((p) => `secrets/hardcoded/${p.id}`),
]

/** 按完整 ID 或斜杠分隔的命名空间匹配。 */
export function ruleMatches(selector: string, ruleId: string): boolean {
  return ruleId === selector || ruleId.startsWith(`${selector}/`)
}

/** 判断选择器是否对应已注册规则。 */
export function isKnownSelector(selector: string): boolean {
  return RULE_IDS.some((id) => ruleMatches(selector, id))
}

/** 按输出规则 ID 选择执行器；同一执行器内的细分结果仍需过滤。 */
export function shouldRunRule(id: string, only: readonly string[], skip: readonly string[]): boolean {
  if (only.length === 0 && skip.length === 0) return true
  const namespace = id.split('/')[0]!
  return RULE_IDS.filter(candidate => candidate.startsWith(`${namespace}/`)).some(candidate =>
    (only.length === 0 || only.some(selector => ruleMatches(selector, candidate))) &&
    !skip.some(selector => ruleMatches(selector, candidate)),
  )
}
