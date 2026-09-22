/** 小型离线评估集；用例来源与预期独立声明。
 * canship-ignore-file */
import { readFileSync } from 'node:fs'
import type { Confidence, Severity } from '../../src/types.js'

export interface ExpectedFinding {
  ruleId: string
  file: string
  severity: Severity
  confidence: Confidence
}
export interface EvaluationCase {
  id: string
  origin: 'synthetic' | 'upstream-derived' | 'mutated-upstream'
  files: Record<string, string>
  expected: ExpectedFinding[]
  partial?: boolean
  skipped?: number
}

const migration = readFileSync(new URL('../fixtures/evaluation/supabase-profiles/migration.sql', import.meta.url), 'utf8')
const migrationPath = 'supabase/migrations/20221017024722_init.sql'
const admin = "import { createClient } from '@supabase/supabase-js';\n" +
  'export const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);\n'
const route = (guard: string) => "import { db } from '@/lib/admin';\n" +
  `export async function GET() { ${guard} return Response.json(await db.from('profiles').select('*')); }`
const firebase = (condition: string, operation = 'read, write') =>
  `service cloud.firestore { match /databases/{database}/documents { match /notes/{id} { allow ${operation}: if ${condition}; } } }`
const finding = (ruleId: string, file: string, severity: Severity = 'P1', confidence: Confidence = 'certain'): ExpectedFinding =>
  ({ ruleId, file, severity, confidence })

export const evaluationCases: readonly EvaluationCase[] = [
  {
    id: 'supabase-upstream-rls-enabled', origin: 'upstream-derived',
    files: { [migrationPath]: migration }, expected: [],
  },
  {
    id: 'supabase-upstream-rls-disabled-later', origin: 'mutated-upstream',
    files: { [migrationPath]: migration, 'supabase/migrations/20221018000000_disable.sql': 'alter table profiles disable row level security;' },
    expected: [finding('supabase/rls-not-enabled', migrationPath)],
  },
  {
    id: 'nextjs-shared-admin-open', origin: 'synthetic',
    files: { 'lib/admin.ts': admin, 'app/api/users/route.ts': route('') },
    expected: [finding('api/admin-db-access-without-auth', 'app/api/users/route.ts', 'P0')],
  },
  {
    id: 'nextjs-shared-admin-guarded', origin: 'synthetic',
    files: { 'lib/admin.ts': admin, 'app/api/users/route.ts': route('await requireAuth();') }, expected: [],
  },
  {
    id: 'nextjs-optional-auth', origin: 'synthetic',
    files: { 'lib/admin.ts': admin, 'app/api/users/route.ts': route('if (process.env.AUTH_ENABLED) { await requireAuth(); }') },
    expected: [finding('api/admin-db-access-without-auth', 'app/api/users/route.ts', 'P0')],
  },
  {
    id: 'workspace-route-group', origin: 'synthetic',
    files: { 'apps/web/lib/admin.ts': admin, 'apps/web/app/(private)/api/users/route.ts': route('') },
    expected: [finding('api/admin-db-access-without-auth', 'apps/web/app/(private)/api/users/route.ts', 'P0')],
  },
  {
    id: 'firebase-open-write', origin: 'synthetic',
    files: { 'firestore.rules': firebase('true') }, expected: [finding('firebase/open-rules', 'firestore.rules')],
  },
  {
    id: 'firebase-authenticated-write', origin: 'synthetic',
    files: { 'firestore.rules': firebase('request.auth != null') }, expected: [],
  },
  {
    id: 'firebase-public-read-review', origin: 'synthetic',
    files: { 'firestore.rules': firebase('true', 'read') },
    expected: [finding('firebase/open-rules', 'firestore.rules', 'P1', 'likely')],
  },
  {
    id: 'cors-reflected-credentials', origin: 'synthetic',
    files: { 'lib/cors.ts': "export function headers(req) { return { 'Access-Control-Allow-Origin': req.headers.get('origin'), 'Access-Control-Allow-Credentials': 'true' }; }" },
    expected: [finding('cors/reflected-origin-with-credentials', 'lib/cors.ts')],
  },
  {
    id: 'cors-fixed-origin', origin: 'synthetic',
    files: { 'lib/cors.ts': "export const headers = { 'Access-Control-Allow-Origin': 'https://app.example.com', 'Access-Control-Allow-Credentials': 'true' };" }, expected: [],
  },
  {
    id: 'incomplete-with-finding', origin: 'synthetic',
    files: { 'firestore.rules': firebase('true'), 'large.ts': ' '.repeat(2 * 1024 * 1024 + 1) },
    expected: [finding('firebase/open-rules', 'firestore.rules')], partial: true, skipped: 1,
  },
]
