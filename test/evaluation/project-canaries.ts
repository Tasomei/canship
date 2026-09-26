/** 在完整应用副本中加入成对检测样本，不改原快照、不执行项目代码。 */
import { cpSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { tmpdir } from 'node:os'
import { scan } from '../../src/engine.js'
import type { Confidence, ScanResult, Severity } from '../../src/types.js'

export interface ProjectFinding {
  rule: string
  severity: Severity
  confidence: Confidence
  file: string | null
  line: number | null
}
export interface ProjectCanary {
  id: string
  file: string
  content: string
  expected: ProjectFinding[]
}

/** 每个固定项目配一个开放样本和一个受限样本，预期差异只在新增文件。 */
export function projectCanaries(project: string): ProjectCanary[] {
  return [false, true].map(guarded => {
    let file: string
    let content: string
    let rule: string
    let severity: Severity = 'P1'
    let line = 1
    if (project === 'nextjs-with-supabase' || project === 'supabase-nextjs-user-management') {
      file = 'app/canship-evaluation-actions.ts'
      content = "'use server';\nimport { createClient } from '@supabase/supabase-js';\n" +
        'const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);\n' +
        `export async function removeCanary() { ${guarded ? 'await requireAuth(); ' : ''}await db.from('canship_canary').delete(); }\n`
      rule = 'api/admin-db-access-without-auth'
      severity = 'P0'
      line = 4
    } else if (project === 'supabase-react-user-management') {
      file = 'supabase/migrations/99999999999999_canship_canary.sql'
      content = 'create table public.canship_canary (id uuid, user_id uuid);\n' +
        'alter table public.canship_canary enable row level security;\n' +
        `create policy canary on public.canship_canary for update using (${guarded ? 'auth.uid() = user_id' : 'true'});\n`
      rule = 'supabase/permissive-policy'
      line = 3
    } else if (project === 'firebase-auth') {
      file = 'canship-canary.rules.json'
      content = JSON.stringify({ rules: { '.write': guarded ? 'auth != null' : true } })
      rule = 'firebase/open-rules'
    } else if (project === 'firebase-firestore') {
      file = 'canship-canary.rules'
      content = `match /canary/{id} { allow write: if ${guarded ? 'request.auth != null' : 'true'}; }\n`
      rule = 'firebase/open-rules'
    } else throw new Error('Unknown evaluation project.')
    return { id: guarded ? 'guarded-canary' : 'open-canary', file, content,
      expected: guarded ? [] : [{ rule, severity, confidence: 'certain', file, line }] }
  })
}

/** 副本位置由系统临时目录生成；拒绝路径越界和覆盖已有样本。 */
export async function scanWithCanary(source: string, canary: ProjectCanary): Promise<ScanResult> {
  const temp = mkdtempSync(join(tmpdir(), 'canship-project-canary-'))
  try {
    const copy = join(temp, 'project')
    const target = resolve(copy, canary.file)
    const path = relative(copy, target)
    if (!path || path === '..' || path.startsWith(`..${sep}`) || isAbsolute(path) || isAbsolute(canary.file)) {
      throw new Error('Invalid canary path.')
    }
    if (existsSync(resolve(source, canary.file))) throw new Error('Canary would overwrite a snapshot file.')
    cpSync(source, copy, { recursive: true, dereference: false, errorOnExist: true, force: false })
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, canary.content, { flag: 'wx' })
    return await scan(copy)
  } finally {
    // 仅移除本次创建的副本，不触碰输入快照。
    rmSync(temp, { recursive: true, force: true })
  }
}
