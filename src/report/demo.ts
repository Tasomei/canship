/** 演示只使用固定合成数据，不扫描目录或读取配置、环境变量。 */
import { createHash } from 'node:crypto'
import type { Finding, ScanResult } from '../types.js'
import { renderHtml } from './html.js'

export function renderDemoReport(): string {
  const samples: Pick<Finding, 'ruleId' | 'severity' | 'confidence' | 'file' | 'line' | 'title'>[] = [
    { ruleId: 'exposure/secret-in-public-env', severity: 'P0', confidence: 'certain', file: '.env.local', line: 2, title: 'Example: a private credential in a public environment variable' },
    { ruleId: 'cors/reflected-origin-with-credentials', severity: 'P1', confidence: 'certain', file: 'src/server.ts', line: 18, title: 'Example: reflected origins with credentials' },
    { ruleId: 'api/db-write-without-auth', severity: 'P1', confidence: 'likely', file: 'src/api/orders.ts', line: 26, title: 'Example: a database write with unproven authentication' },
    { ruleId: 'redirect/open', severity: 'P2', confidence: 'likely', file: 'src/routes/redirect.ts', line: 42, title: 'Example: a caller-selected redirect target' },
  ]
  const findings: Finding[] = samples.map((sample, index) => ({ ...sample, excerpt: null,
    sourceFingerprint: createHash('sha256').update(`canship-synthetic-demo-${index}`).digest('hex'),
    why: ['This is a synthetic example, not a result from your project. Severity and confidence describe the illustrated finding.'],
    fix: ['Review the illustrative before/after example and adapt it to the actual application.'],
    humanOnly: index === 0 ? ['For a real exposure, revoke the credential with its provider; changing code alone does not revoke it.'] : [],
  }))
  const result: ScanResult = { findings, filesScanned: 4, durationMs: 0, partial: false,
    errors: [], skipped: [], ignored: [], ignoredFindings: [], ruleSelection: null, vendored: 0 }
  return renderHtml(result, { root: 'synthetic-demo', generatedAt: '', version: 'demo', demonstration: true })
}
