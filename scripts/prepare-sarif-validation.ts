/** 仅输出合成验收数据，不扫描目录、不写文件、不上传报告。 */
import { createHash } from 'node:crypto'
import { renderSarif } from '../src/report/sarif.js'
import type { Finding, ScanResult } from '../src/types.js'

if (process.argv.length !== 2) {
  process.stderr.write('This preview takes no arguments and performs no upload.\n')
  process.exitCode = 3
} else {
  const fixture = ["rules_version = '2';", 'service cloud.firestore {', '  match /databases/{database}/documents {',
    '    // 仅供合成验收。', '    match /sampleA/{id} {', '      // 公开读取测试。',
    '      allow read: if true;', '    }', '    match /sampleB/{id} {', '      // 公开读取测试。',
    '      allow read: if true;', '    }', '  }', '}', ''].join('\n')
  const file = 'synthetic/firestore.rules'
  const findings: Finding[] = [7, 11].map((line, index) => ({
    ruleId: 'firebase/open-rules', severity: 'P1', confidence: 'likely', file, line,
    title: 'Synthetic public-read validation', excerpt: null,
    sourceFingerprint: createHash('sha256').update(`canship-sarif-synthetic-${index}`).digest('hex'),
    why: ['Synthetic test input, not a production finding.'], fix: ['No production resource is involved.'],
  }))
  const cases = ['initial', 'repeat', 'moved', 'wording-and-version'] as const
  const reports = cases.map(id => {
    const moved = id === 'moved' || id === 'wording-and-version'
    const changed = id === 'wording-and-version'
    const result: ScanResult = { findings: findings.map(finding => ({ ...finding,
      line: finding.line! + (moved ? 3 : 0), ...(changed ? { title: 'Reworded synthetic public-read validation' } : {}) })),
      filesScanned: 1, durationMs: 0, partial: false, errors: [], skipped: [], ignored: [], ignoredFindings: [],
      ruleSelection: null, vendored: 0 }
    return { id, fixture: { path: file, content: (moved ? '\n\n\n' : '') + fixture },
      sarif: JSON.parse(renderSarif(result, { version: changed ? '0.0.0-validation.2' : '0.0.0-validation.1' })) }
  })
  process.stdout.write(JSON.stringify({ schemaVersion: 1, kind: 'sarif-validation-preview', synthetic: true,
    scanPerformed: false, networkPerformed: false, uploaded: false,
    notice: 'Local synthetic preview only. GitHub alert continuity remains unverified. Upload requires separate approval and matching fixture commits in an isolated test branch.',
    expected: { findingsPerReport: 2, relationship: 'Later cases should retain the initial alert identities; compare GitHub alert numbers after each upload.' },
    cases: reports }, null, 2) + '\n')
}
