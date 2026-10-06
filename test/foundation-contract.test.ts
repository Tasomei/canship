/** 共用状态矩阵、后续命令和覆盖说明不依赖展示格式。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { summarize, scanExitCode } from '../src/summary.js'
import { followupArgs, followupCommand } from '../src/report/commands.js'
import { renderReport } from '../src/report/terminal.js'
import { renderHtml } from '../src/report/html.js'
import { diagnosticCodeOf } from '../src/diagnostics.js'
import type { Finding, ScanResult } from '../src/types.js'

const finding = (confidence: 'certain' | 'likely', severity: 'P0' | 'P2'): Finding => ({
  ruleId:'api/db-write-without-auth', confidence, severity, title:'Example', file:'src/api.ts', line:1, excerpt:null, why:[], fix:[],
})
const result = (over: Partial<ScanResult> = {}): ScanResult => ({findings:[], filesScanned:1,durationMs:0,partial:false,
  errors:[],skipped:[],ignored:[],ignoredFindings:[],ruleSelection:null,vendored:0,...over})

for (const partial of [false,true]) for (const [findings,expected] of [
  [[],0], [[finding('certain','P0')],1], [[finding('likely','P0')],2], [[finding('certain','P2')],2],
] as const) {
  test(`shared verdict: ${expected}, partial ${partial}`, () => {
    const r=result({findings:[...findings],partial})
    assert.equal(summarize(r).exitCode, expected || (partial ? 3 : 0))
    assert.equal(scanExitCode(r),summarize(r).exitCode)
    assert.equal(scanExitCode(r,true),expected)
  })
}
test('coverage contradictions and changed-file views preserve the full status', () => {
  assert.equal(scanExitCode(result({filesScanned:0})),3)
  assert.equal(scanExitCode(result({errors:[{ruleId:'test',file:null,message:'example',kind:'crashed'}]})),3)
  const changed=result({changeView:{baseCommit:'a',mergeBase:'a',changedFiles:0,hiddenFindings:1,totalFindings:1,totalBlocking:1,totalLikely:0}})
  assert.equal(scanExitCode(changed,true),1)
})
test('follow-up arguments preserve scope and privacy, removing output side effects', () => {
  assert.deepEqual(followupArgs(['./my app','--only=api','--no-excerpts','--baseline=accepted.json','--no-config','--report=old.html','--sarif=old.sarif','--open','--verbose']),
    ['./my app','--only=api','--no-excerpts','--baseline=accepted.json','--no-config'])
  assert.equal(followupArgs(['bad\npath']),null)
  assert.equal(followupArgs(['bad\u202epath']),null)
})
test('commands quote shell metacharacters without executing them', () => {
  assert.equal(followupCommand(["./O'Brien app",'--no-excerpts'],['--verbose'],'win32'),"npx canship './O''Brien app' --no-excerpts --verbose")
  assert.equal(followupCommand(["./O'Brien app"],['--verbose'],'linux'),"npx canship './O'\"'\"'Brien app' --verbose")
  assert.equal(followupCommand(['./$(untrusted);x'],[],'win32'),"npx canship './$(untrusted);x'")
})
test('clean reports do not claim that excluded checks ran', () => {
  const r=result({ruleSelection:{only:['cors'],skip:[],removed:0}})
  const text=renderReport(r,{root:'.',showingLikely:false,hiddenLikely:0,exitCode:0})
  const html=renderHtml(r,{root:'.',generatedAt:''})
  for(const output of [text,html]) {
    assert.match(output,/No findings in enabled checks/)
    assert.doesNotMatch(output,/Checked for|API keys hardcoded|All built-in rule groups enabled/)
  }
})
test('hidden findings get an actionable review command with the original target', () => {
  const output=renderReport(result(),{root:'.',showingLikely:false,hiddenLikely:1,rerunArgs:['./web','--no-excerpts'],exitCode:2})
  assert.match(output,/npx canship \.\/web --no-excerpts --all --verbose/)
})
test('best-effort success still discloses incomplete coverage', () => {
  assert.match(renderReport(result({partial:true}),{root:'.',showingLikely:false,hiddenLikely:0,exitCode:0}),/incomplete coverage accepted/)
})
test('diagnostic identity does not depend on message text', () => {
  assert.equal(diagnosticCodeOf({kind:'crashed',ruleId:'api/auth'}),'RULE_EXECUTION_FAILED')
  assert.equal(diagnosticCodeOf({kind:'incomplete',ruleId:'engine/openapi-routes'}),'ROUTE_UNRESOLVED')
  assert.equal(diagnosticCodeOf({kind:'incomplete',ruleId:'engine/findings-limit'}),'FINDINGS_LIMIT')
})
