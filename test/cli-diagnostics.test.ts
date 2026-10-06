/** 参数、配置和文件输出失败保留稳定代码及完整标准输出。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, rmSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { scan } from '../src/index.js'

const roots: string[]=[]
after(()=>{for(const root of roots)rmSync(root,{recursive:true,force:true})})
const project=()=>{const root=mkdtempSync(join(tmpdir(),'canship-diagnostic-'));roots.push(root);writeFileSync(join(root,'index.ts'),'export const ok=true;');return root}
const cli=(...args:string[])=>spawnSync(process.execPath,['--import','tsx','src/cli.ts',...args],{encoding:'utf8'})
test('parameter and unavailable-root errors have stable codes',()=>{
  assert.match(cli('--unknown').stderr,/\[INVALID_ARGUMENT\]/)
  assert.match(cli(join(project(),'missing')).stderr,/\[SCAN_ROOT_UNAVAILABLE\]/)
})
test('configuration and baseline failures are distinguishable',()=>{
  const root=project();writeFileSync(join(root,'canship.config.json'),'{broken')
  assert.match(cli(root).stderr,/\[CONFIG_INVALID\]/)
  assert.match(cli(root,'--no-config','--baseline').stderr,/\[BASELINE_INVALID\]/)
})
test('API input errors retain TypeError compatibility and never echo the invalid root',async()=>{
  await assert.rejects(scan(''),(error:unknown)=>error instanceof TypeError && (error as TypeError & {code:string}).code==='INVALID_ARGUMENT')
  await assert.rejects(scan(join(project(),'PRIVATE_MISSING_ROOT')),(error:unknown)=>{
    assert.equal((error as {code:string}).code,'SCAN_ROOT_UNAVAILABLE')
    assert.doesNotMatch(String(error),/PRIVATE_MISSING_ROOT/)
    return true
  })
})
test('output failure overrides the terminal exit label even with best-effort',()=>{
  const root=project();const path=join(root,'index.ts');const original=readFileSync(path,'utf8')
  for(const flags of [[],['--best-effort']]){
    const run=cli(root,`--report=${path}`,...flags)
    assert.equal(run.status,3)
    assert.match(run.stdout,/exit 3 · report output failed/)
    assert.doesNotMatch(run.stdout,/exit 0/)
    assert.match(run.stderr,/\[OUTPUT_WRITE_FAILED\]/)
    assert.equal(readFileSync(path,'utf8'),original)
  }
})
test('output failure preserves machine-readable scan output',()=>{
  const root=project();const run=cli(root,'--json',`--report=${join(root,'index.ts')}`)
  assert.equal(run.status,3)
  assert.equal(JSON.parse(run.stdout).schemaVersion,1)
  assert.match(run.stderr,/\[OUTPUT_WRITE_FAILED\]/)
})
test('conflicting output destinations are refused before files are created',()=>{
  const root=project();const target=join(root,'report.json')
  const run=cli(root,`--sarif=${target}`,`--report=${target}`)
  assert.equal(run.status,3)
  assert.match(run.stderr,/\[INVALID_ARGUMENT\]/)
  assert.equal(existsSync(target),false)
})
