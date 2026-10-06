/** 旧格式迁移仅保留原接受额度，不接受新问题，不改原文件。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { applyBaseline, buildBaseline, fingerprintOf, legacyFingerprintOf, migrateBaseline, readBaseline } from '../src/baseline.js'
import { scan } from '../src/engine.js'
import type { Finding } from '../src/types.js'
import type { BaselineFile } from '../src/baseline.js'

const roots: string[]=[]
after(()=>{for(const root of roots)rmSync(root,{recursive:true,force:true})})
const finding=(over:Partial<Finding>={}):Finding=>({ruleId:'api/db-write-without-auth',file:'src/a.ts',line:1,title:'Original wording',
  severity:'P1',confidence:'likely',excerpt:null,sourceFingerprint:'source-a',why:[],fix:[],...over})
const legacy=(f:Finding,count=1):BaselineFile=>({version:2,generatedAt:'',entries:[{fingerprint:legacyFingerprintOf(f),ruleId:f.ruleId,file:f.file,title:f.title,count}]})

test('v3 identity survives title, language and line changes',()=>{
  assert.equal(fingerprintOf(finding()),fingerprintOf(finding({title:'新的文案',line:80})))
  assert.notEqual(fingerprintOf(finding()),fingerprintOf(finding({sourceFingerprint:'source-b'})))
})
test('v2 remains readable and matches its original evidence after wording changes',()=>{
  const f=finding({title:'New wording'})
  assert.equal(applyBaseline([f],legacy(finding())).suppressed,1)
  assert.equal(applyBaseline([finding({sourceFingerprint:'source-b'})],legacy(finding())).suppressed,0)
})
test('migration accepts no newly discovered evidence and preserves duplicate budgets',()=>{
  const old=finding()
  const migrated=migrateBaseline([old,old,finding({sourceFingerprint:'source-b'})],legacy(old))
  assert.equal(migrated.version,4)
  assert.equal(migrated.entries.reduce((n,e)=>n+e.count,0),1)
  assert.equal(applyBaseline([old,old],migrated).kept.length,1)
})
test('stale legacy entries cause migration to fail instead of disappearing',()=>{
  assert.throws(()=>migrateBaseline([],legacy(finding())),/all accepted entries to match/)
})
test('v3 baseline metadata still discloses rule, path and title without excerpts',()=>{
  const built=buildBaseline([finding()])
  assert.equal(built.entries[0]!.title,'Original wording')
  assert.doesNotMatch(JSON.stringify(built),/source-a|excerpt/)
})
test('CLI migration prints JSON, leaves the source unchanged and accepts no new findings',async()=>{
  const root=mkdtempSync(join(tmpdir(),'canship-migrate-'));roots.push(root)
  writeFileSync(join(root,'firestore.rules'),'match /items/{id} { allow write: if true; }')
  const first=(await scan(root)).findings[0]!
  const path=join(root,'accepted.json');const original=JSON.stringify(legacy(first))
  writeFileSync(path,original)
  writeFileSync(join(root,'storage.rules'),'match /other/{id} { allow write: if true; }')
  const run=spawnSync(process.execPath,['--import','tsx','src/cli.ts',root,`--baseline-migrate=${path}`],{encoding:'utf8'})
  assert.equal(run.status,0,run.stderr)
  const upgraded=JSON.parse(run.stdout)
  assert.equal(upgraded.version,4)
  assert.equal(upgraded.entries.reduce((n:number,e:{count:number})=>n+e.count,0),1)
  assert.equal(readFileSync(path,'utf8'),original)
  assert.equal(readBaseline(path).version,2)
  assert.match(run.stderr,/1 current findings remain unaccepted/)
  for(const option of ['--json','--baseline-write','--best-effort','--only=firebase']) {
    const invalid=spawnSync(process.execPath,['--import','tsx','src/cli.ts',root,`--baseline-migrate=${path}`,option],{encoding:'utf8'})
    assert.equal(invalid.status,3)
    assert.equal(invalid.stdout,'')
  }
})
