/** 构建身份和能力查询不读取目标项目，也不暴露机器信息。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { classifyBuild, getBuildInfo, getCapabilities } from '../src/build-info.js'
import { spawnSync } from 'node:child_process'

const revision='a'.repeat(40)
test('only a clean matching version tag identifies a release',()=>{
  assert.equal(classifyBuild('1.0.0',revision,revision,false).channel,'release')
  assert.equal(classifyBuild('1.0.0-rc.1',revision,revision,false).channel,'prerelease')
  for(const [tag,dirty] of [[null,false],[revision,true],[revision,null]] as const)
    assert.equal(classifyBuild('1.0.0',revision,tag,dirty).channel,'development')
})
test('unknown sources are development builds without arbitrary identifiers',()=>{
  const info=classifyBuild('1.0.0','PRIVATE_MACHINE_SENTINEL',null,null)
  assert.equal(info.revision,null)
  assert.doesNotMatch(JSON.stringify(info),/PRIVATE_MACHINE_SENTINEL/)
})
test('callers cannot alter shared build identity or capabilities',()=>{
  const info=getBuildInfo();info.channel='release'
  assert.equal(getBuildInfo().channel,'development')
  const capabilities=getCapabilities();capabilities.staticScan.network=true
  assert.equal(getCapabilities().staticScan.network,false)
})
test('build-info is independent of scan options and has a distinct JSON kind',()=>{
  const run=(args:string[])=>spawnSync(process.execPath,['--import','tsx','src/cli.ts',...args],{encoding:'utf8'})
  const output=run(['--build-info','--json'])
  assert.equal(output.status,0,output.stderr)
  const info=JSON.parse(output.stdout)
  assert.equal(info.kind,'build-info')
  assert.equal(info.channel,'development')
  assert.equal(info.capabilities.staticScan.network,false)
  assert.equal(run(['--build-info','--report']).status,3)
})
