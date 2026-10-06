/** 文件输出只能更新工具自有文件，失败不破坏已有内容。 */
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync, mkdirSync, symlinkSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { writeOutput } from '../src/output.js'

const root=mkdtempSync(join(tmpdir(),'canship-output-boundary-'))
after(()=>rmSync(root,{recursive:true,force:true}))
const html='<title>canship report</title><script id="canship-data"></script>'
test('new output is created and tool-owned output can be replaced atomically',()=>{
  const path=join(root,'report.html')
  writeOutput(path,html,'html')
  writeOutput(path,html+'updated','html')
  assert.equal(readFileSync(path,'utf8'),html+'updated')
  assert.equal(readdirSync(root).some(name=>name.endsWith('.tmp')),false)
})
test('unrelated source, JSON and cross-format outputs are preserved',()=>{
  for(const [name,content,kind] of [['source.ts','export const keep=1;','html'],['settings.json','{"keep":true}','baseline'],['different.json','{"version":3,"entries":[]}','sarif']] as const) {
    const path=join(root,name);writeFileSync(path,content)
    assert.throws(()=>writeOutput(path,html,kind),/Refusing to replace/)
    assert.equal(readFileSync(path,'utf8'),content)
  }
})
test('a linked output target cannot redirect writes',()=>{
  const directory=join(root,'directory');mkdirSync(directory)
  const link=join(root,'link');symlinkSync(directory,link,process.platform==='win32'?'junction':'dir')
  assert.throws(()=>writeOutput(link,html,'html'),/symbolic link/)
  assert.deepEqual(readdirSync(directory),[])
})
test('legacy baseline ownership is recognized without accepting arbitrary JSON',()=>{
  const path=join(root,'legacy.json');writeFileSync(path,'{"version":2,"entries":[]}')
  writeOutput(path,'{"version":3,"entries":[]}','baseline')
  assert.equal(JSON.parse(readFileSync(path,'utf8')).version,3)
})
