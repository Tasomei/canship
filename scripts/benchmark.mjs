/** 固定合成规模的性能门槛；只输出统计，不输出目录或源码。 */
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { performance } from 'node:perf_hooks'
import { scan, summarize } from '../dist/index.js'

const root=mkdtempSync(join(tmpdir(),'canship-benchmark-'))
try {
  for(let i=0;i<250;i++)writeFileSync(join(root,`module-${i}.ts`),`export const value${i} = ${i};\n`)
  const samples=[]
  for(let run=0;run<3;run++){
    const started=performance.now()
    const result=await scan(root)
    if(result.filesScanned!==250||summarize(result).exitCode!==0)throw new Error('Benchmark scan contract failed.')
    samples.push(Math.round(performance.now()-started))
  }
  const median=[...samples].sort((a,b)=>a-b)[1]
  console.log(JSON.stringify({files:250,runs:3,medianMs:median,maxAllowedMs:15000,heapMiB:Math.round(process.memoryUsage().heapUsed/1024/1024)}))
  if(median>15000)process.exitCode=1
} finally {
  // 仅清理本次创建的合成项目。
  rmSync(root,{recursive:true,force:true})
}
