/** 隔离进程拦截网络及写入 API，验证默认扫描的权限边界。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'

const root=mkdtempSync(join(tmpdir(),'canship-permissions-'))
after(()=>rmSync(root,{recursive:true,force:true}))
test('default scan makes no network calls, executes no project scripts and changes no files',()=>{
  writeFileSync(join(root,'package.json'),JSON.stringify({scripts:{preinstall:'exit 77',prepare:'exit 88'}}))
  writeFileSync(join(root,'index.ts'),'throw new Error("PROJECT_CODE_MUST_NOT_EXECUTE");')
  const before=readdirSync(root).map(name=>[name,readFileSync(join(root,name),'utf8')])
  const source=`
    import {scan} from './src/index.ts';
    import fs from 'node:fs';import fsp from 'node:fs/promises';
    import net from 'node:net';import tls from 'node:tls';import http from 'node:http';import https from 'node:https';import dns from 'node:dns';
    import cp from 'node:child_process';import {syncBuiltinESMExports} from 'node:module';import {basename} from 'node:path';
    let forbidden=0;const deny=()=>{forbidden++;throw new Error('FORBIDDEN_CAPABILITY')};
    globalThis.fetch=deny;
    for(const [object,names] of [[net,['connect','createConnection']],[tls,['connect']],[http,['request','get']],[https,['request','get']],[dns,['lookup','resolve']],
      [fs,['writeFileSync','appendFileSync','renameSync','unlinkSync','mkdirSync','rmSync','copyFileSync']],
      [fsp,['writeFile','appendFile','rename','unlink','mkdir','rm','copyFile']],
      [cp,['exec','execSync','execFile','spawn','spawnSync']]])for(const name of names)object[name]=deny;
    const original=cp.execFileSync;cp.execFileSync=(file,args,...rest)=>{
      if(!['git','git.exe'].includes(basename(file).toLowerCase())||!args.some(arg=>['--version','rev-parse','ls-files','log','show','status'].includes(arg)))return deny();
      return original(file,args,...rest);
    };
    syncBuiltinESMExports();
    const result=await scan(process.argv[1]);
    if(forbidden||result.partial||result.filesScanned!==2)process.exitCode=1;
    console.log(JSON.stringify({forbidden,partial:result.partial}));`
  const checked=spawnSync(process.execPath,['--import','tsx','--input-type=module','-e',source,root],{encoding:'utf8',timeout:30000})
  assert.equal(checked.status,0,checked.stderr+checked.stdout)
  assert.equal(JSON.parse(checked.stdout).forbidden,0)
  assert.deepEqual(readdirSync(root).map(name=>[name,readFileSync(join(root,name),'utf8')]),before)
})
