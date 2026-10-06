import { defineConfig } from 'tsup'
import { readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { classifyBuild } from './src/build-info.js'

/** 构建版本统一读取包信息。 */
const { version } = JSON.parse(readFileSync('./package.json', 'utf8')) as { version: string }
const git = (args: string[]): string | null => {
  const result = spawnSync('git', args, {encoding:'utf8',timeout:5000,maxBuffer:1024*1024,windowsHide:true})
  return result.status === 0 ? result.stdout.trim() : null
}
const status = git(['status','--porcelain','--untracked-files=no'])
const identity = classifyBuild(version, git(['rev-parse','HEAD']), git(['rev-parse','--verify',`refs/tags/v${version}^{}`]), status === null ? null : status !== '')

export default defineConfig({
  entry: ['src/cli.ts', 'src/index.ts'],
  dts: { entry: 'src/index.ts' },
  format: ['esm'],
  target: 'node18',
  // 合并为单文件以减少下载及启动成本。
  bundle: true,
  splitting: false,
  clean: true,
  minify: false,
  sourcemap: false,
  define: { __CANSHIP_VERSION__: JSON.stringify(version), __CANSHIP_BUILD_INFO__: JSON.stringify(identity) },
  // 可执行入口需要解释器声明。
  banner: { js: '#!/usr/bin/env node' },
})
