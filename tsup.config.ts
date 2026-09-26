import { defineConfig } from 'tsup'
import { readFileSync } from 'node:fs'

/** 构建版本统一读取包信息。 */
const { version } = JSON.parse(readFileSync('./package.json', 'utf8')) as { version: string }

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
  define: { __CANSHIP_VERSION__: JSON.stringify(version) },
  // 可执行入口需要解释器声明。
  banner: { js: '#!/usr/bin/env node' },
})
