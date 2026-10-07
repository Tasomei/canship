/** 插件独立打包，不把 VS Code 宿主依赖带入 npm 扫描器。 */
import { build } from 'tsup'
import { readFileSync } from 'node:fs'
import { dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { getBuildInfo } from '../dist/index.js'

process.chdir(dirname(dirname(fileURLToPath(import.meta.url))))

const manifest = JSON.parse(readFileSync(new URL('../extensions/vscode/package.json', import.meta.url), 'utf8'))
if (manifest.main !== './dist/extension.cjs') throw new Error('Unexpected extension entry point.')
const identity = getBuildInfo()
await build({ config: false, entry: { extension: 'extensions/vscode/src/extension.ts', worker: 'extensions/vscode/src/worker.ts' },
  format: ['cjs'], target: 'node18', outDir: 'extensions/vscode/dist', bundle: true, splitting: false, clean: true,
  dts: false, sourcemap: false, minify: false, external: ['vscode'],
  define: { __CANSHIP_VERSION__: JSON.stringify(identity.version), __CANSHIP_BUILD_INFO__: JSON.stringify(identity) } })
