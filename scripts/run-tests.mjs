/** 显式发现测试文件，避免不同终端或 Node 版本的通配符差异导致空测试通过。 */

import { readdirSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = resolve(fileURLToPath(new URL('..', import.meta.url)))
const testDir = join(root, 'test')

/** 递归收集测试目录中的测试文件。 */
function findTests(dir) {
  const found = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    // 夹具仅作输入，不执行其中的模拟项目代码。
    if (entry.isDirectory()) {
      if (entry.name === 'fixtures' || entry.name === 'node_modules') continue
      found.push(...findTests(join(dir, entry.name)))
    } else if (entry.name.endsWith('.test.ts')) {
      found.push(join(dir, entry.name))
    }
  }
  return found
}

if (!existsSync(testDir)) {
  process.stderr.write(`run-tests: no test directory at ${testDir}\n`)
  process.exit(1)
}

const files = findTests(testDir).sort()

if (files.length === 0) {
  process.stderr.write(
    'run-tests: found no *.test.ts files under test/.\n' +
      'Refusing to report success for a run that executed nothing.\n',
  )
  process.exit(1)
}

process.stdout.write(`run-tests: ${files.length} test file(s)\n`)

const result = spawnSync(
  process.execPath,
  ['--import', 'tsx', '--test', ...files],
  { stdio: 'inherit', cwd: root },
)

if (result.error) {
  process.stderr.write(`run-tests: ${result.error.message}\n`)
  process.exit(1)
}

process.exit(result.status ?? 1)
