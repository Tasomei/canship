/**
 * Test runner.
 *
 * This exists because `node --import tsx --test test/**\/*.test.ts` was a
 * publish gate that could pass without running anything.
 *
 * Three layers had to line up for that to work, and they did not:
 *   - `sh` does not expand `**`; it degrades to `*`, and `test/*\/*.test.ts`
 *     does not match a file sitting directly in `test/`.
 *   - `cmd.exe` does not expand globs at all.
 *   - So the pattern reached node verbatim — and node only learned to treat a
 *     positional argument as a glob after v20, which documents them as
 *     "one or more paths".
 *
 * On Node 20 the pattern was therefore a path, no such path existed, and the
 * runner reported `tests 0` and exited **0**. Two of the six CI cells were
 * green without executing a single assertion, and `prepublishOnly` runs this
 * same script — so the one gate standing between a broken build and the
 * registry could wave it through.
 *
 * Finding the files here removes every one of those variables: no shell
 * expansion, no version-dependent glob, and an empty result is a failure
 * rather than a pass. That last part is the point. A test command that cannot
 * distinguish "everything passed" from "nothing ran" is the same bug canship
 * exits 3 to avoid, sitting in canship's own toolchain.
 */

import { readdirSync, existsSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const root = resolve(fileURLToPath(new URL('..', import.meta.url)))
const testDir = join(root, 'test')

/** Every *.test.ts under test/, at any depth */
function findTests(dir) {
  const found = []
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    // Fixtures are inputs to the tests, not tests. They also contain
    // deliberately broken code that must never be executed.
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
