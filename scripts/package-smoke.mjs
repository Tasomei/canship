/** 在隔离目录离线安装实际打包产物，验证发布文件及主要 CLI 契约。 */
import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const version = JSON.parse(readFileSync(join(repository, 'package.json'), 'utf8')).version
const root = mkdtempSync(join(tmpdir(), 'canship-package-smoke-'))
function npm(args, cwd) {
  const executable = process.platform === 'win32' ? process.execPath : 'npm'
  const prefix = process.platform === 'win32' ? [join(dirname(process.execPath), 'node_modules/npm/bin/npm-cli.js')] : []
  const result = spawnSync(executable, [...prefix, ...args], { cwd, encoding: 'utf8', shell: false,
    timeout: 60_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true })
  assert.equal(result.status, 0, 'Package operation failed')
  return result.stdout
}
try {
  const packed = JSON.parse(npm(['pack', '--ignore-scripts', '--json', '--pack-destination', root], repository))[0]
  const expected = ['LICENSE', 'README-zh-CN.md', 'README.md', 'dist/cli.js', 'dist/index.js', 'dist/index.d.ts',
    'package.json', 'schemas/scan-report-v1.schema.json'].sort()
  assert.deepEqual(packed.files.map(file => file.path).sort(), expected)
  const install = join(root, 'installed')
  mkdirSync(install)
  writeFileSync(join(install, 'package.json'), '{"name":"canship-package-check","private":true}')
  npm(['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--package-lock=false', '--no-save', join(root, packed.filename)], install)
  const packageRoot = join(install, 'node_modules/canship')
  const pkg = JSON.parse(readFileSync(join(packageRoot, 'package.json'), 'utf8'))
  assert.equal(pkg.version, version)
  assert.equal(Object.keys(pkg.dependencies ?? {}).length, 0)
  assert.equal(pkg.bin.canship, 'dist/cli.js')
  assert.equal(npm(['exec', '--offline', '--yes=false', '--', 'canship', '--version'], install).trim(), version)
  assert.match(readFileSync(join(packageRoot, 'README.md'), 'utf8'), /A local static scanner/)
  const entry = join(packageRoot, 'dist/cli.js')
  function cli(args) {
    const result = spawnSync(process.execPath, [entry, ...args], { cwd: install, encoding: 'utf8',
      timeout: 30_000, maxBuffer: 8 * 1024 * 1024, windowsHide: true })
    assert.equal(result.error, undefined)
    return result
  }
  assert.equal(cli(['--version']).stdout.trim(), version)
  assert.match(cli(['--help']).stdout, /--no-excerpts/)
  assert.equal(JSON.parse(cli(['--list-rules', '--json']).stdout).kind, 'rule-catalog')
  function sample(name, files) {
    const dir = join(root, name)
    mkdirSync(dir)
    for (const [file, content] of Object.entries(files)) writeFileSync(join(dir, file), content)
    return dir
  }
  const clean = sample('clean', { 'index.ts': 'export const value = 1;' })
  // 从实际安装包按包名导入，验证入口无 CLI 副作用及声明文件可被消费。
  const consumer = join(install, 'consumer.mjs')
  writeFileSync(consumer, `import { scan, summarize, listRules } from 'canship';
import assert from 'node:assert/strict';
const result = await scan(process.argv[2], { noExcerpts: true });
assert.equal(summarize(result).exitCode, 0);
assert.ok(listRules().length > 10);
console.log('API_OK');
`)
  const api = spawnSync(process.execPath, [consumer, clean], { cwd: install, encoding: 'utf8', timeout: 30_000, windowsHide: true })
  assert.equal(api.status, 0, api.stderr)
  assert.equal(api.stdout.trim(), 'API_OK')
  writeFileSync(join(install, 'consumer.mts'), `import { scan, summarize, listRules } from 'canship';
import type { ScanOptions, ScanResult } from 'canship';
const options: ScanOptions = { only: ['firebase'], noExcerpts: true };
const result: ScanResult = await scan('.', options);
const code: 0 | 1 | 2 | 3 = summarize(result).exitCode;
const id: string = listRules()[0]!.id;
void code; void id;
`)
  writeFileSync(join(install, 'tsconfig.json'), JSON.stringify({ compilerOptions: {
    target: 'ES2022', module: 'NodeNext', moduleResolution: 'NodeNext', strict: true, noEmit: true, types: [],
  }, files: ['consumer.mts'] }))
  const types = spawnSync(process.execPath, [join(repository, 'node_modules/typescript/bin/tsc'), '-p', install],
    { cwd: install, encoding: 'utf8', timeout: 30_000, windowsHide: true })
  assert.equal(types.status, 0, types.stdout + types.stderr)
  const cleanResult = cli([clean, '--json'])
  assert.equal(cleanResult.status, 0)
  assert.equal(JSON.parse(cleanResult.stdout).partial, false)
  const open = sample('open', { 'firestore.rules': 'match /items/{id} { allow write: if true; }' })
  assert.equal(cli([open, '--json']).status, 1)
  const readOnly = sample('public-read', { 'firestore.rules': 'match /items/{id} { allow read: if true; }' })
  const hidden = cli([readOnly, '--json'])
  assert.equal(hidden.status, 2)
  assert.equal(JSON.parse(hidden.stdout).hiddenLikely, 1)
  const partial = sample('partial', { 'index.ts': 'export const value = 1;', 'large.ts': ' '.repeat(2 * 1024 * 1024 + 1) })
  assert.equal(cli([partial, '--json']).status, 3)
  const accepted = cli([partial, '--json', '--best-effort'])
  assert.equal(accepted.status, 0)
  assert.equal(JSON.parse(accepted.stdout).partial, true)
  assert.equal(cli([open, '--baseline-write']).status, 0)
  const baseline = cli([open, '--json', '--baseline'])
  assert.equal(baseline.status, 0)
  assert.equal(JSON.parse(baseline.stdout).baselineSuppressed, 1)
  const privateExcerpt = sample('excerpt', { 'cors.ts': "const note='PRIVATE_SMOKE_SENTINEL'; app.use(cors({origin:true,credentials:true}));" })
  const html = join(root, 'report.html')
  const sarif = join(root, 'report.sarif')
  const report = cli([privateExcerpt, '--json', '--no-excerpts', `--report=${html}`, `--sarif=${sarif}`])
  assert.equal(report.status, 1)
  assert.equal(JSON.parse(report.stdout).excerptsOmitted, true)
  for (const text of [report.stdout, readFileSync(html, 'utf8'), readFileSync(sarif, 'utf8')]) assert.doesNotMatch(text, /PRIVATE_SMOKE_SENTINEL/)
  assert.equal(JSON.parse(readFileSync(sarif, 'utf8')).version, '2.1.0')
  console.log(JSON.stringify({ version, packageFiles: expected.length, runtimeDependencies: 0, smoke: 'passed' }))
} finally {
  // 仅移除本次创建的隔离安装与样本目录。
  rmSync(root, { recursive: true, force: true })
}
