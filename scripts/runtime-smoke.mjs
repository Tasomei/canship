/** 在 package.json 声明支持的较旧 Node 版本上运行已构建的 CLI；构建与完整测试仍使用当前 Node。 */
import assert from 'node:assert/strict'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { tmpdir } from 'node:os'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const repository = dirname(dirname(fileURLToPath(import.meta.url)))
const cli = join(repository, 'dist/cli.js')
const { version } = JSON.parse(readFileSync(join(repository, 'package.json'), 'utf8'))

function run(args) {
  const result = spawnSync(process.execPath, [cli, ...args], { cwd: repository, encoding: 'utf8',
    timeout: 60_000, maxBuffer: 16 * 1024 * 1024, windowsHide: true, env: { ...process.env, NO_COLOR: '1' } })
  assert.equal(result.error, undefined)
  return result
}

const clean = mkdtempSync(join(tmpdir(), 'canship-runtime-smoke-'))
try {
  assert.equal(run(['--version']).stdout.trim(), version)

  // 存在阻断结果时退出码为 1，JSON 完整且覆盖完整。
  const vulnerable = run([join(repository, 'test/fixtures/vulnerable-nextjs'), '--json', '--no-excerpts'])
  assert.equal(vulnerable.status, 1)
  const report = JSON.parse(vulnerable.stdout)
  assert.equal(report.partial, false)
  assert.ok(report.findings.some(f => f.ruleId === 'exposure/supabase-service-role-in-client'))

  writeFileSync(join(clean, 'package.json'), '{"name":"runtime-smoke"}\n')
  writeFileSync(join(clean, 'index.ts'), 'export const ready = true\n')
  assert.equal(run([clean]).status, 0)

  // 探测预览不发起网络请求。
  const plan = run(['--probe=https://app.example.com/status', '--json'])
  assert.equal(plan.status, 0)
  assert.equal(JSON.parse(plan.stdout).networkPerformed, false)

  process.stdout.write(`runtime smoke passed on Node ${process.versions.node}\n`)
} finally {
  rmSync(clean, { recursive: true, force: true })
}
