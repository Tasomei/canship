/** 验证临时私钥在所有输出中的整块脱敏，不使用账号凭据。 */
import { test, after } from 'node:test'
import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtempSync, writeFileSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { redactAll, redactLine } from '../src/redact.js'

const root = mkdtempSync(join(tmpdir(), 'canship-private-key-output-'))
after(() => rmSync(root, { recursive: true, force: true }))
const pem = generateKeyPairSync('ed25519').privateKey.export({ format: 'pem', type: 'pkcs8' }).toString()
const body = pem.split('\n').filter(line => line && !line.startsWith('-----')).join('')
const cli = fileURLToPath(new URL('../src/cli.ts', import.meta.url))

test('private key bodies are removed before an isolated header can be redacted', () => {
  for (const value of [pem, pem.replaceAll('\n', '\r\n'), JSON.stringify(pem)]) {
    assert.ok(!redactAll(value).includes(body))
    assert.ok(!redactLine(value, pem.split('\n')[0]!).includes(body))
  }
  assert.equal(redactAll('before ' + pem + ' after'), 'before [REDACTED PRIVATE KEY]\n after')
  assert.ok(!redactAll(pem.replace('-----END PRIVATE KEY-----', '')).includes(body))
})

test('multiple private blocks are removed without masking public certificates', () => {
  const certificate = '-----BEGIN CERTIFICATE-----\nPUBLIC_CERTIFICATE\n-----END CERTIFICATE-----'
  const input = pem + certificate + pem
  const output = redactAll(input)
  assert.equal(output.match(/\[REDACTED PRIVATE KEY\]/g)?.length, 2)
  assert.ok(output.includes(certificate))
  assert.ok(!output.includes(body))
  for (const label of ['RSA PRIVATE KEY', 'EC PRIVATE KEY', 'OPENSSH PRIVATE KEY', 'ENCRYPTED PRIVATE KEY', 'PGP PRIVATE KEY BLOCK']) {
    assert.equal(redactAll(`-----BEGIN ${label}-----\nPRIVATE_BODY\n-----END ${label}-----`), '[REDACTED PRIVATE KEY]')
  }
})

test('the CLI never emits a single-line PEM body in terminal, prompt, JSON, HTML or SARIF', () => {
  writeFileSync(join(root, 'key.js'), `const key = ${JSON.stringify(pem)};\n`)
  const html = join(root, 'report.html')
  const sarif = join(root, 'report.sarif')
  for (const options of [[], ['--fix-prompt'], ['--json', `--report=${html}`, `--sarif=${sarif}`]]) {
    const result = spawnSync(process.execPath, ['--import', 'tsx', cli, root, '--only=secrets', ...options], {
      encoding: 'utf8', timeout: 20_000, windowsHide: true,
    })
    assert.equal(result.status, 1)
    assert.ok(!result.stdout.includes(body), 'private key body reached stdout')
    assert.ok(!result.stderr.includes(body), 'private key body reached stderr')
    if (options.includes('--json')) {
      const report = JSON.parse(result.stdout)
      assert.ok(report.findings.some((finding: { ruleId: string }) => finding.ruleId === 'secrets/hardcoded/private-key'))
      for (const path of [html, sarif]) assert.ok(!readFileSync(path, 'utf8').includes(body))
    }
  }
})
