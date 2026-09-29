import { test } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { collectFiles } from '../src/walker.js'

test('unknown file probes obey the shared read budget', () => {
  const root = fs.mkdtempSync(join(tmpdir(), 'canship-probe-budget-'))
  const original = fs.readSync
  let calls = 0
  let bytes = 0
  try {
    for (let i = 0; i < 24; i++) fs.writeFileSync(join(root, `${i}.custom`), 'x'.repeat(64))
    fs.readSync = ((...args: Parameters<typeof fs.readSync>) => {
      calls++
      const read = original(...args)
      bytes += read
      return read
    }) as typeof fs.readSync
    syncBuiltinESMExports()
    const tiny = collectFiles(root, false, null, { maxBytes: 1, maxFiles: 1 })
    assert.equal(calls, 0)
    assert.equal(bytes, 0)
    assert.equal(tiny.files.length, 0)
    assert.match(tiny.skipped[0]!.detail!, /scan read budget exceeded/)
    const one = collectFiles(root, false, null, { maxFiles: 1 })
    assert.equal(calls, 2)
    assert.equal(bytes, 128)
    assert.equal(one.files.length, 1)
    assert.match(one.skipped[0]!.detail!, /scan read budget exceeded/)
    calls = 0
    bytes = 0
    const exact = collectFiles(root, false, null, { maxBytes: 128 })
    assert.equal(exact.files.length, 1)
    assert.equal(calls, 2)
    assert.equal(bytes, 128)
    assert.match(exact.skipped[0]!.detail!, /scan read budget exceeded/)
  } finally {
    fs.readSync = original
    syncBuiltinESMExports()
    fs.rmSync(root, { recursive: true, force: true })
  }
})

test('binary probes count toward the file budget', () => {
  const root = fs.mkdtempSync(join(tmpdir(), 'canship-binary-budget-'))
  try {
    for (let i = 0; i < 4; i++) fs.writeFileSync(join(root, `${i}.custom`), Buffer.alloc(64))
    const result = collectFiles(root, false, null, { maxFiles: 1 })
    assert.equal(result.files.length, 0)
    assert.equal(result.skipped.length, 1)
    assert.match(result.skipped[0]!.detail!, /scan read budget exceeded/)
  } finally { fs.rmSync(root, { recursive: true, force: true }) }
})

test('a short budget reads credential files, then source, before unknown-type probes', () => {
  const root = fs.mkdtempSync(join(tmpdir(), 'canship-budget-order-'))
  try {
    // 名称按字母序会让未知类型排在前面，确保顺序来自优先级而不是遍历顺序。
    for (const name of ['a.custom', 'b.custom']) fs.writeFileSync(join(root, name), 'text')
    fs.writeFileSync(join(root, 'z.ts'), 'export {}')
    fs.writeFileSync(join(root, '.env'), 'TOKEN=value')
    for (const [maxFiles, expected] of [[1, ['.env']], [2, ['.env', 'z.ts']]] as const) {
      const result = collectFiles(root, false, null, { maxFiles })
      assert.deepEqual(result.files.map(file => file.path), expected)
      assert.equal(result.skipped.length, 1)
      assert.match(result.skipped[0]!.detail!, /scan read budget exceeded/)
    }
  } finally { fs.rmSync(root, { recursive: true, force: true }) }
})

test('directory discovery accepts the exact entry limit and discloses truncation', () => {
  const root = fs.mkdtempSync(join(tmpdir(), 'canship-entry-budget-'))
  try {
    for (let i = 0; i < 3; i++) fs.writeFileSync(join(root, `${i}.ts`), 'export {}')
    const exact = collectFiles(root, false, null, { maxEntries: 3 })
    assert.equal(exact.files.length, 3)
    assert.deepEqual(exact.skipped, [])
    const limited = collectFiles(root, false, null, { maxEntries: 2 })
    assert.equal(limited.files.length, 2)
    assert.equal(limited.skipped.length, 1)
    assert.match(limited.skipped[0]!.detail!, /directory entry budget exceeded/)
  } finally { fs.rmSync(root, { recursive: true, force: true }) }
})

test('oversized extensionless binary files need only a budgeted probe', () => {
  const root = fs.mkdtempSync(join(tmpdir(), 'canship-large-binary-'))
  try {
    fs.writeFileSync(join(root, 'blob'), Buffer.alloc(2 * 1024 * 1024 + 1))
    const exact = collectFiles(root, false, null, { maxBytes: 4096 })
    assert.equal(exact.files.length, 0)
    assert.deepEqual(exact.skipped, [])
    const limited = collectFiles(root, false, null, { maxBytes: 4095 })
    assert.equal(limited.files.length, 0)
    assert.equal(limited.skipped.length, 1)
    assert.match(limited.skipped[0]!.detail!, /scan read budget exceeded/)
  } finally { fs.rmSync(root, { recursive: true, force: true }) }
})
