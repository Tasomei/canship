/** 终端适配保持信息和命令完整；Shell 验收只解析合成参数或调用无副作用的替身。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { renderReport } from '../src/report/terminal.js'
import { followupArgs, followupCommand } from '../src/report/commands.js'
import { visibleWidth } from '../src/report/columns.js'
import type { Finding, ScanResult } from '../src/types.js'

const item: Finding = { ruleId: 'api/db-write-without-auth', severity: 'P1', confidence: 'certain',
  title: 'Database writes need authentication', file: 'api.ts', line: 12, excerpt: null,
  why: ['Review the caller before changing stored data.'], fix: ['Reject requests without a valid user.'] }
const result = (overrides: Partial<ScanResult> = {}): ScanResult => ({ findings: [item], filesScanned: 1, durationMs: 1,
  partial: false, errors: [], skipped: [], ignored: [], ignoredFindings: [], ruleSelection: null, vendored: 0, ...overrides })
const plain = (text: string) => text.replace(new RegExp(`${String.fromCharCode(27)}\\[[0-9;]*m`, 'g'), '')

test('24 to 48 column reports keep prose and counts inside the requested width', () => {
  for (const width of [24, 32, 40, 48]) {
    const output = plain(renderReport(result(), { root: '.', showingLikely: true, hiddenLikely: 0, exitCode: 1, width }))
    // 可复制命令保持单一逻辑行，由终端软换行。
    const overflow = output.split('\n').filter(line => !line.includes('npx canship') && line.length > width)
    assert.deepEqual(overflow, [], `overflow at ${width}`)
    assert.match(output.replace(/\s+/g, ' '), /Database writes need authentication/)
    assert.ok(output.includes('P1') && output.includes('12') && output.includes('exit 1'))
  }
})

test('invalid terminal widths cannot crash or erase a report', () => {
  for (const width of [NaN, Infinity, -Infinity, -1, 0, 24.5]) {
    const output = plain(renderReport(result(), { root: '.', showingLikely: true, hiddenLikely: 0, width }))
    assert.match(output.replace(/\s+/g, ' '), /Database writes need authentication/)
    assert.ok(output.length < 10000)
  }
})

test('long Chinese paths, excerpts and commands remain intact at narrow widths', () => {
  const path = '项目/这是保留完整文字的长目录名称/接口.ts'
  const excerpt = 'const unchanged = "合成代码示例，不应截断或改写"'
  const args = [path, '--only=api,cors', '--no-excerpts']
  const output = plain(renderReport(result({ findings: [{ ...item, file: path, excerpt }] }),
    { root: path, showingLikely: true, hiddenLikely: 0, verbose: true, width: 32, rerunArgs: args }))
  assert.ok(output.includes(path))
  assert.ok(output.includes(excerpt))
  assert.ok(output.includes(followupCommand(args, ['--report', '--open'])))
  assert.equal(output.includes('…'), false)
})

test('PowerShell commands quote argument arrays, splatting and smart single quotes', () => {
  const command = followupCommand(['@project', '--only=api,cors', './设计‘稿’'], [], 'win32')
  assert.equal(command, "npx canship '@project' '--only=api,cors' './设计‘‘稿’’'")
})

test('generated commands round-trip through the platform shell without invoking npm', () => {
  const args = ['@project', '--only=api,cors', './中文 空格', "./O'Brien", './设计‘稿’', './低引号\u201a反引号\u201b', './$(literal);value', '--no-excerpts']
  assert.deepEqual(followupArgs(args), args)
  const command = followupCommand(args, ['--verbose'])
  if (process.platform === 'win32') {
    // 只读 AST；拒绝表达式、变量和额外命令，绝不执行待测字符串。
    const script = `[Console]::InputEncoding=[System.Text.UTF8Encoding]::new($false)
      [Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
      $tokens=$null; $issues=$null
      $ast=[System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(),[ref]$tokens,[ref]$issues)
      if($issues.Count){throw 'Invalid command syntax'}
      $commands=@($ast.FindAll({param($node) $node -is [System.Management.Automation.Language.CommandAst]},$true))
      if($commands.Count -ne 1){throw 'Unexpected command count'}
      $values=@(foreach($element in $commands[0].CommandElements){
        if($element -is [System.Management.Automation.Language.StringConstantExpressionAst]){$element.Value}
        elseif($element -is [System.Management.Automation.Language.CommandParameterAst] -and $null -eq $element.Argument){$element.Extent.Text}
        else{throw 'Argument is not a literal'}
      })
      ConvertTo-Json -InputObject $values -Compress`
    const parsed = spawnSync('pwsh', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script],
      { input: command, encoding: 'utf8', timeout: 15000, windowsHide: true })
    assert.equal(parsed.status, 0, parsed.stderr)
    assert.deepEqual(JSON.parse(parsed.stdout), ['npx', 'canship', ...args, '--verbose'])
  } else {
    // POSIX 平台调用只输出参数的函数，不查找真实 npx。
    const parsed = spawnSync('/bin/sh', ['-c', `npx() { printf '%s\\0' "$@"; }; ${command}`], { encoding: 'utf8', timeout: 15000 })
    assert.equal(parsed.status, 0, parsed.stderr)
    assert.deepEqual(parsed.stdout.split('\0').slice(0, -1), ['canship', ...args, '--verbose'])
  }
})

test('FORCE_COLOR=0 keeps redirected output free of ANSI sequences', () => {
  const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e',
    "import {red} from './src/colors.ts';process.stdout.write(red('plain'));"],
  { encoding: 'utf8', env: { ...process.env, NO_COLOR: '', FORCE_COLOR: '0' }, timeout: 15000 })
  assert.equal(child.status, 0, child.stderr)
  assert.equal(child.stdout, 'plain')
})

test('common CJK characters and grapheme clusters use display columns rather than UTF-16 length', () => {
  for (const [text, columns] of [['abc', 3], ['中文', 4], ['かな', 4], ['한글', 4], ['Ａ１', 4], ['ｶﾅ', 2],
    ['e\u0301', 1], ['👩‍💻', 2], ['🇨🇳', 2], ['1️⃣', 2], ['a\tb', 9], [String.fromCharCode(27) + '[31m中文' + String.fromCharCode(27) + '[0m', 4]] as const) {
    assert.equal(visibleWidth(text), columns)
  }
  const title = '中文报告 '.repeat(12).trim()
  const output = plain(renderReport(result({ findings: [{ ...item, title }] }), { root: '.', showingLikely: true, hiddenLikely: 0, width: 32 }))
  assert.deepEqual(output.split('\n').filter(line => !line.includes('npx canship') && visibleWidth(line) > 32), [])
  assert.equal((output.match(/中文报告/g) ?? []).length, 12)
})

test('empty, hidden, baseline and incomplete verdicts remain readable on narrow terminals', () => {
  for (const state of ['empty', 'hidden', 'baseline', 'incomplete']) {
    const scan = result({ findings: [], filesScanned: state === 'empty' ? 0 : 1, partial: state === 'incomplete',
      errors: state === 'incomplete' ? [{ kind: 'incomplete', ruleId: 'example/check', file: null, message: 'Synthetic check could not complete.' }] : [] })
    const output = plain(renderReport(scan, { root: '.', showingLikely: false, hiddenLikely: state === 'hidden' ? 2 : 0,
      baselineSuppressed: state === 'baseline' ? 3 : 0, width: 32 }))
    assert.deepEqual(output.split('\n').filter(line => !line.includes('npx canship') && visibleWidth(line) > 32), [], state)
    assert.doesNotMatch(output, /No findings in enabled checks/)
  }
})

test('narrow follow-up commands occupy their own copyable logical lines', () => {
  const output = plain(renderReport(result(), { root: '.', showingLikely: true, hiddenLikely: 0, width: 24,
    rerunArgs: ['./应用 目录', '--only=api,cors', '--no-excerpts'] }))
  const commands = output.split('\n').filter(line => line.includes('npx canship'))
  assert.ok(commands.length > 0)
  assert.ok(commands.every(line => line.startsWith('npx canship')))
})

test('the actual CLI preserves Chinese targets and keeps redirected JSON free of terminal formatting', () => {
  const root = mkdtempSync(join(tmpdir(), 'canship-中文‘目录’,样例-'))
  const env: NodeJS.ProcessEnv = { ...process.env, NO_COLOR: '1' }
  delete env.FORCE_COLOR
  try {
    writeFileSync(join(root, '应用.ts'), 'export const sample = true;\n')
    const script = `Object.defineProperty(process.stdout,'isTTY',{value:true});Object.defineProperty(process.stdout,'columns',{value:32});
      process.argv=['node','canship',${JSON.stringify(root)},'--no-progress','--no-excerpts'];await import('./src/cli.ts');`
    const terminal = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', script], { encoding: 'utf8', env, timeout: 30000 })
    assert.equal(terminal.status, 0, terminal.stderr)
    assert.equal(terminal.stderr, '')
    assert.ok(terminal.stdout.includes(root))
    assert.ok(terminal.stdout.includes(followupCommand([root, '--no-progress', '--no-excerpts'], ['--report', '--open'])))
    assert.doesNotMatch(terminal.stdout, new RegExp(String.fromCharCode(27)))
    const json = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli.ts', root, '--json', '--no-excerpts'],
      { encoding: 'utf8', env, timeout: 30000 })
    assert.equal(json.status, 0, json.stderr)
    assert.equal(json.stderr, '')
    const report = JSON.parse(json.stdout)
    assert.equal(report.filesScanned, 1)
    assert.equal(report.partial, false)
    assert.deepEqual(report.findings, [])
  } finally { rmSync(root, { recursive: true, force: true }) }
})

test('NO_COLOR retains priority when forced colors are also configured', () => {
  const child = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e',
    "import {red} from './src/colors.ts';process.stdout.write(red('plain'));"],
  { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1', FORCE_COLOR: '1' }, timeout: 15000 })
  assert.equal(child.status, 0, child.stderr)
  assert.equal(child.stdout, 'plain')
})

test('large line numbers and likely badges have reserved space without losing title words', () => {
  for (const width of [24, 40, 60, 80]) {
    const output = plain(renderReport(result({ findings: [{ ...item, line: 1234567, confidence: 'likely', title: 'item '.repeat(30).trim() }] }),
      { root: '.', showingLikely: true, hiddenLikely: 0, width }))
    assert.deepEqual(output.split('\n').filter(line => !line.includes('npx canship') && visibleWidth(line) > width), [], String(width))
    assert.equal((output.match(/item/g) ?? []).length, 30)
    assert.ok(output.includes('1234567') && output.includes('likely'))
  }
})

test('narrow category summaries retain aggregate counts for every severity', () => {
  const output = plain(renderReport(result({ findings: [item, { ...item, ruleId: 'secrets/hardcoded/openai', severity: 'P0' }] }),
    { root: '.', showingLikely: true, hiddenLikely: 0, width: 24 }))
  const totals = output.slice(output.indexOf('\nall\n')).split('─')[0]!
  for (const count of ['P0 1', 'P1 1', 'P2 0', 'total 2']) assert.ok(totals.includes(count), count)
})
