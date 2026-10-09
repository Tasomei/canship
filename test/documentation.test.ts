/** 首页保持简短，完整参数、离线引用及双语示例不得因拆分而丢失。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, statSync } from 'node:fs'
import { dirname, resolve, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../', import.meta.url))
const read = (file: string) => readFileSync(resolve(root, file), 'utf8')
const pages = ['README.md', 'README-zh-CN.md', 'docs/reference.md', 'docs/reference-zh-CN.md',
  'docs/framework-support.md', 'docs/framework-support-zh-CN.md']
const anchors = (text: string) => [...text.matchAll(/^#{1,6} (.+)$/gm)].map(match => match[1]!.trim().toLowerCase()
  .replace(/[^\p{L}\p{N}\p{M}\s_-]/gu, '').replace(/\s/g, '-'))

test('documentation links resolve to real package files and section anchors', () => {
  for (const page of pages) {
    const markdown = read(page)
    for (const match of markdown.matchAll(/\]\((\.[^\s)]*)\)/g)) {
      const [path, fragment] = match[1]!.split('#')
      const target = resolve(root, dirname(page), path!)
      const local = relative(root, target)
      assert.ok(local !== '..' && !local.startsWith('..' + sep), `${page} escapes package`)
      assert.equal(statSync(target).isFile(), true, `${page} links to a missing file`)
      if (fragment) assert.ok(anchors(readFileSync(target, 'utf8')).includes(decodeURIComponent(fragment)), `${page}: missing anchor ${fragment}`)
    }
  }
})

test('English and Chinese entry points preserve identical commands and visible screenshots', () => {
  const en = read('README.md'), zh = read('README-zh-CN.md')
  const version: string = JSON.parse(read('package.json')).version
  const commands = (text: string) => [...text.matchAll(/^```(?:powershell|yaml)\r?\n([\s\S]*?)^```/gm)].map(match => match[1]!.replace(/\r/g, ''))
  assert.equal(commands(en).length, 6)
  assert.deepEqual(commands(en), commands(zh))
  assert.deepEqual(commands(en).slice(0, 5), ['', ' "./my-app"', ' --list-rules', ' --all --verbose', ' --all --report']
    .map(args => `npx canship@${version}${args}\n`))
  assert.ok(commands(en)[5]!.includes(`version: '${version}'`))
  for (const markdown of [en, zh]) {
    assert.doesNotMatch(markdown, /<details\b/i)
    const images = [...markdown.matchAll(/!\[[^\]]*\]\(([^)]+)\)/g)].map(match => match[1])
    assert.deepEqual(images, ['https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/terminal.png',
      'https://raw.githubusercontent.com/Tasomei/canship/main/docs/images/report.png'])
    assert.ok(markdown.includes(`\`${version}\``) && markdown.includes('`next`'))
    assert.ok(markdown.includes('/blob/v0.7.1/README'))
    assert.ok(markdown.includes('--no-excerpts') && markdown.includes('--best-effort'))
  }
  assert.ok(en.length < 9000 && zh.length < 5000, 'Keep detailed contracts in the linked reference')
})

test('only the selected text references are added to the npm package', () => {
  const files: string[] = JSON.parse(read('package.json')).files
  assert.ok(files.includes('docs/reference.md') && files.includes('docs/reference-zh-CN.md'))
  assert.ok(files.includes('docs/framework-support.md') && files.includes('docs/framework-support-zh-CN.md'))
  assert.ok(!files.includes('docs') && !files.includes('docs/'), 'Do not accidentally package screenshots or development assets')
  const en = read('docs/reference.md'), zh = read('docs/reference-zh-CN.md')
  for (const text of [en, zh]) {
    for (const flag of ['--baseline-migrate', '--baseline-prune', '--probe-canary-sha256', '--workspace', '--compare', '--init=pre-commit']) assert.ok(text.includes(flag), flag)
    for (const kind of ['workspace-report', 'report-comparison', 'share-summary', 'effective-config']) assert.ok(text.includes(kind), kind)
    assert.ok(text.includes('16') && text.includes('4096') && text.includes('401/403'))
  }
})
