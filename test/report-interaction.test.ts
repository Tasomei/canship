/** 执行报告脚本，验证组合筛选、定位、复制失败和打印后的状态恢复。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { runInNewContext } from 'node:vm'
import { renderHtml } from '../src/report/html.js'
import type { Finding, ScanResult } from '../src/types.js'

const finding = (over: Partial<Finding> = {}): Finding => ({ ruleId: 'firebase/open-rules', file: 'a.ts', line: 1,
  title: 'A finding', severity: 'P1', confidence: 'certain', excerpt: null, sourceFingerprint: 'synthetic-a', why: [], fix: [], ...over })
const findings = [finding(), finding({ file: 'b.ts', confidence: 'likely', sourceFingerprint: 'synthetic-b' }),
  finding({ file: 'c.ts', severity: 'P2', confidence: 'likely', sourceFingerprint: 'synthetic-c' })]
function page(items = findings) {
  const result: ScanResult = { findings: items, filesScanned: 3, durationMs: 0, partial: false,
    errors: [], skipped: [], ignored: [], ignoredFindings: [], ruleSelection: null, vendored: 0 }
  return renderHtml(result, { root: 'sample', generatedAt: '' })
}

class Element {
  children: Array<Element | string> = []
  dataset: Record<string, string> = {}
  attributes: Record<string, string> = {}
  classes = new Set<string>()
  className = ''
  id = ''
  open = false
  hidden = false
  value = ''
  focused = false
  scrolled = false
  private text = ''
  onclick: (event: { preventDefault(): void }) => void = () => {}
  oninput = () => {}
  classList = { add: (name: string) => this.classes.add(name),
    toggle: (name: string, on: boolean) => on ? this.classes.add(name) : this.classes.delete(name) }
  set textContent(value: string) { this.text = value; this.children = [] }
  get textContent() { return this.text }
  appendChild(child: Element | string) { this.children.push(child) }
  removeChild(child: Element) { this.children = this.children.filter(item => item !== child) }
  setAttribute(name: string, value: string) { this.attributes[name] = value }
  focus() { this.focused = true }
  select() {}
  scrollIntoView() { this.scrolled = true }
  querySelector() { return this }
}

function harness(clipboardWorks = true) {
  const html = page()
  const data = JSON.parse(/<script type="application\/json" id="canship-data">([\s\S]*?)<\/script>/.exec(html)![1]!)
  const nodes = Object.fromEntries(['canship-data', 'list', 'count', 'empty', 'q', 'clear', 'print'].map(id => [id, new Element()]))
  nodes['canship-data']!.textContent = JSON.stringify(data)
  const rows = [...html.matchAll(/<details class="f" id="([^"]+)" data-i="([^"]+)" data-sev="([^"]+)" data-cat="([^"]+)" data-conf="([^"]+)" data-file="([^"]+)" data-text="([^"]+)"/g)].map(match => {
    const row = new Element(); row.id = match[1]!;
    row.dataset = { i: match[2]!, sev: match[3]!, cat: match[4]!, conf: match[5]!, file: match[6]!, text: match[7]! }
    return row
  })
  function buttons(key: string, values: string[]) {
    return values.map(value => { const button = new Element(); button.dataset[key] = value; return button })
  }
  const severity = buttons('filterSev', ['', 'P0', 'P1', 'P2'])
  const confidence = buttons('filterConf', ['', 'certain', 'likely'])
  const groups = buttons('group', ['file', 'sev', 'cat'])
  const refs = buttons('copyRef', ['1', '2', '3']); refs.forEach(button => { button.textContent = 'copy reference' })
  const lists: Record<string, Element[]> = { 'details.f': rows, '[data-filter-sev]': severity,
    '[data-filter-conf]': confidence, '[data-group]': groups, '[data-copy-ref]': refs }
  const events = new Map<string, () => void>()
  const copied: string[] = []
  const document = { body: new Element(), activeElement: new Element(),
    getElementById: (id: string) => nodes[id] ?? null, querySelectorAll: (selector: string) => lists[selector] ?? [],
    createElement: () => new Element(), createTextNode: (text: string) => text, execCommand: () => false }
  const window = { location: { hash: '' }, addEventListener: (name: string, callback: () => void) => events.set(name, callback), print() {} }
  const navigator = clipboardWorks ? { clipboard: { writeText: async (text: string) => { copied.push(text) } } } : {}
  runInNewContext(/<script>([\s\S]*?)<\/script>/.exec(html)![1]!, { document, window, navigator, setTimeout: () => {} }, { timeout: 1000 })
  const click = (element: Element) => element.onclick({ preventDefault() {} })
  const visible = () => nodes['list']!.children.flatMap(child => typeof child === 'string' ? [] : child.children).filter(child => rows.includes(child as Element)) as Element[]
  return { nodes, rows, severity, confidence, groups, refs, events, copied, window, click, visible, data, document }
}

test('confidence and severity filters combine and disclose visible versus report totals', () => {
  const h = harness()
  assert.equal(h.nodes['count']!.textContent, '3 of 3 findings in this report')
  h.click(h.confidence[2]!)
  assert.equal(h.visible().length, 2)
  assert.equal(h.confidence[2]!.attributes['aria-pressed'], 'true')
  h.click(h.severity[2]!)
  assert.equal(h.visible().length, 1)
  assert.equal(h.nodes['count']!.textContent, '1 of 3 findings in this report')
  h.nodes['q']!.value = 'no match'; h.nodes['q']!.oninput()
  assert.equal(h.nodes['empty']!.hidden, false)
  h.click(h.nodes['clear']!)
  assert.equal(h.visible().length, 3)
  assert.equal(h.nodes['q']!.value, '')
})

test('anchors survive wording and line changes and duplicates still have unique IDs', () => {
  const ids = (html: string) => [...html.matchAll(/<details class="f" id="([^"]+)"/g)].map(match => match[1])
  assert.deepEqual(ids(page([finding()])), ids(page([finding({ title: '另一种措辞', line: 80 })])))
  const duplicates = ids(page([finding(), finding({ line: 2 })]))
  assert.equal(new Set(duplicates).size, 2)
  for (const id of duplicates) assert.match(id!, /^finding-[a-f0-9]{64}(?:-\d+)?$/)
})

test('a fragment reveals a filtered finding, opens details and focuses its summary', () => {
  const h = harness(); h.click(h.confidence[1]!)
  const target = h.rows.find(row => row.dataset.conf === 'likely')!
  h.window.location.hash = '#' + target.id; h.events.get('hashchange')!()
  assert.ok(h.visible().includes(target))
  assert.equal(target.open, true)
  assert.equal(target.focused, true)
  assert.equal(target.scrolled, true)
  const before = h.visible().length
  h.window.location.hash = '#unrecognised'; h.events.get('hashchange')!()
  assert.equal(h.visible().length, before)
})

test('printing includes every report row then restores filters and detail states', () => {
  const h = harness(); h.click(h.confidence[2]!); h.rows[1]!.open = true
  const visible = h.visible(); const open = h.rows.map(row => row.open)
  h.events.get('beforeprint')!()
  assert.equal(h.visible().length, 3)
  assert.ok(h.rows.every(row => row.open))
  h.events.get('beforeprint')!()
  h.events.get('afterprint')!()
  assert.deepEqual(h.visible(), visible)
  assert.deepEqual(h.rows.map(row => row.open), open)
  assert.equal(h.confidence[2]!.attributes['aria-pressed'], 'true')
})

test('copy reference contains a rule, relative location and fragment, not the report URL', async () => {
  const h = harness(); h.click(h.refs[0]!); await Promise.resolve()
  assert.equal(h.copied[0], h.data.references['1'])
  assert.match(h.copied[0]!, /firebase\/open-rules · a.ts:1\n#finding-[a-f0-9]{64}/)
  assert.ok(!h.copied[0]!.includes('sample'))
  assert.equal(h.refs[0]!.textContent, 'copied')
})

test('failed clipboard fallback does not claim success and restores focus', () => {
  const h = harness(false); h.click(h.refs[0]!)
  assert.equal(h.refs[0]!.textContent, 'copy unavailable')
  assert.equal(h.document.activeElement.focused, true)
})

test('secondary text contrast exceeds 4.5 to 1 in both default themes', () => {
  const html = page()
  function luminance(hex: string) {
    const rgb = hex.slice(1).match(/../g)!.map(value => parseInt(value, 16) / 255)
      .map(value => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4)
    return rgb[0]! * 0.2126 + rgb[1]! * 0.7152 + rgb[2]! * 0.0722
  }
  const themes = [...html.matchAll(/--paper:(#[a-f0-9]{6});--ink:#[a-f0-9]{6};--ink-2:#[a-f0-9]{6};--ink-3:(#[a-f0-9]{6})/g)]
  assert.equal(themes.length, 2)
  for (const theme of themes) {
    const a = luminance(theme[1]!); const b = luminance(theme[2]!)
    assert.ok((Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05) >= 4.5)
  }
})
