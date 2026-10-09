/** 仅模拟 GitHub 响应，不联网、不读取真实令牌。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { TARGET, parseContext, prepareUpload, validateCloud } from '../scripts/sarif-cloud-validation.mjs'

const root = fileURLToPath(new URL('..', import.meta.url))
const generated = spawnSync(process.execPath, ['--import', 'tsx', 'scripts/prepare-sarif-validation.ts'],
  { cwd: root, encoding: 'utf8' })
assert.equal(generated.status, 0, generated.stderr)
const preview = JSON.parse(generated.stdout)
const sha = 'a'.repeat(40)
const environment = (caseId = 'initial'): NodeJS.ProcessEnv => ({ CANSHIP_SARIF_CONFIRM: 'synthetic-only',
  GITHUB_REPOSITORY: TARGET.repository, GITHUB_REF: TARGET.ref, GITHUB_SHA: sha,
  GITHUB_TOKEN: 'synthetic-token', CANSHIP_SARIF_CASE: caseId, CANSHIP_SARIF_ID: 'upload-current' })
type Options = { ids?: number[]; history?: boolean; pending?: number; failed?: boolean; wrongSha?: boolean;
  wrongCategory?: boolean; extraInstances?: boolean; fixed?: boolean; duplicate?: boolean;
  wrongConfiguration?: boolean; primaryFingerprint?: boolean; foreignHistory?: boolean; paginated?: boolean;
  httpError?: number; throwNetwork?: boolean; missingCurrent?: boolean; wrongVersion?: boolean;
  wrongWording?: boolean; changedPrimary?: boolean }

function mock(caseId = 'initial', options: Options = {}) {
  const calls: URL[] = []
  let polls = 0
  const prepared = prepareUpload(preview, caseId)
  const numbers = options.ids ?? (caseId === 'reduced' ? [101] : [101, 102])
  const analysis = { id: 200, ref: TARGET.ref, category: options.wrongCategory ? `${TARGET.category}-other` : TARGET.category,
    commit_sha: options.wrongSha ? 'b'.repeat(40) : sha, sarif_id: 'upload-current',
    tool: { name: 'canship', version: options.wrongVersion ? '0.0.0-unexpected' : prepared.expected.version },
    results_count: numbers.length, error: '', warning: '', analysis_key: 'workflow:job', environment: '{}' }
  const initialAnalysis = { ...analysis, id: 100, sarif_id: 'upload-initial', results_count: 2,
    analysis_key: options.wrongConfiguration ? 'other:job' : analysis.analysis_key }
  function sarif(id: string, lineNumbers: number[], ids: number[]) {
    const log = structuredClone(prepareUpload(preview, id).log)
    for (const [index, result] of log.runs[0].results.entries()) {
      result.locations[0].physicalLocation.region.startLine = lineNumbers[index]
      result.properties = { 'github/alertNumber': ids[index] }
      if (options.primaryFingerprint !== false) result.partialFingerprints.primaryLocationLineHash =
        `${options.changedPrimary && id !== 'initial' ? 'def' : 'abc'}:${index + 1}`
      if (options.wrongWording) result.message.text = 'Unexpected wording'
    }
    return log
  }
  const fetcher: typeof globalThis.fetch = async (input, init) => {
    const url = new URL(String(input))
    calls.push(url)
    assert.equal(init?.method, 'GET')
    assert.equal(init?.redirect, 'error')
    assert.equal(url.origin, 'https://api.github.com')
    assert.ok(url.pathname.startsWith(`/repos/${TARGET.repository}/code-scanning/`))
    if (options.throwNetwork) throw new Error('PRIVATE_RESPONSE synthetic-token')
    if (options.httpError) return new Response('PRIVATE_RESPONSE synthetic-token', { status: options.httpError })
    const endpoint = url.pathname.split('/code-scanning/')[1]!
    let body: unknown
    if (endpoint === 'sarifs/upload-current') {
      body = { processing_status: options.failed ? 'failed' : polls++ < (options.pending ?? 0) ? 'pending' : 'complete' }
    } else if (endpoint === 'analyses' && url.searchParams.has('sarif_id')) {
      assert.equal(url.searchParams.get('ref'), TARGET.ref)
      assert.equal(url.searchParams.get('sarif_id'), 'upload-current')
      body = options.missingCurrent ? [] : [analysis]
    } else if (endpoint === 'analyses') {
      assert.equal(url.searchParams.get('ref'), TARGET.ref)
      assert.equal(url.searchParams.get('direction'), 'asc')
      const other = { ...initialAnalysis, category: 'real-scanner', id: 99 }
      body = options.paginated && url.searchParams.get('page') === '1'
        ? Array.from({ length: 100 }, () => other)
        : [...(options.foreignHistory ? [other] : []),
          ...(options.history !== false && caseId !== 'initial' ? [initialAnalysis] : []), analysis]
    } else if (endpoint === 'analyses/100') body = sarif('initial', [7, 11], [101, 102])
    else if (endpoint === 'analyses/200') body = sarif(caseId, prepared.expected.lines,
      options.duplicate ? [101, 101] : numbers)
    else if (/^alerts\/10[12]\/instances$/.test(endpoint)) {
      assert.equal(url.searchParams.get('ref'), TARGET.ref)
      const number = Number(endpoint.split('/')[1])
      const index = numbers.indexOf(number)
      const instance = { ref: TARGET.ref, category: TARGET.category, analysis_key: 'workflow:job', environment: '{}',
        state: index < 0 && options.fixed !== false ? 'fixed' : 'open',
        commit_sha: index < 0 ? 'b'.repeat(40) : sha,
        location: { path: TARGET.path, start_line: prepared.expected.lines[index] ?? 14 } }
      body = [instance, ...(options.extraInstances ? [{ ...instance, ref: 'refs/heads/main', state: 'open' },
        { ...instance, category: `${TARGET.category}-unrelated`, state: 'open' }] : [])]
    } else throw new Error(`Unexpected test endpoint ${endpoint}`)
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } })
  }
  return { calls, run: () => validateCloud(preview, environment(caseId), {
    fetch: fetcher, verifyFixture: (_commit, content) => assert.equal(content, prepared.fixture),
    sleep: async () => {}, attempts: 3,
  }) }
}

test('默认 CLI 不读取预览文件、不联网，缺确认时仅输出固定错误', () => {
  const result = spawnSync(process.execPath, ['scripts/sarif-cloud-validation.mjs', '--preview=PRIVATE_PATH'],
    { cwd: root, encoding: 'utf8', env: { ...process.env, CANSHIP_SARIF_CONFIRM: '', GITHUB_TOKEN: 'PRIVATE_TOKEN' } })
  assert.equal(result.status, 1)
  assert.equal(result.stdout, '')
  assert.equal(result.stderr, 'SARIF validation failed: CONFIRMATION_REQUIRED.\n')
})

test('固定仓库、分支、提交和上传 ID 缺一不可', () => {
  for (const changes of [{ GITHUB_REPOSITORY: 'other/repo' }, { GITHUB_REF: 'refs/heads/main' },
    { GITHUB_SHA: 'HEAD' }, { CANSHIP_SARIF_ID: '' }, { CANSHIP_SARIF_ID: '../other' }, { GITHUB_TOKEN: '' }]) {
    assert.throws(() => parseContext({ ...environment(), ...changes }))
  }
})

test('五个预览案例通过封闭检查，原始对象不被修改', () => {
  const before = JSON.stringify(preview)
  for (const id of ['initial', 'repeat', 'moved', 'wording-and-version', 'reduced']) {
    const prepared = prepareUpload(preview, id)
    assert.equal(prepared.log.runs[0].automationDetails.id, `${TARGET.category}/`)
  }
  assert.equal(JSON.stringify(preview), before)
})

test('拒绝真实路径、任意源码和附加报告内容', () => {
  for (const mutate of [
    (item: any) => { item.fixture.content += 'PRIVATE_SOURCE' },
    (item: any) => { item.sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri = 'src/real.ts' },
    (item: any) => { item.sarif.runs[0].results[0].message.text = 'PRIVATE_MESSAGE' },
    (item: any) => { item.sarif.runs[0].artifacts = [{ contents: { text: 'PRIVATE_SOURCE' } }] },
  ]) {
    const changed = structuredClone(preview)
    mutate(changed.cases[0])
    assert.throws(() => prepareUpload(changed, 'initial'))
  }
})

test('初次等待上传完成后建立编号，后续保持初始 A/B 编号', async () => {
  for (const id of ['initial', 'repeat', 'moved', 'wording-and-version']) {
    const api = mock(id, { pending: 1, foreignHistory: true, extraInstances: true })
    const result = await api.run()
    assert.deepEqual(result.baseline, [101, 102])
    assert.deepEqual(result.active.map(item => item.number), [101, 102])
    assert.equal(result.hasPlatformFingerprint, true)
    assert.equal(api.calls[0]!.pathname.split('/').at(-2), 'sarifs')
    assert.doesNotMatch(JSON.stringify(result), /synthetic-token|Synthetic public-read|allow read/)
  }
})

test('减少结果必须保留 A 且 B 在本分支本配置 fixed，旧 SHA 允许保留在 fixed 实例', async () => {
  const result = await mock('reduced', { extraInstances: true }).run()
  assert.deepEqual(result.active, [{ number: 101, line: 10 }])
  assert.deepEqual(result.fixed, [102])
  await assert.rejects(mock('reduced', { fixed: false }).run(), /BRANCH_INSTANCES_MISMATCH/)
})

test('同数量的新编号或 A/B 交换不能误报连续性通过', async () => {
  await assert.rejects(mock('moved', { ids: [201, 202] }).run(), /ALERT_IDENTITY_CHANGED/)
  await assert.rejects(mock('moved', { ids: [102, 101] }).run(), /ALERT_IDENTITY_CHANGED/)
  await assert.rejects(mock('moved', { duplicate: true }).run(), /DUPLICATE_ALERT_NUMBER/)
})

test('其他提交、category 前缀碰撞及配置变化不能替代本次分析', async () => {
  await assert.rejects(mock('moved', { wrongSha: true }).run(), /UPLOADED_ANALYSIS_MISMATCH/)
  await assert.rejects(mock('moved', { wrongCategory: true }).run(), /UPLOADED_ANALYSIS_MISMATCH/)
  await assert.rejects(mock('moved', { wrongConfiguration: true }).run(), /ANALYSIS_CONFIGURATION_CHANGED/)
  await assert.rejects(mock('moved', { missingCurrent: true }).run(), /UPLOADED_ANALYSIS_MISMATCH/)
})

test('已处理失败、处理超时和没有初始基线分别报错', async () => {
  await assert.rejects(mock('initial', { failed: true }).run(), /UPLOAD_PROCESSING_FAILED/)
  await assert.rejects(mock('initial', { pending: 9 }).run(), /UPLOAD_PROCESSING_TIMEOUT/)
  await assert.rejects(mock('moved', { history: false }).run(), /INITIAL_ANALYSIS_REQUIRED/)
})

test('遍历历史分页且没有平台指纹时如实输出 false', async () => {
  const result = await mock('moved', { paginated: true, primaryFingerprint: false }).run()
  assert.deepEqual(result.baseline, [101, 102])
  assert.equal(result.hasPlatformFingerprint, false)
})

test('API 错误不得泄露响应内容或令牌', async () => {
  await assert.rejects(mock('initial', { httpError: 403 }).run(), error => {
    assert.equal(String(error), 'Error: SARIF validation failed: API_HTTP_403.')
    return true
  })
  await assert.rejects(mock('initial', { throwNetwork: true }).run(), error => {
    assert.equal(String(error), 'Error: SARIF validation failed: API_UNAVAILABLE.')
    return true
  })
})

test('核对平台实际工具版本和文案，平台指纹变化仅披露而不替代编号判定', async () => {
  await assert.rejects(mock('wording-and-version', { wrongVersion: true }).run(), /UPLOADED_ANALYSIS_MISMATCH/)
  await assert.rejects(mock('wording-and-version', { wrongWording: true }).run(), /UPLOADED_WORDING_MISMATCH/)
  const result = await mock('reduced', { changedPrimary: true }).run()
  assert.equal(result.verified, true)
  assert.equal(result.platformFingerprintsUnchanged, false)
  assert.deepEqual(result.fixed, [102])
})

test('提交中的合成文件不匹配时在任何请求前中止', async () => {
  let requests = 0
  await assert.rejects(validateCloud(preview, environment(), {
    fetch: async () => { requests++; throw new Error('Unexpected network') },
    verifyFixture: () => { throw new Error('PRIVATE_PATH') },
  }), /COMMITTED_FIXTURE_MISMATCH/)
  assert.equal(requests, 0)
})
