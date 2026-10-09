/** 仅在明确授权的合成分支中验收 GitHub 告警连续性。 */
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'

export const TARGET = Object.freeze({ repository: 'Tasomei/canship',
  ref: 'refs/heads/codex/sarif-upgrade-validation', category: 'canship-upgrade-validation-20261009',
  path: 'synthetic/firestore.rules', rule: 'firebase/open-rules' })
const CASES = ['initial', 'repeat', 'moved', 'wording-and-version', 'reduced']
const INITIAL_TITLE = 'Synthetic public-read validation'
const UPDATED_TITLE = 'Reworded synthetic public-read validation'
const WHY = 'Synthetic test input, not a production finding.'
const FIX = 'No production resource is involved.'

export class ValidationError extends Error {
  constructor(code) { super(`SARIF validation failed: ${code}.`); this.code = code }
}
function ensure(condition, code) { if (!condition) throw new ValidationError(code) }
function keys(value, allowed) {
  ensure(value && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).every(key => allowed.includes(key)), 'UNEXPECTED_REPORT_FIELD')
}
function categoryMatches(category) { return category === TARGET.category || category === `${TARGET.category}/` }
function expectedCase(id) {
  ensure(CASES.includes(id), 'INVALID_CASE')
  const moved = !['initial', 'repeat'].includes(id)
  const changed = ['wording-and-version', 'reduced'].includes(id)
  return { lines: id === 'reduced' ? [10] : moved ? [10, 14] : [7, 11],
    title: changed ? UPDATED_TITLE : INITIAL_TITLE,
    version: changed ? '0.0.0-validation.2' : '0.0.0-validation.1' }
}

export function parseContext(env) {
  ensure(env.CANSHIP_SARIF_CONFIRM === 'synthetic-only', 'CONFIRMATION_REQUIRED')
  ensure(env.GITHUB_REPOSITORY === TARGET.repository && env.GITHUB_REF === TARGET.ref, 'WRONG_TARGET')
  ensure(typeof env.GITHUB_SHA === 'string' && /^[a-f0-9]{40}$/.test(env.GITHUB_SHA), 'INVALID_COMMIT')
  ensure(typeof env.GITHUB_TOKEN === 'string' && env.GITHUB_TOKEN.length > 0 &&
    !/[\r\n]/.test(env.GITHUB_TOKEN), 'MISSING_TOKEN')
  expectedCase(env.CANSHIP_SARIF_CASE)
  ensure(typeof env.CANSHIP_SARIF_ID === 'string' && /^[a-zA-Z0-9-]{1,100}$/.test(env.CANSHIP_SARIF_ID),
    'UPLOAD_ID_REQUIRED')
  return { sha: env.GITHUB_SHA, caseId: env.CANSHIP_SARIF_CASE, token: env.GITHUB_TOKEN,
    uploadId: env.CANSHIP_SARIF_ID }
}

/** 上传内容采用封闭字段集，拒绝源码、任意路径和附加元数据。 */
export function prepareUpload(preview, caseId) {
  ensure(preview?.schemaVersion === 1 && preview.kind === 'sarif-validation-preview' &&
    preview.synthetic === true && preview.scanPerformed === false && preview.networkPerformed === false &&
    preview.uploaded === false && Array.isArray(preview.cases), 'INVALID_PREVIEW')
  const selected = preview.cases.filter(item => item.id === caseId)
  ensure(selected.length === 1, 'MISSING_OR_DUPLICATE_CASE')
  const item = selected[0]
  const expected = expectedCase(caseId)
  ensure(item.fixture?.path === TARGET.path && typeof item.fixture.content === 'string', 'INVALID_FIXTURE')
  const original = ["rules_version = '2';", 'service cloud.firestore {', '  match /databases/{database}/documents {',
    '    // 仅供合成验收。', '    match /sampleA/{id} {', '      // 公开读取测试。',
    '      allow read: if true;', '    }', '    match /sampleB/{id} {', '      // 公开读取测试。',
    `      allow read: if ${caseId === 'reduced' ? 'false' : 'true'};`, '    }', '  }', '}', ''].join('\n')
  ensure(item.fixture.content === (['initial', 'repeat'].includes(caseId) ? '' : '\n\n\n') + original,
    'UNEXPECTED_FIXTURE_CONTENT')
  const log = structuredClone(item.sarif)
  keys(log, ['$schema', 'version', 'runs'])
  ensure(log.$schema === 'https://json.schemastore.org/sarif-2.1.0.json' && log.version === '2.1.0' &&
    Array.isArray(log.runs) && log.runs.length === 1, 'INVALID_SARIF')
  const run = log.runs[0]
  keys(run, ['tool', 'results', 'invocations'])
  keys(run.tool, ['driver'])
  const driver = run.tool.driver
  keys(driver, ['name', 'version', 'informationUri', 'rules'])
  ensure(driver.name === 'canship' && driver.version === expected.version &&
    driver.informationUri === 'https://github.com/Tasomei/canship' && Array.isArray(driver.rules) &&
    driver.rules.length === 1, 'INVALID_TOOL')
  const rule = driver.rules[0]
  keys(rule, ['id', 'name', 'shortDescription', 'fullDescription', 'help', 'properties', 'defaultConfiguration'])
  ensure(rule.id === TARGET.rule && rule.name === TARGET.rule, 'INVALID_RULE')
  for (const [field, text] of [['shortDescription', expected.title], ['fullDescription', WHY],
    ['help', `${WHY}\nHow to fix:\n${FIX}`]]) {
    keys(rule[field], ['text'])
    ensure(rule[field].text === text, 'UNEXPECTED_RULE_TEXT')
  }
  keys(rule.properties, ['canship-severity', 'canship-confidence'])
  ensure(rule.properties['canship-severity'] === 'P1' && rule.properties['canship-confidence'] === 'likely',
    'UNEXPECTED_CLASSIFICATION')
  keys(rule.defaultConfiguration, ['level'])
  ensure(rule.defaultConfiguration.level === 'warning', 'UNEXPECTED_CLASSIFICATION')
  ensure(Array.isArray(run.invocations) && run.invocations.length === 1, 'INVALID_INVOCATION')
  keys(run.invocations[0], ['executionSuccessful'])
  ensure(run.invocations[0].executionSuccessful === true, 'INCOMPLETE_REPORT')
  ensure(Array.isArray(run.results) && run.results.length === expected.lines.length, 'INVALID_RESULT_COUNT')
  for (const [index, result] of run.results.entries()) {
    keys(result, ['ruleId', 'level', 'message', 'locations', 'partialFingerprints'])
    ensure(result.ruleId === TARGET.rule && result.level === 'warning', 'INVALID_RESULT_RULE')
    keys(result.message, ['text'])
    ensure(result.message.text === expected.title, 'UNEXPECTED_RESULT_TEXT')
    ensure(Array.isArray(result.locations) && result.locations.length === 1, 'INVALID_LOCATION')
    keys(result.locations[0], ['physicalLocation'])
    const location = result.locations[0].physicalLocation
    keys(location, ['artifactLocation', 'region'])
    keys(location.artifactLocation, ['uri'])
    keys(location.region, ['startLine'])
    ensure(location.artifactLocation.uri === TARGET.path && location.region.startLine === expected.lines[index],
      'INVALID_LOCATION')
    keys(result.partialFingerprints, ['canshipFindingV2', 'canshipFindingV3', 'primaryLocationLineHash'])
    ensure(/^[a-f0-9]{64}$/.test(result.partialFingerprints.canshipFindingV2) &&
      /^[a-f0-9]{64}$/.test(result.partialFingerprints.canshipFindingV3) &&
      (result.partialFingerprints.primaryLocationLineHash === undefined ||
        /^[a-f0-9:]{1,128}$/.test(result.partialFingerprints.primaryLocationLineHash)), 'INVALID_FINGERPRINT')
  }
  run.automationDetails = { id: `${TARGET.category}/` }
  return { log, fixture: item.fixture.content, expected }
}

function query(values) { return new URLSearchParams(values).toString() }
function analysisMatches(item) {
  return item.ref === TARGET.ref && item.tool?.name === 'canship' && categoryMatches(item.category)
}
function analysisValid(item) {
  return Number.isSafeInteger(item.id) && item.id > 0 && !item.error && !item.warning
}
function resultRows(log) {
  ensure(log?.runs?.length === 1 && Array.isArray(log.runs[0].results), 'INVALID_ANALYSIS_SARIF')
  const rows = log.runs[0].results.map(result => {
    const location = result.locations?.[0]?.physicalLocation
    const raw = result.properties?.['github/alertNumber']
    const number = typeof raw === 'string' && /^\d+$/.test(raw) ? Number(raw) : raw
    ensure(result.ruleId === TARGET.rule && location?.artifactLocation?.uri === TARGET.path &&
      Number.isInteger(location.region?.startLine) && Number.isSafeInteger(number) && number > 0,
      'UNEXPECTED_ANALYSIS_RESULT')
    return { number, line: location.region.startLine }
  }).sort((a, b) => a.line - b.line)
  ensure(new Set(rows.map(row => row.number)).size === rows.length, 'DUPLICATE_ALERT_NUMBER')
  return rows
}

export async function validateCloud(preview, env, dependencies = {}) {
  const context = parseContext(env)
  const prepared = prepareUpload(preview, context.caseId)
  const fetcher = dependencies.fetch ?? globalThis.fetch
  const sleep = dependencies.sleep ?? (ms => new Promise(resolve => setTimeout(resolve, ms)))
  const attempts = dependencies.attempts ?? 36
  ensure(Number.isInteger(attempts) && attempts > 0 && attempts <= 120, 'INVALID_POLL_LIMIT')
  const verifyFixture = dependencies.verifyFixture ?? ((sha, fixture) => {
    const head = execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
    const content = execFileSync('git', ['show', `${sha}:${TARGET.path}`],
      { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 64 * 1024 })
    ensure(head === sha && content === fixture, 'COMMITTED_FIXTURE_MISMATCH')
  })
  try { await verifyFixture(context.sha, prepared.fixture) }
  catch { throw new ValidationError('COMMITTED_FIXTURE_MISMATCH') }
  const base = `https://api.github.com/repos/${TARGET.repository}/code-scanning/`
  async function request(endpoint, { accept = 'application/vnd.github+json' } = {}) {
    let response
    try {
      response = await fetcher(base + endpoint, { method: 'GET',
        headers: { Authorization: `Bearer ${context.token}`, Accept: accept,
          'X-GitHub-Api-Version': '2022-11-28' },
        redirect: 'error', signal: AbortSignal.timeout(20_000) })
    } catch { throw new ValidationError('API_UNAVAILABLE') }
    ensure(response.ok, `API_HTTP_${Number.isInteger(response.status) ? response.status : 'ERROR'}`)
    try { return await response.json() } catch { throw new ValidationError('INVALID_API_JSON') }
  }
  async function pages(endpoint, parameters) {
    const all = []
    for (let page = 1; page <= 20; page++) {
      const rows = await request(`${endpoint}?${query({ ...parameters, per_page: '100', page: String(page) })}`)
      ensure(Array.isArray(rows), 'INVALID_API_LIST')
      all.push(...rows)
      if (rows.length < 100) return all
    }
    throw new ValidationError('API_PAGINATION_LIMIT')
  }
  let complete = false
  for (let attempt = 0; attempt < attempts; attempt++) {
    const status = await request(`sarifs/${context.uploadId}`)
    ensure(status.processing_status !== 'failed', 'UPLOAD_PROCESSING_FAILED')
    if (status.processing_status === 'complete') { complete = true; break }
    ensure(status.processing_status === 'pending', 'INVALID_PROCESSING_STATUS')
    if (attempt + 1 < attempts) await sleep(5000)
  }
  ensure(complete, 'UPLOAD_PROCESSING_TIMEOUT')
  const analyses = (await pages('analyses', { sarif_id: context.uploadId, ref: TARGET.ref, tool_name: 'canship' }))
    .filter(item => analysisMatches(item) && item.commit_sha === context.sha && item.sarif_id === context.uploadId)
  ensure(analyses.length === 1 && analysisValid(analyses[0]) &&
    analyses[0].results_count === prepared.expected.lines.length &&
    analyses[0].tool.version === prepared.expected.version, 'UPLOADED_ANALYSIS_MISMATCH')
  const analysis = analyses[0]
  const currentSarif = await request(`analyses/${analysis.id}`, { accept: 'application/sarif+json' })
  const rows = resultRows(currentSarif)
  ensure(rows.length === prepared.expected.lines.length &&
    rows.every((row, index) => row.line === prepared.expected.lines[index]), 'UPLOADED_LOCATIONS_MISMATCH')
  ensure(currentSarif.runs[0].results.every(result => result.message?.text === prepared.expected.title),
    'UPLOADED_WORDING_MISMATCH')
  const history = (await pages('analyses', { tool_name: 'canship', ref: TARGET.ref, direction: 'asc' }))
    .filter(item => analysisMatches(item) && item.sarif_id !== context.uploadId)
  ensure(history.every(analysisValid), 'EXISTING_ANALYSIS_ERROR')
  ensure(context.caseId === 'initial' || history.length > 0, 'INITIAL_ANALYSIS_REQUIRED')
  let baseline = rows
  let baselineSarif = currentSarif
  if (history.length) {
    baselineSarif = await request(`analyses/${history[0].id}`, { accept: 'application/sarif+json' })
    baseline = resultRows(baselineSarif)
    ensure(baseline.length === 2 && baseline[0].line === 7 && baseline[1].line === 11,
      'INVALID_INITIAL_ANALYSIS')
    ensure(history[0].analysis_key === analysis.analysis_key && history[0].environment === analysis.environment,
      'ANALYSIS_CONFIGURATION_CHANGED')
  }
  ensure(rows.every((row, index) => row.number === baseline[index].number), 'ALERT_IDENTITY_CHANGED')
  const fixed = context.caseId === 'reduced' ? [baseline[1].number] : []
  let instancesVerified = false
  for (let attempt = 0; attempt < attempts; attempt++) {
    let valid = true
    for (const row of baseline) {
      const instances = (await pages(`alerts/${row.number}/instances`, { ref: TARGET.ref }))
        .filter(instance => instance.ref === TARGET.ref && categoryMatches(instance.category) &&
          instance.analysis_key === analysis.analysis_key && instance.environment === analysis.environment)
      const active = rows.find(item => item.number === row.number)
      valid &&= instances.length === 1 && (active
        ? instances[0].state === 'open' && instances[0].commit_sha === context.sha &&
          instances[0].location?.path === TARGET.path && instances[0].location?.start_line === active.line
        : instances[0].state === 'fixed')
    }
    if (valid) { instancesVerified = true; break }
    if (attempt + 1 < attempts) await sleep(5000)
  }
  ensure(instancesVerified, 'BRANCH_INSTANCES_MISMATCH')
  const platformHashes = log => log.runs[0].results.map(result => ({
    number: Number(result.properties?.['github/alertNumber']), hash: result.partialFingerprints?.primaryLocationLineHash,
  }))
  const currentHashes = platformHashes(currentSarif)
  const baselineHashes = platformHashes(baselineSarif)
  const hasPlatformFingerprint = currentHashes.every(item => typeof item.hash === 'string' && item.hash.length > 0)
  return { schemaVersion: 1, synthetic: true, verified: true, case: context.caseId,
    repository: TARGET.repository, ref: TARGET.ref, category: TARGET.category, commit: context.sha,
    uploadId: context.uploadId, analysisId: analysis.id, toolVersion: prepared.expected.version,
    hasPlatformFingerprint,
    platformFingerprintsUnchanged: hasPlatformFingerprint && baselineHashes.every(item => typeof item.hash === 'string')
      ? currentHashes.every(item => item.hash === baselineHashes.find(previous => previous.number === item.number)?.hash) : null,
    reportSha256: createHash('sha256').update(JSON.stringify(prepared.log)).digest('hex'),
    baseline: baseline.map(row => row.number), active: rows, fixed }
}

export async function main(args = process.argv.slice(2), env = process.env) {
  try {
    parseContext(env)
    ensure(args.length === 1 && args[0].startsWith('--preview=') && args[0].length > 10, 'PREVIEW_ARGUMENT_REQUIRED')
    const text = readFileSync(args[0].slice(10), 'utf8')
    ensure(Buffer.byteLength(text) <= 128 * 1024, 'PREVIEW_TOO_LARGE')
    const result = await validateCloud(JSON.parse(text), env)
    process.stdout.write(`${JSON.stringify(result)}\n`)
    return 0
  } catch (error) {
    process.stderr.write(`${error instanceof ValidationError ? error.message : 'SARIF validation failed: LOCAL_INPUT_ERROR.'}\n`)
    return 1
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  process.exitCode = await main()
}
