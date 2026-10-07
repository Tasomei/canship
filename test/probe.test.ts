/** 联网模式的目标与同意边界；所有执行测试使用模拟传输，不访问外部服务。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { createProbePlan, isPublicProbeAddress, parseProbeTarget, ProbeError, PROBE_LIMITS, PROBE_ORIGIN, sameProbeAddress } from '../src/probe-target.js'
import { checkProbeProxy, checkProbeRuntime, copyProbeResponse, selectProbeAddress, summarizeProbeHeaders } from '../src/probe-network.js'
import { executeProbe, renderProbe } from '../src/probe.js'
import type { ProbeAddress } from '../src/probe-target.js'

const url = 'https://api.example.com/status'
const address: ProbeAddress = { address: '8.8.8.8', family: 4 }
const response = () => summarizeProbeHeaders({ 'strict-transport-security': 'max-age=31536000', 'set-cookie': ['PRIVATE_COOKIE'], 'x-private': 'PRIVATE_HEADER' }, 200)
test('special-purpose IPv4, IPv6 and cloud-platform targets are refused', () => {
  const rejected = ['0.1.2.3', '10.0.0.1', '100.64.0.1', '100.127.255.254', '127.0.0.1', '168.63.129.16', '169.254.169.254',
    '172.16.0.1', '172.31.255.254', '192.0.0.9', '192.0.2.1', '192.31.196.1', '192.52.193.1', '192.88.99.1', '192.168.0.1',
    '192.175.48.1', '198.18.0.1', '198.19.255.254', '198.51.100.1', '203.0.113.1', '224.0.0.1', '255.255.255.255',
    '::', '::1', '::ffff:127.0.0.1', '::ffff:808:808', '64:ff9b::808:808', '100::1', '2001::1', '2001:db8::1',
    '2001:20::1', '2002:7f00:1::', '2620:4f:8000::1', '3fff::1', 'fc00::1', 'fe80::1', 'fe80::1%1', 'ff02::1']
  for (const value of rejected) assert.equal(isPublicProbeAddress(value), false, value)
  for (const value of ['1.1.1.1', '8.8.8.8', '100.63.255.254', '100.128.0.1', '172.15.255.254', '172.32.0.1',
    '2001:4860:4860::8888', '2606:4700:4700::1111']) assert.equal(isPublicProbeAddress(value), true, value)
  assert.equal(sameProbeAddress('::ffff:8.8.8.8', address), true)
  assert.equal(sameProbeAddress('0:0:0:0:0:ffff:808:808', address), true)
  assert.equal(sameProbeAddress('2606:4700:4700:0:0:0:0:1111', { address: '2606:4700:4700::1111', family: 6 }), true)
})
test('URL validation rejects ambiguous, credential-bearing and non-HTTPS targets without echoing values', () => {
  for (const input of ['http://api.example.com', 'https://localhost/', 'https://app.internal/', 'https://example.com:8443/',
    'https://127.1/', 'https://0x7f000001/', 'https://2130706433/', 'https://[::ffff:127.0.0.1]/', 'https:////example.com/',
    'https://user:PRIVATE_PASSWORD@example.com/', 'https://example.com/?token=PRIVATE_QUERY', 'https://example.com/#PRIVATE_FRAGMENT',
    'https://example.com\\@other.example.com/', 'https://example.com/a/../secret', 'https://example.com/%2e%2e/',
    'https://example.com/a%2fb', 'https://example.com/a b', 'https://example.com/\nPRIVATE_LINE']) {
    assert.throws(() => parseProbeTarget(input), error => error instanceof ProbeError && error.code === 'PROBE_TARGET_INVALID' && !error.message.includes('PRIVATE'))
  }
  assert.equal(parseProbeTarget('https://API.EXAMPLE.COM:443/status').url, url)
  assert.equal(parseProbeTarget('https://[2606:4700:4700::1111]/status').hostname, '2606:4700:4700::1111')
})
test('plan preview is stable, explicit and independent of caller mutations', () => {
  const plan = createProbePlan(url)
  assert.equal(plan.networkPerformed, false)
  assert.equal(plan.credentials, false)
  assert.equal(plan.redirects, false)
  assert.equal(plan.responseBodiesRetained, false)
  assert.match(plan.confirmation, /^[a-f0-9]{64}$/)
  assert.deepEqual(plan.requests.map(item => item.method), ['HEAD', 'OPTIONS'])
  Reflect.set(plan.limits, 'requests', 99)
  assert.equal(createProbePlan(url).limits.requests, 2)
  assert.equal(PROBE_LIMITS.requests, 2)
  assert.notEqual(createProbePlan(url, true).confirmation, createProbePlan(url).confirmation)
  assert.notEqual(createProbePlan(url + '/different').confirmation, createProbePlan(url).confirmation)
  assert.match(renderProbe(plan), /no network performed/)
  assert.match(plan.notice, /can observe your IP/)
})
test('no DNS or HTTP runs before exact confirmation, including changed expectations', async () => {
  let calls = 0
  const io = { resolve: async () => { calls++; return [address] }, request: async () => { calls++; return response() } }
  for (const [confirmation, expectAuth] of [['wrong', false], [createProbePlan(url).confirmation, true]] as const) {
    await assert.rejects(executeProbe(url, confirmation, expectAuth, undefined, io), error => error instanceof ProbeError && error.code === 'PROBE_CONFIRMATION_REQUIRED')
  }
  assert.equal(calls, 0)
})
test('mixed, empty, malformed and oversized DNS answers never reach HTTP', async () => {
  for (const addresses of [[], [address, { address: '10.0.0.1', family: 4 }], Array(33).fill(address), Array(1), [{ address: '8.8.8.8', family: 6 }]]) {
    let requests = 0
    await assert.rejects(executeProbe(url, createProbePlan(url).confirmation, false, undefined, {
      resolve: async () => addresses as ProbeAddress[], request: async () => { requests++; return response() },
    }), error => error instanceof ProbeError && error.code === 'PROBE_ADDRESS_REFUSED')
    assert.equal(requests, 0)
  }
  assert.equal(Object.isFrozen(selectProbeAddress([address])), true)
})
test('only two methods run against the pinned target and response fields are whitelisted', async () => {
  const requests: string[] = []
  const result = await executeProbe(url, createProbePlan(url).confirmation, false, undefined, {
    resolve: async () => [address], request: async (target, pinned, method) => {
      assert.equal(target.url, url); assert.deepEqual(pinned, address)
      requests.push(method)
      return { ...response(), cookie: 'PRIVATE_COOKIE', body: 'PRIVATE_BODY', location: 'PRIVATE_REDIRECT' }
    },
  })
  assert.deepEqual(requests, ['HEAD', 'OPTIONS'])
  assert.equal(result.exitCode, 0)
  assert.equal(result.partial, false)
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_|8\.8\.8\.8/)
  assert.match(result.notice, /do not prove application security/)
})
test('malformed transport summaries cannot become successful canary evidence', () => {
  const valid = response()
  for (const fields of [{ status: 199 }, { status: 600 }, { status: 200.5 }, { allowOrigin: 'PRIVATE_ORIGIN' },
    { hstsPresent: 'PRIVATE_VALUE' }, { canary: { state: 'matched', bytes: 0 } },
    { canary: { state: 'matched', bytes: 4097 } }, { canary: { state: 'different', bytes: 24 }, status: 403 },
    { canary: { state: 'not-read', bytes: 0 } }, { canary: { state: 'not-read', bytes: 24 }, status: 403 },
    { canary: { state: 'PRIVATE_STATE', bytes: 24 } }]) {
    assert.throws(() => copyProbeResponse({ ...valid, ...fields } as never), error =>
      error instanceof ProbeError && error.code === 'PROBE_RESPONSE_INVALID' && !error.message.includes('PRIVATE'))
  }
  for (const bytes of [16, 4096]) assert.deepEqual(copyProbeResponse({ ...valid, canary: { state: 'matched', bytes } }).canary,
    { state: 'matched', bytes })
  assert.deepEqual(copyProbeResponse({ ...valid, status: 403, canary: { state: 'not-read', bytes: 0 } }).canary,
    { state: 'not-read', bytes: 0 })
})

test('reflected credentials and requested auth rejection create review observations, not exploit claims', async () => {
  const result = await executeProbe(url, createProbePlan(url, true).confirmation, true, undefined, {
    resolve: async () => [address], request: async () => summarizeProbeHeaders({ 'access-control-allow-origin': PROBE_ORIGIN,
      'access-control-allow-credentials': 'true' }, 200),
  })
  assert.equal(result.exitCode, 2)
  assert.ok(result.observations.some(item => item.code === 'CORS_PROBE_ORIGIN_CREDENTIALS'))
  assert.ok(result.observations.some(item => item.code === 'AUTH_REJECTION_NOT_OBSERVED'))
  assert.match(result.observations[0]!.message, /does not prove/)
  assert.equal(summarizeProbeHeaders({ 'access-control-allow-credentials': 'TRUE' }, 200).credentialsAllowed, false)
})
test('redirects are observations on the original target, never a new target request', async () => {
  const targets: string[] = []
  const result = await executeProbe(url, createProbePlan(url).confirmation, false, undefined, {
    resolve: async () => [address], request: async target => { targets.push(target.url); return summarizeProbeHeaders({ location: 'https://PRIVATE_REDIRECT.invalid/secret' }, 302) },
  })
  assert.deepEqual(targets, [url, url])
  assert.ok(result.observations.every(item => item.code === 'REDIRECT_NOT_FOLLOWED'))
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_REDIRECT/)
})
test('transport failure and cancellation cannot become a completed validation', async () => {
  let count = 0
  const io = { resolve: async () => [address], request: async () => { count++; throw new Error('PRIVATE_REMOTE_ERROR') } }
  const failed = await executeProbe(url, createProbePlan(url).confirmation, false, undefined, io)
  assert.equal(failed.exitCode, 3); assert.equal(failed.partial, true); assert.equal(count, 1)
  assert.doesNotMatch(JSON.stringify(failed), /PRIVATE_REMOTE/)
  const controller = new AbortController(); controller.abort('PRIVATE_REASON')
  await assert.rejects(executeProbe(url, createProbePlan(url).confirmation, false, controller.signal, io), error => error instanceof ProbeError && error.code === 'PROBE_CANCELLED')
})
test('canary GET needs a dedicated path, digest and new confirmation without exposing body data', async () => {
  const target = 'https://api.example.com/.well-known/canship-canary.txt'
  const digest = createHash('sha256').update('synthetic canary content').digest('hex')
  assert.throws(() => createProbePlan(url, false, digest), error => error instanceof ProbeError && error.code === 'PROBE_CANARY_INVALID')
  const plan = createProbePlan(target, false, digest)
  assert.equal(plan.limits.requests, 3)
  assert.deepEqual(plan.requests.map(item => item.method), ['HEAD', 'OPTIONS', 'GET'])
  assert.notEqual(plan.confirmation, createProbePlan(target).confirmation)
  const methods: string[] = []
  const result = await executeProbe(target, plan.confirmation, false, undefined, {
    resolve: async () => [address], request: async (_target, _address, method, _signal, expected) => {
      methods.push(method)
      if (method === 'GET') { assert.equal(expected, digest); return { ...response(), canary: { state: 'matched', bytes: 24, body: 'PRIVATE_BODY', computedDigest: 'PRIVATE_HASH' } } }
      assert.equal(expected, undefined); return response()
    },
  }, digest)
  assert.deepEqual(methods, ['HEAD', 'OPTIONS', 'GET'])
  assert.equal(result.exitCode, 2)
  assert.ok(result.observations.some(item => item.code === 'CANARY_READ_WITHOUT_CREDENTIALS'))
  assert.doesNotMatch(JSON.stringify(result), /PRIVATE_|PRIVATE_HASH/)
})
test('configured proxies are refused without disclosing or bypassing their settings', () => {
  for (const key of ['HTTP_PROXY', 'https_proxy', 'ALL_PROXY']) assert.throws(() => checkProbeProxy({ [key]: 'http://PRIVATE_PROXY.invalid' }),
    error => error instanceof ProbeError && error.code === 'PROBE_PROXY_UNSUPPORTED' && !error.message.includes('PRIVATE_PROXY'))
  assert.doesNotThrow(() => checkProbeProxy({}))
})
test('network tracing and insecure TLS overrides fail without changing caller configuration', () => {
  for (const env of [{ NODE_DEBUG: 'http,https' }, { NODE_DEBUG_NATIVE: 'tls' }, { NODE_TLS_REJECT_UNAUTHORIZED: '0' }, { NODE_OPTIONS: '--tls-keylog=PRIVATE_FILE' }]) {
    const original = JSON.stringify(env)
    assert.throws(() => checkProbeRuntime(env, []), error => error instanceof ProbeError && error.code === 'PROBE_RUNTIME_UNSUPPORTED' && !error.message.includes('PRIVATE_FILE'))
    assert.equal(JSON.stringify(env), original)
  }
  assert.throws(() => checkProbeRuntime({}, ['--trace-tls']), ProbeError)
  assert.doesNotThrow(() => checkProbeRuntime({}, []))
})
test('CLI preview ignores project files and incompatible modes never execute a probe', () => {
  const directory = mkdtempSync(join(tmpdir(), 'canship-probe-preview-'))
  writeFileSync(join(directory, 'canship.config.json'), 'PRIVATE_INVALID_PROJECT_CONFIG')
  writeFileSync(join(directory, '.env'), 'PRIVATE_ENV_VALUE')
  const cli = (...args: string[]) => spawnSync(process.execPath, ['--import', new URL('../node_modules/tsx/dist/loader.mjs', import.meta.url).href,
    fileURLToPath(new URL('../src/cli.ts', import.meta.url)), ...args], { cwd: directory, encoding: 'utf8', timeout: 15_000 })
  try {
  const preview = cli(`--probe=${url}`, '--json')
  assert.equal(preview.status, 0, preview.stderr)
  assert.equal(JSON.parse(preview.stdout).kind, 'probe-plan')
  assert.equal(JSON.parse(preview.stdout).networkPerformed, false)
  for (const flags of [['--probe-expect-auth'], [`--probe=${url}`, '--report'], [`--probe=${url}`, '.'],
    [`--probe=${url}`, '--no-config'], [`--probe=${url}`, '--confirm-probe=' + '0'.repeat(64)],
    ['--probe=https://example.com/?PRIVATE_QUERY', '--json']]) {
    const result = cli(...flags)
    assert.equal(result.status, 3)
    assert.equal(result.stdout, '')
    assert.doesNotMatch(result.stderr, /PRIVATE_QUERY/)
  }
  } finally { rmSync(directory, { recursive: true, force: true }) }
})
