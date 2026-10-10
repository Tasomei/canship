/** 在模拟 DNS 与 HTTPS 上验证传输限制，禁止测试访问真实目标。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import https from 'node:https'
import { syncBuiltinESMExports } from 'node:module'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { resolveProbeAddresses, requestProbe } from '../src/probe-network.js'
import { parseProbeTarget, ProbeError, PROBE_LIMITS, PROBE_ORIGIN } from '../src/probe-target.js'

test('DNS queries both families, permits absent records and treats resolver errors as failures', async () => {
  const queried: string[] = []
  const resolved = await resolveProbeAddresses('api.example.com', undefined, () => ({
    resolve4: async host => { queried.push('A:' + host); return ['8.8.8.8'] },
    resolve6: async host => { queried.push('AAAA:' + host); return ['2606:4700:4700::1111'] }, cancel() {},
  }))
  assert.deepEqual(queried, ['A:api.example.com', 'AAAA:api.example.com'])
  assert.deepEqual(resolved.map(value => value.family), [4, 6])
  assert.deepEqual(await resolveProbeAddresses('api.example.com', undefined, () => ({ resolve4: async () => ['8.8.8.8'],
    resolve6: async () => { throw { code: 'ENODATA' } }, cancel() {}, })), [{ address: '8.8.8.8', family: 4 }])
  await assert.rejects(resolveProbeAddresses('api.example.com', undefined, () => ({ resolve4: async () => ['8.8.8.8'],
    resolve6: async () => { throw { code: 'SERVFAIL', message: 'PRIVATE_DNS_ERROR' } }, cancel() {}, })),
  error => error instanceof ProbeError && error.code === 'PROBE_DNS_FAILED' && !error.message.includes('PRIVATE'))
  assert.deepEqual(await resolveProbeAddresses('8.8.8.8', undefined, () => { throw new Error('Literal address must not query DNS') }), [{ address: '8.8.8.8', family: 4 }])
})
test('unreachable DNS servers fall back to the system resolver; answers and partial failures do not', async () => {
  const unreachable = (code: string) => () => ({ resolve4: async () => { throw { code } }, resolve6: async () => { throw { code } }, cancel() {} })
  let lookups = 0
  const system = async () => { lookups++; return [{ address: '8.8.8.8', family: 4 }, { address: '2606:4700:4700::1111', family: 6 }, { address: 'x', family: 0 }] }
  assert.deepEqual(await resolveProbeAddresses('api.example.com', undefined, unreachable('ECONNREFUSED'), system),
    [{ address: '8.8.8.8', family: 4 }, { address: '2606:4700:4700::1111', family: 6 }])
  assert.equal(lookups, 1)
  // 回退结果照样交给公网地址校验，这里只确认不做额外放行。
  assert.deepEqual(await resolveProbeAddresses('api.example.com', undefined, unreachable('ECONNREFUSED'), async () => [{ address: '10.0.0.1', family: 4 }]),
    [{ address: '10.0.0.1', family: 4 }])
  // 否定回答、一族成功一族失败都不回退。
  assert.deepEqual(await resolveProbeAddresses('api.example.com', undefined, unreachable('ENOTFOUND'), system), [])
  await assert.rejects(resolveProbeAddresses('api.example.com', undefined, () => ({ resolve4: async () => ['8.8.8.8'],
    resolve6: async () => { throw { code: 'ECONNREFUSED' } }, cancel() {} }), system), error => error instanceof ProbeError && error.code === 'PROBE_DNS_FAILED')
  assert.equal(lookups, 1)
  // 系统解析器失败时不泄露错误内容。
  await assert.rejects(resolveProbeAddresses('api.example.com', undefined, unreachable('ECONNREFUSED'), async () => { throw new Error('PRIVATE_LOOKUP_ERROR') }),
    error => error instanceof ProbeError && error.code === 'PROBE_DNS_FAILED' && !error.message.includes('PRIVATE'))
})
test('the system-resolver fallback honours cancellation and the shared DNS deadline', async () => {
  const unreachable = () => ({ resolve4: async () => { throw { code: 'ECONNREFUSED' } }, resolve6: async () => { throw { code: 'ECONNREFUSED' } }, cancel() {} })
  const hanging = () => new Promise<never>(() => {})
  const controller = new AbortController()
  const cancelled = resolveProbeAddresses('api.example.com', controller.signal, unreachable, hanging)
  setTimeout(() => controller.abort('PRIVATE_ABORT_REASON'), 20)
  await assert.rejects(cancelled, error => error instanceof ProbeError && error.code === 'PROBE_CANCELLED')
  const started = Date.now()
  await assert.rejects(resolveProbeAddresses('api.example.com', undefined, unreachable, hanging),
    error => error instanceof ProbeError && error.code === 'PROBE_DNS_TIMEOUT')
  assert.ok(Date.now() - started < PROBE_LIMITS.dnsTimeoutMs + 1000)
})
test('DNS cancellation and its deadline cancel outstanding queries', async () => {
  for (const cancelled of [true, false]) {
    const rejectors: ((error: unknown) => void)[] = []
    let stopped = 0
    const controller = new AbortController()
    const pending = resolveProbeAddresses('api.example.com', controller.signal, () => ({
      resolve4: () => new Promise((_resolve, reject) => rejectors.push(reject)),
      resolve6: () => new Promise((_resolve, reject) => rejectors.push(reject)),
      cancel() { stopped++; for (const reject of rejectors) reject({ code: 'ECANCELLED' }) },
    }))
    if (cancelled) controller.abort('PRIVATE_ABORT_REASON')
    await assert.rejects(pending, error => error instanceof ProbeError && error.code === (cancelled ? 'PROBE_CANCELLED' : 'PROBE_DNS_TIMEOUT'))
    assert.equal(stopped, 1)
  }
})
test('HTTPS pins lookup, preserves host verification, omits credentials and destroys response streams', async () => {
  const original = https.request
  const proxySettings = Object.fromEntries(Object.entries(process.env).filter(([key]) => /^(?:http_proxy|https_proxy|all_proxy)$/i.test(key)))
  for (const key of Object.keys(proxySettings)) delete process.env[key]
  const target = parseProbeTarget('https://api.example.com/status'), pinned = { address: '8.8.8.8', family: 4 as const }
  let mode = 'headers', options: any, responseDestroyed = false, requestDestroyed = false, bodyListeners = 0
  https.request = ((value: any, callback: any) => {
    options = value
    const req = new EventEmitter() as any
    req.destroy = () => { requestDestroyed = true; return req }
    req.end = () => queueMicrotask(() => {
      if (mode === 'hang') return
      if (mode === 'error') { req.emit('error', new Error('PRIVATE_REMOTE_ERROR')); return }
      if (mode === 'information') { for (let i = 0; i < 5; i++) req.emit('information', {}); return }
      const response = new EventEmitter() as any
      response.statusCode = mode === 'status' ? 199 : mode === 'redirect' ? 302 : mode === 'denied' ? 403 : 200
      response.socket = { authorized: mode !== 'certificate', remoteAddress: mode === 'peer' ? '10.0.0.1' : '::ffff:8.8.8.8' }
      response.headers = { 'set-cookie': ['PRIVATE_COOKIE'], location: 'https://PRIVATE_REDIRECT.invalid/',
        'access-control-allow-origin': PROBE_ORIGIN, 'access-control-allow-credentials': 'true' }
      if (mode === 'compressed') response.headers['content-encoding'] = 'gzip'
      response.destroy = () => { responseDestroyed = true; bodyListeners = response.listenerCount('data') }
      callback(response)
      if (value.method === 'GET' && mode !== 'denied' && mode !== 'compressed') {
        const bytes = Buffer.from(mode === 'oversized' ? 'x'.repeat(4097) : mode === 'short' ? 'tiny' : 'synthetic canary content')
        response.emit('data', bytes)
        response.complete = mode !== 'incomplete'
        response.emit('end')
      }
    })
    return req
  }) as typeof https.request
  syncBuiltinESMExports()
  try {
    const response = await requestProbe(target, pinned, 'OPTIONS')
    assert.equal(options.hostname, 'api.example.com')
    assert.equal(options.headers.Host, 'api.example.com')
    assert.equal(options.servername, 'api.example.com')
    assert.equal(options.family, 4)
    assert.equal(options.port, 443)
    assert.equal(options.rejectUnauthorized, true)
    assert.equal(options.insecureHTTPParser, false)
    assert.equal(options.maxHeaderSize, PROBE_LIMITS.maxHeaderBytes)
    assert.equal(options.headers.Origin, PROBE_ORIGIN)
    assert.equal(options.headers['Access-Control-Request-Method'], 'GET')
    assert.equal(options.auth, undefined)
    assert.equal(options.headers.Cookie, undefined)
    assert.equal(options.headers.Authorization, undefined)
    options.lookup('another-name', {}, (error: unknown, address: string, family: number) => { assert.equal(error, null); assert.equal(address, '8.8.8.8'); assert.equal(family, 4) })
    options.lookup('another-name', { all: true }, (error: unknown, addresses: unknown) => { assert.equal(error, null); assert.deepEqual(addresses, [pinned]) })
    assert.equal(response.credentialsAllowed, true)
    assert.doesNotMatch(JSON.stringify(response), /PRIVATE_|8\.8\.8\.8/)
    assert.equal(responseDestroyed, true); assert.equal(requestDestroyed, true); assert.equal(bodyListeners, 0)
    for (const [next, code] of [['peer', 'PROBE_TLS_FAILED'], ['certificate', 'PROBE_TLS_FAILED'], ['status', 'PROBE_RESPONSE_INVALID'],
      ['information', 'PROBE_RESPONSE_LIMIT'], ['error', 'PROBE_REQUEST_FAILED'], ['hang', 'PROBE_REQUEST_TIMEOUT']]) {
      mode = next!
      await assert.rejects(requestProbe(target, pinned, 'HEAD', undefined, 20), error => error instanceof ProbeError && error.code === code && !error.message.includes('PRIVATE'))
    }
    mode = 'redirect'
    assert.equal((await requestProbe(target, pinned, 'HEAD')).redirect, true)
    assert.equal(options.headers.Origin, undefined)
    const controller = new AbortController(); mode = 'hang'
    const pending = requestProbe(target, pinned, 'HEAD', controller.signal)
    controller.abort()
    await assert.rejects(pending, error => error instanceof ProbeError && error.code === 'PROBE_CANCELLED')
    const canary = parseProbeTarget('https://api.example.com/canship-canary.txt')
    const digest = createHash('sha256').update('synthetic canary content').digest('hex')
    mode = 'canary'
    const matched = await requestProbe(canary, pinned, 'GET', undefined, 100, digest)
    assert.deepEqual(matched.canary, { state: 'matched', bytes: 24 })
    assert.doesNotMatch(JSON.stringify(matched), /synthetic canary content|PRIVATE_COOKIE/)
    assert.equal(options.headers['Accept-Encoding'], 'identity')
    assert.equal((await requestProbe(canary, pinned, 'GET', undefined, 100, '0'.repeat(64))).canary?.state, 'different')
    for (const [next, code] of [['oversized', 'PROBE_CANARY_SIZE'], ['short', 'PROBE_CANARY_SIZE'], ['incomplete', 'PROBE_CANARY_SIZE'], ['compressed', 'PROBE_RESPONSE_ENCODING']]) {
      mode = next!
      await assert.rejects(requestProbe(canary, pinned, 'GET', undefined, 100, digest), error => error instanceof ProbeError && error.code === code)
    }
    mode = 'denied'
    assert.deepEqual((await requestProbe(canary, pinned, 'GET', undefined, 100, digest)).canary, { state: 'not-read', bytes: 0 })
    await assert.rejects(requestProbe(canary, pinned, 'GET'), error => error instanceof ProbeError && error.code === 'PROBE_CANARY_INVALID')
  } finally {
    https.request = original; syncBuiltinESMExports()
    for (const [key, value] of Object.entries(proxySettings)) if (value !== undefined) process.env[key] = value
  }
})
test('the actual CLI preview succeeds with both network entry points disabled', () => {
  const code = `import https from 'node:https';import dns from 'node:dns/promises';import {syncBuiltinESMExports} from 'node:module';
    https.request=()=>{throw new Error('NETWORK_MUST_NOT_RUN')};dns.Resolver=class{constructor(){throw new Error('DNS_MUST_NOT_RUN')}};
    syncBuiltinESMExports();if((await import('node:dns/promises')).Resolver!==dns.Resolver)throw new Error('Guard not active');
    process.argv=['node','canship','--probe=https://api.example.com/status','--json'];await import('./src/cli.ts');`
  const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], { encoding: 'utf8', timeout: 15_000 })
  assert.equal(result.status, 0, result.stderr)
  assert.equal(JSON.parse(result.stdout).networkPerformed, false)
})
