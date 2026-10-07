/** 在确认目标后解析并固定公网地址；请求不继承代理、凭据或重定向行为。 */
import { Resolver } from 'node:dns/promises'
import { isIP } from 'node:net'
import { Agent, request } from 'node:https'
import { createHash } from 'node:crypto'
import type { ClientRequest, IncomingHttpHeaders } from 'node:http'
import type { TLSSocket } from 'node:tls'
import { ProbeError, PROBE_LIMITS, PROBE_ORIGIN, isPublicProbeAddress, sameProbeAddress, parseProbeTarget, validateCanary } from './probe-target.js'
import type { ProbeAddress, ProbeTarget, ProbeMethod } from './probe-target.js'

export function checkProbeCancelled(signal?: AbortSignal): void {
  if (signal?.aborted) throw new ProbeError('PROBE_CANCELLED', 'Probe cancelled; no complete validation result was produced.')
}
/** 不绕过现有代理策略，也不把批准的目标交给未校验的代理。 */
export function checkProbeProxy(env: NodeJS.ProcessEnv = process.env): void {
  if (Object.entries(env).some(([key, value]) => ['http_proxy', 'https_proxy', 'all_proxy'].includes(key.toLowerCase()) && Boolean(value?.trim()))) {
    throw new ProbeError('PROBE_PROXY_UNSUPPORTED', 'Configured proxies are not supported. No probe was sent; use static scanning or an approved direct-network environment.')
  }
}
/** 拒绝可能记录 TLS 内容或削弱校验的运行时选项，不修改调用方配置。 */
export function checkProbeRuntime(env: NodeJS.ProcessEnv = process.env, args: readonly string[] = process.execArgv): void {
  if (env.NODE_TLS_REJECT_UNAUTHORIZED === '0' || Boolean(env.NODE_DEBUG?.trim()) ||
    Boolean(env.NODE_DEBUG_NATIVE?.trim()) || /--(?:trace-tls|tls-keylog)(?:[=\s]|$)/.test([env.NODE_OPTIONS ?? '', ...args].join(' '))) {
    throw new ProbeError('PROBE_RUNTIME_UNSUPPORTED', 'Network tracing or TLS overrides are active. No probe was sent; use static scanning or an approved standard runtime.')
  }
}
interface ProbeResolver { resolve4(hostname: string): Promise<string[]>; resolve6(hostname: string): Promise<string[]>; cancel(): void }
export async function resolveProbeAddresses(hostname: string, signal?: AbortSignal,
  createResolver: () => ProbeResolver = () => new Resolver({ timeout: PROBE_LIMITS.dnsTimeoutMs, tries: 1 })): Promise<ProbeAddress[]> {
  checkProbeCancelled(signal)
  const literal = isIP(hostname)
  if (literal === 4 || literal === 6) return [{ address: hostname, family: literal }]
  const resolver = createResolver()
  let timedOut = false, stopped = false
  const cancel = () => { if (!stopped) { stopped = true; resolver.cancel() } }
  const timer = setTimeout(() => { timedOut = true; cancel() }, PROBE_LIMITS.dnsTimeoutMs)
  signal?.addEventListener('abort', cancel, { once: true })
  try {
    const [a, aaaa] = await Promise.allSettled([
      Promise.resolve().then(() => { checkProbeCancelled(signal); return resolver.resolve4(hostname) }),
      Promise.resolve().then(() => { checkProbeCancelled(signal); return resolver.resolve6(hostname) }),
    ])
    checkProbeCancelled(signal)
    if (timedOut) throw new ProbeError('PROBE_DNS_TIMEOUT', 'DNS resolution exceeded the probe time limit.')
    const addresses: ProbeAddress[] = []
    for (const [result, family] of [[a, 4], [aaaa, 6]] as const) {
      if (result.status === 'fulfilled') addresses.push(...result.value.map(address => ({ address, family })))
      else if (!['ENODATA', 'ENOTFOUND'].includes(String(result.reason?.code))) throw new ProbeError('PROBE_DNS_FAILED', 'DNS resolution did not complete for the requested target.')
    }
    return addresses
  } finally { clearTimeout(timer); signal?.removeEventListener('abort', cancel); cancel() }
}

export function selectProbeAddress(addresses: ProbeAddress[]): ProbeAddress {
  if (!Array.isArray(addresses) || !addresses.length || addresses.length > 32 || [...addresses].some(value => !value ||
    typeof value.address !== 'string' || isIP(value.address) !== value.family || !isPublicProbeAddress(value.address))) {
    throw new ProbeError('PROBE_ADDRESS_REFUSED', 'The target did not resolve exclusively to ordinary public addresses. No HTTP request was sent.')
  }
  const selected = addresses.find(address => address.family === 4) ?? addresses[0]!
  return Object.freeze({ address: selected.address, family: selected.family })
}

const header = (headers: IncomingHttpHeaders, key: string): string => typeof headers[key] === 'string' ? headers[key] : ''
export function summarizeProbeHeaders(headers: IncomingHttpHeaders, status: number) {
  const origin = header(headers, 'access-control-allow-origin')
  return { status, redirect: status >= 300 && status < 400, locationPresent: Boolean(header(headers, 'location')),
    allowOrigin: origin === PROBE_ORIGIN ? 'probe-origin' as const : origin === '*' ? 'wildcard' as const : origin ? 'other' as const : 'absent' as const,
    credentialsAllowed: header(headers, 'access-control-allow-credentials') === 'true',
    hstsPresent: Boolean(header(headers, 'strict-transport-security')), cspPresent: Boolean(header(headers, 'content-security-policy')) }
}
export type ProbeResponse = ReturnType<typeof summarizeProbeHeaders> & { canary?: { state: 'matched' | 'different' | 'not-read'; bytes: number } }

/** 即使传输适配层扩展字段，报告仍只保留无正文的白名单。 */
export function copyProbeResponse(value: ProbeResponse): ProbeResponse {
  if (!value || !Number.isInteger(value.status) || value.status < 200 || value.status > 599 ||
    !['probe-origin', 'wildcard', 'other', 'absent'].includes(value.allowOrigin) ||
    [value.locationPresent, value.credentialsAllowed, value.hstsPresent, value.cspPresent].some(field => typeof field !== 'boolean')) {
    throw new ProbeError('PROBE_RESPONSE_INVALID', 'The probe response summary is invalid.')
  }
  if (value.canary && (!['matched', 'different', 'not-read'].includes(value.canary.state) || !Number.isInteger(value.canary.bytes) ||
    value.canary.bytes < 0 || value.canary.bytes > PROBE_LIMITS.maxCanaryBytes ||
    (value.canary.state === 'not-read' ? value.canary.bytes !== 0 || value.status === 200 : value.canary.bytes < PROBE_LIMITS.minCanaryBytes || value.status !== 200))) throw new ProbeError('PROBE_RESPONSE_INVALID', 'The canary summary is invalid.')
  return { status: value.status, redirect: value.status >= 300 && value.status < 400, locationPresent: value.locationPresent,
    allowOrigin: value.allowOrigin, credentialsAllowed: value.credentialsAllowed, hstsPresent: value.hstsPresent, cspPresent: value.cspPresent,
    ...(value.canary ? { canary: { state: value.canary.state, bytes: value.canary.bytes } } : {}) }
}

export async function requestProbe(target: ProbeTarget, address: ProbeAddress, method: ProbeMethod, signal?: AbortSignal,
  timeoutMs: number = PROBE_LIMITS.requestTimeoutMs, canarySha256?: string): Promise<ProbeResponse> {
  checkProbeCancelled(signal)
  checkProbeProxy()
  checkProbeRuntime()
  if (!['HEAD', 'OPTIONS', 'GET'].includes(method)) throw new ProbeError('PROBE_METHOD_INVALID', 'Only planned HEAD, OPTIONS and canary GET requests are supported.')
  target = parseProbeTarget(target.url)
  const expected = method === 'GET' ? validateCanary(target, canarySha256 ?? '') : null
  selectProbeAddress([address])
  return new Promise((resolve, reject) => {
    const agentOptions = { keepAlive: false, maxSockets: 1, maxCachedSessions: 0, rejectUnauthorized: true, proxyEnv: {} }
    const agent = new Agent(agentOptions)
    let req: ClientRequest | undefined
    let settled = false, informational = 0
    const done = (error?: ProbeError, result?: ProbeResponse) => {
      if (settled) return
      settled = true; clearTimeout(timer); signal?.removeEventListener('abort', abort)
      req?.destroy(); agent.destroy()
      if (error) reject(error); else resolve(result!)
    }
    const abort = () => done(new ProbeError('PROBE_CANCELLED', 'Probe cancelled; no complete validation result was produced.'))
    const timer = setTimeout(() => done(new ProbeError('PROBE_REQUEST_TIMEOUT', 'The probe request exceeded its time limit.')), timeoutMs)
    try { req = request({ protocol: 'https:', hostname: target.hostname, port: 443, path: target.path, method, agent,
      family: address.family, rejectUnauthorized: true, maxHeaderSize: PROBE_LIMITS.maxHeaderBytes,
      insecureHTTPParser: false, servername: isIP(target.hostname) ? '' : target.hostname,
      lookup: (_hostname, options, callback) => options.all ? callback(null, [{ ...address }]) : callback(null, address.address, address.family),
      headers: { Host: target.host, 'User-Agent': 'canship-probe', Accept: '*/*', 'Accept-Encoding': 'identity', Connection: 'close',
        ...(method === 'OPTIONS' ? { Origin: PROBE_ORIGIN, 'Access-Control-Request-Method': 'GET' } : {}) },
    }, response => {
      if (settled) { response.destroy(); return }
      response.on('aborted', () => done(new ProbeError('PROBE_REQUEST_FAILED', 'The probe response did not finish.')))
      response.on('error', () => done(new ProbeError('PROBE_REQUEST_FAILED', 'The probe response failed.')))
      const socket = response.socket as TLSSocket | null
      const peer = socket?.remoteAddress
      if (!socket?.authorized || !peer || !sameProbeAddress(peer, address)) {
        done(new ProbeError('PROBE_TLS_FAILED', 'The peer address or TLS verification did not match the approved target.')); response.destroy(); return
      }
      const status = response.statusCode
      if (!status || status < 200 || status > 599) { done(new ProbeError('PROBE_RESPONSE_INVALID', 'The endpoint did not provide a valid final HTTP status.')); response.destroy(); return }
      const summary = summarizeProbeHeaders(response.headers, status)
      if (expected !== null && status === 200) {
        const encoding = response.headers['content-encoding'], length = response.headers['content-length']
        if (encoding !== undefined && (typeof encoding !== 'string' || encoding.trim().toLowerCase() !== 'identity')) {
          done(new ProbeError('PROBE_RESPONSE_ENCODING', 'Compressed canary responses are not accepted.')); response.destroy(); return
        }
        if (length !== undefined && (!/^\d+$/.test(length) || Number(length) > PROBE_LIMITS.maxCanaryBytes || Number(length) < PROBE_LIMITS.minCanaryBytes)) {
          done(new ProbeError('PROBE_CANARY_SIZE', 'The canary body is outside the 16–4096 byte limit.')); response.destroy(); return
        }
        const hash = createHash('sha256'); let bytes = 0
        response.on('data', (chunk: Buffer) => {
          if (settled) return
          if (!Buffer.isBuffer(chunk) || (bytes += chunk.length) > PROBE_LIMITS.maxCanaryBytes) {
            done(new ProbeError('PROBE_CANARY_SIZE', 'The canary body exceeded its byte limit.')); response.destroy(); return
          }
          hash.update(chunk)
        })
        response.on('end', () => {
          if (settled) return
          if (!response.complete || bytes < PROBE_LIMITS.minCanaryBytes) { done(new ProbeError('PROBE_CANARY_SIZE', 'The canary body was incomplete or too short.')); return }
          done(undefined, { ...summary, canary: { state: hash.digest('hex') === expected ? 'matched' : 'different', bytes } })
        })
        return
      }
      if (expected !== null) { done(undefined, { ...summary, canary: { state: 'not-read', bytes: 0 } }); response.destroy(); return }
      done(undefined, summary); response.destroy()
    }) } catch { done(new ProbeError('PROBE_REQUEST_FAILED', 'The HTTPS request could not be initialized.')); return }
    if (settled) { req.destroy(); return }
    req.on('information', () => { if (++informational > PROBE_LIMITS.maxInformationalResponses) done(new ProbeError('PROBE_RESPONSE_LIMIT', 'Too many informational responses.')) })
    req.on('error', () => done(new ProbeError('PROBE_REQUEST_FAILED', 'The HTTPS request failed; no response body or remote error text was retained.')))
    signal?.addEventListener('abort', abort, { once: true })
    if (signal?.aborted) abort(); else req.end()
  })
}
