/** 联网校验仅接受普通公网地址；特殊用途网段按 IANA 登记保守拒绝。 */
import { isIP } from 'node:net'
import { createHash } from 'node:crypto'
import { redactAll } from './redact.js'
import { getBuildInfo } from './build-info.js'

export class ProbeError extends Error {
  constructor(readonly code: string, message: string) { super(message) }
}
export const PROBE_ORIGIN = 'https://canship-probe.invalid'
export const PROBE_LIMITS = Object.freeze({ requests: 2, canaryRequests: 3, dnsTimeoutMs: 3000, requestTimeoutMs: 5000, maxHeaderBytes: 16384, maxInformationalResponses: 4, minCanaryBytes: 16, maxCanaryBytes: 4096 })
export type ProbeMethod = 'HEAD' | 'OPTIONS' | 'GET'
export interface ProbeTarget { url: string; hostname: string; host: string; path: string }
export interface ProbeAddress { address: string; family: 4 | 6 }

function ipv4(address: string): bigint { return address.split('.').reduce((value, part) => value * 256n + BigInt(part), 0n) }
function ipv6(address: string): bigint {
  const [left, right] = address.toLowerCase().split('::')
  const start = left ? left.split(':') : [], end = right ? right.split(':') : []
  const parts = right === undefined ? start : [...start, ...Array<string>(8 - start.length - end.length).fill('0'), ...end]
  return parts.reduce((value, part) => (value << 16n) + BigInt('0x' + part), 0n)
}
function inBlock(value: bigint, block: bigint, prefix: number, width: number): boolean {
  const shift = BigInt(width - prefix)
  return value >> shift === block >> shift
}
// 2026-10-07 核对 IANA 登记；额外拒绝组播、过渡机制及 Azure 平台虚拟地址。
const v4Blocks = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '168.63.129.16/32', '169.254.0.0/16', '172.16.0.0/12',
  '192.0.0.0/24', '192.0.2.0/24', '192.31.196.0/24', '192.52.193.0/24', '192.88.99.0/24', '192.168.0.0/16',
  '192.175.48.0/24', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4']
  .map(block => { const [address, prefix] = block.split('/'); return { address: ipv4(address!), prefix: Number(prefix) } })
const v6Blocks = ['2001::/23', '2001:db8::/32', '2002::/16', '2620:4f:8000::/48', '3fff::/20']
  .map(block => { const [address, prefix] = block.split('/'); return { address: ipv6(address!), prefix: Number(prefix) } })

export function isPublicProbeAddress(address: string): boolean {
  if (address.includes('%')) return false
  const family = isIP(address)
  if (family === 4) return !v4Blocks.some(block => inBlock(ipv4(address), block.address, block.prefix, 32))
  if (family !== 6 || address.includes('.')) return false
  const value = ipv6(address)
  return inBlock(value, ipv6('2000::'), 3, 128) && !v6Blocks.some(block => inBlock(value, block.address, block.prefix, 128))
}

/** 套接字可能使用 IPv4 映射形式或另一种 IPv6 压缩形式。 */
export function sameProbeAddress(actual: string, expected: ProbeAddress): boolean {
  const peer = actual.replace(/^::ffff:(?=\d+\.)/i, '')
  if (isIP(peer) === 4 && expected.family === 4) return ipv4(peer) === ipv4(expected.address)
  if (isIP(peer) !== 6 || peer.includes('.') || peer.includes('%')) return false
  const value = ipv6(peer)
  return expected.family === 6 ? value === ipv6(expected.address) : value >> 32n === 0xffffn && (value & 0xffffffffn) === ipv4(expected.address)
}

export function parseProbeTarget(input: string): ProbeTarget {
  const invalid = () => new ProbeError('PROBE_TARGET_INVALID', 'Use one explicit HTTPS URL on port 443, without credentials, query, fragment, unsafe characters or a special-use address.')
  if (typeof input !== 'string' || input.length > 2048 || !/^https:\/\/[^/]/i.test(input) || /[\u0000-\u0020\u007f-\u009f\\%]/.test(input) || /\/\.{1,2}(?:\/|$)/.test(input) || redactAll(input) !== input) throw invalid()
  let url: URL
  try { url = new URL(input) } catch { throw invalid() }
  if (url.protocol !== 'https:' || url.port || url.username || url.password || url.search || url.hash || /[?#@]/.test(input)) throw invalid()
  // 不向下游转发另一个 URL 或编码后的路径语法。
  if (!/^\/(?:[A-Za-z0-9._~-]+\/)*[A-Za-z0-9._~-]*$/.test(url.pathname)) throw invalid()
  const hostname = url.hostname.replace(/^\[|\]$/g, '')
  if (isIP(hostname)) { if (!isPublicProbeAddress(hostname)) throw invalid() }
  else {
    const labels = hostname.split('.')
    if (hostname.length > 253 || labels.length < 2 || labels.some(label => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)) ||
      /\.(?:localhost|local|internal|test|invalid|example|onion|home|lan|corp)$/i.test(hostname)) throw invalid()
  }
  return Object.freeze({ url: url.href, hostname, host: url.host, path: url.pathname })
}

export function validateCanary(target: ProbeTarget, hash: string): string {
  if (!/^[a-f0-9]{64}$/i.test(hash) || !/\/canship-canary(?:\.(?:txt|json))?$/.test(target.path)) {
    throw new ProbeError('PROBE_CANARY_INVALID', 'Canary GET requires a SHA-256 digest and a dedicated resource named canship-canary, canship-canary.txt or canship-canary.json.')
  }
  return hash.toLowerCase()
}

export function createProbePlan(input: string, expectAuth = false, canarySha256?: string) {
  if (typeof expectAuth !== 'boolean') throw new ProbeError('PROBE_TARGET_INVALID', 'The expected authentication rejection must be a boolean.')
  const target = parseProbeTarget(input)
  const canary = canarySha256 === undefined ? null : { expectedSha256: validateCanary(target, canarySha256),
    minimumBytes: PROBE_LIMITS.minCanaryBytes, maximumBytes: PROBE_LIMITS.maxCanaryBytes }
  const requests: { method: ProbeMethod; origin: string | null; requestedMethod?: string }[] = [
    { method: 'HEAD', origin: null }, { method: 'OPTIONS', origin: PROBE_ORIGIN, requestedMethod: 'GET' },
    ...(canary ? [{ method: 'GET' as const, origin: null }] : []),
  ]
  const plan = { schemaVersion: 1, kind: 'probe-plan' as const, build: getBuildInfo(), target: target.url, expectUnauthenticatedDenial: expectAuth,
    requests, canary, limits: { ...PROBE_LIMITS, requests: canary ? PROBE_LIMITS.canaryRequests : PROBE_LIMITS.requests }, credentials: false, redirects: false, responseBodiesRetained: false,
    notice: 'Only test endpoints you own or are authorized to assess. The digest binds options, not domain ownership. Execution contacts DNS and the target, which can observe your IP and requested path. Requests can have side effects. Canary GET is only for dedicated synthetic data and hashes a bounded body. Configured proxies cause refusal, not a direct-connection fallback. No credentials are sent; response bodies and cookies are not saved.' }
  const confirmation = createHash('sha256').update(JSON.stringify(plan)).digest('hex')
  return { ...plan, confirmation, networkPerformed: false }
}
