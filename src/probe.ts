/** 联网模式与静态扫描分离；只有与计划匹配的显式确认才允许 DNS 和 HTTPS。 */
import { createProbePlan, parseProbeTarget, ProbeError, PROBE_LIMITS } from './probe-target.js'
import { checkProbeCancelled, checkProbeProxy, checkProbeRuntime, copyProbeResponse, resolveProbeAddresses, requestProbe, selectProbeAddress } from './probe-network.js'
import type { ProbeAddress, ProbeTarget, ProbeMethod } from './probe-target.js'
import type { ProbeResponse } from './probe-network.js'

interface ProbeIO {
  resolve(hostname: string, signal?: AbortSignal): Promise<ProbeAddress[]>
  request(target: ProbeTarget, address: ProbeAddress, method: ProbeMethod, signal?: AbortSignal, canarySha256?: string): Promise<ProbeResponse>
}
const DEFAULT_IO: ProbeIO = { resolve: resolveProbeAddresses, request: (target, address, method, signal, canary) => requestProbe(target, address, method, signal, PROBE_LIMITS.requestTimeoutMs, canary) }
export async function executeProbe(input: string, confirmation: string, expectAuth = false, signal?: AbortSignal,
  io: ProbeIO = DEFAULT_IO, canarySha256?: string) {
  const plan = createProbePlan(input, expectAuth, canarySha256)
  if (confirmation !== plan.confirmation) throw new ProbeError('PROBE_CONFIRMATION_REQUIRED', 'Review the current probe plan and pass its exact confirmation digest. No network request was sent.')
  checkProbeCancelled(signal)
  if (io === DEFAULT_IO) { checkProbeProxy(); checkProbeRuntime() }
  const target = parseProbeTarget(input)
  let addresses: ProbeAddress[]
  try { addresses = await io.resolve(target.hostname, signal) }
  catch (error) {
    checkProbeCancelled(signal)
    if (error instanceof ProbeError) throw error
    throw new ProbeError('PROBE_DNS_FAILED', 'DNS resolution did not complete for the requested target.')
  }
  const address = selectProbeAddress(addresses)
  checkProbeCancelled(signal)
  const results: { method: ProbeMethod; response: ProbeResponse | null; error: string | null }[] = []
  for (const { method } of plan.requests) {
    checkProbeCancelled(signal)
    try {
      const response = copyProbeResponse(await io.request(target, address, method, signal, method === 'GET' ? plan.canary!.expectedSha256 : undefined))
      if (method === 'GET' && !response.canary) throw new ProbeError('PROBE_RESPONSE_INVALID', 'The canary result is missing.')
      results.push({ method, response, error: null })
    }
    catch (error) {
      checkProbeCancelled(signal)
      if (error instanceof ProbeError && error.code === 'PROBE_CANCELLED') throw error
      results.push({ method, response: null, error: error instanceof ProbeError ? error.code : 'PROBE_REQUEST_FAILED' }); break
    }
  }
  checkProbeCancelled(signal)
  const observations: { code: string; review: boolean; message: string }[] = []
  for (const result of results) {
    const response = result.response
    if (!response) continue
    if (response.allowOrigin === 'probe-origin' && response.credentialsAllowed) observations.push({ code: 'CORS_PROBE_ORIGIN_CREDENTIALS', review: true,
      message: `${result.method} permitted the probe origin with credentials. Review the policy; this does not prove that business data can be read.` })
    if (response.allowOrigin === 'wildcard' && response.credentialsAllowed) observations.push({ code: 'CORS_WILDCARD_CREDENTIALS', review: true,
      message: `${result.method} combined a wildcard origin with credentials. Browsers reject this combination; it is not evidence of a data leak.` })
    if (response.redirect) observations.push({ code: 'REDIRECT_NOT_FOLLOWED', review: false, message: `${result.method} returned a redirect. Its destination was not contacted or recorded.` })
    if (expectAuth && result.method !== 'OPTIONS' && response.status !== 401 && response.status !== 403) observations.push({ code: 'AUTH_REJECTION_NOT_OBSERVED', review: true,
      message: `${result.method} did not return the requested 401/403 rejection. This requires review; a status code does not prove authentication or authorization correctness.` })
    if (response.canary) observations.push({ code: response.canary.state === 'matched' ? 'CANARY_READ_WITHOUT_CREDENTIALS' : 'CANARY_NOT_CONFIRMED',
      review: response.canary.state !== 'not-read' || (response.status !== 401 && response.status !== 403),
      message: response.canary.state === 'matched' ? 'The dedicated synthetic canary matched without credentials. This proves only that this test resource was readable, not access to business records.'
        : 'The supplied canary content was not confirmed. Review the status and test setup; no response body or computed digest was saved.' })
  }
  const partial = results.length !== plan.requests.length || results.some(result => result.error !== null)
  return { schemaVersion: 1, kind: 'probe-report' as const, target: plan.target, networkPerformed: true, partial,
    exitCode: partial ? 3 : observations.some(item => item.review) ? 2 : 0, results, observations,
    notice: 'Only the approved unauthenticated requests are assessed. Header presence and status codes do not prove application security. No response bodies, computed body digests, cookies, credentials, redirect destinations or resolved IP addresses are included.' }
}

export function renderProbe(value: ReturnType<typeof createProbePlan> | Awaited<ReturnType<typeof executeProbe>>): string {
  if (value.kind === 'probe-plan') return ['canship probe plan — no network performed', `Target: ${value.target}`,
    'Requests: HEAD; OPTIONS with a fixed probe Origin and Access-Control-Request-Method: GET.',
    ...(value.canary ? [`Additional GET: dedicated synthetic canary, ${value.canary.minimumBytes}–${value.canary.maximumBytes} bytes; expected SHA-256 ${value.canary.expectedSha256}.`] : []),
    `Expect unauthenticated HEAD${value.canary ? '/GET' : ''} rejection: ${value.expectUnauthenticatedDenial}`, value.notice,
    `Limits: ${value.limits.requests} requests; DNS ${value.limits.dnsTimeoutMs} ms; each request ${value.limits.requestTimeoutMs} ms; headers ${value.limits.maxHeaderBytes} bytes.`,
    'No credentials, redirects, project config, or saved response bodies.',
    `After reviewing, repeat the same probe options with --confirm-probe=${value.confirmation}`, ''].join('\n')
  return ['canship probe observations', `Target: ${value.target}`, ...value.results.flatMap(result => [
    `${result.method}: ${result.response?.status ?? result.error}`,
    ...(result.response ? [`  CORS origin: ${result.response.allowOrigin}; credentials: ${result.response.credentialsAllowed}.`,
      `  Header presence only: HSTS ${result.response.hstsPresent}; CSP ${result.response.cspPresent}.`,
      ...(result.response.canary ? [`  Canary: ${result.response.canary.state}; ${result.response.canary.bytes} bytes.`] : [])] : []),
  ]),
    ...value.observations.map(item => `[${item.code}] ${item.message}`), value.notice,
    `exit ${value.exitCode} · ${value.partial ? 'probe incomplete' : 'approved requests completed; not a security verdict'}`, ''].join('\n')
}
