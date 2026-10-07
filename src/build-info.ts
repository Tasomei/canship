/** 构建身份只包含公开版本与提交摘要，不读取运行机器或扫描项目的信息。 */
export interface BuildInfo {
  version: string
  channel: 'development' | 'prerelease' | 'release'
  revision: string | null
  dirty: boolean | null
}

export function classifyBuild(version: string, revision: string | null, tagRevision: string | null, dirty: boolean | null): BuildInfo {
  if (!/^\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?$/.test(version)) throw new Error('Invalid package version.')
  const verifiedRevision = revision && /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(revision) ? revision : null
  const released = verifiedRevision !== null && tagRevision === verifiedRevision && dirty === false
  return { version, channel: released ? version.includes('-') ? 'prerelease' : 'release' : 'development', revision: verifiedRevision, dirty }
}

declare const __CANSHIP_VERSION__: string | undefined
declare const __CANSHIP_BUILD_INFO__: BuildInfo | undefined
export const VERSION = typeof __CANSHIP_VERSION__ === 'string' ? __CANSHIP_VERSION__ : '0.0.0-dev'
const identity: BuildInfo = typeof __CANSHIP_BUILD_INFO__ === 'object' ? __CANSHIP_BUILD_INFO__
  : {version:VERSION,channel:'development',revision:null,dirty:null}

export function getBuildInfo(): BuildInfo { return { ...identity } }
export function buildLabel(): string {
  return identity.channel === 'release' ? VERSION : `${VERSION} (${identity.channel}${identity.revision ? ` ${identity.revision.slice(0,7)}` : ''}${identity.dirty ? ' dirty' : ''})`
}

/** 能力声明与边界测试配套；未来联网模式不得继承静态扫描的默认授权。 */
export function getCapabilities() {
  return { staticScan: { network:false, projectCodeExecution:false, projectWrites:false }, fileOutputs:'explicit-only', onlineValidation:true,
    onlineValidationPolicy: { cliOnly: true, defaultEnabled: false, confirmation: 'plan-digest', credentials: false, responseBodiesRetained: false } }
}
