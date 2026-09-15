/** 共享凭据模式，仅收录具有明确格式的值；不使用熵值推断。 */

export interface SecretPattern {
  /** 规则 ID 后缀。 */
  id: string
  /** 报告中的凭据名称。 */
  name: string
  /** 带全局标记的匹配模式。 */
  pattern: RegExp
  /** 凭据暴露的实际影响。 */
  impact: string
  /** 凭据轮换入口。 */
  rotateAt?: string
  /** 适用于轮换指令的名称。 */
  rotateLabel?: string
  /** 用于占位符判断的实际秘密捕获组。 */
  secretGroup?: number
  /** 附加排除条件；返回真值时不报告。 */
  ignoreIf?: (match: RegExpExecArray) => boolean
  /** 提供方按设计允许公开的标识符。 */
  publicByDesign?: boolean
}

/** 排除示例域名及本地开发地址。 */
const IRRELEVANT_HOSTS =
  /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal|.*\.?example\.(?:com|org|net)|.*\.(?:test|invalid|localhost))$/i

/** 多条规则共用的凭据格式源。 */
export const JWT_SOURCE = String.raw`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`

/** Supabase 服务端私密密钥格式。 */
export const SB_SECRET_SOURCE = String.raw`sb_secret_[A-Za-z0-9_-]{8,}`

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'openai',
    name: 'OpenAI API key',
    pattern: /\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    impact: 'Anyone with this key can spend your OpenAI credit. Leaked keys are typically abused within minutes of going public.',
    rotateAt: 'https://platform.openai.com/api-keys',
  },
  {
    id: 'anthropic',
    name: 'Anthropic API key',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    impact: 'Anyone with this key can spend your Anthropic credit.',
    rotateAt: 'https://console.anthropic.com/settings/keys',
  },
  {
    id: 'aws-access-key-id',
    name: 'AWS access key ID',
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    impact: 'Combined with its secret, this grants access to your AWS account — S3 buckets, databases, and compute you pay for.',
    rotateAt: 'https://console.aws.amazon.com/iam/home#/security_credentials',
  },
  {
    id: 'stripe-live',
    name: 'Stripe live secret key',
    pattern: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g,
    impact: 'This is a LIVE key. Anyone holding it can read your customer records and move real money.',
    rotateAt: 'https://dashboard.stripe.com/apikeys',
  },
  {
    id: 'github-token',
    name: 'GitHub token',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
    impact: 'Grants access to your repositories — including private ones, and the ability to push code.',
    rotateAt: 'https://github.com/settings/tokens',
  },
  {
    id: 'npm-token',
    name: 'npm access token',
    // 仅检查令牌形状，不校验其校验码。
    pattern: /\bnpm_[A-Za-z0-9]{36}\b/g,
    impact:
      'Publishes packages under your account. Anyone who installs one afterwards runs whatever that version contains.',
    rotateAt: 'https://docs.npmjs.com/creating-and-viewing-access-tokens',
  },
  {
    id: 'google-api-key',
    name: 'Google API key',
    pattern: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    impact: 'Depending on its scope, this can be used to run up billed usage on Google Cloud services.',
    rotateAt: 'https://console.cloud.google.com/apis/credentials',
    // Google 项目标识符不直接作为私密凭据报告。
    publicByDesign: true,
  },
  {
    id: 'slack-token',
    name: 'Slack token',
    pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g,
    impact: 'Grants access to your Slack workspace — reading messages and posting as you or your bot.',
    rotateAt: 'https://api.slack.com/apps',
  },
  {
    id: 'sendgrid',
    name: 'SendGrid API key',
    pattern: /\bSG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{22,}\b/g,
    impact: 'Anyone with this key can send email from your domain — which means they can send phishing email that passes your SPF/DKIM checks.',
    rotateAt: 'https://app.sendgrid.com/settings/api_keys',
  },
  {
    id: 'supabase-secret-key',
    name: 'Supabase secret key',
    rotateLabel: 'Supabase secret key',
    // 共享新版 Supabase 私密密钥模式，与公开密钥区分。
    pattern: new RegExp(String.raw`\b${SB_SECRET_SOURCE}\b`, 'g'),
    impact:
      'This is the server-side Supabase key. It bypasses every Row Level Security policy — it is effectively your database root password.',
    rotateAt: 'your Supabase dashboard, Project Settings -> API Keys',
  },
  {
    id: 'private-key',
    name: 'Private key file contents',
    rotateLabel: 'private key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
    impact: 'A private key in source code can be used to impersonate your server, decrypt traffic, or log into your machines.',
  },
  {
    id: 'db-connection-string',
    name: 'Database connection string with password',
    pattern:
      /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^\s:@/'"`]+:([^\s@/'"`]+)@(\[[^\]\s]+\]|[^\s'"`/:]+)(?::\d+)?(?:[/?#][^\s'"`]*)?/g,
    // 仅用密码组判断占位符，避免主机名影响判断。
    secretGroup: 1,
    // 支持 IPv6，并排除示例和本地地址。
    ignoreIf: (m) => IRRELEVANT_HOSTS.test(m[2] ?? ''),
    rotateLabel: 'database password',
    impact: 'This contains your database username AND password. Anyone with it can read, modify, or delete your entire database.',
  },
]

/** 获取应参与占位符判断的秘密部分。 */
export function secretPartOf(match: RegExpExecArray, pat: SecretPattern): string {
  if (pat.secretGroup === undefined) return match[0]
  return match[pat.secretGroup] ?? match[0]
}

/** 仅完整模板标记可按形状排除。 */
const PLACEHOLDER_SHAPE = /^(?:<[^>\r\n]*>|\[[^\]\r\n]*\]|\.\.\.|\*{4,})$/

/** 占位词必须占据完整片段，避免随机值误命中。 */
const LONG_PLACEHOLDER_SEGMENT =
  /(?:^|[-_.])(?:youre|example|placeholder|changeme|change-me|change_me|replace|insert|paste|dummy|sample|test-key|testkey|fixme|abcdef|123456|foobar|redacted|hidden)(?:[-_.]|$)/i

/** 短占位前缀必须有明确分隔符。 */
const MY_PREFIX = /(?:^|[-_.])my[-_.]/i

/** 短占位词必须同时满足前后边界。 */
const SHORT_PLACEHOLDER =
  /(?:^|[-_.])(?:x{4,}|y{4,}|z{4,}|your|here|goes|todo|fake)(?:[-_.]|$)/i

/** 连续文本至少包含两个占位词才判为模板。 */
const COUNTED_PLACEHOLDER_WORDS =
  /youre|example|placeholder|changeme|replace|insert|paste|dummy|sample|testkey|fixme|foobar|redacted|hidden|your|here|goes|todo|fake/gi

function namesItselfTwice(secret: string): boolean {
  // 共享全局模式每次使用前后都重置位置。
  COUNTED_PLACEHOLDER_WORDS.lastIndex = 0
  const seen = new Set<string>()
  let match: RegExpExecArray | null
  while ((match = COUNTED_PLACEHOLDER_WORDS.exec(secret)) !== null) {
    seen.add(match[0].toLowerCase())
    if (seen.size >= 2) break
  }
  COUNTED_PLACEHOLDER_WORDS.lastIndex = 0
  return seen.size >= 2
}

/** 识别凭据内部的独立测试片段。 */
const DUMMY_SEGMENT = /(?:^|[-_.])(?:test|dummy|fake|sample|placeholder|example|demo|mock|stub)(?:[-_.]|$)/i

/** 仅带分隔符的测试前缀可作为占位信号。 */
const DUMMY_PREFIX = /^(?:test|dummy|fake|sample|placeholder|example|demo|mock|stub|dev|local)[-_]/i

/** 判断值是否为明确占位符。 */
export function isPlaceholder(secret: string): boolean {
  const lower = secret.toLowerCase()
  if (DUMMY_PREFIX.test(secret)) return true
  if (DUMMY_SEGMENT.test(secret)) return true
  if (MY_PREFIX.test(secret)) return true
  if (SHORT_PLACEHOLDER.test(secret)) return true
  if (LONG_PLACEHOLDER_SEGMENT.test(secret)) return true
  if (namesItselfTwice(secret)) return true
  if (PLACEHOLDER_SHAPE.test(secret)) return true

  // 移除提供方前缀后，低字符多样性值视为模板。
  const body = lower.replace(/^(sk-ant-|sk-proj-|sk-|rk_live_|sk_live_|akia|aiza|sg\.|gh[pousr]_)/, '')
  if (body.length >= 8) {
    const distinct = new Set(body.replace(/[^a-z0-9]/g, '')).size
    if (distinct <= 3) return true
  }
  return false
}

/** 要求已知凭据格式匹配整个值。 */
export function findKnownSecret(value: string): SecretPattern | null {
  const trimmed = value.trim()
  for (const pat of SECRET_PATTERNS) {
    pat.pattern.lastIndex = 0
    const m = pat.pattern.exec(trimmed)
    // 重置共享模式的匹配位置。
    pat.pattern.lastIndex = 0
    if (m === null || m[0] !== trimmed) continue
    // 统一应用占位符和附加排除条件。
    if (isPlaceholder(secretPartOf(m, pat)) || pat.ignoreIf?.(m)) continue
    return pat
  }
  return null
}

/** 判断完整值是否为已知凭据。 */
export function matchesKnownSecret(value: string): boolean {
  return findKnownSecret(value) !== null
}

/** 注释中的凭据仍需报告，此判断仅用于补充说明。 */
export function isCommentedOut(line: string): boolean {
  return /^\s*(?:\/\/|#|\/\*|\*)/.test(line)
}
