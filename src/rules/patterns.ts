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
  /** 规则目录名称；前缀由多家共用时与报告名称不同。 */
  catalogName?: string
  /** 前缀由多家共用时按周边文本确定提供方；返回 null 时沿用默认描述。 */
  describe?: (secret: string, context: SecretContext) => SecretLabel | null
}

/** 判断提供方的周边文本；行内证据优先于整个文件。 */
export interface SecretContext {
  line: string
  text: string
  /** line 仅为变量名时，其中的提供方名称直接确定归属。 */
  lineIsName?: boolean
}

/** 报告中的凭据名称及处置说明。 */
export type SecretLabel = Pick<SecretPattern, 'name' | 'impact' | 'rotateAt' | 'rotateLabel'>

/** 排除示例域名及本地开发地址。 */
const IRRELEVANT_HOSTS =
  /^(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]|host\.docker\.internal|.*\.?example\.(?:com|org|net)|.*\.(?:test|invalid|localhost))$/i

/** 多条规则共用的凭据格式源。 */
export const JWT_SOURCE = String.raw`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`

/** Supabase 服务端私密密钥格式。 */
export const SB_SECRET_SOURCE = String.raw`sb_secret_[A-Za-z0-9_-]{8,}`

/** PEM 私钥标头；检测与整块脱敏共用。 */
export const PRIVATE_KEY_BEGIN_SOURCE = String.raw`-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY(?: BLOCK)?-----`

/** 依次检查行内和整个文件，只有一方证据时才确定提供方。 */
function providerIn(context: SecretContext, choose: (text: string) => SecretLabel | 'default' | null): SecretLabel | 'default' | null {
  return choose(context.line) ?? choose(context.text)
}

/** 指向非 OpenAI 地址的 baseURL / base_url 配置。 */
const FOREIGN_BASE_URL = /\bbase_?url\b["'`]?\s*[:=]\s*["'`]https?:\/\/(?!api\.openai\.com\b)[^\s"'`]+/i

const DEEPSEEK_KEY: SecretLabel = {
  name: 'DeepSeek API key',
  impact: 'Anyone with this key can call DeepSeek models billed to your account.',
  rotateAt: 'the DeepSeek platform (https://platform.deepseek.com)',
}

const COMPATIBLE_KEY: SecretLabel = {
  name: 'API key for an OpenAI-compatible service',
  impact: 'This sk- key is configured for a non-OpenAI endpoint. Anyone with it can call that service and spend the credit of your account there.',
  rotateLabel: 'key',
  rotateAt: 'the console of the service named in the base URL',
}

const SK_DASH_KEY: SecretLabel = {
  name: 'OpenAI-style API key',
  impact: 'This key uses the sk- format shared by OpenAI and several OpenAI-compatible providers. Anyone with it can spend the credit of the account that issued it.',
  rotateLabel: 'key',
  rotateAt: 'the console of the provider that issued it (OpenAI: https://platform.openai.com/api-keys)',
}

const CLERK_LIVE_KEY: SecretLabel = {
  name: 'Clerk secret key',
  impact: 'This is a production Clerk secret key. It grants full access to the Clerk Backend API: anyone holding it can read, create, modify and delete your users and their sessions.',
  rotateAt: 'the Clerk Dashboard (https://dashboard.clerk.com), under API keys',
}

const SK_LIVE_KEY: SecretLabel = {
  name: 'sk_live_ secret key',
  impact: 'Stripe and Clerk both issue production secret keys in this format. A Stripe key can read customer records and move real money; a Clerk key gives full access to your users and sessions.',
  rotateLabel: 'key',
  rotateAt: 'the dashboard of the service that issued it (Stripe: https://dashboard.stripe.com/apikeys; Clerk: https://dashboard.clerk.com)',
}

export const SECRET_PATTERNS: SecretPattern[] = [
  {
    id: 'openai',
    name: 'OpenAI API key',
    catalogName: 'OpenAI or OpenAI-compatible API key',
    // OpenRouter 密钥同样以 sk- 开头，由下方的专用格式识别。
    pattern: /\bsk-(?!ant-|or-v1-)(?:proj-)?[A-Za-z0-9_-]{20,}\b/g,
    impact: 'Anyone with this key can spend your OpenAI credit. Leaked keys are typically abused within minutes of going public.',
    rotateAt: 'https://platform.openai.com/api-keys',
    // DeepSeek 等兼容服务同样使用 sk- 前缀；只有 OpenAI 专用前缀或标记可直接确定提供方。
    describe: (secret, context) => {
      if (/^sk-(?:proj|svcacct|admin)-/.test(secret) || secret.includes('T3BlbkFJ')) return null
      // 兼容服务常用 OpenAI SDK 调用，因此代码中的 openai 字样只在没有其他服务证据时生效；变量名除外。
      const other = (text: string) => /deepseek/i.test(text) ? DEEPSEEK_KEY : FOREIGN_BASE_URL.test(text) ? COMPATIBLE_KEY : null
      const inLine = other(context.line)
      if (inLine !== null) return inLine
      if (context.lineIsName && /openai/i.test(context.line)) return null
      return other(context.text) ?? (/openai/i.test(context.line) || /openai/i.test(context.text) ? null : SK_DASH_KEY)
    },
  },
  {
    id: 'anthropic',
    name: 'Anthropic API key',
    pattern: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    impact: 'Anyone with this key can spend your Anthropic credit.',
    rotateAt: 'https://console.anthropic.com/settings/keys',
  },
  // 以下前缀取自各服务官方文档；除 Replicate 外文档未给出长度，只设最小长度以排除示例占位符。
  {
    id: 'openrouter',
    name: 'OpenRouter API key',
    pattern: /\bsk-or-v1-[A-Za-z0-9]{32,}\b/g,
    impact: 'Anyone with this key can spend your OpenRouter credit on any model it routes to, up to the key\'s limit.',
    rotateAt: 'https://openrouter.ai/settings/keys',
  },
  {
    id: 'groq',
    name: 'Groq API key',
    pattern: /\bgsk_[A-Za-z0-9]{40,}\b/g,
    impact: 'Anyone with this key can run models on your Groq account and use up its rate limits and billing.',
    rotateAt: 'https://console.groq.com/keys',
  },
  {
    id: 'huggingface',
    name: 'Hugging Face access token',
    pattern: /\bhf_[A-Za-z0-9]{30,}\b/g,
    impact: 'Depending on its scope, this token can read your private models and datasets, push to your repositories, and spend on paid inference.',
    rotateAt: 'https://huggingface.co/settings/tokens',
  },
  {
    id: 'replicate',
    name: 'Replicate API token',
    // 官方文档：共 40 个字符，始终以 r8_ 开头。
    pattern: /\br8_[A-Za-z0-9]{37}\b/g,
    impact: 'Anyone with this token can run paid predictions on your Replicate account and read your models and predictions.',
    rotateAt: 'https://replicate.com/account/api-tokens',
  },
  {
    id: 'xai',
    name: 'xAI API key',
    pattern: /\bxai-[A-Za-z0-9]{40,}\b/g,
    impact: 'Anyone with this key can call Grok models on your xAI account and spend its credit.',
    rotateAt: 'https://console.x.ai',
  },
  {
    id: 'perplexity',
    name: 'Perplexity API key',
    pattern: /\bpplx-[A-Za-z0-9]{40,}\b/g,
    impact: 'Anyone with this key can run Perplexity API requests billed to your account.',
    rotateAt: 'https://console.perplexity.ai',
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
    catalogName: 'Stripe or Clerk live secret key',
    // Clerk 生产私密密钥同样以 sk_live_ 开头；rk_live_ 仅为 Stripe 受限密钥。
    describe: (secret, context) => {
      if (secret.startsWith('rk_')) return null
      const found = providerIn(context, text => {
        const clerk = /clerk/i.test(text)
        return clerk === /stripe/i.test(text) ? null : clerk ? CLERK_LIVE_KEY : 'default'
      })
      return found === 'default' ? null : found ?? SK_LIVE_KEY
    },
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
  // 以下格式参照 gitleaks 默认规则，只收录前缀可自证提供方、无需关键字上下文的格式。
  {
    id: 'gitlab-token',
    name: 'GitLab token',
    pattern: /\b(?:glpat|gldt)-[0-9A-Za-z_-]{20,300}(?:\.[0-9a-z]{9})?(?![0-9A-Za-z_-])|\bglptt-[0-9a-f]{40}\b/g,
    impact: 'Depending on its scope, this token can read and push to your GitLab repositories, including private ones, or trigger pipelines.',
    rotateAt: 'your GitLab settings (personal, project or deploy tokens)',
  },
  {
    id: 'shopify-token',
    name: 'Shopify app token or secret',
    pattern: /\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b/g,
    impact: 'Depending on the app\'s access scopes, this can read and change your store\'s orders, customers and products.',
    rotateAt: 'the Shopify admin or Partner Dashboard where the app was created',
  },
  {
    id: 'linear-api-key',
    name: 'Linear API key',
    pattern: /\blin_api_[A-Za-z0-9]{40}\b/g,
    impact: 'Anyone with this key can read and change your Linear issues, projects and comments as you.',
    rotateAt: 'your Linear account settings (API keys)',
  },
  {
    id: 'notion-token',
    name: 'Notion integration token',
    pattern: /\bntn_[0-9]{11}[A-Za-z0-9]{35}\b/g,
    impact: 'Anyone with this token can read and edit every Notion page and database shared with the integration.',
    rotateAt: 'the Notion integration settings',
  },
  {
    id: 'digitalocean-token',
    name: 'DigitalOcean personal access token',
    pattern: /\bdop_v1_[a-f0-9]{64}\b/g,
    impact: 'Depending on its scope, this token can create, read and destroy Droplets, databases and other billed resources in your DigitalOcean account.',
    rotateAt: 'https://cloud.digitalocean.com/account/api/tokens',
  },
  {
    id: 'sentry-user-token',
    name: 'Sentry user auth token',
    pattern: /\bsntryu_[a-f0-9]{64}\b/g,
    impact: 'Depending on its scopes, this token can read your error events, which often contain user data, and change projects in your Sentry organization.',
    rotateAt: 'your Sentry user settings (personal tokens)',
  },
  {
    id: 'planetscale-credential',
    name: 'PlanetScale token or password',
    pattern: /\bpscale_(?:tkn|pw)_[A-Za-z0-9_=.-]{32,64}(?![A-Za-z0-9_=.-])/g,
    impact: 'A database password gives direct access to your data; a service token can manage databases and branches in your PlanetScale organization.',
    rotateAt: 'your PlanetScale organization (database passwords or service tokens)',
  },
  {
    id: 'doppler-token',
    name: 'Doppler personal token',
    pattern: /\bdp\.pt\.[A-Za-z0-9]{43}\b/g,
    impact: 'Anyone with this token can read every secret your Doppler account can access.',
    rotateAt: 'the Doppler dashboard (personal tokens)',
  },
  {
    id: 'flyio-token',
    name: 'Fly.io access token',
    pattern: /\bfo1_[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g,
    impact: 'Anyone with this token can deploy, read secrets of, and destroy apps in your Fly.io organization.',
    rotateAt: 'the Fly.io dashboard or `fly tokens revoke`',
  },
  {
    id: 'postman-api-key',
    name: 'Postman API key',
    pattern: /\bPMAK-[a-fA-F0-9]{24}-[a-fA-F0-9]{34}\b/g,
    impact: 'Anyone with this key can read your Postman workspaces, including collections and environments that often hold other credentials.',
    rotateAt: 'your Postman account settings (API keys)',
  },
  {
    id: 'heroku-api-key',
    name: 'Heroku API key',
    pattern: /\bHRKU-AA[0-9A-Za-z_-]{58}(?![0-9A-Za-z_-])/g,
    impact: 'Anyone with this key can deploy to, read config vars of, and delete your Heroku apps.',
    rotateAt: 'your Heroku account settings (API key or authorizations)',
  },
  {
    // Stripe 官方文档确认此前缀；其他 webhook 服务也可能使用，故采用中性名称。
    id: 'webhook-signing-secret',
    name: 'Webhook signing secret',
    pattern: /\bwhsec_[A-Za-z0-9+/]{24,}={0,2}/g,
    impact: 'Anyone with this secret can forge webhook events that your endpoint accepts as genuine, for example marking unpaid orders as paid.',
    rotateLabel: 'signing secret',
    rotateAt: 'the webhook endpoint settings of the service that issued it (Stripe: Dashboard -> Webhooks)',
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
    pattern: new RegExp(PRIVATE_KEY_BEGIN_SOURCE, 'g'),
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

/** 获取报告使用的凭据名称及处置说明。 */
export function labelOf(pat: SecretPattern, secret: string, context: SecretContext): SecretLabel {
  return pat.describe?.(secret, context) ?? pat
}

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
  const body = lower.replace(/^(sk-ant-|sk-proj-|sk-or-v1-|sk-|rk_live_|sk_live_|akia|aiza|sg\.|gh[pousr]_|gsk_|hf_|r8_|xai-|pplx-|glpat-|gldt-|glptt-|shp(?:at|ca|pa|ss)_|lin_api_|ntn_|dop_v1_|sntryu_|pscale_(?:tkn|pw)_|dp\.pt\.|fo1_|pmak-|hrku-aa|whsec_)/, '')
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
