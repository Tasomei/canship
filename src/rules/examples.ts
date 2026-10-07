/** 修复示例说明常见模式，不代表可直接替换项目代码或完成运行时验证。 */
import { SECRET_PATTERNS } from './patterns.js'
export interface FixExample {
  context: string
  before: string
  after: string
  limitation: string
}
const publicEnv: FixExample = {
  context: 'Server-only environment value',
  before: 'NEXT_PUBLIC_SERVER_TOKEN=<private value>',
  after: 'SERVER_TOKEN=<server-only value>',
  limitation: 'Use the value only in server code. Rotate any exposed credential; renaming does not revoke it.',
}
const auth: FixExample = {
  context: 'Supabase route with a request-scoped session client and a separate admin client',
  before: "await admin.from('items').delete().eq('id', id);",
  after: "const { data: { user }, error } = await sessionClient.auth.getUser();\nif (error || !user) return new Response(null, { status: 401 });\nif (!await canDelete(user.id, id)) return new Response(null, { status: 403 });\nawait admin.from('items').delete().eq('id', id);",
  limitation: 'Bind sessionClient to the caller. Implement canDelete with actual resource ownership or permissions; authentication alone is insufficient.',
}
const firestore: FixExample = {
  context: 'Firestore document ownership',
  before: 'match /users/{uid} { allow read, write: if true; }',
  after: 'match /users/{uid} {\n  allow read, write: if request.auth != null && request.auth.uid == uid;\n}',
  limitation: 'Firestore syntax only. Review field validation and overlapping rules; adapt ownership to the data model.',
}
const cors: FixExample = {
  context: 'Express cors middleware with credentialed access from one trusted site',
  before: 'app.use(cors({ origin: true, credentials: true }));',
  after: "app.use(cors({ origin: 'https://app.example.com', credentials: true }));",
  limitation: 'Replace the example origin with an exact trusted origin. CORS does not replace authentication, authorization or CSRF controls.',
}
const examples: Readonly<Record<string, FixExample>> = {
  'api/admin-db-access-without-auth': auth,
  'api/db-write-without-auth': auth,
  'exposure/private-name-in-public-env': publicEnv,
  'exposure/secret-in-public-env': publicEnv,
  'exposure/supabase-service-role-in-client': { ...publicEnv, context: 'Supabase admin credential',
    limitation: 'Never ship an admin key to the client. Use a publishable/anon key with appropriate RLS for client access; rotate exposed admin credentials.' },
  'cors/reflected-origin-with-credentials': cors,
  'cors/wildcard-with-credentials': { ...cors, before: "app.use(cors({ origin: '*', credentials: true }));" },
  'firebase/open-rules': firestore,
  'firebase/test-mode-rules': { ...firestore, before: 'allow read, write: if request.time < timestamp.date(2030, 1, 1);' },
  'supabase/rls-not-enabled': {
    context: 'Supabase table with a UUID owner_id column',
    before: 'CREATE TABLE public.notes (id uuid PRIMARY KEY, owner_id uuid NOT NULL, body text);',
    after: 'ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;\nCREATE POLICY owner_access ON public.notes TO authenticated\nUSING ((SELECT auth.uid()) = owner_id)\nWITH CHECK ((SELECT auth.uid()) = owner_id);',
    limitation: 'Apply ownership checks appropriate to the application. Review grants and other policies; service-role access bypasses RLS.',
  },
  'auth/unverified-session': {
    context: 'Server-side Supabase identity verification',
    before: 'const { data: { session } } = await supabase.auth.getSession();\nif (!session) return new Response(null, { status: 401 });',
    after: 'const { data: { user }, error } = await supabase.auth.getUser();\nif (error || !user) return new Response(null, { status: 401 });',
    limitation: 'Use a client bound to the current request. Verified identity still requires resource-specific authorization.',
  },
  'injection/sql': {
    context: 'PostgreSQL driver with bound parameters',
    before: 'await db.query("SELECT * FROM users WHERE id = " + id);',
    after: "await db.query('SELECT * FROM users WHERE id = $1', [id]);",
    limitation: 'Use the parameter syntax of your actual driver. Parameters do not substitute table names or authorize access.',
  },
  'injection/command': {
    context: 'A fixed executable with separately validated arguments',
    before: "exec('tool --input ' + requestValue);",
    after: "execFile(TRUSTED_EXECUTABLE, ['--input', validatedValue], { shell: false });",
    limitation: 'Set TRUSTED_EXECUTABLE to a trusted absolute path. Validate argument meaning and filesystem access; never let the caller choose the executable.',
  },
  'redirect/open': {
    context: 'Named destinations on a fixed application origin',
    before: 'return Response.redirect(requestedUrl);',
    after: "const path = destination === 'settings' ? '/settings' : '/dashboard';\nreturn Response.redirect(new URL(path, APP_ORIGIN));",
    limitation: 'APP_ORIGIN must be trusted configuration, not a request header. Do not replace the fixed paths with caller-controlled URLs.',
  },
  'ssrf/request-url': {
    context: 'Named server resources instead of caller-provided hosts',
    before: 'return fetch(requestedUrl);',
    after: "if (resource !== 'status') return new Response(null, { status: 400 });\nreturn fetch('https://api.example.com/status', { redirect: 'error' });",
    limitation: 'Use a destination you control. Review DNS and egress restrictions; a URL allowlist alone is not a complete SSRF defense.',
  },
  'webhook/unverified-signature': {
    context: 'Stripe webhook using the original request-body bytes',
    before: 'const event = JSON.parse(rawBody);\nawait handle(event);',
    after: 'let event;\ntry { event = stripe.webhooks.constructEvent(rawBody, signature, SERVER_SIGNING_SECRET); }\ncatch { return new Response(null, { status: 400 }); }\nawait handle(event);',
    limitation: 'Preserve raw bytes and use the endpoint signing secret. Verification must finish before side effects; implement replay/idempotency handling separately.',
  },
}

/** 返回副本，调用方不能修改后续报告的示例。 */
export function fixExampleFor(ruleId: string): FixExample | null {
  if (SECRET_PATTERNS.some(pattern => !pattern.publicByDesign && ruleId === `secrets/hardcoded/${pattern.id}`)) return {
    context: 'A credential used only by a server runtime',
    before: "const apiKey = '<private value>';",
    after: "const apiKey = process.env.SERVICE_API_KEY;\nif (!apiKey) throw new Error('Server credential is missing');",
    limitation: 'Use trusted server-side configuration, never a public/client environment prefix. Rotate the old credential and review history and deployed bundles.',
  }
  if (!Object.hasOwn(examples, ruleId)) return null
  return { ...examples[ruleId]! }
}
