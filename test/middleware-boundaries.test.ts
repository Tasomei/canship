/** 鉴权调用、回调顺序及实例作用域的边界回归。 */
import { after, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../src/engine.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })
async function findings(files: Record<string, string>, rule = 'api/admin-db-access-without-auth') {
  const root = mkdtempSync(join(tmpdir(), 'canship-boundaries-'))
  roots.push(root)
  for (const [name, content] of Object.entries(files)) {
    const path = join(root, name)
    mkdirSync(dirname(path), { recursive: true })
    writeFileSync(path, content)
  }
  const result = await scan(root)
  assert.equal(result.partial, false)
  assert.deepEqual(result.errors, [])
  return result.findings.filter(f => f.ruleId === rule)
}
const ADMIN = "import {createClient} from '@supabase/supabase-js';const admin=createClient(process.env.SUPABASE_URL,process.env.SUPABASE_SERVICE_ROLE_KEY);"
const WRITE = "await admin.from('items').delete().neq('id',0);"
const EXPRESS = `import express from 'express';${ADMIN}const app=express();`

for (const [body, protectedRoute] of [
  ['if(req.headers.authorization) await requireAuth(req); next();', false],
  ['req.headers.authorization &&\n await requireAuth(req); next();', false],
  ['req.headers.authorization ?\n await requireAuth(req) : null; next();', false],
  ['await requireAuth(req).catch(()=>{}); next();', false],
  ['(async()=>await requireAuth(req))(); next();', false],
  ['if(req.query.strict){if(!req.user)return res.sendStatus(401);} next();', false],
  ['requireAuth(req); next();', false],
  ['next(); await requireAuth(req);', false],
  ['try { await requireAuth(req); } catch(error) { console.log(error); } next();', false],
  ['try { validateRequest(req); } catch(error) { return res.status(401).end(); } next();', false],
  ['await requireAuth(req); next();', true],
  ['if(!req.user) return res.sendStatus(401); next();', true],
] as const) {
  test(`middleware enforcement: ${body}`, async () => {
    const source = `${EXPRESS}async function guard(req,res,next){${body}}app.post('/items',guard,async(req,res)=>{${WRITE}res.end();});`
    assert.equal((await findings({ 'server.ts': source })).length, protectedRoute ? 0 : 1)
  })
}

for (const [catchBody, protectedRoute] of [
  ['', false], ['console.log(error);', false], ['return next();', false],
  ['return res.status(400).send();', true], ['throw error;', true],
] as const) {
  test(`webhook failure must reject: ${catchBody}`, async () => {
    const source = `import express from 'express';const app=express();function check(req,res,next){
      try{req.body=stripe.webhooks.constructEvent(req.body,req.headers['stripe-signature'],process.env.STRIPE_WEBHOOK_SECRET);}
      catch(error){${catchBody}}next();}
      app.post('/stripe',check,async(req,res)=>{const event=req.body;if(event.type==='invoice.paid')await markPaid(event.data.object.id);res.end();});`
    assert.equal((await findings({ 'server.ts': source }, 'webhook/unverified-signature')).length, protectedRoute ? 0 : 1)
  })
}

for (const [implementation, awaited, protectedRoute] of [
  ['return Promise.resolve(null);', false, false],
  ['return validateAsync(token);', false, false],
  ['return Promise.resolve(null);', true, true],
  ['return token ? { id: 1 } : null;', false, true],
] as const) {
  test(`a non-async declaration does not prove a synchronous result: ${implementation}/${awaited}`, async () => {
    const source = `${ADMIN}function validateSessionToken(token){${implementation}}
      export async function POST(req){const token=req.headers.get('authorization');
      const session=${awaited ? 'await ' : ''}validateSessionToken(token);
      if(!session)return new Response('no',{status:401});${WRITE}return new Response('ok');}`
    assert.equal((await findings({ 'app/api/items/route.ts': source })).length, protectedRoute ? 0 : 1)
  })
}

for (const prefix of ['/', '*']) {
  test(`Hono inherited middleware keeps its path: ${prefix}`, async () => {
    const files = {
      'server.ts': `import {Hono} from 'hono';import {bearerAuth} from 'hono/bearer-auth';import {routes} from './routes';
        const app=new Hono();app.use('${prefix}',bearerAuth({token:process.env.AUTH_TOKEN}));routes(app);`,
      'routes.ts': `${ADMIN}export function routes(router){router.post('/items',async(c)=>{${WRITE}return c.json({ok:true});});}`,
    }
    assert.equal((await findings(files)).length, prefix === '*' ? 0 : 1)
  })
}

test('named callbacks before the final responder are scanned', async () => {
  const source = `${EXPRESS}async function remove(req,res,next){${WRITE}next();}app.post('/items',remove,(req,res)=>res.end());`
  assert.equal((await findings({ 'server.ts': source })).length, 1)
})

for (const body of ['if(req.headers.authorization) await req.jwtVerify();', 'try { await req.jwtVerify(); } catch(error) { return; }']) {
  test(`Fastify rejection must cover missing credentials and failures: ${body}`, async () => {
    const source = `import Fastify from 'fastify';${ADMIN}const app=Fastify();
      app.addHook('onRequest',async(req,reply)=>{${body}});
      app.post('/items',async(req,reply)=>{${WRITE}return {};});`
    assert.equal((await findings({ 'server.ts': source })).length, 1)
  })
}

test('imported callbacks before the final responder are scanned', async () => {
  assert.equal((await findings({
    'server.ts': "import express from 'express';import {remove} from './controller';const app=express();app.post('/items',remove,(req,res)=>res.end());",
    'controller.ts': `${ADMIN}export async function remove(req,res,next){${WRITE}next();}`,
  })).length, 1)
})

for (const guarded of [false, true]) {
  test(`Fastify decorators cannot borrow another application's implementation: ${guarded}`, async () => {
    assert.equal((await findings({
      'private.ts': "import Fastify from 'fastify';const privateApp=Fastify();privateApp.decorate('authenticate',async(req,reply)=>{if(!req.user)return reply.code(401).send();});",
      'public.ts': `import Fastify from 'fastify';${ADMIN}const publicApp=Fastify();
        publicApp.decorate('authenticate',async(req,reply)=>{${guarded ? 'if(!req.user)return reply.code(401).send();' : ''}});
        publicApp.post('/items',{onRequest:publicApp.authenticate},async(req,reply)=>{${WRITE}return {};});`,
    })).length, guarded ? 0 : 1)
  })
}

test('an imported passthrough helper does not erase request-input evidence', async () => {
  assert.equal((await findings({
    'lib/identity.ts': 'export function identity(value){return value;}',
    'app/api/items/route.ts': "import {identity} from '../../../lib/identity';export async function POST(req){const body=await req.json();const {id}=identity(body);return prisma.$queryRawUnsafe('SELECT * FROM items WHERE id='+id);}",
  }, 'injection/sql')).length, 1)
})

test('a Promise-returning arrow cannot borrow a later function body', async () => {
  assert.equal((await findings({ 'app/api/items/route.ts': `${ADMIN}
    const validateSessionToken = token => Promise.resolve(null);
    function other(){return null;}
    export async function POST(req){const session=validateSessionToken(req.headers.get('authorization'));
      if(!session)return new Response('no',{status:401});${WRITE}return new Response('ok');}`,
  })).length, 1)
})

for (const registered of [false, true]) {
  test(`Fastify library decorators require registration on the current instance: ${registered}`, async () => {
    assert.equal((await findings({
      'other.ts': "import basicAuth from '@fastify/basic-auth';export {basicAuth};",
      'server.ts': `import Fastify from 'fastify';import basicAuth from '@fastify/basic-auth';${ADMIN}const app=Fastify();
        ${registered ? "app.register(basicAuth,{validate:validateCredentials});" : 'app.basicAuth=async(req,reply)=>{};'}
        app.post('/items',{onRequest:app.basicAuth},async(req,reply)=>{${WRITE}return {};});`,
    })).length, registered ? 0 : 1)
  })
}
