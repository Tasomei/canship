/** 框架说明与路由类别、双语标识及代表性正反例保持关联。 */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import type { Route } from '../src/rules/apiauth.js'

const read = (file: string) => readFileSync(new URL('../' + file, import.meta.url), 'utf8')
const pages = ['docs/framework-support.md', 'docs/framework-support-zh-CN.md'].map(read)
const evidence = {
  next: ['Next.js', 'frameworks', 'an exported action writing with the admin client is reported by name',
    'a file that only mentions the directive is not an action file'],
  sveltekit: ['SvelteKit', 'frameworks', 'a +server.ts endpoint is checked',
    'a page server file without actions is not a route'],
  nuxt: ['Nuxt / Nitro', 'frameworks', 'a server/routes route is checked',
    'a tRPC router under src/server/api is not a Nuxt route'],
  remix: ['Remix / React Router', 'frameworks', 'a loader in a flat route file is checked',
    'a route module without a loader or action is not requestable'],
  astro: ['Astro', 'frameworks', 'an endpoint outside /api is checked too',
    'a script in src/pages that exports no HTTP method is not an endpoint'],
  express: ['Express', 'express', 'an unprotected write is reported with the registered path',
    'calls that only look like routes are ignored without an express import'],
  hono: ['Hono', 'hono', 'an unprotected write is reported with the registered path',
    'middleware that only logs, or applies to another path, does not protect the route'],
  fastify: ['Fastify', 'fastify', 'shorthand routes, options objects, and full declarations are found',
    'hooks apply within the plugin and to plugins registered after them, not to siblings'],
} satisfies Record<Route['framework'], [string, string, string, string]>

const sections = (page: string) => page.split(/^## /m).slice(1).map(part => {
  const newline = part.indexOf('\n')
  return { heading: part.slice(0, newline).trim(), body: part.slice(newline + 1) }
})
const links = (text: string) => [...text.matchAll(/\]\((https:\/\/github\.com\/Tasomei\/canship\/blob\/main\/test\/[^)]+)\)/g)].map(match => match[1]!)

test('each route framework documents live positive and boundary regression cases', () => {
  for (const [heading, suite, positive, boundary] of Object.values(evidence)) {
    const file = `test/${suite}.test.ts`
    const source = read(file)
    for (const title of [positive, boundary]) assert.ok(source.includes(`test('${title}',`), `${file}: missing regression ${title}`)
    for (const page of pages) {
      const matches = sections(page).filter(section => section.heading === heading)
      assert.equal(matches.length, 1, `${heading}: exactly one section per language`)
      assert.ok(links(matches[0]!.body).includes(`https://github.com/Tasomei/canship/blob/main/${file}`), heading)
    }
  }
})

test('bilingual framework sections retain identical technical identifiers and evidence links', () => {
  const en = sections(pages[0]!), zh = sections(pages[1]!)
  assert.equal(en.length, Object.keys(evidence).length + 2)
  assert.equal(zh.length, en.length)
  const tokens = (text: string) => [...text.matchAll(/`([^`]+)`/g)].map(match => match[1])
  for (let index = 0; index < en.length; index++) {
    assert.deepEqual(tokens(en[index]!.body), tokens(zh[index]!.body), en[index]!.heading)
    assert.deepEqual(links(en[index]!.body), links(zh[index]!.body), en[index]!.heading)
  }
})

test('framework evidence links point to existing local test files', () => {
  for (const page of pages) {
    const references = links(page)
    assert.ok(references.length >= Object.keys(evidence).length)
    for (const link of references) {
      const file = link.slice('https://github.com/Tasomei/canship/blob/main/'.length)
      assert.match(file, /^test\/[a-z-]+\.test\.ts$/)
      assert.match(read(file), /\btest\(/, file)
    }
  }
})
