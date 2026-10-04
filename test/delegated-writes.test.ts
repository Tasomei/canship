/** 处理函数调用 service、model 等项目函数完成的写入：跟进两层，守卫在调用处判断，鉴权函数内的记账写入不算。 */

import { after, describe, test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { scan } from '../src/engine.js'
import type { Finding } from '../src/types.js'

const roots: string[] = []
after(() => { for (const root of roots) rmSync(root, { recursive: true, force: true }) })

async function findings(files: Record<string, string>): Promise<Finding[]> {
  const root = mkdtempSync(join(tmpdir(), 'canship-delegated-'))
  roots.push(root)
  for (const [path, content] of Object.entries({ 'package.json': '{"name":"x"}\n', ...files })) {
    const target = join(root, path)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, content)
  }
  return (await scan(root)).findings
}
const writes = (list: Finding[]) => list.filter(f => f.ruleId === 'api/db-write-without-auth').map(f => [f.file, f.line])

const PRISMA = "const { PrismaClient } = require('@prisma/client')\nconst prisma = new PrismaClient()\n"
const SERVICE = PRISMA + 'async function deleteProject(id) {\n  await prisma.project.delete({ where: { id } })\n}\nmodule.exports = { deleteProject }\n'
const route = (handler: string, middleware = '') => "const express = require('express')\nconst { deleteProject } = require('./services/project')\nconst app = express()\n" +
  `app.delete('/projects/:id', ${middleware}async (req, res) => {\n${handler}  await deleteProject(req.params.id)\n  res.sendStatus(204)\n})\n`

describe('writes delegated to project functions', () => {
  test('a service write reached from an open route is reported at the call, with the write location', async () => {
    const list = await findings({ 'server.js': route(''), 'services/project.js': SERVICE })
    assert.deepEqual(writes(list), [['server.js', 5]])
    const finding = list.find(f => f.ruleId === 'api/db-write-without-auth')!
    assert.ok(finding.why.some(p => p.includes('services/project.js:4')))
    assert.ok(finding.evidence?.some(step => step.file === 'services/project.js' && step.line === 4))
  })

  test('a guard in the handler or a rejecting middleware before the call protects the delegated write', async () => {
    assert.deepEqual(writes(await findings({ 'server.js': route('  if (!req.user) return res.sendStatus(401)\n'), 'services/project.js': SERVICE })), [])
    const guard = 'function requireAuth(req, res, next) {\n  if (!req.user) return res.status(401).end()\n  next()\n}\n'
    assert.deepEqual(writes(await findings({ 'server.js': guard + route('', 'requireAuth, '), 'services/project.js': SERVICE })), [])
  })

  test('a service that checks the caller itself before writing is not reported', async () => {
    const guarded = PRISMA + "async function deleteProject(id, user) {\n  if (!user) throw new Error('unauthorized')\n  await prisma.project.delete({ where: { id } })\n}\nmodule.exports = { deleteProject }\n"
    assert.deepEqual(writes(await findings({ 'server.js': route(''), 'services/project.js': guarded })), [])
  })

  test('two levels are followed (route → service → model); a third is not', async () => {
    const model = "const mongoose = require('mongoose')\nconst Project = mongoose.model('Project')\nexports.removeProject = (id) => Project.deleteOne({ _id: id })\n"
    const service = "const { removeProject } = require('../models/project')\nasync function deleteProject(id) {\n  return removeProject(id)\n}\nmodule.exports = { deleteProject }\n"
    const list = await findings({ 'server.js': route(''), 'services/project.js': service, 'models/project.js': model })
    assert.deepEqual(writes(list), [['server.js', 5]])
    assert.ok(list[0]!.why.some(p => p.includes('models/project.js:3') && p.includes('services/project.js:3')))
    const deeper = "const { removeProject } = require('./inner')\nexports.removeProject = (id) => removeProject(id)\n"
    assert.deepEqual(writes(await findings({ 'server.js': route(''), 'services/project.js': service, 'models/project.js': deeper, 'models/inner.js': model })), [])
  })

  test('methods on imported model objects and re-exported functions are resolved', async () => {
    const workspace = PRISMA + 'const Workspace = {\n  delete: async function (clause) {\n    await prisma.workspaces.delete({ where: clause })\n  },\n}\nmodule.exports = { Workspace }\n'
    const objectRoute = "const express = require('express')\nconst { Workspace } = require('../models/workspace')\nconst app = express()\n" +
      "app.delete('/workspace/:slug', async (req, res) => {\n  await Workspace.delete({ slug: req.params.slug })\n  res.end()\n})\n"
    assert.deepEqual(writes(await findings({ 'endpoints/workspace.js': objectRoute, 'models/workspace.js': workspace })), [['endpoints/workspace.js', 5]])
    const reexport = "module.exports = {\n  ...require('./userMethods'),\n}\n"
    const methods = PRISMA + 'const deleteUserById = (id) => prisma.user.delete({ where: { id } })\nmodule.exports = { deleteUserById }\n'
    const userRoute = "const express = require('express')\nconst { deleteUserById } = require('../models')\nconst app = express()\n" +
      "app.delete('/user', async (req, res) => {\n  await deleteUserById(req.body.id)\n  res.end()\n})\n"
    assert.deepEqual(writes(await findings({ 'routes/user.js': userRoute, 'models/index.js': reexport, 'models/userMethods.js': methods })), [['routes/user.js', 5]])
  })

  test('writes inside an authentication helper are part of authentication, not a delegated write', async () => {
    const auth = PRISMA + "async function requireUser(req) {\n  if (!req.user) throw new Error('unauthorized')\n  await prisma.user.update({ where: { id: req.user.id }, data: { lastSeen: new Date() } })\n  return req.user\n}\nmodule.exports = { requireUser }\n"
    const list = await findings({ 'lib/auth.js': auth, 'server.js': "const express = require('express')\nconst { requireUser } = require('./lib/auth')\nconst app = express()\n" +
      "app.get('/me', async (req, res) => {\n  res.json(await requireUser(req))\n})\n" })
    assert.deepEqual(writes(list), [])
  })

  test('file-based routes (Next.js) keep their previous behaviour', async () => {
    const list = await findings({
      'lib/projects.ts': "import { db } from './db'\nexport async function deleteProject(id: string) {\n  await db.project.delete({ where: { id } })\n}\n",
      'app/api/projects/[id]/route.ts': "import { deleteProject } from '@/lib/projects'\nexport async function DELETE(_: Request, { params }: { params: { id: string } }) {\n  await deleteProject(params.id)\n  return new Response(null, { status: 204 })\n}\n",
    })
    assert.deepEqual(writes(list), [])
  })
})
