/**
 * 请求输入进入 SQL 文本或 shell 命令。只检查可被直接请求的路由与 Server Function，
 * 只追踪同一函数内的赋值和拼接；参数化查询与带标签的模板不报告。
 */
import type { Finding, ProjectRule, ScanContext, ScanFile } from '../types.js'
import { commentsMaskedOf } from '../mask.js'
import { lineNumberAt } from './offsets.js'
import { bindingsOf, namePattern } from './bindings.js'
import { argumentExpressions } from './auth-values.js'
import type { Route } from './apiauth.js'
import { InputFlow, handlerFileOf, reportInputLimit, type Taint } from './request-input.js'

type SinkKind = 'sql' | 'command'

/** 整个参数即可构成完整查询或命令的接口，请求值直接作为参数也危险。 */
const SQL_UNSAFE = /(?:\.\s*\$(?:queryRawUnsafe|executeRawUnsafe)|(?<![\w$.])Prisma\s*\.\s*raw|(?<![\w$.])sql\s*\.\s*(?:raw|unsafe))\s*\(/g
/** knex 等的原始片段接口：只有拼接出的字符串才危险，参数绑定走第二个实参。 */
const SQL_RAW_FRAGMENT = /\.\s*(?:raw|whereRaw|orWhereRaw|andWhereRaw|havingRaw|orHavingRaw|orderByRaw|groupByRaw|joinRaw|fromRaw)\s*\(/g
/** 驱动的通用查询接口（pg、mysql2、sqlite、pg-promise、Vercel Postgres）；名称常见，须同时像 SQL。 */
const SQL_DRIVER = /\.\s*(?:query|execute|exec|prepare|run|all|get|unsafe|many|one|none|any|oneOrNone|manyOrNone)\s*\(/g
/** 查询构建器的条件接口（TypeORM 等）；拼接出的条件字符串须含比较。 */
const SQL_CONDITION = /\.\s*(?:where|andWhere|orWhere|having|andHaving|orHaving)\s*\(/g

const LOOKS_LIKE_SQL = /\bselect\b[\s\S]*\bfrom\b|\binsert\s+into\b|\bdelete\s+from\b|\bupdate\s+[\w."`]+\s+set\b|\bwhere\b|\border\s+by\b/i
const LOOKS_LIKE_CONDITION = /[=<>]|\b(?:like|ilike|in|is|between)\b/i

const CHILD_PROCESS = /^(?:node:)?child_process$/
const SHELL_EXPORTS = new Set(['exec', 'execSync'])
const SPAWN_EXPORTS = new Set(['spawn', 'spawnSync', 'execFile', 'execFileSync'])

interface Callees { shell: Set<string>; spawn: Set<string>; namespaces: Set<string> }

/** 本文件中来自 child_process 或 execa 的命令函数名，含别名、require、命名空间和 promisify。 */
function commandCallees(file: ScanFile): Callees {
  const callees: Callees = { shell: new Set(), spawn: new Set(), namespaces: new Set() }
  for (const binding of bindingsOf(file).imports) {
    if (binding.spec !== undefined && CHILD_PROCESS.test(binding.spec)) {
      if (binding.imported === 'default') callees.namespaces.add(binding.local)
      else if (SHELL_EXPORTS.has(binding.imported)) callees.shell.add(binding.local)
      else if (SPAWN_EXPORTS.has(binding.imported)) callees.spawn.add(binding.local)
    } else if (binding.spec === 'execa' && /^execaCommand(?:Sync)?$/.test(binding.imported)) {
      callees.shell.add(binding.local)
    }
  }
  const source = commentsMaskedOf(file)
  for (const m of source.matchAll(/\bimport\s*\*\s*as\s+([A-Za-z_$][\w$]*)\s+from\s*['"](?:node:)?child_process['"]/g)) {
    callees.namespaces.add(m[1]!)
  }
  for (const m of source.matchAll(/\b(?:const|let|var)\s+(\{[^{}]{0,500}\}|[A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['"](?:node:)?child_process['"]\s*\)/g)) {
    const target = m[1]!
    if (!target.startsWith('{')) { callees.namespaces.add(target); continue }
    for (const part of target.slice(1, -1).split(',')) {
      const names = /^\s*([A-Za-z_$][\w$]*)\s*(?::\s*([A-Za-z_$][\w$]*))?\s*$/.exec(part)
      if (!names) continue
      if (SHELL_EXPORTS.has(names[1]!)) callees.shell.add(names[2] ?? names[1]!)
      else if (SPAWN_EXPORTS.has(names[1]!)) callees.spawn.add(names[2] ?? names[1]!)
    }
  }
  // const run = promisify(exec) / util.promisify(cp.exec)
  for (const m of source.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:[A-Za-z_$][\w$]*\s*\.\s*)?promisify\s*\(\s*(?:([A-Za-z_$][\w$]*)\s*\.\s*)?([A-Za-z_$][\w$]*)\s*\)/g)) {
    const [, local, namespace, name] = m
    const viaNamespace = namespace !== undefined && callees.namespaces.has(namespace)
    if ((namespace === undefined && callees.shell.has(name!)) || (viaNamespace && SHELL_EXPORTS.has(name!))) callees.shell.add(local!)
    else if ((namespace === undefined && callees.spawn.has(name!)) || (viaNamespace && SPAWN_EXPORTS.has(name!))) callees.spawn.add(local!)
  }
  return callees
}

interface Sink { kind: SinkKind; at: number; open: number; close: number; mode: 'unsafe' | 'fragment' | 'driver' | 'condition' | 'shell' | 'spawn' }

function sinksIn(code: string, pairs: Map<number, number>, callees: Callees): Sink[] {
  const sinks = new Map<number, Sink>()
  const add = (regex: RegExp, kind: SinkKind, mode: Sink['mode']): void => {
    regex.lastIndex = 0
    for (const m of code.matchAll(regex)) {
      const open = m.index + m[0].length - 1
      const close = pairs.get(open)
      // 同一位置只保留最先匹配、限制最少的接口。
      if (close === undefined || sinks.has(open)) continue
      sinks.set(open, { kind, at: m.index, open, close, mode })
    }
  }
  if (callees.shell.size > 0) add(new RegExp(`(?<![\\w$.])(?:${namePattern(callees.shell)})\\s*\\(`, 'g'), 'command', 'shell')
  if (callees.spawn.size > 0) add(new RegExp(`(?<![\\w$.])(?:${namePattern(callees.spawn)})\\s*\\(`, 'g'), 'command', 'spawn')
  if (callees.namespaces.size > 0) {
    const ns = namePattern(callees.namespaces)
    add(new RegExp(`(?<![\\w$.])(?:${ns})\\s*\\.\\s*(?:exec|execSync)\\s*\\(`, 'g'), 'command', 'shell')
    add(new RegExp(`(?<![\\w$.])(?:${ns})\\s*\\.\\s*(?:spawn|spawnSync|execFile|execFileSync)\\s*\\(`, 'g'), 'command', 'spawn')
  }
  add(SQL_UNSAFE, 'sql', 'unsafe')
  add(SQL_RAW_FRAGMENT, 'sql', 'fragment')
  add(SQL_DRIVER, 'sql', 'driver')
  add(SQL_CONDITION, 'sql', 'condition')
  return [...sinks.values()].sort((a, b) => a.at - b.at)
}

interface Hit { taint: Taint }

/** 判断接收位置的实参是否由请求输入构成。 */
function hitOf(sink: Sink, code: string, source: string, pairs: Map<number, number>, flow: InputFlow): Hit | null {
  const args = argumentExpressions(code, code, sink.open + 1, sink.close, pairs)
  if (args.length === 0) return null
  const firstAt = sink.open + 1 + (code.slice(sink.open + 1, sink.close).length - code.slice(sink.open + 1, sink.close).trimStart().length)
  const first = args[0]!
  const firstSource = source.slice(firstAt, firstAt + first.length)

  if (sink.mode === 'spawn') {
    // spawn 与 execFile 只有启用 shell 时才会解析命令文本。
    if (!/\bshell\s*:\s*true\b/.test(code.slice(sink.open, sink.close))) return null
    const taint = flow.taintOf(code.slice(sink.open + 1, sink.close), sink.open + 1) ?? flow.builtOf(first, firstAt)
    return taint ? { taint } : null
  }

  const built = flow.builtOf(first, firstAt)
  const identifier = /^[A-Za-z_$][\w$]*$/.exec(first)
  const builtVariable = identifier ? flow.built.get(identifier[0]) : undefined
  const text = built ? firstSource : identifier && builtVariable ? flow.assignedText(identifier[0]) : null
  const stringTaint = built ?? builtVariable ?? null

  if (sink.mode === 'shell' || sink.mode === 'unsafe') {
    const taint = stringTaint ?? flow.taintOf(first, firstAt)
    return taint ? { taint } : null
  }
  if (!stringTaint || text === null) return null
  if (sink.mode === 'driver' && !LOOKS_LIKE_SQL.test(text)) return null
  if (sink.mode === 'condition' && !LOOKS_LIKE_CONDITION.test(text)) return null
  return { taint: stringTaint }
}

function capitalised(text: string): string {
  return `${text.charAt(0).toUpperCase()}${text.slice(1)}`
}

function findingFor(kind: SinkKind, route: Route, file: ScanFile, line: number, originLine: number, certain: boolean): Finding {
  const lowered = certain ? [] : [
    'The value passes through other code or a check before it gets here, and the scan cannot tell whether that makes it safe. ' +
      'Confirm the value is restricted to what the query or command expects.',
  ]
  const excerpt = (file.lines[line - 1] ?? '').trim()
  if (kind === 'sql') {
    return {
      ruleId: 'injection/sql', severity: 'P1', confidence: certain ? 'certain' : 'likely',
      title: `${capitalised(route.url)} builds a SQL query from request input`,
      file: file.path, line, excerpt,
      why: [
        `The query text is assembled from a value the caller controls (read on line ${originLine}). Whoever calls ` +
          `${route.url} can change the query itself, not just the value it compares against — read other rows, ` +
          `skip filters, or change data.`,
        ...lowered,
      ],
      fix: [
        'Pass values as parameters instead of splicing them into the SQL text: the tagged form ' +
          '(prisma.$queryRaw`… ${id}`, sql`… ${id}`) or placeholders ($1, ?) with a separate values array.',
        'If a column name or sort direction has to vary, choose it from a fixed list in code instead of using the request value.',
      ],
    }
  }
  return {
    ruleId: 'injection/command', severity: 'P1', confidence: certain ? 'certain' : 'likely',
    title: `${capitalised(route.url)} runs a shell command built from request input`,
    file: file.path, line, excerpt,
    why: [
      `The command line includes a value the caller controls (read on line ${originLine}) and is run through a shell. ` +
        `Characters such as ; | $( ) let a caller append their own commands, which run with your server's permissions.`,
      ...lowered,
    ],
    fix: [
      'Use execFile or spawn with an argument array and no shell option, so the value is passed as one argument and never parsed by a shell.',
      'Check the value against a fixed list of allowed values before using it.',
    ],
  }
}

export const injectionRule: ProjectRule = {
  id: 'injection/request-input',
  severity: 'P1',

  check(ctx: ScanContext): Finding[] {
    const findings: Finding[] = []
    for (const file of ctx.files) {
      const analysed = handlerFileOf(file)
      if (!analysed || analysed.handlers.length === 0) continue
      const { code, source, pairs, lineStarts } = analysed
      const sinks = sinksIn(code, pairs, commandCallees(file))
      if (sinks.length === 0) continue
      const reported = new Set<number>()
      for (const { route, body, flow } of analysed.handlers) {
        for (const sink of sinks) {
          if (sink.at <= body.start || sink.close >= body.end || reported.has(sink.at)) continue
          const hit = hitOf(sink, code, source, pairs, flow)
          if (!hit) continue
          reported.add(sink.at)
          const certain = hit.taint.level === 'direct' && !flow.validatedBefore(hit.taint.names, sink.at)
          findings.push(findingFor(sink.kind, route, file, lineNumberAt(lineStarts, sink.at),
            lineNumberAt(lineStarts, hit.taint.origin), certain))
        }
      }
      reportInputLimit(ctx, file, analysed)
    }
    return findings
  },
}
