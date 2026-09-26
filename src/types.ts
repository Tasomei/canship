/** 扫描器的核心数据结构。 */

/** 严重度：P0 为高影响凭据或权限问题，P1 为访问控制问题，P2 为其他配置问题。 */
export type Severity = 'P0' | 'P1' | 'P2'

/** 参与发布阻断判断的严重度。 */
export const BLOCKING: ReadonlySet<Severity> = new Set<Severity>(['P0', 'P1'])

/** 置信度：certain 表示确定证据，likely 表示需人工确认。 */
export type Confidence = 'certain' | 'likely'

/** 参与扫描的文件。 */
export interface ScanFile {
  /** 相对扫描根目录的路径，统一使用斜杠。 */
  path: string
  /** 文件全文。 */
  content: string
  /** 按行拆分的内容，用于定位。 */
  lines: string[]
  /** 测试或示例上下文；由引擎统一降低置信度。 */
  isExampleContext: boolean
}

/** 静态证据位置，不包含源码摘录或运行时结论。 */
export interface EvidenceStep {
  kind: 'operation' | 'import' | 'admin-client' | 'auth-helper'
  file: string
  line: number | null
  description: string
}

/** 单条扫描结果。 */
export interface Finding {
  /** 对外展示的规则 ID。 */
  ruleId: string
  severity: Severity
  confidence: Confidence
  /** 简明描述问题及影响。 */
  title: string
  /** 相对文件路径；无具体文件时为空。 */
  file: string | null
  /** 从 1 开始的行号；无法定位时为空。 */
  line: number | null
  /** 展示摘录；最终输出必须完整脱敏。 */
  excerpt: string | null
  /** 原始来源行或文件证据的摘要，独立于展示用的脱敏和截断。 */
  sourceFingerprint?: string
  evidence?: EvidenceStep[]
  /** 展示链达到长度上限，不影响已经完成的扫描。 */
  evidenceTruncated?: boolean
  /** 影响说明，每个元素独立表示一个段落。 */
  why: string[]
  /** 可执行的代码修复步骤。 */
  fix: string[]
  /** 需人工执行的轮换、控制台配置或历史重写步骤。 */
  humanOnly?: string[]
}

/** 单文件检测规则。 */
export interface Rule {
  id: string
  severity: Severity
  /** 快速判断规则是否适用于该文件。 */
  appliesTo(file: ScanFile): boolean
  /** 执行检查；空数组表示未发现问题。 */
  check(file: ScanFile, ctx: ScanContext): Finding[]
}

/** 每次扫描执行一次的跨文件规则。 */
export interface ProjectRule {
  id: string
  severity: Severity
  check(ctx: ScanContext): Finding[] | Promise<Finding[]>
}

/** 区分有效仓库、非仓库及无法检查的仓库。 */
export type GitStatus = 'repo' | 'not-a-repo' | 'unavailable'

/** 一次扫描的上下文。 */
export interface ScanContext {
  /** 扫描根目录的绝对路径。 */
  root: string
  /** 本次扫描读取的全部文件。 */
  files: ScanFile[]
  /** Git 仓库识别结果。 */
  git: GitStatus
  gitExecutable: string | null
  /** 记录扫描缺口，同时保留已产生的结果。 */
  reportIncomplete(ruleId: string, message: string): void
}

/** 文件未被读取的原因。 */
export type SkipReason =
  /** 超过文件大小限制。 */
  | 'too-large'
  /** 权限不足、设备错误或扫描期间文件变化。 */
  | 'unreadable'
  /** 目录无法列出，内容未知。 */
  | 'directory-unreadable'
  /** 扩展名可扫描但实际内容为二进制。 */
  | 'binary'
  /** 不跟随的符号链接。 */
  | 'symlink'
  /** Git 返回的不透明嵌套仓库或子模块。 */
  | 'nested-repository'

/** 按对外规则 ID 或命名空间选择规则。 */
export interface ScanOptions {
  /** 仅执行匹配规则；与 skip 互斥。 */
  only?: string[]
  /** 排除匹配规则。 */
  skip?: string[]
  /** 是否遵从被扫描项目中的忽略标记；默认遵从，扫描不可信项目时应关闭。 */
  honorIgnoreMarkers?: boolean
}

/** 规则筛选条件及过滤统计。 */
export interface RuleSelection {
  only: string[]
  skip: string[]
  /** 已执行规则中被过滤的结果数，不估算未执行规则。 */
  removed: number
}

/** 被逐行忽略标记抑制的结果位置。 */
export interface IgnoredFinding {
  file: string
  /** 结果所在行号，从 1 开始。 */
  line: number
  ruleId: string
}

/** 发现但未检查的文件或目录。 */
export interface SkippedFile {
  path: string
  reason: SkipReason
  /** 额外说明，如文件大小。 */
  detail?: string
}

/** 规则异常或达到资源上限。 */
export interface ScanError {
  /** 规则 ID，或遍历器标识。 */
  ruleId: string
  /** 单文件规则处理的文件路径。 */
  file: string | null
  message: string
  /** 区分执行异常与已知扫描缺口。 */
  kind: 'crashed' | 'incomplete'
}

/** 变更视图的比较基准、隐藏数量及完整扫描统计。 */
export interface ChangeView {
  baseCommit: string
  mergeBase: string
  changedFiles: number
  hiddenFindings: number
  totalFindings: number
  totalBlocking: number
  totalLikely: number
}

/** 扫描汇总；结果为空时仍需保留完整性信息。 */
export interface ScanResult {
  /** 仅筛选展示；统计和退出码仍基于完整扫描。 */
  changeView?: ChangeView
  findings: Finding[]
  /** 实际读取并扫描的文件数。 */
  filesScanned: number
  /** 扫描耗时，单位为毫秒。 */
  durationMs: number
  /** 规则异常及不完整记录。 */
  errors: ScanError[]
  /** 未检查的文件和目录。 */
  skipped: SkippedFile[]
/** 整文件忽略标记排除的文件；必须显式披露。 */
  ignored: string[]
  /** 逐行忽略标记抑制的位置及规则。 */
  ignoredFindings: IgnoredFinding[]
  /** 本次规则筛选信息；未筛选时为空。 */
  ruleSelection: RuleSelection | null
  /** 排除的第三方路径数。 */
  vendored: number
  /** 是否存在扫描缺口；为真时不能推断整个项目无问题。 */
  partial: boolean
}
