export const TARGET: Readonly<{ repository: string; ref: string; category: string; path: string; rule: string }>
export class ValidationError extends Error { code: string; constructor(code: string) }
export function parseContext(env: NodeJS.ProcessEnv): { sha: string; caseId: string; token: string; uploadId: string }
export function prepareUpload(preview: unknown, caseId: string): {
  log: Record<string, any>; fixture: string; expected: { lines: number[]; title: string; version: string }
}
export function validateCloud(preview: unknown, env: NodeJS.ProcessEnv, dependencies?: {
  fetch?: typeof globalThis.fetch; sleep?: (ms: number) => Promise<void>; attempts?: number;
  verifyFixture?: (sha: string, fixture: string) => void | Promise<void>;
}): Promise<{ schemaVersion: number; synthetic: boolean; verified: boolean; case: string;
  repository: string; ref: string; category: string; commit: string; uploadId: string; analysisId: number;
  toolVersion: string; hasPlatformFingerprint: boolean; platformFingerprintsUnchanged: boolean | null;
  reportSha256: string; baseline: number[];
  active: { number: number; line: number }[]; fixed: number[] }>
export function main(args?: string[], env?: NodeJS.ProcessEnv): Promise<number>
