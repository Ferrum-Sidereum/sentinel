export interface SecretInfo { name: string; placeholder: string }
export interface EntityInfo { name: string; toLLM: string; toUntrusted: string }
export interface PatternInfo { name: string; expression: string }
export interface PolicyInfo { revision: string; entities: EntityInfo[]; patterns: PatternInfo[] }
export interface Snapshot { secrets: SecretInfo[]; policy: PolicyInfo; version: string }
export interface FindingInfo { category: string; detector: string; confidence: number; startByte: number; endByte: number }
export interface ScanResult { findings: FindingInfo[]; elapsedMs: number; bytes: number }
export interface ActivityRow { time: string; type: string; count: number }
export interface ActivityPage { rows: ActivityRow[]; truncated: boolean; skipped: number }
interface Backend {
 Snapshot(): Promise<Snapshot>;
 AddSecret(name: string, value: string): Promise<SecretInfo[]>;
 DeleteSecret(name: string, confirmation: string): Promise<SecretInfo[]>;
 Scan(text: string): Promise<ScanResult>;
 SavePolicy(revision: string, entities: EntityInfo[], patterns: PatternInfo[]): Promise<PolicyInfo>;
 Activity(): Promise<ActivityPage>;
}
declare global { interface Window { go?: { main?: { App?: Backend } } } }
// Wails' runtime creates window.go before the app loads. This narrow handwritten
// contract matches App's JSON DTOs; generated bindings remain in wailsjs/.
function backend(): Backend {
 const bridge = window.go?.main?.App;
 if (!bridge) throw new Error("Desktop bridge unavailable. Open Sentinel with Wails, not in a browser tab.");
 return bridge;
}
export const api: Backend = {
 Snapshot: () => backend().Snapshot(),
 AddSecret: (name, value) => backend().AddSecret(name, value),
 DeleteSecret: (name, confirmation) => backend().DeleteSecret(name, confirmation),
 Scan: text => backend().Scan(text),
 SavePolicy: (revision, entities, patterns) => backend().SavePolicy(revision, entities, patterns),
 Activity: () => backend().Activity()
};
export function errorMessage(error: unknown): string {
 return typeof error === "string" ? error : error instanceof Error ? error.message : "Operation failed. Please retry.";
}
