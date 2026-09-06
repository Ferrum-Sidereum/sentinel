import { useEffect, useState } from "react";
import { errorMessage } from "./api";

// WP-20 UI: live feed, approvals, onboarding wizard, tray, enriched secrets.
// No secret values are rendered: SecretList carries only metadata + mask.

export interface FeedEntry { seq: number; time: string; type: string; secret: string; host: string; decided: string; count: number }
export interface FeedPage { entries: FeedEntry[]; counters: { resolutions: number; denials: number; redactions: number }; truncated: boolean }
export interface ApprovalRequest { secret: string; consumer: string; dest: string; reason: string; timeoutS: number }
export interface TrayState { paused: boolean; gateways: Record<string, boolean>; recentDenies: number }
export interface WizardStep { id: string; title: string; done: boolean; cli: string; detail: string }
export interface SecretMeta { name: string; lastUsed: string; useCount: number; expiry: string; expired: boolean; hosts: string[]; masked: string }

interface Bridge extends Record<string, (...args: never[]) => Promise<never>> {
 ActivityFeed(f: unknown): Promise<FeedPage>;
 PendingApprovals(): Promise<ApprovalRequest[]>;
 ResolveApproval(secret: string, scope: string): Promise<{ allow: boolean; scope: string }>;
 Tray(): Promise<TrayState>;
 SetEgressPaused(paused: boolean): Promise<TrayState>;
 Wizard(): Promise<WizardStep[]>;
 WizardInit(): Promise<WizardStep[]>;
 SecretList(): Promise<SecretMeta[]>;
}
function bridge(): Bridge {
 const b = (window as unknown as { go?: { main?: { App?: Bridge } } }).go?.main?.App;
 if (!b) throw new Error("Desktop bridge unavailable.");
 return b as Bridge;
}
export const wp20 = {
 feed: (type = "", secret = "") => bridge().ActivityFeed({ type, secret, limit: 100 }),
 approvals: () => bridge().PendingApprovals(),
 resolve: (secret: string, scope: string) => bridge().ResolveApproval(secret, scope),
 tray: () => bridge().Tray(),
 setPaused: (paused: boolean) => bridge().SetEgressPaused(paused),
 wizard: () => bridge().Wizard(),
 wizardInit: () => bridge().WizardInit(),
 secrets: () => bridge().SecretList(),
};

export function ApprovalsPanel() {
 const [items, setItems] = useState<ApprovalRequest[]>([]);
 const [error, setError] = useState("");
 async function reload() {
  try { setItems(await wp20.approvals()); } catch (e) { setError(errorMessage(e)); }
 }
 useEffect(() => { void reload(); const id = setInterval(reload, 3000); return () => clearInterval(id); }, []);
 async function decide(secret: string, scope: string) {
  try { await wp20.resolve(secret, scope); await reload(); } catch (e) { setError(errorMessage(e)); }
 }
 if (items.length === 0) return null;
 return <section aria-label="Pending approvals">{error && <p role="alert">{error}</p>}
  {items.map(a => <article key={a.secret}>
   <h3>{a.secret}</h3><p>{a.consumer} → {a.dest} ({a.reason})</p>
   <button onClick={() => void decide(a.secret, "once")}>Once</button>
   <button onClick={() => void decide(a.secret, "15m")}>15 min</button>
   <button onClick={() => void decide(a.secret, "session")}>Session</button>
   <button onClick={() => void decide(a.secret, "deny")}>Deny</button>
  </article>)}
 </section>;
}

export function TrayPanel() {
 const [tray, setTray] = useState<TrayState | null>(null);
 useEffect(() => { wp20.tray().then(setTray).catch(() => undefined); }, []);
 if (!tray) return null;
 const dots = Object.entries(tray.gateways).map(([gw, ok]) =>
  <span key={gw} title={gw} style={{ color: ok ? "green" : "red" }}>● {gw}</span>);
 return <div role="status">{dots}
  {tray.recentDenies > 0 && <span aria-label="recent denials">⛔ {tray.recentDenies}</span>}
  <button onClick={() => wp20.setPaused(!tray.paused).then(setTray)}>
   {tray.paused ? "Resume egress" : "Pause egress"}</button>
 </div>;
}

export function WizardPanel() {
 const [steps, setSteps] = useState<WizardStep[]>([]);
 const [error, setError] = useState("");
 useEffect(() => { wp20.wizard().then(setSteps).catch(e => setError(errorMessage(e))); }, []);
 return <section aria-label="Onboarding">{error && <p role="alert">{error}</p>}
  <ol>{steps.map(s => <li key={s.id}>{s.done ? "✓" : "○"} {s.title}
   <code>{s.cli}</code><p>{s.detail}</p></li>)}</ol>
  <button onClick={() => wp20.wizardInit().then(setSteps).catch(e => setError(errorMessage(e)))}>
   Run init (idempotent)</button>
 </section>;
}

export function SecretsPanel() {
 const [secrets, setSecrets] = useState<SecretMeta[]>([]);
 useEffect(() => { wp20.secrets().then(setSecrets).catch(() => undefined); }, []);
 return <table><thead><tr><th>Name</th><th>Masked</th><th>Uses</th><th>Last used</th><th>Expiry</th><th>Hosts</th></tr></thead>
  <tbody>{secrets.map(s => <tr key={s.name}>
   <td>{s.name}</td><td>{s.masked}</td><td>{s.useCount}</td>
   <td>{s.lastUsed || "—"}</td><td>{s.expiry || "—"}{s.expired ? " (expired)" : ""}</td>
   <td>{s.hosts.join(", ")}</td></tr>)}</tbody></table>;
}

export function FeedPanel() {
 const [feed, setFeed] = useState<FeedPage | null>(null);
 const [type, setType] = useState("");
 useEffect(() => { wp20.feed(type).then(setFeed).catch(() => undefined); }, [type]);
 return <section aria-label="Live activity">
  <p>Resolutions: {feed?.counters.resolutions ?? 0} · Denials: {feed?.counters.denials ?? 0} · Redactions: {feed?.counters.redactions ?? 0}</p>
  <label>Filter type <input value={type} onChange={e => setType(e.target.value)} placeholder="approval_denied" /></label>
  <ul>{feed?.entries.map(e => <li key={e.seq}>{e.time} · {e.type} · {e.secret || "—"} · {e.host || "—"} · {e.decided || "—"}</li>)}</ul>
  {feed?.truncated && <p>Truncated to latest 100.</p>}
 </section>;
}
