import { useEffect, useRef, useState } from "react";
import type { FormEvent, ReactNode } from "react";
import { api, errorMessage } from "./api";
import type { ActivityPage, EntityInfo, PatternInfo, PolicyInfo, ScanResult, SecretInfo, Snapshot } from "./api";

type Page = "scan" | "vault" | "policy" | "activity";
const navigation: { id: Page; name: string; glyph: string }[] = [
 { id: "scan", name: "Scan", glyph: "⌕" }, { id: "vault", name: "Vault", glyph: "◇" },
 { id: "policy", name: "Policy", glyph: "≡" }, { id: "activity", name: "Audit", glyph: "↳" }
];
function Notice({ children, error = false }: { children: ReactNode; error?: boolean }) {
 return <div className={error ? "notice error" : "notice"} role={error ? "alert" : "status"}>{children}</div>;
}
function Header({ eyebrow, title, description }: { eyebrow: string; title: string; description: string }) {
 return <header className="page-heading"><p className="eyebrow">{eyebrow}</p><h1>{title}</h1><p>{description}</p></header>;
}
export default function App() {
 const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
 const [error, setError] = useState("");
 const [loading, setLoading] = useState(true);
 const [page, setPage] = useState<Page>("scan");
 const [busy, setBusy] = useState(false);
 const [dirty, setDirty] = useState(false);
 const [pendingPage, setPendingPage] = useState<Page | null>(null);
 async function reload() {
  setLoading(true); setError("");
  try { setSnapshot(await api.Snapshot()); } catch (e) { setError(errorMessage(e)); }
  finally { setLoading(false); }
 }
 useEffect(() => { void reload(); }, []);
 function navigate(target: Page) {
  if (busy || page === target) return;
  if (dirty) { setPendingPage(target); return; }
  setPage(target);
 }
 if (!snapshot) return <main className="boot"><div className="brand-mark" aria-hidden="true">S</div><h1>{loading ? "Opening your workspace" : "Sentinel needs attention"}</h1><p>{loading ? "Checking the vault and local policy." : "No replacement master key was generated for existing data."}</p>{loading ? <div className="skeleton" aria-label="Loading" /> : <><Notice error>{error}</Notice><button className="primary" onClick={() => void reload()}>Retry</button></>}</main>;
 return <div className="app-shell"><aside className="sidebar">
  <div className="brand"><span className="brand-mark" aria-hidden="true">S</span><div><strong>sentinel</strong><span>LOCAL WORKSPACE</span></div></div>
  <nav aria-label="Workspace">{navigation.map(item => <button key={item.id} disabled={busy} aria-current={page === item.id ? "page" : undefined} onClick={() => navigate(item.id)}><span className="nav-glyph" aria-hidden="true">{item.glyph}</span>{item.name}</button>)}</nav>
  <div className="sidebar-foot"><span className="pill">Desktop companion</span><p>No network proxy is started by this window.</p><small>{snapshot.version}</small></div>
 </aside><div className="workspace"><div className="topbar"><span>WINDOWS / LOCAL ONLY</span><span className="ready"><i aria-hidden="true" />Vault checked at startup</span></div>
 {pendingPage && <div className="discard"><p>Leave this page? Unsaved input and scan results will be cleared.</p><button onClick={() => setPendingPage(null)}>Keep editing</button><button className="danger" onClick={() => { setDirty(false); setPage(pendingPage); setPendingPage(null); }}>Discard and leave</button></div>}
 <main className="content" aria-busy={busy}>
  {page === "scan" && <ScanPage setBusy={setBusy} setDirty={setDirty} />}
  {page === "vault" && <VaultPage secrets={snapshot.secrets} onChange={secrets => setSnapshot({ ...snapshot, secrets })} setBusy={setBusy} setDirty={setDirty} />}
  {page === "policy" && <PolicyPage policy={snapshot.policy} onChange={policy => setSnapshot({ ...snapshot, policy })} setBusy={setBusy} setDirty={setDirty} />}
  {page === "activity" && <AuditPage setBusy={setBusy} />}
 </main></div></div>;
}
type ActivityControl = { setBusy: (b: boolean) => void; setDirty: (b: boolean) => void };
function ScanPage({ setBusy, setDirty }: ActivityControl) {
 const [text, setText] = useState(""); const [result, setResult] = useState<ScanResult | null>(null);
 const [error, setError] = useState(""); const [running, setRunning] = useState(false);
 const bytes = new TextEncoder().encode(text).length;
 function update(value: string) { setText(value); setResult(null); setError(""); setDirty(!!value); }
 async function scan(event: FormEvent) {
  event.preventDefault(); setRunning(true); setBusy(true); setError(""); setResult(null);
  try { setResult(await api.Scan(text)); } catch (e) { setError(errorMessage(e)); }
  finally { setRunning(false); setBusy(false); }
 }
 return <><Header eyebrow="01 / INSPECT" title="Before it leaves." description="Check text with your Go scanner, saved patterns and vault matches. Nothing is sent to an LLM." />
 <div className="scope-note"><span aria-hidden="true">↳</span><p>This is a local detector test, not a policy simulation or proof that a connected app is protected.</p></div>
 <form onSubmit={e => void scan(e)}><div className="section-label"><label htmlFor="scan-input">Text to inspect</label><span>{bytes.toLocaleString()} / 65,536 bytes</span></div>
 <textarea id="scan-input" className="scan-input" spellCheck={false} autoComplete="off" disabled={running} value={text} onChange={e => update(e.target.value)} placeholder={"Paste a prompt, configuration snippet, or tool output.\nInput stays in this window until you clear it or leave this page."} />
 <div className="form-actions"><button className="primary" disabled={running || bytes === 0 || bytes > 65536}>{running ? "Scanning locally…" : "Scan text"}<span aria-hidden="true">↗</span></button><button type="button" disabled={running || !text} onClick={() => update("")}>Clear</button><button type="button" className="text-button" disabled={running} onClick={() => update("Contact demo@example.test.\npassword=synthetic-example-only")}>Use synthetic sample</button></div></form>
 {error && <Notice error>{error}</Notice>}
 <section className="results" aria-live="polite"><div className="section-label"><h2>Findings</h2>{result && <span>{result.findings.length} detected · {result.elapsedMs} ms</span>}</div>
 {!result ? <div className="empty"><span aria-hidden="true">⌕</span><p>{running ? "Checking locally…" : "Your next check starts here."}</p><small>Results show categories and UTF-8 byte offsets, never matched values.</small></div> : result.findings.length === 0 ? <div className="empty"><p>No matches found.</p><small>Absence of findings is not a guarantee that the text contains no sensitive data.</small></div> : <div className="table-scroll"><table><thead><tr><th>Category</th><th>Detector</th><th>Confidence</th><th>Byte range</th></tr></thead><tbody>{result.findings.map((f, i) => <tr key={i}><td><strong>{f.category}</strong></td><td>{f.detector}</td><td>{Math.round(f.confidence * 100)}%</td><td className="mono">{f.startByte} .. {f.endByte}</td></tr>)}</tbody></table></div>}</section>
 <p className="footnote">The sandbox uses the core allowlist and reports detections before action thresholds. Manual scans are not written to the audit log.</p></>;
}
function VaultPage({ secrets, onChange, setBusy, setDirty }: { secrets: SecretInfo[]; onChange: (s: SecretInfo[]) => void } & ActivityControl) {
 const [name, setName] = useState(""); const [value, setValue] = useState("");
 const [running, setRunning] = useState(false); const [error, setError] = useState(""); const [message, setMessage] = useState("");
 const [target, setTarget] = useState<string | null>(null); const [confirmation, setConfirmation] = useState("");
 const nameInput = useRef<HTMLInputElement>(null);
 async function add(event: FormEvent) {
  event.preventDefault(); setRunning(true); setBusy(true); setError(""); setMessage("");
  const submittedValue = value; setValue("");
  try { onChange(await api.AddSecret(name, submittedValue)); setName(""); setDirty(false); setMessage("Secret saved. Existing entries were not overwritten."); nameInput.current?.focus(); }
  catch (e) { setError(errorMessage(e)); setDirty(!!name); }
  finally { setRunning(false); setBusy(false); }
 }
 async function remove() {
  if (!target) return;
  setRunning(true); setBusy(true); setError(""); setMessage("");
  try { onChange(await api.DeleteSecret(target, confirmation)); setTarget(null); setConfirmation(""); setMessage("Secret deleted."); }
  catch (e) { setError(errorMessage(e)); }
  finally { setRunning(false); setBusy(false); }
 }
 return <><Header eyebrow="02 / STORE" title="Secrets, kept local." description="Encrypted values stay in the existing Go vault. The desktop never reads a saved value back into the interface." />
 <div className="scope-note"><span aria-hidden="true">◇</span><p>Uses your existing Windows credential and vault.db. Host binding and key rotation remain CLI operations.</p></div>
 <form onSubmit={e => void add(e)} className="vault-form"><label>Name<input ref={nameInput} value={name} maxLength={64} autoComplete="off" disabled={running} placeholder="service-api-key" onChange={e => { setName(e.target.value); setDirty(!!e.target.value || !!value); }} /></label><label>Secret value<input type="password" value={value} autoComplete="new-password" spellCheck={false} disabled={running} placeholder="Stored encrypted, never revealed" onChange={e => { setValue(e.target.value); setDirty(!!name || !!e.target.value); }} /></label><button className="primary" disabled={running || !name.trim() || !value}>{running ? "Working…" : "Add secret"}</button></form>
 {error && <Notice error>{error}</Notice>}{message && <Notice>{message}</Notice>}
 <div className="section-label"><h2>Stored entries</h2><span>{secrets.length} total</span></div>
 {secrets.length === 0 ? <div className="empty"><p>Your vault is empty.</p><small>Add a named secret above to include it in local scans.</small></div> : <ul className="secret-list">{secrets.map(secret => <li key={secret.name}><div className="secret-row"><div><strong>{secret.name}</strong><code>{secret.placeholder}</code></div><button disabled={running} onClick={() => { setTarget(secret.name); setConfirmation(""); setError(""); }}>Delete…</button></div>
 {target === secret.name && <div className="inline-confirm"><label>Type <code>{secret.name}</code> to delete this entry permanently.<input aria-label="Confirm stored name" autoComplete="off" value={confirmation} disabled={running} onChange={e => setConfirmation(e.target.value)} /></label><div className="form-actions"><button className="danger" disabled={running || confirmation !== target} onClick={() => void remove()}>Delete permanently</button><button disabled={running} onClick={() => { setTarget(null); setConfirmation(""); }}>Cancel</button></div></div>}</li>)}</ul>}
 <p className="footnote">Deleting an entry can break clients that reference it. This shell does not change existing names, host bindings or placeholder semantics.</p></>;
}
const modes = ["", "off", "allow", "mask", "pseudonymize", "hash", "block", "block_unless_placeholder"];
function PolicyPage({ policy, onChange, setBusy, setDirty }: { policy: PolicyInfo; onChange: (p: PolicyInfo) => void } & ActivityControl) {
 const [entities, setEntities] = useState<EntityInfo[]>(policy.entities.map(e => ({ ...e })));
 const [patterns, setPatterns] = useState<PatternInfo[]>(policy.patterns.map(p => ({ ...p })));
 const [running, setRunning] = useState(false); const [error, setError] = useState(""); const [message, setMessage] = useState("");
 const [review, setReview] = useState(false); const [discard, setDiscard] = useState(false); const [removeIndex, setRemoveIndex] = useState<number | null>(null);
 const changed = JSON.stringify(entities) !== JSON.stringify(policy.entities) || JSON.stringify(patterns) !== JSON.stringify(policy.patterns);
 function edit() { setDirty(true); setReview(false); setMessage(""); }
 async function save() {
  setBusy(true); setRunning(true); setError(""); setMessage("");
  try { const p = await api.SavePolicy(policy.revision, entities, patterns); onChange(p); setEntities(p.entities); setPatterns(p.patterns); setDirty(false); setReview(false); setMessage("Policy saved. Restart existing CLI processes to ensure they use the new settings."); }
  catch (e) { setError(errorMessage(e)); }
  finally { setBusy(false); setRunning(false); }
 }
 async function reload() {
  setBusy(true); setRunning(true); setError("");
  try { const p = (await api.Snapshot()).policy; onChange(p); setEntities(p.entities); setPatterns(p.patterns); setDirty(false); setReview(false); }
  catch (e) { setError(errorMessage(e)); }
  finally { setBusy(false); setRunning(false); }
 }
 function updateEntity(index: number, field: "toLLM" | "toUntrusted", mode: string) { setEntities(entities.map((e, i) => i === index ? { ...e, [field]: mode } : e)); edit(); }
 return <><Header eyebrow="03 / CONFIGURE" title="Make the rules explicit." description="Edit the existing policy.yaml without replacing host rules, allowlists or detector settings." />
 <Notice>Saving changes configuration, not the running proxy. Core enforcement limitations remain unchanged; off and allow can expose data.</Notice>
 <div className="section-label"><h2>Entity actions</h2><span>Existing Go policy modes</span></div>
 <div className="table-scroll"><table><thead><tr><th>Entity</th><th>To LLM</th><th>To untrusted</th></tr></thead><tbody>{entities.map((entity, i) => <tr key={entity.name}><td className="mono">{entity.name}</td>{(["toLLM", "toUntrusted"] as const).map(field => <td key={field}><select aria-label={`${entity.name} ${field}`} value={entity[field]} disabled={running} onChange={e => updateEntity(i, field, e.target.value)}>{!modes.includes(entity[field]) && <option>{entity[field]}</option>}{modes.map(mode => <option key={mode} value={mode}>{mode || "inherit"}</option>)}</select></td>)}</tr>)}</tbody></table></div>
 <div className="section-label patterns-heading"><h2>Custom patterns</h2><button disabled={running || patterns.length >= 128} onClick={() => { setPatterns([...patterns, { name: "", expression: "" }]); edit(); }}>Add pattern</button></div>
 <p className="footnote">Go RE2 syntax. Patterns are applied by this scanner; the legacy LLM gateway does not yet call ScanCustom.</p>
 {patterns.length === 0 && <div className="empty compact"><p>No custom patterns yet.</p></div>}
 {patterns.map((pattern, i) => <div className="pattern-row" key={i}><label>Name<input value={pattern.name} maxLength={64} disabled={running} onChange={e => { setPatterns(patterns.map((p, j) => j === i ? { ...p, name: e.target.value } : p)); edit(); }} /></label><label>Expression<input className="mono" spellCheck={false} value={pattern.expression} disabled={running} onChange={e => { setPatterns(patterns.map((p, j) => j === i ? { ...p, expression: e.target.value } : p)); edit(); }} /></label>{removeIndex === i ? <div className="remove-controls"><button className="danger" disabled={running} onClick={() => { setPatterns(patterns.filter((_, j) => j !== i)); setRemoveIndex(null); edit(); }}>Confirm remove</button><button disabled={running} onClick={() => setRemoveIndex(null)}>Keep</button></div> : <button disabled={running} onClick={() => setRemoveIndex(i)}>Remove…</button>}</div>)}
 {error && <Notice error>{error}</Notice>}{message && <Notice>{message}</Notice>}
 <div className="save-bar">{!review ? <button className="primary" disabled={running || !changed} onClick={() => setReview(true)}>Review changes</button> : <div className="review"><p>Save {entities.length} entity rules and {patterns.length} custom patterns? Existing policy will be backed up; a lower protection mode may permit sensitive data.</p><button className="primary" disabled={running} onClick={() => void save()}>{running ? "Saving…" : "Confirm and save"}</button><button disabled={running} onClick={() => setReview(false)}>Keep editing</button></div>}
 {!changed && <button disabled={running} onClick={() => void reload()}>Reload from disk</button>}
 {changed && !discard && <button disabled={running} onClick={() => setDiscard(true)}>Discard edits…</button>}
 {changed && discard && <><button className="danger" disabled={running} onClick={() => { setEntities(policy.entities.map(e => ({ ...e }))); setPatterns(policy.patterns.map(p => ({ ...p }))); setDirty(false); setReview(false); setDiscard(false); setMessage(""); }}>Confirm discard</button><button disabled={running} onClick={() => setDiscard(false)}>Keep edits</button></>}
 </div><p className="footnote">Close other policy editors before saving. Revision checks catch prior edits, but the legacy CLI does not share a cross-process write lock. Hash mode is preserved for compatibility, not recommended until the core's hash-key handling is fixed.</p></>;
}
function AuditPage({ setBusy }: { setBusy: (b: boolean) => void }) {
 const [data, setData] = useState<ActivityPage | null>(null); const [error, setError] = useState(""); const [running, setRunning] = useState(false);
 async function reload() {
  setBusy(true); setRunning(true); setError(""); setData(null);
  try { setData(await api.Activity()); } catch (e) { setError(errorMessage(e)); }
  finally { setBusy(false); setRunning(false); }
 }
 useEffect(() => { void reload(); }, []);
 return <><Header eyebrow="04 / REVIEW" title="A smaller paper trail." description="Read the core's local audit log without exposing raw metadata, paths, prompts or credential values." />
 <div className="section-label"><h2>Latest recorded events</h2><button disabled={running} onClick={() => void reload()}>{running ? "Reading…" : "Refresh"}</button></div>
 {error && <Notice error>{error}</Notice>}{data?.truncated && <Notice>Showing up to 100 events from the last 256 KiB, not the complete audit history.</Notice>}{!!data?.skipped && <Notice>{data.skipped} malformed records were skipped.</Notice>}
 {!data ? <div className="empty"><p>{running ? "Reading local events…" : "Audit data unavailable."}</p></div> : data.rows.length === 0 ? <div className="empty"><span aria-hidden="true">↳</span><p>No recorded events in this window.</p><small>CLI activity can populate audit.jsonl. This companion does not start a proxy or log manual scans.</small></div> : <div className="table-scroll"><table><thead><tr><th>Time (local)</th><th>Event</th><th>Count</th></tr></thead><tbody>{data.rows.map((row, i) => <tr key={i}><td>{new Date(row.time).toLocaleString()}</td><td className="mono">{row.type}</td><td>{row.count || "Not recorded"}</td></tr>)}</tbody></table></div>}
 <p className="footnote">Unknown event names appear as legacy.event. This view is not a live protection indicator or a complete security audit.</p></>;
}
