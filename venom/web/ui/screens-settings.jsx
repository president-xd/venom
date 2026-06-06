/* ============================================================
   VENOM - Knowledge base + Settings (real data from /api)
   ============================================================ */

function KnowledgeAddForm({ onSaved, onCancel }) {
  const [f, setF] = React.useState({ name: "", desc: "", cwe: "", probe: "", exploit: "" });
  const [busy, setBusy] = React.useState(false);
  const [err, setErr] = React.useState(null);
  const set = (k) => (e) => setF((p) => ({ ...p, [k]: e.target.value }));

  const save = async () => {
    if (!f.name.trim()) { setErr("A name is required."); return; }
    setBusy(true); setErr(null);
    try {
      const r = await window.API.post("/api/knowledge", f);
      if (r && r.ok) { onSaved(r.entry); }
      else { setErr((r && r.error) || "Could not save."); setBusy(false); }
    } catch (e) { setErr("Could not reach the server."); setBusy(false); }
  };

  return (
    <div className="card card-pad" style={{ marginBottom: 18, borderColor: "var(--accent-line)", boxShadow: "0 0 0 2px var(--accent-soft)" }}>
      <div className="between" style={{ marginBottom: 12 }}>
        <h2 className="h2">Add a knowledge-base entry</h2>
        <button className="btn btn-sm btn-ghost" onClick={onCancel}><Ic name="x" size={14} /></button>
      </div>
      <div className="field">
        <label>Name <span style={{ color: "var(--sev-crit)" }}>*</span></label>
        <input className="input" value={f.name} onChange={set("name")} placeholder="e.g. Tenant boundary bypass via header" />
      </div>
      <div className="field">
        <label>Description</label>
        <input className="input" value={f.desc} onChange={set("desc")} placeholder="What the flaw is, in one line." />
      </div>
      <div className="field">
        <label>CWE / reference</label>
        <input className="input mono" value={f.cwe} onChange={set("cwe")} placeholder="CWE-639 · OWASP API1" />
      </div>
      <div className="field">
        <label>Probe (how to test cheaply)</label>
        <textarea className="textarea" value={f.probe} onChange={set("probe")} rows={2} placeholder="Swap the X-Tenant-Id header to a neighbouring tenant and re-read." />
      </div>
      <div className="field mb0">
        <label>Exploit idea</label>
        <textarea className="textarea" value={f.exploit} onChange={set("exploit")} rows={2} placeholder="Read/modify another tenant's object via the trusted header." />
      </div>
      {err && <div className="row gap10" style={{ marginTop: 12 }}><Ic name="alert" size={15} style={{ color: "var(--sev-crit)" }} /><span style={{ fontSize: 12.5, color: "var(--sev-crit)" }}>{err}</span></div>}
      <div className="row gap10" style={{ marginTop: 16, justifyContent: "flex-end" }}>
        <button className="btn btn-sm" onClick={onCancel}>Cancel</button>
        <button className="btn btn-sm btn-primary" onClick={save} disabled={busy}>
          {busy ? <><Ic name="spinner" size={14} className="spin" /> Saving</> : <><Ic name="check" size={14} /> Save entry</>}
        </button>
      </div>
    </div>
  );
}

function KnowledgeBase() {
  const [classes, setClasses] = React.useState(window.VENOM.VULN_CLASSES || []);
  const [adding, setAdding] = React.useState(false);

  const refresh = React.useCallback(() => {
    if (!window.API) return;
    window.API.get("/api/vuln-classes").then((d) => {
      if (d && d.classes) { setClasses(d.classes); window.VENOM.VULN_CLASSES = d.classes; }
    }).catch(() => {});
  }, []);
  React.useEffect(() => { refresh(); }, [refresh]);

  return (
    <div className="page fade-in">
      <div className="between" style={{ marginBottom: 22, alignItems: "flex-start" }}>
        <div>
          <h1 className="h1">Business-logic knowledge base</h1>
          <p className="sub">{classes.length} vulnerability-class priors from OWASP WSTG §4.10 + PortSwigger, used when the agent forms hypotheses. Not rigid playbooks.</p>
        </div>
        <button className="btn btn-primary" onClick={() => setAdding(true)}><Ic name="plus" size={16} /> Add entry</button>
      </div>

      {adding && <KnowledgeAddForm onCancel={() => setAdding(false)} onSaved={() => { setAdding(false); refresh(); }} />}

      <div className="vc-grid">
        {classes.map((v) => (
          <div className="vc" key={v.id} style={{ cursor: "default", alignItems: "stretch", flexDirection: "column", gap: 8 }}>
            <div className="between" style={{ alignItems: "flex-start" }}>
              <div className="vc-t" style={{ fontSize: 13.5 }}>{v.name}{v.custom && <span className="tag" style={{ marginLeft: 8, color: "var(--accent-ink)", background: "var(--accent-soft)", borderColor: "var(--accent-line)" }}>custom</span>}</div>
              <span className="tag mono" style={{ flexShrink: 0 }}>{v.cwe}</span>
            </div>
            {v.desc && <div className="vc-d">{v.desc}</div>}
            {v.probe && (
              <div style={{ marginTop: 2 }}>
                <div className="eyebrow" style={{ marginBottom: 3 }}>Probe</div>
                <div style={{ fontSize: 12, color: "var(--ink-2)", lineHeight: 1.45 }}>{v.probe}</div>
              </div>
            )}
            {v.exploit && (
              <div>
                <div className="eyebrow" style={{ marginBottom: 3 }}>Exploit idea</div>
                <div style={{ fontSize: 12, color: "var(--ink-2)", lineHeight: 1.45 }}>{v.exploit}</div>
              </div>
            )}
            {v.refs && v.refs.length > 0 && (
              <div className="row gap6 wrap" style={{ marginTop: 2 }}>
                {v.refs.map((r, k) => <span className="tag" key={k} style={{ fontSize: 10 }}>{r}</span>)}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function Settings({ t, setTweak, accents }) {
  const [providers, setProviders] = React.useState(null);
  const [fleet, setFleet] = React.useState(null);
  const [status, setStatus] = React.useState(window.VENOM_STATUS || null);
  t = t || { theme: "auto", accent: "amber", density: "comfortable" };
  setTweak = setTweak || (() => {});
  accents = accents || [];

  React.useEffect(() => {
    if (!window.API) return;
    window.API.providers().then((d) => setProviders(d)).catch(() => setProviders({ providers: [] }));
    window.API.agents().then((d) => setFleet(d.fleet || [])).catch(() => setFleet([]));
    window.API.status().then((d) => setStatus(d)).catch(() => {});
  }, []);

  const onPill = (ok) => (
    <span className={`pill ${ok ? "pill-done" : "pill-idle"}`}>
      <span className="dot" />{ok ? "enabled" : "offline"}
    </span>
  );

  return (
    <div className="page fade-in">
      <div style={{ marginBottom: 22 }}>
        <h1 className="h1">Settings & providers</h1>
        <p className="sub">Model fleet, LLM providers, air-gap mode, audit keys and redaction; read live from this VENOM process.</p>
      </div>

      {/* appearance — visible theme/accent/density controls (no hidden panel needed) */}
      <div className="card card-pad" style={{ marginBottom: 14 }}>
        <div className="eyebrow" style={{ marginBottom: 12 }}>Appearance</div>
        <div className="row" style={{ gap: 28, flexWrap: "wrap", alignItems: "center" }}>
          <div className="row gap10">
            <span style={{ fontSize: 13, color: "var(--ink-2)", minWidth: 48 }}>Theme</span>
            <div className="seg">
              {["auto", "light", "dark"].map((v) => (
                <button key={v} className={t.theme === v ? "on" : ""} onClick={() => setTweak("theme", v)}
                  style={{ textTransform: "capitalize" }}>{v}</button>
              ))}
            </div>
          </div>
          <div className="row gap10">
            <span style={{ fontSize: 13, color: "var(--ink-2)", minWidth: 48 }}>Density</span>
            <div className="seg">
              {["comfortable", "compact"].map((v) => (
                <button key={v} className={t.density === v ? "on" : ""} onClick={() => setTweak("density", v)}
                  style={{ textTransform: "capitalize" }}>{v}</button>
              ))}
            </div>
          </div>
          {accents.length > 0 && (
            <div className="row gap10">
              <span style={{ fontSize: 13, color: "var(--ink-2)", minWidth: 48 }}>Accent</span>
              <div className="row gap6">
                {accents.map((a) => (
                  <button key={a.id} title={a.id} onClick={() => setTweak("accent", a.id)}
                    style={{ width: 22, height: 22, borderRadius: "50%", background: a.swatch, cursor: "pointer",
                      border: t.accent === a.id ? "2px solid var(--ink)" : "2px solid transparent",
                      boxShadow: "0 0 0 1px var(--border-strong)" }} />
                ))}
              </div>
            </div>
          )}
        </div>
        <p className="muted" style={{ fontSize: 11.5, marginTop: 10, marginBottom: 0 }}>
          Theme "auto" follows your operating system. Choices persist in this browser.
        </p>
      </div>

      <div className="detail-grid" style={{ gridTemplateColumns: "1fr 1fr" }}>
        {/* providers */}
        <div className="card card-pad">
          <div className="eyebrow" style={{ marginBottom: 12 }}>LLM providers</div>
          {!providers && <div className="muted" style={{ fontSize: 13 }}>loading...</div>}
          {providers && (providers.providers || []).length === 0 && (
            <div className="muted" style={{ fontSize: 13 }}>No providers configured. VENOM runs offline (deterministic playbooks + flows).</div>
          )}
          <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
            {providers && (providers.providers || []).map((p) => (
              <div className="identity-card" key={p.id} style={{ background: "var(--surface-2)" }}>
                <div className="ava" style={{ background: p.enabled ? "var(--ok-soft)" : "var(--surface-3)", color: p.enabled ? "var(--ok)" : "var(--ink-3)", borderRadius: 8 }}>
                  <Ic name={p.enabled ? "checkCirc" : "globe"} size={16} />
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontWeight: 600, fontSize: 13 }}>{p.name}</div>
                  <div className="mono" style={{ fontSize: 11, color: "var(--ink-3)", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.model || "default"}</div>
                </div>
                {onPill(p.enabled)}
              </div>
            ))}
          </div>
          {providers && (
            <div className="row gap10" style={{ marginTop: 14, justifyContent: "space-between" }}>
              <span className="muted" style={{ fontSize: 12 }}>Fallback chain: NVIDIA -> OpenRouter -> Ollama</span>
              <span className={`pill ${providers.any_enabled ? "pill-done" : "pill-idle"}`}><span className="dot" />{providers.any_enabled ? "agent loop available" : "offline mode"}</span>
            </div>
          )}
        </div>

        {/* governance */}
        <div>
          <div className="card card-pad" style={{ marginBottom: 14 }}>
            <div className="eyebrow" style={{ marginBottom: 12 }}>Safety & governance</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 11 }}>
              <div className="between"><span style={{ fontSize: 13 }}>Scope guard</span><span className="pill pill-done"><span className="dot" />{status && status.kill_switch ? "halted" : "armed"}</span></div>
              <div className="between"><span style={{ fontSize: 13 }}>Kill switch</span><span className={`pill ${status && status.kill_switch ? "pill-live" : "pill-idle"}`}><span className="dot" />{status && status.kill_switch ? "engaged" : "ready"}</span></div>
              <div className="between"><span style={{ fontSize: 13 }}>Secret redaction</span><span className="pill pill-done"><span className="dot" />always on</span></div>
              <div className="between"><span style={{ fontSize: 13 }}>Air-gap mode</span><span className={`pill ${status && status.air_gap ? "pill-done" : "pill-idle"}`}><span className="dot" />{status && status.air_gap ? "on" : "off"}</span></div>
              <div className="between"><span style={{ fontSize: 13 }}>Audit trail</span><span className="pill pill-done"><span className="dot" />HMAC-signed</span></div>
            </div>
          </div>

          <div className="card card-pad">
            <div className="eyebrow" style={{ marginBottom: 6 }}>Build</div>
            <div className="meta-row"><span className="ml">Version</span><span className="mv mono">{(status && status.version) || "0.1.0"}</span></div>
            <div className="meta-row"><span className="ml">Runtime</span><span className="mv">in-process VulnLab target</span></div>
          </div>
        </div>
      </div>

      {/* fleet */}
      <div className="card card-pad" style={{ marginTop: 14 }}>
        <div className="eyebrow" style={{ marginBottom: 12 }}>Multi-agent fleet</div>
        <table className="eng-table">
          <thead><tr><th style={{ width: "24%" }}>Role</th><th>Model</th><th>Provider</th><th>Function</th></tr></thead>
          <tbody>
            {(fleet || []).map((a) => (
              <tr key={a.role} style={{ cursor: "default" }}>
                <td><span style={{ fontWeight: 600, textTransform: "capitalize" }}>{a.role}</span></td>
                <td className="mono" style={{ fontSize: 12 }}>{a.model}</td>
                <td className="mono" style={{ fontSize: 12, color: "var(--ink-3)" }}>{a.provider}</td>
                <td style={{ fontSize: 12, color: "var(--ink-2)" }}>{a.description}</td>
              </tr>
            ))}
            {fleet === null && <tr><td colSpan={4} className="muted">loading...</td></tr>}
          </tbody>
        </table>
      </div>
    </div>
  );
}

Object.assign(window, { KnowledgeBase, Settings });
