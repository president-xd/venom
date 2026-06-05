/* ============================================================
   VENOM — Findings list · Finding detail · Report
   ============================================================ */

function highlightPy(src) {
  const esc = src.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const RE = /(#[^\n]*)|(f?"[^"]*"|'[^']*')|\b(async|def|await|return|import|for|in|if|else|and|or|not|None|True|False)\b|\b(\d+\.?\d*)\b/g;
  return esc.replace(RE, (m, cm, str, kw, num) => {
    if (cm) return `<span class="c-cm">${cm}</span>`;
    if (str) return `<span class="c-str">${str}</span>`;
    if (kw) return `<span class="c-kw">${kw}</span>`;
    if (num) return `<span class="c-num">${num}</span>`;
    return m;
  });
}

const SEV_ORDER = { crit: 0, high: 1, med: 2, low: 3, info: 4 };

function FindingsList({ findings, openFinding, runId }) {
  const all = findings || window.VENOM.FINDINGS;
  const [filter, setFilter] = React.useState("all");
  const [q, setQ] = React.useState("");

  let rows = all.filter((f) => {
    if (filter === "crit" && f.severity !== "crit") return false;
    if (filter === "high" && !["crit", "high"].includes(f.severity)) return false;
    if (filter === "confirmed" && !f.confirmed) return false;
    if (q && !(f.title + f.vclass + f.path).toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  });
  rows = [...rows].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);

  const counts = {
    all: all.length,
    crit: all.filter((f) => f.severity === "crit").length,
    high: all.filter((f) => ["crit", "high"].includes(f.severity)).length,
    confirmed: all.filter((f) => f.confirmed).length,
  };

  const dl = (kind) => {
    if (!runId) return;
    const url = kind === "sarif" ? window.API.sarifUrl(runId) : window.API.findingsJsonUrl(runId);
    window.open(url, "_blank");
  };

  return (
    <div className="page page-wide fade-in">
      <div className="between" style={{ marginBottom: 18 }}>
        <div>
          <h1 className="h1">Findings</h1>
          <p className="sub">{runId + " · VulnLab"} | risk-ranked, every confirmed item carries before/after evidence.</p>
        </div>
        <div className="row gap10">
          <button className="btn" onClick={() => dl("sarif")} disabled={!runId} title={runId ? "Download SARIF" : "Available after a live run"}><Ic name="download" size={15} /> SARIF</button>
          <button className="btn" onClick={() => dl("json")} disabled={!runId} title={runId ? "Download findings.json" : "Available after a live run"}><Ic name="download" size={15} /> findings.json</button>
        </div>
      </div>

      <div className="find-toolbar">
        <div className="seg">
          {[["all", `All · ${counts.all}`], ["crit", `Critical · ${counts.crit}`], ["high", `High+ · ${counts.high}`], ["confirmed", `Confirmed · ${counts.confirmed}`]].map(([k, l]) => (
            <button key={k} className={filter === k ? "on" : ""} onClick={() => setFilter(k)}>{l}</button>
          ))}
        </div>
        <div className="search-in">
          <Ic name="search" />
          <input placeholder="Filter by title, class, endpoint…" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
      </div>

      <div className="find-head">
        <div>Severity</div><div>Finding</div><div>Class</div><div>Confirmation</div><div>ID</div>
      </div>
      {rows.map((f) => (
        <div className="find-row" key={f.id} onClick={() => openFinding(f.id)}>
          <Sev s={f.severity} />
          <div style={{ minWidth: 0 }}>
            <div className="fr-title">{f.title}</div>
            <div className="fr-sub"><Method m={f.method} /> {f.path}</div>
          </div>
          <div className="fr-class">{f.vclass}<div className="mono" style={{ fontSize: 10.5, color: "var(--ink-4)", marginTop: 2 }}>{f.cwe}</div></div>
          <div>
            {f.confirmed
              ? <span className="pill pill-done"><Ic name="check" size={11} /> {f.oracle}</span>
              : <span className="pill pill-idle"><Ic name="clock" size={11} /> unconfirmed</span>}
          </div>
          <div className="mono" style={{ fontSize: 12, color: "var(--ink-3)" }}>{f.id}</div>
        </div>
      ))}
      {rows.length === 0 && <div className="empty">{all.length === 0 ? "This run confirmed no findings. Logged honestly; nothing is fabricated." : "No findings match this filter."}</div>}
    </div>
  );
}

/* ------------------------------------------------------------------ */

function FindingDetail({ finding, findings, back, openFinding }) {
  const f = finding;
  const all = findings || window.VENOM.FINDINGS;
  const idx = all.findIndex((x) => x.id === f.id);

  return (
    <div className="page page-wide fade-in">
      <button className="btn btn-ghost btn-sm" onClick={back} style={{ marginBottom: 14, marginLeft: -8 }}>
        <Ic name="arrowL" size={15} /> All findings
      </button>

      <div className="between" style={{ alignItems: "flex-start", marginBottom: 6 }}>
        <div style={{ minWidth: 0 }}>
          <div className="row gap10" style={{ marginBottom: 8 }}>
            <Sev s={f.severity} />
            <span className="mono" style={{ fontSize: 12, color: "var(--ink-3)" }}>{f.id}</span>
            {f.confirmed
              ? <span className="pill pill-done"><Ic name="check" size={11} /> confirmed · {f.oracle} oracle</span>
              : <span className="pill pill-idle"><Ic name="clock" size={11} /> unconfirmed · logged as lead</span>}
          </div>
          <h1 className="h1">{f.title}</h1>
          <div className="row gap10" style={{ marginTop: 8 }}>
            <Method m={f.method} />
            <span className="mono" style={{ fontSize: 13, color: "var(--ink-2)" }}>{f.path}</span>
          </div>
        </div>
      </div>

      <div className="detail-grid" style={{ marginTop: 22 }}>
        {/* ---- main ---- */}
        <div>
          <p className="lede" style={{ marginTop: 0 }}>{f.summary}</p>

          {/* oracle */}
          <div className={`oracle-card ${f.confirmed ? "pass" : ""}`} style={{ marginTop: 18, background: f.confirmed ? "var(--ok-soft)" : "var(--surface-2)", borderColor: f.confirmed ? "oklch(0.82 0.08 152)" : "var(--border)" }}>
            <div className="row gap10" style={{ marginBottom: 10, alignItems: "flex-start" }}>
              <Ic name={f.confirmed ? "shieldChk" : "alert"} size={17} style={{ color: f.confirmed ? "var(--ok)" : "var(--sev-med)", flexShrink: 0, marginTop: 1 }} />
              <b style={{ fontSize: 13.5, lineHeight: 1.35 }}>{f.confirmed ? `Confirmed by ${f.oracle}` : "Unconfirmed · honest verdict"}</b>
            </div>
            {(f.oracleRows || []).map((r, k) => (
              <div className="oracle-row" key={k}>
                <Ic name={r.ok ? "checkCirc" : "xCirc"} className="o-ic" style={{ color: r.ok ? "var(--ok)" : "var(--ink-4)" }} />
                <span style={{ color: r.ok ? "var(--ink)" : "var(--ink-3)" }}>{r.t}</span>
              </div>
            ))}
          </div>

          {/* request log */}
          <h2 className="h2" style={{ margin: "26px 0 12px" }}>Request log</h2>
          <div className="evidence-block">
            <div className="evidence-head"><Ic name="terminal" className="e-ic" /> Scope-guarded trace · X-Pentest-ID: {f.id}</div>
            <div className="http-log">
              {(f.log || []).map((l, k) => {
                const cls = l.kind === "deny" ? "deny" : l.kind === "win" ? "win" : "";
                const st = String(l.s)[0];
                return (
                  <div className={`hl ${cls}`} key={k}>
                    <span className="seq">{k + 1}</span>
                    <span className={`meth m-${l.m}`} style={{ color: methColor(l.m) }}>{l.m}</span>
                    <span className="pth">{l.p}</span>
                    {l.note && <span style={{ color: "var(--ink-4)", marginLeft: 8 }}>· {l.note}</span>}
                    <span className={`st st-${st}`}>{l.s}</span>
                  </div>
                );
              })}
            </div>
          </div>

          {/* state delta — only when a value actually moved (no fabricated delta) */}
          {f.state && (<>
            <h2 className="h2" style={{ margin: "26px 0 12px" }}>State delta (before → after)</h2>
            <div className="evidence-block">
              <div className="state-delta">
                <div className="state-box">
                  <div className="sb-lab">{f.state.label}</div>
                  <div className="sb-val">{f.state.before}</div>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--ink-3)", marginTop: 4 }}>baseline</div>
                </div>
                <div className="delta-arrow">
                  <Ic name="arrowR" size={22} />
                  <div className="d-amt">{f.state.note}</div>
                </div>
                <div className="state-box after">
                  <div className="sb-lab">{f.state.label}</div>
                  <div className="sb-val">{f.state.after}</div>
                  <div className="mono" style={{ fontSize: 10.5, color: "var(--ink-3)", marginTop: 4 }}>post-exploit</div>
                </div>
              </div>
            </div>
          </>)}

          {/* exploit code — only when the agent actually authored one */}
          {f.code
            ? (<>
                <h2 className="h2" style={{ margin: "26px 0 12px" }}>
                  <span className="row gap10" style={{ display: "inline-flex" }}><Ic name="flask" size={16} style={{ color: "var(--ink-3)" }} /> Sandboxed exploit</span>
                </h2>
                <p className="muted" style={{ fontSize: 12.5, marginTop: 0, marginBottom: 10 }}>AST-validated · action-grounded to discovered endpoints · hard timeout. Authored by the {f.origin === "agent" || f.origin === "oneshot" ? "CodeGen agent" : f.origin} and run in the sandbox.</p>
                <pre className="code" dangerouslySetInnerHTML={{ __html: highlightPy(f.code) }} />
              </>)
            : (<>
                <h2 className="h2" style={{ margin: "26px 0 12px" }}>
                  <span className="row gap10" style={{ display: "inline-flex" }}><Ic name="flask" size={16} style={{ color: "var(--ink-3)" }} /> How it was confirmed</span>
                </h2>
                <p className="muted" style={{ fontSize: 12.5, marginTop: 0, marginBottom: 10 }}>
                  No synthesized exploit script for this finding — it was confirmed deterministically via <b>{f.oracle}</b> ({f.origin}). The scope-guarded request log above is the evidence.
                </p>
              </>)}

          {/* impact + remediation */}
          <h2 className="h2" style={{ margin: "26px 0 12px" }}>Impact</h2>
          <p style={{ marginTop: 0 }}>{f.impact}</p>

          <h2 className="h2" style={{ margin: "26px 0 12px" }}>Remediation</h2>
          <ol className="rem-list">
            {(f.remediation || []).map((r, k) => (
              <li key={k}><span className="num">{k + 1}</span><span>{r}</span></li>
            ))}
          </ol>
        </div>

        {/* ---- side meta ---- */}
        <div>
          <div className="card card-pad meta-card">
            <div className="eyebrow" style={{ marginBottom: 6 }}>Classification</div>
            <div className="meta-row"><span className="ml">Class</span><span className="mv">{f.vclass}</span></div>
            <div className="meta-row"><span className="ml">CWE</span><span className="mv mono">{f.cwe}</span></div>
            <div className="meta-row"><span className="ml">OWASP</span><span className="mv mono">{f.owasp}</span></div>
            <div className="meta-row"><span className="ml">Endpoint</span><span className="mv mono" style={{ fontSize: 12 }}>{f.method} {f.path}</span></div>
            <div className="meta-row"><span className="ml">Oracle mode</span><span className="mv">{f.oracle}</span></div>
            <div className="meta-row"><span className="ml">Identities</span><span className="mv">attacker · victim</span></div>
            <div className="meta-row">
              <span className="ml">Status</span>
              <span className="mv">{f.confirmed
                ? <span style={{ color: "var(--ok)" }}>Confirmed with evidence</span>
                : <span style={{ color: "var(--sev-med)" }}>Unconfirmed lead</span>}</span>
            </div>
          </div>

          <div className="card card-pad" style={{ marginTop: 14 }}>
            <div className="eyebrow" style={{ marginBottom: 10 }}>Evidence & audit</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {f.state
                ? <div className="row gap10"><Ic name="checkCirc" size={15} style={{ color: "var(--ok)" }} /><span style={{ fontSize: 12.5 }}>Before/after state delta captured</span></div>
                : <div className="row gap10"><Ic name="xCirc" size={15} style={{ color: "var(--ink-4)" }} /><span style={{ fontSize: 12.5, color: "var(--ink-3)" }}>No state delta (confirmed by {f.oracle})</span></div>}
              {f.authored
                ? <div className="row gap10"><Ic name="checkCirc" size={15} style={{ color: "var(--ok)" }} /><span style={{ fontSize: 12.5 }}>Sandboxed exploit code attached</span></div>
                : null}
              <div className="row gap10"><Ic name="checkCirc" size={15} style={{ color: "var(--ok)" }} /><span style={{ fontSize: 12.5 }}>Full request log attached</span></div>
              <div className="row gap10"><Ic name="lock" size={15} style={{ color: "var(--ink-3)" }} /><span style={{ fontSize: 12.5 }}>Audit trail HMAC-signed</span></div>
              <div className="row gap10"><Ic name="shield" size={15} style={{ color: "var(--ink-3)" }} /><span style={{ fontSize: 12.5 }}>Secrets redacted in artifacts</span></div>
            </div>
            <button className="btn btn-sm" style={{ width: "100%", marginTop: 14 }} onClick={() => navigator.clipboard && navigator.clipboard.writeText(f.code || "")}><Ic name="copy" size={14} /> Copy reproduction</button>
          </div>

          {/* nav between findings */}
          <div className="row gap10" style={{ marginTop: 14 }}>
            <button className="btn btn-sm" disabled={idx <= 0} onClick={() => openFinding(all[idx - 1].id)} style={{ flex: 1 }}><Ic name="arrowL" size={14} /> Prev</button>
            <button className="btn btn-sm" disabled={idx >= all.length - 1} onClick={() => openFinding(all[idx + 1].id)} style={{ flex: 1 }}>Next <Ic name="arrowR" size={14} /></button>
          </div>
        </div>
      </div>
    </div>
  );
}

function methColor(m) {
  return ({ GET: "oklch(0.7 0.1 230)", POST: "oklch(0.72 0.13 152)", DELETE: "oklch(0.68 0.18 25)", PATCH: "var(--accent)", PUT: "var(--accent)" })[m] || "var(--ink)";
}

/* ------------------------------------------------------------------ */

const SEV_COLOR = { crit: "var(--sev-crit)", high: "var(--sev-high)", med: "var(--sev-med)", low: "var(--ink-3)", info: "var(--ink-4)" };

function fmtDate(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  return isNaN(d) ? String(iso).slice(0, 10) : d.toISOString().slice(0, 10);
}

function Report({ findings, runId, meta, openFinding }) {
  const all = findings || window.VENOM.FINDINGS;
  const confirmed = all.filter((f) => f.confirmed);
  const m = meta || {};
  const by = (s) => confirmed.filter((f) => f.severity === s).length;
  const live = !!runId;
  const today = new Date().toISOString().slice(0, 10);
  const sevs = ["crit", "high", "med", "low"];
  const total = confirmed.length || 1;

  // Honest summary derived from the REAL confirmation methods.
  const methods = [...new Set(confirmed.map((f) => f.oracle).filter(Boolean))];
  const authWindow = m.authorization_date ? `${fmtDate(m.authorization_date)} → ${fmtDate(m.expiry_date)}` : `${today} (24h)`;
  const kv = (k, v, mono) => (
    <div className="report-kv"><span className="k">{k}</span><span className={"v" + (mono ? " mono" : "")}>{v}</span></div>
  );

  return (
    <div className="page fade-in">
      <div className="report">
        <div className="between no-print" style={{ marginBottom: 16 }}>
          <div className="eyebrow">Engagement report · generated by VENOM</div>
          <div className="row gap10">
            <button className="btn btn-sm" onClick={() => window.print()}><Ic name="download" size={14} /> Print / PDF</button>
            <button className="btn btn-sm" onClick={() => live && window.open(window.API ? window.API.reportUrl(runId) : "#", "_blank")} disabled={!live}><Ic name="download" size={14} /> Markdown</button>
            <button className="btn btn-sm" onClick={() => live && window.open(window.API.findingsJsonUrl(runId), "_blank")} disabled={!live}><Ic name="download" size={14} /> JSON</button>
            <button className="btn btn-sm" onClick={() => live && window.open(window.API.sarifUrl(runId), "_blank")} disabled={!live}><Ic name="download" size={14} /> SARIF</button>
          </div>
        </div>

        <div className="report-sheet">
          {/* ---- masthead ---- */}
          <div className="report-mast">
            <div>
              <div className="row gap10" style={{ marginBottom: 10 }}>
                <div className="sb-mark" style={{ width: 28, height: 28 }}><Ic name="bug" size={16} /></div>
                <span style={{ fontWeight: 700, letterSpacing: "0.14em" }}>VENOM</span>
              </div>
              <div style={{ fontSize: 22, fontWeight: 700, letterSpacing: "-0.01em" }}>Business-Logic Penetration Test</div>
              <div style={{ fontSize: 13, color: "var(--ink-2)", marginTop: 6 }}>{m.target_name || "VulnLab"} — engagement report</div>
            </div>
            <div style={{ textAlign: "right", fontSize: 12 }} className="mono">
              <div style={{ color: "var(--ink-3)" }}>{m.engagement_id || runId}</div>
              <div style={{ marginTop: 4 }}>{today}</div>
              <div style={{ marginTop: 4, color: "var(--ink-3)" }}>CONFIDENTIAL</div>
            </div>
          </div>

          {/* ---- 1. executive summary ---- */}
          <h2 className="rh">1 · Executive summary</h2>
          <p className="lede">
            VENOM conducted an authorized, scope-guarded business-logic penetration test of <b>{m.target_name || "the target"}</b> ({m.base_url || "http://localhost:8000"}).
            The engagement ran as an autonomous LLM-driven agent — reconnaissance, business-model inference, adversarial
            hypothesis generation, sandboxed exploit synthesis, and differential verification — across <b>{m.tests_run || all.length}</b> test cases.
            It confirmed <b>{confirmed.length} business-logic {confirmed.length === 1 ? "finding" : "findings"}</b>
            {by("crit") + by("high") > 0 ? <> ({by("crit")} critical, {by("high")} high)</> : null}.
            {methods.length ? <> Each finding was proven by {methods.join(", ")} — a concrete state transition or privileged action, not a scanner signature.</> : null}
            {" "}Every outbound request passed the scope guard; the agent stopped at proof-of-concept and persisted no access.
          </p>

          {/* severity distribution */}
          <div className="sev-dist">
            {sevs.map((s) => by(s) > 0 ? <span key={s} style={{ width: `${(by(s) / total) * 100}%`, background: SEV_COLOR[s] }} /> : null)}
            {confirmed.length === 0 && <span style={{ width: "100%", background: "var(--border)" }} />}
          </div>
          <div className="exec-stat">
            <div className="es"><div className="n" style={{ color: "var(--sev-crit)" }}>{by("crit")}</div><div className="l">Critical</div></div>
            <div className="es"><div className="n" style={{ color: "var(--sev-high)" }}>{by("high")}</div><div className="l">High</div></div>
            <div className="es"><div className="n" style={{ color: "var(--sev-med)" }}>{by("med")}</div><div className="l">Medium</div></div>
            <div className="es"><div className="n">{m.tests_run || all.length}</div><div className="l">Tests run</div></div>
          </div>

          {/* ---- 2. scope & authorization ---- */}
          <h2 className="rh">2 · Scope &amp; authorization</h2>
          <div className="report-meta-grid">
            <div>
              {kv("Target", m.target_name || "VulnLab")}
              {kv("Authorized base URL", m.base_url || "http://localhost:8000", true)}
              {kv("Out of scope", (m.out_of_scope && m.out_of_scope.length ? m.out_of_scope.join(", ") : "—"), true)}
              {kv("Authorized by", m.authorized_by || "—")}
            </div>
            <div>
              {kv("Window", authWindow, true)}
              {kv("Rate limit", (m.rate_limit != null ? `${m.rate_limit} req/s` : "—") + (m.destructive ? " · destructive allowed" : " · non-destructive"), true)}
              {kv("Identities", (m.identities && m.identities.length ? m.identities.join(", ") : "—"))}
              {kv("Endpoints discovered", m.endpoints != null ? m.endpoints : "—", true)}
            </div>
          </div>
          {m.objective ? <p style={{ fontSize: 13, marginTop: 10 }}><b>Objective:</b> {m.objective}</p> : null}

          {/* ---- 3. methodology ---- */}
          <h2 className="rh">3 · Methodology</h2>
          <p>The engagement was executed by VENOM's autonomous agent ({m.engine || "LLM-driven"}). Each finding is the
            product of the following pipeline, with every request mediated by the scope guard and all agent-authored
            code executed in an AST-validated, action-grounded sandbox:</p>
          <table className="rep-table">
            <tbody>
              <tr><td style={{ width: 150, fontWeight: 600 }}>Recon</td><td>Authenticated crawl + forced-browse to enumerate endpoints, forms and parameters.</td></tr>
              <tr><td style={{ fontWeight: 600 }}>Model inference</td><td>The LLM reconstructs the intended business model (entities, state machines, rules, economic flows).</td></tr>
              <tr><td style={{ fontWeight: 600 }}>Hypotheses</td><td>Adversarial hypotheses are generated per rule across the business-logic attack lenses.</td></tr>
              <tr><td style={{ fontWeight: 600 }}>Exploitation</td><td>The agent writes real exploit code, grounded to discovered endpoints, and runs it in the sandbox.</td></tr>
              <tr><td style={{ fontWeight: 600 }}>Verification</td><td>A finding is confirmed only by a differential oracle (denied → succeeded), a measured state delta, or response-content proof — never a bare 2xx.</td></tr>
            </tbody>
          </table>

          {/* ---- 4. findings summary ---- */}
          <h2 className="rh">4 · Findings summary</h2>
          <table className="rep-table">
            <thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>Class</th><th>Confirmation</th></tr></thead>
            <tbody>
              {[...confirmed].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]).map((f) => (
                <tr key={f.id} style={{ cursor: "pointer" }} onClick={() => openFinding(f.id)}>
                  <td className="mono">{f.id}</td>
                  <td><Sev s={f.severity} /></td>
                  <td style={{ fontWeight: 600 }}>{f.title}</td>
                  <td style={{ color: "var(--ink-3)", fontSize: 12 }}>{f.cwe}</td>
                  <td style={{ fontSize: 12, color: "var(--ok)" }}>{f.oracle}</td>
                </tr>
              ))}
              {confirmed.length === 0 && <tr><td colSpan={5} style={{ color: "var(--ink-3)" }}>No confirmed findings in this run.</td></tr>}
            </tbody>
          </table>

          {/* ---- 5. detailed findings ---- */}
          {confirmed.length > 0 && <h2 className="rh">5 · Detailed findings</h2>}
          {[...confirmed].sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]).map((f, idx) => (
            <div className="finding-section" key={f.id}>
              <div className="fs-head">
                <div>
                  <div className="row gap10" style={{ marginBottom: 4 }}>
                    <span className="mono" style={{ fontSize: 12, color: "var(--ink-3)" }}>{f.id}</span>
                    <b style={{ fontSize: 15 }}>{f.title}</b>
                  </div>
                  <div className="row gap6" style={{ flexWrap: "wrap" }}>
                    <span className="fs-tag">{f.method} {f.path}</span>
                    <span className="fs-tag">{f.vclass}</span>
                    <span className="fs-tag">{f.cwe}</span>
                    {f.owasp && f.owasp !== "—" ? <span className="fs-tag">OWASP {f.owasp}</span> : null}
                  </div>
                </div>
                <Sev s={f.severity} />
              </div>

              <p style={{ fontSize: 13, margin: "10px 0 6px" }}><b>Impact.</b> {f.impact}</p>
              <p style={{ fontSize: 13, margin: "0 0 10px" }}><b>Confirmation.</b> Proven via <b>{f.oracle}</b> ({f.origin}). {f.state ? `Measured state change — ${f.state.label}: ${f.state.before} → ${f.state.after} (${f.state.note}).` : "Confirmed from the scope-guarded request log below."}</p>

              {/* request log */}
              <div style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--ink-3)", margin: "8px 0 4px", fontFamily: "var(--mono)" }}>Reproduction · scope-guarded trace</div>
              <div className="http-log" style={{ border: "1px solid var(--border)", borderRadius: 8 }}>
                {(f.log || []).map((l, k) => (
                  <div className={`hl ${l.kind === "deny" ? "deny" : l.kind === "win" ? "win" : ""}`} key={k}>
                    <span className="seq">{k + 1}</span>
                    <span className="meth" style={{ color: methColor(l.m) }}>{l.m}</span>
                    <span className="pth">{l.p}</span>
                    {l.note && <span style={{ color: "var(--ink-4)", marginLeft: 8 }}>· {l.note}</span>}
                    <span className="st">{l.s}</span>
                  </div>
                ))}
                {(f.log || []).length === 0 && <div className="hl"><span className="pth" style={{ color: "var(--ink-3)" }}>(no request log captured)</span></div>}
              </div>

              {/* exploit code only when authored */}
              {f.code ? (<>
                <div style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: "0.06em", color: "var(--ink-3)", margin: "12px 0 4px", fontFamily: "var(--mono)" }}>Agent-authored exploit (sandboxed)</div>
                <pre className="code" style={{ fontSize: 11.5 }} dangerouslySetInnerHTML={{ __html: highlightPy(f.code) }} />
              </>) : null}

              {/* cvss + remediation */}
              {f.cvss ? <p style={{ fontSize: 12.5, margin: "10px 0 4px" }}><b>CVSS.</b> <span className="mono">{f.cvss}</span></p> : null}
              <p style={{ fontSize: 12.5, margin: "10px 0 4px" }}><b>Remediation.</b></p>
              <ol className="rem-list" style={{ marginTop: 2 }}>
                {(f.remediation || []).map((r, k) => <li key={k}><span className="num">{k + 1}</span><span>{r}</span></li>)}
              </ol>
              {(f.references && f.references.length) ? (
                <p style={{ fontSize: 11.5, color: "var(--ink-3)", marginTop: 8 }}><b>References:</b> {f.references.join(" · ")}</p>
              ) : null}
            </div>
          ))}

          {/* ---- footer / attestation ---- */}
          <div className="report-foot">
            <b>Attestation.</b> This engagement was conducted under written authorization within the stated window.
            Every outbound request passed the scope guard ({m.base_url || "in-scope hosts only"}); agent-authored code ran
            in an AST-validated, action-grounded sandbox with a hard timeout; the audit trail is HMAC-signed and secrets
            are redacted from all artifacts. The agent operated to proof-of-concept only and did not persist access,
            exfiltrate data, or perform destructive actions beyond the authorized budget.
            <br /><br />
            Generated by VENOM{m.provider ? ` · agent provider ${m.provider}` : ""} · {today}.
          </div>
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { FindingsList, FindingDetail, Report, highlightPy });
