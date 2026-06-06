/* ============================================================
   VENOM - Dashboard + New Engagement wizard (scope -> describe)
   ============================================================ */

function Dashboard({ go, openEngagement }) {
  const eng = window.VENOM.ENGAGEMENTS;
  const sum = (k) => eng.reduce((a, e) => a + (e[k] || 0), 0);
  const totalFindings = sum("crit") + sum("high") + sum("med") + sum("low");
  const stats = [
    { lab: "Engagements", num: String(eng.length), delta: eng.length ? "launched from this console" : "launch your first run", edge: "var(--accent)" },
    { lab: "Confirmed findings", num: String(totalFindings), delta: `across ${eng.length} engagement${eng.length === 1 ? "" : "s"}`, edge: "var(--info)" },
    { lab: "Critical", num: String(sum("crit")), delta: "highest severity", edge: "var(--sev-crit)" },
    { lab: "High", num: String(sum("high")), delta: "confirmed with evidence", edge: "var(--ok)" },
  ];
  return (
    <div className="page fade-in">
      <div className="between" style={{ marginBottom: 22 }}>
        <div>
          <h1 className="h1">Engagements</h1>
          <p className="sub">Authorized business-logic penetration tests. Every request passes the scope guard.</p>
        </div>
        <button className="btn btn-primary btn-lg" onClick={() => go("describe")}>
          <Ic name="plus" size={16} /> New engagement
        </button>
      </div>

      <div className="stat-grid" style={{ marginBottom: 24 }}>
        {stats.map((s, i) => (
          <div className="stat" key={i}>
            <div className="accent-edge" style={{ background: s.edge }} />
            <div className="lab">{s.lab}</div>
            <div className="num tnum">{s.num}</div>
            <div className="delta">{s.delta}</div>
          </div>
        ))}
      </div>

      <div className="card">
        <div className="between" style={{ padding: "15px 18px 12px" }}>
          <h2 className="h2">Recent engagements</h2>
          <div className="row gap10">
            <span className="pill pill-idle"><Ic name="filter" size={12} /> All targets</span>
          </div>
        </div>
        <div style={{ padding: "0 4px 4px" }}>
          <table className="eng-table">
            <thead>
              <tr>
                <th style={{ width: "30%" }}>Target</th>
                <th>Engagement</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Lead</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {eng.map((e) => (
                <tr key={e.id} onClick={() => openEngagement(e)}>
                  <td>
                    <div className="eng-name">{e.name}{e.live && <span className="tag" style={{ marginLeft: 8, color: "var(--ok)", borderColor: "oklch(0.83 0.07 152)", background: "var(--ok-soft)" }}>live</span>}{e.demo && <span className="tag" style={{ marginLeft: 8 }}>demo</span>}</div>
                    <div className="eng-url mono">{e.url}</div>
                  </td>
                  <td className="mono" style={{ fontSize: 12, color: "var(--ink-2)" }}>{e.id}</td>
                  <td>
                    {e.status === "live" && <Pill kind="live">running</Pill>}
                    {e.status === "done" && <Pill kind="done">complete</Pill>}
                    {e.status === "review" && <Pill kind="review">in review</Pill>}
                    {e.status === "error" && <Pill kind="review">error</Pill>}
                  </td>
                  <td><SevBar crit={e.crit} high={e.high} med={e.med} low={e.low} width={96} /></td>
                  <td style={{ color: "var(--ink-2)" }}>{e.owner}</td>
                  <td style={{ color: "var(--ink-3)" }}>{e.started}</td>
                </tr>
              ))}
              {eng.length === 0 && (
                <tr><td colSpan={6} style={{ padding: "30px 14px", textAlign: "center", color: "var(--ink-3)", cursor: "default" }}>
                  No engagements yet, click <b>New engagement</b> to launch your first scope-guarded run.
                </td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------------------------------------------ */

function StepPips({ step }) {
  const steps = ["Authorize target", "Identities & limits", "Describe the attack"];
  return (
    <div className="steps">
      {steps.map((s, i) => (
        <React.Fragment key={i}>
          {i > 0 && <div className="step-line" />}
          <div className={`step-pip ${i === step ? "active" : i < step ? "done" : ""}`}>
            <span className="n">{i < step ? <Ic name="check" size={13} /> : i + 1}</span>
            <span className="t">{s}</span>
          </div>
        </React.Fragment>
      ))}
    </div>
  );
}

function NewEngagement({ onLaunch }) {
  const [step, setStep] = React.useState(0);
  const [url, setUrl] = React.useState("http://localhost:8000");
  const [rate, setRate] = React.useState(5);
  const [destructive, setDestructive] = React.useState(false);
  const [crawl, setCrawl] = React.useState(true);
  const [think, setThink] = React.useState(true);
  const [prompt, setPrompt] = React.useState("");
  const VC = window.VENOM.VULN_CLASSES;
  const EX = window.VENOM.EXAMPLE_PROMPTS;
  const [picked, setPicked] = React.useState(() => (VC || []).slice(0, 3).map((v) => v.id));
  const [scopeMsg, setScopeMsg] = React.useState(null);   // {ok, text}
  const [launching, setLaunching] = React.useState(false);

  // Real, editable scope: in-scope path prefixes (additive) + hard-blocked hosts.
  // Entered through inline fields - no browser prompt; the operator types the value.
  const [scopePaths, setScopePaths] = React.useState(["/shop/*", "/api/*"]);
  const [oos, setOos] = React.useState(["stripe.com", "auth0.com"]);
  const [newPrefix, setNewPrefix] = React.useState("");
  const [newHost, setNewHost] = React.useState("");
  // Email-client / inbox URL - needed by registration-flow labs (email parser
  // discrepancy, truncation, account-takeover) to read the confirmation link.
  const [emailUrl, setEmailUrl] = React.useState("");

  // Real, editable test identities. The agent escalates FROM a low-privileged user,
  // so it must be able to LOG IN. Defaults to PortSwigger's standard wiener:peter
  // (also the bundled VulnLab's low-priv user), so a BurpSuite access-control lab
  // works out of the box; edit/add for any target.
  const [identities, setIdentities] = React.useState([
    { name: "attacker", username: "wiener", password: "peter", login_path: "/login" },
  ]);
  const setIdent = (i, k, v) => setIdentities((s) => s.map((it, j) => j === i ? { ...it, [k]: v } : it));
  const addIdentity = () => setIdentities((s) => [...s, { name: "user" + (s.length + 1), username: "", password: "", login_path: "/login" }]);
  const removeIdentity = (i) => setIdentities((s) => s.filter((_, j) => j !== i));
  const builtIdentities = () => identities.filter((i) => i.username.trim()).map((i, idx) => ({
    name: i.name.trim() || i.username.trim(), role: idx === 0 ? "attacker" : "victim",
    auth: {
      type: "form_login", login_url: i.login_path.trim() || "/login", method: "POST",
      username: i.username.trim(), password: i.password,
      username_field: "username", password_field: "password",
    },
  }));
  const addPrefix = () => {
    let p = newPrefix.trim();
    if (!p) return;
    if (!p.startsWith("/")) p = "/" + p;                       // normalize to a path
    if (!scopePaths.includes(p)) setScopePaths((s) => [...s, p]);
    setNewPrefix("");
  };
  const addOos = () => {
    const h = newHost.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
    if (!h) return;
    if (!oos.includes(h)) setOos((s) => [...s, h]);
    setNewHost("");
  };

  // written authorization - filled by the operator (not hardcoded)
  const today = new Date().toISOString().slice(0, 10);
  const inAWeek = new Date(Date.now() + 7 * 864e5).toISOString().slice(0, 10);
  const [engName, setEngName] = React.useState("VulnLab engagement");
  const [authBy, setAuthBy] = React.useState("");
  const [authDate, setAuthDate] = React.useState(today);
  const [expiry, setExpiry] = React.useState(inAWeek);

  const toggle = (id) => setPicked((p) => p.includes(id) ? p.filter((x) => x !== id) : [...p, id]);

  const authPayload = () => ({
    target_name: engName || "VulnLab",
    authorized_by: authBy.trim(),
    authorization_date: authDate ? authDate + "T00:00:00Z" : "",
    expiry_date: expiry ? expiry + "T23:59:59Z" : "",
    scope_paths: scopePaths,
    out_of_scope: oos,
    email_client_url: emailUrl.trim(),     // inbox URL for registration/email labs
  });

  const continueScope = async () => {
    setScopeMsg(null);
    if (!authBy.trim()) {
      setScopeMsg({ ok: false, text: "Written authorization: enter who authorized this engagement." });
      return;
    }
    try {
      const r = await window.API.validateScope({ url, rate, destructive, ...authPayload() });
      if (!r.ok) { setScopeMsg({ ok: false, text: r.error || "Scope invalid." }); return; }
      setScopeMsg({ ok: true, text: r.summary });
      setStep(1);
    } catch (e) { setStep(1); }   // offline preview still advances
  };

  const doLaunch = async () => {
    setLaunching(true);
    await onLaunch({
      // Target the URL the operator actually entered - NOT a hardcoded demo host.
      target_url: url, objective: prompt, rate, destructive, classes: picked,
      // The live engagement is an LLM-driven hunt; these toggles reach the backend.
      use_llm: true, think, crawl,
      identities: builtIdentities(),     // real credentials so the agent can log in
      ...authPayload(),
    });
  };

  return (
    <div className="page fade-in" style={{ maxWidth: 920 }}>
      <h1 className="h1" style={{ marginBottom: 4 }}>New engagement</h1>
      <p className="sub" style={{ marginBottom: 22 }}>Authorize a target, describe what to attack, and VENOM handles recon, exploitation and proof.</p>
      <StepPips step={step} />

      {step === 0 && (
        <div className="fade-in">
          <div className="card card-pad" style={{ marginBottom: 16 }}>
            <h2 className="h2" style={{ marginBottom: 4 }}>Authorization</h2>
            <p className="sub" style={{ marginBottom: 18 }}>VENOM refuses every request outside this scope. There is no bypass flag.</p>
            <div className="field">
              <label>Target base URL</label>
              <input className="input mono" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://..." />
              <p className="hint">The engagement targets <b>exactly this URL</b>. <code>localhost:8000</code> runs the <b>bundled VulnLab</b> in-process (safe, always authorized). Any other URL is hunted <b>live over HTTP</b> - you must be authorized to test it, and supply identities for authenticated flows. Every request is gated by scheme + host + port + path prefix.</p>
            </div>
            <label style={{ display: "block", marginTop: 6 }}>In-scope path prefixes <span className="hint" style={{ display: "inline", margin: 0 }}>(click a chip to remove)</span></label>
            <div className="row gap10 wrap" style={{ marginTop: 4 }}>
              {scopePaths.map((p) => (
                <span className="chip" key={p} title="remove" style={{ cursor: "pointer" }}
                  onClick={() => setScopePaths((s) => s.filter((x) => x !== p))}>
                  <Ic name="globe" size={13} /> {p}<span style={{ marginLeft: 5, color: "var(--ink-4)", fontWeight: 700 }}>×</span>
                </span>
              ))}
              {scopePaths.length === 0 && <span className="hint" style={{ margin: 0 }}>whole host in scope</span>}
            </div>
            <div className="row gap10" style={{ marginTop: 8 }}>
              <input className="input mono" style={{ maxWidth: 200 }} value={newPrefix}
                onChange={(e) => setNewPrefix(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addPrefix(); } }}
                placeholder="/admin/*" aria-label="New in-scope path prefix" />
              <button className="btn btn-sm btn-ghost" onClick={addPrefix} disabled={!newPrefix.trim()}><Ic name="plus" size={13} /> Add prefix</button>
            </div>
            <hr className="div" />
            <div className="field mb0">
              <label>Out of scope (hard-blocked) <span className="hint" style={{ display: "inline", margin: 0 }}>(click a chip to remove)</span></label>
              <div className="row gap10 wrap">
                {oos.map((h) => (
                  <span className="chip" key={h} title="remove"
                    style={{ cursor: "pointer", background: "var(--crit-soft)", color: "var(--sev-crit)", borderColor: "oklch(0.85 0.06 22)" }}
                    onClick={() => setOos((s) => s.filter((x) => x !== h))}>
                    {h}<span style={{ marginLeft: 5, fontWeight: 700 }}>×</span>
                  </span>
                ))}
              </div>
              <div className="row gap10" style={{ marginTop: 8 }}>
                <input className="input mono" style={{ maxWidth: 240 }} value={newHost}
                  onChange={(e) => setNewHost(e.target.value)}
                  onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); addOos(); } }}
                  placeholder="payments.example.com" aria-label="New out-of-scope host" />
                <button className="btn btn-sm btn-ghost" onClick={addOos} disabled={!newHost.trim()}><Ic name="plus" size={13} /> Add host</button>
              </div>
            </div>
            <hr className="div" />
            <div className="field mb0">
              <label>Email client / inbox URL <span className="hint" style={{ display: "inline", margin: 0 }}>(optional - for registration / email-parser labs)</span></label>
              <input className="input mono" value={emailUrl} onChange={(e) => setEmailUrl(e.target.value)}
                placeholder="https://exploit-....exploit-server.net/email" aria-label="Email client URL" />
              <p className="hint">If the lab confirms registration by email, paste the inbox/exploit-server email URL. VENOM reads the confirmation link to complete account-takeover & email-parser-discrepancy flows. Its host is auto-added to scope.</p>
            </div>
          </div>

          <div className="card card-pad" style={{ marginBottom: 16 }}>
            <h2 className="h2" style={{ marginBottom: 4 }}>Written authorization</h2>
            <p className="sub" style={{ marginBottom: 16 }}>You fill this in. It is recorded on every request (X-Pentest-ID) and in the signed report, and it sets the engagement's authorized time window.</p>
            <div className="field">
              <label>Engagement name</label>
              <input className="input" value={engName} onChange={(e) => setEngName(e.target.value)} placeholder="e.g. Q2 payments review" />
            </div>
            <div className="field">
              <label>Authorized by <span style={{ color: "var(--sev-crit)" }}>*</span></label>
              <input className="input" value={authBy} onChange={(e) => setAuthBy(e.target.value)} placeholder="e.g. Jane Smith, CISO" />
              <p className="hint">Name and role of the person who authorized this test.</p>
            </div>
            <div className="auth-dates">
              <div className="field mb0">
                <label>Authorization date</label>
                <input className="input mono" type="date" value={authDate} onChange={(e) => setAuthDate(e.target.value)} />
              </div>
              <div className="field mb0">
                <label>Expiry date</label>
                <input className="input mono" type="date" value={expiry} onChange={(e) => setExpiry(e.target.value)} />
                <p className="hint">After this, the scope guard halts all requests.</p>
              </div>
            </div>
          </div>

          {scopeMsg && !scopeMsg.ok && (
            <div className="card card-pad" style={{ marginBottom: 16, background: "var(--crit-soft)", borderColor: "oklch(0.85 0.06 22)" }}>
              <div className="row gap10"><Ic name="alert" size={16} style={{ color: "var(--sev-crit)" }} /><span style={{ fontSize: 13, color: "var(--sev-crit)" }}>{scopeMsg.text}</span></div>
            </div>
          )}

          <div className="between">
            <span />
            <button className="btn btn-primary btn-lg" onClick={continueScope}>Continue <Ic name="arrowR" size={15} /></button>
          </div>
        </div>
      )}

      {step === 1 && (
        <div className="fade-in">
          <div className="card card-pad" style={{ marginBottom: 16 }}>
            <h2 className="h2" style={{ marginBottom: 4 }}>Identities &amp; credentials</h2>
            <p className="sub" style={{ marginBottom: 16 }}>The agent escalates <b>from</b> a low-privileged user, so it must log in. Enter real credentials for the target (form login). The first identity is the attacker; add a second to provision/own victim objects.</p>
            <div className="row gap14" style={{ flexDirection: "column", alignItems: "stretch" }}>
              {identities.map((it, i) => (
                <div className="card card-pad" key={i} style={{ background: "var(--surface-2)" }}>
                  <div className="between" style={{ marginBottom: 8 }}>
                    <span className="tag">{i === 0 ? "attacker (low-priv)" : "victim / second actor"}</span>
                    {identities.length > 1 && <button className="btn btn-sm btn-ghost" onClick={() => removeIdentity(i)} style={{ color: "var(--sev-crit)" }}>Remove</button>}
                  </div>
                  <div className="auth-dates" style={{ gridTemplateColumns: "1fr 1fr" }}>
                    <div className="field mb0"><label>Username</label>
                      <input className="input mono" value={it.username} placeholder="wiener" onChange={(e) => setIdent(i, "username", e.target.value)} /></div>
                    <div className="field mb0"><label>Password</label>
                      <input className="input mono" type="password" value={it.password} placeholder="peter" onChange={(e) => setIdent(i, "password", e.target.value)} /></div>
                    <div className="field mb0"><label>Login path</label>
                      <input className="input mono" value={it.login_path} placeholder="/login" onChange={(e) => setIdent(i, "login_path", e.target.value)} /></div>
                    <div className="field mb0"><label>Label</label>
                      <input className="input" value={it.name} placeholder="attacker" onChange={(e) => setIdent(i, "name", e.target.value)} /></div>
                  </div>
                </div>
              ))}
              <button className="btn btn-sm btn-ghost" style={{ alignSelf: "flex-start" }} onClick={addIdentity}><Ic name="plus" size={13} /> Add identity</button>
              <p className="hint" style={{ margin: 0 }}>No credentials? Leave blank to hunt unauthenticated (limited - most access-control flaws need a session). Defaults to <code>wiener:peter</code> (PortSwigger / bundled VulnLab).</p>
            </div>
          </div>

          <div className="card card-pad" style={{ marginBottom: 16 }}>
            <h2 className="h2" style={{ marginBottom: 14 }}>Limits & safety</h2>
            <div className="field">
              <label>Rate limit · <span className="mono">{rate} req/s</span></label>
              <input type="range" min="1" max="20" value={rate} onChange={(e) => setRate(+e.target.value)} style={{ width: "100%", accentColor: "var(--accent)" }} />
              <p className="hint">Token-bucket enforced at the HTTP layer. Bursts for race tests bypass this only inside a confirmed concurrency window.</p>
            </div>
            <div className="toggle-row">
              <div><div style={{ fontWeight: 600, fontSize: 13 }}>Crawl to discover</div><div className="hint" style={{ margin: 0 }}>Find forms/links/params with no artifacts.</div></div>
              <button className={`switch ${crawl ? "on" : ""}`} onClick={() => setCrawl(!crawl)}><span className="knob" /></button>
            </div>
            <div className="toggle-row">
              <div><div style={{ fontWeight: 600, fontSize: 13 }}>Adaptive reasoning <span className="tag mono">--think</span></div><div className="hint" style={{ margin: 0 }}>Observe -> probe -> re-think -> exploit -> verify.</div></div>
              <button className={`switch ${think ? "on" : ""}`} onClick={() => setThink(!think)}><span className="knob" /></button>
            </div>
            <div className="toggle-row">
              <div><div style={{ fontWeight: 600, fontSize: 13 }}>Allow destructive methods</div><div className="hint" style={{ margin: 0 }}>DELETE/PUT require explicit opt-in + a budget cap.</div></div>
              <button className={`switch ${destructive ? "on" : ""}`} onClick={() => setDestructive(!destructive)}><span className="knob" /></button>
            </div>
          </div>

          <div className="between">
            <button className="btn" onClick={() => setStep(0)}><Ic name="arrowL" size={15} /> Back</button>
            <button className="btn btn-primary btn-lg" onClick={() => setStep(2)}>Describe the attack <Ic name="arrowR" size={15} /></button>
          </div>
        </div>
      )}

      {step === 2 && (
        <div className="fade-in">
          <div style={{ marginBottom: 18 }}>
            <h2 className="h2" style={{ marginBottom: 4 }}>What should VENOM attack?</h2>
            <p className="sub">Describe the flaw or hypothesis in plain language. VENOM grounds it against the discovered surface, then proves it.</p>
          </div>

          <div className="prompt-box" style={{ marginBottom: 14 }}>
            <textarea rows={3} value={prompt} onChange={(e) => setPrompt(e.target.value)}
              placeholder="e.g. Free users shouldn't be able to read another account's wallet. Check object-level authorization on the wallet endpoints, and whether the payout token leaks across accounts." />
            <div className="prompt-foot">
              <span className="tag mono"><Ic name="terminal" size={12} style={{ verticalAlign: "-2px", marginRight: 4 }} />natural language</span>
              <span className="muted" style={{ fontSize: 12 }}>Grounded to discovered endpoints, no hallucinated paths.</span>
              <div className="spacer" style={{ flex: 1 }} />
            </div>
          </div>

          <div style={{ marginBottom: 18 }}>
            <div className="eyebrow" style={{ marginBottom: 8 }}>Or start from a hypothesis</div>
            {EX.map((q, i) => (
              <button className="example-q" key={i} onClick={() => setPrompt(q)}>{q}</button>
            ))}
          </div>

          <div style={{ marginBottom: 20 }}>
            <div className="between" style={{ marginBottom: 10 }}>
              <div className="eyebrow">Vulnerability classes to hunt</div>
              <span className="muted" style={{ fontSize: 12 }}>{picked.length} selected</span>
            </div>
            <div className="vc-grid">
              {VC.map((v) => (
                <button className={`vc ${picked.includes(v.id) ? "on" : ""}`} key={v.id} onClick={() => toggle(v.id)}>
                  <span className="vc-check">{picked.includes(v.id) && <Ic name="check" size={13} stroke={3} />}</span>
                  <span style={{ minWidth: 0 }}>
                    <div className="vc-t">{v.name}</div>
                    <div className="vc-d">{v.desc}</div>
                    <div className="vc-cwe">{v.cwe}</div>
                  </span>
                </button>
              ))}
            </div>
          </div>

          <div className="card card-pad" style={{ background: "var(--surface-2)", marginBottom: 20, borderStyle: "dashed" }}>
            <div className="row gap10" style={{ alignItems: "flex-start" }}>
              <Ic name="shieldChk" size={18} style={{ color: "var(--ok)", flexShrink: 0, marginTop: 1 }} />
              <div>
                <div style={{ fontWeight: 600, fontSize: 13 }}>Live run against the bundled VulnLab</div>
                <div className="hint" style={{ margin: "3px 0 0" }}>This launch executes a <b>real</b>, scope-guarded engagement in-process against VulnLab. The agent stops at proof-of-concept and never persists access or destroys data.</div>
              </div>
            </div>
          </div>

          <div className="between">
            <button className="btn" onClick={() => setStep(1)}><Ic name="arrowL" size={15} /> Back</button>
            <button className="btn btn-primary btn-lg" onClick={doLaunch} disabled={launching}>
              {launching ? <><Ic name="spinner" size={15} className="spin" /> Launching...</> : <><Ic name="zap" size={15} /> Launch engagement</>}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

Object.assign(window, { Dashboard, NewEngagement, StepPips });
