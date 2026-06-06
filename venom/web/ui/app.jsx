/* ============================================================
   VENOM - root app: routing + state (wired to the real backend)
   ============================================================ */

const ACCENTS = [
  { id: "amber", swatch: "#cf7d1c", accent: "oklch(0.685 0.158 56)", strong: "oklch(0.60 0.165 50)", ink: "oklch(0.44 0.13 50)", soft: "oklch(0.955 0.038 70)", line: "oklch(0.86 0.07 65)" },
  { id: "blue",  swatch: "#3667cf", accent: "oklch(0.62 0.135 250)", strong: "oklch(0.54 0.145 255)", ink: "oklch(0.45 0.12 255)", soft: "oklch(0.955 0.03 250)", line: "oklch(0.85 0.06 250)" },
  { id: "teal",  swatch: "#0f8d80", accent: "oklch(0.655 0.11 182)", strong: "oklch(0.575 0.12 184)", ink: "oklch(0.45 0.09 186)", soft: "oklch(0.955 0.03 182)", line: "oklch(0.85 0.05 184)" },
  { id: "rose",  swatch: "#cf3f66", accent: "oklch(0.625 0.18 12)", strong: "oklch(0.545 0.19 12)", ink: "oklch(0.46 0.16 14)", soft: "oklch(0.955 0.03 15)", line: "oklch(0.85 0.07 15)" },
];

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "accent": "amber",
  "density": "comfortable",
  "runSpeed": 2,
  "theme": "auto"
}/*EDITMODE-END*/;

// Graceful degradation: a render error in ONE screen shows a message instead of a
// blank app. Keyed by route in <App/> so navigating away clears a one-off error.
class ErrorBoundary extends React.Component {
  constructor(props) { super(props); this.state = { err: null }; }
  static getDerivedStateFromError(err) { return { err }; }
  componentDidCatch(err, info) { try { console.error("UI render error:", err, info); } catch (_) {} }
  render() {
    if (this.state.err) {
      return <Placeholder icon="alert" title="This view hit a render error"
        note={String((this.state.err && this.state.err.message) || this.state.err)} />;
    }
    return this.props.children;
  }
}

// Login gate — shown until /api/me confirms a session. Each operator then sees
// only their own engagements.
function LoginScreen({ onLogin }) {
  const [u, setU] = React.useState("");
  const [p, setP] = React.useState("");
  const [err, setErr] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setErr("");
    const msg = await onLogin(u, p);
    setBusy(false);
    if (msg) setErr(msg);
  };
  return (
    <div className="login-wrap">
      <form className="login-card card" onSubmit={submit}>
        <div className="login-brand">
          <div className="sb-mark"><Ic name="bug" size={17} /></div>
          <div>
            <div className="login-word">VENOM</div>
            <div className="login-tag">business-logic pentest console</div>
          </div>
        </div>
        <h1 className="h2" style={{ margin: "18px 0 4px" }}>Sign in</h1>
        <p className="muted" style={{ fontSize: 12.5, marginTop: 0, marginBottom: 16 }}>
          Authorized operators only. Each operator's engagements are private to their account.
        </p>
        <label className="login-lab">Username</label>
        <input className="login-input" value={u} autoFocus autoComplete="username"
          onChange={(e) => setU(e.target.value)} placeholder="operator" />
        <label className="login-lab">Password</label>
        <input className="login-input" type="password" value={p} autoComplete="current-password"
          onChange={(e) => setP(e.target.value)} placeholder="password" />
        {err && <div className="login-err">{err}</div>}
        <button className="btn btn-primary login-btn" type="submit" disabled={busy || !u || !p}>
          {busy ? "Signing in..." : "Sign in"}
        </button>
      </form>
    </div>
  );
}

function App() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [me, setMe] = React.useState(undefined);   // undefined=checking, null=anon, {..}=user
  const [route, setRoute] = React.useState("dashboard");
  const [findingId, setFindingId] = React.useState(null);
  const [runFinished, setRunFinished] = React.useState(false);
  const [runId, setRunId] = React.useState(null);             // live engagement id (null = demo)
  const [liveFindings, setLiveFindings] = React.useState(null);
  const [liveMeta, setLiveMeta] = React.useState(null);       // real engagement metadata for the report
  const [status, setStatus] = React.useState(window.VENOM_STATUS || null);
  const [, force] = React.useReducer((x) => x + 1, 0);

  // boot: confirm the session first; only then overlay real data onto the seed.
  React.useEffect(() => {
    if (!window.API) { setMe(null); return; }
    window.API.me().then((d) => {
      if (d && d.authenticated) {
        setMe(d.user);
        window.API.boot().then(() => { setStatus(window.VENOM_STATUS); force(); });
      } else {
        setMe(null);
      }
    }).catch(() => setMe(null));
  }, []);

  const handleLogin = async (username, password) => {
    const r = await window.API.login(username, password);
    if (r && r.ok && r.user) {
      setMe(r.user);
      try { await window.API.boot(); setStatus(window.VENOM_STATUS); force(); } catch (e) {}
      return null;                       // success
    }
    return (r && r.error) || "Login failed";
  };
  const handleLogout = async () => {
    try { await window.API.logout(); } catch (e) {}
    setMe(null); setRunId(null); setRoute("dashboard");
  };

  // keep the engagement list LIVE - poll so a running engagement shows the moment
  // it is launched and a finished one updates without a manual page reload.
  React.useEffect(() => {
    const tick = () => {
      if (!window.API) return;
      window.API.get("/api/engagements").then((d) => {
        if (d && Array.isArray(d.engagements)) {
          const prev = JSON.stringify(window.VENOM.ENGAGEMENTS || []);
          if (JSON.stringify(d.engagements) !== prev) { window.VENOM.ENGAGEMENTS = d.engagements; force(); }
        }
      }).catch(() => {});
    };
    const id = setInterval(tick, 4000);
    window.addEventListener("focus", tick);
    return () => { clearInterval(id); window.removeEventListener("focus", tick); };
  }, []);

  // apply tweaks
  React.useEffect(() => {
    const a = ACCENTS.find((x) => x.id === t.accent) || ACCENTS[0];
    const r = document.documentElement.style;
    r.setProperty("--accent", a.accent);
    r.setProperty("--accent-strong", a.strong);
    r.setProperty("--accent-ink", a.ink);
    r.setProperty("--accent-soft", a.soft);
    r.setProperty("--accent-line", a.line);
  }, [t.accent]);
  React.useEffect(() => {
    document.documentElement.setAttribute("data-density", t.density);
  }, [t.density]);
  // Theme: "auto" follows the OS (CSS @media), "light"/"dark" force it.
  React.useEffect(() => {
    const root = document.documentElement;
    if (t.theme === "light" || t.theme === "dark") root.setAttribute("data-theme", t.theme);
    else root.removeAttribute("data-theme");
  }, [t.theme]);

  // Pull the real findings for a finished run. Guarded on `liveFindings === null`
  // and with it in the deps, so the fetch is idempotent AND self-healing: any render
  // where a finished run still has no findings re-triggers it (covers a missed initial
  // fire), and once an array is set the guard stops it - never a perpetual "Loading".
  React.useEffect(() => {
    if (runId && runFinished && liveFindings === null && window.API) {
      let cancelled = false;
      window.API.runFindings(runId)
        .then((d) => { if (!cancelled) { setLiveFindings((d && d.findings) || []); setLiveMeta((d && d.meta) || null); } })
        .catch(() => { if (!cancelled) setLiveFindings([]); });   // never strand the UI
      return () => { cancelled = true; };
    }
  }, [runId, runFinished, liveFindings]);

  // For a real run we use ONLY that run's findings (never leak the demo seed), and
  // `findings` is ALWAYS an array so list/detail/report can't crash into a blank app.
  // `findingsReady` is false while a finished run's findings are still being fetched.
  const findingsReady = !runId || Array.isArray(liveFindings);
  const findings = runId ? (Array.isArray(liveFindings) ? liveFindings : []) : (window.VENOM.FINDINGS || []);
  const findingCount = findings.length;
  const engLabel = runId ? "VulnLab" : "Engagement";
  const go = (r) => { setRoute(r); document.querySelector(".content")?.scrollTo(0, 0); };
  const openFinding = (id) => { setFindingId(id); setRoute("finding"); document.querySelector(".content")?.scrollTo(0, 0); };
  const finding = findings.find((f) => f.id === findingId);
  const noRun = !runId;

  // Select an engagement from the dashboard to view its run (live if running,
  // otherwise its real captured logs shown statically).
  const viewEngagement = (e) => {
    setRunId(e.id);
    setRunFinished(e.status !== "live");
    setLiveFindings(null);
    go("run");
  };

  const launch = async (opts) => {
    setRunFinished(false);
    setLiveFindings(null);
    let id = null;
    try {
      const r = await window.API.startRun(opts);
      id = r && r.id ? r.id : null;
      if (r && r.error) console.warn("launch:", r.error);
    } catch (e) { console.warn("launch failed", e); }
    setRunId(id);
    go("run");
  };

  // ---- top bar config per route ----
  const crumbsFor = () => {
    switch (route) {
      case "dashboard": return [{ label: "Engagements" }];
      case "describe": return [{ label: "Engagements", onClick: () => go("dashboard") }, { label: "New engagement" }];
      case "run": return [{ label: "Engagements", onClick: () => go("dashboard") }, { label: engLabel }, { label: "Live run" }];
      case "findings": return [{ label: "Engagements", onClick: () => go("dashboard") }, { label: engLabel }, { label: "Findings" }];
      case "finding": return [{ label: "Engagements", onClick: () => go("dashboard") }, { label: "Findings", onClick: () => go("findings") }, { label: finding ? finding.id : "Finding" }];
      case "report": return [{ label: "Engagements", onClick: () => go("dashboard") }, { label: engLabel }, { label: "Report" }];
      case "knowledge": return [{ label: "Knowledge base" }];
      case "settings": return [{ label: "Settings" }];
      default: return [{ label: "VENOM" }];
    }
  };
  const showTarget = !!runId && ["run", "findings", "finding", "report"].includes(route);
  // Reflect the REAL target of the selected run (never hardcode the demo host - an
  // external engagement must show the host the operator actually entered).
  const curEng = (window.VENOM.ENGAGEMENTS || []).find((e) => e.id === runId);
  const target = curEng ? `${curEng.url || "target"} · ${curEng.name || "engagement"}` : "engagement";
  // The status pill reflects the ACTUAL run state (runFinished), not the route - a
  // live run viewed from Findings/Report must still read "live", not "complete".
  const topRight = (runId && ["run", "findings", "report"].includes(route)) ? (
    <Pill kind={runFinished ? "done" : "live"}>{runFinished ? "engagement complete" : "live"}</Pill>
  ) : null;

  let body;
  switch (route) {
    case "dashboard":
      body = <Dashboard go={go} openEngagement={viewEngagement} />; break;
    case "describe":
      body = <NewEngagement onLaunch={launch} />; break;
    case "run":
      body = noRun
        ? <Placeholder icon="radar" title="No active engagement" note="Launch one from New engagement; it runs live against the bundled VulnLab and streams the agent trace here." />
        : <LiveRun runId={runId} finished={runFinished} defaultSpeed={t.runSpeed} onComplete={() => setRunFinished(true)} goFindings={() => go("findings")} />; break;
    case "findings":
      body = noRun
        ? <Placeholder icon="bug" title="No findings yet" note="Launch an engagement to produce confirmed, evidence-backed findings." />
        : !findingsReady
          ? <Placeholder icon={runFinished ? "bug" : "radar"} title={runFinished ? "Loading findings..." : "Engagement in progress"}
              note={runFinished ? "Fetching the confirmed findings for this run." : "Findings appear here as the agent confirms them - watch the Live run for the streaming trace."} />
          : <FindingsList findings={findings} openFinding={openFinding} runId={runId} />; break;
    case "finding":
      body = noRun || !findingsReady
        ? <Placeholder icon="radar" title="Loading..." note="Findings are still being prepared for this run." />
        : finding
          ? <FindingDetail finding={finding} findings={findings} back={() => go("findings")} openFinding={openFinding} />
          : <Placeholder icon="bug" title="Finding not found" note="Pick a finding from the list." />; break;
    case "report":
      body = noRun
        ? <Placeholder icon="doc" title="No report yet" note="Launch an engagement to generate a Markdown / JSON / SARIF report." />
        : !findingsReady
          ? <Placeholder icon={runFinished ? "doc" : "radar"} title={runFinished ? "Preparing report..." : "Engagement in progress"}
              note={runFinished ? "Compiling the report from this run's confirmed findings." : "The report is generated once the engagement completes."} />
          : <Report findings={findings} runId={runId} meta={liveMeta} openFinding={openFinding} />; break;
    case "knowledge":
      body = <KnowledgeBase />; break;
    case "settings":
      body = <Settings t={t} setTweak={setTweak} accents={ACCENTS} />; break;
    default:
      body = <Dashboard go={go} openEngagement={() => go("run")} />;
  }

  // ---- auth gate (all hooks above run unconditionally) ----
  if (me === undefined) return <div className="login-wrap"><div className="muted">Loading...</div></div>;
  if (me === null) return <LoginScreen onLogin={handleLogin} />;

  return (
    <div className="app">
      <Sidebar route={route} go={go} findingCount={findingCount} status={status}
        user={me} onLogout={handleLogout} />
      <div className="main">
        <TopBar crumbs={crumbsFor()} target={showTarget ? target : null} right={topRight} />
        <div className="content"><ErrorBoundary key={route}>{body}</ErrorBoundary></div>
      </div>

      <TweaksPanel title="Tweaks">
        <TweakSection label="Brand accent" />
        <TweakRow label="Color">
          <div className="row gap6">
            {ACCENTS.map((a) => (
              <button key={a.id} title={a.id} onClick={() => setTweak("accent", a.id)}
                style={{ width: 24, height: 24, borderRadius: "50%", background: a.swatch, cursor: "pointer",
                  border: t.accent === a.id ? "2px solid var(--ink)" : "2px solid transparent",
                  boxShadow: "0 0 0 1px var(--border-strong)" }} />
            ))}
          </div>
        </TweakRow>
        <TweakSection label="Display" />
        <TweakRadio label="Theme" value={t.theme} options={["auto", "light", "dark"]}
          onChange={(v) => setTweak("theme", v)} />
        <TweakRadio label="Density" value={t.density} options={["comfortable", "compact"]}
          onChange={(v) => setTweak("density", v)} />
        <TweakRadio label="Default agent speed" value={String(t.runSpeed)} options={["1", "2", "4"]}
          onChange={(v) => setTweak("runSpeed", +v)} />
      </TweaksPanel>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
