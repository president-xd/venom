/* ============================================================
   VENOM — root app: routing + state (wired to the real backend)
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
  "runSpeed": 2
}/*EDITMODE-END*/;

function App() {
  const [t, setTweak] = useTweaks(TWEAK_DEFAULTS);
  const [route, setRoute] = React.useState("dashboard");
  const [findingId, setFindingId] = React.useState(null);
  const [runFinished, setRunFinished] = React.useState(false);
  const [runId, setRunId] = React.useState(null);             // live engagement id (null = demo)
  const [liveFindings, setLiveFindings] = React.useState(null);
  const [liveMeta, setLiveMeta] = React.useState(null);       // real engagement metadata for the report
  const [status, setStatus] = React.useState(window.VENOM_STATUS || null);
  const [, force] = React.useReducer((x) => x + 1, 0);

  // boot: overlay real data (vuln classes, engagements, status) onto the seed
  React.useEffect(() => {
    if (window.API) window.API.boot().then(() => { setStatus(window.VENOM_STATUS); force(); });
  }, []);

  // keep the engagement list LIVE — poll so a running engagement shows the moment
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

  // pull the real findings once a live run completes
  React.useEffect(() => {
    if (runId && runFinished && window.API) {
      window.API.runFindings(runId).then((d) => { setLiveFindings(d.findings || []); setLiveMeta(d.meta || null); });
    }
  }, [runId, runFinished]);

  const findings = (runId && liveFindings) ? liveFindings : window.VENOM.FINDINGS;
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
  const target = "localhost:8000 · VulnLab";
  const topRight = (runId && (route === "run" || route === "findings" || route === "report")) ? (
    <Pill kind={runFinished || route !== "run" ? "done" : "live"}>{runFinished || route !== "run" ? "engagement complete" : "live"}</Pill>
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
        : <FindingsList findings={findings} openFinding={openFinding} runId={runId} />; break;
    case "finding":
      body = finding
        ? <FindingDetail finding={finding} findings={findings} back={() => go("findings")} openFinding={openFinding} />
        : <Placeholder icon="bug" title="Finding not found" note="Pick a finding from the list." />; break;
    case "report":
      body = noRun
        ? <Placeholder icon="doc" title="No report yet" note="Launch an engagement to generate a Markdown / JSON / SARIF report." />
        : <Report findings={findings} runId={runId} meta={liveMeta} openFinding={openFinding} />; break;
    case "knowledge":
      body = <KnowledgeBase />; break;
    case "settings":
      body = <Settings />; break;
    default:
      body = <Dashboard go={go} openEngagement={() => go("run")} />;
  }

  return (
    <div className="app">
      <Sidebar route={route} go={go} findingCount={findingCount} status={status} />
      <div className="main">
        <TopBar crumbs={crumbsFor()} target={showTarget ? target : null} right={topRight} />
        <div className="content">{body}</div>
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
        <TweakRadio label="Density" value={t.density} options={["comfortable", "compact"]}
          onChange={(v) => setTweak("density", v)} />
        <TweakRadio label="Default agent speed" value={String(t.runSpeed)} options={["1", "2", "4"]}
          onChange={(v) => setTweak("runSpeed", +v)} />
      </TweaksPanel>
    </div>
  );
}

ReactDOM.createRoot(document.getElementById("root")).render(<App />);
