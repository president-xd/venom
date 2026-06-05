/* ============================================================
   VENOM — Live agent run: pipeline tracker + streaming console
   Live mode (runId) streams a REAL engagement over SSE; without a
   runId it replays the scripted demo timeline.
   ============================================================ */

function buildTimeline() {
  const { STAGES, LOG } = window.VENOM;
  const events = [];
  STAGES.forEach((st, order) => {
    (LOG[st.id] || []).forEach((line) => events.push({ ...line, stageId: st.id, order }));
  });
  return events;
}

function LiveRun({ runId, onComplete, goFindings, finished, defaultSpeed = 2 }) {
  const { STAGES } = window.VENOM;
  const live = !!runId;

  // ---- demo timeline ----
  const events = React.useMemo(() => (live ? [] : buildTimeline()), [live]);

  // ---- live state ----
  const [liveEvents, setLiveEvents] = React.useState([]);
  const [liveStatus, setLiveStatus] = React.useState("running");   // running | done | error
  const [liveFindings, setLiveFindings] = React.useState([]);
  const [liveCount, setLiveCount] = React.useState(0);
  const [runKey, setRunKey] = React.useState(0);

  // ---- demo state ----
  const [i, setI] = React.useState(finished && !live ? events.length : 0);
  const [playing, setPlaying] = React.useState(!finished && !live);
  const [speed, setSpeed] = React.useState(defaultSpeed);
  const [elapsed, setElapsed] = React.useState(0);
  const bodyRef = React.useRef(null);
  const timer = React.useRef(null);

  // ===== LIVE: stream if the run is still running, else show real logs statically =====
  const [isStatic, setIsStatic] = React.useState(false);
  React.useEffect(() => {
    if (!live) return;
    setLiveEvents([]); setLiveStatus("running"); setElapsed(0); setLiveFindings([]); setLiveCount(0); setIsStatic(false);
    let es = null, tick = null, cancelled = false, finishedLocal = false;
    window.API.runStatus(runId).then((s) => {
      if (cancelled) return;
      if (s && s.status === "running") {
        const started = Date.now();
        es = window.API.streamRun(runId, (ev) => {
          if (ev.t === "done" || ev.t === "error") {
            finishedLocal = true;
            setLiveCount(ev.findings_count || 0);
            setLiveStatus(ev.error ? "error" : "done");
          } else {
            setLiveEvents((prev) => [...prev, ev]);
          }
        });
        tick = setInterval(() => { if (!finishedLocal) setElapsed(+(((Date.now() - started) / 1000)).toFixed(1)); }, 100);
      } else {
        // finished engagement -> render the actual captured logs at once (no animation)
        setIsStatic(true);
        const evs = (s && s.events || []).filter((e) => e.t !== "done" && e.t !== "error");
        setLiveEvents(evs);
        // real total wall-clock = the last captured event's timestamp
        const last = evs.reduce((m, e) => (e.ts != null && e.ts > m ? e.ts : m), 0);
        setElapsed(+Number(last).toFixed(1));
        setLiveCount((s && s.findings_count) || 0);
        setLiveStatus((s && s.status) || "done");
      }
    }).catch(() => { if (!cancelled) setLiveStatus("error"); });
    return () => { cancelled = true; if (es) es.close(); if (tick) clearInterval(tick); };
  }, [live, runId, runKey]);

  // ===== LIVE: on finish, notify parent + fetch real findings =====
  React.useEffect(() => {
    if (live && liveStatus !== "running") {
      onComplete && onComplete();
      window.API.runFindings(runId).then((d) => {
        setLiveFindings(d.findings || []);
        setLiveCount((d.findings || []).length);
      }).catch(() => {});
    }
  }, [live, liveStatus]);

  // ===== DEMO: advance loop =====
  React.useEffect(() => {
    if (live || !playing || i >= events.length) return;
    const line = events[i];
    let base = line.t === "stage" ? 720 : line.t === "think" ? 460 : 360;
    if (line.t === "hit") base = 640;
    const delay = base / speed;
    timer.current = setTimeout(() => {
      setI((n) => n + 1);
      setElapsed((e) => +(e + delay / 1000 * 3.2).toFixed(1));
    }, delay);
    return () => clearTimeout(timer.current);
  }, [i, playing, speed, live]);

  React.useEffect(() => {
    if (!live && i >= events.length && playing) { setPlaying(false); onComplete && onComplete(); }
  }, [i]);

  // autoscroll console
  const played = live ? liveEvents : events.slice(0, i);
  React.useEffect(() => {
    if (bodyRef.current) bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
  }, [played.length]);

  const done = live ? (liveStatus !== "running") : (i >= events.length);
  const total = live ? Math.max(liveEvents.length, 1) : events.length;
  const currentOrder = played.length ? Math.max(...played.map((p) => p.order || 0)) : -1;
  const stageState = (order) => {
    if (done) return "done";
    if (order < currentOrder) return "done";
    if (order === currentOrder) return "active";
    return "idle";
  };

  const hits = played.filter((p) => p.t === "hit");
  const demoConfirmed = window.VENOM.FINDINGS.filter((f) => f.confirmed);
  const shownFindings = live ? liveFindings : demoConfirmed.slice(0, hits.length);
  const findingsTotal = live ? liveCount : demoConfirmed.length;
  const progress = live
    ? (done ? 100 : Math.min(96, Math.round((Math.max(0, currentOrder) / 6) * 100)))
    : Math.round((i / events.length) * 100);

  const restart = () => {
    if (live) { setRunKey((k) => k + 1); return; }
    setI(0); setElapsed(0); setPlaying(true);
  };

  return (
    <div className="page page-wide fade-in">
      <div className="between" style={{ marginBottom: 16 }}>
        <div style={{ minWidth: 0 }}>
          <div className="row gap10">
            <h1 className="h1" style={{ whiteSpace: "nowrap" }}>Live run</h1>
            {done ? <Pill kind="done">{liveStatus === "error" ? "error" : "complete"}</Pill> : <Pill kind="live">running</Pill>}
          </div>
          <p className="sub mono" style={{ fontSize: 12.5, marginTop: 4 }}>
            {runId || "demo"} · VulnLab · {STAGES.length}-stage pipeline · --crawl --think --live
          </p>
        </div>
        {done && liveStatus !== "error" && (
          <button className="btn btn-primary btn-lg" onClick={goFindings}>
            View {findingsTotal} findings <Ic name="arrowR" size={15} />
          </button>
        )}
      </div>

      {/* control bar */}
      <div className="runbar">
        {live ? (
          <span className="btn btn-sm" style={{ minWidth: 100, cursor: "default", opacity: done ? 1 : 0.85 }}>
            {done ? (liveStatus === "error" ? <><Ic name="alert" size={14} style={{ color: "var(--sev-crit)" }} /> Error</> : <><Ic name="check" size={14} style={{ color: "var(--ok)" }} /> {isStatic ? "Logs" : "Complete"}</>) : <><Ic name="spinner" size={14} className="spin" /> Streaming</>}
          </span>
        ) : (
          <button className="btn btn-sm" onClick={() => done ? restart() : setPlaying(!playing)} style={{ minWidth: 92 }}>
            {done ? <><Ic name="restart" size={14} /> Replay</> : playing ? <><Ic name="pause" size={14} /> Pause</> : <><Ic name="play" size={14} /> Resume</>}
          </button>
        )}
        {!live && !done && <button className="btn btn-sm btn-ghost" onClick={restart} title="Restart"><Ic name="restart" size={14} /></button>}
        <div className="progress"><i style={{ width: `${progress}%` }} /></div>
        <span className="mono tnum" style={{ fontSize: 12, color: "var(--ink-3)", minWidth: 38 }}>{progress}%</span>
        {!live && (
          <div className="speed-seg">
            {[1, 2, 4].map((s) => (
              <button key={s} className={speed === s ? "on" : ""} onClick={() => setSpeed(s)}>{s}×</button>
            ))}
          </div>
        )}
        {(!isStatic) && (
          <span className="mono tnum row gap6" style={{ fontSize: 12, color: "var(--ink-3)", minWidth: 78, justifyContent: "flex-end" }}>
            <Ic name="clock" size={13} /> {elapsed.toFixed(1)}s
          </span>
        )}
        {isStatic && (
          <span className="mono tnum row gap6" style={{ fontSize: 12, color: "var(--ink-3)", minWidth: 78, justifyContent: "flex-end" }}>
            {played.length} log lines
          </span>
        )}
      </div>

      <div className="run-grid">
        {/* ---- pipeline ---- */}
        <div>
          <div className="card card-pad" style={{ marginBottom: 14 }}>
            <div className="eyebrow" style={{ marginBottom: 14 }}>Pipeline</div>
            <div className="pipeline">
              {STAGES.map((st, order) => {
                const state = stageState(order);
                return (
                  <div className={`pstage ${state}`} key={st.id}>
                    <div className="rail">
                      <div className="node">
                        {state === "done" ? <Ic name="check" size={14} stroke={3} />
                          : state === "active" ? <Ic name="spinner" size={14} className="spin" stroke={2.4} />
                          : <Ic name={st.icon} size={13} />}
                      </div>
                      <div className="line" />
                    </div>
                    <div className="body">
                      <div className="ps-t">{st.title}</div>
                      <div className="ps-d">{st.desc}</div>
                      {state === "active" && <div className="ps-meta">working…</div>}
                      {!live && state === "done" && order === 4 && <div className="ps-meta" style={{ color: "var(--sev-high)" }}>3 hypotheses confirmed</div>}
                      {live && done && order === 5 && <div className="ps-meta" style={{ color: "var(--sev-high)" }}>{findingsTotal} findings confirmed</div>}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="card card-pad">
            <div className="eyebrow" style={{ marginBottom: 12 }}>Agent fleet</div>
            <div style={{ display: "flex", flexDirection: "column", gap: 9 }}>
              {(window.VENOM.FLEET && window.VENOM.FLEET.length ? window.VENOM.FLEET : []).map((a, k) => {
                // The real fleet from /api/agents. Stage→role lighting: which roles are
                // active once the pipeline reaches infer/hypothesize/exploit.
                const roleOrder = { research: 1, orchestrator: 2, hypothesis: 3, codegen: 4, summarizer: 5, reporter: 6 };
                const on = currentOrder >= (roleOrder[a.role] || 1);
                return (
                  <div className="row gap10" key={k} style={{ justifyContent: "space-between" }}>
                    <div className="row gap10">
                      <span className="guard-dot" style={{ background: on ? "var(--accent)" : "var(--border-strong)", boxShadow: on ? "0 0 0 3px var(--accent-soft)" : "none" }} />
                      <span style={{ fontSize: 12.5, fontWeight: 600, textTransform: "capitalize" }}>{a.role}</span>
                    </div>
                    <span className="mono" style={{ fontSize: 11, color: "var(--ink-3)" }} title={a.provider}>{a.model}</span>
                  </div>
                );
              })}
              {!(window.VENOM.FLEET && window.VENOM.FLEET.length) && (
                <span className="muted" style={{ fontSize: 11.5 }}>No fleet configured (set a provider in .env).</span>
              )}
            </div>
          </div>
        </div>

        {/* ---- console ---- */}
        <div>
          <div className="console">
            <div className="console-head">
              <div className="dots"><i/><i/><i/></div>
              <span className="ttl">venom · agent trace</span>
              <div className="spacer" style={{ flex: 1 }} />
              <span className="mono" style={{ fontSize: 11, color: "var(--ink-4)" }}>{played.length} events</span>
            </div>
            <div className="console-body" ref={bodyRef}>
              {played.map((line, k) => (
                <div className={`logline l-${line.t}`} key={k}>
                  <span className="ts">{line.ts != null ? fmtClock(line.ts) : fmtTs(k, line.order)}</span>
                  <span className="tx">{line.x}</span>
                </div>
              ))}
              {!done && (
                <div className="logline"><span className="ts" /><span className="tx"><span className="cursor-blink" /></span></div>
              )}
              {done && liveStatus !== "error" && (
                <div className="logline l-ok"><span className="ts">{fmtTs(total, 6)}</span><span className="tx">trace closed · audit trail HMAC-signed</span></div>
              )}
            </div>
          </div>

          {/* confirmed findings strip */}
          {shownFindings.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <div className="eyebrow" style={{ marginBottom: 8 }}>Confirmed this run · {shownFindings.length}</div>
              <div className="run-finds">
                {shownFindings.map((f) => (
                  <div className="run-find" key={f.id}>
                    <Sev s={f.severity} />
                    <div style={{ minWidth: 0, flex: 1 }}>
                      <div className="rf-t">{f.title}</div>
                      <div className="rf-e"><Method m={f.method} /> {f.path} · {f.cwe}</div>
                    </div>
                    <Ic name="checkCirc" size={18} style={{ color: "var(--ok)", flexShrink: 0 }} />
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function fmtClock(sec) {
  // REAL wall-clock offset (seconds since run start) -> mm:ss.s
  const v = Math.max(0, Number(sec) || 0);
  const m = Math.floor(v / 60);
  const s = v % 60;
  return `${String(m).padStart(2, "0")}:${s.toFixed(1).padStart(4, "0")}`;
}

function fmtTs(k, order) {
  // Fallback only for static/seed events that carry no real timestamp.
  const base = 0.4 + k * 0.83 + (order || 0) * 1.1;
  return fmtClock(base);
}

Object.assign(window, { LiveRun, fmtClock });
