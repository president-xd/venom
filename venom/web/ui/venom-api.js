/* ============================================================
   VENOM — API client. Bridges the React UI to the real engine.
   Loads live data into window.VENOM (seed stays as fallback so the
   UI is never blank), and streams a live run's trace over SSE.
   ============================================================ */
(function () {
  async function get(url) {
    const r = await fetch(url, { headers: { Accept: "application/json" } });
    if (!r.ok) throw new Error(url + " -> " + r.status);
    return r.json();
  }
  async function post(url, body) {
    const r = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    return r.json();
  }

  // Stream a live engagement's trace. onEvent({t, x, order, ...}); the server
  // emits an `end` event when the run is finished.
  function streamRun(id, onEvent, onEnd) {
    const es = new EventSource("/api/runs/" + id + "/stream");
    es.onmessage = (e) => {
      try { onEvent(JSON.parse(e.data)); } catch (_) {}
    };
    es.addEventListener("end", () => { es.close(); onEnd && onEnd(); });
    return es;
  }

  // Overlay real data onto the seed before first render — progressive enhancement.
  async function boot() {
    const [vc, eng, status, agents] = await Promise.allSettled([
      get("/api/vuln-classes"), get("/api/engagements"), get("/api/status"), get("/api/agents"),
    ]);
    if (vc.status === "fulfilled" && (vc.value.classes || []).length)
      window.VENOM.VULN_CLASSES = vc.value.classes;
    if (eng.status === "fulfilled" && (eng.value.engagements || []).length)
      window.VENOM.ENGAGEMENTS = eng.value.engagements;
    if (agents.status === "fulfilled" && (agents.value.fleet || []).length)
      window.VENOM.FLEET = agents.value.fleet;     // real models per role
    window.VENOM_STATUS = status.status === "fulfilled" ? status.value
      : { scope_guard: "armed", kill_switch: false };
    return true;
  }

  window.API = {
    get, post, streamRun, boot,
    startRun: (opts) => post("/api/runs", opts),
    runStatus: (id) => get("/api/runs/" + id),
    runFindings: (id) => get("/api/runs/" + id + "/findings"),
    validateScope: (body) => post("/api/scope/validate", body),
    providers: () => get("/api/providers"),
    agents: () => get("/api/agents"),
    status: () => get("/api/status"),
    reportUrl: (id) => "/api/runs/" + id + "/report.md",
    sarifUrl: (id) => "/api/runs/" + id + "/findings.sarif",
    findingsJsonUrl: (id) => "/api/runs/" + id + "/findings.json",
  };
})();
