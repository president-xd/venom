/* ============================================================
   VENOM — UI reference data (window.VENOM)
   Engagements / findings / live-trace come from the real backend
   (/api/*). No demo rows: the UI shows only real runs you launch.
   VULN_CLASSES is overlaid from /api/vuln-classes on boot (the list
   below is a fallback). STAGES + EXAMPLE_PROMPTS are static reference
   data (the pipeline shape and prompt hints).
   ============================================================ */
window.VENOM = (function () {

  // ---- vuln classes (fallback; /api/vuln-classes overlays the real KB) ----
  const VULN_CLASSES = [
    { id: "bola",      name: "Broken Object-Level Auth (BOLA / IDOR)", cwe: "CWE-639 · OWASP API1",
      desc: "Access another tenant's objects by guessing/altering IDs." },
    { id: "massassign", name: "Mass-assignment privilege escalation", cwe: "CWE-915 · OWASP API3",
      desc: "Inject privileged fields (role, is_admin) the server binds blindly." },
    { id: "race",      name: "Race condition / TOCTOU", cwe: "CWE-362",
      desc: "Concurrent bursts that bypass single-use or balance checks." },
    { id: "price",     name: "Client-side price & parameter tampering", cwe: "CWE-602",
      desc: "Server trusts a price/quantity supplied by the client." },
    { id: "workflow",  name: "Workflow / sequence bypass", cwe: "CWE-840",
      desc: "Reach a terminal step (refund, ship) without its precondition." },
    { id: "bac",       name: "Broken access control (forced browse)", cwe: "CWE-284 · OWASP API5",
      desc: "Hidden privileged endpoints reachable without authorization." },
    { id: "trustid",   name: "Trusted-identity account takeover", cwe: "CWE-290",
      desc: "A client-supplied identity parameter is trusted for auth." },
    { id: "overflow",  name: "Integer overflow on economic totals", cwe: "CWE-190",
      desc: "Quantity/total wraps to bypass spend or inventory limits." },
    { id: "coupon",    name: "Coupon / gift-card arbitrage", cwe: "CWE-840",
      desc: "Discount or credit reused beyond its single-use intent." },
    { id: "negqty",    name: "Negative-quantity balancing", cwe: "CWE-840",
      desc: "Negative line items credit the cart below the real total." },
  ];

  // ---- pipeline stages (the live-run tracker shape) ----
  const STAGES = [
    { id: "scope",     title: "Load scope",        desc: "authz + identities", icon: "shield" },
    { id: "discover",  title: "Ingest / Discover", desc: "crawl + OpenAPI/HAR", icon: "radar" },
    { id: "model",     title: "Infer model",       desc: "entity/transition graph", icon: "graph" },
    { id: "hypothesize", title: "Hypothesize",     desc: "5-lens attack chains", icon: "bulb" },
    { id: "exploit",   title: "Exploit",           desc: "sandboxed test code", icon: "bolt" },
    { id: "confirm",   title: "Confirm",           desc: "success oracle (differential / content)", icon: "check" },
    { id: "report",    title: "Report",            desc: "md + json + SARIF", icon: "doc" },
  ];

  // ---- example hypotheses for the New-engagement prompt box ----
  const EXAMPLE_PROMPTS = [
    "Free users shouldn't see other accounts' wallets; check object-level auth on /wallet.",
    "Can a regular user promote themselves to admin by editing their profile?",
    "Test whether refunds can be replayed concurrently to over-credit a wallet.",
    "Find any checkout flow where the client controls the price or quantity.",
  ];

  // Real data — populated from the backend (/api/engagements, /api/runs/*, /api/agents).
  const FINDINGS = [];
  const ENGAGEMENTS = [];
  const FLEET = [];            // the real multi-agent fleet, loaded from /api/agents
  const LOG = {};

  return { VULN_CLASSES, STAGES, LOG, FINDINGS, ENGAGEMENTS, FLEET, EXAMPLE_PROMPTS };
})();
