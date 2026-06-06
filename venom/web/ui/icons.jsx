/* ============================================================
   VENOM - icons + shared UI atoms
   Simple stroke icons (Lucide-ish), hand-written & minimal.
   ============================================================ */

function Icon({ d, paths, size = 17, fill = false, stroke = 2, className = "", style }) {
  return (
    <svg className={className} style={style} width={size} height={size} viewBox="0 0 24 24"
      fill={fill ? "currentColor" : "none"} stroke="currentColor" strokeWidth={stroke}
      strokeLinecap="round" strokeLinejoin="round">
      {paths || <path d={d} />}
    </svg>
  );
}

const ICONS = {
  grid:    <><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
  target:  <><circle cx="12" cy="12" r="8"/><circle cx="12" cy="12" r="3.2"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3"/></>,
  bug:     <><path d="M8 9V6a4 4 0 0 1 8 0v3"/><rect x="6" y="9" width="12" height="10" rx="5"/><path d="M3 13h3M18 13h3M4 18l2.5-1.5M20 18l-2.5-1.5M4 8l2.5 1.5M20 8l-2.5 1.5M12 9v10"/></>,
  doc:     <><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5M9 13h6M9 17h6"/></>,
  logout:  <><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/></>,
  book:    <><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20"/><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z"/></>,
  gear:    <><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></>,
  shield:  <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></>,
  shieldChk: <><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></>,
  radar:   <><path d="M19.07 4.93A10 10 0 1 0 21 12"/><path d="M12 12l6-6"/><circle cx="12" cy="12" r="4"/><circle cx="12" cy="12" r="1" fill="currentColor"/></>,
  graph:   <><circle cx="5" cy="6" r="2.5"/><circle cx="19" cy="6" r="2.5"/><circle cx="12" cy="18" r="2.5"/><path d="M7 7.5l4 8.5M17 7.5l-4 8.5M7 6h10"/></>,
  bulb:    <><path d="M9 18h6M10 22h4"/><path d="M12 2a7 7 0 0 0-4 12.7c.6.5 1 1.3 1 2.1V18h6v-1.2c0-.8.4-1.6 1-2.1A7 7 0 0 0 12 2z"/></>,
  bolt:    <><path d="M13 2 4 14h7l-1 8 9-12h-7l1-8z"/></>,
  check:   <><path d="M20 6 9 17l-5-5"/></>,
  checkCirc: <><circle cx="12" cy="12" r="9"/><path d="M9 12l2 2 4-4"/></>,
  x:       <><path d="M18 6 6 18M6 6l12 12"/></>,
  xCirc:   <><circle cx="12" cy="12" r="9"/><path d="M15 9l-6 6M9 9l6 6"/></>,
  chevR:   <><path d="m9 6 6 6-6 6"/></>,
  chevD:   <><path d="m6 9 6 6 6-6"/></>,
  arrowR:  <><path d="M5 12h14M13 5l7 7-7 7"/></>,
  arrowL:  <><path d="M19 12H5M11 18l-6-6 6-6"/></>,
  play:    <><path d="M6 4l14 8-14 8z" fill="currentColor" stroke="none"/></>,
  pause:   <><rect x="6" y="5" width="4" height="14" rx="1" fill="currentColor" stroke="none"/><rect x="14" y="5" width="4" height="14" rx="1" fill="currentColor" stroke="none"/></>,
  restart: <><path d="M3 12a9 9 0 1 0 3-6.7L3 8"/><path d="M3 3v5h5"/></>,
  plus:    <><path d="M12 5v14M5 12h14"/></>,
  search:  <><circle cx="11" cy="11" r="7"/><path d="m21 21-4.3-4.3"/></>,
  filter:  <><path d="M3 5h18M6 12h12M10 19h4"/></>,
  clock:   <><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></>,
  globe:   <><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18z"/></>,
  user:    <><circle cx="12" cy="8" r="3.5"/><path d="M5 20c0-3.3 3.1-6 7-6s7 2.7 7 6"/></>,
  users:   <><circle cx="9" cy="8" r="3"/><path d="M3 20c0-3 2.7-5.5 6-5.5S15 17 15 20"/><path d="M16 5.5a3 3 0 0 1 0 5.5M21 20c0-2.4-1.6-4.4-4-5"/></>,
  key:     <><circle cx="7.5" cy="15.5" r="3.5"/><path d="M10 13 20 3M17 6l2 2M14 9l2 2"/></>,
  lock:    <><rect x="4" y="11" width="16" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></>,
  code:    <><path d="m16 18 4-6-4-6M8 6l-4 6 4 6M14 4l-4 16"/></>,
  terminal:<><path d="m4 17 6-5-6-5M12 19h8"/></>,
  layers:  <><path d="M12 2 2 7l10 5 10-5-10-5z"/><path d="m2 12 10 5 10-5M2 17l10 5 10-5"/></>,
  alert:   <><path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></>,
  download:<><path d="M12 3v12M7 10l5 5 5-5M5 21h14"/></>,
  spinner: <><path d="M12 3a9 9 0 1 0 9 9" /></>,
  copy:    <><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></>,
  flask:   <><path d="M9 3h6M10 3v6L5 19a1.5 1.5 0 0 0 1.3 2.2h11.4A1.5 1.5 0 0 0 19 19l-5-10V3"/><path d="M7.5 14h9"/></>,
  zap:     <><path d="M13 2 4 14h7l-1 8 9-12h-7l1-8z"/></>,
};

function Ic({ name, ...rest }) {
  return <Icon paths={ICONS[name] || ICONS.x} {...rest} />;
}

// ---- severity badge ----
const SEV_LABEL = { crit: "Critical", high: "High", med: "Medium", low: "Low", info: "Info" };
function Sev({ s }) {
  return <span className={`sev sev-${s}`}><span className="bar"/>{SEV_LABEL[s] || s}</span>;
}

// ---- method tag ----
function Method({ m }) {
  return <span className={`tag tag-method m-${m}`}>{m}</span>;
}

// ---- status pill ----
function Pill({ kind, children }) {
  const map = { live: "pill-live", done: "pill-done", review: "pill-idle", idle: "pill-idle" };
  return <span className={`pill ${map[kind] || ""}`}><span className="dot"/>{children}</span>;
}

// ---- severity mini-bar (counts) ----
function SevBar({ crit = 0, high = 0, med = 0, low = 0, width = 120 }) {
  const total = crit + high + med + low;
  if (!total) return <span className="muted mono" style={{ fontSize: 11 }}>clean</span>;
  const seg = (n, varname) => n ? <i style={{ width: `${(n / total) * 100}%`, background: `var(${varname})` }} /> : null;
  return (
    <div className="row gap10">
      <div className="sevbar" style={{ width }}>
        {seg(crit, "--sev-crit")}{seg(high, "--sev-high")}{seg(med, "--sev-med")}{seg(low, "--sev-low")}
      </div>
      <span className="mono tnum" style={{ fontSize: 11, color: "var(--ink-3)" }}>{total}</span>
    </div>
  );
}

Object.assign(window, { Icon, Ic, ICONS, Sev, SEV_LABEL, Method, Pill, SevBar });
