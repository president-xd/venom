/* ============================================================
   VENOM - app shell: Sidebar + TopBar
   ============================================================ */

function Sidebar({ route, go, findingCount, status, user, onLogout }) {
  const killed = status && status.kill_switch;
  const name = (user && user.name) || "Operator";
  const role = (user && user.role) || "operator";
  const initials = name.split(/\s+/).map((w) => w[0]).join("").slice(0, 2).toUpperCase() || "OP";
  const Item = ({ id, icon, label, count, target }) => (
    <button className={`sb-item ${route === id || (target && target.includes(route)) ? "active" : ""}`}
      onClick={() => go(id)}>
      <Ic name={icon} className="sb-ic" size={17} />
      <span>{label}</span>
      {count != null && <span className="badge-count tnum">{count}</span>}
    </button>
  );
  return (
    <aside className="sidebar">
      <div className="sb-brand">
        <div className="sb-mark"><Ic name="bug" size={18} stroke={2.1} /></div>
        <div className="sb-word">VENOM<small>business-logic agent</small></div>
      </div>
      <nav className="sb-nav">
        <Item id="dashboard" icon="grid" label="Dashboard" />
        <Item id="describe" icon="target" label="New engagement" />
        <div className="sb-section">Current engagement</div>
        <Item id="run" icon="radar" label="Live run" target={["run"]} />
        <Item id="findings" icon="bug" label="Findings" count={findingCount} target={["findings", "finding"]} />
        <Item id="report" icon="doc" label="Report" />
        <div className="sb-section">Library</div>
        <Item id="knowledge" icon="book" label="Knowledge base" />
        <Item id="settings" icon="gear" label="Settings" />
      </nav>
      <div className="sb-foot">
        <div className="guard">
          <span className="guard-dot" style={killed ? { background: "var(--sev-crit)", boxShadow: "0 0 0 3px var(--crit-soft)" } : null} />
          <span>Scope guard <b>{killed ? "halted" : "armed"}</b></span>
        </div>
        <div className="guard" style={{ marginTop: 7 }}>
          <Ic name="lock" size={13} style={{ color: killed ? "var(--sev-crit)" : "oklch(0.6 0.01 80)" }} />
          <span>{killed ? "kill-switch ENGAGED" : "kill-switch ready"}</span>
        </div>
        <div className="sb-user">
          <div className="sb-ava">{initials}</div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div className="nm">{name}</div>
            <div className="rl">{role} · authorized</div>
          </div>
          {onLogout && (
            <button className="sb-logout" title="Sign out" onClick={onLogout}>
              <Ic name="logout" size={15} />
            </button>
          )}
        </div>
      </div>
    </aside>
  );
}

function TopBar({ crumbs, target, right }) {
  return (
    <header className="topbar">
      <div className="crumbs">
        {crumbs.map((c, i) => (
          <React.Fragment key={i}>
            {i > 0 && <Ic name="chevR" size={13} className="sep" />}
            {c.onClick
              ? <button className="c-link" onClick={c.onClick}>{c.label}</button>
              : <span className={i === crumbs.length - 1 ? "c-cur" : ""}>{c.label}</span>}
          </React.Fragment>
        ))}
      </div>
      <div className="spacer" />
      {target && (
        <div className="tb-target">
          <Ic name="globe" size={13} />
          {target}
        </div>
      )}
      {right}
    </header>
  );
}

// Generic placeholder screen for nav items outside the core flow
function Placeholder({ icon, title, note }) {
  return (
    <div className="page">
      <div className="empty">
        <div style={{ width: 52, height: 52, borderRadius: 12, background: "var(--surface-3)", display: "grid", placeItems: "center", margin: "0 auto 16px", color: "var(--ink-3)" }}>
          <Ic name={icon} size={26} />
        </div>
        <div className="h2" style={{ color: "var(--ink-2)" }}>{title}</div>
        <p className="sub" style={{ maxWidth: 380, margin: "8px auto 0" }}>{note}</p>
      </div>
    </div>
  );
}

Object.assign(window, { Sidebar, TopBar, Placeholder });
