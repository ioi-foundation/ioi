// Sidebar + Topbar
const Sidebar = ({ active, setActive }) => {
  const groups = [
    { label: 'Procurement', items: [
      { id: 'catalog', label: 'Service Catalog', icon: 'package', count: 6 },
      { id: 'requests', label: 'New Requests', icon: 'box', count: 2 },
      { id: 'governance', label: 'Governance', icon: 'shield', count: '' },
    ]},
    { label: 'Operations', items: [
      { id: 'instances', label: 'Active Instances', icon: 'activity', count: 3 },
      { id: 'audit', label: 'Audit Trails', icon: 'history', count: '' },
      { id: 'settlement', label: 'Settlement', icon: 'card', count: '' },
    ]},
  ];
  return (
    <aside className="sidebar">
      <div className="brand"><img className="brand-mark" src="logo.svg" alt=""/>sas<em>.xyz</em></div>
      <div className="brand-sub">
        <div>Service-as-Software</div>
        <AsciiPulse width={14} />
      </div>

      {groups.map(g => (
        <div key={g.label} className="nav-group">
          <div className="nav-group-label">{g.label}</div>
          {g.items.map(it => (
            <div key={it.id}
              className={`nav-item ${active === it.id ? 'active' : ''}`}
              onClick={() => setActive(it.id)}>
              <span style={{display:'inline-flex', alignItems:'center', gap:10}}>
                <Icon name={it.icon} size={14}/>
                {it.label}
              </span>
              {it.count !== '' && <span className="count">{it.count}</span>}
            </div>
          ))}
        </div>
      ))}

      <div className="side-footer">
        <div className="side-footer-label">Organization</div>
        <div className="org">
          <div className="org-avatar">A</div>
          <div>
            <div>Acme Corp Global</div>
            <div className="org-sub">Policy · 2026.4</div>
          </div>
        </div>
      </div>
    </aside>
  );
};

const Topbar = () => (
  <header className="topbar">
    <div className="search">
      <Icon name="search" size={15} />
      <input placeholder="Search outcomes, services, or policy envelopes…" />
      <span className="kbd">⌘K</span>
    </div>
    <div className="topbar-right">
      <AsciiTicker width={32} />
      <div className="topbar-divider"/>
      <div className="release-tag"><span className="dot"/>v2.4.0 Stable</div>
      <div className="topbar-divider"/>
      <div className="icon-btn"><Icon name="bell" size={17}/><span className="bell-dot"/></div>
      <div className="user-pill">
        <div className="avatar">H</div>
        <div>
          <div className="who">Heath Ledger</div>
          <div className="who-sub">Procurement · Owner</div>
        </div>
      </div>
    </div>
  </header>
);

window.Sidebar = Sidebar;
window.Topbar = Topbar;
