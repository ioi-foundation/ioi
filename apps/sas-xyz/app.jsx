// Main App
const { useState: useStateApp, useEffect } = React;

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "accent": "indigo",
  "paper": "light",
  "density": "default"
}/*EDITMODE-END*/;

const App = () => {
  const [active, setActive] = useStateApp(() => localStorage.getItem('sas.tab') || 'catalog');
  const [selected, setSelected] = useStateApp(null);
  const [tweaks, setTweaks] = useStateApp(TWEAK_DEFAULTS);
  const [tweaksOpen, setTweaksOpen] = useStateApp(false);

  useEffect(() => { localStorage.setItem('sas.tab', active); }, [active]);

  // Tweaks host handshake
  useEffect(() => {
    const handler = (e) => {
      if (!e.data || typeof e.data !== 'object') return;
      if (e.data.type === '__activate_edit_mode') setTweaksOpen(true);
      if (e.data.type === '__deactivate_edit_mode') setTweaksOpen(false);
    };
    window.addEventListener('message', handler);
    window.parent.postMessage({ type: '__edit_mode_available' }, '*');
    return () => window.removeEventListener('message', handler);
  }, []);

  const updateTweak = (k, v) => {
    const next = { ...tweaks, [k]: v };
    setTweaks(next);
    window.parent.postMessage({ type: '__edit_mode_set_keys', edits: { [k]: v } }, '*');
  };

  const activate = (id) => {
    setSelected(null);
    setActive('instances');
  };

  return (
    <div className="app" data-accent={tweaks.accent} data-paper={tweaks.paper === 'dark' ? 'ink' : 'light'} data-density={tweaks.density}>
      <Sidebar active={active} setActive={setActive} />
      <main className="main">
        <Topbar />
        {active === 'catalog' && <CatalogPage onSelect={setSelected} />}
        {active === 'instances' && <InstancesPage />}
        {active === 'audit' && <AuditPage />}
        {active === 'settlement' && <SettlementPage />}
        {active === 'requests' && <RequestsPlaceholder />}
        {active === 'governance' && <GovernancePlaceholder />}
      </main>
      {selected && <Drawer service={selected} onClose={() => setSelected(null)} onActivate={activate} />}
      {tweaksOpen && <TweaksPanel tweaks={tweaks} update={updateTweak} onClose={() => setTweaksOpen(false)} />}
    </div>
  );
};

const RequestsPlaceholder = () => {
  // Funnel: 4 stages with a "draft" dot slowly walking through.
  const tick = React.useState(0)[0];
  const [step, setStep] = React.useState(0);
  React.useEffect(() => {
    const id = setInterval(() => setStep(s => (s + 1) % 8), 1400);
    return () => clearInterval(id);
  }, []);
  const stages = [
    { key: 'DRAFT',    count: 2, glyph: '◇' },
    { key: 'LEGAL',    count: 1, glyph: '◇' },
    { key: 'MATCH',    count: 0, glyph: '◇' },
    { key: 'PROCURED', count: 3, glyph: '◆' },
  ];
  // The "in-flight" dot position (0..3) — walks forward then resets.
  const pos = step < 4 ? step : -1;

  return (
    <div className="content">
      <div className="page-head">
        <div>
          <div className="eyebrow"><span className="bullet"/> Procurement / Requests</div>
          <h1 className="page-title">Draft an <em>outcome</em> spec.</h1>
          <p className="page-lede">Describe what done looks like — we'll match vendors, negotiate posture, and draft a policy envelope before Legal reviews.</p>
        </div>
      </div>

      <div className="funnel-card">
        <div className="funnel-head">
          <span className="section-label" style={{margin:0}}>Active pipeline · 6 requests</span>
          <span className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.14em', textTransform:'uppercase'}}>Updated live</span>
        </div>
        <div className="funnel-row">
          {stages.map((s, i) => (
            <React.Fragment key={s.key}>
              <div className={`funnel-stage ${pos === i ? 'hot' : ''}`}>
                <div className="funnel-stage-glyph mono">{s.glyph}</div>
                <div className="funnel-stage-count serif-italic">{s.count}</div>
                <div className="funnel-stage-label mono">{s.key}</div>
                <div className="funnel-stage-sub mono">{['outcome spec','policy draft','vendor match','bonded & live'][i]}</div>
              </div>
              {i < stages.length - 1 && (
                <div className={`funnel-arrow mono ${pos === i ? 'hot' : ''}`}>
                  {pos === i ? '──◆→' : '────'}
                </div>
              )}
            </React.Fragment>
          ))}
        </div>
        <div className="funnel-foot mono">
          <span>Median time from draft → procured: <strong>2.4 days</strong></span>
          <span>SLA: <strong>5 business days</strong></span>
        </div>
      </div>
    </div>
  );
};

const GovernancePlaceholder = () => {
  const ENVELOPES = [
    { id: 'A', name: 'Alpha',   rule: 'No PII egress',           count: 4 },
    { id: 'B', name: 'Bravo',   rule: 'Budget cap $5k/mo',        count: 6 },
    { id: 'C', name: 'Charlie', rule: 'Human gate on write',      count: 2 },
    { id: 'D', name: 'Delta',   rule: 'EU-only residency',        count: 1 },
    { id: 'E', name: 'Echo',    rule: 'Read-only systems',        count: 3 },
    { id: 'F', name: 'Foxtrot', rule: 'Dual-sig over $500',       count: 2 },
    { id: 'G', name: 'Golf',    rule: 'Weekly evidence review',   count: 5 },
    { id: 'H', name: 'Hotel',   rule: 'Time-box 24h',             count: 0 },
    { id: 'I', name: 'India',   rule: 'Audit within 72h',         count: 3 },
    { id: 'J', name: 'Juliet',  rule: 'Vendor scope lock',        count: 1 },
    { id: 'K', name: 'Kilo',    rule: 'No external calls',        count: 2 },
    { id: 'L', name: 'Lima',    rule: 'Reversible within 24h',    count: 8 },
    { id: 'M', name: 'Mike',    rule: 'Per-outcome pricing',      count: 4 },
    { id: 'N', name: 'November',rule: 'Restricted to Finance',    count: 1 },
  ];
  const [active, setActive] = React.useState(0);
  React.useEffect(() => {
    const id = setInterval(() => setActive(a => (a + 1) % ENVELOPES.length), 1600);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="content">
      <div className="page-head">
        <div>
          <div className="eyebrow"><span className="bullet"/> Procurement / Governance</div>
          <h1 className="page-title">Policy <em>envelopes</em>.</h1>
          <p className="page-lede">Reusable, auditable constraints — budget caps, data classes, human-in-loop gates — applied to any service at procurement time.</p>
        </div>
        <div className="stat-strip">
          <div className="stat"><span className="stat-label">Envelopes</span><span className="stat-val">14</span></div>
          <div className="stat-sep"/>
          <div className="stat"><span className="stat-label">Applied</span><span className="stat-val">42<span className="unit">total</span></span></div>
        </div>
      </div>

      <div className="envelope-card">
        <div className="envelope-head">
          <span className="section-label" style={{margin:0}}>Envelope library · {ENVELOPES.length} active</span>
          <span className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.14em', textTransform:'uppercase'}}>Auto-cycling focus</span>
        </div>
        <div className="envelope-grid">
          {ENVELOPES.map((e, i) => (
            <div key={e.id} className={`envelope ${active === i ? 'active' : ''}`}>
              <div className="env-id mono">[{e.id}]</div>
              <div className="env-name serif-italic">{e.name}</div>
              <div className="env-rule mono">{e.rule}</div>
              <div className="env-count mono">{e.count} services</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

const TweaksPanel = ({ tweaks, update, onClose }) => (
  <div className="tweaks-panel">
    <div className="tweaks-head">
      <span>Tweaks</span>
      <span style={{cursor:'pointer', letterSpacing:'0.05em'}} onClick={onClose}>×</span>
    </div>
    <div className="tweaks-body">
      <div className="tweak">
        <div className="tweak-label">Accent</div>
        <div className="tweak-row">
          {['indigo','plum','azure','coral'].map(c => (
            <div key={c} className={`tweak-chip ${tweaks.accent === c ? 'active' : ''}`} onClick={() => update('accent', c)}>{c}</div>
          ))}
        </div>
      </div>
      <div className="tweak">
        <div className="tweak-label">Paper</div>
        <div className="tweak-row">
          {['light','dark'].map(c => (
            <div key={c} className={`tweak-chip ${tweaks.paper === c ? 'active' : ''}`} onClick={() => update('paper', c)}>{c}</div>
          ))}
        </div>
      </div>
      <div className="tweak">
        <div className="tweak-label">Density</div>
        <div className="tweak-row">
          {['default','compact'].map(c => (
            <div key={c} className={`tweak-chip ${tweaks.density === c ? 'active' : ''}`} onClick={() => update('density', c)}>{c}</div>
          ))}
        </div>
      </div>
    </div>
  </div>
);

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
