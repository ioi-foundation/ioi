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

const RequestsPlaceholder = () => (
  <div className="content">
    <div className="page-head">
      <div>
        <div className="eyebrow"><span className="bullet"/> Procurement / Requests</div>
        <h1 className="page-title">Draft an <em>outcome</em> spec.</h1>
        <p className="page-lede">Describe what done looks like — we'll match vendors, negotiate posture, and draft a policy envelope before Legal reviews.</p>
      </div>
    </div>
    <div style={{padding:'80px 40px', border:'1px dashed var(--rule)', borderRadius:16, textAlign:'center', background:'rgba(255,253,247,0.4)'}}>
      <div className="serif-italic" style={{fontSize:28, marginBottom:8}}>2 draft requests in progress</div>
      <div className="mono" style={{fontSize:11, color:'var(--muted)', letterSpacing:'0.1em'}}>DRAFT · LEGAL REVIEW · VENDOR MATCH · PROCURED</div>
    </div>
  </div>
);

const GovernancePlaceholder = () => (
  <div className="content">
    <div className="page-head">
      <div>
        <div className="eyebrow"><span className="bullet"/> Procurement / Governance</div>
        <h1 className="page-title">Policy <em>envelopes</em>.</h1>
        <p className="page-lede">Reusable, auditable constraints — budget caps, data classes, human-in-loop gates — applied to any service at procurement time.</p>
      </div>
    </div>
    <div style={{padding:'80px 40px', border:'1px dashed var(--rule)', borderRadius:16, textAlign:'center', background:'rgba(255,253,247,0.4)'}}>
      <div className="serif-italic" style={{fontSize:28, marginBottom:8}}>14 envelopes in library</div>
      <div className="mono" style={{fontSize:11, color:'var(--muted)', letterSpacing:'0.1em'}}>ALPHA · BRAVO · CHARLIE · DELTA · …</div>
    </div>
  </div>
);

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
