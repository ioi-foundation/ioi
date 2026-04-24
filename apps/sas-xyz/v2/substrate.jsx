// Substrate catalog — browse every provider that can fulfill any outcome.
// The commoditized-provider thesis made visible.

const ALL_PROVIDERS = [
  // Finance / AP
  { id: 'p-finflow',  name: 'FinFlow Autonomous', category: 'Finance · AP', price: 1.20, unit: '/ outcome', since: '2022', region: 'US + EU', certs: ['SOC2', 'ISO-27001'], envelopes: ['Alpha'], running: 1, bids: 284, rating: 4.7, note: 'Current on CT-0014' },
  { id: 'p-ledgerly', name: 'Ledgerly',           category: 'Finance · AP', price: 0.80, unit: '/ outcome', since: '2024', region: 'US', certs: ['SOC2'], envelopes: ['Alpha'], running: 0, bids: 112, rating: 4.4, note: 'Cheapest envelope-fit' },
  { id: 'p-accru',    name: 'Accru Reconcile',    category: 'Finance · AP', price: 1.05, unit: '/ outcome', since: '2023', region: 'Global', certs: ['SOC2', 'ISO-27001'], envelopes: ['Alpha'], running: 0, bids: 76, rating: 4.6, note: 'Enterprise grade' },
  { id: 'p-booka',    name: 'Booka',              category: 'Finance · AP', price: 0.65, unit: '/ outcome', since: '2025', region: 'EU', certs: ['SOC2'], envelopes: [], running: 0, bids: 18, rating: 4.2, note: 'New entrant · EU-only' },

  // HR / onboarding
  { id: 'p-cohort',  name: 'Cohort Labor',  category: 'HR · Onboarding', price: 120, unit: '/ hire', since: '2021', region: 'Global', certs: ['SOC2', 'ISO-27001'], envelopes: ['Mike'], running: 1, bids: 49, rating: 4.5, note: 'Current on CT-0021' },
  { id: 'p-rally',   name: 'Rally HR',      category: 'HR · Onboarding', price: 140, unit: '/ hire', since: '2020', region: 'US + EU', certs: ['SOC2'], envelopes: ['Mike'], running: 0, bids: 62, rating: 4.3, note: 'Swapped out Mar 4' },
  { id: 'p-foundry', name: 'Foundry People',category: 'HR · Onboarding', price: 95,  unit: '/ hire', since: '2024', region: 'Global', certs: ['SOC2'], envelopes: ['Mike'], running: 0, bids: 34, rating: 4.4, note: null },

  // DevOps / security
  { id: 'p-sentinel',name: 'Sentinel Core',  category: 'DevOps · Patching', price: 12, unit: '/ CVE', since: '2022', region: 'Global', certs: ['SOC2', 'FedRAMP'], envelopes: ['Bravo'], running: 1, bids: 38, rating: 4.8, note: 'Current on CT-0019' },
  { id: 'p-patchd',  name: 'Patchd.io',      category: 'DevOps · Patching', price: 10, unit: '/ CVE', since: '2023', region: 'US', certs: ['SOC2'], envelopes: ['Bravo'], running: 0, bids: 22, rating: 4.5, note: null },
  { id: 'p-aegis',   name: 'Aegis Runtime',  category: 'DevOps · Patching', price: 15, unit: '/ CVE', since: '2019', region: 'Global', certs: ['SOC2', 'FedRAMP', 'ISO-27001'], envelopes: ['Bravo'], running: 0, bids: 41, rating: 4.6, note: 'Enterprise incumbent' },

  // Legal / contracts
  { id: 'p-paragraph',name: 'Paragraph Legal',category: 'Legal · Contracts', price: 48, unit: '/ redline', since: '2023', region: 'US', certs: ['SOC2'], envelopes: ['Juliet'], running: 1, bids: 29, rating: 4.7, note: 'Current on CT-0026' },
  { id: 'p-vertex',   name: 'Vertex Legal',    category: 'Legal · Contracts', price: 60, unit: '/ redline', since: '2021', region: 'US + EU', certs: ['SOC2'], envelopes: ['Juliet'], running: 0, bids: 18, rating: 4.3, note: 'Swapped out Feb 18' },
  { id: 'p-clauselab',name: 'Clause Lab',      category: 'Legal · Contracts', price: 42, unit: '/ redline', since: '2024', region: 'US', certs: ['SOC2'], envelopes: [], running: 0, bids: 11, rating: 4.2, note: 'New entrant' },

  // Support
  { id: 'p-frontline',name: 'Frontline',       category: 'Support · Escalation', price: 0.40, unit: '/ ticket', since: '2023', region: 'Global', certs: ['SOC2'], envelopes: [], running: 0, bids: 3,  rating: 4.1, note: null },
  { id: 'p-escalor',  name: 'Escalor',         category: 'Support · Escalation', price: 0.55, unit: '/ ticket', since: '2022', region: 'US', certs: ['SOC2'], envelopes: [], running: 0, bids: 8,  rating: 4.4, note: null },

  // Analytics
  { id: 'p-dashkit',  name: 'Dashkit',         category: 'Analytics · Dashboards', price: 0.20, unit: '/ refresh', since: '2024', region: 'US + EU', certs: ['SOC2'], envelopes: [], running: 0, bids: 5, rating: 4.0, note: null },
  { id: 'p-freshview',name: 'Freshview',       category: 'Analytics · Dashboards', price: 0.30, unit: '/ refresh', since: '2025', region: 'US', certs: [], envelopes: [], running: 0, bids: 2, rating: 3.9, note: 'Unverified' },
];

const CATEGORIES = [
  { id: 'all', label: 'All categories' },
  { id: 'Finance · AP', label: 'Finance · AP' },
  { id: 'HR · Onboarding', label: 'HR · Onboarding' },
  { id: 'DevOps · Patching', label: 'DevOps · Patching' },
  { id: 'Legal · Contracts', label: 'Legal · Contracts' },
  { id: 'Support · Escalation', label: 'Support · Escalation' },
  { id: 'Analytics · Dashboards', label: 'Analytics · Dashboards' },
];

const SubstrateCatalog = () => {
  const [cat, setCat] = React.useState('all');
  const [onlyFit, setOnlyFit] = React.useState(false);

  const filtered = ALL_PROVIDERS.filter(p => (cat === 'all' || p.category === cat) && (!onlyFit || p.envelopes.length > 0));

  // Group by category
  const byCat = React.useMemo(() => {
    const m = new Map();
    filtered.forEach(p => {
      if (!m.has(p.category)) m.set(p.category, []);
      m.get(p.category).push(p);
    });
    for (const [k, arr] of m) arr.sort((a, b) => a.price - b.price);
    return [...m.entries()];
  }, [filtered]);

  const totalRunning = ALL_PROVIDERS.filter(p => p.running).length;

  return (
    <div className="page">
      <div className="hero" style={{paddingBottom:32, marginBottom:32}} data-screen-label="02 Substrate">
        <div className="hero-eyebrow mono">
          <span className="bullet" /> Substrate · {ALL_PROVIDERS.length} providers · {totalRunning} currently running
        </div>
        <h1 className="hero-title serif" style={{fontSize:58}}>
          Providers are <em>interchangeable</em>.
        </h1>
        <p className="hero-lede">
          Every vendor that can bid on an outcome appears here, priced per outcome. They compete on speed, cost, and envelope-fit — not on lock-in.
          Swapping never breaks your audit chain.
        </p>
      </div>

      {/* Filter bar */}
      <div style={{
        display:'flex', gap:10, flexWrap:'wrap', alignItems:'center',
        padding:'16px 18px', border:'1px solid var(--rule-soft)', borderRadius:12,
        background:'var(--paper)', marginBottom:24,
      }}>
        <span className="mono" style={{fontSize:10, letterSpacing:'0.16em', textTransform:'uppercase', color:'var(--muted)', marginRight:4}}>
          Filter ·
        </span>
        {CATEGORIES.map(c => (
          <div key={c.id} onClick={() => setCat(c.id)} className="mono" style={{
            fontSize:11, letterSpacing:'0.04em',
            padding:'5px 11px', borderRadius:999,
            cursor:'pointer',
            background: cat === c.id ? 'var(--ink)' : 'var(--paper-2)',
            color: cat === c.id ? 'var(--paper)' : 'var(--ink-2)',
            border:'1px solid ' + (cat === c.id ? 'var(--ink)' : 'var(--rule-soft)'),
          }}>{c.label}</div>
        ))}
        <div style={{flex:1}} />
        <div onClick={() => setOnlyFit(v => !v)} className="mono" style={{
          fontSize:11, letterSpacing:'0.04em',
          padding:'5px 11px', borderRadius:999,
          cursor:'pointer',
          background: onlyFit ? 'var(--accent-soft)' : 'var(--paper-2)',
          color: onlyFit ? 'var(--accent-ink)' : 'var(--muted)',
          border:'1px solid ' + (onlyFit ? 'oklch(0.82 0.08 270 / 0.5)' : 'var(--rule-soft)'),
          fontWeight: onlyFit ? 600 : 400,
        }}>
          {onlyFit ? '✓ ' : ''}Envelope-passing only
        </div>
      </div>

      {byCat.map(([catName, providers]) => {
        const prices = providers.map(p => p.price);
        const min = Math.min(...prices);
        const max = Math.max(...prices);
        const sampleUnit = providers[0].unit;
        return (
          <div key={catName} style={{marginBottom: 40}}>
            <div style={{display:'flex', justifyContent:'space-between', alignItems:'baseline', marginBottom:12}}>
              <div>
                <h2 className="serif" style={{fontSize:30, letterSpacing:'-0.015em', margin:'0 0 4px', fontWeight:400}}>
                  <em>{catName}</em>
                </h2>
                <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.08em'}}>
                  {providers.length} providers · price range ${min}–${max} {sampleUnit}
                </div>
              </div>
            </div>

            {/* Price spread band */}
            <div style={{position:'relative', height: 32, marginBottom:16, background:'var(--paper-2)', borderRadius:999, border:'1px solid var(--rule-soft)'}}>
              {providers.map((p, i) => {
                const pct = max === min ? 50 : ((p.price - min) / (max - min)) * 100;
                return (
                  <div key={p.id} title={`${p.name} · $${p.price}`} style={{
                    position:'absolute',
                    left: `calc(${pct}% - 4px)`,
                    top: 6, bottom: 6,
                    width: 8, borderRadius: 2,
                    background: p.running ? 'var(--accent)' : p.envelopes.length ? 'var(--ink)' : 'var(--muted-2)',
                    boxShadow: p.running ? '0 0 0 3px var(--accent-soft)' : 'none',
                  }} />
                );
              })}
              <div className="mono" style={{position:'absolute', left:10, top:'50%', transform:'translateY(-50%)', fontSize:9, color:'var(--muted)', letterSpacing:'0.12em', textTransform:'uppercase'}}>
                ${min}
              </div>
              <div className="mono" style={{position:'absolute', right:10, top:'50%', transform:'translateY(-50%)', fontSize:9, color:'var(--muted)', letterSpacing:'0.12em', textTransform:'uppercase'}}>
                ${max}
              </div>
            </div>

            {/* Provider cards */}
            <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(320px, 1fr))', gap:12}}>
              {providers.map(p => (
                <div key={p.id} style={{
                  padding:'18px 20px',
                  border: p.running ? '1.5px solid var(--accent)' : '1px solid var(--rule-soft)',
                  background:'var(--paper)',
                  borderRadius:12,
                  display:'flex', flexDirection:'column', gap:10,
                  position:'relative',
                }}>
                  {p.running && (
                    <div className="mono" style={{
                      position:'absolute', top:-9, left:16,
                      fontSize:9, letterSpacing:'0.14em', textTransform:'uppercase',
                      padding:'2px 8px', borderRadius:3,
                      background:'var(--accent)', color:'var(--paper)', fontWeight:600,
                    }}>
                      Running now
                    </div>
                  )}

                  <div style={{display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:10}}>
                    <div>
                      <div className="serif" style={{fontSize:22, lineHeight:1.1}}>
                        {p.name}
                      </div>
                      <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.04em', marginTop:3}}>
                        since {p.since} · {p.region}
                      </div>
                    </div>
                    <div style={{textAlign:'right', whiteSpace:'nowrap'}}>
                      <div className="serif" style={{fontSize:24, letterSpacing:'-0.01em', lineHeight:1}}>
                        <em>${p.price}</em>
                      </div>
                      <div className="mono" style={{fontSize:9.5, color:'var(--muted)', letterSpacing:'0.04em', marginTop:2}}>
                        {p.unit}
                      </div>
                    </div>
                  </div>

                  <div style={{display:'flex', flexWrap:'wrap', gap:5}}>
                    {p.certs.map(c => (
                      <span key={c} className="mono" style={{fontSize:9, letterSpacing:'0.1em', textTransform:'uppercase', padding:'2px 6px', borderRadius:3, background:'var(--paper-2)', color:'var(--muted)', border:'1px solid var(--rule-soft)'}}>{c}</span>
                    ))}
                    {p.envelopes.map(e => (
                      <span key={e} className="mono" style={{fontSize:9, letterSpacing:'0.1em', textTransform:'uppercase', padding:'2px 6px', borderRadius:3, background:'oklch(0.95 0.03 185)', color:'var(--sage-ink)', fontWeight:600}}>
                        fits {e}
                      </span>
                    ))}
                    {p.envelopes.length === 0 && (
                      <span className="mono" style={{fontSize:9, letterSpacing:'0.1em', textTransform:'uppercase', padding:'2px 6px', borderRadius:3, background:'var(--paper-2)', color:'var(--muted-2)'}}>no envelope yet</span>
                    )}
                  </div>

                  <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', paddingTop:8, borderTop:'1px dashed var(--rule-soft)'}}>
                    <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.04em'}}>
                      ★ {p.rating} · {p.bids} bids / 90d
                    </div>
                    {p.note && (
                      <div className="mono" style={{fontSize:9.5, color:'var(--ink-2)', letterSpacing:'0.04em'}}>
                        {p.note}
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </div>
  );
};

window.SubstrateCatalog = SubstrateCatalog;
