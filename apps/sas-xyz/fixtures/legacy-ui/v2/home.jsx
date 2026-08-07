// HomeView — the default authenticated landing page.
// Frame: "Welcome back" → command strip → ticker → your contracts → trending outcomes rail → browse all.
// Uses ContractsView for the portfolio surface; adds a trending rail below.

const HomeView = ({
  contracts, draftsList, completes,
  onOpenContract, onSwap, onDraft, onResumeDraft, onDiscardDraft,
  onCategory, onCommission, onBrowseAll,
}) => {
  // Top 6 catalog items by liveness (or first 6 if liveness absent)
  const trending = React.useMemo(() => {
    const items = window.CATALOG_ITEMS || [];
    return items.slice(0, 6);
  }, []);

  const trendingByCategory = React.useMemo(() => {
    const items = window.CATALOG_ITEMS || [];
    const cats = window.CATALOG_CATEGORIES || [];
    return cats.map(c => ({
      ...c,
      items: items.filter(it => it.category === c.id).slice(0, 3),
    })).filter(c => c.items.length > 0);
  }, []);

  // Rail scroll ref + handlers
  const railRef = React.useRef(null);
  const scrollRail = (dir) => {
    if (!railRef.current) return;
    const amount = 340;
    railRef.current.scrollBy({ left: dir * amount, behavior: 'smooth' });
  };

  return (
    <div className="page ui-dash-container" data-screen-label="00 Home">
      <h1 className="ui-dash-heading">
        Welcome back, Hana
      </h1>

      <div className="ui-dash-cards">
        {/* Card 1 — Action Required */}
        <div className="ui-dash-card">
          <div className="ui-dash-card-icon icon-action">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
              <polyline points="14 2 14 8 20 8" />
              <line x1="12" y1="18" x2="12" y2="12" />
              <line x1="9" y1="15" x2="15" y2="15" />
            </svg>
          </div>
          <div className="ui-dash-card-body">
            <div className="card-k card-k-action">Recommended For You</div>
            <div className="card-v">Draft a new contract</div>
            <div className="card-sub">Get tailored agents for your needs.</div>
            <button className="btn accent" onClick={() => onDraft('')} style={{marginTop: 8, alignSelf:'flex-start', padding: '8px 16px', fontSize: 13}}>Draft contract</button>
          </div>
        </div>

        {/* Card 2 — Attention */}
        <div className="ui-dash-card">
          <div className="ui-dash-card-icon icon-attention">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
              <polyline points="22,6 12,13 2,6" />
            </svg>
          </div>
          <div className="ui-dash-card-body">
            <div className="card-k card-k-attention">Attention</div>
            <div className="card-v">Review new receipts</div>
            <div className="card-sub">You have {contracts.length} active contracts streaming receipts.</div>
          </div>
        </div>

        {/* Card 3 — System Health */}
        <div className="ui-dash-card">
          <div className="ui-dash-card-icon icon-health">
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="20" x2="18" y2="10" />
              <line x1="12" y1="20" x2="12" y2="4" />
              <line x1="6" y1="20" x2="6" y2="14" />
            </svg>
          </div>
          <div className="ui-dash-card-body">
            <div className="card-k card-k-health">System Health</div>
            <div className="card-v">99.94% SLA met</div>
            <div className="card-sub">Rolling 7d · +0.02 vs last week</div>
          </div>
        </div>
      </div>

      {/* ───────────── Pick up where you left off — with rail arrows ───────────── */}
      <div className="ui-rail-header">
        <h2>Pick up where you left off</h2>
        <div className="ui-rail-arrows">
          <button className="ui-rail-arrow" onClick={() => scrollRail(-1)} title="Scroll left">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="15 18 9 12 15 6" />
            </svg>
          </button>
          <button className="ui-rail-arrow" onClick={() => scrollRail(1)} title="Scroll right">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="9 6 15 12 9 18" />
            </svg>
          </button>
        </div>
      </div>

      <ContractsView
        contracts={contracts}
        draftsList={draftsList}
        completes={completes}
        onOpenContract={onOpenContract}
        onSwap={onSwap}
        onDraft={onDraft}
        onResumeDraft={onResumeDraft}
        onDiscardDraft={onDiscardDraft}
        embedded
        railRef={railRef}
      />

      {/* ───────────── Trending outcomes rail ───────────── */}
      <section style={{marginTop: 56}}>
        <div className="section-head" style={{marginBottom: 18}}>
          <div>
            <div className="mono" style={{fontSize:9.5, letterSpacing:'0.16em', textTransform:'uppercase', color:'var(--muted-2)', marginBottom: 8}}>
              <span style={{display:'inline-block', width:5, height:5, borderRadius:'50%', background:'var(--coral)', marginRight:7, verticalAlign:'middle'}} />
              Trending in the market
            </div>
            <h2 className="section-title serif">Outcomes your peers are contracting.</h2>
            <p className="section-sub mono" style={{marginTop:6}}>
              Browse by category · commission a draft from any card
            </p>
          </div>
          <span onClick={onBrowseAll} className="mono" style={{fontSize:11, color:'var(--accent-ink)', letterSpacing:'0.06em', textTransform:'uppercase', cursor:'pointer'}}>
            browse all →
          </span>
        </div>

        <div style={{display:'flex', flexDirection:'column', gap: 28}}>
          {trendingByCategory.map(cat => (
            <div key={cat.id}>
              <div className="home-cat-row" style={{display:'flex', justifyContent:'space-between', alignItems:'flex-end', marginBottom: 10, gap: 10, flexWrap:'wrap'}}>
                <div style={{display:'flex', alignItems:'flex-end', gap: 12, flexWrap:'wrap'}}>
                  <span className="serif" style={{fontSize: 19, letterSpacing:'-0.01em'}}>
                    {cat.name}
                  </span>
                  <span className="mono" style={{fontSize: 9.5, letterSpacing:'0.12em', textTransform:'uppercase', color:'var(--muted-2)'}}>
                    {cat.items.length} outcomes
                  </span>
                </div>
                <span onClick={() => onCategory(cat.id)} className="mono" style={{fontSize: 10, letterSpacing:'0.06em', color:'var(--muted)', cursor:'pointer', textTransform:'uppercase'}}>
                  see all →
                </span>
              </div>
              <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(320px, 1fr))', gap: 10}}>
                {cat.items.map(it => (
                  <TrendingCard key={it.id} item={it} onCommission={() => onCommission(it)} />
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
};

const TrendingCard = ({ item, onCommission }) => (
  <div
    onClick={onCommission}
    style={{
      padding:'14px 16px',
      border:'1px solid var(--rule-soft)',
      background:'var(--paper)',
      borderRadius: 10,
      cursor:'pointer',
      display:'flex', flexDirection:'column', gap: 8,
      transition:'border-color 0.12s, transform 0.12s',
    }}
    onMouseEnter={(e) => e.currentTarget.style.borderColor = 'var(--ink-2)'}
    onMouseLeave={(e) => e.currentTarget.style.borderColor = 'var(--rule-soft)'}
  >
    <div style={{display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap: 10}}>
      <div className="serif" style={{fontSize: 15, lineHeight: 1.3, flex: 1}}>
        {item.title}
      </div>
      {item.priceRange && (
        <div className="mono" style={{fontSize: 10, color:'var(--muted)', letterSpacing:'0.02em', whiteSpace:'nowrap', flexShrink:0}}>
          {item.priceRange}
        </div>
      )}
    </div>
    <div style={{fontSize: 12, color:'var(--muted)', lineHeight: 1.4}}>
      {item.tagline}
    </div>
    <div style={{display:'flex', gap: 10, alignItems:'center', marginTop: 2, flexWrap:'wrap'}}>
      {item.providerCount && (
        <span className="mono" style={{fontSize: 10, color:'var(--ink-2)', letterSpacing:'0.02em'}}>
          {item.providerCount} providers
        </span>
      )}
      {item.sla && (
        <span className="mono" style={{fontSize: 10, color:'var(--muted)', letterSpacing:'0.02em'}}>
          · SLA {item.sla}
        </span>
      )}
      <span style={{flex: 1}} />
      <span className="mono" style={{fontSize: 10, color:'var(--accent-ink)', letterSpacing:'0.06em', textTransform:'uppercase'}}>
        commission →
      </span>
    </div>
  </div>
);

window.HomeView = HomeView;
