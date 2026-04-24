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

  return (
    <div className="page" data-screen-label="00 Home">
      {/* ───────────── Welcome + portfolio (existing ContractsView) ───────────── */}
      <div style={{marginBottom: 8}}>
        <div className="mono" style={{fontSize:10, letterSpacing:'0.16em', textTransform:'uppercase', color:'var(--muted-2)'}}>
          <span style={{display:'inline-block', width:5, height:5, borderRadius:'50%', background:'var(--sage)', marginRight:7, verticalAlign:'middle'}} />
          Welcome back, Hana
        </div>
        <h1 className="serif" style={{fontSize: 40, letterSpacing:'-0.02em', lineHeight:1.1, marginTop: 8, marginBottom: 4}}>
          Your book is <em>running</em>.
        </h1>
        <p className="mono" style={{fontSize:11, color:'var(--muted)', letterSpacing:'0.04em', marginTop: 4}}>
          {contracts.length} active · {draftsList.length} drafting · {completes.length} archived
        </p>
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
