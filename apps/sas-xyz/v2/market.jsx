// Market — the unified marketplace surface. Two modes:
//   · Outcomes  → what you can buy (Catalog)
//   · Suppliers → who's selling it (Providers)
// dApp-style: the marketplace is one destination with a segmented switch.

const CATEGORY_HEROES = {
  finance:   { title: 'Finance & Accounting',       tagline: 'Reconcile, close, detect — outcome-priced.', gradient: 'linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f3460 100%)' },
  hr:        { title: 'People & Hiring',             tagline: 'Onboard, verify, comply — per hire.',          gradient: 'linear-gradient(135deg, #1a1a2e 0%, #2d1b4e 50%, #4a1942 100%)' },
  security:  { title: 'Security & Compliance',       tagline: 'Patch, audit, certify — per scan.',            gradient: 'linear-gradient(135deg, #1a1a2e 0%, #0d2137 50%, #1a3a4a 100%)' },
  legal:     { title: 'Legal & Contracts',            tagline: 'Redline, sign, archive — per document.',       gradient: 'linear-gradient(135deg, #1a1a2e 0%, #2e1f0f 50%, #3d2b1f 100%)' },
  support:   { title: 'Support & Operations',         tagline: 'Route, resolve, escalate — per ticket.',       gradient: 'linear-gradient(135deg, #1a1a2e 0%, #1a2e1a 50%, #2d4a2e 100%)' },
  analytics: { title: 'Data & Analytics',             tagline: 'Ingest, model, report — per insight.',         gradient: 'linear-gradient(135deg, #1a1a2e 0%, #1a1a3e 50%, #2d2d6e 100%)' },
};

const MarketView = ({ mode, onMode, activeCategory, onCategory, catalogProps, providersProps }) => {
  // Map top-nav category id to providers category label (reusing app.jsx's map is too clumsy; local)
  const CAT_TO_PROVIDER_CAT = {
    finance:  'Finance · AP',
    hr:       'HR · Onboarding',
    security: 'DevOps · Patching',
    legal:    'Legal · Contracts',
    support:  'Support · Escalation',
    analytics:'Analytics · Dashboards',
  };

  const catalogCategoryLabel = React.useMemo(() => {
    if (!activeCategory) return null;
    const c = (window.CATALOG_CATEGORIES || []).find(c => c.id === activeCategory);
    return c ? c.name : activeCategory;
  }, [activeCategory]);

  const hero = activeCategory ? CATEGORY_HEROES[activeCategory] : null;

  return (
    <div>
      {/* Category hero banner — shown when a category is selected */}
      {hero && (
        <div className="market-category-hero" style={{ background: hero.gradient }}>
          <div className="market-category-hero-inner">
            <h1 className="market-category-hero-title">{hero.title}</h1>
            <p className="market-category-hero-tagline">{hero.tagline}</p>
          </div>
        </div>
      )}

      <div className="page" style={{paddingBottom: 0}}>
        {activeCategory ? (
          // Category page: breadcrumb + small "see suppliers instead" link.
          // Toggle is suppressed — the page is now an outcomes directory.
          <div style={{display:'flex', alignItems:'center', justifyContent:'space-between', gap:16, marginBottom: 0, flexWrap: 'wrap'}}>
            <div style={{display:'flex', alignItems:'center', gap:10}}>
              <span onClick={() => onCategory(null)} className="mono" style={{fontSize:10, letterSpacing:'0.14em', textTransform:'uppercase', color:'var(--muted-2)', cursor:'pointer'}}>
                Market
              </span>
              <span className="mono" style={{fontSize:10, color:'var(--muted-2)'}}>/</span>
              <span style={{fontSize:18, fontFamily:'var(--sans, sans-serif)', fontWeight:600, letterSpacing:'-0.01em'}}>
                {catalogCategoryLabel}
              </span>
              <span onClick={() => onCategory(null)} className="mono" style={{fontSize:10, letterSpacing:'0.06em', color:'var(--accent-ink)', cursor:'pointer', textTransform:'uppercase', marginLeft:6}}>
                × clear
              </span>
            </div>
            <div style={{display:'flex', alignItems:'center', gap:14}}>
              <span
                onClick={() => onMode(mode === 'outcomes' ? 'suppliers' : 'outcomes')}
                className="mono"
                style={{fontSize:10, letterSpacing:'0.12em', textTransform:'uppercase', color:'var(--accent-ink)', cursor:'pointer'}}
              >
                {mode === 'outcomes' ? 'See suppliers instead →' : '← Back to outcomes'}
              </span>
              <span className="mono" style={{fontSize: 10, letterSpacing: '0.14em', textTransform: 'uppercase', color:'var(--muted)'}}>
                Marketplace · live
              </span>
            </div>
          </div>
        ) : (
          // All-market: segmented switch sits above content.
          <div style={{
            display:'flex', justifyContent:'space-between', alignItems:'center',
            gap: 16, marginBottom: 0,
          }}>
            <div style={{display:'inline-flex', padding:4, borderRadius: 999, border:'1px solid var(--rule)', background:'var(--paper)'}}>
              {[
                { k:'outcomes',  label:'Outcomes',  sub:'what you buy' },
                { k:'suppliers', label:'Suppliers', sub:'who delivers' },
              ].map(opt => {
                const active = mode === opt.k;
                return (
                  <div key={opt.k} onClick={() => onMode(opt.k)} style={{
                    padding: '8px 16px', borderRadius: 999, cursor: 'pointer',
                    background: active ? 'var(--ink)' : 'transparent',
                    color: active ? 'var(--paper)' : 'var(--ink-2)',
                    display: 'flex', alignItems: 'baseline', gap: 8,
                    transition: 'background .15s, color .15s',
                  }}>
                    <span style={{fontSize: 15, fontFamily:'var(--sans, sans-serif)', fontWeight: 500, letterSpacing: '-0.005em'}}>{opt.label}</span>
                    <span className="mono" style={{fontSize: 9.5, letterSpacing: '0.12em', textTransform: 'uppercase', opacity: 0.7}}>
                      {opt.sub}
                    </span>
                  </div>
                );
              })}
            </div>
            <div className="mono" style={{fontSize: 10, letterSpacing: '0.14em', textTransform: 'uppercase', color:'var(--muted)'}}>
              Marketplace · live
            </div>
          </div>
        )}
      </div>

      {mode === 'outcomes'  && <CatalogView   {...catalogProps}  initialCategory={activeCategory || 'all'} onClearFilter={() => onCategory(null)} />}
      {mode === 'suppliers' && <ProvidersView {...providersProps} initialCategory={activeCategory ? CAT_TO_PROVIDER_CAT[activeCategory] : 'all'} />}
    </div>
  );
};

window.MarketView = MarketView;
