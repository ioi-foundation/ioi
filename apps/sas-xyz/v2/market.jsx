// Market — the unified marketplace surface. Two modes:
//   · Outcomes  → what you can buy (Catalog)
//   · Suppliers → who's selling it (Providers)
// dApp-style: the marketplace is one destination with a segmented switch.

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

  return (
    <div>
      <div className="page" style={{paddingBottom: 0}}>
        {activeCategory && (
          <div style={{display:'flex', alignItems:'center', gap:10, marginBottom:14}}>
            <span className="mono" style={{fontSize:10, letterSpacing:'0.14em', textTransform:'uppercase', color:'var(--muted-2)'}}>Market / </span>
            <span className="serif" style={{fontSize:18, letterSpacing:'-0.01em'}}>
              <em>{catalogCategoryLabel}</em>
            </span>
            <span onClick={() => onCategory(null)} className="mono" style={{fontSize:10, letterSpacing:'0.06em', color:'var(--accent-ink)', cursor:'pointer', textTransform:'uppercase', marginLeft:6}}>
              × clear
            </span>
          </div>
        )}
        {/* Segmented switch — sits above whichever surface we're showing */}
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
                  <span className="serif" style={{fontSize: 15, letterSpacing: '-0.005em'}}>{opt.label}</span>
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
      </div>

      {mode === 'outcomes'  && <CatalogView   {...catalogProps}  initialCategory={activeCategory || 'all'} onClearFilter={() => onCategory(null)} />}
      {mode === 'suppliers' && <ProvidersView {...providersProps} initialCategory={activeCategory ? CAT_TO_PROVIDER_CAT[activeCategory] : 'all'} />}
    </div>
  );
};

window.MarketView = MarketView;
