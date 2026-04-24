// Catalog — productized, shoppable outcomes.
// Demand-side browse. Each card has "Commission this" which pre-fills a draft.

const CatalogView = ({ onCommission, onProviderClick, initialCategory = 'all', onClearFilter }) => {
  const [cat, setCat] = React.useState(initialCategory);
  const [query, setQuery] = React.useState('');

  React.useEffect(() => {
    setCat(initialCategory || 'all');
  }, [initialCategory]);

  const items = CATALOG_ITEMS.filter(it => {
    if (cat !== 'all' && it.category !== cat) return false;
    if (query && !(it.title + ' ' + it.tagline).toLowerCase().includes(query.toLowerCase())) return false;
    return true;
  });

  // Group by category
  const byCat = React.useMemo(() => {
    const m = new Map();
    items.forEach(it => {
      const c = CATALOG_CATEGORIES.find(c => c.id === it.category);
      const label = c?.name || it.category;
      if (!m.has(label)) m.set(label, []);
      m.get(label).push(it);
    });
    return [...m.entries()];
  }, [items]);

  return (
    <div className="page">
      <div className="hero" style={{paddingBottom:28, marginBottom:24}} data-screen-label="03 Catalog">
        <div className="hero-eyebrow mono">
          <span className="bullet" /> Catalog · {CATALOG_ITEMS.length} productized outcomes
        </div>
        <h1 className="hero-title serif" style={{fontSize:54}}>
          Shop <em>outcomes</em>, not software.
        </h1>
        <p className="hero-lede">
          Commoditized work, priced per result. Pick a card, click <b>Commission</b>, and we pre-fill a contract draft with the productized terms. You still approve before anything runs.
        </p>
      </div>

      {/* Filter bar */}
      <div style={{
        display:'flex', gap:12, flexWrap:'wrap', alignItems:'center',
        padding:'14px 18px', border:'1px solid var(--rule-soft)', borderRadius:12,
        background:'var(--paper)', marginBottom:28,
      }}>
        <div style={{display:'flex', gap:6, flexWrap:'wrap', flex:1}}>
          <Chip active={cat === 'all'} onClick={() => setCat('all')}>All</Chip>
          {CATALOG_CATEGORIES.map(c => (
            <Chip key={c.id} active={cat === c.id} onClick={() => setCat(c.id)}>{c.name}</Chip>
          ))}
        </div>
        <div style={{display:'flex', alignItems:'center', gap:8, padding:'4px 12px', border:'1px solid var(--rule-soft)', borderRadius:999, minWidth:220}}>
          <Icon name="history" size={12} />
          <input
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Filter by keyword…"
            style={{border:'none', outline:'none', background:'transparent', fontSize:12, color:'var(--ink)', width:'100%', fontFamily:'inherit'}}
          />
        </div>
      </div>

      {byCat.map(([catName, arr]) => (
        <div key={catName} style={{marginBottom: 36}}>
          <div style={{display:'flex', alignItems:'baseline', justifyContent:'space-between', marginBottom:12}}>
            <h2 className="serif" style={{fontSize:22, fontWeight:400, letterSpacing:'-0.01em', margin:0}}>
              <em>{catName}</em>
            </h2>
            <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.08em'}}>
              {arr.length} outcome{arr.length > 1 ? 's' : ''}
            </div>
          </div>
          <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(360px, 1fr))', gap:12}}>
            {arr.map(it => <CatalogCard key={it.id} item={it} onCommission={onCommission} onProviderClick={onProviderClick} />)}
          </div>
        </div>
      ))}

      {items.length === 0 && (
        <div style={{padding:'60px 20px', textAlign:'center', color:'var(--muted)'}} className="mono">
          No outcomes match.
        </div>
      )}
    </div>
  );
};

const Chip = ({ active, onClick, children }) => (
  <div onClick={onClick} className="mono" style={{
    fontSize:11, letterSpacing:'0.04em',
    padding:'5px 11px', borderRadius:999, cursor:'pointer',
    background: active ? 'var(--ink)' : 'var(--paper-2)',
    color: active ? 'var(--paper)' : 'var(--ink-2)',
    border: '1px solid ' + (active ? 'var(--ink)' : 'var(--rule-soft)'),
  }}>{children}</div>
);

const CatalogCard = ({ item, onCommission, onProviderClick }) => {
  const isLive = /ago|just now|m ago|h ago|s ago/.test(item.lastFulfilled);

  return (
    <div style={{
      padding:'20px 22px',
      border:'1px solid var(--rule-soft)',
      background:'var(--paper)',
      borderRadius:14,
      display:'flex', flexDirection:'column', gap:14,
      minHeight: 240,
    }}>
      {/* Head */}
      <div>
        <div style={{display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:10, marginBottom:8}}>
          <h3 className="serif" style={{fontSize:21, fontWeight:400, letterSpacing:'-0.005em', lineHeight:1.2, margin:0}}>
            <em>{item.title}</em>
          </h3>
          {isLive && (
            <div className="mono" style={{
              display:'flex', alignItems:'center', gap:4,
              fontSize:9.5, color:'var(--sage-ink)', letterSpacing:'0.08em',
              textTransform:'uppercase', fontWeight:600, whiteSpace:'nowrap',
            }}>
              <span style={{width:5, height:5, borderRadius:'50%', background:'var(--sage)', animation:'pulse 1.5s infinite'}} />
              Live
            </div>
          )}
        </div>
        <p style={{fontSize:13.5, lineHeight:1.45, color:'var(--ink-2)', margin:0}}>
          {item.tagline}
        </p>
      </div>

      {/* Price band */}
      <div style={{padding:'10px 12px', background:'var(--paper-2)', borderRadius:8, display:'flex', alignItems:'baseline', justifyContent:'space-between'}}>
        <div>
          <div className="mono" style={{fontSize:9, letterSpacing:'0.14em', textTransform:'uppercase', color:'var(--muted)', marginBottom:2}}>
            Price range · {item.providers} providers
          </div>
          <div className="serif" style={{fontSize:22, letterSpacing:'-0.01em'}}>
            <em>${formatPrice(item.priceFrom)}</em>
            <span style={{color:'var(--muted)'}}> – ${formatPrice(item.priceTo)}</span>
          </div>
          <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.04em', marginTop:2}}>
            {item.priceUnit}
          </div>
        </div>
        <div style={{textAlign:'right'}}>
          <div className="mono" style={{fontSize:9, letterSpacing:'0.14em', textTransform:'uppercase', color:'var(--muted)', marginBottom:2}}>
            SLA
          </div>
          <div className="mono" style={{fontSize:11, color:'var(--ink)', letterSpacing:'0.02em'}}>
            {item.sla}
          </div>
        </div>
      </div>

      {/* Meta row */}
      <div style={{display:'flex', flexWrap:'wrap', gap:5}}>
        <span className="mono" style={{fontSize:9.5, letterSpacing:'0.1em', textTransform:'uppercase', padding:'2px 6px', borderRadius:3, background:'var(--paper-2)', color:'var(--muted)', border:'1px solid var(--rule-soft)'}}>
          {item.envelope}
        </span>
        {item.tags.map(t => (
          <span key={t} className="mono" style={{fontSize:9, letterSpacing:'0.1em', textTransform:'uppercase', padding:'2px 6px', borderRadius:3, background:'var(--paper-2)', color:'var(--muted)', border:'1px solid var(--rule-soft)'}}>{t}</span>
        ))}
      </div>

      {/* Liveness + action */}
      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', paddingTop:10, borderTop:'1px dashed var(--rule-soft)', marginTop:'auto'}}>
        <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.04em'}}>
          Last fulfilled <b style={{color:'var(--ink-2)'}}>{item.lastFulfilled}</b>
          {' · '}
          <span
            onClick={(e) => { e.stopPropagation(); onProviderClick?.(item); }}
            style={{color:'var(--accent-ink)', cursor: onProviderClick ? 'pointer' : 'default', textDecoration: onProviderClick ? 'underline' : 'none'}}
          >
            {item.providers} providers
          </span>
          {' · '}{item.running} running
        </div>
        <button className="btn accent" onClick={() => onCommission(item)} style={{padding:'6px 12px', fontSize:11}}>
          Commission →
        </button>
      </div>
    </div>
  );
};

const formatPrice = (p) => p >= 100 ? p.toLocaleString() : p.toFixed(p < 1 ? 2 : 0);

window.CatalogView = CatalogView;
