// Providers — dense supply-side directory.
// Reference surface, not browse. Table over cards. Power-user oriented.

const ProvidersView = ({ initialCategory = 'all', onClearFilter }) => {
  const [sortBy, setSortBy] = React.useState('rating');
  const [cat, setCat] = React.useState(initialCategory);
  const [onlyRunning, setOnlyRunning] = React.useState(false);

  React.useEffect(() => { setCat(initialCategory); }, [initialCategory]);

  const filtered = ALL_PROVIDERS.filter(p =>
    (cat === 'all' || p.category === cat) &&
    (!onlyRunning || p.running)
  ).sort((a, b) => {
    if (sortBy === 'rating') return b.rating - a.rating;
    if (sortBy === 'price') return a.price - b.price;
    if (sortBy === 'bids') return b.bids - a.bids;
    return a.name.localeCompare(b.name);
  });

  const cats = ['all', ...new Set(ALL_PROVIDERS.map(p => p.category))];

  return (
    <div className="page">
      <div className="hero" style={{paddingBottom:24, marginBottom:20}} data-screen-label="04 Providers">
        <div className="hero-eyebrow mono">
          <span className="bullet" /> Providers · supply-side directory
        </div>
        <h1 className="hero-title serif" style={{fontSize:48}}>
          The <em>supply side</em>, as a directory.
        </h1>
        <p className="hero-lede" style={{maxWidth:640}}>
          Who's fulfilling your contracts, who else can, their reputation and history. For vendor management and dispute research.
        </p>
      </div>

      {/* Toolbar */}
      <div style={{display:'flex', gap:10, flexWrap:'wrap', alignItems:'center', marginBottom:14, padding:'10px 14px', border:'1px solid var(--rule-soft)', borderRadius:10, background:'var(--paper)'}}>
        <span className="mono" style={{fontSize:10, letterSpacing:'0.16em', textTransform:'uppercase', color:'var(--muted)'}}>Filter</span>
        <select value={cat} onChange={e => setCat(e.target.value)} className="mono" style={{fontSize:11, padding:'4px 10px', border:'1px solid var(--rule-soft)', borderRadius:4, background:'var(--paper)'}}>
          {cats.map(c => <option key={c} value={c}>{c === 'all' ? 'All categories' : c}</option>)}
        </select>
        {cat !== 'all' && onClearFilter && (
          <span onClick={() => { setCat('all'); onClearFilter && onClearFilter(); }} className="mono" style={{fontSize:10, letterSpacing:'0.08em', color:'var(--accent-ink)', cursor:'pointer', padding:'3px 8px', borderRadius:999, background:'var(--accent-soft)'}}>
            clear ×
          </span>
        )}
        <label className="mono" style={{fontSize:11, color:'var(--muted)', display:'flex', gap:6, alignItems:'center', cursor:'pointer'}}>
          <input type="checkbox" checked={onlyRunning} onChange={e => setOnlyRunning(e.target.checked)} />
          Running on a contract
        </label>
        <div style={{flex:1}} />
        <span className="mono" style={{fontSize:10, letterSpacing:'0.16em', textTransform:'uppercase', color:'var(--muted)'}}>Sort</span>
        {['rating','price','bids','name'].map(k => (
          <span key={k} onClick={() => setSortBy(k)} className="mono" style={{fontSize:11, padding:'3px 9px', borderRadius:4, cursor:'pointer', background: sortBy === k ? 'var(--ink)' : 'transparent', color: sortBy === k ? 'var(--paper)' : 'var(--ink-2)'}}>
            {k}
          </span>
        ))}
        <span className="mono" style={{fontSize:10, color:'var(--muted-2)', marginLeft:8}}>{filtered.length} of {ALL_PROVIDERS.length}</span>
      </div>

      {/* Dense table */}
      <div style={{border:'1px solid var(--rule-soft)', borderRadius:10, overflow:'hidden', background:'var(--paper)'}}>
        <div style={{
          display:'grid',
          gridTemplateColumns:'1.6fr 1.6fr 0.9fr 0.9fr 1fr 1.3fr 0.6fr',
          gap:14, padding:'10px 18px',
          background:'var(--paper-2)', borderBottom:'1px solid var(--rule-soft)',
          fontFamily:'var(--mono)', fontSize:9.5, letterSpacing:'0.14em', textTransform:'uppercase', color:'var(--muted)', fontWeight:600,
        }}>
          <div>Provider</div>
          <div>Category</div>
          <div style={{textAlign:'right'}}>Price</div>
          <div style={{textAlign:'center'}}>Rating</div>
          <div style={{textAlign:'right'}}>Bids · 90d</div>
          <div>Region · certs</div>
          <div style={{textAlign:'right'}}>Status</div>
        </div>
        {filtered.map((p, i) => (
          <div key={p.id} style={{
            display:'grid',
            gridTemplateColumns:'1.6fr 1.6fr 0.9fr 0.9fr 1fr 1.3fr 0.6fr',
            gap:14, padding:'12px 18px',
            borderBottom: i < filtered.length - 1 ? '1px solid var(--rule-soft)' : 'none',
            alignItems:'center',
            fontSize:12.5,
          }}>
            <div>
              <div className="serif" style={{fontSize:16}}>{p.name}</div>
              <div className="mono" style={{fontSize:9.5, color:'var(--muted)', letterSpacing:'0.04em'}}>since {p.since}</div>
            </div>
            <div style={{color:'var(--ink-2)', fontSize:12}}>{p.category}</div>
            <div style={{textAlign:'right', fontFamily:'var(--mono)'}}>${p.price} <span style={{color:'var(--muted-2)', fontSize:10}}>{p.unit}</span></div>
            <div style={{textAlign:'center', fontFamily:'var(--mono)'}}>★ {p.rating}</div>
            <div style={{textAlign:'right', fontFamily:'var(--mono)', color:'var(--ink-2)'}}>{p.bids}</div>
            <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.03em'}}>
              {p.region}
              {p.certs.length > 0 && <span> · {p.certs.join(', ')}</span>}
            </div>
            <div style={{textAlign:'right'}}>
              {p.running ? (
                <span className="mono" style={{fontSize:9, letterSpacing:'0.1em', textTransform:'uppercase', padding:'2px 6px', borderRadius:3, background:'var(--accent)', color:'var(--paper)', fontWeight:600}}>running</span>
              ) : p.envelopes.length > 0 ? (
                <span className="mono" style={{fontSize:9, letterSpacing:'0.1em', textTransform:'uppercase', padding:'2px 6px', borderRadius:3, background:'oklch(0.95 0.03 185)', color:'var(--sage-ink)', fontWeight:600}}>fit</span>
              ) : (
                <span className="mono" style={{fontSize:9, letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--muted-2)'}}>—</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

window.ProvidersView = ProvidersView;
