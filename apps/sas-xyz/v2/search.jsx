// SearchPalette — universal ⌘K command palette.
// Searches across: running contracts, completed contracts, catalog outcomes, providers, pages.
// Substring match · grouped results · keyboard navigation · enter to commit.

const PAGES = [
  { key: 'Home',      label: 'Home',             sub: 'your book of contracts' },
  { key: 'Market',    label: 'Market',           sub: 'browse all outcomes' },
  { key: 'Envelopes', label: 'Envelopes library', sub: 'policy bundles' },
  { key: 'Activity',  label: 'Activity log',      sub: 'full receipt ledger' },
  { key: 'Inbox',     label: 'Inbox archive',     sub: 'all notification items' },
  { key: 'Overview',  label: 'Overview',          sub: 'the thesis · about sas.xyz' },
];

const SearchPalette = ({ open, onClose, onAction }) => {
  const [query, setQuery] = React.useState('');
  const [activeIndex, setActiveIndex] = React.useState(0);
  const inputRef = React.useRef(null);

  // Focus input when opened; reset state on close
  React.useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIndex(0);
      setTimeout(() => inputRef.current?.focus(), 30);
    }
  }, [open]);

  // ─── Build result sections (flat list + section metadata) ───
  const results = React.useMemo(() => {
    const q = query.trim().toLowerCase();
    const matches = (haystack) => !q || haystack.toLowerCase().includes(q);

    const out = [];

    // Pages always visible (when empty) or filtered (when querying)
    const pageHits = PAGES.filter(p =>
      matches(p.label) || matches(p.sub) || matches(p.key)
    );
    if (pageHits.length) {
      out.push({ section: 'Pages', kind: 'page', items: pageHits.map(p => ({
        key: `page:${p.key}`,
        label: p.label,
        sub: p.sub,
        kbd: '↵ go',
        action: { type: 'tab', tab: p.key },
      })) });
    }

    // Running contracts
    const contracts = (window.CONTRACTS || []).filter(c =>
      matches(c.outcome) || matches(c.code) || matches(c.substrate?.name || '') || matches(c.envelope?.name || '')
    );
    if (contracts.length) {
      out.push({ section: 'Your contracts', kind: 'contract', items: contracts.slice(0, 6).map(c => ({
        key: `ct:${c.id}`,
        label: c.outcome,
        sub: `${c.code} · ${c.substrate?.name || '—'} · ${c.receipts30d || 0} receipts/30d`,
        kbd: '↵ open',
        action: { type: 'contract', id: c.id },
        badge: c.health === 'warn' ? 'warn' : 'ok',
      })) });
    }

    // Completed contracts
    const completes = (window.COMPLETE_CONTRACTS || []).filter(c =>
      matches(c.outcome) || matches(c.code) || matches(c.terminalState || '')
    );
    if (completes.length) {
      out.push({ section: 'Archived contracts', kind: 'complete', items: completes.slice(0, 4).map(c => ({
        key: `done:${c.id}`,
        label: c.outcome,
        sub: `${c.code} · ${c.terminalState} · closed ${c.closed || ''}`,
        kbd: '↵ open',
        action: { type: 'contract', id: c.id },
      })) });
    }

    // Catalog outcomes
    const cats = window.CATALOG_CATEGORIES || [];
    const catalog = (window.CATALOG_ITEMS || []).filter(it =>
      matches(it.title) || matches(it.tagline) || matches(it.category)
    );
    if (catalog.length) {
      out.push({ section: 'Commission an outcome', kind: 'catalog', items: catalog.slice(0, 6).map(it => {
        const cat = cats.find(c => c.id === it.category);
        return {
          key: `cat:${it.id}`,
          label: it.title,
          sub: `${cat?.name || it.category} · ${it.priceRange || 'market pricing'}`,
          kbd: '↵ draft',
          action: { type: 'commission', item: it },
        };
      }) });
    }

    // Providers
    const providers = (window.ALL_PROVIDERS || []).filter(p =>
      matches(p.name) || matches(p.category)
    );
    if (providers.length) {
      out.push({ section: 'Suppliers', kind: 'provider', items: providers.slice(0, 5).map(p => ({
        key: `prov:${p.id}`,
        label: p.name,
        sub: `${p.category} · since ${p.since || '—'} · ${(p.certs || []).join(', ') || 'no certs'}`,
        kbd: '↵ view',
        action: { type: 'provider', category: p.category },
      })) });
    }

    return out;
  }, [query]);

  const flat = results.flatMap(sec => sec.items);

  // Clamp activeIndex when results change
  React.useEffect(() => {
    if (activeIndex >= flat.length) setActiveIndex(0);
  }, [flat.length, activeIndex]);

  // Keyboard
  React.useEffect(() => {
    if (!open) return;
    const h = (e) => {
      if (e.key === 'Escape') { e.preventDefault(); onClose(); return; }
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setActiveIndex(i => Math.min(flat.length - 1, i + 1));
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setActiveIndex(i => Math.max(0, i - 1));
      }
      if (e.key === 'Enter') {
        e.preventDefault();
        const hit = flat[activeIndex];
        if (hit) { onAction(hit.action); onClose(); }
      }
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [open, flat, activeIndex, onClose, onAction]);

  if (!open) return null;

  // Compute absolute index per item for highlight
  let runningIdx = 0;

  return (
    <div
      onClick={onClose}
      style={{
        position:'fixed', inset:0, zIndex: 200,
        background:'rgba(11,11,46,0.28)',
        backdropFilter:'blur(6px)',
        display:'flex', alignItems:'flex-start', justifyContent:'center',
        paddingTop:'12vh',
        animation:'fadeIn 0.14s ease-out',
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 640, maxWidth:'92vw', maxHeight:'70vh',
          background:'var(--paper)',
          border:'1px solid var(--rule)',
          borderRadius: 14,
          boxShadow:'0 30px 80px -30px rgba(11,11,46,0.45)',
          display:'flex', flexDirection:'column',
          overflow:'hidden',
          animation:'popIn 0.18s ease-out',
        }}
      >
        {/* Input */}
        <div style={{
          padding:'16px 20px', borderBottom:'1px solid var(--rule-soft)',
          display:'flex', alignItems:'center', gap:12,
        }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{color:'var(--muted-2)', flexShrink:0}}>
            <circle cx="11" cy="11" r="7" />
            <path d="M21 21l-4.3-4.3" />
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Jump to a contract, outcome, provider, or page…"
            className="serif"
            style={{
              flex:1, border:'none', outline:'none', background:'transparent',
              fontSize: 18, color:'var(--ink)', letterSpacing:'-0.005em',
            }}
          />
          <span className="mono" style={{fontSize:9.5, color:'var(--muted-2)', letterSpacing:'0.08em', padding:'3px 7px', border:'1px solid var(--rule)', borderRadius:4}}>
            esc
          </span>
        </div>

        {/* Results */}
        <div style={{flex:1, overflowY:'auto', padding:'8px 0'}}>
          {flat.length === 0 && (
            <div style={{padding:'40px 20px', textAlign:'center'}}>
              <div className="mono" style={{fontSize:10, letterSpacing:'0.14em', textTransform:'uppercase', color:'var(--muted-2)'}}>
                no results
              </div>
              <div className="serif" style={{fontSize:15, color:'var(--ink-2)', marginTop:10, lineHeight:1.5}}>
                Nothing matches "<em>{query}</em>". Try a contract code, outcome, or provider name.
              </div>
            </div>
          )}
          {results.map(sec => (
            <div key={sec.section} style={{padding:'6px 0'}}>
              <div className="mono" style={{
                fontSize:9, letterSpacing:'0.18em', textTransform:'uppercase',
                color:'var(--muted-2)', padding:'6px 20px',
              }}>
                {sec.section}
              </div>
              {sec.items.map(item => {
                const idx = runningIdx++;
                const active = idx === activeIndex;
                return (
                  <div
                    key={item.key}
                    onClick={() => { onAction(item.action); onClose(); }}
                    onMouseEnter={() => setActiveIndex(idx)}
                    style={{
                      padding:'9px 20px',
                      display:'flex', alignItems:'center', gap:12,
                      cursor:'pointer',
                      background: active ? 'var(--paper-2)' : 'transparent',
                      borderLeft: active ? '2px solid var(--ink)' : '2px solid transparent',
                    }}
                  >
                    <SectionIcon kind={sec.kind} />
                    <div style={{flex:1, minWidth:0}}>
                      <div className="serif" style={{fontSize:14, color:'var(--ink)', lineHeight:1.3, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis'}}>
                        {item.label}
                      </div>
                      <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.02em', marginTop:2, whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis'}}>
                        {item.sub}
                      </div>
                    </div>
                    {item.badge === 'warn' && (
                      <span className="mono" style={{fontSize:8.5, letterSpacing:'0.1em', textTransform:'uppercase', color:'var(--coral-ink)', padding:'2px 6px', background:'oklch(0.96 0.06 25)', borderRadius:3}}>
                        warn
                      </span>
                    )}
                    <span className="mono" style={{fontSize:9.5, color: active ? 'var(--ink-2)' : 'var(--muted-2)', letterSpacing:'0.06em', whiteSpace:'nowrap'}}>
                      {item.kbd}
                    </span>
                  </div>
                );
              })}
            </div>
          ))}
        </div>

        {/* Footer */}
        <div style={{
          padding:'10px 20px', borderTop:'1px solid var(--rule-soft)',
          background:'var(--paper-2)',
          display:'flex', justifyContent:'space-between', alignItems:'center',
        }}>
          <span className="mono" style={{fontSize:10, color:'var(--muted-2)', letterSpacing:'0.04em'}}>
            {flat.length} result{flat.length === 1 ? '' : 's'} · substring match
          </span>
          <div style={{display:'flex', gap:14}}>
            <Kbd label="↑↓" hint="navigate" />
            <Kbd label="↵"  hint="open" />
            <Kbd label="esc" hint="close" />
          </div>
        </div>
      </div>
    </div>
  );
};

const Kbd = ({ label, hint }) => (
  <span style={{display:'flex', alignItems:'center', gap:5}}>
    <span className="mono" style={{fontSize:9.5, letterSpacing:'0.04em', padding:'2px 5px', border:'1px solid var(--rule)', borderRadius:3, background:'var(--paper)', color:'var(--ink-2)'}}>
      {label}
    </span>
    <span className="mono" style={{fontSize:9.5, color:'var(--muted-2)', letterSpacing:'0.06em'}}>{hint}</span>
  </span>
);

const SectionIcon = ({ kind }) => {
  const color = {
    page:     'var(--muted)',
    contract: 'var(--sage-ink)',
    complete: 'var(--muted-2)',
    catalog:  'var(--accent-ink)',
    provider: 'var(--coral-ink)',
  }[kind] || 'var(--muted)';

  const paths = {
    page:     <><rect x="4" y="4" width="16" height="16" rx="2" /><path d="M4 9h16" /></>,
    contract: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /></>,
    complete: <><circle cx="12" cy="12" r="9" /><path d="M8 12l3 3 5-6" /></>,
    catalog:  <><circle cx="9" cy="21" r="1" /><circle cx="20" cy="21" r="1" /><path d="M1 1h4l2.7 13.4a2 2 0 0 0 2 1.6h9.7a2 2 0 0 0 2-1.6L23 6H6" /></>,
    provider: <><circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" /></>,
  }[kind];

  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" style={{flexShrink:0, opacity:0.85}}>
      {paths}
    </svg>
  );
};

window.SearchPalette = SearchPalette;
