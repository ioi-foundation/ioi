// Catalog — Fiverr-style category directory.
// Flow: hero (in market.jsx) → "Most popular" subcategory pill rail
//     → "Explore [Category]" subcategory grid → All services listing (only on category pages).

const CatalogView = ({ onCommission, onProviderClick, initialCategory = 'all' }) => {
  const [cat, setCat] = React.useState(initialCategory);
  const [highlightItem, setHighlightItem] = React.useState(null);

  React.useEffect(() => {
    setCat(initialCategory || 'all');
    setHighlightItem(null);
  }, [initialCategory]);

  React.useEffect(() => {
    if (!highlightItem) return;
    const t = setTimeout(() => setHighlightItem(null), 1800);
    return () => clearTimeout(t);
  }, [highlightItem]);

  const isCategory = cat !== 'all';
  const activeCategory = isCategory ? CATALOG_CATEGORIES.find(c => c.id === cat) : null;
  const categoryLabel = activeCategory ? activeCategory.name : null;

  // Items in scope (used for the listing on category pages).
  const items = React.useMemo(() => (
    CATALOG_ITEMS.filter(it => isCategory ? it.category === cat : true)
  ), [cat, isCategory]);

  // ── Most popular pill rail ───────────────────────────────────────────
  // On a category page: this category's subcategories.
  // On all-market: a marquee of trending subcategories across the marketplace.
  const popularPills = React.useMemo(() => {
    if (isCategory) {
      return (activeCategory?.subcategories || []).map(s => ({
        id: `${cat}:${s.id}`,
        label: s.name,
        toneId: cat,
        onClick: () => scrollToSubcategory(s.id),
      }));
    }
    // All-market: pick the first subcategory of each top-level category.
    const out = [];
    CATALOG_CATEGORIES.forEach(c => {
      (c.subcategories || []).slice(0, 2).forEach(s => {
        out.push({
          id: `${c.id}:${s.id}`,
          label: s.name,
          toneId: c.id,
          onClick: () => setCat(c.id),
        });
      });
    });
    return out.slice(0, 12);
  }, [cat, isCategory, activeCategory]);

  // ── Explore grid ────────────────────────────────────────────────────
  // All-market: 6 cards, one per category, each listing 5 subcategory names.
  // Single category: N cards, one per subcategory, each listing its concrete services.
  const exploreCards = React.useMemo(() => {
    if (isCategory) {
      return (activeCategory?.subcategories || []).map(s => ({
        kind: 'subcategory',
        id: s.id,
        name: s.name,
        toneId: cat,
        links: (s.services || []).map(svc => ({
          label: svc.label,
          itemId: svc.itemId || null,
          onClick: () => {
            if (svc.itemId) {
              setHighlightItem(svc.itemId);
              const el = document.getElementById(`cat-item-${svc.itemId}`);
              if (el) el.scrollIntoView({ behavior: 'smooth', block: 'center' });
            } else {
              scrollToSubcategory(s.id);
            }
          },
        })),
      }));
    }
    return CATALOG_CATEGORIES.map(c => ({
      kind: 'category',
      id: c.id,
      name: c.name,
      toneId: c.id,
      links: (c.subcategories || []).slice(0, 5).map(s => ({
        label: s.name,
        onClick: () => setCat(c.id),
      })),
    }));
  }, [cat, isCategory, activeCategory]);

  // ── Listing groups (only on category pages) ─────────────────────────
  const itemsBySubcategory = React.useMemo(() => {
    if (!isCategory) return [];
    return (activeCategory?.subcategories || [])
      .map(s => ({
        sub: s,
        items: items.filter(it => it.subcategory === s.id),
      }))
      .filter(group => group.items.length > 0);
  }, [items, isCategory, activeCategory]);

  // ── Rail scroll ─────────────────────────────────────────────────────
  const railRef = React.useRef(null);
  const scrollRail = (dir) => {
    if (!railRef.current) return;
    railRef.current.scrollBy({ left: dir * 380, behavior: 'smooth' });
  };

  const scrollToSubcategory = (subId) => {
    const el = document.getElementById(`cat-sub-${subId}`);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <div className="page" data-screen-label="03 Catalog">

      {/* All-market: keep the editorial sub-hero. Category pages: skip — the gradient hero in MarketView already serves as headline. */}
      {!isCategory && (
        <div style={{marginBottom: 36}}>
          <div className="mono" style={{fontSize: 10, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--muted-2)', marginBottom: 10, display: 'flex', alignItems: 'center', gap: 6}}>
            <span style={{width: 5, height: 5, borderRadius: '50%', background: 'var(--sage)', display: 'inline-block'}} />
            Catalog · {CATALOG_ITEMS.length} productized outcomes
          </div>
          <h1 style={{fontFamily: 'var(--sans, sans-serif)', fontSize: 42, fontWeight: 700, letterSpacing: '-0.025em', lineHeight: 1.1, margin: '0 0 10px', color: 'var(--ink)'}}>
            Shop <em style={{fontStyle: 'normal', color: 'var(--ink)'}}>outcomes</em>, not software.
          </h1>
          <p style={{fontSize: 16, lineHeight: 1.55, color: 'var(--muted)', margin: 0, maxWidth: 640}}>
            Commoditized work, priced per result. Pick a card, click <b>Commission</b>, and we pre-fill a
            contract draft with the productized terms. You still approve before anything runs.
          </p>
        </div>
      )}

      {/* ────────── Most popular pill rail ────────── */}
      {popularPills.length > 0 && (
        <section style={{marginBottom: 48}}>
          <div className="ui-rail-header" style={{marginBottom: 16}}>
            <h2 style={{fontFamily: 'var(--sans, sans-serif)', fontSize: 22, fontWeight: 600, color: '#404145', margin: 0}}>
              Most popular{categoryLabel ? ` in ${categoryLabel}` : ''}
            </h2>
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
          <div className="cat-popular-rail" ref={railRef}>
            {popularPills.map(p => (
              <PopularPill key={p.id} pill={p} />
            ))}
          </div>
        </section>
      )}

      {/* ────────── Explore grid ────────── */}
      <section style={{marginBottom: 56}}>
        <h2 style={{fontFamily: 'var(--sans, sans-serif)', fontSize: 22, fontWeight: 600, color: '#404145', margin: '0 0 20px'}}>
          Explore{categoryLabel ? ` ${categoryLabel}` : ' the marketplace'}
        </h2>
        <div className="cat-explore-grid">
          {exploreCards.map(card => (
            <ExploreCard key={card.id} card={card} />
          ))}
        </div>
      </section>

      {/* ────────── Listing — only on a single-category page ────────── */}
      {isCategory && itemsBySubcategory.length > 0 && (
        <section>
          <h2 style={{fontFamily: 'var(--sans, sans-serif)', fontSize: 22, fontWeight: 600, color: '#404145', margin: '0 0 24px'}}>
            All {categoryLabel} services
          </h2>
          {itemsBySubcategory.map(({sub, items: arr}) => (
            <div key={sub.id} id={`cat-sub-${sub.id}`} style={{marginBottom: 36, scrollMarginTop: 24}}>
              <div style={{display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 12}}>
                <h3 style={{fontFamily: 'var(--sans, sans-serif)', fontSize: 18, fontWeight: 600, letterSpacing: '-0.01em', margin: 0, color: '#404145'}}>
                  {sub.name}
                </h3>
                <div className="mono" style={{fontSize: 10, color: 'var(--muted)', letterSpacing: '0.08em'}}>
                  {arr.length} outcome{arr.length > 1 ? 's' : ''}
                </div>
              </div>
              <div style={{display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(360px, 1fr))', gap: 12}}>
                {arr.map(it => (
                  <CatalogCard
                    key={it.id}
                    item={it}
                    highlighted={highlightItem === it.id}
                    onCommission={onCommission}
                    onProviderClick={onProviderClick}
                  />
                ))}
              </div>
            </div>
          ))}
        </section>
      )}
    </div>
  );
};

// ─── Tone palette — matches data-v3 `tone` attribute ────────────────
const TONE = {
  finance:   { bg: 'oklch(0.94 0.04 260)', accent: 'oklch(0.55 0.16 260)', ink: 'oklch(0.30 0.10 260)' },
  hr:        { bg: 'oklch(0.94 0.04 350)', accent: 'oklch(0.60 0.16 350)', ink: 'oklch(0.32 0.10 350)' },
  security:  { bg: 'oklch(0.93 0.05 195)', accent: 'oklch(0.55 0.13 195)', ink: 'oklch(0.30 0.08 195)' },
  legal:     { bg: 'oklch(0.94 0.05 75)',  accent: 'oklch(0.60 0.14 75)',  ink: 'oklch(0.32 0.08 75)'  },
  support:   { bg: 'oklch(0.93 0.05 150)', accent: 'oklch(0.55 0.13 150)', ink: 'oklch(0.30 0.08 150)' },
  analytics: { bg: 'oklch(0.93 0.04 290)', accent: 'oklch(0.55 0.15 290)', ink: 'oklch(0.30 0.10 290)' },
};
const toneFor = (id) => TONE[id] || { bg: 'var(--paper-2)', accent: 'var(--ink)', ink: 'var(--ink)' };

// ─── Popular pill — Fiverr-style tag with icon ──────────────────────
const PopularPill = ({ pill }) => {
  const t = toneFor(pill.toneId);
  return (
    <button className="cat-popular-pill" onClick={pill.onClick}>
      <span className="cat-popular-pill-icon" style={{background: t.bg, color: t.ink}}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="20 6 9 17 4 12" />
        </svg>
      </span>
      <span className="cat-popular-pill-label">{pill.label}</span>
      <svg className="cat-popular-pill-arrow" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="9 6 15 12 9 18" />
      </svg>
    </button>
  );
};

// ─── Explore card — illustrated banner + service link list ─────────
const ExploreCard = ({ card }) => {
  const t = toneFor(card.toneId);
  return (
    <div className="cat-explore-card">
      <div className="cat-explore-card-banner" style={{background: `linear-gradient(135deg, ${t.bg} 0%, ${t.accent} 200%)`}}>
        <CardGlyph toneId={card.toneId} accent={t.accent} ink={t.ink} />
      </div>
      <div className="cat-explore-card-body">
        <div className="cat-explore-card-name">{card.name}</div>
        <div className="cat-explore-card-links">
          {card.links.map((link, idx) => (
            <a key={idx} className={`cat-explore-link${!link.itemId && card.kind === 'subcategory' ? ' cat-explore-link-soon' : ''}`}
               onClick={(e) => { e.preventDefault(); link.onClick && link.onClick(); }}>
              <span>{link.label}</span>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" style={{flexShrink: 0, opacity: 0.45}}>
                <polyline points="9 6 15 12 9 18" />
              </svg>
            </a>
          ))}
        </div>
      </div>
    </div>
  );
};

// Lightweight per-tone glyph for the banner area — keeps cards visually distinct
// without illustration assets.
const CardGlyph = ({ toneId, accent, ink }) => {
  // A simple geometric glyph that shifts per tone.
  const seed = toneId.charCodeAt(0) % 4;
  return (
    <svg viewBox="0 0 200 110" width="100%" height="100%" preserveAspectRatio="xMidYMid slice" style={{display: 'block'}}>
      <defs>
        <linearGradient id={`g-${toneId}`} x1="0" y1="0" x2="1" y2="1">
          <stop offset="0%" stopColor={accent} stopOpacity="0.18" />
          <stop offset="100%" stopColor={accent} stopOpacity="0.06" />
        </linearGradient>
      </defs>
      {seed === 0 && <>
        <circle cx="60" cy="55" r="36" fill={`url(#g-${toneId})`} />
        <rect x="100" y="30" width="70" height="50" rx="8" fill={accent} fillOpacity="0.15" />
        <rect x="115" y="45" width="40" height="6" rx="3" fill={ink} fillOpacity="0.30" />
        <rect x="115" y="58" width="26" height="6" rx="3" fill={ink} fillOpacity="0.18" />
      </>}
      {seed === 1 && <>
        <rect x="20" y="25" width="60" height="60" rx="10" fill={accent} fillOpacity="0.18" />
        <circle cx="135" cy="55" r="30" fill={`url(#g-${toneId})`} />
        <path d="M100 55 L130 35 L130 75 Z" fill={accent} fillOpacity="0.25" />
      </>}
      {seed === 2 && <>
        <rect x="30" y="35" width="50" height="40" rx="6" fill={accent} fillOpacity="0.18" />
        <rect x="90" y="25" width="50" height="60" rx="6" fill={accent} fillOpacity="0.28" />
        <rect x="150" y="40" width="34" height="30" rx="6" fill={accent} fillOpacity="0.14" />
      </>}
      {seed === 3 && <>
        <circle cx="55" cy="55" r="28" fill={accent} fillOpacity="0.22" />
        <circle cx="105" cy="55" r="20" fill={accent} fillOpacity="0.32" />
        <circle cx="150" cy="55" r="14" fill={accent} fillOpacity="0.18" />
      </>}
    </svg>
  );
};

// ─── Full catalog card — appears in the per-subcategory listing ──────
const CatalogCard = ({ item, highlighted, onCommission, onProviderClick }) => {
  const isLive = /ago|just now|m ago|h ago|s ago/.test(item.lastFulfilled);

  return (
    <div id={`cat-item-${item.id}`} className={`cat-listing-card ${highlighted ? 'cat-listing-card-highlight' : ''}`} style={{scrollMarginTop: 24}}>
      {/* Head */}
      <div>
        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, marginBottom: 8}}>
          <h3 className="serif" style={{fontSize: 21, fontWeight: 400, letterSpacing: '-0.005em', lineHeight: 1.2, margin: 0}}>
            <em>{item.title}</em>
          </h3>
          {isLive && (
            <div className="mono" style={{
              display: 'flex', alignItems: 'center', gap: 4,
              fontSize: 9.5, color: 'var(--sage-ink)', letterSpacing: '0.08em',
              textTransform: 'uppercase', fontWeight: 600, whiteSpace: 'nowrap',
            }}>
              <span style={{width: 5, height: 5, borderRadius: '50%', background: 'var(--sage)', animation: 'pulse 1.5s infinite'}} />
              Live
            </div>
          )}
        </div>
        <p style={{fontSize: 13.5, lineHeight: 1.45, color: 'var(--ink-2)', margin: 0}}>
          {item.tagline}
        </p>
      </div>

      {/* Price band */}
      <div style={{padding: '10px 12px', background: 'var(--paper-2)', borderRadius: 8, display: 'flex', alignItems: 'baseline', justifyContent: 'space-between'}}>
        <div>
          <div className="mono" style={{fontSize: 9, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 2}}>
            Price range · {item.providers} providers
          </div>
          <div className="serif" style={{fontSize: 22, letterSpacing: '-0.01em'}}>
            <em>${formatPrice(item.priceFrom)}</em>
            <span style={{color: 'var(--muted)'}}> – ${formatPrice(item.priceTo)}</span>
          </div>
          <div className="mono" style={{fontSize: 10, color: 'var(--muted)', letterSpacing: '0.04em', marginTop: 2}}>
            {item.priceUnit}
          </div>
        </div>
        <div style={{textAlign: 'right'}}>
          <div className="mono" style={{fontSize: 9, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 2}}>
            SLA
          </div>
          <div className="mono" style={{fontSize: 11, color: 'var(--ink)', letterSpacing: '0.02em'}}>
            {item.sla}
          </div>
        </div>
      </div>

      {/* Meta row */}
      <div style={{display: 'flex', flexWrap: 'wrap', gap: 5}}>
        <span className="mono" style={{fontSize: 9.5, letterSpacing: '0.1em', textTransform: 'uppercase', padding: '2px 6px', borderRadius: 3, background: 'var(--paper-2)', color: 'var(--muted)', border: '1px solid var(--rule-soft)'}}>
          {item.envelope}
        </span>
        {item.tags.map(t => (
          <span key={t} className="mono" style={{fontSize: 9, letterSpacing: '0.1em', textTransform: 'uppercase', padding: '2px 6px', borderRadius: 3, background: 'var(--paper-2)', color: 'var(--muted)', border: '1px solid var(--rule-soft)'}}>{t}</span>
        ))}
      </div>

      {/* Liveness + action */}
      <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', paddingTop: 10, borderTop: '1px dashed var(--rule-soft)', marginTop: 'auto'}}>
        <div className="mono" style={{fontSize: 10, color: 'var(--muted)', letterSpacing: '0.04em'}}>
          Last fulfilled <b style={{color: 'var(--ink-2)'}}>{item.lastFulfilled}</b>
          {' · '}
          <span
            onClick={(e) => { e.stopPropagation(); onProviderClick?.(item); }}
            style={{color: 'var(--accent-ink)', cursor: onProviderClick ? 'pointer' : 'default', textDecoration: onProviderClick ? 'underline' : 'none'}}
          >
            {item.providers} providers
          </span>
          {' · '}{item.running} running
        </div>
        <button className="btn accent" onClick={() => onCommission(item)} style={{padding: '6px 12px', fontSize: 11}}>
          Commission →
        </button>
      </div>
    </div>
  );
};

const formatPrice = (p) => p >= 100 ? p.toLocaleString() : p.toFixed(p < 1 ? 2 : 0);

window.CatalogView = CatalogView;
