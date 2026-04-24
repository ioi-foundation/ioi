// Service Catalog page
const { useState, useMemo } = React;

// --- URL hash serialization for filter state ---
const parseHash = () => {
  const h = (typeof window !== 'undefined' ? window.location.hash : '').replace(/^#/, '');
  const params = new URLSearchParams(h);
  const v = params.get('view');
  return {
    view: (v === 'ledger' || v === 'list') ? 'list' : 'grid',
    filter: params.get('domain') || null,
    postureFilter: params.get('posture') || null,
  };
};
const writeHash = ({ view, filter, postureFilter }) => {
  const params = new URLSearchParams();
  if (view === 'list') params.set('view', 'ledger');
  if (filter) params.set('domain', filter);
  if (postureFilter) params.set('posture', postureFilter);
  const next = params.toString();
  const target = next ? `#${next}` : '';
  if (window.location.hash !== target) {
    history.replaceState(null, '', window.location.pathname + window.location.search + target);
  }
};

const PostureBadge = ({ posture, postureKey, onClick, isActive, size }) => {
  const clickable = !!onClick;
  return (
    <span
      className={`posture-badge ${postureKey} ${clickable ? 'is-clickable' : ''} ${isActive ? 'is-active' : ''} ${size === 'sm' ? 'is-sm' : ''}`}
      onClick={clickable ? (e) => { e.stopPropagation(); onClick(); } : undefined}
      role={clickable ? 'button' : undefined}
      title={clickable ? `Filter by ${posture}` : undefined}
    >
      <span className="d" />
      {posture}
    </span>
  );
};

const Dossier = ({ service, onClick }) => {
  const [hover, setHover] = useState(false);
  return (
  <div className="dossier" onClick={onClick}
       onMouseEnter={() => setHover(true)}
       onMouseLeave={() => setHover(false)}>
    <div className="dossier-head">
      <div className="dossier-id">
        <span className="seq">SVC · {service.seq}</span>
        <div style={{marginTop:4, color:'var(--muted)'}}>{service.tags.join(' · ')}</div>
        <AsciiPosture postureKey={service.postureKey} animated={hover} />
      </div>
      <PostureBadge posture={service.execution} postureKey={service.postureKey} />
    </div>

    <div className="dossier-outcome-label">Outcome</div>
    <div className="dossier-outcome serif"><em>{service.outcome}</em></div>
    <div className="dossier-desc">{service.description}</div>

    <div className="dossier-meta">
      <div className="meta-row">
        <div className="meta-k">Provider</div>
        <div className="meta-v">{service.provider}</div>
      </div>
      <div className="meta-row">
        <div className="meta-k">Evidence</div>
        <div className="meta-v">{service.evidence}</div>
      </div>
      <div className="meta-row full">
        <div className="meta-k">Policy Envelope</div>
        <div className="meta-v policy">“{service.policy}”</div>
      </div>
    </div>

    <div className="dossier-foot">
      <div className="price">
        <span className="amount">${service.price.toFixed(service.price % 1 ? 2 : 0)}</span>
        <span className="unit">{service.priceUnit}</span>
      </div>
      <button className="btn">
        View dossier <Icon name="arrow" size={14} />
      </button>
    </div>
  </div>
  );
};

// Empty-state card shown when the active filter combination yields 0 matches.
// Names the conflict, offers narrow recoveries ("Relax Posture" / "Relax Domain")
// with live counts, and a total clear as last resort.
const EmptyState = ({
  filter, postureFilter, activePosture,
  countWithoutPosture, countWithoutDomain,
  onRelaxPosture, onRelaxDomain, onClearAll,
}) => {
  const facets = [];
  if (filter) facets.push(filter);
  if (activePosture) facets.push(activePosture.label);

  return (
    <div className="empty-card">
      <div className="empty-inner">
        <div className="empty-eyebrow mono">
          <span className="empty-dot" /> 0 matches · query returned empty
        </div>
        <div className="empty-head serif-italic">
          No services match this query.
        </div>
        <div className="empty-conflict mono">
          {facets.join(' · ')} <span className="empty-arrow">→</span> <b>0 matches</b>
          <div className="empty-conflict-note">
            Acme&rsquo;s catalog has no {filter && <em>{filter}</em>}{filter && postureFilter && ' · '}{activePosture && <em>{activePosture.label}-posture</em>} services procured under Policy 2026.4.
          </div>
        </div>

        <div className="empty-recoveries">
          {postureFilter && (
            <button className="empty-recovery" onClick={onRelaxPosture}>
              <span className="empty-recovery-label mono">Relax posture</span>
              <span className="empty-recovery-effect">
                Show all <b>{countWithoutPosture}</b> {filter ? <em>{filter}</em> : null} services
              </span>
              <span className="empty-recovery-arrow">→</span>
            </button>
          )}
          {filter && (
            <button className="empty-recovery" onClick={onRelaxDomain}>
              <span className="empty-recovery-label mono">Relax domain</span>
              <span className="empty-recovery-effect">
                Show all <b>{countWithoutDomain}</b> {activePosture ? <em>{activePosture.label}</em> : null} services
              </span>
              <span className="empty-recovery-arrow">→</span>
            </button>
          )}
          <button className="empty-recovery is-muted" onClick={onClearAll}>
            <span className="empty-recovery-label mono">Clear all</span>
            <span className="empty-recovery-effect">
              Show all <b>{SERVICES.length}</b> catalog services
            </span>
            <span className="empty-recovery-arrow">→</span>
          </button>
        </div>

        <div className="empty-footer mono">
          Or <a className="empty-link">draft an outcome specification →</a> to request this service.
        </div>
      </div>
    </div>
  );
};

const CatalogPage = ({ onSelect }) => {
  const initial = parseHash();
  const [filter, setFilter] = useState(initial.filter);
  const [postureFilter, setPostureFilter] = useState(initial.postureFilter);
  const [view, setView] = useState(initial.view);
  const [copied, setCopied] = useState(false);

  // Sync state → URL hash
  React.useEffect(() => {
    writeHash({ view, filter, postureFilter });
  }, [view, filter, postureFilter]);

  // Listen for back/forward
  React.useEffect(() => {
    const onHash = () => {
      const s = parseHash();
      setFilter(s.filter);
      setPostureFilter(s.postureFilter);
      setView(s.view);
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  const copyQuery = () => {
    const url = window.location.href;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(url).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1800);
      }).catch(() => {});
    }
  };

  // All distinct domain tags, derived from SERVICES
  const DOMAINS = ['Finance', 'Legal', 'DevOps', 'Security', 'HR', 'Marketing'];
  const POSTURES = [
    { k: 'autonomous', label: 'Auto' },
    { k: 'gated',      label: 'Gated' },
    { k: 'local',      label: 'Local' },
    { k: 'isolated',   label: 'Iso' },
  ];

  // Intersection counts: domain count reflects the currently-active posture filter,
  // posture count reflects the currently-active domain filter.
  const domainCount = (d) => SERVICES.filter(s =>
    s.tags.includes(d) && (!postureFilter || s.postureKey === postureFilter)
  ).length;
  const postureCount = (pk) => SERVICES.filter(s =>
    s.postureKey === pk && (!filter || s.tags.includes(filter))
  ).length;

  const togglePosture = (k) => setPostureFilter(p => p === k ? null : k);
  const toggleFilter  = (k) => setFilter(f => f === k ? null : k);
  const clearAll = () => { setFilter(null); setPostureFilter(null); };

  const visible = SERVICES.filter(s =>
    (!filter || s.tags.includes(filter)) &&
    (!postureFilter || s.postureKey === postureFilter)
  );

  const anyFilter = filter || postureFilter;
  const activePosture = POSTURES.find(p => p.k === postureFilter);
  const isEmpty = visible.length === 0 && anyFilter;

  // "Relax one facet" counts — show the user what each recovery yields.
  const countWithoutPosture = filter ? SERVICES.filter(s => s.tags.includes(filter)).length : SERVICES.length;
  const countWithoutDomain  = postureFilter ? SERVICES.filter(s => s.postureKey === postureFilter).length : SERVICES.length;

  return (
    <div className="content">
      <div className="banner">
        <span className="banner-label">Vetted</span>
        <span>Private catalog for <strong>Acme Corp Global</strong>. Approved by Legal + Infosec under Corporate Policy <strong>2026.4</strong>.</span>
        <span className="banner-cta">Policy changelog →</span>
        <AsciiRule width={200} />
      </div>

      <div className={`deltas-strip ${anyFilter ? 'is-collapsed' : ''}`}>
        {anyFilter ? (
          <button className="deltas-collapsed mono" onClick={clearAll} title="Clear filters to review catalog changes">
            <span className="deltas-collapsed-dot" />
            <span><b>{CATALOG_DELTAS.length}</b> governed changes</span>
            <span className="deltas-collapsed-sep">·</span>
            <span className="deltas-collapsed-muted">6d window</span>
            <span className="deltas-collapsed-cta">view changelog →</span>
          </button>
        ) : (
          <>
            <div className="deltas-head">
              <div className="deltas-label">
                <span className="mono">Since you last visited</span>
                <span className="deltas-meta mono">{CATALOG_DELTAS.length} governed changes · 6d window</span>
              </div>
              <a className="deltas-cta mono">View full changelog →</a>
            </div>
            <div className="deltas-row">
              {CATALOG_DELTAS.map(d => (
                <div key={d.id} className={`delta delta-${d.kind}`}>
                  <div className="delta-glyph mono">{d.glyph}</div>
                  <div className="delta-body">
                    <div className="delta-top mono">
                      <span className="delta-actor">{d.actor}</span>
                      <span className="delta-sep">·</span>
                      <span className="delta-seq">SVC {d.seq}</span>
                      <span className="delta-when">{d.when}</span>
                    </div>
                    <div className="delta-headline serif-italic">{d.headline}</div>
                    <div className="delta-detail">{d.detail}</div>
                    <div className="delta-by mono">{d.by}</div>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      <div className={`page-head ${anyFilter ? 'is-filtered' : ''}`}>
        {anyFilter ? (
          <div className="page-head-compact">
            <div className="eyebrow"><span className="bullet" /> Procurement / Service Catalog / <em>Filtered query</em></div>
            <button className="return-link mono" onClick={clearAll}>
              ← return to full catalog
            </button>
          </div>
        ) : (
          <div>
            <div className="eyebrow"><span className="bullet" /> Procurement / Service Catalog</div>
            <h1 className="page-title">Deployable <em>labor</em>,<br/>bounded by contract.</h1>
            <p className="page-lede">Every service below is a vetted, reversible commitment: a defined outcome, a runtime posture, a policy envelope, and a settlement rail. Procure what you need; the catalog enforces the rest.</p>
          </div>
        )}
        <div className="stat-strip">
          {anyFilter ? (
            <div className="stat query-readout">
              <div className="query-head">
                <span className="stat-label">Filtered view</span>
                <div className="query-actions">
                  <button
                    className={`query-copy mono ${copied ? 'is-copied' : ''}`}
                    onClick={copyQuery}
                    title="Copy shareable link to this filtered view"
                  >
                    {copied ? 'copied ✓' : 'copy query →'}
                  </button>
                  <button className="posture-clear mono" onClick={clearAll}>
                    clear all ×
                  </button>
                </div>
              </div>
              <div className="query-result">
                <span className="serif query-count">
                  {visible.length}<span className="query-of"> / {SERVICES.length}</span>
                </span>
                <span className="query-word serif-italic">services</span>
              </div>
              <div className="query-facets mono">
                {filter && (
                  <span className="query-facet">
                    <span className="query-facet-k">Domain</span>
                    <span className="query-facet-v">{filter}</span>
                    <button className="query-facet-x" onClick={() => setFilter(null)} aria-label="Clear domain">×</button>
                  </span>
                )}
                {postureFilter && (
                  <span className="query-facet">
                    <span className="query-facet-k">Posture</span>
                    <span className="query-facet-v">
                      <i className={`pl-dot seg-${postureFilter}`} />
                      {activePosture?.label}
                    </span>
                    <button className="query-facet-x" onClick={() => setPostureFilter(null)} aria-label="Clear posture">×</button>
                  </span>
                )}
              </div>
            </div>
          ) : (
            <>
              <div className="stat">
                <span className="stat-label">Active</span>
                <span className="stat-val">12</span>
              </div>
              <div className="stat-sep" />
              <div className="stat">
                <span className="stat-label">Pending</span>
                <span className="stat-val">4</span>
              </div>
              <div className="stat-sep" />
              <div className="stat">
                <span className="stat-label">Monthly</span>
                <span className="stat-val">$1.4<span className="unit">k</span></span>
              </div>
            </>
          )}
          <div className="stat-sep" />
          <div className="stat posture-stat">
            <div className="posture-stat-head">
              <span className="stat-label">Posture mix{filter ? <span className="stat-label-scope"> · in {filter}</span> : null}</span>
            </div>
            <div className="posture-bar" role="group" aria-label="Filter by runtime posture">
              {POSTURES.map(p => {
                const n = postureCount(p.k);
                const empty = n === 0;
                return (
                  <button
                    key={p.k}
                    type="button"
                    className={`posture-seg seg-${p.k} ${postureFilter === p.k ? 'is-active' : ''} ${postureFilter && postureFilter !== p.k ? 'is-dim' : ''} ${empty ? 'is-empty' : ''}`}
                    style={{flex: Math.max(n, 0.25)}}
                    onClick={() => !empty && togglePosture(p.k)}
                    disabled={empty}
                    aria-pressed={postureFilter === p.k}
                    title={`${p.label} · ${n}${empty ? ' · no matches' : ' · click to filter'}`}
                  >
                    {n > 0 && <span className="posture-seg-n mono">{n}</span>}
                  </button>
                );
              })}
            </div>
            <div className="posture-caption mono">
              {POSTURES.map((p, i) => (
                <React.Fragment key={p.k}>
                  <span className={postureFilter === p.k ? 'is-active' : ''}>{p.label}</span>
                  {i < POSTURES.length - 1 && <span className="posture-caption-sep">·</span>}
                </React.Fragment>
              ))}
            </div>
          </div>
        </div>
      </div>

      <div className="filter-row">
        <div className="filters">
          {DOMAINS.map(d => {
            const n = domainCount(d);
            const empty = n === 0;
            return (
              <div
                key={d}
                className={`filter ${filter === d ? 'active' : ''} ${empty ? 'is-empty' : ''}`}
                onClick={() => !empty && toggleFilter(d)}
              >
                {d} <span className="num">{n}</span>
              </div>
            );
          })}
        </div>
        <div className="view-switch">
          <button className={view === 'grid' ? 'active' : ''} onClick={() => setView('grid')}>
            <Icon name="grid" size={12} /> Dossier
          </button>
          <button className={view === 'list' ? 'active' : ''} onClick={() => setView('list')}>
            <Icon name="list" size={12} /> Ledger
          </button>
        </div>
      </div>

      {view === 'grid' ? (
        isEmpty ? (
          <EmptyState
            filter={filter}
            postureFilter={postureFilter}
            activePosture={activePosture}
            countWithoutPosture={countWithoutPosture}
            countWithoutDomain={countWithoutDomain}
            onRelaxPosture={() => setPostureFilter(null)}
            onRelaxDomain={() => setFilter(null)}
            onClearAll={clearAll}
          />
        ) : (
          <div className="grid">
            {visible.map(s => <Dossier key={s.id} service={s} onClick={() => onSelect(s)} />)}
            <div className="dossier request">
              <div className="request-inner">
                <div className="request-plus">+</div>
                <div className="request-title">Request a service</div>
                <div className="request-desc">Submit an outcome specification. Vendor matching, policy drafting, and pricing negotiation are handled for you.</div>
                <div className="mono" style={{fontSize:11, color:'var(--muted)', letterSpacing:'0.06em', marginTop:4}}>
                  &gt; draft outcome<AsciiCursor />
                </div>
                <button className="btn ghost" style={{marginTop:8}}>Draft specification <Icon name="arrow" size={12}/></button>
              </div>
            </div>
          </div>
        )
      ) : (
        <div className="tbl-card">
          {anyFilter && (
            <div className="ledger-query-strip mono">
              <span className="ledger-query-label">Query active</span>
              <span className="ledger-query-sep">→</span>
              {filter && (
                <span className="query-facet query-facet-inline">
                  <span className="query-facet-k">Domain</span>
                  <span className="query-facet-v">{filter}</span>
                  <button className="query-facet-x" onClick={(e) => { e.stopPropagation(); setFilter(null); }} aria-label="Clear domain">×</button>
                </span>
              )}
              {postureFilter && (
                <span className="query-facet query-facet-inline">
                  <span className="query-facet-k">Posture</span>
                  <span className="query-facet-v">
                    <i className={`pl-dot seg-${postureFilter}`} />
                    {activePosture?.label}
                  </span>
                  <button className="query-facet-x" onClick={(e) => { e.stopPropagation(); setPostureFilter(null); }} aria-label="Clear posture">×</button>
                </span>
              )}
              <span className="ledger-query-count">
                <b>{visible.length}</b> / {SERVICES.length} rows
              </span>
            </div>
          )}
          <div className="tbl-card-head" style={{gridTemplateColumns: '60px 2fr 1.4fr 1fr 1fr 120px'}}>
            <div>No.</div><div>Service</div><div>Outcome</div><div>Posture</div><div>Pricing</div><div></div>
          </div>
          {isEmpty ? (
            <EmptyState
              filter={filter}
              postureFilter={postureFilter}
              activePosture={activePosture}
              countWithoutPosture={countWithoutPosture}
              countWithoutDomain={countWithoutDomain}
              onRelaxPosture={() => setPostureFilter(null)}
              onRelaxDomain={() => setFilter(null)}
              onClearAll={clearAll}
            />
          ) : visible.map(s => (
            <div key={s.id} className="audit-row" onClick={() => onSelect(s)}
              style={{gridTemplateColumns: '60px 2fr 1.4fr 1fr 1fr 120px'}}>
              <div className="mono" style={{color:'var(--muted)', fontSize:11}}>{s.seq}</div>
              <div>
                <div className="serif" style={{fontSize:20, lineHeight:1.1}}>{s.name}</div>
                <div className="mono" style={{fontSize:10, color:'var(--muted)', marginTop:4, letterSpacing:'0.05em'}}>{s.provider}</div>
              </div>
              <div className="serif-italic" style={{fontSize:16, color:'var(--ink-2)'}}>{s.outcome}</div>
              <div>
                <PostureBadge
                  posture={s.execution}
                  postureKey={s.postureKey}
                  isActive={postureFilter === s.postureKey}
                  onClick={() => togglePosture(s.postureKey)}
                />
              </div>
              <div className="serif" style={{fontSize:18}}>
                ${s.price.toFixed(s.price % 1 ? 2 : 0)}
                <span className="mono" style={{fontSize:10, color:'var(--muted)', marginLeft:6}}>{s.priceUnit}</span>
              </div>
              <div style={{textAlign:'right'}}>
                <button className="btn ghost" style={{fontSize:11, padding:'6px 12px'}}>Open <Icon name="arrow" size={11}/></button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

window.CatalogPage = CatalogPage;
window.PostureBadge = PostureBadge;
