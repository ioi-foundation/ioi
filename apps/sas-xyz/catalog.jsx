// Service Catalog page
const { useState, useMemo } = React;

const PostureBadge = ({ posture, postureKey }) => (
  <span className={`posture-badge ${postureKey}`}>
    <span className="d" />
    {posture}
  </span>
);

const Dossier = ({ service, onClick }) => (
  <div className="dossier" onClick={onClick}>
    <div className="dossier-head">
      <div className="dossier-id">
        <span className="seq">SVC · {service.seq}</span>
        <div style={{marginTop:4, color:'var(--muted)'}}>{service.tags.join(' · ')}</div>
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

const CatalogPage = ({ onSelect }) => {
  const [filter, setFilter] = useState('All');
  const [view, setView] = useState('grid');

  const filters = [
    { k: 'All', n: SERVICES.length },
    { k: 'Finance', n: 1 },
    { k: 'Legal', n: 2 },
    { k: 'DevOps', n: 1 },
    { k: 'Security', n: 1 },
    { k: 'HR', n: 1 },
    { k: 'Marketing', n: 1 },
  ];
  const visible = filter === 'All' ? SERVICES : SERVICES.filter(s => s.tags.includes(filter));

  return (
    <div className="content">
      <div className="banner">
        <span className="banner-label">Vetted</span>
        <span>Private catalog for <strong>Acme Corp Global</strong>. Approved by Legal + Infosec under Corporate Policy <strong>2026.4</strong>.</span>
        <span className="banner-cta">Policy changelog →</span>
      </div>

      <div className="page-head">
        <div>
          <div className="eyebrow"><span className="bullet" /> Procurement / Service Catalog</div>
          <h1 className="page-title">Deployable <em>labor</em>,<br/>bounded by contract.</h1>
          <p className="page-lede">Every service below is a vetted, reversible commitment: a defined outcome, a runtime posture, a policy envelope, and a settlement rail. Procure what you need; the catalog enforces the rest.</p>
        </div>
        <div className="stat-strip">
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
          <div className="stat-sep" />
          <div className="stat">
            <span className="stat-label">Budget</span>
            <span className="stat-val">$12.4<span className="unit">k left</span></span>
          </div>
        </div>
      </div>

      <div className="filter-row">
        <div className="filters">
          {filters.map(f => (
            <div key={f.k} className={`filter ${filter === f.k ? 'active' : ''}`} onClick={() => setFilter(f.k)}>
              {f.k} <span className="num">{f.n}</span>
            </div>
          ))}
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
        <div className="grid">
          {visible.map(s => <Dossier key={s.id} service={s} onClick={() => onSelect(s)} />)}
          <div className="dossier request">
            <div className="request-inner">
              <div className="request-plus">+</div>
              <div className="request-title">Request a service</div>
              <div className="request-desc">Submit an outcome specification. Vendor matching, policy drafting, and pricing negotiation are handled for you.</div>
              <button className="btn ghost" style={{marginTop:8}}>Draft specification <Icon name="arrow" size={12}/></button>
            </div>
          </div>
        </div>
      ) : (
        <div className="tbl-card">
          <div className="tbl-card-head" style={{gridTemplateColumns: '60px 2fr 1.4fr 1fr 1fr 120px'}}>
            <div>No.</div><div>Service</div><div>Outcome</div><div>Posture</div><div>Pricing</div><div></div>
          </div>
          {visible.map(s => (
            <div key={s.id} className="audit-row" onClick={() => onSelect(s)}
              style={{gridTemplateColumns: '60px 2fr 1.4fr 1fr 1fr 120px'}}>
              <div className="mono" style={{color:'var(--muted)', fontSize:11}}>{s.seq}</div>
              <div>
                <div className="serif" style={{fontSize:20, lineHeight:1.1}}>{s.name}</div>
                <div className="mono" style={{fontSize:10, color:'var(--muted)', marginTop:4, letterSpacing:'0.05em'}}>{s.provider}</div>
              </div>
              <div className="serif-italic" style={{fontSize:16, color:'var(--ink-2)'}}>{s.outcome}</div>
              <div><PostureBadge posture={s.execution} postureKey={s.postureKey}/></div>
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
