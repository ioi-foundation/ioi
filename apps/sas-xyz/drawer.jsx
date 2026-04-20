// Service detail drawer
const Drawer = ({ service, onClose, onActivate }) => {
  if (!service) return null;
  return (
    <>
      <div className="scrim" onClick={onClose} />
      <div className="drawer" role="dialog" aria-label="Service dossier">
        <div className="drawer-head">
          <div style={{minWidth:0}}>
            <div className="drawer-eyebrow">
              <span className="dot" />
              Dossier · SVC {service.seq} · Vetted
            </div>
            <h2 className="drawer-title"><em>{service.outcome}</em></h2>
            <div className="drawer-provider">
              <strong>{service.name}</strong> &nbsp;·&nbsp; Provider: <strong>{service.provider}</strong>
            </div>
          </div>
          <button className="drawer-close" onClick={onClose} aria-label="Close">
            <Icon name="x" size={16} />
          </button>
        </div>

        <div className="drawer-body">
          <section className="section">
            <div className="section-label">
              <span>Engagement summary</span>
              <span className="right">Tags · {service.tags.join(' / ')}</span>
            </div>
            <div className="outcome-card">
              <p className="desc" style={{fontSize:15, color:'var(--ink-2)', lineHeight:1.55}}>{service.description}</p>
            </div>
          </section>

          <section className="section">
            <div className="section-label"><span>Governance</span></div>
            <div className="split-2">
              <div className="chip-card sage">
                <div className="k">Policy envelope · Alpha</div>
                <div className="v">“{service.policy}”</div>
              </div>
              <div className="chip-card accent">
                <div className="k">Recourse class IV</div>
                <div className="v">{service.recourse}</div>
              </div>
            </div>
          </section>

          <section className="section">
            <div className="section-label"><span>Operational anatomy</span></div>
            <div className="anatomy-table">
              <div className="anatomy-row">
                <div className="anatomy-k">Runtime posture</div>
                <div className="anatomy-v">{service.execution}</div>
                <div className="anatomy-note"><PostureBadge posture={service.execution} postureKey={service.postureKey}/></div>
              </div>
              <div className="anatomy-row">
                <div className="anatomy-k">Privacy class</div>
                <div className="anatomy-v">{service.privacy}</div>
                <div className="anatomy-note">Enforced at VPC boundary</div>
              </div>
              <div className="anatomy-row">
                <div className="anatomy-k">Evidence chain</div>
                <div className="anatomy-v">{service.evidence}</div>
                <div className="anatomy-note">SHA-256 signed</div>
              </div>
              <div className="anatomy-row">
                <div className="anatomy-k">Settlement logic</div>
                <div className="anatomy-v">{service.settlement}</div>
                <div className="anatomy-note">Net 15 · ACH</div>
              </div>
            </div>
          </section>

          <section className="section">
            <div className="section-label"><span>Connects to</span><span className="right">{service.connects.length} systems</span></div>
            <div className="connects">
              {service.connects.map(c => (
                <span key={c} className="connect-chip"><span className="sq"/>{c}</span>
              ))}
            </div>
          </section>

          <div className="procure-card">
            <div className="procure-top">
              <div>
                <div className="procure-label">Outcome pricing</div>
                <div className="procure-price">
                  <em>${service.price.toFixed(service.price % 1 ? 2 : 0)}</em>
                  <span className="u">{service.priceUnit}</span>
                </div>
              </div>
              <div className="procure-status">
                <div className="procure-label">Availability</div>
                <span className="status-pill">Dormant · Ready</span>
              </div>
            </div>
            <button className="procure-btn" onClick={() => onActivate(service.id)}>
              <Icon name="zap" size={14}/> Procure & Connect
            </button>
            <div className="procure-foot">
              Activation initiates a bonded deployment handshake. Approval via Corporate Policy 2026.4 is pre-verified. Reversible within 24h.
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

window.Drawer = Drawer;
