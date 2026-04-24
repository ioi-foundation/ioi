// Service detail drawer
const EvidenceSample = ({ sample }) => {
  if (!sample) return null;
  return (
    <div className="evidence-doc">
      <div className="evidence-doc-head">
        <div>
          <div className="evidence-doc-title serif-italic">{sample.title}</div>
          <div className="evidence-doc-meta mono">{sample.filename} · {sample.ts}</div>
        </div>
        <div className="evidence-doc-seal">
          <div className="evidence-seal-ring">
            <div className="evidence-seal-inner serif-italic">S</div>
          </div>
          <div className="evidence-seal-label mono">SEALED</div>
        </div>
      </div>

      <div className="evidence-doc-body mono">
        {sample.lines.map((l, i) => (
          <div key={i} className={`evidence-line ${l.ok ? 'ok' : 'flag'}`}>
            <span className="ev-k">{l.k}</span>
            <span className="ev-v">{l.v}</span>
            <span className="ev-s">{l.s}</span>
          </div>
        ))}
      </div>

      <div className="evidence-doc-summary serif-italic">{sample.summary}</div>

      <div className="evidence-doc-foot">
        <div className="evidence-foot-col">
          <div className="evidence-foot-k mono">Evidence hash</div>
          <div className="evidence-foot-v mono">{sample.hash}</div>
        </div>
        <div className="evidence-foot-col">
          <div className="evidence-foot-k mono">Signed by</div>
          <div className="evidence-foot-v mono">{sample.signer}</div>
        </div>
      </div>

      <div className="evidence-doc-actions">
        <a className="evidence-action">Verify on-chain <Icon name="arrow" size={12}/></a>
        <a className="evidence-action">Open full artifact <Icon name="arrow" size={12}/></a>
      </div>
    </div>
  );
};

const Drawer = ({ service, onClose, onActivate }) => {
  const [handshake, setHandshake] = React.useState(null); // null | {step, running}
  React.useEffect(() => { setHandshake(null); }, [service && service.id]);
  if (!service) return null;

  const HANDSHAKE_STEPS = [
    'Policy envelope 2026.4 matched',
    'Bond escrowed · $' + service.price.toFixed(service.price % 1 ? 2 : 0),
    'Runtime sandbox provisioned',
    'Evidence chain initialized',
    'Awaiting first outcome',
  ];

  const beginHandshake = () => {
    if (handshake) return;
    setHandshake({ step: 0 });
    let i = 0;
    const advance = () => {
      i += 1;
      if (i < HANDSHAKE_STEPS.length) {
        setHandshake({ step: i });
        setTimeout(advance, 420);
      } else {
        setHandshake({ step: i, done: true });
        setTimeout(() => onActivate(service.id), 600);
      }
    };
    setTimeout(advance, 420);
  };
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
            <div className="section-label"><span>Evidence sample</span><span className="right">Signed artifact · SHA-256</span></div>
            <EvidenceSample sample={EVIDENCE_SAMPLES[service.id]} />
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
                {handshake ? (
                  <span className="status-pill handshake">
                    {handshake.done ? 'Live · Connected' : 'Handshake in progress'}
                  </span>
                ) : (
                  <span className="status-pill">Dormant · Ready</span>
                )}
              </div>
            </div>

            {handshake && (
              <div className="handshake-log mono">
                {HANDSHAKE_STEPS.map((s, i) => {
                  const state = i < handshake.step ? 'done' : i === handshake.step ? 'active' : 'pending';
                  const glyph = state === 'done' ? '[✓]' : state === 'active' ? '[▸]' : '[ ]';
                  return (
                    <div key={i} className={`hs-row ${state}`}>
                      <span className="hs-glyph">{glyph}</span>
                      <span className="hs-label">{s}</span>
                      {state === 'active' && <span className="hs-tail"><AsciiBar slots={8} hz={10}/></span>}
                    </div>
                  );
                })}
              </div>
            )}

            <button
              className="procure-btn"
              onClick={beginHandshake}
              disabled={!!handshake}
              style={handshake ? { opacity: 0.7, cursor: 'default' } : undefined}
            >
              {handshake
                ? (handshake.done ? <>Connected <Icon name="zap" size={14}/></> : <>Handshaking… <AsciiBar slots={10} hz={12}/></>)
                : <><Icon name="zap" size={14}/> Procure & Connect</>
              }
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
