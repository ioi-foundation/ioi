// Contract card — primary object on the home view
const ContractCard = ({ contract, onOpen, onSwap }) => {
  const c = contract;
  return (
    <div className="contract" onClick={() => onOpen(c)}>
      <div className="contract-head">
        <div className="contract-meta mono">
          <span className="ct-id">{c.code}</span>
          <span className="sep">·</span>
          <span>Active · since {c.established.split(',')[0]}</span>
        </div>
        <div className={`contract-health ${c.health === 'warn' ? 'warn' : ''}`}>
          <span className="d" />
          {c.health === 'warn' ? 'Attention' : 'Nominal'}
        </div>
      </div>

      <h3 className="contract-outcome serif">
        <em>{c.outcome}</em>
      </h3>

      <Pulse data={c.pulse} />

      <div className="contract-substrate mono">
        <span className="k">Fulfilled by</span>
        <span className="v">{c.substrate.name}</span>
        <span className="swap" onClick={(e) => { e.stopPropagation(); onSwap(c); }}>
          swap →
        </span>
      </div>

      <div className="contract-stats">
        <div>
          <div className="contract-stat-k mono">Receipts · 30d</div>
          <div className="contract-stat-v serif">{c.receipts30d.toLocaleString()}</div>
        </div>
        <div>
          <div className="contract-stat-k mono">Spend · 30d</div>
          <div className="contract-stat-v serif">
            <em>${c.spend30d.toFixed(c.spend30d % 1 ? 2 : 0)}</em>
          </div>
        </div>
        <div>
          <div className="contract-stat-k mono">SLA</div>
          <div className="contract-stat-v serif" style={{fontSize: 15}}>
            {c.slaActual}
          </div>
        </div>
      </div>
    </div>
  );
};

// Detail view (modal-style overlay) — receipt stream is the center.
// Completed contracts render read-only, with a terminal banner + dispute thread / lineage link.
const ContractDetail = ({ contract, streamItems, onClose, onSwap, onPickReceipt }) => {
  const c = contract;
  const isCompleted = !!c.terminalState;
  const stream = streamItems || (isCompleted ? (COMPLETE_STREAMS?.[c.id] || []) : (STREAMS[c.id] || []));
  const alts = isCompleted ? [] : (ALTERNATIVES[c.id] || []);
  const disputeThread = isCompleted && c.dispute ? (DISPUTE_THREADS?.[c.id] || []) : [];

  return (
    <>
      <div className="detail-scrim" onClick={onClose} />
      <div className="detail" role="dialog" aria-label="Contract detail">
        <div className="detail-main">
          <div className="detail-head">
            <div style={{minWidth: 0, flex: 1}}>
              <div className="detail-eyebrow mono">
                <span style={{display:'inline-block', width: 5, height: 5, borderRadius:'50%', background: isCompleted ? 'var(--muted-2)' : (c.health === 'warn' ? 'var(--coral)' : 'var(--sage)')}} />
                {isCompleted
                  ? <>Contract {c.code} · {c.terminalState} · closed {c.closed}</>
                  : <>Contract {c.code} · active since {c.established}</>}
              </div>
              <h2 className="detail-title serif">
                <em>{c.outcome}</em>
              </h2>
            </div>
            <button className="detail-close" onClick={onClose} aria-label="Close">
              <Icon name="x" size={16} />
            </button>
          </div>

          <div className="detail-body">
            {isCompleted && <TerminalBanner contract={c} />}
            {!isCompleted && (
            <div style={{marginBottom: 20, padding:'14px 18px', background:'var(--paper-2)', border:'1px solid var(--rule-soft)', borderRadius:10}}>
              <div style={{display:'flex', justifyContent:'space-between', alignItems:'baseline'}}>
                <div className="mono" style={{fontSize:10, letterSpacing:'0.18em', textTransform:'uppercase', color:'var(--ink)', fontWeight:600}}>
                  Pulse · last {c.pulse.length} events
                </div>
                <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.08em'}}>
                  click a cell to open its receipt
                </div>
              </div>
              <PulseScrubber
                data={c.pulse}
                streamLength={stream.length}
                onPickReceipt={(i) => onPickReceipt && onPickReceipt(c.id, i)}
              />
            </div>
            )}
            <div className="stream-label">
              <span className="stream-label-k mono">
                {isCompleted ? 'Receipt stream · archived' : 'Receipt stream · live'}
              </span>
              <span className="stream-label-meta mono">
                {isCompleted
                  ? `${c.receipts} total · chain sealed · audit-retrievable`
                  : `${stream.length} visible · chain intact · all signed`}
              </span>
            </div>
            <Stream items={stream} onPick={(i) => onPickReceipt && onPickReceipt(c.id, i)} />

            {disputeThread.length > 0 && (
              <DisputeThread thread={disputeThread} dispute={c.dispute} />
            )}
          </div>
        </div>

        <aside className="detail-side">
          <div>
            <div className="side-section-label mono">The outcome</div>
            <div className="side-outcome-box">
              "{c.promise}"
              <div className="side-outcome-sub mono">SLA target · {c.slaTarget} · actual {c.slaActual}</div>
            </div>
          </div>

          <div>
            <div className="side-section-label mono">Fulfilled by</div>
            <div className="provider">
              <div className="provider-head">
                <div style={{minWidth: 0, flex: 1}}>
                  <h4 className="provider-name serif"><em>{c.substrate.name}</em></h4>
                  <div className="provider-sub mono">{c.substrate.model}</div>
                </div>
              </div>
              <div className="provider-bars">
                <div className="provider-bar-row">
                  <span className="provider-bar-k">SLA attain</span>
                  <div className="provider-bar-track"><div className="provider-bar-fill" style={{width: '96%'}}/></div>
                  <span className="provider-bar-v">96%</span>
                </div>
                <div className="provider-bar-row">
                  <span className="provider-bar-k">Envelope fit</span>
                  <div className="provider-bar-track"><div className="provider-bar-fill" style={{width: '100%'}}/></div>
                  <span className="provider-bar-v">100%</span>
                </div>
                <div className="provider-bar-row">
                  <span className="provider-bar-k">Unit cost</span>
                  <div className="provider-bar-track"><div className="provider-bar-fill" style={{width: '58%', background: 'var(--muted-2)'}}/></div>
                  <span className="provider-bar-v">median</span>
                </div>
              </div>
              {!isCompleted && (
                <div className="provider-actions">
                  <button className="provider-action" onClick={() => onSwap(c)}>Swap provider</button>
                  <button className="provider-action primary">Open contract</button>
                </div>
              )}
              {isCompleted && (
                <div className="mono" style={{padding:'10px 12px', fontSize:10, color:'var(--muted)', letterSpacing:'0.04em', borderTop:'1px dashed var(--rule-soft)', marginTop:10}}>
                  Engagement closed {c.closed} · receipts archived · no further actions
                </div>
              )}
            </div>
          </div>

          {isCompleted && c.lineage && (
            <div>
              <div className="side-section-label mono">Lineage</div>
              <div style={{padding:'14px 16px', border:'1px solid var(--rule-soft)', background:'var(--accent-soft)', borderRadius:10}}>
                <div className="mono" style={{fontSize:10, letterSpacing:'0.14em', textTransform:'uppercase', color:'var(--accent-ink)', marginBottom:4, fontWeight:600}}>
                  {c.lineage.kind === 'scope-expansion' ? 'Scope expansion' : 'Superseded'}
                </div>
                <div style={{fontSize:13, lineHeight:1.4, color:'var(--ink)'}}>
                  Replaced mid-flight by <span className="mono" style={{color:'var(--accent-ink)', fontWeight:600}}>{c.lineage.supersededBy}</span>.
                  Forward-linked chain · envelope inherited.
                </div>
              </div>
            </div>
          )}

          {alts.length > 0 && (
            <div>
              <div className="side-section-label mono">Interchangeable substrate · {alts.length}</div>
              <div className="alts">
                {alts.map(a => (
                  <div key={a.id} className="alt" onClick={() => onSwap(c, a)}>
                    <div>
                      <div className="alt-name serif">{a.name}</div>
                      <div className="alt-meta mono">{a.meta}</div>
                    </div>
                    <div className="alt-price mono">
                      ${a.price.toFixed(a.price % 1 ? 2 : 0)}<span style={{color:'var(--muted)'}}> {a.unit}</span>
                      <div><span className={a.diff < 0 ? 'diff-down' : 'diff-up'}>{a.diff > 0 ? '+' : ''}{a.diff}%</span></div>
                    </div>
                    <span className="alt-swap">swap →</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          <div>
            <div className="side-section-label mono">Policy envelope</div>
            <div className="envelope-mini">
              <div className="envelope-mini-head mono">
                <span className="name">{c.envelope.name}</span>
                <span className="state">enforced · 0 drift</span>
              </div>
              <div className="envelope-mini-rules mono">
                {(c.envelope.rules || []).map((r, i) => <span key={i}>{r}</span>)}
                {isCompleted && !c.envelope.rules && (
                  <span style={{color:'var(--muted)'}}>Envelope archived with contract</span>
                )}
              </div>
            </div>
          </div>
        </aside>
      </div>
    </>
  );
};

// Terminal banner shown at the top of a completed contract's detail body.
const TERMINAL_BANNER = {
  completed:  { label:'Completed on schedule', bg:'oklch(0.95 0.03 185)', fg:'var(--sage-ink)', border:'oklch(0.85 0.08 185 / 0.4)' },
  superseded: { label:'Superseded',             bg:'var(--accent-soft)',  fg:'var(--accent-ink)', border:'oklch(0.85 0.08 270 / 0.4)' },
  disputed:   { label:'Disputed · resolved',    bg:'oklch(0.96 0.06 25)', fg:'var(--coral-ink)', border:'oklch(0.85 0.08 25 / 0.5)' },
};

const TerminalBanner = ({ contract: c }) => {
  const t = TERMINAL_BANNER[c.terminalState] || TERMINAL_BANNER.completed;
  return (
    <div style={{
      marginBottom: 20, padding:'16px 20px',
      background: t.bg, border:`1px solid ${t.border}`,
      borderRadius:10,
      display:'grid', gridTemplateColumns:'auto 1fr auto', gap:16, alignItems:'center',
    }}>
      <div className="mono" style={{
        fontSize:10, letterSpacing:'0.14em', textTransform:'uppercase',
        padding:'3px 9px', borderRadius:3,
        background: t.fg, color:'var(--paper)', fontWeight:600,
      }}>
        {t.label}
      </div>
      <div style={{fontSize:13, lineHeight:1.45, color:'var(--ink-2)'}}>{c.terminalNote}</div>
      <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.04em', textAlign:'right'}}>
        {c.durationDays}d · {c.receipts} receipts<br/>
        ${(c.totalSpend || 0).toLocaleString()} total
      </div>
    </div>
  );
};

// Dispute thread — chronological log of dispute-specific events.
const THREAD_STYLE = {
  filed:     { fg:'var(--coral-ink)',  bg:'oklch(0.96 0.06 25)' },
  responded: { fg:'var(--ink-2)',      bg:'var(--paper-2)' },
  accepted:  { fg:'var(--ink-2)',      bg:'var(--paper-2)' },
  requested: { fg:'var(--accent-ink)', bg:'var(--accent-soft)' },
  provided:  { fg:'var(--ink-2)',      bg:'var(--paper-2)' },
  ruled:     { fg:'var(--sage-ink)',   bg:'oklch(0.95 0.03 185)' },
};

const DisputeThread = ({ thread, dispute }) => (
  <div style={{marginTop:28}}>
    <div style={{display:'flex', alignItems:'baseline', justifyContent:'space-between', marginBottom:12}}>
      <div className="mono" style={{fontSize:10, letterSpacing:'0.18em', textTransform:'uppercase', color:'var(--ink)', fontWeight:600}}>
        Dispute thread · {thread.length} events
      </div>
      <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.04em'}}>
        Arbiter: {dispute?.arbiter} · resolved {dispute?.resolvedOn}
      </div>
    </div>
    <div style={{border:'1px solid var(--rule-soft)', borderRadius:10, background:'var(--paper)', overflow:'hidden'}}>
      {thread.map((t, i) => {
        const st = THREAD_STYLE[t.label] || THREAD_STYLE.responded;
        return (
          <div key={i} style={{
            display:'grid', gridTemplateColumns:'100px 1fr', gap:14,
            padding:'12px 16px',
            borderBottom: i < thread.length - 1 ? '1px solid var(--rule-soft)' : 'none',
          }}>
            <div>
              <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.04em', marginBottom:3}}>{t.ts}</div>
              <div className="serif" style={{fontSize:13}}>{t.who}</div>
            </div>
            <div>
              <span className="mono" style={{
                display:'inline-block', marginBottom:6,
                fontSize:9, letterSpacing:'0.12em', textTransform:'uppercase', fontWeight:600,
                padding:'2px 7px', borderRadius:3,
                background: st.bg, color: st.fg,
              }}>{t.label}</span>
              <div style={{fontSize:13, lineHeight:1.5, color:'var(--ink-2)'}}>{t.text}</div>
            </div>
          </div>
        );
      })}
    </div>
  </div>
);

window.ContractCard = ContractCard;
window.ContractDetail = ContractDetail;
