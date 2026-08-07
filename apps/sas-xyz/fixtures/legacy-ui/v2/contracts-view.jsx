// Contracts view — dual-axis sub-nav.
// Lifecycle (instances): Draft · Active · Complete   |   Library (templates): Envelopes

const ContractsView = ({
  contracts, draftsList, completes,
  onOpenContract, onSwap, onDraft, onResumeDraft, onDiscardDraft,
  embedded = false,
  railRef = null,
}) => {
  const [sub, setSub] = React.useState('contracts');
  const [filter, setFilter] = React.useState('all'); // all | draft | active | complete
  const [completeFilter, setCompleteFilter] = React.useState('all');

  const totalReceipts = contracts.reduce((a, c) => a + c.receipts30d, 0);

  const filteredCompletes = completes.filter(c =>
    completeFilter === 'all' ? true : c.terminalState === completeFilter
  );

  const showActive   = filter === 'all' || filter === 'active';
  const showDrafts   = filter === 'all' || filter === 'draft';
  const showComplete = filter === 'all' || filter === 'complete';

  // Sidebar icon SVGs
  const SidebarIcon = ({ name }) => {
    const icons = {
      explore: (
        <svg className="sidebar-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
      ),
      active: (
        <svg className="sidebar-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10" />
          <polyline points="12 6 12 12 16 14" />
        </svg>
      ),
      drafts: (
        <svg className="sidebar-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
          <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
        </svg>
      ),
      completed: (
        <svg className="sidebar-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="20 6 9 17 4 12" />
        </svg>
      ),
      saved: (
        <svg className="sidebar-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M20.84 4.61a5.5 5.5 0 0 0-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 0 0-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 0 0 0-7.78z" />
        </svg>
      ),
      search: (
        <svg className="sidebar-icon" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="11" cy="11" r="8" />
          <line x1="21" y1="21" x2="16.65" y2="16.65" />
        </svg>
      ),
    };
    return icons[name] || null;
  };

  return (
    <div className={embedded ? '' : 'page'}>
      {/* ─── Sub-nav: Contracts (unified) · Envelopes (library) ─── */}
      {!embedded && (
        <div style={{
          display:'flex', alignItems:'center', gap:4,
          padding:'0 0 0',
          borderBottom:'1px solid var(--rule-soft)',
          marginBottom: 32,
        }}>
          <SubTab active={sub === 'contracts'} onClick={() => setSub('contracts')}>
            Contracts <Count>{contracts.length + draftsList.length + completes.length}</Count>
          </SubTab>

          <div style={{width:1, height:22, background:'var(--rule)', margin:'0 14px 0 10px', alignSelf:'center'}} />

          <SubTab active={sub === 'envelopes'} onClick={() => setSub('envelopes')}>
            Envelopes
            <span className="mono" style={{fontSize:9, letterSpacing:'0.14em', textTransform:'uppercase', marginLeft:8, color:'var(--muted-2)', fontWeight:400}}>
              library
            </span>
          </SubTab>

          <div style={{flex:1}} />
          <button className="btn accent" onClick={() => onDraft('')} style={{padding:'8px 14px', fontSize:12}}>
            + New contract
          </button>
        </div>
      )}

      {/* ─── CONTRACTS (unified) ─── */}
      {(embedded || sub === 'contracts') && (
        <div data-screen-label="01 Contracts">
          {/* Command Center strip — birds-eye view */}
          {!embedded && (
            <div className="cmd-strip">
            <div className="cmd-cell">
              <div className="cmd-cell-k">active contracts</div>
              <div className="cmd-cell-v">{contracts.length}</div>
              <div className="cmd-cell-sub good">all healthy</div>
            </div>
            <div className="cmd-cell">
              <div className="cmd-cell-k">sla · rolling 7d</div>
              <div className="cmd-cell-v">99.94<span className="unit">%</span></div>
              <div className="cmd-cell-sub good">+0.02 vs last week</div>
            </div>
            <div className="cmd-cell">
              <div className="cmd-cell-k">receipts · 30d</div>
              <div className="cmd-cell-v">{totalReceipts.toLocaleString()}</div>
              <div className="cmd-cell-sub">across {contracts.length} contracts</div>
            </div>
            <div className="cmd-cell">
              <div className="cmd-cell-k">in escrow now</div>
              <div className="cmd-cell-v">${contracts.reduce((a,c) => a + (c.spend30d || 0) * 3, 0).toLocaleString()}</div>
              <div className="cmd-cell-sub">staged · releases on receipt</div>
            </div>
            <div className="cmd-cell">
              <div className="cmd-cell-k">saved vs. seat-saas</div>
              <div className="cmd-cell-v">$12,400</div>
              <div className="cmd-cell-sub good">this month · no idle hours</div>
            </div>
            </div>
          )}

          {/* Live ticker — receipt events streaming across all contracts */}
          {!embedded && (
          <div style={{
            display:'flex', alignItems:'center', gap:14,
            padding:'10px 20px', marginTop:-24, marginBottom:32,
            border:'1px solid var(--rule-soft)', borderTop:0,
            borderRadius:'0 0 12px 12px', background:'var(--paper-2)',
          }}>
            <span className="mono" style={{fontSize:9, letterSpacing:'0.18em', textTransform:'uppercase', color:'var(--muted-2)', whiteSpace:'nowrap', flexShrink:0}}>
              <span style={{display:'inline-block', width:5, height:5, borderRadius:'50%', background:'var(--sage)', marginRight:6, verticalAlign:'middle'}} />
              live feed
            </span>
            <AsciiTicker style={{flex:1, minWidth:0}} />
            </div>
          )}

          <div className={embedded ? "ui-split-layout" : ""}>
            {/* Filter pills or sidebar */}
            {embedded ? (
              <div className="ui-sidebar-nav">
                <button className={'ui-sidebar-link' + (filter === 'all' ? ' active' : '')} onClick={() => setFilter('all')}>
                  <SidebarIcon name="explore" />
                  Keep exploring
                </button>
                <button className={'ui-sidebar-link' + (filter === 'active' ? ' active' : '')} onClick={() => setFilter('active')}>
                  <SidebarIcon name="active" />
                  Active contracts
                </button>
                <button className={'ui-sidebar-link' + (filter === 'draft' ? ' active' : '')} onClick={() => setFilter('draft')}>
                  <SidebarIcon name="drafts" />
                  Drafts in flight
                </button>
                <button className={'ui-sidebar-link' + (filter === 'complete' ? ' active' : '')} onClick={() => setFilter('complete')}>
                  <SidebarIcon name="completed" />
                  Completed
                </button>
                <div style={{height: 1, background: 'var(--rule-soft)', margin: '8px 0'}} />
                <button className="ui-sidebar-link" style={{color: 'var(--muted-2)', fontSize: 14}}>
                  <SidebarIcon name="saved" />
                  Saved services
                </button>
              </div>
            ) : (
              <div className="section-head">
                <div>
                  <h2 className="section-title serif">Your contracts</h2>
                  <p className="section-sub mono" style={{marginTop:6}}>
                    One list · filter by state · sorted by recency
                  </p>
                </div>
                <div style={{display:'flex', gap:6}}>
                  {[
                    { id:'all',      label:'All',      n: contracts.length + draftsList.length + completes.length },
                    { id:'active',   label:'Active',   n: contracts.length },
                    { id:'draft',    label:'Draft',    n: draftsList.length },
                    { id:'complete', label:'Complete', n: completes.length },
                  ].map(f => (
                    <div key={f.id} onClick={() => setFilter(f.id)} className="mono" style={{
                      fontSize:11, letterSpacing:'0.04em',
                      padding:'5px 11px', borderRadius:999, cursor:'pointer',
                      background: filter === f.id ? 'var(--ink)' : 'var(--paper)',
                      color: filter === f.id ? 'var(--paper)' : 'var(--ink-2)',
                      border:'1px solid ' + (filter === f.id ? 'var(--ink)' : 'var(--rule-soft)'),
                    }}>
                      {f.label} <span style={{opacity:0.6}}>({f.n})</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="ui-split-content">


          {/* Active contracts — the signal */}
          {showActive && contracts.length > 0 && (
            <>
              {filter === 'all' && (
                <div className="mono" style={{fontSize:9.5, letterSpacing:'0.16em', textTransform:'uppercase', color:'var(--muted-2)', marginBottom:12}}>
                  Active · <span style={{color:'var(--sage-ink)'}}>{contracts.length}</span>
                </div>
              )}
              {embedded ? (
                /* Horizontal rail mode for embedded (Home view) */
                <div className="ui-contract-rail" ref={railRef}>
                  {contracts.map(c => (
                    <ContractCard key={c.id} contract={c} onOpen={onOpenContract} onSwap={onSwap} compact />
                  ))}
                </div>
              ) : (
                <div className="contracts">
                  {contracts.map(c => (
                    <ContractCard key={c.id} contract={c} onOpen={onOpenContract} onSwap={onSwap} />
                  ))}
                </div>
              )}
            </>
          )}

          {/* Drafts — dashed cards, less prominent */}
          {showDrafts && draftsList.length > 0 && (
            <>
              <div className="mono" style={{
                fontSize:9.5, letterSpacing:'0.16em', textTransform:'uppercase',
                color:'var(--muted-2)',
                margin: filter === 'all' ? '36px 0 12px' : '0 0 12px',
                display:'flex', alignItems:'center', gap:10,
              }}>
                <span>Drafts · <span style={{color:'var(--coral-ink)'}}>{draftsList.length}</span></span>
                <span style={{flex:1, height:1, background:'var(--rule-soft)'}} />
                <span style={{fontSize:9, color:'var(--muted-2)', letterSpacing:'0.12em', textTransform:'none', fontStyle:'italic'}}>
                  resume · not yet running
                </span>
              </div>
              <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(380px, 1fr))', gap:12}}>
                {draftsList.map(d => <DraftCard key={d.id} draft={d} onResume={onResumeDraft} onDiscard={onDiscardDraft} />)}
              </div>
            </>
          )}

          {/* Completes — compact rows, archival */}
          {showComplete && completes.length > 0 && (
            <>
              <div className="mono" style={{
                fontSize:9.5, letterSpacing:'0.16em', textTransform:'uppercase',
                color:'var(--muted-2)',
                margin: filter === 'all' ? '36px 0 12px' : '0 0 12px',
                display:'flex', alignItems:'center', gap:10,
              }}>
                <span>Complete · <span>{filteredCompletes.length}</span></span>
                <span style={{flex:1, height:1, background:'var(--rule-soft)'}} />
                <div style={{display:'flex', gap:4}}>
                  {[
                    { id:'all',        label:'All' },
                    { id:'completed',  label:'Completed' },
                    { id:'superseded', label:'Superseded' },
                    { id:'disputed',   label:'Disputed' },
                  ].map(f => (
                    <span key={f.id} onClick={() => setCompleteFilter(f.id)} style={{
                      fontSize:9, letterSpacing:'0.12em', textTransform:'uppercase',
                      padding:'2px 8px', borderRadius:999, cursor:'pointer',
                      background: completeFilter === f.id ? 'var(--ink)' : 'transparent',
                      color: completeFilter === f.id ? 'var(--paper)' : 'var(--muted)',
                      border:'1px solid ' + (completeFilter === f.id ? 'var(--ink)' : 'var(--rule-soft)'),
                    }}>
                      {f.label}
                    </span>
                  ))}
                </div>
              </div>

              <div style={{display:'flex', flexDirection:'column', gap:10}}>
                {filteredCompletes.map(c => <CompleteRow key={c.id} c={c} onOpen={onOpenContract} />)}
              </div>
            </>
          )}

          {/* Empty state — only when filter yields nothing */}
          {((filter === 'active'   && contracts.length === 0) ||
            (filter === 'draft'    && draftsList.length === 0) ||
            (filter === 'complete' && filteredCompletes.length === 0)) && (
            <div style={{padding:'60px 20px', textAlign:'center'}}>
              <div className="mono" style={{fontSize:10, color:'var(--muted-2)', letterSpacing:'0.14em', textTransform:'uppercase'}}>
                nothing in this state
              </div>
              <div className="serif" style={{fontSize:17, color:'var(--ink-2)', marginTop:10}}>
                {filter === 'draft'    && 'No drafts in flight. Start one?'}
                {filter === 'active'   && 'No active contracts. Draft one to begin.'}
                {filter === 'complete' && 'Nothing has terminated yet.'}
              </div>
              {filter !== 'complete' && (
                <button className="btn accent" onClick={() => onDraft('')} style={{marginTop:18, padding:'8px 16px', fontSize:12}}>
                  + New contract
                </button>
              )}
            </div>
          )}
          </div>
        </div>
        </div>
      )}

      {/* ─── ENVELOPES (library) ─── */}
      {sub === 'envelopes' && (
        <div data-screen-label="01 Contracts · Envelopes">
          <EnvelopeEditor />
        </div>
      )}
    </div>
  );
};

// ─── Primitives ─────────────────────────────────────────────────────
const SubTab = ({ active, onClick, children }) => (
  <button onClick={onClick} className="mono" style={{
    padding:'12px 16px 14px',
    fontSize:12, letterSpacing:'0.04em',
    background:'transparent', border:'none',
    borderBottom: active ? '2px solid var(--ink)' : '2px solid transparent',
    marginBottom:-1,
    color: active ? 'var(--ink)' : 'var(--muted)',
    fontWeight: active ? 600 : 400,
    cursor:'pointer',
    display:'flex', alignItems:'center', gap:8,
  }}>
    {children}
  </button>
);

const Count = ({ children }) => (
  <span className="mono" style={{
    fontSize:10, padding:'1px 6px', borderRadius:999,
    background:'var(--paper-2)', color:'var(--muted)',
    fontWeight:500, letterSpacing:'0.02em', minWidth:14, textAlign:'center',
  }}>{children}</span>
);

// ─── Draft card ────────────────────────────────────────────────────
const DraftCard = ({ draft, onResume, onDiscard }) => (
  <div
    onClick={() => onResume(draft)}
    style={{
      padding:'18px 20px',
      border: draft.blocked ? '1px solid oklch(0.85 0.08 25 / 0.5)' : '1px solid var(--rule-soft)',
      background:'var(--paper)',
      borderRadius:12,
      cursor:'pointer',
      display:'flex', flexDirection:'column', gap:12,
      position:'relative',
    }}
  >
    <div style={{display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:10}}>
      <div className="mono" style={{fontSize:10, letterSpacing:'0.16em', textTransform:'uppercase', color:'var(--muted)'}}>
        Draft · {draft.started}
      </div>
      <div className="mono" style={{
        fontSize:9.5, letterSpacing:'0.12em', textTransform:'uppercase',
        padding:'2px 7px', borderRadius:3,
        background: draft.blocked ? 'oklch(0.96 0.06 25)' : 'var(--paper-2)',
        color: draft.blocked ? 'var(--coral-ink)' : 'var(--ink-2)',
        fontWeight: 600,
      }}>
        {draft.step}
      </div>
    </div>

    <div className="serif" style={{fontSize:19, lineHeight:1.25}}>
      "{draft.outcome}"
    </div>

    <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', paddingTop:10, borderTop:'1px dashed var(--rule-soft)'}}>
      <div className="mono" style={{fontSize:10.5, color:'var(--muted)', letterSpacing:'0.04em'}}>
        Envelope · <b style={{color:'var(--ink-2)'}}>{draft.envelope}</b>
        {draft.bidsExpected && <> · bids {draft.bidsIn}/{draft.bidsExpected}</>}
      </div>
      <div style={{display:'flex', gap:8}}>
        <span onClick={(e) => { e.stopPropagation(); onDiscard(draft.id); }} className="mono" style={{fontSize:10.5, letterSpacing:'0.04em', color:'var(--muted-2)', cursor:'pointer'}}>
          discard
        </span>
        <span className="mono" style={{fontSize:10.5, letterSpacing:'0.04em', color:'var(--accent-ink)', fontWeight:600}}>
          resume →
        </span>
      </div>
    </div>
  </div>
);

// ─── Complete-contract row ─────────────────────────────────────────
const CompleteRow = ({ c, onOpen }) => {
  const badge = {
    completed:  { label:'Completed',  bg:'oklch(0.95 0.03 185)',     fg:'var(--sage-ink)' },
    superseded: { label:'Superseded', bg:'var(--accent-soft)',        fg:'var(--accent-ink)' },
    disputed:   { label:'Disputed',   bg:'oklch(0.96 0.06 25)',       fg:'var(--coral-ink)' },
  }[c.terminalState];

  return (
    <div
      onClick={() => onOpen && onOpen(c)}
      style={{
        padding:'18px 22px',
        border:'1px solid var(--rule-soft)',
        background:'var(--paper)',
        borderRadius:12,
        display:'grid',
        gridTemplateColumns:'auto 1fr auto',
        gap:22, alignItems:'center',
        cursor:'pointer',
        transition:'border-color 0.12s',
      }}
      onMouseEnter={(e) => e.currentTarget.style.borderColor = 'var(--ink-2)'}
      onMouseLeave={(e) => e.currentTarget.style.borderColor = 'var(--rule-soft)'}
    >
      <div style={{
        width:36, textAlign:'center',
        fontFamily:'var(--mono)', fontSize:10, letterSpacing:'0.14em', fontWeight:600,
        color:'var(--ink)',
      }}>
        {c.code}
      </div>

      <div>
        <div style={{display:'flex', alignItems:'baseline', gap:10, marginBottom:4, flexWrap:'wrap'}}>
          <div className="serif" style={{fontSize:20, lineHeight:1.2}}>
            "{c.outcome}"
          </div>
          <span className="mono" style={{
            fontSize:9.5, letterSpacing:'0.14em', textTransform:'uppercase',
            padding:'2px 8px', borderRadius:3,
            background: badge.bg, color: badge.fg, fontWeight:600,
          }}>{badge.label}</span>
        </div>
        <div className="mono" style={{fontSize:10.5, color:'var(--muted)', letterSpacing:'0.04em', marginBottom:6}}>
          {c.established} → {c.closed} · {c.durationDays} days · {c.receipts} receipts · ${c.totalSpend.toLocaleString()} total · {c.substrate.name}
        </div>
        <div style={{fontSize:13, color:'var(--ink-2)', lineHeight:1.4, maxWidth:720}}>
          {c.terminalNote}
          {c.lineage?.supersededBy && (
            <span> · <span style={{color:'var(--accent-ink)', fontFamily:'var(--mono)', fontSize:11}}>→ {c.lineage.supersededBy}</span></span>
          )}
        </div>
        {c.dispute && (
          <div style={{marginTop:8, padding:'8px 10px', background:'oklch(0.96 0.06 25 / 0.4)', border:'1px dashed oklch(0.85 0.08 25)', borderRadius:6, fontSize:12, color:'var(--coral-ink)'}}>
            <b>Ruling:</b> {c.dispute.ruling} · {c.dispute.resolution}
          </div>
        )}
      </div>

      <div style={{textAlign:'right'}}>
        <span className="mono" style={{fontSize:11, color:'var(--ink-2)', letterSpacing:'0.04em'}}>
          view receipts →
        </span>
      </div>
    </div>
  );
};

window.ContractsView = ContractsView;
