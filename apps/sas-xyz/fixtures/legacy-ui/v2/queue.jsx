// Exception / human-review queue.
// The 2% of events that envelopes route to humans land here.

const EXCEPTIONS = [
  {
    id: 'EX-0812',
    contractId: 'ct-books',
    contractCode: 'CT-0014',
    outcome: 'Keep the books tax-ready.',
    ts: '4 min ago',
    who: 'Mia L. · Finance',
    rule: 'PO match required · none found',
    summary: 'Invoice <em>INV-22843</em> for <em>$87.14</em> from Coffeehaus LLC has no PO on file and no recurring-vendor template. Provider (FinFlow) cannot auto-approve under Envelope Alpha.',
    context: [
      { k: 'Vendor',   v: 'Coffeehaus LLC · on allowlist' },
      { k: 'Amount',   v: '$87.14 · under budget cap' },
      { k: 'Recurring',v: 'No prior invoices in last 12m' },
      { k: 'PO search',v: 'No match to any open PO' },
    ],
    provider: 'FinFlow Autonomous v4.2',
    envelope: 'Alpha · Finance',
    suggestion: 'Approve as one-off · coffee/catering pattern',
    options: [
      { key: 'approve', label: 'Approve one-off', tone: 'primary' },
      { key: 'route',   label: 'Route to AP manager' },
      { key: 'reject',  label: 'Reject — send to vendor' },
    ],
    severity: 'low',
  },
  {
    id: 'EX-0811',
    contractId: 'ct-hires',
    contractCode: 'CT-0021',
    outcome: 'Provision new hires to day-one ready.',
    ts: '1h ago',
    who: 'Jordan S. · Head of People',
    rule: 'Policy ack outstanding · can\'t seal onboarding',
    summary: 'Mia Dresden (Munich Sales) is 3 of 4 sealed. Remaining step is the DE works-council addendum — it cannot auto-complete. Cohort Labor blocked the seal awaiting human sign-off.',
    context: [
      { k: 'Start date',v: 'Apr 22, 2026 (3 days out)' },
      { k: 'Sealed',   v: 'Identity · Payroll · Device' },
      { k: 'Blocked',  v: 'Works-council addendum (DE)' },
      { k: 'Rollback', v: '72h armed' },
    ],
    provider: 'Cohort Labor v2.1',
    envelope: 'Mike · HR',
    suggestion: 'Countersign the addendum — standard for DE hires',
    options: [
      { key: 'sign',   label: 'Countersign addendum', tone: 'primary' },
      { key: 'delay',  label: 'Delay start date' },
    ],
    severity: 'med',
  },
  {
    id: 'EX-0810',
    contractId: 'ct-contracts',
    contractCode: 'CT-0026',
    outcome: 'Redline inbound vendor contracts.',
    ts: '1h ago',
    who: 'S. Liu · General Counsel',
    rule: 'Indemnity cap above playbook threshold',
    summary: 'Ledgerly MSA proposes $250k indemnity cap · playbook v3.1 caps at $100k. Paragraph Legal escalated with a pre-drafted counter-redline.',
    context: [
      { k: 'Counter',     v: 'Ledgerly Inc.' },
      { k: 'Exposure',    v: '$250k proposed · $100k playbook' },
      { k: 'Precedent',   v: '7 similar cases · 6 settled at $150k' },
      { k: 'Counter-draft',v: 'Paragraph produced · ready to send' },
    ],
    provider: 'Paragraph Legal',
    envelope: 'Juliet · Legal',
    suggestion: 'Send the counter-redline at $150k per precedent',
    options: [
      { key: 'counter', label: 'Send counter · $150k', tone: 'primary' },
      { key: 'accept',  label: 'Accept $250k' },
      { key: 'escalate',label: 'Escalate to board' },
    ],
    severity: 'high',
  },
  {
    id: 'EX-0809',
    contractId: 'ct-cves',
    contractCode: 'CT-0019',
    outcome: 'Keep staging patched against known CVEs.',
    ts: '41 min ago',
    who: 'G. Reid · SRE Lead',
    rule: 'Two-eyes sign-off required before prod promote',
    summary: 'CVE-2025-44302 (openssl→3.2.2) is staged and green. Red/green passed 412/412. Promoting to prod needs a second approver.',
    context: [
      { k: 'CVE score', v: '8.1 · high' },
      { k: 'Snapshot',  v: 'snap-9f22 armed' },
      { k: 'Red/green', v: '412 / 412 pass' },
      { k: 'Approver 1',v: 'G. Reid ✓' },
    ],
    provider: 'Sentinel Core',
    envelope: 'Bravo · DevOps',
    suggestion: 'Co-approve · standard CVE workflow',
    options: [
      { key: 'approve', label: 'Co-approve · promote', tone: 'primary' },
      { key: 'hold',    label: 'Hold for review' },
    ],
    severity: 'med',
  },
];

const sevColor = (s) => s === 'high' ? 'var(--coral-ink)' : s === 'med' ? 'var(--accent-ink)' : 'var(--sage-ink)';
const sevBg    = (s) => s === 'high' ? 'oklch(0.96 0.06 25)' : s === 'med' ? 'var(--accent-soft)' : 'oklch(0.95 0.03 185)';

const QueueView = ({ onOpenContract }) => {
  const [selectedId, setSelectedId] = React.useState(EXCEPTIONS[0].id);
  const [resolved, setResolved] = React.useState({}); // { id: { option } }
  const ex = EXCEPTIONS.find(e => e.id === selectedId);
  const pending = EXCEPTIONS.filter(e => !resolved[e.id]);

  const resolve = (id, option) => {
    setResolved(prev => ({ ...prev, [id]: option }));
    // Advance to next pending
    const remaining = EXCEPTIONS.filter(e => !{...resolved, [id]: option}[e.id]);
    if (remaining.length) setSelectedId(remaining[0].id);
  };

  return (
    <div className="page">
      <div className="hero" style={{paddingBottom:28, marginBottom:28}} data-screen-label="02 Queue">
        <div className="hero-eyebrow mono">
          <span className="bullet" style={{background:'var(--coral)'}} /> Human-review queue · {pending.length} pending
        </div>
        <h1 className="hero-title serif" style={{fontSize:58}}>
          Where the <em>2%</em> lands.
        </h1>
        <p className="hero-lede">
          Envelopes route anything they can't decide to a human. Every item here is one policy rule away from auto-completing. Decide in place; the receipt chain picks up where it left off.
        </p>
      </div>

      <div style={{display:'grid', gridTemplateColumns:'360px 1fr', gap:20, alignItems:'start'}}>
        {/* List */}
        <aside style={{display:'flex', flexDirection:'column', gap:8, position:'sticky', top: 90}}>
          <div className="mono" style={{fontSize:10, letterSpacing:'0.18em', textTransform:'uppercase', color:'var(--muted)', padding:'4px 10px 6px'}}>
            {pending.length} pending · {EXCEPTIONS.length - pending.length} resolved today
          </div>
          {EXCEPTIONS.map(e => {
            const isResolved = !!resolved[e.id];
            const isActive = e.id === selectedId;
            return (
              <div key={e.id}
                onClick={() => setSelectedId(e.id)}
                style={{
                  padding:'14px 16px',
                  border: isActive ? '1.5px solid var(--ink)' : '1px solid var(--rule-soft)',
                  background: isActive ? 'var(--paper)' : 'transparent',
                  borderRadius:10,
                  cursor:'pointer',
                  opacity: isResolved ? 0.55 : 1,
                  display:'flex', flexDirection:'column', gap:6,
                }}>
                <div style={{display:'flex', justifyContent:'space-between', alignItems:'baseline', gap:8}}>
                  <div className="mono" style={{fontSize:10, letterSpacing:'0.14em', color:'var(--ink)', fontWeight:600}}>{e.id}</div>
                  <div className="mono" style={{fontSize:9.5, letterSpacing:'0.14em', textTransform:'uppercase', padding:'2px 6px', borderRadius:3, background: sevBg(e.severity), color: sevColor(e.severity), fontWeight:600}}>
                    {isResolved ? 'resolved' : e.severity}
                  </div>
                </div>
                <div className="serif" style={{fontSize:16, lineHeight:1.2}}>
                  {e.rule}
                </div>
                <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.04em'}}>
                  {e.contractCode} · {e.ts} · {e.who}
                </div>
              </div>
            );
          })}
        </aside>

        {/* Detail */}
        <main style={{background:'var(--paper)', border:'1px solid var(--rule-soft)', borderRadius:14, overflow:'hidden'}}>
          {resolved[ex.id] ? (
            <div style={{padding:'60px 40px', textAlign:'center'}}>
              <div className="serif" style={{fontSize:36, color:'var(--sage-ink)', marginBottom:12}}>
                Resolved
              </div>
              <div className="mono" style={{fontSize:11, color:'var(--muted)', letterSpacing:'0.08em'}}>
                Decision: <b style={{color:'var(--ink)'}}>{resolved[ex.id].label}</b> · receipt chain resumed · next event auto-sealed
              </div>
            </div>
          ) : (
            <>
              <div style={{padding:'24px 32px 20px', borderBottom:'1px solid var(--rule-soft)'}}>
                <div className="mono" style={{fontSize:10, letterSpacing:'0.18em', textTransform:'uppercase', color:'var(--muted)', marginBottom:10, display:'flex', gap:10, alignItems:'center'}}>
                  <span style={{padding:'3px 8px', background: sevBg(ex.severity), color: sevColor(ex.severity), borderRadius:3, fontWeight:600}}>{ex.severity}</span>
                  {ex.id} · {ex.ts} · for {ex.who}
                </div>
                <h2 className="serif" style={{fontSize:30, lineHeight:1.1, letterSpacing:'-0.015em', margin:'0 0 8px', fontWeight:400}}>
                  {ex.rule}
                </h2>
                <div onClick={() => onOpenContract && onOpenContract(ex.contractId)} className="mono" style={{fontSize:11, color:'var(--accent-ink)', letterSpacing:'0.04em', cursor:'pointer', display:'inline-block'}}>
                  {ex.contractCode} · {ex.outcome} →
                </div>
              </div>

              <div style={{padding:'22px 32px', display:'flex', flexDirection:'column', gap:22}}>
                <div>
                  <div className="mono" style={{fontSize:10, letterSpacing:'0.18em', textTransform:'uppercase', color:'var(--ink)', fontWeight:600, marginBottom:8}}>
                    Why it stopped
                  </div>
                  <div className="serif" style={{fontSize:17, lineHeight:1.5, color:'var(--ink)', maxWidth:640}} dangerouslySetInnerHTML={{__html: ex.summary}} />
                </div>

                <div>
                  <div className="mono" style={{fontSize:10, letterSpacing:'0.18em', textTransform:'uppercase', color:'var(--ink)', fontWeight:600, marginBottom:10}}>
                    Context the provider assembled
                  </div>
                  <div style={{display:'grid', gridTemplateColumns:'repeat(2, 1fr)', gap:1, background:'var(--rule-soft)', border:'1px solid var(--rule-soft)', borderRadius:10, overflow:'hidden'}}>
                    {ex.context.map((c, i) => (
                      <div key={i} style={{background:'var(--paper)', padding:'12px 14px'}}>
                        <div className="mono" style={{fontSize:9.5, letterSpacing:'0.14em', textTransform:'uppercase', color:'var(--muted)', marginBottom:4}}>{c.k}</div>
                        <div style={{fontSize:13, color:'var(--ink-2)', fontFamily:'var(--mono)', letterSpacing:'0.03em'}}>{c.v}</div>
                      </div>
                    ))}
                  </div>
                </div>

                <div style={{padding:'14px 16px', border:'1px solid oklch(0.82 0.08 270 / 0.4)', background:'var(--accent-soft)', borderRadius:10, display:'flex', gap:12, alignItems:'flex-start'}}>
                  <div style={{width:22, height:22, borderRadius:'50%', border:'1.5px dashed var(--accent-ink)', display:'flex', alignItems:'center', justifyContent:'center', fontFamily:'var(--serif)', fontSize:13, color:'var(--accent-ink)', flexShrink:0, marginTop:1, fontWeight:600}}>S</div>
                  <div style={{fontSize:13, lineHeight:1.5, color:'var(--accent-ink)'}}>
                    <b>Recommended</b> — {ex.suggestion}
                  </div>
                </div>

                <div>
                  <div className="mono" style={{fontSize:10, letterSpacing:'0.18em', textTransform:'uppercase', color:'var(--muted)', marginBottom:10}}>
                    Decide · {ex.provider} will seal the receipt under {ex.envelope}
                  </div>
                  <div style={{display:'flex', gap:10, flexWrap:'wrap'}}>
                    {ex.options.map(o => (
                      <button key={o.key}
                        className={`btn ${o.tone === 'primary' ? '' : 'ghost'}`}
                        onClick={() => resolve(ex.id, o)}
                      >
                        {o.label}
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
};

window.QueueView = QueueView;
window.PENDING_EXCEPTIONS = EXCEPTIONS.length; // for topbar badge
