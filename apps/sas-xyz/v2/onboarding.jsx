// Onboarding empty-state · "from nothing" first-outcome flow.
// Triggered by a Tweak toggle or fresh-workspace state.

const ONBOARD_STEPS = [
  {
    eyebrow: 'Step 1 of 3',
    title: 'Welcome to Acme · <em>fresh workspace</em>',
    body: 'No contracts yet. No providers attached. No envelope written. Let\'s draft one outcome together — end to end in about a minute.',
    cta: 'Start',
    visual: 'empty',
  },
  {
    eyebrow: 'Step 2 of 3',
    title: 'Pick an <em>outcome</em>, not a tool.',
    body: 'You\'re not shopping for software. You\'re stating a result the business wants. Pick one to demo — you can add more in a minute.',
    cta: null,
    visual: 'outcomes',
  },
  {
    eyebrow: 'Step 3 of 3',
    title: 'Watch the <em>first receipt</em> land.',
    body: 'Your envelope is drafted. Three providers bid. You pick the best fit. Within seconds, a signed receipt lands in the stream — audit-ready from moment one.',
    cta: 'Open workspace',
    visual: 'running',
  },
];

const DEMO_OUTCOMES = [
  { icon: 'file',   outcome: 'Keep our invoices reconciled nightly', kind: 'Finance · AP',   unit: '$1.20 / invoice' },
  { icon: 'shield', outcome: 'Patch staging against new CVEs within 3h', kind: 'DevOps · Patching', unit: '$12 / CVE' },
  { icon: 'zap',    outcome: 'Route customer escalations to a human in 10 min', kind: 'Support · Escalation', unit: '$0.40 / ticket' },
  { icon: 'db',     outcome: 'Refresh the ARR dashboard every morning', kind: 'Analytics · Dashboards', unit: '$0.20 / refresh' },
];

const Onboarding = ({ onClose }) => {
  const [step, setStep] = React.useState(0);
  const [picked, setPicked] = React.useState(null);
  const current = ONBOARD_STEPS[step];

  return (
    <div className="swap-scrim" onClick={onClose}>
      <div className="swap-modal" onClick={e => e.stopPropagation()} style={{width:'min(780px, 96vw)'}}>
        <div className="swap-head">
          <div className="swap-eyebrow mono">{current.eyebrow}</div>
          <h3 className="swap-title serif" dangerouslySetInnerHTML={{__html: current.title}} />
          <p style={{fontSize:15, lineHeight:1.55, color:'var(--ink-2)', margin:'14px 0 0', maxWidth:620}}>
            {current.body}
          </p>
          <div style={{display:'flex', gap:8, marginTop:20}}>
            {ONBOARD_STEPS.map((s, i) => (
              <div key={i} style={{flex:1, height:3, borderRadius:2, background: i <= step ? 'var(--ink)' : 'var(--rule-soft)'}} />
            ))}
          </div>
        </div>

        <div className="swap-body" style={{minHeight: 240}}>
          {current.visual === 'empty' && (
            <div style={{padding:'40px 20px', display:'flex', alignItems:'center', justifyContent:'center', minHeight:200}}>
              <div style={{textAlign:'center'}}>
                <div style={{fontFamily:'var(--mono)', fontSize:90, color:'var(--rule)', lineHeight:1, letterSpacing:'-0.02em'}}>Ø</div>
                <div className="mono" style={{fontSize:11, color:'var(--muted)', letterSpacing:'0.14em', textTransform:'uppercase', marginTop:8}}>
                  0 contracts · 0 receipts · 0 providers attached
                </div>
              </div>
            </div>
          )}

          {current.visual === 'outcomes' && (
            <div style={{display:'flex', flexDirection:'column', gap:10}}>
              {DEMO_OUTCOMES.map((o, i) => (
                <div key={i}
                  onClick={() => setPicked(i)}
                  style={{
                    padding:'14px 18px',
                    border: picked === i ? '1.5px solid var(--ink)' : '1px solid var(--rule-soft)',
                    background: picked === i ? 'var(--paper-2)' : 'var(--paper)',
                    borderRadius:10, cursor:'pointer',
                    display:'grid', gridTemplateColumns:'32px 1fr auto', gap:14, alignItems:'center',
                    transition:'all .15s',
                  }}>
                  <div style={{width:28, height:28, borderRadius:8, background:'var(--paper-2)', display:'flex', alignItems:'center', justifyContent:'center', color:'var(--muted)'}}>
                    <Icon name={o.icon} size={15} />
                  </div>
                  <div>
                    <div className="serif" style={{fontSize:17, lineHeight:1.2}}>{o.outcome}</div>
                    <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.04em', marginTop:3}}>{o.kind}</div>
                  </div>
                  <div className="mono" style={{fontSize:11, color:'var(--ink-2)', letterSpacing:'0.04em'}}>{o.unit}</div>
                </div>
              ))}
            </div>
          )}

          {current.visual === 'running' && (
            <div style={{display:'flex', flexDirection:'column', gap:14}}>
              <div style={{padding:'24px 22px', background:'var(--ink)', color:'var(--paper)', borderRadius:12}}>
                <div className="mono" style={{fontSize:10, letterSpacing:'0.18em', textTransform:'uppercase', color:'oklch(0.85 0.02 270)', marginBottom:10}}>
                  CT-0001 · contract live
                </div>
                <div className="serif" style={{fontSize:26, lineHeight:1.1, letterSpacing:'-0.015em'}}>
                  "<em>{DEMO_OUTCOMES[picked ?? 0].outcome}</em>"
                </div>
                <div className="mono" style={{fontSize:10.5, color:'oklch(0.8 0.06 270)', letterSpacing:'0.04em', marginTop:10}}>
                  Provider selected · envelope drafted · policy hash chained · waiting on first event
                </div>
              </div>
              <div style={{padding:'12px 14px', background:'var(--paper-2)', border:'1px solid var(--rule-soft)', borderRadius:8, display:'flex', gap:10, alignItems:'center'}}>
                <div style={{width:8, height:8, borderRadius:'50%', background:'var(--sage)', animation:'pulse 1.2s infinite'}} />
                <div className="mono" style={{fontSize:11, color:'var(--muted)', letterSpacing:'0.04em'}}>First receipt inbound…</div>
              </div>
            </div>
          )}
        </div>

        <div className="swap-foot">
          <div className="swap-foot-note mono">
            {step === 0 && 'Takes ~60 seconds · you can skip anytime'}
            {step === 1 && (picked != null ? 'Selected — ready to draft' : 'Pick one to continue')}
            {step === 2 && 'Your workspace is ready'}
          </div>
          <div className="swap-foot-actions">
            {step > 0 && <button className="btn ghost" onClick={() => setStep(step - 1)}>← Back</button>}
            <button className="btn ghost" onClick={onClose}>Skip</button>
            {step < ONBOARD_STEPS.length - 1 ? (
              <button className="btn accent" onClick={() => setStep(step + 1)} disabled={step === 1 && picked == null}>
                Continue →
              </button>
            ) : (
              <button className="btn accent" onClick={onClose}>{current.cta} →</button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

window.Onboarding = Onboarding;
