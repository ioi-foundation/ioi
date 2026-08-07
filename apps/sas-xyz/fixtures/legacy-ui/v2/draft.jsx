// Draft-an-outcome wizard: parse → bid → pick → live
// 4 steps, each clearly scaffolded. Same modal frame as swap.

const PARSED_SPECS = {
  // Keyed loosely by prompt keywords; otherwise generic fallback.
  reconcile: {
    outcome: 'Keep vendor invoices reconciled nightly.',
    detail:  'Three-way match every incoming invoice against PO + receipt. Flag any variance > 0.5% for human review. Settle weekly.',
    sla: '≤ 6h per invoice · weekly reconciliation report',
    envelope: {
      name: 'Alpha · Finance',
      rules: ['Budget cap $500/mo', 'Vendor allowlist only', 'Human review on mismatch'],
    },
    schema: ['invoice_id', 'po_ref', 'receipt_ref', 'variance_pct', 'decision', 'signer'],
  },
  access: {
    outcome: 'Run a weekly access review across SaaS estate.',
    detail:  'Enumerate every user × app × role combination; flag stale accounts, unused roles, and orphaned OAuth grants. Ship a one-click revoke queue.',
    sla: 'Fri 09:00 local · < 4h to compile',
    envelope: {
      name: 'Charlie · Security',
      rules: ['Read-only scopes only', 'No automatic revokes — human confirms', 'SOC2 evidence pack attached'],
    },
    schema: ['subject_id', 'app', 'role', 'last_used', 'recommendation', 'signer'],
  },
  generic: {
    outcome: 'Resolve customer escalations to a human in under 10 minutes.',
    detail:  'Triage inbound escalations, summarize context, route to the correct on-call. Acknowledge with SLA commitment to the customer.',
    sla: 'p95 ≤ 10min to human ack',
    envelope: {
      name: 'Delta · Support',
      rules: ['No refunds without human approval', 'PII masked in routing', 'Transcripts retained 90d'],
    },
    schema: ['ticket_id', 'severity', 'routed_to', 'ack_time', 'transcript_hash', 'signer'],
  },
};

const pickSpec = (prompt) => {
  const p = (prompt || '').toLowerCase();
  if (/invoice|reconcil|book|ap\b/.test(p))      return PARSED_SPECS.reconcile;
  if (/access|review|saas|permission/.test(p))   return PARSED_SPECS.access;
  return PARSED_SPECS.generic;
};

// Real parse via window.claude.complete. Returns a spec or null on failure.
const parseWithClaude = async (prompt) => {
  if (!window.claude || !window.claude.complete) return null;
  const sys = `You are the sas.xyz outcome parser. Convert a user's plain-English business outcome into a structured spec.

Return ONLY valid JSON matching this exact shape — no prose, no markdown, no code fences:
{
  "outcome": "short declarative sentence, ≤ 10 words, no period",
  "detail": "1-2 sentences describing HOW the outcome is fulfilled and WHAT the key guarantees are",
  "sla": "concise SLA in business terms (e.g. '≤ 6h per event', 'Fri 09:00 local')",
  "envelope": {
    "name": "GreekLetter · Domain (e.g. 'Alpha · Finance', 'Bravo · DevOps', 'Charlie · Security', 'Delta · Support', 'Echo · Analytics', 'Juliet · Legal', 'Mike · HR')",
    "rules": ["3-5 short policy rules, each a sentence fragment < 8 words"]
  },
  "schema": ["4-7 snake_case field names for the receipt schema, always ending with 'signer'"]
}

Pick the envelope whose domain best matches the outcome. Be specific, concrete, and auditable. Never invent fields like timestamps — receipts always have those.`;

  try {
    const raw = await window.claude.complete({
      messages: [
        { role: 'user', content: `${sys}\n\nUSER OUTCOME:\n${prompt}` },
      ],
    });
    // Extract JSON even if model accidentally wraps it
    const m = raw.match(/\{[\s\S]*\}/);
    if (!m) return null;
    const parsed = JSON.parse(m[0]);
    if (!parsed.outcome || !parsed.envelope || !parsed.schema) return null;
    return parsed;
  } catch (e) {
    return null;
  }
};

const BIDS = [
  { id: 'b-ledgerly', name: 'Ledgerly',       meta: 'Since 2024 · SOC2 · 1,820 customers', price: '$0.80 / outcome',  sla: '9h median',  fit: 100, badge: 'Cheapest' },
  { id: 'b-finflow',  name: 'FinFlow',        meta: 'Since 2022 · SOC2 + ISO · finance specialist', price: '$1.20 / outcome', sla: '11h median', fit: 100, badge: 'Best fit' },
  { id: 'b-accru',    name: 'Accru Reconcile',meta: 'Since 2023 · SOC2 · enterprise grade', price: '$1.05 / outcome', sla: '14h median', fit: 96,  badge: null },
];

// ─── Component ────────────────────────────────────────────────────
const DraftWizard = ({ initialPrompt, onClose, onGoLive }) => {
  const [step, setStep] = React.useState(0);
  const [prompt, setPrompt] = React.useState(initialPrompt || '');
  const [parsing, setParsing] = React.useState(false);
  const [parsedSpec, setParsedSpec] = React.useState(null);
  const [parseSource, setParseSource] = React.useState(null); // 'claude' | 'fallback'
  const [chosenBid, setChosenBid] = React.useState(null);
  const spec = parsedSpec || pickSpec(prompt);

  const go = async (next) => {
    if (next === 1 && !parsing) {
      setParsing(true);
      const claudeSpec = await parseWithClaude(prompt);
      if (claudeSpec) {
        setParsedSpec(claudeSpec);
        setParseSource('claude');
      } else {
        setParsedSpec(pickSpec(prompt));
        setParseSource('fallback');
      }
      setParsing(false);
      setStep(1);
      return;
    }
    setStep(next);
  };

  const steps = ['Describe', 'Review spec', 'Pick provider', 'Go live'];

  return (
    <div className="swap-scrim" onClick={onClose}>
      <div className="swap-modal" onClick={e => e.stopPropagation()} style={{width: 'min(740px, 96vw)'}}>
        <div className="swap-head">
          <div className="swap-eyebrow mono">Draft an outcome · step {step + 1} of 4</div>
          <h3 className="swap-title serif">
            {step === 0 && <>State what you want, <em>not how</em>.</>}
            {step === 1 && <><em>Outcome spec</em> · drafted for your approval</>}
            {step === 2 && <><em>Three providers</em> can fulfill this</>}
            {step === 3 && <>Contract <em>live</em>. First receipt en route.</>}
          </h3>
          {/* progress */}
          <div style={{display:'flex', gap:8, marginTop:18}}>
            {steps.map((s, i) => (
              <div key={i} style={{flex:1, height:3, borderRadius:2, background: i <= step ? 'var(--ink)' : 'var(--rule-soft)'}} />
            ))}
          </div>
        </div>

        <div className="swap-body">
          {step === 0 && (
            <div style={{display:'flex', flexDirection:'column', gap:14}}>
              <div className="prompt" style={{boxShadow:'none'}}>
                <div className="prompt-head">
                  <span className="prompt-head-label mono">Outcome · plain English</span>
                </div>
                <textarea
                  className="prompt-input"
                  placeholder="e.g. keep our invoices reconciled nightly, flag any vendor change over 10%…"
                  value={prompt}
                  onChange={e => setPrompt(e.target.value)}
                  autoFocus
                  style={{minHeight:100}}
                />
              </div>
              <div className="prompt-hint mono">
                We'll parse this into a structured spec — outcome, SLA, envelope, receipt schema — and show it before anything runs.
              </div>
            </div>
          )}

          {step === 1 && (
            <div style={{display:'flex', flexDirection:'column', gap:16}}>
              <div className="side-outcome-box">
                "{spec.outcome}"
                <div className="side-outcome-sub mono">
                  Parsed from your prompt · SLA {spec.sla}
                  {parseSource === 'claude' && <span style={{marginLeft:8, color:'var(--sage-ink)'}}>· live</span>}
                  {parseSource === 'fallback' && <span style={{marginLeft:8, color:'var(--muted-2)'}}>· template</span>}
                </div>
              </div>

              <div style={{display:'flex', flexDirection:'column', gap:8}}>
                <div className="side-section-label mono">Promise · detail</div>
                <div style={{padding:'14px 16px', background:'var(--paper-2)', border:'1px solid var(--rule-soft)', borderRadius:10, fontSize:13, lineHeight:1.55, color:'var(--ink-2)'}}>
                  {spec.detail}
                </div>
              </div>

              <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:12}}>
                <div>
                  <div className="side-section-label mono">Proposed envelope</div>
                  <div className="envelope-mini">
                    <div className="envelope-mini-head mono">
                      <span className="name">{spec.envelope.name}</span>
                      <span className="state">drafted</span>
                    </div>
                    <div className="envelope-mini-rules mono">
                      {spec.envelope.rules.map((r, i) => <span key={i}>{r}</span>)}
                    </div>
                  </div>
                </div>
                <div>
                  <div className="side-section-label mono">Receipt schema</div>
                  <div style={{padding:'12px 14px', background:'var(--paper)', border:'1px solid var(--rule-soft)', borderRadius:10, fontFamily:'var(--mono)', fontSize:11, color:'var(--ink-2)', letterSpacing:'0.03em', lineHeight:1.8}}>
                    {spec.schema.map((f, i) => (
                      <div key={i}>· {f}</div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {step === 2 && (
            <div style={{display:'flex', flexDirection:'column', gap:12}}>
              <div className="side-section-label mono" style={{marginBottom:0}}>
                Sealed bids · all envelope-compatible
              </div>
              {BIDS.map(b => (
                <div
                  key={b.id}
                  onClick={() => setChosenBid(b.id)}
                  style={{
                    padding:'16px 18px',
                    border: chosenBid === b.id ? '1.5px solid var(--ink)' : '1px solid var(--rule-soft)',
                    background: chosenBid === b.id ? 'var(--paper-2)' : 'var(--paper)',
                    borderRadius:12,
                    cursor:'pointer',
                    display:'grid',
                    gridTemplateColumns:'24px 1fr auto',
                    gap:14,
                    alignItems:'center',
                    transition: 'all .15s',
                  }}
                >
                  <div style={{
                    width:18, height:18, borderRadius:'50%',
                    border:'1.5px solid ' + (chosenBid === b.id ? 'var(--ink)' : 'var(--rule)'),
                    background: chosenBid === b.id ? 'var(--ink)' : 'transparent',
                    display:'flex', alignItems:'center', justifyContent:'center',
                    color:'var(--paper)', fontSize:10,
                  }}>{chosenBid === b.id && '✓'}</div>
                  <div>
                    <div style={{display:'flex', alignItems:'baseline', gap:8, marginBottom:2}}>
                      <div className="serif" style={{fontSize:20, fontWeight:400}}>{b.name}</div>
                      {b.badge && (
                        <span className="mono" style={{
                          fontSize:9, letterSpacing:'0.12em', textTransform:'uppercase',
                          padding:'2px 6px', borderRadius:3,
                          background: b.badge === 'Best fit' ? 'var(--accent-soft)' : 'oklch(0.95 0.03 185)',
                          color: b.badge === 'Best fit' ? 'var(--accent-ink)' : 'var(--sage-ink)',
                          fontWeight:600,
                        }}>{b.badge}</span>
                      )}
                    </div>
                    <div className="mono" style={{fontSize:10.5, color:'var(--muted)', letterSpacing:'0.04em'}}>{b.meta}</div>
                    <div className="mono" style={{fontSize:10.5, color:'var(--ink-2)', letterSpacing:'0.04em', marginTop:4}}>SLA: {b.sla} · envelope fit {b.fit}%</div>
                  </div>
                  <div className="serif" style={{fontSize:17, letterSpacing:'-0.005em', textAlign:'right', whiteSpace:'nowrap'}}>
                    {b.price}
                  </div>
                </div>
              ))}
              <div className="swap-guarantee" style={{marginTop:4}}>
                <span className="swap-guarantee-glyph">S</span>
                <span>
                  <b>You can swap later.</b> Whichever you pick, the outcome spec and receipt schema stay stable. Switching providers never breaks your audit chain.
                </span>
              </div>
            </div>
          )}

          {step === 3 && (
            <div style={{display:'flex', flexDirection:'column', gap:14, alignItems:'stretch'}}>
              <div style={{
                padding:'28px 24px', background:'var(--ink)', color:'var(--paper)',
                borderRadius:12, display:'flex', flexDirection:'column', gap:10,
              }}>
                <div className="mono" style={{fontSize:10, letterSpacing:'0.18em', textTransform:'uppercase', color:'oklch(0.85 0.02 270)'}}>
                  Contract established
                </div>
                <div className="serif" style={{fontSize:28, lineHeight:1.1, letterSpacing:'-0.015em'}}>
                  "<em>{spec.outcome}</em>"
                </div>
                <div className="mono" style={{fontSize:11, color:'oklch(0.8 0.06 270)', letterSpacing:'0.04em', marginTop:6}}>
                  CT-0030 · fulfilled by {BIDS.find(b => b.id === chosenBid)?.name || 'FinFlow'} · envelope {spec.envelope.name} · policy hash 0x8d1b2c…7789
                </div>
              </div>

              <div style={{display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:10}}>
                {[
                  {k:'SLA', v: spec.sla},
                  {k:'First receipt', v: 'expected < 6h'},
                  {k:'Rollback', v: 'armed · 30d'},
                ].map((x, i) => (
                  <div key={i} style={{padding:'12px 14px', background:'var(--paper-2)', border:'1px solid var(--rule-soft)', borderRadius:8}}>
                    <div className="mono" style={{fontSize:9.5, letterSpacing:'0.16em', textTransform:'uppercase', color:'var(--muted)', marginBottom:4}}>{x.k}</div>
                    <div className="serif" style={{fontSize:15, lineHeight:1.2}}>{x.v}</div>
                  </div>
                ))}
              </div>

              <div className="mono" style={{fontSize:11, color:'var(--muted)', letterSpacing:'0.04em', textAlign:'center', padding:'8px 0'}}>
                Waiting on first event from upstream system…
              </div>
            </div>
          )}
        </div>

        <div className="swap-foot">
          <div className="swap-foot-note mono">
            {step === 0 && (parsing ? 'Parsing into structured spec…' : 'Nothing runs until you approve · step 1 of 4')}
            {step === 1 && 'You can edit any field before providers bid'}
            {step === 2 && (chosenBid ? 'Provider selected · ready to go live' : 'Pick one to continue')}
            {step === 3 && 'First receipt will appear in the stream automatically'}
          </div>
          <div className="swap-foot-actions">
            {step === 0 && (
              <>
                <button className="btn ghost" onClick={onClose}>Cancel</button>
                <button className="btn accent" onClick={() => go(1)} disabled={!prompt.trim() || parsing}>
                  {parsing ? 'Parsing…' : 'Parse →'}
                </button>
              </>
            )}
            {step === 1 && (
              <>
                <button className="btn ghost" onClick={() => setStep(0)}>← Back</button>
                <button className="btn accent" onClick={() => setStep(2)}>Request bids →</button>
              </>
            )}
            {step === 2 && (
              <>
                <button className="btn ghost" onClick={() => setStep(1)}>← Back</button>
                <button className="btn accent" onClick={() => setStep(3)} disabled={!chosenBid}>
                  Go live →
                </button>
              </>
            )}
            {step === 3 && (
              <>
                <button className="btn ghost" onClick={onClose}>Later</button>
                <button className="btn" onClick={() => onGoLive && onGoLive({ spec, bid: BIDS.find(b => b.id === chosenBid) })}>
                  Open contract ↗
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

window.DraftWizard = DraftWizard;
