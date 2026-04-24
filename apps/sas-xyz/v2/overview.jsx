// Overview — the thesis page. Marketing long-form read.
// Arc: Hero → Operator tax → Three shifts → How it works (5 beats) → vs. SaaS → CTA.

const OverviewView = ({ onTab, onDraft, contracts, totalReceipts, activeEscrow }) => {
  const scrollTo = (id) => {
    const el = document.getElementById(id);
    if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  return (
    <div className="overview" data-screen-label="00 Overview">
      {/* ───────────────────────── HERO ───────────────────────── */}
      <section className="ov-hero">
        <div className="ov-eyebrow mono">
          <span className="bullet" /> sas.xyz · the end of SaaS
        </div>
        <h1 className="ov-headline serif">
          Stop paying for tools.<br/>
          Pay for <em>outcomes</em>.
        </h1>
        <p className="ov-lede">
          You're paying for the tool <em>and</em> the person to hold the tool. Software charges for seats.
          You hire humans to operate those seats. The work itself is what you actually wanted — and it's the
          one thing no one's selling you directly.
        </p>
        <p className="ov-lede" style={{marginTop: 0}}>
          sas.xyz does. State the outcome, seal the envelope, fund the escrow. Providers compete on proof.
          Money releases on receipts, not on features shipped.
        </p>
        <div className="ov-cta-row">
          <button className="btn accent" onClick={() => scrollTo('how')}>
            See how it works <span className="mono" style={{marginLeft:8, opacity:0.7}}>↓</span>
          </button>
          <button className="btn" onClick={() => onTab('Market')}>Browse the market</button>
          <button className="btn ghost" onClick={() => onDraft('')}>Draft a contract</button>
        </div>

        {/* Ambient stats — pulled live from your actual state */}
        <div className="ov-stats">
          <div>
            <div className="ov-stat-n serif">{contracts}</div>
            <div className="ov-stat-k mono">live contracts</div>
          </div>
          <div>
            <div className="ov-stat-n serif">{totalReceipts.toLocaleString()}</div>
            <div className="ov-stat-k mono">receipts / 30d</div>
          </div>
          <div>
            <div className="ov-stat-n serif">${activeEscrow.toLocaleString()}</div>
            <div className="ov-stat-k mono">in escrow right now</div>
          </div>
          <div>
            <div className="ov-stat-n serif">99.94<span className="ov-stat-unit">%</span></div>
            <div className="ov-stat-k mono">sla met, rolling 7d</div>
            <AsciiBars cols={18} style={{marginTop: 8}} />
          </div>
        </div>

        {/* Ambient ASCII seam beneath the hero */}
        <div style={{marginTop: 40, display:'flex', alignItems:'center', gap: 14}}>
          <span className="mono" style={{fontSize: 9, letterSpacing:'0.18em', textTransform:'uppercase', color:'var(--muted-2)', whiteSpace:'nowrap'}}>live · receipts streaming</span>
          <div style={{flex: 1, overflow:'hidden'}}>
            <AsciiWave cols={140} />
          </div>
        </div>
      </section>

      {/* ───────────────────────── OPERATOR TAX ───────────────────────── */}
      <section className="ov-section ov-operator-tax">
        <div className="ov-section-head">
          <div className="ov-section-num mono">01</div>
          <div className="ov-section-title serif">The operator tax</div>
        </div>
        <div className="ov-operator-grid">
          <div className="ov-operator-body">
            <p>
              Every SaaS purchase comes with a hidden line item. You don't buy Salesforce and get sales.
              You buy a database and hire five people to input, nudge, and drag rows around in it.
              The tool is the sticker price. The operators are the real invoice.
            </p>
            <p>
              For a decade that tradeoff was fine. Software couldn't do the work, so humans did — and the
              software just kept score. That era ended when the software started finishing tasks.
              Which means the operator tax is now the biggest unpriced item on your balance sheet.
            </p>
          </div>

          {/* Visual: a seat-based invoice vs an outcome-based one */}
          <div className="ov-invoice-stack">
            <div className="ov-invoice ov-invoice-old">
              <div className="ov-invoice-head">
                <div className="mono">seat-based saas · q1</div>
                <div className="mono ov-invoice-tag">what you pay for</div>
              </div>
              <div className="ov-invoice-lines">
                <div><span>Platform · 124 seats</span><span className="serif">$48,360</span></div>
                <div><span>4 ops FTE to keep it fed</span><span className="serif">$97,200</span></div>
                <div><span>Integrations consultant · q1</span><span className="serif">$28,500</span></div>
                <div><span>Training, admin, churn</span><span className="serif">$14,200</span></div>
                <div className="ov-invoice-total"><span>paid</span><span className="serif">$188,260</span></div>
                <div className="ov-invoice-result mono">outcomes shipped · <em>unknown</em></div>
              </div>
            </div>
            <div className="ov-invoice ov-invoice-new">
              <div className="ov-invoice-head">
                <div className="mono">outcome-based · q1</div>
                <div className="mono ov-invoice-tag ov-tag-good">what you paid for</div>
              </div>
              <div className="ov-invoice-lines">
                <div><span>4,218 invoices matched</span><span className="serif">$12,900</span></div>
                <div><span>82 hires onboarded</span><span className="serif">$9,840</span></div>
                <div><span>312 contracts redlined</span><span className="serif">$14,976</span></div>
                <div><span>Tier-2 support · 5,106 resolved</span><span className="serif">$24,300</span></div>
                <div className="ov-invoice-total"><span>paid</span><span className="serif">$62,016</span></div>
                <div className="ov-invoice-result ov-result-good mono">every dollar · <em>receipt-linked</em></div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ───────────────────────── THREE SHIFTS ───────────────────────── */}
      <section className="ov-section ov-shifts">
        <div className="ov-section-head">
          <div className="ov-section-num mono">02</div>
          <div className="ov-section-title serif">Three shifts happening at once</div>
        </div>
        <div className="ov-shift-grid">
          {[
            {
              k:'from', kt:'features',
              t:'to', tt:'outcomes',
              body:`SaaS competes on button counts. The buyer doesn't care about buttons — they care about success rate. If one provider hits 99.9% on your KYC workload and another hits 98%, there's no UI comparison to run. The higher-certainty outcome wins.`,
            },
            {
              k:'from', kt:'subscription',
              t:'to', tt:'escrow',
              body:`A subscription charges you whether the work happens or not. Escrow charges you when the work is proven. Your vendor's incentive flips: idle hours are a cost center for them, not a revenue line for us.`,
            },
            {
              k:'from', kt:'data exposure',
              t:'to', tt:'mutual blindness',
              body:`For a decade we were told better software required surrendering data. It doesn't anymore. The worker sees your data to do the task; it cannot exfiltrate. The provider's logic stays encrypted; you cannot steal it. Utility without exposure, verified by math.`,
            },
          ].map((s, i) => (
            <div key={i} className="ov-shift">
              <div className="ov-shift-arc">
                <div className="ov-shift-from">
                  <span className="mono">{s.k}</span>
                  <span className="serif"><em>{s.kt}</em></span>
                </div>
                <div className="ov-shift-arrow mono">→</div>
                <div className="ov-shift-to">
                  <span className="mono">{s.t}</span>
                  <span className="serif"><em>{s.tt}</em></span>
                </div>
              </div>
              <p className="ov-shift-body">{s.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ───────────────────────── HOW IT WORKS ───────────────────────── */}
      <section className="ov-section ov-how" id="how">
        <div className="ov-section-head">
          <div className="ov-section-num mono">03</div>
          <div className="ov-section-title serif">How a contract moves</div>
        </div>
        <p className="ov-section-lede">
          Five beats, start to finish. You write one; the system enforces the other four.
        </p>

        {/* Beat 1 — Intent */}
        <div className="ov-beat">
          <div className="ov-beat-n mono">i.</div>
          <div className="ov-beat-copy">
            <h3 className="serif">Intent</h3>
            <p>
              Write the outcome in English. The system parses it into a structured spec — envelope,
              SLA, rate, boundary conditions. Nothing runs until you approve.
            </p>
            <div className="ov-beat-quote serif">
              <em>"Resolve tier-2 support escalations under 4h median, max $18 / resolution, refund on 2nd breach."</em>
            </div>
          </div>
          <div className="ov-beat-visual ov-beat-intent">
            <div className="ov-intent-row">
              <span className="mono">ENVELOPE</span>
              <span className="serif">$24,000 · q1</span>
            </div>
            <div className="ov-intent-row">
              <span className="mono">SLA</span>
              <span className="serif">median &lt; 4h</span>
            </div>
            <div className="ov-intent-row">
              <span className="mono">RATE CAP</span>
              <span className="serif">$18 / resolved</span>
            </div>
            <div className="ov-intent-row">
              <span className="mono">REFUND</span>
              <span className="serif">on 2nd SLA breach</span>
            </div>
            <div className="ov-intent-row">
              <span className="mono">DATA</span>
              <span className="serif">stays in-VPC</span>
            </div>
          </div>
        </div>

        {/* Beat 2 — Escrow */}
        <div className="ov-beat ov-beat-alt">
          <div className="ov-beat-n mono">ii.</div>
          <div className="ov-beat-copy">
            <h3 className="serif">Escrow</h3>
            <p>
              Funds move to a contract-bound escrow. Providers see the envelope and bid against it.
              You pick. Money doesn't release yet — it's staged against proof-of-work.
            </p>
            <p className="ov-beat-aside mono">
              No subscriptions. No seats. Nothing auto-renews.
            </p>
          </div>
          <div className="ov-beat-visual ov-escrow">
            <div className="ov-escrow-chip">
              <div className="mono">staged</div>
              <div className="serif ov-escrow-amt">$24,000</div>
              <div className="mono ov-escrow-sub">0 released · 0 consumed</div>
            </div>
            <div style={{display:'flex', flexDirection:'column', alignItems:'center', gap: 4}}>
              <AsciiFlow cols={24} speed={1} />
              <div className="ov-escrow-arrow mono" style={{fontSize:12, opacity:0.5}}>↓</div>
            </div>
            <div className="ov-escrow-chip ov-escrow-live">
              <div className="mono">live · meter on</div>
              <div className="serif ov-escrow-amt">$6,128</div>
              <div className="mono ov-escrow-sub">340 receipts released</div>
            </div>
          </div>
        </div>

        {/* Beat 3 — Mutual Blindness */}
        <div className="ov-beat">
          <div className="ov-beat-n mono">iii.</div>
          <div className="ov-beat-copy">
            <h3 className="serif">Mutual blindness</h3>
            <p>
              The worker operates inside a boundary. It sees your data to do the work; it cannot
              call home, log rows, or package context to train on later. The provider's model
              stays encrypted — you use the intelligence without stealing it.
            </p>
            <p>
              You don't need to know how the math works to trust the shape. Data doesn't move.
              Model doesn't leak. Both are verified before anything runs.
            </p>
          </div>
          <div className="ov-beat-visual ov-blindness">
            <div className="ov-blind-box">
              <div className="ov-blind-label mono">your vpc</div>
              <div className="ov-blind-content serif">data</div>
              <div className="ov-blind-note mono">stays put</div>
            </div>
            <div className="ov-blind-seam">
              <div className="ov-blind-seam-label mono">boundary · sealed</div>
              <AsciiLattice cols={6} rows={5} />
              <div className="ov-blind-badge mono"><span className="ov-check">✓</span> verified by math</div>
            </div>
            <div className="ov-blind-box">
              <div className="ov-blind-label mono">provider</div>
              <div className="ov-blind-content serif">model</div>
              <div className="ov-blind-note mono">encrypted</div>
            </div>
          </div>
        </div>

        {/* Beat 4 — Receipts */}
        <div className="ov-beat ov-beat-alt">
          <div className="ov-beat-n mono">iv.</div>
          <div className="ov-beat-copy">
            <h3 className="serif">Receipts<AsciiCaret /></h3>
            <p>
              Every unit of work produces a signed receipt. Not a log entry — a cryptographic record
              you can take to an auditor. Timestamped, hash-chained, irrefutable.
            </p>
            <p>
              When a receipt lands, the corresponding slice of escrow releases. Your ledger is the
              sum of receipts. You can stop at any time; no termination fee, no 30-day clause.
            </p>
          </div>
          <div className="ov-beat-visual ov-receipts">
            {[
              { ok:true,  title:'Ticket #22844 resolved', sub:'0x7a2c9f…df82 · 2m 14s', amt:'$14.20' },
              { ok:true,  title:'Ticket #22843 resolved', sub:'0x4b1a3e…e921 · 1m 51s', amt:'$14.20' },
              { ok:true,  title:'Ticket #22842 routed to tier-3', sub:'0x9c3d77…a834 · 48s', amt:'$4.00' },
              { ok:true,  title:'Ticket #22841 resolved', sub:'0x2e5f88…1c44 · 3m 02s', amt:'$14.20' },
              { ok:false, title:'Ticket #22840 breach · refund issued', sub:'0x3a4e66…b2a1 · 4h 22m', amt:'-$14.20' },
            ].map((r, i) => (
              <div key={i} className={`ov-receipt ${r.ok ? '' : 'ov-receipt-refund'}`}>
                <div className="ov-receipt-dot" />
                <div className="ov-receipt-body">
                  <div className="serif ov-receipt-title">{r.title}</div>
                  <div className="mono ov-receipt-sub">{r.sub}</div>
                </div>
                <div className="serif ov-receipt-amt">{r.amt}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Beat 5 — Arbitration */}
        <div className="ov-beat">
          <div className="ov-beat-n mono">v.</div>
          <div className="ov-beat-copy">
            <h3 className="serif">Arbitration, when it's needed</h3>
            <p>
              Sometimes a receipt doesn't pass the envelope. You dispute it. An arbiter — not a
              support ticket — reviews the trail and rules. Funds reverse, or release. The provider
              pays for the ruling; their reputation stake takes the hit.
            </p>
            <p>
              Support isn't an SLA on a help article. It's baked into the money.
            </p>
          </div>
          <div className="ov-beat-visual ov-dispute">
            <div className="ov-dispute-step">
              <div className="mono ov-dispute-ts">T+0</div>
              <div>
                <div className="mono ov-dispute-actor">you</div>
                <div className="serif">Dispute filed · 2 tickets breached envelope</div>
              </div>
            </div>
            <div className="ov-dispute-step">
              <div className="mono ov-dispute-ts">T+18m</div>
              <div>
                <div className="mono ov-dispute-actor">arbiter · frost</div>
                <div className="serif">Reviewed receipt chain · confirmed breach</div>
              </div>
            </div>
            <div className="ov-dispute-step ov-dispute-final">
              <div className="mono ov-dispute-ts">T+24m</div>
              <div>
                <div className="mono ov-dispute-actor">ruling</div>
                <div className="serif">$284.00 refunded · rep stake decremented</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ───────────────────────── VS. SAAS ───────────────────────── */}
      <section className="ov-section ov-vs">
        <div className="ov-section-head">
          <div className="ov-section-num mono">04</div>
          <div className="ov-section-title serif">Against the SaaS default</div>
        </div>
        <p className="ov-section-lede">
          Every buyer will do this comparison in their head. Here's it done out loud.
        </p>

        <table className="ov-compare">
          <thead>
            <tr>
              <th></th>
              <th className="ov-compare-col ov-compare-old">
                <span className="mono">the SaaS you have</span>
              </th>
              <th className="ov-compare-col ov-compare-new">
                <span className="mono">sas.xyz</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {[
              ['Unit of sale',       'Seat',                             'Receipt'],
              ['You pay when',       'The calendar ticks',               'Work completes'],
              ['Idle cost',          'Full',                             'Zero'],
              ['Vendor incentive',   'Retention, upsell',                'Throughput, accuracy'],
              ['Failure handling',   'Support ticket · you pursue',      'Dispute · arbiter rules'],
              ['Data location',      'Their cloud, their logs',          'Your VPC, sealed boundary'],
              ['Integration',        'Consultants, 6-12 weeks',          'Envelope · ~1 day'],
              ['Switching cost',     'Renewal date, migration budget',   'End of current envelope'],
              ['Audit trail',        'Log export, probably',             'Signed receipts, always'],
              ['Comparing vendors',  'Feature matrix',                   'SLA + rep stake + price'],
            ].map((row, i) => (
              <tr key={i}>
                <td className="mono ov-compare-k">{row[0]}</td>
                <td className="ov-compare-old-cell serif"><span className="ov-strike">{row[1]}</span></td>
                <td className="ov-compare-new-cell serif"><em>{row[2]}</em></td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      {/* ───────────────────────── CLOSE ───────────────────────── */}
      <section className="ov-section ov-close">
        <div className="ov-close-inner">
          <div className="ov-close-mark mono">·</div>
          <div style={{display:'flex', justifyContent:'center', marginBottom: 24, opacity: 0.8}}>
            <AsciiWave cols={96} amp={1.2} density={0.6} />
          </div>
          <h2 className="ov-close-headline serif">
            We don't sell you a shovel. We sell you the hole, dug to spec, verified by math.
          </h2>
          <p className="ov-close-lede">
            The tool is invisible. The service is everything. And every dollar of it is linked to a
            receipt you can hand a regulator.
          </p>
          <div className="ov-cta-row" style={{justifyContent:'center', marginTop: 32}}>
            <button className="btn accent" onClick={() => onDraft('')}>
              Draft a contract <span className="mono" style={{marginLeft:8, opacity:0.7}}>→</span>
            </button>
            <button className="btn" onClick={() => onTab('Market')}>Browse the market</button>
            <button className="btn ghost" onClick={() => onTab('Portfolio')}>See running contracts</button>
          </div>
          <div className="ov-close-foot mono">
            <span>no seats · no auto-renewal · no exit fees</span>
          </div>
        </div>
      </section>

      {/* ───────────────────────── FOOTER ───────────────────────── */}
      <footer className="ov-footer">
        <div>
          <div className="ov-foot-mark">
            <img src="v2/logo.svg" alt="" />
            sas<em>.xyz</em>
          </div>
          <div className="ov-foot-tagline">
            A marketplace for outcomes, not seats. Receipts, not renewals.
          </div>
        </div>
        <div className="ov-foot-cols">
          <div className="ov-foot-col">
            <div className="ov-foot-head">Product</div>
            <a className="ov-foot-link" onClick={() => onTab('Market')}>Market</a>
            <a className="ov-foot-link" onClick={() => onTab('Portfolio')}>Portfolio</a>
            <a className="ov-foot-link" onClick={() => onTab('Activity')}>Activity log</a>
            <a className="ov-foot-link" onClick={() => onDraft('')}>Draft a contract</a>
          </div>
          <div className="ov-foot-col">
            <div className="ov-foot-head">Learn</div>
            <a className="ov-foot-link" onClick={() => scrollTo('how')}>How it works</a>
            <a className="ov-foot-link" onClick={() => scrollTo('compare')}>vs. SaaS</a>
            <a className="ov-foot-link" onClick={() => scrollTo('shifts')}>The three shifts</a>
          </div>
          <div className="ov-foot-col">
            <div className="ov-foot-head">Company</div>
            <a className="ov-foot-link">About</a>
            <a className="ov-foot-link">Careers</a>
            <a className="ov-foot-link">Contact</a>
            <a className="ov-foot-link">Press</a>
          </div>
          <div className="ov-foot-col">
            <div className="ov-foot-head">Legal</div>
            <a className="ov-foot-link">Terms</a>
            <a className="ov-foot-link">Privacy</a>
            <a className="ov-foot-link">Security</a>
            <a className="ov-foot-link">SOC 2</a>
          </div>
        </div>
        <div className="ov-foot-legal">
          <span>© 2026 sas.xyz · policy 2026.4 · envelope intact</span>
          <span>built in the open · signed with receipts</span>
        </div>
      </footer>
    </div>
  );
};
