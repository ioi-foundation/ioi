// Settlement view — the CFO surface.
// Shows: month-to-date ledger, per-outcome unit economics, savings from swaps,
// settlement runs. Everything is outcome-denominated, not seat-denominated.

const SETTLEMENT_MONTH = 'April 2026';
const MTD_SPEND = 2416.50;
const MTD_RECEIPTS = 1094;
const MTD_SAVINGS = 412.80;   // from swaps vs. baseline
const UNIT_COST_TREND = [1.38, 1.41, 1.32, 1.28, 1.24, 1.21, 1.19, 1.21, 1.18, 1.17, 1.14, 1.12]; // last 12 weeks

const LEDGER_BY_CONTRACT = [
  { id: 'ct-books',     code: 'CT-0014', outcome: 'Keep the books tax-ready.',              receipts: 1041, unit: '$0.50', spend: 520.50, baseline: 682.00, delta: -24 },
  { id: 'ct-hires',     code: 'CT-0021', outcome: 'Provision new hires to day-one ready.',   receipts: 7,    unit: '$120',  spend: 840.00, baseline: 900.00, delta: -7 },
  { id: 'ct-cves',      code: 'CT-0019', outcome: 'Keep staging patched against known CVEs.',receipts: 32,   unit: '$12',   spend: 384.00, baseline: 384.00, delta: 0 },
  { id: 'ct-contracts', code: 'CT-0026', outcome: 'Redline inbound vendor contracts.',       receipts: 14,   unit: '$48',   spend: 672.00, baseline: 840.00, delta: -20 },
];

const SETTLEMENT_RUNS = [
  { when: 'Apr 16, 2026', window: 'Apr 09 – Apr 15', txns: 284, amount: 602.14, state: 'settled', hash: '0x8812…aa31' },
  { when: 'Apr 09, 2026', window: 'Apr 02 – Apr 08', txns: 261, amount: 584.02, state: 'settled', hash: '0x7a2c…df82' },
  { when: 'Apr 02, 2026', window: 'Mar 26 – Apr 01', txns: 298, amount: 611.80, state: 'settled', hash: '0x9c3d…a834' },
  { when: 'Mar 26, 2026', window: 'Mar 19 – Mar 25', txns: 251, amount: 577.40, state: 'settled', hash: '0x3a4e…b2a1' },
];

const SWAP_HISTORY = [
  { when: 'Mar 04', from: 'Rally HR',     to: 'Cohort Labor',   contract: 'CT-0021', delta: '−7%',  chain: 'intact' },
  { when: 'Feb 18', from: 'Vertex Legal', to: 'Paragraph Legal',contract: 'CT-0026', delta: '−20%', chain: 'intact' },
  { when: 'Jan 27', from: 'Accru',        to: 'FinFlow',        contract: 'CT-0014', delta: '−12%', chain: 'intact' },
];

const Sparkline = ({ data, height = 36, accent = 'var(--accent)' }) => {
  const max = Math.max(...data);
  const min = Math.min(...data);
  const range = Math.max(max - min, 0.0001);
  const pts = data.map((v, i) => {
    const x = (i / (data.length - 1)) * 100;
    const y = 100 - ((v - min) / range) * 100;
    return `${x},${y}`;
  }).join(' ');
  return (
    <svg viewBox="0 0 100 100" preserveAspectRatio="none" style={{ width: '100%', height }}>
      <polyline points={pts} fill="none" stroke={accent} strokeWidth="2" vectorEffect="non-scaling-stroke" />
      <polyline points={`0,100 ${pts} 100,100`} fill={accent} opacity="0.08" />
    </svg>
  );
};

const SettlementView = () => {
  return (
    <div className="page">
      <div className="hero" style={{ paddingBottom: 32, marginBottom: 40 }} data-screen-label="04 Settlement">
        <div className="hero-eyebrow mono">
          <span className="bullet" style={{ background: 'var(--sage)' }} /> Settlement · {SETTLEMENT_MONTH} · month to date
        </div>
        <h1 className="hero-title serif" style={{ fontSize: 58 }}>
          You paid for <em>outcomes</em>, not seats.
        </h1>
        <p className="hero-lede">
          This is what the money bought — reconciled books, patched systems, provisioned hires, redlined contracts.
          Every dollar ties to a signed receipt. Every swap ties to an audit trail.
        </p>
      </div>

      {/* Top summary band */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 1,
        background: 'var(--rule-soft)',
        border: '1px solid var(--rule-soft)',
        borderRadius: 14,
        overflow: 'hidden',
        marginBottom: 40,
      }}>
        {[
          { k: 'Spend · MTD',      v: `$${MTD_SPEND.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`, sub: 'across 4 contracts' },
          { k: 'Receipts · MTD',   v: MTD_RECEIPTS.toLocaleString(), sub: 'all signed · chain intact' },
          { k: 'Savings vs baseline', v: `$${MTD_SAVINGS.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`, sub: '−14.6% from swaps', good: true },
          { k: 'Next settlement',  v: 'Apr 23', sub: 'Fri 09:00 UTC' },
        ].map((x, i) => (
          <div key={i} style={{ background: 'var(--paper)', padding: '22px 22px 20px' }}>
            <div className="mono" style={{ fontSize: 10, letterSpacing: '0.16em', textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 10 }}>
              {x.k}
            </div>
            <div className="serif" style={{ fontSize: 32, lineHeight: 1, letterSpacing: '-0.015em', color: x.good ? 'var(--sage-ink)' : 'var(--ink)' }}>
              {x.good && <span style={{ marginRight: 4 }}>−</span>}
              <em>{x.v.replace(/^−/, '')}</em>
            </div>
            <div className="mono" style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '0.04em', marginTop: 8 }}>
              {x.sub}
            </div>
          </div>
        ))}
      </div>

      {/* Unit cost trend + swap history side-by-side */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 20, marginBottom: 56 }}>
        <div style={{ padding: '22px 24px', border: '1px solid var(--rule-soft)', borderRadius: 14, background: 'var(--paper)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 4 }}>
            <div>
              <div className="mono" style={{ fontSize: 10, letterSpacing: '0.16em', textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 6 }}>
                Unit cost · blended · last 12 weeks
              </div>
              <div className="serif" style={{ fontSize: 28, letterSpacing: '-0.015em' }}>
                <em>$1.12</em> <span className="mono" style={{ fontSize: 11, color: 'var(--muted)', letterSpacing: '0.05em', marginLeft: 4 }}>/ outcome</span>
              </div>
            </div>
            <div className="mono" style={{ fontSize: 10, letterSpacing: '0.1em', textTransform: 'uppercase', color: 'var(--sage-ink)', fontWeight: 600 }}>
              ▼ 18.8% · 12w
            </div>
          </div>
          <div style={{ marginTop: 10, marginBottom: 10 }}>
            <Sparkline data={UNIT_COST_TREND} height={64} />
          </div>
          <div className="mono" style={{ fontSize: 10.5, color: 'var(--muted)', letterSpacing: '0.04em', borderTop: '1px dashed var(--rule-soft)', paddingTop: 10 }}>
            Blended cost across all outcome types · adjusted for mix. Two provider swaps moved this line in the last 90 days.
          </div>
        </div>

        <div style={{ padding: '22px 24px', border: '1px solid var(--rule-soft)', borderRadius: 14, background: 'var(--paper)' }}>
          <div className="mono" style={{ fontSize: 10, letterSpacing: '0.16em', textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 14 }}>
            Swaps · last 90 days
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {SWAP_HISTORY.map((s, i) => (
              <div key={i} style={{
                display: 'grid',
                gridTemplateColumns: '52px 1fr auto',
                gap: 10,
                alignItems: 'center',
                padding: '10px 0',
                borderTop: i === 0 ? 'none' : '1px dashed var(--rule-soft)',
              }}>
                <div className="mono" style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '0.04em' }}>{s.when}</div>
                <div>
                  <div className="serif" style={{ fontSize: 14, lineHeight: 1.3 }}>
                    <span style={{ color: 'var(--muted)', textDecoration: 'line-through', textDecorationColor: 'var(--rule)' }}>{s.from}</span>
                    <span style={{ color: 'var(--muted-2)', margin: '0 6px' }}>→</span>
                    <em>{s.to}</em>
                  </div>
                  <div className="mono" style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '0.04em', marginTop: 2 }}>
                    {s.contract} · chain {s.chain}
                  </div>
                </div>
                <div className="mono" style={{ fontSize: 11, color: 'var(--sage-ink)', fontWeight: 600, letterSpacing: '0.04em' }}>
                  {s.delta}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Ledger by contract */}
      <div className="section-head">
        <h2 className="section-title serif">Ledger <em>by outcome</em></h2>
        <div className="section-sub mono">{LEDGER_BY_CONTRACT.length} contracts · {SETTLEMENT_MONTH}</div>
      </div>

      <div style={{ border: '1px solid var(--rule-soft)', borderRadius: 12, background: 'var(--paper)', overflow: 'hidden', marginBottom: 56 }}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: '110px 1fr 100px 80px 120px 80px',
          gap: 16,
          padding: '12px 22px',
          background: 'var(--paper-2)',
          fontFamily: 'var(--mono)',
          fontSize: 10,
          letterSpacing: '0.14em',
          textTransform: 'uppercase',
          color: 'var(--muted)',
        }}>
          <span>Contract</span>
          <span>Outcome</span>
          <span style={{ textAlign: 'right' }}>Receipts</span>
          <span style={{ textAlign: 'right' }}>Unit</span>
          <span style={{ textAlign: 'right' }}>Spend</span>
          <span style={{ textAlign: 'right' }}>Δ vs base</span>
        </div>
        {LEDGER_BY_CONTRACT.map((row, i) => (
          <div key={row.id} style={{
            display: 'grid',
            gridTemplateColumns: '110px 1fr 100px 80px 120px 80px',
            gap: 16,
            padding: '16px 22px',
            borderTop: '1px solid var(--rule-soft)',
            alignItems: 'center',
          }}>
            <div className="mono" style={{ fontSize: 11, color: 'var(--ink)', fontWeight: 600, letterSpacing: '0.04em' }}>{row.code}</div>
            <div className="serif" style={{ fontSize: 16, lineHeight: 1.2 }}>
              {row.outcome}
            </div>
            <div className="mono" style={{ fontSize: 12, textAlign: 'right', color: 'var(--ink-2)' }}>{row.receipts.toLocaleString()}</div>
            <div className="mono" style={{ fontSize: 12, textAlign: 'right', color: 'var(--muted)' }}>{row.unit}</div>
            <div className="serif" style={{ fontSize: 17, textAlign: 'right' }}>
              <em>${row.spend.toFixed(2)}</em>
            </div>
            <div className="mono" style={{
              fontSize: 11,
              textAlign: 'right',
              color: row.delta < 0 ? 'var(--sage-ink)' : row.delta > 0 ? 'var(--coral-ink)' : 'var(--muted)',
              fontWeight: row.delta !== 0 ? 600 : 400,
              letterSpacing: '0.04em',
            }}>
              {row.delta > 0 ? '+' : ''}{row.delta}%
            </div>
          </div>
        ))}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '110px 1fr 100px 80px 120px 80px',
          gap: 16,
          padding: '16px 22px',
          borderTop: '1px solid var(--rule)',
          background: 'var(--paper-2)',
          alignItems: 'center',
        }}>
          <div className="mono" style={{ fontSize: 10, letterSpacing: '0.16em', textTransform: 'uppercase', color: 'var(--muted)' }}>Total</div>
          <div />
          <div className="mono" style={{ fontSize: 12, textAlign: 'right', color: 'var(--ink)', fontWeight: 600 }}>
            {LEDGER_BY_CONTRACT.reduce((a, r) => a + r.receipts, 0).toLocaleString()}
          </div>
          <div />
          <div className="serif" style={{ fontSize: 20, textAlign: 'right' }}>
            <em>${LEDGER_BY_CONTRACT.reduce((a, r) => a + r.spend, 0).toFixed(2)}</em>
          </div>
          <div className="mono" style={{ fontSize: 11, textAlign: 'right', color: 'var(--sage-ink)', fontWeight: 600 }}>−14.6%</div>
        </div>
      </div>

      {/* Settlement runs */}
      <div className="section-head">
        <h2 className="section-title serif">Settlement <em>runs</em></h2>
        <div className="section-sub mono">Weekly · signed + published</div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {SETTLEMENT_RUNS.map((r, i) => (
          <div key={i} style={{
            display: 'grid',
            gridTemplateColumns: '120px 1fr 90px 120px 160px auto',
            gap: 16,
            padding: '14px 22px',
            border: '1px solid var(--rule-soft)',
            borderRadius: 10,
            background: 'var(--paper)',
            alignItems: 'center',
          }}>
            <div className="mono" style={{ fontSize: 11, color: 'var(--ink)', fontWeight: 600, letterSpacing: '0.04em' }}>{r.when}</div>
            <div className="mono" style={{ fontSize: 10.5, color: 'var(--muted)', letterSpacing: '0.04em' }}>Window: {r.window}</div>
            <div className="mono" style={{ fontSize: 11, textAlign: 'right', color: 'var(--ink-2)' }}>{r.txns} txns</div>
            <div className="serif" style={{ fontSize: 17, textAlign: 'right' }}>
              <em>${r.amount.toFixed(2)}</em>
            </div>
            <div className="mono" style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '0.04em' }}>chain {r.hash}</div>
            <div className="mono" style={{
              fontSize: 9.5, letterSpacing: '0.14em', textTransform: 'uppercase',
              padding: '4px 8px', borderRadius: 3,
              background: 'oklch(0.95 0.03 185)', color: 'var(--sage-ink)',
              fontWeight: 600,
            }}>
              {r.state}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

window.SettlementView = SettlementView;
