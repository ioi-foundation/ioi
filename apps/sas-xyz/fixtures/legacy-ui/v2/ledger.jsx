// Ledger — receipts + payments + disputes.
// Evidentiary + financial record. Broader than the old Settlement view.

const LEDGER_ENTRIES = [
  { date: 'Apr 22', kind: 'payment',  label: 'Weekly settlement · FinFlow Autonomous',  ref: 'CT-0014 · 412 receipts', amount: -161.30, bal: 48210.55, state: 'cleared' },
  { date: 'Apr 21', kind: 'release',  label: 'Escrow release · Sentinel Core',           ref: 'CT-0019 · batch 0411',    amount: -384.00, bal: 48371.85, state: 'cleared' },
  { date: 'Apr 20', kind: 'escrow',   label: 'Escrow deposit · Accru Reconcile',          ref: 'CT-0023 · Q2 forecast',   amount: -2400.00, bal: 48755.85, state: 'pending' },
  { date: 'Apr 19', kind: 'receipt',  label: '1,041 receipts accepted · invoices',        ref: 'CT-0014',                 amount: 0,      bal: 51155.85, state: 'accepted' },
  { date: 'Apr 18', kind: 'payment',  label: 'Weekly settlement · Paragraph Legal',       ref: 'CT-0026 · 14 redlines',   amount: -672.00, bal: 51155.85, state: 'cleared' },
  { date: 'Apr 15', kind: 'dispute',  label: 'Dispute filed · Frontline · batch 0311',    ref: 'CT-0011 · disputed',       amount: 0,      bal: 51827.85, state: 'resolved' },
  { date: 'Apr 15', kind: 'refund',   label: 'Partial refund · Frontline',                ref: 'CT-0011 · arbiter ruling', amount: +312.40, bal: 51827.85, state: 'cleared' },
  { date: 'Apr 12', kind: 'payment',  label: 'Weekly settlement · Cohort Labor',          ref: 'CT-0021 · 4 hires',       amount: -480.00, bal: 51515.45, state: 'cleared' },
  { date: 'Apr 09', kind: 'settle',   label: 'Q1 books close · final settlement',         ref: 'CT-0008 · completed',     amount: -2568.00, bal: 51995.45, state: 'cleared' },
  { date: 'Apr 08', kind: 'receipt',  label: '214 receipts sealed · Q1 close',            ref: 'CT-0008',                 amount: 0,      bal: 54563.45, state: 'accepted' },
];

const kindStyle = {
  payment:  { label:'Payment',  fg:'var(--ink-2)',      bg:'var(--paper-2)' },
  release:  { label:'Release',  fg:'var(--sage-ink)',   bg:'oklch(0.95 0.03 185)' },
  escrow:   { label:'Escrow',   fg:'var(--accent-ink)', bg:'var(--accent-soft)' },
  receipt:  { label:'Receipts', fg:'var(--muted)',      bg:'var(--paper-2)' },
  dispute:  { label:'Dispute',  fg:'var(--coral-ink)',  bg:'oklch(0.96 0.06 25)' },
  refund:   { label:'Refund',   fg:'var(--sage-ink)',   bg:'oklch(0.95 0.03 185)' },
  settle:   { label:'Settled',  fg:'var(--ink-2)',      bg:'var(--paper-2)' },
};

const LedgerView = () => {
  const [tab, setTab] = React.useState('all');
  const filtered = tab === 'all' ? LEDGER_ENTRIES : LEDGER_ENTRIES.filter(e => e.kind === tab);

  const paid30 = LEDGER_ENTRIES.filter(e => e.amount < 0).reduce((a, e) => a + e.amount, 0);
  const escrowOpen = LEDGER_ENTRIES.filter(e => e.state === 'pending').reduce((a, e) => a + Math.abs(e.amount), 0);
  const disputesResolved = LEDGER_ENTRIES.filter(e => e.kind === 'dispute').length;

  return (
    <div className="page">
      <div className="hero" style={{paddingBottom:28, marginBottom:24}} data-screen-label="05 Ledger">
        <div className="hero-eyebrow mono"><span className="bullet" /> Ledger · receipts · payments · disputes</div>
        <h1 className="hero-title serif" style={{fontSize:54}}>
          Every dollar <em>traceable</em> to a signed receipt.
        </h1>
        <p className="hero-lede">
          Your financial and evidentiary record. Receipts accepted, funds held in escrow, payments cleared, disputes filed and resolved — one chronological chain.
        </p>
      </div>

      {/* Summary cards */}
      <div style={{display:'grid', gridTemplateColumns:'repeat(3, 1fr)', gap:12, marginBottom:28}}>
        <SumCard k="Paid · last 30d" v={`$${Math.abs(paid30).toLocaleString(undefined,{minimumFractionDigits:2, maximumFractionDigits:2})}`} sub="across 8 providers" />
        <SumCard k="Held in escrow" v={`$${escrowOpen.toLocaleString(undefined,{minimumFractionDigits:2, maximumFractionDigits:2})}`} sub="releases on acceptance" tone="accent" />
        <SumCard k="Disputes · resolved" v={`${disputesResolved} / ${disputesResolved}`} sub="100% resolution rate" tone="sage" />
      </div>

      {/* Filter tabs */}
      <div style={{display:'flex', gap:6, marginBottom:14, flexWrap:'wrap'}}>
        {[
          { id:'all', label:'All entries' },
          { id:'payment', label:'Payments' },
          { id:'escrow', label:'Escrow' },
          { id:'release', label:'Releases' },
          { id:'receipt', label:'Receipt batches' },
          { id:'dispute', label:'Disputes' },
          { id:'refund', label:'Refunds' },
        ].map(t => (
          <div key={t.id} onClick={() => setTab(t.id)} className="mono" style={{
            fontSize:11, letterSpacing:'0.04em',
            padding:'5px 11px', borderRadius:999, cursor:'pointer',
            background: tab === t.id ? 'var(--ink)' : 'var(--paper-2)',
            color: tab === t.id ? 'var(--paper)' : 'var(--ink-2)',
            border:'1px solid ' + (tab === t.id ? 'var(--ink)' : 'var(--rule-soft)'),
          }}>{t.label}</div>
        ))}
      </div>

      {/* Ledger table */}
      <div style={{border:'1px solid var(--rule-soft)', borderRadius:10, overflow:'hidden', background:'var(--paper)'}}>
        <div style={{
          display:'grid',
          gridTemplateColumns:'70px 100px 1fr 1fr 120px 100px',
          gap:14, padding:'10px 18px',
          background:'var(--paper-2)', borderBottom:'1px solid var(--rule-soft)',
          fontFamily:'var(--mono)', fontSize:9.5, letterSpacing:'0.14em', textTransform:'uppercase', color:'var(--muted)', fontWeight:600,
        }}>
          <div>Date</div>
          <div>Kind</div>
          <div>Entry</div>
          <div>Ref</div>
          <div style={{textAlign:'right'}}>Amount</div>
          <div style={{textAlign:'right'}}>Balance</div>
        </div>
        {filtered.map((e, i) => {
          const st = kindStyle[e.kind];
          return (
            <div key={i} style={{
              display:'grid',
              gridTemplateColumns:'70px 100px 1fr 1fr 120px 100px',
              gap:14, padding:'12px 18px',
              borderBottom: i < filtered.length - 1 ? '1px solid var(--rule-soft)' : 'none',
              alignItems:'center', fontSize:12.5,
            }}>
              <div className="mono" style={{fontSize:11, color:'var(--muted)', letterSpacing:'0.04em'}}>{e.date}</div>
              <div>
                <span className="mono" style={{fontSize:9, letterSpacing:'0.12em', textTransform:'uppercase', padding:'2px 7px', borderRadius:3, background: st.bg, color: st.fg, fontWeight:600}}>
                  {st.label}
                </span>
              </div>
              <div style={{fontSize:13, color:'var(--ink)'}}>{e.label}</div>
              <div className="mono" style={{fontSize:10.5, color:'var(--muted)', letterSpacing:'0.03em'}}>{e.ref}</div>
              <div style={{textAlign:'right', fontFamily:'var(--mono)', fontSize:12, color: e.amount > 0 ? 'var(--sage-ink)' : e.amount < 0 ? 'var(--ink)' : 'var(--muted-2)', fontWeight:600}}>
                {e.amount === 0 ? '—' : (e.amount > 0 ? '+' : '') + '$' + Math.abs(e.amount).toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2})}
              </div>
              <div style={{textAlign:'right', fontFamily:'var(--mono)', fontSize:11, color:'var(--muted)'}}>
                ${e.bal.toLocaleString(undefined, {minimumFractionDigits:2, maximumFractionDigits:2})}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};

const SumCard = ({ k, v, sub, tone }) => (
  <div style={{
    padding:'18px 20px',
    background: tone === 'accent' ? 'var(--accent-soft)' : tone === 'sage' ? 'oklch(0.95 0.03 185)' : 'var(--paper)',
    border:'1px solid ' + (tone === 'accent' ? 'oklch(0.85 0.08 270 / 0.4)' : tone === 'sage' ? 'oklch(0.85 0.08 185 / 0.4)' : 'var(--rule-soft)'),
    borderRadius:12,
  }}>
    <div className="mono" style={{fontSize:10, letterSpacing:'0.14em', textTransform:'uppercase', color:'var(--muted)', marginBottom:6}}>{k}</div>
    <div className="serif" style={{fontSize:30, letterSpacing:'-0.01em', lineHeight:1}}><em>{v}</em></div>
    <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.04em', marginTop:6}}>{sub}</div>
  </div>
);

window.LedgerView = LedgerView;
