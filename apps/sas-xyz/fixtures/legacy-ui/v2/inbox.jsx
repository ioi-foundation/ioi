// Inbox — items awaiting action.
// Sorted by obligation: YOU block → PROVIDER blocks → ARBITER blocks.

const OBLIGATION_GROUPS = [
  {
    key: 'you',
    title: 'Your action required',
    subtitle: 'Nothing moves until you decide',
    accent: 'var(--coral)',
    accentSoft: 'oklch(0.96 0.06 25)',
    accentInk: 'var(--coral-ink)',
  },
  {
    key: 'provider',
    title: 'Waiting on provider',
    subtitle: 'Provider is blocked on your answer to their question',
    accent: 'var(--accent)',
    accentSoft: 'var(--accent-soft)',
    accentInk: 'var(--accent-ink)',
  },
  {
    key: 'arbiter',
    title: 'Waiting on arbiter',
    subtitle: 'Third-party dispute resolution in progress',
    accent: 'var(--muted-2)',
    accentSoft: 'var(--paper-2)',
    accentInk: 'var(--ink-2)',
  },
];

const kindLabel = (k) => ({
  acceptance: 'Acceptance review',
  exception: 'Policy exception',
  clarification: 'Clarification request',
  dispute: 'Dispute thread',
}[k] || k);

const InboxView = ({ items, onOpenContract, onResolve }) => {
  const grouped = React.useMemo(() => {
    const m = {};
    OBLIGATION_GROUPS.forEach(g => { m[g.key] = []; });
    items.forEach(it => { if (!m[it.blocking]) m[it.blocking] = []; m[it.blocking].push(it); });
    return m;
  }, [items]);

  const youCount = grouped.you?.length || 0;

  return (
    <div className="page">
      <div className="hero" style={{paddingBottom:28, marginBottom:28}} data-screen-label="02 Inbox">
        <div className="hero-eyebrow mono">
          <span className="bullet" style={{background: youCount > 0 ? 'var(--coral)' : 'var(--sage)'}} />
          Inbox · {youCount > 0 ? `${youCount} need your action` : 'no action required'}
        </div>
        <h1 className="hero-title serif" style={{fontSize:54}}>
          Sorted by <em>who's waiting on whom</em>.
        </h1>
        <p className="hero-lede">
          Your own obligations surface first. Next: things your providers are asking before they can proceed. Last: disputes being resolved by a third party — nothing for you to do but track.
        </p>
      </div>

      {OBLIGATION_GROUPS.map(g => {
        const list = grouped[g.key] || [];
        if (list.length === 0) return null;
        return (
          <section key={g.key} style={{marginBottom: 32}}>
            <div style={{
              display:'flex', alignItems:'baseline', gap:14,
              padding:'0 0 12px',
              borderBottom:'1px solid var(--rule-soft)',
              marginBottom: 14,
            }}>
              <div style={{width:6, height:6, borderRadius:'50%', background: g.accent, alignSelf:'center'}} />
              <h2 className="serif" style={{fontSize:24, margin:0, letterSpacing:'-0.01em', fontWeight:400}}>
                <em>{g.title}</em>
              </h2>
              <span className="mono" style={{fontSize:11, color:'var(--muted)', letterSpacing:'0.04em'}}>
                {list.length} · {g.subtitle}
              </span>
            </div>

            <div style={{display:'flex', flexDirection:'column', gap:10}}>
              {list.map(it => (
                <InboxRow key={it.id} item={it} group={g} onOpenContract={onOpenContract} onResolve={onResolve} />
              ))}
            </div>
          </section>
        );
      })}

      {items.length === 0 && (
        <div style={{padding:'80px 20px', textAlign:'center'}}>
          <div className="serif" style={{fontSize:30, color:'var(--muted)'}}>Inbox zero.</div>
          <div className="mono" style={{fontSize:11, color:'var(--muted-2)', letterSpacing:'0.08em', marginTop:8, textTransform:'uppercase'}}>
            Nothing needs your attention
          </div>
        </div>
      )}
    </div>
  );
};

const InboxRow = ({ item, group, onOpenContract, onResolve }) => {
  const [expanded, setExpanded] = React.useState(item.blocking === 'you');
  const isMuted = item.cta?.[0]?.tone === 'muted';

  return (
    <div style={{
      border: item.blocking === 'you' ? `1.5px solid ${group.accent}` : '1px solid var(--rule-soft)',
      background:'var(--paper)',
      borderRadius:12,
      overflow:'hidden',
    }}>
      <div
        onClick={() => setExpanded(v => !v)}
        style={{
          display:'grid',
          gridTemplateColumns:'auto 1fr auto auto',
          gap:16,
          alignItems:'center',
          padding:'14px 18px',
          cursor:'pointer',
        }}
      >
        <div style={{
          padding:'3px 8px', borderRadius:3,
          background: group.accentSoft, color: group.accentInk,
          fontFamily:'var(--mono)', fontSize:9.5, letterSpacing:'0.12em',
          textTransform:'uppercase', fontWeight:600,
          minWidth: 88, textAlign:'center',
        }}>
          {kindLabel(item.kind)}
        </div>

        <div style={{minWidth:0}}>
          <div className="serif" style={{fontSize:17, lineHeight:1.3, overflow:'hidden', textOverflow:'ellipsis', whiteSpace: expanded ? 'normal' : 'nowrap'}}>
            {item.title}
          </div>
          <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.04em', marginTop:3}}>
            {item.contractCode} · {item.provider} · {item.ts}
            {item.value && <span style={{color:'var(--ink-2)', fontWeight:600}}> · {item.value}</span>}
          </div>
        </div>

        <div className="mono" style={{fontSize:10, color:'var(--muted-2)', letterSpacing:'0.04em'}}>
          {item.id}
        </div>

        <div style={{color:'var(--muted)', fontSize:11, transform: expanded ? 'rotate(180deg)' : 'none', transition:'transform .15s'}}>
          ▾
        </div>
      </div>

      {expanded && (
        <div style={{padding:'4px 18px 18px', display:'flex', flexDirection:'column', gap:14}}>
          <div style={{fontSize:13.5, lineHeight:1.55, color:'var(--ink-2)', maxWidth:680}}>
            {item.body}
          </div>

          {item.contractId && (
            <div onClick={() => onOpenContract(item.contractId)} className="mono" style={{fontSize:11, color:'var(--accent-ink)', letterSpacing:'0.04em', cursor:'pointer', alignSelf:'flex-start'}}>
              Open {item.contractCode} →
            </div>
          )}

          <div style={{display:'flex', gap:8, flexWrap:'wrap', paddingTop: 2}}>
            {item.cta.map(c => (
              <button key={c.key}
                onClick={() => !isMuted && onResolve(item.id, c)}
                disabled={isMuted}
                className={`btn ${c.tone === 'primary' ? 'accent' : c.tone === 'muted' ? '' : 'ghost'}`}
                style={c.tone === 'muted' ? { opacity:0.6, cursor:'default' } : {}}
              >
                {c.label}
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

window.InboxView = InboxView;
