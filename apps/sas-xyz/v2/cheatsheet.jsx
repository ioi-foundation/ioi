// Keyboard shortcuts cheatsheet overlay.
// Triggered by ? key or the bottom-left pill.

const SHORTCUTS = [
  { section: 'Navigate', items: [
    { keys: ['1'], label: 'Outcomes' },
    { keys: ['2'], label: 'Queue' },
    { keys: ['3'], label: 'Substrate' },
    { keys: ['4'], label: 'Envelopes' },
    { keys: ['5'], label: 'Settlement' },
  ]},
  { section: 'Actions', items: [
    { keys: ['⌘', 'K'], label: 'Focus the outcome prompt' },
    { keys: ['⌘', '⏎'], label: 'Draft (from the prompt)' },
    { keys: ['?'], label: 'Show this cheatsheet' },
    { keys: ['Esc'], label: 'Close the topmost overlay' },
  ]},
];

const Key = ({ children }) => (
  <span style={{
    fontFamily:'var(--mono)', fontSize:11,
    padding:'3px 7px', minWidth:22, textAlign:'center',
    background:'var(--paper)', border:'1px solid var(--rule)',
    borderBottomWidth:2,
    borderRadius:4, color:'var(--ink)',
    display:'inline-block',
  }}>{children}</span>
);

const Cheatsheet = ({ onClose }) => (
  <div className="swap-scrim" onClick={onClose}>
    <div className="swap-modal" onClick={e => e.stopPropagation()} style={{width:'min(560px, 94vw)'}}>
      <div className="swap-head">
        <div className="swap-eyebrow mono">Keyboard shortcuts</div>
        <h3 className="swap-title serif">Move through <em>outcomes</em> without touching the mouse.</h3>
      </div>
      <div className="swap-body" style={{display:'flex', flexDirection:'column', gap:22}}>
        {SHORTCUTS.map(sec => (
          <div key={sec.section}>
            <div className="mono" style={{fontSize:10, letterSpacing:'0.18em', textTransform:'uppercase', color:'var(--muted)', marginBottom:10}}>
              {sec.section}
            </div>
            <div style={{display:'flex', flexDirection:'column', gap:8}}>
              {sec.items.map((it, i) => (
                <div key={i} style={{display:'flex', alignItems:'center', justifyContent:'space-between', padding:'8px 0', borderBottom: i < sec.items.length - 1 ? '1px dashed var(--rule-soft)' : 'none'}}>
                  <span style={{fontSize:14, color:'var(--ink-2)'}}>{it.label}</span>
                  <span style={{display:'flex', gap:4}}>
                    {it.keys.map((k, j) => (
                      <React.Fragment key={j}>
                        {j > 0 && <span style={{color:'var(--muted-2)', fontSize:11, lineHeight:'22px'}}>+</span>}
                        <Key>{k}</Key>
                      </React.Fragment>
                    ))}
                  </span>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
      <div className="swap-foot">
        <div className="swap-foot-note mono">Press <span style={{color:'var(--ink)', fontWeight:600}}>Esc</span> to close</div>
        <div className="swap-foot-actions">
          <button className="btn" onClick={onClose}>Got it</button>
        </div>
      </div>
    </div>
  </div>
);

window.Cheatsheet = Cheatsheet;
