// Topbar accessories — bell drawer + avatar menu.
// Both are click-anywhere-to-dismiss popovers anchored to the top-right.

const BellDrawer = ({ items, onClose, onOpenContract, onResolve, onOpenFull }) => {
  const youItems = items.filter(i => i.blocking === 'you');
  const otherCount = items.length - youItems.length;

  React.useEffect(() => {
    const h = (e) => {
      if (e.target.closest('[data-bell-drawer]')) return;
      if (e.target.closest('[title="Notifications"]')) return;
      onClose();
    };
    setTimeout(() => document.addEventListener('mousedown', h), 0);
    return () => document.removeEventListener('mousedown', h);
  }, [onClose]);

  return (
    <div data-bell-drawer style={{
      position:'fixed', top:64, right:24, width:420, maxHeight:'70vh',
      background:'var(--paper)', border:'1px solid var(--rule)', borderRadius:14,
      boxShadow:'0 20px 50px -18px rgba(11,11,46,0.3)',
      zIndex:150, overflow:'hidden',
      display:'flex', flexDirection:'column',
      animation:'popIn 0.18s ease-out',
    }}>
      <div style={{
        padding:'14px 18px', borderBottom:'1px solid var(--rule-soft)',
        display:'flex', justifyContent:'space-between', alignItems:'center',
      }}>
        <div>
          <div className="mono" style={{fontSize:10, letterSpacing:'0.16em', textTransform:'uppercase', color:'var(--muted)'}}>
            Notifications
          </div>
          <div className="serif" style={{fontSize:18, letterSpacing:'-0.01em', marginTop:2}}>
            {youItems.length > 0 ? <><em>{youItems.length}</em> blocking you</> : 'All clear'}
          </div>
        </div>
        <span onClick={onClose} style={{cursor:'pointer', color:'var(--muted)', fontSize:18, padding:'0 4px'}}>×</span>
      </div>

      <div style={{flex:1, overflowY:'auto', padding:'6px 0'}}>
        {youItems.length === 0 && (
          <div style={{padding:'36px 24px', textAlign:'center'}}>
            <div className="mono" style={{fontSize:10, color:'var(--muted-2)', letterSpacing:'0.14em', textTransform:'uppercase'}}>
              nothing to decide right now
            </div>
            <div className="serif" style={{fontSize:15, color:'var(--ink-2)', marginTop:8, lineHeight:1.5}}>
              Receipts are streaming · envelopes intact · no arbitration.
            </div>
          </div>
        )}

        {youItems.map(item => (
          <div key={item.id} style={{
            padding:'14px 18px', borderBottom:'1px dashed var(--rule-soft)',
            display:'flex', flexDirection:'column', gap:8,
          }}>
            <div style={{display:'flex', justifyContent:'space-between', gap:12}}>
              <div style={{minWidth:0, flex:1}}>
                <div className="mono" style={{fontSize:9.5, letterSpacing:'0.14em', textTransform:'uppercase', color:'var(--coral-ink)'}}>
                  {item.kind || 'decision'} · {item.provider}
                </div>
                <div
                  className="serif"
                  style={{fontSize:15, lineHeight:1.35, color:'var(--ink)', marginTop:4}}
                  dangerouslySetInnerHTML={{__html: item.title}}
                />
                {item.value && (
                  <div className="mono" style={{fontSize:10.5, color:'var(--muted)', marginTop:4, letterSpacing:'0.04em'}}>
                    {item.value}
                  </div>
                )}
              </div>
            </div>
            <div style={{display:'flex', gap:6, flexWrap:'wrap'}}>
              {(item.ctas || []).slice(0, 3).map(cta => (
                <button
                  key={cta.key}
                  onClick={() => onResolve(item.id, cta)}
                  className="mono"
                  style={{
                    padding:'5px 10px', borderRadius:999,
                    border:'1px solid ' + (cta.primary ? 'var(--ink)' : 'var(--rule)'),
                    background: cta.primary ? 'var(--ink)' : 'var(--paper)',
                    color: cta.primary ? 'var(--paper)' : 'var(--ink-2)',
                    fontSize:10, letterSpacing:'0.08em', cursor:'pointer',
                  }}
                >{cta.label}</button>
              ))}
              {item.contractId && (
                <span
                  onClick={() => onOpenContract(item.contractId)}
                  className="mono"
                  style={{fontSize:10, color:'var(--accent-ink)', letterSpacing:'0.08em', alignSelf:'center', cursor:'pointer', marginLeft:'auto'}}
                >open contract →</span>
              )}
            </div>
          </div>
        ))}
      </div>

      <div style={{
        padding:'10px 18px', borderTop:'1px solid var(--rule-soft)',
        background:'var(--paper-2)', display:'flex', justifyContent:'space-between', alignItems:'center',
      }}>
        <span className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.06em'}}>
          {otherCount > 0 ? `${otherCount} more waiting on others` : 'up to date'}
        </span>
        <span onClick={onOpenFull} className="mono" style={{fontSize:10, color:'var(--accent-ink)', letterSpacing:'0.08em', cursor:'pointer', textTransform:'uppercase'}}>
          open full inbox →
        </span>
      </div>
    </div>
  );
};

const AvatarMenu = ({ onClose, onItem }) => {
  React.useEffect(() => {
    const h = (e) => {
      if (e.target.closest('[data-avatar-menu]')) return;
      if (e.target.closest('[title="Account"]')) return;
      onClose();
    };
    setTimeout(() => document.addEventListener('mousedown', h), 0);
    return () => document.removeEventListener('mousedown', h);
  }, [onClose]);

  const Group = ({ label, children }) => (
    <div style={{padding:'6px 4px'}}>
      <div className="mono" style={{fontSize:9, letterSpacing:'0.16em', textTransform:'uppercase', color:'var(--muted-2)', padding:'6px 12px'}}>
        {label}
      </div>
      {children}
    </div>
  );

  const Item = ({ k, label, sub, onClick, tone }) => (
    <div onClick={onClick} style={{
      display:'flex', justifyContent:'space-between', alignItems:'center',
      padding:'8px 12px', cursor:'pointer', borderRadius:6,
      color: tone === 'danger' ? 'var(--coral-ink)' : 'var(--ink)',
    }}
      onMouseEnter={e => e.currentTarget.style.background = 'var(--paper-2)'}
      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
    >
      <span style={{fontSize:13}}>{label}</span>
      {sub && <span className="mono" style={{fontSize:9.5, color:'var(--muted-2)', letterSpacing:'0.06em'}}>{sub}</span>}
    </div>
  );

  return (
    <div data-avatar-menu style={{
      position:'fixed', top:64, right:24, width:260,
      background:'var(--paper)', border:'1px solid var(--rule)', borderRadius:12,
      boxShadow:'0 20px 50px -18px rgba(11,11,46,0.3)',
      zIndex:150, overflow:'hidden',
      animation:'popIn 0.16s ease-out',
    }}>
      <div style={{padding:'14px 16px', borderBottom:'1px solid var(--rule-soft)'}}>
        <div className="serif" style={{fontSize:16, letterSpacing:'-0.01em'}}>Hana Okafor</div>
        <div className="mono" style={{fontSize:10, color:'var(--muted)', letterSpacing:'0.04em', marginTop:2}}>
          hana@papabearcarwash.com · admin
        </div>
      </div>

      <Group label="Workspace">
        <Item label="Envelopes"        sub="policy lib"  onClick={() => onItem('envelopes')} />
        <Item label="Activity log"     sub="full ledger" onClick={() => onItem('activity')} />
        <Item label="Inbox (archive)"  sub="all items"   onClick={() => onItem('inbox')} />
        <Item label="Overview"         sub="/ about"     onClick={() => onItem('overview')} />
      </Group>

      <div style={{height:1, background:'var(--rule-soft)', margin:'4px 0'}} />

      <Group label="Account">
        <Item label="Team & roles"      sub="soon" />
        <Item label="Billing & exports" sub="soon" />
        <Item label="API keys"          sub="soon" />
        <Item label="Policy 2026.4"     sub="edit" />
      </Group>

      <div style={{height:1, background:'var(--rule-soft)', margin:'4px 0'}} />

      <Group label="Help">
        <Item label="Keyboard shortcuts" sub="?" onClick={() => onItem('shortcuts')} />
        <Item label="Replay onboarding"          onClick={() => onItem('onboarding')} />
        <Item label="Reset demo state" tone="danger" onClick={() => onItem('reset')} />
      </Group>
    </div>
  );
};

Object.assign(window, { BellDrawer, AvatarMenu });
