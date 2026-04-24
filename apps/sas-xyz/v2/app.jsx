// v2 main app · IA v3: Contracts · Inbox · Catalog · Providers · Ledger

const TWEAK_DEFAULTS = /*EDITMODE-BEGIN*/{
  "accent": "indigo",
  "density": "default"
}/*EDITMODE-END*/;

const CATEGORY_NAV = [
  { id: 'finance',   label: 'Finance' },
  { id: 'hr',        label: 'People' },
  { id: 'security',  label: 'Security' },
  { id: 'legal',     label: 'Legal' },
  { id: 'support',   label: 'Support' },
  { id: 'analytics', label: 'Analytics' },
];

const Topbar = ({ tab, activeCategory, onTab, onCategory, inboxActionCount, onBell, onDraft, onAvatar, onSearchFocus, variant = 'app' }) => {
  if (variant === 'marketing') {
    return (
      <header className="topbar topbar-marketing">
        <div className="brand" onClick={() => onTab('Overview')} style={{cursor:'pointer'}} title="sas.xyz">
          <img src="v2/logo.svg" alt="" />
          sas<em>.xyz</em>
        </div>
        <nav className="top-nav marketing-nav">
          <a onClick={(e) => { e.preventDefault(); document.getElementById('how')?.scrollIntoView({behavior:'smooth'}); }} href="#how">How it works</a>
          <a onClick={(e) => { e.preventDefault(); document.getElementById('compare')?.scrollIntoView({behavior:'smooth'}); }} href="#compare">vs. SaaS</a>
          <a onClick={(e) => { e.preventDefault(); onTab('Market'); }} href="#">Market</a>
        </nav>
        <div className="top-right">
          <button
            onClick={() => onTab('Home')}
            className="mono"
            style={{
              background:'transparent', border:'none', color:'var(--muted)',
              fontSize:11, letterSpacing:'0.08em', textTransform:'uppercase',
              cursor:'pointer', padding:'8px 10px',
            }}
          >Sign in</button>
          <button
            onClick={() => onTab('Home')}
            className="btn accent"
            style={{padding:'8px 16px', fontSize:12}}
          >
            Open app <span className="mono" style={{marginLeft:6, opacity:0.7}}>→</span>
          </button>
        </div>
      </header>
    );
  }
  return (
    <header className="topbar topbar-app">
      <div className="topbar-row">
        <div className="brand" onClick={() => onTab('Overview')} style={{cursor:'pointer'}} title="About sas.xyz">
          <img src="v2/logo.svg" alt="" />
          sas<em>.xyz</em>
        </div>

        <div className="topbar-search" onClick={onSearchFocus}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{color:'var(--muted-2)', flexShrink:0}}>
            <circle cx="11" cy="11" r="7" />
            <path d="M21 21l-4.3-4.3" />
          </svg>
          <span className="topbar-search-placeholder">
            Search outcomes, providers, contracts…
          </span>
          <span className="mono topbar-search-kbd">⌘K</span>
        </div>

        <div className="top-right">
          <button onClick={onDraft} className="btn" style={{padding:'7px 14px', fontSize:12}}>
            <span style={{fontSize:14, lineHeight:1, marginRight:2}}>+</span> New contract
          </button>
          <button
            onClick={onBell}
            title="Notifications"
            style={{
              position:'relative', width:34, height:34, borderRadius:'50%',
              border:'1px solid var(--rule-soft)', background:'var(--paper)',
              cursor:'pointer', display:'flex', alignItems:'center', justifyContent:'center',
              color:'var(--ink-2)',
            }}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9" />
              <path d="M10.3 21a1.94 1.94 0 0 0 3.4 0" />
            </svg>
            {inboxActionCount > 0 && (
              <span className="mono" style={{
                position:'absolute', top:-3, right:-3,
                minWidth:16, height:16, padding:'0 4px', borderRadius:999,
                background:'var(--coral)', color:'white',
                fontSize:9, fontWeight:600, letterSpacing:'0.02em',
                display:'flex', alignItems:'center', justifyContent:'center',
                border:'2px solid var(--paper)',
              }}>{inboxActionCount}</span>
            )}
          </button>
          <button onClick={onAvatar} title="Account" className="avatar" style={{cursor:'pointer', border:'none', padding:0}}>H</button>
        </div>
      </div>

      {/* Category nav — persistent, service-category-first */}
      <nav className="topbar-cats">
        <button
          className={'cat-item' + (tab === 'Home' && !activeCategory ? ' active' : '')}
          onClick={() => { onCategory(null); onTab('Home'); }}
        >
          Home
        </button>
        <div className="cat-divider" />
        {CATEGORY_NAV.map(c => (
          <button
            key={c.id}
            className={'cat-item' + (activeCategory === c.id ? ' active' : '')}
            onClick={() => { onCategory(c.id); onTab('Market'); }}
          >
            {c.label}
          </button>
        ))}
        <div className="cat-divider" />
        <button
          className={'cat-item' + (tab === 'Market' && !activeCategory ? ' active' : '')}
          onClick={() => { onCategory(null); onTab('Market'); }}
        >
          All market
        </button>
        <div style={{flex:1}} />
        <div className="policy-pill mono" title="Policy version · envelope budget"><span className="dot" />Policy 2026.4 · intact</div>
      </nav>
    </header>
  );
};

const NAV = [
  { key: 'Home',     label: 'Home' },
  { key: 'Market',   label: 'Market' },
];
const TAB_ORDER = NAV.map(n => n.key);

// ─── Persistence ────────────────────────────────────────────────────
const STORAGE_KEY = 'sas.xyz.v2.state';

const loadState = () => {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed.contracts || !parsed.streams) return null;
    return parsed;
  } catch (_) { return null; }
};
const saveState = (payload) => {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify({ ...payload, savedAt: Date.now() })); } catch (_) {}
};
const resetState = () => {
  try { localStorage.removeItem(STORAGE_KEY); } catch (_) {}
  location.reload();
};

// ─── App ────────────────────────────────────────────────────────────
const App = () => {
  const [tab, setTab] = React.useState('Home');
  const [activeCategory, setActiveCategory] = React.useState(null);
  const [marketMode, setMarketMode] = React.useState('outcomes');
  const [onboardOpen, setOnboardOpen] = React.useState(false);
  const [bellOpen, setBellOpen] = React.useState(false);
  const [avatarMenuOpen, setAvatarMenuOpen] = React.useState(false);
  const [cheatsheetOpen, setCheatsheetOpen] = React.useState(false);

  const restored = React.useMemo(() => loadState(), []);
  const [contracts, setContracts]   = React.useState(restored?.contracts   || CONTRACTS);
  const [streams,   setStreams]     = React.useState(restored?.streams     || STREAMS);
  const [drafts,    setDrafts]      = React.useState(restored?.drafts      || DRAFTS);
  const [completes, setCompletes]   = React.useState(restored?.completes   || COMPLETE_CONTRACTS);
  const [inbox,     setInbox]       = React.useState(restored?.inbox       || INBOX_ITEMS);
  const [restoreNoticeUntil, setRestoreNoticeUntil] = React.useState(restored ? Date.now() + 4000 : 0);

  const [openContractId, setOpenContractId] = React.useState(null);
  const [swapCtx, setSwapCtx] = React.useState(null);
  const [receipt, setReceipt] = React.useState(null);
  const [draftPrompt, setDraftPrompt] = React.useState(null);
  const [tweaks, setTweaks] = React.useState(TWEAK_DEFAULTS);
  const [tweaksOpen, setTweaksOpen] = React.useState(false);
  const [toast, setToast] = React.useState(null); // { msg, tone }
  const [providersCat, setProvidersCat] = React.useState('all');

  const showToast = (msg, tone = 'ink') => {
    setToast({ msg, tone, id: Date.now() });
    setTimeout(() => setToast(t => (t && t.msg === msg ? null : t)), 3200);
  };

  React.useEffect(() => { window.STREAMS = streams; }, [streams]);
  React.useEffect(() => { window.CONTRACTS = contracts; }, [contracts]);

  React.useEffect(() => {
    const id = requestAnimationFrame(() => saveState({ contracts, streams, drafts, completes, inbox }));
    return () => cancelAnimationFrame(id);
  }, [contracts, streams, drafts, completes, inbox]);

  const openContract = contracts.find(c => c.id === openContractId)
    || completes.find(c => c.id === openContractId) || null;

  // Tweaks protocol
  React.useEffect(() => {
    const handler = (e) => {
      if (!e.data || typeof e.data !== 'object') return;
      if (e.data.type === '__activate_edit_mode') setTweaksOpen(true);
      if (e.data.type === '__deactivate_edit_mode') setTweaksOpen(false);
    };
    window.addEventListener('message', handler);
    window.parent.postMessage({ type: '__edit_mode_available' }, '*');
    return () => window.removeEventListener('message', handler);
  }, []);

  // Global shortcuts
  React.useEffect(() => {
    const h = (e) => {
      const typing = /INPUT|TEXTAREA/.test((e.target.tagName || ''));
      if (e.key === 'Escape') {
        if (cheatsheetOpen) { setCheatsheetOpen(false); return; }
        if (onboardOpen) { setOnboardOpen(false); return; }
        if (swapCtx) { setSwapCtx(null); return; }
        if (receipt) { setReceipt(null); return; }
        if (draftPrompt !== null) { setDraftPrompt(null); return; }
        if (openContractId) { setOpenContractId(null); return; }
      }
      if (typing) return;
      if (e.key === '?') { setCheatsheetOpen(v => !v); return; }
      const n = parseInt(e.key, 10);
      if (n >= 1 && n <= TAB_ORDER.length) setTab(TAB_ORDER[n - 1]);
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  });

  const updateTweak = (k, v) => {
    const next = { ...tweaks, [k]: v };
    setTweaks(next);
    window.parent.postMessage({ type: '__edit_mode_set_keys', edits: { [k]: v } }, '*');
  };

  const inboxActionCount = inbox.filter(i => i.blocking === 'you').length;

  // ─── Handlers ──────────────────────────────────────────────────
  const handleResolveInbox = (id, cta) => {
    const item = inbox.find(i => i.id === id);
    setInbox(prev => prev.filter(i => i.id !== id));
    if (!item) return;
    const msg = cta.key === 'accept'   ? `Accepted · ${item.value || 'funds released'} to ${item.provider}`
              : cta.key === 'revoke'   ? `Accepted + revoke queue started · ${item.provider}`
              : cta.key === 'partial'  ? `Partial acceptance opened · ${item.provider}`
              : cta.key === 'reject'   ? `Rejected · dispute opened against ${item.provider}`
              : cta.key === 'approve'  ? `Approved · envelope unchanged`
              : cta.key === 'route'    ? `Routed to AP manager`
              : cta.key === 'decline'  ? `Scope held · ${item.provider} notified`
              : cta.key === 'counter'  ? `Counter-proposal drafted`
              : cta.key === 'sign'     ? `Countersigned · ${item.provider} unblocked`
              : cta.key === 'delay'    ? `Start date delayed`
              : 'Resolved';
    const tone = cta.key === 'reject' ? 'coral' : cta.key === 'accept' || cta.key === 'approve' || cta.key === 'sign' ? 'sage' : 'ink';
    showToast(msg, tone);
  };

  const CAT_TO_PROVIDER_CAT = {
    finance:  'Finance · AP',
    hr:       'HR · Onboarding',
    security: 'DevOps · Patching',
    legal:    'Legal · Contracts',
    support:  'Support · Escalation',
    analytics:'Analytics · Dashboards',
  };

  const handleCatalogProviderClick = (item) => {
    setProvidersCat(CAT_TO_PROVIDER_CAT[item.category] || 'all');
    setMarketMode('suppliers');
    setTab('Market');
  };

  const handleCommission = (item) => {
    setDraftPrompt(`${item.title} — ${item.tagline}`);
  };

  const handleResumeDraft = (draft) => {
    setDraftPrompt(draft.prompt);
    setDrafts(prev => prev.filter(d => d.id !== draft.id));
  };

  const handleDiscardDraft = (id) => {
    setDrafts(prev => prev.filter(d => d.id !== id));
  };

  const onDraftGoLive = ({ spec, bid }) => {
    if (!spec) { setDraftPrompt(null); return; }
    const nextCode = `CT-00${30 + contracts.length}`;
    const id = `ct-${Date.now().toString(36)}`;
    const newContract = {
      id, code: nextCode,
      outcome: spec.outcome,
      promise: spec.detail || spec.outcome,
      established: new Date().toLocaleDateString('en-US', { month:'short', day:'numeric', year:'numeric' }),
      health: 'ok',
      pulse: Array(40).fill(0).map((_, i) => i === 39 ? 1 : 0),
      receipts30d: 1,
      spend30d: 0,
      spendUnit: '/ mo',
      substrate: { name: bid?.name || 'FinFlow', id: bid?.id || 'p-finflow', model: `${bid?.name || 'FinFlow'} · provider model` },
      envelope: spec.envelope,
      slaTarget: spec.sla,
      slaActual: 'establishing…',
    };
    const firstReceipt = {
      ts:'just now', ok:true,
      title:`Contract <em>${nextCode}</em> established · first receipt pending`,
      sub:`0x${Math.random().toString(16).slice(2,8)}…${Math.random().toString(16).slice(2,6)} · signed ${bid?.name || 'provider'} · now`,
      amt:null, state:'sealed', unit:'',
    };
    setContracts(prev => [newContract, ...prev]);
    setStreams(prev => ({ ...prev, [id]: [firstReceipt] }));
    setDraftPrompt(null);
    setOpenContractId(id);
  };

  const onSwap = (contract, alt = null) => setSwapCtx({ contract, alt });

  const confirmSwap = () => {
    if (!swapCtx) return;
    const { contract, alt: altPreset } = swapCtx;
    const alt = altPreset || (ALTERNATIVES[contract.id] || [])[0];
    if (!alt) { setSwapCtx(null); return; }

    const fromName = contract.substrate.name;
    const toName = alt.name;

    setContracts(prev => prev.map(c =>
      c.id === contract.id
        ? { ...c, substrate: { ...c.substrate, name: toName, id: alt.id, model: `${toName} · provider model` } }
        : c
    ));

    const handoff = [{
      ts:'just now', ok:true, flag:false,
      title:`Substrate handoff · <em>${fromName}</em> → <em>${toName}</em>`,
      sub:`chain forward-linked · envelope unchanged · receipt schema preserved`,
      amt:null, state:'handoff sealed', unit:'',
    }];
    setStreams(prev => ({ ...prev, [contract.id]: [...handoff, ...(prev[contract.id] || [])] }));

    setTimeout(() => {
      const firstUnder = {
        ts:'2s ago', ok:true, flag:false,
        title:`First receipt under <em>${toName}</em> · contract intact`,
        sub:`0x${Math.random().toString(16).slice(2,8)}…${Math.random().toString(16).slice(2,6)} · signed ${toName} · 2s`,
        amt: alt.price, state:'live', unit: alt.unit,
      };
      setStreams(prev => ({ ...prev, [contract.id]: [firstUnder, ...(prev[contract.id] || [])] }));
    }, 1800);

    setSwapCtx(null);
  };

  // ─── Render ────────────────────────────────────────────────────
  return (
    <div className="app" data-accent={tweaks.accent} data-density={tweaks.density}>
      <Topbar
        tab={tab}
        activeCategory={activeCategory}
        onTab={(t) => { if (t !== 'Market') setActiveCategory(null); setTab(t); }}
        onCategory={setActiveCategory}
        variant={tab === 'Overview' ? 'marketing' : 'app'}
        inboxActionCount={inboxActionCount}
        onBell={() => { setBellOpen(v => !v); setAvatarMenuOpen(false); }}
        onAvatar={() => { setAvatarMenuOpen(v => !v); setBellOpen(false); }}
        onDraft={() => setDraftPrompt('')}
        onSearchFocus={() => showToast('Search coming in a later pass · press / for keyboard shortcuts')}
      />

      {tab === 'Overview' && (
        <OverviewView
          onTab={setTab}
          onDraft={(p) => setDraftPrompt(p || '')}
          contracts={contracts.length}
          totalReceipts={contracts.reduce((a,c) => a + (c.receipts30d || 0), 0)}
          activeEscrow={contracts.reduce((a,c) => a + (c.spend30d || 0) * 3, 0) | 0}
        />
      )}
      {tab === 'Home' && (
        <HomeView
          contracts={contracts}
          draftsList={drafts}
          completes={completes}
          onOpenContract={(c) => setOpenContractId(typeof c === 'string' ? c : c.id)}
          onSwap={onSwap}
          onDraft={(p) => setDraftPrompt(p || '')}
          onResumeDraft={handleResumeDraft}
          onDiscardDraft={handleDiscardDraft}
          onCategory={(catId) => { setActiveCategory(catId); setTab('Market'); }}
          onCommission={handleCommission}
          onBrowseAll={() => { setActiveCategory(null); setTab('Market'); }}
        />
      )}
      {tab === 'Portfolio' && (
        <ContractsView
          contracts={contracts}
          draftsList={drafts}
          completes={completes}
          onOpenContract={(c) => setOpenContractId(typeof c === 'string' ? c : c.id)}
          onSwap={onSwap}
          onDraft={(p) => setDraftPrompt(p || '')}
          onResumeDraft={handleResumeDraft}
          onDiscardDraft={handleDiscardDraft}
        />
      )}
      {tab === 'Market' && (
        <MarketView
          mode={marketMode}
          onMode={setMarketMode}
          activeCategory={activeCategory}
          onCategory={setActiveCategory}
          catalogProps={{ onCommission: handleCommission, onProviderClick: handleCatalogProviderClick }}
          providersProps={{ initialCategory: providersCat, onClearFilter: () => setProvidersCat('all') }}
        />
      )}
      {tab === 'Envelopes' && (
        <div className="page" data-screen-label="Envelopes">
          <div style={{marginBottom: 24}}>
            <div className="mono" style={{fontSize:10, letterSpacing:'0.16em', textTransform:'uppercase', color:'var(--muted-2)'}}>
              Library
            </div>
            <h1 className="serif" style={{fontSize: 36, letterSpacing:'-0.02em', lineHeight:1.1, marginTop: 8, marginBottom: 6}}>
              Envelopes.
            </h1>
            <p className="mono" style={{fontSize:11, color:'var(--muted)', letterSpacing:'0.04em', maxWidth: 620, lineHeight: 1.6}}>
              Bundles of constraints on HOW outcomes get fulfilled. Attach to any contract · swap providers without breaking them.
            </p>
          </div>
          <EnvelopeEditor />
        </div>
      )}
      {tab === 'Activity' && <LedgerView />}
      {tab === 'Inbox'    && <InboxView     items={inbox} onOpenContract={(id) => setOpenContractId(id)} onResolve={handleResolveInbox} />}

      {draftPrompt !== null && (
        <DraftWizard
          initialPrompt={draftPrompt}
          onClose={() => setDraftPrompt(null)}
          onGoLive={onDraftGoLive}
        />
      )}
      {openContract && (
        <ContractDetail
          contract={openContract}
          streamItems={openContract.terminalState ? (COMPLETE_STREAMS[openContract.id] || []) : (streams[openContract.id] || [])}
          onClose={() => setOpenContractId(null)}
          onSwap={onSwap}
          onPickReceipt={(contractId, index) => setReceipt({ contractId, index })}
        />
      )}
      {receipt && (
        <ReceiptPane
          contractId={receipt.contractId}
          index={receipt.index}
          onClose={() => setReceipt(null)}
        />
      )}
      {swapCtx && (
        <SwapModal
          contract={swapCtx.contract}
          alt={swapCtx.alt}
          onClose={() => setSwapCtx(null)}
          onConfirm={confirmSwap}
        />
      )}
      {onboardOpen && <Onboarding onClose={() => setOnboardOpen(false)} />}
      {cheatsheetOpen && <Cheatsheet onClose={() => setCheatsheetOpen(false)} />}

      {/* Bell drawer — decision items ("things blocking you") */}
      {bellOpen && (
        <BellDrawer
          items={inbox}
          onClose={() => setBellOpen(false)}
          onOpenContract={(id) => { setBellOpen(false); setOpenContractId(id); }}
          onResolve={(id, cta) => handleResolveInbox(id, cta)}
          onOpenFull={() => { setBellOpen(false); setTab('Inbox'); }}
        />
      )}

      {/* Avatar dropdown — account surface */}
      {avatarMenuOpen && (
        <AvatarMenu
          onClose={() => setAvatarMenuOpen(false)}
          onItem={(k) => {
            setAvatarMenuOpen(false);
            if (k === 'envelopes') setTab('Envelopes');
            if (k === 'activity')  setTab('Activity');
            if (k === 'inbox')     setTab('Inbox');
            if (k === 'overview')  setTab('Overview');
            if (k === 'shortcuts') setCheatsheetOpen(true);
            if (k === 'onboarding') setOnboardOpen(true);
            if (k === 'reset') resetState();
          }}
        />
      )}

      {toast && (
        <div className="mono" style={{
          position:'fixed', bottom:64, right:18, zIndex:70,
          padding:'12px 16px', borderRadius:10,
          background: toast.tone === 'sage' ? 'oklch(0.32 0.06 160)'
                    : toast.tone === 'coral' ? 'oklch(0.42 0.18 25)'
                    : 'var(--ink)',
          color:'var(--paper)',
          fontSize:12, letterSpacing:'0.03em',
          boxShadow:'0 6px 22px rgba(0,0,0,0.18)',
          display:'flex', gap:12, alignItems:'center', maxWidth: 420,
          animation:'toast-in 0.22s ease-out',
        }}>
          <span style={{width:6, height:6, borderRadius:'50%', background:'var(--paper)', opacity:0.6, flexShrink:0}} />
          {toast.msg}
        </div>
      )}

      {restoreNoticeUntil > Date.now() && (
        <div className="mono" style={{
          position:'fixed', bottom:18, right:18, zIndex:60,
          padding:'10px 14px', borderRadius:8,
          background:'var(--ink)', color:'var(--paper)',
          fontSize:11, letterSpacing:'0.06em',
          boxShadow:'0 4px 16px rgba(0,0,0,0.12)',
          display:'flex', gap:10, alignItems:'center',
        }}>
          <span style={{width:6, height:6, borderRadius:'50%', background:'var(--sage)'}} />
          Restored last session
          <span onClick={resetState} style={{cursor:'pointer', color:'oklch(0.8 0.06 270)', textDecoration:'underline', marginLeft:8}}>reset</span>
          <span onClick={() => setRestoreNoticeUntil(0)} style={{cursor:'pointer', marginLeft:4, opacity:0.7}}>×</span>
        </div>
      )}

      {tab !== 'Overview' && (
        <button
          onClick={() => setCheatsheetOpen(true)}
          title="Keyboard shortcuts (?)"
          className="mono"
          style={{
            position:'fixed', bottom:18, left:18, zIndex:50,
            width:32, height:32, borderRadius:'50%',
            border:'1px solid var(--rule)', background:'var(--paper)',
            cursor:'pointer', fontSize:13, color:'var(--muted)',
            boxShadow:'0 2px 6px rgba(0,0,0,0.04)',
          }}
        >?</button>
      )}

      {tweaksOpen && (
        <div className="tweaks-panel">
          <div className="tweaks-head">
            <span>Tweaks</span>
            <span style={{cursor:'pointer'}} onClick={() => setTweaksOpen(false)}>×</span>
          </div>
          <div className="tweaks-body">
            <div>
              <div className="tweak-label">Accent</div>
              <div className="tweak-row">
                {['indigo','plum','azure','coral'].map(c => (
                  <div key={c} className={`tweak-chip ${tweaks.accent === c ? 'active' : ''}`} onClick={() => updateTweak('accent', c)}>{c}</div>
                ))}
              </div>
            </div>
            <div>
              <div className="tweak-label">Density</div>
              <div className="tweak-row">
                {['default','compact'].map(c => (
                  <div key={c} className={`tweak-chip ${tweaks.density === c ? 'active' : ''}`} onClick={() => updateTweak('density', c)}>{c}</div>
                ))}
              </div>
            </div>
            <div>
              <div className="tweak-label">Demo</div>
              <div className="tweak-row">
                <div className="tweak-chip" onClick={() => setOnboardOpen(true)}>Replay onboarding</div>
                <div className="tweak-chip" onClick={() => setCheatsheetOpen(true)}>Shortcuts</div>
                <div className="tweak-chip" onClick={resetState} style={{color:'var(--coral-ink)'}}>Reset state</div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

ReactDOM.createRoot(document.getElementById('root')).render(<App />);
