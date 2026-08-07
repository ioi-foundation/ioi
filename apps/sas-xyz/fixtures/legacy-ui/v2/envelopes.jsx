// Envelope editor — policy-as-code, but human-readable.
// An envelope is a bundle of constraints on HOW outcomes get fulfilled.
// Attach to any contract; swap providers never breaks it.

const ENVELOPES = [
  {
    id: 'env-alpha',
    name: 'Alpha',
    scope: 'Finance',
    owner: 'Mia L. · VP Finance',
    contracts: ['CT-0014'],
    providersPassing: 6,
    providersTotal: 9,
    state: 'enforced',
    rules: [
      { id: 'r1', kind: 'cap',       text: 'Total spend capped at $500/mo',                  state: 'active' },
      { id: 'r2', kind: 'allowlist', text: 'Vendors must be on Acme allowlist',              state: 'active' },
      { id: 'r3', kind: 'gate',      text: 'Human review if invoice has no PO',              state: 'active' },
      { id: 'r4', kind: 'gate',      text: 'Human review if variance > 0.5%',                state: 'active' },
      { id: 'r5', kind: 'region',    text: 'Data may reside in US or EU only',               state: 'active' },
    ],
  },
  {
    id: 'env-mike',
    name: 'Mike',
    scope: 'HR',
    owner: 'Jordan S. · Head of People',
    contracts: ['CT-0021'],
    providersPassing: 3,
    providersTotal: 7,
    state: 'enforced',
    rules: [
      { id: 'r1', kind: 'allowlist', text: 'Role templates must be pre-approved',           state: 'active' },
      { id: 'r2', kind: 'region',    text: 'Geo-fenced to HQ regions (US / EU / SG)',       state: 'active' },
      { id: 'r3', kind: 'rollback',  text: '72h rollback window on every provisioning',     state: 'active' },
      { id: 'r4', kind: 'gate',      text: 'Human sign-off on role changes post-hire',      state: 'active' },
    ],
  },
  {
    id: 'env-bravo',
    name: 'Bravo',
    scope: 'DevOps',
    owner: 'G. Reid · SRE Lead',
    contracts: ['CT-0019'],
    providersPassing: 2,
    providersTotal: 5,
    state: 'enforced',
    rules: [
      { id: 'r1', kind: 'gate',      text: 'Staging only · prod requires two-eyes approval', state: 'active' },
      { id: 'r2', kind: 'rollback',  text: 'Full rollback snapshot before every patch',      state: 'active' },
      { id: 'r3', kind: 'gate',      text: 'Red/green test suite must pass before promote',  state: 'active' },
    ],
  },
  {
    id: 'env-juliet',
    name: 'Juliet',
    scope: 'Legal',
    owner: 'S. Liu · General Counsel',
    contracts: ['CT-0026'],
    providersPassing: 4,
    providersTotal: 8,
    state: 'enforced',
    rules: [
      { id: 'r1', kind: 'allowlist', text: 'Playbook v3.1 required',                         state: 'active' },
      { id: 'r2', kind: 'gate',      text: 'No signing authority — review only',             state: 'active' },
      { id: 'r3', kind: 'gate',      text: 'Escalation to GC over $100k exposure',           state: 'active' },
    ],
  },
];

const RULE_ICON = { cap: '$', allowlist: '✓', gate: '?', region: '◎', rollback: '↺' };

const EnvelopeEditor = () => {
  const [activeId, setActiveId] = React.useState(ENVELOPES[0].id);
  const [envs, setEnvs] = React.useState(ENVELOPES);
  const [dirty, setDirty] = React.useState(false);
  const active = envs.find(e => e.id === activeId);

  const toggleRule = (ruleId) => {
    setEnvs(prev => prev.map(e => e.id !== activeId ? e : {
      ...e,
      rules: e.rules.map(r => r.id !== ruleId ? r : { ...r, state: r.state === 'active' ? 'muted' : 'active' }),
    }));
    setDirty(true);
  };

  return (
    <div className="page">
      <div className="hero" style={{ paddingBottom: 32, marginBottom: 32 }} data-screen-label="03 Envelopes">
        <div className="hero-eyebrow mono">
          <span className="bullet" /> Envelopes · policy across every outcome
        </div>
        <h1 className="hero-title serif" style={{ fontSize: 58 }}>
          Write policy <em>once</em>. Substrate inherits it.
        </h1>
        <p className="hero-lede">
          Envelopes are the durable thing. Providers come and go — the rules stay attached to the outcome.
          Any provider that can't pass a rule simply can't bid.
        </p>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: 20, alignItems: 'start' }}>
        {/* Envelope list */}
        <aside style={{ display: 'flex', flexDirection: 'column', gap: 6, position: 'sticky', top: 90 }}>
          <div className="mono" style={{ fontSize: 10, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'var(--muted)', padding: '4px 10px 10px' }}>
            {envs.length} envelopes
          </div>
          {envs.map(e => (
            <div key={e.id}
              onClick={() => { setActiveId(e.id); setDirty(false); }}
              style={{
                padding: '14px 16px',
                border: e.id === activeId ? '1.5px solid var(--ink)' : '1px solid var(--rule-soft)',
                background: e.id === activeId ? 'var(--paper)' : 'transparent',
                borderRadius: 10,
                cursor: 'pointer',
                transition: 'all .15s',
              }}>
              <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 8, marginBottom: 2 }}>
                <div className="serif" style={{ fontSize: 20, lineHeight: 1.1 }}>{e.name}</div>
                <div className="mono" style={{ fontSize: 9, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--sage-ink)', fontWeight: 600 }}>
                  {e.state}
                </div>
              </div>
              <div className="mono" style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '0.04em' }}>
                {e.scope} · {e.rules.length} rules · {e.contracts.length} contract{e.contracts.length !== 1 ? 's' : ''}
              </div>
            </div>
          ))}
          <div
            style={{
              padding: '14px 16px',
              border: '1px dashed var(--rule)',
              borderRadius: 10,
              cursor: 'pointer',
              marginTop: 6,
            }}
          >
            <div className="serif" style={{ fontSize: 18, color: 'var(--muted)', lineHeight: 1.1 }}>+ New envelope</div>
            <div className="mono" style={{ fontSize: 10, color: 'var(--muted-2)', letterSpacing: '0.04em', marginTop: 2 }}>
              Start from a template or blank
            </div>
          </div>
        </aside>

        {/* Editor */}
        <main style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{
            padding: '26px 28px',
            background: 'var(--paper)',
            border: '1px solid var(--rule-soft)',
            borderRadius: 14,
            display: 'flex',
            flexDirection: 'column',
            gap: 14,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 20 }}>
              <div>
                <div className="mono" style={{ fontSize: 10, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 8 }}>
                  Envelope · {active.scope}
                </div>
                <h2 className="serif" style={{ fontSize: 44, lineHeight: 0.98, letterSpacing: '-0.02em', margin: 0, fontWeight: 400 }}>
                  <em>{active.name}</em>
                </h2>
                <div className="mono" style={{ fontSize: 11, color: 'var(--muted)', letterSpacing: '0.04em', marginTop: 8 }}>
                  Owned by {active.owner} · attached to {active.contracts.join(', ')}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn ghost">Diff vs. last week</button>
                <button className="btn" style={{ opacity: dirty ? 1 : 0.4, pointerEvents: dirty ? 'auto' : 'none' }}>
                  Publish v{active.id === 'env-alpha' ? '2.4' : '1.2'} →
                </button>
              </div>
            </div>

            {/* Fit band */}
            <div style={{
              marginTop: 4,
              padding: '14px 16px',
              background: 'var(--paper-2)',
              border: '1px solid var(--rule-soft)',
              borderRadius: 10,
              display: 'grid',
              gridTemplateColumns: '1fr auto',
              gap: 16,
              alignItems: 'center',
            }}>
              <div>
                <div className="mono" style={{ fontSize: 10, letterSpacing: '0.14em', textTransform: 'uppercase', color: 'var(--muted)', marginBottom: 8 }}>
                  Provider fit · who can bid under these rules
                </div>
                <div style={{
                  height: 8,
                  background: 'var(--rule-soft)',
                  borderRadius: 4,
                  overflow: 'hidden',
                  position: 'relative',
                }}>
                  <div style={{
                    width: `${(active.providersPassing / active.providersTotal) * 100}%`,
                    height: '100%',
                    background: 'var(--sage)',
                    borderRadius: 4,
                  }} />
                </div>
              </div>
              <div className="serif" style={{ fontSize: 28, letterSpacing: '-0.015em', lineHeight: 1, textAlign: 'right' }}>
                <em>{active.providersPassing}</em>
                <span className="mono" style={{ fontSize: 13, color: 'var(--muted)', marginLeft: 4 }}>/ {active.providersTotal}</span>
                <div className="mono" style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '0.08em', textTransform: 'uppercase', marginTop: 4 }}>
                  providers passing
                </div>
              </div>
            </div>
          </div>

          {/* Rules list */}
          <div style={{
            padding: '6px 0',
            background: 'var(--paper)',
            border: '1px solid var(--rule-soft)',
            borderRadius: 14,
          }}>
            <div style={{
              padding: '14px 22px 12px',
              display: 'flex', justifyContent: 'space-between', alignItems: 'baseline',
              borderBottom: '1px solid var(--rule-soft)',
            }}>
              <div className="mono" style={{ fontSize: 10, letterSpacing: '0.18em', textTransform: 'uppercase', color: 'var(--ink)', fontWeight: 600 }}>
                Rules · {active.rules.filter(r => r.state === 'active').length} active
              </div>
              <div className="mono" style={{ fontSize: 10, color: 'var(--muted)', letterSpacing: '0.04em' }}>
                Toggle to stage changes — nothing enforces until you publish.
              </div>
            </div>
            {active.rules.map(r => (
              <div key={r.id} style={{
                display: 'grid',
                gridTemplateColumns: '30px 76px 1fr auto',
                gap: 14,
                alignItems: 'center',
                padding: '16px 22px',
                borderTop: '1px solid var(--rule-soft)',
                opacity: r.state === 'active' ? 1 : 0.45,
              }}>
                <div style={{
                  width: 26, height: 26, borderRadius: '50%',
                  background: r.state === 'active' ? 'var(--accent-soft)' : 'var(--paper-2)',
                  color: r.state === 'active' ? 'var(--accent-ink)' : 'var(--muted)',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontFamily: 'var(--serif)', fontSize: 13, fontWeight: 600,
                }}>
                  {RULE_ICON[r.kind] || '·'}
                </div>
                <div className="mono" style={{ fontSize: 9.5, letterSpacing: '0.16em', textTransform: 'uppercase', color: 'var(--muted)' }}>
                  {r.kind}
                </div>
                <div className="serif" style={{ fontSize: 17, lineHeight: 1.3, color: 'var(--ink)' }}>
                  {r.text}
                </div>
                <div
                  onClick={() => toggleRule(r.id)}
                  className="mono"
                  style={{
                    fontSize: 10, letterSpacing: '0.14em', textTransform: 'uppercase',
                    padding: '5px 10px', borderRadius: 999,
                    cursor: 'pointer',
                    background: r.state === 'active' ? 'oklch(0.95 0.03 185)' : 'var(--paper-2)',
                    color: r.state === 'active' ? 'var(--sage-ink)' : 'var(--muted)',
                    fontWeight: 600,
                    border: '1px solid ' + (r.state === 'active' ? 'oklch(0.82 0.05 185)' : 'var(--rule-soft)'),
                  }}
                >
                  {r.state}
                </div>
              </div>
            ))}

            <div
              style={{
                padding: '14px 22px',
                borderTop: '1px dashed var(--rule-soft)',
                fontFamily: 'var(--mono)',
                fontSize: 11,
                color: 'var(--accent-ink)',
                letterSpacing: '0.04em',
                cursor: 'pointer',
              }}
            >
              + add rule · cap · allowlist · gate · region · rollback · attestation
            </div>
          </div>

          {/* Change impact */}
          {dirty && (
            <div style={{
              padding: '18px 22px',
              background: 'var(--ink)',
              color: 'var(--paper)',
              borderRadius: 12,
              display: 'grid',
              gridTemplateColumns: '1fr auto',
              gap: 20,
              alignItems: 'center',
            }}>
              <div>
                <div className="mono" style={{ fontSize: 10, letterSpacing: '0.16em', textTransform: 'uppercase', color: 'oklch(0.8 0.06 270)', marginBottom: 8 }}>
                  Staged changes · will re-evaluate {active.contracts.length} contract · {active.providersTotal} providers
                </div>
                <div className="serif" style={{ fontSize: 18, lineHeight: 1.4 }}>
                  Rule toggles staged. Publishing will re-run provider fit checks and may force swaps on non-compliant substrate.
                </div>
              </div>
              <button className="btn accent">Publish envelope →</button>
            </div>
          )}
        </main>
      </div>
    </div>
  );
};

window.EnvelopeEditor = EnvelopeEditor;
