// Instances, Audit, Settlement pages
const InstancesPage = () => (
  <div className="content">
    <div className="page-head">
      <div>
        <div className="eyebrow"><span className="bullet"/> Operations / Active</div>
        <h1 className="page-title"><em>In flight.</em></h1>
        <p className="page-lede">Services currently processing governed outcomes. Health is computed from evidence freshness, SLA attainment, and policy drift.</p>
      </div>
      <div className="stat-strip">
        <div className="stat"><span className="stat-label">Instances</span><span className="stat-val">{INSTANCES.length}</span></div>
        <div className="stat-sep"/>
        <div className="stat"><span className="stat-label">Outcomes MTD</span><span className="stat-val">1,051</span></div>
        <div className="stat-sep"/>
        <div className="stat"><span className="stat-label">Drift</span><span className="stat-val">0<span className="unit">events</span></span></div>
      </div>
    </div>

    <div className="tbl-card">
      <div className="tbl-card-head" style={{gridTemplateColumns:'2fr 1fr 1fr 1fr 1fr 1fr 80px'}}>
        <div>Service</div><div>Posture</div><div>Health</div><div>Outcomes MTD</div><div>Spend MTD</div><div>Last sync</div><div></div>
      </div>
      {INSTANCES.map(i => (
        <div key={i.id} className="audit-row" style={{gridTemplateColumns:'2fr 1fr 1fr 1fr 1fr 1fr 80px'}}>
          <div>
            <div className="serif" style={{fontSize:20, lineHeight:1.1}}>{i.name}</div>
            <div className="mono" style={{fontSize:10, color:'var(--muted)', marginTop:4, letterSpacing:'0.05em'}}>{i.provider} · ID {i.id}</div>
          </div>
          <div><PostureBadge posture={i.postureKey === 'gated' ? 'Approval-gated' : i.postureKey === 'local' ? 'Local-first' : 'Autonomous'} postureKey={i.postureKey}/></div>
          <div><span className="live-dot"><span className="pulse"/>{i.health}</span></div>
          <div className="serif" style={{fontSize:22}}>{i.outcomes.toLocaleString()}</div>
          <div className="serif" style={{fontSize:22}}>${i.spend.toFixed(2)}</div>
          <div className="mono" style={{fontSize:11, color:'var(--muted)'}}>{i.lastSync}</div>
          <div style={{textAlign:'right'}}><Icon name="chevR" size={14}/></div>
        </div>
      ))}
    </div>
  </div>
);

const AuditPage = () => (
  <div className="content">
    <div className="page-head">
      <div>
        <div className="eyebrow"><span className="bullet"/> Operations / Audit</div>
        <h1 className="page-title">An <em>immutable</em> record<br/>of delivered work.</h1>
        <p className="page-lede">Every outcome produces a signed artifact and an evidence hash. Regulators, auditors, and your own legal team can verify independently.</p>
      </div>
      <div className="stat-strip">
        <div className="stat"><span className="stat-label">Entries (30d)</span><span className="stat-val">1,287</span></div>
        <div className="stat-sep"/>
        <div className="stat"><span className="stat-label">Chain status</span><span className="stat-val" style={{fontSize:20, color:'var(--sage-ink)'}}>Intact</span></div>
        <div className="stat-sep"/>
        <div className="stat"><span className="stat-label">Disputes</span><span className="stat-val">0</span></div>
      </div>
    </div>

    <div className="tbl-card">
      <div className="tbl-card-head">
        <div>Timestamp</div><div>Service / Proof</div><div>Artifact</div><div>Evidence hash</div><div>State</div>
      </div>
      {AUDIT_ROWS.map((a, i) => (
        <div key={i} className="audit-row">
          <div className="audit-time">
            <span className="date">{a.date}</span>
            <span className="t">{a.time}</span>
          </div>
          <div>
            <div className="audit-name">{a.name}</div>
            <div className="mono" style={{fontSize:10, color:'var(--muted)', marginTop:3, letterSpacing:'0.05em'}}>Verified provider</div>
          </div>
          <div className="audit-proof" style={{display:'flex', alignItems:'center', gap:8}}>
            <Icon name="file" size={12}/> {a.proof}
          </div>
          <div className="audit-hash">{a.hash}</div>
          <div><span className="audit-state">{a.state}</span></div>
        </div>
      ))}
    </div>
  </div>
);

const SettlementPage = () => (
  <div className="content">
    <div className="page-head">
      <div>
        <div className="eyebrow"><span className="bullet"/> Finance / Settlement</div>
        <h1 className="page-title">Pay for <em>delivered</em> outcomes,<br/>not for attempts.</h1>
        <p className="page-lede">Invoices settle automatically when evidence is accepted. Disputes pause payment without pausing service — the bonded rail handles the rest.</p>
      </div>
      <div className="stat-strip">
        <div className="stat"><span className="stat-label">Next settlement</span><span className="stat-val" style={{fontSize:20}}>May 01</span></div>
        <div className="stat-sep"/>
        <div className="stat"><span className="stat-label">Committed</span><span className="stat-val">$900<span className="unit">/mo</span></span></div>
        <div className="stat-sep"/>
        <div className="stat"><span className="stat-label">Variable</span><span className="stat-val">$520<span className="unit">MTD</span></span></div>
      </div>
    </div>

    <div className="settle-grid">
      <div className="ledger-card">
        <div className="ledger-label">Accrued spend · month to date</div>
        <div className="ledger-amount"><em>$1,420</em><span className="cents">.50</span></div>
        <div className="ledger-sub">Across 3 active services · 1,051 settled outcomes · 0 disputes</div>
        <div className="ledger-rows">
          <div className="ledger-row">
            <span className="k">Fixed subscriptions</span>
            <span className="v">$900.<em>00</em></span>
          </div>
          <div className="ledger-row">
            <span className="k">Outcome-based fees</span>
            <span className="v">$520.<em>50</em></span>
          </div>
          <div className="ledger-row total">
            <span className="k">Settled on</span>
            <span className="v"><em>May 01, 2026</em></span>
          </div>
        </div>
      </div>

      <div className="breakdown-card">
        <div className="section-label" style={{marginBottom:18}}><span>By service</span><span className="right">MTD</span></div>
        {[
          { label: 'FinFlow Invoice Ops', count: '1,041 outcomes', cost: '$520.50', trend: '+12%', up: true },
          { label: 'Sager Procurement', count: '1 seat licensed', cost: '$450.00', trend: 'Flat' },
          { label: 'Cohort Onboarding', count: '7 hires provisioned', cost: '$840.00', trend: 'New', up: true },
          { label: 'Sentinel Remediation', count: '0 outcomes', cost: '$0.00', trend: 'Dormant' },
        ].map(b => (
          <div key={b.label} className="breakdown-item">
            <div>
              <div className="breakdown-name">{b.label}</div>
              <div className="breakdown-sub">{b.count}</div>
            </div>
            <div>
              <div className="breakdown-amt">{b.cost}</div>
              <div className={`breakdown-trend ${b.up ? 'up' : ''}`}>{b.trend}</div>
            </div>
          </div>
        ))}
      </div>
    </div>
  </div>
);

window.InstancesPage = InstancesPage;
window.AuditPage = AuditPage;
window.SettlementPage = SettlementPage;
