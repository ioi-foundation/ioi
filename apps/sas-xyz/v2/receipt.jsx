// Full signed receipt — the "proof" layer.
// Keyed by contract id, each stream row maps to a receipt fixture here.

const RECEIPTS = {
  'ct-books': {
    // Fresh invoice match
    0: {
      title: 'Invoice <em>INV-22844</em> matched to <em>PO-8814</em>',
      ts: 'Apr 19, 2026 · 14:07:22 UTC',
      duration: '3.4s end-to-end',
      cost: '$1.20',
      state: 'matched',
      provider: 'FinFlow Autonomous v4.2',
      envelope: 'Alpha · Finance',
      facts: [
        { k: 'Outcome', v: 'matched', serif: true },
        { k: 'Amount', v: '$4,218.00', serif: true },
        { k: 'Vendor', v: 'Relay Auth, Inc.', mono: true },
        { k: 'Chain ref', v: '0x7a2c9f…df82', mono: true },
      ],
      trace: [
        { t: '+0.00s', kind: 'in',   lbl: 'Input',   body: 'Invoice PDF <code>INV-22844.pdf</code> received via supplier portal webhook' },
        { t: '+0.4s',  kind: 'tool', lbl: 'Extract', body: 'Line items parsed · 4 SKUs · totals reconciled · confidence 0.99', ms: '410ms' },
        { t: '+0.9s',  kind: 'tool', lbl: 'Match',   body: 'Queried PO ledger → <code>PO-8814</code> proposed (tolerance ±0.5%)', ms: '520ms' },
        { t: '+1.6s',  kind: 'tool', lbl: 'Check',   body: 'Three-way match vs. <code>PO-8814</code> + receipt <code>RC-9033</code> → all fields within policy', ms: '700ms' },
        { t: '+2.1s',  kind: 'ok',   lbl: 'Decision',body: 'Approved for payment run on Fri · no human review required' },
        { t: '+3.4s',  kind: 'ok',   lbl: 'Sealed',  body: 'Receipt signed by FinFlow · hash chained to prior · published to Acme audit stream' },
      ],
      policyChecks: [
        { pass: true,  rule: 'Vendor on allowlist (rel-auth-inc)' },
        { pass: true,  rule: 'Amount under budget cap ($500/mo ceiling not breached)' },
        { pass: true,  rule: 'PO match within ±0.5% tolerance' },
        { pass: true,  rule: 'Three-way match (PO · receipt · invoice)' },
        { pass: true,  rule: 'Human review skip — confidence ≥ 0.97 threshold' },
      ],
      chain: {
        thisHash:  '0x7a2c9f02ab14ee88c33119b428a7df82',
        prevHash:  '0x4b1a3e7711c299bbaf001ce8c921',
        signer:    'FinFlow Autonomous · key-id fn-prod-02',
        published: 'acme-audit-stream-2026 · block #144,209',
      },
    },
    // Flagged no-PO invoice
    1: {
      title: 'Invoice <em>INV-22843</em> flagged · no PO on file',
      ts: 'Apr 19, 2026 · 14:03:10 UTC',
      duration: '1.2s · routed to human',
      cost: '$0.40',
      state: 'flagged',
      flag: true,
      provider: 'FinFlow Autonomous v4.2',
      envelope: 'Alpha · Finance',
      facts: [
        { k: 'Outcome', v: 'routed', serif: true },
        { k: 'Amount', v: '$87.14', serif: true },
        { k: 'Vendor', v: 'Coffeehaus LLC', mono: true },
        { k: 'Routed to', v: 'Mia L. · Finance', mono: true },
      ],
      trace: [
        { t: '+0.00s', kind: 'in',   lbl: 'Input',    body: 'Invoice <code>INV-22843.pdf</code> received via AP inbox' },
        { t: '+0.3s',  kind: 'tool', lbl: 'Extract',  body: 'Line items parsed · 1 SKU · confidence 0.97', ms: '310ms' },
        { t: '+0.5s',  kind: 'tool', lbl: 'Match',    body: 'No matching PO found in ledger · no recurring vendor template', ms: '220ms' },
        { t: '+0.9s',  kind: 'flag', lbl: 'Exception',body: 'Envelope requires PO or recurring template · cannot auto-approve' },
        { t: '+1.2s',  kind: 'ok',   lbl: 'Routed',   body: 'Case <code>EX-0812</code> opened for <b>Mia L.</b> with extracted context + vendor history' },
      ],
      policyChecks: [
        { pass: true,  rule: 'Vendor on allowlist (coffeehaus-llc)' },
        { pass: true,  rule: 'Amount under budget cap' },
        { pass: false, rule: 'PO match required (none found)' },
        { pass: true,  rule: 'Exception routed to human per policy' },
      ],
      chain: {
        thisHash:  '0x4b1a3e7711c299bbaf001ce8c921',
        prevHash:  '0x9c3d7762efaa9211bb003af1a834',
        signer:    'FinFlow Autonomous · key-id fn-prod-02',
        published: 'acme-audit-stream-2026 · block #144,208',
      },
    },
  },
  'ct-hires': {
    0: {
      title: 'Onboarding kit · <em>Mia Dresden</em> · Munich Sales',
      ts: 'Apr 19, 2026 · 13:49:00 UTC',
      duration: 'orchestrated over 26h',
      cost: '$120.00',
      state: '3/4 sealed',
      flag: true,
      provider: 'Cohort Labor v2.1',
      envelope: 'Mike · HR',
      facts: [
        { k: 'Outcome', v: '3 of 4 sealed', serif: true },
        { k: 'Role template', v: 'EU-Sales-2', mono: true },
        { k: 'Start date', v: 'Apr 22, 2026', mono: true },
        { k: 'Blocking', v: 'Policy ack pending', mono: true },
      ],
      trace: [
        { t: '−26h',  kind: 'in',   lbl: 'Input',   body: 'Hire record received from Workday · role template <code>EU-Sales-2</code>' },
        { t: '−25h',  kind: 'tool', lbl: 'Identity',body: 'Okta account provisioned · SSO groups attached · 2FA enrolled', ms: 'sealed' },
        { t: '−24h',  kind: 'tool', lbl: 'Payroll', body: 'DE payroll record created at Rippling · tax class 1 · health plan selected', ms: 'sealed' },
        { t: '−23h',  kind: 'tool', lbl: 'Device',  body: 'MacBook Pro dispatched · DEP enrolled · encryption verified', ms: 'sealed' },
        { t: '−2m',   kind: 'flag', lbl: 'Blocked', body: 'Policy ack step cannot auto-complete · hire must sign DE works-council addendum' },
      ],
      policyChecks: [
        { pass: true,  rule: 'Role template pre-approved (EU-Sales-2)' },
        { pass: true,  rule: 'Geo-fenced to HQ regions (DE ∈ allowed)' },
        { pass: true,  rule: '72h rollback window armed' },
        { pass: false, rule: 'Policy ack (works-council addendum) outstanding' },
      ],
      chain: {
        thisHash:  '0x2e5f88a17711c44e01d33b92afdd',
        prevHash:  '0x8d1b2c3388f77892c000ab7712de',
        signer:    'Cohort Labor · key-id cl-prod-17',
        published: 'acme-audit-stream-2026 · block #144,112',
      },
    },
  },
  'ct-cves': {
    0: {
      title: 'CVE-2025-44302 patched · openssl→3.2.2',
      ts: 'Apr 19, 2026 · 13:26:00 UTC',
      duration: '2h 41m',
      cost: '$12.00',
      state: 'staged',
      provider: 'Sentinel Core',
      envelope: 'Bravo · DevOps',
      facts: [
        { k: 'Outcome', v: 'staged', serif: true },
        { k: 'CVE score', v: '8.1 · high', serif: true },
        { k: 'Env', v: 'staging · snap-9f22', mono: true },
        { k: 'Awaiting', v: 'two-eyes sign-off', mono: true },
      ],
      trace: [
        { t: '−2h 41m', kind: 'in',   lbl: 'Input',   body: 'CVE-2025-44302 published · NVD feed · affects openssl ≤ 3.2.1' },
        { t: '−2h 38m', kind: 'tool', lbl: 'Shadow',  body: 'Spun staging replica <code>snap-9f22</code> from prod state · isolated VPC', ms: '12min' },
        { t: '−2h 20m', kind: 'tool', lbl: 'Patch',   body: 'Applied openssl 3.2.2 · rebuilt deps · 412/412 smoke tests passed', ms: '98min' },
        { t: '−42m',    kind: 'tool', lbl: 'Red/green',body:'Red team replay of CVE vector → now blocked · green replay of normal traffic → 0 regressions' },
        { t: '−0s',     kind: 'ok',   lbl: 'Staged',  body: 'Candidate ready · awaiting two human approvers for production promote' },
      ],
      policyChecks: [
        { pass: true, rule: 'Staging only · prod not touched' },
        { pass: true, rule: 'Red/green test suite ran (412 cases)' },
        { pass: true, rule: 'Rollback snapshot armed (snap-9f22)' },
        { pass: true, rule: 'Two-eyes required before prod (pending)' },
      ],
      chain: {
        thisHash:  '0x1a87b3ff22cc004402bbde817712',
        prevHash:  '0x8d1b2c3388f77892c000ab7712de',
        signer:    'Sentinel Core · key-id sc-prod-03',
        published: 'acme-audit-stream-2026 · block #144,201',
      },
    },
  },
  'ct-contracts': {
    0: {
      title: '<em>Acme ⇄ Ledgerly</em> MSA · redline v3 accepted',
      ts: 'Apr 19, 2026 · 13:01:00 UTC',
      duration: '19h 22m',
      cost: '$48.00',
      state: 'redlined',
      flag: true,
      provider: 'Paragraph Legal',
      envelope: 'Juliet · Legal',
      facts: [
        { k: 'Outcome', v: 'redlined', serif: true },
        { k: 'Playbook', v: 'v3.1', mono: true },
        { k: 'Clauses flagged', v: '4 · 1 escalated', mono: true },
        { k: 'Counterparty', v: 'Ledgerly Inc.', mono: true },
      ],
      trace: [
        { t: '−19h 22m', kind: 'in',   lbl: 'Input',    body: 'MSA draft v2 received from Ledgerly counsel · 24pp' },
        { t: '−19h 18m', kind: 'tool', lbl: 'Classify', body: 'Mapped to MSA · software-procurement · US jurisdiction' },
        { t: '−18h 50m', kind: 'tool', lbl: 'Redline',  body: '4 flags · indemnity cap (§8.2), auto-renew (§12), DPA reference (§14), assignment (§17)' },
        { t: '−16h 10m', kind: 'flag', lbl: 'Escalate', body: 'Indemnity cap above playbook threshold · escalated to GC with memo' },
        { t: '−0m',      kind: 'ok',   lbl: 'Sealed',   body: 'Redline v3 accepted by counterparty · memo signed · no signing authority used' },
      ],
      policyChecks: [
        { pass: true,  rule: 'Playbook v3.1 applied in full' },
        { pass: true,  rule: 'No signing authority used (review only)' },
        { pass: true,  rule: 'Escalation to GC triggered over $100k indemnity' },
        { pass: true,  rule: 'Audit memo produced and co-signed' },
      ],
      chain: {
        thisHash:  '0x5c9a11bb226611eead0b44ff7021',
        prevHash:  '0x6d7b2288f11881c1221abc441212',
        signer:    'Paragraph Legal · key-id pg-prod-07',
        published: 'acme-audit-stream-2026 · block #144,055',
      },
    },
  },
};

window.RECEIPTS = RECEIPTS;

const synthesizeReceipt = (contractId, index) => {
  const streams = window.STREAMS || {};
  const row = (streams[contractId] || [])[index];
  if (!row) return null;
  const contracts = window.CONTRACTS || [];
  const c = contracts.find(x => x.id === contractId);
  const providerName = c ? c.substrate.name : 'Provider';
  const envelopeName = c ? c.envelope.name : 'Envelope';
  const state = row.state || 'sealed';
  const isFlag = !!row.flag;
  const amt = row.amt;
  return {
    title: row.title,
    ts: row.ts + ' · ' + new Date().toUTCString().slice(5, 22) + ' UTC',
    duration: 'end-to-end',
    cost: amt != null ? ('$' + Number(amt).toFixed(amt % 1 ? 2 : 0)) : '$—',
    state,
    flag: isFlag,
    provider: providerName,
    envelope: envelopeName,
    facts: [
      { k: 'Outcome', v: state, serif: true },
      { k: 'Amount',  v: amt != null ? ('$' + Number(amt).toFixed(amt % 1 ? 2 : 0)) : '—', serif: true },
      { k: 'Provider',v: providerName, mono: true },
      { k: 'Envelope',v: envelopeName, mono: true },
    ],
    trace: [
      { t: 'T+0',   kind: 'in',   lbl: 'Input',    body: 'Event ingested from upstream source' },
      { t: 'T+~',   kind: 'tool', lbl: 'Execute',  body: 'Provider ran outcome under envelope constraints', ms: 'ok' },
      { t: 'T+end', kind: isFlag ? 'flag' : 'ok', lbl: isFlag ? 'Routed' : 'Sealed', body: isFlag ? 'Exception routed to human per envelope policy' : 'Receipt signed and chained' },
    ],
    policyChecks: [
      { pass: true, rule: 'Envelope ' + envelopeName + ' · all rules evaluated' },
      { pass: !isFlag, rule: isFlag ? 'Human review required per envelope · routed' : 'Auto-approval threshold met' },
    ],
    chain: {
      thisHash: '0x' + (Math.random().toString(16).slice(2, 10)) + '…' + (Math.random().toString(16).slice(2, 6)),
      prevHash: '0x' + (Math.random().toString(16).slice(2, 10)) + '…' + (Math.random().toString(16).slice(2, 6)),
      signer:    providerName + ' · key-id auto',
      published: 'acme-audit-stream-2026 · live',
    },
  };
};

const ReceiptPane = ({ contractId, index, onClose }) => {
  const r = (RECEIPTS[contractId] || {})[index] || synthesizeReceipt(contractId, index);
  if (!r) return null;

  return (
    <>
      <div className="receipt-scrim" onClick={onClose} />
      <div className="receipt-pane" role="dialog" aria-label="Receipt detail">
        <div className="receipt-head">
          <div style={{minWidth: 0, flex: 1}}>
            <div className="receipt-eyebrow mono">
              <span className="seal">Signed receipt</span>
              <span style={{color:'var(--muted-2)'}}>·</span>
              <span>{r.ts}</span>
            </div>
            <h3 className="receipt-title serif" dangerouslySetInnerHTML={{__html: r.title}} />
          </div>
          <button className="detail-close" onClick={onClose} aria-label="Close">
            <Icon name="x" size={16} />
          </button>
        </div>

        <div className="receipt-body">
          <div className="receipt-facts">
            {r.facts.map((f, i) => (
              <div key={i} className="receipt-fact">
                <div className="k mono">{f.k}</div>
                <div className={`v ${f.mono ? 'mono' : ''}`}>
                  {f.serif ? <em>{f.v}</em> : f.v}
                </div>
              </div>
            ))}
          </div>

          <div className="receipt-section">
            <div style={{display:'flex', justifyContent:'space-between', alignItems:'baseline'}}>
              <div className="receipt-section-k mono">Execution trace</div>
              <div className="receipt-section-sub mono">{r.duration} · by {r.provider}</div>
            </div>
            <div className="trace">
              {r.trace.map((t, i) => (
                <div key={i} className="trace-row">
                  <div className="trace-t">{t.t}</div>
                  <div className={`trace-dot ${t.kind}`} />
                  <div className="trace-body">
                    <span className="lbl">{t.lbl}</span>
                    <span dangerouslySetInnerHTML={{__html: t.body}} />
                  </div>
                  <div className="trace-ms">{t.ms || ''}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="receipt-section">
            <div style={{display:'flex', justifyContent:'space-between', alignItems:'baseline'}}>
              <div className="receipt-section-k mono">Policy checks</div>
              <div className="receipt-section-sub mono">Envelope · {r.envelope}</div>
            </div>
            <div className="policy-checks">
              {r.policyChecks.map((p, i) => (
                <div key={i} className={`policy-check ${p.pass ? '' : 'fail'}`}>
                  <div className="mk">{p.pass ? '✓' : '!'}</div>
                  <div className="rule">{p.rule}</div>
                  <div className="state">{p.pass ? 'pass' : 'route'}</div>
                </div>
              ))}
            </div>
          </div>

          <div className="receipt-section">
            <div className="receipt-section-k mono">Signature chain</div>
            <div className="chain">
              <div className="chain-head mono">
                <span>SHA-256 · Ed25519 · acme-audit-stream-2026</span>
                <span className="ok">✓ verified · 0 gaps</span>
              </div>
              <div className="chain-row">
                <div className="k">this</div>
                <div className="v mono">{r.chain.thisHash}</div>
              </div>
              <div className="chain-row">
                <div className="k">prev</div>
                <div className="v mono"><em>{r.chain.prevHash}</em></div>
              </div>
              <div className="chain-row">
                <div className="k">signer</div>
                <div className="v mono">{r.chain.signer}</div>
              </div>
              <div className="chain-row">
                <div className="k">published</div>
                <div className="v mono">{r.chain.published}</div>
              </div>
            </div>
          </div>
        </div>

        <div className="receipt-foot">
          <div className="receipt-foot-meta mono">
            Outcome billed · {r.cost} · state: {r.state}
          </div>
          <div className="receipt-foot-actions">
            <button className="btn ghost">Export JSON</button>
            <button className="btn">View on chain ↗</button>
          </div>
        </div>
      </div>
    </>
  );
};

window.ReceiptPane = ReceiptPane;
