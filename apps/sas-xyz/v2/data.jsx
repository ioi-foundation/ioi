// v2 data — outcome contracts, receipt streams, substrate providers

// Running outcome contracts — the primary objects.
const CONTRACTS = [
  {
    id: 'ct-books',
    code: 'CT-0014',
    outcome: 'Keep the books tax-ready.',
    promise: 'Reconcile every vendor invoice against bookkeeping within 24h; flag exceptions for human review.',
    established: 'Mar 02, 2026',
    health: 'ok',
    // Pulse: last ~40 receipts, 1 = ok, 0 = no-event, -1 = flagged
    pulse: [1,1,1,1,1,1,0,1,1,1,1,-1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,-1,1,1,1,1,1,1,0,1,1,1,1,1],
    receipts30d: 1041,
    spend30d: 520.50,
    spendUnit: '/ mo',
    substrate: { name: 'FinFlow Autonomous', id: 'p-finflow', model: 'Invoice Operations Service v4.2' },
    envelope: { name: 'Alpha · Finance', rules: ['Budget cap $500/mo', 'Vendor allowlist only', 'Human review on mismatch'] },
    slaTarget: '< 24h',
    slaActual: '11h median',
  },
  {
    id: 'ct-hires',
    code: 'CT-0021',
    outcome: 'Provision new hires to day-one ready.',
    promise: 'Identity, payroll, device, and compliance set up by start date; role templates pre-approved.',
    established: 'Jan 14, 2026',
    health: 'warn',
    pulse: [1,1,1,1,0,0,1,1,1,0,0,1,1,1,1,0,0,1,1,1,-1,1,1,0,0,1,1,1,1,1,0,0,1,1,1,1,-1,1,1,0],
    receipts30d: 7,
    spend30d: 840,
    spendUnit: '/ mo',
    substrate: { name: 'Cohort Labor', id: 'p-cohort', model: 'Onboarding Orchestrator v2.1' },
    envelope: { name: 'Mike · HR', rules: ['Role templates pre-approved', 'Geo-fenced to HQ regions', '72h rollback window'] },
    slaTarget: '≤ 2 business days',
    slaActual: '1.4d median',
  },
  {
    id: 'ct-cves',
    code: 'CT-0019',
    outcome: 'Keep staging patched against known CVEs.',
    promise: 'Identify new CVEs, spin shadow envs, request two-eyes approval before production promote.',
    established: 'Feb 07, 2026',
    health: 'ok',
    pulse: [1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,-1,1,1,1,1,1,1,1],
    receipts30d: 32,
    spend30d: 384,
    spendUnit: '/ mo',
    substrate: { name: 'Sentinel Core', id: 'p-sentinel', model: 'Vulnerability Remediation Engine' },
    envelope: { name: 'Bravo · DevOps', rules: ['Staging only · prod gated', 'Two-eyes sign-off for promote', 'Full rollback liability'] },
    slaTarget: '≤ 6h per CVE',
    slaActual: '3.2h median',
  },
  {
    id: 'ct-contracts',
    code: 'CT-0026',
    outcome: 'Redline inbound vendor contracts.',
    promise: 'First-pass review against playbook v3.1 with counsel memo and escalation flags.',
    established: 'Apr 03, 2026',
    health: 'ok',
    pulse: [0,1,0,0,1,0,0,0,1,0,0,1,0,0,0,1,0,0,1,0,-1,0,1,0,0,0,1,0,0,1,0,0,0,1,0,0,1,0,0,1],
    receipts30d: 14,
    spend30d: 672,
    spendUnit: '/ mo',
    substrate: { name: 'Paragraph Legal', id: 'p-paragraph', model: 'Contract First-Pass Review' },
    envelope: { name: 'Juliet · Legal', rules: ['Playbook v3.1', 'No signing authority', 'Escalation to GC over $100k'] },
    slaTarget: '≤ 48h',
    slaActual: '22h median',
  },
];

// Receipt stream for a contract — each item is a signed outcome.
const STREAMS = {
  'ct-books': [
    { ts: 'just now',      ok: true,  title: 'Invoice <em>INV-22844</em> matched to <em>PO-8814</em>', sub: '0x7a2c9f…df82 · signed FinFlow · 3s', amt: 4218.00, state: 'matched', unit: 'USD' },
    { ts: '4m ago',        ok: true,  title: 'Invoice <em>INV-22843</em> flagged · no PO on file',     sub: '0x4b1a3e…e921 · signed FinFlow · routed to Mia', amt: 87.14, state: 'flagged', unit: 'USD', flag: true },
    { ts: '12m ago',       ok: true,  title: 'Invoice <em>INV-22842</em> matched to receipt <em>9031</em>', sub: '0x9c3d77…a834 · signed FinFlow · 1s', amt: 612.50, state: 'matched', unit: 'USD' },
    { ts: '37m ago',       ok: true,  title: 'Invoice <em>INV-22841</em> matched to <em>PO-8812</em>', sub: '0x2e5f88…1c44 · signed FinFlow · 2s', amt: 4218.00, state: 'matched', unit: 'USD' },
    { ts: '2h 14m ago',    ok: true,  title: 'Weekly reconciliation trace sealed',                      sub: '0x8d1b2c…7789 · signed FinFlow · covers 38 txns · $12,048.22', amt: null, state: 'sealed', unit: '' },
    { ts: '5h 02m ago',    ok: true,  title: 'Invoice <em>INV-22840</em> matched to <em>PO-8811</em>', sub: '0x3a4e66…b2a1 · signed FinFlow · 1s', amt: 1930.00, state: 'matched', unit: 'USD' },
    { ts: 'yesterday',     ok: true,  title: 'Invoice <em>INV-22839</em> matched to receipt <em>9028</em>', sub: '0x5c9a11…2266 · signed FinFlow · 2s', amt: 245.00, state: 'matched', unit: 'USD' },
  ],
  'ct-hires': [
    { ts: '18m ago',       ok: true,  title: 'Onboarding kit · <em>Mia Dresden</em> · Munich Sales',  sub: 'chain 0x2e5f88…1c44 · 3 of 4 steps sealed · policy ack pending', amt: 120, state: '3/4 sealed', flag: true },
    { ts: '2d ago',        ok: true,  title: 'Onboarding kit · <em>Omar K.</em> · Berlin Eng',        sub: 'chain 0x8d1b2c…7789 · all 4 steps sealed · role tpl EU-Eng-3', amt: 120, state: 'sealed' },
    { ts: '4d ago',        ok: true,  title: 'Onboarding kit · <em>Sofia R.</em> · London Ops',       sub: 'chain 0x3a4e66…b2a1 · all 4 steps sealed', amt: 120, state: 'sealed' },
    { ts: '6d ago',        ok: true,  title: 'Onboarding kit · <em>Jamal T.</em> · NYC Growth',       sub: 'chain 0x5c9a11…2266 · all 4 steps sealed', amt: 120, state: 'sealed' },
  ],
  'ct-cves': [
    { ts: '41m ago',       ok: true,  title: 'CVE-2025-44302 patched · openssl→3.2.2',                sub: '0x1a87b3…4402 · signed Sentinel · red/green ✓ · awaiting prod two-eyes', amt: 12, state: 'staged' },
    { ts: '3h 20m ago',    ok: true,  title: 'CVE-2025-44219 promoted to production',                   sub: '0x8d1b2c…7789 · two-eyes: G.Reid + S.Liu · 412/412 smoke', amt: 12, state: 'promoted' },
    { ts: 'yesterday',     ok: true,  title: 'CVE-2025-44219 patched (staging)',                        sub: '0x7a2c9f…df82 · signed Sentinel · snapshot snap-9f22', amt: 12, state: 'staged' },
    { ts: '3d ago',        ok: true,  title: 'CVE-2025-43981 promoted to production',                   sub: '0x9c3d77…a834 · two-eyes: G.Reid + M.Park', amt: 12, state: 'promoted' },
  ],
  'ct-contracts': [
    { ts: '1h 12m ago',    ok: true,  title: '<em>Acme ⇄ Ledgerly</em> MSA · redline v3 accepted',     sub: 'memo 0x5c9a11…2266 · 4 clauses · 1 escalation to GC', amt: 48, state: 'redlined', flag: true },
    { ts: '3d ago',        ok: true,  title: '<em>Acme ⇄ Parallel</em> DPA · clean pass',              sub: 'memo 0x6d7b22…8812 · 0 flags · no signing authority used', amt: 48, state: 'redlined' },
    { ts: '5d ago',        ok: true,  title: '<em>Acme ⇄ Relay Auth</em> SOW · auto-renew struck',     sub: 'memo 0x3a4e66…b2a1 · opt-in required', amt: 48, state: 'redlined' },
  ],
};

// Alternative providers for a given contract — the "swap" primitive.
const ALTERNATIVES = {
  'ct-books': [
    { id: 'p-ledgerly', name: 'Ledgerly',          meta: 'Since 2024 · SOC2 · 1,820 Acme-equiv customers', price: 0.80, unit: '/ outcome', diff: -33, sla: '9h median', envelope: 'match' },
    { id: 'p-accru',    name: 'Accru Reconcile',   meta: 'Since 2023 · SOC2 + ISO · finance-only', price: 1.05, unit: '/ outcome', diff: -12, sla: '14h median', envelope: 'match' },
    { id: 'p-parallel', name: 'Parallel Books',    meta: 'Since 2025 · SOC2 Type I', price: 0.64, unit: '/ outcome', diff: -47, sla: '18h median', envelope: 'partial' },
  ],
  'ct-hires': [
    { id: 'p-keystone', name: 'Keystone Onboard',  meta: 'Since 2023 · global payroll reach', price: 95,  unit: '/ hire', diff: -21, sla: '1.2d median', envelope: 'match' },
    { id: 'p-rally',    name: 'Rally HR',          meta: 'Since 2022 · EU specialist', price: 110, unit: '/ hire', diff: -8,  sla: '1.0d median', envelope: 'match' },
  ],
  'ct-cves': [
    { id: 'p-bastion',  name: 'Bastion Remediate', meta: 'Since 2024 · kernel-class CVEs', price: 9,   unit: '/ remediation', diff: -25, sla: '4h median', envelope: 'match' },
  ],
  'ct-contracts': [
    { id: 'p-claus',    name: 'Claus Review',      meta: 'Since 2023 · NY/DE bar panel', price: 38, unit: '/ document', diff: -20, sla: '24h median', envelope: 'match' },
    { id: 'p-vertex',   name: 'Vertex Legal',      meta: 'Since 2022 · enterprise MSA specialist', price: 55, unit: '/ document', diff: +15, sla: '14h median', envelope: 'match' },
  ],
};

window.CONTRACTS = CONTRACTS;
window.STREAMS = STREAMS;
window.ALTERNATIVES = ALTERNATIVES;
