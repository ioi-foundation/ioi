// Extended data for the IA v3 rebuild.
// Adds: drafts, completed contracts (with lineage), inbox items, productized catalog.

// ─── Drafts ─────────────────────────────────────────────────────────
// In-progress contract drafts — not yet live. Saved state of the wizard.
const DRAFTS = [
  {
    id: 'dr-weekly-access',
    prompt: 'Run a weekly access review across our SaaS estate and produce SOC2 evidence.',
    outcome: 'Run a weekly access review across SaaS estate',
    started: '2h ago',
    step: 'Awaiting bids',
    stepIdx: 2,
    envelope: 'Charlie · Security',
    bidsExpected: 3,
    bidsIn: 2,
  },
  {
    id: 'dr-board-memo',
    prompt: 'Summarize board pre-reads into a 2-page memo every Friday.',
    outcome: 'Summarize board pre-reads into a 2pp memo',
    started: 'yesterday',
    step: 'Spec review',
    stepIdx: 1,
    envelope: 'Echo · Exec',
    bidsExpected: null,
    bidsIn: 0,
  },
  {
    id: 'dr-dunning',
    prompt: 'Handle customer dunning and collections with escalation rules.',
    outcome: 'Run customer dunning with 3-step escalation',
    started: '4d ago',
    step: 'Envelope unresolved',
    stepIdx: 1,
    envelope: 'needs human',
    bidsExpected: null,
    bidsIn: 0,
    blocked: true,
  },
];

// ─── Completed contracts ────────────────────────────────────────────
// Three terminal states: completed · superseded · disputed.
const COMPLETE_CONTRACTS = [
  {
    id: 'ct-q1-close',
    code: 'CT-0008',
    outcome: 'Close Q1 books by April 10.',
    promise: 'Run period-end close, reconcile all GL accounts, produce audit pack.',
    established: 'Mar 01, 2026',
    closed: 'Apr 09, 2026',
    durationDays: 39,
    receipts: 214,
    totalSpend: 2568.00,
    terminalState: 'completed',   // completed · superseded · disputed
    terminalNote: 'Closed on schedule · 1 day early · all reconciliations clean',
    substrate: { name: 'FinFlow Autonomous', id: 'p-finflow' },
    envelope: { name: 'Alpha · Finance' },
    lineage: null,
    dispute: null,
  },
  {
    id: 'ct-q1-plan',
    code: 'CT-0005',
    outcome: 'Keep Q1 hiring plan synced with budget model.',
    promise: 'Reconcile headcount plan against budget; alert on drift > 5%.',
    established: 'Jan 02, 2026',
    closed: 'Mar 12, 2026',
    durationDays: 69,
    receipts: 48,
    totalSpend: 1104.00,
    terminalState: 'superseded',
    terminalNote: 'Scope expanded to include contractor spend — replaced by CT-0022',
    substrate: { name: 'Cohort Labor', id: 'p-cohort' },
    envelope: { name: 'Mike · HR' },
    lineage: { supersededBy: 'CT-0022', kind: 'scope-expansion' },
    dispute: null,
  },
  {
    id: 'ct-support-rm',
    code: 'CT-0011',
    outcome: 'Resolve tier-2 support escalations within 2h.',
    promise: 'Triage inbound escalations, resolve or hand off with summary.',
    established: 'Feb 04, 2026',
    closed: 'Mar 28, 2026',
    durationDays: 52,
    receipts: 389,
    totalSpend: 1555.60,
    terminalState: 'disputed',
    terminalNote: 'Acceptance failed on batch 0311 · arbitration partial-refund',
    substrate: { name: 'Frontline', id: 'p-frontline' },
    envelope: { name: 'Delta · Support' },
    lineage: null,
    dispute: {
      arbiter: 'Escrow Arbitration Panel',
      attributedTo: 'provider',
      resolution: 'Partial refund · $312.40 returned · 18 receipts voided',
      resolvedOn: 'Mar 28, 2026',
      ruling: 'Provider missed SLA on 18 of 52 escalations in batch 0311. Remaining 34 accepted.',
    },
  },
];

// ─── Inbox items ─────────────────────────────────────────────────────
// Sorted by obligation: your action first, then provider, then arbiter.
const INBOX_ITEMS = [
  // === YOU are blocking ===
  {
    id: 'in-0034',
    kind: 'acceptance',
    blocking: 'you',
    title: 'Accept Q2 forecast deliverable',
    body: 'Accru Reconcile delivered the Q2 forecast pack on time. Once you accept, $2,400 releases from escrow.',
    contractCode: 'CT-0023',
    contractId: null,
    provider: 'Accru Reconcile',
    ts: '12m ago',
    value: '$2,400 in escrow',
    cta: [
      { key: 'accept',  label: 'Accept · release funds', tone: 'primary' },
      { key: 'reject',  label: 'Reject · open dispute' },
      { key: 'partial', label: 'Partial accept' },
    ],
  },
  {
    id: 'in-0033',
    kind: 'acceptance',
    blocking: 'you',
    title: 'Accept weekly access-review batch',
    body: '412 user×app×role combinations reviewed. 3 flagged for revoke — your one-click queue is ready.',
    contractCode: 'CT-0017',
    contractId: null,
    provider: 'Sentinel Core',
    ts: '1h ago',
    value: '$840 in escrow',
    cta: [
      { key: 'accept', label: 'Accept · release funds', tone: 'primary' },
      { key: 'revoke', label: 'Accept + run revoke queue' },
      { key: 'reject', label: 'Reject' },
    ],
  },
  {
    id: 'in-0032',
    kind: 'exception',
    blocking: 'you',
    title: 'Invoice INV-22843 has no PO · approve as one-off?',
    body: 'Coffeehaus LLC · $87.14 · vendor on allowlist but no matching PO. Provider cannot auto-approve under envelope Alpha.',
    contractCode: 'CT-0014',
    contractId: 'ct-books',
    provider: 'FinFlow Autonomous',
    ts: '4m ago',
    value: null,
    cta: [
      { key: 'approve', label: 'Approve one-off', tone: 'primary' },
      { key: 'route',   label: 'Route to AP manager' },
      { key: 'reject',  label: 'Reject' },
    ],
  },

  // === PROVIDER is blocking ===
  {
    id: 'in-0031',
    kind: 'clarification',
    blocking: 'provider',
    title: 'Ledgerly asks: expand Q2 scope to include prepaid accounts?',
    body: '47 prepaid-insurance line items fall outside the current envelope. Ledgerly proposes a $0.20 surcharge per item, ~$9.40 this month.',
    contractCode: 'CT-0014',
    contractId: 'ct-books',
    provider: 'Ledgerly',
    ts: '3h ago',
    value: '$9.40 / mo uplift',
    cta: [
      { key: 'approve', label: 'Expand scope', tone: 'primary' },
      { key: 'decline', label: 'Keep scope as-is' },
      { key: 'counter', label: 'Counter-propose terms' },
    ],
  },
  {
    id: 'in-0030',
    kind: 'clarification',
    blocking: 'provider',
    title: 'Cohort Labor asks: confirm DE works-council template',
    body: 'Needs countersigned works-council addendum before sealing Mia Dresden\'s onboarding. Standard for DE hires.',
    contractCode: 'CT-0021',
    contractId: 'ct-hires',
    provider: 'Cohort Labor',
    ts: '1h ago',
    value: null,
    cta: [
      { key: 'sign',  label: 'Countersign', tone: 'primary' },
      { key: 'delay', label: 'Delay start date' },
    ],
  },

  // === ARBITER is blocking ===
  {
    id: 'in-0029',
    kind: 'dispute',
    blocking: 'arbiter',
    title: 'Dispute 03-28 · arbiter deliberating',
    body: 'Frontline disputed the partial refund amount ($312.40). Arbiter requested 3 more receipts; we provided them yesterday.',
    contractCode: 'CT-0011',
    contractId: 'ct-support-rm',
    provider: 'Frontline',
    ts: 'yesterday',
    value: '$312.40 contested',
    cta: [
      { key: 'wait', label: 'Awaiting ruling · ETA 48h', tone: 'muted' },
    ],
  },
];

// ─── Productized catalog ──────────────────────────────────────────────
// Shoppable outcome cards — the demand-side browse surface.
// Each includes a price RANGE across providers + sample SLA + liveness signal.
// 3-level taxonomy: Category > Subcategory > Service (= CATALOG_ITEM)
// Subcategories drive the "Explore [Category]" grid on a single category page.
// Each subcategory has 3-5 service strings; only some map to a real CATALOG_ITEM
// via `itemId` — the rest are surfaced as "coming soon" links so the directory feels populated.
const CATALOG_CATEGORIES = [
  { id: 'finance',   name: 'Finance & Accounting', tone: 'indigo',
    subcategories: [
      { id: 'recon',   name: 'Reconciliation',
        services: [
          { label: 'Invoice reconciliation, nightly', itemId: 'cat-invoice-recon' },
          { label: 'Three-way match (PO ↔ invoice ↔ receipt)' },
          { label: 'GL exception detection' },
          { label: 'Bank statement reconciliation' },
        ]},
      { id: 'close',   name: 'Period Close',
        services: [
          { label: 'Quarterly books close', itemId: 'cat-q-close' },
          { label: 'Month-end close' },
          { label: 'Audit pack generation' },
          { label: 'Intercompany eliminations' },
        ]},
      { id: 'ap',      name: 'AP Operations',
        services: [
          { label: 'Duplicate-payment detection', itemId: 'cat-ap-scan' },
          { label: 'Vendor onboarding & W-9' },
          { label: 'Payment run scheduling' },
          { label: 'Expense categorization' },
        ]},
      { id: 'revrec',  name: 'Revenue Recognition',
        services: [
          { label: 'ASC 606 deferred revenue' },
          { label: 'Subscription accruals' },
          { label: 'Contract waterfall' },
        ]},
    ]},
  { id: 'hr',        name: 'People & Hiring', tone: 'rose',
    subcategories: [
      { id: 'onboard',   name: 'Onboarding',
        services: [
          { label: 'New-hire provisioning', itemId: 'cat-onboard' },
          { label: 'Day-one welcome pack' },
          { label: 'Identity & SSO setup' },
          { label: 'Device shipment & MDM' },
        ]},
      { id: 'offboard',  name: 'Offboarding',
        services: [
          { label: 'Termination & offboarding', itemId: 'cat-offboard' },
          { label: 'SaaS revoke sweep' },
          { label: 'Final-pay trigger' },
          { label: 'Exit documentation' },
        ]},
      { id: 'verify',    name: 'Background Verification',
        services: [
          { label: 'Identity verification' },
          { label: 'Reference checks' },
          { label: 'Right-to-work checks' },
        ]},
      { id: 'contractor',name: 'Contractor Operations',
        services: [
          { label: '1099 onboarding' },
          { label: 'EOR / global hire' },
          { label: 'Contractor compliance' },
        ]},
    ]},
  { id: 'security',  name: 'Security & Compliance', tone: 'teal',
    subcategories: [
      { id: 'patch',    name: 'Patch Management',
        services: [
          { label: 'CVE patching — staging to prod', itemId: 'cat-cve' },
          { label: 'Critical-CVE rapid response' },
          { label: 'Dependency upgrade sweeps' },
        ]},
      { id: 'access',   name: 'Access Reviews',
        services: [
          { label: 'Weekly access review', itemId: 'cat-access' },
          { label: 'Stale-account sweep' },
          { label: 'Privileged-role recertification' },
          { label: 'SaaS estate audit' },
        ]},
      { id: 'evidence', name: 'Audit Evidence',
        services: [
          { label: 'SOC 2 evidence collection' },
          { label: 'ISO 27001 evidence pack' },
          { label: 'PCI-DSS quarterly' },
        ]},
      { id: 'vendor',   name: 'Vendor Risk',
        services: [
          { label: 'Vendor risk assessment' },
          { label: 'Subprocessor monitoring' },
          { label: 'Penetration testing' },
        ]},
    ]},
  { id: 'legal',     name: 'Legal & Contracts', tone: 'amber',
    subcategories: [
      { id: 'redline',  name: 'Contract Redline',
        services: [
          { label: 'Inbound contract redline', itemId: 'cat-redline' },
          { label: 'MSA negotiation support' },
          { label: 'SaaS order-form review' },
        ]},
      { id: 'dpa',      name: 'Data & Privacy',
        services: [
          { label: 'DPA & subprocessor review', itemId: 'cat-dpa' },
          { label: 'GDPR transfer assessment' },
          { label: 'Privacy policy update' },
        ]},
      { id: 'nda',      name: 'NDA & Routine',
        services: [
          { label: 'NDA generation' },
          { label: 'NDA tracking & e-sign' },
          { label: 'Standard-form library' },
        ]},
      { id: 'reg',      name: 'Regulatory Filings',
        services: [
          { label: 'IP assignment review' },
          { label: 'Annual regulatory filings' },
          { label: 'Beneficial-ownership reports' },
        ]},
    ]},
  { id: 'support',   name: 'Support & Operations', tone: 'sage',
    subcategories: [
      { id: 'tier2',    name: 'Escalation Triage',
        services: [
          { label: 'Tier-2 escalation triage', itemId: 'cat-tier2' },
          { label: 'After-hours coverage' },
          { label: 'P1 incident commander' },
        ]},
      { id: 'routing',  name: 'Ticket Operations',
        services: [
          { label: 'Inbound ticket routing' },
          { label: 'SLA monitoring & alerts' },
          { label: 'Auto-tagging & deflection' },
        ]},
      { id: 'csat',     name: 'Customer Voice',
        services: [
          { label: 'CSAT & NPS surveys' },
          { label: 'Quarterly QBR pack' },
          { label: 'Churn-signal triage' },
        ]},
      { id: 'kb',       name: 'Knowledge Base',
        services: [
          { label: 'KB article maintenance' },
          { label: 'Support macro updates' },
          { label: 'Self-serve audit' },
        ]},
    ]},
  { id: 'analytics', name: 'Data & Analytics', tone: 'violet',
    subcategories: [
      { id: 'dash',     name: 'Dashboards',
        services: [
          { label: 'Morning dashboard refresh', itemId: 'cat-dash' },
          { label: 'Executive scorecard' },
          { label: 'Real-time metric alerts' },
        ]},
      { id: 'forecast', name: 'Forecasting',
        services: [
          { label: 'Pipeline forecasting' },
          { label: 'Revenue waterfall' },
          { label: 'Cash-runway model' },
        ]},
      { id: 'churn',    name: 'Churn & Retention',
        services: [
          { label: 'Churn prediction model' },
          { label: 'Cohort retention curves' },
          { label: 'Expansion-signal scoring' },
        ]},
      { id: 'reports',  name: 'Reporting',
        services: [
          { label: 'Board pre-read pack' },
          { label: 'Investor update memo' },
          { label: 'Usage analytics digest' },
        ]},
    ]},
];

const CATALOG_ITEMS = [
  // Finance
  {
    id: 'cat-invoice-recon',
    category: 'finance',
    subcategory: 'recon',
    title: 'Invoice reconciliation, nightly',
    tagline: 'Three-way match invoice ↔ PO ↔ receipt. Flag variance > 0.5%.',
    priceFrom: 0.65, priceTo: 1.20, priceUnit: '/ invoice',
    sla: '≤ 6h per invoice',
    providers: 4,
    lastFulfilled: '3s ago',
    running: 38,  // customers currently using
    envelope: 'Alpha · Finance',
    tags: ['SOC2', 'GAAP'],
  },
  {
    id: 'cat-q-close',
    category: 'finance',
    subcategory: 'close',
    title: 'Quarterly books close',
    tagline: 'Period-end close, GL reconciliation, audit pack delivery.',
    priceFrom: 1800, priceTo: 3400, priceUnit: '/ quarter',
    sla: 'Delivered T+10 business days',
    providers: 3,
    lastFulfilled: 'Apr 09',
    running: 12,
    envelope: 'Alpha · Finance',
    tags: ['SOC2', 'Audit-ready'],
  },
  {
    id: 'cat-ap-scan',
    category: 'finance',
    subcategory: 'ap',
    title: 'Duplicate-payment detection',
    tagline: 'Scan AP run for duplicates across invoice, vendor, amount.',
    priceFrom: 0.02, priceTo: 0.08, priceUnit: '/ line',
    sla: '< 15min per run',
    providers: 5,
    lastFulfilled: '1m ago',
    running: 71,
    envelope: 'Alpha · Finance',
    tags: ['SOC2'],
  },

  // HR
  {
    id: 'cat-onboard',
    category: 'hr',
    subcategory: 'onboard',
    title: 'New-hire provisioning',
    tagline: 'Identity, payroll, device, compliance — day-one ready.',
    priceFrom: 95, priceTo: 140, priceUnit: '/ hire',
    sla: '≤ 2 business days',
    providers: 3,
    lastFulfilled: '2h ago',
    running: 26,
    envelope: 'Mike · HR',
    tags: ['SOC2', 'EU-OK'],
  },
  {
    id: 'cat-offboard',
    category: 'hr',
    subcategory: 'offboard',
    title: 'Termination & offboarding',
    tagline: 'SaaS revoke, device recall, final-pay trigger, exit docs.',
    priceFrom: 60, priceTo: 95, priceUnit: '/ exit',
    sla: 'Same day',
    providers: 3,
    lastFulfilled: '6h ago',
    running: 18,
    envelope: 'Mike · HR',
    tags: ['SOC2'],
  },

  // Security
  {
    id: 'cat-cve',
    category: 'security',
    subcategory: 'patch',
    title: 'CVE patching — staging to prod',
    tagline: 'Identify, stage, test, promote under two-eyes sign-off.',
    priceFrom: 9, priceTo: 15, priceUnit: '/ CVE',
    sla: '≤ 6h to staging',
    providers: 3,
    lastFulfilled: '41m ago',
    running: 14,
    envelope: 'Bravo · DevOps',
    tags: ['SOC2', 'FedRAMP'],
  },
  {
    id: 'cat-access',
    category: 'security',
    subcategory: 'access',
    title: 'Weekly access review',
    tagline: 'SaaS estate × user × role · stale-account detection.',
    priceFrom: 0.10, priceTo: 0.25, priceUnit: '/ identity',
    sla: 'Fri 09:00 local',
    providers: 4,
    lastFulfilled: '3d ago',
    running: 22,
    envelope: 'Charlie · Security',
    tags: ['SOC2', 'ISO-27001'],
  },

  // Legal
  {
    id: 'cat-redline',
    category: 'legal',
    subcategory: 'redline',
    title: 'Inbound contract redline',
    tagline: 'First-pass review against your playbook · counsel memo.',
    priceFrom: 38, priceTo: 60, priceUnit: '/ document',
    sla: '≤ 48h',
    providers: 3,
    lastFulfilled: '1h ago',
    running: 9,
    envelope: 'Juliet · Legal',
    tags: ['Bar-panel'],
  },
  {
    id: 'cat-dpa',
    category: 'legal',
    subcategory: 'dpa',
    title: 'DPA & subprocessor review',
    tagline: 'GDPR/CCPA fit check, transfer mechanism, subprocessor audit.',
    priceFrom: 48, priceTo: 82, priceUnit: '/ document',
    sla: '≤ 72h',
    providers: 2,
    lastFulfilled: '3d ago',
    running: 6,
    envelope: 'Juliet · Legal',
    tags: ['GDPR', 'CCPA'],
  },

  // Support
  {
    id: 'cat-tier2',
    category: 'support',
    subcategory: 'tier2',
    title: 'Tier-2 escalation triage',
    tagline: 'Inbound ticket → triage → resolve or hand off with context.',
    priceFrom: 0.40, priceTo: 0.75, priceUnit: '/ ticket',
    sla: '≤ 10min to ack',
    providers: 2,
    lastFulfilled: 'just now',
    running: 4,
    envelope: 'Delta · Support',
    tags: [],
  },

  // Analytics
  {
    id: 'cat-dash',
    category: 'analytics',
    subcategory: 'dash',
    title: 'Morning dashboard refresh',
    tagline: 'ARR, pipeline, usage — freshened before 09:00.',
    priceFrom: 0.20, priceTo: 0.30, priceUnit: '/ refresh',
    sla: 'Daily 08:45 local',
    providers: 2,
    lastFulfilled: 'Mon',
    running: 3,
    envelope: 'Echo · Analytics',
    tags: [],
  },
];

window.DRAFTS = DRAFTS;
window.COMPLETE_CONTRACTS = COMPLETE_CONTRACTS;
window.INBOX_ITEMS = INBOX_ITEMS;
window.CATALOG_CATEGORIES = CATALOG_CATEGORIES;
window.CATALOG_ITEMS = CATALOG_ITEMS;

// ─── Completed-contract streams + dispute threads ──────────────────
const COMPLETE_STREAMS = {
  'ct-q1-close': [
    { ts:'Apr 09',  ok:true, title:'Audit pack sealed · <em>Q1 2026</em> close complete', sub:'0xf4c8b2…a901 · signed FinFlow · final · 214 prior receipts',  amt:null, state:'final', unit:'' },
    { ts:'Apr 09',  ok:true, title:'GL reconciliation · <em>all 47 accounts</em> · 0 variances', sub:'0xa81c22…b4d7 · signed FinFlow · covers $11.2M in movement', amt:null, state:'sealed', unit:'' },
    { ts:'Apr 08',  ok:true, title:'Intercompany eliminations sealed', sub:'0x3b2e15…8c12 · signed FinFlow · 8 entries', amt:null, state:'sealed', unit:'' },
    { ts:'Apr 07',  ok:true, title:'Period-end accruals · <em>$482,110</em> posted', sub:'0x7d4a88…2f56 · signed FinFlow · reviewed by Mia', amt:482110, state:'sealed', unit:'USD' },
    { ts:'Apr 05',  ok:true, title:'Bank reconciliation · <em>6 accounts</em> cleared', sub:'0x2c9f71…a024 · signed FinFlow · 3 exceptions, all resolved', amt:null, state:'sealed', unit:'' },
    { ts:'Apr 02',  ok:true, title:'Q1 books close kickoff · scope confirmed', sub:'0x9e1b44…71c8 · signed FinFlow · contract start', amt:null, state:'sealed', unit:'' },
  ],
  'ct-q1-plan': [
    { ts:'Mar 12',  ok:true, title:'Contract superseded · <em>CT-0022</em> takes over', sub:'0xd1e488…77a2 · signed Cohort · lineage link forward · envelope preserved', amt:null, state:'superseded', unit:'' },
    { ts:'Mar 10',  ok:true, title:'Scope expansion approved · <em>contractor spend</em> added', sub:'0x4a8b11…22ee · signed Cohort · drafted v2, awaiting countersign', amt:null, state:'sealed', unit:'' },
    { ts:'Mar 04',  ok:true, title:'Weekly plan reconciliation · <em>0.3% drift</em> · within envelope', sub:'0x8f2c7d…4910 · signed Cohort · 48 receipts total', amt:null, state:'sealed', unit:'' },
    { ts:'Feb 14',  ok:true, title:'Headcount plan synced with budget model', sub:'0x1b9a65…c048 · signed Cohort · 12 roles reconciled', amt:null, state:'sealed', unit:'' },
    { ts:'Jan 08',  ok:true, title:'Contract established · <em>Q1 hiring plan sync</em>', sub:'0x7f3e22…d811 · signed Cohort · first receipt pending', amt:null, state:'sealed', unit:'' },
  ],
  'ct-support-rm': [
    { ts:'Mar 28',  ok:true,  title:'Dispute resolved · <em>partial refund $312.40</em> returned', sub:'arbiter ruling · Escrow Arbitration Panel · batch 0311 partial voided', amt:312.40, state:'refund', unit:'USD' },
    { ts:'Mar 26',  ok:true,  title:'Arbiter ruling issued · fault attributed to <em>provider</em>', sub:'0xab2c99…3312 · 18 of 52 receipts voided · remaining 34 accepted', amt:null, state:'ruling', unit:'' },
    { ts:'Mar 22',  ok:true,  title:'Dispute evidence · final submission', sub:'0x7e4411…bb02 · 3 additional receipts provided on request', amt:null, state:'dispute', unit:'', flag:true },
    { ts:'Mar 15',  ok:false, title:'Acceptance <em>failed</em> · batch 0311 · 18 SLA misses', sub:'0x2a88c3…e410 · routed to arbitration · funds held', amt:null, state:'rejected', unit:'', flag:true },
    { ts:'Mar 14',  ok:true,  title:'Batch 0311 delivered · <em>52 escalations</em> triaged', sub:'0x6d1b09…22af · signed Frontline · awaiting acceptance', amt:null, state:'pending', unit:'' },
    { ts:'Feb 20',  ok:true,  title:'Batch 0208 accepted · <em>47 escalations</em> · clean', sub:'0x4c38a1…b771 · signed Frontline · $188 released', amt:188, state:'accepted', unit:'USD' },
    { ts:'Feb 04',  ok:true,  title:'Contract established · <em>tier-2 escalation triage</em>', sub:'0xc01e55…f209 · signed Frontline · first receipt pending', amt:null, state:'sealed', unit:'' },
  ],
};

// Dispute thread — structured log of dispute-specific events.
const DISPUTE_THREADS = {
  'ct-support-rm': [
    { who:'You',                ts:'Mar 15', label:'filed',     text:'18 of 52 escalations in batch 0311 missed the 2h SLA. Requesting full refund for the batch ($832).' },
    { who:'Frontline',          ts:'Mar 16', label:'responded', text:'Contested. 6 of the 18 were acknowledged within SLA but resolution extended due to customer unresponsiveness — we argue those should be excluded.' },
    { who:'Arbiter',            ts:'Mar 18', label:'accepted',  text:'Case accepted. Panel assigned: 3 arbiters, standard timeline 7 business days.' },
    { who:'Arbiter',            ts:'Mar 21', label:'requested', text:'Request additional evidence: full escalation chain for receipts 0311-04, 0311-12, 0311-15.' },
    { who:'You',                ts:'Mar 22', label:'provided',  text:'Evidence submitted. Customer-unresponsive claim does not apply to 0311-04 and 0311-15; chain shows inbound replies within 20min.' },
    { who:'Arbiter',            ts:'Mar 26', label:'ruled',     text:'Partial fault attributed to provider on 18 of 18 contested receipts. 6 excluded claims rejected. 18 receipts voided, $312.40 refunded. Remaining 34 accepted, funds released to Frontline.' },
    { who:'Frontline',          ts:'Mar 28', label:'accepted',  text:'Ruling accepted. Refund processed. Acknowledging internal SLA gap; remediation plan attached for any future engagement.' },
  ],
};

window.COMPLETE_STREAMS = COMPLETE_STREAMS;
window.DISPUTE_THREADS = DISPUTE_THREADS;
