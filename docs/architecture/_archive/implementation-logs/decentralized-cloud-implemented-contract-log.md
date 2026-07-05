# decentralized.cloud — Implemented Contract Narration (candidate plane, first cut)

Status: archived implementation build log (verbatim extraction).
Doctrine status: archived
Implementation status: n/a (historical record)
Archived from: `docs/architecture/domains/decentralized/cloud.md` on 2026-07-05.
Canonical owner: `docs/architecture/domains/decentralized/cloud.md` (live doctrine); this file is history, not authority.
Superseded by: the canonical owner doc. Git history retains the original placement.

---

## Implemented Contract (candidate plane, first cut)

Daemon-owned realization of the candidate semantics above, from LOCAL FACTS
ONLY (verified ProviderAccount catalog, environment-class eligibility, static
adapter capabilities, preflight posture, provider receipt history). Endpoints
under `/v1/hypervisor/cloud-candidates`:

```text
POST /intents                      create CloudResourceIntent (validated against the
                                   bounded resource classes; not authority) + first batch
GET  /intents/:id
GET  /candidates?intent_ref=…      evidence-bound, expiring candidates; expired/superseded
                                   are never placement-eligible (requote via refresh)
POST /candidates/refresh           supersede + re-derive (the requote)
GET  /candidate-sources            source registry; external sources without adapters are
                                   candidate_source_unavailable WITH evidence — no fake prices
GET  /placement-advisory[?intent_ref] deterministic, reason-coded recommendation among
                                   run_local / verified BYO SSH / provider-capable venues;
                                   requotes when provider facts change; explicit
                                   no_eligible_candidate → effective_venue run_local
```

Each candidate embeds its CandidateEvidence, CustodyPlan, FailoverPlan, and
SpendEstimate projections (`quote_ref` stays null until a pricing adapter
exists). Candidates and advisories are never authority — provider mutation
still demands wallet grants on the execution lane. `routing_fee_basis:
eligible_future` is declared only when multiple real candidates are compared;
`fee_object_minted` stays false and no RoutingDecisionReceipt exists.
"Let Hypervisor choose" consumes the advisory (venue policy, launch preview,
environment records snapshot advisory/candidate refs); the four venue choices
and pinned-provider override are preserved.

Done-bar: `apps/hypervisor/scripts/verify-hypervisor-cloud-candidate-plane.mjs`.

Vast is the first live external quote source (`vast_candidate_source.rs`,
`adapter:vast-quote`): sealed-bearer preflight through the existing resolver,
offer-catalog fetch when a verified `vast` ProviderAccount exists, normalization
into candidates with verbatim ProviderQuote/SpendEstimate prices, source health
(`candidate_source_unavailable` → `credential_verified_unprobed` →
`live_quote_source` | `fixture_quote_source` | `degraded_unreachable`, all with
evidence), and quote-only posture (`lifecycle: quote_preflight_only`,
`placement_eligible: advisory_only`,
`execution_blocked_reason: provider_kind_lifecycle_not_implemented`,
`marketplace_host_NOT_private`). Fixture mode is unmistakably marked
`fixture_evidence` and can never be claimed as live supply. Done-bar:
`verify-hypervisor-vast-candidate-adapter.mjs`.

The guarded Vast LIFECYCLE (first paid external GPU lifecycle path) is narrow
by canon: create is QUOTE-GATED (fresh, live-or-simulator, priced, account-bound
candidate; fixture quotes can never provision; expired quotes require requote;
price capped by a declared max), budget discovery runs first, and the wallet
capability challenge binds account + quote_ref + candidate_ref + max hourly
price + GPU facts + teardown policy + external_spend posture. The instance then
reuses the BYO SSH workspace/custody contract verbatim (real remote exec,
snapshot tar → daemon custody → admitted sha256 state_root, re-hash before
restore). Provider-native ids are evidence only; teardown always runs and is
receipted; outage injection/recover fail closed with named reasons. The
lifecycle SIMULATOR (control plane simulated, ssh/custody lane real) validates
the state machine and receipts and always reports live_provisioning_not_run —
live execution is never claimed unless actually run. Done-bar:
`verify-hypervisor-vast-lifecycle.mjs`.

SpendEstimate reconciliation is realized daemon-side: exposures open from
admitted quote-backed creates, reserve estimate headroom against
`external_spend`, accrete receipt/state-root evidence, and close (or warn) on
teardown — estimates stay unsettled until the customer's own provider bill;
Hypervisor never fakes settlement.
