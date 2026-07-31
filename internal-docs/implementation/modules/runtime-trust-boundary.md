---
module_id: runtime-trust-boundary
module_class: method
title: Runtime trust-boundary and PEP method
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M0]
legacy_id: stage-guides/m0/runtime-trust-boundary.md
canon_owners:
  - docs/architecture/components/daemon-runtime/doctrine.md
  - docs/architecture/components/daemon-runtime/api.md
  - docs/architecture/components/agentgres/doctrine.md
  - docs/architecture/components/wallet-network/doctrine.md
  - docs/architecture/components/connectors-tools/doctrine.md
---

# Runtime Trust-Boundary Method

The master activates this method through M0.9, WP-RUNTIME, and the selected M9
route proof. The dated 198-method census is retained as audit evidence; current
code must always be re-inventoried before a cut uses it.

## Classification question

For each public facade method, ask whether moving it would weaken deterministic
transition admission, owner-supplied policy or authority enforcement,
exact-effect fencing, accepted-truth ordering, receipt/evidence binding, replay,
or stable invocation semantics. Size, line count, naming, and compatibility are
inventory signals only.

Classify each callable exactly once as:

- trusted admission/effect core;
- owner service that plans or prepares but re-enters the same gate;
- policy-filtered projection/read service;
- bounded compatibility gateway with an explicit residual obligation; or
- retirement.

Owner services may prepare, select, render, or inspect. They cannot mint
authority, append accepted truth, issue success receipts, or invoke an effect
outside the same owner-qualified boundary.

## Six proof gates

1. Inventory every public callable and fail on missing, duplicate, renamed, or
   newly added unclassified methods.
2. Name the canonical subject owner and the exact accepted-truth or effect
   boundary for every method.
3. Name the policy-enforcement point, product-authority provider when an effect
   crosses authority, and the final invoker. An unsigned review chain is never
   an authority input.
4. Name the Agentgres operation/head/root and receipt/evidence behavior where
   accepted truth or an external effect is relevant.
5. Prove the old and new routes converge on the same admission, authority,
   writer-fence, idempotency, final-invoker, and receipt spine; denial must
   produce zero invoker calls.
6. Regenerate the route/final-invoker, runtime-residual, and Hypervisor-surface
   projections at the macro boundary and retain the exact adversarial evidence.

## Required outputs

- a content-bound method inventory and exact-one classification;
- owner, trust, authority, truth, receipt, and final-invoker maps;
- explicit compatibility residuals with stop conditions;
- extraction-specific substitution, stale-authority, bypass, retry, crash, and
  replay tests; and
- the owning record’s future literal exit contract.

Passing this method for one inventory proves only that inventory and its tested
routes. It does not prove terminal runtime convergence, product readiness, or a
stage exit.

