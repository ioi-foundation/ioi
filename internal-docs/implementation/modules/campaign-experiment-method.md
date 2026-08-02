---
module_id: campaign-experiment-method
module_class: method
title: Campaign experiment, evaluator, and fault method
sequencer: program/sequence.v1.json
status_owner: work-item records
stage_ids: [M8]
legacy_id: stage-guides/m8/campaign-experiment-method.md
canon_owners:
  - docs/architecture/foundations/bounded-recursive-improvement.md
  - docs/architecture/foundations/institutional-learning-boundary.md
  - docs/architecture/components/daemon-runtime/improvement-governance-gates.md
  - docs/architecture/components/hypervisor/evaluations.md
  - docs/architecture/components/hypervisor/foundry.md
---

# Campaign Experiment Method

This method is active only when M8 pulls an order-zero Campaign. Canon owns the
objects and Search/Judgment/Authority split. The method does not create an RSI
engine, recursive seat, promotion authority, or production mutation path.

## Frozen experiment contract

Before observing a candidate, freeze the governance/profile revision, exact
target base, order, Agenda, finite budget, search space, eligibility rules,
EvaluationEpoch, exposure ledger, cutoff, evidence claim, metrics, statistical
decision rule, stopping rule, rollback/recall trigger, and negative-result
retention path. Branches and retries consume the same ancestor budget; they do
not reset it.

Search proposes. Judgment evaluates against an unchanged epoch. Authority stays
with the target owner and receives only an UpgradeProposal. The candidate may
not select or mutate its evaluator, see held-out material beyond policy, alter
the cutoff after exposure, promote itself, or change production.

## Proof method

- Reproduce candidate selection and scores from immutable inputs and retained
  exposure/order facts.
- Separate exploratory, confirmatory, challenge, and post-selection evidence.
- Retain negative, invalid, inconclusive, exploit, superseded, and challenged
  results; report false accepts/rejects and support cost.
- Run evaluator substitution, leakage, overfit, budget-reset, branch-amplifier,
  stale-base, provider-loss, source-revocation, restart, and replay faults.
- Prove a direct one-shot proposal path remains available when a Campaign is
  unnecessary.
- Hand promotion, canary, rollback, recall, and kill decisions to the ordinary
  owner-governance path with the applicable product authority and receipts.

## Outputs and stop rules

Outputs are an immutable experiment manifest, candidate/evidence index,
EvaluationEpoch and exposure refs, statistical report, retained negative
battery, reproducibility bundle, target-owner proposal, and future literal exit
contract. Stop on evaluator conflict, mutable thresholds, unbounded budgets,
missing rights/lineage, candidate-controlled judgment, lost negative evidence,
or any self-promotion path. Passing an experiment proves only its frozen target
and epoch; it is not a recursive-improvement, production, or stage claim.

