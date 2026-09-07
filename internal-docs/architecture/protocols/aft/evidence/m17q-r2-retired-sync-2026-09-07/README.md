# Retired process adopted successor-root history through sync (2026-09-07)

Scope: an orchestration authority-boundary defect found by the first clean
M16Q R2 attempt on `5ae464c11`. It is not one of the thirteen R1 findings and
it changes no QUV theorem, Q-A/Q-EA premise, policy root or schema. It is
retained because the mandatory `quv_disjoint_reconfiguration` gate failed on
it, because the mechanism let synced bytes stand in for successor authority,
and because the fixture's expected retirement refusal had previously been
produced by that very mechanism.

## Observation (`removed-rule-process/`)

The clean run `20260907T014928Z-5ae464c1146e` (moved out of the tree; only
this phase is retained here, gzipped, with `phase-results.tsv`, `commit.txt`
and `environment.txt`) passed every gate through `quv_status_squat_evidence`
and failed `quv_disjoint_reconfiguration` after 506 s with

```
Error: [retired old-root QUV node 2] Timeout waiting for pattern
'local ML-DSA signer belongs to neither the effective set nor the staged QUV successor set'.
```

`components/validator-20200-orch.log.gz` (the retired old-root member) shows:

1. before restart its executed projection was height 2 and its Agentgres
   admitted tip height 1; the other retired members stayed at height 2;
2. at restart it recovered from admitted height 1 (`Recovering chain state
   from height 1`), so `select_aft_pq_startup_root` observed height 1, below
   the activation height 3, `recovery_required` was false and startup took the
   ordinary old-member path;
3. it then initiated sync from the admitted cursor toward a successor peer at
   height 14, applied heights 2..14 (`Block sync complete!`, catch-up vote for
   H=14) and thereafter ticked with `neither local Ed25519 nor configured
   ML-DSA-44 key is authorized by the effective AFT validator set at height 15`
   once per second. The expected refusal never appeared.

The engine's `effective_validator_set_for` follows the canonical
`ValidatorSetsV1` projection (`next` becomes effective at its
`effective_from_height`), so the successor-signed QCs verified. Nothing in the
sync or gossip path consulted the process-local QUV install gate, which is the
only thing Q-EA7 allows to activate a successor. Before the R2 sync repairs the
same retired member had usually followed successor history through sync
*before* its restart, so its admitted height at restart was already at or
above activation and the startup check refused it — the passing diagnostic was
itself produced by the defect.

## Repair

`crates/validator/src/standard/orchestration/consensus.rs`:
`quv_successor_root_gate(handoff_enabled, staged_successor,
local_has_install_gate, height)` returns `Admit` when QUV handoff is not
configured, no successor is staged in this process, or `height` is below the
staged `effective_from_height`; `DeferUntilLocalInstall` when this process is
a staged successor (it holds a durable handoff store) whose gate has not
activated (`aft_quv_staged_successor` is cleared only by
`activate_installed_handoff`); and `RefuseRetired` when the process holds no
successor identity. `QUV_RETIRED_SIGNER_REFUSAL` is the single refusal text.

Applied at three points:

- `sync.rs` apply loop: per fetched block before any replacement/execution.
  Defer drops sync progress and returns (a later status response re-initiates
  from the admitted cursor after activation). Refuse sets
  `aft_quv_retired`, drops sync progress, quarantines the node and logs the
  refusal at `error` level (`target: quv`). The status-response handler does
  not re-initiate sync once `aft_quv_retired` is set.
- `gossip.rs` `handle_gossip_block`: same gate after the existing
  handoff-only branch; Defer ignores the block, Refuse is terminal as above.
- `lifecycle.rs` startup: after role selection, the workload's durable
  executed projection (`get_execution_status().height`), not only the
  admitted tip, is passed through the gate; a retired process whose projection
  already crossed activation refuses at startup.

Heights below activation, including the exact QC-certified boundary at
activation minus one that late successors must still receive, are unaffected.
No timeout, silence or synced/gossiped bytes grant or infer successor
authority; a successor still activates only from its own durable install gate.

## Regressions (`unit/`)

- `standard::orchestration::consensus::production::tests::quv_successor_root_gate_refuses_retired_and_defers_uninstalled_successor`
  pins the refusal text and every branch (disabled, no staged successor,
  heights 0/1/7 admitted for both roles, heights 8/9/14/u64::MAX refused for
  the old-only role and deferred for the pending successor).
  `quv-successor-root-gate.txt` is the passing transcript together with the
  existing `quv_post_activation_restart_stays_on_old_root_until_local_gate_recovers`.
- Removed-rule control `control-mutant-activation-boundary-removed.txt`:
  with the activation comparison neutralised (`|| true`, every height
  admitted) the regression fails at the first retired assertion
  (`left: Admit, right: RefuseRetired`); the mutant was restored and the
  diff verified before the campaigns ran.
- Both tests are required by the new mandatory M16Q phase
  `quv_successor_root_gate` in `.github/scripts/run_aft_m16q_qualification.sh`.
- Process-level removed-rule control: `removed-rule-process/` is the failed
  campaign on the unrepaired tree described above.

## Disjoint handoff campaign on the fixed tree (`disjoint-process/`)

`test_aft_quv_disjoint_successors_install_live_handoff_before_activation`
passed standalone (exit 0, 569.24 s; `started.txt` binds the tree state,
`campaign.log` and `components/` are the raw outputs). Gate events:

- validator 20600 (a successor restarted at 07:41:20 before its gate
  re-activated) received a sync batch reaching height 4 at 07:41:24.144 and
  logged `Deferring successor-root sync until the local QUV install gate
  activates.` (`applying_height=4`); 42 ms later it logged `Recovered QUV
  successor authority from its durable local install gate` and continued.
- validator 20400 (the retired old-root member, `keyed[0]`) restarted at
  07:41:45, recovered from admitted height 1 exactly as in the failed run,
  and at 07:41:46.753 refused `applying_height=3` from a successor peer with
  the retirement diagnostic (`refusing successor-root history from sync, node
  stopped`), once per delivered batch (two batches, 2 ms apart). It initiated
  no further sync. The fixture's retired-member assertion passed on that line.
- No retired member followed successor history before its restart.

`handoff-evidence-check.txt`: `check_aft_quv_handoff_evidence.py` passed
(4 successors, 4 expected correct members, maximum valid reply 888 ms within
the 24 000 ms qualified envelope, `portable_final_receipt=false`), with the
checker change below.

### Handoff evidence checker: fixture-terminated admission release

The first execution of this checker against a disjoint campaign (the phase
had never run: earlier retained runs predate it and the R2 attempt failed
before it) rejected the passing campaign with `completed operation lacks
final admission release`. Cause: the interrupted successor (`keyed[7]`,
validator 20300) is armed by the fixture to exit in the deliberate crash
window after its handoff state is durable and before its anchor advances.
Its handoff operation logged `operation_finished` at 07:40:43.7038 and the
process exited at 07:40:43.765; `operation_admission_released` is logged when
the admitted authorization is consumed by activation, which that process never
reached. The same finished-without-release shape is present in every retained
R1 disjoint/overlap campaign, so it is the fixture's designed crash, not a
release-lane defect.

Repair (`.github/scripts/check_aft_quv_handoff_evidence.py`): a finished
operation without a release is excused only when the same component log
carries a later `startup` record and no later event for that nonce; every
other missing release still fails, including for the audited handoff
operation. Self-test now has 2 positive and 34 negative cases (four new:
missing release without a restart, restart stamped before completion, restart
in a different component, and a later nonce event after the restart);
`unit/handoff-checker-self-test.txt`.

## Overlapping handoff campaign on the fixed tree (`overlap-process/`)

`test_aft_quv_overlapping_member_installs_and_recovers_the_same_live_handoff`
passed standalone (exit 0, 263.10 s). `handoff-evidence-check.txt` passed with
the same checker (4 successors, 4 expected correct members, maximum valid
reply 824 ms, `portable_final_receipt=false`). Gate events:

- at 07:46:22.136 the three old-only members (validators 20300, 20400,
  20600) each received the first successor-root block (height 3) as gossip
  from the same overlapping peer within 0.3 ms of each other and refused it
  with the retirement diagnostic (`refusing successor-root history from
  gossip, node stopped`). None adopted it; each was quarantined.
- 20400 and 20600 then received one unsolicited (opportunistic) blocks
  response each (height 3, at 07:46:27 and 07:46:26) and refused it again from
  the sync apply loop. The refusal is idempotent. After this campaign the
  blocks-response handler was given an early return once `aft_quv_retired`
  is set (an authority-neutral log-noise change verified by the 257
  orchestration unit tests and format check, and exercised next by the clean
  full R2 run, not by a rerun of these campaigns).
- the retired non-overlapping member (`keyed[1]`, validator 20300) restarted
  at 07:46:29 and refused height 3 again from sync at 07:46:30.336, which is
  the line the fixture asserts.
- the overlapping member (validator 20500) restarted at 07:46:25, recovered
  from its durable gate and produced the two further canonical blocks the
  fixture requires; no deferral was needed because it activated before any
  successor-root batch reached it.

## What this does and does not establish

It closes one reproduced authority bypass in the orchestration and restores the
fixture's retirement diagnostic to a cause that is actually the rule. It does
not qualify reconfiguration in general, does not add an observer profile for
retired members, and does not by itself make any M16Q gate pass; the
definitive clean R2 run on the committed tree is recorded separately under
`../m16q-runs/`.
