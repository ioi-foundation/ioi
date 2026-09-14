#!/usr/bin/env node
// ACC-4 · an ambiguous external effect reconciles — the composed journey runner.
//
// A clause table over scripts/lib/acceptance-journey.mjs. The journey document says this journey
// "is not satisfied by CI: CI exercises no live external effect". The live half is therefore held
// the way M01.7 holds it (re-scoped 2026-09-12): the one owner-authorized live execution is
// RETAINED and an applicability gate proves, on every run, that the retained evidence still
// describes THIS tree (integrated commit is an ancestor, coordinates well-formed, terminal claims
// carried, structural mutations executed). R-139 (2026-09-14, MVP owner, owner-reversible) applies
// that precedent to the journey: fresh live runs (M09.6's dual-branch transaction, M12.9's fresh
// certificate) are SCHEDULED-OUTSTANDING with their exact prerequisite and do not hold the MVP
// gate; they are printed on every run and are never a pass.
//
//   node scripts/check-acceptance-external-effect-reconciliation.mjs [--mutation-batteries] [--mutation] [--evidence <out.json>]

import { runJourney, app, rootScript, node } from "./lib/acceptance-journey.mjs";

const absent = (unit, check, what) => ({ what: `${what} — ${check} (${unit}) is To be authored`, owner: unit });
const LIVE_RULING = "R-139 (2026-09-14, MVP owner): the M01.7 precedent — retained live evidence re-qualified by check:t7-retained-capstone-applicability on every run";
const LIVE_PREREQ = "an owner-authorized Akash account with a funded deposit (IOI_C7_EMAIL, IOI_C7_PASSWORD_FILE, IOI_WALLET_SECRET_PASS), authorized leg by leg";

const CLAUSES = [
  { id: "1", clause: "Intent before effect: an intent root is committed before the external call", unit: "M01.6", checks: [app("check:governed-effect-assurance-floor")] },
  { id: "2", clause: "Outcome after effect: an outcome root is committed after it, naming what the provider reported", unit: "M01.6", provenBy: "1" },
  { id: "3", clause: "Ambiguity is a state, not a retry: a timeout, dropped connection or unparseable response puts the action in reconciliation_required and nothing retries from it", unit: "M01.6", provenBy: "1" },
  { id: "4", clause: "Reconciliation reads the other side: resolution comes from the provider's own record; for escrow providers close acceptance does not close reconciliation — refund settlement or the final debit is read back independently", unit: "M07.3 · M01.7 · M09.6", checks: [node("apps/hypervisor/scripts/verify-hypervisor-provider-spend-reconciliation.mjs"), rootScript("check:provider-spend-reconciliation"), rootScript("check:t7-retained-capstone-applicability")], battery: [{ ...rootScript("mutate:provider-spend-reconciliation"), cost: "minutes" }, { ...rootScript("mutate:t7-retained-capstone-applicability"), cost: "minutes" }], scheduled: [{ what: "a FRESH dual-branch live transaction (no-qualified-bid close reaching provider-confirmed refund, and the positive branch reaching bid, lease, C6 retrieved_live, endpoint, teardown, zero open exposure) assembled and verified independently — M09.6's check:provider-neutral-live-transaction", prerequisite: LIVE_PREREQ, ruling: LIVE_RULING }] },
  { id: "5", clause: "Restore is not reconciliation: restoring the environment leaves the external effect exactly as unreconciled as it was", unit: "M06.2", checks: [rootScript("check:typed-effect-recovery"), app("check:backup-restore")], battery: { ...rootScript("mutate:typed-effect-recovery"), cost: "multi-hour" } },
  { id: "6", clause: "Recovery posture is declared per action — replayable, checkpointable, compensatable, reconciliation-required or non-retryable — and the runtime honours the declaration", unit: "M06.2", provenBy: "5" },
  { id: "7", clause: "Spend follows the same shape: a charge that may or may not have landed is reconciled against provider billing before any figure is reported; a local estimate or spent: 0 projection cannot substitute", unit: "M07.3", provenBy: "4" },
  { id: "N1", negative: true, clause: "An external side effect is never recorded as fail-closed refused after it happened", unit: "M01.6", provenBy: "1" },
  { id: "N2", negative: true, clause: "No compensating action is claimed that the provider cannot confirm", unit: "M07.3", provenBy: "4" },
  // check:c8-v3-canonical-bundle is NOT composed: as registered it takes a bundle directory argument
  // and there is no tracked v3 bundle, so it cannot run as written (measured 2026-09-14, R-137). The
  // relying-party battery (40 resealed semantic mutations rejected) and the U1 real-campaign relying
  // party (56 mutations over retained real evidence) are the executable forms of the same claim.
  { id: "N3", negative: true, clause: "No success certificate is emitted while a deposit is refund_pending, a provider lease is unclosed, or the final debit/refund is unknown", unit: "M12.9 · M12.10 · M06.7", checks: [app("check:c8-v3-relying-party"), app("check:c8-v3-portable-bundle"), app("check:u1-real-campaign-relying-party"), app("check:c7-c8-capstone", ["--", "--self-test"])], scheduled: [{ what: "a NEW C8 certificate assembled from fresh durable evidence with its generated output mutation-tested — M12.9's check:c8-bounded-live-effect-certificate (assemble-c7-c8-evidence.mjs reads akash-deployments/leases/endpoints and eleven c7-*.json artifacts including the wallet transaction cast)", prerequisite: LIVE_PREREQ, ruling: LIVE_RULING }] },
  { id: "E", clause: "Journey evidence: the provider transport boundary, proposal provenance and the Agentgres-owned recognized-effect publication order", unit: "M01.8 · M06.8", checks: [app("check:provider-transport"), app("check:provider-proposal-provenance"), rootScript("check:recognized-effect-publication-order")], battery: { ...rootScript("mutate:recognized-effect-publication-order"), cost: "minutes" }, scheduled: [{ what: "check:provider-transport:live — the transport boundary against a real provider", prerequisite: "a provider API key for one registered model provider", ruling: LIVE_RULING }] },
];

await runJourney({
  gate: "ACC-4",
  title: "an ambiguous external effect reconciles",
  doc: "internal-docs/implementation/acceptance/journey-04-external-effect-reconciliation.md",
  clauses: CLAUSES,
});
