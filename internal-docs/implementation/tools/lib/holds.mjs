// The ONE open-successor hold ledger, shared by every tool that may not treat a
// held closure as a satisfied one: transition, certify-stage, generate-now, and
// check-program.
//
// WHY IT EXISTS
//
// A canon reviewer may disposition a drifted subject `successor_required`: the
// change reaches a closure that was already proven, and the honest repair is a
// SUCCESSOR record, never a rewrite of the verified closure. Until 2026-07-29
// that disposition advanced the baseline and required nothing further — 15 of
// them were recorded and no successor was ever demanded by any machine. The
// same shape appeared again when a `verified` record was withdrawn and its
// corrective successor was owed but unnamed.
//
// A hold is therefore opened per disposition and closed only by an ADMITTED
// successor. While a hold is open, every predecessor it names projects as
//
//     verified_historical_with_open_successor
//
// and never as unqualified `verified`. That qualification is not cosmetic: it
// is the difference between "this was proven, at the revision it was proven
// against" and "this is proven now".
//
// SHAPE
//
// The ledger is APPEND-ONLY, like every other attestation ledger here. Hold
// identities are seeded from their sources and never rewritten; a hold's state
// changes only by appending to its own `state_transitions`. Nothing in this
// module derives a hold from a projection, and nothing here changes any status:
// the status a record holds is still owned by its status authority. This adds a
// QUALIFICATION to how a status may be projected, and a refusal to certify on
// top of one.
import fs from "node:fs";
import path from "node:path";
import { ESTATE_ROOT, readJson, writeJsonDeterministic } from "./estate.mjs";

export const LEDGER_REL = "_archive/holds/open-successor-holds.v1.json";
export const LEDGER_ABS = path.join(ESTATE_ROOT, LEDGER_REL);
export const FORMAT = "ioi.program.open_successor_holds.v1";
export const QUALIFIED_STATUS = "verified_historical_with_open_successor";

// A hold is open, or it was closed by an admitted successor, or the owner
// withdrew the requirement in writing. There is no fourth way out, and in
// particular there is no "stale" or "no longer relevant".
export const HOLD_STATES = new Set([
  "open",
  "successor_admitted",
  "requirement_withdrawn_by_owner",
]);

export const SOURCE_KINDS = new Set([
  "canon_acceptance_disposition",
  "withdrawn_verification",
]);

// --- the subordinate successor graph (added 2026-07-29 under owner ruling) --
//
// `required_successor.work_item_id` is SINGULAR, and that was a real modelling
// defect, not a stylistic one. osh-0001 qualifies seven verified closures whose
// re-proofs are genuinely different pieces of work. A singular field left only
// two shapes: open a second hold over the same disposition, which double-counts
// one requirement, or merge two proof contracts into one successor, so neither
// is proven on its own terms. The owner refused both.
//
// A hold may therefore carry `required_successor.successor_graph`:
//
//   {
//     "aggregate": "<work_item_id>",          // MUST equal required_successor.work_item_id
//     "subordinate_proofs": [                 // each re-proves ONE qualified predecessor
//       { "work_item_id": "...", "re_proves_predecessor": "..." }
//     ],
//     "outstanding_predecessors": [           // qualified, owed, and not yet authored
//       { "predecessor": "...", "why": "..." }
//     ]
//   }
//
// The graph is ENFORCED rather than asserted: the aggregate must be a real
// aggregate_exit record that actually joins every subordinate as a child, every
// qualified predecessor must appear exactly once across the two lists, and a
// discharge is refused while any subordinate is unproven or anything is
// outstanding. A hold can no longer be closed by pointing at an aggregate that
// joined nothing.
export const SUBORDINATE_KEY = "successor_graph";

export function successorGraph(hold) {
  return hold?.required_successor?.[SUBORDINATE_KEY] ?? null;
}

// --- direct re-proof by the aggregate (added 2026-07-29 under owner ruling) --
//
// Some qualified predecessors do not need a subordinate of their own: the
// aggregate re-proves them itself. Expressing that as a subordinate whose
// work_item_id IS the aggregate would force the aggregate to join itself as its
// own child, and the owner's instruction was the opposite — "no aggregate
// beneath the aggregate". The graph therefore carries a third list:
//
//   "directly_re_proven_by_aggregate": [ { "predecessor": "...", "why": "..." } ]
//
// It counts as coverage, it is attributed to the aggregate, and it is enforced:
// the AGGREGATE RECORD must itself declare the predecessor in its
// `directly_re_proves` list, so the claim lives where the proof will, not only
// in the ledger.
export const DIRECT_KEY = "directly_re_proven_by_aggregate";

// Every predecessor the graph accounts for, and how.
export function graphCoverage(graph) {
  const covered = new Map();
  for (const entry of graph?.subordinate_proofs ?? []) {
    if (entry?.re_proves_predecessor) {
      covered.set(entry.re_proves_predecessor, entry.work_item_id ?? null);
    }
  }
  for (const entry of graph?.[DIRECT_KEY] ?? []) {
    if (entry?.predecessor) {
      covered.set(entry.predecessor, graph?.aggregate ?? null);
    }
  }
  const outstanding = new Set(
    (graph?.outstanding_predecessors ?? []).map((e) => e?.predecessor).filter(Boolean),
  );
  return { covered, outstanding };
}

// --- partial successors ordered under an UNNAMED successor -------------------
//
// A hold whose qualified population is only partly mapped must be able to say
// "this proof was ordered, and it does not discharge me". Setting
// required_successor.work_item_id to that one record would claim the opposite:
// the singular field IS the discharge target, so naming a partial proof there
// would let one proof close a hold that qualifies eleven closures. osh-0003 is
// exactly that shape.
//
// So a hold may carry, alongside a NULL required_successor.work_item_id:
//
//   "partial_successors_ordered": [
//     { "work_item_id": "...", "re_proves_predecessor": "...", "why": "..." }
//   ],
//   "successor_unnamed_because": "..."
//
// Enforced: each entry must be a real record re-proving a predecessor this hold
// actually qualifies, the reason must be stated, and the hold may not be
// discharged on the strength of them — discharge still needs a named, admitted
// successor.
export const PARTIAL_KEY = "partial_successors_ordered";

export function partialSuccessors(hold) {
  return hold?.required_successor?.[PARTIAL_KEY] ?? [];
}

export function emptyLedger() {
  return {
    evidence_format: FORMAT,
    role:
      "One open hold per disposition that requires a successor. A hold names where the requirement came from, the canon subject or record it concerns, the predecessor closures it qualifies, and what a successor must do to discharge it.",
    rule:
      "Append-only. Hold identities are seeded from their named sources and are never rewritten or reordered; the sequence is dense. A hold's state changes only by appending to its own state_transitions, and `state` is the last transition's target, written by tooling and re-derived on every check.",
    projection_directive:
      `While a hold is open, every predecessor record it names MUST project as ${QUALIFIED_STATUS} and MUST NOT project as unqualified verified. A projection is not permitted to round the qualification off.`,
    claim_boundary:
      "A hold records an owed successor and nothing else. Opening one asserts no defect in the predecessor's original proof, changes no status, and closes no stage. Discharging one asserts only that a successor was admitted — the successor's own proof is the successor's own obligation.",
    consumed_by: [
      "internal-docs/implementation/tools/transition.mjs",
      "internal-docs/implementation/tools/certify-stage.mjs",
      "internal-docs/implementation/tools/generate-now.mjs",
      "internal-docs/implementation/tools/check-program.mjs",
      "internal-docs/implementation/tools/check-open-successor-holds.mjs",
    ],
    holds: [],
  };
}

export function readHoldLedger() {
  if (!fs.existsSync(LEDGER_ABS)) return emptyLedger();
  return readJson(LEDGER_ABS);
}

export function writeHoldLedger(ledger) {
  writeJsonDeterministic(LEDGER_ABS, ledger);
  return LEDGER_ABS;
}

// State is the last appended transition's target. Stored `state` is a cache of
// this and is verified against it, never trusted over it.
export function derivedState(hold) {
  const transitions = hold.state_transitions ?? [];
  if (transitions.length === 0) return "open";
  return transitions[transitions.length - 1].to;
}

export function isOpen(hold) {
  return derivedState(hold) === "open";
}

export function openHolds(ledger = readHoldLedger()) {
  return (ledger.holds ?? []).filter(isOpen);
}

// Every open hold that qualifies this record — either because the record is one
// of the hold's predecessor closures, or because the record IS the withdrawn
// verification the hold was opened over.
export function openHoldsForRecord(workItemId, ledger = readHoldLedger()) {
  return openHolds(ledger).filter((h) =>
    (h.predecessor_records ?? []).includes(workItemId)
  );
}

// The open holds this record would DISCHARGE by reaching verified: the holds
// that name it as their admitted successor.
export function openHoldsAwaitingSuccessor(workItemId, ledger = readHoldLedger()) {
  return openHolds(ledger).filter((h) =>
    (h.required_successor?.work_item_id ?? null) === workItemId
  );
}

// The projection rule, in one place. `status` is what the status authority
// says; the return value is what a projection is permitted to display.
export function projectedStatus(workItemId, status, ledger = readHoldLedger()) {
  if (status !== "verified") return status;
  return openHoldsForRecord(workItemId, ledger).length > 0
    ? QUALIFIED_STATUS
    : status;
}

export function qualifiedRecords(ledger = readHoldLedger()) {
  const out = new Map();
  for (const hold of openHolds(ledger)) {
    for (const id of hold.predecessor_records ?? []) {
      if (!out.has(id)) out.set(id, []);
      out.get(id).push(hold.hold_id);
    }
  }
  return out;
}

export function appendStateTransition(ledger, holdId, transition) {
  const hold = (ledger.holds ?? []).find((h) => h.hold_id === holdId);
  if (!hold) throw new Error(`unknown hold: ${holdId}`);
  hold.state_transitions = [...(hold.state_transitions ?? []), transition];
  hold.state = derivedState(hold);
  return ledger;
}
