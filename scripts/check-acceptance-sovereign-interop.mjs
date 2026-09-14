#!/usr/bin/env node
// ACC-13 · two sovereign systems interoperate without merging — the composed journey runner.
//
// A clause table over scripts/lib/acceptance-journey.mjs. The journey document says it plainly:
// the four AIIP commands are required registration points owned by M11.1–M11.4, and "until each
// exists, exercises a real two-sovereign fixture and passes its planted cross-domain mutations,
// ACC-13 fails; architecture/docs or broad daemon tests cannot substitute". This runner exists so
// that failure is composed, named per clause, and recorded on one basis rather than implied.
// M11.4 is product_track (ADR 0053) and is named where a clause depends on it.
//
//   node scripts/check-acceptance-sovereign-interop.mjs [--mutation] [--evidence <out.json>]

import { runJourney, rootScript } from "./lib/acceptance-journey.mjs";

const absent = (unit, check, what) => ({ what: `${what} — ${check} (${unit}) is To be authored`, owner: unit });

const CLAUSES = [
  { id: "1", clause: "Terms precede the crossing: CollaborationTerms with an exact accepted root; nothing crosses before every required party has accepted", unit: "M11.1", absences: [absent("M11.1", "check:aiip-collaboration-discovery", "collaboration terms with an exact accepted root")] },
  { id: "2", clause: "Discovery is a policy-bound projection, not database access", unit: "M11.1", absences: [absent("M11.1", "check:aiip-collaboration-discovery", "policy-bound room-discovery publication")] },
  { id: "3", clause: "The handoff carries refs, not tables: bounded signed handoffs and refs cross; each domain's truth stays local", unit: "M11.1", absences: [absent("M11.1", "check:aiip-collaboration-discovery", "typed external participation and the least-disclosing ParticipantStateBundle producer over M04.8-owned refs")] },
  { id: "4", clause: "Semantics cross by crosswalk: the action arrives through an accepted crosswalk and a receipted mapping decision, both challengeable", unit: "M05.2 · M11.1", absences: [absent("M11.1", "check:aiip-collaboration-discovery", "the crosswalk crossing between two sovereign domains (the single-domain crosswalk is ACC-6 clause 4's and is not restated here)")] },
  { id: "5", clause: "Bindings are replaceable: A2A, MCP, directory, HTTP/RPC and chain/escrow are transports; no completion state, task state or registry entry is read as IOI verification, acceptance or authority", unit: "M11.3", absences: [absent("M11.3", "check:aiip-binding-replaceability", "versioned binding profiles and the substitution test")] },
  { id: "6", clause: "Exit is portable and does not end the room: a receipted, policy-filtered ParticipantStateBundle verifies without hosted database access; a participant leaves with lineage, credit and dispute history intact", unit: "M11.2", absences: [absent("M11.2", "check:aiip-portable-exit", "bundle verification and exit continuity")] },
  { id: "7", clause: "Federated admission is declared and enforced, distinct from hosted admission, and unreachable without terms acceptance", unit: "M11.2", absences: [absent("M11.2", "check:aiip-portable-exit", "hosted/federated mode fencing")] },
  { id: "8", clause: "Enrollment stays optional: a compatible system remains fully operable while the connected/secured service plane exists and is unused by it", unit: "M02.5 · M11.4", checks: [rootScript("check:network-enrollment-continuity-plane")], absences: [absent("M11.4 (product_track)", "check:aiip-enrollment-settlement", "the connected/secured service plane itself")] },
  { id: "9", clause: "Settlement crosses only what was agreed, preserving marketplace, service, verifier, attribution, dispute and settlement owner boundaries", unit: "M11.4 (product_track)", absences: [absent("M11.4 (product_track)", "check:aiip-enrollment-settlement", "the settlement envelope")] },
  { id: "N1", negative: true, clause: "No AIIP path is used inside one system_id", unit: "M11.1", absences: [absent("M11.1", "check:aiip-collaboration-discovery", "the same-system negative")] },
  // The first run (2026-09-14) failed HERE, on the runner's own table: this predicate exempted
  // clause 8 but not the evidence clause E, so a green architecture-contracts run read as a claim
  // of organizational independence. The predicate now says what it means — the only clauses that
  // execute anything are the single-system enrollment lane and the journey's named evidence, and
  // neither is an AIIP crossing or an independence claim.
  { id: "N2", negative: true, clause: "Same-owner multiplicity is explicitly not a pass; ACC-14 clause 7 is where an independently operated external Worker completes the arc", unit: "M11 · ACC-14", structural: (clauses) => { const executing = clauses.filter((c) => (c.checks ?? []).length > 0).map((c) => c.id); const allowed = new Set(["8", "E"]); const stray = executing.filter((id) => !allowed.has(id)); return { ok: stray.length === 0, detail: `executing clauses ${JSON.stringify(executing)} — the single-system enrollment lane (8) and the named evidence (E) only; every AIIP clause is a typed absence${stray.length ? `; stray executing clauses: ${stray.join(", ")}` : ""}` }; } },
  { id: "E", clause: "Journey evidence: architecture contracts and docs", unit: "M11", checks: [rootScript("check:architecture-contracts"), rootScript("check:architecture-docs")] },
];

await runJourney({
  gate: "ACC-13",
  title: "two sovereign systems interoperate without merging",
  doc: "internal-docs/implementation/acceptance/journey-13-sovereign-interop.md",
  clauses: CLAUSES,
});
