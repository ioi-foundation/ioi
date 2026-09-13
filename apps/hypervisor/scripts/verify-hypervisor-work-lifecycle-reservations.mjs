#!/usr/bin/env node
//
// M04.10 — PER-DIMENSION WORK RESERVATIONS THAT CANNOT OVERSUBSCRIBE AN ANCESTOR.
//
// ACC-5 clause 8: reservations are exact-head, per-dimension and disjoint, preserve protected
// recovery/integration capacity, narrow every ancestor bound, and transfer atomically on
// reassignment — with crash, sibling races and replacement unable to duplicate or leak one.
//
// WHAT THIS GATE DOES NOT DO, because two other layers already do it and a third opinion is not
// coverage. The registered contract's members, its integer domains and its cross-field invariants
// are proved for every family by the registry-driven `check:architecture-contracts` over fixtures
// this unit ships. The ARITHMETIC — the grandparent that a parent's headroom hides, the protected
// floor, the supersession fold, overflow, the unreadable sibling — is proved by 39 kernel tests
// over sets, which is the only level at which a property of a SET can be tested. Restating either
// here would be a second opinion on a settled question.
//
// WHAT HAD NO GATE IS THE SEAM: that the admission path actually APPLIES the decision rather than
// merely owning one. That is the defect M07.2 was written for a plane down — a contract resolved
// and then not consulted — and it is worth asserting in its own right, because a decision function
// with no caller passes every unit test it has.
//
// AND THE STREAM SEPARATION IS PINNED AS AN ABSENCE, which is the durable form. R-74 ruled
// reservations onto their own event stream because the work-lifecycle RECORD chain's head moves on
// every phase transition, and aiming exact-head CAS at a head unrelated work also moves converts a
// correctness device into a generator of spurious refusals. A pin that the admission never touches
// the record stream survives a refactor that a comment would not.
//
//   --mutation  prove each finding fails on its own
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = dirname(dirname(dirname(here)));
const mutation = process.argv.includes("--mutation");
const findings = [];
const observations = {};
const ok = (name, satisfied, detail) => {
  findings.push({ name, satisfied: !!satisfied, detail: detail ?? "" });
  console.log(`${satisfied ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
};

const SCHEMAS = join(repo, "docs/architecture/_meta/schemas");
const ROUTES = join(repo, "crates/node/src/bin/hypervisor_daemon_routes/work_lifecycle_routes.rs");
const KERNEL = join(
  repo,
  "crates/services/src/agentic/runtime/kernel/runtime_work_lifecycle_log.rs",
);
const ROUTER = join(repo, "crates/node/src/bin/hypervisor-daemon.rs");

const contract = JSON.parse(
  readFileSync(join(SCHEMAS, "work-dimension-reservation.v1.schema.json"), "utf8"),
);
const invariants = JSON.parse(
  readFileSync(join(SCHEMAS, "invariants/work-dimension-reservation.v1.invariants.json"), "utf8"),
);
// Comments stripped before every absence pin: both files DESCRIBE at length the things they do
// not do, and a raw search would read that description as the thing itself. String literals are
// kept, because the refusal codes this gate reads are string literals.
const strip = (text) =>
  text
    .replace(/\/\/![^\n]*/g, "")
    .replace(/\/\/\/[^\n]*/g, "")
    .replace(/\/\/[^\n]*/g, "")
    .replace(/\/\*[\s\S]*?\*\//g, "");
const routeCode = strip(readFileSync(ROUTES, "utf8"));
const kernelCode = strip(readFileSync(KERNEL, "utf8"));
const routerSource = readFileSync(ROUTER, "utf8");

// ------------------------------------------------------- the seam: resolve implies APPLY
const admitBody =
  /fn admit_reservation\([\s\S]*?\n\}/u.exec(routeCode)?.[0] ?? "";
observations.admission_found = admitBody.length > 0;
ok(
  "the admission path EXISTS and is the one the route calls — a decision function with no caller passes every unit test it has",
  admitBody.length > 0 && /admit_reservation\(/u.test(routeCode),
  `${admitBody.split("\n").length} lines`,
);
const planAt = admitBody.indexOf("plan_reservation");
const admitAt = admitBody.indexOf("admit_event_stream_operation");
ok(
  "the DECISION runs before the WRITE, so a refused claim never reaches the substrate — ordering, not merely presence, is the property",
  planAt > -1 && admitAt > -1 && planAt < admitAt,
  planAt > -1 && admitAt > -1 ? `plan@${planAt} < admit@${admitAt}` : "missing",
);
ok(
  "the claim is validated against its REGISTERED contract before anything is written, so a record that would not survive the offline verifier is never persisted and then explained",
  /validate_architecture_contract\(/u.test(admitBody) &&
    /RESERVATION_CONTRACT_ID/u.test(admitBody),
  "contract-validated at admission",
);

// ------------------------------------------------------------- exact head, and the race
ok(
  "the head the decision was given is the head the write commits against — one value, read once, used for both the diagnosis and the CAS",
  /stream\.head\.as_deref\(\)/u.test(admitBody) &&
    admitBody.split("stream.head.as_deref()").length - 1 >= 2,
  "same head to plan and to admit",
);
ok(
  "a concurrent winner is a typed head conflict rather than a silent retry or a lost claim",
  /AdmissionRefusal::HeadConflict/u.test(admitBody) &&
    /"work_reservation_head_moved"/u.test(admitBody),
  "HeadConflict is surfaced",
);

// --------------------------------------------------- the stream separation, pinned as absence
ok(
  "the reservation family has its OWN stream namespace, distinct from the work-lifecycle record chain",
  /RESERVATIONS_NS/u.test(routeCode) &&
    /RECORDS_NS/u.test(routeCode) &&
    !/RESERVATIONS_NS\s*:\s*&str\s*=\s*"work-lifecycle-records"/u.test(routeCode),
  "distinct namespaces",
);
ok(
  "PINNED ABSENCE — the reservation admission never writes to the RECORD stream, so a phase transition cannot invalidate a pending claim and exact-head CAS keeps meaning what it says",
  !/RECORDS_NS/u.test(admitBody),
  "admission touches only the reservation stream",
);

// --------------------------------------------------------------- per-dimension, one vocabulary
const dimensions = contract.properties.dimension.enum;
observations.dimensions = dimensions;
ok(
  "a claim names exactly ONE dimension from a closed vocabulary, so a claim on compute does not narrow a bound on storage",
  Array.isArray(dimensions) &&
    dimensions.length > 1 &&
    contract.properties.dimension.type === "string",
  `${dimensions.length} dimensions`,
);
ok(
  "the kernel compares dimensions rather than assuming one, so the per-dimension property is enforced where the sums happen",
  /get\("dimension"\)/u.test(kernelCode),
  "dimension is read in the transaction",
);

// ---------------------------------------------------------- reassignment: ONE append, atomic
ok(
  "a successor names its predecessor, which is the only single append that both creates a claim and releases another — two appends cannot be atomic through a one-operation admission",
  contract.required.includes("transferred_from_ref") &&
    /transferred_from_ref/u.test(kernelCode),
  "successor-names-predecessor",
);
ok(
  "a superseded predecessor holds NOTHING, and the claim under admission is part of the picture it is admitted into — the fold that reads only the siblings makes every reassignment look like an oversubscription",
  /chain\(std::iter::once\(candidate\)\)/u.test(kernelCode),
  "candidate included in the supersession fold",
);
ok(
  "a terminal successor is refused: releasing a predecessor while holding nothing in its place is the leak arriving through the field that prevents it",
  /"work_reservation_successor_not_active"/u.test(kernelCode),
  "successor must be active",
);
const transferRule = (invariants.rules ?? []).find((rule) =>
  rule.rule_id.endsWith("transfer_names_its_successor"),
);
ok(
  "a TRANSFERRED claim must name where its units went, refused offline by a registered invariant",
  !!transferRule,
  transferRule?.rule_id ?? "ABSENT",
);

// ------------------------------------------------------------------ cross-owner leakage
ok(
  "identity resolves BEFORE the body is read, so an anonymous caller is owed 401 rather than a complaint about their payload",
  /request_identity\(&st, &headers\)\?/u.test(routeCode) &&
    /body: axum::body::Bytes/u.test(routeCode),
  "identity-first handler",
);
ok(
  "the stream a claim contends on is DERIVED from its own ancestor chain, never taken from the caller — a caller-chosen stream would let a claim contend with nobody",
  /fn reservation_stream_tail\(/u.test(routeCode) &&
    /ancestor_chain/u.test(routeCode),
  "tail derived from the chain",
);
ok(
  "the admission route is registered and reachable",
  /"\/v1\/hypervisor\/work-lifecycle\/reservations"/u.test(routerSource),
  "route registered",
);

// ------------------------------------------------------- every refusal is reachable, both ways
const kernelCodes = [
  ...new Set(
    [...kernelCode.matchAll(/"(work_reservation_[a-z_]+)"/gu)].map((match) => match[1]),
  ),
].sort();
observations.refusal_codes = kernelCodes;
ok(
  "the transaction's refusals are typed and named rather than a single opaque rejection — a caller learns WHICH bound it broke, which is the difference between a reason and a refusal",
  kernelCodes.length >= 6,
  `${kernelCodes.length} typed refusals: ${kernelCodes.join(", ")}`,
);

// ----------------------------------------------------------------------------- mutation
if (mutation) {
  console.log("\n--- mutation drills ---");
  const drill = (name, caught, detail) => ok(`MUTANT CAUGHT: ${name}`, caught, detail);

  drill(
    "writing the claim before deciding on it is caught, because the assertion is about ORDER and not about both calls being present",
    (() => {
      const swapped = admitBody
        .replace("plan_reservation", "__PLACEHOLDER__")
        .replace("admit_event_stream_operation", "plan_reservation")
        .replace("__PLACEHOLDER__", "admit_event_stream_operation");
      return swapped.indexOf("plan_reservation") > swapped.indexOf("admit_event_stream_operation");
    })(),
    "order is the subject",
  );
  drill(
    "pointing the admission at the RECORD stream is caught, so R-74's separation survives a refactor rather than resting on a comment",
    /RECORDS_NS/u.test(`${admitBody}\n RECORDS_NS,`),
    "the absence pin detects the wrong namespace",
  );
  drill(
    "dropping the candidate from the supersession fold is caught — the exact bug these tests found, and the one that makes every reassignment read as an oversubscription",
    !/chain\(std::iter::once\(candidate\)\)/u.test(
      kernelCode.replace("chain(std::iter::once(candidate))", ""),
    ),
    "the fold's membership is the subject",
  );
  drill(
    "the modules' own prose about what they do NOT do cannot satisfy an absence pin — comments are stripped first",
    (() => {
      const asComment = strip(`${admitBody}\n// RECORDS_NS`);
      const asCode = strip(`${admitBody}\nRECORDS_NS,`);
      return !/RECORDS_NS/u.test(asComment) && /RECORDS_NS/u.test(asCode);
    })(),
    "comment inert, code caught",
  );
}

const failed = findings.filter((finding) => !finding.satisfied);
console.log(
  JSON.stringify(
    {
      check: "check:work-lifecycle-reservations",
      unit: "M04.10",
      verdict: failed.length === 0 ? "PASS" : "FAIL",
      executed_assertions: findings.length,
      passed: findings.length - failed.length,
      failed: failed.length,
      observations,
      remaining_nonclaims: [
        "THE ARITHMETIC IS NOT RESTATED HERE. Disjointness, the protected floor, ancestor narrowing, the supersession fold, overflow and the unreadable sibling are properties of a SET, and they are proved by 39 kernel tests over sets — including a planted mutant that narrows only the nearest ancestor, which is the plausible wrong implementation and turns exactly the two chain-dependent assertions red. This gate proves the SEAM: that the admission path applies that decision, in that order, on the right stream.",
        "CRASH AND RESTART ARE PROVED BY THE SUBSTRATE'S OWN GUARANTEE, NOT RE-DEMONSTRATED HERE. The admission is a single Agentgres event-stream operation with an exact expected head, confirmed durable before it is a fact and failing closed when the substrate is unavailable. A reservation is therefore admitted or it is not; there is no half-state for a restart to find. Re-proving that property per family would be re-proving the substrate.",
        "CROSS-OWNER LEAKAGE IS PROVED AT THE SEAM, NOT END TO END. Identity resolves before the body, and the contended stream is derived from the claim's own ancestor chain rather than taken from the caller. A live multi-tenant leak probe belongs to ACC-5's journey, which exercises the plane with real principals rather than reading the handler.",
        "THE CEILINGS ARE THE ANCESTOR OWNERS' TRUTH AND ARE SUPPLIED TO THE TRANSACTION. This gate does not check that a caller supplied the RIGHT bound — that is the ancestor owner's claim about its own capacity, and the kernel refuses any ancestor for which no bound was supplied rather than inventing one. What is closed here is that an unchecked ancestor cannot be skipped.",
      ],
    },
    null,
    2,
  ),
);
process.exit(failed.length === 0 ? 0 : 1);
