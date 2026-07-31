#!/usr/bin/env node
// Machine enforcement of open-successor holds.
//
//   node tools/check-open-successor-holds.mjs            report
//   node tools/check-open-successor-holds.mjs --check    same, exit 1 on error
//   node tools/check-open-successor-holds.mjs --seed     append any hold whose
//                                                        source exists and which
//                                                        the ledger is missing
//
// A `successor_required` disposition used to advance the canon baseline and
// require nothing further. This bar makes it require something: a hold in
// _archive/holds/open-successor-holds.v1.json, open until a named successor is
// admitted, qualifying every predecessor closure it names.
//
// Fail-closed properties:
//   * COVERAGE — every `successor_required` disposition in the acceptance
//     ledger, and every WITHDRAWN verification in a work-item record, must have
//     a hold. A disposition with no hold is `hold-missing`, and no amount of
//     green elsewhere hides it.
//   * NO INVENTED HOLDS — a hold whose source disposition does not exist is
//     `hold-unsourced`. The ledger tracks reality; it does not author it.
//   * STATE INTEGRITY — `state` must equal the last appended transition's
//     target, and a discharge must name a successor record that actually exists
//     and is actually verified. A hold cannot be closed by assertion.
//   * AN OPEN HOLD IS A FAILING BAR. Not a warning, not a skip. The program is
//     not certifiable while a proven closure has an owed, unwritten successor.
//
// --seed is append-only and idempotent: it never rewrites, reorders, or removes
// a hold, and it never closes one.
import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  ESTATE_ROOT,
  finding,
  progress,
  readJson,
  REPO_ROOT,
  report,
} from "./lib/estate.mjs";
import {
  derivedState,
  DIRECT_KEY,
  emptyLedger,
  graphCoverage,
  HOLD_STATES,
  isOpen,
  PARTIAL_KEY,
  partialSuccessors,
  QUALIFIED_STATUS,
  readHoldLedger,
  SOURCE_KINDS,
  successorGraph,
  writeHoldLedger,
} from "./lib/holds.mjs";

function resolvesAtParkedCommit(hold, state) {
  if (state !== "requirement_withdrawn_by_owner") return false;
  const transitions = hold.state_transitions ?? [];
  const transition = transitions[transitions.length - 1] ?? {};
  const commit = transition.subject_parked_at_commit;
  const subject = transition.subject_parked_path;
  const expectedSha256 = hold.subject_accepted_sha256 ?? hold.subject_baseline_sha256;
  if (!commit || subject !== hold.subject || !expectedSha256) return false;
  try {
    const bytes = execFileSync("git", ["show", `${commit}:${subject}`], {
      cwd: REPO_ROOT,
      encoding: null,
      stdio: ["ignore", "pipe", "ignore"],
    });
    return crypto.createHash("sha256").update(bytes).digest("hex") === expectedSha256;
  } catch {
    return false;
  }
}
import { loadWorkItems, statusAuthority } from "./generate-now.mjs";

const ACCEPTANCES_REL = "_archive/attestations/canon-acceptances.v1.json";
const SUCCESSOR_REQUIRED = "successor_required";

// Which verified closures a canon subject's hold qualifies. Three declared
// bindings, all of them written down by somebody: the canon map's own
// work_items list, a record's canon_owners citation, and a retained literal
// exit log that certifies the subject as its artifact. Union, then keep only
// the closures that are actually verified — an unverified record is not a
// closure and needs no qualification.
function boundRecords(subjectId, { records, canonMap, logArtifacts }) {
  const bound = new Set();
  const mapEntry = canonMap.subjects.find((s) => s.id === subjectId);
  for (const id of mapEntry?.work_items ?? []) bound.add(id);
  for (const record of records) {
    const owners = (record.canon_owners ?? []).map((o) =>
      typeof o === "string" ? o : o?.path
    );
    if (owners.includes(subjectId)) bound.add(record.work_item_id);
  }
  for (const [workItemId, artifact] of logArtifacts) {
    if (artifact === subjectId) bound.add(workItemId);
  }
  return [...bound].sort();
}

// A canon-acceptance hold qualifies closures that existed when the accepted
// change made their proof historical. A record first verified after that
// acceptance is current implementation against the accepted bytes, not a
// predecessor merely because it cites the same owner file. Treating every
// later verified record as a predecessor makes a file-level hold contagious
// forever and can circularly block the successor work itself.
function verifiedByAcceptance(record, acceptedAtCommit) {
  const verifiedAtCommit = record.last_status_transaction?.at_commit ?? null;
  if (!acceptedAtCommit || !verifiedAtCommit) return true;
  try {
    execFileSync(
      "git",
      ["merge-base", "--is-ancestor", verifiedAtCommit, acceptedAtCommit],
      { cwd: REPO_ROOT, stdio: "ignore" },
    );
    return true;
  } catch {
    return false;
  }
}

// work_item_id -> the artifact its retained literal exit log binds.
function literalLogArtifacts() {
  const out = [];
  const evidenceRoot = path.join(ESTATE_ROOT, "evidence");
  if (!fs.existsSync(evidenceRoot)) return out;
  for (const dir of fs.readdirSync(evidenceRoot).sort()) {
    if (!/^M\d{1,2}$/u.test(dir)) continue;
    for (const entry of fs.readdirSync(path.join(evidenceRoot, dir)).sort()) {
      if (!entry.endsWith(".exit.v1.txt")) continue;
      const text = fs.readFileSync(path.join(evidenceRoot, dir, entry), "utf8");
      const line = text.split("\n").find((l) => l.startsWith("ARTIFACT="));
      if (line) {
        out.push([entry.replace(/\.exit\.v1\.txt$/u, ""), line.slice("ARTIFACT=".length)]);
      }
    }
  }
  return out;
}

// Every hold the sources REQUIRE, keyed so a hold can be matched to its source
// without depending on ordering or on any id this tool assigns.
export function requiredHolds() {
  const records = loadWorkItems();
  const canonMap = readJson(path.join(ESTATE_ROOT, "program", "canon-map.v1.json"));
  const logArtifacts = literalLogArtifacts();
  const verified = new Set(
    records.filter((r) => statusAuthority(r).status === "verified").map((r) =>
      r.work_item_id
    ),
  );
  const required = [];

  // --- source 1: `successor_required` dispositions in the acceptance ledger
  const acceptancesAbs = path.join(ESTATE_ROOT, ACCEPTANCES_REL);
  if (fs.existsSync(acceptancesAbs)) {
    const ledger = readJson(acceptancesAbs);
    for (const entry of ledger.entries ?? []) {
      for (const subject of entry.subjects_reviewed ?? []) {
        if (subject.disposition !== SUCCESSOR_REQUIRED) continue;
        const bound = boundRecords(subject.id, { records, canonMap, logArtifacts });
        const predecessorRecords = bound.filter((id) => {
          const record = records.find((candidate) => candidate.work_item_id === id);
          return record && verified.has(id) &&
            verifiedByAcceptance(record, entry.accepted_at_commit ?? null);
        });
        required.push({
          source_key: `canon_acceptance:${entry.sequence}:${subject.id}`,
          source: {
            kind: "canon_acceptance_disposition",
            ledger: `internal-docs/implementation/${ACCEPTANCES_REL}`,
            acceptance_sequence: entry.sequence,
            reviewer_ref: entry.reviewer_ref ?? null,
            accepted_at_commit: entry.accepted_at_commit ?? null,
            disposition: SUCCESSOR_REQUIRED,
          },
          subject: subject.id,
          subject_kind: "canon_subject",
          subject_baseline_sha256: subject.baseline_sha256 ?? null,
          subject_accepted_sha256: subject.tree_sha256 ?? null,
          predecessor_records: predecessorRecords,
          bound_but_unverified_records: bound.filter((id) => !verified.has(id)),
          bound_post_acceptance_verified_records: bound.filter((id) => {
            const record = records.find((candidate) => candidate.work_item_id === id);
            return record && verified.has(id) &&
              !verifiedByAcceptance(record, entry.accepted_at_commit ?? null);
          }),
          required_successor: {
            work_item_id: null,
            requirement:
              `A successor record that re-proves, over ${subject.id} at ${subject.tree_sha256 ?? "the accepted revision"}, whatever the predecessor closures below proved over ${subject.baseline_sha256 ?? "the prior revision"}. The predecessors are never rewritten to absorb this change.`,
          },
        });
      }
    }
  }

  // --- source 2: withdrawn verifications in work-item records
  for (const record of records) {
    const correction = record.verification_correction;
    if (!correction || correction.state !== "WITHDRAWN") continue;
    required.push({
      source_key: `withdrawn_verification:${record.work_item_id}`,
      source: {
        kind: "withdrawn_verification",
        record: `internal-docs/implementation/${record.file}`,
        withdrawn_on: correction.withdrawn_on ?? null,
        withdrawn_at_commit: correction.withdrawn_at_commit ?? null,
        withdrawn_by: correction.withdrawn_by ?? null,
      },
      subject: `internal-docs/implementation/${record.file}`,
      subject_kind: "work_item_record",
      subject_baseline_sha256: null,
      subject_accepted_sha256: null,
      predecessor_records: [record.work_item_id],
      bound_but_unverified_records: [],
      required_successor: {
        work_item_id: null,
        requirement:
          (correction.corrective_successor_requirements ?? []).join(" ").trim() ||
          "A corrective successor that satisfies the withdrawn record's stated requirements.",
      },
    });
  }

  return required;
}

function seed(ledger, required) {
  const known = new Map((ledger.holds ?? []).map((h) => [h.source_key, h]));
  let next = (ledger.holds ?? []).length;
  const added = [];
  for (const req of required) {
    // An existing OPEN hold takes on predecessors that have become verified
    // since it was opened. Under-qualifying is the dangerous direction: it
    // would let a held closure project as unqualified verified.
    const existing = known.get(req.source_key);
    if (existing && isOpen(existing)) {
      const missing = req.predecessor_records.filter((id) =>
        !(existing.predecessor_records ?? []).includes(id)
      );
      if (missing.length > 0) {
        existing.predecessor_records = [
          ...(existing.predecessor_records ?? []),
          ...missing,
        ].sort();
      }
    }
    if (known.has(req.source_key)) continue;
    next += 1;
    const hold = {
      hold_id: `osh-${String(next).padStart(4, "0")}`,
      ...req,
      projection_qualification: QUALIFIED_STATUS,
      state: "open",
      state_transitions: [],
    };
    ledger.holds = [...(ledger.holds ?? []), hold];
    added.push(hold.hold_id);
  }
  return added;
}

export function evaluate({ ledger, required, byId, statusOf }) {
  const findings = [];
  const holds = ledger.holds ?? [];
  const bySource = new Map(holds.map((h) => [h.source_key, h]));
  const requiredKeys = new Set(required.map((r) => r.source_key));

  if (ledger.evidence_format !== emptyLedger().evidence_format) {
    findings.push(
      finding(
        "error",
        "ledger-format",
        `hold ledger declares evidence_format "${ledger.evidence_format}"; expected "${emptyLedger().evidence_format}"`,
      ),
    );
  }

  // --- coverage: no sourced disposition may be unheld
  for (const req of required) {
    if (!bySource.has(req.source_key)) {
      findings.push(
        finding(
          "error",
          "hold-missing",
          `${req.source_key} requires a successor and no hold records it; run --seed. A disposition that demands a successor while nothing tracks the demand is the exact defect this ledger exists to close.`,
          { source_key: req.source_key },
        ),
      );
    }
  }

  holds.forEach((hold, index) => {
    const where = hold.hold_id ?? `hold[${index}]`;
    if (hold.hold_id !== `osh-${String(index + 1).padStart(4, "0")}`) {
      findings.push(
        finding(
          "error",
          "hold-sequence",
          `${where} is at position ${index + 1}; hold ids are dense, ordered, and never rewritten`,
        ),
      );
    }
    if (!SOURCE_KINDS.has(hold.source?.kind)) {
      findings.push(
        finding("error", "hold-source-kind", `${where}: unknown source kind "${hold.source?.kind}"`),
      );
    }
    // A closure already verified by the acceptance commit and bound to a held
    // subject must be named. Later proofs against the accepted revision are
    // successors/current implementation, not historical predecessors.
    const req = required.find((r) => r.source_key === hold.source_key);
    if (req && isOpen(hold)) {
      const missing = req.predecessor_records.filter((id) =>
        !(hold.predecessor_records ?? []).includes(id)
      );
      if (missing.length > 0) {
        findings.push(
          finding(
            "error",
            "hold-predecessor-drift",
            `${where} does not name closure(s) already verified by its acceptance commit: ${missing.join(", ")}; they would project as unqualified verified. Run --seed.`,
          ),
        );
      }
    }
    if (!requiredKeys.has(hold.source_key)) {
      findings.push(
        finding(
          "error",
          "hold-unsourced",
          `${where} names source ${hold.source_key}, which no acceptance disposition and no withdrawn verification produces. A hold with no source was authored, not derived.`,
        ),
      );
    }
    const state = derivedState(hold);
    if (!HOLD_STATES.has(state)) {
      findings.push(
        finding("error", "hold-state", `${where}: state "${state}" is not one of ${[...HOLD_STATES].join(" | ")}`),
      );
    }
    if (hold.state !== state) {
      findings.push(
        finding(
          "error",
          "hold-state-cache",
          `${where}: records state "${hold.state}" but its transitions derive "${state}"; the stored state is a cache and may never disagree with the chain`,
        ),
      );
    }
    if (hold.projection_qualification !== QUALIFIED_STATUS) {
      findings.push(
        finding(
          "error",
          "hold-qualification",
          `${where}: projection_qualification is "${hold.projection_qualification}"; every hold qualifies its predecessors as ${QUALIFIED_STATUS}`,
        ),
      );
    }

    // --- the subject must resolve. A requirement explicitly withdrawn from
    // this checkout may instead bind the exact subject bytes at the commit
    // where its gated implementation was parked. This is not a discharge: it
    // qualifies no current predecessor and creates no current product claim.
    const subjectAbs = path.join(REPO_ROOT, hold.subject ?? "");
    if (!hold.subject || (!fs.existsSync(subjectAbs) && !resolvesAtParkedCommit(hold, state))) {
      findings.push(
        finding(
          "error",
          "hold-subject-unresolved",
          `${where}: subject does not resolve in this checkout: ${hold.subject ?? "(none)"}`,
        ),
      );
    }

    // --- predecessors must be real records
    for (const id of hold.predecessor_records ?? []) {
      if (!byId.has(id)) {
        findings.push(
          finding("error", "hold-predecessor-unknown", `${where}: names unknown predecessor record ${id}`),
        );
      }
    }

    // --- the subordinate successor graph, when the hold carries one.
    // A singular successor reference could not express a hold whose qualified
    // closures need several distinct proofs. The graph can; these rejections are
    // what stop it from being a decorative field.
    const graph = successorGraph(hold);
    if (graph) {
      const root = hold.required_successor?.work_item_id ?? null;
      if (graph.aggregate !== root) {
        findings.push(
          finding(
            "error",
            "hold-graph-root-mismatch",
            `${where}: successor_graph.aggregate is "${graph.aggregate}" but required_successor.work_item_id is "${root}". The graph's root and the hold's singular successor reference are the same thing and may never disagree.`,
          ),
        );
      }
      const aggregate = root ? byId.get(root) : null;
      if (!aggregate) {
        findings.push(
          finding("error", "hold-graph-aggregate-unknown", `${where}: names aggregate successor ${root ?? "(none)"}, which is not a record`),
        );
      } else if (aggregate.record_role !== "aggregate_exit") {
        findings.push(
          finding(
            "error",
            "hold-graph-aggregate-not-an-aggregate",
            `${where}: successor ${root} has record_role "${aggregate.record_role}"; a graph root joins children and must be an aggregate_exit`,
          ),
        );
      }
      const joined = new Set(aggregate?.aggregate_child_ids ?? []);
      for (const entry of graph.subordinate_proofs ?? []) {
        const id = entry?.work_item_id ?? null;
        if (!id || !byId.has(id)) {
          findings.push(
            finding("error", "hold-graph-subordinate-unknown", `${where}: subordinate proof ${id ?? "(unnamed)"} is not a record`),
          );
          continue;
        }
        if (aggregate && !joined.has(id)) {
          findings.push(
            finding(
              "error",
              "hold-graph-subordinate-unjoined",
              `${where}: names ${id} as a subordinate proof, but ${root} does not join it as a child. A graph asserted only in the ledger is not a graph the aggregate owns.`,
            ),
          );
        }
      }
      // A predecessor the AGGREGATE re-proves itself is coverage too, and the
      // aggregate must own the claim rather than have it asserted about it.
      // Expressing this as a subordinate would put an aggregate beneath the
      // aggregate, which is exactly what the owner refused.
      const directlyClaimed = new Set(aggregate?.directly_re_proves ?? []);
      for (const entry of graph?.[DIRECT_KEY] ?? []) {
        const predecessor = entry?.predecessor ?? null;
        if (!predecessor || !(hold.predecessor_records ?? []).includes(predecessor)) {
          findings.push(
            finding(
              "error",
              "hold-graph-direct-not-a-predecessor",
              `${where}: ${DIRECT_KEY} names ${predecessor ?? "(unnamed)"}, which this hold does not qualify. A graph may account for the closures the hold names and no others.`,
            ),
          );
          continue;
        }
        if (!entry.why) {
          findings.push(
            finding(
              "error",
              "hold-graph-direct-unexplained",
              `${where}: ${DIRECT_KEY} names ${predecessor} with no stated reason. Folding a predecessor into the aggregate is a scope decision and must argue itself.`,
            ),
          );
        }
        if (aggregate && !directlyClaimed.has(predecessor)) {
          findings.push(
            finding(
              "error",
              "hold-graph-direct-unclaimed",
              `${where}: the ledger says ${root} re-proves ${predecessor} directly, but ${root} does not declare it in directly_re_proves. A claim asserted only in the ledger is not a claim the aggregate owns.`,
            ),
          );
        }
      }

      // Every qualified predecessor must be accounted for exactly once: covered
      // by a named subordinate, or enumerated as outstanding. Silence is the
      // failure mode this closes.
      const { covered, outstanding } = graphCoverage(graph);
      for (const predecessor of hold.predecessor_records ?? []) {
        const isCovered = covered.has(predecessor);
        const isOutstanding = outstanding.has(predecessor);
        if (!isCovered && !isOutstanding) {
          findings.push(
            finding(
              "error",
              "hold-graph-predecessor-uncovered",
              `${where}: qualified closure ${predecessor} appears in neither subordinate_proofs nor outstanding_predecessors. A graph that omits a predecessor reports itself complete while a proof is missing.`,
            ),
          );
        } else if (isCovered && isOutstanding) {
          findings.push(
            finding(
              "error",
              "hold-graph-predecessor-uncovered",
              `${where}: qualified closure ${predecessor} is listed as both covered and outstanding; it is one or the other`,
            ),
          );
        }
      }
    }

    // --- proofs ordered under a hold whose successor is deliberately UNNAMED.
    // The point of the shape is that a partial proof may be recorded WITHOUT
    // being mistaken for the discharge target.
    const partials = partialSuccessors(hold);
    if (partials.length > 0) {
      if (hold.required_successor?.work_item_id) {
        findings.push(
          finding(
            "error",
            "hold-partial-with-named-successor",
            `${where}: carries ${PARTIAL_KEY} while required_successor.work_item_id names ${hold.required_successor.work_item_id}. Partial proofs are how a hold records work ordered under an UNNAMED successor; once a successor is named, they belong in its graph.`,
          ),
        );
      }
      if (!hold.required_successor?.successor_unnamed_because) {
        findings.push(
          finding(
            "error",
            "hold-partial-unexplained",
            `${where}: orders partial successors and states no successor_unnamed_because. A hold that records ordered work without saying why its successor is still unnamed reads as a discharge in progress.`,
          ),
        );
      }
      for (const entry of partials) {
        const id = entry?.work_item_id ?? null;
        if (!id || !byId.has(id)) {
          findings.push(
            finding("error", "hold-partial-unknown", `${where}: ${PARTIAL_KEY} names ${id ?? "(unnamed)"}, which is not a record`),
          );
          continue;
        }
        if (!(hold.predecessor_records ?? []).includes(entry?.re_proves_predecessor)) {
          findings.push(
            finding(
              "error",
              "hold-partial-not-a-predecessor",
              `${where}: ${id} is recorded as re-proving ${entry?.re_proves_predecessor ?? "(unnamed)"}, which this hold does not qualify`,
            ),
          );
        }
        if (!entry?.why) {
          findings.push(
            finding("error", "hold-partial-unexplained", `${where}: ${id} is ordered with no stated reason`),
          );
        }
      }
    }

    // --- a discharge must be an admitted successor, not an assertion
    if (state === "successor_admitted") {
      const successorId = hold.required_successor?.work_item_id ?? null;
      const successor = successorId ? byId.get(successorId) : null;
      if (!successor) {
        findings.push(
          finding(
            "error",
            "hold-discharge-unnamed",
            `${where} is discharged but names no existing successor record`,
          ),
        );
      } else if (statusOf(successor) !== "verified") {
        findings.push(
          finding(
            "error",
            "hold-discharge-unproven",
            `${where} is discharged by ${successorId}, which is ${statusOf(successor)}; a hold is closed by an admitted successor, never by a proposed one`,
          ),
        );
      }
      // A graph-rooted hold is discharged by the WHOLE graph. An aggregate that
      // reached verified while a subordinate is unproven, or while a qualified
      // predecessor is still outstanding, discharges nothing.
      if (graph) {
        for (const entry of graph.subordinate_proofs ?? []) {
          const sub = entry?.work_item_id ? byId.get(entry.work_item_id) : null;
          if (!sub || statusOf(sub) !== "verified") {
            findings.push(
              finding(
                "error",
                "hold-discharge-graph-incomplete",
                `${where} is discharged while subordinate proof ${entry?.work_item_id ?? "(unnamed)"} is ${sub ? statusOf(sub) : "absent"}; the aggregate closes the hold only when its whole subordinate graph is proven`,
              ),
            );
          }
        }
        if ((graph.outstanding_predecessors ?? []).length > 0) {
          findings.push(
            finding(
              "error",
              "hold-discharge-graph-incomplete",
              `${where} is discharged while ${graph.outstanding_predecessors.length} qualified predecessor(s) are still outstanding: ${graph.outstanding_predecessors.map((e) => e.predecessor).join(", ")}`,
            ),
          );
        }
      }
    }

    // --- an open hold is a failing bar, enumerated by name
    if (isOpen(hold)) {
      findings.push(
        finding(
          "error",
          "hold-open",
          `${where} is OPEN: ${hold.subject} (${hold.source?.kind}${
            hold.source?.acceptance_sequence
              ? `, acceptance sequence ${hold.source.acceptance_sequence}`
              : ""
          }); successor ${hold.required_successor?.work_item_id ?? "NOT YET NAMED"}; qualifies ${
            (hold.predecessor_records ?? []).length
          } predecessor closure(s) as ${QUALIFIED_STATUS}`,
          { hold_id: hold.hold_id, subject: hold.subject },
        ),
      );
    }
  });

  return findings;
}

// --- fail-closed self-test -------------------------------------------------
//
// Every rejection above is exercised against a synthetic bad ledger on every
// run. A bar whose rejections are never fired is a bar nobody can distinguish
// from an empty function.
const SELF_TEST_SOURCE_KEY = "withdrawn_verification:self-test-record";

// Set by selfTest(). A hand-typed rejection count is a claim nobody checks, and
// this one had already gone stale: it said 20 while the table carried 26.
let SELF_TEST_CASE_COUNT = 0;

function selfTest() {
  const findings = [];
  const baseHold = () => ({
    hold_id: "osh-0001",
    source_key: SELF_TEST_SOURCE_KEY,
    source: { kind: "withdrawn_verification", record: "internal-docs/implementation/README.md" },
    subject: "internal-docs/implementation/README.md",
    subject_kind: "work_item_record",
    predecessor_records: ["self-test-record"],
    required_successor: { work_item_id: null, requirement: "self test" },
    projection_qualification: QUALIFIED_STATUS,
    state: "open",
    state_transitions: [],
  });
  const required = [{
    source_key: SELF_TEST_SOURCE_KEY,
    predecessor_records: ["self-test-record"],
  }];
  const byId = new Map([
    ["self-test-record", { work_item_id: "self-test-record", status: "proposed" }],
    [
      "self-test-aggregate",
      {
        work_item_id: "self-test-aggregate",
        status: "proposed",
        record_role: "aggregate_exit",
        aggregate_child_ids: ["self-test-subordinate"],
        directly_re_proves: ["self-test-direct"],
      },
    ],
    ["self-test-subordinate", { work_item_id: "self-test-subordinate", status: "proposed", record_role: "implementation_cut" }],
    ["self-test-unjoined", { work_item_id: "self-test-unjoined", status: "proposed", record_role: "implementation_cut" }],
    ["self-test-direct", { work_item_id: "self-test-direct", status: "proposed", record_role: "implementation_cut" }],
  ]);
  const statusOf = (r) => r.status;
  const run = (mutate, extraRequired = required) => {
    const ledger = { ...emptyLedger(), holds: [baseHold()] };
    mutate(ledger);
    return evaluate({ ledger, required: extraRequired, byId, statusOf }).map((f) => f.check);
  };
  // A well-formed graph, used as the base every graph rejection mutates.
  const withGraph = (l, overrides = {}) => {
    l.holds[0].required_successor = {
      work_item_id: "self-test-aggregate",
      requirement: "self test",
      successor_graph: {
        aggregate: "self-test-aggregate",
        subordinate_proofs: [
          { work_item_id: "self-test-subordinate", re_proves_predecessor: "self-test-record" },
        ],
        outstanding_predecessors: [],
        ...overrides,
      },
    };
    return l;
  };

  const cases = [
    ["hold-missing", () => {}, [
      ...required,
      { source_key: "canon_acceptance:99:docs/nowhere.md", predecessor_records: [] },
    ]],
    ["hold-sequence", (l) => { l.holds[0].hold_id = "osh-0007"; }],
    ["hold-source-kind", (l) => { l.holds[0].source.kind = "vibes"; }],
    ["hold-unsourced", (l) => { l.holds[0].source_key = "withdrawn_verification:never-happened"; }],
    ["hold-state-cache", (l) => { l.holds[0].state = "successor_admitted"; }],
    ["hold-qualification", (l) => { l.holds[0].projection_qualification = "verified"; }],
    ["hold-subject-unresolved", (l) => { l.holds[0].subject = "does/not/exist.md"; }],
    ["hold-predecessor-unknown", (l) => { l.holds[0].predecessor_records = ["no-such-record"]; }],
    ["hold-predecessor-drift", (l) => { l.holds[0].predecessor_records = []; }],
    ["hold-discharge-unnamed", (l) => {
      l.holds[0].state = "successor_admitted";
      l.holds[0].state_transitions = [{ from: "open", to: "successor_admitted" }];
    }],
    ["hold-discharge-unproven", (l) => {
      l.holds[0].required_successor = { work_item_id: "self-test-record" };
      l.holds[0].state = "successor_admitted";
      l.holds[0].state_transitions = [{ from: "open", to: "successor_admitted" }];
    }],
    ["ledger-format", (l) => { l.evidence_format = "something.else.v1"; }],
    ["hold-open", () => {}],
    // --- subordinate successor graph
    ["hold-graph-root-mismatch", (l) => { withGraph(l, { aggregate: "someone-else" }); }],
    ["hold-graph-aggregate-unknown", (l) => {
      withGraph(l);
      l.holds[0].required_successor.work_item_id = "no-such-aggregate";
      l.holds[0].required_successor.successor_graph.aggregate = "no-such-aggregate";
    }],
    ["hold-graph-aggregate-not-an-aggregate", (l) => {
      withGraph(l);
      l.holds[0].required_successor.work_item_id = "self-test-subordinate";
      l.holds[0].required_successor.successor_graph.aggregate = "self-test-subordinate";
    }],
    ["hold-graph-subordinate-unknown", (l) => {
      withGraph(l, {
        subordinate_proofs: [{ work_item_id: "no-such-record", re_proves_predecessor: "self-test-record" }],
      });
    }],
    ["hold-graph-subordinate-unjoined", (l) => {
      withGraph(l, {
        subordinate_proofs: [{ work_item_id: "self-test-unjoined", re_proves_predecessor: "self-test-record" }],
      });
    }],
    // --- direct re-proof by the aggregate: no aggregate beneath the aggregate
    ["hold-graph-direct-not-a-predecessor", (l) => {
      withGraph(l, {
        directly_re_proven_by_aggregate: [{ predecessor: "self-test-direct", why: "x" }],
      });
    }],
    ["hold-graph-direct-unexplained", (l) => {
      l.holds[0].predecessor_records = ["self-test-record", "self-test-direct"];
      withGraph(l, {
        directly_re_proven_by_aggregate: [{ predecessor: "self-test-direct" }],
      });
    }, [{ source_key: SELF_TEST_SOURCE_KEY, predecessor_records: ["self-test-record", "self-test-direct"] }]],
    ["hold-graph-direct-unclaimed", (l) => {
      l.holds[0].predecessor_records = ["self-test-record", "self-test-subordinate"];
      withGraph(l, {
        directly_re_proven_by_aggregate: [{ predecessor: "self-test-subordinate", why: "x" }],
      });
    }, [{ source_key: SELF_TEST_SOURCE_KEY, predecessor_records: ["self-test-record", "self-test-subordinate"] }]],
    // --- partial successors ordered under a deliberately unnamed successor
    ["hold-partial-with-named-successor", (l) => {
      withGraph(l);
      l.holds[0].required_successor.partial_successors_ordered = [
        { work_item_id: "self-test-subordinate", re_proves_predecessor: "self-test-record", why: "x" },
      ];
      l.holds[0].required_successor.successor_unnamed_because = "x";
    }],
    ["hold-partial-unexplained", (l) => {
      l.holds[0].required_successor = {
        work_item_id: null,
        requirement: "self test",
        partial_successors_ordered: [
          { work_item_id: "self-test-subordinate", re_proves_predecessor: "self-test-record", why: "x" },
        ],
      };
    }],
    ["hold-partial-unknown", (l) => {
      l.holds[0].required_successor = {
        work_item_id: null,
        requirement: "self test",
        successor_unnamed_because: "x",
        partial_successors_ordered: [
          { work_item_id: "no-such-record", re_proves_predecessor: "self-test-record", why: "x" },
        ],
      };
    }],
    ["hold-partial-not-a-predecessor", (l) => {
      l.holds[0].required_successor = {
        work_item_id: null,
        requirement: "self test",
        successor_unnamed_because: "x",
        partial_successors_ordered: [
          { work_item_id: "self-test-subordinate", re_proves_predecessor: "self-test-direct", why: "x" },
        ],
      };
    }],
    ["hold-graph-predecessor-uncovered", (l) => {
      withGraph(l, { subordinate_proofs: [], outstanding_predecessors: [] });
    }],
    ["hold-discharge-graph-incomplete", (l) => {
      withGraph(l);
      l.holds[0].state = "successor_admitted";
      l.holds[0].state_transitions = [{ from: "open", to: "successor_admitted" }];
    }],
  ];

  SELF_TEST_CASE_COUNT = cases.length;

  for (const [expected, mutate, extraRequired] of cases) {
    const checks = run(mutate, extraRequired);
    if (!checks.includes(expected)) {
      findings.push(
        finding(
          "error",
          "self-test",
          `the ${expected} rejection did not fire against its synthetic bad input; this bar has lost its teeth (got: ${[...new Set(checks)].join(", ") || "nothing"})`,
        ),
      );
    }
  }

  // And the positive case: a discharged, well-formed, fully proven GRAPH
  // produces nothing. A bar that refuses the good case refuses nothing.
  const clean = (() => {
    const ledger = { ...emptyLedger(), holds: [baseHold()] };
    ledger.holds[0].required_successor = {
      work_item_id: "self-test-aggregate",
      successor_graph: {
        aggregate: "self-test-aggregate",
        subordinate_proofs: [
          { work_item_id: "self-test-subordinate", re_proves_predecessor: "self-test-record" },
        ],
        outstanding_predecessors: [],
      },
    };
    ledger.holds[0].state = "successor_admitted";
    ledger.holds[0].state_transitions = [{ from: "open", to: "successor_admitted" }];
    const verifiedById = new Map([
      ...byId,
      [
        "self-test-aggregate",
        {
          work_item_id: "self-test-aggregate",
          status: "verified",
          record_role: "aggregate_exit",
          aggregate_child_ids: ["self-test-subordinate"],
        },
      ],
      ["self-test-subordinate", { work_item_id: "self-test-subordinate", status: "verified", record_role: "implementation_cut" }],
    ]);
    return evaluate({ ledger, required, byId: verifiedById, statusOf });
  })();
  if (clean.length > 0) {
    findings.push(
      finding(
        "error",
        "self-test",
        `a well-formed, discharged hold was rejected: ${clean.map((f) => f.check).join(", ")}. A bar that refuses the good case refuses nothing meaningfully.`,
      ),
    );
  }
  return findings;
}

function main() {
  const seeding = process.argv.includes("--seed");
  const ledger = fs.existsSync(
      path.join(ESTATE_ROOT, "_archive", "holds", "open-successor-holds.v1.json"),
    )
    ? readHoldLedger()
    : emptyLedger();
  const required = requiredHolds();

  if (seeding) {
    const added = seed(ledger, required);
    writeHoldLedger(ledger);
    process.stdout.write(
      added.length === 0
        ? "no new hold to seed; every sourced disposition already holds\n"
        : `seeded ${added.length} hold(s): ${added.join(", ")}\n`,
    );
  }

  const byId = new Map(loadWorkItems().map((r) => [r.work_item_id, r]));
  const selfTestFindings = selfTest();
  const findings = [
    ...selfTestFindings,
    ...evaluate({
      ledger,
      required,
      byId,
      statusOf: (record) => statusAuthority(record).status,
    }),
  ];

  const holds = ledger.holds ?? [];
  const open = holds.filter(isOpen).length;
  const qualified = new Set(
    holds.filter(isOpen).flatMap((h) => h.predecessor_records ?? []),
  );
  progress(
    `open-successor holds: ${holds.length} recorded, ${open} open, ${qualified.size} record(s) projected as ${QUALIFIED_STATUS}; ${
      selfTestFindings.length === 0
        ? `${SELF_TEST_CASE_COUNT} predeclared rejections self-tested`
        : "SELF-TEST FAILING"
    }`,
  );

  process.exit(report("check-open-successor-holds", findings));
}

if (import.meta.url === `file://${process.argv[1]}`) main();
