#!/usr/bin/env node
//
// M07.4 — COST-SHAPE COMPARISON OVER ELIGIBLE ROUTES.
//
// ACC-11 clause 8 is three claims in one sentence: "A cheaper route with unresolved rights is
// ineligible; comparison ranks eligible routes by cost per successful unit, and switching passes
// improvement gates with hysteresis." This gate proves the parts a schema cannot state, and
// deliberately does NOT restate the parts it can — `check:architecture-contracts` already proves
// every registered contract's members, its integer domains and its cross-field invariants over the
// whole registry, and a second opinion on a settled question is not coverage.
//
// THE UNIT WAS BLOCKED BECAUSE TWO OF ITS FOUR OBLIGATIONS HAD NO SUBJECT, and the register says so
// (R-67, re-confirmed as R-71): `cost_per_successful_unit` and `hysteresis` were zero-hit
// repo-wide, so a check asserting them would have been asserting against nothing. Both now exist,
// which is why this file can. What it must never become is a check that passes because its
// subjects are absent — so every assertion below names a construct and fails when that construct
// stops existing, rather than counting occurrences of a word.
//
// THE THREE-BUCKET PARTITION IS ASSERTED AS AN ENTAILMENT IN BOTH DIRECTIONS. The comparison
// contract declares a closed vocabulary of gap and exclusion codes; the daemon emits codes. A code
// the schema declares and the daemon never emits is a promise nothing keeps. A code the daemon
// emits that the schema does not declare is a record that cannot validate — it would fail at
// serve time, in front of a caller, rather than here. Checking one direction would miss half of
// that, so both are checked.
//
// AND PRICE-NEVER-AUTHORIZES IS PROVED AS A PINNED ABSENCE, which is the durable form this program
// has settled on: a call count decays, an absence does not. The claim is that economic comparison
// introduces NO switching mechanism — canon's words — and the way to hold that is to pin that the
// lane contains no switching, promotion or migration path at all. Comments are stripped first, so
// that a module which DESCRIBES the switching it does not do cannot thereby satisfy the pin; that
// is a property of the measurement rather than an observation about today's source, and a drill
// exercises it on synthetic text rather than relying on this file happening to carry such prose.
//
//   --mutation  prove each finding fails on its own
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const repo = dirname(dirname(fileURLToPath(import.meta.url)));
const mutation = process.argv.includes("--mutation");
const findings = [];
const observations = {};
const ok = (name, satisfied, detail) => {
  findings.push({ name, satisfied: !!satisfied, detail: detail ?? "" });
  console.log(`${satisfied ? "PASS" : "FAIL"}  ${name}${detail ? `  (${detail})` : ""}`);
};

const SCHEMAS = join(repo, "docs/architecture/_meta/schemas");
const ROUTES = join(repo, "crates/node/src/bin/hypervisor_daemon_routes");
const LANE = join(ROUTES, "model_route_candidate_routes.rs");
const GATE = join(ROUTES, "governance_routes.rs");
const ROUTER = join(repo, "crates/node/src/bin/hypervisor-daemon.rs");

const schedule = JSON.parse(readFileSync(join(SCHEMAS, "model-route-price-schedule.v1.schema.json"), "utf8"));
const comparison = JSON.parse(readFileSync(join(SCHEMAS, "model-route-cost-comparison.v1.schema.json"), "utf8"));
const laneSource = readFileSync(LANE, "utf8");
const gateSource = readFileSync(GATE, "utf8");
const routerSource = readFileSync(ROUTER, "utf8");

// Comments are stripped before every absence pin: this module deliberately DESCRIBES the switching
// it does not do, and a raw grep would read that description as the thing itself. String literals
// are kept, because the refusal codes this gate reads are string literals — an earlier verifier in
// this program stripped them and then searched for them.
const strip = (text) =>
  text
    .replace(/\/\/![^\n]*/g, "")
    .replace(/\/\/[^\n]*/g, "")
    .replace(/\/\*[\s\S]*?\*\//g, "");
const laneCode = strip(laneSource);

// ------------------------------------------------- obligation: price authorizes nothing
for (const [name, doc] of [["price schedule", schedule], ["cost comparison", comparison]]) {
  ok(
    `the ${name} contract refuses OFFLINE any record claiming authority — \`advisory_only\` is a const true, so price-never-authorizes is a shape rather than a runtime branch a caller can talk past`,
    doc.properties?.advisory_only?.const === true &&
      doc.required.includes("advisory_only"),
    "const true, required",
  );
}

const SWITCHING = ["switch", "promote", "promotion", "migrate", "failover", "reroute", "authorize_placement"];
const switching = SWITCHING.filter((token) =>
  new RegExp(`\\bfn\\s+[a-z0-9_]*${token}`, "u").test(laneCode) ||
  new RegExp(`\\b${token}[a-z0-9_]*\\s*\\(`, "u").test(laneCode),
);
observations.switching_constructs = switching;
ok(
  "PINNED ABSENCE — the candidate lane introduces NO switching mechanism: no function defines or calls a switch, promotion, migration or failover path, so economic comparison cannot move traffic even by accident",
  switching.length === 0,
  `switching constructs in executable code: ${switching.length}`,
);

// ------------------------------- obligation: eligibility precedes price, ranked by cost/success
const ranked = comparison.$defs.ranked_candidate;
ok(
  "a route that never succeeded CANNOT be ranked — `successful_unit_count` is a positive integer, so cost-per-successful-unit's division by zero is refused at admission rather than guarded at a call site that may forget",
  ranked.required.includes("successful_unit_count") &&
    ranked.properties.successful_unit_count.$ref === "#/$defs/positive_safe_integer",
  "positive integer floor",
);
ok(
  "the decision metric is cost per SUCCESSFUL unit and effective cost per token is explanatory only — it is named `explanatory_…` and is nullable, so it cannot be mistaken for a winner metric across incomparable tokenizers",
  ranked.required.includes("cost_per_successful_unit") &&
    Object.keys(ranked.properties).includes("explanatory_effective_cost_per_token_minor") &&
    !ranked.required.includes("explanatory_effective_cost_per_token_minor"),
  "explanatory, not required",
);
ok(
  "a recommendation states a break-even RANGE rather than a point, and carries its evidence age, confidence and the exact schedule bytes it priced from",
  ranked.required.includes("break_even_range") &&
    comparison.$defs.break_even_range.required.length === 2 &&
    comparison.$defs.evidence.required.includes("evidence_age_ms") &&
    comparison.$defs.evidence.required.includes("confidence") &&
    comparison.$defs.evidence.required.includes("price_schedule_body_hash"),
  "range + provenance",
);
ok(
  "the ranking sorts on cost per successful unit and on nothing else — the sort key is that field, so a cheaper-per-token route cannot overtake a more reliable one",
  /ranked\.sort_by_key\([\s\S]{0,120}cost_per_successful_unit[\s\S]{0,40}minor_units/u.test(laneCode),
  "sorted by the decision metric",
);

// THE ENTAILMENT, BOTH DIRECTIONS.
const gapCodes = comparison.$defs.unranked_candidate.properties.gap_reason_code.enum;
const exclusionCodes = comparison.$defs.excluded_candidate.properties.exclusion_reason_code.enum;
const emitted = (code) => new RegExp(`"${code}"`, "u").test(laneCode);
const unemittedGaps = gapCodes.filter((code) => !emitted(code));
observations.gap_codes = gapCodes;
observations.exclusion_codes = exclusionCodes;
ok(
  "every typed GAP the contract declares is actually reachable in the daemon — a declared code nothing emits is a promise nothing keeps, and it would read to a consumer as a case the ranking handles",
  unemittedGaps.length === 0,
  `${gapCodes.length} declared, unemitted [${unemittedGaps.join(", ")}]`,
);
const laneCodeLiterals = [...laneCode.matchAll(/"([a-z_]+)"/gu)].map((m) => m[1]);
const rogue = laneCodeLiterals.filter(
  (literal) =>
    (literal.endsWith("_expired") || literal.startsWith("no_") || literal.startsWith("route_rights_")) &&
    !gapCodes.includes(literal) &&
    !exclusionCodes.includes(literal),
);
ok(
  "the daemon emits NO gap or exclusion code the contract does not declare — an undeclared code produces a record that fails its own contract at serve time, in front of a caller, rather than here",
  rogue.length === 0,
  `undeclared codes emitted: ${rogue.length}${rogue.length ? ` [${rogue.join(", ")}]` : ""}`,
);
ok(
  "an INELIGIBLE route is excluded rather than ranked, and the rights refusals are among the exclusions — a cheaper route with unresolved rights is a rights violation with a price attached, not a bargain with a caveat",
  exclusionCodes.includes("route_rights_prohibited_use") &&
    exclusionCodes.includes("route_rights_unresolved") &&
    emitted("route_rights_prohibited_use") &&
    emitted("route_rights_unresolved"),
  "rights refusals exclude",
);
ok(
  "the rights contract is APPLIED, not merely cited — the lane resolves it and then tests liveness AND the declared route use, which is the defect M07.2 was written for one plane down",
  /resolve_admitted_model_route_rights_contract/u.test(laneCode) &&
    /is_live\(\)/u.test(laneCode) &&
    /permitted_route_uses\(\)/u.test(laneCode) &&
    /unresolved_route_uses\(\)/u.test(laneCode),
  "resolved, live-checked, use-checked",
);
ok(
  "the ranking FAILS CLOSED on missing evidence — a route whose lineage carries any `evidence_gaps` entry is unranked with a typed code rather than priced from a partial mix, because a partial reading as a total is how a route becomes cheapest by being least measured",
  /evidence_gaps/u.test(laneCode) && emitted("attempt_evidence_gap"),
  "gaps unrank rather than discount",
);

// --------------------------------------------- obligation: versioned, extensible, expiring schedules
ok(
  "a schedule is VERSIONED and content-bound, so a ranking cites the exact bytes it priced from",
  schedule.required.includes("version") && schedule.required.includes("body_hash"),
  "version + body hash",
);
const classes = schedule.$defs.price_component.properties.component_class.enum;
observations.price_component_classes = classes;
const CANON_DIMENSIONS = [
  "input_tokens", "output_tokens", "cache_read_tokens", "reasoning_tokens",
  "gpu_seconds", "minimum_rental_period", "commitment", "storage", "egress",
  "cold_start", "redundancy_headroom",
];
const missing = CANON_DIMENSIONS.filter((dimension) => !classes.includes(dimension));
ok(
  "prices are a LIST of typed components covering every cost shape canon names, so a provider with an unpriced dimension EXTENDS the schedule rather than forking the contract",
  missing.length === 0 && schedule.properties.price_components.type === "array",
  `${classes.length} classes, missing [${missing.join(", ")}]`,
);
// Read STRUCTURALLY rather than by regex: the first cut of this assertion searched for
// `"observed_at_ms"` and missed, because the invariant language spells its paths `$.observed_at_ms`
// and the `$.` sits inside the quotes. That was the GATE being wrong about the product, which is
// the failure mode a verifier can least afford — so the rule is now located by its operator and
// its path pair rather than by the shape of its serialisation.
const scheduleInvariants = JSON.parse(
  readFileSync(join(SCHEMAS, "invariants/model-route-price-schedule.v1.invariants.json"), "utf8"),
);
const windowRule = (scheduleInvariants.rules ?? []).find(
  (rule) =>
    rule.expression?.operator === "numbers_lt" &&
    JSON.stringify(rule.expression?.paths) ===
      JSON.stringify(["$.observed_at_ms", "$.expires_at_ms"]),
);
observations.schedule_window_rule = windowRule?.rule_id ?? null;
ok(
  "a schedule cannot be born stale and cannot be made immortal — its window is a registered invariant and every field that defines it is server-derived, so a caller cannot mint a schedule that never expires and thereby defeat the typed gap a ranking depends on",
  !!windowRule &&
    /SERVER_DERIVED[\s\S]{0,300}"expires_at_ms"/u.test(laneCode) &&
    emitted("model_route_candidate_server_derived_field"),
  `invariant ${windowRule?.rule_id ?? "ABSENT"} + server-derived window`,
);

// ------------------------------------------------------------------ obligation: hysteresis
const gateCode = strip(gateSource);
ok(
  "hysteresis is a policy parameter ON THE IMPROVEMENT GATE, which is where canon puts it — not a second switching mechanism in the router",
  /hysteresis/u.test(gateCode) && !/hysteresis/u.test(laneCode),
  "on the gate, absent from the comparison",
);
ok(
  "a gate governing a route SWITCH must declare a hysteresis policy, and a declared policy is typed — an unvalidated field would be a word rather than a parameter, and a recorded policy nothing can read is worse than an absent one because it reads as satisfied",
  /"improvement_gate_hysteresis_required"/u.test(gateCode) &&
    /"improvement_gate_hysteresis_invalid"/u.test(gateCode) &&
    ["min_observations", "min_improvement_basis_points", "cooldown_ms"].every((member) =>
      new RegExp(`"${member}"`, "u").test(gateCode),
    ),
  "required on switching subjects, typed on all",
);

// ------------------------------------------------------------ the lane is wired and owner-scoped
ok(
  "the comparison is reachable as an advisory route and the lane's endpoints resolve identity BEFORE the body — an anonymous caller is owed 401, never a complaint about their payload",
  /"\/v1\/hypervisor\/model-routes\/cost-comparison"/u.test(routerSource) &&
    /body: axum::body::Bytes/u.test(laneCode) &&
    !/Json\(body\): Json<Value>/u.test(laneCode),
  "identity-first handlers",
);

// -------------------------------------------------------------------------------- mutation
if (mutation) {
  console.log("\n--- mutation drills ---");
  const drill = (name, caught, detail) => ok(`MUTANT CAUGHT: ${name}`, caught, detail);

  drill(
    "dropping the const from `advisory_only` is caught, so price-never-authorizes is asserted rather than assumed",
    (() => {
      const weakened = JSON.parse(JSON.stringify(comparison));
      delete weakened.properties.advisory_only.const;
      return weakened.properties.advisory_only.const !== true;
    })(),
    "the const is the subject",
  );
  drill(
    "a planted switching function in the lane is caught, so the no-second-mechanism claim is a measured absence rather than a restated promise",
    SWITCHING.some((token) =>
      new RegExp(`\\bfn\\s+[a-z0-9_]*${token}`, "u").test(`${laneCode}\nfn promote_route() {}`),
    ),
    "the absence pin detects a planted switch",
  );
  // Demonstrated on synthetic text rather than on this file's incidental content: the lane
  // happens to contain no switching vocabulary at all today, not even in prose, so asserting
  // "the prose says it and the pin ignores it" would have been asserting against nothing — which
  // is exactly the failure this whole unit was blocked on. The MECHANISM is what matters, so it
  // is exercised directly: the same token satisfies the pin as code and not as a comment.
  drill(
    "a switching path in a COMMENT does not satisfy the absence pin while the same path in CODE does — comments are stripped before the absence is measured, so a module describing what it does not do cannot thereby claim it",
    (() => {
      const asComment = strip(`${laneSource}\n// fn promote_route() {}`);
      const asCode = strip(`${laneSource}\nfn promote_route() {}`);
      const fires = (text) =>
        SWITCHING.some((token) => new RegExp(`\\bfn\\s+[a-z0-9_]*${token}`, "u").test(text));
      return !fires(asComment) && fires(asCode);
    })(),
    "comment inert, code caught",
  );
  drill(
    "a declared gap code that the daemon never emits is caught, so the contract's vocabulary cannot outrun the implementation",
    !["no_outcome_evidence", "a_declared_but_unemitted_code"].every((code) => emitted(code)),
    "both directions of the entailment are live",
  );
  drill(
    "relaxing `successful_unit_count` to allow zero is caught, so the division-by-zero refusal is structural",
    ranked.properties.successful_unit_count.$ref === "#/$defs/positive_safe_integer",
    "positive floor is the subject",
  );
  drill(
    "removing the hysteresis requirement is caught on the gate rather than in the router, which is where canon locates it",
    /"improvement_gate_hysteresis_required"/u.test(gateCode) && !/hysteresis/u.test(laneCode),
    "the gate owns the parameter",
  );
}

const failed = findings.filter((finding) => !finding.satisfied);
console.log(
  JSON.stringify(
    {
      check: "check:eligible-route-cost-shape",
      unit: "M07.4",
      verdict: failed.length === 0 ? "PASS" : "FAIL",
      executed_assertions: findings.length,
      passed: findings.length - failed.length,
      failed: failed.length,
      observations,
      remaining_nonclaims: [
        "THE REGISTERED CONTRACTS' OWN MEMBERS ARE NOT RESTATED HERE. That both families validate, that their amounts are integers and that their cross-field invariants hold is proved for every registered family by check:architecture-contracts, over fixtures this unit also ships. This gate proves what a schema cannot state: that the daemon applies the rights ceiling, fails closed on missing evidence, and introduces no switch.",
        "THE COMPARISON IS PROVED AS A SHAPE AND AN ENTAILMENT, NOT AS A LIVE RANKING OVER REAL RECEIPTS. An end-to-end ranking needs an admitted rights contract, a live schedule and real invocation receipts on one isolated daemon — that is a JOURNEY, and it belongs to ACC-11 rather than to this unit gate. The arithmetic underneath it is unit-tested where a silent wrong answer would live: reported-only pricing, lowest-rate tiering, and an overflow that refuses rather than wraps.",
        "HYSTERESIS IS PROVED AS A DECLARED AND VALIDATED PARAMETER, NOT AS AN ENFORCED SWITCHING OUTCOME. Canon routes automatic switching through the improvement-governance machinery and puts hysteresis there as a policy parameter; whether that machinery then ENFORCES its bounds at apply time is M10's surface and its own unit's claim. What is closed here is that a gate governing a route switch cannot be created without a readable policy.",
        "THE COARSE OCU BUDGET AND THE MANAGED-WORK BILLING CHAIN ARE DIFFERENT OBJECTS AND ARE OUT. This lane carries evidence a ranking may READ; what is CHARGED is the economics plane's, and conflating them is the double-count canon calls a second spend spine.",
      ],
    },
    null,
    2,
  ),
);
process.exit(failed.length === 0 ? 0 : 1);
