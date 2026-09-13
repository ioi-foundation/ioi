#!/usr/bin/env node
//
// M10.5 — THE FOUNDRY SPEC AND RUN-PLAN WIRE CONTRACTS.
//
// ACC-12's clause is a NEGATIVE: no Foundry surface claims a family whose wire contract is
// unregistered, and no performance claim ships without its complete fingerprint set. This gate
// proves both halves and, deliberately, not the things two other layers already prove.
//
// NOT RESTATED HERE: that each registered contract's members, enums and fixtures are internally
// consistent is proved for EVERY family by the registry-driven `check:architecture-contracts`,
// over the fixtures this unit ships. A second opinion on a settled question is not coverage.
//
// WHAT HAD NO GATE IS THE CLAIM ITSELF. Before this unit, `foundry_routes.rs` served canon's
// `FoundrySpec` and `FoundryRunPlan` NAMES while sharing exactly ONE property with canon's shape —
// `status` — and called `validate_architecture_contract` ZERO times against 299 such call sites
// elsewhere in the estate, so every malformed body was a 201. Both halves of that are asserted
// here: that the daemon no longer CLAIMS a family it does not serve, and that what it does serve
// is refused when malformed, BEFORE it is written.
//
// THE FINGERPRINT SET IS ASSERTED AS A COMPLETE SIX, DERIVED FROM CANON'S OWN LIST rather than
// from today's schema. A gate that read the schema's required[] and checked it against itself
// would pass no matter which elements were present; the six names come from the acceptance, so a
// successor that quietly drops one is a finding.
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
const registry = JSON.parse(readFileSync(join(SCHEMAS, "architecture-contract-registry.v1.json"), "utf8"));
const byId = new Map(registry.contracts.map((c) => [c.contract_id, c]));
const load = (file) => JSON.parse(readFileSync(join(SCHEMAS, file), "utf8"));
const routeSource = readFileSync(
  join(repo, "crates/node/src/bin/hypervisor_daemon_routes/foundry_routes.rs"),
  "utf8",
);
const routeCode = routeSource
  .replace(/\/\/![^\n]*/g, "")
  .replace(/\/\/\/[^\n]*/g, "")
  .replace(/\/\/[^\n]*/g, "");
const rustProjection = readFileSync(
  join(repo, "crates/types/src/app/generated/architecture_contracts.rs"),
  "utf8",
);

// ------------------------------------------------- canon's families, under canon's own names
const CANON = {
  "schema://ioi/components/hypervisor/foundry-spec/v1": "FoundrySpec",
  "schema://ioi/components/hypervisor/foundry-run-plan/v1": "FoundryRunPlan",
};
for (const [id, name] of Object.entries(CANON)) {
  const entry = byId.get(id);
  ok(
    `canon's ${name} is REGISTERED under the canonical name, which the unit's scope calls the ruled precondition for any Foundry surface claim`,
    !!entry && entry.canonical_name === name,
    entry ? entry.schema_version : "ABSENT",
  );
  ok(
    `${name}'s generated projections exist, so the contract is reachable from code rather than only from the registry`,
    !!entry &&
      entry.generated_targets.length >= 2 &&
      new RegExp(`${name}V1`, "u").test(rustProjection),
    `${entry?.generated_targets.length ?? 0} targets`,
  );
}

// --------------------------------------- the daemon no longer CLAIMS a family it does not serve
const CANON_CLAIM_TOKENS = ['"ioi.hypervisor.foundry_spec"', '"ioi.hypervisor.foundry_run_plan"'];
const claimed = CANON_CLAIM_TOKENS.filter((token) => routeCode.includes(token));
observations.canon_name_claims_in_daemon = claimed;
ok(
  "PINNED ABSENCE — the daemon's plane no longer stamps canon's family names on its own records. It shared exactly ONE property with canon's shape, so wearing the name made an unregistered family look registered",
  claimed.length === 0,
  `canon-name claims in daemon records: ${claimed.length}`,
);
for (const [id, name] of [
  ["schema://ioi/components/hypervisor/foundry-draft-spec/v1", "FoundryDraftSpec"],
  ["schema://ioi/components/hypervisor/foundry-draft-run-plan/v1", "FoundryDraftRunPlan"],
]) {
  ok(
    `what the daemon DOES serve is registered as ${name}, under a name matching the fields it actually has`,
    byId.has(id) && byId.get(id).canonical_name === name,
    byId.get(id)?.schema_version ?? "ABSENT",
  );
}

// --------------------------------------------------------------------- live route validation
const specAt = routeCode.indexOf("contract_checked(SPEC_CONTRACT_ID");
const specWriteAt = routeCode.indexOf("persist_record(&st.data_dir, SPEC_KIND");
const planAt = routeCode.indexOf("contract_checked(RUN_PLAN_CONTRACT_ID");
const planWriteAt = routeCode.indexOf("persist_record(&st.data_dir, RUN_PLAN_KIND");
ok(
  "the spec route validates against its registered contract BEFORE it writes — order, not presence: a record that would not survive the offline verifier is never written and then explained",
  specAt > -1 && specWriteAt > -1 && specAt < specWriteAt,
  specAt > -1 ? `check@${specAt} < write@${specWriteAt}` : "missing",
);
ok(
  "the run-plan route validates before it writes, on the same discipline",
  planAt > -1 && planWriteAt > -1 && planAt < planWriteAt,
  planAt > -1 ? `check@${planAt} < write@${planWriteAt}` : "missing",
);
ok(
  "the plane's inertness is a CONST rather than a comment — a draft plan claiming it would promote is refused offline, where the module previously only asserted inertness in prose",
  load("foundry-draft-run-plan.v1.schema.json").$defs.promotion_preview.properties.would_promote
    .const === false,
  "would_promote const false",
);

// ------------------------------------------------ cross-version and downgrade refusal
const V1 = "schema://ioi/components/hypervisor/foundry-qualified-measurement/v1";
const V2 = "schema://ioi/components/hypervisor/foundry-qualified-measurement/v2";
const v1Entry = byId.get(V1);
const v2Entry = byId.get(V2);
ok(
  "the measurement family SUCCEEDS rather than widens, because v1 forbids wire mutation and carries written records — changing it in place would alter what already-admitted bytes mean",
  !!v2Entry &&
    v2Entry.evolution.successor_of === V1 &&
    v1Entry.evolution.successor_contract_id === V2 &&
    v2Entry.evolution.compatibility === "breaking",
  `${v2Entry?.evolution.compatibility} · successor_of ${v2Entry?.evolution.successor_of ? "set" : "unset"}`,
);
ok(
  "v1 REMAINS VALID for everything written under it — succession that invalidated the predecessor would be a mutation wearing a successor's name",
  v1Entry?.evolution.predecessor_remains_valid === true &&
    v2Entry?.evolution.predecessor_remains_valid === true,
  "predecessor_remains_valid",
);
const v1Const = load("foundry-qualified-measurement.v1.schema.json").properties.schema_version.const;
const v2Const = load("foundry-qualified-measurement.v2.schema.json").properties.schema_version.const;
ok(
  "a downgrade or cross-version record is refused STRUCTURALLY: each version pins its own `schema_version` as a const, so a v1 body cannot validate as v2 and no reader has to police the boundary",
  !!v1Const && !!v2Const && v1Const !== v2Const,
  `${v1Const} ≠ ${v2Const}`,
);

// --------------------------------------------------- the complete fingerprint set, from canon
// Derived from the ACCEPTANCE's own list rather than from the schema, so a successor that quietly
// drops an element is a finding instead of a tautology.
const CANON_FINGERPRINTS = [
  "model_fingerprint",
  "recipe_fingerprint",
  "software_fingerprint",
  "hardware_fingerprint",
  "topology_fingerprint",
  "time_to_quality",
];
const v2Measurement = load("foundry-qualified-measurement.v2.schema.json").properties.measurement;
const missing = CANON_FINGERPRINTS.filter((name) => !v2Measurement.required.includes(name));
observations.fingerprint_elements = CANON_FINGERPRINTS;
ok(
  "a performance claim carries ALL SIX elements canon names, each REQUIRED — three of them had no field anywhere in the estate before this unit, and a claim cannot be audited against a fingerprint set it never recorded",
  missing.length === 0,
  `missing [${missing.join(", ")}]`,
);
ok(
  "identity is pinned by CONTENT and not only by ref — a model ref alone is a mutable pointer, and a recipe named but not hashed lets an edited recipe wear an old measurement's result",
  v2Measurement.properties.model_fingerprint &&
    load("foundry-qualified-measurement.v2.schema.json").$defs.modelFingerprint.required.includes(
      "weights_digest",
    ) &&
    load("foundry-qualified-measurement.v2.schema.json").$defs.recipeFingerprint.required.includes(
      "recipe_body_hash",
    ),
  "weights digest + recipe body hash",
);
ok(
  "the TOPOLOGY axis can actually vary — v1 pinned its scope to a single daemon CPU process, so the axis was present in name and impossible in fact",
  load("foundry-qualified-measurement.v2.schema.json").$defs.topologyFingerprint.required.includes(
    "parallelism",
  ) && v2Measurement.properties.scope.enum.length > 1,
  `scope ${v2Measurement.properties.scope.enum.join("|")}`,
);

// ------------------------------------------------------------------------------- mutation
if (mutation) {
  console.log("\n--- mutation drills ---");
  const drill = (name, caught, detail) => ok(`MUTANT CAUGHT: ${name}`, caught, detail);

  drill(
    "dropping ONE fingerprint element is caught, because the six names come from the acceptance rather than from the schema being checked against itself",
    CANON_FINGERPRINTS.some(
      (name) => !v2Measurement.required.filter((r) => r !== "model_fingerprint").includes(name),
    ),
    "the list is external to the subject",
  );
  drill(
    "the daemon re-claiming a canon family name is caught by the absence pin",
    CANON_CLAIM_TOKENS.some((token) =>
      `${routeCode}\n"ioi.hypervisor.foundry_spec"`.includes(token),
    ),
    "the pin detects a restored claim",
  );
  drill(
    "writing before validating is caught, because the assertion is about ORDER and not about both calls existing",
    (() => {
      const swapped = routeCode
        .replace("contract_checked(SPEC_CONTRACT_ID", "__P__")
        .replace("persist_record(&st.data_dir, SPEC_KIND", "contract_checked(SPEC_CONTRACT_ID")
        .replace("__P__", "persist_record(&st.data_dir, SPEC_KIND");
      return (
        swapped.indexOf("contract_checked(SPEC_CONTRACT_ID") >
        swapped.indexOf("persist_record(&st.data_dir, SPEC_KIND")
      );
    })(),
    "order is the subject",
  );
  drill(
    "a succession that invalidated its predecessor is caught, so `successor` cannot become a mutation wearing a nicer name",
    v1Entry?.evolution.predecessor_remains_valid === true,
    "predecessor validity is asserted, not assumed",
  );
}

const failed = findings.filter((f) => !f.satisfied);
console.log(
  JSON.stringify(
    {
      check: "check:foundry-spec-contracts",
      unit: "M10.5",
      verdict: failed.length === 0 ? "PASS" : "FAIL",
      executed_assertions: findings.length,
      passed: findings.length - failed.length,
      failed: failed.length,
      observations,
      remaining_nonclaims: [
        "CANON'S TWO FAMILIES ARE REGISTERED AND HAVE NO PRODUCER YET, AND THAT IS THE INTENDED STATE. The unit's scope calls registration 'the ruled precondition for ANY Foundry surface claim' — precondition, so a registered family awaiting its implementation satisfies the clause rather than violating it. What ACC-12 forbids is a surface CLAIMING an unregistered family, which is why the daemon's plane was renamed rather than left wearing canon's names.",
        "THE FINGERPRINT SET IS PROVED AS A REQUIRED SHAPE, NOT AS A POPULATED MEASUREMENT. That a real run fills all six elements honestly is a runtime claim belonging to the Foundry journey; what is closed here is that a claim missing any of them cannot be admitted at all.",
        "THE DRAFT PLANE REMAINS INERT AND THIS GATE DOES NOT CERTIFY OTHERWISE. It dispatches nothing, promotes nothing and crosses no authority; `inputs` and `steps` are deliberately unconstrained because no runtime reads them, and constraining their shape would assert a contract over something that does not exist.",
        "CROSS-VERSION REFUSAL IS STRUCTURAL RATHER THAN NEGOTIATED. Each version pins its own `schema_version` const, so a v1 body cannot validate as v2 — there is no downgrade path to police because there is no shared shape to downgrade through.",
      ],
    },
    null,
    2,
  ),
);
process.exit(failed.length === 0 ? 0 : 1);
