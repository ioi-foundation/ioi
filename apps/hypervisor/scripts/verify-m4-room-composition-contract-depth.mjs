#!/usr/bin/env node

// Successor contract-depth guard for ADR 0030. This verifier proves that the current room
// vocabulary composes through SystemScopedObjectBinding and does not retain the retired
// RoomAdmittedObjectBase admission/receipt spine. The architecture-contract bar performs the
// executable fixture validation; this guard checks the cross-family ownership shape that one
// schema in isolation cannot prove.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SCHEMAS = join(ROOT, "docs", "architecture", "_meta", "schemas");
const registry = JSON.parse(
  readFileSync(join(SCHEMAS, "architecture-contract-registry.v1.json"), "utf8"),
);
const contracts = new Map(
  registry.contracts.map((contract) => [contract.contract_id, contract]),
);

const results = [];
const EXPECTED_CHECKS = 22;
const check = (name, pass, detail = "") =>
  results.push({ name, pass: Boolean(pass), detail });
const readJson = (path) => JSON.parse(readFileSync(path, "utf8"));
const schemaFor = (contract) => readJson(join(SCHEMAS, contract.schema_ref));
const exactSet = (actual, expected) =>
  JSON.stringify([...(actual || [])].sort()) ===
  JSON.stringify([...expected].sort());
const sortJson = (value) => {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, sortJson(value[key])]),
  );
};
const canonical = (value) => JSON.stringify(sortJson(value));
const keysDeep = (value, found = new Set()) => {
  if (Array.isArray(value)) {
    for (const item of value) keysDeep(item, found);
  } else if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value)) {
      found.add(key);
      keysDeep(child, found);
    }
  }
  return found;
};

const bindingId = "schema://ioi/foundations/system-scoped-object-binding/v1";
const bindingContract = contracts.get(bindingId);
const bindingSchema = bindingContract && schemaFor(bindingContract);
const bindingFields = [
  "schema_version",
  "system_id",
  "parent_scope_ref",
  "proposed_or_issued_by_ref",
  "payload_root",
  "created_at",
  "updated_at",
];
const parallelSpineFields = [
  "room_admission",
  "expected_room_revision",
  "expected_predecessor_commitment_ref",
  "admission_policy_ref",
  "admission_decision_ref",
  "admission_receipt_ref",
  "admitted_sequence",
  "resulting_room_revision",
  "resulting_transition_commitment_ref",
  "resulting_room_state_root",
  "resulting_receipt_root",
];

check("binding-registered", bindingContract?.schema_version === "ioi.foundations.system-scoped-object-binding.v1");
check(
  "binding-exact-fields",
  bindingSchema &&
    exactSet(bindingSchema.required, bindingFields) &&
    exactSet(Object.keys(bindingSchema.properties || {}), bindingFields),
);
check(
  "binding-closed-shape",
  bindingSchema?.type === "object" && bindingSchema?.additionalProperties === false,
);
check(
  "binding-has-no-parallel-spine",
  bindingSchema && parallelSpineFields.every((field) => !keysDeep(bindingSchema).has(field)),
);
check(
  "binding-negative-parallel-field-fixture",
  bindingContract?.negative_fixture_refs?.some(
    (fixture) =>
      fixture.path ===
        "fixtures/system-scoped-object-binding-v1/negative-parallel-admission-field.json" &&
      fixture.expected_failure === "schema" &&
      existsSync(join(SCHEMAS, fixture.path)),
  ),
);

const familyNames = [
  "work-frontier-item",
  "work-claim-lease",
  "attempt",
  "finding",
  "verifier-challenge",
  "participant-state-bundle",
  "work-result",
  "outcome-delta",
];
const familyContracts = familyNames.map((name) =>
  contracts.get(
    `${familyNames.indexOf(name) < 6 ? "schema://ioi/applications/ioi-ai" : "schema://ioi/foundations"}/${name}/v3`,
  ),
);
const familySchemas = familyContracts.map((contract) => contract && schemaFor(contract));

check("all-v3-families-registered", familyContracts.every(Boolean));
check(
  "all-v3-schema-identities-exact",
  familyContracts.every(
    (contract, index) =>
      contract.schema_version ===
        `${index < 6 ? "ioi.applications.ioi-ai" : "ioi.foundations"}.${familyNames[index]}.v3` &&
      familySchemas[index]?.properties?.schema_version?.const === contract.schema_version,
  ),
);
check(
  "all-v3-families-require-system-binding-field",
  familySchemas.every((schema) => schema?.required?.includes("system_binding")),
);

const portableBinding = bindingSchema && {
  type: bindingSchema.type,
  additionalProperties: bindingSchema.additionalProperties,
  required: bindingSchema.required,
  properties: bindingSchema.properties,
};
check(
  "all-v3-families-embed-exact-binding",
  familySchemas.every(
    (schema) =>
      canonical(schema?.$defs?.systemBinding || {}) === canonical(portableBinding || {}),
  ),
);
check(
  "all-v3-families-omit-room-admission",
  familySchemas.every((schema) => !keysDeep(schema).has("room_admission")),
);
check(
  "all-v3-families-omit-parallel-evidence-fields",
  familySchemas.every((schema) =>
    parallelSpineFields.every((field) => !keysDeep(schema).has(field)),
  ),
);
check(
  "all-v3-families-have-no-live-predecessor",
  familyContracts.every(
    (contract) =>
      contract.evolution?.successor_of === null &&
      contract.evolution?.predecessor_remains_valid === false,
  ),
);
check(
  "all-v3-families-delete-v1-v2-contracts",
  familyNames.every(
    (name, index) =>
      ["v1", "v2"].every(
        (version) =>
          !contracts.has(
            `${index < 6 ? "schema://ioi/applications/ioi-ai" : "schema://ioi/foundations"}/${name}/${version}`,
          ) &&
          !contracts.has(`schema://ioi/foundations/${name}/${version}`),
      ),
  ),
);
check(
  "all-v3-positive-fixtures-retained",
  familyContracts.every(
    (contract) =>
      contract.positive_fixture_refs?.length > 0 &&
      contract.positive_fixture_refs.every((path) => existsSync(join(SCHEMAS, path))),
  ),
);
check(
  "all-v3-adversarial-fixtures-retained",
  familyContracts.every(
    (contract) =>
      contract.negative_fixture_refs?.length > 0 &&
      contract.negative_fixture_refs.every((fixture) =>
        existsSync(join(SCHEMAS, fixture.path)),
      ),
  ),
);
check(
  "room-admission-base-unregistered",
  !contracts.has("schema://ioi/foundations/room-admitted-object-base/v2"),
);

const roomContract = contracts.get("schema://ioi/applications/ioi-ai/outcome-room/v2");
const roomSchema = roomContract && schemaFor(roomContract);
check(
  "outcome-room-keeps-projection-roots-not-cas-spine",
  roomSchema?.required?.includes("room_state_root") &&
    roomSchema?.required?.includes("room_receipt_root") &&
    !roomSchema?.required?.includes("expected_room_revision") &&
    !roomSchema?.required?.includes("expected_predecessor_commitment_ref"),
);

const graph = schemaFor(
  contracts.get("schema://ioi/applications/ioi-ai/collaborative-work-graph/v1"),
);
check(
  "work-graph-is-derived-nonwritable",
  graph?.properties?.authoritative?.const === false &&
    graph?.properties?.client_writable?.const === false,
);
const discussion = schemaFor(
  contracts.get("schema://ioi/applications/ioi-ai/outcome-room-discussion-projection/v1"),
);
check(
  "discussion-is-derived-nonwritable",
  discussion?.properties?.authoritative?.const === false &&
    discussion?.properties?.client_writable?.const === false,
);

const expectedApplicationContracts = [
  "attempt/v3",
  "capability-offer/v3",
  "collaborative-work-graph/v1",
  "finding/v3",
  "goal-grounding-loop/v1",
  "goal-run-activation-receipt/v1",
  "goal-run-activation/v1",
  "goal-run-admission-path-decision/v1",
  "goal-run-admitted-state/v1",
  "goal-run-execution-ceiling/v1",
  "goal-run-profile-resolution-receipt/v1",
  "goal-run-profile/v1",
  "goal-run/v1",
  "outcome-room-discussion-projection/v1",
  "outcome-room/v2",
  "participant-state-bundle/v3",
  "resource-offer/v3",
  "room-participant-lease/v3",
  "room-participation-request/v3",
  "verifier-challenge/v3",
  "work-claim-lease/v3",
  "work-frontier-item/v3",
].map((tail) => `schema://ioi/applications/ioi-ai/${tail}`);
check(
  "ioi-ai-application-namespace-is-exact",
  exactSet(
    [...contracts.keys()].filter((id) =>
      id.startsWith("schema://ioi/applications/ioi-ai/"),
    ),
    expectedApplicationContracts,
  ),
);
check(
  "foundations-contain-no-ioi-ai-family-aliases",
  expectedApplicationContracts.every(
    (id) =>
      !contracts.has(
        id.replace("schema://ioi/applications/ioi-ai/", "schema://ioi/foundations/"),
      ),
  ),
);
const substrateVocabularyLeaks = [
  "goal_run_ref",
  "outcome_room_ref",
  "room_system_id",
  "work_claim_ref",
  "attempt_ref",
  "finding_refs",
  "challenge_refs",
];
const scmPublication = schemaFor(
  contracts.get("schema://ioi/components/connectors-tools/scm-publication-effect/v2"),
);
check(
  "substrate-contracts-use-generic-scope-origin-and-publication-vocabulary",
  [familySchemas[6], familySchemas[7]].every((schema) =>
    substrateVocabularyLeaks.every((field) => !keysDeep(schema).has(field)),
  ) &&
    scmPublication?.properties?.attempt?.required?.includes(
      "publication_attempt_ref",
    ) &&
    !keysDeep(scmPublication).has("attempt_ref"),
);

if (results.length !== EXPECTED_CHECKS) {
  console.error(`FAIL verifier-shape: ${results.length}/${EXPECTED_CHECKS} checks declared`);
  process.exit(1);
}
for (const result of results) {
  if (!result.pass) {
    console.error(`FAIL ${result.name}${result.detail ? ` — ${result.detail}` : ""}`);
    continue;
  }
  console.log(`PASS ${result.name}`);
}
const passed = results.filter((result) => result.pass).length;
if (passed !== EXPECTED_CHECKS) {
  console.error(`FAIL room composition contract depth: ${passed}/${EXPECTED_CHECKS} passed`);
  process.exit(1);
}
console.log(`${EXPECTED_CHECKS}/${EXPECTED_CHECKS} passed`);
console.log("M4 room composition contract depth: OK");
