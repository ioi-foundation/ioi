#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import {
  failWith,
  implementationRoot,
  readJson,
  repoRoot,
  sha256,
  sha256File,
  stableJson,
  STATUS_VALUES,
} from "./lib.mjs";
import { contentBoundLiteralEvidence } from "./content-bound-literal.mjs";
import { validateWorkItemMigrationFinalization } from "./check-work-item-migration-finalization.mjs";

const workItemsRoot = path.join(implementationRoot, "work-items");
const files = fs.readdirSync(workItemsRoot).filter((name) => name.endsWith(".v1.json")).sort();
const errors = [];
const notices = [];
const records = new Map();
// §4.1 owns the planning payload below. Machine-wrapper compatibility fields
// are checked separately and do not amend or compete with the sole sequencer.
const masterRequiredStrings = [
  "work_item_id", "stage_id", "record_role", "status",
  "objective", "falsifiable_claim", "selected_profile",
  "current_implementation_evidence", "adversarial_or_fault_proof",
  "rollback_or_stop_rule", "source_provenance",
];
const masterRequiredArrays = [
  "canon_owners", "contract_families", "private_artifacts",
  "dependency_work_item_ids", "aggregate_child_ids",
  "aggregate_child_dispositions",
  "in_scope", "out_of_scope", "implementation_actions",
  "consequential_effects_and_final_invokers", "applicable_pg_ids",
  "positive_proof", "product_journey_and_states",
  "ordered_product_operator_journey",
  "metrics_and_frozen_thresholds", "compatibility_and_migration",
  "code_anchors", "evidence_refs", "remaining_nonclaims",
];
const wrapperRequiredStrings = ["evidence_format", "last_status_transaction"];
const wrapperRequiredArrays = ["required_work", "exit_criteria", "pg_gate_states"];
const roles = new Set(["implementation_cut", "aggregate_exit", "private_verifier", "conditional_future"]);
const codeAnchorPresentWhenValues = new Set(["merged", "pr_open", "current_precedent", "planned"]);
const codeAnchorRequiredInCheckout = new Set(["merged", "current_precedent"]);
const pgApplicability = new Set(["required_now", "conditional", "later", "out_of_scope"]);
const pgClosureStatuses = new Set(["open", "evidence_ready", "closed", "not_applicable"]);
const pgProfileSelections = new Set(["selected", "not_selected", "deferred", "not_applicable"]);
const canonicalTextCache = new Map();
const registry = readJson(path.join(repoRoot, "docs/architecture/_meta/schemas/architecture-contract-registry.v1.json"));
const registeredNames = new Set(registry.contracts.flatMap((entry) => [entry.contract_id, entry.canonical_name]));
const registeredByName = new Map();
for (const contract of registry.contracts) {
  const entries = registeredByName.get(contract.canonical_name) ?? [];
  entries.push(contract);
  registeredByName.set(contract.canonical_name, entries);
}
const contractRouting = readJson(path.join(implementationRoot, "tools/contract-owner-locators.v1.json"));
const aliasNames = new Set(Object.keys(contractRouting.aliases));
const rejectedGenericNames = new Set(Object.keys(contractRouting.rejected_generic_candidates));
const privateArtifactNames = new Set(Object.keys(contractRouting.private_artifacts));
const pendingContractNames = new Set(Object.keys(contractRouting.pending_contract_definitions));
const preservationLedger = readJson(path.join(
  implementationRoot,
  "audits/reconciliation/work-item-status-preservation.v1.json",
));
const preExistingStatuses = new Map(
  preservationLedger.before.map((entry) => [entry.work_item_id, entry.status]),
);
const baselineRoot = path.join(implementationRoot, "_archive/pre-unification-baseline/work-items");
const mechanismGateRegistryPath = path.join(implementationRoot, "proof-gates/mechanism-gate-registry.md");
const mechanismGateRegistry = fs.readFileSync(mechanismGateRegistryPath, "utf8");
const knownPgIds = new Set([...mechanismGateRegistry.matchAll(/^\| (PG-[^ |]+) \|/gmu)].map((match) => match[1]));
const approvedExternalGateOwners = new Map(Object.entries({
  "applicable-pg-profile-gates": "proof-gates/mechanism-gate-registry.md",
  "commercial-legal-assurance-demand-approval": "docs/architecture/foundations/ecosystem-assurance-certification-liability.md",
  "selected-decentralized-profile": "ioi-target-end-state-master-implementation-guide.md",
  "later-explicit-sequencer-amendment": "ioi-target-end-state-master-implementation-guide.md",
  "conditional-embodied-registration": "ioi-target-end-state-master-implementation-guide.md",
  "independent-operation-preregistration": "docs/architecture/foundations/aiip.md",
  "selected-managed-authority-overlay": "ioi-target-end-state-master-implementation-guide.md",
}));

const REQUIRED_ORDERED_JOURNEYS = {
  "m1-system-genesis-product-journey": ["review_package", "preview_genesis", "admit_genesis", "initialize", "activate", "inspect_receipt", "recover_or_dissolve"],
  "project-discovery-startup-and-session-chain": ["discover_project", "select_candidate", "resolve_recipe", "preview_startup", "launch_environment", "open_session", "stop_and_cleanup"],
  "m3-work-session-automation-product-journey": ["create_or_select_work", "open_session", "admit_worker_and_tools", "execute", "inspect_result", "cancel_or_retry", "replay_and_export"],
  "m6-home-workspace-operational-journey": ["open_home", "inspect_empty_or_active", "start_or_resume", "approve_or_deny", "inspect_receipt", "recover"],
  "m6-systems-workspace-operational-journey": ["list_systems", "open_system_detail", "propose_transition", "approve_or_deny_transition", "inspect_topology_and_receipt", "recover_or_dissolve"],
  "m6-projects-workspace-operational-journey": ["discover", "select_candidate", "create", "start", "fail_or_deny", "cleanup"],
  "m6-applications-workspace-operational-journey": ["open_catalog", "search_or_filter", "inspect_detail", "open_application", "unavailable_or_denied", "resolve_alias_and_return"],
  "m6-work-workspace-operational-journey": ["list_work", "inspect_detail", "cancel_or_archive", "recover", "verify_proof"],
  "m6-automations-operational-journey": ["create", "edit", "run", "pause_or_resume", "cancel", "recover", "monitor"],
  "m6-packages-operational-journey": ["browse", "inspect", "admit", "install", "publish", "rollback_or_recall", "portable_export"],
  "m6-developer-workspace-operational-journey": ["open_repository", "open_session_or_work", "edit", "run", "cancel", "recover", "inspect_result_and_receipt"],
  "sdk-cli-adk-odk-builder-journey": ["discover_contract", "scaffold", "validate", "preview", "invoke_through_owner", "inspect_receipt", "upgrade_or_rollback"],
  "m7-studio-operational-journey": ["design", "validate", "simulate", "propose", "owner_handoff", "inspect_receipt"],
  "m7-ontology-operational-journey": ["define", "version", "map", "act", "dispute", "migrate"],
  "m7-data-operational-journey": ["register_source", "test", "sync", "transform", "replay", "recover", "egress"],
  "m8-evaluations-operational-journey": ["define", "freeze_epoch", "execute", "judge", "challenge", "reverify", "export"],
  "m8-improvement-operational-journey": ["propose", "simulate", "evaluate", "owner_approve_or_reject", "canary", "rollback_or_recall", "export"],
  "m8-foundry-operational-journey": ["register", "plan_run", "execute_run", "evaluate", "propose_promotion", "owner_promote_or_reject", "rollback_or_provider_exit"],
  "m9-governance-operational-journey": ["review", "approve_or_reject", "revoke", "enforce", "appeal", "export"],
  "m9-provenance-operational-journey": ["open_timeline", "inspect_lineage", "verify", "export", "replay", "recover"],
  "m9-developer-console-operational-journey": ["register", "authorize", "test", "probe", "revoke", "recover"],
  "m9-environments-operational-journey": ["create", "launch", "verify_readiness", "operate", "backup", "restore", "stop", "delete", "cleanup"],
  "m9-sovereign-local-terminal-journey": ["bootstrap_local", "create_or_import_system", "run_local_work", "inspect_receipts", "restart_and_replay", "backup_export_restore", "disconnect_and_continue"],
  "m10-operations-operational-journey": ["observe", "promote_or_fence", "rejoin", "declare_incident", "recover", "verify_rpo_rto", "export"],
  "m11-foundry-promotion-safety-case-and-product-journey": ["register_candidate", "compile_profile", "simulate", "run_sil", "run_hil", "run_shadow", "review_safety_case", "promote_nonlive_or_rollback"],
  "m11-embodied-systems-nonlive-operational-journey": ["register", "compile", "simulate", "run_sil", "run_hil", "run_shadow", "rollback"],
  "m12-federation-product-and-operator-journey": ["discovery", "terms", "counter_or_decline", "admission", "dispute", "portable_exit"],
  "m13-two-sovereign-surplus-and-decline-proof": ["preregister", "freeze_outside_options_costs_risks_and_benefits", "negotiate_or_decline", "perform_useful_work", "verify_and_accept", "dispute_or_revoke", "portable_exit", "safe_decline_control"],
  "m13-independent-operation-and-external-worker-product-proof": ["discover_worker", "negotiate", "admit_lease", "perform_work", "contribute", "verify_and_accept", "revoke_or_retire", "portable_exit", "repeat_and_independence_audit"],
  "m14-service-family-owner-contract-and-product-surfaces": ["service_registry", "order", "delivery", "acceptance", "payment_or_dispute", "suspension", "exit"],
  "connected-worker-capability-supply-and-hiring": ["discover_capability", "negotiate_terms", "hire_or_decline", "admit_lease", "deliver", "accept_or_dispute", "revoke_or_retire", "portable_exit"],
};

const REQUIRED_GENERIC_METRIC_THRESHOLDS = {
  "generic.unauthorized_final_invoker_calls": 0,
  "generic.duplicate_or_status_inferred_effects": 0,
  "generic.unresolved_required_owner_dependency_mappings": 0,
  "generic.exact_retained_successful_literal_exit_lines": 1,
};

const GENERIC_HONEST_STATE_OVERLAY = [
  "loading_or_pending",
  "honest_empty",
  "ready_or_proposed",
  "denied_or_revoked",
  "unavailable_or_degraded",
  "stale_conflict_or_ambiguous",
  "recovery_or_rollback",
  "completed",
];

const REQUIRED_STAGE_METRIC_THRESHOLDS = {
  M0: { "m0.unowned_or_second_sequencer_facts": 0 },
  M1: { "m1.unauthorized_or_duplicate_genesis_effects": 0 },
  M2: { "m2.simultaneous_effective_writers_per_system": "<=1" },
  M3: { "m3.direct_path_substitution_failures": 0 },
  M4: { "m4.direct_client_shared_graph_writes": 0 },
  M5: { "m5.accepted_participant_effects_without_current_lease": 0 },
  M6: { "m6.consequential_controls_without_owner_authority_receipt_disposition": 0 },
  M7: { "m7.semantic_effects_with_unknown_or_mutable_version": 0 },
  M8: { "m8.self_promotion_or_mutable_evaluation_effects": 0 },
  M9: { "m9.fixture_or_projection_substituted_terminal_successes": 0 },
  M10: {
    "m10.dual_effective_writer_intervals": 0,
    "m10.unfrozen_rpo_rto_trials": 0,
  },
  M11: {
    "m11.live_actuator_calls": 0,
    "m11.accepted_distributed_effects_without_single_writer_proof": 0,
  },
  M12: {
    "m12.foreign_direct_truth_or_authority_mutations": 0,
    "m12.required_federation_journey_transition_coverage": "100_percent",
  },
  M13: {
    "m13.outside_option_coverage": "100_percent_of_required_parties",
    "m13.declared_cost_coverage": "100_percent_of_required_parties",
    "m13.declared_risk_coverage": "100_percent_of_required_parties",
    "m13.contracted_benefit_coverage": "100_percent_of_required_parties",
    "m13.positive_surplus_floor": "positive_for_every_required_party_and_sponsor_above_outside_option",
    "m13.repeat_useful_work_floor": ">=2",
    "m13.independence_violations": 0,
    "m13.subsidy_disclosure_and_baseline_coverage": "100_percent_of_trial_subsidy_and_eligible_baselines",
    "m13.safe_decline_control": ">=1",
  },
  M14: {
    "m14.unrelated_external_organizations": ">=3",
    "m14.public_service_families": ">=2",
    "m14.sustained_declared_period": "one_nonzero_preregistered_sustained_period",
    "m14.willingness_to_pay_or_bear_risk": "100_percent_of_counted_demand",
    "m14.independent_service_supply": "100_percent_of_selected_service_families",
    "m14.attack_cost_and_security_budget_coverage": ">=100_percent_of_budget",
    "m14.frozen_safety_margin": ">0",
    "m14.zero_appreciation_viability": "value_persists_at_appreciation=0",
    "m14.no_l1_compatible_alternative": "no_l1_remains_valid_until_l1_strictly_beats_compatible_alternative",
  },
  FUTURE: { "future.effects_before_explicit_amendment": 0 },
};

const CONDITIONAL_AGGREGATE_CHILD_RULES = [
  {
    aggregate_id: "m9-selected-profile-aggregate-exit-and-claim-publication",
    child_id: "m9-managed-optionality-overlay",
    activation_gate_id: "selected-managed-authority-overlay",
    selection_state: "conditional_not_selected",
  },
  {
    aggregate_id: "m11-selected-profile-exit-proof",
    child_id: "m11-embodied-systems-nonlive-operational-journey",
    activation_gate_id: "conditional-embodied-registration",
    selection_state: "conditional_not_selected",
  },
  {
    aggregate_id: "m14-selected-profile-aggregate-exit",
    child_id: "decentralized-profile-admission-and-exit",
    activation_gate_id: "selected-decentralized-profile",
    selection_state: "conditional_not_selected",
  },
];

const FUTURE_SEMANTIC_OVERRIDES = {
  "m11-canonical-contract-registry-and-legacy-ref-migration": {
    profile_terms: ["canonical-contract", "reference-migration", "outside the active M0–M14 path"],
    effect_terms: ["canonical contract registration", "read-old/write-new"],
    forbidden_terms: ["live physical actuator effect", "native LocalControlSupervisor/controller final invoker"],
  },
  "m14-cross-plane-correlated-failure-injection": {
    profile_terms: ["correlated-failure", "optional M14 services", "outside the active M0–M14 path"],
    effect_terms: ["fault injection", "isolated fault harness"],
    forbidden_terms: ["live physical actuator effect", "native LocalControlSupervisor/controller final invoker"],
  },
};

function externalGateOwnerPath(owner) {
  return owner?.startsWith("docs/") ? path.join(repoRoot, owner) : path.join(implementationRoot, owner ?? "");
}

function canonText(file) {
  if (!canonicalTextCache.has(file)) canonicalTextCache.set(file, fs.readFileSync(path.join(repoRoot, file), "utf8"));
  return canonicalTextCache.get(file);
}

function canonicalCandidate(name) {
  let current = name;
  const seen = new Set();
  while (contractRouting.aliases[current] !== undefined) {
    if (seen.has(current)) throw new Error(`contract alias cycle at ${current}`);
    seen.add(current);
    current = contractRouting.aliases[current];
  }
  return current;
}

function wholeToken(source, value) {
  const escaped = value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
  return new RegExp(`(^|[^A-Za-z0-9_])${escaped}([^A-Za-z0-9_]|$)`, "mu").test(source);
}

function sorted(values) {
  return [...values].sort((left, right) => left.localeCompare(right));
}

function recognizedIncompleteCheckout(record) {
  return record?.status === "verified"
    && record.evidence_index?.historical_status_preserved === true
    && record.evidence_index?.checkout_validation === "legacy_status_unavailable_in_this_checkout";
}

function codeAnchorSkip(record, anchor, reason) {
  return {
    result: "SKIP",
    check: "work-item-checkout-code-anchor",
    work_item_id: record.work_item_id,
    ref: anchor.path,
    must_contain: anchor.must_contain ?? null,
    present_when: anchor.present_when,
    reason,
    nonclaim: "This SKIP preserves only the pre-existing historical status. The unavailable checkout anchor or token is not implementation or evidence proof, changes no status, and closes no work item or stage.",
  };
}

function inspectCodeAnchor(record, anchor, io = {}) {
  const existsSync = io.existsSync ?? fs.existsSync;
  const readFileSync = io.readFileSync ?? fs.readFileSync;
  const result = { errors: [], notices: [] };
  const label = record?.work_item_id ?? "unknown-work-item";
  if (!anchor || typeof anchor !== "object") {
    result.errors.push(`${label}: malformed code anchor`);
    return result;
  }
  if (typeof anchor.path !== "string" || anchor.path.trim() === "") {
    result.errors.push(`${label}: malformed code anchor path`);
    return result;
  }
  if (!codeAnchorPresentWhenValues.has(anchor.present_when)) {
    result.errors.push(`${label}: malformed code anchor present_when ${anchor.present_when ?? "missing"}`);
    return result;
  }
  if (
    Object.prototype.hasOwnProperty.call(anchor, "must_contain")
    && (typeof anchor.must_contain !== "string" || anchor.must_contain.trim() === "")
  ) {
    result.errors.push(`${label}: code anchor ${anchor.path} has a malformed must_contain token`);
    return result;
  }
  const absolute = path.resolve(repoRoot, anchor.path);
  const relative = path.relative(repoRoot, absolute);
  if (path.isAbsolute(anchor.path) || relative === ".." || relative.startsWith(`..${path.sep}`)) {
    result.errors.push(`${label}: code anchor path escapes the repository: ${anchor.path}`);
    return result;
  }
  const requiredNow = codeAnchorRequiredInCheckout.has(anchor.present_when);
  if (!existsSync(absolute)) {
    if (requiredNow) {
      if (recognizedIncompleteCheckout(record)) {
        result.notices.push(codeAnchorSkip(
          record,
          anchor,
          `${anchor.present_when} code anchor is unavailable in this recognized incomplete checkout`,
        ));
      } else {
        result.errors.push(`${label}: required ${anchor.present_when} code anchor is missing: ${anchor.path}`);
      }
    }
    return result;
  }
  if (anchor.must_contain === undefined) return result;
  let content;
  try {
    content = readFileSync(absolute, "utf8");
  } catch (error) {
    result.errors.push(`${label}: cannot read code anchor ${anchor.path}: ${error.message}`);
    return result;
  }
  if (content.includes(anchor.must_contain)) return result;
  if (requiredNow && recognizedIncompleteCheckout(record)) {
    result.notices.push(codeAnchorSkip(
      record,
      anchor,
      `${anchor.present_when} code anchor token is unavailable in this recognized incomplete checkout`,
    ));
  } else {
    result.errors.push(`${label}: code anchor ${anchor.path} does not contain exact token ${JSON.stringify(anchor.must_contain)}`);
  }
  return result;
}

function runCodeAnchorSelfTests() {
  const currentRecord = {
    work_item_id: "self-test-current",
    status: "proposed",
    evidence_index: {
      historical_status_preserved: false,
      checkout_validation: "not_applicable_until_evidence_ready",
    },
  };
  const legacyRecord = {
    work_item_id: "self-test-legacy",
    status: "verified",
    evidence_index: {
      historical_status_preserved: true,
      checkout_validation: "legacy_status_unavailable_in_this_checkout",
    },
  };
  const anchor = {
    path: "self-test/code-anchor.txt",
    must_contain: "required-token",
    present_when: "merged",
  };
  const cases = [
    {
      name: "exact token passes",
      inspected: inspectCodeAnchor(currentRecord, anchor, {
        existsSync: () => true,
        readFileSync: () => "prefix required-token suffix",
      }),
      errors: 0,
      notices: 0,
    },
    {
      name: "missing token fails current anchor",
      inspected: inspectCodeAnchor(currentRecord, anchor, {
        existsSync: () => true,
        readFileSync: () => "prefix different-token suffix",
      }),
      errors: 1,
      notices: 0,
    },
    {
      name: "missing current target fails",
      inspected: inspectCodeAnchor(currentRecord, anchor, { existsSync: () => false }),
      errors: 1,
      notices: 0,
    },
    {
      name: "legacy token mismatch is explicit nonclaim SKIP",
      inspected: inspectCodeAnchor(legacyRecord, anchor, {
        existsSync: () => true,
        readFileSync: () => "older checkout content",
      }),
      errors: 0,
      notices: 1,
    },
    {
      name: "legacy missing target is explicit nonclaim SKIP",
      inspected: inspectCodeAnchor(legacyRecord, anchor, { existsSync: () => false }),
      errors: 0,
      notices: 1,
    },
    {
      name: "not-yet-present PR anchor is not a current claim",
      inspected: inspectCodeAnchor(currentRecord, { ...anchor, present_when: "pr_open" }, { existsSync: () => false }),
      errors: 0,
      notices: 0,
    },
    {
      name: "empty must_contain fails shape validation",
      inspected: inspectCodeAnchor(currentRecord, { ...anchor, must_contain: "" }, { existsSync: () => true }),
      errors: 1,
      notices: 0,
    },
    {
      name: "repository escape fails before I/O",
      inspected: inspectCodeAnchor(currentRecord, { ...anchor, path: "../outside" }, { existsSync: () => true }),
      errors: 1,
      notices: 0,
    },
  ];
  const failures = [];
  for (const testCase of cases) {
    if (testCase.inspected.errors.length !== testCase.errors) {
      failures.push(`${testCase.name}: expected ${testCase.errors} error(s), found ${testCase.inspected.errors.length}`);
    }
    if (testCase.inspected.notices.length !== testCase.notices) {
      failures.push(`${testCase.name}: expected ${testCase.notices} notice(s), found ${testCase.inspected.notices.length}`);
    }
    for (const notice of testCase.inspected.notices) {
      if (notice.result !== "SKIP" || !notice.nonclaim.includes("not implementation or evidence proof")) {
        failures.push(`${testCase.name}: checkout exception is not an explicit SKIP nonclaim`);
      }
    }
  }
  failWith("work-item code-anchor self-test", failures);
  process.stdout.write(`work-item code-anchor self-test passed: ${cases.length} positive, negative, boundary, and explicit-SKIP cases\n`);
}

if (process.argv.includes("--self-test-code-anchors")) {
  runCodeAnchorSelfTests();
  process.exit(0);
}

function stageRank(stageId) {
  return stageId === "FUTURE" ? 15 : Number(stageId.slice(1));
}

function actionPlanApplicationOwnerIds() {
  const actionPlan = fs.readFileSync(
    path.join(implementationRoot, "audits/2026-07-22-directory-unification-plan.md"),
    "utf8",
  );
  const start = actionPlan.indexOf("| Proposed application owner ID / stage");
  const end = actionPlan.indexOf("Each stage aggregate must join", start);
  if (start < 0 || end < 0) throw new Error("action-plan application-owner table is missing");
  return [...actionPlan.slice(start, end).matchAll(/^\| `([^`]+)` \/ M\d+(?: conditional)? \|/gmu)]
    .map((match) => match[1]);
}

const actionPlanOwnerIds = actionPlanApplicationOwnerIds();
for (const workItemId of actionPlanOwnerIds) {
  if (!REQUIRED_ORDERED_JOURNEYS[workItemId]) {
    errors.push(`${workItemId}: action-plan application owner has no checker-owned ordered journey mapping`);
  }
}

function evidenceBindingForRecord(record) {
  const expectedLiteral = record.evidence_index?.literal_exit ?? null;
  const evidenceFiles = [...new Set(record.evidence_refs ?? [])].sort().map((ref) => {
    const absolute = path.join(repoRoot, ref);
    const exists = fs.existsSync(absolute);
    return {
      path: ref,
      exists,
      sha256: exists ? sha256File(absolute) : null,
      exact_literal_line_count: exists && expectedLiteral
        ? Number(contentBoundLiteralEvidence(ref, expectedLiteral))
        : 0,
    };
  });
  const body = {
    expected_literal: expectedLiteral,
    evidence_files: evidenceFiles,
    exact_literal_line_count: evidenceFiles.reduce((total, file) => total + file.exact_literal_line_count, 0),
  };
  return {
    ...body,
    literal_valid: body.exact_literal_line_count === 1,
    evidence_bundle_sha256: sha256(stableJson(body)),
  };
}

function gateLiteralValid(gate) {
  if (gate?.closure_status !== "closed" || typeof gate.literal_exit !== "string") return false;
  const count = (gate.evidence_refs ?? []).reduce(
    (total, ref) => total + Number(contentBoundLiteralEvidence(ref, gate.literal_exit)),
    0,
  );
  return count === 1;
}

for (const [contractName, ownerPath] of Object.entries(contractRouting.canonical_owners)) {
  const absolute = path.join(repoRoot, ownerPath);
  if (!fs.existsSync(absolute)) errors.push(`reviewed contract locator ${contractName} has missing owner ${ownerPath}`);
  else if (!wholeToken(canonText(ownerPath), contractName)) errors.push(`reviewed contract locator ${contractName} is absent from ${ownerPath}`);
}
for (const [contractName, ownerPaths] of Object.entries(contractRouting.semantic_owner_paths)) {
  if (!Array.isArray(ownerPaths) || ownerPaths.length === 0) errors.push(`semantic owner routing for ${contractName} must be a nonempty array`);
  for (const ownerPath of ownerPaths ?? []) if (!fs.existsSync(path.join(repoRoot, ownerPath))) errors.push(`semantic owner routing for ${contractName} has missing owner ${ownerPath}`);
}

for (const name of files) {
  const file = path.join(workItemsRoot, name);
  let record;
  try {
    record = readJson(file);
  } catch (error) {
    errors.push(`${name}: invalid JSON: ${error.message}`);
    continue;
  }
  records.set(record.work_item_id, record);
  if (name !== `${record.work_item_id}.v1.json`) errors.push(`${name}: filename does not match work_item_id`);
  for (const field of [...masterRequiredStrings, ...wrapperRequiredStrings]) {
    if (typeof record[field] !== "string" || record[field].trim() === "") errors.push(`${name}: missing nonempty ${field}`);
  }
  for (const field of [...masterRequiredArrays, ...wrapperRequiredArrays]) {
    if (!Array.isArray(record[field])) errors.push(`${name}: ${field} must be an array`);
  }
  if (record.evidence_format !== "ioi.program.work_item.v1") errors.push(`${name}: unknown evidence_format`);
  if (!STATUS_VALUES.has(record.status)) errors.push(`${name}: unknown status ${record.status}`);
  if (!roles.has(record.record_role)) errors.push(`${name}: unknown record_role ${record.record_role}`);
  if (!/^(?:M(?:[0-9]|1[0-4])|FUTURE)$/u.test(record.stage_id ?? "")) errors.push(`${name}: malformed stage_id ${record.stage_id}`);
  if (record.stage_id === "FUTURE" && record.record_role !== "conditional_future") errors.push(`${name}: FUTURE requires conditional_future role`);
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(record.last_status_transaction ?? "")) errors.push(`${name}: last_status_transaction must be an ISO date`);
  if (!(Number.isInteger(record.pr) || record.pr === null)) errors.push(`${name}: pr must be integer or null`);
  if (record.external_gates !== undefined && !Array.isArray(record.external_gates)) errors.push(`${name}: optional external_gates must be an array`);
  const seenExternalGates = new Set();
  for (const gate of record.external_gates ?? []) {
    if (!gate || typeof gate !== "object") {
      errors.push(`${name}: external_gates entries must be objects`);
      continue;
    }
    if (typeof gate.gate_id !== "string" || !/^[a-z0-9]+(?:-[a-z0-9]+)*$/u.test(gate.gate_id)) {
      errors.push(`${name}: malformed external gate_id ${gate.gate_id ?? "missing"}`);
      continue;
    }
    if (seenExternalGates.has(gate.gate_id)) errors.push(`${name}: duplicate external gate_id ${gate.gate_id}`);
    seenExternalGates.add(gate.gate_id);
    const expectedOwner = approvedExternalGateOwners.get(gate.gate_id);
    if (expectedOwner === undefined) errors.push(`${name}: unapproved external gate ${gate.gate_id}`);
    else if (gate.owner !== expectedOwner) errors.push(`${name}: external gate ${gate.gate_id} must use approved owner ${expectedOwner}`);
    if (typeof gate.owner !== "string" || !fs.existsSync(externalGateOwnerPath(gate.owner))) {
      errors.push(`${name}: external gate ${gate.gate_id} has missing owner ${gate.owner ?? "missing"}`);
    }
    if (typeof gate.activation_condition !== "string" || gate.activation_condition.trim().length < 20) {
      errors.push(`${name}: external gate ${gate.gate_id} lacks a substantive activation_condition`);
    }
  }
  if (!record.canon_snapshot || !Array.isArray(record.canon_snapshot.owners) || !/^[a-f0-9]{64}$/u.test(record.canon_snapshot.aggregate_sha256 ?? "")) errors.push(`${name}: invalid canon_snapshot`);

  const owners = new Set(record.canon_owners ?? []);
  for (const owner of owners) {
    const absolute = path.join(repoRoot, owner);
    if (!owner.startsWith("docs/architecture/") && !owner.startsWith("docs/decisions/")) errors.push(`${name}: non-canonical owner path ${owner}`);
    if (!fs.existsSync(absolute)) errors.push(`${name}: missing canon owner ${owner}`);
  }
  for (const snapshot of record.canon_snapshot?.owners ?? []) {
    if (!owners.has(snapshot.path)) errors.push(`${name}: snapshot owner is not declared: ${snapshot.path}`);
    const absolute = path.join(repoRoot, snapshot.path ?? "");
    if (fs.existsSync(absolute) && sha256File(absolute) !== snapshot.sha256) errors.push(`${name}: stale canon owner digest ${snapshot.path}`);
  }

  for (const family of record.contract_families ?? []) {
    if (!family || typeof family !== "object" || typeof family.name !== "string" || typeof family.owner_path !== "string") {
      errors.push(`${name}: contract_families entries require name and owner_path`);
      continue;
    }
    if (aliasNames.has(family.name)) errors.push(`${name}: alias ${family.name} must be canonicalized before entering contract_families`);
    if (rejectedGenericNames.has(family.name)) errors.push(`${name}: rejected generic ${family.name} cannot enter contract_families`);
    if (privateArtifactNames.has(family.name)) errors.push(`${name}: private artifact ${family.name} cannot enter contract_families`);
    if (pendingContractNames.has(family.name)) errors.push(`${name}: pending definition ${family.name} cannot enter contract_families`);
    if (!owners.has(family.owner_path)) errors.push(`${name}: contract ${family.name} owner is not in canon_owners`);
    if (!Array.isArray(family.semantic_owner_paths)) errors.push(`${name}: contract ${family.name} semantic_owner_paths must be an array`);
    for (const semanticOwner of family.semantic_owner_paths ?? []) {
      if (!owners.has(semanticOwner)) errors.push(`${name}: contract ${family.name} semantic owner ${semanticOwner} is not in canon_owners`);
    }
    const expectedSemanticOwners = contractRouting.semantic_owner_paths[family.name] ?? [];
    if (JSON.stringify(family.semantic_owner_paths) !== JSON.stringify(expectedSemanticOwners)) errors.push(`${name}: ${family.name} semantic-owner paths differ from reviewed routing`);
    if (family.classification !== "canonical_contract") errors.push(`${name}: ${family.name} is not classified canonical_contract`);
    const registered = registeredByName.get(family.name) ?? [];
    if (registered.length > 0) {
      const ownerRefs = [...new Set(registered.map((entry) => entry.canonical_owner_ref))];
      const ownerPaths = [...new Set(ownerRefs.map((ref) => ref.replace(/^canon:\/\//u, "").split("#", 1)[0]))];
      if (ownerPaths.length !== 1 || family.owner_path !== ownerPaths[0]) errors.push(`${name}: registered contract ${family.name} must use canonical owner ${ownerPaths.join("|")}, found ${family.owner_path}`);
      if (family.canonical_owner_ref !== ownerRefs[0]) errors.push(`${name}: registered contract ${family.name} has stale/missing canonical_owner_ref`);
      const expectedIds = registered.map((entry) => entry.contract_id).sort();
      const expectedVersions = registered.map((entry) => entry.schema_version).sort();
      if (JSON.stringify(family.contract_ids) !== JSON.stringify(expectedIds)) errors.push(`${name}: registered contract ${family.name} has incomplete contract_ids`);
      if (JSON.stringify(family.schema_versions) !== JSON.stringify(expectedVersions)) errors.push(`${name}: registered contract ${family.name} has incomplete schema_versions`);
      if (family.registry_resolution !== "architecture_contract_registry") errors.push(`${name}: registered contract ${family.name} must resolve through the architecture registry`);
      if (family.owner_role !== "registry_canonical_owner") errors.push(`${name}: registered contract ${family.name} must mark registry_canonical_owner`);
    } else {
      const reviewedOwner = contractRouting.canonical_owners[family.name];
      if (!reviewedOwner) errors.push(`${name}: unregistered canonical object ${family.name} has no reviewed owner locator`);
      if (family.owner_path !== reviewedOwner) errors.push(`${name}: unregistered canonical object ${family.name} must use reviewed shape owner ${reviewedOwner}`);
      if (family.registry_resolution !== "reviewed_owner_locator") errors.push(`${name}: unregistered canonical object ${family.name} must declare reviewed_owner_locator resolution`);
      if (family.owner_role !== "reviewed_shape_owner") errors.push(`${name}: unregistered canonical object ${family.name} must mark reviewed_shape_owner`);
      if (reviewedOwner && fs.existsSync(path.join(repoRoot, reviewedOwner)) && !wholeToken(canonText(reviewedOwner), family.name)) {
        errors.push(`${name}: reviewed shape owner ${reviewedOwner} lacks exact identifier ${family.name}`);
      }
      if (family.canonical_owner_ref !== null || JSON.stringify(family.contract_ids) !== "[]" || JSON.stringify(family.schema_versions) !== "[]") errors.push(`${name}: unregistered canonical object ${family.name} must not invent registry identity`);
    }
  }

  const configuredAllowlist = contractRouting.work_item_contract_allowlists[record.work_item_id];
  if (configuredAllowlist !== undefined) {
    const expectedCanonicalNames = configuredAllowlist
      .map(canonicalCandidate)
      .filter((candidate) => registeredByName.has(candidate) || contractRouting.canonical_owners[candidate]);
    const actualCanonicalNames = (record.contract_families ?? []).map((family) => family.name);
    if (JSON.stringify(sorted(actualCanonicalNames)) !== JSON.stringify(sorted(expectedCanonicalNames))) {
      errors.push(`${name}: contract_families do not equal the reviewed per-record allowlist`);
    }
    const expectedPending = configuredAllowlist
      .map(canonicalCandidate)
      .filter((candidate) => pendingContractNames.has(candidate) || rejectedGenericNames.has(candidate));
    const actualPending = (record.private_artifacts ?? [])
      .filter((artifact) => artifact?.artifact_class === "private_pending_contract_definition_gap")
      .map((artifact) => artifact.candidate_name);
    for (const candidate of expectedPending) {
      if (!actualPending.includes(candidate)) errors.push(`${name}: missing pending contract-definition artifact for ${candidate}`);
    }
  }
  for (const artifact of record.private_artifacts ?? []) {
    if (!artifact?.artifact_id || !artifact?.artifact_class || artifact.product_authority !== false || artifact.architecture_canon !== false) errors.push(`${name}: malformed private artifact classification`);
    if (artifact?.artifact_class === "private_pending_contract_definition_gap") {
      const expected = contractRouting.pending_contract_definitions[artifact.candidate_name];
      if (!artifact.candidate_name || !artifact.decision_owner || !artifact.required_exit || !artifact.reason) errors.push(`${name}: pending contract artifact lacks candidate/decision/exit/reason metadata`);
      if (!/^[A-Z][A-Z0-9_]*_EXIT=0$/u.test(artifact.required_exit ?? "")) errors.push(`${name}: pending contract artifact has malformed required_exit`);
      if (!fs.existsSync(path.join(repoRoot, artifact.decision_owner ?? ""))) errors.push(`${name}: pending contract artifact has missing decision_owner ${artifact.decision_owner}`);
      if (expected && (artifact.decision_owner !== expected.decision_owner || artifact.required_exit !== expected.required_exit || artifact.reason !== expected.reason)) errors.push(`${name}: pending contract artifact ${artifact.candidate_name} differs from reviewed routing`);
    }
    if (artifact?.artifact_id?.startsWith("private-artifact:")) {
      if (artifact.artifact_class !== contractRouting.private_artifacts[artifact.candidate_name]) errors.push(`${name}: private artifact ${artifact.candidate_name} differs from reviewed classification`);
    }
  }
  for (const effect of record.consequential_effects_and_final_invokers ?? []) {
    for (const field of ["effect", "final_invoker", "authority_source", "receipt_or_evidence", "negative_behavior"]) {
      if (typeof effect?.[field] !== "string" || effect[field].trim() === "") errors.push(`${name}: effect entry lacks ${field}`);
    }
    if (/unsigned hash chain/iu.test(effect.authority_source ?? "")) errors.push(`${name}: workflow evidence is used as product authority`);
  }
  if (record.stage_id === "FUTURE") {
    const semanticOverride = FUTURE_SEMANTIC_OVERRIDES[record.work_item_id];
    const effectText = JSON.stringify(record.consequential_effects_and_final_invokers ?? []);
    if (semanticOverride) {
      for (const term of semanticOverride.profile_terms) {
        if (!record.selected_profile.includes(term)) errors.push(`${name}: FUTURE selected profile omits objective-specific term ${term}`);
      }
      for (const term of semanticOverride.effect_terms) {
        if (!effectText.includes(term)) errors.push(`${name}: FUTURE effect/final-invoker family omits objective-specific term ${term}`);
      }
      for (const term of semanticOverride.forbidden_terms) {
        if (`${record.selected_profile}\n${effectText}`.includes(term)) errors.push(`${name}: FUTURE objective is contradicted by unrelated effect/profile term ${term}`);
      }
    }
    const explicitlyPhysical = record.work_item_id === "live-embodied-promotion";
    if (!explicitlyPhysical && /live physical actuator effect|native LocalControlSupervisor\/controller final invoker/iu.test(`${record.selected_profile}\n${effectText}`)) {
      errors.push(`${name}: non-physical FUTURE objective inherited the generic live-embodied effect family`);
    }
  }
  const overlayStates = (record.product_journey_and_states ?? []).map((entry) => entry?.state);
  if (JSON.stringify(overlayStates) !== JSON.stringify(GENERIC_HONEST_STATE_OVERLAY)) {
    errors.push(`${name}: generic honest-state overlay is incomplete, reordered, or genericized`);
  }
  for (const state of record.product_journey_and_states ?? []) {
    if (typeof state?.required_behavior !== "string" || state.required_behavior.trim().length < 20) {
      errors.push(`${name}: honest-state ${state?.state ?? "missing"} lacks substantive required behavior`);
    }
  }
  const expectedJourney = REQUIRED_ORDERED_JOURNEYS[record.work_item_id];
  const actualJourney = record.ordered_product_operator_journey ?? [];
  if (expectedJourney) {
    const actualTransitionIds = actualJourney.map((transition) => transition?.transition_id);
    if (JSON.stringify(actualTransitionIds) !== JSON.stringify(expectedJourney)) {
      errors.push(`${name}: ordered product/operator journey differs from its reviewed record-specific transitions`);
    }
    for (let index = 0; index < actualJourney.length; index += 1) {
      const transition = actualJourney[index];
      if (transition?.order !== index + 1) errors.push(`${name}: ordered journey transition ${transition?.transition_id ?? index} has wrong order`);
      for (const field of ["required_behavior", "advancement_evidence", "negative_behavior"]) {
        if (typeof transition?.[field] !== "string" || transition[field].trim().length < 40) {
          errors.push(`${name}: ordered journey transition ${transition?.transition_id ?? index} lacks substantive ${field}`);
        }
      }
    }
  } else if (actualJourney.length > 0) {
    errors.push(`${name}: ordered journey exists without a checker-owned record-specific mapping`);
  }
  const seenMetricIds = new Set();
  for (const metric of record.metrics_and_frozen_thresholds ?? []) {
    if (!metric?.metric_id || !/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/u.test(metric.metric_id) || !metric?.metric || metric.threshold === undefined || !metric?.unit || !metric?.threshold_source || metric.frozen_before_observation !== true) errors.push(`${name}: malformed or unfrozen metric`);
    if (seenMetricIds.has(metric?.metric_id)) errors.push(`${name}: duplicate frozen metric ${metric?.metric_id}`);
    seenMetricIds.add(metric?.metric_id);
  }
  const metricById = new Map((record.metrics_and_frozen_thresholds ?? []).map((metric) => [metric.metric_id, metric]));
  for (const [metricId, threshold] of Object.entries(REQUIRED_GENERIC_METRIC_THRESHOLDS)) {
    const metric = metricById.get(metricId);
    if (!metric || JSON.stringify(metric.threshold) !== JSON.stringify(threshold)) errors.push(`${name}: missing or changed generic frozen metric floor ${metricId}`);
  }
  for (const [metricId, threshold] of Object.entries(REQUIRED_STAGE_METRIC_THRESHOLDS[record.stage_id] ?? {})) {
    const metric = metricById.get(metricId);
    if (!metric || JSON.stringify(metric.threshold) !== JSON.stringify(threshold)) errors.push(`${name}: missing or changed ${record.stage_id} frozen metric floor ${metricId}`);
  }
  if (expectedJourney) {
    const journeyMetricId = `journey.${record.work_item_id}.ordered_transition_coverage`;
    const metric = metricById.get(journeyMetricId);
    if (!metric || metric.threshold !== "100_percent_in_declared_order" || metric.unit !== `${expectedJourney.length} declared transitions`) {
      errors.push(`${name}: ordered journey lacks its record-specific frozen coverage floor`);
    }
  }
  const declaredPgIds = record.applicable_pg_ids ?? [];
  if (declaredPgIds.some((pgId) => typeof pgId !== "string" || !knownPgIds.has(pgId))) errors.push(`${name}: applicable_pg_ids contains an unknown/non-string gate`);
  if (new Set(declaredPgIds).size !== declaredPgIds.length) errors.push(`${name}: duplicate applicable_pg_ids`);
  const pgStates = record.pg_gate_states ?? [];
  const stateIds = pgStates.map((entry) => entry?.pg_id);
  if (JSON.stringify([...declaredPgIds].sort()) !== JSON.stringify([...stateIds].sort())) errors.push(`${name}: pg_gate_states must cover exactly applicable_pg_ids`);
  if (new Set(stateIds).size !== stateIds.length) errors.push(`${name}: duplicate pg_gate_states`);
  for (const gate of pgStates) {
    if (!knownPgIds.has(gate?.pg_id)) errors.push(`${name}: unknown pg_gate_state ${gate?.pg_id}`);
    if (!pgApplicability.has(gate?.applicability)) errors.push(`${name}: ${gate?.pg_id} has unknown applicability ${gate?.applicability}`);
    if (!pgProfileSelections.has(gate?.profile_selection)) errors.push(`${name}: ${gate?.pg_id} has unknown profile_selection ${gate?.profile_selection}`);
    if (!/^(?:M(?:[0-9]|1[0-4])|FUTURE)$/u.test(gate?.closure_stage_id ?? "")) errors.push(`${name}: ${gate?.pg_id} has malformed closure_stage_id ${gate?.closure_stage_id}`);
    if (!pgClosureStatuses.has(gate?.closure_status)) errors.push(`${name}: ${gate?.pg_id} has unknown closure_status ${gate?.closure_status}`);
    if (!Array.isArray(gate?.evidence_refs)) errors.push(`${name}: ${gate?.pg_id} evidence_refs must be an array`);
    if (typeof gate?.status_basis !== "string" || gate.status_basis.trim() === "") errors.push(`${name}: ${gate?.pg_id} requires a status_basis`);
    if (gate?.closure_status === "closed") {
      if (!/^[A-Z][A-Z0-9_]*_EXIT=0$/u.test(gate?.literal_exit ?? "")) errors.push(`${name}: closed ${gate?.pg_id} lacks an exact literal exit`);
      if ((gate?.evidence_refs ?? []).length === 0) errors.push(`${name}: closed ${gate?.pg_id} lacks retained evidence_refs`);
    } else if (gate?.literal_exit !== null) {
      errors.push(`${name}: non-closed ${gate?.pg_id} must not carry a successful literal exit`);
    }
    if (gate?.applicability === "out_of_scope" && gate?.closure_status !== "not_applicable") errors.push(`${name}: out_of_scope ${gate?.pg_id} must be not_applicable`);
    if (gate?.applicability !== "out_of_scope" && gate?.closure_status === "not_applicable") errors.push(`${name}: applicable ${gate?.pg_id} cannot be not_applicable`);
    if (gate?.applicability === "required_now" && gate?.profile_selection !== "selected") errors.push(`${name}: required_now ${gate?.pg_id} must be selected`);
    if (gate?.applicability === "conditional" && !new Set(["selected", "not_selected"]).has(gate?.profile_selection)) errors.push(`${name}: conditional ${gate?.pg_id} must be selected or not_selected`);
    if (gate?.applicability === "later" && gate?.profile_selection !== "deferred") errors.push(`${name}: later ${gate?.pg_id} must be deferred`);
    if (gate?.applicability === "out_of_scope" && gate?.profile_selection !== "not_applicable") errors.push(`${name}: out_of_scope ${gate?.pg_id} must have not_applicable selection`);
    if (gate?.profile_selection === "not_selected" && gate?.closure_status !== "open") errors.push(`${name}: nonselected conditional ${gate?.pg_id} must remain open`);
    if (gate?.scope_review !== undefined && gate.scope_review !== "pending_cross-contract_scope_decision") errors.push(`${name}: ${gate?.pg_id} has an unknown scope_review`);
  }
  if (!record.evidence_index || typeof record.evidence_index !== "object" || typeof record.evidence_index.literal_exit !== "string") errors.push(`${name}: invalid evidence_index`);
  const exitLiterals = JSON.stringify(record.exit_criteria ?? []).match(/\b[A-Z][A-Z0-9_]*_EXIT=0\b/gu) ?? [];
  if (exitLiterals.length !== 1) errors.push(`${name}: exit_criteria must declare exactly one future literal *_EXIT=0 (found ${exitLiterals.length})`);
  if (record.evidence_index?.literal_exit !== exitLiterals[0]) errors.push(`${name}: evidence_index literal_exit does not match exit_criteria`);
  for (const ref of record.evidence_refs ?? []) {
    const historicalUnavailable = record.evidence_index?.historical_status_preserved === true
      && (record.evidence_index?.historical_unavailable_refs ?? []).includes(ref);
    if (typeof ref !== "string") errors.push(`${name}: malformed retained evidence ref`);
    else if (!fs.existsSync(path.join(repoRoot, ref)) && historicalUnavailable) notices.push({
      result: "SKIP",
      check: "work-item-checkout-evidence-ref",
      work_item_id: record.work_item_id,
      ref,
      reason: "retained historical evidence ref is unavailable in this recognized incomplete checkout",
      nonclaim: "This missing checkout ref does not invalidate the preserved historical status, but SKIP is not proof, changes no status, and closes no work item or stage.",
    });
    else if (!fs.existsSync(path.join(repoRoot, ref))) errors.push(`${name}: missing retained evidence ref ${ref}`);
  }
  const historicalVerifiedStatus = record.status === "verified"
    && record.evidence_index?.historical_status_preserved === true
    && record.evidence_index?.checkout_validation === "legacy_status_unavailable_in_this_checkout";
  if (record.status === "verified" && !historicalVerifiedStatus) {
    const expectedOutputPaths = new Set(record.evidence_index?.expected_output_paths ?? []);
    const strictLiteralRefs = [...new Set(record.evidence_refs ?? [])].filter((ref) => (
      expectedOutputPaths.has(ref)
      && contentBoundLiteralEvidence(ref, record.evidence_index.literal_exit)
    ));
    if (strictLiteralRefs.length !== 1) {
      errors.push(`${name}: verified current record requires exactly one expected-path content-bound literal exit (found ${strictLiteralRefs.length})`);
    }
  }
  for (const anchor of record.code_anchors ?? []) {
    const inspected = inspectCodeAnchor(record, anchor);
    for (const error of inspected.errors) errors.push(`${name}: ${error}`);
    notices.push(...inspected.notices);
  }
  if ((record.remaining_nonclaims ?? []).length === 0) errors.push(`${name}: remaining_nonclaims must be nonempty`);
  if ((record.in_scope ?? []).length === 0 || (record.out_of_scope ?? []).length === 0 || (record.implementation_actions ?? []).length === 0) errors.push(`${name}: executable scope/actions must be nonempty`);
  if ((record.positive_proof ?? []).length === 0 || (record.product_journey_and_states ?? []).length === 0 || (record.metrics_and_frozen_thresholds ?? []).length === 0) errors.push(`${name}: proof/journey/metrics must be nonempty`);
  if (record.record_role === "aggregate_exit" && (record.aggregate_child_ids ?? []).length === 0) errors.push(`${name}: aggregate_exit has no children`);
  if (record.record_role !== "aggregate_exit" && (record.aggregate_child_ids ?? []).length > 0) errors.push(`${name}: non-aggregate record declares aggregate children`);
  if (record.record_role === "aggregate_exit" && (!record.aggregate_verification_binding || typeof record.aggregate_verification_binding !== "object")) errors.push(`${name}: aggregate_exit lacks exact verification binding`);
  if (record.record_role !== "aggregate_exit" && record.aggregate_verification_binding !== null) errors.push(`${name}: non-aggregate record carries an aggregate verification binding`);
  if (record.record_role !== "aggregate_exit" && (record.aggregate_child_dispositions ?? []).length > 0) errors.push(`${name}: non-aggregate record carries aggregate child dispositions`);
}

if (records.size !== files.length) errors.push("duplicate or missing work_item_id values");
for (const record of records.values()) {
  if (/journey/iu.test(record.work_item_id) && !REQUIRED_ORDERED_JOURNEYS[record.work_item_id]) {
    errors.push(`${record.work_item_id}: journey record lacks a checker-owned ordered transition mapping`);
  }
}
for (const record of records.values()) {
  if (record.status === "proposed" && contractRouting.work_item_contract_allowlists[record.work_item_id] === undefined) {
    errors.push(`${record.work_item_id}: proposed record lacks a reviewed per-record contract allowlist`);
  }
}
const mappedContractNames = new Set([...records.values()].flatMap((record) => (record.contract_families ?? []).map((family) => family.name)));
for (const registeredName of new Set(registry.contracts.map((entry) => entry.canonical_name))) {
  if (!mappedContractNames.has(registeredName)) errors.push(`registered canonical contract ${registeredName} has no bounded proposed/current work-item mapping`);
}
const pgClosureOwners = new Map();
for (const record of records.values()) {
  for (const gate of record.pg_gate_states ?? []) {
    const ownersForGate = pgClosureOwners.get(gate.pg_id) ?? [];
    ownersForGate.push({ work_item_id: record.work_item_id, gate });
    pgClosureOwners.set(gate.pg_id, ownersForGate);
  }
  if (preExistingStatuses.get(record.work_item_id) !== undefined && preExistingStatuses.get(record.work_item_id) !== "proposed") {
    if ((record.applicable_pg_ids ?? []).length > 0 || (record.pg_gate_states ?? []).length > 0) errors.push(`${record.work_item_id}: historical non-proposed scope cannot acquire proof-gate ownership`);
  }
}
for (const pgId of knownPgIds) {
  const owningRecords = pgClosureOwners.get(pgId) ?? [];
  if (owningRecords.length !== 1) errors.push(`${pgId}: expected exactly one closure owner, found ${owningRecords.length}`);
  if (owningRecords.some(({ work_item_id: ownerId }) => records.get(ownerId)?.record_role === "aggregate_exit")) errors.push(`${pgId}: aggregate records may join gate evidence but cannot own closure`);
}
for (const pgId of pgClosureOwners.keys()) if (!knownPgIds.has(pgId)) errors.push(`unknown mechanism gate owner mapping ${pgId}`);

const pg11Owner = pgClosureOwners.get("PG-1.1")?.[0];
if (
  pg11Owner?.work_item_id !== "m11-canonical-contract-registry-and-legacy-ref-migration" ||
  pg11Owner?.gate?.applicability !== "required_now" ||
  pg11Owner?.gate?.profile_selection !== "selected" ||
  pg11Owner?.gate?.closure_stage_id !== "M11"
) {
  errors.push("PG-1.1 must remain selected, required_now, M11-targeted, and owned by the canonical-contract migration record");
}
const pg11OwnerRecord = records.get("m11-canonical-contract-registry-and-legacy-ref-migration");
if (pg11OwnerRecord?.stage_id === "FUTURE") {
  if (pg11Owner?.gate?.closure_status !== "open" || pg11Owner?.gate?.literal_exit !== null) {
    errors.push("PG-1.1 must remain open with no successful literal while its owner is FUTURE/amendment-gated");
  }
  if (!(pg11OwnerRecord.external_gates ?? []).some((gate) => gate.gate_id === "later-explicit-sequencer-amendment")) {
    errors.push("PG-1.1 FUTURE owner lacks the later explicit sequencer amendment gate");
  }
}

const m0Census = records.get("m0-program-control-selected-profile-exit-proof")?.proof_gate_census;
if (m0Census?.role !== "oversight_projection_only_not_closure_authority") errors.push("m0-program-control-selected-profile-exit-proof: missing non-authoritative proof-gate census role");
const censusRows = m0Census?.dispositions ?? [];
if (censusRows.length !== knownPgIds.size) errors.push(`M0 proof-gate census must project ${knownPgIds.size} dispositions`);
for (const row of censusRows) {
  const owner = pgClosureOwners.get(row.pg_id)?.[0];
  if (!owner || owner.work_item_id !== row.closure_owner_work_item_id || owner.gate.applicability !== row.applicability) errors.push(`M0 proof-gate census mismatch for ${row.pg_id}`);
}

for (const [id, baselineStatus] of preExistingStatuses) {
  if (baselineStatus === "proposed") continue;
  const baselinePath = path.join(baselineRoot, `${id}.v1.json`);
  if (!fs.existsSync(baselinePath)) {
    errors.push(`${id}: missing immutable pre-unification baseline record`);
    continue;
  }
  const baseline = readJson(baselinePath);
  const currentRecord = records.get(id);
  if (!currentRecord) continue;
  const comparisons = [
    ["objective", currentRecord.objective, baseline.objective],
    ["required_work", currentRecord.required_work ?? [], baseline.required_work ?? []],
    ["canon_owners", sorted(currentRecord.canon_owners ?? []), sorted(baseline.canon_owners ?? [])],
    ["contract_families", sorted((currentRecord.contract_families ?? []).map((family) => family.name)), sorted((baseline.contract_families ?? []).map((family) => typeof family === "string" ? family : family.name))],
    ["evidence_refs", currentRecord.evidence_refs ?? [], baseline.evidence_refs ?? []],
  ];
  for (const [field, actual, expected] of comparisons) {
    if (JSON.stringify(actual) !== JSON.stringify(expected)) errors.push(`${id}: historical non-proposed ${field} differs from immutable pre-unification scope`);
  }
}
for (const [id, record] of records) {
  for (const dependency of record.dependency_work_item_ids ?? []) {
    if (!records.has(dependency)) errors.push(`${id}: unknown dependency_work_item_id ${dependency}`);
    if (dependency === id) errors.push(`${id}: self dependency`);
    const dependencyRecord = records.get(dependency);
    const stageRank = (stageId) => stageId === "FUTURE" ? 15 : Number(stageId.slice(1));
    if (dependencyRecord && stageRank(dependencyRecord.stage_id) > stageRank(record.stage_id)) errors.push(`${id}: dependency ${dependency} belongs to later stage ${dependencyRecord.stage_id}`);
  }
  for (const child of record.aggregate_child_ids ?? []) {
    if (!records.has(child)) errors.push(`${id}: unknown aggregate child ${child}`);
    if (child === id) errors.push(`${id}: aggregate includes itself`);
  }
}

const topLevelAggregateIds = new Set([
  "m0-program-control-selected-profile-exit-proof",
  "m1-selected-profile-exit-proof",
  "m2-selected-profile-exit-proof",
  "m3-direct-path-and-exit-proof",
  "m4-outcome-room-system-spine",
  "m5-selected-profile-exit-proof",
  "m6-product-surface-and-typed-workspaces",
  "m7-semantic-definition-action-plane",
  "m8-model-supply-route-substitution-and-selected-exit",
  "m9-selected-profile-aggregate-exit-and-claim-publication",
  "m10-two-failure-domain-continuity",
  "m11-selected-profile-exit-proof",
  "m12-selected-profile-exit-proof",
  "m13-selected-profile-aggregate-exit",
  "m14-selected-profile-aggregate-exit",
]);
const aggregateMembership = new Map();
for (const aggregate of records.values()) {
  for (const childId of aggregate.aggregate_child_ids ?? []) {
    const memberships = aggregateMembership.get(childId) ?? [];
    memberships.push(aggregate.work_item_id);
    aggregateMembership.set(childId, memberships);
  }
}
const aggregateDispositionCounts = {
  aggregate_membership: 0,
  top_level: 0,
  p0: 0,
  future: 0,
};
for (const record of records.values()) {
  const explicitDispositions = [
    record.stage_id === "FUTURE" ? "future" : null,
    topLevelAggregateIds.has(record.work_item_id) ? "top_level" : null,
    record.work_item_id === "m5-p0-readiness-verifier" ? "p0" : null,
  ].filter(Boolean);
  if (explicitDispositions.length > 1) {
    errors.push(`${record.work_item_id}: has overlapping explicit aggregate dispositions ${explicitDispositions.join(", ")}`);
  }
  const expectedMembershipCount = explicitDispositions.length === 0 ? 1 : 0;
  const memberships = aggregateMembership.get(record.work_item_id) ?? [];
  if (memberships.length !== expectedMembershipCount) errors.push(`${record.work_item_id}: expected ${expectedMembershipCount} aggregate membership(s), found ${memberships.length} (${memberships.join(", ") || "none"})`);
  for (const aggregateId of memberships) {
    const aggregate = records.get(aggregateId);
    if (aggregate?.stage_id !== record.stage_id) errors.push(`${record.work_item_id}: aggregate ${aggregateId} belongs to different stage ${aggregate?.stage_id}`);
  }
  if (explicitDispositions.length === 1) aggregateDispositionCounts[explicitDispositions[0]] += 1;
  else if (memberships.length === 1) aggregateDispositionCounts.aggregate_membership += 1;
}

for (const {
  aggregate_id: aggregateId,
  child_id: childId,
  activation_gate_id: gateId,
} of CONDITIONAL_AGGREGATE_CHILD_RULES) {
  const aggregate = records.get(aggregateId);
  const child = records.get(childId);
  if (!aggregate || !child) {
    errors.push(`${aggregateId}: missing conditional child or aggregate ${childId}`);
    continue;
  }
  if (!aggregate.aggregate_child_ids.includes(childId)) errors.push(`${aggregateId}: conditional child mapping omits ${childId}`);
  if (aggregate.dependency_work_item_ids.includes(childId)) errors.push(`${aggregateId}: conditional child ${childId} must not be an unconditional dependency`);
  if (!(child.external_gates ?? []).some((gate) => gate?.gate_id === gateId)) errors.push(`${childId}: missing activation gate ${gateId}`);
  const disposition = (aggregate.aggregate_child_dispositions ?? []).find((entry) => entry.child_work_item_id === childId);
  if (!new Set(["conditional_not_selected", "conditional_selected"]).has(disposition?.selection_state)) errors.push(`${aggregateId}: conditional child ${childId} lacks a machine-readable selection disposition`);
  if (disposition?.activation_gate_id !== gateId) errors.push(`${aggregateId}: conditional child ${childId} has wrong activation gate`);
  if (disposition?.selection_authority !== "ioi-target-end-state-master-implementation-guide.md") errors.push(`${aggregateId}: conditional child ${childId} has wrong selection authority`);
  if (!Array.isArray(disposition?.selection_evidence_refs)) errors.push(`${aggregateId}: conditional child ${childId} selection_evidence_refs must be an array`);
  if (disposition?.selection_state === "conditional_selected") {
    if ((disposition.selection_evidence_refs ?? []).length === 0) errors.push(`${aggregateId}: selected conditional child ${childId} lacks retained selection evidence`);
    for (const ref of disposition.selection_evidence_refs ?? []) {
      if (!fs.existsSync(path.join(repoRoot, ref)) && !fs.existsSync(path.join(implementationRoot, ref))) errors.push(`${aggregateId}: selected conditional child ${childId} has missing selection evidence ${ref}`);
    }
  } else if ((disposition?.selection_evidence_refs ?? []).length > 0) {
    errors.push(`${aggregateId}: nonselected conditional child ${childId} must not carry selection evidence`);
  }
}

const conditionalRulePairs = new Set(
  CONDITIONAL_AGGREGATE_CHILD_RULES.map((rule) => `${rule.aggregate_id}\u0000${rule.child_id}`),
);
for (const aggregate of [...records.values()].filter((record) => record.record_role === "aggregate_exit")) {
  const aggregateId = aggregate.work_item_id;
  const dispositions = aggregate.aggregate_child_dispositions ?? [];
  const dispositionIds = dispositions.map((entry) => entry?.child_work_item_id);
  if (new Set(dispositionIds).size !== dispositionIds.length) errors.push(`${aggregateId}: duplicate aggregate child dispositions`);
  if (JSON.stringify(dispositionIds) !== JSON.stringify(aggregate.aggregate_child_ids)) errors.push(`${aggregateId}: child dispositions must exactly cover aggregate_child_ids in order`);
  for (const disposition of dispositions) {
    const conditional = conditionalRulePairs.has(`${aggregateId}\u0000${disposition.child_work_item_id}`);
    if (!conditional) {
      if (disposition.selection_state !== "unconditional_active") errors.push(`${aggregateId}: unconditional child ${disposition.child_work_item_id} is not active`);
      if (disposition.activation_gate_id !== null) errors.push(`${aggregateId}: unconditional child ${disposition.child_work_item_id} invents an activation gate`);
      if (disposition.selection_authority !== "sole-sequencer stage membership") errors.push(`${aggregateId}: unconditional child ${disposition.child_work_item_id} has wrong selection authority`);
      if (!Array.isArray(disposition.selection_evidence_refs) || disposition.selection_evidence_refs.length !== 0) errors.push(`${aggregateId}: unconditional child ${disposition.child_work_item_id} must use an empty selection-evidence array`);
    }
    if (typeof disposition.disposition_basis !== "string" || disposition.disposition_basis.length < 40) errors.push(`${aggregateId}: child ${disposition.child_work_item_id} lacks a substantive disposition basis`);
  }

  const binding = aggregate.aggregate_verification_binding ?? {};
  if (binding.schema_version !== "ioi.program.aggregate-verification-binding.v1") errors.push(`${aggregateId}: aggregate binding schema mismatch`);
  if (JSON.stringify(binding.child_dispositions) !== JSON.stringify(dispositions)) errors.push(`${aggregateId}: aggregate binding child dispositions are stale`);
  const childBindings = binding.child_bindings ?? [];
  const dependencyBindings = binding.dependency_bindings ?? [];
  if (JSON.stringify(childBindings.map((entry) => entry.work_item_id)) !== JSON.stringify(aggregate.aggregate_child_ids)) errors.push(`${aggregateId}: aggregate binding does not exactly bind every child`);
  if (JSON.stringify(dependencyBindings.map((entry) => entry.work_item_id)) !== JSON.stringify(aggregate.dependency_work_item_ids)) errors.push(`${aggregateId}: aggregate binding does not exactly bind every unconditional dependency`);
  if (new Set(childBindings.map((entry) => entry.work_item_id)).size !== childBindings.length) errors.push(`${aggregateId}: duplicate child digest bindings`);
  if (new Set(dependencyBindings.map((entry) => entry.work_item_id)).size !== dependencyBindings.length) errors.push(`${aggregateId}: duplicate dependency digest bindings`);

  const dispositionByChild = new Map(dispositions.map((entry) => [entry.child_work_item_id, entry]));
  const verifyRecordBinding = (entry, expectedRelation, expectedSelectionState) => {
    const target = records.get(entry?.work_item_id);
    if (!target) return;
    const targetFile = path.join(workItemsRoot, `${target.work_item_id}.v1.json`);
    if (entry.relation !== expectedRelation) errors.push(`${aggregateId}: ${target.work_item_id} has wrong binding relation ${entry.relation}`);
    if (entry.selection_state !== expectedSelectionState) errors.push(`${aggregateId}: ${target.work_item_id} has stale binding selection state`);
    if (entry.record_sha256 !== sha256File(targetFile)) errors.push(`${aggregateId}: ${target.work_item_id} record digest is stale`);
    if (entry.status_at_binding !== target.status) errors.push(`${aggregateId}: ${target.work_item_id} status binding is stale`);
    const expectedEvidenceBinding = evidenceBindingForRecord(target);
    if (JSON.stringify(entry.evidence_binding) !== JSON.stringify(expectedEvidenceBinding)) errors.push(`${aggregateId}: ${target.work_item_id} evidence digest/literal binding is stale`);
  };
  for (const entry of childBindings) {
    verifyRecordBinding(
      entry,
      "aggregate_child",
      dispositionByChild.get(entry.work_item_id)?.selection_state ?? null,
    );
  }
  for (const entry of dependencyBindings) verifyRecordBinding(entry, "unconditional_dependency", null);
  const expectedAggregateEvidence = evidenceBindingForRecord(aggregate);
  if (JSON.stringify(binding.aggregate_evidence_binding) !== JSON.stringify(expectedAggregateEvidence)) errors.push(`${aggregateId}: own evidence digest/literal binding is stale`);
  const bindingPayload = {
    child_dispositions: binding.child_dispositions,
    child_bindings: childBindings,
    dependency_bindings: dependencyBindings,
    aggregate_evidence_binding: binding.aggregate_evidence_binding,
  };
  if (binding.binding_payload_sha256 !== sha256(stableJson(bindingPayload))) errors.push(`${aggregateId}: aggregate binding payload digest is stale`);
  if (typeof binding.nonclaim !== "string" || !binding.nonclaim.includes("does not promote")) errors.push(`${aggregateId}: aggregate binding lacks its non-promotion nonclaim`);

  if (aggregate.status === "verified") {
    if (!expectedAggregateEvidence.literal_valid) errors.push(`${aggregateId}: verified aggregate lacks exactly one retained standalone literal exit line`);
    const activeChildIds = dispositions
      .filter((entry) => new Set(["unconditional_active", "conditional_selected"]).has(entry.selection_state))
      .map((entry) => entry.child_work_item_id);
    const closureRecordIds = [...new Set([...activeChildIds, ...aggregate.dependency_work_item_ids])];
    for (const recordId of closureRecordIds) {
      const closureRecord = records.get(recordId);
      if (closureRecord?.status !== "verified") errors.push(`${aggregateId}: verified aggregate has non-verified active child/dependency ${recordId}`);
      if (closureRecord && !evidenceBindingForRecord(closureRecord).literal_valid) errors.push(`${aggregateId}: verified aggregate has literal-invalid active child/dependency ${recordId}`);
    }
    if (topLevelAggregateIds.has(aggregateId)) {
      for (const [pgId, owners] of pgClosureOwners) {
        const owner = owners[0];
        const gate = owner?.gate;
        if (!gate || stageRank(gate.closure_stage_id) > stageRank(aggregate.stage_id)) continue;
        const requiredForSelectedProfile = gate.applicability === "required_now"
          || (gate.applicability === "conditional" && gate.profile_selection === "selected");
        if (!requiredForSelectedProfile) continue;
        if (gate.closure_status !== "closed" || !gateLiteralValid(gate)) {
          errors.push(`${aggregateId}: verified aggregate has open or literal-invalid required/selected proof gate ${pgId}`);
        }
      }
    }
  }
}

const visiting = new Set();
const visited = new Set();
function visit(id, trail = []) {
  if (visiting.has(id)) {
    errors.push(`dependency cycle: ${[...trail, id].join(" -> ")}`);
    return;
  }
  if (visited.has(id) || !records.has(id)) return;
  visiting.add(id);
  const record = records.get(id);
  for (const dependency of record.dependency_work_item_ids ?? []) visit(dependency, [...trail, id]);
  visiting.delete(id);
  visited.add(id);
}
for (const id of records.keys()) visit(id);

const migrationFinalization = validateWorkItemMigrationFinalization();
for (const error of migrationFinalization.errors) {
  errors.push(`migration finalization: ${error}`);
}

for (const notice of notices) process.stdout.write(`${JSON.stringify(notice)}\n`);
failWith("work-item check", errors);
const statuses = [...records.values()].reduce((accumulator, record) => {
  accumulator[record.status] = (accumulator[record.status] ?? 0) + 1;
  return accumulator;
}, {});
process.stdout.write(
  `work-item check passed: ${records.size} schema-valid planning records; statuses ${JSON.stringify(statuses)}; `
  + `stage/aggregate disposition invariant: ${records.size}/${records.size} records each have exactly one stage plus exactly one aggregate membership or an explicit top-level/P0/FUTURE disposition `
  + `(${aggregateDispositionCounts.aggregate_membership} aggregate members, ${aggregateDispositionCounts.top_level} top-level, ${aggregateDispositionCounts.p0} P0, ${aggregateDispositionCounts.future} FUTURE); `
  + `${notices.length} explicit checkout SKIP nonclaim(s). SKIP is not proof, changes no status, and closes no work item or stage.\n`,
);
