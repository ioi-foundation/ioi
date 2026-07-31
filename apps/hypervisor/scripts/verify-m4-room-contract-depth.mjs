#!/usr/bin/env node

// Canon-depth guard for OutcomeRoom, RoomAdmittedObjectBase, the two implemented M4 room-child
// families, the M4 graph/discussion projections, and the six provisional M5 child families.
// Registry presence and field names are insufficient: properties and finite collection domains
// are compared with owner declarations, embedded RoomAdmittedObjectBase copies are compared
// recursively, and the registry must retain positive and adversarial fixtures.

import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const SCHEMAS = join(ROOT, "docs", "architecture", "_meta", "schemas");
const registry = JSON.parse(
  readFileSync(join(SCHEMAS, "architecture-contract-registry.v1.json"), "utf8"),
);

const results = [];
const EXPECTED_CHECKS = 19;
const check = (name, pass, detail = "") =>
  results.push({ name, pass: !!pass, detail });
const exactSet = (actual, expected) =>
  JSON.stringify([...(actual || [])].sort()) ===
  JSON.stringify([...expected].sort());

const TIMESTAMP_PATTERN =
  "^[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])T(?:[01][0-9]|2[0-3]):[0-5][0-9]:(?:[0-5][0-9]|60)(?:[.][0-9]+|)(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$";
const HASH_PATTERN = "^sha256:[0-9a-f]{64}$";
const NON_TERMINAL_ADMISSION_STATUSES = ["proposed", "evaluating", "rejected"];
const ADMITTED_TRUTH_FIELDS = [
  "admitted_sequence",
  "resulting_room_revision",
  "resulting_transition_commitment_ref",
  "resulting_room_state_root",
  "resulting_receipt_root",
];
const TERMINAL_REQUIRED_FIELDS = [
  "admission_decision_ref",
  "admission_receipt_ref",
  ...ADMITTED_TRUTH_FIELDS,
  "updated_at",
];
const uriPattern = (schemes) =>
  schemes.length === 1
    ? `^${schemes[0]}://[^\\s]{1,500}$`
    : `^(?:${schemes.join("|")})://[^\\s]{1,500}$`;

const shape = {
  const: (value) => ({ kind: "const", value }),
  enum: (...values) => ({ kind: "enum", values }),
  uri: (...schemes) => ({ kind: "pattern", pattern: uriPattern(schemes) }),
  pattern: (pattern) => ({ kind: "pattern", pattern }),
  hash: { kind: "pattern", pattern: HASH_PATTERN },
  timestamp: { kind: "timestamp" },
  string: { kind: "type", type: "string" },
  boundedString: (minLength, maxLength) => ({
    kind: "bounded_string",
    minLength,
    maxLength,
  }),
  number: { kind: "type", type: "number" },
  boolean: { kind: "type", type: "boolean" },
  null: { kind: "type", type: "null" },
  integer: (minimum, maximum) => ({ kind: "integer", minimum, maximum }),
  object: (properties) => ({ kind: "object", properties }),
  anyObject: { kind: "type", type: "object" },
  array: (items, maxItems) => ({ kind: "array", items, maxItems }),
  nullable: (value) => ({ kind: "nullable", value }),
  anyOf: (...values) => ({ kind: "any_of", values }),
  literalOrUri: (literal, ...schemes) => ({
    kind: "literal_or_uri",
    literal,
    schemes,
  }),
};

const BASE = {
  schema_version: shape.const("ioi.foundations.room-admitted-object-base.v2"),
  room_system_id: shape.uri("system"),
  outcome_room_ref: shape.uri("outcome-room"),
  proposed_or_issued_by_ref: shape.uri("participant-lease", "system"),
  expected_room_revision: shape.integer(0),
  expected_predecessor_commitment_ref: shape.uri("commitment"),
  payload_root: shape.hash,
  admission_policy_ref: shape.uri("policy"),
  admission_decision_ref: shape.nullable(shape.uri("decision")),
  admission_receipt_ref: shape.nullable(shape.uri("receipt")),
  admitted_sequence: shape.nullable(shape.integer(0)),
  resulting_room_revision: shape.nullable(shape.integer(0)),
  resulting_transition_commitment_ref: shape.nullable(shape.uri("commitment")),
  resulting_room_state_root: shape.nullable(shape.hash),
  resulting_receipt_root: shape.nullable(shape.hash),
  created_at: shape.timestamp,
  updated_at: shape.nullable(shape.timestamp),
  admission_status: shape.enum(
    "proposed",
    "evaluating",
    "admitted",
    "rejected",
    "superseded",
    "revoked",
  ),
};

const roomAdmission = shape.object(BASE);
const nullableRoomAdmission = shape.nullable(roomAdmission);
const revision = shape.integer(undefined);
const canonicalRef = shape.pattern("^[a-z][a-z0-9+._-]*://[^\\s]{1,500}$");

const OUTCOME_ROOM = {
  schema_version: shape.const("ioi.foundations.outcome-room.v2"),
  outcome_room_id: shape.uri("outcome-room"),
  system_id: shape.uri("system"),
  genesis_ref: shape.nullable(shape.uri("genesis")),
  package_id: shape.uri("package"),
  manifest_ref: shape.pattern(
    "^package://[^\\s?#\\\\]{1,160}/release/[^\\s?#\\\\]{1,160}$",
  ),
  constitution_ref: shape.uri("constitution"),
  active_profile_refs: shape.object({
    deployment_profile_ref: shape.uri("deployment-profile"),
    ordering_admission_finality_profile_ref: shape.uri("ordering-profile"),
    oracle_evidence_profile_refs: shape.array(
      shape.uri("oracle-evidence-profile"),
      64,
    ),
    lifecycle_continuity_profile_ref: shape.uri("lifecycle-profile"),
    network_enrollment_ref: shape.nullable(shape.uri("network-enrollment")),
  }),
  autonomous_system_state_ref: shape.uri("agentgres"),
  owner_or_sponsor_ref: shape.uri(
    "system",
    "user",
    "org",
    "project",
    "domain",
    "service",
  ),
  objective_ref: shape.uri("goal", "task", "service"),
  objective: shape.boundedString(1, 4096),
  constraint_refs: shape.array(
    shape.uri("constraint", "policy", "budget"),
    64,
  ),
  acceptance_criteria_refs: shape.array(
    shape.uri("rubric", "gate", "policy"),
    64,
  ),
  stop_policy_ref: shape.uri("policy"),
  room_mode: shape.enum(
    "private_goal",
    "permissioned_team",
    "cross_org",
    "open_challenge",
  ),
  visibility_policy_ref: shape.uri("policy"),
  participation_policy_ref: shape.uri("policy"),
  privacy_policy_ref: shape.uri("policy"),
  contribution_policy_ref: shape.uri("policy"),
  cooperation_surplus_policy_ref: shape.uri("policy"),
  collaboration_terms_refs: shape.array(shape.uri("terms"), 64),
  discovery_and_external_admission_policy_refs: shape.array(
    shape.uri("policy", "room-discovery", "aiip"),
    64,
  ),
  artifact_license_rights_retention_and_export_policy_refs: shape.array(
    shape.uri("policy", "license"),
    64,
  ),
  coordination_topology: shape.enum("hosted_admission", "federated_admission"),
  coordination_policy_ref: shape.uri("policy"),
  host_domain_ref: shape.nullable(shape.uri("system", "domain")),
  ordering_and_merge_policy_ref: shape.uri("policy"),
  conflict_and_failover_policy_ref: shape.uri("policy"),
  multi_party_collaboration_ref: shape.nullable(shape.uri("collaboration")),
  ontology_profile_refs: shape.array(
    shape.uri("ontology", "semantic-profile", "ontology-mapping"),
    64,
  ),
  scorecard_and_guardrail_refs: shape.array(
    shape.uri("benchmark", "rubric", "gate", "policy"),
    64,
  ),
  verifier_path_refs: shape.array(shape.uri("verifier-path"), 64),
  resource_and_budget_refs: shape.array(
    shape.uri("resource-pool", "budget", "goal-budget", "order"),
    64,
  ),
  settlement_policy_ref: shape.nullable(shape.uri("policy")),
  participant_lease_refs: shape.array(shape.uri("participant-lease"), 64),
  member_goal_run_refs: shape.array(shape.uri("goal"), 64),
  participation_request_refs: shape.array(
    shape.uri("participation-request"),
    64,
  ),
  resource_offer_refs: shape.array(shape.uri("resource-offer"), 64),
  capability_offer_refs: shape.array(shape.uri("capability-offer"), 64),
  frontier_item_refs: shape.array(shape.uri("frontier"), 64),
  attempt_refs: shape.array(shape.uri("attempt"), 64),
  finding_refs: shape.array(shape.uri("finding"), 64),
  verifier_challenge_refs: shape.array(shape.uri("verifier-challenge"), 64),
  discussion_projection_refs: shape.array(
    shape.uri("projection", "message"),
    64,
  ),
  admission_and_replay_refs: shape.array(
    shape.uri("receipt", "replay", "agentgres"),
    128,
  ),
  contribution_refs: shape.array(
    shape.uri("contribution", "receipt"),
    64,
  ),
  participant_state_bundle_refs: shape.array(
    shape.uri("participant-state"),
    64,
  ),
  latest_sequence: shape.integer(0, 127),
  latest_transition_commitment_ref: shape.uri("commitment"),
  room_state_root: shape.hash,
  room_receipt_root: shape.hash,
  status: shape.enum(
    "proposed",
    "open",
    "active",
    "paused",
    "blocked",
    "verifying",
    "accepted",
    "disputed",
    "settled",
    "closed",
    "revoked",
    "archived",
  ),
};

const PRODUCER_COMPONENT_RESOLUTION = shape.object({
  resolved_component_set_snapshot_ref: shape.nullable(shape.uri("artifact")),
  resolved_component_set_hash: shape.nullable(shape.hash),
  component_resolution_receipt_ref: shape.nullable(shape.uri("receipt")),
  resolver_kind: shape.enum("harness_profile", "agent_harness_adapter", "none"),
  resolver_revision_ref: shape.nullable(
    shape.pattern(
      "^(?:harness-profile|agent-harness-adapter)://[^\\s]{1,500}/revision/[^\\s]{1,500}$",
    ),
  ),
  resolver_content_hash: shape.nullable(shape.hash),
});

const WORK_RESULT = {
  schema_version: shape.const("ioi.foundations.work-result.v2"),
  work_result_id: shape.uri("work-result"),
  work_subject_ref: shape.uri(
    "goal",
    "automation-run",
    "work-run",
    "run",
    "invocation",
    "work-claim",
    "attempt",
  ),
  goal_run_ref: shape.nullable(shape.uri("goal")),
  outcome_room_ref: shape.nullable(shape.uri("outcome-room")),
  room_admission: nullableRoomAdmission,
  produced_by_ref: shape.uri(
    "system",
    "participant-lease",
    "worker",
    "service",
    "org",
    "domain",
  ),
  submitted_by_ref: shape.uri(
    "system",
    "participant-lease",
    "worker",
    "service",
    "org",
    "domain",
  ),
  operator_and_affiliation_refs: shape.array(canonicalRef, 64),
  work_claim_ref: shape.nullable(shape.uri("work-claim")),
  attempt_ref: shape.nullable(shape.uri("attempt")),
  invocation_or_run_ref: shape.nullable(
    shape.uri(
      "harness-invocation",
      "run",
      "work-run",
      "automation-run",
      "service",
    ),
  ),
  result_profile: shape.enum(
    "software_implementation",
    "research",
    "ontology_mutation",
    "incident_resolution",
    "service_delivery",
    "physical_mission",
    "review",
    "evaluation",
    "custom",
  ),
  result_profile_ref: shape.nullable(shape.uri("schema", "profile")),
  result_payload_ref: shape.nullable(
    shape.pattern(
      "^(?:(?:implementation-result|artifact|cid)://[^\\s]{1,500}|encrypted_ref)$",
    ),
  ),
  producer_component_resolution: PRODUCER_COMPONENT_RESOLUTION,
  declared_method_and_lineage_refs: shape.array(
    shape.uri(
      "method",
      "attempt",
      "finding",
      "work-result",
      "artifact",
      "trace",
    ),
    64,
  ),
  information_flow_label_refs: shape.array(shape.uri("ifc-label"), 64),
  outcome_class: shape.enum(
    "positive",
    "negative",
    "inconclusive",
    "invalid",
    "exploit_found",
    "superseded",
  ),
  status: shape.enum(
    "completed",
    "failed",
    "blocked",
    "partial",
    "challenged",
    "superseded",
  ),
  outcome_delta_refs: shape.array(shape.uri("outcome-delta"), 64),
  finding_refs: shape.array(shape.uri("finding"), 64),
  claim_refs: shape.array(
    shape.uri("finding", "ontology-assertion", "evidence"),
    64,
  ),
  uncertainty: shape.anyOf(
    shape.number,
    shape.string,
    shape.anyObject,
    shape.null,
  ),
  supporting_evidence_refs: shape.array(
    shape.uri("artifact", "evidence", "receipt", "ledger"),
    64,
  ),
  contradicting_evidence_refs: shape.array(
    shape.uri("finding", "ontology-assertion", "evidence", "artifact"),
    64,
  ),
  artifact_receipt_and_trace_refs: shape.array(
    shape.uri("artifact", "receipt", "ledger", "trace"),
    64,
  ),
  resource_and_cost_refs: shape.array(
    shape.uri("resource-lease", "cost", "quote", "budget", "ledger", "receipt"),
    64,
  ),
  authority_and_policy_refs: shape.array(
    shape.pattern(
      "^(?:(?:grant|policy|receipt)://[^\\s]{1,500}|scope:[^\\s]{1,500})$",
    ),
    64,
  ),
  blocker_and_decision_request_refs: shape.array(
    shape.uri("blocker", "handoff", "proposal"),
    64,
  ),
  verifier_refs: shape.array(
    shape.uri("verifier-path", "worker", "gate", "receipt"),
    64,
  ),
  license_disclosure_retention_and_export_refs: shape.array(
    shape.uri("license", "policy", "restricted-view", "receipt"),
    64,
  ),
  reproduction_state: shape.nullable(
    shape.enum(
      "unreviewed",
      "reproducible",
      "not_reproduced",
      "contradicted",
      "invalidated",
    ),
  ),
  reproduction_refs: shape.array(
    shape.uri("attempt", "work-result", "evidence", "receipt"),
    64,
  ),
  acceptance_ref: shape.nullable(
    shape.uri("acceptance", "decision", "receipt"),
  ),
  challenge_refs: shape.array(
    shape.uri("verifier-challenge", "dispute", "evidence"),
    64,
  ),
  supersedes_work_result_ref: shape.nullable(shape.uri("work-result")),
  superseded_by_ref: shape.nullable(shape.uri("work-result", "outcome-delta")),
  summary_ref: shape.nullable(shape.uri("message", "artifact")),
  next_action: shape.enum(
    "none",
    "repair",
    "review",
    "verify",
    "replicate",
    "synthesize",
    "ask_user",
    "escalate",
    "update_frontier",
  ),
};

const OUTCOME_DELTA = {
  schema_version: shape.const("ioi.foundations.outcome-delta.v2"),
  outcome_delta_id: shape.uri("outcome-delta"),
  work_subject_ref: shape.uri(
    "goal",
    "automation-run",
    "work-run",
    "run",
    "invocation",
    "work-claim",
    "attempt",
  ),
  outcome_room_ref: shape.nullable(shape.uri("outcome-room")),
  room_admission: nullableRoomAdmission,
  proposed_by_ref: shape.uri(
    "work-result",
    "attempt",
    "finding",
    "participant-lease",
  ),
  target_ref: shape.uri(
    "frontier",
    "finding",
    "ontology",
    "state",
    "capability",
    "policy",
    "routing-prior",
    "service",
  ),
  delta_kind: shape.enum(
    "create",
    "update",
    "supersede",
    "reject",
    "merge",
    "promote",
    "rollback",
    "course_correct",
    "close",
  ),
  payload_ref: shape.uri("artifact", "patch", "mapping", "state-delta"),
  precondition_and_invariant_refs: shape.array(
    shape.uri("policy", "gate", "state"),
    64,
  ),
  expected_effect_ref: shape.nullable(shape.uri("effect")),
  verifier_and_acceptance_refs: shape.array(
    shape.uri("verifier-path", "rubric", "gate"),
    64,
  ),
  information_flow_label_refs: shape.array(shape.uri("ifc-label"), 64),
  status: shape.enum(
    "proposed",
    "evaluating",
    "admitted",
    "rejected",
    "superseded",
    "rolled_back",
  ),
};

const ATTEMPT_BOUND_COORDINATES = shape.object({
  outcome_room: shape.object({
    record_ref: shape.uri("outcome-room"),
    host_domain_ref: shape.uri("domain"),
    control_hash: shape.hash,
  }),
  frontier_item: shape.object({
    record_ref: shape.uri("frontier"),
    outcome_room_ref: shape.uri("outcome-room"),
    revision,
    record_hash: shape.hash,
  }),
  work_claim: shape.object({
    record_ref: shape.uri("work-claim"),
    outcome_room_ref: shape.uri("outcome-room"),
    frontier_item_ref: shape.uri("frontier"),
    claimant_ref: shape.uri("participant-lease"),
    revision,
    record_hash: shape.hash,
  }),
  participant_lease: shape.object({
    record_ref: shape.uri("participant-lease"),
    outcome_room_ref: shape.uri("outcome-room"),
    principal_ref: shape.uri("worker", "agent"),
    revision,
    record_hash: shape.hash,
  }),
  goal_run: shape.object({
    record_ref: shape.uri("goal"),
    outcome_room_ref: shape.uri("outcome-room"),
    updated_at: shape.nullable(shape.timestamp),
    record_hash: shape.hash,
  }),
});

const FINDING_BOUND_COORDINATES = shape.object({
  attempt: shape.object({
    record_ref: shape.uri("attempt"),
    outcome_room_ref: shape.uri("outcome-room"),
    participant_ref: shape.uri("participant-lease"),
    work_result_ref: shape.uri("work-result"),
    revision,
    record_hash: shape.hash,
  }),
  work_result: shape.object({
    record_ref: shape.uri("work-result"),
    outcome_room_ref: shape.uri("outcome-room"),
    goal_run_ref: shape.uri("goal"),
    goal_ref: shape.uri("goal"),
    updated_at: shape.nullable(shape.timestamp),
    record_hash: shape.hash,
  }),
  participant_lease: shape.object({
    record_ref: shape.uri("participant-lease"),
    outcome_room_ref: shape.uri("outcome-room"),
    principal_ref: shape.uri("worker", "agent"),
    revision,
    record_hash: shape.hash,
  }),
  supersedes_finding: shape.nullable(
    shape.object({
      record_ref: shape.uri("finding"),
      outcome_room_ref: shape.uri("outcome-room"),
      revision,
      record_hash: shape.hash,
    }),
  ),
});

const FAMILIES = {
  "work-frontier-item.v2": {
    anchor: "workfrontieritemenvelope",
    invariant: {
      invariant_id:
        "invariant://ioi/foundations/work-frontier-item/room-binding/v2",
      path: "invariants/work-frontier-item.v2.invariants.json",
    },
    properties: {
      schema_version: shape.const("ioi.foundations.work-frontier-item.v2"),
      frontier_item_id: shape.uri("frontier"),
      room_admission: roomAdmission,
      item_kind: shape.enum(
        "question",
        "problem",
        "hypothesis",
        "task",
        "review_need",
        "verification_need",
        "resource_need",
        "synthesis_need",
      ),
      objective: shape.string,
      dependency_refs: shape.array(shape.uri("frontier", "attempt", "finding")),
      related_attempt_and_finding_refs: shape.array(
        shape.uri("attempt", "finding"),
      ),
      required_capability_refs: shape.array(
        shape.uri("capability", "worker", "tool"),
      ),
      required_context_resource_authority_and_evidence_refs: shape.array(
        shape.pattern(
          "^(?:(?:context-profile|resource|evidence)://[^\\s]{1,500}|scope:[^\\s]{1,500})$",
        ),
      ),
      expected_value: shape.nullable(shape.number),
      uncertainty: shape.nullable(shape.number),
      priority: shape.nullable(shape.number),
      duplication_policy: shape.enum(
        "exclusive",
        "allowed",
        "encouraged",
        "independent_replication_required",
      ),
      claimability: shape.enum(
        "open",
        "invited_only",
        "assigned",
        "paused",
        "closed",
      ),
      max_concurrency: shape.nullable(shape.integer(undefined)),
      expires_at: shape.nullable(shape.timestamp),
      stop_condition_ref: shape.nullable(shape.uri("policy")),
      status: shape.enum(
        "open",
        "claimed",
        "blocked",
        "replicating",
        "verifying",
        "accepted",
        "rejected",
        "superseded",
        "closed",
      ),
    },
    positiveFixture: "fixtures/work-frontier-item-v2/positive-admitted.json",
    negativeFixture:
      "fixtures/work-frontier-item-v2/negative-room-substitution.json",
    admittedFixture: "fixtures/work-frontier-item-v2/positive-admitted.json",
    nonTerminalFixture:
      "fixtures/work-frontier-item-v2/negative-evaluating-carries-admitted-roots.json",
    nonTerminalStatus: "evaluating",
    fixtureSemantics: (positive, negative) =>
      !Object.hasOwn(positive, "outcome_room_ref") &&
      positive.required_context_resource_authority_and_evidence_refs.includes(
        "scope:room.verify",
      ) &&
      negative.dependency_refs.some((ref) => ref.startsWith("goal://")),
  },
  "work-claim-lease.v2": {
    anchor: "workclaimleaseenvelope",
    invariant: {
      invariant_id:
        "invariant://ioi/foundations/work-claim-lease/room-claim/v2",
      path: "invariants/work-claim-lease.v2.invariants.json",
    },
    properties: {
      schema_version: shape.const("ioi.foundations.work-claim-lease.v2"),
      work_claim_id: shape.uri("work-claim"),
      outcome_room_ref: shape.nullable(shape.uri("outcome-room")),
      room_admission: nullableRoomAdmission,
      frontier_item_ref: shape.nullable(shape.uri("frontier")),
      claimant_ref: shape.uri(
        "participant-lease",
        "system",
        "domain",
        "worker",
        "service",
        "agent",
        "org",
      ),
      claimant_participant_lease_ref: shape.nullable(
        shape.uri("participant-lease"),
      ),
      eligibility_match_receipt_ref: shape.nullable(shape.uri("receipt")),
      task_offer_ref: shape.nullable(shape.uri("packet")),
      task_acceptance_ref: shape.nullable(shape.uri("packet")),
      routing_decision_ref: shape.nullable(shape.uri("routing-decision")),
      collaboration_terms_ref: shape.uri("terms"),
      collaboration_terms_root: shape.hash,
      terms_acceptance_ref: shape.uri("receipt"),
      contribution_policy_ref: shape.uri("policy"),
      quote_ref: shape.nullable(shape.uri("quote")),
      budget_reservation_ref: shape.nullable(
        shape.uri("budget", "spend", "allocation"),
      ),
      settlement_profile_ref: shape.uri("policy"),
      bounded_scope_ref: shape.uri("task", "task-brief", "policy"),
      context_lease_refs: shape.array(shape.uri("context-lease")),
      authority_resource_compute_data_budget_and_tool_lease_refs: shape.array(
        shape.uri(
          "grant",
          "resource-lease",
          "compute",
          "view",
          "budget",
          "tool-lease",
        ),
      ),
      duplicate_work_policy: shape.enum(
        "exclusive",
        "allowed",
        "independent_replication",
        "adversarial_replication",
      ),
      issued_at: shape.timestamp,
      expires_at: shape.timestamp,
      heartbeat_ref: shape.nullable(shape.uri("heartbeat", "receipt")),
      renewal_count: shape.integer(undefined),
      release_or_reassignment_reason: shape.nullable(shape.string),
      status: shape.enum(
        "proposed",
        "active",
        "waiting",
        "released",
        "expired",
        "reassigned",
        "completed",
        "quarantined",
        "revoked",
      ),
    },
    positiveFixture:
      "fixtures/work-claim-lease-v2/positive-direct-bilateral.json",
    negativeFixture:
      "fixtures/work-claim-lease-v2/negative-wrong-task-offer-scheme.json",
    admittedFixture:
      "fixtures/work-claim-lease-v2/positive-active-room-claim.json",
    nonTerminalFixture:
      "fixtures/work-claim-lease-v2/negative-rejected-carries-admitted-roots.json",
    nonTerminalStatus: "rejected",
    fixtureSemantics: (positive, negative) =>
      positive.outcome_room_ref === null &&
      positive.room_admission === null &&
      positive.frontier_item_ref === null &&
      negative.task_offer_ref.startsWith("artifact://"),
  },
  "attempt.v2": {
    anchor: "attemptenvelope",
    invariant: {
      invariant_id:
        "invariant://ioi/foundations/attempt/frozen-room-coordinates/v2",
      path: "invariants/attempt.v2.invariants.json",
    },
    properties: {
      schema_version: shape.const("ioi.foundations.attempt.v2"),
      attempt_id: shape.uri("attempt"),
      outcome_room_ref: shape.nullable(shape.uri("outcome-room")),
      room_admission: nullableRoomAdmission,
      work_subject_ref: shape.uri(
        "goal",
        "automation-run",
        "work-run",
        "run",
        "invocation",
        "work-claim",
      ),
      goal_run_ref: shape.nullable(shape.uri("goal")),
      frontier_item_ref: shape.nullable(shape.uri("frontier")),
      work_claim_ref: shape.nullable(shape.uri("work-claim")),
      participant_ref: shape.uri(
        "participant-lease",
        "system",
        "worker",
        "agent",
      ),
      bound_coordinates: shape.nullable(ATTEMPT_BOUND_COORDINATES),
      declared_method_and_hypothesis_refs: shape.array(
        shape.uri("method", "finding", "artifact"),
      ),
      parent_and_derivation_refs: shape.array(
        shape.uri("attempt", "artifact", "finding"),
      ),
      input_state_and_environment_refs: shape.array(
        shape.uri("state", "environment", "worktree", "dataset"),
      ),
      worker_model_resolver_tool_and_runtime_version_refs: shape.array(
        shape.pattern(
          "^(?:(?:worker|model-route|runtime)://[^\\s]{1,500}|(?:harness-profile|agent-harness-adapter|tool)://[^\\s]{1,500}/revision/[^\\s]{1,500})$",
        ),
      ),
      authority_and_policy_refs: shape.array(shape.uri("grant", "policy")),
      resource_and_cost_refs: shape.array(
        shape.uri("resource-lease", "spend", "ledger"),
      ),
      outcome_class: shape.enum(
        "positive",
        "negative",
        "inconclusive",
        "invalid",
        "exploit_found",
        "superseded",
      ),
      work_result_ref: shape.nullable(shape.uri("work-result")),
      outcome_delta_refs: shape.array(shape.uri("outcome-delta")),
      artifact_evidence_and_receipt_refs: shape.array(
        shape.uri("artifact", "evidence", "receipt", "ledger"),
      ),
      verifier_refs: shape.array(
        shape.uri("verifier-path", "verifier-challenge"),
      ),
      reproduction_state: shape.enum(
        "unreviewed",
        "reproducible",
        "not_reproduced",
        "contradicted",
        "invalidated",
      ),
      artifact_license_ip_retention_and_export_refs: shape.array(
        shape.uri("license", "policy"),
      ),
      contribution_refs: shape.array(shape.uri("contribution", "receipt")),
      status: shape.enum(
        "draft",
        "running",
        "submitted",
        "admitted",
        "challenged",
        "accepted",
        "rejected",
        "superseded",
      ),
    },
    positiveFixture: "fixtures/attempt-v2/positive-non-room.json",
    negativeFixture:
      "fixtures/attempt-v2/negative-wrong-work-subject-scheme.json",
    admittedFixture: "fixtures/attempt-v2/positive-hosted-admitted.json",
    nonTerminalFixture:
      "fixtures/attempt-v2/negative-proposed-carries-admitted-roots.json",
    nonTerminalStatus: "proposed",
    fixtureSemantics: (positive, negative) =>
      [
        positive.outcome_room_ref,
        positive.room_admission,
        positive.bound_coordinates,
        positive.goal_run_ref,
        positive.frontier_item_ref,
        positive.work_claim_ref,
      ].every((value) => value === null) &&
      negative.work_subject_ref.startsWith("artifact://"),
  },
  "finding.v2": {
    anchor: "findingenvelope",
    invariant: {
      invariant_id:
        "invariant://ioi/foundations/finding/frozen-room-coordinates/v2",
      path: "invariants/finding.v2.invariants.json",
    },
    properties: {
      schema_version: shape.const("ioi.foundations.finding.v2"),
      finding_id: shape.uri("finding"),
      outcome_room_ref: shape.nullable(shape.uri("outcome-room")),
      room_admission: nullableRoomAdmission,
      attempt_ref: shape.uri("attempt"),
      work_result_ref: shape.uri("work-result"),
      participant_ref: shape.uri("participant-lease"),
      proposed_by_ref: shape.uri(
        "participant-lease",
        "system",
        "worker",
        "service",
        "org",
        "domain",
      ),
      bound_coordinates: shape.nullable(FINDING_BOUND_COORDINATES),
      proposition: shape.string,
      finding_kind: shape.enum(
        "hypothesis",
        "observation",
        "claim",
        "negative_result",
        "integrity_incident",
        "mapping_claim",
        "causal_claim",
        "counterexample",
        "synthesis",
      ),
      confidence_or_uncertainty: shape.nullable(shape.number),
      valid_time: shape.nullable(shape.anyObject),
      transaction_time: shape.timestamp,
      source_and_observation_context_refs: shape.array(
        shape.uri("attempt", "observation", "participant-lease", "domain"),
      ),
      supporting_evidence_refs: shape.array(
        shape.uri("evidence", "artifact", "receipt"),
      ),
      proof_refs: shape.array(shape.uri("evidence", "artifact", "receipt")),
      contradicting_evidence_refs: shape.array(
        shape.uri("evidence", "artifact", "finding"),
      ),
      applicability_and_counterexample_refs: shape.array(
        shape.uri("policy", "finding", "ontology"),
      ),
      provenance_ontology_and_mapping_refs: shape.array(
        shape.uri("provenance", "ontology", "ontology-mapping"),
      ),
      proposed_effect_refs: shape.array(
        shape.uri("frontier", "routing-prior", "policy", "capability"),
      ),
      supersedes_ref: shape.nullable(shape.uri("finding")),
      dispute_ref: shape.nullable(shape.uri("dispute")),
      status: shape.enum(
        "branch_local",
        "proposed",
        "admitted",
        "contradicted",
        "superseded",
        "disputed",
        "rejected",
        "archived",
      ),
    },
    positiveFixture: "fixtures/finding-v2/positive-non-room.json",
    negativeFixture: "fixtures/finding-v2/negative-wrong-source-scheme.json",
    admittedFixture: "fixtures/finding-v2/positive-hosted-admitted.json",
    nonTerminalFixture:
      "fixtures/finding-v2/negative-evaluating-carries-admitted-roots.json",
    nonTerminalStatus: "evaluating",
    fixtureSemantics: (positive, negative) =>
      positive.outcome_room_ref === null &&
      positive.room_admission === null &&
      positive.bound_coordinates === null &&
      negative.source_and_observation_context_refs.some((ref) =>
        ref.startsWith("goal://"),
      ),
  },
  "verifier-challenge.v2": {
    anchor: "verifierchallengeenvelope",
    invariant: {
      invariant_id:
        "invariant://ioi/foundations/verifier-challenge/room-binding/v2",
      path: "invariants/verifier-challenge.v2.invariants.json",
    },
    properties: {
      schema_version: shape.const("ioi.foundations.verifier-challenge.v2"),
      verifier_challenge_id: shape.uri("verifier-challenge"),
      outcome_room_ref: shape.nullable(shape.uri("outcome-room")),
      room_admission: nullableRoomAdmission,
      challenger_ref: shape.uri(
        "participant-lease",
        "system",
        "worker",
        "org",
        "user",
      ),
      challenged_ref: shape.uri(
        "attempt",
        "finding",
        "verifier-path",
        "benchmark",
        "rubric",
        "evidence",
        "eligibility",
        "decision",
      ),
      challenge_kind: shape.enum(
        "metric",
        "rule",
        "verifier",
        "evidence",
        "eligibility",
        "result",
        "exploit",
        "independence",
        "collusion",
        "mapping",
      ),
      challenge_evidence_refs: shape.array(
        shape.uri("evidence", "artifact", "receipt"),
      ),
      adjudicator_policy_ref: shape.uri("policy"),
      prior_rule_version_ref: shape.nullable(
        shape.uri("rubric", "verifier-path"),
      ),
      proposed_rule_version_ref: shape.nullable(
        shape.uri("rubric", "verifier-path"),
      ),
      affected_attempt_refs: shape.array(shape.uri("attempt")),
      reverification_required: shape.boolean,
      adjudication_ref: shape.nullable(shape.uri("decision", "dispute")),
      status: shape.enum(
        "proposed",
        "admitted",
        "investigating",
        "upheld",
        "rejected",
        "rule_changed",
        "reverifying",
        "resolved",
        "withdrawn",
      ),
    },
    positiveFixture: "fixtures/verifier-challenge-v2/positive-non-room.json",
    negativeFixture:
      "fixtures/verifier-challenge-v2/negative-unsupported-challenger-kind.json",
    admittedFixture:
      "fixtures/verifier-challenge-v2/positive-hosted-admitted.json",
    nonTerminalFixture:
      "fixtures/verifier-challenge-v2/negative-rejected-carries-admitted-roots.json",
    nonTerminalStatus: "rejected",
    fixtureSemantics: (positive, negative) =>
      positive.outcome_room_ref === null &&
      positive.room_admission === null &&
      negative.challenger_ref.startsWith("goal://"),
  },
  "participant-state-bundle.v2": {
    anchor: "participantstatebundleenvelope",
    invariant: {
      invariant_id:
        "invariant://ioi/foundations/participant-state-bundle/portable-room-binding/v2",
      path: "invariants/participant-state-bundle.v2.invariants.json",
    },
    properties: {
      schema_version: shape.const(
        "ioi.foundations.participant-state-bundle.v2",
      ),
      participant_state_bundle_id: shape.uri("participant-state"),
      outcome_room_ref: shape.uri("outcome-room"),
      room_admission: roomAdmission,
      participant_lease_ref: shape.uri("participant-lease"),
      participant_and_home_domain_refs: shape.array(
        shape.uri("worker", "service", "org", "domain", "system"),
      ),
      coordination_topology: shape.enum(
        "hosted_admission",
        "federated_admission",
      ),
      bundle_reason: shape.enum(
        "checkpoint",
        "voluntary_retirement",
        "lease_expiry",
        "revocation",
        "quarantine",
        "room_close",
      ),
      source_admission_watermark_ref: shape.pattern(
        "^(?:(?:receipt|agentgres)://[^\\s]{1,500}|sha256:[0-9a-f]{64})$",
      ),
      released_or_reassigned_claim_refs: shape.array(
        shape.uri("work-claim", "decision", "receipt"),
      ),
      preserved_contribution_attempt_finding_and_result_refs: shape.array(
        shape.uri(
          "contribution",
          "attempt",
          "finding",
          "work-result",
          "outcome-delta",
        ),
      ),
      preserved_receipt_acceptance_settlement_and_dispute_refs: shape.array(
        shape.uri(
          "receipt",
          "acceptance",
          "settlement-intent",
          "dispute",
          "decision",
        ),
      ),
      portable_artifact_and_view_refs: shape.array(
        shape.uri(
          "artifact",
          "restricted-view",
          "redacted-summary",
          "evidence",
          "replay",
        ),
      ),
      lineage_and_supersession_refs: shape.array(
        shape.uri("contribution", "attempt", "finding", "work-result"),
      ),
      export_license_retention_and_recall_policy_refs: shape.array(
        shape.uri("policy", "license", "revocation"),
      ),
      excluded_context_classes: shape.array(
        shape.enum(
          "raw_secret",
          "protected_plaintext",
          "unauthorized_connector_payload",
          "unrelated_private_memory",
          "private_room_database_state",
          "revoked_restricted_view",
          "non_opted_in_training_trace",
        ),
      ),
      released_future_access_refs: shape.array(
        shape.uri("revocation", "context-lease", "grant", "receipt"),
      ),
      revocation_or_supersession_refs: shape.array(
        shape.uri("revocation", "participant-state", "decision", "receipt"),
      ),
      revocation_effect: shape.enum(
        "none",
        "future_access_only",
        "restricted_view_keys_revoked",
        "erroneous_export_superseded",
      ),
      bundle_artifact_ref: shape.pattern(
        "^(?:(?:artifact|cid)://[^\\s]{1,500}|encrypted_ref)$",
      ),
      bundle_root: shape.hash,
      room_database_access_required: shape.const(false),
      issued_at: shape.timestamp,
      signature: shape.string,
      status: shape.enum(
        "prepared",
        "exported",
        "acknowledged",
        "superseded",
        "revoked",
      ),
    },
    positiveFixture:
      "fixtures/participant-state-bundle-v2/positive-hosted-export.json",
    negativeFixture:
      "fixtures/participant-state-bundle-v2/negative-encrypted-ref-smuggling.json",
    admittedFixture:
      "fixtures/participant-state-bundle-v2/positive-hosted-export.json",
    nonTerminalFixture:
      "fixtures/participant-state-bundle-v2/negative-proposed-carries-admitted-roots.json",
    nonTerminalStatus: "proposed",
    fixtureSemantics: (positive, negative) =>
      positive.bundle_artifact_ref === "encrypted_ref" &&
      positive.source_admission_watermark_ref.startsWith("sha256:") &&
      negative.bundle_artifact_ref.startsWith("encrypted_ref:"),
  },
};

function resolve(schema, root) {
  let current = schema;
  const seen = new Set();
  while (
    current &&
    typeof current.$ref === "string" &&
    current.$ref.startsWith("#/")
  ) {
    if (seen.has(current.$ref)) return null;
    seen.add(current.$ref);
    current = current.$ref
      .slice(2)
      .split("/")
      .reduce((value, key) => value?.[key], root);
  }
  return current;
}

function compareSchema(actualInput, expected, root, at = "$") {
  const actual = resolve(actualInput, root);
  if (!actual || !expected) return [`${at}: missing schema`];
  if (expected.kind === "const")
    return actual.const === expected.value ? [] : [`${at}: const`];
  if (expected.kind === "enum")
    return exactSet(actual.enum, expected.values) ? [] : [`${at}: enum`];
  if (expected.kind === "pattern") {
    return actual.type === "string" && actual.pattern === expected.pattern
      ? []
      : [`${at}: pattern`];
  }
  if (expected.kind === "timestamp") {
    return actual.type === "string" &&
      actual.format === "date-time" &&
      actual.pattern === TIMESTAMP_PATTERN
      ? []
      : [`${at}: timestamp`];
  }
  if (expected.kind === "type")
    return actual.type === expected.type
      ? []
      : [`${at}: type=${expected.type}`];
  if (expected.kind === "bounded_string") {
    return actual.type === "string" &&
      actual.minLength === expected.minLength &&
      actual.maxLength === expected.maxLength
      ? []
      : [
          `${at}: bounded string ${expected.minLength}..${expected.maxLength}`,
        ];
  }
  if (expected.kind === "integer") {
    if (actual.type !== "integer") return [`${at}: type=integer`];
    if (expected.minimum === undefined)
      return actual.minimum === -9007199254740991 &&
        actual.maximum === 9007199254740991
        ? []
        : [`${at}: portable full-range integer`];
    return actual.minimum === expected.minimum &&
      (expected.maximum === undefined || actual.maximum === expected.maximum)
      ? []
      : [
          `${at}: integer ${expected.minimum}..${expected.maximum ?? "portable-max"}`,
        ];
  }
  if (expected.kind === "any_of") {
    if (
      !Array.isArray(actual.anyOf) ||
      actual.anyOf.length !== expected.values.length
    )
      return [`${at}: exact anyOf union`];
    const unmatched = [...actual.anyOf];
    const errors = [];
    for (const expectedBranch of expected.values) {
      const index = unmatched.findIndex(
        (actualBranch) =>
          compareSchema(actualBranch, expectedBranch, root, at).length === 0,
      );
      if (index === -1)
        errors.push(`${at}: missing anyOf branch ${expectedBranch.kind}`);
      else unmatched.splice(index, 1);
    }
    return errors;
  }
  if (expected.kind === "nullable") {
    if (!Array.isArray(actual.anyOf) || actual.anyOf.length !== 2)
      return [`${at}: nullable union`];
    const nullBranch = actual.anyOf.find((branch) => branch.type === "null");
    const valueBranch = actual.anyOf.find((branch) => branch.type !== "null");
    return nullBranch && valueBranch
      ? compareSchema(valueBranch, expected.value, root, `${at}|value`)
      : [`${at}: nullable branches`];
  }
  if (expected.kind === "array") {
    if (
      actual.type !== "array" ||
      actual.uniqueItems !== true ||
      (expected.maxItems !== undefined &&
        actual.maxItems !== expected.maxItems)
    )
      return [`${at}: unique array`];
    return compareSchema(actual.items, expected.items, root, `${at}[]`);
  }
  if (expected.kind === "object") {
    if (actual.type !== "object" || actual.additionalProperties !== false)
      return [`${at}: closed object`];
    const fields = Object.keys(expected.properties);
    const errors = [];
    if (!exactSet(actual.required, fields))
      errors.push(`${at}: required fields`);
    if (!exactSet(Object.keys(actual.properties || {}), fields))
      errors.push(`${at}: property fields`);
    for (const [field, fieldShape] of Object.entries(expected.properties)) {
      errors.push(
        ...compareSchema(
          actual.properties?.[field],
          fieldShape,
          root,
          `${at}.${field}`,
        ),
      );
    }
    return errors;
  }
  if (expected.kind === "literal_or_uri") {
    if (!Array.isArray(actual.anyOf) || actual.anyOf.length !== 2)
      return [`${at}: literal-or-uri union`];
    const literal = actual.anyOf.find(
      (branch) => branch.const === expected.literal,
    );
    const uri = actual.anyOf.find((branch) => branch.type === "string");
    return literal && uri && uri.pattern === uriPattern(expected.schemes)
      ? []
      : [`${at}: literal-or-uri domain`];
  }
  return [`${at}: unsupported expected shape ${expected.kind}`];
}

function hasExactRoomBindingConditional(schema) {
  return (schema.allOf || []).some(
    (clause) =>
      clause?.if?.properties?.outcome_room_ref?.type === "string" &&
      clause?.then?.properties?.room_admission?.$ref ===
        "#/$defs/roomAdmission" &&
      clause?.else?.properties?.room_admission?.type === "null",
  );
}

function hasTerminalCasPositionConditional(schema, requireComplete = false) {
  return (schema.allOf || []).some((clause) => {
    const statuses = clause?.if?.properties?.admission_status?.enum;
    const properties = clause?.then?.properties;
    const casPositionIsRequired =
      exactSet(statuses, ["admitted", "superseded", "revoked"]) &&
      properties?.admitted_sequence?.type === "integer" &&
      properties?.admitted_sequence?.minimum === 0 &&
      properties?.admitted_sequence?.maximum === 9007199254740991 &&
      properties?.resulting_room_revision?.type === "integer" &&
      properties?.resulting_room_revision?.minimum === 0 &&
      properties?.resulting_room_revision?.maximum === 9007199254740991 &&
      properties?.updated_at?.type === "string" &&
      properties?.updated_at?.format === "date-time" &&
      properties?.updated_at?.pattern === TIMESTAMP_PATTERN;
    if (!casPositionIsRequired || !requireComplete) return casPositionIsRequired;
    return (
      exactSet(Object.keys(properties || {}), TERMINAL_REQUIRED_FIELDS) &&
      properties?.admission_decision_ref?.type === "string" &&
      properties?.admission_receipt_ref?.type === "string" &&
      properties?.resulting_transition_commitment_ref?.type === "string" &&
      properties?.resulting_room_state_root?.type === "string" &&
      properties?.resulting_receipt_root?.type === "string"
    );
  });
}

function hasNonTerminalNoAdmittedTruthConditional(schema) {
  return (schema?.allOf || []).some((clause) => {
    const statuses = clause?.if?.properties?.admission_status?.enum;
    const properties = clause?.then?.properties;
    return (
      exactSet(statuses, NON_TERMINAL_ADMISSION_STATUSES) &&
      exactSet(Object.keys(properties || {}), ADMITTED_TRUTH_FIELDS) &&
      ADMITTED_TRUTH_FIELDS.every(
        (field) => properties?.[field]?.type === "null",
      )
    );
  });
}

function isStatusOnlyAdmittedTruthNegative(
  admittedRecord,
  nonTerminalRecord,
  expectedStatus,
  admissionField = "room_admission",
) {
  const admitted =
    admissionField === null ? admittedRecord : admittedRecord?.[admissionField];
  const nonTerminal =
    admissionField === null
      ? nonTerminalRecord
      : nonTerminalRecord?.[admissionField];
  if (
    admitted?.admission_status !== "admitted" ||
    nonTerminal?.admission_status !== expectedStatus
  )
    return false;
  if (
    !ADMITTED_TRUTH_FIELDS.every(
      (field) =>
        admitted[field] !== null && nonTerminal[field] === admitted[field],
    )
  )
    return false;
  const normalized = JSON.parse(JSON.stringify(nonTerminalRecord));
  const normalizedAdmission =
    admissionField === null ? normalized : normalized[admissionField];
  normalizedAdmission.admission_status = "admitted";
  return JSON.stringify(normalized) === JSON.stringify(admittedRecord);
}

const registryEntries = new Map(
  (registry.contracts || []).map((entry) => [entry.contract_id, entry]),
);
const baseSchema = JSON.parse(
  readFileSync(
    join(SCHEMAS, "room-admitted-object-base.v2.schema.json"),
    "utf8",
  ),
);
const baseErrors = compareSchema(
  baseSchema,
  roomAdmission,
  baseSchema,
  "RoomAdmittedObjectBase",
);
const baseEntry = registryEntries.get(
  "schema://ioi/foundations/room-admitted-object-base/v2",
);
const baseInvariantPath =
  "invariants/room-admitted-object-base.v2.invariants.json";
const baseInvariant = JSON.parse(
  readFileSync(join(SCHEMAS, baseInvariantPath), "utf8"),
);
const baseInvariantRuleIds = [
  "room_admission.decision.required_for_terminal_truth",
  "room_admission.receipt.required_for_terminal_truth",
  "room_admission.transition.required_for_terminal_truth",
  "room_admission.state_root.required_for_terminal_truth",
  "room_admission.receipt_root.required_for_terminal_truth",
  "room_admission.sequence.required_for_terminal_truth",
  "room_admission.revision.required_for_terminal_truth",
  "room_admission.updated_at.required_for_terminal_truth",
];
const basePositivePath =
  "fixtures/room-admitted-object-base-v2/positive-proposed-zero-revision.json";
const baseNegativePath =
  "fixtures/room-admitted-object-base-v2/negative-agentgres-decision-ref.json";
const baseMissingCasPath =
  "fixtures/room-admitted-object-base-v2/negative-admitted-missing-cas-position.json";
const baseAdmittedPath =
  "fixtures/room-admitted-object-base-v2/positive-admitted.json";
const baseNonTerminalPath =
  "fixtures/room-admitted-object-base-v2/negative-proposed-carries-admitted-roots.json";
const basePositive = JSON.parse(
  readFileSync(join(SCHEMAS, basePositivePath), "utf8"),
);
const baseNegative = JSON.parse(
  readFileSync(join(SCHEMAS, baseNegativePath), "utf8"),
);
const baseAdmitted = JSON.parse(
  readFileSync(join(SCHEMAS, baseAdmittedPath), "utf8"),
);
const baseNonTerminal = JSON.parse(
  readFileSync(join(SCHEMAS, baseNonTerminalPath), "utf8"),
);
const outcomeRoomSchema = JSON.parse(
  readFileSync(join(SCHEMAS, "outcome-room.v2.schema.json"), "utf8"),
);
const workResultSchema = JSON.parse(
  readFileSync(join(SCHEMAS, "work-result.v2.schema.json"), "utf8"),
);
const outcomeDeltaSchema = JSON.parse(
  readFileSync(join(SCHEMAS, "outcome-delta.v2.schema.json"), "utf8"),
);
const collaborativeWorkGraphSchema = JSON.parse(
  readFileSync(
    join(SCHEMAS, "collaborative-work-graph.v1.schema.json"),
    "utf8",
  ),
);
const discussionProjectionSchema = JSON.parse(
  readFileSync(
    join(SCHEMAS, "outcome-room-discussion-projection.v1.schema.json"),
    "utf8",
  ),
);
const exactArrayCapErrors = (schema, expected, label) =>
  Object.entries(expected).flatMap(([field, maximum]) => {
    const property = schema.properties?.[field];
    return property?.type === "array" &&
      property?.uniqueItems === true &&
      property?.maxItems === maximum
      ? []
      : [`${label}.${field}: unique array capped at ${maximum}`];
  });
const outcomeRoomErrors = [
  ...compareSchema(
    outcomeRoomSchema,
    shape.object(OUTCOME_ROOM),
    outcomeRoomSchema,
    "OutcomeRoom",
  ),
  ...(outcomeRoomSchema.$defs?.refs?.type === "array" &&
  outcomeRoomSchema.$defs.refs.uniqueItems === true &&
  outcomeRoomSchema.$defs.refs.maxItems === 64
    ? []
    : ["OutcomeRoom.$defs.refs: unique array capped at 64"]),
];
const workResultErrors = [
  ...compareSchema(
    workResultSchema,
    shape.object(WORK_RESULT),
    workResultSchema,
    "WorkResult",
  ),
  ...compareSchema(
    workResultSchema.$defs?.roomAdmission,
    roomAdmission,
    workResultSchema,
    "WorkResult.$defs.roomAdmission",
  ),
];
const outcomeDeltaErrors = [
  ...compareSchema(
    outcomeDeltaSchema,
    shape.object(OUTCOME_DELTA),
    outcomeDeltaSchema,
    "OutcomeDelta",
  ),
  ...compareSchema(
    outcomeDeltaSchema.$defs?.roomAdmission,
    roomAdmission,
    outcomeDeltaSchema,
    "OutcomeDelta.$defs.roomAdmission",
  ),
];
const graphProjectionErrors = exactArrayCapErrors(
  collaborativeWorkGraphSchema,
  {
    member_goal_run_refs: 64,
    participant_refs: 64,
    frontier_item_refs: 64,
    work_claim_refs: 64,
    attempt_refs: 64,
    finding_refs: 64,
    verifier_challenge_refs: 64,
    work_result_refs: 64,
    outcome_delta_refs: 64,
    source_admission_receipt_refs: 128,
    information_flow_label_refs: 64,
  },
  "CollaborativeWorkGraph",
);
const discussionProjectionErrors = exactArrayCapErrors(
  discussionProjectionSchema,
  {
    source_admission_receipt_refs: 128,
    information_flow_label_refs: 64,
    permitted_subject_refs: 67,
    message_refs: 64,
    redaction_summary_refs: 64,
  },
  "OutcomeRoomDiscussionProjection",
);
const outcomeRoomEntry = registryEntries.get(
  "schema://ioi/foundations/outcome-room/v2",
);
const workResultEntry = registryEntries.get(
  "schema://ioi/foundations/work-result/v2",
);
const outcomeDeltaEntry = registryEntries.get(
  "schema://ioi/foundations/outcome-delta/v2",
);
const graphProjectionEntry = registryEntries.get(
  "schema://ioi/foundations/collaborative-work-graph/v1",
);
const discussionProjectionEntry = registryEntries.get(
  "schema://ioi/foundations/outcome-room-discussion-projection/v1",
);
const outcomeRoomPositivePath =
  "fixtures/outcome-room-v2/positive-hosted-active.json";
const outcomeRoomWrongDomainPath =
  "fixtures/outcome-room-v2/negative-owner-scheme.json";
const outcomeRoomOverCardinalityPath =
  "fixtures/outcome-room-v2/negative-over-cardinality.json";
const outcomeRoomOverObjectivePath =
  "fixtures/outcome-room-v2/negative-over-objective.json";
const outcomeRoomMaxSequencePath =
  "fixtures/outcome-room-v2/negative-max-sequence.json";
const outcomeRoomOverReplayPath =
  "fixtures/outcome-room-v2/negative-over-replay-cardinality.json";
const workResultDirectPath =
  "fixtures/work-result-v2/positive-direct-non-room.json";
const workResultArrayPath =
  "fixtures/work-result-v2/negative-array-uncertainty.json";
const workResultAdmittedPath =
  "fixtures/work-result-v2/positive-hosted-admitted.json";
const workResultNonTerminalPath =
  "fixtures/work-result-v2/negative-evaluating-carries-admitted-roots.json";
const workResultOverCardinalityPath =
  "fixtures/work-result-v2/negative-over-cardinality.json";
const outcomeDeltaDirectPath =
  "fixtures/outcome-delta-v2/positive-direct-non-room.json";
const outcomeDeltaAdmittedPath =
  "fixtures/outcome-delta-v2/positive-hosted-admitted.json";
const outcomeDeltaNonTerminalPath =
  "fixtures/outcome-delta-v2/negative-rejected-carries-admitted-roots.json";
const outcomeDeltaOverCardinalityPath =
  "fixtures/outcome-delta-v2/negative-over-cardinality.json";
const graphOverCardinalityPath =
  "fixtures/collaborative-work-graph-v1/negative-over-cardinality.json";
const graphOverReceiptsPath =
  "fixtures/collaborative-work-graph-v1/negative-over-source-receipts.json";
const discussionOverSubjectsPath =
  "fixtures/outcome-room-discussion-projection-v1/negative-over-permitted-subjects.json";
const discussionOverReceiptsPath =
  "fixtures/outcome-room-discussion-projection-v1/negative-over-source-receipts.json";
const outcomeRoomPositive = JSON.parse(
  readFileSync(join(SCHEMAS, outcomeRoomPositivePath), "utf8"),
);
const outcomeRoomWrongDomain = JSON.parse(
  readFileSync(join(SCHEMAS, outcomeRoomWrongDomainPath), "utf8"),
);
const outcomeRoomOverCardinality = JSON.parse(
  readFileSync(join(SCHEMAS, outcomeRoomOverCardinalityPath), "utf8"),
);
const outcomeRoomOverObjective = JSON.parse(
  readFileSync(join(SCHEMAS, outcomeRoomOverObjectivePath), "utf8"),
);
const outcomeRoomMaxSequence = JSON.parse(
  readFileSync(join(SCHEMAS, outcomeRoomMaxSequencePath), "utf8"),
);
const outcomeRoomOverReplay = JSON.parse(
  readFileSync(join(SCHEMAS, outcomeRoomOverReplayPath), "utf8"),
);
const workResultDirect = JSON.parse(
  readFileSync(join(SCHEMAS, workResultDirectPath), "utf8"),
);
const workResultArray = JSON.parse(
  readFileSync(join(SCHEMAS, workResultArrayPath), "utf8"),
);
const workResultAdmitted = JSON.parse(
  readFileSync(join(SCHEMAS, workResultAdmittedPath), "utf8"),
);
const workResultNonTerminal = JSON.parse(
  readFileSync(join(SCHEMAS, workResultNonTerminalPath), "utf8"),
);
const workResultOverCardinality = JSON.parse(
  readFileSync(join(SCHEMAS, workResultOverCardinalityPath), "utf8"),
);
const outcomeDeltaDirect = JSON.parse(
  readFileSync(join(SCHEMAS, outcomeDeltaDirectPath), "utf8"),
);
const outcomeDeltaAdmitted = JSON.parse(
  readFileSync(join(SCHEMAS, outcomeDeltaAdmittedPath), "utf8"),
);
const outcomeDeltaNonTerminal = JSON.parse(
  readFileSync(join(SCHEMAS, outcomeDeltaNonTerminalPath), "utf8"),
);
const outcomeDeltaOverCardinality = JSON.parse(
  readFileSync(join(SCHEMAS, outcomeDeltaOverCardinalityPath), "utf8"),
);
const graphOverCardinality = JSON.parse(
  readFileSync(join(SCHEMAS, graphOverCardinalityPath), "utf8"),
);
const graphOverReceipts = JSON.parse(
  readFileSync(join(SCHEMAS, graphOverReceiptsPath), "utf8"),
);
const discussionOverSubjects = JSON.parse(
  readFileSync(join(SCHEMAS, discussionOverSubjectsPath), "utf8"),
);
const discussionOverReceipts = JSON.parse(
  readFileSync(join(SCHEMAS, discussionOverReceiptsPath), "utf8"),
);
const releasePattern = new RegExp(
  outcomeRoomSchema.properties.manifest_ref.pattern,
);
const coreErrors = [
  ...baseErrors,
  ...outcomeRoomErrors,
  ...workResultErrors,
  ...outcomeDeltaErrors,
  ...graphProjectionErrors,
  ...discussionProjectionErrors,
];
check(
  "M4 room, child, graph, and discussion contracts match canonical value domains and retain bounded adversarial coverage",
  baseErrors.length === 0 &&
    baseEntry?.positive_fixture_refs?.includes(basePositivePath) &&
    baseEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === baseNegativePath &&
        fixture.expected_failure === "schema",
    ) &&
    baseEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === baseMissingCasPath &&
        fixture.expected_failure === "schema",
    ) &&
    baseEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === baseNonTerminalPath &&
        fixture.expected_failure === "schema",
    ) &&
    baseEntry?.cross_field_invariant_refs?.length === 1 &&
    baseEntry.cross_field_invariant_refs[0]?.invariant_id ===
      "invariant://ioi/foundations/room-admitted-object-base/cas/v2" &&
    baseEntry.cross_field_invariant_refs[0]?.path === baseInvariantPath &&
    exactSet(
      baseInvariant.rules?.map((rule) => rule.rule_id),
      baseInvariantRuleIds,
    ) &&
    hasTerminalCasPositionConditional(baseSchema) &&
    hasNonTerminalNoAdmittedTruthConditional(baseSchema) &&
    isStatusOnlyAdmittedTruthNegative(
      baseAdmitted,
      baseNonTerminal,
      "proposed",
      null,
    ) &&
    basePositive.expected_room_revision === 0 &&
    basePositive.resulting_room_revision === null &&
    basePositive.admission_decision_ref === null &&
    baseNegative.admission_decision_ref.startsWith("agentgres://") &&
    outcomeRoomErrors.length === 0 &&
    outcomeRoomEntry?.schema_ref === "outcome-room.v2.schema.json" &&
    outcomeRoomEntry?.canonical_owner_ref ===
      "canon://docs/architecture/foundations/objects/collaborative-pursuit.md#outcomeroomenvelope" &&
    outcomeRoomEntry?.positive_fixture_refs?.includes(
      outcomeRoomPositivePath,
    ) &&
    outcomeRoomEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === outcomeRoomWrongDomainPath &&
        fixture.expected_failure === "schema",
    ) &&
    outcomeRoomEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === outcomeRoomOverCardinalityPath &&
        fixture.expected_failure === "schema",
    ) &&
    outcomeRoomEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === outcomeRoomOverObjectivePath &&
        fixture.expected_failure === "schema",
    ) &&
    outcomeRoomEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === outcomeRoomMaxSequencePath &&
        fixture.expected_failure === "schema",
    ) &&
    outcomeRoomEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === outcomeRoomOverReplayPath &&
        fixture.expected_failure === "schema",
    ) &&
    outcomeRoomPositive.manifest_ref.endsWith("/release/2.1.0") &&
    outcomeRoomWrongDomain.owner_or_sponsor_ref.startsWith("artifact://") &&
    outcomeRoomOverCardinality.constraint_refs.length === 65 &&
    outcomeRoomOverObjective.objective.length === 4097 &&
    outcomeRoomMaxSequence.latest_sequence === 128 &&
    outcomeRoomOverReplay.admission_and_replay_refs.length === 129 &&
    releasePattern.test("package://ioi/outcome-room/release/2.1.0") &&
    releasePattern.test(
      `package://ioi/outcome-room/release/sha256:${"a".repeat(64)}`,
    ) &&
    !releasePattern.test("package://ioi/outcome-room/version/2.1.0") &&
    workResultErrors.length === 0 &&
    hasExactRoomBindingConditional(workResultSchema) &&
    workResultEntry?.canonical_owner_ref ===
      "canon://docs/architecture/foundations/objects/work-results-and-lifecycle.md#workresultenvelope-and-outcomedeltaenvelope" &&
    workResultEntry?.positive_fixture_refs?.includes(workResultDirectPath) &&
    workResultEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === workResultArrayPath &&
        fixture.expected_failure === "schema",
    ) &&
    workResultEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === workResultNonTerminalPath &&
        fixture.expected_failure === "schema",
    ) &&
    workResultEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === workResultOverCardinalityPath &&
        fixture.expected_failure === "schema",
    ) &&
    hasNonTerminalNoAdmittedTruthConditional(
      workResultSchema.$defs?.roomAdmission,
    ) &&
    isStatusOnlyAdmittedTruthNegative(
      workResultAdmitted,
      workResultNonTerminal,
      "evaluating",
    ) &&
    workResultDirect.outcome_room_ref === null &&
    workResultDirect.room_admission === null &&
    Array.isArray(workResultArray.uncertainty) &&
    workResultOverCardinality.information_flow_label_refs.length === 65 &&
    outcomeDeltaErrors.length === 0 &&
    hasExactRoomBindingConditional(outcomeDeltaSchema) &&
    outcomeDeltaEntry?.canonical_owner_ref ===
      "canon://docs/architecture/foundations/objects/work-results-and-lifecycle.md#workresultenvelope-and-outcomedeltaenvelope" &&
    outcomeDeltaEntry?.positive_fixture_refs?.includes(
      outcomeDeltaDirectPath,
    ) &&
    outcomeDeltaEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === outcomeDeltaNonTerminalPath &&
        fixture.expected_failure === "schema",
    ) &&
    outcomeDeltaEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === outcomeDeltaOverCardinalityPath &&
        fixture.expected_failure === "schema",
    ) &&
    hasNonTerminalNoAdmittedTruthConditional(
      outcomeDeltaSchema.$defs?.roomAdmission,
    ) &&
    isStatusOnlyAdmittedTruthNegative(
      outcomeDeltaAdmitted,
      outcomeDeltaNonTerminal,
      "rejected",
    ) &&
    outcomeDeltaDirect.outcome_room_ref === null &&
    outcomeDeltaDirect.room_admission === null &&
    outcomeDeltaOverCardinality.information_flow_label_refs.length === 65 &&
    graphProjectionErrors.length === 0 &&
    graphProjectionEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === graphOverCardinalityPath &&
        fixture.expected_failure === "schema",
    ) &&
    graphProjectionEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === graphOverReceiptsPath &&
        fixture.expected_failure === "schema",
    ) &&
    graphOverCardinality.work_result_refs.length === 65 &&
    graphOverReceipts.source_admission_receipt_refs.length === 129 &&
    discussionProjectionErrors.length === 0 &&
    discussionProjectionEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === discussionOverSubjectsPath &&
        fixture.expected_failure === "schema",
    ) &&
    discussionProjectionEntry?.negative_fixture_refs?.some(
      (fixture) =>
        fixture.path === discussionOverReceiptsPath &&
        fixture.expected_failure === "schema",
    ) &&
    discussionOverSubjects.permitted_subject_refs.length === 68 &&
    discussionOverReceipts.source_admission_receipt_refs.length === 129,
  `${coreErrors.slice(0, 6).join(", ") || outcomeRoomPositivePath}; ${workResultDirectPath}; ${outcomeDeltaDirectPath}`,
);

for (const [stem, family] of Object.entries(FAMILIES)) {
  const contractId = `schema://ioi/foundations/${stem.replace(".v2", "/v2")}`;
  const schema = JSON.parse(
    readFileSync(join(SCHEMAS, `${stem}.schema.json`), "utf8"),
  );
  const entry = registryEntries.get(contractId);
  const inlineErrors = compareSchema(
    schema.$defs?.roomAdmission,
    roomAdmission,
    schema,
    `${stem}.$defs.roomAdmission`,
  );
  const admittedFixture = JSON.parse(
    readFileSync(join(SCHEMAS, family.admittedFixture), "utf8"),
  );
  const nonTerminalFixture = JSON.parse(
    readFileSync(join(SCHEMAS, family.nonTerminalFixture), "utf8"),
  );
  check(
    `${entry?.canonical_name || stem}: registry, fixtures, invariant, and embedded 18-field base resolve canonically`,
    schema.$id === contractId &&
      entry?.schema_ref === `${stem}.schema.json` &&
      entry?.canonical_owner_ref ===
        `canon://docs/architecture/foundations/objects/collaborative-pursuit.md#${family.anchor}` &&
      entry.positive_fixture_refs?.every((fixture) =>
        existsSync(join(SCHEMAS, fixture)),
      ) &&
      entry.negative_fixture_refs?.every((fixture) =>
        existsSync(join(SCHEMAS, fixture.path)),
      ) &&
      Array.isArray(entry.cross_field_invariant_refs) &&
      entry.cross_field_invariant_refs.length === 1 &&
      entry.cross_field_invariant_refs[0]?.invariant_id ===
        family.invariant.invariant_id &&
      entry.cross_field_invariant_refs[0]?.path === family.invariant.path &&
      existsSync(join(SCHEMAS, family.invariant.path)) &&
      inlineErrors.length === 0 &&
      hasTerminalCasPositionConditional(schema.$defs?.roomAdmission, true) &&
      hasNonTerminalNoAdmittedTruthConditional(schema.$defs?.roomAdmission) &&
      entry.negative_fixture_refs?.some(
        (fixture) =>
          fixture.path === family.nonTerminalFixture &&
          fixture.expected_failure === "schema",
      ) &&
      isStatusOnlyAdmittedTruthNegative(
        admittedFixture,
        nonTerminalFixture,
        family.nonTerminalStatus,
      ),
    inlineErrors.slice(0, 3).join(", ") || contractId,
  );
  const semanticErrors = compareSchema(
    schema,
    shape.object(family.properties),
    schema,
    entry?.canonical_name || stem,
  );
  check(
    `${entry?.canonical_name || stem}: every property matches its canonical semantic value domain`,
    semanticErrors.length === 0,
    semanticErrors.slice(0, 5).join(", "),
  );
  const positive = JSON.parse(
    readFileSync(join(SCHEMAS, family.positiveFixture), "utf8"),
  );
  const negative = JSON.parse(
    readFileSync(join(SCHEMAS, family.negativeFixture), "utf8"),
  );
  check(
    `${entry?.canonical_name || stem}: registry retains the required positive and wrong-domain adversarial fixtures`,
    entry?.positive_fixture_refs?.includes(family.positiveFixture) &&
      entry?.negative_fixture_refs?.some(
        (fixture) =>
          fixture.path === family.negativeFixture &&
          fixture.expected_failure === "schema",
      ) &&
      family.fixtureSemantics(positive, negative),
    `${family.positiveFixture}; ${family.negativeFixture}`,
  );
}

let failed = 0;
for (const result of results) {
  console.log(
    `  ${result.pass ? "PASS" : "FAIL"}  ${result.name}${result.detail ? `  (${result.detail})` : ""}`,
  );
  if (!result.pass) failed += 1;
}
console.log(`\n${results.length - failed}/${results.length} passed`);
const coverageMismatch = results.length !== EXPECTED_CHECKS;
if (coverageMismatch)
  console.error(
    `FAIL verifier coverage changed: expected ${EXPECTED_CHECKS}, got ${results.length}`,
  );
console.log(
  `M4 room contract depth: ${failed || coverageMismatch ? "FAIL" : "OK"}`,
);
process.exit(failed || coverageMismatch ? 1 : 0);
