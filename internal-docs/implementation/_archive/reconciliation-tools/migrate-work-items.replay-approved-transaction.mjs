#!/usr/bin/env node

// Approved SA-2/SA-7/SA-9 one-time migration. The script preserves every
// pre-existing status exactly, enriches the full record contract, and creates
// planning-only records as proposed. It emits no exit log and cannot promote a
// record. Once its dated finalization artifact exists, routine replay is
// permanently refused; future records are maintained by normal reviewed status
// transactions, not by reapplying reconciliation templates.

import fs from "node:fs";
import path from "node:path";
import {
  implementationRoot,
  readJson,
  repoRoot,
  sha256,
  sha256File,
  stableJson,
} from "./lib.mjs";

const workItemsRoot = path.join(implementationRoot, "work-items");
const finalizationPath = path.join(
  implementationRoot,
  "audits/reconciliation/work-item-migration-finalization.v1.json",
);
if (process.argv.length !== 3 || process.argv[2] !== "--replay-approved-transaction") {
  process.stderr.write("usage: migrate-work-items.mjs --replay-approved-transaction (one-time reconciliation only)\n");
  process.exit(2);
}
if (fs.existsSync(finalizationPath)) {
  process.stderr.write("work-item migration refused: the approved one-time reconciliation is finalized; edit records only through a reviewed live status/planning transaction\n");
  process.exit(1);
}
const actionPlanPath = path.join(implementationRoot, "audits/2026-07-22-directory-unification-plan.md");
const preservationPath = path.join(implementationRoot, "audits/reconciliation/work-item-status-preservation.v1.json");
const plan = fs.readFileSync(actionPlanPath, "utf8");
const contractRegistry = readJson(path.join(repoRoot, "docs/architecture/_meta/schemas/architecture-contract-registry.v1.json"));
const contractRouting = readJson(path.join(implementationRoot, "tools/contract-owner-locators.v1.json"));
const registeredContractsByName = new Map();
for (const contract of contractRegistry.contracts) {
  const entries = registeredContractsByName.get(contract.canonical_name) ?? [];
  entries.push(contract);
  registeredContractsByName.set(contract.canonical_name, entries);
}

const OWNER_CODES = {
  META: [
    "docs/architecture/_meta/start-here.md",
    "docs/architecture/_meta/source-of-truth-map.md",
    "docs/architecture/_meta/current-canon-defaults.md",
    "docs/architecture/_meta/public-web-estate.md",
    "docs/architecture/_meta/schemas/architecture-contract-registry.v1.json",
    "docs/decisions/README.md",
  ],
  SYSTEM: [
    "docs/architecture/foundations/governed-autonomous-systems.md",
    "docs/architecture/foundations/common-objects-and-envelopes.md",
    "docs/architecture/foundations/invariants.md",
  ],
  SECURITY: [
    "docs/architecture/foundations/verifiable-bounded-agency.md",
    "docs/architecture/foundations/security-privacy-policy-invariants.md",
  ],
  SEMANTIC: ["docs/architecture/foundations/domain-ontologies-and-data-recipes.md"],
  LEARNING: [
    "docs/architecture/foundations/institutional-learning-boundary.md",
    "docs/architecture/foundations/bounded-recursive-improvement.md",
    "docs/architecture/components/daemon-runtime/portable-memory-vault.md",
    "docs/architecture/components/daemon-runtime/improvement-governance-gates.md",
  ],
  WORKERS: [
    "docs/architecture/foundations/mixture-of-workers.md",
    "docs/architecture/foundations/worker-training-lifecycle.md",
    "docs/architecture/domains/aiagent/digital-worker-ontology.md",
    "docs/architecture/domains/aiagent/vertical-ontology-packs.md",
    "docs/architecture/domains/aiagent/integration-surface-taxonomy.md",
    "docs/architecture/domains/aiagent/managed-worker-instance-lifecycle.md",
    "docs/architecture/domains/aiagent/managed-agent-console-contract.md",
    "docs/architecture/domains/aiagent/worker-endpoints.md",
    "docs/architecture/domains/aiagent/worker-marketplace.md",
  ],
  ECON: [
    "docs/architecture/foundations/economic-flywheel-and-pricing-boundaries.md",
    "docs/architecture/domains/marketplace-neutrality.md",
  ],
  ASSURANCE: ["docs/architecture/foundations/ecosystem-assurance-certification-liability.md"],
  PHYSICAL: [
    "docs/architecture/foundations/physical-action-safety.md",
    "docs/architecture/components/daemon-runtime/embodied-runtime.md",
  ],
  AIIP: ["docs/architecture/foundations/aiip.md"],
  L1: [
    "docs/architecture/foundations/ioi-l1-mainnet.md",
    "docs/architecture/foundations/ioi-l1-contract-interfaces.md",
  ],
  AGENTGRES: [
    "docs/architecture/components/agentgres/doctrine.md",
    "docs/architecture/components/agentgres/api-object-model.md",
    "docs/architecture/components/agentgres/artifact-ref-plane.md",
    "docs/architecture/components/agentgres/postgres-bridge-and-readiness-contract.md",
    "docs/architecture/components/agentgres/projection-system-reference.md",
  ],
  DAEMON: [
    "docs/architecture/components/daemon-runtime/doctrine.md",
    "docs/architecture/components/daemon-runtime/api.md",
    "docs/architecture/components/daemon-runtime/default-harness-profile.md",
    "docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md",
    "docs/architecture/components/daemon-runtime/platform-operability.md",
  ],
  MEASURED: [
    "docs/architecture/components/daemon-runtime/runtime-nodes-tee-depin.md",
    "docs/architecture/components/daemon-runtime/task-capsule-protocol.md",
    "docs/architecture/components/daemon-runtime/private-workspace-ctee.md",
    "docs/architecture/components/daemon-runtime/hypervisoros.md",
  ],
  SURFACES: ["docs/architecture/components/hypervisor/core-clients-surfaces.md"],
  ENVIRONMENTS: [
    "docs/architecture/components/hypervisor/providers-and-environments.md",
    "docs/architecture/components/hypervisor/byo-provider-plane.md",
  ],
  IDENTITY: ["docs/architecture/components/hypervisor/identity-access-and-metering.md"],
  FOUNDRY: ["docs/architecture/components/hypervisor/foundry.md"],
  EVALUATIONS: ["docs/architecture/components/hypervisor/evaluations.md"],
  IMPROVEMENT: ["docs/architecture/components/hypervisor/improvement.md"],
  CONNECTORS: [
    "docs/architecture/components/connectors-tools/doctrine.md",
    "docs/architecture/components/connectors-tools/contracts.md",
  ],
  MODELS: [
    "docs/architecture/components/model-router/doctrine.md",
    "docs/architecture/components/model-router/api-byok-mounting.md",
  ],
  WALLET: [
    "docs/architecture/components/wallet-network/doctrine.md",
    "docs/architecture/components/wallet-network/api-authority-scopes.md",
    "docs/architecture/components/wallet-network/product-exchange-risk.md",
  ],
  STORAGE: [
    "docs/architecture/components/storage-backends/doctrine.md",
    "docs/architecture/components/storage-backends/filecoin-cas.md",
  ],
  ROOMS: [
    "docs/architecture/domains/ioi-ai/control-plane.md",
    "docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md",
  ],
  SERVICES: [
    "docs/architecture/domains/sas/service-endpoints.md",
    "docs/architecture/domains/sas/service-marketplace.md",
  ],
  DECENTRALIZED: [
    "docs/architecture/domains/decentralized/README.md",
    "docs/architecture/domains/decentralized/cloud.md",
    "docs/architecture/domains/decentralized/exchange.md",
    "docs/architecture/domains/decentralized/trade.md",
  ],
};

const STAGE_CODES = {
  M0: ["META"],
  M1: ["SYSTEM", "SECURITY", "SURFACES"],
  M2: ["SYSTEM", "AGENTGRES", "ENVIRONMENTS", "MEASURED"],
  M3: ["SYSTEM", "DAEMON", "CONNECTORS", "AGENTGRES"],
  M4: ["ROOMS", "SYSTEM", "AGENTGRES"],
  M5: ["ROOMS", "IDENTITY", "WALLET", "CONNECTORS"],
  M6: ["SURFACES", "DAEMON"],
  M7: ["SEMANTIC", "AGENTGRES", "SECURITY"],
  M8: ["LEARNING", "MODELS", "FOUNDRY", "EVALUATIONS", "IMPROVEMENT"],
  M9: ["SURFACES", "DAEMON", "WALLET", "STORAGE", "ASSURANCE"],
  M10: ["SYSTEM", "AGENTGRES", "ENVIRONMENTS", "MEASURED"],
  M11: ["PHYSICAL", "FOUNDRY", "EVALUATIONS", "ASSURANCE"],
  M12: ["AIIP", "ROOMS", "SEMANTIC", "SECURITY"],
  M13: ["AIIP", "WORKERS", "ECON", "ROOMS"],
  M14: ["SERVICES", "ECON", "L1", "ASSURANCE", "WALLET"],
  FUTURE: ["PHYSICAL", "ASSURANCE", "FOUNDRY"],
};

const NAME_CORRECTIONS = {
  ActionContract: "OntologyActionContract",
  ActivationTransaction: "EmbodiedGraphActivationTransaction",
  EmbodiedUnit: "EmbodiedUnitIdentity",
  NativeProfile: "NativeEmbodiedRuntimeProfile",
  PhysicalStream: "PhysicalStreamContract",
  ResourceGroup: "EmbodiedResourceGroup",
  RuntimeGraph: "EmbodiedRuntimeGraphManifest",
  RuntimeGraphManifest: "EmbodiedRuntimeGraphManifest",
  ProjectDiscovery: "HypervisorProjectDiscoveryProposal",
  StartupPlan: "HypervisorEnvironmentStartupPlan",
  ModelSpec: "FoundrySpec",
  RunPlan: "FoundryRunPlan",
  SurfaceDefinition: "HypervisorApplicationSurfaceRegistration",
  SurfaceRelease: "HypervisorSurfaceReleaseRecord",
  SurfaceInstallation: "HypervisorSurfaceInstallationBinding",
  SystemInterfaceBinding: "HypervisorSystemInterfaceBinding",
  SurfaceServingRecord: "HypervisorSurfaceServingBinding",
  SurfaceAliasReceipt: "HypervisorRouteAliasRegistration",
  SystemsProjection: "HypervisorSystemsProjection",
  WorkProjection: "HypervisorProductSurfaceProjection",
  EmbodiedRuntimeUnit: "EmbodiedUnitIdentity",
  EmbodiedRuntimeGroup: "EmbodiedResourceGroup",
  EmbodiedNativeProfile: "NativeEmbodiedRuntimeProfile",
  EmbodiedRuntimeGraph: "EmbodiedRuntimeGraphManifest",
  SensorStreamContract: "PhysicalStreamContract",
  LocalSafetySupervisor: "LocalControlSupervisor",
  FleetAllocation: "FleetMissionAllocationLease",
  SpacetimeReservation: "SpacetimeReservationLease",
  AssuranceCase: "EmbodiedDeploymentAssuranceCase",
};

const SA9_STAGE = {
  "production-information-flow-and-declassification": "M3",
  "production-receipt-checkpoint-and-offline-proof": "M3",
  "project-discovery-startup-and-session-chain": "M2",
  "managed-billing-work-credits-and-supplier-reconciliation": "M8",
  "dispute-adjudication-remedy-kernel": "M12",
  "foundry-evaluations-production-loop": "M8",
  "worker-training-and-local-marketplace-supply": "M8",
  "connected-worker-capability-supply-and-hiring": "M14",
  "platform-operability-observability-and-incidents": "M9",
  "hypervisoros-ctee-task-capsule-attestation": "M9",
  "agentgres-production-readiness-and-branch-effects": "M3",
  "ecosystem-assurance-and-public-claim-estate": "M14",
  "live-embodied-promotion": "FUTURE",
  "sdk-cli-adk-odk-builder-journey": "M6",
  "storage-profile-repair-and-availability": "M2",
  "marketplace-neutral-routing-contribution-accounting": "M8",
  "decentralized-profile-admission-and-exit": "M14",
};

const AGGREGATES = new Set([
  "m0-program-control-selected-profile-exit-proof",
  "m1-5-protected-transitions",
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

const STAGE_AGGREGATE = {
  M0: "m0-program-control-selected-profile-exit-proof",
  M1: "m1-selected-profile-exit-proof",
  M2: "m2-selected-profile-exit-proof",
  M3: "m3-direct-path-and-exit-proof",
  M4: "m4-outcome-room-system-spine",
  M5: "m5-selected-profile-exit-proof",
  M6: "m6-product-surface-and-typed-workspaces",
  M7: "m7-semantic-definition-action-plane",
  M8: "m8-model-supply-route-substitution-and-selected-exit",
  M9: "m9-selected-profile-aggregate-exit-and-claim-publication",
  M10: "m10-two-failure-domain-continuity",
  M11: "m11-selected-profile-exit-proof",
  M12: "m12-selected-profile-exit-proof",
  M13: "m13-selected-profile-aggregate-exit",
  M14: "m14-selected-profile-aggregate-exit",
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

const PREVIOUS_STAGE = {
  M1: "M0", M2: "M1", M3: "M2", M4: "M3", M5: "M4", M6: "M5",
  M7: "M6", M8: "M7", M9: "M8", M10: "M9", M11: "M10",
  M12: "M11", M13: "M12", M14: "M13", FUTURE: "M11",
};

const STAGE_PROFILE = {
  M0: "Private program-control and selected-profile planning; no product effect or capability claim.",
  M1: "One single-authority, single-node bounded System package/genesis/lifecycle profile.",
  M2: "The selected single-node deployment with explicit observed membership, writer epoch, routes, restore, and cleanup truth.",
  M3: "Generic direct and System-bound GoalRun pursuit with replaceable Sessions, workers, models, and harnesses.",
  M4: "One hosted OutcomeRoom compiled as a bounded System; no external participant or federation claim.",
  M5: "Hosted room participation with one proposal-only local agent, bounded leases, and portable filtered exit.",
  M6: "The canonical five-workspace Hypervisor shell and contract-pulled application registration over real M1–M5 reads.",
  M7: "One System-local versioned ontology/data/action profile; compatibility and mapping grant no authority.",
  M8: "One enterprise-owned learning boundary, provider-exit trial, and finite order-zero improvement Campaign.",
  M9: "The selected single-node sovereign-local terminal product journey; managed authority is an optional separate overlay.",
  M10: "One logical System across two admitted failure domains; no consensus or useful-distribution claim.",
  M11: "Useful same-System distribution plus simulation/SIL/HIL/shadow embodied proof; no live actuator or E1+ claim.",
  M12: "Two separately sovereign Systems negotiating exact-root AIIP terms; no surplus or M13 claim.",
  M13: "A preregistered, independently operated two-sovereign trial with safe decline and portable exit; no M14 service claim.",
  M14: "Demand-gated connected/secured service planning with an explicit valid no-L1 branch and no mainnet/native-asset claim.",
  FUTURE: "Conditional live embodied promotion outside the active M0–M14 closure path pending a later explicit sequencer amendment.",
};

const STAGE_EFFECT = {
  M0: ["private plan/check projection write", "private deterministic writer only", "none; workflow evidence never authorizes product effects", "unsigned checker report and source manifest", "refuse mutation on unknown source, owner, status, or exit evidence"],
  M1: ["bounded-System genesis or protected lifecycle transition", "Hypervisor daemon bounded-System admission/finalization path", "local/domain policy plus the applicable exact authority grant", "Agentgres operation and ReceiptEnvelope", "deny before admission on stale head, wrong owner, changed body, or revoked authority"],
  M2: ["membership, writer-fence, route, restore, activation, or cleanup transition", "daemon owner-qualified membership/environment change-plan invoker", "System governance and applicable exact authority; node placement grants nothing", "transition operation, head/root, and effect receipt", "zero final-invoker calls for foreign/stale/deposed/caller-authored context"],
  M3: ["runtime work/tool invocation or lifecycle transition", "daemon RuntimeToolContract/work-lifecycle final invoker", "local/domain policy and applicable grant; harness/MCP transports grant nothing", "invocation/result operation and ReceiptEnvelope", "deny stale context, widened lease, duplicate idempotency key, or cancelled ancestor"],
  M4: ["OutcomeRoom shared-graph admission", "room owner admission followed by Agentgres append", "room/System governance; UI and participant evidence do not self-admit", "room transition receipt and resulting root", "deny wrong System, stale predecessor, changed child body, or direct client write"],
  M5: ["participant, claim, result, challenge, or closeout transition", "room participant/frontier/result owner admission path", "explicit participant/claim/authority leases; pairing grants none", "admission/acceptance receipt and room root", "deny replay, expired/revoked lease, wrong origin, self-acceptance, or disputed settlement"],
  M6: ["consequential product control", "the owning daemon/domain final invoker named by the compiled action descriptor", "local/domain policy and applicable wallet grant or sealed intent", "owner operation plus effect ReceiptEnvelope", "disabled/denied/unavailable state and zero invoker calls; no fixture fallback"],
  M7: ["semantic transformation or ontology-bound action", "daemon ontology/data/action-contract final invoker", "local/domain policy plus applicable grant; semantic compatibility grants nothing", "TransformationRun/action operation and ReceiptEnvelope", "deny unknown version, stale recipe, mapping dispute, failed oracle, or IFC refusal"],
  M8: ["learning egress, Foundry run, or target-owner promotion proposal", "egress PEP, Foundry executor, or ordinary target-owner governance invoker", "source/route rights plus local/domain policy and applicable authority", "egress/run/proposal receipt; no self-promotion receipt", "deny forbidden route, mutable epoch, evaluator conflict, exhausted budget, or unowned promotion"],
  M9: ["selected exact repository or lifecycle effect", "daemon-recomputed final repository/environment/lifecycle invoker", "sovereign-local exact authority or separately proven managed wallet grant", "effect-bound ReceiptEnvelope and offline proof index", "zero invoker calls for substitution, expiry, revocation, deposed writer, stale head, or unknown completion"],
  M10: ["writer promotion, fencing, rejoin, or recovery effect", "daemon continuity/fencing final invoker and resource-side fence", "System governance plus current epoch/floor/authority facts", "promotion/fence/recovery receipt and root", "one effective writer or fail closed; never infer success from timeout"],
  M11: ["distributed assignment or non-live embodied action proposal", "daemon assignment invoker or LocalControlSupervisor simulation/SIL/HIL/shadow boundary", "System governance and safety policy; placement/model/cloud grants nothing", "assignment or non-live stage receipt", "deny stale allocation/two writers/unsafe input; invoke no live actuator"],
  M12: ["AIIP packet admission, restricted disclosure, terms, dispute, or exit transition", "each sovereign System's local AIIP/domain admission path", "each local policy/authority plane independently; peer traffic grants nothing", "signed packet/local admission/disclosure receipt", "deny replay, wrong root, missing terms, undisclosed context, premature settlement, or foreign direct control"],
  M13: ["trial work admission, acceptance, revocation, dispute, or portable exit", "each independently operated System's local final invoker", "each sovereign party's own policy/authority under frozen terms", "trial contribution/acceptance/exit evidence bundle", "safe decline and local continuation; no shared admin, database, or authority"],
  M14: ["selected connected service, settlement, enrollment, suspension, or exit effect", "selected service/settlement owner final invoker after all gates", "explicit enrollment plus local/domain and applicable portable/high-risk authority", "service/payment/dispute/exit receipt", "deny implicit enrollment, unmet demand/security/legal gate, unresolved dispute, or unselected L1"],
  FUTURE: ["live physical actuator effect", "native LocalControlSupervisor/controller final invoker", "later explicitly approved physical-action authority and local safety policy", "PhysicalActionExecutionReceipt", "no actuator call before later sequencer approval; emergency-stop/fence/recovery failures stop promotion"],
};

// The generic honest-state overlay remains common to every record. These reviewed transition
// vocabularies are the additional ordered product/operator paths whose identity and order must not
// collapse back into that generic overlay. New application-owner rows or journey records fail the
// checker until an explicit mapping is added here and independently in check-work-items.mjs.
const ORDERED_JOURNEY_TRANSITIONS = {
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

function frozenMetric(metricId, metric, threshold, unit, thresholdSource) {
  return {
    metric_id: metricId,
    metric,
    threshold,
    unit,
    threshold_source: thresholdSource,
    frozen_before_observation: true,
  };
}

const GENERIC_FROZEN_METRIC_FLOORS = [
  frozenMetric("generic.unauthorized_final_invoker_calls", "unauthorized or wrong-final-invoker calls", 0, "calls", "cross-stage proof discipline"),
  frozenMetric("generic.duplicate_or_status_inferred_effects", "duplicate or status-inferred effects", 0, "effects", "cross-stage proof discipline"),
  frozenMetric("generic.unresolved_required_owner_dependency_mappings", "unresolved required owner/dependency mappings", 0, "mappings", "single-owner planning rule"),
  frozenMetric("generic.exact_retained_successful_literal_exit_lines", "exact retained successful literal exit lines", 1, "standalone lines", "literal exit rule"),
];

const STAGE_FROZEN_METRIC_FLOORS = {
  M0: [frozenMetric("m0.unowned_or_second_sequencer_facts", "unowned facts or second-sequencer facts", 0, "facts", "M0 program-control floor")],
  M1: [frozenMetric("m1.unauthorized_or_duplicate_genesis_effects", "unauthorized or duplicate bounded-System genesis effects", 0, "effects", "M1 selected-profile floor")],
  M2: [frozenMetric("m2.simultaneous_effective_writers_per_system", "simultaneous effective writers per bounded System", "<=1", "writers per System", "M2 membership/fencing floor")],
  M3: [frozenMetric("m3.direct_path_substitution_failures", "selected direct-path substitutions that change authority, truth, or accepted effect", 0, "substitutions", "M3 direct-path preservation floor")],
  M4: [frozenMetric("m4.direct_client_shared_graph_writes", "direct client writes admitted to the shared OutcomeRoom graph", 0, "writes", "M4 room admission floor")],
  M5: [frozenMetric("m5.accepted_participant_effects_without_current_lease", "accepted participant effects without current identity, claim, and authority lease", 0, "effects", "M5 participant/frontier floor")],
  M6: [frozenMetric("m6.consequential_controls_without_owner_authority_receipt_disposition", "consequential product controls without owner, final-invoker, authority, receipt, and negative-path disposition", 0, "controls", "M6 product-surface floor")],
  M7: [frozenMetric("m7.semantic_effects_with_unknown_or_mutable_version", "semantic effects admitted with unknown or mutable ontology/recipe/action version", 0, "effects", "M7 semantic-definition floor")],
  M8: [frozenMetric("m8.self_promotion_or_mutable_evaluation_effects", "self-promotion or mutable-evaluation effects", 0, "effects", "M8 learning and improvement floor")],
  M9: [frozenMetric("m9.fixture_or_projection_substituted_terminal_successes", "fixture, shell, or projection states substituted for terminal owner success", 0, "success claims", "M9 terminal-product floor")],
  M10: [
    frozenMetric("m10.dual_effective_writer_intervals", "dual-effective-writer intervals", 0, "intervals", "M10 continuity floor"),
    frozenMetric("m10.unfrozen_rpo_rto_trials", "continuity trials observed before RPO/RTO floors were frozen", 0, "trials", "M10 continuity floor"),
  ],
  M11: [
    frozenMetric("m11.live_actuator_calls", "live actuator calls", 0, "calls", "M11 non-live boundary"),
    frozenMetric("m11.accepted_distributed_effects_without_single_writer_proof", "accepted distributed effects without one-writer/fencing proof", 0, "effects", "M11 distribution floor"),
  ],
  M12: [
    frozenMetric("m12.foreign_direct_truth_or_authority_mutations", "foreign direct truth or authority mutations", 0, "mutations", "M12 AIIP sovereignty floor"),
    frozenMetric("m12.required_federation_journey_transition_coverage", "discovery through portable-exit transition coverage", "100_percent", "declared transitions", "M12 federation journey floor"),
  ],
  M13: [
    frozenMetric("m13.outside_option_coverage", "required parties with outside option frozen before trial", "100_percent_of_required_parties", "required parties", "M13.2 and M13 exit proof"),
    frozenMetric("m13.declared_cost_coverage", "required parties with all trial costs frozen before trial", "100_percent_of_required_parties", "required parties", "M13.2"),
    frozenMetric("m13.declared_risk_coverage", "required parties with material trial risks frozen before trial", "100_percent_of_required_parties", "required parties", "M13.2"),
    frozenMetric("m13.contracted_benefit_coverage", "required parties with contracted benefit and private valuation method frozen before trial", "100_percent_of_required_parties", "required parties", "M13.2"),
    frozenMetric("m13.positive_surplus_floor", "party surplus after declared cost and risk plus sponsor value over frozen outside option", "positive_for_every_required_party_and_sponsor_above_outside_option", "party-level preregistered valuation", "M13 exit proof"),
    frozenMetric("m13.repeat_useful_work_floor", "useful cross-sovereign work cycles preserving separate identity, truth, admission, and authority", ">=2", "accepted cycles", "M13.3 repeat floor"),
    frozenMetric("m13.independence_violations", "proof steps requiring shared runtime, database, administrator, authority, or continued hosted trust", 0, "violations", "M13 independence exit proof"),
    frozenMetric("m13.subsidy_disclosure_and_baseline_coverage", "subsidy disclosed and compared with eligible same-domain/direct-local baseline", "100_percent_of_trial_subsidy_and_eligible_baselines", "trial economics", "M13.5"),
    frozenMetric("m13.safe_decline_control", "negative-surplus controls with safe decline, zero foreign effect, and local continuation", ">=1", "controls", "M13.6"),
  ],
  M14: [
    frozenMetric("m14.unrelated_external_organizations", "unrelated external organizations with recurring paid or risk-bearing demand", ">=3", "organizations", "literal M14 exit floor"),
    frozenMetric("m14.public_service_families", "public service families carrying recurring paid or risk-bearing demand", ">=2", "service families", "literal M14 exit floor"),
    frozenMetric("m14.sustained_declared_period", "recurring demand observation over a preregistered sustained declared period", "one_nonzero_preregistered_sustained_period", "declared period", "literal M14 exit floor"),
    frozenMetric("m14.willingness_to_pay_or_bear_risk", "counted external demand backed by payment or explicit risk bearing", "100_percent_of_counted_demand", "demand observations", "M14.3 and exit proof"),
    frozenMetric("m14.independent_service_supply", "selected service families with independent operator supply commitment", "100_percent_of_selected_service_families", "selected service families", "literal M14 exit floor"),
    frozenMetric("m14.attack_cost_and_security_budget_coverage", "modeled fees and bonded value covering selected attack, security, and availability budget", ">=100_percent_of_budget", "modeled value", "M14.3 and exit proof"),
    frozenMetric("m14.frozen_safety_margin", "frozen margin above selected security and availability budget", ">0", "preregistered margin", "literal M14 exit floor"),
    frozenMetric("m14.zero_appreciation_viability", "connected/secured-service value with token-price appreciation set to zero", "value_persists_at_appreciation=0", "scenario", "M14.4"),
    frozenMetric("m14.no_l1_compatible_alternative", "valid no-L1 branch unless sovereign L1 beats the mature compatible alternative", "no_l1_remains_valid_until_l1_strictly_beats_compatible_alternative", "selected settlement posture", "M14.5 and no-L1 rule"),
  ],
  FUTURE: [frozenMetric("future.effects_before_explicit_amendment", "candidate effects before a later explicit sequencer amendment", 0, "effects", "FUTURE amendment gate")],
};

const RECORD_PROFILE_OVERRIDES = {
  "m11-canonical-contract-registry-and-legacy-ref-migration": "Amendment-gated, inert cross-family canonical-contract registry and read-old/write-new reference-migration planning. It is outside the active M0–M14 path and proves no runtime consumer, physical action, or live embodied capability.",
  "m14-cross-plane-correlated-failure-injection": "Amendment-gated, inert selected-plane correlated-failure planning for optional M14 services. It is outside the active M0–M14 path and proves no injected production fault, service demand, settlement, L1, or stage exit.",
};

const RECORD_EFFECT_OVERRIDES = {
  "m11-canonical-contract-registry-and-legacy-ref-migration": [
    "canonical contract registration, generated projection, or explicitly owner-approved read-old/write-new persisted-reference migration",
    "the named canonical contract owner/registry generator and each explicitly enumerated persistence/runtime consumer after amendment; the private work-item migrator is never a product final invoker",
    "a later explicit sequencer amendment plus each canonical owner's migration approval and ordinary domain authority; a compatibility alias, registry row, or private plan grants nothing",
    "owner approvals, registry/generator parity, exact consumer digests, collision fixtures, migration residual, rollback evidence, and the future content-bound exit bundle",
    "before amendment perform no product write; after amendment reject unowned families, legacy new writes, collisions, partial consumer coverage, stale digests, or missing rollback",
  ],
  "m14-cross-plane-correlated-failure-injection": [
    "bounded test-only fault injection against an explicitly selected optional service plane",
    "the selected plane owner's isolated fault harness after amendment; the private planner and aggregate are never production final invokers",
    "a later explicit sequencer amendment, explicit plane selection, owner approval, isolated-test authorization, and preserved no-L1 exclusions",
    "frozen fault schedule, expected-state matrix, actual-state/obligation comparison, negative and inconclusive evidence, recovery evidence, and future content-bound exit bundle",
    "before amendment inject nothing; after amendment reject unselected/production targets, missing isolation, ambiguous success, obligation loss, or omitted no-L1 disposition",
  ],
};

const PG_OWNER_BY_ID = {
  "PG-0.1": { id: "m8-order-zero-improvement-and-direct-path", applicability: "required_now" },
  "PG-0.2": { id: "m8-order-zero-improvement-and-direct-path", applicability: "required_now" },
  "PG-0.3": { id: "m11-canonical-contract-registry-and-legacy-ref-migration", applicability: "later", closure_stage_id: "M11" },
  "PG-1.1": { id: "m11-canonical-contract-registry-and-legacy-ref-migration", applicability: "required_now", closure_stage_id: "M11" },
  "PG-1.2": { id: "sdk-cli-adk-odk-builder-journey", applicability: "required_now" },
  "PG-1.3": { id: "m9-terminal-product-state-and-release-supply-chain", applicability: "required_now" },
  "PG-2.1": { id: "m9-managed-optionality-overlay", applicability: "conditional" },
  "PG-2.2": { id: "m6-consequential-action-authority-receipt-unification", applicability: "required_now" },
  "PG-2.3": { id: "production-receipt-checkpoint-and-offline-proof", applicability: "required_now" },
  "PG-2.4": { id: "production-receipt-checkpoint-and-offline-proof", applicability: "required_now" },
  "PG-2.5": { id: "m12-aiip-channel-envelope-profile", applicability: "required_now" },
  "PG-2.6": { id: "m14-l1-authorization-decision", applicability: "conditional" },
  "PG-3.1": { id: "production-information-flow-and-declassification", applicability: "required_now" },
  "PG-3.2": { id: "m9-authority-gateway-equivalence-and-coverage", applicability: "conditional" },
  "PG-3.3": { id: "production-information-flow-and-declassification", applicability: "conditional" },
  "PG-3.4": { id: "production-information-flow-and-declassification", applicability: "required_now" },
  "PG-3.5": { id: "m4-room-graph-truth-and-product-projection", applicability: "required_now" },
  "PG-3.6": { id: "m8-learning-boundary-provider-exit", applicability: "required_now" },
  "PG-4A.1": { id: "m2-membership-readiness-plane", applicability: "required_now" },
  "PG-4A.2": { id: "m10-attestation-temporal-floor-and-revocation-continuity", applicability: "conditional" },
  "PG-4A.3": { id: "m2-writer-fence-and-lost-suffix", applicability: "required_now" },
  "PG-4A.4": { id: "m2-writer-fence-and-lost-suffix", applicability: "required_now" },
  "PG-4A.5": { id: "m10-topology-chaos-and-operator-product-proof", applicability: "required_now" },
  "PG-4A.6": { id: "m10-topology-chaos-and-operator-product-proof", applicability: "required_now" },
  "PG-4B.1": { id: "m3-result-lifecycle-negative-retention", applicability: "required_now" },
  "PG-4B.2": { id: "m3-result-lifecycle-negative-retention", applicability: "required_now" },
  "PG-4B.3": { id: "agentgres-production-readiness-and-branch-effects", applicability: "required_now" },
  "PG-4B.4": { id: "m3-result-lifecycle-negative-retention", applicability: "required_now" },
  "PG-4B.5": { id: "m3-result-lifecycle-negative-retention", applicability: "required_now" },
  "PG-4B.6": { id: "m3-result-lifecycle-negative-retention", applicability: "required_now" },
  "PG-5.1": { id: "m11-embodied-nonlive-graph-proof", applicability: "required_now" },
  "PG-5.2": { id: "live-embodied-promotion", applicability: "later" },
  "PG-5.3": { id: "live-embodied-promotion", applicability: "later" },
  "PG-5.4": { id: "live-embodied-promotion", applicability: "later" },
  "PG-5.5": { id: "live-embodied-promotion", applicability: "later" },
  "PG-6A.1": { id: "managed-billing-work-credits-and-supplier-reconciliation", applicability: "required_now" },
  "PG-6A.2": { id: "m14-service-family-owner-contract-and-product-surfaces", applicability: "conditional" },
  "PG-6A.3": { id: "m14-service-family-owner-contract-and-product-surfaces", applicability: "conditional" },
  "PG-6A.4": { id: "managed-billing-work-credits-and-supplier-reconciliation", applicability: "required_now" },
  "PG-6B.1": { id: "dispute-adjudication-remedy-kernel", applicability: "required_now" },
  "PG-6B.2": { id: "dispute-adjudication-remedy-kernel", applicability: "required_now" },
  "PG-6B.3": { id: "m14-service-family-owner-contract-and-product-surfaces", applicability: "required_now" },
  "PG-6B.4": { id: "dispute-adjudication-remedy-kernel", applicability: "conditional" },
  "PG-6B.5": { id: "dispute-adjudication-remedy-kernel", applicability: "required_now" },
  "PG-6C.1": { id: "hypervisoros-ctee-task-capsule-attestation", applicability: "conditional" },
  "PG-6C.2": { id: "hypervisoros-ctee-task-capsule-attestation", applicability: "conditional" },
  "PG-6C.3": { id: "hypervisoros-ctee-task-capsule-attestation", applicability: "conditional" },
  "PG-6D.1": { id: "ecosystem-assurance-and-public-claim-estate", applicability: "required_now" },
  "PG-6D.2": { id: "ecosystem-assurance-and-public-claim-estate", applicability: "conditional" },
  "PG-6D.3": { id: "ecosystem-assurance-and-public-claim-estate", applicability: "out_of_scope" },
  "PG-7.1": { id: "platform-operability-observability-and-incidents", applicability: "required_now" },
  "PG-7.2": { id: "platform-operability-observability-and-incidents", applicability: "required_now" },
  "PG-7.3": { id: "m10-attestation-temporal-floor-and-revocation-continuity", applicability: "required_now" },
  "PG-7.4": { id: "production-receipt-checkpoint-and-offline-proof", applicability: "required_now" },
  "PG-7.5": { id: "m9-terminal-product-state-and-release-supply-chain", applicability: "required_now" },
  "PG-7.6": { id: "managed-billing-work-credits-and-supplier-reconciliation", applicability: "required_now" },
  "PG-7.7": { id: "platform-operability-observability-and-incidents", applicability: "required_now" },
  "PG-7.8": { id: "platform-operability-observability-and-incidents", applicability: "required_now" },
};

function pgGateStates(workItemId, ownerStageId) {
  return Object.entries(PG_OWNER_BY_ID)
    .filter(([, owner]) => owner.id === workItemId)
    .map(([pgId, owner]) => {
    const applicability = owner.applicability;
    return {
      pg_id: pgId,
      applicability,
      closure_stage_id: owner.closure_stage_id ?? ownerStageId,
      profile_selection: applicability === "required_now"
        ? "selected"
        : applicability === "conditional"
          ? "not_selected"
          : applicability === "later"
            ? "deferred"
            : "not_applicable",
      closure_status: applicability === "out_of_scope" ? "not_applicable" : "open",
      evidence_refs: [],
      literal_exit: null,
      status_basis: applicability === "out_of_scope"
        ? "The selected profile makes no legal-conformity assertion; a separately accountable issuer decision is required to select this gate."
        : owner.scope_review
          ? `No gate-specific retained literal exit evidence is present; ${owner.scope_review} remains unresolved and this tentative assignment cannot close the gate.`
          : "No gate-specific retained literal exit evidence is present; planning and reference-mechanism evidence do not close a production-integration gate.",
      ...(owner.scope_review ? { scope_review: owner.scope_review } : {}),
    };
  });
}

const PRECEDENT_ANCHOR = {
  M0: "scripts/check-architecture-docs.mjs",
  M1: "crates/types/src/app/generated/architecture_contracts.rs",
  M2: "crates/services/src/agentic/runtime/kernel/mod.rs",
  M3: "crates/services/src/agentic/runtime/kernel/mod.rs",
  M4: "apps/hypervisor/scripts/ioi-api-adapter.mjs",
  M5: "apps/hypervisor/scripts/ioi-api-adapter.mjs",
  M6: "apps/hypervisor/scripts/surface-registry.mjs",
  M7: "crates/types/src/app/generated/architecture_contracts.rs",
  M8: "crates/services/src/agentic/runtime/kernel/mod.rs",
  M9: "apps/hypervisor/scripts/serve-product-ui.mjs",
  M10: "crates/services/src/agentic/runtime/kernel/mod.rs",
  M11: "crates/services/src/agentic/runtime/kernel/runtime_physical_action_intent_admission.rs",
  M12: "crates/types/src/app/generated/architecture_contracts.rs",
  M13: "apps/hypervisor/scripts/ioi-api-adapter.mjs",
  M14: "crates/types/src/app/generated/architecture_contracts.rs",
  FUTURE: "crates/services/src/agentic/runtime/kernel/runtime_physical_action_intent_admission.rs",
};

function section(start, end) {
  const startIndex = plan.indexOf(start);
  const endIndex = plan.indexOf(end, startIndex + start.length);
  if (startIndex < 0 || endIndex < 0) throw new Error(`cannot locate plan section ${start}`);
  return plan.slice(startIndex, endIndex);
}

function tableRows(source, { stageMap = null } = {}) {
  const rows = [];
  for (const line of source.split(/\r?\n/u)) {
    if (!line.startsWith("| `")) continue;
    const cells = line.slice(1, -1).split("|").map((cell) => cell.trim());
    const idMatch = /^`([^`]+)`(?:\s*\/\s*(M\d+)(?:\s+conditional)?(?:\s+\([^)]*\))?)?$/u.exec(cells[0]);
    if (!idMatch) continue;
    const id = idMatch[1];
    const stage = idMatch[2] ?? stageMap?.[id];
    if (!stage) continue;
    rows.push({ id, stage, ownersAndContracts: cells[1], dependencies: cells[2], deliverable: cells[3], negative: cells[4], amendment: cells[5] });
  }
  return rows;
}

const selectedRows = [
  ...tableRows(section("#### Selected-spine records: M0–M6", "#### Selected-spine records: M7–M14")),
  ...tableRows(section("#### Selected-spine records: M7–M14", "#### Unassigned A–Z records")),
];
const appRows = tableRows(section("| Proposed application owner ID / stage", "Each stage aggregate must join"));
const sa9Rows = tableRows(section("#### Unassigned A–Z records", "## Canon-change adaptability workflow"), { stageMap: SA9_STAGE });
for (const row of appRows) {
  if (!ORDERED_JOURNEY_TRANSITIONS[row.id]) {
    throw new Error(`action-plan application owner lacks an ordered product/operator journey: ${row.id}`);
  }
}
const specs = new Map([...selectedRows, ...appRows, ...sa9Rows].map((row) => [row.id, row]));

// The delegated post-migration audit found candidate scope beyond the approved
// SA-1 through SA-9 stage graph. Preserve those candidates only as FUTURE,
// amendment-gated proposals; they are not admitted M11/M14 aggregate children.
const delegatedReviewGapSpecs = [
  {
    id: "m11-canonical-contract-registry-and-legacy-ref-migration",
    stage: "FUTURE",
    ownersAndContracts: "`SYSTEM` `DAEMON` `AGENTGRES` `PHYSICAL` — cross-family canonical reference migration and remaining consequential pilot contract registration",
    dependencies: "`m10-two-failure-domain-continuity` `m3-direct-path-and-exit-proof` `m9-selected-profile-aggregate-exit-and-claim-publication`",
    deliverable: "Amendment-ready owner-complete read-old/write-new migration census, remaining pilot-family registry/consumer matrix, and future content-bound FUTURE_CANONICAL_CONTRACT_REGISTRY_MIGRATION_EXIT=0",
    negative: "any persisted legacy reference gains a new write, a collision is accepted, an owner family is omitted, or registration/projection exists without its actual runtime consumer and adversarial fixtures",
    objective: "Preserve an amendment-ready candidate for the estate-wide read-old/write-new migration of persisted legacy references and cross-stage contract integration without admitting it to M11 or changing current stage order.",
    requiredWork: [
      "Keep PG-0.3 open/later while defining the exact owner/family census, read aliases, canonical new writes, collision fixtures, migration residual, rollback rule, and sequencer amendment needed before closure work can activate.",
      "Keep PG-1.1 open and required_now while defining the cross-stage GoalRun, grounding, runtime assignment/harness invocation, and remaining non-live physical-action integration amendment; required_now does not activate this FUTURE candidate and schema registration is not runtime proof.",
      "Retain per-family owner approvals, generated projections, real consumer anchors, positive/adversarial fixtures, and a content-bound literal exit; no live actuator or M12+ claim.",
    ],
    sourceProvenance: "Unapproved candidate record preserved from the delegated 2026-07-23 semantic-ownership audit. It remains FUTURE behind a later explicit sequencer amendment; PG-0.3 stays open/later, PG-1.1 stays open/required_now, and this record is not an M11 aggregate child or implementation claim.",
    createdAt: "2026-07-23",
  },
  {
    id: "m14-cross-plane-correlated-failure-injection",
    stage: "FUTURE",
    ownersAndContracts: "`DAEMON` `AGENTGRES` `WALLET` `STORAGE` `ENVIRONMENTS` `MEASURED` `ECON` `SERVICES` `L1` — selected-profile correlated failure matrix",
    dependencies: "`m13-selected-profile-aggregate-exit` `platform-operability-observability-and-incidents` `m10-topology-chaos-and-operator-product-proof` `hypervisoros-ctee-task-capsule-attestation` `managed-billing-work-credits-and-supplier-reconciliation` `dispute-adjudication-remedy-kernel` `m14-service-family-owner-contract-and-product-surfaces`",
    deliverable: "Amendment-ready optional-plane correlated-failure schedule, expected state/obligation matrix, safe no-L1 exclusions, and future content-bound FUTURE_CROSS_PLANE_CORRELATED_FAILURE_EXIT=0",
    negative: "a selected daemon, Agentgres, authority, storage, clock, provider, fleet, attestation, billing, dispute, service, or settlement failure combination is omitted or turns unknown or ambiguous evidence into authority, delivery, payment, settlement, or success",
    objective: "Preserve a later-amendment candidate for correlated failure injection across optional M14 service planes while leaving current PG-7.2 with the approved M9 operability owner.",
    requiredWork: [
      "Do not change the current PG-7.2 owner; define the sequencer amendment or separate future gate required before optional M14 service-plane correlated faults can activate.",
      "Freeze the candidate selected-plane matrix and explicitly disposition every unselected plane, including the valid no-L1 branch.",
      "Define expected degraded, denied, ambiguous, recovery, reconciliation, and safe-exit states across daemon, Agentgres, authority, storage, clock, provider, fleet, attestation, billing, dispute, service, and settlement owners.",
      "Retain actual-state/obligation comparison evidence and a content-bound literal exit; never promote a conditional service, L1, cohort, or public claim from planning or partial fault coverage.",
    ],
    sourceProvenance: "Unapproved candidate record preserved from the delegated 2026-07-23 gate-scope audit. It remains FUTURE behind a later explicit sequencer amendment, owns no current PG, is not an M14 aggregate child, and makes no implementation claim.",
    createdAt: "2026-07-23",
  },
];
for (const spec of delegatedReviewGapSpecs) specs.set(spec.id, spec);

const existingFiles = fs.readdirSync(workItemsRoot).filter((name) => name.endsWith(".v1.json")).sort();
const existing = new Map(existingFiles.map((name) => {
  const record = readJson(path.join(workItemsRoot, name));
  return [record.work_item_id, record];
}));

let preservation;
if (fs.existsSync(preservationPath)) {
  preservation = readJson(preservationPath);
} else {
  preservation = {
    schema_version: "ioi.program.work-item-status-preservation.v1",
    captured_at: "2026-07-22",
    before_count: existing.size,
    before: [...existing.entries()].map(([id, record]) => ({
      work_item_id: id,
      status: record.status,
      sha256: sha256File(path.join(workItemsRoot, `${id}.v1.json`)),
    })),
    rule: "The private planning migration may enrich content but must not change any pre-existing status.",
  };
}

for (const baseline of preservation.before) {
  if (!existing.has(baseline.work_item_id)) throw new Error(`missing pre-existing record ${baseline.work_item_id}`);
  if (existing.get(baseline.work_item_id).status !== baseline.status) throw new Error(`pre-existing status drift before migration: ${baseline.work_item_id}`);
}

const baselineRecords = new Map();
for (const baseline of preservation.before) {
  const baselinePath = path.join(
    implementationRoot,
    `_archive/pre-unification-baseline/work-items/${baseline.work_item_id}.v1.json`,
  );
  if (!fs.existsSync(baselinePath)) throw new Error(`missing exact pre-unification record ${baseline.work_item_id}`);
  const record = readJson(baselinePath);
  if (record.work_item_id !== baseline.work_item_id || record.status !== baseline.status) {
    throw new Error(`invalid exact pre-unification record ${baseline.work_item_id}`);
  }
  baselineRecords.set(baseline.work_item_id, record);
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function codesFrom(text, stage) {
  const explicit = [...text.matchAll(/`([A-Z][A-Z0-9_-]+)`/gu)].map((match) => match[1]).filter((code) => OWNER_CODES[code]);
  return unique(explicit.length > 0 ? explicit : (STAGE_CODES[stage] ?? []));
}

function ownersFor(original, spec, stage, preserveHistoricalScope = false) {
  if (preserveHistoricalScope) {
    return unique(original?.canon_owners ?? []).filter((owner) => fs.existsSync(path.join(repoRoot, owner))).sort();
  }
  const fromCodes = codesFrom(spec?.ownersAndContracts ?? "", stage).flatMap((code) => OWNER_CODES[code]);
  const hasExplicitCodes = [...(spec?.ownersAndContracts ?? "").matchAll(/`([A-Z][A-Z0-9_-]+)`/gu)]
    .some((match) => OWNER_CODES[match[1]]);
  const owners = unique([...(hasExplicitCodes ? [] : (original?.canon_owners ?? [])), ...fromCodes]);
  return owners.filter((owner) => fs.existsSync(path.join(repoRoot, owner))).sort();
}

function canonicalCandidate(name) {
  let current = NAME_CORRECTIONS[name] ?? name;
  const seen = new Set();
  while (contractRouting.aliases[current] !== undefined) {
    if (seen.has(current)) throw new Error(`contract alias cycle at ${current}`);
    seen.add(current);
    current = contractRouting.aliases[current];
  }
  return current;
}

function pendingDefinition(name, reason = null) {
  const configured = contractRouting.pending_contract_definitions[name];
  if (configured) return { name, ...configured };
  const rejected = contractRouting.rejected_generic_candidates[name];
  const suffix = name.toUpperCase().replace(/[^A-Z0-9]+/gu, "_");
  return {
    name,
    decision_owner: "docs/architecture/_meta/source-of-truth-map.md",
    required_exit: `${suffix}_CONTRACT_DEFINITION_EXIT=0`,
    reason: reason ?? rejected ?? "The approved planning record names this candidate, but no exact registered or reviewed canonical owner locator currently exists.",
  };
}

function resolveContract(name) {
  const corrected = canonicalCandidate(name);
  const registered = registeredContractsByName.get(corrected) ?? [];
  if (registered.length > 0) {
    const ownerRefs = unique(registered.map((entry) => entry.canonical_owner_ref));
    const ownerPaths = unique(ownerRefs.map((ref) => ref.replace(/^canon:\/\//u, "").split("#", 1)[0]));
    if (ownerPaths.length !== 1) throw new Error(`registered contract ${corrected} has ambiguous canonical owners: ${ownerPaths.join(", ")}`);
    return {
      name: corrected,
      owner_path: ownerPaths[0],
      owner_role: "registry_canonical_owner",
      semantic_owner_paths: contractRouting.semantic_owner_paths[corrected] ?? [],
      canonical_owner_ref: ownerRefs[0],
      contract_ids: registered.map((entry) => entry.contract_id).sort(),
      schema_versions: registered.map((entry) => entry.schema_version).sort(),
      registry_resolution: "architecture_contract_registry",
      classification: "canonical_contract",
    };
  }
  const exactOwner = contractRouting.canonical_owners[corrected];
  if (exactOwner) {
    if (!fs.existsSync(path.join(repoRoot, exactOwner))) throw new Error(`reviewed owner locator for ${corrected} is missing: ${exactOwner}`);
    return {
      name: corrected,
      owner_path: exactOwner,
      owner_role: "reviewed_shape_owner",
      semantic_owner_paths: contractRouting.semantic_owner_paths[corrected] ?? [],
      canonical_owner_ref: null,
      contract_ids: [],
      schema_versions: [],
      registry_resolution: "reviewed_owner_locator",
      classification: "canonical_contract",
    };
  }
  return null;
}

function contractsAndPending(id, original, preserveHistoricalScope = false) {
  const configuredAllowlist = contractRouting.work_item_contract_allowlists[id];
  const originalCandidates = (original?.contract_families ?? []).map((entry) => typeof entry === "string" ? entry : entry.name);
  const rawCandidates = unique(
    preserveHistoricalScope
      ? originalCandidates
      : configuredAllowlist ?? originalCandidates,
  );
  const contracts = [];
  const pending = [];
  const privateArtifactNames = [...(contractRouting.work_item_private_artifact_allowlists[id] ?? [])];
  for (const candidate of rawCandidates) {
    const corrected = canonicalCandidate(candidate);
    if (contractRouting.private_artifacts[corrected]) {
      privateArtifactNames.push(corrected);
      continue;
    }
    if (contractRouting.pending_contract_definitions[corrected]) {
      pending.push(pendingDefinition(corrected));
      continue;
    }
    if (contractRouting.rejected_generic_candidates[corrected]) {
      pending.push(pendingDefinition(corrected, contractRouting.rejected_generic_candidates[corrected]));
      continue;
    }
    const resolved = resolveContract(corrected);
    if (resolved) {
      contracts.push(resolved);
      continue;
    }
    pending.push(pendingDefinition(corrected));
  }
  const deduped = [...new Map(contracts.map((entry) => [`${entry.name}:${entry.owner_path}`, entry])).values()];
  const dedupedPending = [...new Map(pending.map((entry) => [entry.name, entry])).values()];
  return { contracts: deduped, pending: dedupedPending, privateArtifactNames: unique(privateArtifactNames) };
}

function exitLiteral(original, spec, id) {
  const source = JSON.stringify(original?.exit_criteria ?? []) + " " + (spec?.deliverable ?? "");
  const found = source.match(/\b[A-Z][A-Z0-9_]*_EXIT=0\b/u)?.[0];
  if (found) return found;
  return `${id.toUpperCase().replace(/[^A-Z0-9]+/gu, "_")}_EXIT=0`;
}

function clean(text) {
  let normalized = text;
  for (const [stale, current] of Object.entries(NAME_CORRECTIONS).sort((left, right) => right[0].length - left[0].length)) {
    normalized = normalized.replace(new RegExp(`\\b${stale}\\b`, "gu"), current);
  }
  normalized = normalized
    .replace(/EvalSuite\/Run/gu, "evaluation-suite revision, EvaluationEpoch, and evaluation run (exact run type pending owner definition)")
    .replace(/EvalSuite/gu, "evaluation-suite revision")
    .replace(/EvalRun/gu, "evaluation run (exact type pending owner definition)")
    .replace(/RuntimeActionDescriptor/gu, "private RuntimeActionDescriptor projection")
    .replace(/EffectReceipt/gu, "ReceiptEnvelope or applicable owner-defined effect receipt")
    .replace(/ArchitectureCoverageEntry/gu, "private ArchitectureCoverageEntry projection");
  return normalized
    .replace(/`?[A-Z][A-Z0-9_]*_EXIT=0`?/gu, "the declared literal exit contract")
    .replace(/\s+/gu, " ")
    .trim()
    .replace(/[.;:]?\s*$/, "");
}

function recordRole(id, stage) {
  if (stage === "FUTURE") return "conditional_future";
  if (AGGREGATES.has(id)) return "aggregate_exit";
  if (/verifier|lint|census|coverage|readiness-verifier/iu.test(id)) return "private_verifier";
  return "implementation_cut";
}

function externalGates(stage, id) {
  const gates = [];
  if (["M9", "M10", "M11", "M12", "M13", "M14"].includes(stage)) {
    gates.push({ gate_id: "applicable-pg-profile-gates", owner: "proof-gates/mechanism-gate-registry.md", activation_condition: "Every applicable gate is selected and evidenced in the owning work-item records; planning creates no closure." });
  }
  if (stage === "M13") gates.push({ gate_id: "independent-operation-preregistration", owner: "docs/architecture/foundations/aiip.md", activation_condition: "Independent administration, custody, outside options, costs, risks, and valuation are frozen before observation." });
  if (stage === "M14") gates.push({ gate_id: "commercial-legal-assurance-demand-approval", owner: "docs/architecture/foundations/ecosystem-assurance-certification-liability.md", activation_condition: "Repeated M13 evidence and explicit legal, commercial, assurance, demand, security, and economics decisions exist." });
  if (id === "m9-managed-optionality-overlay") gates.push({ gate_id: "selected-managed-authority-overlay", owner: "ioi-target-end-state-master-implementation-guide.md", activation_condition: "The ordered managed-optionality overlay is explicitly selected; the sovereign-local lane remains independently valid and passing it never implies this overlay." });
  if (id === "m11-embodied-systems-nonlive-operational-journey") gates.push({ gate_id: "conditional-embodied-registration", owner: "ioi-target-end-state-master-implementation-guide.md", activation_condition: "Embodied Systems registration is explicitly pulled after its contracts, route, projection, and implementation are real; otherwise this journey remains outside the M11 aggregate dependency set." });
  if (id === "decentralized-profile-admission-and-exit") gates.push({ gate_id: "selected-decentralized-profile", owner: "ioi-target-end-state-master-implementation-guide.md", activation_condition: "A decentralized profile is explicitly selected for the M14 service posture; candidate intelligence alone does not pull the profile into the aggregate exit." });
  if (stage === "FUTURE") gates.push({ gate_id: "later-explicit-sequencer-amendment", owner: "ioi-target-end-state-master-implementation-guide.md", activation_condition: "A later user-approved amendment assigns and activates this candidate after every named prerequisite; a proposed FUTURE record creates no current sequence or claim." });
  return gates;
}

function evidenceRefs(original) {
  return unique(original?.evidence_refs ?? []).filter((ref) => fs.existsSync(path.join(repoRoot, ref)));
}

function codeAnchors(original, stage) {
  const anchors = [...(original?.code_anchors ?? [])];
  if (anchors.length === 0) anchors.push({ path: PRECEDENT_ANCHOR[stage], present_when: "current_precedent", evidence_scope: "adjacent implementation precedent only; not proof of this work item" });
  return anchors;
}

function orderedJourneyFor(id) {
  return (ORDERED_JOURNEY_TRANSITIONS[id] ?? []).map((transitionId, index) => ({
    order: index + 1,
    transition_id: transitionId,
    required_behavior: `The ${id} product/operator path exposes ${transitionId.replace(/_/gu, " ")} through the declared canonical owner; presentation, workflow evidence, and sequence position grant no product authority.`,
    advancement_evidence: "Advance only from canonical owner state plus the applicable admission/effect receipt or explicit read-only projection evidence; retain predecessor and selected-profile context.",
    negative_behavior: "On denial, revocation, stale/conflicting state, dependency loss, or ambiguous effect, remain in or enter the explicit honest-state overlay and do not infer advancement.",
  }));
}

function metricsFor(id, stage) {
  const journey = ORDERED_JOURNEY_TRANSITIONS[id] ?? [];
  return [
    ...GENERIC_FROZEN_METRIC_FLOORS,
    ...(STAGE_FROZEN_METRIC_FLOORS[stage] ?? []),
    ...(journey.length > 0 ? [
      frozenMetric(
        `journey.${id}.ordered_transition_coverage`,
        `ordered product/operator transition coverage for ${id}`,
        "100_percent_in_declared_order",
        `${journey.length} declared transitions`,
        "reviewed action-plan/stage journey mapping",
      ),
    ] : []),
  ];
}

function makeRecord(id, stage, original, spec) {
  const preExisting = preservation.before.some((entry) => entry.work_item_id === id);
  const historicalScopeLocked = preExisting && original?.status !== "proposed";
  let owners = ownersFor(original, spec, stage, historicalScopeLocked);
  const { contracts, pending, privateArtifactNames } = contractsAndPending(id, original, historicalScopeLocked);
  owners = unique([
    ...owners,
    ...contracts.flatMap((contract) => [contract.owner_path, ...(contract.semantic_owner_paths ?? [])]),
  ]).sort();
  const literal = exitLiteral(original, spec, id);
  const objective = original?.objective ?? spec?.objective ?? `Produce the bounded plan, owner integration, product/operator states, and proof bundle for ${clean(spec.deliverable)}.`;
  const negative = clean(historicalScopeLocked
    ? original?.adversarial_or_fault_proof ?? original?.falsifiable_claim ?? "the original bounded claim is violated"
    : spec?.negative ?? original?.adversarial_or_fault_proof ?? "the declared owner, effect, proof, or nonclaim boundary is violated");
  const effect = RECORD_EFFECT_OVERRIDES[id] ?? STAGE_EFFECT[stage];
  const originalEvidenceRefs = unique(original?.evidence_refs ?? []);
  const availableRefs = evidenceRefs(original);
  const refs = historicalScopeLocked ? originalEvidenceRefs : availableRefs;
  const missingHistoricalRefs = originalEvidenceRefs.filter((ref) => !availableRefs.includes(ref));
  const ownerSnapshots = owners.map((owner) => ({ path: owner, sha256: sha256File(path.join(repoRoot, owner)) }));
  const aggregateDigest = sha256(ownerSnapshots.map((entry) => `${entry.path}:${entry.sha256}`).join("\n"));
  const retainedStatus = original?.status ?? "proposed";
  const carriedNonclaims = (original?.remaining_nonclaims ?? []).filter((nonclaim) => !(
    id === "m9-authority-gateway-equivalence-and-coverage"
    && /until canon assigns its owner/iu.test(nonclaim)
  )).filter((nonclaim) => !(
    new Set([
      "m11-canonical-contract-registry-and-legacy-ref-migration",
      "m14-cross-plane-correlated-failure-injection",
    ]).has(id)
    && /Simulation\/SIL\/HIL\/shadow|live actuator|E1\+|Node count or placement/iu.test(nonclaim)
  ));
  if (!original && retainedStatus !== "proposed") throw new Error(`new record ${id} is not proposed`);
  return {
    evidence_format: "ioi.program.work_item.v1",
    work_item_id: id,
    stage_id: stage,
    record_role: recordRole(id, stage),
    required_work: original?.required_work ?? spec?.requiredWork ?? [`Approved plan-level gap closure: ${id}`],
    status: retainedStatus,
    objective,
    falsifiable_claim: original?.falsifiable_claim ?? `This plan is incomplete or its future claim fails if ${negative}.`,
    selected_profile: RECORD_PROFILE_OVERRIDES[id] ?? STAGE_PROFILE[stage],
    canon_owners: owners,
    canon_snapshot: {
      captured_at: "2026-07-22",
      aggregate_sha256: aggregateDigest,
      owners: ownerSnapshots,
    },
    contract_families: contracts,
    private_artifacts: [
      {
        artifact_id: `work-item-record:${id}`,
        artifact_class: "private_implementation_plan_and_status_record",
        path: `internal-docs/implementation/work-items/${id}.v1.json`,
        product_authority: false,
        architecture_canon: false,
      },
      {
        artifact_id: `future-exit-contract:${literal}`,
        artifact_class: "private_future_literal_exit_contract",
        path: null,
        product_authority: false,
        architecture_canon: false,
      },
      ...privateArtifactNames.map((name) => ({
        artifact_id: `private-artifact:${name}`,
        artifact_class: contractRouting.private_artifacts[name],
        candidate_name: name,
        path: null,
        product_authority: false,
        architecture_canon: false,
      })),
      ...pending.map((entry) => ({
        artifact_id: `pending-contract-definition:${entry.name}`,
        artifact_class: "private_pending_contract_definition_gap",
        candidate_name: entry.name,
        decision_owner: entry.decision_owner,
        required_exit: entry.required_exit,
        reason: entry.reason,
        path: null,
        product_authority: false,
        architecture_canon: false,
      })),
    ],
    current_implementation_evidence: preExisting
      ? `Pre-migration record status is preserved as ${retainedStatus}. Existing anchors and refs prove only their original named scope. Missing checkout refs: ${missingHistoricalRefs.length ? missingHistoricalRefs.join(", ") : "none"}. Newly populated schema, proof-shape, journey, metric, gate, and exit-contract fields are planning metadata and are not covered by the historical status. This migration adds no runtime or stage claim.`
      : "Planning only. Canon and current repository/Hypervisor precedents were inventoried, but no retained literal exit or implementation proof exists for this new proposed record.",
    dependency_work_item_ids: [],
    external_gates: externalGates(stage, id),
    aggregate_child_ids: [],
    aggregate_child_dispositions: [],
    aggregate_verification_binding: null,
    in_scope: historicalScopeLocked ? [
      `The exact pre-migration objective and required-work labels only: ${clean(objective)}; ${(original?.required_work ?? []).join(", ") || "no additional labels"}.`,
      "Schema enrichment and future revalidation metadata without adding a canonical owner, contract family, effect, or product claim to the historical status.",
    ] : [
      clean(spec?.ownersAndContracts ?? `The canonical owner and contract crossings declared by ${id}`),
      clean(spec?.deliverable ?? objective),
      "Positive, adversarial, stale-state, substitution, fault, recovery, product/operator-state, and retained-evidence planning for the bounded claim.",
    ],
    out_of_scope: unique([
      negative,
      ...carriedNonclaims,
      historicalScopeLocked ? "Any semantic scope beyond the exact pre-migration objective, required-work labels, owners, and contract families requires a separate proposed successor record." : null,
      "Creating this record does not implement behavior, activate work, close its literal exit, or change a stage.",
    ]),
    implementation_actions: historicalScopeLocked ? [
      "Preserve the exact original objective, required-work labels, canonical owners, empty/original contract-family set, status, and retained evidence references.",
      "Treat newly populated proof/journey/metric fields as future revalidation guidance only; they do not retroactively widen what the historical status proves.",
      `Require a separate proposed successor record for any wider scope and never emit ${literal} from this migration.`,
    ] : [
      `Resolve and freeze the exact canonical owners and contract revisions for: ${clean(spec?.ownersAndContracts ?? objective)}.`,
      `Implement the bounded owner/runtime/product crossings needed to deliver: ${clean(spec?.deliverable ?? objective)}.`,
      `Build positive plus adversarial/fault runners that reject: ${negative}.`,
      `Retain an evidence index and require the exact content-bound ${literal}; never infer success from a task/process exit code.`,
    ],
    consequential_effects_and_final_invokers: [{
      effect: effect[0],
      final_invoker: effect[1],
      authority_source: effect[2],
      receipt_or_evidence: effect[3],
      negative_behavior: effect[4],
    }],
    applicable_pg_ids: historicalScopeLocked ? [] : pgGateStates(id, stage).map((gate) => gate.pg_id),
    pg_gate_states: historicalScopeLocked ? [] : pgGateStates(id, stage),
    ...(id === "m0-program-control-selected-profile-exit-proof" ? {
      proof_gate_census: {
        role: "oversight_projection_only_not_closure_authority",
        registry_ref: "internal-docs/implementation/proof-gates/mechanism-gate-registry.md",
        dispositions: Object.entries(PG_OWNER_BY_ID).map(([pgId, owner]) => ({
          pg_id: pgId,
          closure_owner_work_item_id: owner.id,
          applicability: owner.applicability,
          ...(owner.scope_review ? { scope_review: owner.scope_review } : {}),
        })),
        nonclaim: "The M0 aggregate projects all gate dispositions but owns and closes none of them.",
      },
    } : {}),
    positive_proof: [
      `The selected profile completes the bounded ${id} journey through the declared owner path and produces the exact expected truth/effect/evidence outputs.`,
      "Restart/replay or independent reconstruction preserves the same owner refs, heads/roots, receipts, and explicit nonclaims where applicable.",
      `The retained evidence file contains exactly one line equal to ${literal} only after the full claim is independently reviewed.`,
    ],
    adversarial_or_fault_proof: original?.adversarial_or_fault_proof ?? `Reject and retain evidence for ${negative}; include substitution, stale-state, denial, dependency-loss, retry/ambiguity, restart, and recovery branches where applicable.`,
    product_journey_and_states: [
      { state: "loading_or_pending", required_behavior: "Show bounded progress and frozen context without implying admission, readiness, or success." },
      { state: "honest_empty", required_behavior: "Render no-data/not-yet-admitted truth without fixtures or fabricated defaults." },
      { state: "ready_or_proposed", required_behavior: `Expose the exact proposal and owner context for ${id}; presentation grants no authority.` },
      { state: "denied_or_revoked", required_behavior: `Fail closed for ${negative}; make the denial inspectable and invoke nothing consequential.` },
      { state: "unavailable_or_degraded", required_behavior: "Name the missing owner/dependency and preserve narrower nonclaims; never substitute plausible mock truth." },
      { state: "stale_conflict_or_ambiguous", required_behavior: "Preserve predecessor, idempotency, reconciliation, and retry obligations without inferring success." },
      { state: "recovery_or_rollback", required_behavior: "Resume, compensate, fence, reconcile, or stop under the declared rollback rule with retained evidence." },
      { state: "completed", required_behavior: `Show owner truth, receipt/evidence links, remaining nonclaims, and only the exact ${literal} when actually retained.` },
    ],
    ordered_product_operator_journey: orderedJourneyFor(id),
    metrics_and_frozen_thresholds: metricsFor(id, stage),
    compatibility_and_migration: [
      "Preserve existing valid object, route, receipt, and evidence identities until an explicit owner-approved successor/migration exists.",
      "Read-old/write-new behavior, alias duration, mixed-version refusal, hash impact, rollback, and residual cleanup are explicit per affected family.",
      "No route, UI, fixture, archive, or compatibility layer becomes a second truth, authority, status, or sequencing owner.",
    ],
    evidence_index: {
      literal_exit: literal,
      retained_refs: refs,
      expected_output_paths: [`internal-docs/implementation/evidence/${stage}/${id}.exit.v1.txt`],
      historical_unavailable_refs: missingHistoricalRefs,
      negative_and_inconclusive_retention: true,
      producer_independence_required: true,
      checkout_validation: retainedStatus === "verified" ? "legacy_status_unavailable_in_this_checkout" : "not_applicable_until_evidence_ready",
      historical_status_preserved: historicalScopeLocked,
      task_exit_code_is_proof: false,
    },
    code_anchors: codeAnchors(original, stage),
    evidence_refs: refs,
    remaining_nonclaims: unique([
      ...carriedNonclaims,
      id === "m9-authority-gateway-equivalence-and-coverage"
        ? "Daemon doctrine owns the IOI Authority Gateway and HypervisorOS owns EnforcementCoverageDeclaration; private route censuses, comparison manifests, and exit logs remain non-canonical workflow evidence."
        : null,
      stage === "M12" ? "No M13 two-sovereign proof, surplus, correctness, acceptance, or settlement claim." : null,
      stage === "M13" ? "No M14 connected/secured-service, demand, network-effect, native-asset, or L1 claim." : null,
      stage === "M14" ? "The valid no-L1 branch remains available; planning proves no demand, mainnet, native asset, or recurring external cohort." : null,
      ["M10", "M11"].includes(stage) ? "Node count or placement grants no authority, consensus, sovereign independence, or federation." : null,
      stage === "M11" || id === "live-embodied-promotion" ? "Simulation/SIL/HIL/shadow or a planned record proves no live actuator path or E1+ claim." : null,
      id === "m11-canonical-contract-registry-and-legacy-ref-migration" ? "This amendment-gated candidate is inert planning for canonical registration and reference migration; it proves no consumer integration, product write, physical action, or live embodied capability." : null,
      id === "m14-cross-plane-correlated-failure-injection" ? "This amendment-gated candidate injects no fault and proves no selected service, demand, settlement, L1, recovery, or stage exit." : null,
      "This docs-and-orchestration record closes no work item, stage, runtime capability, application, or public claim.",
    ]),
    rollback_or_stop_rule: `Stop before implementation or claim widening on unknown owner/contract, missing dependency, uncontrolled final invoker, absent authority/receipt path, stale canon digest, mutable threshold, or failed branch: ${negative}. Roll back only through the affected owner's explicit successor/compensation path; never change status by prose.`,
    exit_criteria: [
      clean(spec?.deliverable ?? objective),
      `All positive, adversarial, stale-state, substitution, fault, recovery, product/operator-state, compatibility, migration, and evidence obligations above pass for the selected profile.`,
      `Retained evidence contains exactly one literal ${literal}; a task/process exit code, UI state, plan, or aggregate cannot substitute.`,
    ],
    pr: original?.pr ?? null,
    source_provenance: preExisting && original?.source_provenance
      ? (original.source_provenance.includes("Enriched under approved SA-2/SA-7/SA-9")
        ? original.source_provenance
        : `${original.source_provenance} Enriched under approved SA-2/SA-7/SA-9 private migration on 2026-07-22; status preserved.`)
      : spec?.sourceProvenance ?? `Approved private plan-level gap record from internal-docs/implementation/audits/2026-07-22-directory-unification-plan.md under SA-2/SA-7/SA-9; created proposed on 2026-07-22 and makes no implementation claim.`,
    last_status_transaction: original?.last_status_transaction ?? spec?.createdAt ?? "2026-07-22",
  };
}

const records = new Map();
for (const [id, current] of existing) {
  const original = baselineRecords.get(id) ?? current;
  const spec = specs.get(id);
  const stage = delegatedReviewGapSpecs.some((candidate) => candidate.id === id)
    ? spec.stage
    : original.stage_id;
  records.set(id, makeRecord(id, stage, original, spec));
}
for (const [id, spec] of specs) {
  if (!records.has(id)) records.set(id, makeRecord(id, spec.stage, null, spec));
}

const allIds = new Set(records.keys());
for (const [id, record] of records) {
  const original = existing.get(id);
  const baselineRecordPath = path.join(implementationRoot, `_archive/pre-unification-baseline/work-items/${id}.v1.json`);
  const dependencySource = fs.existsSync(baselineRecordPath) ? readJson(baselineRecordPath) : original;
  const spec = specs.get(id);
  const dependencies = [];
  for (const candidate of dependencySource?.dependencies ?? dependencySource?.dependency_work_item_ids ?? []) if (allIds.has(candidate)) dependencies.push(candidate);
  for (const match of (spec?.dependencies ?? "").matchAll(/`([^`]+)`/gu)) if (allIds.has(match[1])) dependencies.push(match[1]);
  const previous = PREVIOUS_STAGE[record.stage_id];
  if (record.status === "proposed" && previous && STAGE_AGGREGATE[previous]) dependencies.push(STAGE_AGGREGATE[previous]);
  record.dependency_work_item_ids = unique(dependencies).filter((dependency) => dependency !== id && dependency !== STAGE_AGGREGATE[record.stage_id]);
}

const explicitDependencies = {
  "m0-canon-owner-coverage-and-orphan-verifier": ["m0-work-item-contract-completeness-and-owner-lint"],
  "m0-route-final-invoker-pg-census-maintenance": ["m0-canon-owner-coverage-and-orphan-verifier"],
  "m0-selected-profile-baseline-evidence-and-claim-lock": ["m0-work-item-contract-completeness-and-owner-lint", "m0-canon-owner-coverage-and-orphan-verifier"],
  "m0-source-disposition-and-single-sequencer-verifier": ["m0-work-item-contract-completeness-and-owner-lint"],
  "m1-protected-migration-dissolution-enrollment": ["m1-5b-generic-protected-transitions", "m1-5c-amendment-execution"],
  "m1-system-genesis-product-journey": ["m1-genesis-admission", "m1-sequence-zero-materialization", "m1-governed-initialize-activate", "m1-5-protected-transitions", "m1-dual-genesis-and-read-projection"],
  "m2-agentgres-replay-recovery-and-product-topology": ["m2-membership-readiness-plane", "m2-writer-fence-and-lost-suffix", "m2-route-restore-activation-cleanup", "m2-node-attestation-identity-secret-readiness"],
  "project-discovery-startup-and-session-chain": ["m1-selected-profile-exit-proof", "m2-membership-readiness-plane", "m2-route-restore-activation-cleanup"],
  "storage-profile-repair-and-availability": ["m1-selected-profile-exit-proof", "m2-route-restore-activation-cleanup", "m2-agentgres-replay-recovery-and-product-topology"],
  "m3-work-session-automation-product-journey": ["m2-selected-profile-exit-proof", "m3-goal-kernel-context-and-runtime-truth-spine"],
  "production-information-flow-and-declassification": ["m0-route-final-invoker-pg-census-maintenance", "m2-selected-profile-exit-proof", "m3-goal-kernel-context-and-runtime-truth-spine"],
  "production-receipt-checkpoint-and-offline-proof": ["m2-selected-profile-exit-proof", "m3-goal-kernel-context-and-runtime-truth-spine"],
  "agentgres-production-readiness-and-branch-effects": ["m2-agentgres-replay-recovery-and-product-topology", "m3-goal-kernel-context-and-runtime-truth-spine"],
  "m5-pairing-identity-and-gateway-scope": ["m4-outcome-room-system-spine", "m5-local-agent-pairing"],
  "m5-attribution-acceptance-and-challenge-boundary": ["m4-outcome-room-system-spine", "m5-participant-frontier-result-closeout", "m5-portable-exit-independent-clients"],
  "m5-p0-readiness-verifier": ["m3-direct-path-and-exit-proof", "m4-outcome-room-system-spine", "m5-selected-profile-exit-proof"],
  "m6-surface-compiler-and-source-convergence": ["m5-p0-readiness-verifier", "m0-canon-owner-coverage-and-orphan-verifier"],
  "m6-production-truth-fallback-retirement": ["m5-p0-readiness-verifier", "m6-surface-compiler-and-source-convergence"],
  "m6-consequential-action-authority-receipt-unification": ["m3-direct-path-and-exit-proof", "m5-selected-profile-exit-proof", "m6-surface-compiler-and-source-convergence"],
  "m6-systems-work-projection-and-mission-alias-migration": ["m5-p0-readiness-verifier", "m6-surface-compiler-and-source-convergence"],
  "m6-owner-application-registration-and-shell-state-coverage": ["m6-surface-compiler-and-source-convergence", "m6-production-truth-fallback-retirement", "m6-catalog-route-alias-migration-accessibility"],
  "m6-catalog-route-alias-migration-accessibility": ["m6-surface-compiler-and-source-convergence", "m6-systems-work-projection-and-mission-alias-migration"],
  "m6-reference-shell-disposition-and-depth-ledger": ["m6-owner-application-registration-and-shell-state-coverage", "m6-consequential-action-authority-receipt-unification"],
  "sdk-cli-adk-odk-builder-journey": ["m5-p0-readiness-verifier", "m6-surface-compiler-and-source-convergence"],
  "m6-home-workspace-operational-journey": ["m6-surface-compiler-and-source-convergence", "m6-production-truth-fallback-retirement", "m6-consequential-action-authority-receipt-unification", "m6-catalog-route-alias-migration-accessibility"],
  "m6-systems-workspace-operational-journey": ["m6-surface-compiler-and-source-convergence", "m6-production-truth-fallback-retirement", "m6-consequential-action-authority-receipt-unification", "m6-catalog-route-alias-migration-accessibility", "m6-systems-work-projection-and-mission-alias-migration"],
  "m6-projects-workspace-operational-journey": ["m6-surface-compiler-and-source-convergence", "m6-production-truth-fallback-retirement", "m6-consequential-action-authority-receipt-unification", "m6-catalog-route-alias-migration-accessibility", "project-discovery-startup-and-session-chain"],
  "m6-applications-workspace-operational-journey": ["m6-surface-compiler-and-source-convergence", "m6-production-truth-fallback-retirement", "m6-consequential-action-authority-receipt-unification", "m6-catalog-route-alias-migration-accessibility", "m6-reference-shell-disposition-and-depth-ledger"],
  "m6-work-workspace-operational-journey": ["m5-p0-readiness-verifier", "m6-surface-compiler-and-source-convergence", "m6-production-truth-fallback-retirement", "m6-consequential-action-authority-receipt-unification", "m6-catalog-route-alias-migration-accessibility", "m6-systems-work-projection-and-mission-alias-migration"],
  "m6-automations-operational-journey": ["m6-surface-compiler-and-source-convergence", "m6-production-truth-fallback-retirement", "m6-consequential-action-authority-receipt-unification", "m6-catalog-route-alias-migration-accessibility"],
  "m6-packages-operational-journey": ["m6-surface-compiler-and-source-convergence", "m6-production-truth-fallback-retirement", "m6-consequential-action-authority-receipt-unification", "m6-catalog-route-alias-migration-accessibility"],
  "m6-developer-workspace-operational-journey": ["m6-surface-compiler-and-source-convergence", "m6-production-truth-fallback-retirement", "m6-consequential-action-authority-receipt-unification", "m6-catalog-route-alias-migration-accessibility"],
  "m7-ontology-action-final-invoker-and-product-proof": ["m7-data-transformation-provenance-replay", "m6-consequential-action-authority-receipt-unification"],
  "m7-studio-operational-journey": ["m6-product-surface-and-typed-workspaces", "m7-data-transformation-provenance-replay", "m7-ontology-action-final-invoker-and-product-proof"],
  "m7-ontology-operational-journey": ["m6-product-surface-and-typed-workspaces", "m7-data-transformation-provenance-replay", "m7-ontology-action-final-invoker-and-product-proof"],
  "m7-data-operational-journey": ["m6-product-surface-and-typed-workspaces", "m7-data-transformation-provenance-replay", "m7-ontology-action-final-invoker-and-product-proof"],
  "m8-model-supply-route-substitution-and-selected-exit": [],
  "foundry-evaluations-production-loop": ["m7-semantic-definition-action-plane", "m8-learning-custody-memory-and-provider-rights"],
  "m8-evaluations-operational-journey": ["m7-semantic-definition-action-plane", "foundry-evaluations-production-loop"],
  "m8-improvement-operational-journey": ["m7-semantic-definition-action-plane", "m8-order-zero-improvement-and-direct-path", "m8-evaluations-operational-journey"],
  "m8-foundry-operational-journey": ["m7-semantic-definition-action-plane", "m8-learning-custody-memory-and-provider-rights", "foundry-evaluations-production-loop"],
  "managed-billing-work-credits-and-supplier-reconciliation": ["m7-semantic-definition-action-plane"],
  "worker-training-and-local-marketplace-supply": ["m5-attribution-acceptance-and-challenge-boundary", "m7-semantic-definition-action-plane", "managed-billing-work-credits-and-supplier-reconciliation"],
  "marketplace-neutral-routing-contribution-accounting": ["m5-attribution-acceptance-and-challenge-boundary", "managed-billing-work-credits-and-supplier-reconciliation", "worker-training-and-local-marketplace-supply"],
  "m9-terminal-product-state-and-release-supply-chain": ["m8-model-supply-route-substitution-and-selected-exit", "m9-compact-advanced-object-hash-parity", "m9-sovereign-local-terminal-journey", "m9-authority-gateway-equivalence-and-coverage", "m9-lifecycle-evidence-operator-proof"],
  "platform-operability-observability-and-incidents": ["m8-model-supply-route-substitution-and-selected-exit"],
  "hypervisoros-ctee-task-capsule-attestation": ["m8-model-supply-route-substitution-and-selected-exit", "m9-terminal-product-state-and-release-supply-chain"],
  "m9-governance-operational-journey": ["m8-model-supply-route-substitution-and-selected-exit", "m9-authority-gateway-equivalence-and-coverage", "m9-sovereign-local-terminal-journey"],
  "m9-provenance-operational-journey": ["m8-model-supply-route-substitution-and-selected-exit", "production-receipt-checkpoint-and-offline-proof", "m9-lifecycle-evidence-operator-proof"],
  "m9-developer-console-operational-journey": ["m8-model-supply-route-substitution-and-selected-exit", "m9-authority-gateway-equivalence-and-coverage", "m9-sovereign-local-terminal-journey"],
  "m9-environments-operational-journey": ["m8-model-supply-route-substitution-and-selected-exit", "hypervisoros-ctee-task-capsule-attestation", "m9-terminal-product-state-and-release-supply-chain"],
  "m10-topology-chaos-and-operator-product-proof": ["m9-selected-profile-aggregate-exit-and-claim-publication", "m10-attestation-temporal-floor-and-revocation-continuity"],
  "m10-operations-operational-journey": ["m9-selected-profile-aggregate-exit-and-claim-publication", "m10-attestation-temporal-floor-and-revocation-continuity", "m10-topology-chaos-and-operator-product-proof"],
  "m11-foundry-promotion-safety-case-and-product-journey": ["m11-canonical-embodied-contract-alignment", "m11-embodied-nonlive-graph-proof", "m11-useful-same-system-distribution"],
  "m11-canonical-contract-registry-and-legacy-ref-migration": ["m11-selected-profile-exit-proof"],
  "m11-embodied-systems-nonlive-operational-journey": ["m6-surface-compiler-and-source-convergence", "m10-two-failure-domain-continuity", "m11-canonical-embodied-contract-alignment", "m11-embodied-nonlive-graph-proof", "m11-foundry-promotion-safety-case-and-product-journey"],
  "m12-federation-product-and-operator-journey": ["m12-ifc-disclosure-receipt-and-settlement-binding", "m12-aiip-channel-envelope-profile", "m12-terms-discovery-semantic-negotiation", "m12-federated-admission-portable-exit-and-bindings"],
  "dispute-adjudication-remedy-kernel": ["m5-attribution-acceptance-and-challenge-boundary", "m8-model-supply-route-substitution-and-selected-exit", "managed-billing-work-credits-and-supplier-reconciliation", "marketplace-neutral-routing-contribution-accounting", "m11-selected-profile-exit-proof"],
  "m13-independent-operation-and-external-worker-product-proof": ["m12-selected-profile-exit-proof", "m13-sovereignty-trial-preregistration", "m13-two-sovereign-surplus-and-decline-proof"],
  "m14-service-family-owner-contract-and-product-surfaces": ["m13-selected-profile-aggregate-exit", "managed-billing-work-credits-and-supplier-reconciliation", "marketplace-neutral-routing-contribution-accounting", "dispute-adjudication-remedy-kernel"],
  "connected-worker-capability-supply-and-hiring": ["m13-selected-profile-aggregate-exit", "worker-training-and-local-marketplace-supply", "managed-billing-work-credits-and-supplier-reconciliation", "marketplace-neutral-routing-contribution-accounting", "dispute-adjudication-remedy-kernel"],
  "ecosystem-assurance-and-public-claim-estate": ["m13-selected-profile-aggregate-exit"],
  "m14-cross-plane-correlated-failure-injection": ["m14-selected-profile-aggregate-exit"],
  "decentralized-profile-admission-and-exit": ["m13-selected-profile-aggregate-exit", "m14-service-family-owner-contract-and-product-surfaces"],
  "live-embodied-promotion": ["m11-selected-profile-exit-proof"],
};
for (const [id, dependencies] of Object.entries(explicitDependencies)) {
  if (!records.has(id)) continue;
  records.get(id).dependency_work_item_ids = unique(dependencies).filter((dependency) => records.has(dependency) && dependency !== id);
}

for (const [stage, aggregateId] of Object.entries(STAGE_AGGREGATE)) {
  const aggregate = records.get(aggregateId);
  if (!aggregate) throw new Error(`missing aggregate ${aggregateId}`);
  let children = [...records.values()]
    .filter((record) => record.stage_id === stage && record.work_item_id !== aggregateId)
    .map((record) => record.work_item_id);
  if (stage === "M1") children = children.filter((id) => !["m1-5b-generic-protected-transitions", "m1-5c-amendment-execution", "m1-protected-migration-dissolution-enrollment"].includes(id));
  if (stage === "M5") children = children.filter((id) => id !== "m5-p0-readiness-verifier");
  aggregate.aggregate_child_ids = children.sort();
  aggregate.dependency_work_item_ids = aggregate.aggregate_child_ids.filter((id) => ![
    "m9-managed-optionality-overlay",
    "m11-embodied-systems-nonlive-operational-journey",
    "decentralized-profile-admission-and-exit",
  ].includes(id));
  if (stage === "M9") {
    aggregate.dependency_work_item_ids.push(
      "production-information-flow-and-declassification",
      "production-receipt-checkpoint-and-offline-proof",
      "agentgres-production-readiness-and-branch-effects",
    );
  }
}
const protectedAggregate = records.get("m1-5-protected-transitions");
protectedAggregate.aggregate_child_ids = ["m1-5b-generic-protected-transitions", "m1-5c-amendment-execution", "m1-protected-migration-dissolution-enrollment"];
protectedAggregate.dependency_work_item_ids = [...protectedAggregate.aggregate_child_ids];

for (const record of records.values()) {
  if (record.record_role !== "aggregate_exit") {
    record.aggregate_child_ids = [];
    record.aggregate_child_dispositions = [];
    record.aggregate_verification_binding = null;
  }
  record.dependency_work_item_ids = unique(record.dependency_work_item_ids).sort();
}

const conditionalRuleByPair = new Map(
  CONDITIONAL_AGGREGATE_CHILD_RULES.map((rule) => [`${rule.aggregate_id}\u0000${rule.child_id}`, rule]),
);
for (const record of records.values()) {
  if (record.record_role !== "aggregate_exit") continue;
  record.aggregate_child_dispositions = record.aggregate_child_ids.map((childId) => {
    const rule = conditionalRuleByPair.get(`${record.work_item_id}\u0000${childId}`);
    if (!rule) {
      return {
        child_work_item_id: childId,
        selection_state: "unconditional_active",
        activation_gate_id: null,
        selection_authority: "sole-sequencer stage membership",
        selection_evidence_refs: [],
        disposition_basis: "This child is an unconditional member of the selected stage aggregate and must close before aggregate verification.",
      };
    }
    return {
      child_work_item_id: childId,
      selection_state: rule.selection_state,
      activation_gate_id: rule.activation_gate_id,
      selection_authority: "ioi-target-end-state-master-implementation-guide.md",
      selection_evidence_refs: [],
      disposition_basis: "This child remains in the complete aggregate census but is inactive until its explicit sequencer-owned activation gate is selected; nonselection creates no closure claim.",
    };
  });
  record.aggregate_verification_binding = null;
}
for (const rule of CONDITIONAL_AGGREGATE_CHILD_RULES) {
  const aggregate = records.get(rule.aggregate_id);
  const child = records.get(rule.child_id);
  if (!aggregate?.aggregate_child_ids.includes(rule.child_id)) {
    throw new Error(`${rule.aggregate_id} omits conditional aggregate child ${rule.child_id}`);
  }
  if (aggregate.dependency_work_item_ids.includes(rule.child_id)) {
    throw new Error(`${rule.aggregate_id} incorrectly makes conditional child ${rule.child_id} unconditional`);
  }
  if (!(child?.external_gates ?? []).some((gate) => gate.gate_id === rule.activation_gate_id)) {
    throw new Error(`${rule.child_id} lacks conditional activation gate ${rule.activation_gate_id}`);
  }
}

function exactStandaloneLiteralLineCount(file, literal) {
  if (!fs.existsSync(file)) return 0;
  return fs.readFileSync(file, "utf8").split(/\r?\n/u).filter((line) => line.trim() === literal).length;
}

function evidenceBindingFor(record) {
  const expectedLiteral = record.evidence_index?.literal_exit ?? null;
  const files = unique(record.evidence_refs ?? []).sort().map((ref) => {
    const absolute = path.join(repoRoot, ref);
    const exists = fs.existsSync(absolute);
    return {
      path: ref,
      exists,
      sha256: exists ? sha256File(absolute) : null,
      exact_literal_line_count: exists && expectedLiteral
        ? exactStandaloneLiteralLineCount(absolute, expectedLiteral)
        : 0,
    };
  });
  const body = {
    expected_literal: expectedLiteral,
    evidence_files: files,
    exact_literal_line_count: files.reduce((total, file) => total + file.exact_literal_line_count, 0),
  };
  return {
    ...body,
    literal_valid: body.exact_literal_line_count === 1,
    evidence_bundle_sha256: sha256(stableJson(body)),
  };
}

function boundRecord(recordId, relation, selectionState = null) {
  const record = records.get(recordId);
  if (!record) throw new Error(`aggregate binding names unknown record ${recordId}`);
  return {
    work_item_id: recordId,
    relation,
    selection_state: selectionState,
    record_sha256: sha256(stableJson(record)),
    status_at_binding: record.status,
    evidence_binding: evidenceBindingFor(record),
  };
}

const aggregateBindingVisiting = new Set();
const aggregateBindingComplete = new Set();
function finalizeAggregateBinding(aggregateId) {
  if (aggregateBindingComplete.has(aggregateId)) return;
  if (aggregateBindingVisiting.has(aggregateId)) throw new Error(`aggregate binding cycle at ${aggregateId}`);
  aggregateBindingVisiting.add(aggregateId);
  const aggregate = records.get(aggregateId);
  if (!aggregate || aggregate.record_role !== "aggregate_exit") throw new Error(`cannot bind non-aggregate ${aggregateId}`);
  const referencedIds = unique([
    ...aggregate.aggregate_child_ids,
    ...aggregate.dependency_work_item_ids,
  ]);
  for (const referencedId of referencedIds) {
    if (records.get(referencedId)?.record_role === "aggregate_exit") finalizeAggregateBinding(referencedId);
  }
  const dispositionByChild = new Map(
    aggregate.aggregate_child_dispositions.map((entry) => [entry.child_work_item_id, entry]),
  );
  const childBindings = aggregate.aggregate_child_ids.map((childId) =>
    boundRecord(childId, "aggregate_child", dispositionByChild.get(childId)?.selection_state ?? null),
  );
  const dependencyBindings = aggregate.dependency_work_item_ids.map((dependencyId) =>
    boundRecord(dependencyId, "unconditional_dependency"),
  );
  const aggregateEvidenceBinding = evidenceBindingFor(aggregate);
  const bindingPayload = {
    child_dispositions: aggregate.aggregate_child_dispositions,
    child_bindings: childBindings,
    dependency_bindings: dependencyBindings,
    aggregate_evidence_binding: aggregateEvidenceBinding,
  };
  aggregate.aggregate_verification_binding = {
    schema_version: "ioi.program.aggregate-verification-binding.v1",
    ...bindingPayload,
    binding_payload_sha256: sha256(stableJson(bindingPayload)),
    nonclaim: "This exact-digest binding is a private closure precondition. It does not promote a child, dependency, proof gate, aggregate, work item, or stage and cannot substitute for literal-valid retained evidence.",
  };
  aggregateBindingVisiting.delete(aggregateId);
  aggregateBindingComplete.add(aggregateId);
}
for (const aggregateId of AGGREGATES) finalizeAggregateBinding(aggregateId);

for (const record of records.values()) {
  fs.writeFileSync(path.join(workItemsRoot, `${record.work_item_id}.v1.json`), stableJson(record));
}

for (const baseline of preservation.before) {
  const current = readJson(path.join(workItemsRoot, `${baseline.work_item_id}.v1.json`));
  if (current.status !== baseline.status) throw new Error(`migration changed status for ${baseline.work_item_id}: ${baseline.status} -> ${current.status}`);
}
preservation.after_count = records.size;
preservation.added_count = records.size - preservation.before.length;
preservation.after_statuses = [...records.values()].reduce((accumulator, record) => {
  accumulator[record.status] = (accumulator[record.status] ?? 0) + 1;
  return accumulator;
}, {});
preservation.existing_statuses_unchanged = preservation.before.every((entry) => records.get(entry.work_item_id)?.status === entry.status);
preservation.new_records_all_proposed = [...records.values()].filter((record) => !preservation.before.some((entry) => entry.work_item_id === record.work_item_id)).every((record) => record.status === "proposed");
preservation.no_exit_logs_created = true;
preservation.nonclaims = [
  "Record enrichment and creation implement no runtime behavior.",
  "A declared *_EXIT=0 is a future contract, not retained evidence.",
  "No work item or stage changed status in this transaction."
];
fs.writeFileSync(preservationPath, stableJson(preservation));

process.stdout.write(`work-item migration written: ${preservation.before.length} statuses preserved, ${preservation.added_count} proposed records added, ${records.size} total\n`);
