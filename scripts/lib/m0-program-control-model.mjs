import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  aggregateLiteralCalls,
  assertUniqueIdentities,
  attachRustHandlerDefinitions,
  buildRustFunctionIndex,
  discoverAxumRoutes,
  discoverJsStorageMutations,
  discoverJsOutboundCalls,
  discoverLiteralCalls,
  discoverProtoService,
  discoverJsSystemEffects,
  discoverProtoServiceNames,
  discoverRustFunctions,
  discoverRustMatchServiceMethods,
  discoverRustServiceInterfaceMethods,
  discoverSwitchCases,
  discoverTonicServiceRegistrations,
  discoverWalletServiceMethods,
  javascriptSourceHasEffects,
  lexSource,
  readRepoFile,
  rustModuleSourceMap,
  sha256,
  sortByIdentity,
} from "./m0-program-control.mjs";

export const EVIDENCE_DIR = "docs/evidence/m0-program-control";
export const REVIEW_FILE = `${EVIDENCE_DIR}/reviewed-entry-lock.json`;
export const REVIEW_ANCHOR_FILE = `${EVIDENCE_DIR}/review-epoch-anchor.json`;
export const PROGRAM_SOURCE_FILE = `${EVIDENCE_DIR}/program-control-source.json`;
export const README_FILE = `${EVIDENCE_DIR}/README.md`;
export const M0_BASELINE_AS_OF_DATE = "2026-07-18";
export const AS_OF_DATE = "2026-07-19";

const REPOSITORY_BASELINE_ANCHOR = Object.freeze({
  sequence: 2,
  epoch_id: "pr-91-integrated-authority-and-m1-4-review-2026-07-20",
  entry_sha256:
    "c2624cdd359487b3cde76b107b467dd610f6fd80166b065baf653cf68fa7e50d",
});

// The anchor is an unsigned hash chain. Legacy entries (sequence <= 6) retain
// their historical Ed25519 evidence blocks as immutable retained claims, but
// no key is pinned, read, or verified: a co-located machine key proved nothing
// beyond what the predecessor hash chain already proves, so the ceremony was
// retired (2026-07-22 program decision) rather than left overclaiming.
// Real signing authority arrives later with wallet-network auth.
export const SUPPLIED_SNAPSHOT_ASSURANCE_POSTURE = Object.freeze({
  chain_integrity_within_snapshot: "verified",
  snapshot_head_binding: "verified",
  repository_baseline_present: true,
  authorship_binding: "self_declared_label_unsigned",
  accepted_head_currentness: "not_established",
  coherent_snapshot_rollback_resistance: "not_established",
});

const REPOSITORY_ANCHOR_CONTEXT = Object.freeze({
  repository_baseline: REPOSITORY_BASELINE_ANCHOR,
});

const REVIEW_COMPARISON_BASELINE = Object.freeze({
  baseline_id: "m0-review-lock-branch-point-2026-07-18",
  source_commit: "562d1b08999be2e9bbb967ef60bb250f440452e5",
  reviewed_as_of: "2026-07-18",
  reviewed_entry_count: 1538,
  entry_commitments_sha256:
    "5241809de8f95ca1e9ec020bc9f98c73688865c163102944e259a8c59bdb19f0",
});

export const GENERATED_ARTIFACT_FILES = [
  "effect-census.json",
  "selected-profile.json",
  "pg-gate-map.json",
  "current-baselines.json",
  "blocker-ledger.json",
  "release-ladder.json",
  "program-evidence-index.json",
  "m0-exit-report.json",
  "manifest.json",
];

const MUTATING_HTTP_METHODS = new Set([
  "ANY",
  "CONNECT",
  "DELETE",
  "PATCH",
  "POST",
  "PUT",
  "TRACE",
]);
const ENTRY_CLASSIFICATIONS = new Set([
  "consequential",
  "read_only",
  "plan_only",
  "compatibility",
  "internal_only",
  "unavailable_contract",
]);
const IMPLEMENTATION_STATES = new Set(["terminal", "partial", "unavailable", "not_applicable"]);
const PG_DISPOSITIONS = new Set(["required_now", "conditional", "later", "out_of_scope"]);
const BASELINE_CATEGORIES = new Set(["product", "reliability", "cost", "comprehension"]);
const REVIEW_DIMENSIONS = [
  "classification_and_effect_class",
  "owner_and_source_anchor",
  "handler_and_final_invoker_claim",
  "pre_effect_gates_without_ui_inference",
  "durable_evidence_idempotency_and_recovery",
  "selected_profile_applicability_and_typed_blocker",
];
const REQUIRED_PROOF_LANE_VALIDATION_POSTURE =
  "semantically validated exact lane ids, order, prerequisites, evidence sets, blocker identities, route sets, and canon-anchored owner sources; named blockers remain open until the product journeys pass";
const REQUIRED_PROOF_LANES = Object.freeze([
  Object.freeze({
    lane_id: "sovereign_local_completeness",
    order: 1,
    prerequisite_lane_id: undefined,
    starting_state: "fresh standalone deployment",
    claim_requirement:
      "required for the minimum-L0 local-completeness claim and every stronger claim that depends on it",
    authority_posture:
      "deployment-local authentication remains distinct from locally permitted exact-effect authority; no portable delegated-authority claim",
    endpoint_posture:
      "all IOI-managed endpoints denied; loopback and declared local IPC allowed",
    required_evidence: Object.freeze([
      "network-blocked terminal product journey",
      "restart and replay",
      "backup and clean restore",
      "offline evidence export and independent verification",
    ]),
  }),
  Object.freeze({
    lane_id: "managed_optionality_overlay",
    order: 2,
    prerequisite_lane_id: "sovereign_local_completeness",
    starting_state:
      "the same independently operable System after a passing sovereign-local lane",
    claim_requirement:
      "required only for managed-optionality claims and claims that depend on managed attachment",
    authority_posture:
      "provider-neutral account authentication plus passkey-capable context-bound portable authority when connected policy requires it",
    connection_posture:
      "explicitly attach one named managed service, execute one admitted operation, prove no implicit transfer or unnamed-use billing, then revoke or detach it",
    required_evidence: Object.freeze([
      "explicit attachment receipt",
      "connected identity and context-bound portable authority when required",
      "one explicitly leased and receipted named managed-service use",
      "exact binding, data-view, lease, RuntimeAssignment, custody, usage, charge, and receipt inspection",
      "zero implicit transfer or charge without named service use",
      "detach or revocation receipt",
      "post-detach continuation for locally satisfied dependencies",
    ]),
  }),
]);
const REQUIRED_PROOF_LANE_BINDINGS = Object.freeze([
  Object.freeze({
    binding_id: "sovereign-local-identity",
    lane_id: "sovereign_local_completeness",
    step: 1,
    blocker_ref: "BLK-M0-SELECTED-LOCAL-IDENTITY-AUTHORITY",
    blocker_type: "local_authority_path_unavailable",
    blocker_state: "open",
    route_identities: Object.freeze([
      "http:hypervisor-daemon:POST /v1/hypervisor/auth/login",
      "http:hypervisor-daemon:GET /v1/hypervisor/auth/whoami",
    ]),
  }),
  Object.freeze({
    binding_id: "managed-connected-identity",
    lane_id: "managed_optionality_overlay",
    step: 1,
    blocker_ref: "BLK-M0-SELECTED-IDENTITY-STEP-UP",
    blocker_type: "authority_path_unavailable",
    blocker_state: "open",
    route_identities: Object.freeze([]),
  }),
  Object.freeze({
    binding_id: "sovereign-local-effect-authority",
    lane_id: "sovereign_local_completeness",
    step: 9,
    blocker_ref: "BLK-M0-SELECTED-LOCAL-IDENTITY-AUTHORITY",
    blocker_type: "local_authority_path_unavailable",
    blocker_state: "open",
    route_identities: Object.freeze([
      "http:hypervisor-daemon:POST /v1/hypervisor/authority/preflight",
    ]),
  }),
  Object.freeze({
    binding_id: "managed-portable-effect-authority",
    lane_id: "managed_optionality_overlay",
    step: 9,
    blocker_ref: "BLK-M0-SELECTED-IDENTITY-STEP-UP",
    blocker_type: "authority_path_unavailable",
    blocker_state: "open",
    route_identities: Object.freeze([
      "service:wallet.network:issue_session_grant@v1",
      "service:wallet.network:issue_principal_authority_binding@v1",
    ]),
  }),
  Object.freeze({
    binding_id: "managed-attach-and-use",
    lane_id: "managed_optionality_overlay",
    step: 13,
    blocker_ref: "BLK-M0-SELECTED-MANAGED-ATTACH-USE",
    blocker_type: "managed_service_use_proof_unavailable",
    blocker_state: "open",
    route_identities: Object.freeze([]),
  }),
  Object.freeze({
    binding_id: "managed-detach-and-continue",
    lane_id: "managed_optionality_overlay",
    step: 13,
    blocker_ref: "BLK-M0-SELECTED-MANAGED-DETACH",
    blocker_type: "managed_detach_continuity_unavailable",
    blocker_state: "open",
    route_identities: Object.freeze([]),
  }),
]);

function hasExactStringSet(actual, expected) {
  return Array.isArray(actual)
    && actual.length === expected.length
    && new Set(actual).size === actual.length
    && [...actual].sort().every((value, index) => (
      value === [...expected].sort()[index]
    ));
}

export const PG_IDS = [
  "PG-0.1", "PG-0.2", "PG-0.3",
  "PG-1.1", "PG-1.2", "PG-1.3",
  "PG-2.1", "PG-2.2", "PG-2.3", "PG-2.4", "PG-2.5", "PG-2.6",
  "PG-3.1", "PG-3.2", "PG-3.3", "PG-3.4", "PG-3.5", "PG-3.6",
  "PG-4A.1", "PG-4A.2", "PG-4A.3", "PG-4A.4", "PG-4A.5", "PG-4A.6",
  "PG-4B.1", "PG-4B.2", "PG-4B.3", "PG-4B.4", "PG-4B.5", "PG-4B.6",
  "PG-5.1", "PG-5.2", "PG-5.3", "PG-5.4", "PG-5.5",
  "PG-6A.1", "PG-6A.2", "PG-6A.3", "PG-6A.4",
  "PG-6B.1", "PG-6B.2", "PG-6B.3", "PG-6B.4", "PG-6B.5",
  "PG-6C.1", "PG-6C.2", "PG-6C.3",
  "PG-6D.1", "PG-6D.2", "PG-6D.3",
  "PG-7.1", "PG-7.2", "PG-7.3", "PG-7.4",
  "PG-7.5", "PG-7.6", "PG-7.7", "PG-7.8",
];

const CANON_BASIS_FILES = [
  "docs/architecture/_meta/execution-horizons.md",
  "docs/architecture/_meta/implementation-matrix.md",
  "docs/architecture/_meta/source-of-truth-map.md",
  "docs/architecture/foundations/common-objects-and-envelopes.md",
  "docs/architecture/foundations/governed-autonomous-systems.md",
  "docs/architecture/foundations/invariants.md",
  "docs/architecture/foundations/institutional-learning-boundary.md",
  "docs/architecture/components/daemon-runtime/doctrine.md",
  "docs/architecture/components/daemon-runtime/api.md",
  "docs/architecture/components/daemon-runtime/events-receipts-delivery-bundles.md",
  "docs/architecture/components/daemon-runtime/platform-operability.md",
  "docs/architecture/components/daemon-runtime/improvement-governance-gates.md",
  "docs/architecture/components/wallet-network/doctrine.md",
  "docs/architecture/components/wallet-network/api-authority-scopes.md",
  "docs/architecture/components/agentgres/doctrine.md",
  "docs/architecture/components/agentgres/api-object-model.md",
  "docs/architecture/components/hypervisor/core-clients-surfaces.md",
  "docs/architecture/components/hypervisor/identity-access-and-metering.md",
  "docs/architecture/components/hypervisor/providers-and-environments.md",
  "docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md",
  "docs/conformance/hypervisor-core/platform-operability.md",
  "docs/conformance/hypervisor-core/platform-fault-matrix.v1.json",
  "docs/conformance/hypervisor-core/sovereign-local-completeness.md",
  "docs/conformance/hypervisor-core/sovereign-local-completeness-matrix.v1.json",
];

const EXTERNAL_UNTRACKED_OPERATOR_INPUTS = [
  {
    input_id: "target_end_state_master_implementation_guide",
    path:
      "internal-docs/implementation/ioi-target-end-state-master-implementation-guide.md",
    role: "external operator sequencing input",
    tracking_posture: "ignored_untracked",
    evidence_binding: "not_read_not_hashed_not_bound",
  },
  {
    input_id: "canon_mechanism_hardening_action_plan",
    path:
      "internal-docs/implementation/canon-mechanism-hardening-action-plan.md",
    role: "external operator production-gate input",
    tracking_posture: "ignored_untracked",
    evidence_binding: "not_read_not_hashed_not_bound",
  },
];

function createSequencingAuthority() {
  return {
    external_untracked_operator_inputs:
      EXTERNAL_UNTRACKED_OPERATOR_INPUTS.map((entry) => ({ ...entry })),
    legacy_default: "non_authoritative",
    tracked_architecture_evidence_authority: {
      root: "docs/architecture/",
      binding: "program_control_source.canon_basis_sha256",
      role: "committed architecture and status evidence authority",
    },
    tracked_conformance_evidence: {
      root: "docs/conformance/",
      binding: "program_control_source.canon_basis_sha256",
      role: "committed selected-profile conformance evidence",
    },
    rule:
      "External untracked operator inputs may sequence work, but only tracked canon and conformance sources bound in canon_basis provide committed M0 evidence.",
  };
}

function createPgGateMetadata() {
  return {
    external_definition_input: {
      path:
        "internal-docs/implementation/canon-mechanism-hardening-action-plan.md",
      tracking_posture: "ignored_untracked",
      evidence_binding: "not_read_not_hashed_not_bound",
    },
    tracked_selected_profile_authority:
      "docs/architecture/_meta/execution-horizons.md",
  };
}

const DISCOVERY_COVERAGE = Object.freeze({
  axum_route_registry: Object.freeze({
    pattern:
      /(?:\.|::)(?:fallback|fallback_service|merge|method_not_allowed_fallback|nest|nest_service|route|route_service)\s*\(/u,
    suffix: ".rs",
    root: "crates",
    files: Object.freeze({
      "crates/node/src/bin/hypervisor-daemon.rs":
        "enumerated Hypervisor daemon registry",
      "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs":
        "enumerated conditional session-preview registry",
      "crates/plugins/http-rpc-gateway/src/lib.rs":
        "enumerated IBC HTTP registry",
      "crates/telemetry/src/http.rs":
        "enumerated telemetry HTTP registry",
      "crates/validator/src/standard/provider/server.rs":
        "enumerated provider HTTP registry",
    }),
  }),
  blockchain_service_implementation: Object.freeze({
    pattern:
      /impl(?:\s*<[^>{}]+>)?\s+(?:[A-Za-z_][A-Za-z0-9_]*::)*BlockchainService\s+for/u,
    suffix: ".rs",
    root: "crates",
    files: Object.freeze({
      "crates/consensus/src/service.rs": "enumerated native service",
      "crates/execution/src/runtime_service/mod.rs":
        "enumerated manifest-defined dynamic service wildcard",
      "crates/macros/src/lib.rs":
        "service_interface expansion source; generated registries are enumerated and macro-bound",
      "crates/plugins/ibc-service/src/core/registry.rs": "enumerated native service",
      "crates/services/src/agentic/leakage.rs": "enumerated native service",
      "crates/services/src/agentic/runtime/service/mod.rs": "enumerated native service",
      "crates/services/src/guardian_registry/service.rs": "enumerated native service",
      "crates/services/src/identity/mod.rs": "enumerated native service",
      "crates/services/src/provider_registry/mod.rs": "enumerated native service",
      "crates/services/src/wallet_network/mod.rs":
        "enumerated wallet.network service registry",
      "crates/vm/wasm/src/wasm_service.rs":
        "no externally callable service method; transaction decorator and end-block hooks only",
    }),
  }),
  proto_rpc_registry: Object.freeze({
    pattern: /\brpc\s+[A-Za-z_][A-Za-z0-9_]*\s*\(/u,
    suffix: ".proto",
    root: "crates",
    files: Object.freeze({
      "crates/ipc/proto/blockchain/v1/blockchain.proto":
        "enumerated mounted workload RPC registries",
      "crates/ipc/proto/control/v1/control.proto":
        "enumerated mounted workload and conditional Guardian RPC registries",
      "crates/ipc/proto/model_mount/v1/model_mount.proto":
        "enumerated unmounted compatibility contract",
      "crates/ipc/proto/public/v1/public.proto":
        "enumerated mounted public API registry",
    }),
  }),
  tonic_service_registration: Object.freeze({
    pattern: /\.add_service\s*\(/u,
    suffix: ".rs",
    root: "crates",
    files: Object.freeze({
      "crates/node/src/bin/guardian.rs":
        "enumerated conditional Guardian gRPC registry",
      "crates/validator/src/standard/orchestration/lifecycle.rs":
        "enumerated mounted public API registry",
      "crates/validator/src/standard/workload/ipc/mod.rs":
        "enumerated mounted internal workload RPC registries",
    }),
  }),
  rust_listener_or_server_source: Object.freeze({
    pattern:
      /(?:TcpListener::bind|UnixListener::bind|warp::serve|axum::serve|Server::builder|Server::bind|serve_with_shutdown|serve_with_incoming)/u,
    suffix: ".rs",
    root: "crates",
    files: Object.freeze({
      "crates/agentgres/src/bin/replica.rs":
        "enumerated standalone AGRS2 replication binary registration",
      "crates/agentgres/src/mux.rs":
        "ReplicaServer binds occur only in the cfg(test) module",
      "crates/agentgres/src/replica.rs":
        "enumerated standalone AGRS2 replication wildcard",
      "crates/cli/src/testing/backend.rs": "test support, not a shipped application listener",
      "crates/cli/src/testing/validator.rs": "test support, not a shipped application listener",
      "crates/node/src/bin/guardian.rs": "enumerated conditional Guardian gRPC registry",
      "crates/node/src/bin/hypervisor-daemon.rs": "enumerated Hypervisor daemon registry",
      "crates/node/src/bin/hypervisor_daemon_routes/editor_host.rs":
        "ephemeral free-port reservation and private child runtime, reached through enumerated daemon and proxy entries",
      "crates/node/src/bin/hypervisor_daemon_routes/editor_proxy.rs":
        "enumerated dynamic lease-gated editor proxy wildcard",
      "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs":
        "enumerated conditional session-preview registry",
      "crates/node/src/bin/signer.rs": "enumerated signer POST /sign surface",
      "crates/plugins/http-rpc-gateway/src/lib.rs": "enumerated IBC HTTP registry",
      "crates/services/src/agentic/runtime/connectors/google_auth.rs":
        "enumerated conditional Google OAuth callback",
      "crates/services/src/agentic/runtime/kernel/model_mount/lifecycle/inventory.rs":
        "cfg(test) fixture listener within a production source file",
      "crates/services/src/agentic/runtime/kernel/model_mount/provider_execution.rs":
        "cfg(test) fixture listener within a production source file",
      "crates/services/src/agentic/runtime/kernel/model_mount/provider_execution/stream.rs":
        "cfg(test) fixture listener within a production source file",
      "crates/services/src/agentic/runtime/kernel/model_mount/storage_control.rs":
        "cfg(test) fixture listener within a production source file",
      "crates/telemetry/src/http.rs": "enumerated telemetry HTTP registry",
      "crates/validator/src/common/guardian/server.rs":
        "enumerated encrypted Guardian channel wildcard",
      "crates/validator/src/standard/orchestration/lifecycle.rs":
        "enumerated mounted public API registry",
      "crates/validator/src/standard/provider/server.rs":
        "enumerated provider HTTP registry",
      "crates/validator/src/standard/workload/ipc/mod.rs":
        "enumerated mounted internal workload RPC registries",
    }),
  }),
  service_interface_registry: Object.freeze({
    pattern:
      /#\s*\[\s*(?:[A-Za-z_][A-Za-z0-9_]*::)*service_interface/u,
    suffix: ".rs",
    root: "crates",
    files: Object.freeze({
      "crates/cli/src/commands/scaffold.rs":
        "source template only; generated services are not mounted by this file",
      "crates/services/src/agentic/evolution.rs": "enumerated unavailable legacy service",
      "crates/services/src/agentic/optimizer.rs": "enumerated native service",
      "crates/services/src/governance/mod.rs": "enumerated native service",
      "crates/services/src/market/mod.rs": "enumerated native service",
    }),
  }),
});

const ACTIVE_JAVASCRIPT_EFFECT_SOURCE_COVERAGE = Object.freeze({
  "apps/benchmarks/src/App.tsx": "active application read projection",
  "apps/hypervisor/scripts/augmentation/10-run-timeline.js":
    "dynamically concatenated product UI read crossing",
  "apps/hypervisor/scripts/augmentation/35-app-catalog.js":
    "dynamically concatenated product UI read crossing",
  "apps/hypervisor/scripts/augmentation/40-home-explorer.js":
    "dynamically concatenated product UI read crossing",
  "apps/hypervisor/scripts/augmentation/50-new-session.js":
    "dynamically concatenated product UI read, plan, and mutation crossings",
  "apps/hypervisor/scripts/augmentation/70-cockpit-panel.js":
    "dynamically concatenated product UI read and mutation crossings",
  "apps/hypervisor/scripts/ioi-agent-runs.mjs":
    "standing product UI daemon crossings",
  "apps/hypervisor/scripts/ioi-api-adapter.mjs":
    "standing product UI daemon crossings and local preference file",
  "apps/hypervisor/scripts/serve-product-ui.mjs":
    "standing product UI server, proxy, and daemon crossings",
  "apps/hypervisor/src/dev/hypervisorDevHostBridge.ts":
    "Vite development replay mutation crossing",
  "apps/hypervisor/src/dev/hypervisorDevReplayClient.ts":
    "Vite development replay read crossing and local endpoint state",
  "apps/hypervisor/src/services/HypervisorClientRuntime.ts":
    "active literal host commands and local compatibility state",
  "apps/hypervisor/src/services/hypervisorAppearance.ts":
    "active browser appearance compatibility state",
  "apps/hypervisor/src/services/hypervisorHostBridge.ts":
    "dynamic host bridge leaf; all active literal callers are enumerated",
  "apps/hypervisor/src/services/hypervisorLaunchState.ts":
    "active literal host commands and local compatibility state",
  "apps/hypervisor/surfaces/approvals/index.mjs":
    "standing product UI read and mutation crossings",
  "apps/hypervisor/surfaces/ontology-context.mjs":
    "standing product UI read crossing",
  "apps/hypervisor/surfaces/ontology-manager/index.mjs":
    "standing product UI read crossings",
  "apps/hypervisor/surfaces/pipeline/index.mjs":
    "standing product UI read crossings",
  "apps/hypervisor/surfaces/sources/index.mjs":
    "standing product UI read and mutation crossings",
  "apps/sas-xyz/v2/app.jsx": "active demo application browser compatibility state",
  "scripts/lib/mint-approval-grant.mjs":
    "explicit test-signer child-process crossing, dynamically loaded only by the development flag",
  "scripts/hypervisor-app-dev-replay-server.mjs":
    "development replay dispatch, local evidence write, and configured model upstream",
});

const ACTIVE_JAVASCRIPT_SERVER_SOURCE_COVERAGE = Object.freeze({
  "apps/hypervisor/product-ui/server.cjs":
    "spawned reference UI compatibility server; dynamic mock and static fallback are file-locked",
  "apps/hypervisor/scripts/serve-product-ui.mjs":
    "standing product UI HTTP and WebSocket compatibility facade",
  "scripts/hypervisor-app-dev-replay-server.mjs":
    "explicit development replay HTTP server",
});

const JS_SYSTEM_EFFECT_ACTIONS = Object.freeze({
  "js-system-effect:apps/hypervisor/scripts/ioi-api-adapter.mjs#saveStore": Object.freeze({
    surface: "hypervisor-product-ui-local-state",
    operation: "ANY /api/ioi.v1.UserService/SetPreference",
    method: "ANY",
    path: "/api/ioi.v1.UserService/SetPreference",
    active_state: "standing_serve_product_ui_compatibility_surface",
  }),
  "js-system-effect:apps/hypervisor/scripts/serve-product-ui.mjs#module_scope_line_6433":
    Object.freeze({
      surface: "hypervisor-product-ui-process",
      operation: "PROCESS_EXIT product-ui reference bundle unavailable",
      method: "PROCESS_EXIT",
      path: "serve-product-ui process",
      active_state: "standing_serve_product_ui_startup_failure",
    }),
  "js-system-effect:apps/hypervisor/scripts/serve-product-ui.mjs#module_scope_line_6437":
    Object.freeze({
      surface: "hypervisor-product-ui-process",
      operation: "PROCESS_START product-ui reference server",
      method: "PROCESS_START",
      path: "REF_SERVER",
      active_state: "standing_serve_product_ui_startup",
    }),
  "js-system-effect:apps/hypervisor/scripts/serve-product-ui.mjs#module_scope_line_6441":
    Object.freeze({
      surface: "hypervisor-product-ui-process",
      operation: "PROCESS_EXIT propagate product-ui reference server exit",
      method: "PROCESS_EXIT",
      path: "serve-product-ui process",
      active_state: "standing_serve_product_ui_child_exit_handler",
    }),
  "js-system-effect:apps/hypervisor/scripts/serve-product-ui.mjs#module_scope_line_6442":
    Object.freeze({
      surface: "hypervisor-product-ui-process",
      operation: "SIGINT terminate product-ui reference server",
      method: "SIGINT",
      path: "productUi child",
      active_state: "standing_serve_product_ui_signal_handler",
    }),
  "js-system-effect:apps/hypervisor/scripts/serve-product-ui.mjs#waitForMirror":
    Object.freeze({
      surface: "hypervisor-product-ui-process",
      operation: "PROCESS_EXIT product-ui reference server startup timeout",
      method: "PROCESS_EXIT",
      path: "serve-product-ui process",
      active_state: "standing_serve_product_ui_startup_probe_failure",
    }),
  "js-system-effect:scripts/hypervisor-app-dev-replay-server.mjs#module_scope_line_3701":
    Object.freeze({
      surface: "hypervisor-dev-replay",
      operation: "PROCESS_EXIT development replay startup failure",
      method: "PROCESS_EXIT",
      path: "hypervisor dev replay process",
      active_state: "development_replay_cli_failure",
    }),
  "js-system-effect:scripts/hypervisor-app-dev-replay-server.mjs#shutdown":
    Object.freeze({
      surface: "hypervisor-dev-replay",
      operation: "PROCESS_EXIT development replay signal shutdown",
      method: "PROCESS_EXIT",
      path: "hypervisor dev replay process",
      active_state: "development_replay_signal_handler",
    }),
  "js-system-effect:apps/hypervisor/scripts/serve-product-ui.mjs#module_scope_line_6443":
    Object.freeze({
      surface: "hypervisor-product-ui-process",
      operation: "SIGTERM terminate product-ui reference server",
      method: "SIGTERM",
      path: "productUi child",
      active_state: "standing_serve_product_ui_signal_handler",
    }),
  "js-system-effect:scripts/hypervisor-app-dev-replay-server.mjs#writeEvidenceFile":
    Object.freeze({
      surface: "hypervisor-dev-replay",
      operation: "explicitly configured development evidence file write",
      method: "EXPLICIT_WRITE",
      path: "configured --evidence path",
      active_state: "development_replay_with_explicit_evidence_path",
    }),
  "js-system-effect:scripts/lib/mint-approval-grant.mjs#mintApprovalGrant": Object.freeze({
    surface: "hypervisor-product-ui-test-signer",
    operation: "PROCESS_EXEC build and invoke deterministic test approval signer",
    method: "PROCESS_EXEC",
    path: "cargo build then target/debug/mint-approval-grant",
    active_state: "development_only_when_IOI_WALLET_TEST_SIGNER_equals_1",
  }),
});

const ROUTE_DIRECTORY = "crates/node/src/bin/hypervisor_daemon_routes";
const DAEMON_FILE = "crates/node/src/bin/hypervisor-daemon.rs";
const WALLET_DIRECTORY = "crates/services/src/wallet_network";
const WALLET_FILE = "crates/services/src/wallet_network/mod.rs";
const PUBLIC_PROTO = "crates/ipc/proto/public/v1/public.proto";
const GUARDIAN_PROTO = "crates/ipc/proto/control/v1/control.proto";

const PROTO_SERVICE_INVENTORY = Object.freeze({
  "crates/ipc/proto/blockchain/v1/blockchain.proto": Object.freeze([
    "ChainControl",
    "ContractControl",
    "StakingControl",
    "StateQuery",
    "SystemControl",
  ]),
  "crates/ipc/proto/control/v1/control.proto": Object.freeze([
    "GuardianControl",
    "WorkloadControl",
  ]),
  "crates/ipc/proto/model_mount/v1/model_mount.proto": Object.freeze([
    "ModelMountService",
  ]),
  "crates/ipc/proto/public/v1/public.proto": Object.freeze([
    "PublicApi",
  ]),
});

const TONIC_SERVICE_MOUNTS = Object.freeze({
  "crates/node/src/bin/guardian.rs": Object.freeze(["GuardianControl"]),
  "crates/validator/src/standard/orchestration/lifecycle.rs":
    Object.freeze(["PublicApi"]),
  "crates/validator/src/standard/workload/ipc/mod.rs": Object.freeze([
    "ChainControl",
    "ContractControl",
    "StakingControl",
    "StateQuery",
    "SystemControl",
    "WorkloadControl",
  ]),
});

function listFiles(repoRoot, relativeDirectory, suffix) {
  return fs.readdirSync(path.join(repoRoot, relativeDirectory))
    .filter((name) => name.endsWith(suffix))
    .sort()
    .map((name) => `${relativeDirectory}/${name}`);
}

function listFilesRecursive(repoRoot, relativeDirectory, suffix) {
  const files = [];
  const visit = (directory) => {
    for (const entry of fs.readdirSync(path.join(repoRoot, directory), { withFileTypes: true })) {
      const relativePath = `${directory}/${entry.name}`;
      if (entry.isDirectory()) {
        visit(relativePath);
      } else if (entry.isFile() && entry.name.endsWith(suffix)) {
        files.push(relativePath);
      }
    }
  };
  visit(relativeDirectory);
  return files.sort();
}

const JAVASCRIPT_SOURCE_SUFFIXES = [".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"];

function listJavaScriptFilesRecursive(repoRoot, relativeDirectory) {
  return JAVASCRIPT_SOURCE_SUFFIXES.flatMap((suffix) => (
    listFilesRecursive(repoRoot, relativeDirectory, suffix)
  ))
    .filter((relativePath) => (
      !/(?:^|\/)(?:dist|build|generated|node_modules)(?:\/|$)/u.test(relativePath)
      && !/\.(?:test|spec)\.[^.]+$/u.test(relativePath)
    ))
    .sort();
}

function activeApplicationSourceFiles(repoRoot) {
  const roots = fs.readdirSync(path.join(repoRoot, "apps"), { withFileTypes: true })
    .filter((entry) => entry.isDirectory())
    .map((entry) => `apps/${entry.name}/src`)
    .filter((relativePath) => fs.existsSync(path.join(repoRoot, relativePath)));
  if (fs.existsSync(path.join(repoRoot, "apps/sas-xyz/v2"))) {
    roots.push("apps/sas-xyz/v2");
  }
  return [...new Set(
    roots.flatMap((relativePath) => listJavaScriptFilesRecursive(repoRoot, relativePath)),
  )].sort();
}

function sourceFilesMatching(repoRoot, relativePaths, pattern) {
  return relativePaths.filter((relativePath) => (
    pattern.test(readRepoFile(repoRoot, relativePath).source)
  ));
}

function resolveJavaScriptModule(repoRoot, fromFile, specifier) {
  if (!specifier.startsWith(".")) {
    return null;
  }
  const base = path.posix.normalize(
    path.posix.join(path.posix.dirname(fromFile), specifier),
  );
  for (const candidate of [
    base,
    ...JAVASCRIPT_SOURCE_SUFFIXES.map((suffix) => `${base}${suffix}`),
    ...JAVASCRIPT_SOURCE_SUFFIXES.map((suffix) => `${base}/index${suffix}`),
  ]) {
    if (fs.existsSync(path.join(repoRoot, candidate))) {
      return candidate;
    }
  }
  throw new Error(`${fromFile}: unresolved relative JavaScript module ${specifier}`);
}

function staticJavaScriptImports(repoRoot, relativePath) {
  const { source } = readRepoFile(repoRoot, relativePath);
  const tokens = lexSource(source, { language: "javascript" });
  const imports = [];
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index].value === "from" && tokens[index + 1]?.type === "string") {
      imports.push(tokens[index + 1].value);
      continue;
    }
    if (tokens[index].value !== "import") {
      continue;
    }
    if (tokens[index + 1]?.type === "string") {
      imports.push(tokens[index + 1].value);
    } else if (
      tokens[index + 1]?.value === "("
      && tokens[index + 2]?.type === "string"
    ) {
      imports.push(tokens[index + 2].value);
    }
  }
  return [...new Set(
    imports
      .map((specifier) => resolveJavaScriptModule(repoRoot, relativePath, specifier))
      .filter((resolved) => resolved !== null),
  )].sort();
}

function staticJavaScriptClosure(repoRoot, entrypoint) {
  const closure = new Set();
  const visit = (relativePath) => {
    if (closure.has(relativePath)) {
      return;
    }
    closure.add(relativePath);
    for (const dependency of staticJavaScriptImports(repoRoot, relativePath)) {
      visit(dependency);
    }
  };
  visit(entrypoint);
  return [...closure].sort();
}

function sourceFilesContaining(repoRoot, { root, suffix, pattern }) {
  return listFilesRecursive(repoRoot, root, suffix)
    .filter((relativePath) => !/(?:^|\/)tests?(?:\/|\.rs$)/u.test(relativePath))
    .filter((relativePath) => pattern.test(readRepoFile(repoRoot, relativePath).source))
    .sort();
}

function assertExactCoverageSet(label, observed, expected) {
  const observedSet = new Set(observed);
  const expectedSet = new Set(expected);
  const unexpected = observed.filter((relativePath) => !expectedSet.has(relativePath));
  const missing = expected.filter((relativePath) => !observedSet.has(relativePath));
  if (unexpected.length > 0 || missing.length > 0) {
    throw new Error(
      `${label} discovery coverage changed; classify the source before updating M0: `
      + `unexpected=[${unexpected.join(", ")}] missing=[${missing.join(", ")}]`,
    );
  }
}

function activeJavaScriptEffectSources(repoRoot) {
  const applicationFiles = activeApplicationSourceFiles(repoRoot);
  const productUiFiles = [
    ...staticJavaScriptClosure(
      repoRoot,
      "apps/hypervisor/scripts/serve-product-ui.mjs",
    ),
    ...listFiles(repoRoot, "apps/hypervisor/scripts/augmentation", ".js"),
  ];
  const candidates = [...new Set([
    ...applicationFiles,
    ...productUiFiles,
    "scripts/hypervisor-app-dev-replay-server.mjs",
  ])].sort();
  return candidates.filter((relativePath) => (
    /\binvoke(?:\s*<[^;>{}]+>)?\s*\(/u
      .test(readRepoFile(repoRoot, relativePath).source)
    || javascriptSourceHasEffects({ repoRoot, relativePath })
  ));
}

function activeJavaScriptServerSources(repoRoot) {
  const candidates = [...new Set([
    ...activeApplicationSourceFiles(repoRoot),
    ...staticJavaScriptClosure(
      repoRoot,
      "apps/hypervisor/scripts/serve-product-ui.mjs",
    ),
    "apps/hypervisor/product-ui/server.cjs",
    "scripts/hypervisor-app-dev-replay-server.mjs",
  ])].sort();
  const serverPattern =
    /(?:\bcreateServer\s*\(|\bWebSocketServer\s*\(|\.listen\s*\()/u;
  return candidates.filter((relativePath) => (
    serverPattern.test(readRepoFile(repoRoot, relativePath).source)
  ));
}

function assertRepositoryDiscoveryCoverage(repoRoot) {
  for (const [coverageId, coverage] of Object.entries(DISCOVERY_COVERAGE)) {
    assertExactCoverageSet(
      coverageId,
      sourceFilesContaining(repoRoot, coverage),
      Object.keys(coverage.files).sort(),
    );
  }
  assertExactCoverageSet(
    "active_javascript_effect_source",
    activeJavaScriptEffectSources(repoRoot),
    Object.keys(ACTIVE_JAVASCRIPT_EFFECT_SOURCE_COVERAGE).sort(),
  );
  assertExactCoverageSet(
    "active_javascript_server_source",
    activeJavaScriptServerSources(repoRoot),
    Object.keys(ACTIVE_JAVASCRIPT_SERVER_SOURCE_COVERAGE).sort(),
  );
  for (const [relativePath, services] of Object.entries(PROTO_SERVICE_INVENTORY)) {
    assertExactCoverageSet(
      `proto_service_inventory:${relativePath}`,
      discoverProtoServiceNames({ repoRoot, relativePath }),
      [...services],
    );
  }
  for (const [relativePath, services] of Object.entries(TONIC_SERVICE_MOUNTS)) {
    assertExactCoverageSet(
      `tonic_service_mounts:${relativePath}`,
      discoverTonicServiceRegistrations({ repoRoot, relativePath }),
      [...services],
    );
  }
}

function snakeCase(value) {
  return value
    .replaceAll(/([a-z0-9])([A-Z])/gu, "$1_$2")
    .replaceAll(/([A-Z])([A-Z][a-z])/gu, "$1_$2")
    .toLowerCase();
}

function attachRpcHandlers({
  entries,
  functionIndex,
  sourceFileForService,
  prefix = "",
}) {
  return entries.map((entry) => {
    const functionName = `${prefix}${snakeCase(entry.rpc_method)}`;
    const sourceFile = sourceFileForService(entry, functionName);
    let candidates = functionIndex.get(sourceFile)?.get(functionName) ?? [];
    if (candidates.length > 1) {
      const rpcCandidates = candidates.filter((candidate) => (
        candidate.source.includes("Request<")
        || candidate.source.includes("Request <")
      ));
      if (rpcCandidates.length === 1) {
        candidates = rpcCandidates;
      }
    }
    if (candidates.length !== 1) {
      return {
        ...entry,
        handler: functionName,
        handler_source_file: sourceFile,
        handler_source_symbol: functionName,
        handler_anchor: null,
        handler_resolution: candidates.length === 0 ? "unresolved" : "ambiguous",
      };
    }
    const definition = candidates[0];
    return {
      ...entry,
      handler: functionName,
      handler_source_file: definition.relativePath,
      handler_source_symbol: functionName,
      handler_anchor: {
        line: definition.line,
        sha256: definition.sha256,
      },
      handler_resolution: "function_body",
      handler_calls: [...new Set(definition.callSequence)].sort(),
      handler_call_sequence: definition.callSequence,
    };
  });
}

function fileLockedEntry({
  repoRoot,
  identity,
  kind,
  surface,
  operation,
  relativePath,
  symbol,
  activeState = "active",
  httpMethod = null,
  httpPath = null,
  serviceMethod = null,
}) {
  const { source } = readRepoFile(repoRoot, relativePath);
  return {
    identity,
    kind,
    surface,
    operation,
    method: httpMethod,
    path: httpPath,
    service_method: serviceMethod,
    source_file: relativePath,
    source_symbol: symbol,
    handler: symbol,
    active_state: activeState,
    source_anchor: {
      line: 1,
      sha256: sha256(source),
    },
    handler_source_file: relativePath,
    handler_source_symbol: symbol,
    handler_anchor: {
      line: 1,
      sha256: sha256(source),
    },
    handler_resolution: "bounded_file_lock",
    handler_calls: [],
    handler_call_sequence: [],
  };
}

function rustFunctionAnchoredEntry({
  repoRoot,
  identity,
  kind,
  surface,
  operation,
  registrationFile,
  registrationSymbol,
  handlerFile,
  handlerSymbol,
  activeState = "active",
}) {
  const { source: registrationSource } = readRepoFile(repoRoot, registrationFile);
  const candidates = discoverRustFunctions({
    repoRoot,
    relativePath: handlerFile,
  }).filter((definition) => definition.name === handlerSymbol);
  if (candidates.length !== 1) {
    throw new Error(
      `${handlerFile}: expected one ${handlerSymbol} function, found ${candidates.length}`,
    );
  }
  const definition = candidates[0];
  return {
    identity,
    kind,
    surface,
    operation,
    source_file: registrationFile,
    source_symbol: registrationSymbol,
    handler: handlerSymbol,
    active_state: activeState,
    source_anchor: {
      line: 1,
      sha256: sha256(registrationSource),
    },
    handler_source_file: definition.relativePath,
    handler_source_symbol: handlerSymbol,
    handler_anchor: {
      line: definition.line,
      sha256: definition.sha256,
    },
    handler_resolution: "function_body",
    handler_calls: [...new Set(definition.callSequence)].sort(),
    handler_call_sequence: definition.callSequence,
  };
}

function attachSameFileRoutes(repoRoot, entries, relativePath) {
  const functionIndex = buildRustFunctionIndex({
    repoRoot,
    relativePaths: [relativePath],
  });
  return attachRustHandlerDefinitions({
    repoRoot,
    entries,
    functionIndex,
    defaultSourceFile: relativePath,
  });
}

export function discoverRepositorySurface(repoRoot) {
  assertRepositoryDiscoveryCoverage(repoRoot);
  const routeFiles = listFiles(repoRoot, ROUTE_DIRECTORY, ".rs");
  const daemonFunctionIndex = buildRustFunctionIndex({
    repoRoot,
    relativePaths: [DAEMON_FILE, ...routeFiles],
  });
  const daemon = attachRustHandlerDefinitions({
    repoRoot,
    entries: discoverAxumRoutes({
      repoRoot,
      relativePath: DAEMON_FILE,
      surface: "hypervisor-daemon",
    }),
    functionIndex: daemonFunctionIndex,
    defaultSourceFile: DAEMON_FILE,
    moduleSourceFiles: rustModuleSourceMap(routeFiles),
  });

  const ibcFile = "crates/plugins/http-rpc-gateway/src/lib.rs";
  const telemetryFile = "crates/telemetry/src/http.rs";
  const providerFile = "crates/validator/src/standard/provider/server.rs";
  const ibc = attachSameFileRoutes(
    repoRoot,
    discoverAxumRoutes({
      repoRoot,
      relativePath: ibcFile,
      surface: "ibc-http-gateway",
    }),
    ibcFile,
  );
  const telemetry = attachSameFileRoutes(
    repoRoot,
    discoverAxumRoutes({
      repoRoot,
      relativePath: telemetryFile,
      surface: "telemetry-http",
    }),
    telemetryFile,
  );
  const provider = attachSameFileRoutes(
    repoRoot,
    discoverAxumRoutes({
      repoRoot,
      relativePath: providerFile,
      surface: "provider-http",
    }),
    providerFile,
  );
  const previewHttp = attachSameFileRoutes(
    repoRoot,
    discoverAxumRoutes({
      repoRoot,
      relativePath: `${ROUTE_DIRECTORY}/lifecycle_routes.rs`,
      surface: "session-preview-http",
    }).map((entry) => ({
      ...entry,
      active_state: "conditional_authorized_session_preview_listener",
    })),
    `${ROUTE_DIRECTORY}/lifecycle_routes.rs`,
  );

  const walletSourceFiles = listFilesRecursive(
    repoRoot,
    WALLET_DIRECTORY,
    ".rs",
  ).filter((relativePath) => (
    relativePath !== WALLET_FILE
    && !relativePath.includes("/tests/")
    && !relativePath.endsWith("/tests.rs")
  ));
  const walletFunctionIndex = buildRustFunctionIndex({
    repoRoot,
    relativePaths: [WALLET_FILE, ...walletSourceFiles],
  });
  const wallet = attachRustHandlerDefinitions({
    repoRoot,
    entries: discoverWalletServiceMethods({
      repoRoot,
      relativePath: WALLET_FILE,
    }),
    functionIndex: walletFunctionIndex,
    defaultSourceFile: WALLET_FILE,
    moduleSourceFiles: rustModuleSourceMap(walletSourceFiles),
  });

  const literalBlockchainServiceSpecs = [
    {
      relativePath: "crates/consensus/src/service.rs",
      serviceId: "penalties",
      serviceType: "PenaltiesService",
      activeState: "always_mounted",
    },
    {
      relativePath: "crates/services/src/identity/mod.rs",
      serviceId: "identity_hub",
      serviceType: "IdentityHub",
      activeState: "configured_initial_service_default_node_profile",
    },
    {
      relativePath: "crates/services/src/provider_registry/mod.rs",
      serviceId: "provider_registry",
      serviceType: "ProviderRegistryService",
      activeState: "configured_initial_service_default_node_profile",
    },
    {
      relativePath: "crates/services/src/agentic/leakage.rs",
      serviceId: "leakage_controller",
      serviceType: "LeakageController",
      activeState: "configured_initial_service",
    },
    {
      relativePath: "crates/services/src/guardian_registry/service.rs",
      serviceId: "guardian_registry",
      serviceType: "GuardianRegistry",
      activeState: "configured_initial_service_default_node_profile",
    },
    {
      relativePath: "crates/plugins/ibc-service/src/core/registry.rs",
      serviceId: "ibc",
      serviceType: "VerifierRegistry",
      activeState: "feature_and_config_selected_initial_service",
    },
    {
      relativePath: "crates/services/src/agentic/runtime/service/mod.rs",
      serviceId: "desktop_agent",
      serviceType: "RuntimeAgentService",
      activeState: "driver_conditional_or_local_hot_swap",
    },
  ];
  const literalBlockchainServices = literalBlockchainServiceSpecs.flatMap((spec) => (
    discoverRustMatchServiceMethods({
      repoRoot,
      ...spec,
    })
  ));

  const macroBlockchainServiceSpecs = [
    {
      relativePath: "crates/services/src/governance/mod.rs",
      expectedServiceId: "governance",
      activeState: "configured_initial_service_default_node_profile",
    },
    {
      relativePath: "crates/services/src/agentic/optimizer.rs",
      expectedServiceId: "optimizer",
      activeState: "always_mounted_in_standard_workload",
    },
    {
      relativePath: "crates/services/src/market/mod.rs",
      expectedServiceId: "market",
      activeState: "local_node_hot_swap",
    },
    {
      relativePath: "crates/services/src/agentic/evolution.rs",
      expectedServiceId: "evolution",
      activeState: "unmounted_fail_closed_legacy_boundary",
    },
  ];
  const macroDefinitionAnchor = sha256(
    readRepoFile(repoRoot, "crates/macros/src/lib.rs").source,
  );
  const macroBlockchainServices = macroBlockchainServiceSpecs.flatMap((spec) => (
    discoverRustServiceInterfaceMethods({
      repoRoot,
      ...spec,
    })
  )).map((entry) => ({
    ...entry,
    handler_anchor: {
      ...entry.handler_anchor,
      sha256: sha256(
        `${entry.handler_anchor.sha256}:${macroDefinitionAnchor}`,
      ),
    },
    macro_definition_anchor_sha256: macroDefinitionAnchor,
  }));

  const publicHandlerFiles = [
    "crates/validator/src/standard/orchestration/grpc_public.rs",
    "crates/validator/src/standard/orchestration/grpc_public/events_handlers/subscription.rs",
    "crates/validator/src/standard/orchestration/grpc_public/session_handlers.rs",
    "crates/validator/src/standard/orchestration/grpc_public/state_handlers.rs",
    "crates/validator/src/standard/orchestration/grpc_public/tx_handlers.rs",
  ];
  const publicFunctionIndex = buildRustFunctionIndex({
    repoRoot,
    relativePaths: publicHandlerFiles,
  });
  const publicRpc = attachRpcHandlers({
    entries: discoverProtoService({
      repoRoot,
      relativePath: PUBLIC_PROTO,
      serviceName: "PublicApi",
      surface: "public-api",
      activeState: "active",
    }),
    functionIndex: publicFunctionIndex,
    sourceFileForService: (_entry, functionName) => {
      if (functionName.includes("subscribe_events")) {
        return publicHandlerFiles[1];
      }
      if (["get_session_history", "set_runtime_secret"].includes(
        functionName.replace(/^handle_/u, ""),
      )) {
        return publicHandlerFiles[2];
      }
      if (
        ["query_state", "query_raw_state", "get_status", "get_block_by_height", "get_context_blob"]
          .includes(functionName.replace(/^handle_/u, ""))
      ) {
        return publicHandlerFiles[3];
      }
      return publicHandlerFiles[4];
    },
    prefix: "handle_",
  });

  const guardianFile = "crates/node/src/bin/guardian.rs";
  const guardianFunctionIndex = buildRustFunctionIndex({
    repoRoot,
    relativePaths: [guardianFile],
  });
  const guardianRpc = attachRpcHandlers({
    entries: discoverProtoService({
      repoRoot,
      relativePath: GUARDIAN_PROTO,
      serviceName: "GuardianControl",
      surface: "guardian-control",
      activeState: "conditional_env_mount",
    }),
    functionIndex: guardianFunctionIndex,
    sourceFileForService: () => guardianFile,
  });

  const workloadServiceFiles = new Map([
    ["ChainControl", "crates/validator/src/standard/workload/ipc/grpc_blockchain.rs"],
    ["StateQuery", "crates/validator/src/standard/workload/ipc/grpc_blockchain.rs"],
    ["ContractControl", "crates/validator/src/standard/workload/ipc/grpc_blockchain.rs"],
    ["StakingControl", "crates/validator/src/standard/workload/ipc/grpc_blockchain.rs"],
    ["SystemControl", "crates/validator/src/standard/workload/ipc/grpc_blockchain.rs"],
    ["WorkloadControl", "crates/validator/src/standard/workload/ipc/grpc_control.rs"],
  ]);
  const workloadFunctionIndex = buildRustFunctionIndex({
    repoRoot,
    relativePaths: [...workloadServiceFiles.values()],
  });
  const workloadRpc = [];
  for (const [serviceName, sourceFile] of workloadServiceFiles) {
    const proto = serviceName === "WorkloadControl"
      ? GUARDIAN_PROTO
      : "crates/ipc/proto/blockchain/v1/blockchain.proto";
    workloadRpc.push(...attachRpcHandlers({
      entries: discoverProtoService({
        repoRoot,
        relativePath: proto,
        serviceName,
        surface: `workload-ipc-${snakeCase(serviceName)}`,
        activeState: "mounted_internal_ipc",
      }),
      functionIndex: workloadFunctionIndex,
      sourceFileForService: () => sourceFile,
    }));
  }

  const modelMountRpc = discoverProtoService({
    repoRoot,
    relativePath: "crates/ipc/proto/model_mount/v1/model_mount.proto",
    serviceName: "ModelMountService",
    surface: "model-mount-grpc",
    activeState: "unmounted_contract",
  }).map((entry) => ({
    ...entry,
    handler: null,
    handler_source_file: null,
    handler_source_symbol: null,
    handler_anchor: null,
    handler_resolution: "unmounted",
    handler_calls: [],
    handler_call_sequence: [],
  }));

  const applicationSourceFiles = activeApplicationSourceFiles(repoRoot);
  const hypervisorSourceFiles = applicationSourceFiles.filter((relativePath) => (
    relativePath.startsWith("apps/hypervisor/src/")
    && relativePath !== "apps/hypervisor/src/services/hypervisorHostBridge.ts"
  ));
  const jsHostCalls = aggregateLiteralCalls(discoverLiteralCalls({
    repoRoot,
    relativePaths: sourceFilesMatching(
      repoRoot,
      hypervisorSourceFiles,
      /\binvoke(?:\s*<[^;>{}]+>)?\s*\(/u,
    ),
    callee: "invoke",
    identityPrefix: "js-host-action",
    surface: "hypervisor-app",
  })).map((entry) => ({
    ...entry,
    handler_source_file: entry.source_file,
    handler_source_symbol: entry.handler,
    handler_anchor: entry.source_anchor,
    handler_resolution: "host_bridge_call_site",
    handler_calls: ["invoke"],
    handler_call_sequence: ["invoke"],
  }));

  const devCases = discoverSwitchCases({
    repoRoot,
    relativePath: "scripts/hypervisor-app-dev-replay-server.mjs",
    identityPrefix: "dev-replay-action",
    surface: "hypervisor-dev-replay",
  }).map((entry) => ({
    ...entry,
    handler_source_file: entry.source_file,
    handler_source_symbol: entry.source_symbol,
    handler_anchor: entry.source_anchor,
    handler_resolution: "switch_case",
    handler_calls: [],
    handler_call_sequence: [],
  }));

  const jsStorage = discoverJsStorageMutations({
    repoRoot,
    relativePaths: applicationSourceFiles.filter((relativePath) => (
      relativePath.startsWith("apps/hypervisor/src/")
    )),
    surface: "hypervisor-app-local-storage",
    activeState: "active_hypervisor_browser_compatibility_state",
  }).map((entry) => ({
    ...entry,
    handler_source_file: entry.source_file,
    handler_source_symbol: entry.source_symbol,
    handler_anchor: entry.source_anchor,
    handler_resolution: "browser_storage_call",
    handler_calls: [entry.handler],
    handler_call_sequence: [entry.handler],
  }));
  const otherJsStorage = discoverJsStorageMutations({
    repoRoot,
    relativePaths: applicationSourceFiles.filter((relativePath) => (
      !relativePath.startsWith("apps/hypervisor/src/")
    )),
    surface: "other-js-app-local-storage",
    activeState: "active_application_browser_compatibility_state",
  }).map((entry) => ({
    ...entry,
    handler_source_file: entry.source_file,
    handler_source_symbol: entry.source_symbol,
    handler_anchor: entry.source_anchor,
    handler_resolution: "browser_storage_call",
    handler_calls: [entry.handler],
    handler_call_sequence: [entry.handler],
  }));

  const discoveredJsSystemEffects = discoverJsSystemEffects({
    repoRoot,
    relativePaths: activeJavaScriptEffectSources(repoRoot),
  });
  assertExactCoverageSet(
    "active_javascript_system_effect_action",
    discoveredJsSystemEffects.map((entry) => entry.identity),
    Object.keys(JS_SYSTEM_EFFECT_ACTIONS).sort(),
  );
  const jsSystemEffects = discoveredJsSystemEffects.map((entry) => ({
    ...entry,
    ...JS_SYSTEM_EFFECT_ACTIONS[entry.identity],
  }));

  const productUiOutbound = discoverJsOutboundCalls({
    repoRoot,
    relativePaths: [
      "apps/hypervisor/scripts/serve-product-ui.mjs",
      "apps/hypervisor/scripts/ioi-api-adapter.mjs",
      "apps/hypervisor/scripts/ioi-agent-runs.mjs",
      ...listFiles(
        repoRoot,
        "apps/hypervisor/scripts/augmentation",
        ".js",
      ),
      "apps/hypervisor/surfaces/approvals/index.mjs",
      "apps/hypervisor/surfaces/ontology-context.mjs",
      "apps/hypervisor/surfaces/ontology-manager/index.mjs",
      "apps/hypervisor/surfaces/pipeline/index.mjs",
      "apps/hypervisor/surfaces/sources/index.mjs",
    ],
    surface: "hypervisor-product-ui-outbound",
    activeState: "standing_serve_product_ui_compatibility_surface",
  });

  const hypervisorDevSourceFiles = applicationSourceFiles.filter((relativePath) => (
    relativePath.startsWith("apps/hypervisor/src/dev/")
  ));
  const hypervisorDevOutbound = discoverJsOutboundCalls({
    repoRoot,
    relativePaths: hypervisorDevSourceFiles,
    surface: "hypervisor-app-dev-outbound",
    activeState: "vite_development_only",
  });

  const hypervisorAppOutbound = discoverJsOutboundCalls({
    repoRoot,
    relativePaths: applicationSourceFiles.filter((relativePath) => (
      relativePath.startsWith("apps/hypervisor/src/")
      && !hypervisorDevSourceFiles.includes(relativePath)
    )),
    surface: "hypervisor-app-outbound",
    activeState: "active_hypervisor_application",
  });

  const otherAppOutbound = discoverJsOutboundCalls({
    repoRoot,
    relativePaths: applicationSourceFiles.filter((relativePath) => (
      !relativePath.startsWith("apps/hypervisor/src/")
    )),
    surface: "other-js-app-outbound",
    activeState: "active_application",
  });

  const manual = [
    fileLockedEntry({
      repoRoot,
      identity: "http:signer:POST /sign",
      kind: "http",
      surface: "signer-http",
      operation: "POST /sign",
      relativePath: "crates/node/src/bin/signer.rs",
      symbol: "perform_sign",
      httpMethod: "POST",
      httpPath: "/sign",
    }),
    fileLockedEntry({
      repoRoot,
      identity: "compatibility-io:hypervisor-dev-replay:probeModelUpstreamReachable",
      kind: "compatibility_io",
      surface: "hypervisor-dev-replay",
      operation: "GET configured model upstream /models",
      relativePath: "scripts/hypervisor-app-dev-replay-server.mjs",
      symbol: "probeModelUpstreamReachable",
      httpMethod: "GET",
      httpPath: "configured model upstream /models",
    }),
    fileLockedEntry({
      repoRoot,
      identity: "compatibility-io:hypervisor-dev-replay:streamSessionTurn",
      kind: "compatibility_io",
      surface: "hypervisor-dev-replay",
      operation: "POST configured model upstream /chat/completions",
      relativePath: "scripts/hypervisor-app-dev-replay-server.mjs",
      symbol: "streamSessionTurn",
      httpMethod: "POST",
      httpPath: "configured model upstream /chat/completions",
    }),
    fileLockedEntry({
      repoRoot,
      identity:
        "http:hypervisor-product-ui-reference-server:ANY /<dynamic-mock-or-static-route>",
      kind: "http",
      surface: "hypervisor-product-ui-reference-server",
      operation: "ANY /<dynamic-mock-or-static-route>",
      relativePath: "apps/hypervisor/product-ui/server.cjs",
      symbol: "http.createServer compatibility dispatch",
      activeState: "spawned_by_standing_serve_product_ui",
      httpMethod: "ANY",
      httpPath: "/<dynamic-mock-or-static-route>",
    }),
    fileLockedEntry({
      repoRoot,
      identity: "service-dynamic:wasm-runtime:<manifest-method@vN>",
      kind: "dynamic_service_method",
      surface: "blockchain-service:dynamic-wasm",
      operation: "manifest-defined method@vN",
      relativePath: "crates/execution/src/runtime_service/mod.rs",
      symbol: "RuntimeService::handle_service_call",
      activeState: "conditionally_installed_from_validated_manifest",
      serviceMethod: "<manifest-method@vN>",
    }),
    fileLockedEntry({
      repoRoot,
      identity: "service:ibc_channel_manager:<unsupported-method>",
      kind: "service_compatibility_boundary",
      surface: "blockchain-service:ibc_channel_manager",
      operation: "all service methods return Unsupported",
      relativePath: "crates/plugins/ibc-service/src/apps/channel.rs",
      symbol: "BlockchainService::handle_service_call default",
      activeState: "feature_and_config_selected_no_supported_methods",
      serviceMethod: "<unsupported-method>",
    }),
    rustFunctionAnchoredEntry({
      repoRoot,
      identity: "stream:agentgres-replica:AGRS2 <catch-up-or-batch>",
      kind: "binary_stream_protocol",
      surface: "agentgres-replica",
      operation: "AGRS2 catch-up or admitted batch append",
      registrationFile: "crates/agentgres/src/bin/replica.rs",
      registrationSymbol: "substrate-replica main",
      handlerFile: "crates/agentgres/src/replica.rs",
      handlerSymbol: "serve_one",
      activeState: "standalone_binary_when_launched",
    }),
    fileLockedEntry({
      repoRoot,
      identity: "http:google-oauth-callback:GET /?code&state",
      kind: "conditional_http_callback",
      surface: "google-oauth-callback",
      operation: "GET /?code&state",
      relativePath: "crates/services/src/agentic/runtime/connectors/google_auth.rs",
      symbol: "wait_for_google_callback in login",
      activeState: "conditional_pending_google_oauth_session",
      httpMethod: "GET",
      httpPath: "/?code&state",
    }),
    fileLockedEntry({
      repoRoot,
      identity: "stream:hypervisor-editor-proxy:<lease-authenticated-http-or-websocket-bytes>",
      kind: "dynamic_stream_protocol",
      surface: "hypervisor-editor-proxy",
      operation: "lease-authenticated HTTP or WebSocket byte forwarding",
      relativePath: `${ROUTE_DIRECTORY}/editor_proxy.rs`,
      symbol: "handle_conn",
      activeState: "conditional_live_editor_service",
    }),
    fileLockedEntry({
      repoRoot,
      identity: "stream:guardian-encrypted-container:<framed-orchestration-or-workload-request>",
      kind: "dynamic_stream_protocol",
      surface: "guardian-encrypted-container",
      operation: "mTLS and post-quantum encrypted internal framed dispatch",
      relativePath: "crates/validator/src/common/guardian/server.rs",
      symbol: "GuardianContainer::start dispatch loop",
      activeState: "configured_internal_guardian_container",
    }),
  ];

  const entries = sortByIdentity([
    ...daemon,
    ...ibc,
    ...telemetry,
    ...provider,
    ...previewHttp,
    ...wallet,
    ...literalBlockchainServices,
    ...macroBlockchainServices,
    ...publicRpc,
    ...guardianRpc,
    ...workloadRpc,
    ...modelMountRpc,
    ...jsHostCalls,
    ...devCases,
    ...jsStorage,
    ...otherJsStorage,
    ...jsSystemEffects,
    ...productUiOutbound,
    ...hypervisorDevOutbound,
    ...hypervisorAppOutbound,
    ...otherAppOutbound,
    ...manual,
  ]);
  assertUniqueIdentities(entries, "M0 repository surface");
  return entries;
}

function ownerForEntry(entry) {
  if (entry.surface === "wallet.network") {
    return {
      owner: "wallet.network",
      owner_doc: "docs/architecture/components/wallet-network/doctrine.md",
    };
  }
  if (entry.surface === "public-api") {
    return {
      owner: "Validator orchestration public API",
      owner_doc: "docs/architecture/components/daemon-runtime/api.md",
    };
  }
  if (entry.surface.startsWith("blockchain-service:")) {
    const serviceName = entry.surface.slice("blockchain-service:".length);
    return {
      owner: `${serviceName} native blockchain service`,
      owner_doc: "docs/architecture/components/daemon-runtime/api.md",
    };
  }
  if (entry.surface.startsWith("workload-ipc-")) {
    return {
      owner: "Validator workload IPC",
      owner_doc: "docs/architecture/components/daemon-runtime/api.md",
    };
  }
  if (entry.surface === "guardian-control" || entry.surface === "signer-http") {
    return {
      owner: "Guardian and signer boundary",
      owner_doc: "docs/architecture/foundations/governed-autonomous-systems.md",
    };
  }
  if (entry.surface === "provider-http") {
    return {
      owner: "Compute Provider",
      owner_doc: "docs/architecture/components/hypervisor/providers-and-environments.md",
    };
  }
  if (entry.surface === "ibc-http-gateway") {
    return {
      owner: "IBC HTTP gateway",
      owner_doc: "docs/architecture/foundations/governed-autonomous-systems.md",
    };
  }
  if (entry.surface === "telemetry-http") {
    return {
      owner: "Platform telemetry",
      owner_doc: "docs/architecture/components/daemon-runtime/platform-operability.md",
    };
  }
  if (entry.surface === "model-mount-grpc") {
    return {
      owner: "Model Mount compatibility contract",
      owner_doc: "docs/architecture/components/daemon-runtime/api.md",
    };
  }
  if (entry.surface === "agentgres-replica") {
    return {
      owner: "Agentgres",
      owner_doc: "docs/architecture/components/agentgres/api-object-model.md",
    };
  }
  if (entry.surface === "google-oauth-callback") {
    return {
      owner: "Hypervisor connector runtime",
      owner_doc: "docs/architecture/components/daemon-runtime/api.md",
    };
  }
  if (entry.surface === "hypervisor-editor-proxy") {
    return {
      owner: "Hypervisor Daemon/Core editor runtime",
      owner_doc: "docs/architecture/components/hypervisor/core-clients-surfaces.md",
    };
  }
  if (entry.surface === "guardian-encrypted-container") {
    return {
      owner: "Guardian internal container boundary",
      owner_doc: "docs/architecture/foundations/governed-autonomous-systems.md",
    };
  }
  if (entry.surface === "session-preview-http") {
    return {
      owner: "Hypervisor Daemon/Core session preview",
      owner_doc: "docs/architecture/components/daemon-runtime/api.md",
    };
  }
  if (entry.surface === "hypervisor-app-dev-outbound") {
    return {
      owner: "Hypervisor development replay compatibility",
      owner_doc: "docs/architecture/components/hypervisor/core-clients-surfaces.md",
    };
  }
  if (entry.surface === "hypervisor-app-outbound") {
    return {
      owner: "Hypervisor client projection",
      owner_doc: "docs/architecture/components/hypervisor/core-clients-surfaces.md",
    };
  }
  if (entry.surface === "hypervisor-app") {
    return {
      owner: "Hypervisor client projection",
      owner_doc: "docs/architecture/components/hypervisor/core-clients-surfaces.md",
    };
  }
  if (entry.surface === "hypervisor-app-local-storage") {
    return {
      owner: "Hypervisor client compatibility state",
      owner_doc: "docs/architecture/components/hypervisor/core-clients-surfaces.md",
    };
  }
  if (
    entry.surface === "hypervisor-product-ui-outbound"
    || entry.surface === "hypervisor-product-ui-local-state"
    || entry.surface === "hypervisor-product-ui-process"
    || entry.surface === "hypervisor-product-ui-reference-server"
    || entry.surface === "hypervisor-product-ui-test-signer"
  ) {
    return {
      owner: "Hypervisor product UI compatibility facade",
      owner_doc: "docs/architecture/components/hypervisor/core-clients-surfaces.md",
    };
  }
  if (entry.surface === "other-js-app-outbound") {
    return {
      owner: "Application read projection",
      owner_doc: "docs/architecture/_meta/source-of-truth-map.md",
    };
  }
  if (entry.surface === "other-js-app-local-storage") {
    return {
      owner: "Application-local compatibility state",
      owner_doc: "docs/architecture/_meta/source-of-truth-map.md",
    };
  }
  if (entry.surface === "hypervisor-dev-replay") {
    return {
      owner: "Hypervisor development replay compatibility",
      owner_doc: "docs/architecture/components/hypervisor/core-clients-surfaces.md",
    };
  }
  if (entry.surface === "hypervisor-daemon") {
    const source = entry.handler_source_file ?? "";
    if (source.includes("goalrun_routes")) {
      return {
        owner: "GoalRun and Goal Kernel",
        owner_doc: "docs/architecture/foundations/common-objects-and-envelopes.md",
      };
    }
    if (
      /(outcome_room|room_participation|work_frontier_claim|attempt_finding|work_result)/u
        .test(source)
    ) {
      return {
        owner: "OutcomeRoom work coordination",
        owner_doc: "docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md",
      };
    }
    if (source.includes("authority_routes")) {
      return {
        owner: "Hypervisor daemon authority PEP",
        owner_doc: "docs/architecture/components/wallet-network/api-authority-scopes.md",
      };
    }
    return {
      owner: "Hypervisor Daemon/Core",
      owner_doc: "docs/architecture/components/daemon-runtime/api.md",
    };
  }
  return {
    owner: "Repository compatibility surface",
    owner_doc: "docs/architecture/_meta/source-of-truth-map.md",
  };
}

const DIRECT_EFFECT_CALL = /(?:^|::|\.)(?:persist(?:_|$)|persist_record$|persist_env$|persist_availability_locked$|persist_runnability_locked$|write(?:_|$)|write_all$|writeFileSync$|remove_record$|remove_file$|remove_dir_all$|create_dir(?:_all)?$|rename$|save(?:_|$)|store(?:_|$)|store_typed$|append(?:_|$)|append_audit_event(?:_with_records)?$|state\.insert$|state\.delete$|state\.batch_apply$|admit_and_persist|apply_workspace_patch$|Command::new$|spawn$|send$|try_send$|submit_ibc_messages$|set_secret$|provision_with_domain$|perform_sign$|sync_all$|register_service$)/u;
const WALLET_EFFECT_CALL = /^(?:store_typed|append_audit_event(?:_with_records)?|commit_binding|state\.(?:insert|delete|batch_apply)|provider\.(?:read_latest|list_recent|mailbox_total_count|delete_spam|send_reply))$/u;

const PLAN_ONLY_HTTP_IDENTITIES = new Set([
  "http:hypervisor-daemon:POST /v1/hypervisor/authority/evaluate",
  "http:hypervisor-daemon:POST /v1/hypervisor/provider-ladder/resolve",
  "http:hypervisor-daemon:POST /v1/model-mount/tokens/count",
  "http:hypervisor-daemon:POST /v1/threads/:id/snapshots/:snapshot_id/restore-preview",
]);

function directEffectCalls(entry) {
  return entry.handler_effect_calls
    ?? (entry.handler_call_sequence ?? []).filter((call) => DIRECT_EFFECT_CALL.test(call));
}

function uniqueInOrder(values) {
  return values.filter((value, index) => values.indexOf(value) === index);
}

function walletEffectCalls(entry) {
  return uniqueInOrder(
    (entry.handler_call_sequence ?? []).filter((call) => WALLET_EFFECT_CALL.test(call)),
  );
}

function effectClassFor(entry, classification) {
  const text = `${entry.operation} ${entry.handler ?? ""}`.toLowerCase();
  if (classification === "read_only") {
    return text.includes("health") || text.includes("probe")
      ? "external_or_local_observation"
      : "read_projection";
  }
  if (classification === "plan_only") {
    return "plan_or_validation";
  }
  if (classification === "compatibility") {
    return "compatibility_or_simulation";
  }
  if (classification === "unavailable_contract") {
    return "declared_unmounted_contract";
  }
  if (classification === "internal_only") {
    return "internal_runtime_or_state_control";
  }
  if (entry.kind === "js_outbound") {
    return "javascript_network_or_daemon_effect";
  }
  if (entry.kind === "js_local_file_action") {
    return "javascript_local_durable_state";
  }
  if (entry.kind === "js_system_effect") {
    return entry.system_effect_categories.includes("process")
      ? "javascript_process_lifecycle"
      : "javascript_local_durable_state";
  }
  if (entry.kind === "js_local_storage") {
    return "browser_local_durable_state";
  }
  if (entry.surface === "signer-http") {
    return "cryptographic_signature_and_signer_wal";
  }
  if (entry.surface === "provider-http") {
    return "provider_allocation_and_receipt";
  }
  if (entry.surface === "agentgres-replica") {
    return "replicated_durable_log_append";
  }
  if (entry.surface === "google-oauth-callback") {
    return "oauth_token_exchange_and_local_secret_state";
  }
  if (entry.surface === "hypervisor-editor-proxy") {
    return "lease_gated_dynamic_editor_effect";
  }
  if (entry.surface === "guardian-encrypted-container") {
    return "internal_encrypted_dynamic_control";
  }
  if (entry.surface === "ibc-http-gateway") {
    return "network_transaction_submission";
  }
  if (entry.surface === "public-api" && entry.rpc_method === "SubmitTransaction") {
    return "transaction_admission_and_network_fanout";
  }
  if (entry.surface === "public-api" && entry.rpc_method === "SetRuntimeSecret") {
    return "process_local_secret_state";
  }
  if (entry.surface === "wallet.network") {
    if (/(mail_|mailbox_)/u.test(entry.operation)) {
      return "wallet_mail_external_io_and_durable_receipt";
    }
    if (/(grant|authority|policy|client|identity|secret|channel|approval|panic)/u.test(text)) {
      return "wallet_authority_policy_or_secret_state";
    }
    return "wallet_durable_state";
  }
  if (/(authority|grant|approval|policy|revoke|lease)/u.test(text)) {
    return "authority_policy_or_lease_state";
  }
  if (/(workspace|repository|file|git|editor|terminal|exec|coding)/u.test(text)) {
    return "filesystem_repository_or_process_effect";
  }
  if (/(provider|connector|mail|scm|webhook|mcp|download|model)/u.test(text)) {
    return "external_provider_or_network_effect";
  }
  if (/(start|stop|restart|execute|run|spawn|mount|load|unload|cancel)/u.test(text)) {
    return "runtime_or_process_lifecycle";
  }
  if (/(receipt|evidence|export|checkpoint)/u.test(text)) {
    return "evidence_or_export_state";
  }
  return "durable_control_state";
}

function initialClassification(entry, devCaseCommands) {
  if (entry.surface === "session-preview-http") {
    return "read_only";
  }
  if (
    entry.surface === "agentgres-replica"
    || entry.surface === "google-oauth-callback"
    || entry.surface === "hypervisor-editor-proxy"
  ) {
    return "consequential";
  }
  if (entry.surface === "guardian-encrypted-container") {
    return "internal_only";
  }
  if (entry.surface === "model-mount-grpc") {
    return "unavailable_contract";
  }
  const internalReadRpcs = new Set([
    "GetBlocksRange",
    "GetGenesisStatus",
    "QueryContract",
    "GetNextStakedValidators",
    "GetStakedValidators",
    "PrefixScan",
    "QueryRawState",
    "QueryStateAt",
    "GetExpectedModelHash",
    "HealthCheck",
  ]);
  if (entry.surface.startsWith("workload-ipc-") && internalReadRpcs.has(entry.rpc_method)) {
    return "read_only";
  }
  if (
    entry.surface.startsWith("workload-ipc-")
    && entry.rpc_method === "CheckTransactions"
  ) {
    return "plan_only";
  }
  if (
    entry.surface.startsWith("workload-ipc-")
    && entry.rpc_method === "CheckAndTallyProposals"
  ) {
    return "compatibility";
  }
  if (entry.surface.startsWith("workload-ipc-")) {
    return "internal_only";
  }
  if (entry.surface === "blockchain-service:dynamic-wasm") {
    return "unavailable_contract";
  }
  if (entry.surface === "blockchain-service:ibc_channel_manager") {
    return "compatibility";
  }
  if (entry.surface === "blockchain-service:evolution") {
    return "unavailable_contract";
  }
  if (entry.surface.startsWith("blockchain-service:")) {
    return "consequential";
  }
  if (entry.surface === "telemetry-http") {
    return "read_only";
  }
  if (entry.kind === "js_outbound") {
    return ["GET", "HEAD"].includes(entry.method) ? "read_only" : "consequential";
  }
  if (entry.kind === "js_local_file_action") {
    return "consequential";
  }
  if (entry.kind === "js_system_effect") {
    return "consequential";
  }
  if (entry.kind === "js_local_storage") {
    return "consequential";
  }
  if (entry.surface === "hypervisor-dev-replay") {
    if (entry.identity.endsWith(":probeModelUpstreamReachable")) {
      return "read_only";
    }
    if (
      entry.identity.endsWith(":writeEvidenceFile")
      || entry.identity.endsWith(":streamSessionTurn")
    ) {
      return "consequential";
    }
    return "compatibility";
  }
  if (entry.surface === "hypervisor-app") {
    return devCaseCommands.has(entry.command) ? "compatibility" : "unavailable_contract";
  }
  if (entry.kind === "js_local_storage") {
    return "consequential";
  }
  if (entry.surface === "wallet.network") {
    return "consequential";
  }
  if (entry.surface === "guardian-control") {
    if (entry.rpc_method === "LoadAssignedRecoveryShare") {
      return "read_only";
    }
    return "consequential";
  }
  if (entry.surface === "public-api") {
    if (["SubmitTransaction", "SetRuntimeSecret"].includes(entry.rpc_method)) {
      return "consequential";
    }
    if (entry.rpc_method === "DraftTransaction") {
      return "consequential";
    }
    return "read_only";
  }
  if (entry.surface === "ibc-http-gateway") {
    return entry.path === "/v1/ibc/submit" ? "consequential" : "read_only";
  }
  if (entry.surface === "provider-http" || entry.surface === "signer-http") {
    return "consequential";
  }
  if (entry.surface !== "hypervisor-daemon") {
    return "compatibility";
  }

  if (entry.method === "GET") {
    return directEffectCalls(entry).length > 0
      ? "consequential"
      : "read_only";
  }

  if (PLAN_ONLY_HTTP_IDENTITIES.has(entry.identity)) {
    return "plan_only";
  }
  return MUTATING_HTTP_METHODS.has(entry.method) ? "consequential" : "read_only";
}

function gateRecord(state, symbols, note) {
  return {
    state,
    symbols: [...new Set(symbols)].sort(),
    note,
  };
}

function observedGates(entry, classification) {
  if (classification !== "consequential" && classification !== "internal_only") {
    return Object.fromEntries(
      ["authority", "policy", "revocation", "fence", "ifc"].map((gate) => [
        gate,
        gateRecord(
          "not_applicable_no_effect",
          [],
          `No ${gate} gate is claimed because this entry is classified as non-consequential.`,
        ),
      ]),
    );
  }
  const calls = entry.handler_calls ?? [];
  const matching = (pattern) => calls.filter((call) => pattern.test(call));
  const gates = {
    authority: gateRecord(
      "not_established_at_final_invoker",
      [],
      "No authority may be inferred from request fields, UI state, or copied receipt refs.",
    ),
    policy: gateRecord(
      "not_established_at_final_invoker",
      [],
      "No final-invoker policy ordering proof is recorded for this entry.",
    ),
    revocation: gateRecord(
      "not_established_at_final_invoker",
      [],
      "No bounded-staleness revocation check is established at the final invoker.",
    ),
    fence: gateRecord(
      "not_established_at_final_invoker",
      [],
      "No owner-derived active-writer fence is established at the final invoker.",
    ),
    ifc: gateRecord(
      "not_established_at_final_invoker",
      [],
      "No estate-wide label and destination closure is established at the final invoker.",
    ),
  };

  if (entry.surface === "hypervisor-daemon") {
    gates.authority = gateRecord(
      "conditional_transport_auth_not_effect_authority",
      ["lifecycle_routes::auth_gate"],
      "The global auth ring enforces only when configured and is not proof of effect authority.",
    );
  }

  const authorityCalls = matching(/authoriz|grant|approval|signature|signer/iu);
  const policyCalls = matching(/policy|admission|preflight/iu);
  const revocationCalls = matching(/revok|expiry|epoch/iu);
  const fenceCalls = matching(/fence|exact_head|expected_head|revision|idempot/iu);
  const ifcCalls = matching(/ifc|information_flow|label|declass|destination/iu);
  for (const [name, symbols] of [
    ["authority", authorityCalls],
    ["policy", policyCalls],
    ["revocation", revocationCalls],
    ["fence", fenceCalls],
    ["ifc", ifcCalls],
  ]) {
    if (symbols.length > 0) {
      gates[name] = gateRecord(
        "observed_in_handler_not_order_proven",
        symbols,
        "The symbols occur in the handler body; M0 does not claim final-invoker ordering.",
      );
    }
  }

  if (entry.surface === "wallet.network") {
    const sequence = entry.handler_call_sequence ?? [];
    const effectCalls = walletEffectCalls(entry);
    const firstEffectIndex = sequence.findIndex((call) => effectCalls.includes(call));
    const beforeEffect = (pattern) => uniqueInOrder(
      sequence.filter((call, index) => (
        (firstEffectIndex === -1 || index < firstEffectIndex) && pattern.test(call)
      )),
    );
    const handlerAuthority = beforeEffect(
      /ensure_(?:control_root_signer|initialized_wallet_client_role|wallet_client_role)|validate_(?:root_record|.*signature)|validate_registered_approval_grant/iu,
    );
    gates.authority = gateRecord(
      entry.operation === "configure_control_root@v1"
        ? "derived_root_signer_match_before_write"
        : handlerAuthority.includes("ensure_control_root_signer")
            ? "control_root_signer_verified_before_handler_effect"
            : handlerAuthority.includes("ensure_initialized_wallet_client_role")
                ? "initialized_client_role_verified_before_handler_effect"
                : "service_method_role_with_uninitialized_root_compatibility",
      uniqueInOrder([
        "handlers::client_auth::authorize_wallet_method",
        ...handlerAuthority,
      ]),
      entry.operation === "configure_control_root@v1"
        ? "The proposed control-root key derives the transaction signer, and an existing root must match that signer before persistence."
        : handlerAuthority.some((symbol) => (
            symbol === "ensure_control_root_signer"
            || symbol === "ensure_initialized_wallet_client_role"
          ))
            ? "The dispatch role check and listed handler check run before the observed handler effect calls."
            : "The dispatch method-role check runs before the handler, but this path permits the documented uninitialized-root compatibility mode.",
    );
    const policySymbols = beforeEffect(
      /validate|enforce|policy|scope|constraint|capabilit|is_(?:string|constraint)_subset/iu,
    );
    gates.policy = gateRecord(
      policySymbols.length > 0
        ? "method_role_and_handler_checks_before_observed_effect"
        : "method_role_policy_only",
      uniqueInOrder([
        "handlers::client_auth::authorize_wallet_method",
        ...policySymbols,
      ]),
      policySymbols.length > 0
        ? "The listed method-specific validation and constraint calls precede the first observed handler effect call; they are not a generic production PEP."
        : "The method role is checked before dispatch; no additional callable policy check was identified before the handler effect.",
    );
    if (
      entry.operation !== "panic_stop@v1"
      && beforeEffect(/load_revocation_epoch/iu).length > 0
    ) {
      gates.revocation = gateRecord(
        "revocation_epoch_loaded_before_observed_effect",
        ["load_revocation_epoch"],
        "The handler loads and checks the active wallet revocation epoch before its observed effect calls; M0 does not claim estate-wide bounded-staleness closure.",
      );
    }
    const fenceSymbols = beforeEffect(
      /exact_replay|replay|state\.get|enforce_.*window|validate_next_version/iu,
    );
    if (fenceSymbols.length > 0) {
      gates.fence = gateRecord(
        "replay_or_slot_check_before_observed_effect_not_writer_fence",
        fenceSymbols,
        "The listed replay, sequence, or occupied-slot checks precede the first observed handler effect; they are not an owner-derived active-writer fence.",
      );
    }
  }
  if (entry.surface.startsWith("blockchain-service:")) {
    gates.authority = gateRecord(
      "transaction_signer_context_only",
      ["TxContext::signer_account_id"],
      "The chain transaction establishes a signer context; service-specific effect authority is not inferred.",
    );
    gates.policy = gateRecord(
      "service_specific_checks_only",
      (entry.handler_calls ?? []).filter((call) => /valid|policy|authoriz|verify|check/iu.test(call)),
      "Any listed checks are local to the service method and are not a generic production PEP.",
    );
  }
  if (entry.surface === "agentgres-replica") {
    gates.authority = gateRecord(
      "not_established_unauthenticated_replication_peer",
      [],
      "The listener accepts any reachable AGRS2 peer; writer epoch is a fence, not authenticated effect authority.",
    );
    gates.policy = gateRecord(
      "protocol_framing_only_not_effect_policy",
      ["MAGIC", "CATCHUP_CHUNK"],
      "Protocol shape and catch-up framing are checked, but no owner policy authorizes the bytes being appended.",
    );
    gates.revocation = gateRecord(
      "not_established_at_replica_listener",
      [],
      "No revocation source is checked before a catch-up or batch append.",
    );
    gates.fence = gateRecord(
      "writer_epoch_checked_before_append",
      ["MuxEngine::current_epoch", "primary_epoch", "max_epoch", "epoch"],
      "The recovered maximum writer epoch fences stale primaries at handshake and before each batch append.",
    );
    gates.ifc = gateRecord(
      "not_established_for_replication_destination",
      [],
      "The stream carries raw admitted log bytes without an information-flow or destination-policy check at this listener.",
    );
  }
  if (entry.surface === "google-oauth-callback") {
    gates.authority = gateRecord(
      "oauth_state_and_pkce_only_not_product_authority",
      ["wait_for_google_callback", "code_verifier"],
      "Callback state and PKCE bind the OAuth exchange; they do not establish IOI product effect authority.",
    );
    gates.policy = gateRecord(
      "requested_google_scopes_only_not_owner_policy",
      ["resolve_requested_google_oauth_scopes", "requested_scopes"],
      "The connector bounds requested Google scopes, but no owner policy authorizes local bearer-token persistence.",
    );
    gates.revocation = gateRecord(
      "pending_session_timeout_only",
      ["GOOGLE_AUTH_TIMEOUT_SECS", "pending_session_matches"],
      "The pending callback expires and must still match in-memory state; provider-token revocation is not checked before persistence.",
    );
    gates.fence = gateRecord(
      "pending_state_rechecked_before_local_write",
      ["pending_session_matches", "save_google_auth_record"],
      "The same in-memory pending state is checked after token exchange and before the local token record write.",
    );
    gates.ifc = gateRecord(
      "not_established_for_local_bearer_token_file",
      [],
      "No IFC label, destination rule, or explicit file-permission hardening is established for the token record.",
    );
  }
  if (entry.surface === "hypervisor-editor-proxy") {
    gates.authority = gateRecord(
      "active_lease_and_optional_token_match_before_forward",
      ["capability_lease_status", "extract_lease_token"],
      "The bound lease must be active; a supplied token must match, while tokenless same-origin asset and WebSocket requests are admitted.",
    );
    gates.policy = gateRecord(
      "lease_service_binding_only",
      ["bound_lease", "service_id", "internal_port"],
      "The proxy is bound to one service and loopback target, but it cannot authorize the semantics of arbitrary forwarded bytes.",
    );
    gates.revocation = gateRecord(
      "active_lease_rechecked_on_new_connection_only",
      ["capability_lease_status"],
      "Expiry or revocation fails closed for new connections; an established byte stream is not revalidated.",
    );
    gates.fence = gateRecord(
      "not_established_for_forwarded_effect",
      [],
      "No exact-head, operation, idempotency, or owner-derived fence is available at the byte proxy.",
    );
    gates.ifc = gateRecord(
      "loopback_target_only_not_semantic_ifc",
      ["TcpStream::connect((\"127.0.0.1\", internal_port))"],
      "Loopback destination binding is real, but payload labels and destination policy are opaque to the proxy.",
    );
  }
  if (entry.surface === "guardian-encrypted-container") {
    gates.authority = gateRecord(
      "mutual_transport_identity_only",
      ["create_ipc_server_config", "IpcClientType::try_from"],
      "TLS peer identity and a one-byte client type select an internal channel; they do not prove effect-level authority.",
    );
    gates.policy = gateRecord(
      "channel_selection_only",
      ["orchestration_channel", "workload_channel"],
      "The container selects an internal RPC channel and delegates all semantic policy downstream.",
    );
    gates.revocation = gateRecord(
      "certificate_policy_not_effect_revocation",
      ["create_ipc_server_config"],
      "Certificate admission is transport policy; no effect-grant revocation check occurs at dynamic dispatch.",
    );
    gates.fence = gateRecord(
      "not_established_at_encrypted_transport",
      [],
      "No effect fence can be inferred from the encrypted framed transport.",
    );
    gates.ifc = gateRecord(
      "encrypted_channel_only_not_ifc",
      ["server_post_handshake", "AeadWrappedStream"],
      "Confidential transport does not establish information-flow labels or destination closure.",
    );
  }
  if (
    entry.kind === "js_outbound"
    || entry.kind === "js_local_file_action"
    || entry.kind === "js_system_effect"
    || entry.kind === "js_local_storage"
  ) {
    gates.authority = gateRecord(
      "client_or_facade_not_authority",
      [],
      "The JavaScript caller is never accepted as effect authority; real gates must exist downstream.",
    );
    gates.policy = gateRecord(
      "downstream_only_not_established_here",
      [],
      "Any downstream daemon or provider policy is not inferred at this facade call site.",
    );
    if (entry.surface === "hypervisor-product-ui-test-signer") {
      gates.authority = gateRecord(
        "development_flag_and_deterministic_test_key_not_product_authority",
        ["IOI_WALLET_TEST_SIGNER", "mintApprovalGrant"],
        "The helper is reachable only through the explicit development test-signer flag; its deterministic key is never accepted as production authority.",
      );
      gates.policy = gateRecord(
        "caller_supplied_hash_binding_only_not_owner_policy",
        ["--policy-hash", "--request-hash"],
        "The helper signs caller-provided bindings for tests and performs no owner-policy decision.",
      );
    }
  }

  if (entry.surface === "public-api" && entry.rpc_method === "SubmitTransaction") {
    gates.authority = gateRecord(
      "stateless_transaction_signature_only",
      ["verify_stateless_signature"],
      "Signature admission is real; generic effect authority and service policy are downstream.",
    );
    gates.fence = gateRecord(
      "account_nonce_and_mempool_dedup_only",
      ["tx_account_nonce", "tx_pool_ref.add"],
      "Nonce and mempool duplicate handling are not an owner-derived effect fence.",
    );
  }

  if (entry.surface === "ibc-http-gateway") {
    gates.policy = gateRecord(
      "rate_limit_and_resource_bounds_only",
      ["rate_limit_middleware", "RequestBodyLimitLayer"],
      "Transport limits are not transaction authority.",
    );
  }

  return gates;
}

const FINAL_INVOKER_OVERRIDES = new Map([
  [
    "stream:agentgres-replica:AGRS2 <catch-up-or-batch>",
    {
      symbol: "std::fs::File::write_all",
      source_file: "crates/agentgres/src/replica.rs",
      resolution: "verified_effect_leaf",
      note: "The replica appends catch-up and admitted batch bytes to muxlog.bin before acknowledging possession; device flush is asynchronous except at catch-up and connection close.",
    },
  ],
  [
    "http:google-oauth-callback:GET /?code&state",
    {
      symbol: "save_google_auth_record",
      source_file: "crates/services/src/agentic/runtime/connectors/google_auth.rs",
      resolution: "verified_effect_leaf",
      note: "A matching pending state and PKCE exchange lead to the local OAuth token record write.",
    },
  ],
  [
    "http:hypervisor-daemon:POST /v1/hypervisor/authority/preflight",
    {
      symbol: "persist_record[authority-receipts]",
      source_file: "crates/node/src/bin/hypervisor-daemon.rs",
      resolution: "verified_effect_leaf",
      note: "Every admit and refusal branch calls emit_receipt, whose final leaf persists an authority-receipt record.",
    },
  ],
  [
    "http:hypervisor-daemon:POST /v1/hypervisor/failover/evaluate",
    {
      symbol: "persist_plan | failover_run_core",
      source_file: "crates/node/src/bin/hypervisor_daemon_routes/placement_failover_routes.rs",
      resolution: "verified_effect_leaf_alternatives",
      note: "Evaluation persists last-evaluated plan state and, on qualifying evidence, creates a failover run before persisting the triggered plan.",
    },
  ],
  [
    "http:hypervisor-daemon:POST /v1/threads/:id/mcp/validate",
    {
      symbol: "persist_record[agents]",
      source_file: "crates/node/src/bin/hypervisor-daemon.rs",
      resolution: "verified_effect_leaf",
      note: "The shared apply_mcp_control path persists the planner-updated agent even for mcp_validate.",
    },
  ],
  [
    "http:hypervisor-daemon:POST /v1/threads/:id/memory/validate",
    {
      symbol: "admit_and_persist_event",
      source_file: "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs",
      resolution: "verified_effect_leaf",
      note: "The validation projection is wrapped in a memory.validate control event and admitted to the unified log.",
    },
  ],
  [
    "http:hypervisor-daemon:POST /v1/threads/:id/tools/:name/invoke",
    {
      symbol: "coding_tool_workspace::apply_workspace_patch",
      source_file: "crates/services/src/agentic/runtime/kernel/coding_tool_workspace.rs",
      resolution: "verified_effect_leaf_for_file.apply_patch_subdispatch",
      note: "The dynamic route also supports read/plan tools; this leaf is only the selected file.apply_patch effect.",
    },
  ],
  [
    "http:ibc-http-gateway:POST /v1/ibc/submit",
    {
      symbol: "IbcHost::submit_ibc_messages",
      source_file: "crates/plugins/http-rpc-gateway/src/lib.rs",
      resolution: "verified_effect_leaf",
      note: "The handler delegates decoded message bytes directly to the host.",
    },
  ],
  [
    "http:provider-http:POST /v1/provision",
    {
      symbol: "ProviderController::provision_with_domain",
      source_file: "crates/validator/src/standard/provider/mod.rs",
      resolution: "verified_effect_leaf",
      note: "The controller mutates active_jobs and constructs the signed provider receipt.",
    },
  ],
  [
    "http:signer:POST /sign",
    {
      symbol: "perform_sign",
      source_file: "crates/node/src/bin/signer.rs",
      resolution: "verified_effect_leaf",
      note: "The critical section flushes signer WAL state before producing the signature.",
    },
  ],
  [
    "rpc:public-api:SetRuntimeSecret",
    {
      symbol: "runtime_secret::set_secret",
      source_file: "crates/validator/src/standard/orchestration/grpc_public/session_handlers.rs",
      resolution: "verified_effect_leaf",
      note: "The RPC writes bounded process-local secret state.",
    },
  ],
  [
    "rpc:public-api:DraftTransaction",
    {
      symbol: "nonce_manager entry increment | IntentResolver::resolve_intent | Keypair::sign",
      source_file: "crates/validator/src/standard/orchestration/grpc_public/tx_handlers.rs",
      resolution: "verified_effect_leaf_alternatives",
      note: "Drafting reserves an in-process nonce, may invoke the inference runtime, and signs the resulting transaction; it is not a read-only plan.",
    },
  ],
  [
    "rpc:public-api:SubmitTransaction",
    {
      symbol: "tx_pool_ref.add | tx_ingest_tx.try_send",
      source_file: "crates/validator/src/standard/orchestration/grpc_public/tx_handlers.rs",
      resolution: "verified_effect_leaf_alternatives",
      note: "Fast admission mutates the pool and fans out; the screened path enqueues ingestion.",
    },
  ],
  [
    "compatibility-io:hypervisor-dev-replay:streamSessionTurn",
    {
      symbol: "globalThis.fetch",
      source_file: "scripts/hypervisor-app-dev-replay-server.mjs",
      resolution: "verified_effect_leaf",
      note: "POSTs to the explicitly configured OpenAI-compatible development upstream.",
    },
  ],
]);

function javascriptOutboundInvoker(entry) {
  return {
    request: "node:http.request",
    WebSocket: "globalThis.WebSocket",
    EventSource: "globalThis.EventSource",
    sendBeacon: "navigator.sendBeacon",
  }[entry.handler] ?? "globalThis.fetch";
}

function finalInvokerFor(entry, classification) {
  if (classification !== "consequential" && classification !== "internal_only") {
    return null;
  }
  if (FINAL_INVOKER_OVERRIDES.has(entry.identity)) {
    return FINAL_INVOKER_OVERRIDES.get(entry.identity);
  }
  if (entry.surface === "wallet.network") {
    const effects = walletEffectCalls(entry);
    if (effects.length === 0) {
      throw new Error(`${entry.identity}: consequential wallet method has no observed effect call`);
    }
    return {
      symbol: effects.join(" | "),
      source_file: entry.handler_source_file,
      resolution: "verified_service_effect_calls_not_production_pep",
      note: "These exact effect calls are observed in the resolved wallet handler; downstream provider completion and production PEP closure are not claimed.",
    };
  }
  if (entry.surface.startsWith("blockchain-service:")) {
    const candidates = directEffectCalls(entry);
    if (candidates.length > 0) {
      return {
        symbol: candidates.at(-1),
        source_file: entry.handler_source_file,
        resolution: "static_service_arm_candidate_not_order_proven",
        note: "The effect-shaped leaf is statically observed in this method; M0 does not claim complete order or policy closure.",
      };
    }
    return {
      symbol: entry.handler_source_symbol ?? entry.handler,
      source_file: entry.handler_source_file ?? entry.source_file,
      resolution: "service_method_boundary_only",
      note: "No deeper effect leaf was proven; the typed final-invoker blocker remains open.",
    };
  }
  if (entry.kind === "js_outbound") {
    return {
      symbol: javascriptOutboundInvoker(entry),
      source_file: entry.handler_source_file,
      resolution: "verified_javascript_network_leaf",
      note: "This is the facade's external crossing; it does not establish downstream effect success.",
    };
  }
  if (entry.kind === "js_local_file_action") {
    return {
      symbol: "writeFileSync",
      source_file: entry.source_file,
      resolution: "verified_javascript_file_leaf",
      note: "This compatibility preference write is local facade state, never owner truth.",
    };
  }
  if (entry.kind === "js_system_effect") {
    return {
      symbol: entry.handler_call_sequence.join(" | "),
      source_file: entry.handler_source_file,
      resolution: "verified_javascript_system_leaf",
      note: "These exact local filesystem or child-process calls are the active JavaScript system-effect crossing.",
    };
  }
  if (entry.kind === "js_local_storage") {
    return {
      symbol: entry.handler,
      source_file: entry.source_file,
      resolution: "verified_browser_storage_leaf",
      note: "This is local browser compatibility state, never architecture authority or runtime truth.",
    };
  }
  const candidates = directEffectCalls(entry);
  if (candidates.length > 0) {
    return {
      symbol: candidates.at(-1),
      source_file: entry.handler_source_file,
      resolution: "static_candidate_not_order_proven",
      note: "M0 found this effect-shaped call in the handler but does not claim it is the sole final leaf.",
    };
  }
  return {
    symbol: entry.handler_source_symbol ?? entry.handler ?? entry.source_symbol,
    source_file: entry.handler_source_file ?? entry.source_file,
    resolution: "handler_boundary_only",
    note: "No deeper effect leaf was proven; the typed census blocker remains open.",
  };
}

function finalInvokerClaimState(finalInvoker) {
  if (finalInvoker === null) {
    return null;
  }
  if (/^verified_effect_leaf(?:_|$)/u.test(finalInvoker.resolution)) {
    return "verified_effect_leaf";
  }
  if (/^verified_(?:javascript|browser|service)_/u.test(finalInvoker.resolution)) {
    return "verified_boundary_not_downstream_effect";
  }
  return "candidate_or_handler_boundary_not_final";
}

const SELECTED_ROUTE_APPLICABILITY = new Map([
  ["http:hypervisor-daemon:POST /v1/hypervisor/auth/login", "required_journey"],
  ["http:hypervisor-daemon:GET /v1/hypervisor/auth/whoami", "required_journey"],
  ["http:hypervisor-daemon:GET /v1/hypervisor/authority/receipts", "required_journey"],
  ["http:hypervisor-daemon:POST /v1/hypervisor/goal-runs", "required_journey"],
  ["http:hypervisor-daemon:POST /v1/hypervisor/goal-runs/:id/start", "required_journey"],
  ["http:hypervisor-daemon:POST /v1/hypervisor/goal-runs/:id/lifecycle-recovery", "required_journey"],
  ["http:hypervisor-daemon:GET /v1/hypervisor/goal-runs/:id", "required_journey"],
  ["http:hypervisor-daemon:POST /v1/hypervisor/outcome-rooms", "required_journey"],
  ["http:hypervisor-daemon:POST /v1/hypervisor/outcome-rooms/:id/attach-goal-run", "required_journey"],
  ["http:hypervisor-daemon:GET /v1/hypervisor/outcome-rooms/:id", "required_journey"],
  ["http:hypervisor-daemon:POST /v1/hypervisor/work-frontier-items", "required_journey"],
  ["http:hypervisor-daemon:POST /v1/hypervisor/work-claim-leases", "required_journey"],
  ["http:hypervisor-daemon:POST /v1/hypervisor/attempts", "required_journey"],
  ["http:hypervisor-daemon:POST /v1/hypervisor/work-results", "required_journey"],
  ["http:hypervisor-daemon:POST /v1/threads/:id/workspace-change-reviews/detect", "required_journey"],
  ["http:hypervisor-daemon:POST /v1/threads/:id/workspace-change-reviews/control", "required_journey"],
  ["http:hypervisor-daemon:POST /v1/hypervisor/authority/preflight", "required_journey"],
  ["http:hypervisor-daemon:POST /v1/threads/:id/tools/:name/invoke", "required_effect"],
  ["http:hypervisor-daemon:GET /v1/runs/:id/inspect", "required_journey"],
  ["http:hypervisor-daemon:GET /v1/runs/:id/replay", "required_journey"],
  ["service:wallet.network:issue_principal_authority_binding@v1", "adjacent_not_sufficient"],
  ["service:wallet.network:resolve_principal_authority@v1", "adjacent_not_sufficient"],
  ["service:wallet.network:issue_session_grant@v1", "adjacent_not_sufficient"],
  ["service:wallet.network:commit_receipt_root@v1", "adjacent_not_sufficient"],
  ["service:wallet.network:panic_stop@v1", "adjacent_not_sufficient"],
]);

function blockerFor(entry, classification, selectedApplicability) {
  if (selectedApplicability === "required_effect") {
    return "BLK-M0-SELECTED-REPO-EFFECT";
  }
  if (selectedApplicability === "required_journey") {
    return "BLK-M0-SELECTED-JOURNEY-BINDING";
  }
  if (classification === "unavailable_contract") {
    return "BLK-M0-UNMOUNTED-SURFACE";
  }
  if (classification === "compatibility") {
    return "BLK-M0-COMPATIBILITY-NONAUTHORITY";
  }
  if (classification === "internal_only") {
    return "NONCLAIM-M0-INTERNAL-IPC";
  }
  if (entry.surface === "agentgres-replica") {
    return "BLK-M0-AGENTGRES-REPLICA-AUTHORITY";
  }
  if (entry.surface === "google-oauth-callback") {
    return "BLK-M0-GOOGLE-OAUTH-CALLBACK-PROOF";
  }
  if (entry.surface === "hypervisor-editor-proxy") {
    return "BLK-M0-EDITOR-PROXY-DOWNSTREAM";
  }
  if (entry.surface === "wallet.network") {
    return "BLK-M0-WALLET-PRODUCTION-PEP";
  }
  if (entry.surface.startsWith("blockchain-service:")) {
    return "BLK-M0-BLOCKCHAIN-SERVICE-EFFECT-PROOF";
  }
  if (
    entry.kind === "js_outbound"
    || entry.kind === "js_local_file_action"
    || entry.kind === "js_system_effect"
    || entry.kind === "js_local_storage"
  ) {
    if (
      entry.surface === "hypervisor-app-dev-outbound"
      || entry.surface === "hypervisor-dev-replay"
      || entry.surface === "hypervisor-product-ui-test-signer"
    ) {
      return "BLK-M0-COMPATIBILITY-NONAUTHORITY";
    }
    return classification === "consequential"
      ? "NONCLAIM-M0-JAVASCRIPT-FACADE"
      : null;
  }
  if (entry.surface === "hypervisor-app" || entry.surface === "hypervisor-dev-replay") {
    return "BLK-M0-COMPATIBILITY-NONAUTHORITY";
  }
  if (classification === "consequential") {
    return "BLK-M0-FINAL-INVOKER-PROOF";
  }
  return null;
}

function durableEvidenceFor(entry, classification) {
  if (classification !== "consequential" && classification !== "internal_only") {
    return {
      state: "not_applicable",
      symbols: [],
      note: "This entry is classified as read, plan, compatibility, or unavailable.",
    };
  }
  if (entry.surface === "signer-http") {
    return {
      state: "durable_local_wal",
      symbols: ["File::write_all", "File::sync_all", "SignResponse"],
      note: "The WAL is flushed before signature production.",
    };
  }
  if (entry.surface === "wallet.network") {
    const effects = walletEffectCalls(entry);
    const providerEffects = effects.filter((call) => call.startsWith("provider."));
    return {
      state: providerEffects.length > 0
        ? "provider_io_with_transactional_receipt_or_consumption_state"
        : "transactional_wallet_record_or_audit_state",
      symbols: effects,
      note: `Exact handler-scoped effect calls for ${entry.operation}; the resolved source symbol and anchor identify the method-specific record construction.`,
    };
  }
  if (entry.surface === "agentgres-replica") {
    return {
      state: "replica_muxlog_and_possession_ack",
      symbols: ["muxlog.bin", "File::write_all", "write_u64"],
      note: "The replica appends exact log bytes and returns a batch id acknowledgement, but normal acknowledgements precede device flush and are not canonical effect receipts.",
    };
  }
  if (entry.surface === "google-oauth-callback") {
    return {
      state: "local_secret_record_without_canonical_receipt",
      symbols: ["google_workspace_oauth.json", "save_google_auth_record"],
      note: "The connector writes access and refresh token material to local configuration; it emits no canonical operation receipt or evidence chain.",
    };
  }
  if (
    entry.identity
    === "http:hypervisor-daemon:POST /v1/hypervisor/authority/preflight"
  ) {
    return {
      state: "local_authority_receipt_record",
      symbols: ["emit_receipt", "persist_record", "authority-receipts"],
      note: "A local receipt is persisted for both admission and refusal; it is not a portable authority proof or selected effect receipt.",
    };
  }
  if (
    entry.identity
    === "http:hypervisor-daemon:POST /v1/hypervisor/failover/evaluate"
  ) {
    return {
      state: "failover_plan_and_conditional_run_records",
      symbols: ["persist_plan", "failover_run_core"],
      note: "Evaluation updates the plan even when no evidence qualifies and can create a wallet-gated failover run when a trigger qualifies.",
    };
  }
  if (
    entry.identity
    === "http:hypervisor-daemon:POST /v1/threads/:id/mcp/validate"
  ) {
    return {
      state: "updated_agent_record",
      symbols: ["apply_mcp_control", "persist_record"],
      note: "The validation result is committed into the agent record; no production authority receipt is established.",
    };
  }
  if (
    entry.identity
    === "http:hypervisor-daemon:POST /v1/threads/:id/memory/validate"
  ) {
    return {
      state: "unified_runtime_event_with_declared_receipt_refs",
      symbols: ["admit_and_persist_event", "memory.validate"],
      note: "The route persists the planned memory validation event; M0 does not infer a complete receipt chain from declared refs.",
    };
  }
  if (entry.surface === "public-api" && entry.rpc_method === "DraftTransaction") {
    return {
      state: "process_nonce_reservation_and_returned_signed_draft",
      symbols: ["nonce_manager", "signed_tx_bytes"],
      note: "The nonce reservation is process-local and the signed draft is returned to the caller; no durable draft receipt or ambiguous-failure recovery exists.",
    };
  }
  if (entry.surface === "hypervisor-editor-proxy") {
    return {
      state: "proxy_event_only_downstream_effect_unknown",
      symbols: ["persist_record", "editor-proxy-events"],
      note: "Connection events are locally persisted, but arbitrary downstream byte effects and their receipts remain opaque.",
    };
  }
  if (entry.surface === "guardian-encrypted-container") {
    return {
      state: "delegated_internal_channel_evidence_unknown",
      symbols: [],
      note: "The transport itself emits no durable effect record; downstream typed handlers own any state or receipt.",
    };
  }
  if (entry.surface.startsWith("blockchain-service:")) {
    const symbols = directEffectCalls(entry);
    return {
      state: symbols.length > 0
        ? "transactional_state_or_external_effect_symbols_observed"
        : "not_identified",
      symbols: [...new Set(symbols)].sort(),
      note: symbols.length > 0
        ? "The service executes inside transaction state; commit and receipt semantics remain downstream."
        : "No durable record, receipt, or evidence leaf was identified in the dispatch arm or method body.",
    };
  }
  if (entry.kind === "js_outbound") {
    return {
      state: "downstream_response_only",
      symbols: [javascriptOutboundInvoker(entry)],
      note: "No durable commit or receipt is inferred from the JavaScript response.",
    };
  }
  if (entry.kind === "js_local_file_action") {
    return {
      state: "local_compatibility_file",
      symbols: ["writeFileSync", "app-preferences.json"],
      note: "The file is local facade state and is not canonical owner evidence.",
    };
  }
  if (entry.kind === "js_system_effect") {
    return entry.system_effect_categories.includes("process")
      ? {
          state: "child_process_lifecycle_without_durable_receipt",
          symbols: entry.handler_call_sequence,
          note: "The child-process start or signal is observable only through process state and logs; no durable owner receipt is emitted.",
        }
      : {
          state: "local_compatibility_file_without_owner_receipt",
          symbols: entry.handler_call_sequence,
          note: "The explicit local filesystem calls persist compatibility or development evidence state, not canonical owner evidence.",
        };
  }
  if (entry.kind === "js_local_storage") {
    return {
      state: "browser_local_compatibility_state",
      symbols: [entry.handler],
      note: "Browser storage is durable only to this local client profile and is never canonical owner evidence.",
    };
  }
  if (entry.surface === "public-api" && entry.rpc_method === "SubmitTransaction") {
    return {
      state: "process_state_then_chain",
      symbols: ["tx_status_cache", "receipt_map", "tx_pool_ref", "tx_ingest_tx"],
      note: "RPC acceptance is not itself final chain execution.",
    };
  }
  if (entry.surface === "public-api" && entry.rpc_method === "SetRuntimeSecret") {
    return {
      state: "process_local_ttl_state",
      symbols: ["runtime_secret::set_secret"],
      note: "No durable receipt is emitted by this RPC.",
    };
  }
  const symbols = directEffectCalls(entry);
  return {
    state: symbols.length > 0 ? "handler_evidence_symbols_observed" : "not_identified",
    symbols: [...new Set(symbols)].sort(),
    note: symbols.length > 0
      ? "Symbols are observed in the handler; durable commit semantics are not inferred."
      : "No durable record, receipt, or evidence leaf was identified at this boundary.",
  };
}

function recoveryFor(entry, classification) {
  if (classification !== "consequential" && classification !== "internal_only") {
    return {
      idempotency: "not_applicable",
      recovery: "not_applicable",
    };
  }
  if (entry.surface === "agentgres-replica") {
    return {
      idempotency: "connection_local_batch_ids_no_durable_dedup_proof",
      recovery: "offset_catch_up_and_torn_tail_recovery_without_automatic_failover",
    };
  }
  if (entry.surface === "google-oauth-callback") {
    return {
      idempotency: "in_memory_pending_state_only",
      recovery: "no_canonical_receipt_or_ambiguous_token_write_recovery",
    };
  }
  if (
    entry.identity
    === "http:hypervisor-daemon:POST /v1/hypervisor/failover/evaluate"
  ) {
    return {
      idempotency: "one_active_run_check_but_evaluation_timestamps_mutate",
      recovery: "wallet_gated_run_parking_without_end_to_end_fault_proof",
    };
  }
  if (entry.surface === "public-api" && entry.rpc_method === "DraftTransaction") {
    return {
      idempotency: "not_idempotent_process_nonce_is_reserved_per_call",
      recovery: "no_durable_draft_or_nonce_reservation_recovery",
    };
  }
  if (entry.surface === "hypervisor-editor-proxy") {
    return {
      idempotency: "not_established_for_forwarded_bytes",
      recovery: "connection_reconnect_only_effect_recovery_not_established",
    };
  }
  if (entry.kind === "js_local_storage") {
    return {
      idempotency: "browser_storage_last_write_or_remove_only",
      recovery: "no_owner_receipt_or_cross_device_recovery",
    };
  }
  if (entry.kind === "js_system_effect") {
    return entry.system_effect_categories.includes("process")
      ? {
          idempotency: "process_start_or_signal_not_idempotent",
          recovery: "child_exit_propagation_and_signal_forwarding_only",
        }
      : {
          idempotency: "local_file_last_write_without_operation_key",
          recovery: "no_atomic_replace_or_ambiguous_write_recovery_proof",
        };
  }
  if (entry.surface === "guardian-encrypted-container") {
    return {
      idempotency: "delegated_to_typed_internal_handler",
      recovery: "delegated_to_typed_internal_handler",
    };
  }
  if (entry.surface === "wallet.network") {
    const calls = entry.handler_call_sequence ?? [];
    if (calls.includes("exact_replay")) {
      return {
        idempotency: "exact_binding_replay_returns_existing_success",
        recovery: "no_end_to_end_ambiguous_commit_recovery_proof",
      };
    }
    if (calls.some((call) => /replay|enforce_.*window/iu.test(call))) {
      return {
        idempotency: "bounded_replay_or_sequence_state_observed",
        recovery: "retry_refusal_or_window_behavior_without_ambiguous_commit_recovery_proof",
      };
    }
    if (
      calls.includes("state.get")
      && calls.some((call) => /receipt_key|operation|request|_key/iu.test(call))
    ) {
      return {
        idempotency: "occupied_request_or_record_slot_refuses_replay",
        recovery: "no_end_to_end_ambiguous_commit_recovery_proof",
      };
    }
    return {
      idempotency: "not_established",
      recovery: "no_end_to_end_ambiguous_commit_recovery_proof",
    };
  }
  const text = `${entry.operation} ${(entry.handler_calls ?? []).join(" ")}`.toLowerCase();
  return {
    idempotency: text.includes("idempot")
      ? "idempotency_symbol_observed_not_end_to_end_proven"
      : "not_established",
    recovery: /(recover|replay|reconcile|rollback|restore)/u.test(text)
      ? "recovery_symbol_observed_not_fault_proven"
      : "not_established",
  };
}

export function createInitialReview(repoRoot, discoveredEntries) {
  const devCaseCommands = new Set(
    discoveredEntries
      .filter((entry) => entry.kind === "compatibility_dispatch")
      .map((entry) => entry.command),
  );
  const entries = discoveredEntries.map((entry) => {
    const classification = initialClassification(entry, devCaseCommands);
    const selectedProfileApplicability = SELECTED_ROUTE_APPLICABILITY.get(entry.identity)
      ?? "not_selected";
    const blockerRef = blockerFor(entry, classification, selectedProfileApplicability);
    const finalInvoker = finalInvokerFor(entry, classification);
    const anchoredFinalInvoker = finalInvoker === null
      ? null
      : {
          ...finalInvoker,
          claim_state: finalInvokerClaimState(finalInvoker),
          source_anchor_sha256: sha256(
            readRepoFile(repoRoot, finalInvoker.source_file).source,
          ),
        };
    const implementationState = selectedProfileApplicability.startsWith("required_")
      || classification === "unavailable_contract"
      || entry.surface === "hypervisor-app"
      ? "unavailable"
      : classification === "consequential" || classification === "internal_only"
        ? "partial"
        : "not_applicable";
    return {
      identity: entry.identity,
      review_status: "unreviewed",
      review_origin: "heuristic_suggestion",
      kind: entry.kind,
      surface: entry.surface,
      operation: entry.operation,
      method: entry.method ?? null,
      path: entry.path ?? null,
      rpc_service: entry.rpc_service ?? null,
      rpc_method: entry.rpc_method ?? null,
      service_method: entry.service_method ?? null,
      command: entry.command ?? null,
      storage_method: entry.storage_method ?? null,
      storage_key_expression: entry.storage_key_expression ?? null,
      active_state: entry.active_state,
      source_file: entry.source_file,
      source_symbol: entry.source_symbol,
      handler: entry.handler,
      handler_source_file: entry.handler_source_file,
      handler_source_symbol: entry.handler_source_symbol,
      handler_resolution: entry.handler_resolution,
      classification,
      effect_class: effectClassFor(entry, classification),
      ...ownerForEntry(entry),
      registration_anchor_sha256: entry.source_anchor.sha256,
      handler_anchor_sha256: entry.handler_anchor?.sha256 ?? null,
      final_invoker: anchoredFinalInvoker,
      pre_effect_gates: observedGates(entry, classification),
      durable_record_receipt_evidence: durableEvidenceFor(entry, classification),
      idempotency_recovery: recoveryFor(entry, classification),
      selected_profile_applicability: selectedProfileApplicability,
      implementation_state: implementationState,
      blocker_or_nonclaim_ref: blockerRef,
    };
  });
  return {
    evidence_format: "ioi.m0.reviewed_entry_lock.v1",
    lock_state: "worksheet_unreviewed",
    as_of_date: null,
    default_classification: "fail_closed_unclassified",
    discovery_scope: {
      active_surfaces: [
        "Hypervisor daemon Axum registry",
        "conditional Hypervisor session-preview listener",
        "IBC, telemetry, provider, and signer HTTP",
        "standalone Agentgres replication protocol and Google OAuth callback listener",
        "wallet.network service dispatch",
        "registered native blockchain service methods and dynamic WASM boundary",
        "mounted public and conditional Guardian RPC",
        "mounted internal workload RPC and encrypted Guardian channel dispatch",
        "unmounted model-mount RPC compatibility contract",
        "Hypervisor app host commands, development replay crossing, and browser storage mutations",
        "standing product UI JavaScript outbound, dynamically served augmentation, local compatibility effects, and child-process lifecycle",
        "lease-authenticated raw editor proxy",
        "development replay command and actual I/O boundaries",
      ],
      mutation_methods: [
        "ANY",
        "CONNECT",
        "DELETE",
        "DYNAMIC",
        "PATCH",
        "POST",
        "PUT",
        "RPC",
        "TRACE",
        "service_method",
      ],
      rule: "Every discovered identity is listed below; no classification is inherited by a new identity.",
    },
    entries,
  };
}

function sourceLock(repoRoot, relativePath, note) {
  const { source } = readRepoFile(repoRoot, relativePath);
  return {
    source_file: relativePath,
    source_sha256: sha256(source),
    note,
  };
}

function createDiscoverySourceCoverage(repoRoot) {
  const groups = Object.entries(DISCOVERY_COVERAGE).map(([coverageId, coverage]) => ({
    coverage_id: coverageId,
    sources: Object.entries(coverage.files)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([relativePath, note]) => sourceLock(repoRoot, relativePath, note)),
  }));
  groups.push({
    coverage_id: "active_javascript_effect_source",
    sources: Object.entries(ACTIVE_JAVASCRIPT_EFFECT_SOURCE_COVERAGE)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([relativePath, note]) => sourceLock(repoRoot, relativePath, note)),
  });
  groups.push({
    coverage_id: "active_javascript_server_source",
    sources: Object.entries(ACTIVE_JAVASCRIPT_SERVER_SOURCE_COVERAGE)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([relativePath, note]) => sourceLock(repoRoot, relativePath, note)),
  });
  groups.push({
    coverage_id: "active_javascript_system_effect_action",
    actions: discoverJsSystemEffects({
      repoRoot,
      relativePaths: activeJavaScriptEffectSources(repoRoot),
    }).map((entry) => ({
      identity: entry.identity,
      operation: JS_SYSTEM_EFFECT_ACTIONS[entry.identity]?.operation ?? null,
      source_file: entry.source_file,
      source_line: entry.source_anchor.line,
      source_anchor_sha256: entry.source_anchor.sha256,
      calls: entry.handler_call_sequence,
    })),
  });
  return {
    rule:
      "A new production route registry, RPC registry, service implementation, listener source, active JavaScript effect source, or JavaScript filesystem/process action fails before its entries can be consumed.",
    groups,
  };
}

const SELECTED_OBJECT_OWNERS = [
  {
    object_set: "System package, release, genesis, constitution, deployment, membership, and lifecycle",
    owner: "Governed autonomous systems",
    owner_doc: "docs/architecture/foundations/governed-autonomous-systems.md",
  },
  {
    object_set: "GoalRunProfile, GoalRun, GoalGroundingLoop, ContextCell, and handoff",
    owner: "Goal Kernel common objects",
    owner_doc: "docs/architecture/foundations/common-objects-and-envelopes.md",
  },
  {
    object_set: "OutcomeRoom, participation, frontier, claim, attempt, finding, challenge, WorkResult, and OutcomeDelta",
    owner: "OutcomeRoom collaborative outcome pattern",
    owner_doc: "docs/architecture/domains/ioi-ai/collaborative-outcome-pattern.md",
  },
  {
    object_set: "Worker topology, harness invocation, scoped tools, model routes, and selected repository effect",
    owner: "Hypervisor Daemon/Core",
    owner_doc: "docs/architecture/components/daemon-runtime/api.md",
  },
  {
    object_set: "Deployment-local identity, product access, account and entitlement boundaries, and metering posture",
    owner: "Hypervisor identity, access, and metering",
    owner_doc: "docs/architecture/components/hypervisor/identity-access-and-metering.md",
  },
  {
    object_set: "Deployment-local policy and locally permitted exact-effect authority provider selection",
    owner: "Local/domain governance and the selected authority provider",
    owner_doc: "docs/architecture/foundations/invariants.md",
  },
  {
    object_set: "Connected product-session binding, portable approval and grant, revocation, and step-up",
    owner: "wallet.network authority",
    owner_doc: "docs/architecture/components/wallet-network/api-authority-scopes.md",
  },
  {
    object_set: "Operation, exact head/root, receipt, replay, checkpoint, artifact lineage, and export",
    owner: "Agentgres",
    owner_doc: "docs/architecture/components/agentgres/api-object-model.md",
  },
  {
    object_set: "Provider route and isolated work environment",
    owner: "Hypervisor providers and environments",
    owner_doc: "docs/architecture/components/hypervisor/providers-and-environments.md",
  },
  {
    object_set: "Proposal-mediated improvement, target approval, activation, rollback, recall, and suspension",
    owner: "Improvement governance",
    owner_doc: "docs/architecture/components/daemon-runtime/improvement-governance-gates.md",
  },
  {
    object_set: "Learning eligibility, source rights, route rights, export, and revocation impact",
    owner: "Institutional learning boundary",
    owner_doc: "docs/architecture/foundations/institutional-learning-boundary.md",
  },
  {
    object_set: "Visible product projections and unavailable/degraded/completed states",
    owner: "Hypervisor core clients and surfaces",
    owner_doc: "docs/architecture/components/hypervisor/core-clients-surfaces.md",
  },
];

function selectedLaneBindingsForStep(step) {
  return REQUIRED_PROOF_LANE_BINDINGS
    .filter((binding) => binding.step === step)
    .map((binding) => ({
      binding_id: binding.binding_id,
      blocker_ref: binding.blocker_ref,
      lane_id: binding.lane_id,
      route_identities: [...binding.route_identities],
    }));
}

const SELECTED_JOURNEY = [
  {
    step: 1,
    visible_action: "Authenticate through deployment-local identity with every IOI-managed endpoint denied; in the ordered managed overlay, begin from the same independently operable System, link an eligible provider-neutral account, and explicitly enable one named managed service.",
    route_identities: [
      "http:hypervisor-daemon:POST /v1/hypervisor/auth/login",
      "http:hypervisor-daemon:GET /v1/hypervisor/auth/whoami",
    ],
    state: "unavailable",
    blocker_ref: "BLK-M0-SELECTED-LOCAL-IDENTITY-AUTHORITY",
    lane_bindings: selectedLaneBindingsForStep(1),
  },
  {
    step: 2,
    visible_action: "Choose the bounded software-change template.",
    route_identities: [],
    state: "unavailable",
    blocker_ref: "BLK-M0-SELECTED-PACKAGE-GENESIS",
  },
  {
    step: 3,
    visible_action: "Describe the goal, repository, constraints, authority, and acceptance.",
    route_identities: [
      "http:hypervisor-daemon:POST /v1/hypervisor/goal-runs",
    ],
    state: "unavailable",
    blocker_ref: "BLK-M0-SELECTED-JOURNEY-BINDING",
  },
  {
    step: 4,
    visible_action: "Validate, preview, and simulate one compiled package/genesis proposal.",
    route_identities: [],
    state: "unavailable",
    blocker_ref: "BLK-M0-SELECTED-PACKAGE-GENESIS",
  },
  {
    step: 5,
    visible_action: "Approve genesis and inspect the stable System.",
    route_identities: [],
    state: "unavailable",
    blocker_ref: "BLK-M0-SELECTED-PACKAGE-GENESIS",
  },
  {
    step: 6,
    visible_action: "Start or admit the GoalRun in its OutcomeRoom-backed work context.",
    route_identities: [
      "http:hypervisor-daemon:POST /v1/hypervisor/outcome-rooms",
      "http:hypervisor-daemon:POST /v1/hypervisor/outcome-rooms/:id/attach-goal-run",
      "http:hypervisor-daemon:POST /v1/hypervisor/goal-runs/:id/start",
    ],
    state: "unavailable",
    blocker_ref: "BLK-M0-SELECTED-JOURNEY-BINDING",
  },
  {
    step: 7,
    visible_action: "Observe planning, claimed work, attempts, verification, and blockers.",
    route_identities: [
      "http:hypervisor-daemon:GET /v1/hypervisor/outcome-rooms/:id",
      "http:hypervisor-daemon:POST /v1/hypervisor/work-frontier-items",
      "http:hypervisor-daemon:POST /v1/hypervisor/work-claim-leases",
      "http:hypervisor-daemon:POST /v1/hypervisor/attempts",
      "http:hypervisor-daemon:POST /v1/hypervisor/work-results",
    ],
    state: "unavailable",
    blocker_ref: "BLK-M0-SELECTED-JOURNEY-BINDING",
  },
  {
    step: 8,
    visible_action: "Review the exact proposed repository effect.",
    route_identities: [
      "http:hypervisor-daemon:POST /v1/threads/:id/workspace-change-reviews/detect",
      "http:hypervisor-daemon:POST /v1/threads/:id/workspace-change-reviews/control",
    ],
    state: "unavailable",
    blocker_ref: "BLK-M0-SELECTED-JOURNEY-BINDING",
  },
  {
    step: 9,
    visible_action: "Satisfy the lane's exact scoped authority ceremony: locally permitted nonportable authority in the sovereign-local lane, and context-bound portable authority with passkey step-up only when connected policy requires it.",
    route_identities: [
      "http:hypervisor-daemon:POST /v1/hypervisor/authority/preflight",
    ],
    state: "unavailable",
    blocker_ref: "BLK-M0-SELECTED-LOCAL-IDENTITY-AUTHORITY",
    lane_bindings: selectedLaneBindingsForStep(9),
  },
  {
    step: 10,
    visible_action: "Let the daemon revalidate and execute or refuse the exact effect.",
    route_identities: [
      "http:hypervisor-daemon:POST /v1/hypervisor/authority/preflight",
      "http:hypervisor-daemon:POST /v1/threads/:id/tools/:name/invoke",
    ],
    state: "unavailable",
    blocker_ref: "BLK-M0-SELECTED-REPO-EFFECT",
  },
  {
    step: 11,
    visible_action: "Inspect the diff, tests, evidence admission, receipt chain, state root, costs, provider route, and learning eligibility; in the managed overlay also inspect the named service's exact bindings, data views, leases, RuntimeAssignment, custody, usage, charges, and receipts.",
    route_identities: [
      "http:hypervisor-daemon:GET /v1/runs/:id/inspect",
      "http:hypervisor-daemon:GET /v1/hypervisor/authority/receipts",
    ],
    state: "unavailable",
    blocker_ref: "BLK-M0-SELECTED-INSPECTION-CHAIN",
  },
  {
    step: 12,
    visible_action: "Restart and replay the decision and effect; back up, restore, export, and independently verify the evidence offline.",
    route_identities: [
      "http:hypervisor-daemon:GET /v1/runs/:id/replay",
      "http:hypervisor-daemon:POST /v1/hypervisor/backups",
      "http:hypervisor-daemon:POST /v1/hypervisor/snapshots/:id/restore",
      "http:hypervisor-daemon:POST /v1/threads/:id/snapshots/:snapshot_id/restore-preview",
      "http:hypervisor-daemon:POST /v1/threads/:id/snapshots/:snapshot_id/restore-apply",
    ],
    state: "unavailable",
    blocker_ref: "BLK-M0-SELECTED-BACKUP-RESTORE",
  },
  {
    step: 13,
    visible_action: "In the managed overlay, revoke or disconnect the named service and prove locally satisfiable continuation; in both lanes, propose an upgrade, exercise rollback or recall, and retire the System.",
    route_identities: [],
    state: "unavailable",
    blocker_ref: "BLK-M0-SELECTED-UPGRADE-LIFECYCLE",
    lane_bindings: selectedLaneBindingsForStep(13),
  },
];

function normalizeSelectedJourney(journey) {
  if (!Array.isArray(journey)) return [];
  return journey.map((step) => ({
    ...step,
    route_identities: [...(step.route_identities ?? [])].sort(),
    lane_bindings: [...(step.lane_bindings ?? [])]
      .map((binding) => ({
        ...binding,
        route_identities: [...(binding.route_identities ?? [])].sort(),
      }))
      .sort((left, right) => left.binding_id.localeCompare(right.binding_id)),
  }));
}

function selectedJourneyMatchesCanonical(journey) {
  return stableStringify(normalizeSelectedJourney(journey))
    === stableStringify(normalizeSelectedJourney(SELECTED_JOURNEY));
}

const PG_DISPOSITION_GROUPS = {
  required_now: [
    "PG-0.2",
    "PG-1.1", "PG-1.2",
    "PG-2.2", "PG-2.3", "PG-2.4",
    "PG-3.1", "PG-3.5", "PG-3.6",
    "PG-4A.5",
    "PG-4B.1", "PG-4B.2", "PG-4B.3", "PG-4B.4", "PG-4B.5",
    "PG-7.1", "PG-7.2", "PG-7.3", "PG-7.4", "PG-7.7", "PG-7.8",
  ],
  conditional: [
    "PG-0.1", "PG-0.3", "PG-1.3", "PG-2.1", "PG-2.6",
    "PG-3.2", "PG-3.3", "PG-3.4", "PG-4B.6",
    "PG-6A.1", "PG-6A.4",
    "PG-6C.1", "PG-6C.2", "PG-6C.3",
    "PG-7.5", "PG-7.6",
  ],
  later: [
    "PG-2.5",
    "PG-4A.1", "PG-4A.2", "PG-4A.3", "PG-4A.4", "PG-4A.6",
  ],
  out_of_scope: [
    "PG-5.1", "PG-5.2", "PG-5.3", "PG-5.4", "PG-5.5",
    "PG-6A.2", "PG-6A.3",
    "PG-6B.1", "PG-6B.2", "PG-6B.3", "PG-6B.4", "PG-6B.5",
    "PG-6D.1", "PG-6D.2", "PG-6D.3",
  ],
};

function pgTopic(id) {
  if (id.startsWith("PG-0.")) return "program-integrity and selected upgrade";
  if (id.startsWith("PG-1.")) return "registered contract and compatibility";
  if (id.startsWith("PG-2.")) return "portable authority and receipt proof";
  if (id.startsWith("PG-3.")) return "information-flow and destination control";
  if (id.startsWith("PG-4A.")) return "multi-node continuity and writer fencing";
  if (id.startsWith("PG-4B.")) return "shared lifecycle and recovery";
  if (id.startsWith("PG-5.")) return "live physical action";
  if (id.startsWith("PG-6A.")) return "commercial accounting and settlement";
  if (id.startsWith("PG-6B.")) return "dispute, bond, and settlement";
  if (id.startsWith("PG-6C.")) return "hardware attestation";
  if (id.startsWith("PG-6D.")) return "legal-regulatory effect";
  return "production operability";
}

function pgRationale(id, disposition) {
  const overrides = {
    "PG-2.1":
      "Portable delegated authority is required only for the managed-optionality overlay. The sovereign-local lane uses locally permitted nonportable authority and makes no portable-authority claim.",
    "PG-2.2":
      "Every selected consequential local or managed policy-enforcement point must verify its lane's current authority before the final invocation; copied authority fields are insufficient.",
    "PG-2.3":
      "The selected sovereign-local journey requires ordinary and consequential receipts through Agentgres-owned append, scheduled checkpoints, and crash-safe inclusion and consistency evidence.",
    "PG-2.4":
      "The selected local export must verify offline integrity and valid-as-of posture from declared signer, key, revocation, and temporal inputs without confusing authentic historical proof with current authority.",
  };
  if (overrides[id]) return overrides[id];
  const topic = pgTopic(id);
  if (disposition === "required_now") {
    return `The selected single-node software-change profile directly needs ${topic}; the gate remains open.`;
  }
  if (disposition === "conditional") {
    return `The selected profile does not activate every ${topic} posture; this gate blocks if its named posture is selected.`;
  }
  if (disposition === "later") {
    return `${topic} belongs to a later horizon than the selected single-node proof.`;
  }
  return `The selected profile expressly excludes ${topic}; a separately selected profile and authority are required.`;
}

function createPgMap() {
  const evidenceRef = {
    required_now: "BLK-M0-PG-REQUIRED-NOT-CLOSED",
    conditional: "COND-M0-PG-SELECTION",
    later: "NONCLAIM-M0-LATER-HORIZON",
    out_of_scope: "NONCLAIM-M0-SELECTED-PROFILE",
  };
  const dispositionById = new Map();
  for (const [disposition, ids] of Object.entries(PG_DISPOSITION_GROUPS)) {
    for (const id of ids) {
      if (dispositionById.has(id)) {
        throw new Error(`duplicate PG disposition source entry: ${id}`);
      }
      dispositionById.set(id, disposition);
    }
  }
  return PG_IDS.map((id) => {
    const disposition = dispositionById.get(id);
    if (disposition === undefined) {
      throw new Error(`missing PG disposition source entry: ${id}`);
    }
    return {
      pg_id: id,
      disposition,
      selected_profile_rationale: pgRationale(id, disposition),
      evidence_or_blocker_ref: evidenceRef[disposition],
      closure_claimed: false,
    };
  });
}

const RELEASE_LADDER = [
  {
    level: "P0",
    name: "walking skeleton",
    criterion: "One fixture traverses selected owner boundaries; it is not production-ready.",
    stage_binding: "M3-M5",
  },
  {
    level: "P1",
    name: "internal product proof",
    criterion: "The terminal M9 journey works with adversarial evidence in an IOI-controlled environment.",
    stage_binding: "M9",
  },
  {
    level: "P2",
    name: "external design-partner proof",
    criterion: "Independent users complete the journey on their data with disclosed support and limits.",
    stage_binding: "M9 external overlay",
  },
  {
    level: "P3",
    name: "production-integrated profile",
    criterion: "Applicable required-now and selected conditional gates close and recovery thresholds pass.",
    stage_binding: "M9 plus PG gates",
  },
  {
    level: "P4",
    name: "distributed L0 proof",
    criterion: "One logical System preserves continuity and performs useful work across admitted nodes.",
    stage_binding: "M10-M11",
  },
  {
    level: "P5",
    name: "sovereign cooperation proof",
    criterion: "Independently governed Systems demonstrate useful positive-surplus work and portable exit.",
    stage_binding: "M13",
  },
  {
    level: "P6",
    name: "embodied deployment proof",
    criterion: "A selected live hardware profile passes its physical-action, runtime, and production gates.",
    stage_binding: "M11 live overlay",
  },
  {
    level: "P7",
    name: "public network demand proof",
    criterion: "Connected and secured services show recurring external demand and sustainable security economics.",
    stage_binding: "M14",
  },
];

const BASELINES = [
  {
    baseline_id: "BASE-M0-PRODUCT",
    category: "product",
    status: "not_measured",
    frozen_as_of: M0_BASELINE_AS_OF_DATE,
    observed_as_of: null,
    cohort: "At least five first-time internal operators using only supported selected-profile product surfaces.",
    method: "Timestamp first eligible sign-in, first valid preview, genesis approval, effect review, terminal inspection, and replay; retain typed blockers.",
    frozen_threshold: {
      unaided_terminal_completion_rate_min: 0.8,
      median_time_to_first_valid_preview_minutes_max: 10,
      median_time_to_genesis_minutes_max: 20,
    },
    observed_value: null,
    absence_evidence: "No qualifying end-to-end selected-profile product cohort exists as of the baseline date.",
    blocker_ref: "BLK-M0-BASELINE-PRODUCT",
  },
  {
    baseline_id: "BASE-M0-RELIABILITY",
    category: "reliability",
    status: "not_measured",
    frozen_as_of: M0_BASELINE_AS_OF_DATE,
    observed_as_of: null,
    cohort: "Thirty selected-profile runs, including at least ten declared crash, restart, stale-authority, or ambiguous-effect injections.",
    method: "Replay owner records and exported evidence; independently reproduce verification and score every terminal, refused, recovered, or ambiguous effect.",
    frozen_threshold: {
      authorized_completion_rate_min: 0.95,
      effect_recovery_success_rate_min: 1,
      receipt_and_replay_completeness_min: 1,
      verifier_reproducibility_min: 1,
    },
    observed_value: null,
    absence_evidence: "No terminal selected-profile runtime and fault cohort exists as of the baseline date.",
    blocker_ref: "BLK-M0-BASELINE-RELIABILITY",
  },
  {
    baseline_id: "BASE-M0-COST",
    category: "cost",
    status: "not_measured",
    frozen_as_of: M0_BASELINE_AS_OF_DATE,
    observed_as_of: null,
    cohort: "Thirty successful selected-profile runs with route-attempt, tool, runtime, storage, and supplier-attributable measurements.",
    method: "Reconcile measured internal cost to each accepted run; report p50, p90, fallback amplification, and unattributed cost without treating accounting as cash movement.",
    frozen_threshold: {
      p50_internal_cost_usd_max: 5,
      p90_internal_cost_usd_max: 15,
      unattributed_cost_fraction_max: 0,
    },
    observed_value: null,
    absence_evidence: "No invoice-reconciled selected-profile run cohort exists as of the baseline date.",
    blocker_ref: "BLK-M0-BASELINE-COST",
  },
  {
    baseline_id: "BASE-M0-COMPREHENSION",
    category: "comprehension",
    status: "not_measured",
    frozen_as_of: M0_BASELINE_AS_OF_DATE,
    observed_as_of: null,
    cohort: "At least five first-time internal operators with no implementation-guide access during the selected journey.",
    method: "Record exposed architecture terms, correct blocker interpretation, unsupported-success attempts, and a post-task comprehension check.",
    frozen_threshold: {
      median_exposed_architecture_terms_max: 8,
      correct_blocker_interpretation_rate_min: 0.9,
      fabricated_success_acceptance_rate_max: 0,
    },
    observed_value: null,
    absence_evidence: "No qualifying first-time-operator comprehension cohort exists as of the baseline date.",
    blocker_ref: "BLK-M0-BASELINE-COMPREHENSION",
  },
];

const REPOSITORY_VALIDATION_BASELINES = [
  {
    baseline_id: "BASE-M0-REPOSITORY-RUSTFMT",
    observed_as_of: M0_BASELINE_AS_OF_DATE,
    command: "cargo fmt --all -- --check",
    status: "existing_failure",
    exit_code: 1,
    tool_version: "rustfmt 1.8.0-stable (01f6ddf758 2026-02-11)",
    reported_file_count: 54,
    reported_diff_hunk_count: 2002,
    raw_output_sha256:
      "27269428c23ccc63ed629b6e6fa9aac7c70cc9d72f7fd3152549e95362032715",
    worktree_mutated: false,
    nonclaim:
      "This records repository-wide pre-existing formatting debt; M0 changes no Rust source and claims no Rustfmt closure.",
    reported_paths: [
      "crates/agentgres/src/bin/bench.rs",
      "crates/agentgres/src/bin/parity.rs",
      "crates/agentgres/src/bin/replica.rs",
      "crates/agentgres/src/bin/shadow.rs",
      "crates/agentgres/src/lib.rs",
      "crates/agentgres/src/mux.rs",
      "crates/agentgres/src/replica.rs",
      "crates/node/src/bin/hypervisor-daemon.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/akash_candidate_source.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/aws_candidate_source.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/azure_candidate_source.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/capability_lease_plan_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/connector_execution_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/connector_mapping_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/connector_session_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/data_source_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/decentralized_cloud_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/domain_apps_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/editor_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/environment_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/eval_suite_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/feedback_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/foundry_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/gcp_candidate_source.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/goalrun_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/governance_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/harness_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/ioi_agent_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/ioi_intelligence_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/k8s_candidate_source.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/lambda_candidate_source.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/lifecycle_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/marketplace_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/materializing_run_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/model_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/odk_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/ontology_projection_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/orchestration_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/outcome_room_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/placement_failover_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/policy_bound_data_view_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/provider_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/room_participation_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/runpod_candidate_source.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/state_machine_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/storage_backend_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/substrate_store.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/transformation_run_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/vast_candidate_source.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/work_frontier_claim_routes.rs",
      "crates/node/src/bin/hypervisor_daemon_routes/work_result_routes.rs",
      "crates/services/src/agentic/runtime/kernel/runtime_goal_run_admission.rs",
      "crates/services/src/agentic/runtime/kernel/runtime_harness_profile_mutation_admission.rs",
      "crates/services/src/agentic/runtime/kernel/runtime_hypervisor_project_create.rs",
    ],
  },
];

const BLOCKERS = [
  {
    blocker_id: "BLK-M0-SELECTED-PACKAGE-GENESIS",
    type: "owner_contract_unavailable",
    state: "open",
    summary: "The selected package-to-genesis System journey has no terminal live owner path.",
  },
  {
    blocker_id: "BLK-M0-SELECTED-JOURNEY-BINDING",
    type: "cross_owner_binding_unavailable",
    state: "open",
    summary: "Live partial objects are not bound into the selected immutable profile, complete network-blocked local journey, and conditional attach, use, inspect, detach, and continuation overlay.",
  },
  {
    blocker_id: "BLK-M0-SELECTED-LOCAL-IDENTITY-AUTHORITY",
    type: "local_authority_path_unavailable",
    state: "open",
    summary: "Deployment-local authentication and locally permitted exact-effect authority remain separate in canon but are not terminal through the selected product and final-invoker path.",
  },
  {
    blocker_id: "BLK-M0-SELECTED-IDENTITY-STEP-UP",
    type: "authority_path_unavailable",
    state: "open",
    summary: "The optional connected provider-neutral sign-in, passkey step-up, context-bound portable grant, and final-invoker revalidation path is not terminal.",
  },
  {
    blocker_id: "BLK-M0-SELECTED-REPO-EFFECT",
    type: "selected_effect_unavailable",
    state: "open",
    summary: "The file.apply_patch leaf exists, but selected GoalRun, authority, revocation, IFC, fence, receipt, and recovery ordering do not.",
  },
  {
    blocker_id: "BLK-M0-SELECTED-INSPECTION-CHAIN",
    type: "evidence_chain_unavailable",
    state: "open",
    summary: "No one selected inspection/export reconstructs diff, tests, evidence, receipts, root, costs, route, learning eligibility, restart, backup, restore, offline verification, and managed binding, data-view, lease, custody, usage, and charge evidence.",
  },
  {
    blocker_id: "BLK-M0-SELECTED-BACKUP-RESTORE",
    type: "backup_restore_proof_unavailable",
    state: "open",
    summary: "Backup, restore preview, restore application, clean-target reconstruction, and offline verification exist only as adjacent routes; they are not bound into one selected-profile proof with authority, currentness, checkpoint equivalence, valid successor-root lineage, and typed refusal evidence.",
  },
  {
    blocker_id: "BLK-M0-SELECTED-MANAGED-ATTACH-USE",
    type: "managed_service_use_proof_unavailable",
    state: "open",
    summary: "The optional managed overlay has no one selected route set that explicitly attaches a named service, admits one use, and reconstructs its binding, data-view, lease, RuntimeAssignment, custody, usage, charge, and receipt evidence.",
  },
  {
    blocker_id: "BLK-M0-SELECTED-MANAGED-DETACH",
    type: "managed_detach_continuity_unavailable",
    state: "open",
    summary: "The optional managed overlay has no one selected revoke or detach path proving that locally satisfied dependencies continue without hidden managed authority, custody, execution, or billing.",
  },
  {
    blocker_id: "BLK-M0-SELECTED-UPGRADE-LIFECYCLE",
    type: "system_lifecycle_unavailable",
    state: "open",
    summary: "Managed revoke or detach with post-detach continuation and selected package/profile proposal, activation, rollback or recall, and System retirement are not terminal.",
  },
  {
    blocker_id: "BLK-M0-WALLET-PRODUCTION-PEP",
    type: "production_pep_unavailable",
    state: "open",
    summary: "wallet.network method checks include legacy compatibility and are not estate-wide production PEP closure.",
  },
  {
    blocker_id: "BLK-M0-BLOCKCHAIN-SERVICE-EFFECT-PROOF",
    type: "final_invoker_order_unproven",
    state: "open",
    summary: "Native blockchain methods are inventoried, but generic authority, final-leaf ordering, receipts, and recovery remain method-specific and partial.",
  },
  {
    blocker_id: "BLK-M0-AGENTGRES-REPLICA-AUTHORITY",
    type: "transport_authority_unavailable",
    state: "open",
    summary: "Replica writer-epoch fencing is real, but the externally reachable AGRS2 listener has no authenticated peer authority, effect policy, revocation, or IFC gate.",
  },
  {
    blocker_id: "BLK-M0-GOOGLE-OAUTH-CALLBACK-PROOF",
    type: "external_secret_effect_proof_partial",
    state: "open",
    summary: "OAuth state and PKCE checks precede local token persistence, but owner authority, hardened secret evidence, idempotency, and recovery are not terminal.",
  },
  {
    blocker_id: "BLK-M0-EDITOR-PROXY-DOWNSTREAM",
    type: "dynamic_downstream_effect_unclassified",
    state: "open",
    summary: "The editor proxy gates new connections with an active lease but cannot classify, fence, receipt, or recover arbitrary forwarded byte effects.",
  },
  {
    blocker_id: "BLK-M0-FINAL-INVOKER-PROOF",
    type: "final_invoker_order_unproven",
    state: "open",
    summary: "A static candidate or handler boundary is recorded without a terminal pre-effect order proof.",
  },
  {
    blocker_id: "BLK-M0-UNMOUNTED-SURFACE",
    type: "unavailable_contract",
    state: "open",
    summary: "The declared surface is unmounted, dynamic, or otherwise unavailable.",
  },
  {
    blocker_id: "BLK-M0-COMPATIBILITY-NONAUTHORITY",
    type: "compatibility_nonclaim",
    state: "open",
    summary: "Development replay and compatibility behavior cannot supply owner truth or authority.",
  },
  {
    blocker_id: "NONCLAIM-M0-JAVASCRIPT-FACADE",
    type: "nonclaim",
    state: "retained",
    summary: "JavaScript application and adapter crossings are protocol clients, never authority or durable owner truth.",
  },
  {
    blocker_id: "NONCLAIM-M0-INTERNAL-IPC",
    type: "nonclaim",
    state: "retained",
    summary: "Mounted workload IPC is internal transport and does not become a public capability claim.",
  },
  {
    blocker_id: "BLK-M0-PG-REQUIRED-NOT-CLOSED",
    type: "production_gate_open",
    state: "open",
    summary: "Every required-now PG gate remains owned and open in the production-gate ledger.",
  },
  {
    blocker_id: "COND-M0-PG-SELECTION",
    type: "conditional_gate",
    state: "retained",
    summary: "The gate becomes blocking only when its named conditional posture is selected.",
  },
  {
    blocker_id: "NONCLAIM-M0-LATER-HORIZON",
    type: "nonclaim",
    state: "retained",
    summary: "The gate belongs to a later horizon and is not closed by M0.",
  },
  {
    blocker_id: "NONCLAIM-M0-SELECTED-PROFILE",
    type: "nonclaim",
    state: "retained",
    summary: "The selected profile excludes this deployment, commercial, legal, or physical posture.",
  },
  ...BASELINES.map((baseline) => ({
    blocker_id: baseline.blocker_ref,
    type: "baseline_not_measured",
    state: "open",
    summary: baseline.absence_evidence,
  })),
];

function blockerLedgerMatchesCanonical(blockers) {
  if (!Array.isArray(blockers) || blockers.length !== BLOCKERS.length) {
    return false;
  }
  const normalize = (entries) => [...entries]
    .sort((left, right) => left.blocker_id.localeCompare(right.blocker_id));
  return stableStringify(normalize(blockers))
    === stableStringify(normalize(BLOCKERS));
}

export function createInitialProgramSource(repoRoot) {
  const canonBasis = CANON_BASIS_FILES.map((relativePath) => {
    const { source } = readRepoFile(repoRoot, relativePath);
    return {
      source_file: relativePath,
      source_sha256: sha256(source),
      role: "landed owner canon",
    };
  });
  return {
    evidence_format: "ioi.m0.program_control_source.v1",
    as_of_date: null,
    program_state: "worksheet_unreviewed",
    review_attestation: null,
    canon_basis: canonBasis,
    canon_contradictions: [],
    sequencing_authority: createSequencingAuthority(),
    discovery_source_coverage: createDiscoverySourceCoverage(repoRoot),
    selected_profile: {
      profile_id: "selected-minimum-l0-outcome-room-bounded-software-change",
      source: "docs/architecture/_meta/execution-horizons.md#selected-minimum-l0-proof-profile",
      level: "minimum selected L0 proof profile; not a MinimumL0 object",
      topology: {
        nodes: 1,
        writers: 1,
        failure_domains: 1,
        ordering_finality: "single_authority",
      },
      exact_effect: {
        effect: "Apply or refuse one sandboxed repository software change.",
        route_identity: "http:hypervisor-daemon:POST /v1/threads/:id/tools/:name/invoke",
        selected_subdispatch: "file.apply_patch",
        final_invoker_symbol: "coding_tool_workspace::apply_workspace_patch",
        implementation_state: "unavailable",
        blocker_ref: "BLK-M0-SELECTED-REPO-EFFECT",
      },
      included: [
        "one immutable package and release through genesis into one stable System",
        "one immutable GoalRunProfile and durable GoalRun in an OutcomeRoom",
        "disclosed first-party worker roles plus an independent deterministic verifier",
        "one isolated sandbox repository and branch",
        "deployment-local identity and a low-risk local product session with locally permitted authority, plus an optional provider-neutral connected overlay with passkey-capable portable authority",
        "exact authority, revocation, IFC, budget, fence, idempotency, recovery, and receipt checks",
        "Agentgres operations, heads, roots, receipts, restart, replay, backup, restore, evidence admission, export, and offline verification",
        "private evaluation and model routes with measured internal cost only",
        "proposal-mediated improvement with target-owner activation, rollback or recall, suspension, and retirement",
      ],
      nonclaims: [
        "no multiple runtime nodes, automatic failover, or cross-system AIIP",
        "no public marketplace, payment, payout, settlement, IOI Network, IOI L1, or native asset",
        "no physical actuation, cTEE claim, public certification, or generalized recursive improvement",
        "no autonomous production access, universal correctness, universal factual truth, or hidden provider non-learning",
        "minimum L0 proves only the sovereign-local lane; managed optionality remains unclaimed until its ordered connected overlay passes",
        "no architecture or production capability closes merely because M0 program control verifies",
      ],
      object_owners: SELECTED_OBJECT_OWNERS,
      proof_lanes: REQUIRED_PROOF_LANES,
      proof_lane_validation_posture: REQUIRED_PROOF_LANE_VALIDATION_POSTURE,
      proof_lane_baseline_extension: {
        baseline_extension_id:
          "BASE-M0-SOVEREIGN-LOCAL-MANAGED-OPTIONALITY",
        blocker_refs: [
          "BLK-M0-BASELINE-PRODUCT",
          "BLK-M0-BASELINE-RELIABILITY",
          "BLK-M0-BASELINE-COST",
          "BLK-M0-BASELINE-COMPREHENSION",
        ],
        cohort:
          "Fresh standalone deployments complete the sovereign-local lane with every IOI-managed endpoint denied; the same Systems enter the connected lane only for managed-optionality claims.",
        frozen_as_of: AS_OF_DATE,
        measurements: {
          comprehension: {
            correct_connect_use_transfer_distinction_rate_min: 0.9,
            correct_local_identity_vs_machine_authority_interpretation_rate_min:
              0.9,
            correct_managed_dependency_unavailable_interpretation_rate_min: 0.9,
          },
          cost: {
            implicit_or_unnamed_managed_charge_count_max: 0,
            managed_charge_without_quote_and_use_receipts_count_max: 0,
          },
          product: {
            managed_attach_named_use_inspect_detach_completion_rate_min_when_claimed:
              0.9,
            network_blocked_terminal_journey_completion_rate_min: 0.9,
            offline_export_and_independent_verification_rate_min: 0.9,
            post_detach_local_continuation_rate_min_when_claimed: 0.9,
          },
          reliability: {
            authentic_stale_restore_authority_reactivation_count_max: 0,
            backup_clean_restore_checkpoint_equivalence_rate_min: 1,
            post_detach_hidden_managed_dependency_count_max_when_claimed: 0,
            restart_replay_duplicate_effect_count_max: 0,
          },
        },
        rule:
          "Additive proof-lane target overlay only; it does not rewrite the frozen 2026-07-18 M0 baselines.",
        status: "not_measured",
      },
      visible_terminal_journey: SELECTED_JOURNEY,
      rollback_stop_rules: [
        "Stop on any hidden database edit, privileged one-off script, copied bearer authority, prompt-only transition, fabricated success, or manually reconstructed evidence chain.",
        "An unavailable owner step remains a typed blocker; compatibility output never substitutes for it.",
        "Revoke or fence authority before recovery, preserve ambiguous effects, and require explicit reconciliation before retry.",
        "Stop on any silent truth, authority, custody, writer, execution, or billing transfer, or when detachment breaks work whose complete dependency closure remains locally satisfied.",
      ],
    },
    pg_gate_map: {
      ...createPgGateMetadata(),
      closure_claimed: false,
      entries: createPgMap(),
    },
    baselines: BASELINES,
    repository_validation_baselines: REPOSITORY_VALIDATION_BASELINES,
    release_ladder: RELEASE_LADDER,
    blocker_ledger: BLOCKERS,
    bounded_discovery_exclusions: [
      sourceLock(
        repoRoot,
        "crates/node/src/bin/hypervisor_daemon_routes/editor_proxy.rs",
        "Dynamic raw bytes cannot be enumerated; the lease-gated wildcard proxy entry is censused and this implementation is file-locked.",
      ),
      sourceLock(
        repoRoot,
        "crates/validator/src/common/guardian/server.rs",
        "Encrypted dynamic frames cannot be enumerated here; the internal wildcard channel entry and typed public/workload RPC registries are censused.",
      ),
      sourceLock(
        repoRoot,
        "apps/hypervisor/product-ui/owned/public/static/assets/main-DLKYFe1Y.js",
        "Harvested/generated compatibility bundle; active owned adapter and outbound crossings are censused instead of treating bundle code as authority.",
      ),
      sourceLock(
        repoRoot,
        "apps/hypervisor/scripts/serve-product-ui.mjs",
        "Dynamic inbound compatibility dispatch and augmentation loading are file-locked while every statically visible outbound crossing is enumerated.",
      ),
      sourceLock(
        repoRoot,
        "apps/hypervisor/product-ui/server.cjs",
        "The spawned reference server has dynamic fixture, missing-chunk, and static-file fallbacks; its single ANY compatibility boundary is censused and the whole dispatch is file-locked.",
      ),
      ...listFiles(
        repoRoot,
        "apps/hypervisor/scripts/augmentation",
        ".js",
      ).map((relativePath) => sourceLock(
        repoRoot,
        relativePath,
        "This active module is dynamically concatenated by serve-product-ui; its literal outbound crossings are censused and the full module is locked against undiscovered dynamic dispatch.",
      )),
      sourceLock(
        repoRoot,
        "crates/node/src/bin/hypervisor_daemon_routes/ioi_intelligence_routes.rs",
        "Twelve CRUD handlers are generated by the family_handlers macro; each literal daemon route and generated symbol is enumerated and the macro source is file-locked.",
      ),
      sourceLock(
        repoRoot,
        "crates/execution/src/runtime_service/mod.rs",
        "Manifest-defined WASM methods are intrinsically dynamic; the validated wildcard boundary is explicit in the census.",
      ),
    ],
    m0_exit_policy: {
      permitted_state: "verified",
      claim_scope: "M0 program control and claim lock only",
      required_conditions: [
        "every discovered entry is explicitly reviewed and source-anchored",
        "every selected object has an owner",
        "every selected effect has a verified final invoker or explicit unavailable blocker",
        "all legacy sequencing is non-authoritative",
        "all 58 PG ids are mapped exactly once without closure claims",
        "every baseline and evidence item is closed or honestly named",
      ],
      architecture_or_production_capability_closure: false,
    },
  };
}

function programSourceReviewMaterial(programSource) {
  const material = structuredClone(programSource ?? {});
  delete material.as_of_date;
  delete material.program_state;
  delete material.review_attestation;
  return material;
}

export function programSourceMaterialSha256(programSource) {
  return sha256(stableStringify(programSourceReviewMaterial(programSource)));
}

export function reviewSnapshotCommitments(
  reviewLock,
  programSource = undefined,
) {
  const epoch = latestReviewEpoch(reviewLock);
  if (epoch === undefined) {
    throw new Error("cannot anchor a review lock without a review epoch");
  }
  const entries = [...(reviewLock?.entries ?? [])]
    .sort((left, right) => left.identity.localeCompare(right.identity));
  return {
    epoch_id: epoch.epoch_id,
    latest_epoch_identity_set_sha256: epoch.identity_set_sha256,
    latest_epoch_reviewed_entry_count: epoch.reviewed_entry_count,
    latest_epoch_reviewed_entry_set_sha256:
      epoch.reviewed_entry_set_sha256,
    program_source_material_sha256: programSource === undefined
      ? undefined
      : programSourceMaterialSha256(programSource),
    review_lock_sha256: sha256(stableStringify(reviewLock)),
    reviewed_as_of: epoch.reviewed_as_of,
    total_reviewed_entry_count: entries.length,
    total_reviewed_entry_set_sha256: reviewedEntrySetSha256(entries),
    total_reviewed_identity_set_sha256:
      reviewIdentitySetSha256(entries.map((entry) => entry.identity)),
  };
}

export function reviewAnchorEntrySha256(entry) {
  return sha256(stableStringify(entry));
}

function latestReviewAnchorEntry(reviewAnchor) {
  return [...(reviewAnchor?.epochs ?? [])]
    .sort((left, right) => left.sequence - right.sequence)
    .at(-1);
}

function hasExactObjectKeys(value, expected) {
  return value !== null
    && typeof value === "object"
    && !Array.isArray(value)
    && stableStringify(Object.keys(value).sort())
      === stableStringify([...expected].sort());
}

function isRfc3339(value) {
  if (typeof value !== "string") {
    return false;
  }
  const parsed = new Date(value);
  return !Number.isNaN(parsed.valueOf())
    && parsed.toISOString() === value;
}

export function validateSuppliedReviewSnapshot(
  reviewLock,
  reviewAnchor,
  programSource = undefined,
  anchorContext = REPOSITORY_ANCHOR_CONTEXT,
) {
  const errors = [];
  const anchorEntries = reviewAnchor?.epochs;
  addError(
    errors,
    hasExactObjectKeys(reviewAnchor, [
      "assurance_posture",
      "chain_policy",
      "epochs",
      "evidence_format",
      "head",
    ]),
    "review anchor has incomplete or unbound top-level fields",
  );
  addError(
    errors,
    reviewAnchor?.evidence_format === "ioi.m0.review_epoch_anchor.v3",
    "review anchor has an unsafe or unknown evidence_format",
  );
  addError(
    errors,
    stableStringify(reviewAnchor?.assurance_posture)
      === stableStringify(SUPPLIED_SNAPSHOT_ASSURANCE_POSTURE),
    "review snapshot does not carry the exact bounded assurance posture",
  );
  addError(
    errors,
    hasExactObjectKeys(reviewAnchor?.chain_policy, [
      "accepted_head_currentness",
      "coherent_snapshot_rollback_resistance",
      "head_binding",
      "historical_validation",
      "monotonicity",
      "predecessor_rule",
      "repository_baseline",
      "signature_authentication",
      "signer_principal_isolation",
    ]),
    "review anchor has an incomplete or extended chain policy",
  );
  addError(
    errors,
    reviewAnchor?.chain_policy?.monotonicity
      === "strict_sequence_and_nondecreasing_review_date_within_supplied_snapshot",
    "review snapshot does not require internally ordered epochs",
  );
  addError(
    errors,
    reviewAnchor?.chain_policy?.predecessor_rule
      === "sha256_of_complete_predecessor_anchor_entry",
    "review anchor does not bind complete predecessor entries",
  );
  addError(
    errors,
    reviewAnchor?.chain_policy?.signature_authentication
      === "none_unsigned_hash_chain",
    "review snapshot must declare unsigned hash-chain authentication and never overclaim a signature ceremony",
  );
  addError(
    errors,
    reviewAnchor?.chain_policy?.historical_validation
      === "retained_claim_and_predecessor_hash_within_supplied_snapshot",
    "review snapshot history is not scoped to supplied retained claims",
  );
  addError(
    errors,
    reviewAnchor?.chain_policy?.head_binding
      === "supplied_snapshot_complete_lock_latest_epoch_and_program_source",
    "review snapshot head does not declare complete supplied-state binding",
  );
  addError(
    errors,
    reviewAnchor?.chain_policy?.signer_principal_isolation
      === "not_established",
    "review snapshot overclaims signer-principal isolation",
  );
  addError(
    errors,
    reviewAnchor?.chain_policy?.accepted_head_currentness
      === "not_established_without_outside_rollback_domain_checkpoint",
    "review snapshot overclaims accepted-head currentness",
  );
  addError(
    errors,
    reviewAnchor?.chain_policy?.coherent_snapshot_rollback_resistance
      === "not_established",
    "review snapshot overclaims coherent-snapshot rollback resistance",
  );
  addError(
    errors,
    stableStringify(reviewAnchor?.chain_policy?.repository_baseline)
      === stableStringify(anchorContext.repository_baseline),
    "review snapshot declares a different repository baseline",
  );
  addError(
    errors,
    Array.isArray(anchorEntries) && anchorEntries.length > 0,
    "review anchor must contain at least one epoch",
  );

  const commitmentEntryKeys = [
    "epoch_id",
    "latest_epoch_identity_set_sha256",
    "latest_epoch_reviewed_entry_count",
    "latest_epoch_reviewed_entry_set_sha256",
    "predecessor_entry_sha256",
    "program_source_material_sha256",
    "review_lock_sha256",
    "reviewed_as_of",
    "reviewer_id",
    "sequence",
    "total_reviewed_entry_count",
    "total_reviewed_entry_set_sha256",
    "total_reviewed_identity_set_sha256",
  ];
  // Retained legacy entries keep their historical signature blocks verbatim so
  // predecessor hashes stay stable; the blocks are immutable retained claims,
  // never re-verified authority.
  const legacyEntryKeys = [...commitmentEntryKeys, "reviewer_evidence", "reviewer_key_id"];
  const unsignedEntryKeys = [...commitmentEntryKeys, "authorship_binding"];
  const legacyEvidenceKeys = [
    "algorithm",
    "evidence_format",
    "evidence_ref",
    "issued_at",
    "public_key_spki_der_base64",
    "signature_base64",
    "signed_payload_sha256",
  ];
  const latestAnchorByEpochId = new Map();
  let predecessor = null;
  let previousReviewDate = null;
  let unsignedEraStarted = false;

  const sortedEntries = [...(anchorEntries ?? [])]
    .sort((left, right) => left.sequence - right.sequence);
  for (const [index, entry] of sortedEntries.entries()) {
    const label = `review anchor sequence ${entry?.sequence ?? "<missing>"}`;
    const isLegacy = entry !== null
      && typeof entry === "object"
      && "reviewer_evidence" in entry;
    addError(
      errors,
      !(isLegacy && unsignedEraStarted),
      `${label} retained legacy claim cannot follow an unsigned entry`,
    );
    if (!isLegacy) {
      unsignedEraStarted = true;
    }
    addError(
      errors,
      hasExactObjectKeys(entry, isLegacy ? legacyEntryKeys : unsignedEntryKeys),
      `${label} has incomplete or unbound fields`,
    );
    addError(
      errors,
      entry?.sequence === index + 1,
      `${label} is not a contiguous monotonic sequence`,
    );
    addError(
      errors,
      isNonEmptyString(entry?.epoch_id),
      `${label} lacks a review-point epoch`,
    );
    const priorSameEpoch = latestAnchorByEpochId.get(entry?.epoch_id);
    const programSourceOnlyContinuation = priorSameEpoch !== undefined
      && !isLegacy
      && [
        "latest_epoch_identity_set_sha256",
        "latest_epoch_reviewed_entry_count",
        "latest_epoch_reviewed_entry_set_sha256",
        "review_lock_sha256",
        "reviewed_as_of",
        "total_reviewed_entry_count",
        "total_reviewed_entry_set_sha256",
        "total_reviewed_identity_set_sha256",
      ].every((field) => entry?.[field] === priorSameEpoch?.[field])
      && entry?.program_source_material_sha256
        !== priorSameEpoch?.program_source_material_sha256;
    addError(
      errors,
      priorSameEpoch === undefined || programSourceOnlyContinuation,
      `${label} may repeat a discovery-review epoch only as an unsigned program-source-only continuation with an unchanged review lock and a changed program-source commitment`,
    );
    latestAnchorByEpochId.set(entry?.epoch_id, entry);
    addError(
      errors,
      Number.isInteger(entry?.total_reviewed_entry_count)
        && entry.total_reviewed_entry_count > 0
        && Number.isInteger(entry?.latest_epoch_reviewed_entry_count)
        && entry.latest_epoch_reviewed_entry_count > 0
        && entry.latest_epoch_reviewed_entry_count
          <= entry.total_reviewed_entry_count,
      `${label} lacks coherent complete-lock and latest-epoch counts`,
    );
    for (const [field, description] of [
      ["review_lock_sha256", "complete review-lock"],
      ["total_reviewed_identity_set_sha256", "total identity-set"],
      ["total_reviewed_entry_set_sha256", "total reviewed-entry-set"],
      ["latest_epoch_identity_set_sha256", "latest-epoch identity-set"],
      ["latest_epoch_reviewed_entry_set_sha256", "latest-epoch entry-set"],
      ["program_source_material_sha256", "program-source material"],
    ]) {
      addError(
        errors,
        /^[0-9a-f]{64}$/u.test(entry?.[field] ?? ""),
        `${label} lacks a ${description} commitment`,
      );
    }
    addError(
      errors,
      isIsoDate(entry?.reviewed_as_of),
      `${label} lacks a valid review date`,
    );
    addError(
      errors,
      isIsoDate(entry?.reviewed_as_of)
        && (
          previousReviewDate === null
          || previousReviewDate <= entry.reviewed_as_of
        ),
      `${label} regresses the review date`,
    );
    previousReviewDate = entry?.reviewed_as_of ?? previousReviewDate;
    const expectedPredecessor = predecessor === null
      ? null
      : reviewAnchorEntrySha256(predecessor);
    addError(
      errors,
      entry?.predecessor_entry_sha256 === expectedPredecessor,
      `${label} does not bind the complete predecessor anchor entry`,
    );
    addError(
      errors,
      isNonEmptyString(entry?.reviewer_id),
      `${label} lacks its self-declared reviewer label`,
    );
    if (isLegacy) {
      const evidence = entry?.reviewer_evidence;
      addError(
        errors,
        isNonEmptyString(entry?.reviewer_key_id),
        `${label} retained legacy claim lacks its historical key id`,
      );
      addError(
        errors,
        hasExactObjectKeys(evidence, legacyEvidenceKeys),
        `${label} has incomplete or extended retained legacy evidence`,
      );
      addError(
        errors,
        evidence?.evidence_format === "ioi.m0.detached_review_signature.v1"
          && evidence?.algorithm === "Ed25519",
        `${label} has unsupported retained legacy evidence`,
      );
      addError(
        errors,
        evidence?.evidence_ref
          === `review-evidence://m0/program-control/${entry?.epoch_id}`,
        `${label} has a mismatched retained evidence ref`,
      );
      addError(
        errors,
        isRfc3339(evidence?.issued_at),
        `${label} lacks a valid retained evidence timestamp`,
      );
      addError(
        errors,
        isNonEmptyString(evidence?.public_key_spki_der_base64)
          && isNonEmptyString(evidence?.signature_base64)
          && /^[0-9a-f]{64}$/u.test(evidence?.signed_payload_sha256 ?? ""),
        `${label} retained legacy claim is structurally incomplete`,
      );
    } else {
      addError(
        errors,
        entry?.authorship_binding === "self_declared_unsigned",
        `${label} must declare unsigned self-declared authorship and never imply a verified signer`,
      );
    }
    predecessor = entry;
  }

  const head = sortedEntries.at(-1);
  const expectedHeadHash = head === undefined
    ? undefined
    : reviewAnchorEntrySha256(head);
  addError(
    errors,
    hasExactObjectKeys(reviewAnchor?.head, [
      "entry_sha256",
      "epoch_id",
      "sequence",
    ])
      && reviewAnchor?.head?.sequence === head?.sequence
      && reviewAnchor?.head?.epoch_id === head?.epoch_id
      && reviewAnchor?.head?.entry_sha256 === expectedHeadHash,
    "review anchor head does not bind the latest complete entry",
  );
  const baselineEntry = sortedEntries.find((entry) => (
    entry.sequence === anchorContext.repository_baseline.sequence
  ));
  addError(
    errors,
    baselineEntry?.epoch_id === anchorContext.repository_baseline.epoch_id
      && reviewAnchorEntrySha256(baselineEntry ?? {})
        === anchorContext.repository_baseline.entry_sha256,
    "review snapshot does not contain the repository baseline anchor",
  );
  addError(
    errors,
    head !== undefined,
    "review snapshot lacks a supplied head entry",
  );
  const snapshotCommitments =
    reviewSnapshotCommitments(reviewLock, programSource);
  for (const [field, expected] of Object.entries(snapshotCommitments)) {
    if (expected === undefined) {
      continue;
    }
    addError(
      errors,
      head?.[field] === expected,
      `review snapshot head does not bind supplied ${field}`,
    );
  }
  validationFailure("M0 unsigned hash-chain supplied snapshot", errors);
  return head;
}

export function validateReviewAnchor(
  reviewLock,
  reviewAnchor,
  programSource = undefined,
) {
  return validateSuppliedReviewSnapshot(
    reviewLock,
    reviewAnchor,
    programSource,
    REPOSITORY_ANCHOR_CONTEXT,
  );
}

function latestReviewEpoch(reviewLock) {
  return [...(reviewLock?.review_attestation?.review_epochs ?? [])]
    .sort((left, right) => (
      left.reviewed_as_of.localeCompare(right.reviewed_as_of)
    ))
    .at(-1);
}

function expectedProgramSourceReviewAttestation(
  programSource,
  reviewLock,
  reviewAnchor,
) {
  const epoch = latestReviewEpoch(reviewLock);
  if (epoch === undefined) {
    throw new Error("cannot attest program source without a review epoch");
  }
  const anchorHead = latestReviewAnchorEntry(reviewAnchor);
  return {
    attestation_format: "ioi.m0.program_control_source_review.v4",
    transition: "worksheet_unreviewed_to_supplied_snapshot_attested",
    verification_scope: "supplied_repository_snapshot",
    review_method:
      "unsigned_hash_chain_and_supplied_snapshot_consistency",
    snapshot_anchor_file: REVIEW_ANCHOR_FILE,
    snapshot_head_sequence: anchorHead.sequence,
    snapshot_head_entry_sha256: reviewAnchorEntrySha256(anchorHead),
    snapshot_predecessor_entry_sha256:
      anchorHead.predecessor_entry_sha256,
    reviewer_label: anchorHead.reviewer_id,
    reviewer_label_status: "self_declared_unsigned",
    review_lock_sha256: sha256(stableStringify(reviewLock)),
    review_epoch_id: epoch.epoch_id,
    reviewed_as_of: epoch.reviewed_as_of,
    reviewed_identity_set_sha256: epoch.identity_set_sha256,
    reviewed_entry_set_sha256: epoch.reviewed_entry_set_sha256,
    program_source_material_sha256:
      programSourceMaterialSha256(programSource),
    assurance_posture: SUPPLIED_SNAPSHOT_ASSURANCE_POSTURE,
  };
}

export function attestProgramSourceReview(
  repoRoot,
  discoveredEntries,
  reviewLock,
  worksheet,
  reviewAnchor = readJsonFile(repoRoot, REVIEW_ANCHOR_FILE),
) {
  validateReviewLock(
    repoRoot,
    discoveredEntries,
    reviewLock,
    reviewAnchor,
  );
  const errors = [];
  addError(
    errors,
    worksheet?.program_state === "worksheet_unreviewed",
    "program source review transition requires an unreviewed worksheet",
  );
  addError(
    errors,
    worksheet?.as_of_date === null,
    "unreviewed program source worksheet must not carry a review date",
  );
  addError(
    errors,
    worksheet?.review_attestation === null,
    "unreviewed program source worksheet must not carry a review attestation",
  );
  validationFailure("M0 program source review transition", errors);
  validateReviewAnchor(reviewLock, reviewAnchor, worksheet);

  const reviewed = structuredClone(worksheet);
  const epoch = latestReviewEpoch(reviewLock);
  reviewed.as_of_date = epoch.reviewed_as_of;
  reviewed.program_state = "reviewed";
  reviewed.review_attestation =
    expectedProgramSourceReviewAttestation(
      reviewed,
      reviewLock,
      reviewAnchor,
    );
  validateProgramSource(
    repoRoot,
    discoveredEntries,
    reviewLock,
    reviewed,
    reviewAnchor,
  );
  return reviewed;
}

function canonicalJsonValue(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalJsonValue);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalJsonValue(value[key])]),
    );
  }
  return value;
}

export function stableStringify(value) {
  return `${JSON.stringify(canonicalJsonValue(value), null, 2)}\n`;
}

export function readJsonFile(repoRoot, relativePath) {
  const absolutePath = path.join(repoRoot, relativePath);
  let source;
  try {
    source = fs.readFileSync(absolutePath, "utf8");
  } catch (error) {
    if (error?.code === "ENOENT") {
      throw new Error(`missing M0 evidence source: ${relativePath}`);
    }
    throw error;
  }
  try {
    return JSON.parse(source);
  } catch (error) {
    throw new Error(`invalid JSON in ${relativePath}: ${error.message}`);
  }
}

function addError(errors, condition, message) {
  if (!condition) {
    errors.push(message);
  }
}

function isNonEmptyString(value) {
  return typeof value === "string" && value.trim().length > 0;
}

function hasExactMembers(actual, expected) {
  return actual.length === expected.length
    && actual.every((value, index) => value === expected[index]);
}

function isIsoDate(value) {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}$/u.test(value)) {
    return false;
  }
  const parsed = new Date(`${value}T00:00:00.000Z`);
  return !Number.isNaN(parsed.valueOf())
    && parsed.toISOString().slice(0, 10) === value;
}

function reviewIdentitySetSha256(identities) {
  return sha256(stableStringify([...identities].sort()));
}

const DISCOVERY_REVIEW_BINDING_FIELDS = [
  "identity",
  "kind",
  "surface",
  "operation",
  "active_state",
  "source_file",
  "source_symbol",
  "handler",
  "handler_source_file",
  "handler_source_symbol",
  "handler_resolution",
  "method",
  "path",
  "rpc_service",
  "rpc_method",
  "service_method",
  "command",
  "storage_method",
  "storage_key_expression",
];

function reviewBoundDiscoveryProjection(entry) {
  return {
    ...Object.fromEntries(
      DISCOVERY_REVIEW_BINDING_FIELDS.map((field) => [
        field,
        entry?.[field] ?? null,
      ]),
    ),
    registration_anchor_sha256: entry?.source_anchor?.sha256 ?? null,
    handler_anchor_sha256: entry?.handler_anchor?.sha256 ?? null,
  };
}

function reviewEntryMaterialSha256(entry) {
  const material = structuredClone(entry);
  delete material.reviewed_as_of;
  return sha256(stableStringify(material));
}

function discoveredEntryMaterialSha256(entry) {
  return sha256(stableStringify(reviewBoundDiscoveryProjection(entry)));
}

function reviewedEntrySetSha256(entries) {
  return sha256(stableStringify(
    [...entries].sort((left, right) => left.identity.localeCompare(right.identity)),
  ));
}

function comparisonBaselineCommitmentsSha256(entries) {
  return sha256(stableStringify(
    [...entries].sort((left, right) => left.identity.localeCompare(right.identity)),
  ));
}

function validationFailure(label, errors) {
  if (errors.length > 0) {
    throw new Error(
      `${label} failed with ${errors.length} error(s):\n${errors.map((error) => `- ${error}`).join("\n")}`,
    );
  }
}

function validateAnchoredFile(repoRoot, relativePath, expectedHash, label, errors) {
  addError(errors, isNonEmptyString(relativePath), `${label} is missing a source file`);
  addError(errors, isNonEmptyString(expectedHash), `${label} is missing a source anchor`);
  if (!isNonEmptyString(relativePath) || !isNonEmptyString(expectedHash)) {
    return;
  }
  try {
    const { source } = readRepoFile(repoRoot, relativePath);
    addError(
      errors,
      sha256(source) === expectedHash,
      `${label} has a stale source anchor for ${relativePath}`,
    );
  } catch (error) {
    errors.push(`${label} source cannot be read: ${error.message}`);
  }
}

const REQUIRED_GATE_NAMES = ["authority", "fence", "ifc", "policy", "revocation"];

export function validateReviewLock(
  repoRoot,
  discoveredEntries,
  reviewLock,
  reviewAnchor = readJsonFile(repoRoot, REVIEW_ANCHOR_FILE),
) {
  const errors = [];
  addError(
    errors,
    reviewLock?.evidence_format === "ioi.m0.reviewed_entry_lock.v1",
    "review lock has an unsafe or unknown evidence_format",
  );
  addError(errors, reviewLock?.lock_state === "reviewed", "review lock is not in reviewed state");
  addError(
    errors,
    reviewLock?.default_classification === "fail_closed_unclassified",
    "review lock must use fail_closed_unclassified as its default",
  );
  addError(
    errors,
    reviewLock?.review_attestation?.reviewed_entry_count === discoveredEntries.length,
    "review attestation count does not match discovery",
  );
  addError(
    errors,
    isNonEmptyString(reviewLock?.review_attestation?.method),
    "review attestation must state its method",
  );
  addError(
    errors,
    !/heuristic|automatic promotion|auto[-_ ]classified/iu.test(
      reviewLock?.review_attestation?.method ?? "",
    ),
    "review attestation describes heuristic or automatic promotion as review",
  );
  addError(
    errors,
    Array.isArray(reviewLock?.review_attestation?.review_groups)
      && reviewLock.review_attestation.review_groups.length > 0,
    "review attestation must name reviewed groups",
  );
  addError(
    errors,
    reviewLock?.review_attestation?.terminal_claim_count === 0,
    "review attestation terminal claim count must match the fail-closed M0 review",
  );
  addError(
    errors,
    reviewLock?.review_attestation?.unresolved_placeholder_count === 0,
    "review attestation reports unresolved placeholders",
  );
  addError(errors, Array.isArray(reviewLock?.entries), "review lock entries must be an array");

  const discoveredByIdentity = new Map();
  for (const entry of discoveredEntries) {
    if (discoveredByIdentity.has(entry.identity)) {
      errors.push(`discovery contains duplicate identity ${entry.identity}`);
    }
    discoveredByIdentity.set(entry.identity, entry);
  }

  const reviewByIdentity = new Map();
  for (const entry of reviewLock?.entries ?? []) {
    if (!isNonEmptyString(entry?.identity)) {
      errors.push("review lock contains an entry without an identity");
      continue;
    }
    if (reviewByIdentity.has(entry.identity)) {
      errors.push(`review lock contains duplicate identity ${entry.identity}`);
    }
    reviewByIdentity.set(entry.identity, entry);
  }

  for (const identity of discoveredByIdentity.keys()) {
    addError(errors, reviewByIdentity.has(identity), `discovered identity is unclassified: ${identity}`);
  }
  for (const identity of reviewByIdentity.keys()) {
    addError(errors, discoveredByIdentity.has(identity), `review identity is no longer discovered: ${identity}`);
  }

  const reviewEpochs = reviewLock?.review_attestation?.review_epochs;
  addError(
    errors,
    Array.isArray(reviewEpochs) && reviewEpochs.length > 0,
    "review attestation must declare at least one review epoch",
  );
  const epochByDate = new Map();
  const epochIds = new Set();
  for (const epoch of reviewEpochs ?? []) {
    const label = `review epoch ${epoch?.epoch_id ?? "<missing>"}`;
    addError(errors, isNonEmptyString(epoch?.epoch_id), `${label} lacks an id`);
    addError(
      errors,
      !epochIds.has(epoch?.epoch_id),
      `${label} duplicates an epoch id`,
    );
    epochIds.add(epoch?.epoch_id);
    addError(
      errors,
      isIsoDate(epoch?.reviewed_as_of),
      `${label} lacks a valid reviewed_as_of date`,
    );
    addError(
      errors,
      !epochByDate.has(epoch?.reviewed_as_of),
      `${label} duplicates review date ${epoch?.reviewed_as_of}`,
    );
    if (isIsoDate(epoch?.reviewed_as_of)) {
      epochByDate.set(epoch.reviewed_as_of, epoch);
    }
    addError(
      errors,
      Number.isInteger(epoch?.reviewed_entry_count)
        && epoch.reviewed_entry_count > 0,
      `${label} lacks a positive reviewed entry count`,
    );
    addError(
      errors,
      /^[0-9a-f]{64}$/u.test(epoch?.identity_set_sha256 ?? ""),
      `${label} lacks an identity set commitment`,
    );
    addError(
      errors,
      /^[0-9a-f]{64}$/u.test(epoch?.reviewed_entry_set_sha256 ?? ""),
      `${label} lacks a complete reviewed-entry commitment`,
    );
    addError(
      errors,
      isNonEmptyString(epoch?.provenance),
      `${label} lacks explicit review provenance`,
    );
    if (epoch?.identity_refs !== undefined) {
      addError(
        errors,
        Array.isArray(epoch.identity_refs)
          && epoch.identity_refs.length > 0
          && new Set(epoch.identity_refs).size === epoch.identity_refs.length
          && epoch.identity_refs.every(isNonEmptyString),
        `${label} has invalid explicit identity refs`,
      );
    }
  }

  const identitiesByReviewDate = new Map();
  for (const reviewed of reviewByIdentity.values()) {
    const date = reviewed.reviewed_as_of;
    if (!identitiesByReviewDate.has(date)) {
      identitiesByReviewDate.set(date, []);
    }
    identitiesByReviewDate.get(date).push(reviewed.identity);
    addError(
      errors,
      epochByDate.has(date),
      `review entry ${reviewed.identity} date ${date ?? "<missing>"} does not bind a declared review epoch`,
    );
  }
  for (const epoch of reviewEpochs ?? []) {
    const label = `review epoch ${epoch?.epoch_id ?? "<missing>"}`;
    const identities = identitiesByReviewDate.get(epoch?.reviewed_as_of) ?? [];
    const reviewedEntries = identities.map((identity) => reviewByIdentity.get(identity));
    addError(
      errors,
      identities.length === epoch?.reviewed_entry_count,
      `${label} has a stale reviewed entry count`,
    );
    addError(
      errors,
      reviewIdentitySetSha256(identities) === epoch?.identity_set_sha256,
      `${label} has a stale identity set commitment`,
    );
    addError(
      errors,
      reviewedEntrySetSha256(reviewedEntries)
        === epoch?.reviewed_entry_set_sha256,
      `${label} has a stale complete reviewed-entry commitment`,
    );
    if (Array.isArray(epoch?.identity_refs)) {
      addError(
        errors,
        hasExactMembers(
          [...epoch.identity_refs].sort(),
          [...identities].sort(),
        ),
        `${label} explicit identity refs do not match its reviewed entries`,
      );
    }
  }
  const latestReviewDate = [...epochByDate.keys()].sort().at(-1);
  addError(
    errors,
    reviewLock?.as_of_date === latestReviewDate,
    "review lock as_of_date does not match its latest declared review epoch",
  );
  addError(
    errors,
    reviewLock?.review_attestation?.reviewed_as_of === latestReviewDate,
    "review attestation date does not match its latest declared review epoch",
  );

  const comparisonBaseline =
    reviewLock?.review_attestation?.comparison_baseline;
  const baselineLabel = "review comparison baseline";
  for (const [field, expected] of Object.entries(
    REVIEW_COMPARISON_BASELINE,
  )) {
    if (field === "entry_commitments_sha256") {
      continue;
    }
    addError(
      errors,
      comparisonBaseline?.[field] === expected,
      `${baselineLabel} has stale or mismatched ${field}`,
    );
  }
  addError(
    errors,
    Array.isArray(comparisonBaseline?.entry_commitments),
    `${baselineLabel} entry commitments must be an array`,
  );
  const baselineByIdentity = new Map();
  for (const commitment of comparisonBaseline?.entry_commitments ?? []) {
    const label =
      `${baselineLabel} entry ${commitment?.identity ?? "<missing>"}`;
    addError(errors, isNonEmptyString(commitment?.identity), `${label} lacks an identity`);
    addError(
      errors,
      !baselineByIdentity.has(commitment?.identity),
      `${label} duplicates an identity`,
    );
    baselineByIdentity.set(commitment?.identity, commitment);
    addError(
      errors,
      /^[0-9a-f]{64}$/u.test(commitment?.discovered_entry_sha256 ?? ""),
      `${label} lacks a discovered-entry commitment`,
    );
    addError(
      errors,
      /^[0-9a-f]{64}$/u.test(commitment?.reviewed_entry_sha256 ?? ""),
      `${label} lacks a reviewed-entry commitment`,
    );
    addError(
      errors,
      isIsoDate(commitment?.reviewed_as_of),
      `${label} lacks an immutable review date`,
    );
  }
  addError(
    errors,
    baselineByIdentity.size
      === REVIEW_COMPARISON_BASELINE.reviewed_entry_count,
    `${baselineLabel} has a stale reviewed entry count`,
  );
  const baselineCommitment = comparisonBaselineCommitmentsSha256(
    comparisonBaseline?.entry_commitments ?? [],
  );
  addError(
    errors,
    comparisonBaseline?.entry_commitments_sha256 === baselineCommitment,
    `${baselineLabel} has a stale entry commitment set`,
  );
  addError(
    errors,
    baselineCommitment
      === REVIEW_COMPARISON_BASELINE.entry_commitments_sha256,
    `${baselineLabel} does not match the immutable comparison commitment`,
  );

  for (const [identity, reviewed] of reviewByIdentity) {
    const discovered = discoveredByIdentity.get(identity);
    const baseline = baselineByIdentity.get(identity);
    const materiallyChanged = baseline === undefined
      || baseline.discovered_entry_sha256
        !== discoveredEntryMaterialSha256(discovered)
      || baseline.reviewed_entry_sha256
        !== reviewEntryMaterialSha256(reviewed);
    addError(
      errors,
      !materiallyChanged || reviewed.reviewed_as_of === latestReviewDate,
      `new or materially changed review entry ${identity} must bind the latest review epoch ${latestReviewDate}`,
    );
    addError(
      errors,
      materiallyChanged
        || reviewed.reviewed_as_of === baseline.reviewed_as_of,
      `unchanged review entry ${identity} must preserve immutable baseline epoch ${baseline?.reviewed_as_of}`,
    );
  }

  const expectedSurfaceCounts = new Map();
  for (const entry of reviewByIdentity.values()) {
    expectedSurfaceCounts.set(
      entry.surface,
      (expectedSurfaceCounts.get(entry.surface) ?? 0) + 1,
    );
  }
  const attestedSurfaces = new Set();
  for (const group of reviewLock?.review_attestation?.review_groups ?? []) {
    const label = `review attestation group ${group?.group_id ?? "<missing>"}`;
    addError(errors, isNonEmptyString(group?.group_id), `${label} lacks an id`);
    addError(errors, isNonEmptyString(group?.surface), `${label} lacks a surface`);
    addError(
      errors,
      group?.group_id === `surface:${group?.surface}`,
      `${label} does not bind its surface`,
    );
    addError(
      errors,
      !attestedSurfaces.has(group?.surface),
      `${label} duplicates surface ${group?.surface}`,
    );
    attestedSurfaces.add(group?.surface);
    addError(
      errors,
      group?.reviewed_entry_count === expectedSurfaceCounts.get(group?.surface),
      `${label} has a stale reviewed entry count`,
    );
    addError(
      errors,
      Array.isArray(group?.review_dimensions)
        && hasExactMembers(
          [...group.review_dimensions].sort(),
          [...REVIEW_DIMENSIONS].sort(),
        ),
      `${label} does not attest every review dimension`,
    );
    addError(
      errors,
      isNonEmptyString(group?.finding)
        && !/heuristic|automatic promotion|auto[-_ ]classified/iu.test(group.finding),
      `${label} lacks a source-aware finding`,
    );
  }
  addError(
    errors,
    hasExactMembers(
      [...attestedSurfaces].sort(),
      [...expectedSurfaceCounts.keys()].sort(),
    ),
    "review attestation groups do not partition every reviewed surface exactly once",
  );

  for (const [identity, reviewed] of reviewByIdentity) {
    const discovered = discoveredByIdentity.get(identity);
    if (discovered === undefined) {
      continue;
    }
    const label = `review entry ${identity}`;
    addError(errors, reviewed.review_status === "reviewed", `${label} is not explicitly reviewed`);
    addError(
      errors,
      reviewed.review_origin === "explicit_m0_review",
      `${label} has heuristic or unresolved review provenance`,
    );
    addError(
      errors,
      isIsoDate(reviewed.reviewed_as_of),
      `${label} lacks a valid dated review`,
    );
    for (const field of [
      "kind",
      "surface",
      "operation",
      "source_file",
      "source_symbol",
      "handler_resolution",
    ]) {
      addError(
        errors,
        reviewed[field] === discovered[field],
        `${label} has stale or mismatched ${field}`,
      );
    }
    for (const field of [
      "active_state",
      "handler",
      "handler_source_file",
      "handler_source_symbol",
    ]) {
      addError(
        errors,
        (reviewed[field] ?? null) === (discovered[field] ?? null),
        `${label} has stale or mismatched ${field}`,
      );
    }
    for (const field of [
      "method",
      "path",
      "rpc_service",
      "rpc_method",
      "service_method",
      "command",
      "storage_method",
      "storage_key_expression",
    ]) {
      addError(
        errors,
        (reviewed[field] ?? null) === (discovered[field] ?? null),
        `${label} has stale or mismatched ${field}`,
      );
    }
    addError(
      errors,
      reviewed.registration_anchor_sha256 === discovered.source_anchor?.sha256,
      `${label} has a stale registration anchor`,
    );
    addError(
      errors,
      (reviewed.handler_anchor_sha256 ?? null) === (discovered.handler_anchor?.sha256 ?? null),
      `${label} has a stale handler anchor`,
    );
    addError(
      errors,
      ENTRY_CLASSIFICATIONS.has(reviewed.classification),
      `${label} has unknown classification ${reviewed.classification}`,
    );
    const handlerEffectCalls = discovered.handler_effect_calls ?? [];
    addError(
      errors,
      reviewed.classification !== "read_only" || handlerEffectCalls.length === 0,
      `${label} is read_only despite observed handler effect calls: ${handlerEffectCalls.join(", ")}`,
    );
    addError(errors, isNonEmptyString(reviewed.effect_class), `${label} lacks an effect class`);
    addError(errors, isNonEmptyString(reviewed.owner), `${label} lacks an owner`);
    addError(errors, isNonEmptyString(reviewed.owner_doc), `${label} lacks an owner document`);
    if (isNonEmptyString(reviewed.owner_doc)) {
      addError(
        errors,
        fs.existsSync(path.join(repoRoot, reviewed.owner_doc)),
        `${label} owner document does not exist: ${reviewed.owner_doc}`,
      );
    }
    addError(
      errors,
      isNonEmptyString(reviewed.selected_profile_applicability),
      `${label} lacks selected-profile applicability`,
    );
    addError(
      errors,
      IMPLEMENTATION_STATES.has(reviewed.implementation_state),
      `${label} has unknown implementation state ${reviewed.implementation_state}`,
    );
    addError(
      errors,
      !/(?:unresolved|ambiguous|error)/iu.test(reviewed.handler_resolution),
      `${label} has unresolved handler resolution ${reviewed.handler_resolution}`,
    );

    const gateNames = Object.keys(reviewed.pre_effect_gates ?? {}).sort();
    addError(
      errors,
      hasExactMembers(gateNames, REQUIRED_GATE_NAMES),
      `${label} must explicitly classify all five pre-effect gates`,
    );
    for (const gateName of REQUIRED_GATE_NAMES) {
      const gate = reviewed.pre_effect_gates?.[gateName];
      addError(errors, isNonEmptyString(gate?.state), `${label} lacks ${gateName} gate state`);
      addError(errors, Array.isArray(gate?.symbols), `${label} lacks ${gateName} gate symbols`);
      addError(errors, isNonEmptyString(gate?.note), `${label} lacks ${gateName} gate evidence note`);
    }

    const isEffect = reviewed.classification === "consequential"
      || reviewed.classification === "internal_only";
    if (isEffect) {
      addError(errors, reviewed.final_invoker !== null, `${label} lacks a final invoker`);
      addError(
        errors,
        ["terminal", "partial", "unavailable"].includes(reviewed.implementation_state),
        `${label} must use terminal, partial, or unavailable`,
      );
      addError(
        errors,
        reviewed.implementation_state === "terminal"
          || isNonEmptyString(reviewed.blocker_or_nonclaim_ref),
        `${label} is non-terminal without a typed blocker or nonclaim`,
      );
    }

    if (reviewed.final_invoker !== null) {
      addError(
        errors,
        isNonEmptyString(reviewed.final_invoker?.symbol),
        `${label} final invoker lacks a symbol`,
      );
      addError(
        errors,
        isNonEmptyString(reviewed.final_invoker?.resolution),
        `${label} final invoker lacks a resolution`,
      );
      addError(
        errors,
        [
          "verified_effect_leaf",
          "verified_boundary_not_downstream_effect",
          "candidate_or_handler_boundary_not_final",
        ].includes(reviewed.final_invoker?.claim_state),
        `${label} final invoker lacks an honest claim state`,
      );
      addError(
        errors,
        isNonEmptyString(reviewed.final_invoker?.note),
        `${label} final invoker lacks an evidence note`,
      );
      validateAnchoredFile(
        repoRoot,
        reviewed.final_invoker?.source_file,
        reviewed.final_invoker?.source_anchor_sha256,
        `${label} final invoker`,
        errors,
      );
      if (
        reviewed.final_invoker?.claim_state
          === "candidate_or_handler_boundary_not_final"
      ) {
        addError(
          errors,
          reviewed.implementation_state !== "terminal"
            && isNonEmptyString(reviewed.blocker_or_nonclaim_ref),
          `${label} launders a candidate boundary without a typed blocker`,
        );
      }
    }

    addError(
      errors,
      isNonEmptyString(reviewed.durable_record_receipt_evidence?.state),
      `${label} lacks durable record, receipt, or evidence state`,
    );
    addError(
      errors,
      Array.isArray(reviewed.durable_record_receipt_evidence?.symbols),
      `${label} lacks durable record, receipt, or evidence symbols`,
    );
    addError(
      errors,
      isNonEmptyString(reviewed.durable_record_receipt_evidence?.note),
      `${label} lacks durable record, receipt, or evidence note`,
    );
    addError(
      errors,
      isNonEmptyString(reviewed.idempotency_recovery?.idempotency),
      `${label} lacks idempotency posture`,
    );
    addError(
      errors,
      isNonEmptyString(reviewed.idempotency_recovery?.recovery),
      `${label} lacks recovery posture`,
    );

    if (reviewed.implementation_state === "terminal") {
      addError(
        errors,
        reviewed.final_invoker?.claim_state === "verified_effect_leaf"
          && /^verified_effect_leaf(?:_|$)/u.test(reviewed.final_invoker?.resolution ?? ""),
        `${label} falsely claims terminality without a verified effect leaf`,
      );
      for (const gateName of REQUIRED_GATE_NAMES) {
        addError(
          errors,
          reviewed.pre_effect_gates?.[gateName]?.state === "verified_pre_effect",
          `${label} falsely claims terminality without verified ${gateName} ordering`,
        );
      }
      addError(
        errors,
        reviewed.durable_record_receipt_evidence?.state
          === "verified_durable_record_receipt_or_evidence",
        `${label} falsely claims terminality without verified durable evidence`,
      );
      addError(
        errors,
        reviewed.idempotency_recovery?.idempotency === "end_to_end_verified",
        `${label} falsely claims terminality without end-to-end idempotency`,
      );
      addError(
        errors,
        reviewed.idempotency_recovery?.recovery === "end_to_end_verified",
        `${label} falsely claims terminality without end-to-end recovery`,
      );
      addError(
        errors,
        reviewed.blocker_or_nonclaim_ref === null,
        `${label} terminal claim still carries a blocker`,
      );
    }
  }

  validationFailure("M0 reviewed entry lock", errors);
  validateReviewAnchor(reviewLock, reviewAnchor);
  return reviewByIdentity;
}

export function validateProgramSource(
  repoRoot,
  discoveredEntries,
  reviewLock,
  programSource,
  reviewAnchor = readJsonFile(repoRoot, REVIEW_ANCHOR_FILE),
) {
  const reviewByIdentity = validateReviewLock(
    repoRoot,
    discoveredEntries,
    reviewLock,
    reviewAnchor,
  );
  const errors = [];
  const latestEpoch = latestReviewEpoch(reviewLock);
  const expectedReviewAttestation =
    expectedProgramSourceReviewAttestation(
      programSource,
      reviewLock,
      reviewAnchor,
    );
  const anchorHead = latestReviewAnchorEntry(reviewAnchor);
  addError(
    errors,
    programSource?.evidence_format === "ioi.m0.program_control_source.v1",
    "program source has an unsafe or unknown evidence_format",
  );
  addError(
    errors,
    programSource?.program_state === "reviewed",
    "program source is not supplied-snapshot attested; an unreviewed worksheet cannot self-promote",
  );
  addError(
    errors,
    programSource?.as_of_date === latestEpoch.reviewed_as_of,
    "program source date does not match the supplied snapshot epoch",
  );
  addError(
    errors,
    programSource?.review_attestation?.attestation_format
      === "ioi.m0.program_control_source_review.v4"
      && programSource?.review_attestation?.transition
        === "worksheet_unreviewed_to_supplied_snapshot_attested"
      && programSource?.review_attestation?.verification_scope
        === "supplied_repository_snapshot",
    "program source lacks the explicit supplied-snapshot transition attestation",
  );
  addError(
    errors,
    programSource?.review_attestation?.review_epoch_id
      === latestEpoch.epoch_id
      && programSource?.review_attestation?.reviewed_as_of
        === latestEpoch.reviewed_as_of
      && programSource?.review_attestation?.reviewed_identity_set_sha256
        === latestEpoch.identity_set_sha256
      && programSource?.review_attestation?.reviewed_entry_set_sha256
        === latestEpoch.reviewed_entry_set_sha256,
    "program source attestation does not bind the supplied snapshot epoch",
  );
  addError(
    errors,
    programSource?.review_attestation?.review_lock_sha256
      === expectedReviewAttestation.review_lock_sha256,
    "program source attestation does not bind the supplied review lock",
  );
  addError(
    errors,
    programSource?.review_attestation?.program_source_material_sha256
      === expectedReviewAttestation.program_source_material_sha256,
    "program source attestation does not match supplied material",
  );
  addError(
    errors,
    anchorHead?.program_source_material_sha256
      === programSourceMaterialSha256(programSource),
    "review snapshot head does not bind supplied program-source material",
  );
  addError(
    errors,
    stableStringify(programSource?.review_attestation)
      === stableStringify(expectedReviewAttestation),
    "program source supplied-snapshot attestation is incomplete or contains unbound fields",
  );
  addError(
    errors,
    Array.isArray(programSource?.canon_contradictions)
      && programSource.canon_contradictions.length === 0,
    "program source records a canon contradiction; stop before changing canon",
  );

  const canonBasis = programSource?.canon_basis ?? [];
  const canonByPath = new Map();
  for (const entry of canonBasis) {
    if (canonByPath.has(entry.source_file)) {
      errors.push(`program source duplicates canon basis ${entry.source_file}`);
    }
    canonByPath.set(entry.source_file, entry);
  }
  addError(
    errors,
    canonBasis.length === CANON_BASIS_FILES.length
      && canonByPath.size === CANON_BASIS_FILES.length,
    "program source canon basis count is stale",
  );
  for (const relativePath of CANON_BASIS_FILES) {
    const basis = canonByPath.get(relativePath);
    addError(errors, basis !== undefined, `program source omits canon basis ${relativePath}`);
    if (basis !== undefined) {
      validateAnchoredFile(
        repoRoot,
        relativePath,
        basis.source_sha256,
        `canon basis ${relativePath}`,
        errors,
      );
    }
  }
  for (const relativePath of canonByPath.keys()) {
    addError(
      errors,
      CANON_BASIS_FILES.includes(relativePath),
      `program source has unexpected canon basis ${relativePath}`,
    );
  }

  addError(
    errors,
    stableStringify(programSource?.sequencing_authority)
      === stableStringify(createSequencingAuthority()),
    "sequencing authority must keep ignored internal guides as unbound external operator inputs and tracked canon as committed evidence authority",
  );
  addError(
    errors,
    canonBasis.some((entry) => (
      entry.source_file.startsWith("docs/architecture/")
    )),
    "program source lacks tracked docs/architecture evidence authority",
  );
  addError(
    errors,
    canonBasis.every((entry) => (
      !entry.source_file.startsWith("internal-docs/implementation/")
    )),
    "ignored internal implementation guidance cannot be bound as M0 evidence",
  );
  let expectedDiscoveryCoverage;
  try {
    assertRepositoryDiscoveryCoverage(repoRoot);
    expectedDiscoveryCoverage = createDiscoverySourceCoverage(repoRoot);
  } catch (error) {
    errors.push(`repository discovery source coverage failed: ${error.message}`);
  }
  if (expectedDiscoveryCoverage !== undefined) {
    addError(
      errors,
      stableStringify(programSource?.discovery_source_coverage)
        === stableStringify(expectedDiscoveryCoverage),
      "program source discovery coverage is incomplete, stale, or reclassified",
    );
  }

  const blockerById = new Map();
  for (const blocker of programSource?.blocker_ledger ?? []) {
    if (blockerById.has(blocker.blocker_id)) {
      errors.push(`duplicate blocker id ${blocker.blocker_id}`);
    }
    blockerById.set(blocker.blocker_id, blocker);
    addError(errors, isNonEmptyString(blocker.type), `blocker ${blocker.blocker_id} lacks a type`);
    addError(errors, isNonEmptyString(blocker.state), `blocker ${blocker.blocker_id} lacks a state`);
    addError(
      errors,
      isNonEmptyString(blocker.summary),
      `blocker ${blocker.blocker_id} lacks a summary`,
    );
  }
  addError(
    errors,
    blockerLedgerMatchesCanonical(programSource?.blocker_ledger),
    "program source blocker ledger does not match the canonical blocker identities, types, states, and summaries",
  );

  const selectedProfile = programSource?.selected_profile;
  addError(
    errors,
    selectedProfile?.profile_id === "selected-minimum-l0-outcome-room-bounded-software-change",
    "selected minimum-L0 profile identity changed",
  );
  addError(
    errors,
    selectedProfile?.topology?.nodes === 1
      && selectedProfile?.topology?.writers === 1
      && selectedProfile?.topology?.failure_domains === 1
      && selectedProfile?.topology?.ordering_finality === "single_authority",
    "selected minimum-L0 topology changed",
  );
  const objectOwners = selectedProfile?.object_owners ?? [];
  addError(
    errors,
    objectOwners.length === SELECTED_OBJECT_OWNERS.length,
    "selected profile object-owner set is incomplete or expanded",
  );
  const requiredOwnerByObjectSet = new Map(
    SELECTED_OBJECT_OWNERS.map((entry) => [entry.object_set, entry]),
  );
  const observedObjectSets = new Set();
  const observedOwnerDocs = new Set();
  for (const [index, objectOwner] of objectOwners.entries()) {
    addError(
      errors,
      isNonEmptyString(objectOwner.object_set),
      `selected object owner ${index} lacks an object set`,
    );
    addError(
      errors,
      isNonEmptyString(objectOwner.owner),
      `selected object owner ${index} lacks an owner`,
    );
    addError(
      errors,
      !observedObjectSets.has(objectOwner.object_set),
      `selected object owner ${index} duplicates object_set ${objectOwner.object_set}`,
    );
    observedObjectSets.add(objectOwner.object_set);
    addError(
      errors,
      !observedOwnerDocs.has(objectOwner.owner_doc),
      `selected object owner ${index} duplicates owner_doc ${objectOwner.owner_doc}`,
    );
    observedOwnerDocs.add(objectOwner.owner_doc);
    const requiredOwner = requiredOwnerByObjectSet.get(objectOwner.object_set);
    addError(
      errors,
      requiredOwner?.owner === objectOwner.owner
        && requiredOwner?.owner_doc === objectOwner.owner_doc,
      `selected object owner ${index} does not match the canonical owner tuple`,
    );
    addError(
      errors,
      isNonEmptyString(objectOwner.owner_doc)
        && canonByPath.has(objectOwner.owner_doc),
      `selected object owner ${index} is not anchored in canon_basis`,
    );
  }
  const localIdentityOwner = objectOwners.find((entry) => (
    entry.object_set
      === "Deployment-local identity, product access, account and entitlement boundaries, and metering posture"
  ));
  addError(
    errors,
    localIdentityOwner?.owner === "Hypervisor identity, access, and metering"
      && localIdentityOwner?.owner_doc
        === "docs/architecture/components/hypervisor/identity-access-and-metering.md",
    "selected sovereign-local identity lane lacks its canonical identity owner source",
  );
  const localAuthorityOwner = objectOwners.find((entry) => (
    entry.object_set
      === "Deployment-local policy and locally permitted exact-effect authority provider selection"
  ));
  addError(
    errors,
    localAuthorityOwner?.owner
      === "Local/domain governance and the selected authority provider"
      && localAuthorityOwner?.owner_doc
        === "docs/architecture/foundations/invariants.md",
    "selected sovereign-local lane lacks its canonical local authority-provider owner source",
  );

  const proofLanes = selectedProfile?.proof_lanes ?? [];
  addError(
    errors,
    proofLanes.length === REQUIRED_PROOF_LANES.length,
    "selected profile must define exactly the canonical proof lanes",
  );
  const requiredProofLaneById = new Map(
    REQUIRED_PROOF_LANES.map((lane) => [lane.lane_id, lane]),
  );
  const proofLaneById = new Map();
  for (const [index, lane] of proofLanes.entries()) {
    addError(
      errors,
      isNonEmptyString(lane.lane_id),
      `selected proof lane ${index + 1} lacks lane_id`,
    );
    if (proofLaneById.has(lane.lane_id)) {
      errors.push(`selected proof lane duplicates ${lane.lane_id}`);
    }
    proofLaneById.set(lane.lane_id, lane);
    addError(
      errors,
      lane.order === index + 1,
      `selected proof lane ${lane.lane_id} has noncanonical order`,
    );
    addError(
      errors,
      isNonEmptyString(lane.starting_state)
        && isNonEmptyString(lane.claim_requirement)
        && isNonEmptyString(lane.authority_posture),
      `selected proof lane ${lane.lane_id} lacks its structural contract`,
    );
    addError(
      errors,
      Array.isArray(lane.required_evidence)
        && lane.required_evidence.length > 0
        && lane.required_evidence.every(isNonEmptyString)
        && new Set(lane.required_evidence).size === lane.required_evidence.length,
      `selected proof lane ${lane.lane_id} lacks unique required evidence`,
    );
    const requiredLane = requiredProofLaneById.get(lane.lane_id);
    addError(
      errors,
      requiredLane !== undefined,
      `selected proof lane ${lane.lane_id} is not canonical`,
    );
    addError(
      errors,
      requiredLane?.order === lane.order
        && requiredLane?.prerequisite_lane_id === lane.prerequisite_lane_id
        && requiredLane?.starting_state === lane.starting_state
        && requiredLane?.claim_requirement === lane.claim_requirement
        && requiredLane?.authority_posture === lane.authority_posture
        && requiredLane?.endpoint_posture === lane.endpoint_posture
        && requiredLane?.connection_posture === lane.connection_posture,
      `selected proof lane ${lane.lane_id} has substituted semantic fields`,
    );
    addError(
      errors,
      requiredLane !== undefined
        && hasExactStringSet(lane.required_evidence, requiredLane.required_evidence),
      `selected proof lane ${lane.lane_id} has a substituted required-evidence set`,
    );
  }
  addError(
    errors,
    proofLanes[0]?.lane_id === "sovereign_local_completeness"
      && proofLanes[0]?.prerequisite_lane_id === undefined,
    "selected sovereign-local proof lane must be first and independent",
  );
  addError(
    errors,
    proofLanes[1]?.lane_id === "managed_optionality_overlay"
      && proofLanes[1]?.prerequisite_lane_id === "sovereign_local_completeness",
    "selected managed proof lane must be an ordered overlay on sovereign-local completeness",
  );
  addError(
    errors,
    selectedProfile?.proof_lane_validation_posture
      === REQUIRED_PROOF_LANE_VALIDATION_POSTURE,
    "selected proof-lane validation posture is stale or overclaims closure",
  );

  const exactEffect = selectedProfile?.exact_effect;
  const exactEffectReview = reviewByIdentity.get(exactEffect?.route_identity);
  addError(errors, exactEffectReview !== undefined, "selected exact effect route is not censused");
  addError(
    errors,
    exactEffect?.selected_subdispatch === "file.apply_patch",
    "selected exact effect subdispatch changed",
  );
  addError(
    errors,
    exactEffect?.final_invoker_symbol === "coding_tool_workspace::apply_workspace_patch",
    "selected exact effect leaf changed",
  );
  addError(
    errors,
    exactEffectReview?.final_invoker?.symbol === exactEffect?.final_invoker_symbol,
    "selected exact effect leaf and reviewed final invoker disagree",
  );
  addError(
    errors,
    ["terminal", "unavailable"].includes(exactEffect?.implementation_state),
    "selected exact effect must be terminal or explicitly unavailable",
  );
  addError(
    errors,
    exactEffect?.implementation_state === "terminal"
      || blockerById.has(exactEffect?.blocker_ref),
    "selected exact effect is unavailable without a typed blocker",
  );

  const journey = selectedProfile?.visible_terminal_journey ?? [];
  addError(errors, journey.length === 13, "selected visible journey must contain exactly 13 steps");
  addError(
    errors,
    selectedJourneyMatchesCanonical(journey),
    "selected visible journey does not match the canonical actions, states, blockers, routes, and lane bindings",
  );
  const requiredLaneBindingById = new Map(
    REQUIRED_PROOF_LANE_BINDINGS.map((binding) => [binding.binding_id, binding]),
  );
  const observedLaneBindingIds = new Set();
  const observedBindingCountByLane = new Map(
    proofLanes.map((lane) => [lane.lane_id, 0]),
  );
  for (const [index, step] of journey.entries()) {
    addError(errors, step.step === index + 1, `selected journey step ${index + 1} is missing`);
    addError(
      errors,
      isNonEmptyString(step.visible_action),
      `selected journey step ${index + 1} lacks visible action`,
    );
    addError(
      errors,
      ["terminal", "unavailable"].includes(step.state),
      `selected journey step ${index + 1} has unsafe state ${step.state}`,
    );
    addError(
      errors,
      step.state === "terminal" || blockerById.has(step.blocker_ref),
      `selected journey step ${index + 1} is unavailable without a typed blocker`,
    );
    for (const identity of step.route_identities ?? []) {
      addError(
        errors,
        reviewByIdentity.has(identity),
        `selected journey step ${index + 1} references undiscovered route ${identity}`,
      );
      addError(
        errors,
        reviewByIdentity.get(identity)?.selected_profile_applicability !== "not_selected",
        `selected journey step ${index + 1} references unselected route ${identity}`,
      );
    }
    const laneBindings = step.lane_bindings ?? [];
    for (const [bindingIndex, binding] of laneBindings.entries()) {
      const label = `selected journey step ${index + 1} lane binding ${bindingIndex + 1}`;
      addError(errors, isNonEmptyString(binding.binding_id), `${label} lacks binding_id`);
      addError(
        errors,
        proofLaneById.has(binding.lane_id),
        `${label} references unknown proof lane ${binding.lane_id}`,
      );
      if (observedLaneBindingIds.has(binding.binding_id)) {
        errors.push(`${label} duplicates binding_id ${binding.binding_id}`);
      }
      observedLaneBindingIds.add(binding.binding_id);
      const requiredBinding = requiredLaneBindingById.get(binding.binding_id);
      addError(
        errors,
        requiredBinding !== undefined,
        `${label} is not a canonical required binding`,
      );
      addError(
        errors,
        requiredBinding?.step === step.step
          && requiredBinding?.lane_id === binding.lane_id,
        `${label} is assigned to the wrong journey step or proof lane`,
      );
      addError(
        errors,
        requiredBinding?.blocker_ref === binding.blocker_ref,
        `${label} has a substituted blocker`,
      );
      addError(
        errors,
        requiredBinding !== undefined
          && hasExactStringSet(
            binding.route_identities,
            requiredBinding.route_identities,
          ),
        `${label} has a substituted route set`,
      );
      if (proofLaneById.has(binding.lane_id)) {
        observedBindingCountByLane.set(
          binding.lane_id,
          (observedBindingCountByLane.get(binding.lane_id) ?? 0) + 1,
        );
      }
      addError(
        errors,
        blockerById.has(binding.blocker_ref),
        `${label} lacks a typed blocker`,
      );
      const bindingBlocker = blockerById.get(binding.blocker_ref);
      addError(
        errors,
        bindingBlocker?.type === requiredBinding?.blocker_type
          && bindingBlocker?.state === requiredBinding?.blocker_state,
        `${label} blocker type or state does not match the canonical open blocker`,
      );
      addError(
        errors,
        Array.isArray(binding.route_identities),
        `${label} lacks route identities`,
      );
      for (const identity of binding.route_identities ?? []) {
        addError(
          errors,
          reviewByIdentity.has(identity),
          `${label} references undiscovered route ${identity}`,
        );
        addError(
          errors,
          reviewByIdentity.get(identity)?.selected_profile_applicability !== "not_selected",
          `${label} references unselected route ${identity}`,
        );
      }
      addError(
        errors,
        (binding.route_identities?.length ?? 0) > 0
          || (step.state === "unavailable" && blockerById.has(binding.blocker_ref)),
        `${label} has neither selected routes nor a typed unavailable contract`,
      );
      addError(
        errors,
        (requiredBinding?.route_identities.length ?? 0) > 0
          || step.state === "unavailable",
        `${label} has an empty route set outside an unavailable parent step`,
      );
    }
  }
  addError(
    errors,
    observedLaneBindingIds.size === REQUIRED_PROOF_LANE_BINDINGS.length,
    "selected journey does not contain the exact required proof-lane binding set",
  );
  for (const requiredBinding of REQUIRED_PROOF_LANE_BINDINGS) {
    addError(
      errors,
      observedLaneBindingIds.has(requiredBinding.binding_id),
      `selected journey omits required proof-lane binding ${requiredBinding.binding_id}`,
    );
  }
  for (const lane of proofLanes) {
    addError(
      errors,
      (observedBindingCountByLane.get(lane.lane_id) ?? 0) > 0,
      `selected proof lane ${lane.lane_id} has no journey binding coverage`,
    );
  }

  const pgEntries = programSource?.pg_gate_map?.entries ?? [];
  const pgMetadata = {
    external_definition_input:
      programSource?.pg_gate_map?.external_definition_input,
    tracked_selected_profile_authority:
      programSource?.pg_gate_map?.tracked_selected_profile_authority,
  };
  addError(
    errors,
    stableStringify(pgMetadata) === stableStringify(createPgGateMetadata()),
    "PG metadata must keep the ignored ledger as an unbound external pointer and tracked canon as selected-profile authority",
  );
  addError(
    errors,
    !Object.hasOwn(programSource?.pg_gate_map ?? {}, "definition_owner"),
    "PG metadata cannot claim the ignored external ledger as a committed definition owner",
  );
  addError(
    errors,
    stableStringify(pgEntries) === stableStringify(createPgMap()),
    "PG map does not match the canonical selected-profile dispositions and rationales",
  );
  const pgById = new Map();
  for (const entry of pgEntries) {
    if (pgById.has(entry.pg_id)) {
      errors.push(`PG map duplicates ${entry.pg_id}`);
    }
    pgById.set(entry.pg_id, entry);
    addError(
      errors,
      PG_DISPOSITIONS.has(entry.disposition),
      `${entry.pg_id} has unknown disposition ${entry.disposition}`,
    );
    addError(
      errors,
      isNonEmptyString(entry.selected_profile_rationale),
      `${entry.pg_id} lacks selected-profile rationale`,
    );
    addError(
      errors,
      blockerById.has(entry.evidence_or_blocker_ref),
      `${entry.pg_id} references unknown evidence or blocker ${entry.evidence_or_blocker_ref}`,
    );
    addError(errors, entry.closure_claimed === false, `${entry.pg_id} falsely claims closure`);
    addError(
      errors,
      !Object.hasOwn(entry, "gate_text") && !Object.hasOwn(entry, "definition"),
      `${entry.pg_id} copies or redefines production-gate text`,
    );
  }
  addError(errors, pgEntries.length === PG_IDS.length, "PG map must contain exactly 58 entries");
  for (const id of PG_IDS) {
    addError(errors, pgById.has(id), `PG map omits ${id}`);
  }
  for (const id of pgById.keys()) {
    addError(errors, PG_IDS.includes(id), `PG map includes unknown id ${id}`);
  }
  addError(
    errors,
    programSource?.pg_gate_map?.closure_claimed === false,
    "PG map falsely claims aggregate closure",
  );

  const baselines = programSource?.baselines ?? [];
  const baselineCategories = [];
  for (const baseline of baselines) {
    baselineCategories.push(baseline.category);
    addError(
      errors,
      BASELINE_CATEGORIES.has(baseline.category),
      `baseline ${baseline.baseline_id} has unknown category`,
    );
    addError(
      errors,
      ["measured", "not_measured"].includes(baseline.status),
      `baseline ${baseline.baseline_id} has unsafe status`,
    );
    addError(
      errors,
      baseline.frozen_as_of === M0_BASELINE_AS_OF_DATE,
      `baseline ${baseline.baseline_id} was not frozen on the M0 baseline date`,
    );
    addError(
      errors,
      isNonEmptyString(baseline.cohort),
      `baseline ${baseline.baseline_id} lacks a frozen cohort`,
    );
    addError(
      errors,
      isNonEmptyString(baseline.method),
      `baseline ${baseline.baseline_id} lacks a frozen method`,
    );
    addError(
      errors,
      baseline.frozen_threshold !== null
        && typeof baseline.frozen_threshold === "object"
        && Object.keys(baseline.frozen_threshold).length > 0,
      `baseline ${baseline.baseline_id} lacks frozen thresholds`,
    );
    if (baseline.status === "not_measured") {
      addError(
        errors,
        baseline.observed_as_of === null,
        `unmeasured baseline ${baseline.baseline_id} fabricates an observation date`,
      );
      addError(
        errors,
        baseline.observed_value === null,
        `unmeasured baseline ${baseline.baseline_id} fabricates an observed value`,
      );
      addError(
        errors,
        isNonEmptyString(baseline.absence_evidence),
        `unmeasured baseline ${baseline.baseline_id} lacks absence evidence`,
      );
      addError(
        errors,
        blockerById.has(baseline.blocker_ref),
        `unmeasured baseline ${baseline.baseline_id} lacks a typed blocker`,
      );
    } else {
      addError(
        errors,
        isNonEmptyString(baseline.observed_as_of),
        `measured baseline ${baseline.baseline_id} lacks an observation date`,
      );
      addError(
        errors,
        baseline.observed_value !== null && baseline.observed_value !== undefined,
        `measured baseline ${baseline.baseline_id} lacks an observed value`,
      );
    }
  }
  addError(
    errors,
    hasExactMembers([...baselineCategories].sort(), [...BASELINE_CATEGORIES].sort()),
    "baselines must map product, reliability, cost, and comprehension exactly once",
  );
  addError(
    errors,
    stableStringify(programSource?.repository_validation_baselines)
      === stableStringify(REPOSITORY_VALIDATION_BASELINES),
    "repository validation baselines are missing or stale",
  );

  const releaseLevels = (programSource?.release_ladder ?? []).map((entry) => entry.level);
  addError(
    errors,
    hasExactMembers(releaseLevels, ["P0", "P1", "P2", "P3", "P4", "P5", "P6", "P7"]),
    "release ladder must map P0 through P7 exactly once",
  );
  for (const release of programSource?.release_ladder ?? []) {
    addError(errors, isNonEmptyString(release.name), `${release.level} lacks a name`);
    addError(errors, isNonEmptyString(release.criterion), `${release.level} lacks a criterion`);
    addError(
      errors,
      isNonEmptyString(release.stage_binding),
      `${release.level} lacks a stage binding`,
    );
  }

  for (const exclusion of programSource?.bounded_discovery_exclusions ?? []) {
    validateAnchoredFile(
      repoRoot,
      exclusion.source_file,
      exclusion.source_sha256,
      `bounded discovery exclusion ${exclusion.source_file}`,
      errors,
    );
    addError(
      errors,
      isNonEmptyString(exclusion.note),
      `bounded discovery exclusion ${exclusion.source_file} lacks rationale`,
    );
  }
  addError(
    errors,
    (programSource?.bounded_discovery_exclusions ?? []).length > 0,
    "bounded dynamic-dispatch exclusions are not recorded",
  );

  for (const reviewed of reviewByIdentity.values()) {
    if (isNonEmptyString(reviewed.blocker_or_nonclaim_ref)) {
      addError(
        errors,
        blockerById.has(reviewed.blocker_or_nonclaim_ref),
        `review entry ${reviewed.identity} references unknown blocker ${reviewed.blocker_or_nonclaim_ref}`,
      );
    }
  }
  addError(
    errors,
    programSource?.m0_exit_policy?.architecture_or_production_capability_closure === false,
    "M0 exit policy falsely closes architecture or production capability",
  );
  addError(
    errors,
    programSource?.m0_exit_policy?.claim_scope === "M0 program control and claim lock only",
    "M0 exit claim scope changed",
  );

  validationFailure("M0 program source", errors);
  return {
    blockerById,
    reviewByIdentity,
  };
}

function countBy(entries, selector) {
  const counts = {};
  for (const entry of entries) {
    const key = selector(entry);
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return Object.fromEntries(Object.entries(counts).sort(([left], [right]) => (
    left.localeCompare(right)
  )));
}

function artifactEnvelope(asOfDate, fingerprint, artifact, body) {
  return {
    evidence_format: `ioi.m0.${artifact}.v1`,
    as_of_date: asOfDate,
    build_fingerprint: fingerprint,
    ...body,
  };
}

export function buildM0Fingerprint(
  repoRoot,
  discoveredEntries,
  reviewLock,
  programSource,
  reviewAnchor = readJsonFile(repoRoot, REVIEW_ANCHOR_FILE),
) {
  const readmeSource = fs.readFileSync(path.join(repoRoot, README_FILE), "utf8");
  return sha256(stableStringify({
    discovered_entries: discoveredEntries,
    program_source: programSource,
    review_epoch_anchor: reviewAnchor,
    readme: {
      path: README_FILE,
      sha256: sha256(readmeSource),
    },
    reviewed_entry_lock: reviewLock,
  }));
}

export function buildM0Artifacts(
  repoRoot,
  discoveredEntries,
  reviewLock,
  programSource,
  reviewAnchor = readJsonFile(repoRoot, REVIEW_ANCHOR_FILE),
) {
  const { blockerById, reviewByIdentity } = validateProgramSource(
    repoRoot,
    discoveredEntries,
    reviewLock,
    programSource,
    reviewAnchor,
  );
  const fingerprint = buildM0Fingerprint(
    repoRoot,
    discoveredEntries,
    reviewLock,
    programSource,
    reviewAnchor,
  );
  const artifactAsOfDate = [...reviewLock.review_attestation.review_epochs]
    .map((epoch) => epoch.reviewed_as_of)
    .sort()
    .at(-1);
  for (const [label, inputDate] of [
    ["review lock", reviewLock.as_of_date],
    ["review attestation", reviewLock.review_attestation.reviewed_as_of],
    ["program source", programSource.as_of_date],
  ]) {
    if (artifactAsOfDate < inputDate) {
      throw new Error(
        `M0 artifact date ${artifactAsOfDate} is older than bound ${label} date ${inputDate}`,
      );
    }
  }
  const envelope = (artifact, body) => artifactEnvelope(
    artifactAsOfDate,
    fingerprint,
    artifact,
    body,
  );
  const reviewedEntries = discoveredEntries.map((discovered) => {
    const discoveryProjection = { ...discovered };
    for (const field of [
      "handler_calls",
      "handler_call_sequence",
      "registration_handler_call_sequence",
    ]) {
      delete discoveryProjection[field];
    }
    return {
      ...discoveryProjection,
      ...reviewByIdentity.get(discovered.identity),
      discovery_source_anchor: discovered.source_anchor,
      discovery_handler_anchor: discovered.handler_anchor,
    };
  });
  const selectedEntries = reviewedEntries.filter((entry) => (
    entry.selected_profile_applicability !== "not_selected"
  ));
  const blockerUsage = new Map([...blockerById.keys()].map((id) => [id, []]));
  for (const entry of reviewedEntries) {
    if (isNonEmptyString(entry.blocker_or_nonclaim_ref)) {
      blockerUsage.get(entry.blocker_or_nonclaim_ref)?.push(entry.identity);
    }
  }
  for (const step of programSource.selected_profile.visible_terminal_journey) {
    if (isNonEmptyString(step.blocker_ref)) {
      blockerUsage.get(step.blocker_ref)?.push(`selected-journey-step:${step.step}`);
    }
    for (const binding of step.lane_bindings ?? []) {
      if (isNonEmptyString(binding.blocker_ref)) {
        blockerUsage.get(binding.blocker_ref)?.push(
          `selected-journey-step:${step.step}:lane:${binding.lane_id}`,
        );
      }
    }
  }
  for (const baseline of programSource.baselines) {
    if (isNonEmptyString(baseline.blocker_ref)) {
      blockerUsage.get(baseline.blocker_ref)?.push(baseline.baseline_id);
    }
  }
  for (const pg of programSource.pg_gate_map.entries) {
    blockerUsage.get(pg.evidence_or_blocker_ref)?.push(pg.pg_id);
  }

  const documents = new Map();
  documents.set("effect-census.json", envelope("effect_census", {
    discovery_rule: reviewLock.discovery_scope.rule,
    counts: {
      total: reviewedEntries.length,
      by_classification: countBy(reviewedEntries, (entry) => entry.classification),
      by_implementation_state: countBy(reviewedEntries, (entry) => entry.implementation_state),
      by_surface: countBy(reviewedEntries, (entry) => entry.surface),
    },
    entries: reviewedEntries,
  }));
  documents.set("selected-profile.json", envelope("selected_profile", {
    claim_scope: "M0 program control only; no architecture or production capability closure",
    profile: programSource.selected_profile,
    selected_entry_counts: {
      total: selectedEntries.length,
      by_applicability: countBy(
        selectedEntries,
        (entry) => entry.selected_profile_applicability,
      ),
      by_state: countBy(selectedEntries, (entry) => entry.implementation_state),
    },
    selected_entries: selectedEntries.map((entry) => ({
      identity: entry.identity,
      selected_profile_applicability: entry.selected_profile_applicability,
      implementation_state: entry.implementation_state,
      final_invoker: entry.final_invoker,
      blocker_or_nonclaim_ref: entry.blocker_or_nonclaim_ref,
    })),
  }));
  documents.set("pg-gate-map.json", envelope("pg_gate_map", {
    external_definition_input:
      programSource.pg_gate_map.external_definition_input,
    tracked_selected_profile_authority:
      programSource.pg_gate_map.tracked_selected_profile_authority,
    closure_claimed: false,
    counts: countBy(programSource.pg_gate_map.entries, (entry) => entry.disposition),
    entries: programSource.pg_gate_map.entries,
  }));
  documents.set("current-baselines.json", envelope("current_baselines", {
    observation_rule:
      "Cohort, method, and threshold are frozen before observation; not_measured is evidence of absence, never zero.",
    counts: countBy(programSource.baselines, (entry) => entry.status),
    baselines: programSource.baselines,
    repository_validation_baselines:
      programSource.repository_validation_baselines,
  }));
  documents.set("blocker-ledger.json", envelope("blocker_ledger", {
    counts: {
      by_state: countBy(programSource.blocker_ledger, (entry) => entry.state),
      by_type: countBy(programSource.blocker_ledger, (entry) => entry.type),
    },
    blockers: programSource.blocker_ledger.map((blocker) => ({
      ...blocker,
      reference_count: blockerUsage.get(blocker.blocker_id)?.length ?? 0,
      references: [...(blockerUsage.get(blocker.blocker_id) ?? [])].sort(),
    })),
  }));
  documents.set("release-ladder.json", envelope("release_ladder", {
    current_program_level: "M0 only; below P0 runtime proof",
    ladder: programSource.release_ladder,
  }));

  const indexItems = [
    {
      path: REVIEW_ANCHOR_FILE,
      role:
        "unsigned hash-chain supplied-snapshot consistency and repository baseline",
      state: "matches_supplied_snapshot",
    },
    {
      path: REVIEW_FILE,
      role: "explicit reviewed claim lock",
      state: "matches_supplied_snapshot",
    },
    {
      path: PROGRAM_SOURCE_FILE,
      role:
        "supplied-snapshot-attested selected-profile, PG, baseline, release, and blocker source",
      state: "matches_supplied_snapshot",
    },
    {
      path: README_FILE,
      role: "human consumption and M0 claim boundary",
      state: "matches_supplied_snapshot",
    },
    ...GENERATED_ARTIFACT_FILES
      .filter((name) => name !== "program-evidence-index.json")
      .map((name) => ({
        path: `${EVIDENCE_DIR}/${name}`,
        role: name === "manifest.json"
          ? "artifact integrity and supplied-snapshot consistency lock"
          : "deterministic M0 evidence projection",
        state: "matches_supplied_snapshot",
      })),
  ];
  documents.set(
    "program-evidence-index.json",
    envelope("program_evidence_index", {
      verification_scope: "supplied_repository_snapshot",
      assurance_posture: SUPPLIED_SNAPSHOT_ASSURANCE_POSTURE,
      consumption_rule:
        "Evidence matches the supplied repository snapshot only when the read-only checker reproduces this fingerprint and every manifest hash; currentness requires an outside rollback-domain checkpoint.",
      evidence_items: indexItems,
      honestly_open_evidence: programSource.baselines
        .filter((entry) => entry.status === "not_measured")
        .map((entry) => ({
          baseline_id: entry.baseline_id,
          blocker_ref: entry.blocker_ref,
          status: entry.status,
        })),
    }),
  );

  const exitConditions = {
    all_discovered_entries_explicitly_reviewed:
      reviewedEntries.length === reviewLock.review_attestation.reviewed_entry_count,
    every_selected_object_has_owner:
      programSource.selected_profile.object_owners.every((entry) => (
        isNonEmptyString(entry.owner) && isNonEmptyString(entry.owner_doc)
      )),
    deployment_local_identity_owner_source_validated:
      programSource.selected_profile.object_owners.some((entry) => (
        entry.object_set
          === "Deployment-local identity, product access, account and entitlement boundaries, and metering posture"
        && entry.owner === "Hypervisor identity, access, and metering"
        && entry.owner_doc
          === "docs/architecture/components/hypervisor/identity-access-and-metering.md"
      )),
    proof_lanes_and_bindings_semantically_validated:
      selectedJourneyMatchesCanonical(
        programSource.selected_profile.visible_terminal_journey,
      )
      && blockerLedgerMatchesCanonical(programSource.blocker_ledger)
      && programSource.selected_profile.object_owners.some((entry) => (
        entry.object_set
          === "Deployment-local policy and locally permitted exact-effect authority provider selection"
        && entry.owner
          === "Local/domain governance and the selected authority provider"
        && entry.owner_doc === "docs/architecture/foundations/invariants.md"
      )),
    selected_effect_has_leaf_or_unavailable_blocker:
      isNonEmptyString(programSource.selected_profile.exact_effect.final_invoker_symbol)
      && (
        programSource.selected_profile.exact_effect.implementation_state === "terminal"
        || blockerById.has(programSource.selected_profile.exact_effect.blocker_ref)
      ),
    sequencing_inputs_are_honestly_bounded:
      stableStringify(programSource.sequencing_authority)
        === stableStringify(createSequencingAuthority()),
    all_58_pg_ids_mapped_once: programSource.pg_gate_map.entries.length === PG_IDS.length,
    baselines_are_measured_or_honestly_named: programSource.baselines.every((entry) => (
      entry.status === "measured"
      || (
        entry.status === "not_measured"
        && entry.observed_value === null
        && blockerById.has(entry.blocker_ref)
      )
    )),
    repository_validation_baseline_recorded:
      programSource.repository_validation_baselines.length > 0,
    evidence_items_match_supplied_snapshot_or_are_honestly_open:
      indexItems.every((entry) => entry.state === "matches_supplied_snapshot"),
    verification_scope_is_supplied_repository_snapshot:
      programSource.review_attestation.verification_scope
        === "supplied_repository_snapshot",
    bounded_snapshot_assurance_is_exact:
      stableStringify(reviewAnchor.assurance_posture)
        === stableStringify(SUPPLIED_SNAPSHOT_ASSURANCE_POSTURE),
  };
  const exitState = Object.values(exitConditions).every(Boolean) ? "verified" : "blocked";
  documents.set("m0-exit-report.json", envelope("exit_report", {
    m0_exit_state: exitState,
    verification_scope: "supplied_repository_snapshot",
    assurance_posture: SUPPLIED_SNAPSHOT_ASSURANCE_POSTURE,
    claim_scope: "M0 program control and claim lock only",
    architecture_or_production_capability_closure: false,
    conditions: exitConditions,
    census_counts: {
      total: reviewedEntries.length,
      consequential: reviewedEntries.filter((entry) => (
        entry.classification === "consequential"
      )).length,
      terminal_consequential: reviewedEntries.filter((entry) => (
        entry.classification === "consequential"
        && entry.implementation_state === "terminal"
      )).length,
      partial_consequential: reviewedEntries.filter((entry) => (
        entry.classification === "consequential"
        && entry.implementation_state === "partial"
      )).length,
      unavailable_consequential: reviewedEntries.filter((entry) => (
        entry.classification === "consequential"
        && entry.implementation_state === "unavailable"
      )).length,
    },
    open_blocker_count: programSource.blocker_ledger.filter((entry) => (
      entry.state === "open"
    )).length,
    nonclaims: [
      "M0 does not close any architecture production-status claim.",
      "M0 does not provide runtime capability, authority, product UX, or a canonical wire contract.",
      "Ignored internal sequencing and PG inputs are external operator pointers, not read, hashed, or bound evidence.",
      "The review anchor is development-workflow integrity evidence only: an unsigned hash chain with a self-declared reviewer label. It carries no cryptographic authorship and is not part of the bounded agency framework's authority model (wallet-network grants, sealed intents, receipts).",
      "The repository does not establish that the accepted snapshot head is current without an outside rollback-domain checkpoint.",
      "The repository does not establish resistance to rollback between internally coherent supplied snapshots.",
    ],
  }));

  const rendered = new Map(
    [...documents].map(([name, document]) => [name, stableStringify(document)]),
  );
  const sourceFiles = [
    REVIEW_ANCHOR_FILE,
    REVIEW_FILE,
    PROGRAM_SOURCE_FILE,
    README_FILE,
  ].map((relativePath) => {
    const source = fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
    return {
      path: relativePath,
      sha256: sha256(source),
    };
  });
  const artifactFiles = [...rendered].map(([name, source]) => ({
    path: `${EVIDENCE_DIR}/${name}`,
    sha256: sha256(source),
  }));
  const manifest = envelope("manifest", {
    consumption_rule:
      "Consumers must run scripts/m0-program-control.mjs --check; matching filenames without matching hashes are stale.",
    source_files: sourceFiles,
    artifact_files: artifactFiles,
  });
  rendered.set("manifest.json", stableStringify(manifest));

  if (exitState !== "verified") {
    throw new Error("internal error: valid M0 source did not satisfy its exit conditions");
  }
  return {
    fingerprint,
    exitState,
    documents,
    rendered,
  };
}

export function loadM0Sources(repoRoot) {
  return {
    reviewAnchor: readJsonFile(repoRoot, REVIEW_ANCHOR_FILE),
    reviewLock: readJsonFile(repoRoot, REVIEW_FILE),
    programSource: readJsonFile(repoRoot, PROGRAM_SOURCE_FILE),
  };
}

export function assertRenderedArtifactsCurrent(
  repoRoot,
  rendered,
  artifactFiles = GENERATED_ARTIFACT_FILES,
) {
  const errors = [];
  const allowedNames = new Set([
    path.basename(REVIEW_ANCHOR_FILE),
    path.basename(REVIEW_FILE),
    path.basename(PROGRAM_SOURCE_FILE),
    path.basename(README_FILE),
    ...artifactFiles,
  ]);
  try {
    for (const entry of fs.readdirSync(
      path.join(repoRoot, EVIDENCE_DIR),
      { withFileTypes: true },
    )) {
      if (!entry.isFile()) {
        errors.push(
          `unexpected non-file evidence entry ${EVIDENCE_DIR}/${entry.name}`,
        );
      } else if (!allowedNames.has(entry.name)) {
        errors.push(
          `unexpected stale evidence artifact ${EVIDENCE_DIR}/${entry.name}`,
        );
      }
    }
  } catch (error) {
    errors.push(
      error?.code === "ENOENT"
        ? `missing evidence directory ${EVIDENCE_DIR}`
        : `cannot enumerate evidence directory ${EVIDENCE_DIR}: ${error.message}`,
    );
  }
  for (const name of artifactFiles) {
    const relativePath = `${EVIDENCE_DIR}/${name}`;
    let actual;
    try {
      actual = fs.readFileSync(path.join(repoRoot, relativePath), "utf8");
    } catch (error) {
      errors.push(
        error?.code === "ENOENT"
          ? `missing generated artifact ${relativePath}`
          : `cannot read generated artifact ${relativePath}: ${error.message}`,
      );
      continue;
    }
    const expected = rendered.get(name);
    if (actual !== expected) {
      let actualDate;
      let expectedDate;
      try {
        actualDate = JSON.parse(actual)?.as_of_date;
        expectedDate = JSON.parse(expected)?.as_of_date;
      } catch {
        // Generic freshness validation below covers malformed artifacts.
      }
      errors.push(
        isIsoDate(actualDate)
          && isIsoDate(expectedDate)
          && actualDate < expectedDate
          ? `generated artifact ${relativePath} date ${actualDate} is older than bound input date ${expectedDate}`
          : `stale generated artifact ${relativePath}`,
      );
    }
  }
  validationFailure("M0 generated artifacts", errors);
}

export function checkM0Artifacts(repoRoot) {
  const discoveredEntries = discoverRepositorySurface(repoRoot);
  const { reviewAnchor, reviewLock, programSource } = loadM0Sources(repoRoot);
  const built = buildM0Artifacts(
    repoRoot,
    discoveredEntries,
    reviewLock,
    programSource,
    reviewAnchor,
  );
  assertRenderedArtifactsCurrent(repoRoot, built.rendered);
  return {
    ...built,
    discoveredEntries,
    reviewAnchor,
    reviewLock,
    programSource,
  };
}
