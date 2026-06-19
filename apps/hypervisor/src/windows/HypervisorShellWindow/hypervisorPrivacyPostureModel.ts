import {
  DEFAULT_HARNESS_PROFILE_OPTION,
  HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES,
  HYPERVISOR_CTEE_PRIVATE_WORKSPACE_PRIVACY_REF,
  HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
} from "./harnessAdapterModel.ts";
import { HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE } from "./hypervisorProviderPlacementModel.ts";
import { HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE } from "./hypervisorSessionOperationsModel.ts";

export type HypervisorExecutionPrivacyPosture =
  | "private_native"
  | "ctee_split"
  | "encrypted_storage_only"
  | "confidential_compute"
  | "remote_api_provider_trust"
  | "unsafe_plaintext_mount";

export type HypervisorWorkspaceCustodyClass =
  | "public_trunk"
  | "redacted_projection"
  | "encrypted_blob_ref"
  | "private_head"
  | "capability_exit";

export type HypervisorModelWeightCustodyLane =
  | "open_or_local_weights"
  | "remote_api_capability"
  | "tee_or_customer_cloud_mount"
  | "provider_trust_mount"
  | "forbidden_plaintext_mount";

export interface HypervisorWorkspaceCustodySegment {
  segment_ref: string;
  label: string;
  custody_class: HypervisorWorkspaceCustodyClass;
  node_plaintext_allowed: boolean;
  owner: "hypervisor_core" | "wallet_network" | "agentgres" | "storage_backend";
  evidence_refs: string[];
}

export interface HypervisorModelWeightCustodyPolicy {
  lane: HypervisorModelWeightCustodyLane;
  label: string;
  protects_workspace_state: boolean;
  protects_model_weights_from_provider_root: boolean;
  allowed_postures: HypervisorExecutionPrivacyPosture[];
  admission_summary: string;
  authority_scope_refs: string[];
}

export interface HypervisorProviderPrivacyCandidate {
  candidate_ref: string;
  label: string;
  posture: HypervisorExecutionPrivacyPosture;
  model_weight_lane: HypervisorModelWeightCustodyLane;
  provider_root_plaintext_risk: "none" | "bounded" | "expected" | "forbidden";
  admission_summary: string;
  receipt_ref: string;
}

export interface HypervisorPrivacyAdmissionControl {
  control_ref: string;
  label: string;
  owner: "wallet_network" | "hypervisor_daemon" | "agentgres";
  blocks_unsafe_plaintext: boolean;
  receipt_ref: string;
}

export type HypervisorPrivacyPostureProjectionSource =
  | "daemon-privacy-posture-projection"
  | "fixture"
  | "unverified";

export interface HypervisorPrivacyPostureProjection {
  schema_version: "ioi.hypervisor.execution_privacy_posture_projection.v1";
  projection_id: string;
  source: HypervisorPrivacyPostureProjectionSource;
  project_ref: string;
  selected_session_ref: string;
  selected_privacy_ref: typeof HYPERVISOR_CTEE_PRIVATE_WORKSPACE_PRIVACY_REF;
  default_model_route_ref: typeof HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF;
  invariant: string;
  workspace_segments: HypervisorWorkspaceCustodySegment[];
  model_weight_policies: HypervisorModelWeightCustodyPolicy[];
  provider_candidates: HypervisorProviderPrivacyCandidate[];
  admission_controls: HypervisorPrivacyAdmissionControl[];
  unsafe_mount_receipt_ref: string;
  runtimeTruthSource: "daemon-runtime";
}

export const HYPERVISOR_PRIVACY_POSTURE_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";
export const HYPERVISOR_PRIVACY_POSTURE_DEFAULT_DAEMON_ENDPOINT =
  "http://127.0.0.1:8765";
export const HYPERVISOR_PRIVACY_POSTURE_PROJECTION_PATH =
  "/v1/hypervisor/privacy-posture";
export const HYPERVISOR_MODEL_WEIGHT_CUSTODY_ADMISSION_PATH =
  "/v1/hypervisor/model-weight-custody-admissions";

export type HypervisorModelWeightCustodyAdmissionActionState =
  | "daemon_admissible"
  | "wallet_step_up_required"
  | "attestation_required"
  | "blocked";

export interface HypervisorModelWeightCustodyAdmissionAction {
  state: HypervisorModelWeightCustodyAdmissionActionState;
  label: string;
  disabled_reason: string | null;
}

export interface HypervisorModelWeightCustodyAdmissionRequest {
  route_ref: string;
  model_ref: string;
  provider_ref: string;
  weight_class:
    | "public_open_weight"
    | "user_local_private_weight"
    | "remote_api_private_weight"
    | "provider_trust_remote_mount"
    | "tee_or_customer_cloud_mount"
    | "forbidden_plaintext_mount";
  mount_target:
    | "local_device"
    | "user_owned_node"
    | "rented_gpu"
    | "customer_cloud"
    | "provider_api"
    | "tee_session"
    | "none";
  execution_privacy_posture: HypervisorExecutionPrivacyPosture;
  remote_provider_can_read_weights: boolean;
  required_controls: string[];
  authority_scope_refs: string[];
  user_disclosure_ref?: string;
  provider_trust_acceptance_ref?: string;
  tee_attestation_ref?: string;
  customer_boundary_ref?: string;
  agentgres_operation_refs: string[];
  artifact_refs: string[];
}

export interface HypervisorModelWeightCustodyAdmission {
  schema_version: "ioi.runtime.model_weight_custody_admission.v1";
  admission_id: string;
  route_ref: string;
  model_ref: string;
  provider_ref: string;
  decision: "admitted" | "admitted_provider_trust";
  weight_class: HypervisorModelWeightCustodyAdmissionRequest["weight_class"];
  mount_target: HypervisorModelWeightCustodyAdmissionRequest["mount_target"];
  execution_privacy_posture: HypervisorExecutionPrivacyPosture;
  remote_provider_can_read_weights: boolean;
  protects_model_weights_from_provider_root: boolean;
  protects_workspace_state: boolean;
  required_controls: string[];
  authority_scope_refs: string[];
  user_disclosure_ref: string | null;
  provider_trust_acceptance_ref: string | null;
  tee_attestation_ref: string | null;
  customer_boundary_ref: string | null;
  agentgres_operation_refs: string[];
  artifact_refs: string[];
  receipt_ref: string;
  admitted_at: string;
  runtimeTruthSource: "daemon-runtime";
}

type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

interface NormalizePrivacyPostureProjectionOptions {
  source?: HypervisorPrivacyPostureProjectionSource;
}

interface LoadPrivacyPostureProjectionOptions
  extends NormalizePrivacyPostureProjectionOptions {
  endpoint?: string;
  fetchImpl?: FetchLike;
  projectId?: string | null;
  sessionRef?: string | null;
}

interface BuildModelWeightCustodyAdmissionRequestOptions {
  providerRef?: string;
  modelRef?: string;
  teeAttestationRef?: string;
  customerBoundaryRef?: string;
  userDisclosureRef?: string;
  providerTrustAcceptanceRef?: string;
}

interface RequestModelWeightCustodyAdmissionOptions
  extends BuildModelWeightCustodyAdmissionRequestOptions {
  endpoint?: string;
  fetchImpl?: FetchLike;
}

function postureForProviderPrivacy(
  privacyPosture: string,
): HypervisorExecutionPrivacyPosture {
  if (privacyPosture === "local_custody" || privacyPosture === "customer_controlled") {
    return "private_native";
  }
  if (privacyPosture === "confidential_compute") {
    return "confidential_compute";
  }
  if (privacyPosture === "ctee_split_required") {
    return "ctee_split";
  }
  if (privacyPosture === "encrypted_storage_only") {
    return "encrypted_storage_only";
  }
  return "remote_api_provider_trust";
}

function modelWeightLaneForPosture(
  posture: HypervisorExecutionPrivacyPosture,
): HypervisorModelWeightCustodyLane {
  if (posture === "private_native") {
    return "open_or_local_weights";
  }
  if (posture === "confidential_compute") {
    return "tee_or_customer_cloud_mount";
  }
  if (posture === "ctee_split" || posture === "encrypted_storage_only") {
    return "forbidden_plaintext_mount";
  }
  if (posture === "unsafe_plaintext_mount") {
    return "provider_trust_mount";
  }
  return "remote_api_capability";
}

function rootRiskForPosture(
  posture: HypervisorExecutionPrivacyPosture,
): HypervisorProviderPrivacyCandidate["provider_root_plaintext_risk"] {
  if (posture === "private_native") {
    return "none";
  }
  if (posture === "confidential_compute" || posture === "ctee_split") {
    return "bounded";
  }
  if (posture === "unsafe_plaintext_mount") {
    return "forbidden";
  }
  return "expected";
}

export function modelWeightCustodyAdmissionAction(
  policy: Pick<HypervisorModelWeightCustodyPolicy, "lane">,
): HypervisorModelWeightCustodyAdmissionAction {
  if (policy.lane === "forbidden_plaintext_mount") {
    return {
      state: "blocked",
      label: "Blocked",
      disabled_reason: "Forbidden plaintext mounts are blocked by daemon policy.",
    };
  }
  if (policy.lane === "provider_trust_mount") {
    return {
      state: "wallet_step_up_required",
      label: "Step-up required",
      disabled_reason:
        "Provider-trust mounts require wallet disclosure and explicit acceptance.",
    };
  }
  if (policy.lane === "tee_or_customer_cloud_mount") {
    return {
      state: "attestation_required",
      label: "Requires attestation",
      disabled_reason:
        "TEE/customer-cloud mounts require attestation or a customer-boundary ref before daemon admission.",
    };
  }
  return {
    state: "daemon_admissible",
    label: "Request admission",
    disabled_reason: null,
  };
}

export const HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE: HypervisorPrivacyPostureProjection =
  {
    schema_version: "ioi.hypervisor.execution_privacy_posture_projection.v1",
    projection_id: "privacy-posture:hypervisor-core/default",
    source: "fixture",
    project_ref: HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.project_ref,
    selected_session_ref:
      HYPERVISOR_SESSION_OPERATIONS_PROJECTION_FIXTURE.selected_session_ref,
    selected_privacy_ref: HYPERVISOR_CTEE_PRIVATE_WORKSPACE_PRIVACY_REF,
    default_model_route_ref: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    invariant:
      "Private workspace state may be encrypted, redacted, split, locally decrypted, or exposed through capability exits; untrusted providers must not receive protected workspace plaintext by default. Model-weight custody is a separate admission lane.",
    workspace_segments: [
      {
        segment_ref: "workspace-segment:public-trunk",
        label: "Public trunk",
        custody_class: "public_trunk",
        node_plaintext_allowed: true,
        owner: "hypervisor_core",
        evidence_refs: ["artifact://workspace/public-trunk"],
      },
      {
        segment_ref: "workspace-segment:redacted-projection",
        label: "Redacted projection",
        custody_class: "redacted_projection",
        node_plaintext_allowed: true,
        owner: "hypervisor_core",
        evidence_refs: ["agentgres://projection/redacted-workspace"],
      },
      {
        segment_ref: "workspace-segment:encrypted-agentgres-refs",
        label: "Encrypted state refs",
        custody_class: "encrypted_blob_ref",
        node_plaintext_allowed: false,
        owner: "agentgres",
        evidence_refs: ["artifact://agentgres/encrypted-workspace-blob"],
      },
      {
        segment_ref: "workspace-segment:private-head",
        label: "Private head",
        custody_class: "private_head",
        node_plaintext_allowed: false,
        owner: "wallet_network",
        evidence_refs: ["lease://wallet/declassification/private-head"],
      },
      {
        segment_ref: "workspace-segment:capability-exit",
        label: "Capability exit",
        custody_class: "capability_exit",
        node_plaintext_allowed: false,
        owner: "wallet_network",
        evidence_refs: ["receipt://capability/exit/private-workspace"],
      },
    ],
    model_weight_policies: [
      {
        lane: "open_or_local_weights",
        label: "Open or local weights",
        protects_workspace_state: true,
        protects_model_weights_from_provider_root: true,
        allowed_postures: ["private_native"],
        admission_summary:
          "Use when weights are open, user-owned locally, or mounted only inside the user's custody domain.",
        authority_scope_refs: ["scope:model.local_mount"],
      },
      {
        lane: "remote_api_capability",
        label: "Remote API capability",
        protects_workspace_state: false,
        protects_model_weights_from_provider_root: true,
        allowed_postures: ["remote_api_provider_trust"],
        admission_summary:
          "Protects proprietary weights by keeping them behind the provider API, but sensitive prompts require redaction or explicit provider trust.",
        authority_scope_refs: ["scope:model.invoke_remote"],
      },
      {
        lane: "tee_or_customer_cloud_mount",
        label: "TEE or customer-cloud mount",
        protects_workspace_state: true,
        protects_model_weights_from_provider_root: true,
        allowed_postures: ["confidential_compute", "private_native"],
        admission_summary:
          "Admits private workspace or proprietary weights only when attestation/customer custody policy permits it.",
        authority_scope_refs: ["scope:cloud.deploy", "scope:secret.release"],
      },
      {
        lane: "provider_trust_mount",
        label: "Provider-trust mount",
        protects_workspace_state: false,
        protects_model_weights_from_provider_root: false,
        allowed_postures: ["unsafe_plaintext_mount", "remote_api_provider_trust"],
        admission_summary:
          "Allowed only for public/redacted workloads or explicit unsafe/provider-trust sessions.",
        authority_scope_refs: ["scope:provider.trust_override"],
      },
      {
        lane: "forbidden_plaintext_mount",
        label: "Forbidden plaintext mount",
        protects_workspace_state: true,
        protects_model_weights_from_provider_root: false,
        allowed_postures: ["ctee_split", "encrypted_storage_only"],
        admission_summary:
          "Rented nodes may compute over public trunks, redacted projections, encrypted refs, or sealed private heads, but must not receive protected workspace plaintext or proprietary weights.",
        authority_scope_refs: ["scope:privacy.enforce_no_plaintext_custody"],
      },
    ],
    provider_candidates:
      HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE.candidates.map(
        (candidate) => {
          const posture = postureForProviderPrivacy(candidate.privacy_posture);
          const modelWeightLane = modelWeightLaneForPosture(posture);
          return {
            candidate_ref: candidate.candidate_ref,
            label: candidate.label,
            posture,
            model_weight_lane: modelWeightLane,
            provider_root_plaintext_risk: rootRiskForPosture(posture),
            admission_summary:
              modelWeightLane === "forbidden_plaintext_mount"
                ? "Admit public trunk, redacted projection, encrypted refs, and capability exits only."
                : candidate.workload_fit,
            receipt_ref: candidate.agentgres_receipt_ref,
          };
        },
      ),
    admission_controls: [
      {
        control_ref: "privacy-control:declassification-gate",
        label: "Declassification gate",
        owner: "wallet_network",
        blocks_unsafe_plaintext: true,
        receipt_ref: "receipt://privacy/declassification-gate",
      },
      {
        control_ref: "privacy-control:model-route-admission",
        label: "Model route admission",
        owner: "hypervisor_daemon",
        blocks_unsafe_plaintext: true,
        receipt_ref: "receipt://privacy/model-route-admission",
      },
      {
        control_ref: "privacy-control:agentgres-restore-validity",
        label: "Agentgres restore validity",
        owner: "agentgres",
        blocks_unsafe_plaintext: true,
        receipt_ref: "receipt://privacy/agentgres-restore-validity",
      },
      {
        control_ref: "privacy-control:harness-adapter-gate",
        label: "Harness adapter gate",
        owner: "hypervisor_daemon",
        blocks_unsafe_plaintext: true,
        receipt_ref: `receipt://privacy/harness/${DEFAULT_HARNESS_PROFILE_OPTION.profile_ref}`,
      },
    ],
    unsafe_mount_receipt_ref: `receipt://privacy/unsafe-mount-blocked/${HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES[0]?.adapter_id ?? "adapter"}`,
    runtimeTruthSource: "daemon-runtime",
  };

function objectRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function arrayOf(value: unknown): Record<string, unknown>[] {
  return Array.isArray(value) ? value.map(objectRecord) : [];
}

function stringValue(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim() ? value.trim() : fallback;
}

function stringList(value: unknown, fallback: string[]): string[] {
  if (!Array.isArray(value)) return fallback;
  const values = value
    .filter((item): item is string => typeof item === "string" && !!item.trim())
    .map((item) => item.trim());
  return values.length > 0 ? values : fallback;
}

function booleanValue(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function safeId(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]+/g, "_");
}

function enumValue<T extends string>(
  value: unknown,
  fallback: T,
  allowed: readonly T[],
): T {
  return typeof value === "string" && allowed.includes(value as T)
    ? (value as T)
    : fallback;
}

function normalizeWorkspaceCustodySegment(
  item: Record<string, unknown>,
  index: number,
): HypervisorWorkspaceCustodySegment {
  const fallback =
    HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.workspace_segments[index] ??
    HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.workspace_segments[0]!;
  return {
    segment_ref: stringValue(item.segment_ref, fallback.segment_ref),
    label: stringValue(item.label, fallback.label),
    custody_class: enumValue(item.custody_class, fallback.custody_class, [
      "public_trunk",
      "redacted_projection",
      "encrypted_blob_ref",
      "private_head",
      "capability_exit",
    ]),
    node_plaintext_allowed: booleanValue(
      item.node_plaintext_allowed,
      fallback.node_plaintext_allowed,
    ),
    owner: enumValue(item.owner, fallback.owner, [
      "hypervisor_core",
      "wallet_network",
      "agentgres",
      "storage_backend",
    ]),
    evidence_refs: stringList(item.evidence_refs, fallback.evidence_refs),
  };
}

function normalizeModelWeightPolicy(
  item: Record<string, unknown>,
  index: number,
): HypervisorModelWeightCustodyPolicy {
  const fallback =
    HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.model_weight_policies[index] ??
    HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.model_weight_policies[0]!;
  return {
    lane: enumValue(item.lane, fallback.lane, [
      "open_or_local_weights",
      "remote_api_capability",
      "tee_or_customer_cloud_mount",
      "provider_trust_mount",
      "forbidden_plaintext_mount",
    ]),
    label: stringValue(item.label, fallback.label),
    protects_workspace_state: booleanValue(
      item.protects_workspace_state,
      fallback.protects_workspace_state,
    ),
    protects_model_weights_from_provider_root: booleanValue(
      item.protects_model_weights_from_provider_root,
      fallback.protects_model_weights_from_provider_root,
    ),
    allowed_postures: stringList(
      item.allowed_postures,
      fallback.allowed_postures,
    ) as HypervisorExecutionPrivacyPosture[],
    admission_summary: stringValue(
      item.admission_summary,
      fallback.admission_summary,
    ),
    authority_scope_refs: stringList(
      item.authority_scope_refs,
      fallback.authority_scope_refs,
    ),
  };
}

function normalizeProviderPrivacyCandidate(
  item: Record<string, unknown>,
  index: number,
): HypervisorProviderPrivacyCandidate {
  const fallback =
    HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.provider_candidates[index] ??
    HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.provider_candidates[0]!;
  return {
    candidate_ref: stringValue(item.candidate_ref, fallback.candidate_ref),
    label: stringValue(item.label, fallback.label),
    posture: enumValue(item.posture, fallback.posture, [
      "private_native",
      "ctee_split",
      "encrypted_storage_only",
      "confidential_compute",
      "remote_api_provider_trust",
      "unsafe_plaintext_mount",
    ]),
    model_weight_lane: enumValue(
      item.model_weight_lane,
      fallback.model_weight_lane,
      [
        "open_or_local_weights",
        "remote_api_capability",
        "tee_or_customer_cloud_mount",
        "provider_trust_mount",
        "forbidden_plaintext_mount",
      ],
    ),
    provider_root_plaintext_risk: enumValue(
      item.provider_root_plaintext_risk,
      fallback.provider_root_plaintext_risk,
      ["none", "bounded", "expected", "forbidden"],
    ),
    admission_summary: stringValue(
      item.admission_summary,
      fallback.admission_summary,
    ),
    receipt_ref: stringValue(item.receipt_ref, fallback.receipt_ref),
  };
}

function normalizePrivacyAdmissionControl(
  item: Record<string, unknown>,
  index: number,
): HypervisorPrivacyAdmissionControl {
  const fallback =
    HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.admission_controls[index] ??
    HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.admission_controls[0]!;
  return {
    control_ref: stringValue(item.control_ref, fallback.control_ref),
    label: stringValue(item.label, fallback.label),
    owner: enumValue(item.owner, fallback.owner, [
      "wallet_network",
      "hypervisor_daemon",
      "agentgres",
    ]),
    blocks_unsafe_plaintext: booleanValue(
      item.blocks_unsafe_plaintext,
      fallback.blocks_unsafe_plaintext,
    ),
    receipt_ref: stringValue(item.receipt_ref, fallback.receipt_ref),
  };
}

export function readHypervisorPrivacyPostureDaemonEndpoint(): string {
  try {
    if (typeof window === "undefined") {
      return HYPERVISOR_PRIVACY_POSTURE_DEFAULT_DAEMON_ENDPOINT;
    }
    return (
      window.localStorage.getItem(
        HYPERVISOR_PRIVACY_POSTURE_DAEMON_ENDPOINT_STORAGE_KEY,
      ) || HYPERVISOR_PRIVACY_POSTURE_DEFAULT_DAEMON_ENDPOINT
    );
  } catch {
    return HYPERVISOR_PRIVACY_POSTURE_DEFAULT_DAEMON_ENDPOINT;
  }
}

export function normalizeHypervisorPrivacyPostureProjection(
  snapshot: unknown,
  options: NormalizePrivacyPostureProjectionOptions = {},
): HypervisorPrivacyPostureProjection {
  const value = objectRecord(snapshot);
  const fallback = HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE;
  const workspaceSegments = arrayOf(value.workspace_segments).map(
    normalizeWorkspaceCustodySegment,
  );
  const modelWeightPolicies = arrayOf(value.model_weight_policies).map(
    normalizeModelWeightPolicy,
  );
  const providerCandidates = arrayOf(value.provider_candidates).map(
    normalizeProviderPrivacyCandidate,
  );
  const admissionControls = arrayOf(value.admission_controls).map(
    normalizePrivacyAdmissionControl,
  );
  return {
    schema_version: "ioi.hypervisor.execution_privacy_posture_projection.v1",
    projection_id: stringValue(value.projection_id, fallback.projection_id),
    source: options.source ?? "daemon-privacy-posture-projection",
    project_ref: stringValue(value.project_ref, fallback.project_ref),
    selected_session_ref: stringValue(
      value.selected_session_ref,
      fallback.selected_session_ref,
    ),
    selected_privacy_ref: stringValue(
      value.selected_privacy_ref,
      fallback.selected_privacy_ref,
    ) as typeof HYPERVISOR_CTEE_PRIVATE_WORKSPACE_PRIVACY_REF,
    default_model_route_ref: stringValue(
      value.default_model_route_ref,
      fallback.default_model_route_ref,
    ) as typeof HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    invariant: stringValue(value.invariant, fallback.invariant),
    workspace_segments:
      workspaceSegments.length > 0
        ? workspaceSegments
        : fallback.workspace_segments,
    model_weight_policies:
      modelWeightPolicies.length > 0
        ? modelWeightPolicies
        : fallback.model_weight_policies,
    provider_candidates:
      providerCandidates.length > 0
        ? providerCandidates
        : fallback.provider_candidates,
    admission_controls:
      admissionControls.length > 0
        ? admissionControls
        : fallback.admission_controls,
    unsafe_mount_receipt_ref: stringValue(
      value.unsafe_mount_receipt_ref,
      fallback.unsafe_mount_receipt_ref,
    ),
    runtimeTruthSource: "daemon-runtime",
  };
}

export function buildHypervisorModelWeightCustodyAdmissionRequest(
  projection: HypervisorPrivacyPostureProjection,
  policy: HypervisorModelWeightCustodyPolicy,
  options: BuildModelWeightCustodyAdmissionRequestOptions = {},
): HypervisorModelWeightCustodyAdmissionRequest {
  const routeRef = projection.default_model_route_ref;
  const modelRef =
    options.modelRef ??
    routeRef.replace(/^model-route:/, "model:") ??
    "model:hypervisor/default";
  const common = {
    route_ref: routeRef,
    model_ref: modelRef,
    provider_ref: options.providerRef ?? "provider:hypervisor-core",
    authority_scope_refs: policy.authority_scope_refs,
    agentgres_operation_refs: [
      `agentgres://operation/privacy-posture/${safeId(projection.projection_id)}`,
    ],
    artifact_refs: [
      `artifact://privacy-posture/${safeId(projection.projection_id)}`,
    ],
  };

  if (policy.lane === "open_or_local_weights") {
    return {
      ...common,
      weight_class: "user_local_private_weight",
      mount_target: "local_device",
      execution_privacy_posture: "private_native",
      remote_provider_can_read_weights: false,
      required_controls: ["local_only"],
    };
  }

  if (policy.lane === "remote_api_capability") {
    return {
      ...common,
      provider_ref: options.providerRef ?? "provider:remote-api",
      weight_class: "remote_api_private_weight",
      mount_target: "provider_api",
      execution_privacy_posture: "remote_api_provider_trust",
      remote_provider_can_read_weights: false,
      required_controls: ["wallet_authorized_api_capability"],
    };
  }

  if (policy.lane === "tee_or_customer_cloud_mount") {
    return {
      ...common,
      provider_ref: options.providerRef ?? "provider:customer-cloud",
      weight_class: "tee_or_customer_cloud_mount",
      mount_target: options.customerBoundaryRef ? "customer_cloud" : "tee_session",
      execution_privacy_posture: "confidential_compute",
      remote_provider_can_read_weights: false,
      required_controls: options.customerBoundaryRef
        ? ["customer_account_boundary"]
        : ["tee_attestation"],
      tee_attestation_ref: options.teeAttestationRef,
      customer_boundary_ref: options.customerBoundaryRef,
    };
  }

  if (policy.lane === "provider_trust_mount") {
    return {
      ...common,
      provider_ref: options.providerRef ?? "provider:rented-gpu",
      weight_class: "provider_trust_remote_mount",
      mount_target: "rented_gpu",
      execution_privacy_posture: "unsafe_plaintext_mount",
      remote_provider_can_read_weights: true,
      required_controls: ["explicit_provider_trust_acceptance"],
      user_disclosure_ref: options.userDisclosureRef,
      provider_trust_acceptance_ref: options.providerTrustAcceptanceRef,
    };
  }

  return {
    ...common,
    provider_ref: options.providerRef ?? "provider:rented-gpu",
    weight_class: "forbidden_plaintext_mount",
    mount_target: "rented_gpu",
    execution_privacy_posture: "unsafe_plaintext_mount",
    remote_provider_can_read_weights: true,
    required_controls: ["no_remote_plaintext_mount"],
  };
}

export function normalizeHypervisorModelWeightCustodyAdmission(
  snapshot: unknown,
): HypervisorModelWeightCustodyAdmission {
  const value = objectRecord(snapshot);
  const requestFallback = buildHypervisorModelWeightCustodyAdmissionRequest(
    HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE,
    HYPERVISOR_PRIVACY_POSTURE_PROJECTION_FIXTURE.model_weight_policies[0]!,
  );
  return {
    schema_version: "ioi.runtime.model_weight_custody_admission.v1",
    admission_id: stringValue(
      value.admission_id,
      `model-weight-custody-admission:${safeId(requestFallback.route_ref)}`,
    ),
    route_ref: stringValue(value.route_ref, requestFallback.route_ref),
    model_ref: stringValue(value.model_ref, requestFallback.model_ref),
    provider_ref: stringValue(value.provider_ref, requestFallback.provider_ref),
    decision: enumValue(value.decision, "admitted", [
      "admitted",
      "admitted_provider_trust",
    ]),
    weight_class: enumValue(value.weight_class, requestFallback.weight_class, [
      "public_open_weight",
      "user_local_private_weight",
      "remote_api_private_weight",
      "provider_trust_remote_mount",
      "tee_or_customer_cloud_mount",
      "forbidden_plaintext_mount",
    ]),
    mount_target: enumValue(value.mount_target, requestFallback.mount_target, [
      "local_device",
      "user_owned_node",
      "rented_gpu",
      "customer_cloud",
      "provider_api",
      "tee_session",
      "none",
    ]),
    execution_privacy_posture: enumValue(
      value.execution_privacy_posture,
      requestFallback.execution_privacy_posture,
      [
        "private_native",
        "ctee_split",
        "encrypted_storage_only",
        "confidential_compute",
        "remote_api_provider_trust",
        "unsafe_plaintext_mount",
      ],
    ),
    remote_provider_can_read_weights: booleanValue(
      value.remote_provider_can_read_weights,
      requestFallback.remote_provider_can_read_weights,
    ),
    protects_model_weights_from_provider_root: booleanValue(
      value.protects_model_weights_from_provider_root,
      true,
    ),
    protects_workspace_state: booleanValue(value.protects_workspace_state, true),
    required_controls: stringList(
      value.required_controls,
      requestFallback.required_controls,
    ),
    authority_scope_refs: stringList(
      value.authority_scope_refs,
      requestFallback.authority_scope_refs,
    ),
    user_disclosure_ref:
      typeof value.user_disclosure_ref === "string" ? value.user_disclosure_ref : null,
    provider_trust_acceptance_ref:
      typeof value.provider_trust_acceptance_ref === "string"
        ? value.provider_trust_acceptance_ref
        : null,
    tee_attestation_ref:
      typeof value.tee_attestation_ref === "string" ? value.tee_attestation_ref : null,
    customer_boundary_ref:
      typeof value.customer_boundary_ref === "string"
        ? value.customer_boundary_ref
        : null,
    agentgres_operation_refs: stringList(
      value.agentgres_operation_refs,
      requestFallback.agentgres_operation_refs,
    ),
    artifact_refs: stringList(value.artifact_refs, requestFallback.artifact_refs),
    receipt_ref: stringValue(
      value.receipt_ref,
      `receipt://model-weight-custody/${safeId(requestFallback.route_ref)}/${safeId(requestFallback.weight_class)}`,
    ),
    admitted_at: stringValue(value.admitted_at, new Date(0).toISOString()),
    runtimeTruthSource: "daemon-runtime",
  };
}

export async function requestHypervisorModelWeightCustodyAdmission(
  projection: HypervisorPrivacyPostureProjection,
  policy: HypervisorModelWeightCustodyPolicy,
  options: RequestModelWeightCustodyAdmissionOptions = {},
): Promise<HypervisorModelWeightCustodyAdmission> {
  const action = modelWeightCustodyAdmissionAction(policy);
  if (action.state !== "daemon_admissible") {
    throw new Error(action.disabled_reason ?? "Model-weight custody admission is disabled");
  }
  const endpoint =
    options.endpoint ?? readHypervisorPrivacyPostureDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for Hypervisor model-weight custody admission");
  }
  const request = buildHypervisorModelWeightCustodyAdmissionRequest(
    projection,
    policy,
    options,
  );
  const response = await fetchImpl(
    `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_MODEL_WEIGHT_CUSTODY_ADMISSION_PATH}`,
    {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify(request),
    },
  );
  const text = await response.text();
  const value = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(
      `Model-weight custody admission request failed with ${response.status}`,
    );
  }
  return normalizeHypervisorModelWeightCustodyAdmission(value);
}

export async function loadHypervisorPrivacyPostureProjection(
  options: LoadPrivacyPostureProjectionOptions = {},
): Promise<HypervisorPrivacyPostureProjection> {
  const endpoint =
    options.endpoint ?? readHypervisorPrivacyPostureDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for Hypervisor privacy posture projection");
  }
  const url = new URL(
    `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_PRIVACY_POSTURE_PROJECTION_PATH}`,
  );
  if (options.projectId) url.searchParams.set("project_id", options.projectId);
  if (options.sessionRef) url.searchParams.set("session_ref", options.sessionRef);
  const response = await fetchImpl(url.toString(), {
    method: "GET",
    headers: { accept: "application/json" },
  });
  const text = await response.text();
  const value = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(
      `Privacy posture projection request failed with ${response.status}`,
    );
  }
  return normalizeHypervisorPrivacyPostureProjection(value, {
    source: options.source ?? "daemon-privacy-posture-projection",
  });
}
