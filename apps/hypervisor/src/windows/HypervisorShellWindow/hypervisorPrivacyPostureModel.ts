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

type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string> },
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
