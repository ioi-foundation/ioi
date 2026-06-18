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

export interface HypervisorPrivacyPostureProjection {
  schema_version: "ioi.hypervisor.execution_privacy_posture_projection.v1";
  projection_id: string;
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
