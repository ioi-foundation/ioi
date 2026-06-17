export type HypervisorProviderIntegrationKind =
  | "local_machine"
  | "customer_cloud"
  | "hyperscaler_confidential"
  | "depin_compute"
  | "decentralized_storage"
  | "gpu_market";

export type HypervisorProviderPrivacyPosture =
  | "local_custody"
  | "customer_controlled"
  | "confidential_compute"
  | "ctee_split_required"
  | "encrypted_storage_only"
  | "provider_trust";

export interface HypervisorProviderPlacementCandidate {
  candidate_ref: string;
  label: string;
  integration_kind: HypervisorProviderIntegrationKind;
  direct_provider_ref: string;
  workload_fit: string;
  privacy_posture: HypervisorProviderPrivacyPosture;
  wallet_authority_scope_refs: string[];
  agentgres_receipt_ref: string;
  storage_policy_ref: string;
  restore_policy_ref: string;
  risk_labels: string[];
}

export interface HypervisorProviderPlacementProjection {
  schema_version: "ioi.hypervisor.provider_placement_projection.v1";
  projection_id: string;
  selected_project_ref: string;
  candidates: HypervisorProviderPlacementCandidate[];
  anti_gateway_invariant: string;
  runtimeTruthSource: "daemon-runtime";
}

export const HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE: HypervisorProviderPlacementProjection =
  {
    schema_version: "ioi.hypervisor.provider_placement_projection.v1",
    projection_id: "provider-placement:hypervisor-core/default",
    selected_project_ref: "project:hypervisor-core",
    anti_gateway_invariant:
      "Hypervisor integrates providers directly; route catalogs may suggest candidates, but wallet.network authorizes spend/secret release and Agentgres records admitted truth.",
    candidates: [
      {
        candidate_ref: "provider-candidate:local-workstation",
        label: "Local workstation",
        integration_kind: "local_machine",
        direct_provider_ref: "provider:local-workstation",
        workload_fit: "Private work, local model mounts, low-latency Workbench sessions.",
        privacy_posture: "local_custody",
        wallet_authority_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
        agentgres_receipt_ref: "receipt://provider/local-workstation/placement",
        storage_policy_ref: "storage-policy:local-encrypted-agentgres-refs",
        restore_policy_ref: "agentgres://restore/local-workstation/latest",
        risk_labels: ["Local custody", "No provider root"],
      },
      {
        candidate_ref: "provider-candidate:customer-gcp-confidential",
        label: "Customer GCP confidential VM",
        integration_kind: "hyperscaler_confidential",
        direct_provider_ref: "provider:gcp/confidential-vm",
        workload_fit: "TEE-backed private compute when the user accepts cloud attestation.",
        privacy_posture: "confidential_compute",
        wallet_authority_scope_refs: ["scope:cloud.deploy", "scope:secret.release"],
        agentgres_receipt_ref: "receipt://provider/gcp-confidential/placement",
        storage_policy_ref: "storage-policy:customer-cloud-encrypted-blobs",
        restore_policy_ref: "agentgres://restore/gcp-confidential/latest",
        risk_labels: ["Cloud TEE assumptions", "Customer account"],
      },
      {
        candidate_ref: "provider-candidate:aws-nitro-control-plane",
        label: "AWS Nitro control plane",
        integration_kind: "hyperscaler_confidential",
        direct_provider_ref: "provider:aws/nitro-enclave",
        workload_fit: "Key-sensitive control plane, release policy, and verifier support.",
        privacy_posture: "confidential_compute",
        wallet_authority_scope_refs: ["scope:cloud.deploy", "scope:secret.release"],
        agentgres_receipt_ref: "receipt://provider/aws-nitro/placement",
        storage_policy_ref: "storage-policy:customer-cloud-encrypted-blobs",
        restore_policy_ref: "agentgres://restore/aws-nitro/latest",
        risk_labels: ["Cloud TEE assumptions", "GPU path separate"],
      },
      {
        candidate_ref: "provider-candidate:akash-gpu",
        label: "Akash GPU provider",
        integration_kind: "depin_compute",
        direct_provider_ref: "provider:akash/gpu-market",
        workload_fit: "Cheap public or redacted compute, harness smoke tests, public jobs.",
        privacy_posture: "ctee_split_required",
        wallet_authority_scope_refs: ["scope:provider.spend", "scope:receipt.write"],
        agentgres_receipt_ref: "receipt://provider/akash/placement",
        storage_policy_ref: "storage-policy:agentgres-encrypted-refs-only",
        restore_policy_ref: "agentgres://restore/akash/latest",
        risk_labels: ["Provider root expected", "No plaintext custody"],
      },
      {
        candidate_ref: "provider-candidate:filecoin-archive",
        label: "Filecoin encrypted archive",
        integration_kind: "decentralized_storage",
        direct_provider_ref: "provider:filecoin/storage",
        workload_fit: "Durable encrypted archive bytes and payload availability.",
        privacy_posture: "encrypted_storage_only",
        wallet_authority_scope_refs: ["scope:storage.write", "scope:archive.restore"],
        agentgres_receipt_ref: "receipt://provider/filecoin/archive-placement",
        storage_policy_ref: "storage-policy:agentgres-artifact-ref-plane",
        restore_policy_ref: "agentgres://restore/filecoin-archive/latest",
        risk_labels: ["Storage backend only", "Agentgres restore truth"],
      },
      {
        candidate_ref: "provider-candidate:gpu-market",
        label: "GPU market provider",
        integration_kind: "gpu_market",
        direct_provider_ref: "provider:gpu-market/generic",
        workload_fit: "Burst public inference, evals, and redacted batch jobs.",
        privacy_posture: "provider_trust",
        wallet_authority_scope_refs: ["scope:provider.spend"],
        agentgres_receipt_ref: "receipt://provider/gpu-market/placement",
        storage_policy_ref: "storage-policy:redacted-projection-only",
        restore_policy_ref: "agentgres://restore/gpu-market/latest",
        risk_labels: ["Provider trust", "Use only with public or redacted state"],
      },
    ],
    runtimeTruthSource: "daemon-runtime",
  };
