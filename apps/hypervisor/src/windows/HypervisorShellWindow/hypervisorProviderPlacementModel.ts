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

export type HypervisorProviderOperationKind =
  | "request_access_lease"
  | "launch_session"
  | "zero_to_idle"
  | "archive"
  | "restore";

export type HypervisorProviderOperationAdmissionState =
  | "requires_wallet_lease"
  | "ready_for_daemon_admission"
  | "blocked";

export interface HypervisorProviderOperationProposal {
  schema_version: "ioi.hypervisor.provider_operation_proposal.v1";
  proposal_ref: string;
  source: "daemon-provider-operation-proposal" | "fixture" | "unverified";
  project_ref: string;
  candidate_ref: string;
  direct_provider_ref: string;
  operation_kind: HypervisorProviderOperationKind;
  admission_state: HypervisorProviderOperationAdmissionState;
  wallet_lease_ref: string;
  required_scope_refs: string[];
  agentgres_operation_ref: string;
  receipt_ref: string;
  state_root_ref: string;
  archive_ref: string;
  restore_ref: string;
  custody_invariant: string;
}

export interface HypervisorProviderPlacementProjection {
  schema_version: "ioi.hypervisor.provider_placement_projection.v1";
  projection_id: string;
  source: "daemon-provider-placement-projection" | "fixture" | "unverified";
  selected_project_ref: string;
  candidates: HypervisorProviderPlacementCandidate[];
  anti_gateway_invariant: string;
  runtimeTruthSource: "daemon-runtime";
}

export const HYPERVISOR_PROVIDER_PLACEMENT_DAEMON_ENDPOINT_STORAGE_KEY =
  "ioi.hypervisor.daemonEndpoint";
export const HYPERVISOR_PROVIDER_PLACEMENT_DEFAULT_DAEMON_ENDPOINT =
  "http://127.0.0.1:8765";
export const HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_PATH =
  "/v1/hypervisor/provider-placement";
export const HYPERVISOR_PROVIDER_OPERATION_PROPOSAL_PATH =
  "/v1/hypervisor/provider-operations";

export const HYPERVISOR_PROVIDER_OPERATION_KINDS: readonly HypervisorProviderOperationKind[] =
  [
    "request_access_lease",
    "launch_session",
    "zero_to_idle",
    "archive",
    "restore",
  ];

type FetchLike = (
  input: string,
  init?: { method?: string; headers?: Record<string, string>; body?: string },
) => Promise<{
  ok: boolean;
  status: number;
  text(): Promise<string>;
}>;

interface NormalizeProviderPlacementProjectionOptions {
  source?: HypervisorProviderPlacementProjection["source"];
}

interface LoadProviderPlacementProjectionOptions
  extends NormalizeProviderPlacementProjectionOptions {
  endpoint?: string;
  fetchImpl?: FetchLike;
  projectId?: string | null;
}

interface NormalizeProviderOperationProposalOptions {
  candidate?: HypervisorProviderPlacementCandidate;
  operationKind?: HypervisorProviderOperationKind;
  projectRef?: string;
  source?: HypervisorProviderOperationProposal["source"];
}

interface ProposeProviderOperationOptions
  extends NormalizeProviderOperationProposalOptions {
  candidate: HypervisorProviderPlacementCandidate;
  endpoint?: string;
  fetchImpl?: FetchLike;
  operationKind: HypervisorProviderOperationKind;
  projectRef: string;
}

export const HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE: HypervisorProviderPlacementProjection =
  {
    schema_version: "ioi.hypervisor.provider_placement_projection.v1",
    projection_id: "provider-placement:hypervisor-core/default",
    source: "fixture",
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
  if (!Array.isArray(value)) {
    return fallback;
  }
  const values = value
    .filter((item): item is string => typeof item === "string" && !!item.trim())
    .map((item) => item.trim());
  return values.length > 0 ? values : fallback;
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

function operationKindValue(
  value: unknown,
  fallback: HypervisorProviderOperationKind,
): HypervisorProviderOperationKind {
  return enumValue(value, fallback, HYPERVISOR_PROVIDER_OPERATION_KINDS);
}

function normalizeProviderPlacementCandidate(
  item: Record<string, unknown>,
  index: number,
): HypervisorProviderPlacementCandidate {
  const fallback =
    HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE.candidates[index] ??
    HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE.candidates[0]!;
  return {
    candidate_ref: stringValue(item.candidate_ref, fallback.candidate_ref),
    label: stringValue(item.label, fallback.label),
    integration_kind: enumValue(item.integration_kind, fallback.integration_kind, [
      "local_machine",
      "customer_cloud",
      "hyperscaler_confidential",
      "depin_compute",
      "decentralized_storage",
      "gpu_market",
    ]),
    direct_provider_ref: stringValue(
      item.direct_provider_ref,
      fallback.direct_provider_ref,
    ),
    workload_fit: stringValue(item.workload_fit, fallback.workload_fit),
    privacy_posture: enumValue(item.privacy_posture, fallback.privacy_posture, [
      "local_custody",
      "customer_controlled",
      "confidential_compute",
      "ctee_split_required",
      "encrypted_storage_only",
      "provider_trust",
    ]),
    wallet_authority_scope_refs: stringList(
      item.wallet_authority_scope_refs,
      fallback.wallet_authority_scope_refs,
    ),
    agentgres_receipt_ref: stringValue(
      item.agentgres_receipt_ref,
      fallback.agentgres_receipt_ref,
    ),
    storage_policy_ref: stringValue(
      item.storage_policy_ref,
      fallback.storage_policy_ref,
    ),
    restore_policy_ref: stringValue(
      item.restore_policy_ref,
      fallback.restore_policy_ref,
    ),
    risk_labels: stringList(item.risk_labels, fallback.risk_labels),
  };
}

export function readHypervisorProviderPlacementDaemonEndpoint(): string {
  try {
    if (typeof window === "undefined") {
      return HYPERVISOR_PROVIDER_PLACEMENT_DEFAULT_DAEMON_ENDPOINT;
    }
    return (
      window.localStorage.getItem(
        HYPERVISOR_PROVIDER_PLACEMENT_DAEMON_ENDPOINT_STORAGE_KEY,
      ) || HYPERVISOR_PROVIDER_PLACEMENT_DEFAULT_DAEMON_ENDPOINT
    );
  } catch {
    return HYPERVISOR_PROVIDER_PLACEMENT_DEFAULT_DAEMON_ENDPOINT;
  }
}

export function normalizeHypervisorProviderPlacementProjection(
  snapshot: unknown,
  options: NormalizeProviderPlacementProjectionOptions = {},
): HypervisorProviderPlacementProjection {
  const value = objectRecord(snapshot);
  const fallback = HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE;
  const candidates = arrayOf(value.candidates).map(
    normalizeProviderPlacementCandidate,
  );
  return {
    schema_version: "ioi.hypervisor.provider_placement_projection.v1",
    projection_id: stringValue(value.projection_id, fallback.projection_id),
    source: options.source ?? "daemon-provider-placement-projection",
    selected_project_ref: stringValue(
      value.selected_project_ref,
      fallback.selected_project_ref,
    ),
    candidates: candidates.length > 0 ? candidates : fallback.candidates,
    anti_gateway_invariant: stringValue(
      value.anti_gateway_invariant,
      fallback.anti_gateway_invariant,
    ),
    runtimeTruthSource: "daemon-runtime",
  };
}

export async function loadHypervisorProviderPlacementProjection(
  options: LoadProviderPlacementProjectionOptions = {},
): Promise<HypervisorProviderPlacementProjection> {
  const endpoint =
    options.endpoint ?? readHypervisorProviderPlacementDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for Hypervisor provider placement projection");
  }
  const query = new URLSearchParams();
  if (options.projectId) {
    query.set("project_id", options.projectId);
  }
  const suffix = query.toString() ? `?${query.toString()}` : "";
  const url = `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_PATH}${suffix}`;
  const response = await fetchImpl(url, {
    method: "GET",
    headers: { accept: "application/json" },
  });
  const text = await response.text();
  const value = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(
      `Provider placement projection request failed with ${response.status}`,
    );
  }
  return normalizeHypervisorProviderPlacementProjection(value, {
    source: options.source ?? "daemon-provider-placement-projection",
  });
}

export function buildHypervisorProviderOperationProposal(
  candidate: HypervisorProviderPlacementCandidate,
  operationKind: HypervisorProviderOperationKind,
  options: {
    projectRef?: string;
    source?: HypervisorProviderOperationProposal["source"];
  } = {},
): HypervisorProviderOperationProposal {
  const projectRef =
    options.projectRef ??
    HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE.selected_project_ref;
  return {
    schema_version: "ioi.hypervisor.provider_operation_proposal.v1",
    proposal_ref: `provider-operation:${operationKind}/${candidate.candidate_ref}`,
    source: options.source ?? "fixture",
    project_ref: projectRef,
    candidate_ref: candidate.candidate_ref,
    direct_provider_ref: candidate.direct_provider_ref,
    operation_kind: operationKind,
    admission_state:
      operationKind === "request_access_lease"
        ? "requires_wallet_lease"
        : "ready_for_daemon_admission",
    wallet_lease_ref: `lease:wallet/provider/${candidate.candidate_ref}/${operationKind}`,
    required_scope_refs: candidate.wallet_authority_scope_refs,
    agentgres_operation_ref: `agentgres://operation/provider/${candidate.candidate_ref}/${operationKind}`,
    receipt_ref: `receipt://provider/${candidate.candidate_ref}/${operationKind}`,
    state_root_ref: `agentgres://state-root/provider/${candidate.candidate_ref}`,
    archive_ref: candidate.storage_policy_ref,
    restore_ref: candidate.restore_policy_ref,
    custody_invariant:
      "Provider operations are proposals until wallet.network grants a scoped lease and Agentgres admits the lifecycle operation, receipt, archive, restore, and state-root refs.",
  };
}

export function normalizeHypervisorProviderOperationProposal(
  snapshot: unknown,
  options: NormalizeProviderOperationProposalOptions = {},
): HypervisorProviderOperationProposal {
  const fallbackCandidate =
    options.candidate ??
    HYPERVISOR_PROVIDER_PLACEMENT_PROJECTION_FIXTURE.candidates[0]!;
  const fallback = buildHypervisorProviderOperationProposal(
    fallbackCandidate,
    options.operationKind ?? "request_access_lease",
    {
      projectRef: options.projectRef,
      source: options.source ?? "daemon-provider-operation-proposal",
    },
  );
  const value = objectRecord(snapshot);
  return {
    schema_version: "ioi.hypervisor.provider_operation_proposal.v1",
    proposal_ref: stringValue(value.proposal_ref, fallback.proposal_ref),
    source: enumValue(value.source, fallback.source, [
      "daemon-provider-operation-proposal",
      "fixture",
      "unverified",
    ]),
    project_ref: stringValue(value.project_ref, fallback.project_ref),
    candidate_ref: stringValue(value.candidate_ref, fallback.candidate_ref),
    direct_provider_ref: stringValue(
      value.direct_provider_ref,
      fallback.direct_provider_ref,
    ),
    operation_kind: operationKindValue(
      value.operation_kind,
      fallback.operation_kind,
    ),
    admission_state: enumValue(value.admission_state, fallback.admission_state, [
      "requires_wallet_lease",
      "ready_for_daemon_admission",
      "blocked",
    ]),
    wallet_lease_ref: stringValue(value.wallet_lease_ref, fallback.wallet_lease_ref),
    required_scope_refs: stringList(
      value.required_scope_refs,
      fallback.required_scope_refs,
    ),
    agentgres_operation_ref: stringValue(
      value.agentgres_operation_ref,
      fallback.agentgres_operation_ref,
    ),
    receipt_ref: stringValue(value.receipt_ref, fallback.receipt_ref),
    state_root_ref: stringValue(value.state_root_ref, fallback.state_root_ref),
    archive_ref: stringValue(value.archive_ref, fallback.archive_ref),
    restore_ref: stringValue(value.restore_ref, fallback.restore_ref),
    custody_invariant: stringValue(
      value.custody_invariant,
      fallback.custody_invariant,
    ),
  };
}

export async function proposeHypervisorProviderOperation(
  options: ProposeProviderOperationOptions,
): Promise<HypervisorProviderOperationProposal> {
  const endpoint =
    options.endpoint ?? readHypervisorProviderPlacementDaemonEndpoint();
  const fetchImpl = options.fetchImpl ?? globalThis.fetch?.bind(globalThis);
  if (!fetchImpl) {
    throw new Error("fetch unavailable for Hypervisor provider operation proposal");
  }
  const response = await fetchImpl(
    `${endpoint.replace(/\/+$/, "")}${HYPERVISOR_PROVIDER_OPERATION_PROPOSAL_PATH}`,
    {
      method: "POST",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        project_ref: options.projectRef,
        candidate_ref: options.candidate.candidate_ref,
        direct_provider_ref: options.candidate.direct_provider_ref,
        operation_kind: options.operationKind,
        wallet_authority_scope_refs:
          options.candidate.wallet_authority_scope_refs,
        storage_policy_ref: options.candidate.storage_policy_ref,
        restore_policy_ref: options.candidate.restore_policy_ref,
      }),
    },
  );
  const text = await response.text();
  const value = text ? JSON.parse(text) : {};
  if (!response.ok) {
    throw new Error(
      `Provider operation proposal request failed with ${response.status}`,
    );
  }
  return normalizeHypervisorProviderOperationProposal(value, {
    candidate: options.candidate,
    operationKind: options.operationKind,
    projectRef: options.projectRef,
    source: options.source ?? "daemon-provider-operation-proposal",
  });
}
