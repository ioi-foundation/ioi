import { runtimeError } from "./runtime-http-utils.mjs";
import {
  booleanValue,
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
} from "./runtime-value-helpers.mjs";

export const WORKER_PACKAGE_INSTALL_ADMISSION_SCHEMA_VERSION =
  "ioi.runtime.worker_package_install_admission.v1";

const INSTALL_MODES = new Set([
  "local_hypervisor_install",
  "managed_instance_initialization",
  "api_worker_binding",
  "workflow_node_install",
]);

const RUNTIME_PROFILES = new Set([
  "local",
  "hosted",
  "provider",
  "depin",
  "private_workspace_ctee",
  "tee",
  "customer_vpc",
]);

const PERSISTENCE_PROFILES = new Set([
  "ephemeral",
  "session",
  "zero_to_idle",
  "persistent",
]);

const RETIRED_ALIASES = [
  "installId",
  "workerPackageRef",
  "workerManifestRef",
  "ownerRef",
  "baseOntologyRef",
  "verticalPackRefs",
  "integrationSurfaceRefs",
  "primitiveCapabilityRequirements",
  "authorityScopeRequirements",
  "agentgresOperationRefs",
  "receiptRefs",
];

export function admitWorkerPackageInstall(request = {}, deps = {}) {
  assertNoRetiredAliases(request);

  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const installId = requiredString(request.install_id, "install_id");
  const workerPackageRef = requiredString(
    request.worker_package_ref,
    "worker_package_ref",
  );
  const workerManifestRef = requiredString(
    request.worker_manifest_ref,
    "worker_manifest_ref",
  );
  const ownerRef = requiredString(request.owner_ref, "owner_ref");
  const installMode = enumValue(request.install_mode, "install_mode", INSTALL_MODES);
  const baseOntologyRef = requiredString(
    request.base_ontology_ref,
    "base_ontology_ref",
  );
  const verticalPackRefs = uniqueStrings(normalizeArray(request.vertical_pack_refs));
  const integrationSurfaceRefs = uniqueStrings(
    normalizeArray(request.integration_surface_refs),
  );
  const primitiveCapabilityRequirements = uniqueStrings(
    normalizeArray(request.primitive_capability_requirements),
  );
  const authorityScopeRequirements = uniqueStrings(
    normalizeArray(request.authority_scope_requirements),
  );
  const riskClasses = uniqueStrings(normalizeArray(request.risk_classes));
  const policyProfileRefs = uniqueStrings(normalizeArray(request.policy_profile_refs));
  const receiptPolicyRef = requiredString(
    request.receipt_policy_ref,
    "receipt_policy_ref",
  );
  const evidenceRequirementRefs = uniqueStrings(
    normalizeArray(request.evidence_requirement_refs),
  );
  const benchmarkProfileRefs = uniqueStrings(
    normalizeArray(request.benchmark_profile_refs),
  );
  const runtimeProfile = enumValue(
    request.runtime_profile,
    "runtime_profile",
    RUNTIME_PROFILES,
  );
  const persistenceProfile = enumValue(
    request.persistence_profile,
    "persistence_profile",
    PERSISTENCE_PROFILES,
  );
  const memoryPolicyRef = optionalString(request.memory_policy_ref) ?? null;
  const archivePolicyRef = optionalString(request.archive_policy_ref) ?? null;
  const packageArtifactRefs = uniqueStrings(
    normalizeArray(request.package_artifact_refs),
  );
  const walletApprovalRef = optionalString(request.wallet_approval_ref) ?? null;
  const installRightRef = optionalString(request.install_right_ref) ?? null;
  const managedInstanceRef = optionalString(request.managed_instance_ref) ?? null;
  const physicalActionPolicyRefs = uniqueStrings(
    normalizeArray(request.physical_action_policy_refs),
  );
  const safetyEnvelopeRefs = uniqueStrings(normalizeArray(request.safety_envelope_refs));
  const emergencyStopAuthorityRefs = uniqueStrings(
    normalizeArray(request.emergency_stop_authority_refs),
  );
  const agentgresOperationRefs = uniqueStrings(
    normalizeArray(request.agentgres_operation_refs),
  );
  const receiptRefs = uniqueStrings(normalizeArray(request.receipt_refs));
  const stateRoot = optionalString(request.state_root) ?? null;
  const hardcodedVerticalRuntime =
    booleanValue(request.hardcoded_vertical_runtime) ?? false;

  assertWorkerPackageInstall({
    installId,
    workerPackageRef,
    workerManifestRef,
    ownerRef,
    installMode,
    baseOntologyRef,
    verticalPackRefs,
    integrationSurfaceRefs,
    primitiveCapabilityRequirements,
    authorityScopeRequirements,
    riskClasses,
    policyProfileRefs,
    receiptPolicyRef,
    evidenceRequirementRefs,
    runtimeProfile,
    persistenceProfile,
    memoryPolicyRef,
    archivePolicyRef,
    packageArtifactRefs,
    walletApprovalRef,
    installRightRef,
    managedInstanceRef,
    physicalActionPolicyRefs,
    safetyEnvelopeRefs,
    emergencyStopAuthorityRefs,
    agentgresOperationRefs,
    receiptRefs,
    hardcodedVerticalRuntime,
  });

  const admissionId =
    optionalString(request.admission_id) ??
    `worker-package-install:${safeId(installId)}:${safeId(installMode)}`;

  return {
    schema_version: WORKER_PACKAGE_INSTALL_ADMISSION_SCHEMA_VERSION,
    admission_id: admissionId,
    install_id: installId,
    worker_package_ref: workerPackageRef,
    worker_manifest_ref: workerManifestRef,
    owner_ref: ownerRef,
    install_mode: installMode,
    base_ontology_ref: baseOntologyRef,
    vertical_pack_refs: verticalPackRefs,
    integration_surface_refs: integrationSurfaceRefs,
    primitive_capability_requirements: primitiveCapabilityRequirements,
    authority_scope_requirements: authorityScopeRequirements,
    risk_classes: riskClasses,
    policy_profile_refs: policyProfileRefs,
    receipt_policy_ref: receiptPolicyRef,
    evidence_requirement_refs: evidenceRequirementRefs,
    benchmark_profile_refs: benchmarkProfileRefs,
    runtime_profile: runtimeProfile,
    persistence_profile: persistenceProfile,
    memory_policy_ref: memoryPolicyRef,
    archive_policy_ref: archivePolicyRef,
    package_artifact_refs: packageArtifactRefs,
    wallet_approval_ref: walletApprovalRef,
    install_right_ref: installRightRef,
    managed_instance_ref: managedInstanceRef,
    physical_action_policy_refs: physicalActionPolicyRefs,
    safety_envelope_refs: safetyEnvelopeRefs,
    emergency_stop_authority_refs: emergencyStopAuthorityRefs,
    agentgres_operation_refs: agentgresOperationRefs,
    receipt_refs: receiptRefs,
    state_root: stateRoot,
    decision: "admitted",
    requiresDaemonGate: true,
    runtimeTruthSource: "daemon-runtime",
    admitted_at: optionalString(request.admitted_at) ?? nowIso(),
  };
}

function assertWorkerPackageInstall({
  installId,
  workerPackageRef,
  workerManifestRef,
  ownerRef,
  installMode,
  baseOntologyRef,
  verticalPackRefs,
  integrationSurfaceRefs,
  primitiveCapabilityRequirements,
  authorityScopeRequirements,
  riskClasses,
  policyProfileRefs,
  receiptPolicyRef,
  evidenceRequirementRefs,
  runtimeProfile,
  persistenceProfile,
  memoryPolicyRef,
  archivePolicyRef,
  packageArtifactRefs,
  walletApprovalRef,
  installRightRef,
  managedInstanceRef,
  physicalActionPolicyRefs,
  safetyEnvelopeRefs,
  emergencyStopAuthorityRefs,
  agentgresOperationRefs,
  receiptRefs,
  hardcodedVerticalRuntime,
}) {
  requirePrefix(installId, "install://", "install_id");
  requirePrefix(workerPackageRef, "package://", "worker_package_ref");
  requireManifestRef(workerManifestRef);
  requireOwnerRef(ownerRef);
  requirePrefix(baseOntologyRef, "ontology:", "base_ontology_ref");
  requireRefs(integrationSurfaceRefs, "integration_surface_refs");
  integrationSurfaceRefs.forEach((ref) =>
    requirePrefix(ref, "integration_surface:", "integration_surface_refs"),
  );
  requireRefs(primitiveCapabilityRequirements, "primitive_capability_requirements");
  primitiveCapabilityRequirements.forEach((ref) =>
    requirePrefix(ref, "prim:", "primitive_capability_requirements"),
  );
  requireRefs(authorityScopeRequirements, "authority_scope_requirements");
  if (authorityScopeRequirements.some((ref) => ref.startsWith("prim:"))) {
    throw admissionError({
      code: "worker_package_install_primitive_scope_masquerade_blocked",
      message:
        "Worker package installs must not treat prim:* execution capabilities as wallet authority scopes.",
      details: { authority_scope_requirements: authorityScopeRequirements },
    });
  }
  authorityScopeRequirements.forEach((ref) =>
    requirePrefix(ref, "scope:", "authority_scope_requirements"),
  );
  if (hardcodedVerticalRuntime) {
    throw admissionError({
      code: "worker_package_install_vertical_runtime_fork_blocked",
      message:
        "Vertical packs extend ontology and policy; they must not fork Hypervisor Daemon runtime truth.",
      details: { hardcoded_vertical_runtime: hardcodedVerticalRuntime },
    });
  }
  requireRefs(policyProfileRefs, "policy_profile_refs");
  policyProfileRefs.forEach((ref) =>
    requirePrefix(ref, "policy://", "policy_profile_refs"),
  );
  requirePrefix(receiptPolicyRef, "receipt_policy://", "receipt_policy_ref");
  requireRefs(evidenceRequirementRefs, "evidence_requirement_refs");
  evidenceRequirementRefs.forEach((ref) =>
    requirePrefix(ref, "evidence_requirement:", "evidence_requirement_refs"),
  );
  requireRefs(packageArtifactRefs, "package_artifact_refs");
  packageArtifactRefs.forEach((ref) =>
    requirePrefix(ref, "artifact://", "package_artifact_refs"),
  );
  requireRefs(agentgresOperationRefs, "agentgres_operation_refs");
  requireRefs(receiptRefs, "receipt_refs");
  if (!walletApprovalRef) {
    throw admissionError({
      code: "worker_package_install_wallet_approval_required",
      message: "Worker package install admission requires wallet.network approval.",
      details: { wallet_approval_ref: walletApprovalRef },
    });
  }
  if (installMode !== "workflow_node_install" && !installRightRef) {
    throw admissionError({
      code: "worker_package_install_right_ref_required",
      message:
        "Worker package install admission requires an install/license right except for workflow-node-only bindings.",
      details: { install_mode: installMode },
    });
  }
  if (installMode === "managed_instance_initialization" && !managedInstanceRef) {
    throw admissionError({
      code: "worker_package_install_managed_instance_ref_required",
      message:
        "Managed worker initialization requires a managed_instance_ref.",
      details: { install_mode: installMode },
    });
  }
  if (["zero_to_idle", "persistent"].includes(persistenceProfile)) {
    if (!memoryPolicyRef || !archivePolicyRef) {
      throw admissionError({
        code: "worker_package_install_persistence_policy_required",
        message:
          "Zero-to-idle and persistent installs require memory and archive policy refs.",
        details: { persistence_profile: persistenceProfile },
      });
    }
  }
  if (memoryPolicyRef) requirePrefix(memoryPolicyRef, "policy://", "memory_policy_ref");
  if (archivePolicyRef) requirePrefix(archivePolicyRef, "policy://", "archive_policy_ref");
  if (installRightRef) requirePrefix(installRightRef, "license://", "install_right_ref");
  if (managedInstanceRef) {
    requirePrefix(managedInstanceRef, "agent://", "managed_instance_ref");
  }
  if (riskClasses.includes("physical_action")) {
    requireRefs(verticalPackRefs, "vertical_pack_refs");
    requireRefs(physicalActionPolicyRefs, "physical_action_policy_refs");
    requireRefs(safetyEnvelopeRefs, "safety_envelope_refs");
    requireRefs(emergencyStopAuthorityRefs, "emergency_stop_authority_refs");
  }
  verticalPackRefs.forEach((ref) =>
    requirePrefix(ref, "vertical_pack:", "vertical_pack_refs"),
  );
  physicalActionPolicyRefs.forEach((ref) =>
    requirePrefix(ref, "policy://", "physical_action_policy_refs"),
  );
  safetyEnvelopeRefs.forEach((ref) =>
    requirePrefix(ref, "safety://", "safety_envelope_refs"),
  );
  emergencyStopAuthorityRefs.forEach((ref) =>
    requirePrefix(ref, "estop://", "emergency_stop_authority_refs"),
  );
  if (
    runtimeProfile === "private_workspace_ctee" &&
    !policyProfileRefs.some((ref) => ref.includes("ctee"))
  ) {
    throw admissionError({
      code: "worker_package_install_ctee_policy_required",
      message:
        "Private Workspace cTEE installs require an explicit cTEE policy profile ref.",
      details: { runtime_profile: runtimeProfile },
    });
  }
}

function requireRefs(refs, field) {
  if (refs.length > 0) return;
  throw admissionError({
    code: `worker_package_install_${field}_required`,
    message: `Worker package install admission requires ${field}.`,
    details: { field },
  });
}

function requireManifestRef(value) {
  if (value.startsWith("manifest://") || value.startsWith("artifact://")) return;
  throw runtimeError({
    status: 400,
    code: "worker_package_install_worker_manifest_ref_invalid",
    message:
      "Worker package install worker_manifest_ref must identify a manifest or artifact ref.",
    details: { worker_manifest_ref: value },
  });
}

function requireOwnerRef(value) {
  const prefixes = ["wallet://", "org://", "project://"];
  if (prefixes.some((prefix) => value.startsWith(prefix))) return;
  throw runtimeError({
    status: 400,
    code: "worker_package_install_owner_ref_invalid",
    message:
      "Worker package install owner_ref must identify a wallet, organization, or project.",
    details: { owner_ref: value, allowed_prefixes: prefixes },
  });
}

function requirePrefix(value, prefix, field) {
  if (value.startsWith(prefix)) return;
  throw runtimeError({
    status: 400,
    code: `worker_package_install_${field}_invalid`,
    message: `Worker package install ${field} must start with ${prefix}.`,
    details: { [field]: value },
  });
}

function assertNoRetiredAliases(request = {}) {
  const body = objectRecord(request) ?? {};
  const retired = RETIRED_ALIASES.filter((field) => Object.hasOwn(body, field));
  if (retired.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "worker_package_install_request_aliases_retired",
    message:
      "Worker package install admission accepts only canonical snake_case request fields.",
    details: { retired_aliases: retired },
  });
}

function enumValue(value, field, allowedValues) {
  const normalized = optionalString(value);
  if (!normalized || !allowedValues.has(normalized)) {
    throw runtimeError({
      status: 400,
      code: `worker_package_install_${field}_invalid`,
      message: `Worker package install admission requires a valid ${field}.`,
      details: {
        [field]: normalized ?? null,
        allowed_values: [...allowedValues],
      },
    });
  }
  return normalized;
}

function requiredString(value, field) {
  const normalized = optionalString(value);
  if (!normalized) {
    throw runtimeError({
      status: 400,
      code: `worker_package_install_${field}_required`,
      message: `Worker package install admission requires ${field}.`,
      details: { field },
    });
  }
  return normalized;
}

function uniqueStrings(values) {
  return [...new Set(values.map((value) => String(value)).filter(Boolean))];
}

function admissionError(error) {
  return runtimeError({ status: 403, ...error });
}
