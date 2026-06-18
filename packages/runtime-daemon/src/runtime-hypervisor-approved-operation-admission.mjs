import { runtimeError } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

export const HYPERVISOR_APPROVED_OPERATION_ADMISSION_SCHEMA_VERSION =
  "ioi.runtime.hypervisor_approved_operation_admission.v1";

const OPERATION_FAMILIES = new Set(["session", "provider"]);

const PROPOSAL_SCHEMA_BY_FAMILY = new Map([
  ["session", "ioi.hypervisor.session_operation_proposal.v1"],
  ["provider", "ioi.hypervisor.provider_operation_proposal.v1"],
]);

const PROPOSAL_SOURCE_BY_FAMILY = new Map([
  ["session", "daemon-session-operation-proposal"],
  ["provider", "daemon-provider-operation-proposal"],
]);

const RETIRED_ALIASES = [
  "operationFamily",
  "proposalRef",
  "proposalSchemaVersion",
  "proposalSource",
  "walletApprovalRef",
  "walletLeaseRef",
  "requiredScopeRefs",
  "agentgresOperationRefs",
  "receiptRefs",
  "stateRootRef",
  "archiveRef",
  "restoreRef",
];

const ARCHIVE_REQUIRED_OPERATIONS = new Set([
  "archive",
  "archive_session",
  "restore",
  "restore_session",
  "zero_to_idle",
]);

const RESTORE_REQUIRED_OPERATIONS = new Set(["restore", "restore_session"]);

export function admitHypervisorApprovedOperation(request = {}, deps = {}) {
  assertNoRetiredAliases(request);

  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const operationFamily = enumValue(
    request.operation_family,
    "operation_family",
    OPERATION_FAMILIES,
  );
  const proposalSchemaVersion = requiredString(
    request.proposal_schema_version,
    "proposal_schema_version",
  );
  const proposalSource = requiredString(
    request.proposal_source ?? request.source,
    "proposal_source",
  );
  assertDaemonProposalBoundary({
    operationFamily,
    proposalSchemaVersion,
    proposalSource,
  });

  const proposalRef = requiredString(request.proposal_ref, "proposal_ref");
  const projectRef = requiredString(request.project_ref, "project_ref");
  const operationKind = requiredString(request.operation_kind, "operation_kind");
  const walletApprovalRef = prefixedString(
    request.wallet_approval_ref,
    "wallet_approval_ref",
    "approval://wallet/",
    403,
  );
  const walletLeaseRef = prefixedString(
    request.wallet_lease_ref,
    "wallet_lease_ref",
    "lease:",
    403,
  );
  const requiredScopeRefs = prefixedRefs(
    request.required_scope_refs,
    "required_scope_refs",
    "scope:",
    { status: 403 },
  );
  const authorityReceiptRefs = prefixedRefs(
    request.authority_receipt_refs,
    "authority_receipt_refs",
    "receipt://",
    { allowEmpty: true },
  );
  const agentgresOperationRefs = prefixedRefs(
    refsFrom(request.agentgres_operation_refs, request.agentgres_operation_ref),
    "agentgres_operation_refs",
    "agentgres://operation/",
  );
  const receiptRefs = prefixedRefs(
    refsFrom(request.receipt_refs, request.receipt_ref),
    "receipt_refs",
    "receipt://",
  );
  const stateRootRef = prefixedString(
    request.state_root_ref,
    "state_root_ref",
    "agentgres://state-root/",
  );
  const artifactRefs = prefixedRefs(
    request.artifact_refs,
    "artifact_refs",
    "artifact://",
    { allowEmpty: true },
  );
  const archiveRef = optionalString(request.archive_ref) ?? null;
  const restoreRef = optionalString(request.restore_ref) ?? null;

  assertOperationSpecificRefs({ operationKind, archiveRef, restoreRef });

  const familyTargets = familyTargetRefs(operationFamily, request);
  const admissionId =
    optionalString(request.admission_id) ??
    `hypervisor-approved-operation:${safeId(operationFamily)}:${safeId(proposalRef)}`;

  return {
    schema_version: HYPERVISOR_APPROVED_OPERATION_ADMISSION_SCHEMA_VERSION,
    admission_id: admissionId,
    operation_family: operationFamily,
    proposal_ref: proposalRef,
    proposal_schema_version: proposalSchemaVersion,
    proposal_source: proposalSource,
    project_ref: projectRef,
    ...familyTargets,
    operation_kind: operationKind,
    target_ref: optionalString(request.target_ref) ?? familyTargets.target_ref ?? null,
    decision: "admitted",
    execution_status: "admitted_for_execution",
    wallet_approval_ref: walletApprovalRef,
    wallet_lease_ref: walletLeaseRef,
    required_scope_refs: requiredScopeRefs,
    authority_receipt_refs: authorityReceiptRefs,
    agentgres_operation_refs: agentgresOperationRefs,
    artifact_refs: artifactRefs,
    receipt_refs: receiptRefs,
    state_root_ref: stateRootRef,
    archive_ref: archiveRef,
    restore_ref: restoreRef,
    custody_invariant:
      optionalString(request.custody_invariant) ??
      "wallet.network approval and Agentgres admission are required before Hypervisor executes this operation.",
    admitted_at: optionalString(request.admitted_at) ?? nowIso(),
    runtimeTruthSource: "daemon-runtime",
  };
}

function assertDaemonProposalBoundary({
  operationFamily,
  proposalSchemaVersion,
  proposalSource,
}) {
  const expectedSchema = PROPOSAL_SCHEMA_BY_FAMILY.get(operationFamily);
  if (proposalSchemaVersion !== expectedSchema) {
    throw admissionError({
      code: "hypervisor_approved_operation_schema_mismatch",
      message:
        "Approved Hypervisor operation admission requires the proposal schema for its operation family.",
      details: {
        operation_family: operationFamily,
        expected_schema_version: expectedSchema,
        proposal_schema_version: proposalSchemaVersion,
      },
    });
  }

  const expectedSource = PROPOSAL_SOURCE_BY_FAMILY.get(operationFamily);
  if (proposalSource !== expectedSource) {
    throw admissionError({
      status: 403,
      code: "hypervisor_approved_operation_proposal_source_not_admissible",
      message:
        "Approved Hypervisor operation admission only accepts daemon-authored proposals, not fixtures or unverified local projections.",
      details: {
        operation_family: operationFamily,
        expected_proposal_source: expectedSource,
        proposal_source: proposalSource,
      },
    });
  }
}

function familyTargetRefs(operationFamily, request) {
  if (operationFamily === "session") {
    return {
      session_ref: requiredString(request.session_ref, "session_ref"),
      environment_ref: requiredString(request.environment_ref, "environment_ref"),
      provider_candidate_ref: requiredString(
        request.provider_candidate_ref,
        "provider_candidate_ref",
      ),
      candidate_ref: null,
      direct_provider_ref: null,
      target_ref: requiredString(request.target_ref, "target_ref"),
    };
  }

  if (operationFamily === "provider") {
    return {
      session_ref: optionalString(request.session_ref) ?? null,
      environment_ref: optionalString(request.environment_ref) ?? null,
      provider_candidate_ref:
        optionalString(request.provider_candidate_ref) ??
        optionalString(request.candidate_ref) ??
        null,
      candidate_ref: requiredString(request.candidate_ref, "candidate_ref"),
      direct_provider_ref: requiredString(
        request.direct_provider_ref,
        "direct_provider_ref",
      ),
      target_ref:
        optionalString(request.target_ref) ??
        optionalString(request.candidate_ref) ??
        null,
    };
  }

  throw requiredFieldError("operation_family");
}

function assertOperationSpecificRefs({ operationKind, archiveRef, restoreRef }) {
  if (ARCHIVE_REQUIRED_OPERATIONS.has(operationKind) && !archiveRef) {
    throw admissionError({
      code: "hypervisor_approved_operation_archive_ref_required",
      message:
        "Archive, restore, and zero-to-idle Hypervisor operations require an Agentgres-governed archive ref.",
      details: { operation_kind: operationKind, required: "archive_ref" },
    });
  }
  if (archiveRef && !archiveRef.startsWith("artifact://")) {
    throw admissionError({
      code: "hypervisor_approved_operation_archive_ref_prefix_invalid",
      message:
        "Archive refs for approved Hypervisor operations must be Agentgres-governed artifact refs.",
      details: {
        operation_kind: operationKind,
        archive_ref: archiveRef,
        expected_prefix: "artifact://",
      },
    });
  }
  if (RESTORE_REQUIRED_OPERATIONS.has(operationKind) && !restoreRef) {
    throw admissionError({
      code: "hypervisor_approved_operation_restore_ref_required",
      message:
        "Restore Hypervisor operations require an Agentgres restore ref before execution admission.",
      details: { operation_kind: operationKind, required: "restore_ref" },
    });
  }
  if (restoreRef && !restoreRef.startsWith("agentgres://restore/")) {
    throw admissionError({
      code: "hypervisor_approved_operation_restore_ref_prefix_invalid",
      message:
        "Restore refs for approved Hypervisor operations must be Agentgres restore refs.",
      details: {
        operation_kind: operationKind,
        restore_ref: restoreRef,
        expected_prefix: "agentgres://restore/",
      },
    });
  }
}

function refsFrom(plural, singular) {
  return uniqueStrings([
    ...normalizeArray(plural),
    ...(optionalString(singular) ? [optionalString(singular)] : []),
  ]);
}

function prefixedRefs(value, field, prefix, { allowEmpty = false, status = 400 } = {}) {
  const refs = uniqueStrings(normalizeArray(value));
  if (!allowEmpty && refs.length === 0) {
    throw admissionError({
      status,
      code: "hypervisor_approved_operation_required_refs_missing",
      message: `Approved Hypervisor operation admission requires ${field}.`,
      details: { field },
    });
  }
  for (const ref of refs) {
    if (!ref.startsWith(prefix)) {
      throw admissionError({
        status,
        code: "hypervisor_approved_operation_ref_prefix_invalid",
        message: `${field} must use ${prefix} refs.`,
        details: { field, ref, expected_prefix: prefix },
      });
    }
  }
  return refs;
}

function prefixedString(value, field, prefix, status = 400) {
  const text = requiredString(value, field, status);
  if (!text.startsWith(prefix)) {
    throw admissionError({
      status,
      code: "hypervisor_approved_operation_ref_prefix_invalid",
      message: `${field} must use a ${prefix} ref.`,
      details: { field, ref: text, expected_prefix: prefix },
    });
  }
  return text;
}

function enumValue(value, field, allowed) {
  const text = requiredString(value, field);
  if (!allowed.has(text)) {
    throw admissionError({
      code: "hypervisor_approved_operation_enum_invalid",
      message: `${field} is not a supported Hypervisor approved-operation value.`,
      details: { field, value: text, allowed: [...allowed] },
    });
  }
  return text;
}

function requiredString(value, field, status = 400) {
  const text = optionalString(value);
  if (!text) {
    throw requiredFieldError(field, status);
  }
  return text;
}

function requiredFieldError(field, status = 400) {
  return admissionError({
    status,
    code: "hypervisor_approved_operation_required_field_missing",
    message: `Approved Hypervisor operation admission requires ${field}.`,
    details: { field },
  });
}

function assertNoRetiredAliases(request) {
  const present = RETIRED_ALIASES.filter((alias) =>
    Object.prototype.hasOwnProperty.call(request, alias),
  );
  if (present.length > 0) {
    throw admissionError({
      code: "hypervisor_approved_operation_retired_alias",
      message:
        "Approved Hypervisor operation admission accepts snake_case fields only.",
      details: { retired_aliases: present },
    });
  }
}

function admissionError({
  status = 400,
  code = "hypervisor_approved_operation_admission_failed",
  message,
  details,
}) {
  return runtimeError({ status, code, message, details });
}
