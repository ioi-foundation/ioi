import type {
  CandidateEvidence,
  ExchangeIntent,
  LookupPrincipalAuthorityBindingParams,
  LookupPrincipalAuthorityBindingReceipt,
  IssuePrincipalAuthorityBindingParams,
  PrincipalAuthorityBindingCoordinates,
  PrincipalAuthorityBindingProofV1,
  PrincipalAuthorityResolutionReceipt,
  PrincipalAuthorityResolutionV1,
  ResolvePrincipalAuthorityParams,
  RevokePrincipalAuthorityBindingParams,
  RiskCoverageState,
  TradeIntent,
  WalletProtocolBytes,
} from "./types.js";
import { approvalAuthorityArtifactHash } from "./principal-authority-hash.js";

export const EXECUTABLE_COVERAGE_STATES: readonly RiskCoverageState[] = ["assessed"] as const;

const INTENT_CANDIDATE_EVIDENCE_MISSING_CODES = {
  exchange: "exchange_intent_candidate_evidence_missing",
  trade: "trade_intent_candidate_evidence_missing",
} as const;

const INTENT_CANDIDATE_EVIDENCE_MISMATCH_CODES = {
  exchange: "exchange_intent_candidate_evidence_mismatch",
  trade: "trade_intent_candidate_evidence_mismatch",
} as const;

export interface WalletProtocolValidationIssue {
  readonly code: string;
  readonly message: string;
  readonly details?: Readonly<Record<string, unknown>>;
}

export class WalletProtocolValidationError extends Error {
  readonly code: string;
  readonly details?: Readonly<Record<string, unknown>>;

  constructor(issue: WalletProtocolValidationIssue) {
    super(issue.message);
    this.name = "WalletProtocolValidationError";
    this.code = issue.code;
    this.details = issue.details;
  }
}

export interface CandidateEvidenceValidationOptions {
  readonly now?: string | Date;
  readonly require_assessed?: boolean;
  readonly require_not_expired?: boolean;
}

export function assertCandidateEvidenceExecutable(
  evidence: CandidateEvidence,
  options: CandidateEvidenceValidationOptions = {},
): CandidateEvidence {
  assertCandidateEvidenceShape(evidence);
  if (options.require_assessed ?? true) {
    if (!EXECUTABLE_COVERAGE_STATES.includes(evidence.coverage_state)) {
      throwValidationError({
        code: "candidate_evidence_not_executable",
        message:
          "Candidate evidence must be assessed before it can support executable exchange or trade intent approval.",
        details: {
          candidate_id: evidence.candidate_id,
          coverage_state: evidence.coverage_state,
        },
      });
    }
  }
  if (options.require_not_expired ?? true) {
    assertCandidateEvidenceNotExpired(evidence, options.now);
  }
  return evidence;
}

export function assertExchangeIntentCandidateEvidence(
  intent: ExchangeIntent,
  options: CandidateEvidenceValidationOptions = {},
): ExchangeIntent {
  assertIntentCandidateEvidence({
    domain: "exchange",
    expectedCandidateId: intent.route_candidate_id,
    evidence: intent.candidate_evidence,
    options,
  });
  return intent;
}

export function assertTradeIntentCandidateEvidence(
  intent: TradeIntent,
  options: CandidateEvidenceValidationOptions = {},
): TradeIntent {
  assertIntentCandidateEvidence({
    domain: "trade",
    expectedCandidateId: intent.venue_candidate_id,
    evidence: intent.candidate_evidence,
    options,
  });
  return intent;
}

const PORTABLE_PRINCIPAL_REF =
  /^(?:(?:worker|service|org|domain):\/\/|agentgres:\/\/domain\/)[A-Za-z0-9](?:[A-Za-z0-9._~:@-]*[A-Za-z0-9])?(?:\/[A-Za-z0-9](?:[A-Za-z0-9._~:@-]*[A-Za-z0-9])?)*$/;
const PRINCIPAL_AUTHORITY_BINDING_REF =
  /^wallet\.network:\/\/principal-authority-binding\/[0-9a-f]{64}$/;

/**
 * Performs fail-closed structural validation of a root-signed binding proof.
 * Cryptographic signature and canonical-hash verification remains a
 * wallet.network service responsibility.
 */
export function assertPrincipalAuthorityBindingProof(
  proof: PrincipalAuthorityBindingProofV1,
): PrincipalAuthorityBindingProofV1 {
  if (proof.schema_version !== 1 || proof.statement.schema_version !== 1) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_schema_invalid",
      "Principal authority binding proofs must use schema version 1.",
    );
  }

  const statement = proof.statement;
  assertPortablePrincipalRef(statement.principal_ref);
  if (statement.authority_kind !== "approval") {
    throwPrincipalAuthorityValidation(
      "principal_authority_kind_invalid",
      "Principal authority bindings may currently bind only approval authority.",
    );
  }
  if (!positiveInteger(statement.binding_version)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_version_invalid",
      "Principal authority binding_version must be a positive integer.",
    );
  }
  if (statement.status !== "active" && statement.status !== "revoked") {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_status_invalid",
      "Principal authority binding status must be active or revoked.",
    );
  }
  if (statement.binding_version > 4_096) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_chain_too_deep",
      "Principal authority binding version exceeds the v1 verification bound.",
    );
  }
  if (statement.status === "active" && statement.binding_version === 4_096) {
    throwPrincipalAuthorityValidation(
      "principal_authority_terminal_revocation_reserved",
      "Principal authority binding version 4096 is reserved for terminal revocation.",
    );
  }

  assertBytes32(statement.authority_id, "authority_id", true);
  assertBytes(statement.authority_public_key, "authority_public_key");
  if (!Number.isInteger(statement.authority_signature_suite)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_signature_suite_invalid",
      "Principal authority signature suite must be an integer COSE algorithm id.",
    );
  }
  assertBytes32(
    statement.approval_authority_snapshot_hash,
    "approval_authority_snapshot_hash",
    true,
  );

  if (statement.binding_version === 1) {
    if (
      statement.previous_binding_ref !== undefined ||
      statement.previous_binding_hash !== undefined
    ) {
      throwPrincipalAuthorityValidation(
        "principal_authority_binding_predecessor_invalid",
        "Binding version 1 must not claim a predecessor.",
      );
    }
  } else {
    assertBindingRef(statement.previous_binding_ref, "previous_binding_ref");
    assertBytes32(statement.previous_binding_hash, "previous_binding_hash", true);
    if (!statement.previous_binding_ref.endsWith(bytesToHex(statement.previous_binding_hash))) {
      throwPrincipalAuthorityValidation(
        "principal_authority_binding_predecessor_hash_mismatch",
        "Previous principal authority binding ref must contain the exact previous binding hash.",
      );
    }
  }

  if (!positiveInteger(statement.signed_at_ms)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_timestamp_invalid",
      "Principal authority signed_at_ms must be a positive integer.",
    );
  }
  if (
    statement.expires_at_ms !== undefined &&
    (!positiveInteger(statement.expires_at_ms) || statement.expires_at_ms <= statement.signed_at_ms)
  ) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_expiry_invalid",
      "Principal authority expires_at_ms must be later than signed_at_ms.",
    );
  }
  assertBytes32(statement.issuer_root_account_id, "issuer_root_account_id", true);
  if (
    statement.reason !== undefined &&
    (!nonEmptyString(statement.reason) || statement.reason.trim() !== statement.reason)
  ) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_reason_invalid",
      "Principal authority binding reason must be trimmed and non-empty when present.",
    );
  }
  if (statement.status === "revoked" && statement.reason === undefined) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_revocation_reason_missing",
      "Revoked principal authority bindings must include a reason.",
    );
  }

  assertBytes32(proof.statement_hash, "statement_hash", true);
  if (!Number.isInteger(proof.issuer_signature_proof.suite)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_issuer_signature_suite_invalid",
      "Issuer signature suite must be an integer COSE algorithm id.",
    );
  }
  assertBytes(proof.issuer_signature_proof.public_key, "issuer_public_key");
  assertBytes(proof.issuer_signature_proof.signature, "issuer_signature");
  assertBindingRef(proof.binding_ref, "binding_ref");
  assertBytes32(proof.binding_hash, "binding_hash", true);
  if (!proof.binding_ref.endsWith(bytesToHex(proof.binding_hash))) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_ref_hash_mismatch",
      "Principal authority binding_ref must contain the exact binding_hash.",
    );
  }
  return proof;
}

/** Validates the active proof accepted by the issue transition. */
export function assertIssuePrincipalAuthorityBindingParams(
  request: IssuePrincipalAuthorityBindingParams,
): IssuePrincipalAuthorityBindingParams {
  const proof = assertPrincipalAuthorityBindingProof(request.proof);
  if (proof.statement.status !== "active") {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_issue_status_invalid",
      "Issue principal authority binding requires an active proof.",
    );
  }
  return request;
}

/** Validates the append-only revoked successor accepted by revocation. */
export function assertRevokePrincipalAuthorityBindingParams(
  request: RevokePrincipalAuthorityBindingParams,
): RevokePrincipalAuthorityBindingParams {
  const proof = assertPrincipalAuthorityBindingProof(request.proof);
  if (proof.statement.status !== "revoked" || proof.statement.binding_version < 2) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_revoke_status_invalid",
      "Revoke principal authority binding requires a revoked successor proof.",
    );
  }
  assertBindingRef(request.predecessor_binding_ref, "predecessor_binding_ref");
  if (proof.statement.previous_binding_ref !== request.predecessor_binding_ref) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_predecessor_mismatch",
      "Revocation request predecessor_binding_ref must exactly match the proof predecessor.",
    );
  }
  return request;
}

/** Validates a resolved authority result and its immutable coordinates. */
export function assertPrincipalAuthorityResolution(
  resolution: PrincipalAuthorityResolutionV1,
): PrincipalAuthorityResolutionV1 {
  if (resolution.schema_version !== 1) {
    throwPrincipalAuthorityValidation(
      "principal_authority_resolution_schema_invalid",
      "Principal authority resolutions must use schema version 1.",
    );
  }
  assertPortablePrincipalRef(resolution.principal_ref);
  if (resolution.authority_kind !== "approval") {
    throwPrincipalAuthorityValidation(
      "principal_authority_kind_invalid",
      "Principal authority resolutions may currently return only approval authority.",
    );
  }
  assertCoordinates(resolution.coordinates);
  assertRequiredScope(resolution.required_scope);
  if (!nonEmptyString(resolution.matched_scope)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_scope_match_invalid",
      "Principal authority resolution matched_scope must name an authority allowlist entry.",
    );
  }
  const authority = resolution.approval_authority;
  if (authority.schema_version !== 1) {
    throwPrincipalAuthorityValidation(
      "principal_authority_snapshot_invalid",
      "Approval authority snapshot must use schema version 1.",
    );
  }
  assertBytes32(authority.authority_id, "approval_authority.authority_id", true);
  assertBytes(authority.public_key, "approval_authority.public_key");
  if (
    !Number.isSafeInteger(authority.signature_suite) ||
    authority.signature_suite < -2_147_483_648 ||
    authority.signature_suite > 2_147_483_647
  ) {
    throwPrincipalAuthorityValidation(
      "principal_authority_snapshot_invalid",
      "Approval authority snapshot signature_suite must be an integer.",
    );
  }
  if (!positiveInteger(authority.expires_at) || typeof authority.revoked !== "boolean") {
    throwPrincipalAuthorityValidation(
      "principal_authority_snapshot_invalid",
      "Approval authority snapshot must carry a safe positive expiry and boolean revocation state.",
    );
  }
  if (!Array.isArray(authority.scope_allowlist)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_snapshot_invalid",
      "Approval authority snapshot scope_allowlist must be an array.",
    );
  }
  for (const scope of authority.scope_allowlist) {
    if (typeof scope !== "string") {
      throwPrincipalAuthorityValidation(
        "principal_authority_snapshot_invalid",
        "Approval authority scope entries must be strings.",
      );
    }
  }
  assertBytes32(resolution.authority_id, "authority_id", true);
  assertBytes(resolution.authority_public_key, "authority_public_key");
  if (
    !Number.isSafeInteger(resolution.authority_signature_suite) ||
    resolution.authority_signature_suite < -2_147_483_648 ||
    resolution.authority_signature_suite > 2_147_483_647
  ) {
    throwPrincipalAuthorityValidation(
      "principal_authority_signature_suite_invalid",
      "Principal authority signature suite must be an integer COSE algorithm id.",
    );
  }
  if (
    !bytesEqual(authority.authority_id, resolution.authority_id) ||
    !bytesEqual(authority.public_key, resolution.authority_public_key) ||
    authority.signature_suite !== resolution.authority_signature_suite
  ) {
    throwPrincipalAuthorityValidation(
      "principal_authority_snapshot_mismatch",
      "Complete approval authority snapshot must match the resolved signer tuple.",
    );
  }
  assertBytes32(
    resolution.approval_authority_snapshot_hash,
    "approval_authority_snapshot_hash",
    true,
  );
  const computedSnapshotHash = approvalAuthorityArtifactHash(authority);
  if (!bytesEqual(computedSnapshotHash, resolution.approval_authority_snapshot_hash)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_snapshot_hash_mismatch",
      "Complete approval authority snapshot does not match its frozen Rust-compatible JCS/SHA-256 hash.",
    );
  }
  if (authority.revoked) {
    throwPrincipalAuthorityValidation(
      "principal_authority_snapshot_inactive",
      "Approval authority snapshot is revoked.",
    );
  }
  if (authority.scope_allowlist.length === 0) {
    throwPrincipalAuthorityValidation(
      "principal_authority_scope_denied",
      "Approval authority snapshot scope_allowlist must not be empty.",
    );
  }
  if (
    !authority.scope_allowlist.includes(resolution.matched_scope) ||
    !scopePatternMatches(resolution.matched_scope, resolution.required_scope)
  ) {
    throwPrincipalAuthorityValidation(
      "principal_authority_scope_match_invalid",
      "Matched scope must be an exact snapshot allowlist entry that covers required_scope.",
    );
  }
  if (!positiveInteger(resolution.resolved_at_ms)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_resolution_timestamp_invalid",
      "Principal authority resolved_at_ms must be a positive integer.",
    );
  }
  if (authority.expires_at < resolution.resolved_at_ms) {
    throwPrincipalAuthorityValidation(
      "principal_authority_snapshot_expired",
      "Approval authority snapshot is expired at resolution time.",
    );
  }
  assertBytes32(resolution.mutation_audit_event_id, "mutation_audit_event_id", true);
  assertBytes32(resolution.mutation_audit_event_hash, "mutation_audit_event_hash", true);
  return resolution;
}

/**
 * Verifies the complete resolution receipt against the caller's exact optional
 * binding coordinates. A stale or foreign result is never accepted as a
 * fallback.
 */
export function assertPrincipalAuthorityResolutionReceipt(
  request: ResolvePrincipalAuthorityParams,
  receipt: PrincipalAuthorityResolutionReceipt,
): PrincipalAuthorityResolutionReceipt {
  assertBytes32(request.request_id, "request_id", true);
  assertPortablePrincipalRef(request.principal_ref);
  if (request.authority_kind !== "approval") {
    throwPrincipalAuthorityValidation(
      "principal_authority_kind_invalid",
      "Principal authority requests may currently resolve only approval authority.",
    );
  }
  assertRequiredScope(request.required_scope);
  if (request.expected_coordinates !== undefined) {
    assertCoordinates(request.expected_coordinates);
  }
  assertBytes32(receipt.request_id, "receipt.request_id", true);
  if (!bytesEqual(request.request_id, receipt.request_id)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_resolution_request_mismatch",
      "Principal authority resolution receipt does not match the request id.",
    );
  }
  if (!positiveInteger(receipt.resolved_at_ms)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_resolution_timestamp_invalid",
      "Principal authority receipt resolved_at_ms must be a positive integer.",
    );
  }
  const resolution = assertPrincipalAuthorityResolution(receipt.resolution);
  if (receipt.resolved_at_ms !== resolution.resolved_at_ms) {
    throwPrincipalAuthorityValidation(
      "principal_authority_resolution_timestamp_mismatch",
      "Principal authority receipt and resolution timestamps must match exactly.",
    );
  }
  if (
    resolution.principal_ref !== request.principal_ref ||
    resolution.authority_kind !== request.authority_kind ||
    resolution.required_scope !== request.required_scope
  ) {
    throwPrincipalAuthorityValidation(
      "principal_authority_resolution_principal_mismatch",
      "Principal authority resolution must match the exact requested principal and authority kind.",
    );
  }
  if (
    request.expected_coordinates !== undefined &&
    !coordinatesEqual(request.expected_coordinates, resolution.coordinates)
  ) {
    throwPrincipalAuthorityValidation(
      "principal_authority_resolution_pin_mismatch",
      "Principal authority resolution does not match the expected binding coordinates.",
    );
  }
  return receipt;
}

/** Validates an immutable-proof lookup receipt against its request pin. */
export function assertLookupPrincipalAuthorityBindingReceipt(
  request: LookupPrincipalAuthorityBindingParams,
  receipt: LookupPrincipalAuthorityBindingReceipt,
): LookupPrincipalAuthorityBindingReceipt {
  assertBytes32(request.request_id, "request_id", true);
  assertBindingRef(request.binding_ref, "binding_ref");
  if (request.expected_binding_hash !== undefined) {
    assertBytes32(request.expected_binding_hash, "expected_binding_hash", true);
    if (!request.binding_ref.endsWith(bytesToHex(request.expected_binding_hash))) {
      throwPrincipalAuthorityValidation(
        "principal_authority_binding_request_pin_mismatch",
        "Principal authority lookup ref must contain the expected binding hash.",
      );
    }
  }
  assertBytes32(receipt.request_id, "receipt.request_id", true);
  if (!bytesEqual(request.request_id, receipt.request_id)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_request_mismatch",
      "Principal authority binding receipt does not match the request id.",
    );
  }
  if (!positiveInteger(receipt.fetched_at_ms)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_timestamp_invalid",
      "Principal authority fetched_at_ms must be a positive integer.",
    );
  }
  const proof = assertPrincipalAuthorityBindingProof(receipt.proof);
  if (proof.binding_ref !== request.binding_ref) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_ref_mismatch",
      "Principal authority binding receipt returned a foreign binding ref.",
    );
  }
  if (
    request.expected_binding_hash !== undefined &&
    !bytesEqual(request.expected_binding_hash, proof.binding_hash)
  ) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_hash_mismatch",
      "Principal authority binding receipt does not match the expected binding hash.",
    );
  }
  return receipt;
}

function assertIntentCandidateEvidence({
  domain,
  expectedCandidateId,
  evidence,
  options,
}: {
  readonly domain: "exchange" | "trade";
  readonly expectedCandidateId: string;
  readonly evidence: readonly CandidateEvidence[];
  readonly options: CandidateEvidenceValidationOptions;
}) {
  if (!Array.isArray(evidence) || evidence.length === 0) {
    throwValidationError({
      code: INTENT_CANDIDATE_EVIDENCE_MISSING_CODES[domain],
      message: "Exchange and trade intents must bind the candidate evidence they approve.",
      details: { expected_candidate_id: expectedCandidateId },
    });
  }
  const matching = evidence.find((candidate) => candidate.candidate_id === expectedCandidateId);
  if (!matching) {
    throwValidationError({
      code: INTENT_CANDIDATE_EVIDENCE_MISMATCH_CODES[domain],
      message: "Intent candidate evidence must include the exact selected candidate id.",
      details: {
        expected_candidate_id: expectedCandidateId,
        candidate_ids: evidence.map((candidate) => candidate.candidate_id),
      },
    });
  }
  for (const candidate of evidence) {
    assertCandidateEvidenceExecutable(candidate, options);
  }
}

function assertCandidateEvidenceShape(evidence: CandidateEvidence) {
  const requiredStringFields = [
    "candidate_id",
    "source",
    "adapter_id",
    "observed_at",
    "expires_at",
    "coverage_state",
  ] as const;
  for (const field of requiredStringFields) {
    if (!nonEmptyString(evidence[field])) {
      throwValidationError({
        code: "candidate_evidence_field_missing",
        message: "Candidate evidence is missing a required string field.",
        details: { field },
      });
    }
  }
  if (!Array.isArray(evidence.evidence_refs) || evidence.evidence_refs.length === 0) {
    throwValidationError({
      code: "candidate_evidence_refs_missing",
      message: "Candidate evidence must include evidence refs.",
      details: { candidate_id: evidence.candidate_id },
    });
  }
  if (!Array.isArray(evidence.risk_labels)) {
    throwValidationError({
      code: "candidate_evidence_risk_labels_missing",
      message: "Candidate evidence must include risk labels.",
      details: { candidate_id: evidence.candidate_id },
    });
  }
  if (!evidence.claims || typeof evidence.claims !== "object") {
    throwValidationError({
      code: "candidate_evidence_claims_missing",
      message: "Candidate evidence must include source claims.",
      details: { candidate_id: evidence.candidate_id },
    });
  }
}

function assertCandidateEvidenceNotExpired(
  evidence: CandidateEvidence,
  now: string | Date | undefined,
) {
  const expiresAtMs = Date.parse(evidence.expires_at);
  if (!Number.isFinite(expiresAtMs)) {
    throwValidationError({
      code: "candidate_evidence_expiry_invalid",
      message: "Candidate evidence expires_at must be a valid timestamp.",
      details: {
        candidate_id: evidence.candidate_id,
        expires_at: evidence.expires_at,
      },
    });
  }
  const nowMs =
    now instanceof Date ? now.getTime() : typeof now === "string" ? Date.parse(now) : Date.now();
  if (Number.isFinite(nowMs) && expiresAtMs <= nowMs) {
    throwValidationError({
      code: "candidate_evidence_expired",
      message: "Candidate evidence is expired and cannot support execution.",
      details: {
        candidate_id: evidence.candidate_id,
        expires_at: evidence.expires_at,
      },
    });
  }
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}

function assertRequiredScope(requiredScope: string) {
  if (
    typeof requiredScope !== "string" ||
    requiredScope.length === 0 ||
    requiredScope.length > 256 ||
    requiredScope !== requiredScope.trim() ||
    requiredScope !== requiredScope.toLowerCase() ||
    !/^[a-z0-9][a-z0-9._:-]*$/.test(requiredScope)
  ) {
    throwPrincipalAuthorityValidation(
      "principal_authority_required_scope_invalid",
      "Principal authority required_scope must be canonical lowercase ASCII.",
    );
  }
}

function scopePatternMatches(rawPattern: string, requiredScope: string) {
  const pattern = rawPattern.trim().toLowerCase();
  if (pattern === "*" || pattern === requiredScope) return true;
  if (pattern.endsWith("::*")) {
    return requiredScope.startsWith(`${pattern.slice(0, -3)}::`);
  }
  if (pattern.endsWith(":*")) {
    return requiredScope.startsWith(`${pattern.slice(0, -2)}:`);
  }
  if (pattern.endsWith("*")) {
    return requiredScope.startsWith(pattern.slice(0, -1));
  }
  return false;
}

function assertPortablePrincipalRef(principalRef: string) {
  if (principalRef.length > 300 || !PORTABLE_PRINCIPAL_REF.test(principalRef)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_principal_ref_invalid",
      "Principal authority refs must be canonical worker, service, org, domain, or agentgres domain refs.",
    );
  }
}

function assertBindingRef(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || !PRINCIPAL_AUTHORITY_BINDING_REF.test(value)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_ref_invalid",
      `Principal authority ${field} is not a canonical binding ref.`,
    );
  }
}

function assertCoordinates(coordinates: PrincipalAuthorityBindingCoordinates) {
  assertBindingRef(coordinates.binding_ref, "coordinates.binding_ref");
  if (!positiveInteger(coordinates.binding_version)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_version_invalid",
      "Principal authority coordinates require a positive binding_version.",
    );
  }
  assertBytes32(coordinates.binding_hash, "coordinates.binding_hash", true);
  if (!coordinates.binding_ref.endsWith(bytesToHex(coordinates.binding_hash))) {
    throwPrincipalAuthorityValidation(
      "principal_authority_binding_ref_hash_mismatch",
      "Principal authority coordinates must bind the exact binding hash.",
    );
  }
}

function assertBytes(value: unknown, field: string): asserts value is WalletProtocolBytes {
  if (!Array.isArray(value) || value.length === 0 || !value.every(validByte)) {
    throwPrincipalAuthorityValidation(
      "principal_authority_bytes_invalid",
      `Principal authority ${field} must be a non-empty byte array.`,
    );
  }
}

function assertBytes32(
  value: unknown,
  field: string,
  requireNonZero: boolean,
): asserts value is WalletProtocolBytes {
  if (
    !Array.isArray(value) ||
    value.length !== 32 ||
    !value.every(validByte) ||
    (requireNonZero && value.every((byte) => byte === 0))
  ) {
    throwPrincipalAuthorityValidation(
      "principal_authority_bytes32_invalid",
      `Principal authority ${field} must be a${requireNonZero ? " non-zero" : ""} 32-byte array.`,
    );
  }
}

function validByte(value: unknown): value is number {
  return Number.isInteger(value) && Number(value) >= 0 && Number(value) <= 255;
}

function positiveInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && Number(value) > 0;
}

function bytesEqual(left: WalletProtocolBytes, right: WalletProtocolBytes) {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function coordinatesEqual(
  left: PrincipalAuthorityBindingCoordinates,
  right: PrincipalAuthorityBindingCoordinates,
) {
  return (
    left.binding_ref === right.binding_ref &&
    left.binding_version === right.binding_version &&
    bytesEqual(left.binding_hash, right.binding_hash)
  );
}

function bytesToHex(bytes: WalletProtocolBytes) {
  return bytes.map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

function throwPrincipalAuthorityValidation(code: string, message: string): never {
  throwValidationError({ code, message });
}

function throwValidationError(issue: WalletProtocolValidationIssue): never {
  throw new WalletProtocolValidationError(issue);
}
