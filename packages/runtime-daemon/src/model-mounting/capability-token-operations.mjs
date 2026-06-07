import crypto from "node:crypto";

import { sanitizeVaultRefs } from "./provider-auth.mjs";
import {
  hashToken,
  notFound,
  normalizeScopes,
  publicToken,
  runtimeError,
} from "./io.mjs";

const RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_SCHEMA_VERSION =
  "ioi.runtime_model_mount_record_state_commit.v1";
const RUNTIME_STATE_STORAGE_BACKEND_REF = "storage://runtime-agentgres/local-json";

export function createToken(state, body = {}, deps = {}) {
  const {
    generateTokenValue = () => `ioi_mnt_${crypto.randomBytes(24).toString("base64url")}`,
    hashToken: hashTokenDep = hashToken,
    normalizeScopes: normalizeScopesDep = normalizeScopes,
    publicToken: publicTokenDep = publicToken,
    randomUUID = () => crypto.randomUUID(),
    sanitizeVaultRefs: sanitizeVaultRefsDep = sanitizeVaultRefs,
  } = deps;
  const now = state.nowIso();
  const tokenValue = generateTokenValue();
  const token = state.walletAuthority.createGrant({
    id: `grant_${randomUUID()}`,
    audience: body.audience ?? "autopilot-local-server",
    allowed: normalizeScopesDep(body.allowed, [
      "model.chat:*",
      "model.responses:*",
      "model.embeddings:*",
      "model.tokenize:*",
      "model.context:*",
      "route.use:*",
    ]),
    denied: normalizeScopesDep(body.denied, ["connector.gmail.send", "filesystem.write", "shell.exec"]),
    expiresAt:
      body.expires_at ??
      body.expiresAt ??
      new Date(state.now().getTime() + 24 * 60 * 60 * 1000).toISOString(),
    revocationEpoch: Number(body.revocation_epoch ?? body.revocationEpoch ?? 0),
    grantId: body.grant_id ?? body.grantId ?? `wallet.grant.${randomUUID()}`,
    vaultRefs: sanitizeVaultRefsDep(body.vault_refs ?? body.vaultRefs ?? {}),
    auditReceiptIds: [],
    tokenHash: hashTokenDep(tokenValue),
    createdAt: now,
    lastUsedAt: null,
    lastUsedScope: null,
    revokedAt: null,
    receiptId: null,
  });
  const receipt = state.receipt("permission_token", {
    summary: `Capability token ${token.id} created for ${token.audience}.`,
    redaction: "redacted",
    evidenceRefs: ["wallet.network.capability_grant", token.grantId],
    details: publicTokenDep(token),
  });
  const stored = { ...token, receiptId: receipt.id };
  commitCapabilityTokenRecordState(state, stored, "model_mount.capability_token.create", [receipt.id]);
  state.tokens.set(stored.id, stored);
  return { ...publicTokenDep(stored), token: tokenValue };
}

export function listTokens(state, deps = {}) {
  const { publicToken: publicTokenDep = publicToken } = deps;
  return [...state.tokens.values()]
    .map(publicTokenDep)
    .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
}

export function revokeToken(state, tokenId, deps = {}) {
  const {
    notFound: notFoundDep = notFound,
    publicToken: publicTokenDep = publicToken,
  } = deps;
  const token = state.tokens.get(tokenId);
  if (!token) throw notFoundDep(`Token not found: ${tokenId}`, { token_id: tokenId });
  const revoked = state.walletAuthority.revokeGrant(token);
  const receipt = state.receipt("permission_token_revocation", {
    summary: `Capability token ${tokenId} revoked.`,
    redaction: "redacted",
    evidenceRefs: ["wallet.network.revocation", token.grantId],
    details: publicTokenDep(revoked),
  });
  const stored = {
    ...revoked,
    auditReceiptIds: [...(Array.isArray(revoked.auditReceiptIds) ? revoked.auditReceiptIds : []), receipt.id],
  };
  commitCapabilityTokenRecordState(state, stored, "model_mount.capability_token.revoke", [
    stored.receiptId,
    receipt.id,
  ]);
  state.tokens.set(tokenId, stored);
  return publicTokenDep(stored);
}

export function authorize(state, authorization, requiredScope, deps = {}) {
  const {
    hashToken: hashTokenDep = hashToken,
    runtimeError: runtimeErrorDep = runtimeError,
  } = deps;
  if (!authorization || !authorization.startsWith("Bearer ")) {
    throw runtimeErrorDep({
      status: 401,
      code: "auth",
      message: "Bearer capability token is required for this model mounting operation.",
      details: { required_scope: requiredScope },
    });
  }
  const tokenHash = hashTokenDep(authorization.slice("Bearer ".length).trim());
  const token = [...state.tokens.values()].find((candidate) => candidate.tokenHash === tokenHash);
  if (!token) {
    throw runtimeErrorDep({
      status: 401,
      code: "auth",
      message: "Capability token was not recognized.",
      details: { required_scope: requiredScope },
    });
  }
  const authorized = state.walletAuthority.authorizeScope(token, requiredScope);
  commitCapabilityTokenRecordState(state, authorized, "model_mount.capability_token.authorize", [
    authorized.receiptId,
  ]);
  state.tokens.set(authorized.id, authorized);
  return authorized;
}

function commitCapabilityTokenRecordState(state, record, operationKind, receiptRefs) {
  if (typeof state.commitRuntimeModelMountRecordState !== "function") {
    const error = new Error("Model-mount capability token persistence requires Rust Agentgres record-state commit.");
    error.status = 500;
    error.code = "model_mount_capability_token_state_commit_unconfigured";
    error.details = {
      token_id: record?.id ?? null,
      grant_id: record?.grantId ?? null,
      receipt_id: record?.receiptId ?? null,
    };
    throw error;
  }
  return normalizeCapabilityTokenRecordStateCommit(state.commitRuntimeModelMountRecordState({
    schema_version: RUNTIME_MODEL_MOUNT_RECORD_STATE_COMMIT_SCHEMA_VERSION,
    record_dir: "tokens",
    record_id: record.id,
    operation_kind: operationKind,
    storage_backend_ref: RUNTIME_STATE_STORAGE_BACKEND_REF,
    record,
    receipt_refs: receiptRefs.filter(Boolean),
  }));
}

function normalizeCapabilityTokenRecordStateCommit(value = {}) {
  const commit = value && typeof value === "object" && !Array.isArray(value) ? value : {};
  const storageRecord = commit.storage_record && typeof commit.storage_record === "object"
    ? commit.storage_record
    : commit.record?.record ?? {};
  const required = {
    record_id: commit.record_id ?? commit.record?.record_id,
    object_ref: commit.object_ref ?? storageRecord.object_ref,
    content_hash: commit.content_hash ?? storageRecord.content_hash,
    admission_hash: commit.admission_hash ?? storageRecord.admission?.admission_hash,
    commit_hash: commit.commit_hash ?? commit.record?.commit_hash,
    written_record: commit.written_record,
  };
  for (const [field, fieldValue] of Object.entries(required)) {
    if (!fieldValue) {
      const error = new Error(`Rust model-mount record state commit returned without ${field}.`);
      error.status = 502;
      error.code = "model_mount_record_state_commit_invalid";
      error.details = { field };
      throw error;
    }
  }
  return {
    ...commit,
    storage_record: storageRecord,
    record_id: required.record_id,
    object_ref: required.object_ref,
    content_hash: required.content_hash,
    admission_hash: required.admission_hash,
    commit_hash: required.commit_hash,
    written_record: required.written_record,
  };
}
