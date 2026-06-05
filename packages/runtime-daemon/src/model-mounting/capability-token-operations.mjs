import crypto from "node:crypto";

import { sanitizeVaultRefs } from "./provider-auth.mjs";
import {
  hashToken,
  notFound,
  normalizeScopes,
  publicToken,
  runtimeError,
} from "./io.mjs";

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
  state.tokens.set(stored.id, stored);
  state.writeMap("tokens", state.tokens);
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
  state.tokens.set(tokenId, revoked);
  state.writeMap("tokens", state.tokens);
  state.receipt("permission_token_revocation", {
    summary: `Capability token ${tokenId} revoked.`,
    redaction: "redacted",
    evidenceRefs: ["wallet.network.revocation", token.grantId],
    details: publicTokenDep(revoked),
  });
  return publicTokenDep(revoked);
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
  state.tokens.set(authorized.id, authorized);
  state.writeMap("tokens", state.tokens);
  return authorized;
}
