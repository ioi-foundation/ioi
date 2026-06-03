import {
  emitRemoteBoundaryEvent,
  matchesAny,
  redact,
  runtimeError,
  stableHash,
} from "./io.mjs";

const SECRET_REDACTION = "[REDACTED]";

export class AgentgresWalletAuthority {
  constructor({ now, appendOperation }) {
    this.now = now;
    this.appendOperation = appendOperation;
  }

  createGrant(token) {
    const grant = {
      ...token,
      authority: "agentgres_wallet_authority",
      walletNetworkShape: {
        grantId: token.grantId,
        revocationEpoch: token.revocationEpoch,
        vaultRefs: token.vaultRefs ?? {},
        auditReceiptIds: [],
      },
    };
    this.auditEvent("grant.create", {
      objectId: grant.id,
      grantId: grant.grantId,
      allowed: grant.allowed,
      denied: grant.denied,
      expiresAt: grant.expiresAt,
    });
    return grant;
  }

  authorizeScope(token, requiredScope) {
    if (token.revokedAt) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Capability token has been revoked.",
        details: { requiredScope, grantId: token.grantId, revocationEpoch: token.revocationEpoch },
      });
    }
    if (Date.parse(token.expiresAt) <= this.now().getTime()) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Capability token has expired.",
        details: { requiredScope, grantId: token.grantId },
      });
    }
    if (matchesAny(requiredScope, token.denied) || !matchesAny(requiredScope, token.allowed)) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Capability token does not grant the required scope.",
        details: { requiredScope, grantId: token.grantId },
      });
    }
    this.auditEvent("scope.authorize", {
      objectId: token.id,
      grantId: token.grantId,
      requiredScope,
      revocationEpoch: token.revocationEpoch,
    });
    emitRemoteBoundaryEvent(process.env.IOI_WALLET_NETWORK_URL, "/grants/authorize", {
      port: "WalletAuthorityPort",
      grantId: token.grantId,
      requiredScope,
      revocationEpoch: token.revocationEpoch,
      tokenIdHash: stableHash(token.id),
    });
    return this.recordLastUsed(token, requiredScope);
  }

  recordLastUsed(token, requiredScope) {
    return {
      ...token,
      lastUsedAt: new Date(this.now().getTime()).toISOString(),
      lastUsedScope: requiredScope,
    };
  }

  revokeGrant(token) {
    const revoked = {
      ...token,
      revokedAt: new Date(this.now().getTime()).toISOString(),
      revocationEpoch: Number(token.revocationEpoch ?? 0) + 1,
    };
    this.auditEvent("grant.revoke", {
      objectId: revoked.id,
      grantId: revoked.grantId,
      revocationEpoch: revoked.revocationEpoch,
    });
    return revoked;
  }

  resolveVaultRef(vaultRef) {
    if (typeof vaultRef !== "string" || !vaultRef.startsWith("vault://")) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Secrets must be referenced through wallet.network vault refs.",
        details: { vaultRef: SECRET_REDACTION },
      });
    }
    this.auditEvent("vault.resolve", {
      objectId: vaultRef,
      vaultRefHash: stableHash(vaultRef),
      resolvedMaterial: false,
    });
    return { vaultRefHash: stableHash(vaultRef), resolvedMaterial: false };
  }

  auditEvent(kind, payload) {
    const objectId = String(payload.objectId ?? payload.grantId ?? kind);
    const safeObjectId = objectId.startsWith("vault://")
      ? `vault_ref_${stableHash(objectId).slice(0, 16)}`
      : objectId;
    const safePayload = redact({ ...payload, objectId: safeObjectId });
    emitRemoteBoundaryEvent(process.env.IOI_WALLET_NETWORK_URL, "/audit", {
      port: "WalletAuthorityPort",
      kind,
      ...safePayload,
    });
    this.appendOperation?.(`wallet.${kind}`, {
      ...safePayload,
      details: safePayload,
    });
  }

  adapterStatus() {
    return {
      port: "WalletAuthorityPort",
      implementation: "agentgres_wallet_authority",
      methods: ["createGrant", "authorizeScope", "revokeGrant", "resolveVaultRef", "auditEvent", "recordLastUsed"],
      remoteAdapter: process.env.IOI_WALLET_NETWORK_URL
        ? { configured: true, urlHash: stableHash(process.env.IOI_WALLET_NETWORK_URL) }
        : { configured: false, failClosed: true },
      evidenceRefs: ["wallet.network.capability_grant", "wallet.network.vault_ref_boundary"],
    };
  }
}
