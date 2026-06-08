import {
  emitRemoteBoundaryEvent,
  redact,
  runtimeError,
  stableHash,
} from "./io.mjs";

const SECRET_REDACTION = "[REDACTED]";

export class AgentgresWalletAuthority {
  constructor({ now }) {
    this.now = now;
  }

  resolveVaultRef(vaultRef) {
    if (typeof vaultRef !== "string" || !vaultRef.startsWith("vault://")) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Secrets must be referenced through wallet.network vault refs.",
        details: { vault_ref: SECRET_REDACTION },
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
  }

  adapterStatus() {
    return {
      port: "WalletAuthorityPort",
      implementation: "wallet_network_vault_ref_boundary",
      methods: ["resolveVaultRef", "auditEvent"],
      remoteAdapter: process.env.IOI_WALLET_NETWORK_URL
        ? { configured: true, urlHash: stableHash(process.env.IOI_WALLET_NETWORK_URL) }
        : { configured: false, failClosed: true },
      evidenceRefs: ["wallet.network.vault_ref_boundary"],
    };
  }
}
