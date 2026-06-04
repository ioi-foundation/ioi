import { requiredString } from "./provider-registry.mjs";

export function bindVaultRef(state, body = {}, deps = {}) {
  const { requiredString: requiredStringDep = requiredString } = deps;
  const vaultRef = requiredStringDep(body.vault_ref ?? body.vaultRef, "vault_ref");
  const material = requiredStringDep(body.material ?? body.secret ?? body.value, "material");
  const metadata = state.vault.bindVaultRef({
    vaultRef,
    material,
    purpose: body.purpose ?? "operator_provider_auth_binding",
    label: body.label ?? null,
  });
  state.writeVaultRefs();
  const receipt = state.receipt("vault_ref_binding", {
    summary: `Vault material bound for ${metadata.vaultRefHash}.`,
    redaction: "redacted",
    evidenceRefs: ["VaultPort.bindVaultRef", metadata.vaultRefHash],
    details: metadata,
  });
  state.writeProjection();
  return { ...metadata, receiptId: receipt.id };
}

export function listVaultRefs(state) {
  return state.vault.listVaultRefs();
}

export function vaultRefMetadata(state, body = {}, deps = {}) {
  const { requiredString: requiredStringDep = requiredString } = deps;
  const vaultRef = requiredStringDep(body.vault_ref ?? body.vaultRef, "vault_ref");
  return state.vault.vaultRefMetadata(vaultRef);
}

export function vaultStatus(state) {
  return state.vault.adapterStatus();
}

export function vaultHealth(state) {
  const health = state.vault.health();
  const receipt = state.receipt("vault_adapter_health", {
    summary: `Vault adapter health is ${health.status}.`,
    redaction: "redacted",
    evidenceRefs: health.evidenceRefs,
    details: health,
  });
  return { ...health, receiptId: receipt.id };
}

export function removeVaultRef(state, body = {}, deps = {}) {
  const { requiredString: requiredStringDep = requiredString } = deps;
  const vaultRef = requiredStringDep(body.vault_ref ?? body.vaultRef, "vault_ref");
  const metadata = state.vault.removeVaultRef(
    vaultRef,
    body.purpose ?? "operator_provider_auth_remove",
  );
  state.writeVaultRefs();
  const receipt = state.receipt("vault_ref_removal", {
    summary: `Vault material removed for ${metadata.vaultRefHash}.`,
    redaction: "redacted",
    evidenceRefs: ["VaultPort.removeVaultRef", metadata.vaultRefHash],
    details: metadata,
  });
  state.writeProjection();
  return { ...metadata, receiptId: receipt.id };
}
