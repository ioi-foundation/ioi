import { requiredString } from "./provider-registry.mjs";

const RETIRED_VAULT_OPERATION_REQUEST_ALIASES = [
  "vaultRef",
  "secret",
  "value",
];

const CANONICAL_VAULT_OPERATION_REQUEST_FIELDS = [
  "vault_ref",
  "material",
];

export function bindVaultRef(state, body = {}, deps = {}) {
  const { requiredString: requiredStringDep = requiredString } = deps;
  assertCanonicalVaultOperationRequestBody(body);
  const vaultRef = requiredStringDep(body.vault_ref, "vault_ref");
  const material = requiredStringDep(body.material, "material");
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
  assertCanonicalVaultOperationRequestBody(body);
  const vaultRef = requiredStringDep(body.vault_ref, "vault_ref");
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
  assertCanonicalVaultOperationRequestBody(body);
  const vaultRef = requiredStringDep(body.vault_ref, "vault_ref");
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

function assertCanonicalVaultOperationRequestBody(body = {}) {
  const retiredAliases = RETIRED_VAULT_OPERATION_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error("Vault operation request aliases are retired; use canonical snake_case request fields.");
  error.status = 400;
  error.code = "vault_operation_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_VAULT_OPERATION_REQUEST_FIELDS,
  };
  throw error;
}
