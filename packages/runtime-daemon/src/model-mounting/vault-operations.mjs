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
  void state;
  const { requiredString: requiredStringDep = requiredString } = deps;
  assertCanonicalVaultOperationRequestBody(body);
  const vaultRef = requiredStringDep(body.vault_ref, "vault_ref");
  const material = requiredStringDep(body.material, "material");
  throwVaultRustCoreRequired(
    "model_mount.vault_ref.bind",
    {
      vault_ref_hash_required: true,
      purpose: body.purpose ?? "operator_provider_auth_binding",
      label: body.label ?? null,
      request_fields: ["vault_ref", "material"],
      vault_ref_present: Boolean(vaultRef),
      material: material ? "[redacted]" : null,
    },
    deps,
  );
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

export function vaultHealth(state, deps = {}) {
  void state;
  throwVaultRustCoreRequired("model_mount.vault.health", {}, deps);
}

export function removeVaultRef(state, body = {}, deps = {}) {
  void state;
  const { requiredString: requiredStringDep = requiredString } = deps;
  assertCanonicalVaultOperationRequestBody(body);
  const vaultRef = requiredStringDep(body.vault_ref, "vault_ref");
  throwVaultRustCoreRequired(
    "model_mount.vault_ref.remove",
    {
      vault_ref_hash_required: true,
      purpose: body.purpose ?? "operator_provider_auth_remove",
      vault_ref_present: Boolean(vaultRef),
    },
    deps,
  );
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

function throwVaultRustCoreRequired(operation_kind, details = {}, deps = {}) {
  throw (deps.runtimeError ?? defaultRuntimeError)({
    status: 501,
    code: "model_mount_vault_rust_core_required",
    message:
      "Vault mutation and health receipt facades require Rust daemon-core wallet/cTEE custody ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.vault",
      evidence_refs: [
        "public_vault_js_facade_retired",
        "rust_daemon_core_wallet_vault_required",
        "rust_daemon_core_ctee_custody_required",
      ],
      ...details,
    },
  });
}

function defaultRuntimeError({ code, message, details, status }) {
  return Object.assign(new Error(message), { code, details, status });
}
