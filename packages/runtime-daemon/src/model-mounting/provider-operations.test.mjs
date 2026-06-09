import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function fakeState() {
  const state = {
    artifacts: new Map(),
    instances: new Map(),
    providers: new Map(),
    healthWrites: [],
    recordStateCommits: [],
    projections: 0,
    receipts: [],
    resolvedVaultRefs: [],
    writes: [],
    stateDir: "/state",
    now: "2026-06-03T22:00:00.000Z",
    drivers: new Map(),
    driverForProvider(provider) {
      return this.drivers.get(provider.id) ?? {};
    },
    lifecycleReceipt(kind, details) {
      const receipt = { id: `lifecycle.${kind}.${this.receipts.length + 1}`, kind, details };
      this.receipts.push(receipt);
      return receipt;
    },
    listArtifacts() {
      return [...this.artifacts.values()];
    },
    listInstances() {
      return [...this.instances.values()];
    },
    nowIso() {
      return this.now;
    },
    normalizeProviderSecretRef(kind, body = {}, existingSecretRef = null) {
      return normalizeProviderSecretRef(this, kind, body, existingSecretRef, providerDeps());
    },
    provider(providerId) {
      return this.providers.get(providerId);
    },
    receipt(kind, payload) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, payload };
      this.receipts.push(receipt);
      return receipt;
    },
    vault: {
      vaultRefMetadata(vaultRef) {
        return { vaultRefHash: `vault-hash:${vaultRef}`, resolvedMaterial: true };
      },
    },
    walletAuthority: {
      resolveVaultRef: (vaultRef) => {
        state.resolvedVaultRefs.push(vaultRef);
        return { vaultRefHash: `vault-hash:${vaultRef}` };
      },
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(JSON.parse(JSON.stringify(request)));
      return {
        source: "rust_agentgres_runtime_model_mount_record_state_commit_command",
        backend: "rust_agentgres_storage",
        record: {
          schema_version: "ioi.runtime_model_mount_record_state_commit.v1",
          record_dir: request.record_dir,
          record_id: request.record_id,
          operation_kind: request.operation_kind,
          storage_backend_ref: request.storage_backend_ref,
          record: {
            record_path: `${request.record_dir}/${request.record_id}.json`,
            object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`,
            content_hash: "sha256:model-mount-record-content",
            payload_refs: [`payload://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`],
            receipt_refs: request.receipt_refs,
            admission: { admission_hash: "sha256:model-mount-record-admission" },
          },
          commit_hash: "sha256:model-mount-record-commit",
        },
        storage_record: {
          record_path: `${request.record_dir}/${request.record_id}.json`,
          object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`,
          content_hash: "sha256:model-mount-record-content",
          payload_refs: [`payload://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`],
          receipt_refs: request.receipt_refs,
          admission: { admission_hash: "sha256:model-mount-record-admission" },
        },
        record_dir: request.record_dir,
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}/records/${request.record_dir}/${request.record_id}.json`,
        content_hash: "sha256:model-mount-record-content",
        admission_hash: "sha256:model-mount-record-admission",
        commit_hash: "sha256:model-mount-record-commit",
        written_record: { record_path: `${request.record_dir}/${request.record_id}.json` },
        evidence_refs: ["rust_agentgres_runtime_model_mount_record_state_commit"],
      };
    },
    writeProjection() {
      this.projections += 1;
    },
  };
  return state;
}

const deps = {
  assertNoPlaintextProviderSecret(body) {
    if (body.api_key || body.apiKey) throw new Error("plaintext provider secret");
  },
  driverForProviderKind(kind) {
    return `driver.${kind}`;
  },
  normalizeProviderAuthHeaderName(value) {
    return String(value ?? "authorization").toLowerCase();
  },
  normalizeProviderAuthScheme(value) {
    return String(value ?? "bearer").toLowerCase().replace(/[-\s]+/g, "_");
  },
  normalizeScopes(value, fallback = []) {
    return Array.isArray(value) ? value : fallback;
  },
  providerHasVaultRef(provider) {
    return typeof provider?.secretRef === "string" && provider.secretRef.startsWith("vault://");
  },
  providerHealthFailureStatus(error) {
    return error.status === 403 ? "blocked" : "degraded";
  },
  providerRequiresVaultSecret(kind) {
    return ["openai", "anthropic", "gemini"].includes(kind);
  },
  providerSecretInput(body) {
    if (Object.prototype.hasOwnProperty.call(body, "api_key_vault_ref")) return body.api_key_vault_ref;
    if (Object.prototype.hasOwnProperty.call(body, "auth_vault_ref")) return body.auth_vault_ref;
    if (Object.prototype.hasOwnProperty.call(body, "secret_ref")) return body.secret_ref;
    return undefined;
  },
  publicProvider(provider, vaultMetadata = null) {
    return {
      id: provider.id,
      kind: provider.kind,
      status: provider.status,
      secretRef: provider.secretRef ? { redacted: true, hash: `hash:${provider.secretRef}` } : null,
      vaultBoundary: vaultMetadata ? { runtimeBound: true } : null,
    };
  },
  safeFileName(value) {
    return String(value).replace(/[^a-z0-9._-]+/gi, "_");
  },
  safeId(value) {
    return String(value).replace(/[^a-z0-9]+/gi, "_");
  },
  writeJson(filePath, value) {
    deps.healthWrites.push({ filePath, value });
  },
  healthWrites: [],
};

function providerDeps(overrides = {}) {
  deps.healthWrites = [];
  return { ...deps, ...overrides };
}

function upsertProvider(state, body = {}) {
  return ModelMountingState.prototype.upsertProvider.call(state, body);
}

function normalizeProviderSecretRef(state, kind, body = {}, existingSecretRef = null) {
  return ModelMountingState.prototype.normalizeProviderSecretRef.call(
    state,
    kind,
    body,
    existingSecretRef,
  );
}

function providerHealth(state, providerId) {
  return ModelMountingState.prototype.providerHealth.call(state, providerId);
}

function listProviderModels(state, providerId) {
  return ModelMountingState.prototype.listProviderModels.call(state, providerId);
}

function listProviderLoaded(state, providerId) {
  return ModelMountingState.prototype.listProviderLoaded.call(state, providerId);
}

function startProvider(state, providerId) {
  return ModelMountingState.prototype.startProvider.call(state, providerId);
}

function stopProvider(state, providerId) {
  return ModelMountingState.prototype.stopProvider.call(state, providerId);
}

test("mounted provider driver factory fails closed before JS driver allocation", () => {
  const state = fakeState();
  state.providers.set("provider.openai", {
    id: "provider.openai",
    kind: "openai",
    driver: "openai_compatible",
    status: "configured",
  });

  assert.throws(
    () => ModelMountingState.prototype.driverForProvider.call(state, state.providers.get("provider.openai")),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_provider_driver_factory_retired");
      assert.equal(error.details.rust_core_boundary, "model_mount.provider_execution");
      assert.equal(error.details.operation_kind, "model_mount.provider.driver_factory");
      assert.equal(error.details.provider_id, "provider.openai");
      assert.equal(error.details.provider_kind, "openai");
      assert.equal(error.details.evidence_refs.includes("js_provider_driver_factory_retired"), true);
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "providerKind"), false);
      return true;
    },
  );
});

test("provider upsert fails closed before vault resolution, record-state commit, or provider mutation", () => {
  const state = fakeState();

  assert.throws(
    () =>
      upsertProvider(
        state,
        {
          id: "provider.openai",
          kind: "openai",
          label: "OpenAI",
          api_key_vault_ref: "vault://provider/openai",
          auth_header_name: "X-API-Key",
          api_format: "openai",
          base_url: "https://api.openai.example/v1",
          privacy_class: "hosted_private",
          evidence_refs: ["operator_provider_config", "wallet.network.vault_ref_boundary"],
          capabilities: ["chat", "responses"],
        },
        providerDeps(),
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_provider_control_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.provider_control");
      assert.equal(error.details.operation, "provider_upsert");
      assert.equal(error.details.operation_kind, "model_mount.provider.write");
      assert.equal(error.details.provider_id, "provider.openai");
      assert.equal(error.details.provider_kind, "openai");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "providerKind"), false);
      return true;
    },
  );

  assert.equal(state.providers.has("provider.openai"), false);
  assert.deepEqual(state.resolvedVaultRefs, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
});

test("provider upsert rejects retired request aliases before vault resolution or state write", () => {
  const state = fakeState();

  assert.throws(
    () =>
      upsertProvider(
        state,
        {
          id: "provider.openai",
          kind: "openai",
          api_key_vault_ref: "vault://provider/openai",
          authScheme: "api_key",
          authHeaderName: "X-API-Key",
          apiFormat: "openai",
          baseUrl: "https://api.openai.example/v1",
          privacyClass: "hosted_private",
          evidenceRefs: ["operator_provider_config"],
        },
        providerDeps(),
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "provider_upsert_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "authScheme",
        "authHeaderName",
        "apiFormat",
        "baseUrl",
        "privacyClass",
        "evidenceRefs",
      ]);
      assert.deepEqual(error.details.canonical_fields, [
        "auth_scheme",
        "auth_header_name",
        "api_format",
        "base_url",
        "privacy_class",
        "evidence_refs",
      ]);
      return true;
    },
  );
  assert.deepEqual(state.resolvedVaultRefs, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.providers.has("provider.openai"), false);
});

test("provider secret normalization rejects plaintext and preserves existing vault refs", () => {
  const state = fakeState();

  assert.equal(
    normalizeProviderSecretRef(state, "openai", {}, "vault://provider/existing", providerDeps()),
    "vault://provider/existing",
  );
  assert.throws(
    () => normalizeProviderSecretRef(state, "openai", { api_key: "plain" }, null, providerDeps()),
    /Provider secrets and auth headers/,
  );
  assert.equal(normalizeProviderSecretRef(state, "openai", { secret_ref: "" }, null, providerDeps()), null);
});

test("provider health mutation facade fails closed before JS driver, receipt, or provider write", async () => {
  const state = fakeState();
  let healthCalls = 0;
  state.providers.set("provider.fixture", {
    id: "provider.fixture",
    kind: "fixture",
    driver: "fixture",
    apiFormat: "ioi_fixture",
    label: "Fixture",
    status: "configured",
    secretRef: "vault://provider/fixture",
    discovery: { evidenceRefs: ["operator_provider_config"] },
  });
  state.drivers.set("provider.fixture", {
    async health() {
      healthCalls += 1;
      return {
        status: "available",
        httpStatus: 200,
        evidenceRefs: ["provider_http_health"],
        authEvidence: {
          vaultRefHash: "vault-hash:provider",
          evidenceRefs: ["VaultPort.resolveVaultRef"],
          headerNames: ["authorization"],
        },
        model_mount_provider_lifecycle: {
          action: "health",
          status: "available",
          lifecycle_hash: "sha256:fixture-health",
          evidence_refs: ["rust_model_mount_provider_lifecycle"],
          execution_backend: "rust_model_mount_fixture_lifecycle",
          backend_id: "backend.fixture",
        },
      };
    },
  });
  const currentDeps = providerDeps();

  await assert.rejects(
    () => providerHealth(state, "provider.fixture", currentDeps),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_provider_health_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.provider_health");
      assert.equal(error.details.operation, "provider_health");
      assert.equal(error.details.operation_kind, "model_mount.provider.health");
      assert.equal(error.details.provider_id, "provider.fixture");
      assert.equal(error.details.provider_kind, "fixture");
      assert.equal(error.details.provider_driver, "fixture");
      assert.equal(error.details.api_format, "ioi_fixture");
      assert.deepEqual(error.details.evidence_refs, [
        "model_mount_provider_health_js_facade_retired",
        "rust_daemon_core_provider_health_required",
        "agentgres_provider_health_record_truth_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "providerKind"), false);
      return true;
    },
  );

  assert.equal(healthCalls, 0);
  assert.equal(state.providers.get("provider.fixture").status, "configured");
  assert.equal(state.providers.get("provider.fixture").discovery.lastHealthCheck, undefined);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.projections, 0);
});

test("hosted provider health fails closed before JS driver execution", async () => {
  const state = fakeState();
  let healthCalls = 0;
  state.providers.set("provider.remote", {
    id: "provider.remote",
    kind: "custom_http",
    label: "Remote",
    status: "configured",
    discovery: { evidenceRefs: ["operator_provider_config"] },
  });
  state.drivers.set("provider.remote", {
    async health() {
      healthCalls += 1;
      const error = new Error("auth failed");
      error.status = 403;
      error.code = "policy";
      error.details = {
        http_status: 401,
        provider_error_hash: "hash:error",
        adapter: "remote_provider_adapter",
        evidence_refs: ["provider_auth_fail_closed"],
      };
      throw error;
    },
  });
  const currentDeps = providerDeps();

  await assert.rejects(
    () => providerHealth(state, "provider.remote", currentDeps),
    (error) => {
      assert.equal(error.code, "model_mount_provider_health_rust_core_required");
      assert.equal(error.status, 501);
      assert.equal(error.details.operation, "provider_health");
      assert.equal(error.details.provider_id, "provider.remote");
      assert.equal(error.details.provider_kind, "custom_http");
      assert.equal(error.details.provider_driver, null);
      assert.equal(error.details.api_format, null);
      assert.equal(Object.hasOwn(error.details, "providerHealthStatus"), false);
      assert.equal(Object.hasOwn(error.details, "providerHealthReceiptId"), false);
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "providerKind"), false);
      assert.equal(Object.hasOwn(error.details, "failureCode"), false);
      assert.equal(Object.hasOwn(error.details, "failureStatus"), false);
      assert.equal(Object.hasOwn(error.details, "httpStatus"), false);
      assert.equal(Object.hasOwn(error.details, "providerErrorHash"), false);
      return true;
    },
  );
  assert.equal(healthCalls, 0);
  assert.equal(state.providers.get("provider.remote").status, "configured");
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.projections, 0);
});

test("provider health does not depend on retired JS Agentgres record-state commit shim", async () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;
  state.providers.set("provider.fixture", {
    id: "provider.fixture",
    kind: "fixture",
    driver: "fixture",
    apiFormat: "ioi_fixture",
    label: "Fixture",
    status: "configured",
    discovery: { evidenceRefs: ["operator_provider_config"] },
  });
  state.drivers.set("provider.fixture", {
    async health() {
      return {
        status: "available",
        evidenceRefs: ["provider_http_health"],
        model_mount_provider_lifecycle: {
          action: "health",
          status: "available",
          lifecycle_hash: "sha256:fixture-health",
          evidence_refs: ["rust_model_mount_provider_lifecycle"],
          execution_backend: "rust_model_mount_fixture_lifecycle",
          backend_id: "backend.fixture",
        },
      };
    },
  });

  await assert.rejects(
    () => providerHealth(state, "provider.fixture", providerDeps()),
    (error) =>
      error.code === "model_mount_provider_health_rust_core_required" &&
      error.details.provider_id === "provider.fixture" &&
      error.details.provider_kind === "fixture",
  );
  assert.equal(state.providers.get("provider.fixture").status, "configured");
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.projections, 0);
});

test("local provider health also fails closed until direct Rust core control exists", async () => {
  const state = fakeState();
  let healthCalls = 0;
  state.providers.set("provider.local", {
    id: "provider.local",
    kind: "ioi_native_local",
    label: "Native",
    status: "configured",
    discovery: { evidenceRefs: ["native_provider"] },
  });
  state.drivers.set("provider.local", {
    async health() {
      healthCalls += 1;
      return {
        status: "available",
        evidenceRefs: ["rust_model_mount_provider_lifecycle"],
        lifecycleHash: "sha256:health",
        model_mount_provider_lifecycle: {
          action: "health",
          status: "available",
          lifecycle_hash: "sha256:health",
          evidence_refs: ["rust_model_mount_provider_lifecycle"],
          execution_backend: "rust_model_mount_native_local_lifecycle",
          backend_id: "backend.native",
        },
      };
    },
  });

  await assert.rejects(
    () => providerHealth(state, "provider.local", providerDeps()),
    (error) =>
      error.code === "model_mount_provider_health_rust_core_required" &&
      error.details.operation === "provider_health" &&
      error.details.provider_id === "provider.local" &&
      error.details.provider_kind === "ioi_native_local" &&
      Object.hasOwn(error.details, "providerId") === false &&
      Object.hasOwn(error.details, "providerKind") === false,
  );
  assert.equal(healthCalls, 0);
  assert.equal(state.providers.get("provider.local").status, "configured");
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.projections, 0);
});

test("provider inventory list facades fail closed before JS driver or local fallback reads", async () => {
  const state = fakeState();
  let listModelCalls = 0;
  let listLoadedCalls = 0;
  let listArtifactsCalls = 0;
  let listInstancesCalls = 0;
  state.providers.set("provider.test", {
    id: "provider.test",
    kind: "custom_http",
    label: "Remote",
    status: "available",
    discovery: { evidenceRefs: ["remote_provider"] },
  });
  state.artifacts.set("artifact.local", { id: "artifact.local", providerId: "provider.test" });
  state.instances.set("instance.local", { id: "instance.local", providerId: "provider.test", status: "loaded" });
  state.listArtifacts = () => {
    listArtifactsCalls += 1;
    return [...state.artifacts.values()];
  };
  state.listInstances = () => {
    listInstancesCalls += 1;
    return [...state.instances.values()];
  };
  state.drivers.set("provider.test", {
    async listModels() {
      listModelCalls += 1;
      return [];
    },
    async listLoaded() {
      listLoadedCalls += 1;
      return [];
    },
  });

  await assert.rejects(
    () => listProviderModels(state, "provider.test"),
    (error) =>
      error.code === "model_mount_provider_inventory_rust_core_required" &&
      error.status === 501 &&
      error.details.rust_core_boundary === "model_mount.provider_inventory" &&
      error.details.operation === "provider_models_list" &&
      error.details.operation_kind === "model_mount.provider.inventory.list_models" &&
      error.details.provider_id === "provider.test" &&
      error.details.provider_kind === "custom_http" &&
      error.details.evidence_refs.includes("model_mount_provider_inventory_js_facade_retired") &&
      error.details.evidence_refs.includes("rust_daemon_core_provider_inventory_required") &&
      error.details.evidence_refs.includes("agentgres_provider_inventory_projection_required") &&
      Object.hasOwn(error.details, "providerId") === false,
  );
  await assert.rejects(
    () => listProviderLoaded(state, "provider.test"),
    (error) =>
      error.code === "model_mount_provider_inventory_rust_core_required" &&
      error.status === 501 &&
      error.details.rust_core_boundary === "model_mount.provider_inventory" &&
      error.details.operation === "provider_loaded_list" &&
      error.details.operation_kind === "model_mount.provider.inventory.list_loaded" &&
      error.details.provider_id === "provider.test" &&
      error.details.provider_kind === "custom_http" &&
      Object.hasOwn(error.details, "providerId") === false,
  );

  assert.equal(listModelCalls, 0);
  assert.equal(listLoadedCalls, 0);
  assert.equal(listArtifactsCalls, 0);
  assert.equal(listInstancesCalls, 0);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
});

test("local provider inventory also fails closed until direct Rust projection exists", async () => {
  const state = fakeState();
  let listModelCalls = 0;
  let listLoadedCalls = 0;
  state.providers.set("provider.local", {
    id: "provider.local",
    kind: "ioi_native_local",
    label: "Native",
    status: "available",
    discovery: { evidenceRefs: ["native_provider"] },
  });
  state.drivers.set("provider.local", {
    async listModels() {
      listModelCalls += 1;
      return Object.assign([{ id: "artifact.native", providerId: "provider.local" }], {
        model_mount_provider_inventory: {
          action: "list_models",
          status: "listed",
          inventory_hash: "sha256:list-models",
          evidence_refs: ["rust_model_mount_provider_inventory"],
          execution_backend: "rust_model_mount_native_local_inventory",
          item_count: 1,
        },
      });
    },
    async listLoaded() {
      listLoadedCalls += 1;
      return Object.assign([{ id: "instance.native", providerId: "provider.local", status: "loaded" }], {
        model_mount_provider_inventory: {
          action: "list_loaded",
          status: "listed",
          inventory_hash: "sha256:list-loaded",
          evidence_refs: ["rust_model_mount_provider_inventory"],
          execution_backend: "rust_model_mount_native_local_inventory",
          item_count: 1,
        },
      });
    },
  });

  await assert.rejects(
    () => listProviderModels(state, "provider.local"),
    (error) =>
      error.code === "model_mount_provider_inventory_rust_core_required" &&
      error.details.rust_core_boundary === "model_mount.provider_inventory" &&
      error.details.operation === "provider_models_list" &&
      error.details.operation_kind === "model_mount.provider.inventory.list_models" &&
      Object.hasOwn(error.details, "providerId") === false,
  );
  await assert.rejects(
    () => listProviderLoaded(state, "provider.local"),
    (error) =>
      error.code === "model_mount_provider_inventory_rust_core_required" &&
      error.details.rust_core_boundary === "model_mount.provider_inventory" &&
      error.details.operation === "provider_loaded_list" &&
      error.details.operation_kind === "model_mount.provider.inventory.list_loaded" &&
      Object.hasOwn(error.details, "providerId") === false,
  );

  assert.equal(listModelCalls, 0);
  assert.equal(listLoadedCalls, 0);
  assert.equal(state.artifacts.has("artifact.native"), false);
  assert.equal(state.instances.has("instance.native"), false);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.projections, 0);
});

test("provider inventory facade does not depend on retired JS artifact record-state commit", async () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;
  let listModelCalls = 0;
  state.providers.set("provider.local", {
    id: "provider.local",
    kind: "ioi_native_local",
    label: "Native",
    status: "available",
    discovery: { evidenceRefs: ["native_provider"] },
  });
  state.drivers.set("provider.local", {
    async listModels() {
      listModelCalls += 1;
      return Object.assign([{ id: "artifact.native", providerId: "provider.local", modelId: "native" }], {
        model_mount_provider_inventory: {
          action: "list_models",
          status: "listed",
          inventory_hash: "sha256:list-models",
          evidence_refs: ["rust_model_mount_provider_inventory"],
          execution_backend: "rust_model_mount_native_local_inventory",
          item_count: 1,
        },
      });
    },
  });

  await assert.rejects(
    () => listProviderModels(state, "provider.local"),
    (error) =>
      error.code === "model_mount_provider_inventory_rust_core_required" &&
      error.details.rust_core_boundary === "model_mount.provider_inventory" &&
      error.details.operation === "provider_models_list" &&
      error.details.operation_kind === "model_mount.provider.inventory.list_models" &&
      error.details.evidence_refs.includes("model_mount_provider_inventory_js_facade_retired") &&
      Object.hasOwn(error.details, "providerId") === false,
  );

  assert.equal(listModelCalls, 0);
  assert.equal(state.artifacts.has("artifact.native"), false);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.receipts, []);
});

test("provider start and stop fail closed until direct Rust core control exists", async () => {
  const state = fakeState();
  let startCalls = 0;
  let stopCalls = 0;
  state.providers.set("provider.custom", {
    id: "provider.custom",
    kind: "custom_http",
    label: "Custom",
    status: "configured",
    discovery: { evidenceRefs: ["operator_provider_config"] },
  });
  state.drivers.set("provider.custom", {
    async start() {
      startCalls += 1;
      return { status: "available" };
    },
    async stop() {
      stopCalls += 1;
      return { status: "stopped" };
    },
  });

  await assert.rejects(
    () => startProvider(state, "provider.custom", providerDeps()),
    (error) =>
      error.code === "model_mount_provider_control_rust_core_required" &&
      error.status === 501 &&
      error.details.operation === "provider_start" &&
      error.details.provider_id === "provider.custom" &&
      error.details.provider_kind === "custom_http" &&
      Object.hasOwn(error.details, "providerId") === false &&
      Object.hasOwn(error.details, "providerKind") === false,
  );
  await assert.rejects(
    () => stopProvider(state, "provider.custom", providerDeps()),
    (error) =>
      error.code === "model_mount_provider_control_rust_core_required" &&
      error.status === 501 &&
      error.details.operation === "provider_stop" &&
      error.details.provider_id === "provider.custom" &&
      error.details.provider_kind === "custom_http" &&
      Object.hasOwn(error.details, "providerId") === false &&
      Object.hasOwn(error.details, "providerKind") === false,
  );
  assert.equal(startCalls, 0);
  assert.equal(stopCalls, 0);
  assert.equal(state.providers.get("provider.custom").status, "configured");
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
});

test("local provider start and stop fail closed until direct Rust core control exists", async () => {
  const state = fakeState();
  state.providers.set("provider.local", {
    id: "provider.local",
    kind: "ioi_native_local",
    label: "Native",
    status: "configured",
    discovery: { evidenceRefs: ["native_provider"] },
  });
  state.drivers.set("provider.local", {});

  await assert.rejects(
    () => startProvider(state, "provider.local", providerDeps()),
    (error) => error.code === "model_mount_provider_control_rust_core_required" &&
      error.details.operation === "provider_start" &&
      error.details.provider_id === "provider.local" &&
      error.details.provider_kind === "ioi_native_local" &&
      Object.hasOwn(error.details, "providerId") === false &&
      Object.hasOwn(error.details, "providerKind") === false,
  );
  await assert.rejects(
    () => stopProvider(state, "provider.local", providerDeps()),
    (error) => error.code === "model_mount_provider_control_rust_core_required" &&
      error.details.operation === "provider_stop" &&
      error.details.provider_id === "provider.local" &&
      error.details.provider_kind === "ioi_native_local" &&
      Object.hasOwn(error.details, "providerId") === false &&
      Object.hasOwn(error.details, "providerKind") === false,
  );
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.receipts, []);
});
