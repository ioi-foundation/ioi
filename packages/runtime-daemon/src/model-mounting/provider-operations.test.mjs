import assert from "node:assert/strict";
import test from "node:test";

import {
  listProviderLoaded,
  listProviderModels,
  normalizeProviderSecretRef,
  providerHealth,
  startProvider,
  stopProvider,
  upsertProvider,
} from "./provider-operations.mjs";

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

test("provider upsert normalizes hosted provider state and keeps secret refs vault-bound", () => {
  const state = fakeState();
  const result = upsertProvider(
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
  );

  assert.equal(result.id, "provider.openai");
  assert.equal(result.status, "configured");
  assert.deepEqual(result.secretRef, { redacted: true, hash: "hash:vault://provider/openai" });
  assert.equal(state.providers.get("provider.openai").driver, "driver.openai");
  assert.equal(state.providers.get("provider.openai").authHeaderName, "x-api-key");
  assert.equal(state.providers.get("provider.openai").apiFormat, "openai");
  assert.equal(state.providers.get("provider.openai").baseUrl, "https://api.openai.example/v1");
  assert.equal(state.providers.get("provider.openai").privacyClass, "hosted_private");
  assert.deepEqual(state.providers.get("provider.openai").discovery.evidenceRefs, [
    "operator_provider_config",
    "wallet.network.vault_ref_boundary",
  ]);
  assert.deepEqual(state.providers.get("provider.openai").capabilities, ["chat", "responses"]);
  assert.deepEqual(state.resolvedVaultRefs, ["vault://provider/openai"]);
  assert.deepEqual(state.writes, []);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].schema_version, "ioi.runtime_model_mount_record_state_commit.v1");
  assert.equal(state.recordStateCommits[0].record_dir, "model-providers");
  assert.equal(state.recordStateCommits[0].record_id, "provider.openai");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.provider.write");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, []);
  assert.equal(state.recordStateCommits[0].record.kind, "openai");
});

test("provider upsert fails closed without Rust Agentgres provider record-state commit", () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () =>
      upsertProvider(
        state,
        {
          id: "provider.openai",
          kind: "openai",
          api_key_vault_ref: "vault://provider/openai",
        },
        providerDeps(),
      ),
    (error) => {
      assert.equal(error.code, "model_mount_provider_state_commit_unconfigured");
      assert.equal(error.details.provider_id, "provider.openai");
      assert.equal(error.details.provider_kind, "openai");
      assert.equal(error.details.record_dir, "model-providers");
      return true;
    },
  );

  assert.equal(state.providers.has("provider.openai"), false);
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
    /plaintext provider secret/,
  );
  assert.equal(normalizeProviderSecretRef(state, "openai", { secret_ref: "" }, null, providerDeps()), null);
});

test("provider health success persists public health and vault metadata boundary", async () => {
  const state = fakeState();
  state.providers.set("provider.openai", {
    id: "provider.openai",
    kind: "openai",
    label: "OpenAI",
    status: "configured",
    secretRef: "vault://provider/openai",
    discovery: { evidenceRefs: ["operator_provider_config"] },
  });
  state.drivers.set("provider.openai", {
    async health() {
      return {
        status: "available",
        httpStatus: 200,
        evidenceRefs: ["provider_http_health"],
        authEvidence: {
          vaultRefHash: "vault-hash:provider",
          evidenceRefs: ["VaultPort.resolveVaultRef"],
          headerNames: ["authorization"],
        },
      };
    },
  });
  const currentDeps = providerDeps();

  const result = await providerHealth(state, "provider.openai", currentDeps);

  assert.equal(result.status, "available");
  assert.equal(result.vaultBoundary.runtimeBound, true);
  assert.equal(state.providers.get("provider.openai").discovery.lastHealthCheck.httpStatus, 200);
  assert.equal(state.receipts.at(-1).kind, "provider_health");
  assert.equal(state.receipts.at(-1).payload.details.provider_id, "provider.openai");
  assert.equal(state.receipts.at(-1).payload.details.provider_kind, "openai");
  assert.equal(state.receipts.at(-1).payload.details.http_status, 200);
  assert.equal(state.receipts.at(-1).payload.details.auth_vault_ref_hash, "vault-hash:provider");
  assert.deepEqual(state.receipts.at(-1).payload.details.provider_auth_evidence_refs, ["VaultPort.resolveVaultRef"]);
  assert.deepEqual(state.receipts.at(-1).payload.details.provider_auth_header_names, ["authorization"]);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "providerId"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "providerKind"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "httpStatus"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "authVaultRefHash"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "providerAuthEvidenceRefs"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "providerAuthHeaderNames"), false);
  assert.equal(state.recordStateCommits[0].schema_version, "ioi.runtime_model_mount_record_state_commit.v1");
  assert.equal(state.recordStateCommits[0].record_dir, "model-providers");
  assert.equal(state.recordStateCommits[0].record_id, "provider.openai");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.provider.health_update");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt.provider_health.1"]);
  assert.equal(state.recordStateCommits[0].record.status, "available");
  assert.equal(state.recordStateCommits[1].record_dir, "provider-health");
  assert.equal(state.recordStateCommits[1].record_id, "health.provider_openai");
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.provider_health.write");
  assert.deepEqual(state.recordStateCommits[1].receipt_refs, ["receipt.provider_health.1"]);
  assert.equal(state.recordStateCommits[1].record.status, "available");
  assert.equal(state.projections, 1);
});

test("provider health failure updates provider status and augments thrown details", async () => {
  const state = fakeState();
  state.providers.set("provider.remote", {
    id: "provider.remote",
    kind: "custom_http",
    label: "Remote",
    status: "configured",
    discovery: { evidenceRefs: ["operator_provider_config"] },
  });
  state.drivers.set("provider.remote", {
    async health() {
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
      assert.equal(error.details.provider_health_status, "blocked");
      assert.equal(error.details.provider_health_receipt_id, "receipt.provider_health.1");
      assert.equal(error.details.provider_id, "provider.remote");
      assert.equal(error.details.provider_kind, "custom_http");
      assert.equal(error.details.failure_code, "policy");
      assert.equal(error.details.failure_status, 403);
      assert.equal(error.details.http_status, 401);
      assert.equal(error.details.provider_error_hash, "hash:error");
      assert.equal(error.details.adapter, "remote_provider_adapter");
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
  assert.equal(state.receipts.at(-1).payload.details.provider_id, "provider.remote");
  assert.equal(state.receipts.at(-1).payload.details.provider_kind, "custom_http");
  assert.equal(state.receipts.at(-1).payload.details.failure_code, "policy");
  assert.equal(state.receipts.at(-1).payload.details.failure_status, 403);
  assert.equal(state.receipts.at(-1).payload.details.http_status, 401);
  assert.equal(state.receipts.at(-1).payload.details.provider_error_hash, "hash:error");
  assert.equal(state.receipts.at(-1).payload.details.adapter, "remote_provider_adapter");
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "providerId"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "providerKind"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "failureCode"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "failureStatus"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "httpStatus"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "providerErrorHash"), false);
  assert.equal(state.providers.get("provider.remote").status, "blocked");
  assert.equal(state.recordStateCommits[0].record_dir, "model-providers");
  assert.equal(state.recordStateCommits[0].record.status, "blocked");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt.provider_health.1"]);
  assert.equal(state.recordStateCommits[1].record_dir, "provider-health");
  assert.equal(state.recordStateCommits[1].record.failureCode, "policy");
  assert.deepEqual(state.recordStateCommits[1].receipt_refs, ["receipt.provider_health.1"]);
  assert.equal(state.projections, 1);
});

test("provider health persistence fails closed without Rust Agentgres record-state commit", async () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;
  state.providers.set("provider.openai", {
    id: "provider.openai",
    kind: "openai",
    label: "OpenAI",
    status: "configured",
    discovery: { evidenceRefs: ["operator_provider_config"] },
  });
  state.drivers.set("provider.openai", {
    async health() {
      return {
        status: "available",
        evidenceRefs: ["provider_http_health"],
      };
    },
  });

  await assert.rejects(
    () => providerHealth(state, "provider.openai", providerDeps()),
    (error) =>
      error.code === "model_mount_provider_state_commit_unconfigured" &&
      error.details.provider_id === "provider.openai" &&
      error.details.provider_kind === "openai",
  );
  assert.equal(state.providers.get("provider.openai").status, "configured");
});

test("local provider health receipts carry Rust lifecycle bindings", async () => {
  const state = fakeState();
  state.providers.set("provider.local", {
    id: "provider.local",
    kind: "ioi_native_local",
    label: "Native",
    status: "configured",
    discovery: { evidenceRefs: ["native_provider"] },
  });
  state.drivers.set("provider.local", {
    async health() {
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

  await providerHealth(state, "provider.local", providerDeps());

  const details = state.receipts.at(-1).payload.details;
  assert.equal(details.provider_kind, "ioi_native_local");
  assert.equal(details.model_mount_provider_lifecycle_action, "health");
  assert.equal(details.model_mount_provider_lifecycle_status, "available");
  assert.equal(details.model_mount_provider_lifecycle_hash, "sha256:health");
  assert.deepEqual(details.model_mount_provider_lifecycle_evidence_refs, ["rust_model_mount_provider_lifecycle"]);
  assert.equal(Object.hasOwn(details, "providerKind"), false);
});

test("provider model and loaded lists use driver results or local fallbacks", async () => {
  const state = fakeState();
  state.providers.set("provider.test", {
    id: "provider.test",
    kind: "fixture",
    label: "Fixture",
    status: "available",
    discovery: { evidenceRefs: ["fixture_provider"] },
  });
  state.artifacts.set("artifact.local", { id: "artifact.local", providerId: "provider.test" });
  state.instances.set("instance.local", { id: "instance.local", providerId: "provider.test", status: "loaded" });
  state.drivers.set("provider.test", {
    async listModels() {
      return [];
    },
    async listLoaded() {
      return [];
    },
  });

  const models = await listProviderModels(state, "provider.test");
  const loaded = await listProviderLoaded(state, "provider.test");

  assert.deepEqual(models.map((record) => record.id), ["artifact.local"]);
  assert.deepEqual(loaded.map((record) => record.id), ["instance.local"]);
  assert.equal(state.receipts.at(-2).details.provider_kind, "fixture");
  assert.equal(state.receipts.at(-2).details.model_id, "Fixture");
  assert.equal(state.receipts.at(-2).details.model_count, 1);
  assert.equal(Object.hasOwn(state.receipts.at(-2).details, "providerKind"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-2).details, "modelId"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-2).details, "modelCount"), false);
  assert.equal(state.receipts.at(-1).details.provider_kind, "fixture");
  assert.equal(state.receipts.at(-1).details.model_id, "Fixture");
  assert.equal(state.receipts.at(-1).details.loaded_count, 1);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "providerKind"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "modelId"), false);
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "loadedCount"), false);
});

test("local provider model and loaded list receipts carry Rust inventory bindings", async () => {
  const state = fakeState();
  state.providers.set("provider.local", {
    id: "provider.local",
    kind: "ioi_native_local",
    label: "Native",
    status: "available",
    discovery: { evidenceRefs: ["native_provider"] },
  });
  state.drivers.set("provider.local", {
    async listModels() {
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

  await listProviderModels(state, "provider.local");
  await listProviderLoaded(state, "provider.local");

  assert.equal(state.receipts.at(-2).details.provider_kind, "ioi_native_local");
  assert.equal(state.receipts.at(-2).details.model_mount_provider_inventory_action, "list_models");
  assert.equal(state.receipts.at(-2).details.model_mount_provider_inventory_hash, "sha256:list-models");
  assert.equal(Object.hasOwn(state.receipts.at(-2).details, "providerKind"), false);
  assert.equal(state.receipts.at(-1).details.model_mount_provider_inventory_action, "list_loaded");
  assert.equal(state.receipts.at(-1).details.model_mount_provider_inventory_hash, "sha256:list-loaded");
  assert.equal(Object.hasOwn(state.receipts.at(-1).details, "providerKind"), false);
});

test("provider start and stop preserve stateless defaults and receipts", async () => {
  const state = fakeState();
  state.providers.set("provider.custom", {
    id: "provider.custom",
    kind: "custom_http",
    label: "Custom",
    status: "configured",
    discovery: { evidenceRefs: ["operator_provider_config"] },
  });
  state.drivers.set("provider.custom", {});

  const started = await startProvider(state, "provider.custom", providerDeps());
  const stopped = await stopProvider(state, "provider.custom", providerDeps());

  assert.equal(started.status, "available");
  assert.equal(stopped.status, "stopped");
  assert.equal(state.providers.get("provider.custom").discovery.lastStop.status, "stopped");
  assert.deepEqual(state.receipts.map((receipt) => receipt.kind), ["provider_start", "provider_stop"]);
  assert.deepEqual(state.receipts.map((receipt) => receipt.details.provider_id), ["provider.custom", "provider.custom"]);
  assert.deepEqual(state.receipts.map((receipt) => receipt.details.provider_kind), ["custom_http", "custom_http"]);
  assert.deepEqual(state.receipts.map((receipt) => receipt.details.model_id), ["Custom", "Custom"]);
  assert.deepEqual(state.receipts.map((receipt) => receipt.details.evidence_refs), [["provider_stateless_start"], ["provider_stateless_stop"]]);
  assert.deepEqual(state.receipts.map((receipt) => Object.hasOwn(receipt.details, "providerId")), [false, false]);
  assert.deepEqual(state.receipts.map((receipt) => Object.hasOwn(receipt.details, "providerKind")), [false, false]);
  assert.deepEqual(state.receipts.map((receipt) => Object.hasOwn(receipt.details, "modelId")), [false, false]);
  assert.deepEqual(state.receipts.map((receipt) => Object.hasOwn(receipt.details, "evidenceRefs")), [false, false]);
  assert.equal(state.recordStateCommits[0].record_dir, "model-providers");
  assert.equal(state.recordStateCommits[0].record_id, "provider.custom");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.provider.start");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["lifecycle.provider_start.1"]);
  assert.equal(state.recordStateCommits[1].record_dir, "model-providers");
  assert.equal(state.recordStateCommits[1].record_id, "provider.custom");
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.provider.stop");
  assert.deepEqual(state.recordStateCommits[1].receipt_refs, ["lifecycle.provider_stop.2"]);
  assert.deepEqual(state.writes, []);
});

test("local provider start and stop fail closed without Rust lifecycle bindings", async () => {
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
    (error) => error.code === "model_mount_provider_control_lifecycle_planning_required" &&
      error.details.operation === "provider_start" &&
      error.details.provider_id === "provider.local" &&
      error.details.provider_kind === "ioi_native_local" &&
      Object.hasOwn(error.details, "providerId") === false &&
      Object.hasOwn(error.details, "providerKind") === false,
  );
  await assert.rejects(
    () => stopProvider(state, "provider.local", providerDeps()),
    (error) => error.code === "model_mount_provider_control_lifecycle_planning_required" &&
      error.details.operation === "provider_stop" &&
      error.details.provider_id === "provider.local" &&
      error.details.provider_kind === "ioi_native_local" &&
      Object.hasOwn(error.details, "providerId") === false &&
      Object.hasOwn(error.details, "providerKind") === false,
  );
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.receipts, []);
});
