import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function loadModel(state, body = {}) {
  return ModelMountingState.prototype.loadModel.call(state, body);
}

function unloadModel(state, body = {}) {
  return ModelMountingState.prototype.unloadModel.call(state, body);
}

function fakeState() {
  const endpoint = {
    id: "endpoint.local.llama",
    providerId: "provider.local",
    modelId: "llama-test",
    apiFormat: "openai",
    backendId: null,
    load_policy: { mode: "on_demand" },
    contextWindow: 4096,
  };
  const provider = {
    id: "provider.local",
    kind: "ioi_native_local",
    driver: "native_local",
    apiFormat: "openai",
  };
  return {
    artifacts: new Map([
      ["artifact.llama", {
        id: "artifact.llama",
        modelId: "llama-test",
        contextWindow: 8192,
        sizeBytes: 4096,
      }],
    ]),
    endpointRecord: endpoint,
    instances: new Map(),
    providerRecord: provider,
    providerLifecycleRequests: [],
    backendProcessMaterializationRequests: [],
    instanceLifecycleRequests: [],
    recordStateCommits: [],
    receipts: [],
    superseded: [],
    transitionRequests: [],
    writes: [],
    now: "2026-06-04T00:00:00.000Z",
    stateDir: "/tmp/ioi-model-loading-test-state",
    driverCalls: [],
    driverForProvider() {
      return {
        load: async ({ endpoint: loadedEndpoint, body }) => {
          this.driverCalls.push(["load", loadedEndpoint.id, body.loadOptions]);
          return {
            backend: "native_local",
            backendId: "backend.native",
            estimate: { fromDriver: true },
            evidenceRefs: ["driver.load"],
            lifecycleHash: "sha256:provider-load",
            process: { id: "process.1", pidHash: "pid.hash" },
            commandArgsHash: "args.hash",
          };
        },
        unload: async ({ instance }) => {
          this.driverCalls.push(["unload", instance.id]);
          return {
            evidenceRefs: ["driver.unload"],
            lifecycleHash: "sha256:provider-unload",
            process: { id: "process.1" },
          };
        },
      };
    },
    endpointById: new Map([["endpoint.local.llama", endpoint]]),
    endpoint(endpointId) {
      const record = this.endpointById.get(endpointId);
      if (!record) throw new Error(`missing endpoint ${endpointId}`);
      return record;
    },
    getModel(modelId) {
      return [...this.artifacts.values()].find((artifact) => artifact.modelId === modelId);
    },
    instance(instanceId) {
      const record = this.instances.get(instanceId);
      if (!record) throw new Error(`missing instance ${instanceId}`);
      return record;
    },
    lifecycleReceipt(kind, details) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, details };
      this.receipts.push(receipt);
      return receipt;
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(JSON.parse(JSON.stringify(request)));
      return {
        record_id: request.record_id,
        commit_hash: `sha256:commit:${request.operation_kind}:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
          admission: {
            admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
          },
        },
      };
    },
    loadedInstanceForEndpoint(endpointId) {
      return [...this.instances.values()].find(
        (instance) => (instance.endpointId ?? instance.endpoint_id) === endpointId && instance.status === "loaded",
      );
    },
    nowIso() {
      return this.now;
    },
    provider(providerId) {
      if (providerId !== this.providerRecord.id) throw new Error(`missing provider ${providerId}`);
      return this.providerRecord;
    },
    planModelMountProviderLifecycle(request) {
      this.providerLifecycleRequests.push(JSON.parse(JSON.stringify(request)));
      const nativeLocal = request.execution_backend === "rust_model_mount_native_local_lifecycle";
      const status = request.action === "unload" ? "unloaded" : "loaded";
      const backendId = request.backend_ref ?? (nativeLocal
        ? "backend.autopilot.native-local.fixture"
        : "backend.fixture");
      const evidenceRefs = [
        "public_provider_lifecycle_js_facade_retired",
        "rust_model_mount_provider_lifecycle",
        "agentgres_provider_lifecycle_truth_required",
        nativeLocal
          ? "rust_model_mount_native_local_lifecycle_backend"
          : "rust_model_mount_fixture_lifecycle_backend",
      ];
      const transportContract = {
        transport_execution_status: "rust_materialized",
        transport_execution_owner: "rust_daemon_core.model_mount.provider_lifecycle",
        transport_materialization_kind: nativeLocal ? "native_local_lifecycle" : "fixture_lifecycle",
        plaintext_secret_material_returned: false,
      };
      const lifecycleHash = `sha256:provider:${request.provider_ref}:${request.action}`;
      const recordId = `provider_lifecycle_${request.provider_ref
        .replace(/[^a-z0-9._-]+/gi, "_")
        .replace(/^_+|_+$/g, "")}_${request.action}_test`;
      const providerLifecycleRecord = {
        id: recordId,
        record_id: recordId,
        object: "ioi.model_mount_provider_lifecycle",
        schema_version: "ioi.model_mount.provider_lifecycle_plan.v1",
        provider_ref: request.provider_ref,
        provider_kind: request.provider_kind,
        endpoint_ref: request.endpoint_ref,
        model_ref: request.model_ref,
        action: request.action,
        operation_kind: request.operation_kind,
        status,
        backend: nativeLocal ? "autopilot.native_local.fixture" : "ioi_fixture",
        backend_id: backendId,
        driver: nativeLocal ? "native_local" : "fixture",
        execution_backend: request.execution_backend,
        transport_contract: transportContract,
        transport_execution_status: "rust_materialized",
        transport_execution_owner: "rust_daemon_core.model_mount.provider_lifecycle",
        transport_materialization_kind: transportContract.transport_materialization_kind,
        plaintext_secret_material_returned: false,
        lifecycle_hash: lifecycleHash,
        record_dir: "model-provider-lifecycle-controls",
        receipt_refs: [],
        rust_core_boundary: "model_mount.provider_lifecycle",
        source: "rust_model_mount_provider_lifecycle_command",
        evidence_refs: evidenceRefs,
      };
      const publicResponse = {
        object: "ioi.model_mount_provider_lifecycle",
        status,
        provider_ref: request.provider_ref,
        provider_kind: request.provider_kind,
        endpoint_ref: request.endpoint_ref,
        model_ref: request.model_ref,
        action: request.action,
        backend_id: backendId,
        provider_backend: providerLifecycleRecord.backend,
        driver: providerLifecycleRecord.driver,
        execution_backend: request.execution_backend,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.provider_lifecycle",
        lifecycle_hash: lifecycleHash,
        transport_contract: transportContract,
        transport_execution_status: "rust_materialized",
      };
      providerLifecycleRecord.public_response = publicResponse;
      const record = {
        ...request,
        operation_kind: request.operation_kind,
        status,
        backend: nativeLocal ? "autopilot.native_local.fixture" : "ioi_fixture",
        backend_id: backendId,
        driver: nativeLocal ? "native_local" : "fixture",
        lifecycle_hash: lifecycleHash,
        evidence_refs: evidenceRefs,
        transport_contract: transportContract,
        rust_core_boundary: "model_mount.provider_lifecycle",
        record_dir: "model-provider-lifecycle-controls",
        record_id: recordId,
        record: providerLifecycleRecord,
        public_response: publicResponse,
        receipt_refs: [],
      };
      return {
        source: "rust_model_mount_provider_lifecycle_command",
        backend: request.execution_backend,
        result: record,
        status,
        backendId,
        providerBackend: record.backend,
        driver: record.driver,
        executionBackend: request.execution_backend,
        lifecycle_hash: record.lifecycle_hash,
        operation_kind: request.operation_kind,
        rust_core_boundary: "model_mount.provider_lifecycle",
        record_dir: "model-provider-lifecycle-controls",
        record_id: recordId,
        record: providerLifecycleRecord,
        public_response: publicResponse,
        receipt_refs: [],
        evidence_refs: record.evidence_refs,
        backendEvidenceRefs: record.evidence_refs,
      };
    },
    planModelMountInstanceLifecycle(request) {
      this.instanceLifecycleRequests.push(JSON.parse(JSON.stringify(request)));
      const estimate = request.action === "estimate";
      const instance = request.instance_ref ? this.instances.get(request.instance_ref) : null;
      const endpoint = request.endpoint_ref
        ? this.endpointById.get(request.endpoint_ref) ?? this.endpointRecord
        : instance?.endpointId || instance?.endpoint_id
          ? this.endpointById.get(instance.endpointId ?? instance.endpoint_id) ?? this.endpointRecord
          : this.endpointRecord;
      const provider = instance?.providerId || instance?.provider_id
        ? { id: instance.providerId ?? instance.provider_id, ...this.providerRecord }
        : this.providerRecord;
      const endpointId = request.endpoint_ref || endpoint.id;
      const modelId = request.model_ref || instance?.modelId || instance?.model_id || endpoint.modelId || endpoint.model_id;
      const providerId = request.provider_ref || instance?.providerId || instance?.provider_id || provider.id;
      const backendId = request.backend_ref || instance?.backendId || instance?.backend_id || endpoint.backendId || endpoint.backend_id || "backend.autopilot.native-local.fixture";
      const driver = request.driver || instance?.driver || provider.driver || endpoint.driver || "native_local";
      const instanceId = request.instance_ref ||
        (estimate ? `model_instance_estimate.${endpointId}` : `model_instance.${endpointId}.${modelId}`);
      const record = {
        schema_version: request.schema_version,
        id: instanceId,
        endpoint_id: endpointId,
        model_id: modelId,
        provider_id: providerId,
        instance_ref: instanceId,
        endpoint_ref: endpointId,
        model_ref: modelId,
        provider_ref: providerId,
        action: request.action,
        status: request.target_status,
        backend_id: backendId,
        driver,
        execution_backend: request.execution_backend,
        provider_lifecycle_hash: estimate
          ? `sha256:estimate-provider-lifecycle-not-executed:${instanceId}`
          : request.provider_lifecycle_hash,
        backend_process_ref: request.backend_process_ref ?? "",
        backend_process_materialization_hash: request.backend_process_materialization_hash ?? "",
        backend_supervision_ref: request.backend_supervision_ref ?? "",
        backend_supervision_hash: request.backend_supervision_hash ?? "",
        backend_supervision_status: request.backend_supervision_status ?? "",
        runtime_engine_id: request.runtime_engine_ref,
        load_options: request.load_options,
        load_estimate: estimate
          ? {
            object: "ioi.model_mount_load_estimate",
            status: "estimated",
            provider_lifecycle_execution: false,
            js_sizing_execution: false,
            js_driver_execution: false,
            runtime_engine_id: request.runtime_engine_ref,
            backend_id: backendId,
            requested_context_tokens: request.load_options.context_length,
            parallel: request.load_options.parallel,
            ttl_seconds: request.load_options.ttl_seconds,
            estimated_memory_bytes: 262144,
            estimate_source: "rust_daemon_core.model_mount.instance_lifecycle",
          }
          : undefined,
        evidence_refs: [
          "rust_model_mount_instance_lifecycle",
          ...(estimate
            ? [
              "rust_model_mount_load_estimate",
              "agentgres_model_instance_estimate_truth_required",
              "model_mount_model_loading_js_estimate_facade_retired",
            ]
            : [
              "rust_model_mount_provider_lifecycle_bound",
              "rust_model_mount_backend_process_materialization_bound",
              "rust_model_mount_backend_process_supervision_bound",
            ]),
          ...request.evidence_refs,
        ],
        instance_lifecycle_hash: `sha256:instance:${instanceId}:${request.action}`,
      };
      return {
        source: "rust_model_mount_instance_lifecycle_command",
        backend: "rust_model_mount_instance_lifecycle",
        result: record,
        action: request.action,
        status: record.status,
        backendId: record.backend_id,
        driver: record.driver,
        executionBackend: record.execution_backend,
        provider_lifecycle_hash: record.provider_lifecycle_hash,
        instance_lifecycle_hash: record.instance_lifecycle_hash,
        evidence_refs: record.evidence_refs,
        backendEvidenceRefs: record.evidence_refs,
      };
    },
    planModelMountBackendProcessMaterialization(request) {
      this.backendProcessMaterializationRequests.push(JSON.parse(JSON.stringify(request)));
      const recordId = `${request.backend_ref}.process`;
      const evidenceRefs = [
        "rust_daemon_core_backend_process_materialization",
        "rust_backend_process_materialization_bound",
        "wallet_network_backend_process_authority_bound",
        "ctee_backend_process_custody_enforced",
        "agentgres_backend_process_materialization_truth_required",
        "rust_backend_process_supervision_bound",
        "js_backend_process_supervisor_retired",
        "command_transport_backend_process_spawn_retired",
        "binary_bridge_backend_process_spawn_retired",
      ];
      const publicResponse = {
        object: "ioi.model_mount_backend_process_materialization",
        id: recordId,
        backend_ref: request.backend_ref,
        backend_kind: request.backend_kind,
        backend_process_ref: `backend_process://${recordId}#sha256:plan`,
        backend_supervision_ref: `backend_supervision://${recordId}#sha256:plan`,
        backend_supervision_hash: "sha256:backend-supervision",
        backend_supervision_status: "rust_fixture_supervision_bound",
        process_materialization_status: "rust_fixture_process_materialized",
        rust_core_boundary: "model_mount.backend_process_materialization",
        process_execution_owner: "rust_daemon_core.model_mount.backend_process_materialization",
        process_supervision_owner: "rust_daemon_core.model_mount.backend_process_supervisor",
        spawn_args_returned: false,
        pid_returned: false,
        plaintext_process_material_returned: false,
        materialization_hash: "sha256:backend-process-materialization",
        authority_hash: "sha256:backend-process-authority",
      };
      const record = {
        id: recordId,
        record_id: recordId,
        schema_version: "ioi.model_mount.backend_process_materialization.v1",
        object: "ioi.model_mount_backend_process_materialization",
        status: "materialized",
        operation_kind: request.operation_kind,
        backend_ref: request.backend_ref,
        backend_kind: request.backend_kind,
        backend_process_ref: publicResponse.backend_process_ref,
        backend_supervision_ref: publicResponse.backend_supervision_ref,
        backend_supervision_hash: publicResponse.backend_supervision_hash,
        backend_supervision_status: publicResponse.backend_supervision_status,
        process_materialization_status: publicResponse.process_materialization_status,
        rust_core_boundary: "model_mount.backend_process_materialization",
        process_execution_owner: "rust_daemon_core.model_mount.backend_process_materialization",
        process_supervision_owner: "rust_daemon_core.model_mount.backend_process_supervisor",
        spawn_contract: {
          spawn_args_returned: false,
          pid_returned: false,
          plaintext_process_material_returned: false,
        },
        supervision_contract: {
          backend_supervision_ref: publicResponse.backend_supervision_ref,
          backend_supervision_hash: publicResponse.backend_supervision_hash,
          backend_supervision_status: publicResponse.backend_supervision_status,
          process_supervision_owner: "rust_daemon_core.model_mount.backend_process_supervisor",
          supervisor_kind: "deterministic_fixture_process",
          supports_supervision: true,
          spawn_required: false,
          spawn_status: "not_required",
          spawn_args_hash: "sha256:redacted-spawn-args",
        },
        public_response: publicResponse,
        evidence_refs: evidenceRefs,
        materialization_hash: "sha256:backend-process-materialization",
        authority_hash: "sha256:backend-process-authority",
      };
      return {
        source: "rust_daemon_core.model_mount.backend_process_materialization",
        schema_version: "ioi.model_mount.backend_process_materialization_plan.v1",
        object: "ioi.model_mount_backend_process_materialization_plan",
        status: "planned",
        rust_core_boundary: "model_mount.backend_process_materialization",
        operation_kind: request.operation_kind,
        record_dir: "model-backend-process-materializations",
        record_id: recordId,
        record,
        public_response: publicResponse,
        process_plan: {
          backend_ref: request.backend_ref,
          backend_kind: request.backend_kind,
          spawn_status: "not_required",
        },
        receipt_refs: [],
        authority_grant_refs: [],
        authority_receipt_refs: [],
        evidence_refs: evidenceRefs,
        materialization_hash: "sha256:backend-process-materialization",
        authority_hash: "sha256:backend-process-authority",
      };
    },
    resolveEndpoint(endpointId, modelId) {
      if (endpointId) return this.endpoint(endpointId);
      if (modelId === this.endpointRecord.modelId) return this.endpointRecord;
      throw new Error("missing endpoint");
    },
    runtimeDefaultLoadOptions() {
      return { ttlSeconds: 120, parallel: 2 };
    },
    runtimeEngineProfile(engineId) {
      return { id: engineId, label: "Native" };
    },
    runtimePreference() {
      return { selectedEngineId: "engine.native" };
    },
    runtimePreferenceForEndpoint() {
      return { selectedEngineId: "engine.native" };
    },
    supersedeLoadedInstances(endpointId, keepInstanceId) {
      this.superseded.push([endpointId, keepInstanceId]);
      return true;
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
  };
}

const deps = {
  defaultBackendForProvider(provider) {
    return provider.kind === "ioi_native_local" ? "backend.native" : "backend.remote";
  },
  expiresAt(now, loadPolicy) {
    return loadPolicy.idleTtlSeconds ? "2026-06-04T00:02:00.000Z" : null;
  },
  hasExplicitTtlOption(value = {}) {
    return Object.hasOwn(value, "ttlSeconds") || Object.hasOwn(value, "ttl_seconds");
  },
  normalizeLoadOptions(value, loadPolicy) {
    return {
      estimateOnly: Boolean(value.estimate_only ?? value.estimateOnly),
      ttlSeconds: value.ttlSeconds ?? value.ttl_seconds ?? loadPolicy.idleTtlSeconds ?? null,
      parallel: value.parallel ?? null,
      gpu: value.gpu ?? null,
      contextLength: value.context_length ?? value.contextLength ?? null,
      identifier: value.identifier ?? null,
    };
  },
  normalizeLoadPolicy(value) {
    return { mode: value?.mode ?? value ?? "on_demand" };
  },
  safeId(value) {
    return String(value).replace(/[^a-z0-9]+/gi, "_");
  },
  schemaVersion: "schema.model-loading.test",
};

test("loadModel rejects retired request aliases before endpoint resolution", async () => {
  const state = fakeState();
  const calls = [];
  state.resolveEndpoint = (...args) => {
    calls.push(args);
    throw new Error("resolveEndpoint should not run");
  };

  await assert.rejects(
    () =>
      loadModel(
        state,
        {
          endpointId: "endpoint.local.llama",
          modelId: "llama-test",
          loadPolicy: "resident",
          loadOptions: { estimate_only: true },
          workflowScope: "workflow-1",
          agentScope: "agent-1",
          instanceId: "instance.legacy",
        },
        deps,
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_loading_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "endpointId",
        "modelId",
        "loadPolicy",
        "loadOptions",
        "workflowScope",
        "agentScope",
        "instanceId",
      ]);
      assert.equal(Object.hasOwn(error.details, "endpointId"), false);
      assert.equal(Object.hasOwn(error.details, "loadPolicy"), false);
      return true;
    },
  );
  assert.deepEqual(calls, []);
  assert.deepEqual(state.driverCalls, []);
  assert.equal(state.receipts.length, 0);
});

test("unloadModel rejects retired request aliases before instance lookup", async () => {
  const state = fakeState();
  const calls = [];
  state.instance = (...args) => {
    calls.push(["instance", ...args]);
    throw new Error("instance lookup should not run");
  };
  state.resolveEndpoint = (...args) => {
    calls.push(["resolveEndpoint", ...args]);
    throw new Error("endpoint lookup should not run");
  };

  await assert.rejects(
    () =>
      unloadModel(
        state,
        {
          endpointId: "endpoint.local.llama",
          modelId: "llama-test",
          loadPolicy: "resident",
          loadOptions: { estimate_only: true },
          workflowScope: "workflow-1",
          agentScope: "agent-1",
          instanceId: "instance.legacy",
        },
        deps,
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_loading_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "endpointId",
        "modelId",
        "loadPolicy",
        "loadOptions",
        "workflowScope",
        "agentScope",
        "instanceId",
      ]);
      return true;
    },
  );
  assert.deepEqual(calls, []);
  assert.deepEqual(state.driverCalls, []);
  assert.equal(state.receipts.length, 0);
});

test("loadModel estimate-only commits Rust estimate record before returning public estimate truth", async () => {
  const state = fakeState();

  const estimate = await loadModel(
    state,
    {
      endpoint_id: "endpoint.local.llama",
      load_policy: "resident",
      load_options: { estimate_only: true, context_length: 2048 },
    },
    deps,
  );

  assert.equal(estimate.status, "estimated");
  assert.equal(estimate.action, "estimate");
  assert.equal(estimate.endpoint_id, "endpoint.local.llama");
  assert.equal(estimate.model_id, "llama-test");
  assert.equal(estimate.provider_id, "provider.local");
  assert.equal(estimate.backend_id, "backend.autopilot.native-local.fixture");
  assert.equal(estimate.runtime_engine_id, "engine.native");
  assert.equal(estimate.load_estimate.object, "ioi.model_mount_load_estimate");
  assert.equal(estimate.load_estimate.js_sizing_execution, false);
  assert.equal(estimate.load_estimate.js_driver_execution, false);
  assert.equal(estimate.load_estimate.provider_lifecycle_execution, false);
  assert.equal(estimate.load_estimate.requested_context_tokens, 2048);
  assert.equal(estimate.evidence_refs.includes("rust_model_mount_load_estimate"), true);
  assert.equal(
    estimate.evidence_refs.includes("agentgres_model_instance_estimate_truth_required"),
    true,
  );
  assert.deepEqual(state.driverCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.instances.size, 0);
  assert.equal(state.providerLifecycleRequests.length, 0);
  assert.equal(state.instanceLifecycleRequests.length, 1);
  assert.equal(state.instanceLifecycleRequests[0].action, "estimate");
  assert.equal(state.instanceLifecycleRequests[0].target_status, "estimated");
  assert.equal(state.instanceLifecycleRequests[0].state_dir, state.stateDir);
  assert.equal(state.instanceLifecycleRequests[0].endpoint_ref, "endpoint.local.llama");
  assert.equal(state.instanceLifecycleRequests[0].model_ref, "");
  assert.equal(state.instanceLifecycleRequests[0].provider_ref, "");
  assert.equal(state.instanceLifecycleRequests[0].backend_ref, "");
  assert.equal(state.instanceLifecycleRequests[0].driver, "");
  assert.equal(state.instanceLifecycleRequests[0].provider_lifecycle_hash, "");
  assert.equal(state.instanceLifecycleRequests[0].runtime_engine_ref, "engine.native");
  assert.equal(state.instanceLifecycleRequests[0].load_options.estimate_only, true);
  assert.equal(state.instanceLifecycleRequests[0].load_options.context_length, 2048);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "model-instances");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.instance.estimate");
  assert.equal(state.recordStateCommits[0].record.action, "estimate");
  assert.equal(state.recordStateCommits[0].record.status, "estimated");
  assert.equal(state.recordStateCommits[0].record.load_estimate.js_sizing_execution, false);
});

test("loadModel commits Rust-planned instance lifecycle without mutating JS instance cache", async () => {
  const state = fakeState();

  const loaded = await loadModel(
    state,
    { endpoint_id: "endpoint.local.llama", id: "instance.explicit", load_options: { identifier: "llama-test" } },
    deps,
  );

  assert.deepEqual(state.driverCalls, []);
  assert.equal(loaded.id, "instance.explicit");
  assert.equal(loaded.status, "loaded");
  assert.equal(loaded.action, "load");
  assert.equal(loaded.endpoint_id, "endpoint.local.llama");
  assert.equal(loaded.model_id, "llama-test");
  assert.equal(loaded.provider_id, "provider.local");
  assert.equal(loaded.backend_id, "backend.autopilot.native-local.fixture");
  assert.equal(loaded.provider_lifecycle_hash, "sha256:provider:provider://provider.local:load");
  assert.equal(
    loaded.backend_process_ref,
    "backend_process://backend.autopilot.native-local.fixture.process#sha256:plan",
  );
  assert.equal(loaded.backend_process_materialization_hash, "sha256:backend-process-materialization");
  assert.equal(
    loaded.backend_supervision_ref,
    "backend_supervision://backend.autopilot.native-local.fixture.process#sha256:plan",
  );
  assert.equal(loaded.backend_supervision_hash, "sha256:backend-supervision");
  assert.equal(loaded.backend_supervision_status, "rust_fixture_supervision_bound");
  assert.equal(loaded.instance_lifecycle_hash, "sha256:instance:instance.explicit:load");
  assert.equal(
    loaded.backend_process_materialization.process_execution_owner,
    "rust_daemon_core.model_mount.backend_process_materialization",
  );
  assert.equal(state.instances.has("instance.explicit"), false);
  assert.equal(state.providerLifecycleRequests.length, 1);
  assert.equal(state.providerLifecycleRequests[0].action, "load");
  assert.equal(state.providerLifecycleRequests[0].execution_backend, "rust_model_mount_native_local_lifecycle");
  assert.equal(state.backendProcessMaterializationRequests.length, 1);
  assert.equal(
    state.backendProcessMaterializationRequests[0].schema_version,
    "ioi.model_mount.backend_process_materialization.v1",
  );
  assert.equal(
    state.backendProcessMaterializationRequests[0].operation_kind,
    "model_mount.backend_process.materialize",
  );
  assert.equal(
    state.backendProcessMaterializationRequests[0].backend_ref,
    "backend.autopilot.native-local.fixture",
  );
  assert.equal(state.backendProcessMaterializationRequests[0].backend_kind, "native_local");
  assert.equal(state.backendProcessMaterializationRequests[0].load_options.identifier, "llama-test");
  assert.equal(state.instanceLifecycleRequests.length, 1);
  assert.equal(state.instanceLifecycleRequests[0].action, "load");
  assert.equal(state.instanceLifecycleRequests[0].target_status, "loaded");
  assert.equal(state.instanceLifecycleRequests[0].execution_backend, "rust_model_mount_instance_lifecycle");
  assert.equal(state.instanceLifecycleRequests[0].state_dir, state.stateDir);
  assert.equal(state.instanceLifecycleRequests[0].endpoint_ref, "endpoint.local.llama");
  assert.equal(state.instanceLifecycleRequests[0].model_ref, "");
  assert.equal(state.instanceLifecycleRequests[0].provider_ref, "");
  assert.equal(state.instanceLifecycleRequests[0].backend_ref, "");
  assert.equal(state.instanceLifecycleRequests[0].driver, "");
  assert.equal(
    state.instanceLifecycleRequests[0].provider_lifecycle_hash,
    "sha256:provider:provider://provider.local:load",
  );
  assert.equal(
    state.instanceLifecycleRequests[0].backend_process_materialization_hash,
    "sha256:backend-process-materialization",
  );
  assert.equal(
    state.instanceLifecycleRequests[0].backend_supervision_hash,
    "sha256:backend-supervision",
  );
  assert.equal(
    state.instanceLifecycleRequests[0].backend_supervision_status,
    "rust_fixture_supervision_bound",
  );
  assert.equal(state.recordStateCommits.length, 2);
  assert.equal(state.recordStateCommits[0].record_dir, "model-backend-process-materializations");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.backend_process.materialize");
  assert.equal(state.recordStateCommits[0].record.process_execution_owner, "rust_daemon_core.model_mount.backend_process_materialization");
  assert.equal(state.recordStateCommits[0].record.process_supervision_owner, "rust_daemon_core.model_mount.backend_process_supervisor");
  assert.equal(state.recordStateCommits[0].record.backend_supervision_hash, "sha256:backend-supervision");
  assert.equal(state.recordStateCommits[1].record_dir, "model-instances");
  assert.equal(state.recordStateCommits[1].record_id, "instance.explicit");
  assert.equal(state.recordStateCommits[1].operation_kind, "model_mount.instance.load");
  assert.equal(state.recordStateCommits[1].record.status, "loaded");
  assert.equal(state.recordStateCommits[1].record.action, "load");
  assert.equal(state.recordStateCommits[1].record.backend_supervision_hash, "sha256:backend-supervision");
  assert.deepEqual(state.recordStateCommits[1].receipt_refs, []);
  assert.deepEqual(state.superseded, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.transitionRequests, []);
});

test("loadModel fails closed for non-migrated provider before JS driver execution", async () => {
  const state = fakeState();
  state.endpointRecord = {
    ...state.endpointRecord,
    providerId: "provider.remote",
    apiFormat: "openai_compatible",
    backendId: "backend.remote",
  };
  state.endpointById.set(state.endpointRecord.id, state.endpointRecord);
  state.providerRecord = {
    id: "provider.remote",
    kind: "openai_compatible",
    driver: "openai_compatible",
    apiFormat: "openai_compatible",
  };

  await assert.rejects(
    () => loadModel(state, { endpoint_id: "endpoint.local.llama", id: "instance.remote" }, deps),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_provider_control_rust_core_required");
      assert.equal(error.details.operation, "model_load");
      assert.equal(error.details.operation_kind, "model_mount.instance.load");
      assert.equal(error.details.unsupported_provider_lifecycle_backend, true);
      assert.equal(error.details.provider_id, "provider.remote");
      assert.equal(error.details.provider_kind, "openai_compatible");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "providerKind"), false);
      return true;
    },
  );

  assert.deepEqual(state.driverCalls, []);
  assert.equal(state.instances.has("instance.remote"), false);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.providerLifecycleRequests, []);
  assert.deepEqual(state.instanceLifecycleRequests, []);
});

test("unloadModel fails closed for non-migrated provider before JS driver execution", async () => {
  const state = fakeState();
  state.providerRecord = {
    id: "provider.remote",
    kind: "custom_http",
    driver: "openai_compatible",
    apiFormat: "openai_compatible",
  };
  state.instances.set("instance.remote", {
    id: "instance.remote",
    endpointId: "endpoint.local.llama",
    providerId: "provider.remote",
    modelId: "llama-test",
    status: "loaded",
  });

  await assert.rejects(
    () => unloadModel(state, { instance_id: "instance.remote" }, deps),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_provider_control_rust_core_required");
      assert.equal(error.details.operation, "model_unload");
      assert.equal(error.details.operation_kind, "model_mount.instance.unload");
      assert.equal(error.details.unsupported_provider_lifecycle_backend, true);
      assert.equal(error.details.provider_id, "provider.remote");
      assert.equal(error.details.provider_kind, "custom_http");
      assert.equal(Object.hasOwn(error.details, "providerId"), false);
      assert.equal(Object.hasOwn(error.details, "providerKind"), false);
      return true;
    },
  );

  assert.deepEqual(state.driverCalls, []);
  assert.equal(state.instances.get("instance.remote").status, "loaded");
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.providerLifecycleRequests, []);
  assert.deepEqual(state.instanceLifecycleRequests, []);
});

test("unloadModel commits Rust-planned instance lifecycle without mutating JS instance cache", async () => {
  const state = fakeState();
  const loaded = {
    id: "instance.loaded",
    endpointId: "endpoint.local.llama",
    providerId: "provider.local",
    modelId: "llama-test",
    status: "loaded",
    providerEvidenceRefs: ["previous"],
  };
  state.instances.set("instance.loaded", loaded);

  const unloaded = await unloadModel(state, { instance_id: "instance.loaded" }, deps);

  assert.deepEqual(state.driverCalls, []);
  assert.equal(unloaded.id, "instance.loaded");
  assert.equal(unloaded.status, "unloaded");
  assert.equal(unloaded.action, "unload");
  assert.equal(unloaded.endpoint_id, "endpoint.local.llama");
  assert.equal(unloaded.model_id, "llama-test");
  assert.equal(unloaded.provider_id, "provider.local");
  assert.equal(unloaded.backend_id, "backend.autopilot.native-local.fixture");
  assert.equal(unloaded.provider_lifecycle_hash, "sha256:provider:provider://provider.local:unload");
  assert.equal(unloaded.instance_lifecycle_hash, "sha256:instance:instance.loaded:unload");
  assert.deepEqual(state.instances.get("instance.loaded"), loaded);
  assert.equal(state.providerLifecycleRequests.length, 1);
  assert.equal(state.providerLifecycleRequests[0].action, "unload");
  assert.equal(state.instanceLifecycleRequests.length, 1);
  assert.equal(state.instanceLifecycleRequests[0].action, "unload");
  assert.equal(state.instanceLifecycleRequests[0].target_status, "unloaded");
  assert.equal(state.instanceLifecycleRequests[0].state_dir, state.stateDir);
  assert.equal(state.instanceLifecycleRequests[0].endpoint_ref, "");
  assert.equal(state.instanceLifecycleRequests[0].model_ref, "");
  assert.equal(state.instanceLifecycleRequests[0].provider_ref, "");
  assert.equal(state.instanceLifecycleRequests[0].backend_ref, "");
  assert.equal(state.instanceLifecycleRequests[0].driver, "");
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "model-instances");
  assert.equal(state.recordStateCommits[0].record_id, "instance.loaded");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.instance.unload");
  assert.equal(state.recordStateCommits[0].record.status, "unloaded");
  assert.equal(state.recordStateCommits[0].record.action, "unload");
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.transitionRequests, []);
});

test("loadModel fails closed if Rust Agentgres commit is unavailable after Rust planning", async () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  await assert.rejects(
    () => loadModel(state, { endpoint_id: "endpoint.local.llama", id: "instance.fail" }, deps),
    (error) => error.code === "model_mount_backend_process_materialization_record_state_commit_unconfigured",
  );

  assert.equal(state.instances.has("instance.fail"), false);
  assert.deepEqual(state.driverCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.providerLifecycleRequests.length, 1);
  assert.equal(state.backendProcessMaterializationRequests.length, 1);
  assert.equal(state.instanceLifecycleRequests.length, 0);
  assert.equal(state.writes.length, 0);
});

test("loadModel estimate-only fails closed without Rust Agentgres estimate commit", async () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  await assert.rejects(
    () =>
      loadModel(
        state,
        {
          endpoint_id: "endpoint.local.llama",
          load_options: { estimate_only: true, context_length: 2048 },
        },
        deps,
      ),
    (error) => error.code === "model_mount_instance_lifecycle_record_state_commit_unconfigured",
  );

  assert.deepEqual(state.driverCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.instances.size, 0);
  assert.equal(state.providerLifecycleRequests.length, 0);
  assert.equal(state.instanceLifecycleRequests.length, 1);
  assert.equal(state.instanceLifecycleRequests[0].action, "estimate");
});

test("unloadModel fails closed if Rust Agentgres commit is unavailable after Rust planning", async () => {
  const state = fakeState();
  const loaded = {
    id: "instance.loaded",
    endpointId: "endpoint.local.llama",
    providerId: "provider.local",
    modelId: "llama-test",
    status: "loaded",
    providerEvidenceRefs: ["previous"],
  };
  state.instances.set("instance.loaded", {
    ...loaded,
  });
  delete state.commitRuntimeModelMountRecordState;

  await assert.rejects(
    () => unloadModel(state, { instance_id: "instance.loaded" }, deps),
    (error) => error.code === "model_mount_instance_lifecycle_record_state_commit_unconfigured",
  );

  assert.deepEqual(state.instances.get("instance.loaded"), loaded);
  assert.deepEqual(state.driverCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.providerLifecycleRequests.length, 1);
  assert.equal(state.instanceLifecycleRequests.length, 1);
  assert.equal(state.writes.length, 0);
});
