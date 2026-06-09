import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function fakeState() {
  return {
    artifacts: new Map(),
    endpoints: new Map(),
    recordStateCommits: [],
    receipts: [],
    writes: [],
    projections: 0,
    endpoint(endpointId) {
      throw new Error(`endpoint lookup should not run: ${endpointId}`);
    },
    getModel(modelId) {
      throw new Error(`artifact lookup should not run: ${modelId}`);
    },
    lifecycleReceipt(kind, details) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, details };
      this.receipts.push(receipt);
      return receipt;
    },
    modelForProviderMount() {
      throw new Error("provider artifact mount lookup should not run");
    },
    nowIso() {
      throw new Error("clock should not run");
    },
    provider(providerId) {
      throw new Error(`provider lookup should not run: ${providerId}`);
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()]]);
    },
    commitRuntimeModelMountRecordState(request) {
      this.recordStateCommits.push(request);
      throw new Error("record-state commit should not run");
    },
    writeProjection() {
      this.projections += 1;
    },
  };
}

function assertNoMutation(state) {
  assert.equal(state.artifacts.size, 0);
  assert.equal(state.endpoints.size, 0);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
}

test("model import rejects retired request aliases before artifact inspection", () => {
  const state = fakeState();

  assert.throws(
    () =>
      ModelMountingState.prototype.importModel.call(
        state,
        {
          modelId: "llama-test",
          sourcePath: "/tmp/model.gguf",
          localPath: "/tmp/model.gguf",
          importMode: "copy",
          providerId: "provider.local.folder",
          displayName: "Llama Test",
          sizeBytes: 123,
          contextWindow: 8192,
          privacyClass: "local_private",
        },
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_import_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "modelId",
        "sourcePath",
        "localPath",
        "importMode",
        "providerId",
        "displayName",
        "sizeBytes",
        "contextWindow",
        "privacyClass",
      ]);
      assert.equal(Object.hasOwn(error.details, "modelId"), false);
      return true;
    },
  );
  assertNoMutation(state);
});

test("artifact and endpoint mutation facades fail closed until Rust core owns them", () => {
  const state = fakeState();
  const cases = [
    [
      () =>
        ModelMountingState.prototype.importModel.call(
          state,
          { model_id: "llama-test", source_path: "/tmp/model.gguf" },
        ),
      "model_mount.artifact.import",
      { model_id: "llama-test" },
    ],
    [
      () =>
        ModelMountingState.prototype.mountEndpoint.call(
          state,
          { model_id: "llama-test", provider_id: "provider.fixture" },
        ),
      "model_mount.endpoint.mount",
      { model_id: "llama-test" },
    ],
    [
      () =>
        ModelMountingState.prototype.unmountEndpoint.call(
          state,
          { endpoint_id: "endpoint.llama" },
        ),
      "model_mount.endpoint.unmount",
      { endpoint_id: "endpoint.llama" },
    ],
  ];

  for (const [run, operationKind, expectedDetails] of cases) {
    assert.throws(run, (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_artifact_endpoint_rust_core_required");
      assert.equal(error.details.operation_kind, operationKind);
      assert.equal(error.details.rust_core_boundary, "model_mount.artifact_endpoint");
      assert.deepEqual(error.details.evidence_refs, [
        "public_artifact_endpoint_js_facade_retired",
        "rust_daemon_core_artifact_endpoint_required",
      ]);
      for (const [key, value] of Object.entries(expectedDetails)) {
        assert.equal(error.details[key], value);
      }
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      assert.equal(Object.hasOwn(error.details, "rustCoreBoundary"), false);
      assert.equal(Object.hasOwn(error.details, "evidenceRefs"), false);
      return true;
    });
  }

  assertNoMutation(state);
});

test("mount and unmount still reject retired request aliases before Rust-core boundary", () => {
  const state = fakeState();

  assert.throws(
    () =>
      ModelMountingState.prototype.mountEndpoint.call(
        state,
        {
          modelId: "llama-test",
          providerId: "provider.fixture",
          apiFormat: "openai",
          baseUrl: "http://127.0.0.1:8080/v1",
          privacyClass: "local_private",
          backendId: "backend.native",
          loadPolicy: "resident",
        },
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_endpoint_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "modelId",
        "providerId",
        "apiFormat",
        "baseUrl",
        "privacyClass",
        "backendId",
        "loadPolicy",
      ]);
      assert.equal(Object.hasOwn(error.details, "modelId"), false);
      return true;
    },
  );

  assert.throws(
    () => ModelMountingState.prototype.unmountEndpoint.call(state, { endpointId: "endpoint.llama" }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_unmount_endpoint_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["endpointId"]);
      assert.equal(Object.hasOwn(error.details, "endpointId"), false);
      return true;
    },
  );

  assertNoMutation(state);
});
