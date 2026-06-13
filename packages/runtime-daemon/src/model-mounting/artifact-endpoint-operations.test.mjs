import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function fakeState({ withPlanner = true, withCommit = true } = {}) {
  return {
    artifacts: new Map(),
    endpoints: new Map(),
    recordStateCommits: [],
    planRequests: [],
    receipts: [],
    writes: [],
    projections: 0,
    ...(withPlanner
      ? {
          planArtifactEndpoint(request) {
            this.planRequests.push(request);
            return artifactEndpointPlan(request);
          },
        }
      : {}),
    ...(withCommit
      ? {
          commitRuntimeModelMountRecordState(request) {
            this.recordStateCommits.push(request);
            return {
              record_id: request.record_id,
              object_ref: `agentgres://model-mounting/${request.record_dir}/${request.record_id}`,
              content_hash: `sha256:${request.operation_kind}:${request.record_id}`,
              admission_hash: `sha256:admission:${request.operation_kind}:${request.record_id}`,
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
        }
      : {}),
    endpoint(endpointId) {
      throw new Error(`endpoint lookup should not run: ${endpointId}`);
    },
    getModel(modelId) {
      throw new Error(`artifact lookup should not run: ${modelId}`);
    },
    lifecycleReceipt(kind) {
      throw new Error(`lifecycle receipt should not run: ${kind}`);
    },
    modelForProviderMount() {
      throw new Error("provider artifact mount lookup should not run");
    },
    nowIso() {
      return "2026-06-13T00:00:00.000Z";
    },
    provider(providerId) {
      throw new Error(`provider lookup should not run: ${providerId}`);
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()]]);
    },
    writeProjection() {
      this.projections += 1;
    },
  };
}

function artifactEndpointPlan(request) {
  const body = request.body ?? {};
  const isImport = request.operation_kind === "model_mount.artifact.import";
  const isUnmount = request.operation_kind === "model_mount.endpoint.unmount";
  const recordDir = isImport ? "model-artifacts" : "model-endpoints";
  const id = isImport
    ? `artifact.${body.model_id}`
    : isUnmount
      ? body.endpoint_id
      : `endpoint.${body.provider_id ?? "provider.local.folder"}.${body.model_id}`;
  const publicResponse = isImport
    ? {
        object: "ioi.model_mount_model_artifact",
        status: "imported",
        id,
        artifact_id: id,
        model_id: body.model_id,
        provider_id: body.provider_id ?? "provider.local.folder",
        plaintext_source_path_returned: false,
      }
    : {
        object: "ioi.model_mount_endpoint",
        status: isUnmount ? "unmounted" : "mounted",
        id,
        endpoint_id: id,
        model_id: body.model_id ?? null,
        provider_id: body.provider_id ?? null,
        load_policy: body.load_policy ?? { mode: "on_demand" },
        plaintext_transport_material_returned: false,
      };
  const evidenceRefs = [
    "public_artifact_endpoint_js_facade_retired",
    "rust_daemon_core_artifact_endpoint",
    "agentgres_artifact_endpoint_truth_required",
  ];
  const record = {
    ...publicResponse,
    record_id: id,
    operation_kind: request.operation_kind,
    rust_core_boundary: "model_mount.artifact_endpoint",
    public_response: publicResponse,
    receipt_refs: request.receipt_refs,
    evidence_refs: evidenceRefs,
    control_hash: `sha256:control:${request.operation_kind}:${id}`,
    authority_hash: `sha256:authority:${request.operation_kind}:${id}`,
  };
  return {
    schema_version: "ioi.model_mount.artifact_endpoint_plan.v1",
    object: "ioi.model_mount_artifact_endpoint_plan",
    status: "planned",
    rust_core_boundary: "model_mount.artifact_endpoint",
    operation_kind: request.operation_kind,
    source: request.source,
    record_dir: recordDir,
    record_id: id,
    record,
    public_response: publicResponse,
    receipt_refs: request.receipt_refs,
    authority_grant_refs: request.authority_grant_refs,
    authority_receipt_refs: request.authority_receipt_refs,
    evidence_refs: evidenceRefs,
    control_hash: record.control_hash,
    authority_hash: record.authority_hash,
  };
}

function assertNoJsMutation(state) {
  assert.equal(state.artifacts.size, 0);
  assert.equal(state.endpoints.size, 0);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
  assert.equal(state.projections, 0);
}

test("model import commits Rust-authored artifact record state", () => {
  const state = fakeState();

  const result = ModelMountingState.prototype.importModel.call(
    state,
    {
      model_id: "llama-test",
      source_path: "/tmp/model.gguf",
      provider_id: "provider.local.folder",
      display_name: "Llama Test",
      receipt_refs: ["receipt://import"],
    },
  );

  assert.equal(result.status, "imported");
  assert.equal(result.rust_core_boundary, "model_mount.artifact_endpoint");
  assert.equal(result.record_dir, "model-artifacts");
  assert.equal(result.record.model_id, "llama-test");
  assert.equal(result.record.public_response.plaintext_source_path_returned, false);
  assert.equal(state.planRequests.length, 1);
  assert.equal(state.planRequests[0].schema_version, "ioi.model_mount.artifact_endpoint.v1");
  assert.equal(state.planRequests[0].operation_kind, "model_mount.artifact.import");
  assert.equal(state.planRequests[0].body.model_id, "llama-test");
  assert.deepEqual(state.planRequests[0].receipt_refs, ["receipt://import"]);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "model-artifacts");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.artifact.import");
  assertNoJsMutation(state);
});

test("mount and unmount commit Rust-authored endpoint record state", () => {
  const state = fakeState();

  const mounted = ModelMountingState.prototype.mountEndpoint.call(
    state,
    {
      model_id: "llama-test",
      provider_id: "provider.fixture",
      load_policy: { mode: "resident" },
      authority_grant_refs: ["grant://wallet/endpoint"],
      authority_receipt_refs: ["receipt://wallet/endpoint"],
    },
  );
  const unmounted = ModelMountingState.prototype.unmountEndpoint.call(
    state,
    { endpoint_id: mounted.endpoint_id },
  );

  assert.equal(mounted.status, "mounted");
  assert.equal(mounted.record_dir, "model-endpoints");
  assert.equal(mounted.record.model_id, "llama-test");
  assert.equal(mounted.record.public_response.plaintext_transport_material_returned, false);
  assert.equal(unmounted.status, "unmounted");
  assert.equal(unmounted.record_dir, "model-endpoints");
  assert.equal(state.planRequests.length, 2);
  assert.equal(state.planRequests[0].operation_kind, "model_mount.endpoint.mount");
  assert.equal(state.planRequests[0].body.provider_id, "provider.fixture");
  assert.deepEqual(state.planRequests[0].authority_grant_refs, ["grant://wallet/endpoint"]);
  assert.equal(state.planRequests[1].operation_kind, "model_mount.endpoint.unmount");
  assert.equal(state.recordStateCommits.length, 2);
  assert.deepEqual(
    state.recordStateCommits.map((commit) => commit.record_dir),
    ["model-endpoints", "model-endpoints"],
  );
  assertNoJsMutation(state);
});

test("artifact and endpoint mutation require Rust planner and record-state commit", () => {
  const missingPlanner = fakeState({ withPlanner: false });
  assert.throws(
    () =>
      ModelMountingState.prototype.mountEndpoint.call(
        missingPlanner,
        { model_id: "llama-test" },
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_artifact_endpoint_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.artifact_endpoint");
      assert.equal(error.details.rust_core_api, "plan_model_mount_artifact_endpoint");
      assert.deepEqual(error.details.evidence_refs, [
        "public_artifact_endpoint_js_facade_retired",
        "rust_daemon_core_artifact_endpoint",
        "agentgres_artifact_endpoint_truth_required",
      ]);
      assert.equal(Object.hasOwn(error.details, "operationKind"), false);
      return true;
    },
  );

  const missingCommit = fakeState({ withCommit: false });
  assert.throws(
    () =>
      ModelMountingState.prototype.unmountEndpoint.call(
        missingCommit,
        { endpoint_id: "endpoint.llama" },
      ),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_mount_artifact_endpoint_record_state_commit_unconfigured");
      assert.equal(error.details.record_dir, "model-endpoints");
      assert.equal(error.details.operation_kind, "model_mount.endpoint.unmount");
      return true;
    },
  );

  assertNoJsMutation(missingPlanner);
  assertNoJsMutation(missingCommit);
});

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
  assertNoJsMutation(state);
  assert.deepEqual(state.planRequests, []);
  assert.deepEqual(state.recordStateCommits, []);
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

  assertNoJsMutation(state);
  assert.deepEqual(state.planRequests, []);
  assert.deepEqual(state.recordStateCommits, []);
});
