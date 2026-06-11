import assert from "node:assert/strict";
import test from "node:test";

import { ModelMountingState } from "../model-mounting.mjs";

function fakeState() {
  const endpoint = {
    id: "endpoint.local.llama",
    providerId: "provider.local",
    modelId: "llama-test",
    backendId: "backend.native",
    artifactId: "artifact.llama",
  };
  const route = {
    id: "route.local-first",
    endpointIds: [endpoint.id],
  };
  const recordStateCommits = [];
  return {
    artifacts: new Map([
      ["artifact.llama", {
        id: "artifact.llama",
        modelId: "llama-test",
        contextWindow: 4,
      }],
    ]),
    authorizationCalls: [],
    receipts: [],
    routeReceiptCount: 0,
    recordStateCommits,
    tokenizerRequiredRequests: [],
    modelMountAdmissionRunner: {
      planTokenizerRequired: (request) => {
        const details = {
          operation: request.operation,
          ...request.details,
          rust_core_boundary: "model_mount.tokenizer",
          source: request.source,
          evidence_refs: request.evidence_refs,
        };
        fakeState.current.tokenizerRequiredRequests.push(request);
        return {
          source: "rust_model_mount_tokenizer_required_command",
          backend: "rust_model_mount_tokenizer_required",
          status: "rust_core_required",
          status_code: 501,
          code: "model_mount_tokenizer_rust_core_required",
          message:
            "Model tokenization and context-fit utilities require direct Rust daemon-core admission and projection.",
          rust_core_boundary: "model_mount.tokenizer",
          operation: request.operation,
          details,
          evidence_refs: request.evidence_refs,
          record: {
            schema_version: "ioi.model_mount.tokenizer_required_result.v1",
            object: "ioi.model_mount_tokenizer_required",
            status: "rust_core_required",
            status_code: 501,
            code: "model_mount_tokenizer_rust_core_required",
            message:
              "Model tokenization and context-fit utilities require direct Rust daemon-core admission and projection.",
            rust_core_boundary: "model_mount.tokenizer",
            operation: request.operation,
            source: request.source,
            evidence_refs: request.evidence_refs,
            details,
            generated_at: "rust_model_mount_core",
          },
        };
      },
    },
    tokenizerRequired(operation, details = {}) {
      return ModelMountingState.prototype.tokenizerRequired.call(this, operation, details);
    },
    routes: new Map([[route.id, route]]),
    writes: [],
    authorize(authorization, requiredScope) {
      this.authorizationCalls.push({ authorization, requiredScope });
      return { authorization, requiredScope, grantId: `grant.${requiredScope}` };
    },
    receipt(kind, payload) {
      const receipt = { id: `receipt.${kind}.${this.receipts.length + 1}`, kind, payload };
      this.receipts.push(receipt);
      return receipt;
    },
    routeSelectionReceipt(selection, payload) {
      this.routeReceiptCount += 1;
      return {
        id: `route-receipt.${this.routeReceiptCount}`,
        selection,
        payload,
      };
    },
    selectRoute({ routeId }) {
      return {
        route: this.routes.get(routeId ?? "route.local-first"),
        endpoint,
        provider: { id: endpoint.providerId },
      };
    },
    writeMap(name, map) {
      this.writes.push([name, [...map.values()].map((record) => ({ ...record }))]);
    },
    commitRuntimeModelMountRecordState(request) {
      recordStateCommits.push(request);
      return {
        record_id: request.record_id,
        object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}`,
        content_hash: `sha256:${request.record_id}`,
        admission_hash: `admit:${request.record_id}`,
        commit_hash: `commit:${request.record_id}`,
        written_record: request.record,
        storage_record: {
          object_ref: `agentgres://model-mounting/records/${request.record_dir}/${request.record_id}`,
          content_hash: `sha256:${request.record_id}`,
          admission: { admission_hash: `admit:${request.record_id}` },
        },
      };
    },
  };
}

test("modelTokenizerUtility fails closed before JS tokenization receipt or route mutation", () => {
  const state = fakeState();
  fakeState.current = state;

  assert.throws(
    () =>
      ModelMountingState.prototype.modelTokenizerUtility.call(
        state,
        {
          authorization: "auth",
          requiredScope: "model.tokenize:*",
          body: { input: "one two three", model: "llama-test", route_id: "route.local-first" },
          operation: "tokenize",
        },
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_tokenizer_rust_core_required");
      assert.equal(error.details.rust_core_boundary, "model_mount.tokenizer");
      assert.equal(error.details.operation, "tokenize");
      assert.equal(error.details.model, "llama-test");
      assert.equal(error.details.route_id, "route.local-first");
      assert.equal(error.details.requested_scope, "model.tokenize:*");
      assert.ok(error.details.evidence_refs.includes("model_mount_tokenizer_js_facade_retired"));
      assert.ok(error.details.evidence_refs.includes("rust_daemon_core_model_tokenizer_required"));
      assert.ok(error.details.evidence_refs.includes("agentgres_model_tokenizer_truth_required"));
      return true;
    },
  );

  assert.deepEqual(state.authorizationCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.routeReceiptCount, 0);
  assert.equal(state.routes.get("route.local-first").lastSelectedModel, undefined);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.tokenizerRequiredRequests.length, 1);
  assert.equal(state.tokenizerRequiredRequests[0].schema_version, "ioi.model_mount.tokenizer_required.v1");
  assert.equal(state.tokenizerRequiredRequests[0].operation, "tokenize");
  assert.equal(state.tokenizerRequiredRequests[0].details.model, "llama-test");
  assert.equal(state.tokenizerRequiredRequests[0].details.route_id, "route.local-first");
  assert.equal(state.tokenizerRequiredRequests[0].details.requested_scope, "model.tokenize:*");
  assert.equal(Object.hasOwn(state.tokenizerRequiredRequests[0].details, "routeId"), false);
  assert.equal(Object.hasOwn(state.tokenizerRequiredRequests[0].details, "requestedScope"), false);
});

test("modelTokenizerUtility does not fall back to JS route record-state commit", () => {
  const state = fakeState();
  fakeState.current = state;
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () =>
      ModelMountingState.prototype.modelTokenizerUtility.call(
        state,
        { authorization: "auth", requiredScope: "model.tokenize:*", body: { input: "one two three" }, operation: "count_tokens" },
      ),
    (error) => {
      assert.equal(error.code, "model_mount_tokenizer_rust_core_required");
      assert.equal(error.details.operation, "count_tokens");
      assert.ok(error.details.evidence_refs.includes("model_mount_tokenizer_js_facade_retired"));
      return true;
    },
  );

  assert.equal(state.routes.get("route.local-first").lastReceiptId, undefined);
  assert.deepEqual(state.recordStateCommits, []);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.tokenizerRequiredRequests.length, 1);
  assert.equal(state.tokenizerRequiredRequests[0].operation, "count_tokens");
});

test("modelTokenizerUtility rejects retired request aliases before authorization", () => {
  const state = fakeState();
  fakeState.current = state;

  assert.throws(
    () =>
      ModelMountingState.prototype.modelTokenizerUtility.call(
        state,
        {
          authorization: "auth",
          requiredScope: "model.tokenize:*",
          body: {
            input: "legacy tokenizer aliases",
            routeId: "route.local-first",
            modelPolicy: { privacy: "legacy" },
            contextLength: 8,
            contextWindow: 8,
            maxOutputTokens: 2,
            reserveOutputTokens: 2,
            reserve_output_tokens: 2,
          },
          operation: "tokenize",
        },
      ),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_tokenizer_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, [
        "routeId",
        "modelPolicy",
        "contextLength",
        "contextWindow",
        "maxOutputTokens",
        "reserveOutputTokens",
        "reserve_output_tokens",
      ]);
      assert.deepEqual(error.details.canonical_fields, [
        "route_id",
        "model_policy",
        "context_length",
        "max_output_tokens",
      ]);
      assert.equal(Object.hasOwn(error.details, "routeId"), false);
      return true;
    },
  );
  assert.deepEqual(state.authorizationCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.deepEqual(state.writes, []);
  assert.deepEqual(state.tokenizerRequiredRequests, []);
});

test("tokenizeModel and countModelTokens fail closed before public JS response envelopes", () => {
  const state = fakeState();
  fakeState.current = state;

  assert.throws(
    () =>
      ModelMountingState.prototype.tokenizeModel.call(
        state,
        { authorization: "auth", body: { input: "alpha beta" } },
      ),
    (error) => {
      assert.equal(error.code, "model_mount_tokenizer_rust_core_required");
      assert.equal(error.details.operation, "tokenize");
      return true;
    },
  );
  assert.throws(
    () =>
      ModelMountingState.prototype.countModelTokens.call(
        state,
        { authorization: "auth", body: { input: "alpha beta gamma" } },
      ),
    (error) => {
      assert.equal(error.code, "model_mount_tokenizer_rust_core_required");
      assert.equal(error.details.operation, "count_tokens");
      return true;
    },
  );

  assert.deepEqual(state.authorizationCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.routeReceiptCount, 0);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.tokenizerRequiredRequests.length, 2);
  assert.equal(state.tokenizerRequiredRequests[0].operation, "tokenize");
  assert.equal(state.tokenizerRequiredRequests[1].operation, "count_tokens");
});

test("fitModelContext fails closed before JS context-fit receipt or truncation envelope", () => {
  const state = fakeState();
  fakeState.current = state;

  assert.throws(
    () =>
      ModelMountingState.prototype.fitModelContext.call(
        state,
        { authorization: "auth", body: { input: "one two three four five", max_output_tokens: 1 } },
      ),
    (error) => {
      assert.equal(error.status, 501);
      assert.equal(error.code, "model_mount_tokenizer_rust_core_required");
      assert.equal(error.details.operation, "context_fit");
      assert.ok(error.details.evidence_refs.includes("model_mount_context_fit_js_facade_retired"));
      assert.ok(error.details.evidence_refs.includes("rust_daemon_core_model_context_fit_required"));
      return true;
    },
  );

  assert.deepEqual(state.authorizationCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.routeReceiptCount, 0);
  assert.deepEqual(state.recordStateCommits, []);
  assert.equal(state.tokenizerRequiredRequests.length, 1);
  assert.equal(state.tokenizerRequiredRequests[0].operation, "context_fit");
});

test("contextWindowForEndpoint honors explicit, artifact, metadata, and default fallbacks", () => {
  const state = fakeState();
  fakeState.current = state;

  assert.equal(
    ModelMountingState.prototype.contextWindowForEndpoint.call(state, { modelId: "missing" }, { context_length: 16 }),
    16,
  );
  assert.equal(
    ModelMountingState.prototype.contextWindowForEndpoint.call(
      state,
      { modelId: "llama-test", artifactId: "artifact.llama" },
      {},
    ),
    4,
  );

  state.artifacts.set("artifact.meta", {
    id: "artifact.meta",
    modelId: "meta-model",
    metadata: { context: 12 },
  });
  assert.equal(ModelMountingState.prototype.contextWindowForEndpoint.call(state, { modelId: "meta-model" }, {}), 12);
  assert.equal(ModelMountingState.prototype.contextWindowForEndpoint.call(state, { modelId: "unknown" }, {}), 4096);
});
