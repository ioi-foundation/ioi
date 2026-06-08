import assert from "node:assert/strict";
import test from "node:test";

import {
  contextWindowForEndpoint,
  countModelTokens,
  fitModelContext,
  modelTokenizerUtility,
  tokenizeModel,
} from "./tokenizer-operations.mjs";

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
    routes: new Map([[route.id, route]]),
    writes: [],
    authorize(authorization, requiredScope) {
      this.authorizationCalls.push({ authorization, requiredScope });
      return { authorization, requiredScope, grantId: `grant.${requiredScope}` };
    },
    contextWindowForEndpoint(endpointRecord, body) {
      return contextWindowForEndpoint(this, endpointRecord, body);
    },
    modelTokenizerUtility(args) {
      return modelTokenizerUtility(this, args, deps);
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

const deps = {
  deterministicTokenizeText(input) {
    return String(input).trim() ? String(input).trim().split(/\s+/) : [];
  },
  inputText(body = {}) {
    return body.input ?? body.prompt ?? "";
  },
  normalizeNonNegativeInteger(value, fallback) {
    const number = Number(value);
    return Number.isFinite(number) && number >= 0 ? Math.floor(number) : fallback;
  },
  schemaVersion: "schema.tokenizer.test",
  stableHash(value) {
    return `hash:${value}`;
  },
  truncateToEstimatedTokens(input, availableTokens) {
    return String(input).trim().split(/\s+/).slice(-availableTokens).join(" ");
  },
};

test("modelTokenizerUtility fails closed before JS tokenization receipt or route mutation", () => {
  const state = fakeState();

  assert.throws(
    () =>
      modelTokenizerUtility(
        state,
        {
          authorization: "auth",
          requiredScope: "model.tokenize:*",
          body: { input: "one two three", model: "llama-test", route_id: "route.local-first" },
          operation: "tokenize",
        },
        deps,
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
});

test("modelTokenizerUtility does not fall back to JS route record-state commit", () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () =>
      modelTokenizerUtility(
        state,
        { authorization: "auth", requiredScope: "model.tokenize:*", body: { input: "one two three" }, operation: "count_tokens" },
        deps,
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
});

test("modelTokenizerUtility rejects retired request aliases before authorization", () => {
  const state = fakeState();

  assert.throws(
    () =>
      modelTokenizerUtility(
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
        deps,
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
});

test("tokenizeModel and countModelTokens fail closed before public JS response envelopes", () => {
  const state = fakeState();

  assert.throws(
    () =>
      tokenizeModel(
        state,
        { authorization: "auth", body: { input: "alpha beta" } },
        { schemaVersion: deps.schemaVersion },
      ),
    (error) => {
      assert.equal(error.code, "model_mount_tokenizer_rust_core_required");
      assert.equal(error.details.operation, "tokenize");
      return true;
    },
  );
  assert.throws(
    () =>
      countModelTokens(
        state,
        { authorization: "auth", body: { input: "alpha beta gamma" } },
        { schemaVersion: deps.schemaVersion, stableHash: deps.stableHash },
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
});

test("fitModelContext fails closed before JS context-fit receipt or truncation envelope", () => {
  const state = fakeState();

  assert.throws(
    () =>
      fitModelContext(
        state,
        { authorization: "auth", body: { input: "one two three four five", max_output_tokens: 1 } },
        deps,
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
});

test("contextWindowForEndpoint honors explicit, artifact, metadata, and default fallbacks", () => {
  const state = fakeState();

  assert.equal(contextWindowForEndpoint(state, { modelId: "missing" }, { context_length: 16 }), 16);
  assert.equal(contextWindowForEndpoint(state, { modelId: "llama-test", artifactId: "artifact.llama" }, {}), 4);

  state.artifacts.set("artifact.meta", {
    id: "artifact.meta",
    modelId: "meta-model",
    metadata: { context: 12 },
  });
  assert.equal(contextWindowForEndpoint(state, { modelId: "meta-model" }, {}), 12);
  assert.equal(contextWindowForEndpoint(state, { modelId: "unknown" }, {}), 4096);
});
