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

test("modelTokenizerUtility records route and redacted tokenization receipt", () => {
  const state = fakeState();

  const utility = modelTokenizerUtility(
    state,
    { authorization: "auth", requiredScope: "model.tokenize:*", body: { input: "one two three" }, operation: "tokenize" },
    deps,
  );

  assert.deepEqual(utility.tokens, ["one", "two", "three"]);
  assert.equal(utility.promptTokens, 3);
  assert.equal(utility.contextWindow, 4);
  assert.equal(utility.receipt.kind, "model_tokenization");
  assert.equal(utility.receipt.payload.details.route_id, "route.local-first");
  assert.equal(utility.receipt.payload.details.route_receipt_id, "route-receipt.1");
  assert.equal(utility.receipt.payload.details.selected_model, "llama-test");
  assert.equal(utility.receipt.payload.details.endpoint_id, "endpoint.local.llama");
  assert.equal(utility.receipt.payload.details.provider_id, "provider.local");
  assert.equal(utility.receipt.payload.details.backend_id, "backend.native");
  assert.equal(utility.receipt.payload.details.selected_backend, "backend.native");
  assert.equal(utility.receipt.payload.details.grant_id, "grant.model.tokenize:*");
  assert.equal(utility.receipt.payload.details.tokenizer_source, "deterministic_estimator");
  assert.equal(utility.receipt.payload.details.input_hash, "hash:one two three");
  assert.deepEqual(utility.receipt.payload.details.token_count, {
    prompt_tokens: 3,
    completion_tokens: 0,
    total_tokens: 3,
  });
  assert.equal(utility.receipt.payload.details.context_window, 4);
  assert.equal(Object.hasOwn(utility.receipt.payload.details, "routeId"), false);
  assert.equal(Object.hasOwn(utility.receipt.payload.details, "routeReceiptId"), false);
  assert.equal(Object.hasOwn(utility.receipt.payload.details, "selectedModel"), false);
  assert.equal(Object.hasOwn(utility.receipt.payload.details, "endpointId"), false);
  assert.equal(Object.hasOwn(utility.receipt.payload.details, "providerId"), false);
  assert.equal(Object.hasOwn(utility.receipt.payload.details, "backendId"), false);
  assert.equal(Object.hasOwn(utility.receipt.payload.details, "selectedBackend"), false);
  assert.equal(Object.hasOwn(utility.receipt.payload.details, "grantId"), false);
  assert.equal(Object.hasOwn(utility.receipt.payload.details, "tokenizerSource"), false);
  assert.equal(Object.hasOwn(utility.receipt.payload.details, "inputHash"), false);
  assert.equal(Object.hasOwn(utility.receipt.payload.details, "tokenCount"), false);
  assert.equal(Object.hasOwn(utility.receipt.payload.details, "contextWindow"), false);
  assert.equal(state.routes.get("route.local-first").lastSelectedModel, undefined);
  assert.equal(state.writes.length, 0);
  assert.deepEqual(state.recordStateCommits, []);
});

test("modelTokenizerUtility does not require JS route record-state commit", () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  const utility = modelTokenizerUtility(
    state,
    { authorization: "auth", requiredScope: "model.tokenize:*", body: { input: "one two three" }, operation: "tokenize" },
    deps,
  );

  assert.equal(utility.receipt.kind, "model_tokenization");
  assert.equal(state.routes.get("route.local-first").lastReceiptId, undefined);
  assert.deepEqual(state.recordStateCommits, []);
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

test("tokenizeModel and countModelTokens preserve public response envelopes", () => {
  const state = fakeState();

  const tokenized = tokenizeModel(
    state,
    { authorization: "auth", body: { input: "alpha beta" } },
    { schemaVersion: deps.schemaVersion },
  );
  const counted = countModelTokens(
    state,
    { authorization: "auth", body: { input: "alpha beta gamma" } },
    { schemaVersion: deps.schemaVersion, stableHash: deps.stableHash },
  );

  assert.equal(tokenized.schemaVersion, "schema.tokenizer.test");
  assert.deepEqual(tokenized.tokens, ["alpha", "beta"]);
  assert.equal(tokenized.token_count, 2);
  assert.equal(tokenized.usage.total_tokens, 2);
  assert.equal(counted.input_hash, "hash:alpha beta gamma");
  assert.equal(counted.token_count, 3);
  assert.equal(counted.route_receipt_id, "route-receipt.2");
});

test("fitModelContext reports fit and keep-tail truncation", () => {
  const state = fakeState();

  const result = fitModelContext(
    state,
    { authorization: "auth", body: { input: "one two three four five", max_output_tokens: 1 } },
    deps,
  );

  assert.equal(result.schemaVersion, "schema.tokenizer.test");
  assert.equal(result.context_window, 4);
  assert.equal(result.reserved_output_tokens, 1);
  assert.equal(result.available_input_tokens, 3);
  assert.equal(result.prompt_tokens, 5);
  assert.equal(result.fits, false);
  assert.equal(result.overflow_tokens, 2);
  assert.equal(result.truncation.applied, true);
  assert.equal(result.fitted_input, "three four five");
  assert.equal(result.fitted_input_hash, "hash:three four five");
  assert.equal(state.receipts.at(-1).kind, "model_context_fit");
  assert.equal(state.receipts.at(-1).payload.details.operation, "context_fit");
  assert.equal(state.receipts.at(-1).payload.details.context_window, 4);
  assert.equal(Object.hasOwn(state.receipts.at(-1).payload.details, "contextWindow"), false);
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
