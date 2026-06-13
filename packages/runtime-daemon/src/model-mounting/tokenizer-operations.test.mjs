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
  const routeSelection = {
    route,
    endpoint,
    provider: { id: endpoint.providerId },
    route_decision: {
      route_ref: route.id,
      provider_ref: endpoint.providerId,
      endpoint_ref: endpoint.id,
      model_ref: endpoint.modelId,
      capability: "chat",
      route_decision_ref: "model_mount://route_decision/test",
      route_decision_hash: "sha256:route-decision",
      receipt_refs: ["receipt://route-selection/test"],
    },
    route_receipt: {
      id: "model-mount/route-control/model_mount.route.select/test",
      kind: "model_route_selection",
    },
    route_control: {
      record_dir: "model-route-selections",
      record_id: "route_selection:route.local-first:test",
      control_hash: "sha256:route-control",
    },
    rust_core_boundary: "model_mount.route_control",
    evidence_refs: ["model_mount_route_control_rust_owned"],
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
    tokenizerPlans: [],
    routeSelections: [],
    routes: new Map([[route.id, route]]),
    writes: [],
    nowIso() {
      return "2026-06-13T00:00:00.000Z";
    },
    selectRoute(request) {
      this.routeSelections.push(request);
      return routeSelection;
    },
    planTokenizer(request) {
      this.tokenizerPlans.push(request);
      const input = typeof request.body?.input === "string" ? request.body.input : "";
      const tokens = input.split(/\s+/).filter(Boolean);
      const tokenCount = tokens.length;
      const record = {
        id: `model_tokenizer:${request.operation}:test`,
        object: "ioi.model_mount_tokenizer_result",
        status: "planned",
        operation: request.operation,
        route_id: request.route_selection.route.id,
        model: request.route_selection.endpoint.modelId,
        endpoint_id: request.route_selection.endpoint.id,
        provider_id: request.route_selection.provider.id,
        route_decision_ref: request.route_selection.route_decision.route_decision_ref,
        route_receipt_ref: "receipt://model-mount/route-control/model_mount.route.select/test",
        required_scope: request.required_scope,
        input_hash: "sha256:input",
        tokens,
        token_count: tokenCount,
        usage: {
          prompt_tokens: tokenCount,
          total_tokens: tokenCount,
        },
        context_window: 4,
        available_input_tokens: 3,
        fits: tokenCount <= 3,
        truncation: {
          applied: tokenCount > 3,
          input_tokens: 3,
          fitted_input: tokens.slice(0, 3).join(" "),
        },
        fitted_input_hash: "sha256:fitted",
      };
      return {
        source: "rust_model_mount_tokenizer_command",
        backend: "rust_model_mount_tokenizer",
        plan: {},
        record_dir: "model-tokenizer-utilities",
        record_id: record.id,
        record,
        operation: request.operation,
        rust_core_boundary: "model_mount.tokenizer",
        receipt_refs: ["receipt://route-selection/test"],
        evidence_refs: ["model_mount_tokenizer_rust_owned", "agentgres_model_tokenizer_truth_required"],
        control_hash: "sha256:tokenizer-control",
      };
    },
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

test("modelTokenizerUtility uses Rust tokenizer planning and Agentgres commit without JS tokenization receipt", () => {
  const state = fakeState();

  const response = ModelMountingState.prototype.modelTokenizerUtility.call(
    state,
    {
      authorization: "auth",
      requiredScope: "model.tokenize:*",
      body: { input: "one two three", model: "llama-test", route_id: "route.local-first" },
      operation: "tokenize",
    },
  );

  assert.equal(response.object, "ioi.model_mount_tokenizer");
  assert.equal(response.status, "committed");
  assert.equal(response.operation, "tokenize");
  assert.equal(response.rust_core_boundary, "model_mount.tokenizer");
  assert.equal(response.route_id, "route.local-first");
  assert.equal(response.model, "llama-test");
  assert.deepEqual(response.tokens, ["one", "two", "three"]);
  assert.equal(response.token_count, 3);
  assert.equal(response.usage.prompt_tokens, 3);
  assert.equal(state.routeSelections.length, 1);
  assert.equal(state.routeSelections[0].routeId, "route.local-first");
  assert.equal(state.routeSelections[0].modelId, "llama-test");
  assert.equal(state.routeSelections[0].capability, "chat");
  assert.equal(state.tokenizerPlans.length, 1);
  assert.equal(state.tokenizerPlans[0].schema_version, "ioi.model_mount.tokenizer.v1");
  assert.equal(state.tokenizerPlans[0].operation, "tokenize");
  assert.equal(state.tokenizerPlans[0].required_scope, "model.tokenize:*");
  assert.equal(state.tokenizerPlans[0].route_selection.route_decision.route_decision_ref, "model_mount://route_decision/test");
  assert.deepEqual(state.tokenizerPlans[0].artifacts.map((artifact) => artifact.id), ["artifact.llama"]);
  assert.deepEqual(state.authorizationCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.routeReceiptCount, 0);
  assert.deepEqual(state.writes, []);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.recordStateCommits[0].record_dir, "model-tokenizer-utilities");
  assert.equal(state.recordStateCommits[0].operation_kind, "model_mount.tokenizer.tokenize");
  assert.deepEqual(state.recordStateCommits[0].receipt_refs, ["receipt://route-selection/test"]);
});

test("modelTokenizerUtility fails closed when Rust tokenizer record-state commit is missing", () => {
  const state = fakeState();
  delete state.commitRuntimeModelMountRecordState;

  assert.throws(
    () =>
      ModelMountingState.prototype.modelTokenizerUtility.call(
        state,
        {
          authorization: "auth",
          requiredScope: "model.tokenize:*",
          body: { input: "one two three", route_id: "route.local-first" },
          operation: "count_tokens",
        },
      ),
    (error) => {
      assert.equal(error.status, 500);
      assert.equal(error.code, "model_mount_tokenizer_record_state_commit_unconfigured");
      assert.equal(error.details.record_dir, "model-tokenizer-utilities");
      return true;
    },
  );

  assert.equal(state.tokenizerPlans.length, 1);
  assert.equal(state.tokenizerPlans[0].operation, "count_tokens");
  assert.deepEqual(state.authorizationCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.routeReceiptCount, 0);
});

test("modelTokenizerUtility rejects retired request aliases before route selection or Rust planning", () => {
  const state = fakeState();

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
  assert.deepEqual(state.routeSelections, []);
  assert.deepEqual(state.tokenizerPlans, []);
});

test("tokenizeModel and countModelTokens return Rust tokenizer records", () => {
  const state = fakeState();

  const tokenized = ModelMountingState.prototype.tokenizeModel.call(
    state,
    { authorization: "auth", body: { input: "alpha beta" } },
  );
  const counted = ModelMountingState.prototype.countModelTokens.call(
    state,
    { authorization: "auth", body: { input: "alpha beta gamma" } },
  );

  assert.equal(tokenized.operation, "tokenize");
  assert.equal(tokenized.token_count, 2);
  assert.equal(counted.operation, "count_tokens");
  assert.equal(counted.token_count, 3);
  assert.deepEqual(state.authorizationCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.routeReceiptCount, 0);
  assert.equal(state.recordStateCommits.length, 2);
  assert.equal(state.tokenizerPlans[0].operation, "tokenize");
  assert.equal(state.tokenizerPlans[1].operation, "count_tokens");
});

test("fitModelContext returns Rust context-fit record without JS truncation receipt", () => {
  const state = fakeState();

  const response = ModelMountingState.prototype.fitModelContext.call(
    state,
    { authorization: "auth", body: { input: "one two three four five", max_output_tokens: 1 } },
  );

  assert.equal(response.operation, "context_fit");
  assert.equal(response.context_window, 4);
  assert.equal(response.available_input_tokens, 3);
  assert.equal(response.fits, false);
  assert.equal(response.truncation.applied, true);
  assert.equal(response.truncation.fitted_input, "one two three");
  assert.deepEqual(state.authorizationCalls, []);
  assert.deepEqual(state.receipts, []);
  assert.equal(state.routeReceiptCount, 0);
  assert.equal(state.recordStateCommits.length, 1);
  assert.equal(state.tokenizerPlans[0].operation, "context_fit");
});
