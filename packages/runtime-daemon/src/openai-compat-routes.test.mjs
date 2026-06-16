import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import {
  anthropicMessagesToCanonicalBody,
  recordModelStreamCanceled,
  writeOpenAiProviderChatCompletionStream,
} from "./openai-compat-routes.mjs";

class FakeResponse extends EventEmitter {
  constructor() {
    super();
    this.headers = {};
    this.statusCode = 0;
    this.destroyed = false;
    this.writableEnded = false;
    this.frames = [];
  }

  setHeader(name, value) {
    this.headers[name.toLowerCase()] = value;
  }

  write(frame) {
    this.frames.push(frame);
    return true;
  }

  end() {
    this.writableEnded = true;
  }
}

function providerStreamFromFrames(frames) {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const frame of frames) {
        controller.enqueue(encoder.encode(frame));
      }
      controller.close();
    },
  });
}

function invocationFixture() {
  return {
    invocation: {
      kind: "chat.completions",
      input: "hello",
      model: "model.native",
      route: { id: "route.native" },
      endpoint: { id: "endpoint.native", providerId: "provider.native" },
      instance: { id: "instance.native", backendId: "backend.native" },
      receipt: {
        id: "receipt.invocation",
        details: {
          backend_id: "backend.native",
          selected_backend: "backend.native",
          stream_source: "provider_native",
          provider_response_kind: "openai.chat.stream",
          backend_evidence_refs: ["backend.native"],
        },
      },
      responseId: "resp.native",
      previousResponseId: null,
      toolReceiptIds: [],
    },
    providerResult: {
      providerResponseKind: "openai.chat.stream",
      backendEvidenceRefs: ["backend.native"],
    },
  };
}

test("Anthropic messages canonical body preserves canonical max_tokens", () => {
  const body = anthropicMessagesToCanonicalBody({
    model: "claude-compatible",
    max_tokens: 128,
    messages: [{ role: "user", content: [{ type: "text", text: "hello" }] }],
  });

  assert.equal(body.max_tokens, 128);
  assert.deepEqual(body.messages, [{ role: "user", content: "hello" }]);
  assert.equal(body.stream, false);
  assert.equal(Object.hasOwn(body, "maxTokens"), false);
});

test("Anthropic messages canonical body rejects retired maxTokens alias", () => {
  assert.throws(
    () =>
      anthropicMessagesToCanonicalBody({
        model: "claude-compatible",
        maxTokens: 128,
        messages: [{ role: "user", content: "hello" }],
      }),
    (error) => {
      assert.equal(error.status, 400);
      assert.equal(error.code, "model_mount_anthropic_messages_request_aliases_retired");
      assert.deepEqual(error.details.retired_aliases, ["maxTokens"]);
      assert.deepEqual(error.details.canonical_fields, ["max_tokens"]);
      assert.equal(Object.hasOwn(error.details, "maxTokens"), false);
      return true;
    },
  );
});

test("OpenAI provider stream shape is bound to the stream receipt without operation append", async () => {
  const request = new EventEmitter();
  const response = new FakeResponse();
  const appended = [];
  const completed = [];
  const frames = [
    'data: {"choices":[{"delta":{"role":"assistant"},"finish_reason":null}]}\n\n',
    'data: {"choices":[{"delta":{"content":"hello"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}\n\n',
    "data: [DONE]\n\n",
  ];
  const streamInvocation = {
    ...invocationFixture(),
    providerStream: providerStreamFromFrames(frames),
  };
  const mounts = {
    appendOperation(kind, payload) {
      appended.push({ kind, payload });
    },
    recordModelStreamCompleted(requested) {
      completed.push(requested);
      return {
        id: "receipt.stream",
        details: {
          token_count: { prompt_tokens: 7, completion_tokens: 11, total_tokens: 18 },
          provider_stream_shape_summary: requested.providerStreamShapeSummary,
        },
      };
    },
  };

  await writeOpenAiProviderChatCompletionStream(request, response, streamInvocation, mounts);

  assert.deepEqual(appended, []);
  assert.equal(completed.length, 1);
  assert.equal(completed[0].providerStreamShapeSummary.schemaVersion, "ioi.model.provider_stream_shape.v1");
  assert.equal(completed[0].providerStreamShapeSummary.framesForwarded, 2);
  assert.equal(completed[0].providerStreamShapeSummary.finishReason, "stop");
  assert.equal(completed[0].providerStreamShapeSummary.jsonPayloads, 2);
  assert.equal(completed[0].providerStreamShapeSummary.delta.contentChunks, 1);
  assert.equal("_deltaToolArgumentBuffers" in completed[0].providerStreamShapeSummary, false);
  assert.equal(response.headers["x-ioi-stream-source"], "provider_native");
  const finalFrame = response.frames.find((frame) => frame.includes('"stream_receipt_id":"receipt.stream"'));
  assert.ok(finalFrame);
  const finalPayload = JSON.parse(finalFrame.replace(/^data: /, "").trim());
  assert.deepEqual(finalPayload.usage, { prompt_tokens: 7, completion_tokens: 11, total_tokens: 18 });
  assert.equal(Object.hasOwn(finalPayload.usage, "tokenCount"), false);
});

test("stream cancellation is delegated to Rust model_mount stream lifecycle admission", () => {
  const { invocation } = invocationFixture();
  const delegated = [];
  const receiptCalls = [];
  const mounts = {
    receipt(kind, payload) {
      receiptCalls.push({ kind, payload });
      throw new Error("Legacy JS stream cancellation receipt authoring must stay retired");
    },
    recordModelStreamCanceled(payload) {
      delegated.push(payload);
      return {
        id: "receipt.stream-cancel",
        kind: "model_invocation_stream_canceled",
        details: {
          rust_daemon_core_receipt_author: "ModelMountCore.plan_model_mount_stream_cancel",
          stream_status: "canceled",
          frames_written: payload.framesWritten,
          cancel_reason: payload.cancelReason,
        },
      };
    },
  };

  const receipt = recordModelStreamCanceled({
    mounts,
    invocation,
    streamKind: "chat.completions",
    framesWritten: 2,
  });

  assert.equal(receipt.kind, "model_invocation_stream_canceled");
  assert.equal(receipt.details.rust_daemon_core_receipt_author, "ModelMountCore.plan_model_mount_stream_cancel");
  assert.equal(delegated.length, 1);
  assert.equal(delegated[0].invocation, invocation);
  assert.equal(delegated[0].streamKind, "chat.completions");
  assert.equal(delegated[0].framesWritten, 2);
  assert.equal(delegated[0].cancelReason, "client_disconnect");
  assert.deepEqual(delegated[0].providerResult, {
    provider_response_kind: "openai.chat.stream",
    backend_evidence_refs: ["backend.native"],
  });
  assert.equal(Object.hasOwn(delegated[0].providerResult, "providerResponseKind"), false);
  assert.deepEqual(receiptCalls, []);
});
