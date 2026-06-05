import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import {
  nativeInvocationResponse,
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
          token_count: requested.providerUsage,
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
  assert.equal(response.frames.some((frame) => frame.includes('"stream_receipt_id":"receipt.stream"')), true);
});

test("stream cancellation receipts use canonical detail metadata", () => {
  const { invocation } = invocationFixture();
  const receipts = [];
  const mounts = {
    receipt(kind, payload) {
      receipts.push({ kind, payload });
      return { id: "receipt.cancel", kind, ...payload };
    },
  };

  recordModelStreamCanceled({
    mounts,
    invocation,
    streamKind: "chat.completions",
    framesWritten: 2,
  });

  assert.equal(receipts.length, 1);
  assert.equal(receipts[0].kind, "model_invocation_stream_canceled");
  assert.equal(receipts[0].payload.details.stream_kind, "chat.completions");
  assert.equal(receipts[0].payload.details.invocation_receipt_id, "receipt.invocation");
  assert.equal(receipts[0].payload.details.route_id, "route.native");
  assert.equal(receipts[0].payload.details.selected_model, "model.native");
  assert.equal(receipts[0].payload.details.backend_id, "backend.native");
  assert.equal(receipts[0].payload.details.selected_backend, "backend.native");
  assert.equal(receipts[0].payload.details.stream_source, "provider_native");
  assert.equal(receipts[0].payload.details.provider_response_kind, "openai.chat.stream");
  assert.deepEqual(receipts[0].payload.details.backend_evidence_refs, ["backend.native"]);
  assert.deepEqual(receipts[0].payload.details.tool_receipt_ids, []);
  assert.equal(receipts[0].payload.details.frames_written, 2);
  assert.equal(Object.hasOwn(receipts[0].payload.details, "streamKind"), false);
  assert.equal(Object.hasOwn(receipts[0].payload.details, "invocationReceiptId"), false);
  assert.equal(Object.hasOwn(receipts[0].payload.details, "routeId"), false);
  assert.equal(Object.hasOwn(receipts[0].payload.details, "selectedModel"), false);
  assert.equal(Object.hasOwn(receipts[0].payload.details, "backendId"), false);
  assert.equal(Object.hasOwn(receipts[0].payload.details, "selectedBackend"), false);
  assert.equal(Object.hasOwn(receipts[0].payload.details, "streamSource"), false);
  assert.equal(Object.hasOwn(receipts[0].payload.details, "providerResponseKind"), false);
  assert.equal(Object.hasOwn(receipts[0].payload.details, "backendEvidenceRefs"), false);
  assert.equal(Object.hasOwn(receipts[0].payload.details, "toolReceiptIds"), false);
  assert.equal(Object.hasOwn(receipts[0].payload.details, "framesWritten"), false);
});

test("native invocation response reads canonical route decision details", () => {
  const { invocation } = invocationFixture();
  const response = nativeInvocationResponse({
    ...invocation,
    routeReceipt: {
      id: "receipt.route",
      details: {
        model_route_decision: { route_id: "route.native", selected_model: "model.native" },
      },
    },
  });

  assert.deepEqual(response.route_decision, { route_id: "route.native", selected_model: "model.native" });
  assert.equal(Object.hasOwn(response.route_decision, "routeId"), false);
  assert.equal(Object.hasOwn(response.route_decision, "selectedModel"), false);

  const legacyOnly = nativeInvocationResponse({
    ...invocation,
    routeReceipt: {
      id: "receipt.route.legacy",
      details: {
        modelRouteDecision: { routeId: "route.legacy" },
      },
    },
  });
  assert.equal(legacyOnly.route_decision, null);
});
