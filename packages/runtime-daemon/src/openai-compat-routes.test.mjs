import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";

import { writeOpenAiProviderChatCompletionStream } from "./openai-compat-routes.mjs";

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
          backendId: "backend.native",
          selectedBackend: "backend.native",
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
          tokenCount: requested.providerUsage,
          providerStreamShapeSummary: requested.providerStreamShapeSummary,
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
