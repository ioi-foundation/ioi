import assert from "node:assert/strict";
import test from "node:test";

import {
  extractedUserQuery,
  jsonLineReadableStream,
  nativeLocalOutput,
  nativeLocalStreamRecords,
  providerStreamFrameDelayMs,
} from "./native-local-fixture.mjs";

test("native local fixture extracts latest user request shapes", () => {
  assert.equal(
    extractedUserQuery("System preface\n\nLatest user request:\nExplain daemon routing\nFinal answer text:"),
    "Explain daemon routing",
  );
  assert.equal(
    extractedUserQuery("user: first\nassistant: ok\nuser: inspect the repo"),
    "inspect the repo",
  );
});

test("native local fixture produces deterministic embedding output", () => {
  const first = nativeLocalOutput({ kind: "embeddings", input: "hello", modelId: "native:test" });
  const second = nativeLocalOutput({ kind: "embeddings", input: "hello", modelId: "native:test" });

  assert.equal(first, second);
  assert.match(first, /^native-local-embedding:native:test:/);
});

test("native local fixture classifies conversational execution mode", () => {
  const output = nativeLocalOutput({
    kind: "responses",
    modelId: "native:test",
    input: "Classify the immediate next execution mode\nLatest user request:\nhello humans",
  });

  assert.deepEqual(JSON.parse(output), { mode: "Chat" });
});

test("native local stream records split text and preserve token counts", () => {
  const records = nativeLocalStreamRecords("a".repeat(130), {
    prompt_tokens: 3,
    completion_tokens: 5,
  });

  assert.equal(records.length, 4);
  assert.equal(records[0].delta.length, 64);
  assert.equal(records[1].delta.length, 64);
  assert.equal(records[2].delta.length, 2);
  assert.deepEqual(records[3], {
    delta: "",
    done: true,
    done_reason: "stop",
    prompt_eval_count: 3,
    eval_count: 5,
  });
});

test("native local JSONL stream emits records and supports explicit abort hook", async () => {
  const emitted = [];
  const handle = jsonLineReadableStream([{ one: 1 }, { two: 2 }]);
  const reader = handle.stream.getReader();
  const decoder = new TextDecoder();
  for (;;) {
    const chunk = await reader.read();
    if (chunk.done) break;
    emitted.push(decoder.decode(chunk.value));
  }
  assert.equal(emitted.join(""), "{\"one\":1}\n{\"two\":2}\n");

  let abortReason = null;
  const aborting = jsonLineReadableStream([{ slow: true }], {
    delayMs: 10,
    onAbort: (reason) => {
      abortReason = reason;
    },
  });
  aborting.abort("test_abort");
  assert.equal(abortReason, "test_abort");
});

test("native local stream delay honors bounded environment override", () => {
  const previous = process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS;
  process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS = "5000";
  try {
    assert.equal(providerStreamFrameDelayMs(), 1000);
  } finally {
    if (previous === undefined) {
      delete process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS;
    } else {
      process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS = previous;
    }
  }
});
