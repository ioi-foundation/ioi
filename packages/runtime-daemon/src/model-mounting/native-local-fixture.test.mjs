import assert from "node:assert/strict";
import test from "node:test";

import { extractedUserQuery, nativeLocalOutput } from "./native-local-fixture.mjs";

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
