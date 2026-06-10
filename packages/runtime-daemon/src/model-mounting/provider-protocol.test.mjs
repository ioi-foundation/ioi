import test from "node:test";
import assert from "node:assert/strict";

import {
  estimateTokens,
} from "./provider-protocol.mjs";

test("estimateTokens preserves provider-result fallback token counts", () => {
  assert.deepEqual(estimateTokens("abcdefgh", "abcd"), {
    prompt_tokens: 2,
    completion_tokens: 1,
    total_tokens: 3,
  });
});
