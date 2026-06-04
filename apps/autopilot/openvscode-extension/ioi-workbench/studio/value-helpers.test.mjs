import assert from "node:assert/strict";
import { test } from "node:test";

import valueHelpers from "./value-helpers.js";

const { firstArray, stringValue } = valueHelpers;

test("Studio value helpers preserve extension string fallback semantics", () => {
  assert.equal(stringValue(" value "), "value");
  assert.equal(stringValue("   ", "fallback"), "fallback");
  assert.equal(stringValue(null, "fallback"), "fallback");
  assert.equal(stringValue(42, "fallback"), "fallback");
});

test("Studio value helpers preserve extension first-array semantics", () => {
  const items = [{ id: 1 }];
  assert.equal(firstArray(items), items);
  assert.deepEqual(firstArray(null), []);
  assert.deepEqual(firstArray({ 0: "not-array" }), []);
});
