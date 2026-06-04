import assert from "node:assert/strict";
import test from "node:test";

import {
  appendOperatorControl,
  booleanValue,
  doctorCheck,
  doctorHash,
  normalizeArray,
  normalizeBooleanOption,
  objectRecord,
  operatorControlSource,
  optionalString,
  relativePathForWorkspace,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

test("runtime value helpers preserve array and string normalization", () => {
  assert.deepEqual(normalizeArray(["a", "", null, "b"]), ["a", "b"]);
  assert.deepEqual(uniqueStrings(["a", "a", 7, null, ""]), ["a", "7"]);
  assert.equal(optionalString("  value  "), "value");
  assert.equal(optionalString("   "), undefined);
  assert.deepEqual(objectRecord({ ok: true }), { ok: true });
  assert.equal(objectRecord(["nope"]), null);
});

test("runtime value helpers preserve safe ids, hashes, and workspace-relative paths", () => {
  assert.equal(safeId("a/b c"), "a_b_c");
  assert.equal(doctorHash("stable").length, 64);
  assert.equal(relativePathForWorkspace("/tmp/work/src/index.js", "/tmp/work"), "src/index.js");
  assert.equal(relativePathForWorkspace("/tmp/elsewhere/index.js", "/tmp/work"), null);
});

test("runtime value helpers preserve doctor and operator-control envelopes", () => {
  assert.deepEqual(doctorCheck("model", "ok", true, "ready", ["a", null, "b"]), {
    id: "model",
    status: "ok",
    required: true,
    summary: "ready",
    evidenceRefs: ["a", "b"],
  });
  assert.equal(booleanValue(true), true);
  assert.equal(booleanValue("false"), false);
  assert.equal(booleanValue("maybe"), null);
  assert.equal(normalizeBooleanOption("1", false), true);
  assert.equal(normalizeBooleanOption("0", true), false);
  assert.equal(normalizeBooleanOption("maybe", true), true);
  assert.equal(operatorControlSource("runtime_auto"), "runtime_auto");
  assert.equal(operatorControlSource("unknown"), "sdk_client");
  assert.deepEqual(
    appendOperatorControl([{ eventId: "event_1" }], { eventId: "event_1" }),
    [{ eventId: "event_1" }],
  );
  assert.deepEqual(
    appendOperatorControl([{ eventId: "event_1" }], { eventId: "event_2" }),
    [{ eventId: "event_1" }, { eventId: "event_2" }],
  );
});
