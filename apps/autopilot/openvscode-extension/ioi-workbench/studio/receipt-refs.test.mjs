import assert from "node:assert/strict";
import { createRequire } from "node:module";
import test from "node:test";

const require = createRequire(import.meta.url);
const { createStudioReceiptRefs } = require("./receipt-refs.js");

function createRefs() {
  const projection = { receipts: [] };
  return createStudioReceiptRefs({
    firstArray: (value) => Array.isArray(value) ? value : [],
    getStudioRuntimeProjection: () => projection,
    uniqueStrings: (values) => [...new Set(values.map((value) => String(value)).filter(Boolean))],
  });
}

test("receipt refs normalize all public alias fields and nested payloads", () => {
  const { normalizeReceiptRefs } = createRefs();
  const refs = normalizeReceiptRefs(
    "receipt.direct",
    {
      receipt_refs: ["receipt.snake"],
      receiptRefs: ["receipt.camel"],
      receiptIds: ["receipt.id"],
      receipts: [
        { id: "receipt.object.id" },
        { receipt_id: "receipt.object.snake" },
        { receiptId: "receipt.object.camel" },
      ],
      event: { receipt_refs: ["receipt.event.snake"], receiptRefs: ["receipt.event.camel"] },
      result: { receipt_refs: ["receipt.result.snake"], receiptRefs: ["receipt.result.camel"] },
      payload_summary: { receipt_refs: ["receipt.payload.snake"], receiptRefs: ["receipt.payload.camel"] },
    },
  );

  assert.deepEqual(refs, [
    "receipt.direct",
    "receipt.snake",
    "receipt.camel",
    "receipt.id",
    "receipt.object.id",
    "receipt.object.snake",
    "receipt.object.camel",
    "receipt.event.snake",
    "receipt.event.camel",
    "receipt.result.snake",
    "receipt.result.camel",
    "receipt.payload.snake",
    "receipt.payload.camel",
  ]);
});

test("receipt refs de-duplicate and ignore missing records", () => {
  const { normalizeReceiptRefs } = createRefs();
  assert.deepEqual(
    normalizeReceiptRefs(null, undefined, { receiptRefs: ["r1", "r1", ""] }, "r2", "r1"),
    ["r1", "r2"],
  );
});

test("receipt projection shapes receipt timeline rows with fallback copy", () => {
  const { studioReceiptProjection } = createRefs();

  assert.deepEqual(studioReceiptProjection({
    receipt_id: "receipt-1",
    type: "tool.file",
    description: "File read receipt.",
  }), {
    id: "receipt-1",
    kind: "tool.file",
    summary: "File read receipt.",
  });
  assert.deepEqual(studioReceiptProjection("receipt-2", "runtime_event"), {
    id: "receipt-2",
    kind: "runtime_event",
    summary: "Daemon receipt projected into Agent Studio.",
  });
  assert.equal(studioReceiptProjection({}), null);
});

test("receipt append updates projection receipts without duplicates", () => {
  const projection = { receipts: [{ id: "receipt-1", kind: "existing", summary: "Existing." }] };
  const { appendStudioReceipts } = createStudioReceiptRefs({
    firstArray: (value) => Array.isArray(value) ? value : [],
    getStudioRuntimeProjection: () => projection,
    uniqueStrings: (values) => [...new Set(values.map((value) => String(value)).filter(Boolean))],
  });

  appendStudioReceipts([
    { id: "receipt-1", kind: "duplicate" },
    { receiptId: "receipt-2", message: "Second receipt." },
    {},
  ], "daemon_tool");

  assert.deepEqual(projection.receipts, [
    { id: "receipt-1", kind: "existing", summary: "Existing." },
    { id: "receipt-2", kind: "daemon_tool", summary: "Second receipt." },
  ]);
});
