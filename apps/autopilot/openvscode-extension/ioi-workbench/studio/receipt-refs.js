"use strict";

function createStudioReceiptRefs({
  firstArray,
  uniqueStrings,
}) {
  function normalizeReceiptRefs(...sources) {
    const refs = [];
    for (const source of sources) {
      if (!source) continue;
      if (typeof source === "string") {
        refs.push(source);
        continue;
      }
      refs.push(
        ...firstArray(source.receipt_refs),
        ...firstArray(source.receiptRefs),
        ...firstArray(source.receiptIds),
        ...firstArray(source.receipts).map((receipt) => receipt?.id || receipt?.receipt_id || receipt?.receiptId),
        ...firstArray(source.event?.receipt_refs),
        ...firstArray(source.event?.receiptRefs),
        ...firstArray(source.result?.receipt_refs),
        ...firstArray(source.result?.receiptRefs),
        ...firstArray(source.payload_summary?.receipt_refs),
        ...firstArray(source.payload_summary?.receiptRefs),
      );
    }
    return uniqueStrings(refs);
  }

  return {
    normalizeReceiptRefs,
  };
}

module.exports = {
  createStudioReceiptRefs,
};
