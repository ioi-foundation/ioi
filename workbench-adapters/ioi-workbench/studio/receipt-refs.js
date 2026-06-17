"use strict";

function createStudioReceiptRefs({
  firstArray,
  getStudioRuntimeProjection = () => ({ receipts: [] }),
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

  function studioReceiptProjection(receiptLike, fallbackKind = "daemon_receipt") {
    const id =
      receiptLike?.id ||
      receiptLike?.receipt_id ||
      receiptLike?.receiptId ||
      (typeof receiptLike === "string" ? receiptLike : null);
    if (!id) {
      return null;
    }
    return {
      id,
      kind: receiptLike?.kind || receiptLike?.type || fallbackKind,
      summary:
        receiptLike?.summary ||
        receiptLike?.description ||
        receiptLike?.message ||
        "Daemon receipt projected into Agent Studio.",
    };
  }

  function appendStudioReceipts(values, fallbackKind = "daemon_receipt") {
    const projection = getStudioRuntimeProjection();
    projection.receipts = firstArray(projection.receipts);
    const projected = firstArray(values)
      .map((value) => studioReceiptProjection(value, fallbackKind))
      .filter(Boolean);
    const existing = new Set(projection.receipts.map((receipt) => receipt.id));
    for (const receipt of projected) {
      if (!existing.has(receipt.id)) {
        projection.receipts.push(receipt);
        existing.add(receipt.id);
      }
    }
  }

  return {
    appendStudioReceipts,
    normalizeReceiptRefs,
    studioReceiptProjection,
  };
}

module.exports = {
  createStudioReceiptRefs,
};
