function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values) {
  return [...new Set(firstArray(values).map((value) => String(value)).filter(Boolean))];
}

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

function formatStudioWorkDuration(durationMs) {
  const seconds = Math.max(0, Math.round(Number(durationMs || 0) / 1000));
  if (seconds <= 0) {
    return "<1s";
  }
  if (seconds < 60) {
    return `${seconds}s`;
  }
  const minutes = Math.floor(seconds / 60);
  const remaining = seconds % 60;
  return remaining ? `${minutes}m ${remaining}s` : `${minutes}m`;
}

function studioCanonicalRuntimeNames(items = [], fields = ["toolId", "label"]) {
  const rawNames = uniqueStrings(firstArray(items).flatMap((item) =>
    fields.map((field) => item?.[field]).filter(Boolean)
  ))
    .map((name) => String(name || "").trim())
    .filter((name) => /[a-z0-9]/i.test(name))
    .filter((name) => !/^(agent\.runtime\.event|runtime\.tool)$/i.test(name));
  return rawNames.filter((name) => !rawNames.some((other) =>
    other !== name && other.toLowerCase().startsWith(name.toLowerCase()) && name.length < other.length
  ));
}

function studioDocumentedWorkRecord(projection = {}, cursor = {}) {
  const actionCards = firstArray(projection.actionCards).slice(cursor.actionCards || 0);
  const policyLeases = firstArray(projection.policyLeases).slice(cursor.policyLeases || 0);
  const commandOutputs = firstArray(projection.commandOutputs).slice(cursor.commandOutputs || 0);
  const diagnosticGates = firstArray(projection.diagnosticGates).slice(cursor.diagnosticGates || 0);
  const diffHunks = firstArray(projection.diffHunks).slice(cursor.diffHunks || 0);
  const browserCards = firstArray(projection.browserCards).slice(cursor.browserCards || 0);
  const workerCards = firstArray(projection.workerCards).slice(cursor.workerCards || 0);
  const computerUseSessions = firstArray(projection.computerUseSessions).slice(cursor.computerUseSessions || 0);
  const receipts = firstArray(projection.receipts).slice(cursor.receipts || 0);
  const lines = [];
  const summaryParts = [];
  const actionToolNames = studioCanonicalRuntimeNames(actionCards).filter((name) => name.toLowerCase() !== "chat__reply");
  const commandToolNames = studioCanonicalRuntimeNames(commandOutputs);
  const retainedShellLifecycle = ["shell__start", "shell__status", "shell__input", "shell__terminate", "shell__reset"]
    .every((toolName) => commandToolNames.includes(toolName));
  if (actionToolNames.length) {
    lines.push(`Used ${actionToolNames.length} daemon tool${actionToolNames.length === 1 ? "" : "s"}`);
    summaryParts.push(`used ${actionToolNames.length} tool${actionToolNames.length === 1 ? "" : "s"}`);
  }
  if (commandOutputs.length) {
    if (retainedShellLifecycle) {
      lines.push("Controlled 1 retained shell session");
      summaryParts.push("controlled 1 shell session");
    } else {
      const commandCount = commandToolNames.length || commandOutputs.length;
      lines.push(`Ran ${commandCount} sandboxed command${commandCount === 1 ? "" : "s"}`);
      summaryParts.push(`ran ${commandCount} command${commandCount === 1 ? "" : "s"}`);
    }
  }
  if (diagnosticGates.length) {
    lines.push(`Checked ${diagnosticGates.length} diagnostic/test gate${diagnosticGates.length === 1 ? "" : "s"}`);
    summaryParts.push(`checked ${diagnosticGates.length} gate${diagnosticGates.length === 1 ? "" : "s"}`);
  }
  if (diffHunks.length) {
    lines.push(`Prepared ${diffHunks.length} patch hunk${diffHunks.length === 1 ? "" : "s"} for review`);
    summaryParts.push(`prepared ${diffHunks.length} patch${diffHunks.length === 1 ? "" : "es"}`);
  }
  if (policyLeases.length) {
    lines.push(`Evaluated ${policyLeases.length} policy lease${policyLeases.length === 1 ? "" : "s"}`);
    summaryParts.push(`checked ${policyLeases.length} policy gate${policyLeases.length === 1 ? "" : "s"}`);
  }
  if (browserCards.length) {
    lines.push(`Observed ${browserCards.length} browser status item${browserCards.length === 1 ? "" : "s"}`);
    summaryParts.push(`observed ${browserCards.length} browser state${browserCards.length === 1 ? "" : "s"}`);
  }
  if (computerUseSessions.length) {
    lines.push(`Managed ${computerUseSessions.length} browser/computer live session${computerUseSessions.length === 1 ? "" : "s"}`);
    summaryParts.push(`managed ${computerUseSessions.length} live session${computerUseSessions.length === 1 ? "" : "s"}`);
  }
  if (workerCards.length) {
    lines.push(`Observed ${workerCards.length} worker/subagent item${workerCards.length === 1 ? "" : "s"}`);
    summaryParts.push(`observed ${workerCards.length} worker${workerCards.length === 1 ? "" : "s"}`);
  }
  const receiptRefs = normalizeReceiptRefs(
    ...actionCards,
    ...policyLeases,
    ...commandOutputs,
    ...diagnosticGates,
    ...diffHunks,
    ...browserCards,
    ...computerUseSessions,
    ...workerCards,
    ...receipts,
  );
  if (!lines.length) {
    return null;
  }
  return {
    status: "completed",
    durationMs: Math.max(0, Date.now() - Number(cursor.startedAtMs || Date.now())),
    lines,
    summaryParts,
    receiptRefs,
    stepCount: lines.length,
    sessionCards: computerUseSessions.slice(-3),
  };
}

function studioTurnHasDocumentedWork(turn = {}) {
  const record = turn.workRecord || null;
  return Boolean(record && firstArray(record.lines).length);
}

function studioDocumentedWorkSummary(record = {}, fallbackStatus = "completed") {
  const parts = firstArray(record.summaryParts).filter(Boolean);
  if (parts.length) {
    return parts.slice(0, 4).join(" · ");
  }
  return String(record.status || fallbackStatus || "completed");
}

module.exports = {
  formatStudioWorkDuration,
  studioDocumentedWorkRecord,
  studioDocumentedWorkSummary,
  studioTurnHasDocumentedWork,
};
