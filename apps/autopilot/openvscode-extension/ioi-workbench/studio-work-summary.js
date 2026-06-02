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

function humanToolName(value = "") {
  return String(value || "")
    .replace(/^browser__/, "browser ")
    .replace(/^file__/, "file ")
    .replace(/^shell__/, "shell ")
    .replace(/^agent__/, "agent ")
    .replace(/__+/g, " ")
    .replace(/[_./-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .toLowerCase();
}

function artifactLabel(artifact = {}) {
  const classId = String(artifact.artifactClass || artifact.artifact_class || "");
  const title = String(artifact.title || "artifact");
  if (classId === "static_html_js" && /\b(website|site|webpage|landing page)\b/i.test(title)) {
    return `Created website artifact: ${title}`;
  }
  if (classId === "react_vite_app") return `Created app preview artifact: ${title}`;
  if (classId === "imported_document") return `Prepared document artifact: ${title}`;
  if (classId === "diff_patch") return `Prepared patch artifact: ${title}`;
  if (classId === "dataset_chart") return `Prepared dataset artifact: ${title}`;
  if (classId === "browser_observation") return `Captured browser session artifact: ${title}`;
  return `Created artifact: ${title}`;
}

function normalizeSourceChips(value) {
  return firstArray(value)
    .map((source) => {
      if (!source || typeof source !== "object" || Array.isArray(source)) return null;
      const url = String(source.url || source.href || source.link || "").trim();
      const domain = String(source.domain || source.hostname || "").replace(/^www\./i, "").trim();
      const title = String(source.title || source.name || source.label || domain || url).replace(/\s+/g, " ").trim();
      const excerpt = String(source.excerpt || source.snippet || source.summary || "").replace(/\s+/g, " ").trim();
      if (!url && !title && !domain) return null;
      return {
        title: title.slice(0, 110),
        domain: domain.slice(0, 80),
        url,
        excerpt: excerpt.slice(0, 220),
        state: String(source.state || source.status || source.sourceHealth || "used").trim() || "used",
      };
    })
    .filter(Boolean)
    .slice(0, 8);
}

function workRowsFromPendingWorklog(pendingWorklog = []) {
  return firstArray(pendingWorklog)
    .map((step) => {
      const label = String(step?.label || step?.title || "").replace(/\s+/g, " ").trim();
      if (!label) return null;
      const detail = String(step?.detail || step?.summary || "").replace(/\s+/g, " ").trim();
      const sourceChips = normalizeSourceChips(step?.sourceChips || step?.source_chips || step?.sources);
      const excerptPreview = String(step?.excerptPreview || step?.excerpt_preview || sourceChips[0]?.excerpt || "")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, 280);
      return {
        id: String(step?.id || step?.stepId || step?.toolName || label).trim(),
        kind: String(step?.publicKind || step?.kind || step?.toolName || "tool").trim(),
        status: String(step?.status || "completed").trim(),
        headline: label,
        summary: detail,
        sourceChips,
        excerptPreview,
      };
    })
    .filter(Boolean);
}

function synthesizeManagedSessionCards({ computerUseSessions = [], browserCards = [], workRows = [], actionToolNames = [], cursor = {} } = {}) {
  if (firstArray(computerUseSessions).length) {
    return firstArray(computerUseSessions);
  }
  const browserRows = firstArray(workRows).filter((row) =>
    /\bbrowser\b|^browser__/.test(String(`${row?.kind || ""} ${row?.headline || ""} ${row?.summary || ""}`).toLowerCase())
  );
  const browserToolName = firstArray(actionToolNames).find((name) => /^browser__/.test(String(name || "")));
  if (!browserRows.length && !firstArray(browserCards).length && !browserToolName) {
    return [];
  }
  const primaryRow = browserRows[browserRows.length - 1] || {};
  const primaryCard = firstArray(browserCards)[firstArray(browserCards).length - 1] || {};
  const detail = String(
    primaryRow.excerptPreview ||
      primaryRow.summary ||
      primaryCard.excerptPreview ||
      primaryCard.summary ||
      primaryCard.detail ||
      "Managed sandbox browser session.",
  )
    .replace(/\s+/g, " ")
    .trim();
  return [
    {
      id: `sandbox-browser:${String(primaryRow.id || primaryCard.id || browserToolName || cursor.startedAtMs || Date.now()).slice(0, 96)}`,
      kind: "sandbox_browser",
      surfaceLabel: "Sandbox browser",
      status: "complete",
      statusLabel: "Complete",
      title: "Browser session",
      detail: detail.slice(0, 220) || "Managed sandbox browser session.",
      lastTool: browserToolName || primaryRow.kind || primaryCard.toolId || "browser",
      actionCount: Math.max(1, browserRows.length || firstArray(browserCards).length || 1),
      waitingForUser: false,
      updatedAt: new Date().toISOString(),
    },
  ];
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
  const conversationArtifacts = firstArray(projection.conversationArtifacts).slice(cursor.conversationArtifacts || 0);
  const pendingWorklog = firstArray(projection.pendingWorklog).slice(cursor.pendingWorklog || 0);
  const receipts = firstArray(projection.receipts).slice(cursor.receipts || 0);
  const lines = [];
  const summaryParts = [];
  const activityLines = [];
  const actionToolNames = studioCanonicalRuntimeNames(actionCards).filter((name) => name.toLowerCase() !== "chat__reply");
  const commandToolNames = studioCanonicalRuntimeNames(commandOutputs);
  const pendingLabels = uniqueStrings(pendingWorklog.map((step) => step?.label || step?.title || ""));
  const pendingRenderCount = pendingLabels.filter((label) => /\b(preview|render|artifact)\b/i.test(label)).length;
  const workRows = workRowsFromPendingWorklog(pendingWorklog);
  const managedSessionCards = synthesizeManagedSessionCards({
    computerUseSessions,
    browserCards,
    workRows,
    actionToolNames,
    cursor,
  });
  const retainedShellLifecycle = ["shell__start", "shell__status", "shell__input", "shell__terminate", "shell__reset"]
    .every((toolName) => commandToolNames.includes(toolName));
  if (actionToolNames.length) {
    lines.push(`Used ${actionToolNames.length} daemon tool${actionToolNames.length === 1 ? "" : "s"}`);
    summaryParts.push(`used ${actionToolNames.length} tool${actionToolNames.length === 1 ? "" : "s"}`);
    for (const name of actionToolNames.slice(0, 6)) {
      activityLines.push(`Used ${humanToolName(name)}.`);
    }
  }
  if (commandOutputs.length) {
    if (retainedShellLifecycle) {
      lines.push("Controlled 1 retained shell session");
      summaryParts.push("controlled 1 shell session");
      activityLines.push("Controlled a retained shell session.");
    } else {
      const commandCount = commandToolNames.length || commandOutputs.length;
      lines.push(`Ran ${commandCount} sandboxed command${commandCount === 1 ? "" : "s"}`);
      summaryParts.push(`ran ${commandCount} command${commandCount === 1 ? "" : "s"}`);
      for (const command of commandOutputs.slice(0, 4)) {
        activityLines.push(`Ran ${command.label || command.toolId || "sandboxed command"}.`);
      }
    }
  }
  if (diagnosticGates.length) {
    lines.push(`Checked ${diagnosticGates.length} diagnostic/test gate${diagnosticGates.length === 1 ? "" : "s"}`);
    summaryParts.push(`checked ${diagnosticGates.length} gate${diagnosticGates.length === 1 ? "" : "s"}`);
    activityLines.push(`Checked ${diagnosticGates.length} diagnostic/test gate${diagnosticGates.length === 1 ? "" : "s"}.`);
  }
  if (diffHunks.length) {
    lines.push(`Prepared ${diffHunks.length} patch hunk${diffHunks.length === 1 ? "" : "s"} for review`);
    summaryParts.push(`prepared ${diffHunks.length} patch${diffHunks.length === 1 ? "" : "es"}`);
    activityLines.push(`Prepared ${diffHunks.length} reviewable patch hunk${diffHunks.length === 1 ? "" : "s"}.`);
  }
  if (policyLeases.length) {
    lines.push(`Evaluated ${policyLeases.length} policy lease${policyLeases.length === 1 ? "" : "s"}`);
    summaryParts.push(`checked ${policyLeases.length} policy gate${policyLeases.length === 1 ? "" : "s"}`);
    activityLines.push(`Checked ${policyLeases.length} policy gate${policyLeases.length === 1 ? "" : "s"}.`);
  }
  if (browserCards.length) {
    lines.push(`Observed ${browserCards.length} browser status item${browserCards.length === 1 ? "" : "s"}`);
    summaryParts.push(`observed ${browserCards.length} browser state${browserCards.length === 1 ? "" : "s"}`);
    activityLines.push(`Observed ${browserCards.length} browser state update${browserCards.length === 1 ? "" : "s"}.`);
  }
  if (managedSessionCards.length) {
    lines.push(`Managed ${managedSessionCards.length} browser/computer live session${managedSessionCards.length === 1 ? "" : "s"}`);
    summaryParts.push(`managed ${managedSessionCards.length} live session${managedSessionCards.length === 1 ? "" : "s"}`);
    activityLines.push(`Managed ${managedSessionCards.length} live browser/computer session${managedSessionCards.length === 1 ? "" : "s"}.`);
  }
  if (conversationArtifacts.length) {
    lines.push(`Created ${conversationArtifacts.length} conversation artifact${conversationArtifacts.length === 1 ? "" : "s"}`);
    summaryParts.push(`created ${conversationArtifacts.length} artifact${conversationArtifacts.length === 1 ? "" : "s"}`);
    for (const artifact of conversationArtifacts.slice(0, 4)) {
      activityLines.push(artifactLabel(artifact));
    }
  }
  if (pendingRenderCount && !conversationArtifacts.length) {
    lines.push("Rendered artifact preview");
    summaryParts.push("rendered preview");
    activityLines.push("Rendered an artifact preview.");
  }
  if (workerCards.length) {
    lines.push(`Observed ${workerCards.length} worker/subagent item${workerCards.length === 1 ? "" : "s"}`);
    summaryParts.push(`observed ${workerCards.length} worker${workerCards.length === 1 ? "" : "s"}`);
    activityLines.push(`Observed ${workerCards.length} worker/subagent update${workerCards.length === 1 ? "" : "s"}.`);
  }
  const receiptRefs = normalizeReceiptRefs(
    ...actionCards,
    ...policyLeases,
    ...commandOutputs,
    ...diagnosticGates,
    ...diffHunks,
    ...browserCards,
    ...computerUseSessions,
    ...conversationArtifacts,
    ...workerCards,
    ...pendingWorklog,
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
    activityLines,
    workRows,
    receiptRefs,
    stepCount: lines.length,
    sessionCards: managedSessionCards.slice(-3),
    artifactCards: conversationArtifacts.slice(-6),
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
