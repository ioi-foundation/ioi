function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function uniqueStrings(values) {
  return [...new Set(firstArray(values).map((value) => String(value)).filter(Boolean))];
}

function publicToolText(value = "") {
  return String(value || "")
    .replace(/\s+/g, " ")
    .replace(/\bshell__start:[a-f0-9]{12,}\b/gi, "<command>")
    .replace(/\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\b/gi, "<ref>")
    .replace(/ioi-session-stdin-[^\s"']+/gi, "<stdin-bridge>")
    .replace(/\/tmp\/[^\s"']+/gi, "<tmp>")
    .replace(/"command_id"\s*:\s*"[^"]+"/gi, "")
    .trim();
}

function publicOutputBlock(value = "", max = 6000) {
  return String(value || "")
    .replace(/\bshell__start:[a-f0-9]{12,}\b/gi, "<command>")
    .replace(/\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\b/gi, "<ref>")
    .replace(/ioi-session-stdin-[^\s"']+/gi, "<stdin-bridge>")
    .replace(/\/tmp\/[^\s"']+/gi, "<tmp>")
    .replace(/"command_id"\s*:\s*"[^"]+"/gi, "")
    .slice(0, max)
    .trim();
}

function publicRefText(value = "") {
  return String(value || "")
    .replace(/\bshell__start:[a-f0-9]{12,}\b/gi, "<command>")
    .replace(/\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\b/gi, "<ref>")
    .replace(/ioi-session-stdin-[^\s"']+/gi, "<stdin-bridge>")
    .replace(/"command_id"\s*:\s*"[^"]+"/gi, "")
    .replace(/\s+/g, " ")
    .trim();
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

function publicCommandVerb(command = {}, toolId = "", status = "") {
  const statusText = publicToolText(status || command.status || "").toLowerCase();
  if (/failed|error/.test(statusText)) return "Failed";
  if (/running|started|pending/.test(statusText)) return "Running";
  if (toolId === "shell__start") return "Started";
  return "Ran";
}

function publicCommandKindLabel(value = "") {
  const text = publicToolText(value);
  if (!text || /^(?:shell|command|running command|ran command|started command)$/i.test(text)) return "";
  const head = text.split(/\s+/)[0].split(/[\\/]/).pop().toLowerCase();
  if (!head) return "";
  if (head === "node" || head === "nodejs") return "Node.js";
  if (head === "python" || head === "python3") return "Python";
  if (["npm", "pnpm", "yarn", "bun", "cargo", "deno", "go", "rustc", "make"].includes(head)) return head;
  if (head === "bash" || head === "sh" || head === "zsh") return "shell";
  return "";
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
      const label = publicToolText(step?.label || step?.title || "");
      if (!label) return null;
      const detail = publicToolText(step?.detail || step?.summary || "");
      const sourceChips = normalizeSourceChips(step?.sourceChips || step?.source_chips || step?.sources);
      const excerptPreview = publicToolText(step?.excerptPreview || step?.excerpt_preview || sourceChips[0]?.excerpt || "").slice(0, 280);
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

function runtimeManagedSessionCards({ computerUseSessions = [] } = {}) {
  if (firstArray(computerUseSessions).length) {
    return firstArray(computerUseSessions);
  }
  return [];
}

function commandOutputText(command = {}) {
  const text = publicOutputBlock(
    command.stdout ||
    command.output ||
    command.chunk ||
    command.text ||
    command.excerptPreview ||
    command.excerpt_preview ||
    ""
  );
  if (!text) return "";
  const commandLabel = publicToolText(command.command || command.commandLabel || command.command_label || "");
  const rowLabel = publicToolText(command.label || "");
  if (commandLabel && text === commandLabel) return "";
  if (rowLabel && text === rowLabel) return "";
  if (/^[a-z0-9_.-]+\s+-lc\s+<arg>$/i.test(text)) return "";
  if (/^[a-z0-9_.-]+\s+-e\s+<inline script>$/i.test(text)) return "";
  if (commandLabel && text === `${commandLabel} · running`) return "";
  return text;
}

function commandMergeKey(command = {}, index = 0) {
  const toolId = publicToolText(command.toolId || command.tool_id || "shell").slice(0, 96);
  const commandLabel = publicToolText(command.command || command.commandLabel || command.command_label || "");
  if (commandLabel) return `${toolId}:${commandLabel}`;
  if (/^shell__|^terminal__/.test(toolId)) return `${toolId}:active-command`;
  return publicToolText(command.id || command.commandId || command.command_id || `${toolId}.${index}`).slice(0, 160);
}

function appendUniqueBlock(existing = "", next = "") {
  const lhs = publicOutputBlock(existing);
  const rhs = publicOutputBlock(next);
  if (!rhs) return lhs;
  if (!lhs) return rhs;
  const lines = new Set(lhs.split(/\r?\n/).map((line) => line.trim()).filter(Boolean));
  const additions = rhs.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !lines.has(line));
  if (!additions.length) return lhs;
  return publicOutputBlock([lhs, ...additions].join("\n"));
}

function mergedCommandOutputs(commandOutputs = []) {
  const merged = new Map();
  firstArray(commandOutputs).forEach((command, index) => {
    if (!command || typeof command !== "object" || Array.isArray(command)) return;
    const key = commandMergeKey(command, index);
    const existing = merged.get(key) || {
      ...command,
      stdout: "",
      stderr: "",
    };
    const nextOutput = commandOutputText(command);
    existing.stdout = appendUniqueBlock(existing.stdout, nextOutput);
    existing.stderr = appendUniqueBlock(existing.stderr, command.stderr || "");
    existing.status = command.status || existing.status;
    existing.exitCode = command.exitCode ?? command.exit_code ?? existing.exitCode ?? existing.exit_code ?? null;
    existing.durationMs = command.durationMs ?? command.duration_ms ?? existing.durationMs ?? existing.duration_ms ?? null;
    existing.command = existing.command || command.command || command.commandLabel || command.command_label || "";
    existing.commandLabel = existing.commandLabel || command.commandLabel || command.command_label || command.command || "";
    if (command.label && /^(?:ran|running|started|failed)\b/i.test(String(command.label))) {
      existing.label = command.label;
    } else {
      existing.label = existing.label || command.label;
    }
    existing.toolId = existing.toolId || command.toolId || command.tool_id || "shell";
    merged.set(key, existing);
  });
  const rows = [...merged.values()];
  const detailedTools = new Set(rows
    .filter((command) => publicToolText(command.command || command.commandLabel || command.command_label || ""))
    .map((command) => publicToolText(command.toolId || command.tool_id || "shell")));
  return rows.filter((command) => {
    const toolId = publicToolText(command.toolId || command.tool_id || "shell");
    if (!detailedTools.has(toolId)) return true;
    if (publicToolText(command.command || command.commandLabel || command.command_label || "")) return true;
    return Boolean(publicOutputBlock(command.stdout || command.stderr || ""));
  });
}

function normalizedCommandOutputs(commandOutputs = []) {
  return mergedCommandOutputs(commandOutputs)
    .map((command, index) => {
      if (!command || typeof command !== "object" || Array.isArray(command)) return null;
      const toolId = publicToolText(command.toolId || command.tool_id || "shell").slice(0, 96);
      const rawLabel = publicToolText(command.label || command.command || toolId || "Command");
      const rawLabelIsGeneric =
        /^[a-z][a-z0-9_]*__[a-z0-9_]+$/i.test(rawLabel) ||
        rawLabel === toolId ||
        /^(?:shell|command|running command|ran command|started command)$/i.test(rawLabel);
      const commandKind = publicCommandKindLabel(command.command || command.commandLabel || command.command_label || "");
      const status = publicToolText(command.status || "completed").slice(0, 32);
      const label = rawLabelIsGeneric && commandKind
        ? `${publicCommandVerb(command, toolId, status)} ${commandKind} command`
        : rawLabel;
      return {
        id: publicToolText(command.id || command.commandId || command.command_id || `command.${index}`).slice(0, 96),
        toolId,
        label: label || "Command",
        status,
        stdout: publicOutputBlock(command.stdout || ""),
        stderr: publicOutputBlock(command.stderr || ""),
        exitCode: command.exitCode ?? command.exit_code ?? null,
        durationMs: command.durationMs ?? command.duration_ms ?? null,
      };
    })
    .filter(Boolean)
    .slice(-4);
}

function isGenericCommandWorkRow(row = {}) {
  const headline = publicToolText(row.headline || row.label || "");
  const kind = publicToolText(row.kind || row.toolId || row.tool_id || "");
  if (/^(?:ran|running|started|failed) command$/i.test(headline)) return true;
  return /^shell__|^terminal__|^command(?:\.|$)/i.test(kind);
}

function isCommandLabelOnlyExcerpt(value = "") {
  const text = publicToolText(value);
  if (!text) return true;
  if (/^[a-z0-9_.-]+\s+-lc\s+<arg>$/i.test(text)) return true;
  if (/^[a-z0-9_.-]+\s+-e\s+<inline script>$/i.test(text)) return true;
  return false;
}

function filterDuplicateCommandWorkRows(workRows = [], commandOutputRows = []) {
  const hasDetailedCommandOutput = firstArray(commandOutputRows).some((command) => {
    const label = publicToolText(command?.label || "");
    const hasOutput = Boolean(publicOutputBlock(command?.stdout || command?.stderr || ""));
    return hasOutput || !/^(?:ran|running|started|failed)?\s*command$/i.test(label);
  });
  if (!hasDetailedCommandOutput) return workRows;
  return firstArray(workRows).filter((row) => {
    if (!isGenericCommandWorkRow(row)) return true;
    return false;
  });
}

function normalizedDiffHunks(diffHunks = []) {
  return firstArray(diffHunks)
    .map((hunk, index) => {
      if (!hunk || typeof hunk !== "object" || Array.isArray(hunk)) return null;
      return {
        title: publicToolText(hunk.title || `Hunk ${index + 1}`).slice(0, 120),
        file: publicRefText(hunk.file || hunk.path || "workspace").slice(0, 220),
        status: publicToolText(hunk.status || "pending").slice(0, 32),
        before: publicOutputBlock(hunk.before || hunk.search || ""),
        after: publicOutputBlock(hunk.after || hunk.replace || ""),
        stale: Boolean(hunk.stale),
        staleReason: publicToolText(hunk.staleReason || hunk.stale_reason || "").slice(0, 160),
        acceptAvailable: hunk.acceptAvailable ?? hunk.accept_available ?? true,
        rejectAvailable: hunk.rejectAvailable ?? hunk.reject_available ?? true,
        rollbackAvailable: hunk.rollbackAvailable ?? hunk.rollback_available ?? false,
        approvalId: publicToolText(hunk.approvalId || hunk.approval_id || "").slice(0, 160),
        changeId: publicToolText(hunk.changeId || hunk.change_id || "").slice(0, 160),
        hunkIndex: Number.isFinite(Number(hunk.hunkIndex ?? hunk.hunk_index)) ? Number(hunk.hunkIndex ?? hunk.hunk_index) : index,
      };
    })
    .filter(Boolean)
    .slice(-6);
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
  const commandOutputRows = normalizedCommandOutputs(commandOutputs);
  const workRows = filterDuplicateCommandWorkRows(workRowsFromPendingWorklog(pendingWorklog), commandOutputRows);
  const reviewableDiffHunks = normalizedDiffHunks(diffHunks);
  const managedSessionCards = runtimeManagedSessionCards({
    computerUseSessions,
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
        activityLines.push(`Ran ${publicToolText(command.label || command.toolId || "sandboxed command")}.`);
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
    commandOutputs: commandOutputRows,
    diffHunks: reviewableDiffHunks,
    sessionCards: managedSessionCards.slice(-3),
    artifactCards: conversationArtifacts.slice(-6),
  };
}

function studioTurnHasDocumentedWork(turn = {}) {
  const record = turn.workRecord || null;
  return Boolean(
    record && (
      firstArray(record.lines).length ||
      firstArray(record.workRows).length ||
      firstArray(record.commandOutputs).length ||
      firstArray(record.diffHunks).length ||
      firstArray(record.sessionCards).length ||
      firstArray(record.artifactCards).length
    )
  );
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
