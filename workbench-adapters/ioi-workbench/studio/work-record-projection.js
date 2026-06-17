const path = require("path");

function defaultStringValue(value, fallback = "") {
  if (value === null || value === undefined) return fallback;
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  return fallback;
}

function defaultFirstArray(value) {
  return Array.isArray(value) ? value : [];
}

function defaultCompactWhitespace(value = "") {
  return defaultStringValue(value).replace(/\s+/g, " ").trim();
}

function studioPublicOutputBlock(value = "", max = 6000) {
  return String(value || "")
    .replace(/\bshell__start:[a-f0-9]{12,}\b/gi, "<command>")
    .replace(/\b(?:receipt|trace|request|turn|thread)_[a-z0-9:_-]{8,}\b/gi, "<ref>")
    .replace(/ioi-session-stdin-[^\s"']+/gi, "<stdin-bridge>")
    .replace(/\/tmp\/[^\s"']+/gi, "<tmp>")
    .replace(/\/home\/[^\s"']+/gi, "<path>")
    .replace(/"command_id"\s*:\s*"[^"]+"/gi, "")
    .slice(0, max)
    .trim();
}

function createStudioWorkRecordProjection(deps = {}) {
  const compactStudioWhitespace = deps.compactStudioWhitespace || defaultCompactWhitespace;
  const firstArray = deps.firstArray || defaultFirstArray;
  const workspacePath = deps.workspacePath || (() => "");
  const studioPendingWorkLabelForTool = deps.studioPendingWorkLabelForTool || ((toolName) => compactStudioWhitespace(toolName));
  const studioSourceRefFromRecord = deps.studioSourceRefFromRecord || (() => null);

  function studioPublicWorkspacePath(value = "") {
    const raw = compactStudioWhitespace(value).replace(/\\/g, "/");
    if (!raw) return "";
    const workspaceRoot = compactStudioWhitespace(workspacePath()).replace(/\\/g, "/");
    if (/^(?:\/|[a-z]:\/)/i.test(raw)) {
      if (workspaceRoot && !/^open a workspace/i.test(workspaceRoot)) {
        const relative = path.relative(workspaceRoot, raw).replace(/\\/g, "/");
        if (relative && !relative.startsWith("..") && !path.isAbsolute(relative)) {
          return relative.slice(0, 180);
        }
      }
      return path.basename(raw).slice(0, 120) || "workspace";
    }
    return raw.replace(/^\.\//, "").slice(0, 180);
  }

  function studioCommandRowHasOutput(command = {}) {
    if (!command || typeof command !== "object" || Array.isArray(command)) return false;
    return Boolean(compactStudioWhitespace(
      command.stdout ||
      command.output ||
      command.chunk ||
      command.text ||
      command.excerptPreview ||
      command.excerpt_preview ||
      command.stderr ||
      "",
    ));
  }

  function studioEffectiveCommandStatus(command = {}, { recordSettled = false } = {}) {
    const status = compactStudioWhitespace(command.status || "completed").slice(0, 32);
    if (recordSettled && studioCommandRowHasOutput(command) && /^(?:running|started|pending)$/i.test(status)) {
      return "completed";
    }
    return status;
  }

  function studioPublicCommandVerb(command = {}, toolId = "", status = "") {
    const statusText = compactStudioWhitespace(status || command.status || "").toLowerCase();
    if (/failed|error/.test(statusText)) return "Failed";
    if (/running|started|pending/.test(statusText)) return "Running";
    if (toolId === "shell__start") return "Started";
    return "Ran";
  }

  function studioPublicCommandKindLabel(value = "") {
    const text = compactStudioWhitespace(value);
    if (!text || /^(?:shell|command|running command|ran command|started command)$/i.test(text)) return "";
    const head = text.split(/\s+/)[0].split(/[\\/]/).pop().toLowerCase();
    if (!head) return "";
    if (head === "node" || head === "nodejs") return "Node.js";
    if (head === "python" || head === "python3") return "Python";
    if (["npm", "pnpm", "yarn", "bun", "cargo", "deno", "go", "rustc", "make"].includes(head)) return head;
    if (head === "bash" || head === "sh" || head === "zsh") return "shell";
    return "";
  }

  function studioPublicCommandOutputForWebview(command = {}, index = 0, options = {}) {
    if (!command || typeof command !== "object" || Array.isArray(command)) return null;
    const toolId = compactStudioWhitespace(command.toolId || command.tool_id || "");
    const rawLabel = compactStudioWhitespace(command.label || command.command || toolId || "Command");
    const effectiveStatus = studioEffectiveCommandStatus(command, options);
    const rawLabelIsGeneric =
      /^[a-z][a-z0-9_]*__[a-z0-9_]+$/i.test(rawLabel) ||
      rawLabel === toolId ||
      /^(?:shell|command|running command|ran command|started command)$/i.test(rawLabel);
    const commandKind = studioPublicCommandKindLabel(command.command || command.commandLabel || command.command_label || "");
    const label = (rawLabelIsGeneric
      ? (commandKind
        ? `${studioPublicCommandVerb(command, toolId, effectiveStatus)} ${commandKind} command`
        : studioPendingWorkLabelForTool(toolId || rawLabel, "", effectiveStatus || "completed"))
      : rawLabel
    ).slice(0, 160);
    if (!label) return null;
    return {
      id: compactStudioWhitespace(command.id || command.commandId || command.command_id || `command.${index}`).slice(0, 96),
      toolId: (toolId || "shell").slice(0, 96),
      label,
      status: effectiveStatus,
      stdout: studioPublicOutputBlock(
        command.stdout ||
        command.output ||
        command.chunk ||
        command.text ||
        command.excerptPreview ||
        command.excerpt_preview ||
        "",
      ),
      stderr: studioPublicOutputBlock(command.stderr || ""),
      exitCode: command.exitCode ?? command.exit_code ?? null,
      durationMs: command.durationMs ?? command.duration_ms ?? null,
    };
  }

  function studioPublicDiffHunkForWebview(hunk = {}, index = 0) {
    if (!hunk || typeof hunk !== "object" || Array.isArray(hunk)) return null;
    const file = studioPublicWorkspacePath(hunk.file || hunk.path || "workspace") || "workspace";
    return {
      title: compactStudioWhitespace(hunk.title || `Hunk ${index + 1}`).slice(0, 120),
      file,
      status: compactStudioWhitespace(hunk.status || "pending").slice(0, 32),
      before: studioPublicOutputBlock(hunk.before || hunk.search || "", 4000),
      after: studioPublicOutputBlock(hunk.after || hunk.replace || "", 4000),
      stale: Boolean(hunk.stale),
      staleReason: compactStudioWhitespace(hunk.staleReason || hunk.stale_reason || "").slice(0, 160),
      acceptAvailable: hunk.acceptAvailable ?? hunk.accept_available ?? true,
      rejectAvailable: hunk.rejectAvailable ?? hunk.reject_available ?? true,
      rollbackAvailable: hunk.rollbackAvailable ?? hunk.rollback_available ?? false,
      approvalId: compactStudioWhitespace(hunk.approvalId || hunk.approval_id || "").slice(0, 160),
      changeId: compactStudioWhitespace(hunk.changeId || hunk.change_id || "").slice(0, 160),
      hunkIndex: Number.isFinite(Number(hunk.hunkIndex ?? hunk.hunk_index)) ? Number(hunk.hunkIndex ?? hunk.hunk_index) : index,
    };
  }

  function studioIsGenericCommandWorkRow(row = {}) {
    const headline = compactStudioWhitespace(row.headline || row.label || "");
    const kind = compactStudioWhitespace(row.kind || row.toolId || row.tool_id || "");
    if (/^(?:ran|running|started|failed) command$/i.test(headline)) return true;
    return /^shell__|^terminal__|^command(?:\.|$)/i.test(kind);
  }

  function studioFilterDuplicateCommandWorkRows(workRows = [], commandOutputs = []) {
    const hasDetailedCommandOutput = firstArray(commandOutputs).some((command) => {
      const label = compactStudioWhitespace(command?.label || "");
      const hasOutput = Boolean(compactStudioWhitespace(command?.stdout || command?.stderr || ""));
      return hasOutput || !/^(?:ran|running|started|failed)?\s*command$/i.test(label);
    });
    if (!hasDetailedCommandOutput) return workRows;
    return firstArray(workRows).filter((row) => !studioIsGenericCommandWorkRow(row));
  }

  function studioPublicWorkRecordForWebview(record = {}) {
    if (!record || typeof record !== "object" || Array.isArray(record)) {
      return null;
    }
    const recordSettled = /^(?:completed|blocked|failed|cancelled|canceled)$/i.test(compactStudioWhitespace(record.status || ""));
    const lines = firstArray(record.lines)
      .map((line) => compactStudioWhitespace(line).slice(0, 160))
      .filter(Boolean)
      .slice(0, 12);
    const mappedWorkRows = firstArray(record.workRows)
      .map((row) => {
        if (!row || typeof row !== "object" || Array.isArray(row)) return null;
        const headline = compactStudioWhitespace(row.headline || row.label || "").slice(0, 160);
        if (!headline) return null;
        return {
          id: compactStudioWhitespace(row.id || row.stepId || headline).slice(0, 96),
          kind: compactStudioWhitespace(row.kind || row.publicKind || "tool").slice(0, 48),
          status: compactStudioWhitespace(row.status || "completed").slice(0, 32),
          headline,
          summary: compactStudioWhitespace(row.summary || row.detail || "").slice(0, 220),
          excerptPreview: compactStudioWhitespace(row.excerptPreview || row.excerpt_preview || "").slice(0, 280),
          sourceChips: firstArray(row.sourceChips || row.source_chips)
            .map((source) => studioSourceRefFromRecord(source))
            .filter(Boolean)
            .slice(0, 6),
        };
      })
      .filter(Boolean)
      .slice(0, 12);
    const sessionCards = firstArray(record.sessionCards)
      .map((session) => {
        if (!session || typeof session !== "object" || Array.isArray(session)) return null;
        const id = compactStudioWhitespace(session.id || session.sessionId || session.title || "managed-session").slice(0, 120);
        return {
          id,
          kind: compactStudioWhitespace(session.kind || "sandbox_browser").slice(0, 48),
          surfaceLabel: compactStudioWhitespace(session.surfaceLabel || session.surface_label || "Sandbox browser").slice(0, 80),
          status: compactStudioWhitespace(session.status || "complete").slice(0, 48),
          statusLabel: compactStudioWhitespace(session.statusLabel || session.status_label || "Complete").slice(0, 80),
          title: compactStudioWhitespace(session.title || "Browser session").slice(0, 120),
          detail: compactStudioWhitespace(session.detail || session.summary || "Managed browser session").slice(0, 240),
          url: compactStudioWhitespace(session.url || "").slice(0, 240),
          pageTitle: compactStudioWhitespace(session.pageTitle || session.page_title || "").slice(0, 120),
          target: compactStudioWhitespace(session.target || "").slice(0, 160),
          lane: compactStudioWhitespace(session.lane || "").slice(0, 80),
          sessionMode: compactStudioWhitespace(session.sessionMode || session.session_mode || "").slice(0, 80),
          lastTool: compactStudioWhitespace(session.lastTool || session.last_tool || "computer-use").slice(0, 80),
          actionCount: Math.max(1, Number(session.actionCount || session.action_count || 1) || 1),
          controlState: compactStudioWhitespace(session.controlState || session.control_state || "observe").slice(0, 48),
          availableControlStates: firstArray(session.availableControlStates || session.available_control_states)
            .map((state) => compactStudioWhitespace(state).slice(0, 48))
            .filter(Boolean)
            .slice(0, 6),
          waitingForUser: Boolean(session.waitingForUser || session.waiting_for_user),
          waitingReason: compactStudioWhitespace(session.waitingReason || session.waiting_reason || "").slice(0, 80),
          replayReady: Boolean(session.replayReady || session.replay_ready),
          updatedAt: compactStudioWhitespace(session.updatedAt || session.updated_at || "").slice(0, 80),
        };
      })
      .filter(Boolean)
      .slice(-3);
    const rawCommandOutputs = firstArray(record.commandOutputs);
    const hasCommandOutput = rawCommandOutputs.some((command) => studioCommandRowHasOutput(command));
    const hasWorkRowOutput = mappedWorkRows.some((row) => compactStudioWhitespace(row.excerptPreview || ""));
    const commandOutputs = rawCommandOutputs
      .map((command, index) => studioPublicCommandOutputForWebview(command, index, { recordSettled }))
      .filter(Boolean)
      .filter((command) => {
        const status = compactStudioWhitespace(command.status || "");
        const emptyOutput = !compactStudioWhitespace(
          command.stdout ||
          command.output ||
          command.chunk ||
          command.text ||
          command.excerptPreview ||
          command.excerpt_preview ||
          "",
        ) && !compactStudioWhitespace(command.stderr || "");
        if (recordSettled && emptyOutput && /^(?:running|started|pending)$/i.test(status)) return false;
        if (recordSettled && (hasCommandOutput || hasWorkRowOutput) && emptyOutput && /^(?:completed|succeeded|success)$/i.test(status)) return false;
        return true;
      })
      .slice(-4);
    const workRows = studioFilterDuplicateCommandWorkRows(mappedWorkRows, commandOutputs);
    const diffHunks = firstArray(record.diffHunks)
      .map((hunk, index) => studioPublicDiffHunkForWebview(hunk, index))
      .filter(Boolean)
      .slice(-6);
    if (!lines.length && !workRows.length && !sessionCards.length && !commandOutputs.length && !diffHunks.length) {
      return null;
    }
    return {
      status: compactStudioWhitespace(record.status || "completed").slice(0, 32),
      durationMs: Math.max(0, Number(record.durationMs || 0) || 0),
      lines,
      workRows,
      commandOutputs,
      diffHunks,
      sessionCards,
      stepCount: Number(record.stepCount || lines.length || workRows.length || commandOutputs.length || diffHunks.length || 0) || lines.length || workRows.length || commandOutputs.length || diffHunks.length,
    };
  }

  return {
    studioCommandRowHasOutput,
    studioEffectiveCommandStatus,
    studioFilterDuplicateCommandWorkRows,
    studioIsGenericCommandWorkRow,
    studioPublicCommandKindLabel,
    studioPublicCommandOutputForWebview,
    studioPublicCommandVerb,
    studioPublicDiffHunkForWebview,
    studioPublicOutputBlock,
    studioPublicWorkRecordForWebview,
    studioPublicWorkspacePath,
  };
}

module.exports = {
  createStudioWorkRecordProjection,
  studioPublicOutputBlock,
};
