"use strict";

function createStudioWorkRunRows({
  compactStudioWhitespace,
  escapeHtml,
  firstArray,
  formatStudioWorkDuration,
  getHunkApprovalId,
  studioCommandRowHasOutput,
  studioPendingWorkLabelForTool,
  studioPublicOutputBlock,
  studioPublicWorkspacePath,
  studioSanitizePublicAssistantText,
  studioSourceChipRows,
  stringValue,
}) {
  function studioCommandSurfaceLabel(command = {}) {
    const toolId = compactStudioWhitespace(command.toolId || command.tool_id || "");
    const rawLabel = compactStudioWhitespace(command.label || command.command || "");
    if (/^shell__|^terminal__/.test(toolId) || /^(?:shell|command)$/i.test(rawLabel)) {
      return "Shell";
    }
    if (/^browser__/.test(toolId)) {
      return "Browser";
    }
    if (/^file__/.test(toolId)) {
      return "File";
    }
    return "";
  }

  function studioCommandPublicActionLabel(command = {}) {
    const toolId = compactStudioWhitespace(command.toolId || command.tool_id || "");
    const rawLabel = compactStudioWhitespace(command.label || command.command || toolId || "");
    const status = compactStudioWhitespace(command.status || "completed");
    if (/^(?:shell|command)$/i.test(rawLabel)) {
      return /running|started/i.test(status) ? "Running command" : "Ran command";
    }
    if (/^shell__|^terminal__/.test(toolId) || rawLabel === toolId) {
      return /running|started/i.test(status) ? "Running command" : "Ran command";
    }
    if (/^[a-z][a-z0-9_]*__[a-z0-9_]+$/i.test(rawLabel)) {
      return studioPendingWorkLabelForTool(toolId || rawLabel, "", status);
    }
    return rawLabel || (/running|started/i.test(status) ? "Running command" : "Ran command");
  }

  function studioCommandDurationLabel(command = {}) {
    const durationMs = command.durationMs ?? command.duration_ms;
    const duration = Number(durationMs);
    return Number.isFinite(duration) ? formatStudioWorkDuration(duration) : "";
  }

  function studioCommandHeadline(command = {}) {
    const label = studioCommandPublicActionLabel(command) || "Ran command";
    const duration = studioCommandDurationLabel(command);
    if (!duration) {
      return label;
    }
    return /\bcommand\b/i.test(label) ? `${label} for ${duration}` : label;
  }

  function studioPublicWorkRowText(value = "") {
    return studioSanitizePublicAssistantText(value)
      .replace(/\b(Patched|Edited|Read)\s+<tmp>(?=$|\s|[.,;:])/gi, "$1 workspace file")
      .replace(/<tmp>/g, "workspace file")
      .trim();
  }

  function studioWorkSummaryRows(workRecord = {}) {
    const hasRicherWorkRows = (
      firstArray(workRecord.commandOutputs).length ||
      firstArray(workRecord.diffHunks).length ||
      firstArray(workRecord.sessionCards).length ||
      firstArray(workRecord.artifactCards).length
    );
    const rows = firstArray(workRecord.workRows).length
      ? firstArray(workRecord.workRows)
      : (hasRicherWorkRows ? [] : firstArray(workRecord.activityLines || workRecord.lines).map((line) => ({ headline: line, status: "completed" })));
    return rows.slice(0, 12).map((row) => {
      const sourceChips = firstArray(row.sourceChips || row.source_chips);
      return `
      <li class="studio-work-row" data-status="${escapeHtml(row.status || "completed")}" data-kind="${escapeHtml(row.kind || "tool")}">
        <div class="studio-work-row__main">
          <strong>${escapeHtml(studioPublicWorkRowText(row.headline || row.label || "Observed work"))}</strong>
          ${row.summary ? `<span>${escapeHtml(studioPublicWorkRowText(row.summary))}</span>` : ""}
        </div>
        ${sourceChips.length ? `<div class="studio-source-chip-list">${studioSourceChipRows(sourceChips, { limit: 6 })}</div>` : ""}
        ${row.excerptPreview ? `<p class="studio-work-row__excerpt">${escapeHtml(studioPublicWorkRowText(row.excerptPreview))}</p>` : ""}
      </li>
    `;
    }).join("");
  }

  function studioWorkCommandOutputRows(workRecord = {}) {
    const recordSettled = /^(?:completed|blocked|failed|cancelled|canceled)$/i.test(compactStudioWhitespace(workRecord.status || ""));
    const rawCommands = firstArray(workRecord.commandOutputs);
    const hasCommandOutput = rawCommands.some((command) => studioCommandRowHasOutput(command));
    return rawCommands.map((command) => {
      if (!recordSettled || !studioCommandRowHasOutput(command) || !/^(?:running|started|pending)$/i.test(compactStudioWhitespace(command?.status || ""))) {
        return command;
      }
      return { ...command, status: "completed", label: studioCommandPublicActionLabel({ ...command, status: "completed" }) };
    }).filter((command) => {
      const status = compactStudioWhitespace(command?.status || "");
      const emptyOutput = !compactStudioWhitespace(command?.stdout || command?.output || "") && !compactStudioWhitespace(command?.stderr || "");
      if (recordSettled && emptyOutput && /^(?:running|started|pending)$/i.test(status)) return false;
      if (recordSettled && hasCommandOutput && emptyOutput && /^(?:completed|succeeded|success)$/i.test(status)) return false;
      return true;
    }).slice(-4).map((command, index) => {
      const stdout = studioPublicOutputBlock(
        command.stdout ||
        command.output ||
        command.chunk ||
        command.text ||
        command.excerptPreview ||
        command.excerpt_preview ||
        ""
      );
      const stderr = studioPublicOutputBlock(command.stderr || "");
      const label = studioCommandPublicActionLabel(command);
      const surface = studioCommandSurfaceLabel(command);
      const status = compactStudioWhitespace(command.status || "completed");
      const exitCode = command.exitCode ?? command.exit_code;
      const duration = Number.isFinite(Number(command.durationMs ?? command.duration_ms))
        ? ` · ${formatStudioWorkDuration(command.durationMs ?? command.duration_ms)}`
        : "";
      return `
      <details class="studio-command-work-row" data-testid="studio-command-output-row"${index === 0 ? " open" : ""}>
        <summary>
          <strong>${escapeHtml(label || "Ran command")}</strong>
          ${surface ? `<span>${escapeHtml(surface)}</span>` : ""}
          <em>${escapeHtml([status, exitCode !== undefined && exitCode !== null ? `exit ${exitCode}` : "", duration.replace(/^ · /, "")].filter(Boolean).join(" · "))}</em>
        </summary>
        <pre data-testid="studio-command-stdout">${escapeHtml(stdout || "No output")}</pre>
        ${stderr ? `<pre class="studio-command-stderr" data-testid="studio-command-stderr">${escapeHtml(stderr)}</pre>` : ""}
      </details>
    `;
    }).join("");
  }

  function studioWorkRecordDiffRows(workRecord = {}) {
    return firstArray(workRecord.diffHunks).slice(-6).map((hunk, index) => {
      const changeId = stringValue(hunk.changeId || hunk.change_id);
      const hunkIndex = Number.isFinite(Number(hunk.hunkIndex ?? hunk.hunk_index)) ? Number(hunk.hunkIndex ?? hunk.hunk_index) : index;
      const acceptAvailable = hunk.acceptAvailable ?? hunk.accept_available ?? true;
      const rejectAvailable = hunk.rejectAvailable ?? hunk.reject_available ?? true;
      const rollbackAvailable = hunk.rollbackAvailable ?? hunk.rollback_available ?? false;
      const staleReason = stringValue(hunk.staleReason || hunk.stale_reason);
      return `
      <article class="studio-diff-hunk" data-testid="studio-inline-diff-hunks" data-native-diff-hunk="true">
        <header>
          <strong>${escapeHtml(hunk.title || `Hunk ${index + 1}`)}</strong>
          <code>${escapeHtml(studioPublicWorkspacePath(hunk.file || "workspace") || "workspace")}</code>
          <mark>${escapeHtml(hunk.status || "pending")}</mark>
        </header>
        ${hunk.stale && staleReason ? `<p class="studio-diff-hunk__stale">Stale: ${escapeHtml(staleReason)}</p>` : ""}
        <pre data-testid="studio-native-diff-hunk"><span class="studio-diff-remove">${escapeHtml(studioPublicOutputBlock(hunk.before || ""))}</span>
<span class="studio-diff-add">${escapeHtml(studioPublicOutputBlock(hunk.after || ""))}</span></pre>
        <footer data-testid="studio-hunk-accept-reject">
          <button type="button" data-testid="studio-hunk-prev" data-studio-hunk-nav="previous">Previous</button>
          <button type="button" data-testid="studio-hunk-next" data-studio-hunk-nav="next">Next</button>
          ${acceptAvailable ? `<button type="button" data-testid="studio-hunk-accept" data-studio-hunk-decision="approve" data-approval-id="${escapeHtml(hunk.approvalId || getHunkApprovalId())}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Accept hunk</button>` : ""}
          ${rejectAvailable ? `<button type="button" data-testid="studio-hunk-reject" data-studio-hunk-decision="reject" data-approval-id="${escapeHtml(hunk.approvalId || getHunkApprovalId())}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Reject hunk</button>` : ""}
          ${rollbackAvailable ? `<button type="button" data-testid="studio-hunk-rollback" data-studio-hunk-decision="rollback" data-approval-id="${escapeHtml(hunk.approvalId || getHunkApprovalId())}" data-hunk-file="${escapeHtml(hunk.file || "workspace")}" data-change-id="${escapeHtml(changeId)}" data-hunk-index="${escapeHtml(String(hunkIndex))}">Roll back hunk</button>` : ""}
        </footer>
      </article>
    `;
    }).join("");
  }

  return {
    studioCommandDurationLabel,
    studioCommandHeadline,
    studioCommandPublicActionLabel,
    studioCommandSurfaceLabel,
    studioPublicWorkRowText,
    studioWorkCommandOutputRows,
    studioWorkRecordDiffRows,
    studioWorkSummaryRows,
  };
}

module.exports = {
  createStudioWorkRunRows,
};
