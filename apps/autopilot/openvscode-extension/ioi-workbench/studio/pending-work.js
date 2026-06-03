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

function createStudioPendingWorkProjection(deps = {}) {
  const stringValue = deps.stringValue || defaultStringValue;
  const firstArray = deps.firstArray || defaultFirstArray;
  const compactStudioWhitespace = deps.compactStudioWhitespace || defaultCompactWhitespace;
  const sanitizeStudioPublicToolText = deps.sanitizeStudioPublicToolText || ((value) => stringValue(value));
  const studioPublicOutputBlock = deps.studioPublicOutputBlock || ((value = "", max = 6000) => stringValue(value).slice(0, max).trim());
  const humanizeStudioToolName = deps.humanizeStudioToolName || ((value) => stringValue(value));
  const studioSourceRefFromRecord = deps.studioSourceRefFromRecord || (() => null);
  const studioRuntimeEventIdentity = deps.studioRuntimeEventIdentity || (() => "");
  const studioRuntimeEventToolName = deps.studioRuntimeEventToolName || (() => "");
  const studioRuntimeEventKind = deps.studioRuntimeEventKind || (() => "");
  const studioRuntimeToolEventDetail = deps.studioRuntimeToolEventDetail || (() => "");
  const studioRuntimeToolEventExcerpt = deps.studioRuntimeToolEventExcerpt || (() => "");
  const studioSourceRefsFromRuntimeEvent = deps.studioSourceRefsFromRuntimeEvent || (() => []);
  const studioFirstSourceExcerptFromEvent = deps.studioFirstSourceExcerptFromEvent || (() => "");
  const getProjection = deps.getProjection || (() => ({}));

  function uniqueStrings(values) {
    return [...new Set(firstArray(values).map((value) => String(value)).filter(Boolean))];
  }

  function isAbstractStudioPendingWorkStep(label, detail) {
    const text = `${label || ""}\n${detail || ""}`.toLowerCase();
    if (!text.trim()) {
      return true;
    }
    return [
      "governed agent run",
      "governed agent harness",
      "daemon session",
      "model route",
      "policy context",
      "daemon-owned",
      "tool calls, policy checks",
      "receipts and traces",
      "receipts stay",
      "traces stay",
      "prepare artifact run",
      "preparing artifact",
      "drafting website artifact",
      "drafted custom website",
      "creating sandboxed artifact",
      "created artifact preview",
      "gathering source context",
      "gathered source context",
    ].some((phrase) => text.includes(phrase));
  }

  function studioVisiblePendingStepDetail(detail = "") {
    const text = sanitizeStudioPublicToolText(stringValue(detail));
    if (/^(?:running|started|completed|pending|status:\s*(?:running|started|completed|pending))$/i.test(text)) {
      return "";
    }
    return text;
  }

  function studioPendingCommandOutputExcerpt(step = {}, fallbackExcerpt = "") {
    const text = studioPublicOutputBlock(
      step.excerptPreview ||
        step.excerpt_preview ||
        step.stdout ||
        step.output ||
        step.chunk ||
        step.text ||
        fallbackExcerpt ||
        "",
      1200,
    );
    if (!text) {
      return "";
    }
    const commandLabel = compactStudioWhitespace(step.command || step.commandLabel || step.command_label || step.detail || "");
    const rowLabel = compactStudioWhitespace(step.label || "");
    if (commandLabel && text === commandLabel) {
      return "";
    }
    if (rowLabel && text === rowLabel) {
      return "";
    }
    if (/^[a-z0-9_.-]+\s+-lc\s+<arg>$/i.test(text)) {
      return "";
    }
    if (/^[a-z0-9_.-]+\s+-e\s+<inline script>$/i.test(text)) {
      return "";
    }
    return text;
  }

  function studioPendingWorkToolName(payload = {}) {
    const explicit = stringValue(
      payload.toolName ||
        payload.tool_name ||
        payload.toolId ||
        payload.tool_id ||
        payload.name ||
        payload.tool,
    );
    if (explicit) {
      return explicit;
    }
    const label = stringValue(payload.label);
    return label.match(/\b[a-z][a-z0-9]*__[a-z0-9_]+\b/i)?.[0] || "";
  }

  function studioPendingWorkStepIsConcrete(payload = {}) {
    const toolName = studioPendingWorkToolName(payload);
    if (!toolName || toolName === "chat__reply") {
      return false;
    }
    const kind = stringValue(payload.kind || payload.eventKind || payload.event_kind).toLowerCase();
    const concreteTool = /(?:^|__)(?:agent|artifact|browser|computer|editor|file|mcp|memory|model|screen|shell|terminal|web|workspace)__?/i.test(toolName) ||
      /\b[a-z][a-z0-9]*__[a-z0-9_]+\b/i.test(toolName);
    if (!concreteTool) {
      return false;
    }
    if (kind && !/tool|receipt|command|shell|browser|file|web|turn\.step|agent\.step/.test(kind)) {
      return false;
    }
    return true;
  }

  function normalizeStudioPendingWorkStep(payload = {}) {
    const label = sanitizeStudioPublicToolText(stringValue(payload.label));
    if (!label) {
      return null;
    }
    const detail = studioVisiblePendingStepDetail(payload.detail);
    if (isAbstractStudioPendingWorkStep(label, detail)) {
      return null;
    }
    if (!studioPendingWorkStepIsConcrete(payload)) {
      return null;
    }
    const toolName = studioPendingWorkToolName(payload);
    const commandStep = /shell|terminal|command/i.test(toolName);
    return {
      id: stringValue(payload.id || payload.stepId || payload.eventId || payload.event_id || payload.toolCallId || payload.tool_call_id),
      label,
      detail,
      status: stringValue(payload.status, "running"),
      at: stringValue(payload.at) || new Date().toISOString(),
      toolName,
      kind: stringValue(payload.kind || payload.eventKind || payload.event_kind),
      sourceChips: firstArray(payload.sourceChips || payload.source_chips || payload.sources)
        .map((source) => studioSourceRefFromRecord(source))
        .filter(Boolean)
        .slice(0, 6),
      excerptPreview: commandStep
        ? studioPendingCommandOutputExcerpt(payload)
        : sanitizeStudioPublicToolText(payload.excerptPreview || payload.excerpt_preview).slice(0, 280),
    };
  }

  function studioPendingWorkLabelForTool(toolName = "", detail = "", status = "") {
    const normalizedTool = stringValue(toolName).toLowerCase();
    const compactDetail = compactStudioWhitespace(detail);
    const statusText = stringValue(status).toLowerCase();
    const domainLike = compactDetail && !/^query:/i.test(compactDetail);
    if (normalizedTool === "web__search") return "Searched web";
    if (normalizedTool === "web__read") return domainLike ? `Read ${compactDetail}` : "Read source";
    if (normalizedTool === "file__search") return "Searched files";
    if (normalizedTool === "file__read" || normalizedTool === "file__view") return domainLike ? `Read ${compactDetail}` : "Read file";
    if (normalizedTool === "file__write") return domainLike ? `Wrote ${compactDetail}` : "Wrote file";
    if (normalizedTool === "file__edit" || normalizedTool === "file__multi_edit") return domainLike ? `Edited ${compactDetail}` : "Edited file";
    if (normalizedTool === "shell__start") {
      if (/failed|error/.test(`${statusText} ${compactDetail}`)) return "Command failed";
      return /running/.test(`${statusText} ${compactDetail}`) ? "Running command" : "Started command";
    }
    if (normalizedTool === "shell__run" || normalizedTool === "terminal__run") {
      if (/failed|error/.test(statusText)) return "Command failed";
      return /running|started/.test(`${statusText} ${compactDetail}`) ? "Running command" : "Ran command";
    }
    if (normalizedTool === "shell__status") return "Checked command status";
    if (normalizedTool === "shell__input") {
      const inputState = `${statusText} ${compactDetail}`;
      if (/already stopped|already terminated|obsolete/i.test(inputState)) return "Skipped obsolete input";
      return /failed|skipped|already sent/i.test(inputState)
        ? "Skipped duplicate input"
        : "Sent input to retained command";
    }
    if (normalizedTool === "shell__terminate") return "Terminated retained command";
    if (normalizedTool === "shell__reset") return "Reset retained shell state";
    if (/^shell__|^terminal__/.test(normalizedTool)) return "Ran command";
    if (/^browser__/.test(normalizedTool)) return "Used browser";
    if (/^screen__|^computer__/.test(normalizedTool)) return "Used computer";
    if (/^memory__/.test(normalizedTool)) return "Used memory";
    if (/^mcp__/.test(normalizedTool)) return "Used connector";
    return humanizeStudioToolName(normalizedTool) || "Used tool";
  }

  function appendStudioPendingWorkStep(payload = {}) {
    const projection = getProjection();
    const step = normalizeStudioPendingWorkStep(payload);
    if (!step) {
      return null;
    }
    const concreteExcerpt = (nextExcerpt = "", previousExcerpt = "") => {
      const next = String(nextExcerpt || "").trim();
      const previous = String(previousExcerpt || "").trim();
      if (!next) return previous;
      if (previous && /^(?:ran command|running command|started command|command completed)$/i.test(next)) {
        return previous;
      }
      return next;
    };
    const rows = firstArray(projection.pendingWorklog).slice();
    const existingIndex = rows.findIndex((row) =>
      (step.id && row.id === step.id) ||
      (step.toolName && row.toolName === step.toolName) ||
      row.label === step.label
    );
    if (existingIndex >= 0) {
      const existing = rows[existingIndex];
      rows[existingIndex] = {
        ...existing,
        ...step,
        detail: step.detail || existing.detail || "",
        sourceChips: firstArray(step.sourceChips).length ? step.sourceChips : firstArray(existing.sourceChips),
        excerptPreview: concreteExcerpt(step.excerptPreview, existing.excerptPreview),
      };
    } else {
      rows.push(step);
    }
    projection.pendingWorklog = rows.slice(-12);
    return step;
  }

  function studioPendingWorklogLastAtMs() {
    const latest = firstArray(getProjection().pendingWorklog).slice(-1)[0];
    const parsed = Date.parse(latest?.at || "");
    return Number.isFinite(parsed) ? parsed : 0;
  }

  function studioRuntimeEventSeen(event = {}) {
    const id = studioRuntimeEventIdentity(event);
    if (!id) {
      return false;
    }
    return firstArray(getProjection().runtimeEventSeenIds).includes(id);
  }

  function markStudioRuntimeEventSeen(event = {}) {
    const projection = getProjection();
    const id = studioRuntimeEventIdentity(event);
    if (!id) {
      return true;
    }
    if (studioRuntimeEventSeen(event)) {
      return false;
    }
    projection.runtimeEventSeenIds = [
      ...firstArray(projection.runtimeEventSeenIds),
      id,
    ].slice(-300);
    return true;
  }

  function studioPendingStepFromRuntimeEvent(event = {}, { kind = "", toolName = "", status = "", summary = "" } = {}) {
    const normalizedTool = stringValue(toolName || studioRuntimeEventToolName(event));
    if (!normalizedTool || normalizedTool === "chat__reply") {
      return null;
    }
    const normalizedKind = stringValue(kind || studioRuntimeEventKind(event)).toLowerCase();
    if (!/tool\.(call|started|output|completed|result)|receipt\.emitted|command|shell|browser|file|web|turn\.step|agent\.step/.test(normalizedKind)) {
      return null;
    }
    const completed = /completed|result|succeeded|failed|error/.test(`${normalizedKind} ${status}`.toLowerCase());
    const detail = studioRuntimeToolEventDetail(event, normalizedTool, summary);
    const sourceChips = studioSourceRefsFromRuntimeEvent(event, summary);
    const excerptPreview =
      studioRuntimeToolEventExcerpt(event, summary) ||
      studioFirstSourceExcerptFromEvent(event, summary);
    return normalizeStudioPendingWorkStep({
      id: normalizedTool,
      label: studioPendingWorkLabelForTool(normalizedTool, detail, completed ? "completed" : "running"),
      detail,
      status: completed ? "completed" : "running",
      at: event.created_at || event.createdAt || new Date().toISOString(),
      kind: normalizedKind,
      toolName: normalizedTool,
      sourceChips,
      excerptPreview,
    });
  }

  return {
    appendStudioPendingWorkStep,
    isAbstractStudioPendingWorkStep,
    markStudioRuntimeEventSeen,
    normalizeStudioPendingWorkStep,
    studioPendingCommandOutputExcerpt,
    studioPendingStepFromRuntimeEvent,
    studioPendingWorkLabelForTool,
    studioPendingWorkStepIsConcrete,
    studioPendingWorkToolName,
    studioPendingWorklogLastAtMs,
    studioRuntimeEventSeen,
    studioVisiblePendingStepDetail,
    uniqueStrings,
  };
}

module.exports = {
  createStudioPendingWorkProjection,
};
