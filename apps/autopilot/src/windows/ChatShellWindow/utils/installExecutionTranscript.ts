import type { AgentEvent, AgentTask } from "../../../types";

export type InstallExecutionTranscript = {
  isInstallWorkflow: boolean;
  title: string;
  status: "pending" | "blocked" | "running" | "complete" | "failed";
  content: string;
  lineCount: number;
};

type InstallResolution = Record<string, string>;

const MAX_TRANSCRIPT_LINES = 96;
const MAX_TRANSCRIPT_CHARS = 10000;
const INSTALL_TOOL_NAMES = new Set([
  "software_install__resolve",
  "software_install__execute_plan",
]);

function asText(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function compactWhitespace(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function addLine(lines: string[], value: string | null | undefined) {
  const line = value?.trim();
  if (!line) return;
  lines.push(line);
}

function boolText(value: unknown): string | null {
  if (typeof value === "boolean") return value ? "true" : "false";
  return asText(value);
}

function mergeResolution(target: InstallResolution, source: InstallResolution) {
  for (const [key, value] of Object.entries(source)) {
    if (value.trim()) {
      target[key] = value.trim();
    }
  }
}

function flattenInstallPayload(value: unknown): InstallResolution {
  const payload = asRecord(value);
  if (!payload) return {};

  const host = asRecord(payload.host);
  const source = asRecord(payload.source);
  const verification = asRecord(payload.verification);
  const resolution: InstallResolution = {};
  const fields: Array<[string, unknown]> = [
    ["stage", payload.stage ?? payload.status],
    ["display_name", payload.display_name],
    ["canonical_id", payload.canonical_id],
    ["target_kind", payload.target_kind],
    ["platform", host?.platform],
    ["architecture", host?.architecture],
    ["source_kind", source?.source_kind],
    ["manager", source?.manager],
    ["package_id", source?.package_id],
    ["installer_url", source?.installer_url],
    ["source_discovery_url", source?.source_discovery_url],
    ["requires_elevation", boolText(payload.requires_elevation)],
    ["command", Array.isArray(payload.command) ? payload.command.join(" ") : payload.command],
    ["verification", verification?.summary ?? payload.verification],
    ["plan_ref", payload.plan_ref],
    ["blocker", payload.blocker],
    ["failure_class", payload.failure_class],
  ];

  for (const [key, raw] of fields) {
    const valueText = asText(raw);
    if (valueText) {
      resolution[key] = valueText;
    }
  }
  return resolution;
}

function resolutionFromEvent(event: AgentEvent): InstallResolution {
  const details = asRecord(event.details);
  if (!details) return {};
  const resolution: InstallResolution = {};
  mergeResolution(resolution, flattenInstallPayload(details.install_resolution));
  mergeResolution(resolution, flattenInstallPayload(details.install_event));
  mergeResolution(resolution, flattenInstallPayload(details.install_final_receipt));
  const payload = asRecord(details.install_payload);
  if (payload) {
    mergeResolution(resolution, flattenInstallPayload(payload.install_event));
    mergeResolution(resolution, flattenInstallPayload(payload.install_final_receipt));
  }
  return resolution;
}

function resolutionFromTask(task: AgentTask | null | undefined): InstallResolution {
  const resolution: InstallResolution = {};
  for (const event of task?.events ?? []) {
    mergeResolution(resolution, resolutionFromEvent(event));
  }
  return resolution;
}

function installTargetLabel(
  task: AgentTask | null | undefined,
  resolution: InstallResolution,
): string | null {
  return asText(resolution.display_name) || asText(task?.gate_info?.target_label) || null;
}

function installRouteLabel(
  task: AgentTask | null | undefined,
  resolution: InstallResolution,
): string {
  const target = installTargetLabel(task, resolution);
  return target ? `Install ${target}` : "Software install";
}

function gateLooksLikeInstall(task: AgentTask | null | undefined): boolean {
  const gate = task?.gate_info;
  if (!gate) return false;
  if (!asText(gate.target_label)) return false;
  return (
    gate.title === "Approve software install" ||
    gate.scope_label === "Software install" ||
    gate.operation_label === "Install"
  );
}

function taskLooksLikeInstall(
  task: AgentTask | null | undefined,
  resolution: InstallResolution,
): boolean {
  if (!task) return false;
  if (Object.keys(resolution).length > 0) return true;
  if (gateLooksLikeInstall(task)) return true;
  return (task.events ?? []).some((event) => {
    const digest = asRecord(event.digest);
    const details = asRecord(event.details);
    const toolName = asText(digest?.tool_name) || asText(details?.tool_name);
    return Boolean(toolName && INSTALL_TOOL_NAMES.has(toolName));
  });
}

function transcriptStatus(task: AgentTask | null | undefined): InstallExecutionTranscript["status"] {
  switch (task?.phase) {
    case "Gate":
      return "blocked";
    case "Running":
      return "running";
    case "Complete":
      return "complete";
    case "Failed":
      return "failed";
    default:
      return "pending";
  }
}

function statusLabel(status: InstallExecutionTranscript["status"]): string {
  switch (status) {
    case "blocked":
      return "awaiting approval";
    case "running":
      return "running";
    case "complete":
      return "complete";
    case "failed":
      return "failed";
    default:
      return "pending";
  }
}

function appendResolutionLines(lines: string[], resolution: InstallResolution, task: AgentTask) {
  const displayName =
    resolution.display_name ||
    task.gate_info?.target_label ||
    task.intent ||
    "software";
  const platform = [resolution.platform, resolution.architecture]
    .filter(Boolean)
    .join(" ");
  const source = [resolution.source_kind, resolution.manager ? `via ${resolution.manager}` : ""]
    .filter(Boolean)
    .join(" ");

  addLine(lines, "$ software_install__resolve");
  addLine(lines, `target: ${displayName}`);
  addLine(lines, platform ? `host: ${platform}` : null);
  addLine(lines, source ? `source: ${source}` : null);
  addLine(lines, resolution.package_id ? `package/source: ${resolution.package_id}` : null);
  addLine(
    lines,
    resolution.source_discovery_url
      ? `discover: ${resolution.source_discovery_url}`
      : null,
  );
  addLine(lines, resolution.installer_url ? `installer: ${resolution.installer_url}` : null);
  addLine(lines, resolution.command ? `command: ${resolution.command}` : null);
  addLine(
    lines,
    resolution.requires_elevation
      ? `elevation: ${
          resolution.requires_elevation === "true" ? "required" : "not required"
        }`
      : null,
  );
  addLine(lines, resolution.verification ? `verify: ${resolution.verification}` : null);
  addLine(lines, resolution.blocker ? `blocker: ${resolution.blocker}` : null);
}

function appendGateLines(lines: string[], task: AgentTask) {
  const gate = task.gate_info;
  if (!gate || !gateLooksLikeInstall(task)) return;
  addLine(lines, "$ approval_gate");
  addLine(lines, gate.target_label ? `target: ${gate.target_label}` : null);
  addLine(lines, gate.surface_label ? `surface: ${gate.surface_label}` : null);
  addLine(lines, gate.scope_label ? `scope: ${gate.scope_label}` : null);
  addLine(lines, gate.description ? `plan: ${compactWhitespace(gate.description)}` : null);
}

function appendCommandEvents(lines: string[], events: AgentEvent[]) {
  const seen = new Set<string>();
  for (const event of events) {
    const kind = String(event.event_type || "").toLowerCase();
    const digest = asRecord(event.digest);
    const details = asRecord(event.details);
    const toolName = asText(digest?.tool_name);
    const commandPreview = asText(digest?.command_preview);
    const streamId = asText(digest?.stream_id);
    const channel = asText(digest?.channel) || "stdout";
    const output = asText(details?.output);
    const chunk = asText(details?.chunk);
    const isCommandStream = kind === "command_stream";
    const isCommandRun = kind === "command_run";

    if (!isCommandStream && !isCommandRun) continue;
    if (toolName && !INSTALL_TOOL_NAMES.has(toolName)) continue;
    if (isCommandRun) continue;

    const body = chunk || output;
    if (!body) continue;

    const commandLabel = commandPreview || toolName || streamId || "command";
    const key = `${kind}:${streamId || commandLabel}:${channel}:${body}`;
    if (seen.has(key)) continue;
    seen.add(key);

    addLine(lines, `$ ${commandLabel}`);
    for (const rawLine of body.split(/\r?\n/)) {
      const line = rawLine.trimEnd();
      if (line.trim()) {
        addLine(lines, isCommandStream ? `[${channel}] ${line}` : line);
      }
    }
  }
}

function appendReceiptEvents(lines: string[], events: AgentEvent[]) {
  const seen = new Set<string>();
  for (const event of events) {
    const kind = String(event.event_type || "").toLowerCase();
    if (kind !== "receipt") continue;
    const digest = asRecord(event.digest);
    const details = asRecord(event.details);
    const payload = asRecord(details?.payload);
    const toolName = asText(digest?.tool_name) || asText(payload?.tool_name);
    if (!toolName || !INSTALL_TOOL_NAMES.has(toolName)) continue;

    const commandPreview = asText(digest?.command_preview) || asText(payload?.command_preview);
    const success = digest?.success;
    const exitCode = digest?.exit_code;
    const errorClass = asText(digest?.error_class) || asText(payload?.error_class);
    const summary =
      asText(details?.summary) ||
      asText(digest?.summary) ||
      asText(event.title) ||
      "Install receipt";
    const key = [
      toolName,
      commandPreview || "",
      String(success ?? ""),
      String(exitCode ?? ""),
      errorClass || "",
      summary,
    ].join("|");
    if (seen.has(key)) continue;
    seen.add(key);

    addLine(lines, `$ ${toolName}`);
    addLine(lines, commandPreview ? `command: ${commandPreview}` : null);
    addLine(lines, `receipt: ${compactWhitespace(summary)}`);
    if (typeof success === "boolean") {
      addLine(lines, `success: ${success ? "true" : "false"}`);
    }
    if (typeof exitCode === "number") {
      addLine(lines, `exit_code: ${exitCode}`);
    }
    addLine(lines, errorClass ? `error_class: ${errorClass}` : null);
  }
}

function clampLines(lines: string[]): string[] {
  const deduped: string[] = [];
  const seen = new Set<string>();
  for (const line of lines) {
    const key = line.trim();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    deduped.push(line);
  }

  const clipped = deduped.slice(-MAX_TRANSCRIPT_LINES);
  const content = clipped.join("\n");
  if (content.length <= MAX_TRANSCRIPT_CHARS) {
    return clipped;
  }

  const tail = content.slice(-MAX_TRANSCRIPT_CHARS);
  return [`... trimmed earlier output ...`, ...tail.split("\n").slice(1)];
}

export function buildInstallExecutionTranscript(
  task: AgentTask | null | undefined,
): InstallExecutionTranscript | null {
  const resolution = resolutionFromTask(task);
  if (!taskLooksLikeInstall(task, resolution) || !task) {
    return null;
  }

  const status = transcriptStatus(task);
  const lines: string[] = [];
  const routeLabel = installRouteLabel(task, resolution);
  addLine(lines, `# ${routeLabel.toLowerCase()}: ${statusLabel(status)}`);

  if (Object.keys(resolution).length > 0) {
    appendResolutionLines(lines, resolution, task);
  }
  appendGateLines(lines, task);
  appendCommandEvents(lines, task.events ?? []);
  appendReceiptEvents(lines, task.events ?? []);

  const clamped = clampLines(lines);
  return {
    isInstallWorkflow: true,
    title: routeLabel,
    status,
    content: clamped.join("\n"),
    lineCount: clamped.length,
  };
}

export const testOnlyInstallExecutionTranscript = {
  flattenInstallPayload,
};
