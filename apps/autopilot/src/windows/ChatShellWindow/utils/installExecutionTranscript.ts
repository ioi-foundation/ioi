import type { AgentEvent, AgentTask, ChatMessage } from "../../../types";

export type InstallExecutionTranscript = {
  isInstallWorkflow: boolean;
  title: string;
  status: "pending" | "blocked" | "running" | "complete" | "failed";
  content: string;
  lineCount: number;
};

type InstallResolution = Record<string, string>;

const SOFTWARE_INSTALL_PATTERN = /software_install\.([a-zA-Z0-9_]+)=([^,\]\n]+)/g;
const SOFTWARE_INSTALL_BLOCK_PATTERN = /\bSOFTWARE_INSTALL\s+([^\n]+)/g;
const SOFTWARE_INSTALL_FIELD_PATTERN = /\b([a-zA-Z0-9_]+)='([^']*)'/g;
const MAX_TRANSCRIPT_LINES = 96;
const MAX_TRANSCRIPT_CHARS = 10000;

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

function parseInstallResolutionFromText(text: string): InstallResolution {
  const resolution: InstallResolution = {};
  for (const match of text.matchAll(SOFTWARE_INSTALL_PATTERN)) {
    const key = match[1]?.trim();
    const value = match[2]?.trim();
    if (key && value) {
      resolution[key] = value;
    }
  }
  for (const blockMatch of text.matchAll(SOFTWARE_INSTALL_BLOCK_PATTERN)) {
    const fields = blockMatch[1] || "";
    for (const fieldMatch of fields.matchAll(SOFTWARE_INSTALL_FIELD_PATTERN)) {
      const key = fieldMatch[1]?.trim();
      const value = fieldMatch[2]?.trim();
      if (key && value) {
        resolution[key] = value;
      }
    }
  }
  return resolution;
}

function mergeResolution(target: InstallResolution, source: InstallResolution) {
  const sourceStage = String(source.stage || "").trim().toLowerCase();
  const sourceAlreadySatisfied =
    sourceStage === "already_installed" || sourceStage === "already_available";
  for (const [key, value] of Object.entries(source)) {
    if (value.trim()) {
      target[key] = value.trim();
    }
  }
  if (sourceAlreadySatisfied) {
    delete target.blocker;
  }
}

function eventText(event: AgentEvent): string {
  return [
    event.title,
    asText(event.digest?.summary),
    asText(event.details?.summary),
    asText(event.details?.receipt_summary),
    asText(event.details?.output),
    asText(event.details?.chunk),
  ]
    .filter(Boolean)
    .join("\n");
}

function resolutionFromTask(task: AgentTask | null | undefined): InstallResolution {
  const resolution: InstallResolution = {};
  for (const message of task?.history ?? []) {
    mergeResolution(resolution, parseInstallResolutionFromText(message.text || ""));
  }
  for (const event of task?.events ?? []) {
    mergeResolution(resolution, parseInstallResolutionFromText(eventText(event)));
  }
  return resolution;
}

function taskHasInstallRouteEvidence(task: AgentTask | null | undefined): boolean {
  const evidence = [
    ...(task?.chat_outcome?.decisionEvidence ?? []),
    ...(task?.chat_session?.outcomeRequest?.decisionEvidence ?? []),
  ].map((entry) => entry.trim());
  return evidence.some(
    (entry) =>
      entry === "local_install_requested" ||
      entry === "desktop_app_install_requested" ||
      entry === "software_install_capability_required",
  );
}

function installEvidenceValue(
  task: AgentTask | null | undefined,
  prefix: string,
): string | null {
  const evidence = [
    ...(task?.chat_outcome?.decisionEvidence ?? []),
    ...(task?.chat_session?.outcomeRequest?.decisionEvidence ?? []),
  ];
  for (const entry of evidence) {
    const trimmed = entry.trim();
    if (!trimmed.startsWith(prefix)) {
      continue;
    }
    const value = trimmed.slice(prefix.length).trim();
    if (value) {
      return value;
    }
  }
  return null;
}

function installTargetLabel(
  task: AgentTask | null | undefined,
  resolution: InstallResolution,
): string | null {
  return (
    asText(resolution.display_name) ||
    asText(task?.gate_info?.target_label) ||
    installEvidenceValue(task, "software_install_target_text:") ||
    null
  );
}

function installRouteLabel(
  task: AgentTask | null | undefined,
  resolution: InstallResolution,
): string {
  const target = installTargetLabel(task, resolution);
  return target ? `Install ${target}` : "Local software install";
}

function taskLooksLikeInstall(
  task: AgentTask | null | undefined,
  resolution: InstallResolution,
): boolean {
  if (!task) return false;
  if (Object.keys(resolution).length > 0) return true;
  if (taskHasInstallRouteEvidence(task) && task.gate_info) {
    return true;
  }
  if (
    taskHasInstallRouteEvidence(task) &&
    task.phase === "Failed" &&
    (String(task.current_step || "").includes("SOFTWARE_INSTALL") ||
      String(task.current_step || "").includes("ERROR_CLASS=InstallerResolutionRequired"))
  ) {
    return true;
  }
  const historyText = (task.history ?? [])
    .map((message) => message.text || "")
    .join("\n")
    .toLowerCase();
  if (
    historyText.includes("software_install__execute_plan") ||
    historyText.includes("software_install.") ||
    historyText.includes("software_install ") ||
    historyText.includes("error_class=installerresolutionrequired")
  ) {
    return true;
  }
  return (task.events ?? []).some((event) => {
    const text = eventText(event).toLowerCase();
    return (
      text.includes("software_install__execute_plan") ||
      text.includes("software_install.") ||
      text.includes("software_install ") ||
      text.includes("error_class=installerresolutionrequired")
    );
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

  addLine(lines, "$ software_install__execute_plan");
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
  if (resolution.requires_elevation) {
    addLine(
      lines,
      `elevation: ${
        resolution.requires_elevation === "true" ? "required" : "not required"
      }`,
    );
  }
  addLine(lines, resolution.verification ? `verify: ${resolution.verification}` : null);
  const stage = String(resolution.stage || "").trim().toLowerCase();
  const alreadySatisfied =
    stage === "already_installed" || stage === "already_available";
  addLine(lines, !alreadySatisfied && resolution.blocker ? `blocker: ${resolution.blocker}` : null);
}

function appendGateFallbackLines(lines: string[], task: AgentTask) {
  const gate = task.gate_info;
  if (!gate) return;
  addLine(lines, "$ software_install__execute_plan");
  addLine(lines, gate.target_label ? `target: ${gate.target_label}` : null);
  addLine(lines, gate.surface_label ? `surface: ${gate.surface_label}` : null);
  addLine(lines, gate.scope_label ? `scope: ${gate.scope_label}` : null);
  addLine(lines, gate.operation_label ? `operation: ${gate.operation_label}` : null);
  addLine(lines, gate.description ? `plan: ${compactWhitespace(gate.description)}` : null);
}

function appendCommandEvents(lines: string[], events: AgentEvent[]) {
  const seen = new Set<string>();
  for (const event of events) {
    const kind = String(event.event_type || "").toLowerCase();
    const digestTool = asText(event.digest?.tool_name);
    const commandPreview = asText(event.digest?.command_preview);
    const streamId = asText(event.digest?.stream_id);
    const channel = asText(event.digest?.channel) || "stdout";
    const output = asText(event.details?.output);
    const chunk = asText(event.details?.chunk);
    const isCommandStream = kind === "command_stream";
    const isCommandRun = kind === "command_run";

    if (!isCommandStream && !isCommandRun) {
      continue;
    }

    const body = chunk || output;
    if (!body) {
      continue;
    }

    const commandLabel = commandPreview || digestTool || streamId || "command";
    const key = `${kind}:${streamId || commandLabel}:${channel}:${body}`;
    if (seen.has(key)) {
      continue;
    }
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
    if (kind !== "receipt") {
      continue;
    }
    const digest = asRecord(event.digest);
    const details = asRecord(event.details);
    const payload = asRecord(details?.payload);
    const toolName = asText(digest?.tool_name) || asText(payload?.tool_name);
    const commandPreview = asText(digest?.command_preview) || asText(payload?.command_preview);
    const isInstallReceipt =
      toolName === "software_install__execute_plan" ||
      eventText(event).includes("software_install.");
    if (!isInstallReceipt) {
      continue;
    }

    const success = digest?.success;
    const exitCode = digest?.exit_code;
    const errorClass = asText(digest?.error_class) || asText(payload?.error_class);
    const summary =
      asText(details?.summary) ||
      asText(digest?.summary) ||
      asText(event.title) ||
      "Install receipt";
    const key = [
      toolName || "install",
      commandPreview || "",
      String(success ?? ""),
      String(exitCode ?? ""),
      errorClass || "",
      summary,
    ].join("|");
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);

    addLine(lines, `$ ${toolName || "software_install__execute_plan"}`);
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

function appendToolHistory(lines: string[], history: ChatMessage[]) {
  for (const message of history) {
    if (message.role !== "tool") {
      continue;
    }
    const text = message.text || "";
    if (!text.trim()) {
      continue;
    }
    addLine(lines, text.replace(/^Tool Output \(([^)]+)\):\s*/, "$ $1\n"));
  }
}

function installFailureText(task: AgentTask): string | null {
  const candidates = [
    task.current_step,
    ...(task.history ?? []).map((message) => message.text),
  ];
  for (const candidate of candidates) {
    const text = asText(candidate);
    if (!text) {
      continue;
    }
    if (
      text.includes("ERROR_CLASS=InstallerResolutionRequired") ||
      text.includes("SOFTWARE_INSTALL")
    ) {
      return compactWhitespace(text.replace(/^Task failed:\s*/i, ""));
    }
  }
  return null;
}

function appendTaskFailure(lines: string[], task: AgentTask) {
  const failure = installFailureText(task);
  if (!failure) {
    return;
  }
  addLine(lines, `failure: ${failure}`);
  const errorClass = failure.match(/\bERROR_CLASS=([A-Za-z0-9_]+)/)?.[1];
  addLine(lines, errorClass ? `error_class: ${errorClass}` : null);
}

function clampLines(lines: string[]): string[] {
  const deduped: string[] = [];
  const seen = new Set<string>();
  for (const line of lines) {
    const key = line.trim();
    if (!key || seen.has(key)) {
      continue;
    }
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
  } else {
    appendGateFallbackLines(lines, task);
  }

  appendCommandEvents(lines, task.events ?? []);
  appendReceiptEvents(lines, task.events ?? []);
  appendToolHistory(lines, task.history ?? []);
  appendTaskFailure(lines, task);

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
  parseInstallResolutionFromText,
};
