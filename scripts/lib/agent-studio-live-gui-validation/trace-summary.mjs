import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
import { basename, join } from "node:path";

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function parseMaybeJson(value) {
  if (typeof value !== "string") return value;
  const trimmed = value.trim();
  if (!trimmed || !["{", "["].includes(trimmed[0])) return value;
  try {
    return JSON.parse(trimmed);
  } catch {
    return value;
  }
}

function traceObject(value) {
  const parsed = parseMaybeJson(value);
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
}

function traceKernelEventObjects(event) {
  const data = event?.data && typeof event.data === "object" ? event.data : {};
  const candidates = [
    data.kernel_event,
    data.kernelEvent,
    data.payload_summary?.kernel_event,
    data.payloadSummary?.kernelEvent,
    event?.payload_summary?.kernel_event,
    event?.payloadSummary?.kernelEvent,
    event?.payload?.kernel_event,
    event?.payload?.kernelEvent,
  ];
  return candidates.map(traceObject).filter(Boolean);
}

function traceRoutingReceipts(event) {
  const receipts = [];
  for (const kernelEvent of traceKernelEventObjects(event)) {
    const routing = traceObject(kernelEvent.RoutingReceipt) || kernelEvent.RoutingReceipt;
    if (routing && typeof routing === "object" && !Array.isArray(routing)) {
      receipts.push(routing);
    }
  }
  return receipts;
}

function actualTraceToolNames(event, toolNamePattern) {
  const names = new Set();
  const data = event?.data && typeof event.data === "object" ? event.data : {};
  const addToolNames = (value) => {
    if (typeof value !== "string") return;
    if (toolNamePattern.test(value)) names.add(value);
    toolNamePattern.lastIndex = 0;
  };
  const addToolNamesFromActionJson = (value) => {
    const parsed = parseMaybeJson(value);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
    addToolNames(parsed.name);
    addToolNames(parsed.tool_name);
    addToolNames(parsed.toolName);
    addToolNames(parsed.tool_normalization?.normalized_name);
    addToolNames(parsed.tool_normalization?.raw_name);
  };

  for (const key of ["tool_name", "toolName", "tool"]) {
    addToolNames(data[key]);
  }
  for (const source of [event, event?.payload, event?.payload_summary, event?.payloadSummary]) {
    if (!source || typeof source !== "object") continue;
    addToolNames(source.tool_name);
    addToolNames(source.toolName);
    addToolNames(source.tool);
    addToolNamesFromActionJson(source.action_json);
    addToolNamesFromActionJson(source.actionJson);
  }
  for (const kernelEvent of traceKernelEventObjects(event)) {
    addToolNames(kernelEvent?.AgentActionResult?.tool_name);
    addToolNames(kernelEvent?.RoutingReceipt?.tool_name);
    addToolNames(kernelEvent?.WorkloadReceipt?.tool_name);
    addToolNames(kernelEvent?.WorkloadReceipt?.receipt?.Exec?.tool_name);
    addToolNamesFromActionJson(kernelEvent?.RoutingReceipt?.action_json);
    addToolNamesFromActionJson(kernelEvent?.RoutingReceipt?.actionJson);
  }
  for (const receipt of traceRoutingReceipts(event)) {
    addToolNames(receipt.tool_name);
    addToolNames(receipt.toolName);
    addToolNamesFromActionJson(receipt.action_json);
    addToolNamesFromActionJson(receipt.actionJson);
  }
  return [...names];
}

export function collectDaemonRuntimeTraceSummary({ daemonStateDir, outputDir, repoRoot = process.cwd() }) {
  const artifactsDir = join(daemonStateDir, "artifacts");
  const traceOutputDir = join(outputDir, "daemon-runtime-traces");
  ensureDir(traceOutputDir);
  const traceFiles = existsSync(artifactsDir)
    ? readdirSync(artifactsDir).filter((file) => file.endsWith("_trace_json.json")).sort()
    : [];
  const summaries = [];
  const observedToolNames = new Set();
  const completedToolNames = new Set();
  const failedToolNames = new Set();
  const observedEventKinds = new Set();
  const toolCompletions = [];
  const toolFailures = [];
  const toolNamePattern = /\b(?:screen|[a-z][a-z0-9_]*(?:__[a-z0-9_]+)+|computer_use\.[a-z0-9_]+)\b/g;

  for (const file of traceFiles) {
    const sourcePath = join(artifactsDir, file);
    let artifact;
    try {
      artifact = JSON.parse(readFileSync(sourcePath, "utf8"));
    } catch {
      continue;
    }
    let trace = null;
    try {
      trace = typeof artifact.content === "string" ? JSON.parse(artifact.content) : artifact.content;
    } catch {
      trace = null;
    }
    const events = Array.isArray(trace?.events) ? trace.events : [];
    const prompt = events
      .map((event) => event?.data?.prompt)
      .find((value) => typeof value === "string" && value.trim());
    for (const event of events) {
      const eventKind = event?.data?.event_kind || event?.data?.eventKind || event?.type;
      if (eventKind) observedEventKinds.add(String(eventKind));
      const eventToolNames = actualTraceToolNames(event, toolNamePattern);
      for (const toolName of eventToolNames) {
        observedToolNames.add(toolName);
      }
      const runtimeEventKind = String(event?.data?.runtimeEventKind || event?.data?.runtime_event_kind || "");
      const eventType = String(event?.type || "");
      const isToolCompleted = eventType === "tool_completed" || runtimeEventKind === "tool.completed";
      const isToolFailed = eventType === "tool_failed" || runtimeEventKind === "tool.failed";
      const routingReceipts = traceRoutingReceipts(event);
      const routingSucceeded = routingReceipts.some((receipt) => receipt?.post_state?.success === true);
      const routingFailed = routingReceipts.some(
        (receipt) => receipt?.post_state?.success === false || receipt?.failure_class_name,
      );
      if (isToolCompleted || routingSucceeded) {
        for (const toolName of eventToolNames) {
          completedToolNames.add(toolName);
          toolCompletions.push({
            file,
            toolName,
            output: String(event?.data?.output || event?.data?.raw_output || event?.data?.message || "").slice(0, 1000),
          });
        }
      }
      if (isToolFailed || routingFailed) {
        for (const toolName of eventToolNames) {
          failedToolNames.add(toolName);
          toolFailures.push({
            file,
            toolName,
            errorClass:
              event?.data?.error_class ||
              event?.data?.errorClass ||
              routingReceipts.find((receipt) => receipt?.failure_class_name)?.failure_class_name ||
              null,
            output: String(event?.data?.output || event?.data?.raw_output || event?.data?.message || "").slice(0, 1000),
          });
        }
      }
    }
    const parsedTracePath = join(traceOutputDir, basename(file).replace(/_trace_json\.json$/, ".parsed-trace.json"));
    writeFileSync(parsedTracePath, `${JSON.stringify(trace || artifact, null, 2)}\n`);
    summaries.push({
      file,
      runId: artifact.runId || trace?.runId || null,
      prompt: prompt || null,
      eventCount: events.length,
      toolNames: [...new Set(events.flatMap((event) => actualTraceToolNames(event, toolNamePattern)))].sort(),
      eventKinds: [...new Set(events.map((event) => event?.data?.event_kind || event?.data?.eventKind || event?.type).filter(Boolean))].sort(),
      parsedTracePath: parsedTracePath.replace(repoRoot + "/", ""),
    });
  }

  const eventLogDir = join(daemonStateDir, "events");
  const eventLogFiles = existsSync(eventLogDir)
    ? readdirSync(eventLogDir).filter((file) => file.endsWith(".jsonl")).sort()
    : [];
  const eventLogSummaries = [];
  for (const file of eventLogFiles) {
    const sourcePath = join(eventLogDir, file);
    const lines = readFileSync(sourcePath, "utf8")
      .split(/\r?\n/)
      .filter((line) => line.trim());
    let eventCount = 0;
    const fileToolNames = new Set();
    const fileEventKinds = new Set();
    for (const line of lines) {
      let event;
      try {
        event = JSON.parse(line);
      } catch {
        continue;
      }
      eventCount += 1;
      const eventKind =
        event?.event_kind ||
        event?.eventKind ||
        event?.payload?.event_kind ||
        event?.payloadSummary?.event_kind ||
        event?.payload_summary?.event_kind ||
        event?.type;
      if (eventKind) {
        observedEventKinds.add(String(eventKind));
        fileEventKinds.add(String(eventKind));
      }
      const eventToolNames = actualTraceToolNames(event, toolNamePattern);
      for (const toolName of eventToolNames) {
        observedToolNames.add(toolName);
        fileToolNames.add(toolName);
      }
      const routingReceipts = traceRoutingReceipts(event);
      const routingSucceeded = routingReceipts.some((receipt) => receipt?.post_state?.success === true);
      const routingFailed = routingReceipts.some(
        (receipt) => receipt?.post_state?.success === false || receipt?.failure_class_name,
      );
      const isToolCompleted = eventKind === "tool.completed" || routingSucceeded;
      const isToolFailed = eventKind === "tool.failed" || routingFailed;
      if (isToolCompleted || routingSucceeded) {
        for (const toolName of eventToolNames) {
          completedToolNames.add(toolName);
          toolCompletions.push({
            file,
            toolName,
            output: String(event?.payload?.output || event?.payload_summary?.output || event?.payloadSummary?.output || "").slice(0, 1000),
          });
        }
      }
      if (isToolFailed) {
        for (const toolName of eventToolNames) {
          failedToolNames.add(toolName);
          toolFailures.push({
            file,
            toolName,
            errorClass:
              event?.payload?.error_class ||
              event?.payload_summary?.error_class ||
              event?.payloadSummary?.errorClass ||
              routingReceipts.find((receipt) => receipt?.failure_class_name)?.failure_class_name ||
              null,
            output: String(event?.payload?.output || event?.payload_summary?.output || event?.payloadSummary?.output || "").slice(0, 1000),
          });
        }
      }
    }
    eventLogSummaries.push({
      file,
      eventCount,
      toolNames: [...fileToolNames].sort(),
      eventKinds: [...fileEventKinds].sort(),
    });
  }

  const summary = {
    schemaVersion: "ioi.autopilot-agent-studio.daemon-runtime-trace-summary.v1",
    daemonStateDir,
    traceCount: summaries.length,
    observedToolNames: [...observedToolNames].sort(),
    completedToolNames: [...completedToolNames].sort(),
    failedToolNames: [...failedToolNames].sort(),
    observedEventKinds: [...observedEventKinds].sort(),
    toolCompletions,
    toolFailures,
    traces: summaries,
    eventLogs: eventLogSummaries,
  };
  writeFileSync(join(outputDir, "daemon-runtime-trace-summary.json"), `${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

export function collectDaemonRuntimeTraceSummaryBestEffort({ daemonStateDir, outputDir, label, repoRoot = process.cwd() }) {
  try {
    return collectDaemonRuntimeTraceSummary({ daemonStateDir, outputDir, repoRoot });
  } catch (error) {
    writeFileSync(
      join(outputDir, `daemon-runtime-trace-summary-${label || "best-effort"}-error.json`),
      `${JSON.stringify({
        label,
        error: String(error?.stack || error?.message || error),
        timestamp: new Date().toISOString(),
      }, null, 2)}\n`,
    );
    return null;
  }
}
