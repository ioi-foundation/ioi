import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "../../..");

const playbookPath = path.join(repoRoot, "docs/computer-use-playbook-spec.md");
const discoveryPath = path.join(
  repoRoot,
  "docs/computer-use-live-discovery-plan.md",
);
const diagnosticsRoot = path.join(
  repoRoot,
  "crates/cli/target/computer_use_suite",
);
const benchmarkStorePath = path.join(
  repoRoot,
  "apps/benchmarks/src/generated/benchmark-store.json",
);
const outputPaths = [
  path.join(repoRoot, "apps/benchmarks/src/generated/benchmark-data.json"),
  path.join(repoRoot, "apps/benchmarks/public/generated/benchmark-data.json"),
];
const liveDataPath = "/generated/benchmark-data.json";

const DISCOVERY_PLAIN_HEADINGS = [
  "Current frontier:",
  "Current blocker:",
  "Decision rule:",
];

const TRACE_LANE_ORDER = [
  "case",
  "runtime",
  "browser",
  "executor",
  "inference",
  "step",
  "receipt",
  "bridge",
];
const REWARD_FLOOR_EPSILON = 1e-4;

function writeOutputFiles(payload) {
  const encoded = JSON.stringify(payload, null, 2);
  for (const targetPath of outputPaths) {
    fs.mkdirSync(path.dirname(targetPath), { recursive: true });
    const tempPath = path.join(
      path.dirname(targetPath),
      `.${path.basename(targetPath)}.${process.pid}.${Date.now()}.tmp`,
    );
    fs.writeFileSync(tempPath, encoded);
    fs.renameSync(tempPath, targetPath);
  }
}

function readText(targetPath) {
  return fs.existsSync(targetPath) ? fs.readFileSync(targetPath, "utf8") : "";
}

function readJson(targetPath, fallback) {
  if (!targetPath || !fs.existsSync(targetPath)) {
    return fallback;
  }
  try {
    return JSON.parse(fs.readFileSync(targetPath, "utf8"));
  } catch {
    return fallback;
  }
}

function toFileHref(targetPath) {
  if (!targetPath || !fs.existsSync(targetPath)) {
    return "";
  }
  return `file://${targetPath}`;
}

function compactText(value, limit = 280) {
  if (!value) {
    return "";
  }
  const text = String(value).replace(/\s+/g, " ").trim();
  if (text.length <= limit) {
    return text;
  }
  return `${text.slice(0, limit - 3)}...`;
}

function summarizeDelta(delta, limit = 6, itemLimit = 160) {
  return {
    added: Array.isArray(delta?.added)
      ? delta.added.slice(0, limit).map((value) => compactText(value, itemLimit))
      : [],
    removed: Array.isArray(delta?.removed)
      ? delta.removed.slice(0, limit).map((value) => compactText(value, itemLimit))
      : [],
    changed: Array.isArray(delta?.changed)
      ? delta.changed.slice(0, limit).map((value) => compactText(value, itemLimit))
      : [],
  };
}

function summarizeExecutionReceipts(receipts) {
  if (!Array.isArray(receipts)) {
    return [];
  }

  const seen = new Set();
  const entries = [];
  for (const receipt of receipts) {
    if (!receipt || typeof receipt !== "object") {
      continue;
    }
    const parts = [];
    if (typeof receipt.stage === "string" && receipt.stage.trim()) {
      parts.push(receipt.stage.trim());
    }
    if (typeof receipt.key === "string" && receipt.key.trim()) {
      parts.push(receipt.key.trim());
    }
    if (parts.length === 0) {
      continue;
    }
    const label = parts.join(":");
    if (seen.has(label)) {
      continue;
    }
    seen.add(label);
    entries.push(label);
    if (entries.length >= 8) {
      break;
    }
  }
  return entries;
}

function findSectionStart(lines, heading) {
  return lines.findIndex((line) => line.trim() === heading);
}

function extractSection(markdown, heading, stopHeadings = []) {
  const lines = markdown.split(/\r?\n/);
  const startIndex = findSectionStart(lines, heading);
  if (startIndex === -1) {
    return "";
  }

  const stopSet = new Set(stopHeadings);
  const collected = [];
  for (let index = startIndex + 1; index < lines.length; index += 1) {
    const trimmed = lines[index].trim();
    if (trimmed) {
      if (/^##\s+/.test(trimmed)) {
        break;
      }
      if (stopSet.has(trimmed)) {
        break;
      }
    }
    collected.push(lines[index]);
  }
  return collected.join("\n").trim();
}

function extractPromptSection(rawText, heading, stopHeadings = []) {
  const lines = String(rawText || "").split(/\r?\n/);
  const startIndex = findSectionStart(lines, heading);
  if (startIndex === -1) {
    return "";
  }

  const stopSet = new Set(stopHeadings);
  const collected = [];
  for (let index = startIndex + 1; index < lines.length; index += 1) {
    const trimmed = lines[index].trim();
    if (trimmed && stopSet.has(trimmed)) {
      break;
    }
    collected.push(lines[index]);
  }
  return collected.join("\n").trim();
}

function extractBulletsFromSection(section) {
  const bullets = [];
  let current = "";

  for (const line of section.split(/\r?\n/)) {
    const bulletMatch = line.match(/^\s*-\s+(.*)$/);
    if (bulletMatch) {
      if (current) {
        bullets.push(current.trim());
      }
      current = bulletMatch[1].trim();
      continue;
    }

    if (current && /^\s{2,}\S/.test(line)) {
      current = `${current} ${line.trim()}`;
    }
  }

  if (current) {
    bullets.push(current.trim());
  }

  return bullets;
}

function extractBulletLines(markdown, heading, stopHeadings = []) {
  return extractBulletsFromSection(extractSection(markdown, heading, stopHeadings));
}

function parseTable(section) {
  const lines = section
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith("|"));
  if (lines.length < 3) {
    return [];
  }

  const headers = lines[0]
    .split("|")
    .slice(1, -1)
    .map((cell) => cell.trim());

  return lines.slice(2).map((line) => {
    const cells = line
      .split("|")
      .slice(1, -1)
      .map((cell) => cell.trim());
    return Object.fromEntries(
      headers.map((header, index) => [header, cells[index] ?? ""]),
    );
  });
}

function parseTableFromSection(markdown, heading, stopHeadings = []) {
  return parseTable(extractSection(markdown, heading, stopHeadings));
}

function extractCodeBlock(markdown, heading, stopHeadings = []) {
  const section = extractSection(markdown, heading, stopHeadings);
  const match = section.match(/```(?:\w+)?\n([\s\S]*?)```/);
  return match ? match[1].trim() : "";
}

function runSortValue(runId) {
  const numeric = Number.parseInt(String(runId).replace(/^run-/, ""), 10);
  if (!Number.isFinite(numeric)) {
    return 0;
  }
  // Older local runs used second-resolution ids while newer retained artifacts may
  // already be millisecond-resolution. Normalize both to a shared millisecond scale.
  return numeric < 1_000_000_000_000 ? numeric * 1000 : numeric;
}

function runFreshnessValue(runId, updatedAtMs) {
  return typeof updatedAtMs === "number" && Number.isFinite(updatedAtMs)
    ? updatedAtMs
    : runSortValue(runId);
}

function inferSuite(caseId) {
  if (caseId.startsWith("miniwob_")) {
    return "MiniWoB++";
  }
  if (caseId.startsWith("osworld_")) {
    return "OSWorld";
  }
  if (caseId.startsWith("workarena_")) {
    return "WorkArena";
  }
  return "Unknown";
}

function summaryEffectiveReward(summary) {
  if (typeof summary?.effective_reward === "number") {
    return summary.effective_reward;
  }
  if (typeof summary?.raw_reward === "number") {
    return summary.raw_reward;
  }
  return typeof summary?.reward === "number" ? summary.reward : null;
}

function summaryRewardFloorMet(summary) {
  if (typeof summary?.reward_floor_met === "boolean") {
    return summary.reward_floor_met;
  }
  const effectiveReward = summaryEffectiveReward(summary);
  if (effectiveReward == null) {
    return null;
  }
  const expectedRewardFloor =
    typeof summary?.expected_reward_floor === "number"
      ? summary.expected_reward_floor
      : 1;
  return effectiveReward + REWARD_FLOOR_EPSILON >= expectedRewardFloor;
}

function resultLabel(summary) {
  const effectiveReward = summaryEffectiveReward(summary);
  const rewardFloorMet = summaryRewardFloorMet(summary);
  if (effectiveReward === null) {
    return "unknown";
  }
  if (rewardFloorMet) {
    return "pass";
  }
  if (effectiveReward > 0) {
    return "near-miss";
  }
  return "red";
}

function summarizeBridgeEvent(event) {
  if (!event || typeof event !== "object") {
    return "";
  }
  const lastEvent = event.last_event && typeof event.last_event === "object"
    ? event.last_event
    : null;
  const target = lastEvent
    ? lastEvent.target_selector || lastEvent.target_id || lastEvent.target_tag
    : null;
  const coordinates = lastEvent &&
    typeof lastEvent.x === "number" &&
    typeof lastEvent.y === "number"
    ? ` at ${lastEvent.x},${lastEvent.y}`
    : "";
  const reward =
    typeof event.reward === "number" ? ` reward ${event.reward.toFixed(3)}` : "";
  return compactText(
    [
      event.trigger ? String(event.trigger) : null,
      typeof event.episode_step === "number"
        ? `episode ${event.episode_step}`
        : null,
      target ? `${String(lastEvent?.kind || "event")} ${String(target)}${coordinates}` : null,
      reward.trim(),
    ]
      .filter(Boolean)
      .join(" | "),
    180,
  );
}

function summarizeTargetIdentity(target) {
  if (!target || typeof target !== "object") {
    return "";
  }
  return compactText(
    [
      target.semantic_id,
      target.dom_id,
      target.selector,
      target.tag_name,
    ]
      .filter((value) => typeof value === "string" && value.trim())
      .join(" | "),
    140,
  );
}

function summarizeClickAttempt(attempt) {
  if (!attempt || typeof attempt !== "object") {
    return null;
  }
  return {
    attemptIndex:
      typeof attempt.attempt_index === "number" ? attempt.attempt_index : null,
    method: typeof attempt.method === "string" ? attempt.method : null,
    dispatchElapsedMs:
      typeof attempt.dispatch_elapsed_ms === "number"
        ? attempt.dispatch_elapsed_ms
        : null,
    verifyElapsedMs:
      typeof attempt.verify_elapsed_ms === "number" ? attempt.verify_elapsed_ms : null,
    settleMs: typeof attempt.settle_ms === "number" ? attempt.settle_ms : null,
    postconditionMet:
      typeof attempt?.postcondition?.met === "boolean"
        ? attempt.postcondition.met
        : null,
    targetDisappeared:
      typeof attempt?.postcondition?.target_disappeared === "boolean"
        ? attempt.postcondition.target_disappeared
        : null,
    treeChanged:
      typeof attempt?.postcondition?.tree_changed === "boolean"
        ? attempt.postcondition.tree_changed
        : null,
    semanticChangeDelta:
      typeof attempt?.postcondition?.semantic_change_delta === "number"
        ? attempt.postcondition.semantic_change_delta
        : null,
    target: summarizeTargetIdentity(attempt.post_target ?? attempt.pre_target ?? null),
  };
}

function summarizeDispatchFailure(entry) {
  if (!entry || typeof entry !== "object") {
    return null;
  }
  return {
    method: typeof entry.method === "string" ? entry.method : null,
    dispatchElapsedMs:
      typeof entry.dispatch_elapsed_ms === "number"
        ? entry.dispatch_elapsed_ms
        : null,
    error: compactText(entry.error ?? "", 180),
  };
}

function summarizeStep(step) {
  const verify =
    step?.action_click_detail?.verify &&
    typeof step.action_click_detail.verify === "object"
      ? step.action_click_detail.verify
      : null;
  const clickAttempts = [
    ...(Array.isArray(verify?.prior_attempts)
      ? verify.prior_attempts.map(summarizeClickAttempt)
      : []),
    ...(verify ? [summarizeClickAttempt(verify)] : []),
  ].filter(Boolean);
  const dispatchFailures = Array.isArray(verify?.prior_dispatch_failures)
    ? verify.prior_dispatch_failures
        .map(summarizeDispatchFailure)
        .filter(Boolean)
    : [];

  return {
    stepIndex: typeof step?.step_index === "number" ? step.step_index : null,
    chosenName: step?.chosen_name ?? null,
    chosenArguments:
      step?.chosen_arguments && typeof step.chosen_arguments === "object"
        ? step.chosen_arguments
        : null,
    requestedId: step?.requested_id ?? null,
    inferenceElapsedMs:
      typeof step?.inference_elapsed_ms === "number"
        ? step.inference_elapsed_ms
        : null,
    inferenceGapFromPreviousFinishMs:
      typeof step?.inference_gap_from_previous_finish_ms === "number"
        ? step.inference_gap_from_previous_finish_ms
        : null,
    actionErrorClass: step?.action_error_class ?? null,
    routingFailureClass: step?.routing_failure_class ?? null,
    routingSuccess: typeof step?.routing_success === "boolean" ? step.routing_success : null,
    targetMismatch: step?.target_mismatch ?? null,
    clickedSemanticId: step?.clicked_semantic_id ?? null,
    chosenTargets: Array.isArray(step?.chosen_targets)
      ? step.chosen_targets.filter((value) => typeof value === "string")
      : [],
    actionOutputSummary: compactText(step?.action_output_summary ?? "", 240),
    pendingState: compactText(step?.pending_state ?? "", 520),
    pendingTargets: Array.isArray(step?.pending_targets)
      ? step.pending_targets.filter((value) => typeof value === "string")
      : [],
    pendingAlignment: typeof step?.pending_alignment === "string"
      ? step.pending_alignment
      : null,
    successSignal: compactText(step?.success_signal ?? "", 520),
    successTargets: Array.isArray(step?.success_targets)
      ? step.success_targets.filter((value) => typeof value === "string")
      : [],
    successAlignment: typeof step?.success_alignment === "string"
      ? step.success_alignment
      : null,
    recentSessionEvents: compactText(step?.recent_session_events ?? "", 360),
    observationTargets: Array.isArray(step?.observation_targets)
      ? step.observation_targets.slice(0, 8).map((value) => compactText(value, 160))
      : [],
    observationDelta: summarizeDelta(step?.observation_delta),
    postActionObservationDelta: summarizeDelta(step?.post_action_observation_delta),
    postActionNewTargetTokens: Array.isArray(step?.post_action_new_target_tokens)
      ? step.post_action_new_target_tokens.filter((value) => typeof value === "string")
      : [],
    executionReceipts: summarizeExecutionReceipts(step?.execution_receipts),
    executionReceiptCount: Array.isArray(step?.execution_receipts)
      ? step.execution_receipts.length
      : 0,
    bridgeEvents: Array.isArray(step?.bridge_events)
      ? step.bridge_events
          .slice(0, 4)
          .map(summarizeBridgeEvent)
          .filter(Boolean)
      : [],
    clickDelivery:
      typeof step?.action_click_detail?.delivery === "string"
        ? step.action_click_detail.delivery
        : null,
    clickAttempts,
    dispatchFailures,
  };
}

function summarizePhaseTiming(phaseTiming) {
  if (!phaseTiming || typeof phaseTiming !== "object") {
    return {};
  }

  const keys = [
    "bootstrap_to_first_inference_start_ms",
    "bootstrap_to_first_grounded_target_ms",
    "first_inference_elapsed_ms",
    "first_receipt_to_first_grounded_target_ms",
    "first_grounded_target_to_terminal_ms",
    "terminal_to_step_finish_tail_ms",
  ];

  return Object.fromEntries(
    keys
      .filter((key) => typeof phaseTiming[key] === "number")
      .map((key) => [key, phaseTiming[key]]),
  );
}

function summarizeDiagnostic(diagnostic) {
  const phaseTiming = summarizePhaseTiming(diagnostic?.phase_timing);
  const timeline = Array.isArray(diagnostic?.timeline)
    ? diagnostic.timeline.slice(0, 8).map(summarizeStep)
    : [];
  return {
    phaseTiming,
    timeline,
  };
}

function normalizeTraceStatus(status) {
  if (typeof status !== "string" || !status.trim()) {
    return "unknown";
  }
  if (status === "near_miss") {
    return "near-miss";
  }
  return status.trim();
}

function summarizeTraceAttributes(attributes) {
  if (attributes == null) {
    return "";
  }
  if (typeof attributes !== "object") {
    return compactText(String(attributes), 220);
  }
  return compactText(JSON.stringify(attributes), 220);
}

function summarizeTraceArtifactLinks(refs) {
  if (!Array.isArray(refs)) {
    return [];
  }
  return refs
    .filter((value) => typeof value === "string" && value.trim())
    .slice(0, 4)
    .map((value) => ({
      label: path.basename(value),
      path: value,
      href: toFileHref(value),
    }))
    .filter((entry) => entry.href);
}

function buildTraceReplayFromBundle(traceBundle, summary) {
  if (!traceBundle || typeof traceBundle !== "object" || !Array.isArray(traceBundle.spans)) {
    return null;
  }

  const spans = traceBundle.spans
    .filter((span) => span && typeof span === "object" && typeof span.id === "string")
    .map((span) => {
      const status = span.id === "case"
        ? resultLabel(summary ?? traceBundle.summary ?? {})
        : normalizeTraceStatus(span.status);
      const summaryText = span.id === "case"
        ? compactText(
            `${(summary ?? traceBundle.summary ?? {})?.query_text ?? span.summary ?? "computer-use case"} | reward=${(summary ?? traceBundle.summary ?? {})?.reward ?? "?"} effective_reward=${summaryEffectiveReward(summary ?? traceBundle.summary ?? {}) ?? "?"} floor_met=${summaryRewardFloorMet(summary ?? traceBundle.summary ?? {}) ?? "?"}`,
            220,
          )
        : compactText(span.summary ?? "", 220);
      return {
        id: span.id,
        lane: typeof span.lane === "string" && span.lane.trim() ? span.lane : "trace",
        parentSpanId:
          typeof span.parent_span_id === "string" ? span.parent_span_id : null,
        stepIndex:
          typeof span.step_index === "number" ? span.step_index : null,
        status,
        summary: summaryText,
        startMs: typeof span.ts_start_ms === "number" ? span.ts_start_ms : null,
        endMs: typeof span.ts_end_ms === "number" ? span.ts_end_ms : null,
        durationMs:
          typeof span.duration_ms === "number"
            ? span.duration_ms
            : typeof span.ts_start_ms === "number" && typeof span.ts_end_ms === "number"
              ? Math.max(span.ts_end_ms - span.ts_start_ms, 0)
              : null,
        capabilityTags: Array.isArray(span.capability_tags)
          ? span.capability_tags.filter((value) => typeof value === "string").slice(0, 8)
          : [],
        attributesSummary: summarizeTraceAttributes(span.attributes),
        artifactLinks: summarizeTraceArtifactLinks(span.artifact_refs),
      };
    })
    .sort((left, right) => {
      const leftStart = left.startMs ?? Number.MAX_SAFE_INTEGER;
      const rightStart = right.startMs ?? Number.MAX_SAFE_INTEGER;
      return (
        TRACE_LANE_ORDER.indexOf(left.lane) - TRACE_LANE_ORDER.indexOf(right.lane) ||
        leftStart - rightStart ||
        left.id.localeCompare(right.id)
      );
    });

  const bookmarks = Array.isArray(traceBundle.bookmarks)
    ? traceBundle.bookmarks
        .filter((bookmark) => bookmark && typeof bookmark === "object")
        .map((bookmark) => ({
          id: typeof bookmark.id === "string" ? bookmark.id : "",
          label: typeof bookmark.label === "string" ? bookmark.label : "",
          spanId: typeof bookmark.span_id === "string" ? bookmark.span_id : "",
          kind: typeof bookmark.kind === "string" ? bookmark.kind : "bookmark",
        }))
        .filter((bookmark) => bookmark.id && bookmark.spanId)
        .slice(0, 10)
    : [];

  return finalizeTraceReplay({
    source: "trace_bundle",
    spans,
    bookmarks,
  });
}

function buildFallbackTraceReplay(summary, diagnostic) {
  const phaseTiming = diagnostic?.phase_timing && typeof diagnostic.phase_timing === "object"
    ? diagnostic.phase_timing
    : {};
  const spans = [];
  const bookmarks = [];

  const phaseStartKeys = [
    "browser_launch_started_at_ms",
    "browser_navigation_started_at_ms",
    "agent_start_service_started_at_ms",
    "first_step_service_started_at_ms",
    "first_inference_started_at_ms",
  ];
  const phaseEndKeys = [
    "browser_launch_finished_at_ms",
    "browser_navigation_finished_at_ms",
    "agent_start_service_finished_at_ms",
    "first_step_service_finished_at_ms",
    "first_inference_finished_at_ms",
    "case_finished_at_ms",
  ];
  const candidateStarts = phaseStartKeys
    .map((key) => phaseTiming[key])
    .filter((value) => typeof value === "number");
  const candidateEnds = phaseEndKeys
    .map((key) => phaseTiming[key])
    .filter((value) => typeof value === "number");

  spans.push({
    id: "case",
    lane: "case",
    parentSpanId: null,
    stepIndex: null,
    status: resultLabel(summary),
    summary: compactText(
      `${summary?.query_text ?? "computer-use case"} | reward=${summary?.reward ?? "?"} effective_reward=${summaryEffectiveReward(summary) ?? "?"} floor_met=${summaryRewardFloorMet(summary) ?? "?"}`,
      220,
    ),
    startMs: candidateStarts.length > 0 ? Math.min(...candidateStarts) : null,
    endMs: candidateEnds.length > 0 ? Math.max(...candidateEnds) : null,
    durationMs: null,
    capabilityTags: ["overall_case_outcome"],
    attributesSummary: "",
    artifactLinks: [],
  });

  for (const [id, label, lane, tags, startKey, endKey] of [
    ["phase:browser_launch", "Browser launch", "runtime", ["startup_latency"], "browser_launch_started_at_ms", "browser_launch_finished_at_ms"],
    ["phase:browser_navigation", "Browser navigation", "browser", ["bridge_sync_observability"], "browser_navigation_started_at_ms", "browser_navigation_finished_at_ms"],
    ["phase:agent_start_service", "Agent start service", "executor", ["execution_runtime"], "agent_start_service_started_at_ms", "agent_start_service_finished_at_ms"],
    ["phase:first_step_service", "First step service", "executor", ["execution_runtime"], "first_step_service_started_at_ms", "first_step_service_finished_at_ms"],
    ["phase:first_inference", "First inference", "inference", ["planning_contract"], "first_inference_started_at_ms", "first_inference_finished_at_ms"],
  ]) {
    const startMs = typeof phaseTiming[startKey] === "number" ? phaseTiming[startKey] : null;
    const endMs = typeof phaseTiming[endKey] === "number" ? phaseTiming[endKey] : startMs;
    if (startMs == null) {
      continue;
    }
    spans.push({
      id,
      lane,
      parentSpanId: "case",
      stepIndex: null,
      status: "completed",
      summary: label,
      startMs,
      endMs,
      durationMs: endMs == null ? null : Math.max(endMs - startMs, 0),
      capabilityTags: tags,
      attributesSummary: "source=diagnostic.phase_timing",
      artifactLinks: [],
    });
  }

  if (Array.isArray(diagnostic?.inference_calls)) {
    diagnostic.inference_calls.forEach((call, index) => {
      if (!call || typeof call !== "object") {
        return;
      }
      spans.push({
        id: `inference:${index}`,
        lane: "inference",
        parentSpanId: "case",
        stepIndex: null,
        status: "completed",
        summary: compactText(
          `${call.method ?? "inference"} ${call.output_utf8 ?? ""}`,
          220,
        ),
        startMs:
          typeof call.started_at_ms === "number" ? call.started_at_ms : null,
        endMs:
          typeof call.finished_at_ms === "number" ? call.finished_at_ms : null,
        durationMs:
          typeof call.elapsed_ms === "number" ? call.elapsed_ms : null,
        capabilityTags: ["planning_contract"],
        attributesSummary: summarizeTraceAttributes({
          tool_name: call.tool_name ?? null,
          elapsed_ms: call.elapsed_ms ?? null,
        }),
        artifactLinks: [],
      });
    });
  }

  if (Array.isArray(diagnostic?.timeline)) {
    diagnostic.timeline.forEach((step, index) => {
      if (!step || typeof step !== "object") {
        return;
      }
      const executionReceipts = Array.isArray(step.execution_receipts)
        ? step.execution_receipts
        : [];
      const receiptTimes = executionReceipts
        .map((receipt) => receipt?.timestamp_ms)
        .filter((value) => typeof value === "number");
      const startMs =
        typeof step.inference_started_at_ms === "number"
          ? step.inference_started_at_ms
          : receiptTimes[0] ?? null;
      const endMs = receiptTimes.length > 0
        ? receiptTimes[receiptTimes.length - 1]
        : typeof step.inference_finished_at_ms === "number"
          ? step.inference_finished_at_ms
          : startMs;
      spans.push({
        id: `step:${typeof step.step_index === "number" ? step.step_index : index}`,
        lane: "step",
        parentSpanId: "case",
        stepIndex:
          typeof step.step_index === "number" ? step.step_index : index,
        status:
          typeof step.action_error_class === "string" && step.action_error_class.trim()
            ? "failed"
            : typeof step.routing_failure_class === "string" &&
                step.routing_failure_class.trim()
              ? "failed"
              : "completed",
        summary: compactText(
          `${step.chosen_name ?? "step"} ${step.requested_id ?? ""}`,
          220,
        ),
        startMs,
        endMs,
        durationMs:
          startMs != null && endMs != null ? Math.max(endMs - startMs, 0) : null,
        capabilityTags: ["observation_surface", "verification_signal"],
        attributesSummary: summarizeTraceAttributes({
          action_error_class: step.action_error_class ?? null,
          routing_failure_class: step.routing_failure_class ?? null,
          observation_targets: Array.isArray(step.observation_targets)
            ? step.observation_targets.length
            : 0,
        }),
        artifactLinks: [],
      });
    });
  }

  if (Array.isArray(diagnostic?.execution_receipts)) {
    diagnostic.execution_receipts.forEach((receipt, index) => {
      if (!receipt || typeof receipt !== "object") {
        return;
      }
      const observed = receipt.observed_value && typeof receipt.observed_value === "object"
        ? receipt.observed_value
        : null;
      const startMs =
        typeof observed?.started_at_ms === "number"
          ? observed.started_at_ms
          : typeof receipt.timestamp_ms === "number"
            ? receipt.timestamp_ms
            : null;
      const endMs =
        typeof observed?.finished_at_ms === "number"
          ? observed.finished_at_ms
          : startMs;
      const key = typeof receipt.key === "string" ? receipt.key : `receipt-${index}`;
      spans.push({
        id: `receipt:${key}:${index}`,
        lane: "receipt",
        parentSpanId: "case",
        stepIndex:
          typeof receipt.step_index === "number" ? receipt.step_index : null,
        status: normalizeTraceStatus(
          observed?.status ??
            (receipt.satisfied === true ? "completed" : "failed"),
        ),
        summary: compactText(
          `${receipt.stage ?? "receipt"} ${key}`,
          220,
        ),
        startMs,
        endMs,
        durationMs:
          startMs != null && endMs != null ? Math.max(endMs - startMs, 0) : null,
        capabilityTags:
          key.includes("executor") || key.includes("action_complete")
            ? ["execution_runtime"]
            : key.includes("policy") || key.includes("determinism")
              ? ["planning_contract"]
              : ["verification_signal"],
        attributesSummary: summarizeTraceAttributes({
          probe_source: receipt.probe_source ?? null,
          observed_value: receipt.observed_value ?? null,
        }),
        artifactLinks: [],
      });
    });
  }

  if (Array.isArray(diagnostic?.sync_history)) {
    diagnostic.sync_history.forEach((sync) => {
      if (!sync || typeof sync !== "object") {
        return;
      }
      const syncIndex =
        typeof sync.sync_index === "number" ? sync.sync_index : 0;
      const ts = typeof sync.last_sync_ms === "number" ? sync.last_sync_ms : null;
      spans.push({
        id: `bridge_sync:${syncIndex}`,
        lane: "bridge",
        parentSpanId: "case",
        stepIndex:
          typeof sync.episode_step === "number" ? sync.episode_step : null,
        status: "observed",
        summary: compactText(
          `${sync.trigger ?? "sync"} reward=${sync.reward ?? 0} terminated=${sync.terminated ?? false}`,
          220,
        ),
        startMs: ts,
        endMs: ts,
        durationMs: 0,
        capabilityTags: ["bridge_sync_observability"],
        attributesSummary: summarizeTraceAttributes({
          visible_text_excerpt: sync.visible_text_excerpt ?? null,
        }),
        artifactLinks: [],
      });
    });
  }

  if (spans.some((span) => span.id === "inference:0")) {
    bookmarks.push({
      id: "first_inference",
      label: "First inference",
      spanId: "inference:0",
      kind: "milestone",
    });
  }
  const timeoutSpan = spans.find((span) => span.id.startsWith("receipt:service_executor_dispatch"));
  if (timeoutSpan) {
    bookmarks.push({
      id: "executor_timeout",
      label: "Executor dispatch",
      spanId: timeoutSpan.id,
      kind: timeoutSpan.status === "completed" ? "milestone" : "failure",
    });
  }
  const terminalSync = [...spans].reverse().find((span) => span.id.startsWith("bridge_sync:"));
  if (terminalSync) {
    bookmarks.push({
      id: "terminal_sync",
      label: "Terminal sync",
      spanId: terminalSync.id,
      kind: "milestone",
    });
  }
  bookmarks.push({
    id: "case_outcome",
    label: "Case outcome",
    spanId: "case",
    kind: "summary",
  });

  return finalizeTraceReplay({
    source: "diagnostic_fallback",
    spans,
    bookmarks,
  });
}

function finalizeTraceReplay({ source, spans, bookmarks }) {
  const normalizedSpans = spans
    .filter((span) => span && typeof span.id === "string")
    .sort((left, right) => {
      const leftOrder = TRACE_LANE_ORDER.indexOf(left.lane);
      const rightOrder = TRACE_LANE_ORDER.indexOf(right.lane);
      const leftRank = leftOrder === -1 ? TRACE_LANE_ORDER.length : leftOrder;
      const rightRank = rightOrder === -1 ? TRACE_LANE_ORDER.length : rightOrder;
      const leftStart = left.startMs ?? Number.MAX_SAFE_INTEGER;
      const rightStart = right.startMs ?? Number.MAX_SAFE_INTEGER;
      return leftRank - rightRank || leftStart - rightStart || left.id.localeCompare(right.id);
    });
  const times = normalizedSpans.flatMap((span) => [
    typeof span.startMs === "number" ? span.startMs : null,
    typeof span.endMs === "number" ? span.endMs : null,
  ]).filter((value) => typeof value === "number");
  const rangeStartMs = times.length > 0 ? Math.min(...times) : null;
  const rangeEndMs = times.length > 0 ? Math.max(...times) : null;
  const lanes = [];
  for (const laneName of [
    ...TRACE_LANE_ORDER,
    ...normalizedSpans
      .map((span) => span.lane)
      .filter((lane) => !TRACE_LANE_ORDER.includes(lane)),
  ]) {
    const laneSpans = normalizedSpans.filter((span) => span.lane === laneName);
    if (laneSpans.length === 0) {
      continue;
    }
    lanes.push({
      lane: laneName,
      spans: laneSpans,
    });
  }
  return {
    source,
    rangeStartMs,
    rangeEndMs,
    spanCount: normalizedSpans.length,
    lanes,
    bookmarks: bookmarks.filter(
      (bookmark) =>
        bookmark &&
        typeof bookmark.id === "string" &&
        typeof bookmark.spanId === "string" &&
        normalizedSpans.some((span) => span.id === bookmark.spanId),
    ),
  };
}

function summarizeTraceReplay(traceBundle, summary, diagnostic) {
  return (
    buildTraceReplayFromBundle(traceBundle, summary) ??
    buildFallbackTraceReplay(summary, diagnostic)
  );
}

function summarizeTraceMetrics(traceAnalysis, summary) {
  if (!traceAnalysis || typeof traceAnalysis !== "object" || !Array.isArray(traceAnalysis.metrics)) {
    return [];
  }

  return traceAnalysis.metrics.slice(0, 8).map((metric) => ({
    metricId: typeof metric.metricId === "string" ? metric.metricId : "",
    label: typeof metric.label === "string" ? metric.label : "",
    status:
      metric.metricId === "overall_case_outcome"
        ? resultLabel(summary)
        : normalizeTraceStatus(metric.status),
    summary:
      metric.metricId === "overall_case_outcome"
        ? compactText(
            `reward=${summary?.reward ?? "?"} effective_reward=${summaryEffectiveReward(summary) ?? "?"} floor_met=${summaryRewardFloorMet(summary) ?? "?"} terminated=${summary?.terminated ?? "?"}`,
            200,
          )
        : compactText(metric.summary ?? "", 200),
    supportingSpanIds: Array.isArray(metric.supportingSpanIds)
      ? metric.supportingSpanIds.filter((value) => typeof value === "string").slice(0, 8)
      : [],
  }));
}

function fallbackTraceMetrics(summary, diagnostic) {
  const timeline = Array.isArray(diagnostic?.timeline) ? diagnostic.timeline : [];
  const phaseTiming = diagnostic?.phase_timing && typeof diagnostic.phase_timing === "object"
    ? diagnostic.phase_timing
    : {};
  const effectiveReward = summaryEffectiveReward(summary);
  const observationPresent = timeline.some((step) => Array.isArray(step?.observation_targets) && step.observation_targets.length > 0);
  const verificationFailed = timeline.some((step) => typeof step?.action_error_class === "string" && step.action_error_class.trim());
  const executorDispatch = typeof phaseTiming.service_executor_dispatch_elapsed_ms === "number"
    ? phaseTiming.service_executor_dispatch_elapsed_ms
    : null;

  return [
    {
      metricId: "overall_case_outcome",
      label: "Overall case outcome",
      status: normalizeTraceStatus(resultLabel(summary)).replace("-", "_"),
      summary: compactText(
        `reward=${summary?.reward ?? "?"} effective_reward=${effectiveReward ?? "?"} floor_met=${summaryRewardFloorMet(summary) ?? "?"} terminated=${summary?.terminated ?? "?"}`,
        140,
      ),
      supportingSpanIds: ["case"],
    },
    {
      metricId: "observation_surface",
      label: "Observation surface",
      status: observationPresent ? "pass" : "unknown",
      summary: observationPresent
        ? "Grounded observation targets were recorded."
        : "No grounded observation targets were available in the summarized timeline.",
      supportingSpanIds: timeline.length > 0 ? [`step:${timeline[0]?.step_index ?? 0}`] : [],
    },
    {
      metricId: "execution_runtime",
      label: "Execution runtime",
      status: executorDispatch == null ? "unknown" : executorDispatch > 12000 ? "red" : "pass",
      summary: executorDispatch == null
        ? "No service executor dispatch timing was captured."
        : `Service executor dispatch elapsed ${executorDispatch}ms.`,
      supportingSpanIds: ["receipt:service_executor_dispatch"],
    },
    {
      metricId: "verification_signal",
      label: "Verification signal",
      status: verificationFailed ? "red" : timeline.length > 0 ? "pass" : "unknown",
      summary: verificationFailed
        ? "At least one summarized step ended with an action error class."
        : "Verification receipts were summarized without an explicit action error.",
      supportingSpanIds: timeline.length > 0 ? [`step:${timeline[0]?.step_index ?? 0}`] : [],
    },
  ];
}

function collectLatestCaseDiagnosticsFromStore() {
  const store = readJson(benchmarkStorePath, null);
  if (!store || !Array.isArray(store.runs)) {
    return [];
  }

  const latestByCase = new Map();
  for (const run of store.runs) {
    if (!run || typeof run !== "object" || !Array.isArray(run.cases)) {
      continue;
    }

    for (const entry of run.cases) {
      if (!entry || typeof entry !== "object" || typeof entry.case_id !== "string") {
        continue;
      }

      const diagnostic = readJson(entry.diagnostic_json_path, null);
      const summaryBlob = readJson(entry.summary_json_path, null);
      const source = diagnostic && typeof diagnostic === "object"
        ? diagnostic
        : summaryBlob && typeof summaryBlob === "object"
          ? summaryBlob
          : null;
      if (!source) {
        continue;
      }

      const traceBundlePath =
        entry.trace_bundle_path ??
        (typeof entry.case_dir === "string"
          ? path.join(entry.case_dir, "trace_bundle.json")
          : null);
      const traceAnalysisPath =
        entry.trace_analysis_path ??
        (typeof entry.case_dir === "string"
          ? path.join(entry.case_dir, "trace_analysis.json")
          : null);
      const traceBundle = readJson(traceBundlePath, null);
      const summary = source.summary ?? {};
      const traceMetrics = summarizeTraceMetrics(readJson(traceAnalysisPath, null), summary);
      const candidate = {
      suite: entry.suite || inferSuite(entry.case_id),
      caseId: entry.case_id,
      runId: run.run_id || "run-local",
      runSort: runFreshnessValue(run.run_id || "run-local", run.updated_at_ms),
        caseDir: entry.case_dir,
        summary,
        findings: Array.isArray(source.findings) ? source.findings : [],
        detail: diagnostic && typeof diagnostic === "object"
          ? summarizeDiagnostic(diagnostic)
          : {
              phaseTiming: summarizePhaseTiming(source.timing),
              timeline: [],
            },
        diagnosticJsonPath: entry.diagnostic_json_path ?? entry.summary_json_path,
        diagnosticMarkdownPath: entry.diagnostic_markdown_path ?? entry.summary_markdown_path,
        benchmarkSummaryJsonPath: entry.summary_json_path,
        benchmarkSummaryMarkdownPath: entry.summary_markdown_path,
        inferenceCallsPath: entry.inference_calls_path,
        inferenceTracePath: entry.inference_trace_path,
        bridgeStatePath: entry.bridge_state_path,
        traceBundlePath,
        traceAnalysisPath,
        traceMetrics: traceMetrics.length > 0
          ? traceMetrics
          : fallbackTraceMetrics(summary, diagnostic ?? source),
        trace: summarizeTraceReplay(traceBundle, summary, diagnostic ?? source),
      };

      const current = latestByCase.get(candidate.caseId);
      if (!current || candidate.runSort >= current.runSort) {
        latestByCase.set(candidate.caseId, candidate);
      }
    }
  }

  return Array.from(latestByCase.values())
    .sort((left, right) => right.runSort - left.runSort)
    .map((entry) => ({
      ...entry,
      result: resultLabel(entry.summary),
      links: {
        caseDir: toFileHref(entry.caseDir),
        diagnosticJson: toFileHref(entry.diagnosticJsonPath),
        diagnosticMarkdown: toFileHref(entry.diagnosticMarkdownPath),
        benchmarkSummaryJson: toFileHref(entry.benchmarkSummaryJsonPath),
        benchmarkSummaryMarkdown: toFileHref(entry.benchmarkSummaryMarkdownPath),
        inferenceCalls: toFileHref(entry.inferenceCallsPath),
        inferenceTrace: toFileHref(entry.inferenceTracePath),
        bridgeState: toFileHref(entry.bridgeStatePath),
        traceBundle: toFileHref(entry.traceBundlePath),
        traceAnalysis: toFileHref(entry.traceAnalysisPath),
      },
    }));
}

function collectLiveRunsFromStore() {
  const store = readJson(benchmarkStorePath, null);
  if (!store || !Array.isArray(store.runs)) {
    return [];
  }

  const latestBySuite = new Map();
  for (const run of store.runs) {
    if (!run || typeof run !== "object") {
      continue;
    }
    const status = typeof run.status === "string" ? run.status.trim() : "completed";
    if (status !== "running") {
      continue;
    }

    const suite = inferSuite(
      typeof run.active_case_id === "string" && run.active_case_id
        ? run.active_case_id
        : typeof run.cases?.[0]?.case_id === "string"
          ? run.cases[0].case_id
          : "",
    );
    if (suite === "Unknown") {
      continue;
    }

    const candidate = {
      suite,
      runId: typeof run.run_id === "string" ? run.run_id : "run-local",
      runSort: runFreshnessValue(run.run_id || "run-local", run.updated_at_ms),
      taskSet: typeof run.task_set === "string" ? run.task_set : "unknown",
      status,
      activeCaseId:
        typeof run.active_case_id === "string" && run.active_case_id
          ? run.active_case_id
          : null,
      totalCases:
        typeof run.total_cases === "number" && Number.isFinite(run.total_cases)
          ? run.total_cases
          : Array.isArray(run.cases)
            ? run.cases.length
            : 0,
      completedCases:
        typeof run.completed_cases === "number" && Number.isFinite(run.completed_cases)
          ? run.completed_cases
          : Array.isArray(run.cases)
            ? run.cases.length
            : 0,
      updatedAtMs:
        typeof run.updated_at_ms === "number" && Number.isFinite(run.updated_at_ms)
          ? run.updated_at_ms
          : null,
    };

    const current = latestBySuite.get(suite);
    if (!current || candidate.runSort >= current.runSort) {
      latestBySuite.set(suite, candidate);
    }
  }

  return Array.from(latestBySuite.values()).sort((left, right) => right.runSort - left.runSort);
}

function collectLatestCaseDiagnostics() {
  const indexed = collectLatestCaseDiagnosticsFromStore();
  if (indexed.length > 0) {
    return indexed;
  }

  if (!fs.existsSync(diagnosticsRoot)) {
    return [];
  }

  const latestByCase = new Map();
  for (const runName of fs.readdirSync(diagnosticsRoot)) {
    if (!runName.startsWith("run-")) {
      continue;
    }
    const agentRoot = path.join(diagnosticsRoot, runName, "agent");
    if (!fs.existsSync(agentRoot)) {
      continue;
    }

    for (const caseId of fs.readdirSync(agentRoot)) {
      const caseDir = path.join(agentRoot, caseId);
      const summaryPath = path.join(caseDir, "diagnostic_summary.json");
      if (!fs.existsSync(summaryPath)) {
        continue;
      }

      const diagnostic = readJson(summaryPath, null);
      if (!diagnostic || typeof diagnostic !== "object") {
        continue;
      }

      const traceAnalysisPath = path.join(caseDir, "trace_analysis.json");
      const traceBundlePath = path.join(caseDir, "trace_bundle.json");
      const traceBundle = readJson(traceBundlePath, null);
      const summary = diagnostic.summary ?? {};
      const traceMetrics = summarizeTraceMetrics(readJson(traceAnalysisPath, null), summary);
      const candidate = {
        suite: inferSuite(caseId),
        caseId,
        runId: runName,
        runSort: runFreshnessValue(runName, null),
        caseDir,
        summary,
        findings: Array.isArray(diagnostic.findings) ? diagnostic.findings : [],
        detail: summarizeDiagnostic(diagnostic),
        diagnosticJsonPath: summaryPath,
        diagnosticMarkdownPath: path.join(caseDir, "diagnostic_summary.md"),
        inferenceCallsPath: path.join(caseDir, "inference_calls.json"),
        inferenceTracePath: path.join(caseDir, "inference_trace.json"),
        bridgeStatePath: path.join(caseDir, "bridge_state.json"),
        traceBundlePath,
        traceAnalysisPath,
        traceMetrics: traceMetrics.length > 0
          ? traceMetrics
          : fallbackTraceMetrics(summary, diagnostic),
        trace: summarizeTraceReplay(
          traceBundle,
          summary,
          diagnostic,
        ),
      };

      const current = latestByCase.get(caseId);
      if (!current || candidate.runSort >= current.runSort) {
        latestByCase.set(caseId, candidate);
      }
    }
  }

  return Array.from(latestByCase.values())
    .sort((left, right) => right.runSort - left.runSort)
    .map((entry) => ({
      ...entry,
      result: resultLabel(entry.summary),
      links: {
        caseDir: toFileHref(entry.caseDir),
        diagnosticJson: toFileHref(entry.diagnosticJsonPath),
        diagnosticMarkdown: toFileHref(entry.diagnosticMarkdownPath),
        inferenceCalls: toFileHref(entry.inferenceCallsPath),
        inferenceTrace: toFileHref(entry.inferenceTracePath),
        bridgeState: toFileHref(entry.bridgeStatePath),
        traceBundle: toFileHref(entry.traceBundlePath),
        traceAnalysis: toFileHref(entry.traceAnalysisPath),
      },
    }));
}

function buildSuiteSummaries(registry, latestCases, liveRuns) {
  const liveRunsBySuite = new Map(liveRuns.map((entry) => [entry.suite, entry]));
  return registry.map((row) => {
    const suiteCases = latestCases.filter((entry) => entry.suite === row.Surface);
    const counts = { pass: 0, "near-miss": 0, red: 0, unknown: 0 };
    for (const entry of suiteCases) {
      counts[entry.result] = (counts[entry.result] ?? 0) + 1;
    }
    const focusCase =
      suiteCases.find((entry) => entry.result === "red") ??
      suiteCases.find((entry) => entry.result === "near-miss") ??
      suiteCases[0] ??
      null;
    return {
      suite: row.Surface,
      maturity: row["Repo maturity"],
      benchmarkStatus: row["Current benchmark status"],
      workspaceStatus: row["Workspace status (last verified)"],
      nextUnlock: row["Next unlock"],
      counts,
      focusCaseId: focusCase?.caseId ?? null,
      focusResult: focusCase?.result ?? "unknown",
      latestRunId: focusCase?.runId ?? null,
      liveRun: liveRunsBySuite.get(row.Surface) ?? null,
    };
  });
}

function generate() {
  const playbook = readText(playbookPath);
  const discovery = readText(discoveryPath);
  const registry = parseTableFromSection(playbook, "## 7. Benchmark Registry");
  const latestCases = collectLatestCaseDiagnostics();
  const liveRuns = collectLiveRunsFromStore();

  const payload = {
    generatedAt: new Date().toISOString(),
    repoRoot,
    liveDataPath,
    docs: {
      playbook: {
        path: playbookPath,
        href: toFileHref(playbookPath),
        content: playbook,
      },
      discovery: {
        path: discoveryPath,
        href: toFileHref(discoveryPath),
        content: discovery,
      },
    },
    registry,
    suiteSummaries: buildSuiteSummaries(registry, latestCases, liveRuns),
    discoverySections: {
      scope: extractBulletLines(discovery, "## Scope"),
      methodInvariants: extractBulletLines(discovery, "## Method Invariants"),
      validationRules: extractBulletLines(discovery, "## Validation Rules", [
        "## Status",
      ]),
      status: extractBulletLines(discovery, "## Status", ["Current frontier:"]),
      currentFrontier: extractBulletLines(discovery, "Current frontier:", [
        "Current blocker:",
      ]),
      currentBlocker: extractBulletLines(discovery, "Current blocker:", [
        "Decision rule:",
      ]),
      decisionRule: extractBulletLines(discovery, "Decision rule:", [
        "## Rolling Window",
      ]),
      rollingWindow: extractBulletLines(discovery, "## Rolling Window", [
        "## Benchmark Snapshot",
      ]),
      currentNextMoveCommand: extractCodeBlock(discovery, "## Current Next Move"),
    },
    benchmarkSnapshot: parseTableFromSection(discovery, "## Benchmark Snapshot", [
      "## Capability Gap Matrix",
    ]),
    capabilityGapMatrix: parseTableFromSection(
      discovery,
      "## Capability Gap Matrix",
      ["## Benchmark Escalation Ladder"],
    ),
    liveRuns,
    latestCases,
  };

  writeOutputFiles(payload);
}

generate();
