import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

import {
  collectStudioArtifactArenaView,
  writeStudioArtifactArenaLedger,
} from "../../../scripts/lib/studio-artifact-arena.mjs";
import { buildAgentModelMatrixView } from "../../../scripts/lib/agent-model-matrix.mjs";
import { collectStudioArtifactCorpusIndex } from "../../../scripts/lib/studio-artifact-corpus.mjs";
import { collectStudioArtifactDistillationView } from "../../../scripts/lib/studio-artifact-distillation.mjs";
import { collectStudioArtifactParityLoopView } from "../../../scripts/lib/studio-artifact-parity-loop.mjs";
import {
  collectStudioArtifactReleaseGatesView,
  writeStudioArtifactReleaseGates,
} from "../../../scripts/lib/studio-artifact-release-gates.mjs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "../../..");

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
const studioArtifactEvidenceRoot = path.join(
  repoRoot,
  "docs",
  "evidence",
  "studio-artifact-surface",
);
const liveDataPath = "/generated/benchmark-data.json";
const liveStorePath = "/generated/benchmark-store.json";
const SUITE_ORDER = ["MiniWoB++", "OSWorld", "WorkArena", "Studio Artifacts", "Unknown"];

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
const STUDIO_ARTIFACT_SUITE = "Studio Artifacts";

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

function resolveRepoPath(targetPath) {
  if (!targetPath || typeof targetPath !== "string") {
    return null;
  }
  return path.isAbsolute(targetPath) ? targetPath : path.join(repoRoot, targetPath);
}

function resolveStudioArtifactEvidencePath(targetPath) {
  if (!targetPath || typeof targetPath !== "string") {
    return null;
  }
  return path.isAbsolute(targetPath)
    ? targetPath
    : path.join(studioArtifactEvidenceRoot, targetPath);
}

function toDisplayPath(targetPath) {
  if (!targetPath || typeof targetPath !== "string") {
    return "";
  }
  if (path.isAbsolute(targetPath)) {
    const repoRelative = path.relative(repoRoot, targetPath);
    if (
      repoRelative &&
      !repoRelative.startsWith("..") &&
      !path.isAbsolute(repoRelative)
    ) {
      return repoRelative.split(path.sep).join("/");
    }
  }
  return String(targetPath).replace(/\\/g, "/");
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
  const normalizedRunId = String(runId);
  const numericMatch =
    normalizedRunId.match(/(\d{10,13})$/) ??
    normalizedRunId.match(/(\d{10,13})/);
  const numeric = Number.parseInt(numericMatch?.[1] ?? "", 10);
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

function artifactClassificationResult(classification) {
  const normalized = String(classification || "").trim().toLowerCase();
  if (normalized === "pass") {
    return "pass";
  }
  if (normalized === "repairable") {
    return "near-miss";
  }
  if (normalized === "blocked") {
    return "red";
  }
  return "unknown";
}

function artifactVerificationMetricStatus(verificationStatus) {
  const normalized = String(verificationStatus || "").trim().toLowerCase();
  if (normalized === "ready" || normalized === "pass") {
    return "pass";
  }
  if (normalized === "partial" || normalized === "repairable") {
    return "near-miss";
  }
  if (normalized) {
    return "red";
  }
  return "unknown";
}

function artifactReward(classification) {
  const result = artifactClassificationResult(classification);
  if (result === "pass") {
    return 1;
  }
  if (result === "near-miss") {
    return 0.5;
  }
  if (result === "red") {
    return 0;
  }
  return null;
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

function summarizeTraceArtifactLinks(refs, options = {}) {
  const resolvePath = options.resolvePath ?? resolveRepoPath;
  const formatPath = options.formatPath ?? toDisplayPath;
  if (!Array.isArray(refs)) {
    return [];
  }
  return refs
    .filter((value) => typeof value === "string" && value.trim())
    .slice(0, 4)
    .map((value) => {
      const resolvedPath = resolvePath(value);
      return {
        label: path.basename(value),
        path: formatPath(value),
        href: toFileHref(resolvedPath),
      };
    })
    .filter((entry) => entry.href);
}

function studioArtifactTraceLinks(entry) {
  return [
    entry.summaryPath,
    entry.manifestPath,
    entry.generationPath,
    entry.routePath,
    entry.inspectPath,
  ]
    .filter((value) => typeof value === "string" && value.trim())
    .slice(0, 4)
    .map((value) => ({
      label: path.basename(value),
      path: value,
      href: toFileHref(resolveStudioArtifactEvidencePath(value)),
    }))
    .filter((value) => value.href);
}

function buildStudioArtifactTrace(entry) {
  const startMs = entry.sortTimestampMs || null;
  const endMs = startMs == null ? null : startMs + 4;
  const result = artifactClassificationResult(entry.effectiveClassification);
  const verificationMetric = artifactVerificationMetricStatus(entry.verificationStatus);
  const shimStatus = entry.shimDependent
    ? "red"
    : entry.renderer === "html_iframe"
      ? "pass"
      : "unknown";
  const provenanceStatus =
    entry.productionProvenanceKind || entry.acceptanceProvenanceKind ? "pass" : "unknown";
  const studioArtifactLinkOptions = {
    resolvePath: resolveStudioArtifactEvidencePath,
    formatPath: (value) => String(value ?? ""),
  };
  const spans = [
    {
      id: "case",
      lane: "case",
      parentSpanId: null,
      stepIndex: null,
      status: result,
      summary: compactText(
        `${entry.prompt} | renderer=${entry.renderer} verification=${entry.verificationStatus} classification=${entry.effectiveClassification}`,
        220,
      ),
      startMs,
      endMs,
      durationMs: startMs == null ? null : 4,
      capabilityTags: ["artifact_outcome"],
      attributesSummary: compactText(
        JSON.stringify({
          lane: entry.laneLabel ?? entry.lane,
          dateRoot: entry.dateRoot,
          fullStudioPath: entry.fullStudioPath,
        }),
        220,
      ),
      artifactLinks: studioArtifactTraceLinks(entry),
    },
    {
      id: "runtime:production",
      lane: "runtime",
      parentSpanId: "case",
      stepIndex: null,
      status: provenanceStatus,
      summary: compactText(
        `production=${entry.productionRuntimeLabel ?? entry.productionProvenanceKind ?? "Unknown"} acceptance=${entry.acceptanceRuntimeLabel ?? entry.acceptanceProvenanceKind ?? "Unknown"}`,
        220,
      ),
      startMs: startMs == null ? null : startMs + 1,
      endMs: startMs == null ? null : startMs + 2,
      durationMs: startMs == null ? null : 1,
      capabilityTags: ["artifact_provenance"],
      attributesSummary: compactText(
        JSON.stringify({
          acceptance: entry.acceptanceRuntimeLabel ?? entry.acceptanceProvenanceKind,
          outputOrigin: entry.outputOriginLabel ?? entry.outputOrigin,
        }),
        220,
      ),
      artifactLinks: summarizeTraceArtifactLinks(
        [entry.generationPath, entry.inspectPath],
        studioArtifactLinkOptions,
      ),
    },
    {
      id: "step:route",
      lane: "step",
      parentSpanId: "case",
      stepIndex: 0,
      status: result,
      summary: compactText(
        `route=${entry.renderer}/${entry.artifactClass} lane=${entry.laneLabel ?? entry.lane}`,
        220,
      ),
      startMs: startMs == null ? null : startMs + 1,
      endMs: startMs == null ? null : startMs + 2,
      durationMs: startMs == null ? null : 1,
      capabilityTags: ["artifact_route"],
      attributesSummary: "",
      artifactLinks: summarizeTraceArtifactLinks([entry.routePath], studioArtifactLinkOptions),
    },
    {
      id: "step:judge",
      lane: "step",
      parentSpanId: "case",
      stepIndex: 1,
      status: result,
      summary: compactText(
        `winner=${entry.winningCandidateId ?? "none"} candidates=${entry.candidateCount} contradiction=${entry.strongestContradiction ?? "none"}`,
        220,
      ),
      startMs: startMs == null ? null : startMs + 2,
      endMs: startMs == null ? null : startMs + 3,
      durationMs: startMs == null ? null : 1,
      capabilityTags: ["artifact_candidate_search"],
      attributesSummary: compactText(
        JSON.stringify({
          pass: entry.passCandidateCount,
          repairable: entry.repairableCandidateCount,
          blocked: entry.blockedCandidateCount,
        }),
        220,
      ),
      artifactLinks: summarizeTraceArtifactLinks(
        [entry.judgePath, entry.generationPath],
        studioArtifactLinkOptions,
      ),
    },
    {
      id: "receipt:verification",
      lane: "receipt",
      parentSpanId: "case",
      stepIndex: null,
      status: verificationMetric,
      summary: compactText(
        `verification=${entry.verificationStatus} lifecycle=${entry.lifecycleState}`,
        220,
      ),
      startMs: startMs == null ? null : startMs + 3,
      endMs: startMs == null ? null : startMs + 4,
      durationMs: startMs == null ? null : 1,
      capabilityTags: ["artifact_verification_gate"],
      attributesSummary: "",
      artifactLinks: summarizeTraceArtifactLinks(
        [entry.manifestPath, entry.inspectPath],
        studioArtifactLinkOptions,
      ),
    },
    {
      id: "receipt:shim",
      lane: "receipt",
      parentSpanId: "case",
      stepIndex: null,
      status: shimStatus,
      summary: entry.shimDependent
        ? "Artifact depended on Studio normalization repair shims."
        : entry.renderer === "html_iframe"
          ? "Artifact rendered without normalization repair shims."
          : "Shim dependency is only tracked for HTML artifacts.",
      startMs: startMs == null ? null : startMs + 4,
      endMs: startMs == null ? null : startMs + 5,
      durationMs: startMs == null ? null : 1,
      capabilityTags: ["artifact_shim_dependency"],
      attributesSummary: compactText(
        JSON.stringify({
          primaryFile: entry.primaryFile,
          fullStudioPath: entry.fullStudioPath,
        }),
        220,
      ),
      artifactLinks: summarizeTraceArtifactLinks(
        [entry.primaryArtifactPath, entry.materializedPrimaryPath].filter(Boolean),
        studioArtifactLinkOptions,
      ),
    },
  ];

  const lanes = Array.from(
    spans.reduce((acc, span) => {
      const current = acc.get(span.lane) ?? [];
      current.push(span);
      acc.set(span.lane, current);
      return acc;
    }, new Map()),
  )
    .map(([lane, laneSpans]) => ({ lane, spans: laneSpans }))
    .sort((left, right) => {
      const leftOrder = TRACE_LANE_ORDER.indexOf(left.lane);
      const rightOrder = TRACE_LANE_ORDER.indexOf(right.lane);
      const leftRank = leftOrder === -1 ? TRACE_LANE_ORDER.length : leftOrder;
      const rightRank = rightOrder === -1 ? TRACE_LANE_ORDER.length : rightOrder;
      return leftRank - rightRank || left.lane.localeCompare(right.lane);
    });

  return {
    source: "studio_artifact_corpus",
    rangeStartMs: startMs,
    rangeEndMs: endMs,
    spanCount: spans.length,
    bookmarks: [
      { label: "Route", spanId: "step:route", kind: "route" },
      { label: "Judge", spanId: "step:judge", kind: "judge" },
      { label: "Verify", spanId: "receipt:verification", kind: "verification" },
    ],
    lanes,
  };
}

function collectStudioArtifactCases(corpus = collectStudioArtifactCorpusIndex({ repoRoot })) {
  return corpus.cases.map((entry) => {
    const result = artifactClassificationResult(entry.effectiveClassification);
    const reward = artifactReward(entry.effectiveClassification);
    const findings = [];
    if (entry.strongestContradiction) {
      findings.push(entry.strongestContradiction);
    }
    if (entry.shimDependent) {
      findings.push("Artifact depended on Studio normalization repair shims.");
    }
    if (entry.winningCandidateRationale) {
      findings.push(entry.winningCandidateRationale);
    }

    return {
      suite: STUDIO_ARTIFACT_SUITE,
      caseId: entry.id,
      runId: `${entry.dateRoot}:${entry.lane}`,
      runSort: entry.sortTimestampMs,
      caseDir: entry.caseDir,
      summary: {
        provider_calls: entry.candidateCount,
        reward,
        raw_reward: reward,
        model: entry.productionRuntimeLabel ?? undefined,
        backend: entry.renderer,
        final_trigger: entry.verificationStatus,
        query_text: entry.prompt,
        episode_step: 1,
        sync_count: entry.shimDependent ? 1 : 0,
      },
      result,
      findings: findings.slice(0, 3),
      detail: {
        phaseTiming: {},
        timeline: [],
      },
      traceMetrics: [
        {
          metricId: "artifact_outcome",
          label: "Artifact outcome",
          status: result,
          summary: compactText(
            `classification=${entry.effectiveClassification} verification=${entry.verificationStatus} renderer=${entry.renderer}`,
            220,
          ),
          supportingSpanIds: ["case"],
        },
        {
          metricId: "artifact_verification_gate",
          label: "Verification gate",
          status: artifactVerificationMetricStatus(entry.verificationStatus),
          summary: compactText(
            `verification=${entry.verificationStatus} lifecycle=${entry.lifecycleState}`,
            220,
          ),
          supportingSpanIds: ["receipt:verification"],
        },
        {
          metricId: "artifact_candidate_search",
          label: "Candidate search",
          status:
            entry.candidateCount > 1
              ? "pass"
              : entry.candidateCount === 1
                ? "near-miss"
                : "unknown",
          summary: compactText(
            `candidates=${entry.candidateCount} pass=${entry.passCandidateCount} repairable=${entry.repairableCandidateCount} blocked=${entry.blockedCandidateCount}`,
            220,
          ),
          supportingSpanIds: ["step:judge"],
        },
        {
          metricId: "artifact_shim_dependency",
          label: "Shim dependency",
          status: entry.shimDependent
            ? "red"
            : entry.renderer === "html_iframe"
              ? "pass"
              : "unknown",
          summary: entry.shimDependent
            ? "Artifact still required Studio normalization repair shims."
            : entry.renderer === "html_iframe"
              ? "Artifact rendered without Studio normalization repair shims."
              : "Shim dependency is only tracked for HTML artifacts.",
          supportingSpanIds: ["receipt:shim"],
        },
        {
          metricId: "artifact_provenance",
          label: "Artifact provenance",
          status:
            entry.productionProvenanceKind || entry.acceptanceProvenanceKind
              ? "pass"
              : "unknown",
          summary: compactText(
            `production=${entry.productionRuntimeLabel ?? entry.productionProvenanceKind ?? "Unknown"} acceptance=${entry.acceptanceRuntimeLabel ?? entry.acceptanceProvenanceKind ?? "Unknown"}`,
            220,
          ),
          supportingSpanIds: ["runtime:production"],
        },
      ],
      trace: buildStudioArtifactTrace(entry),
      links: {
        caseDir: toFileHref(resolveStudioArtifactEvidencePath(entry.caseDir)),
        diagnosticJson: toFileHref(resolveStudioArtifactEvidencePath(entry.summaryPath)),
        diagnosticMarkdown: toFileHref(
          resolveStudioArtifactEvidencePath(entry.materializedReadmePath),
        ),
        inferenceCalls: toFileHref(resolveStudioArtifactEvidencePath(entry.generationPath)),
        inferenceTrace: toFileHref(resolveStudioArtifactEvidencePath(entry.judgePath)),
        bridgeState: toFileHref(resolveStudioArtifactEvidencePath(entry.routePath)),
        traceBundle: toFileHref(resolveStudioArtifactEvidencePath(entry.manifestPath)),
        traceAnalysis: toFileHref(resolveStudioArtifactEvidencePath(entry.inspectPath)),
      },
    };
  });
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

      const caseDir = resolveRepoPath(entry.case_dir);
      const summaryJsonPath = resolveRepoPath(entry.summary_json_path);
      const summaryMarkdownPath = resolveRepoPath(entry.summary_markdown_path);
      const diagnosticJsonPath = resolveRepoPath(entry.diagnostic_json_path);
      const diagnosticMarkdownPath = resolveRepoPath(entry.diagnostic_markdown_path);
      const inferenceCallsPath = resolveRepoPath(entry.inference_calls_path);
      const inferenceTracePath = resolveRepoPath(entry.inference_trace_path);
      const bridgeStatePath = resolveRepoPath(entry.bridge_state_path);
      const diagnostic = readJson(diagnosticJsonPath, null);
      const summaryBlob = readJson(summaryJsonPath, null);
      const source = diagnostic && typeof diagnostic === "object"
        ? diagnostic
        : summaryBlob && typeof summaryBlob === "object"
          ? summaryBlob
          : null;
      if (!source) {
        continue;
      }

      const traceBundlePath =
        resolveRepoPath(entry.trace_bundle_path) ??
        (caseDir
          ? path.join(caseDir, "trace_bundle.json")
          : null);
      const traceAnalysisPath =
        resolveRepoPath(entry.trace_analysis_path) ??
        (caseDir
          ? path.join(caseDir, "trace_analysis.json")
          : null);
      const traceBundle = readJson(traceBundlePath, null);
      const summary = source.summary ?? {};
      const traceMetrics = summarizeTraceMetrics(readJson(traceAnalysisPath, null), summary);
      const candidate = {
        suite: entry.suite || inferSuite(entry.case_id),
        caseId: entry.case_id,
        runId: run.run_id || "run-local",
        runSort: runFreshnessValue(run.run_id || "run-local", run.updated_at_ms),
        caseDir,
        summary,
        findings: Array.isArray(source.findings) ? source.findings : [],
        detail: diagnostic && typeof diagnostic === "object"
          ? summarizeDiagnostic(diagnostic)
          : {
              phaseTiming: summarizePhaseTiming(source.timing),
              timeline: [],
            },
        diagnosticJsonPath: diagnosticJsonPath ?? summaryJsonPath,
        diagnosticMarkdownPath: diagnosticMarkdownPath ?? summaryMarkdownPath,
        benchmarkSummaryJsonPath: summaryJsonPath,
        benchmarkSummaryMarkdownPath: summaryMarkdownPath,
        inferenceCallsPath,
        inferenceTracePath,
        bridgeStatePath,
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
    .sort((left, right) => right.runSort - left.runSort);
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
  const fallback = collectLatestCaseDiagnosticsFromFilesystem();
  const latestByCase = new Map();

  for (const entry of fallback) {
    if (!entry || typeof entry.caseId !== "string") {
      continue;
    }
    const current = latestByCase.get(entry.caseId);
    if (!current || entry.runSort >= current.runSort) {
      latestByCase.set(entry.caseId, entry);
    }
  }

  // Treat store-backed runs as the authoritative retained source when the same
  // case also exists in legacy run-* artifacts, since custom-named reruns only
  // exist in the store path.
  for (const entry of indexed) {
    if (!entry || typeof entry.caseId !== "string") {
      continue;
    }
    latestByCase.set(entry.caseId, entry);
  }

  if (latestByCase.size > 0) {
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

  return [];
}

function collectLatestCaseDiagnosticsFromFilesystem() {
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
    .sort((left, right) => right.runSort - left.runSort);
}

function buildSuiteSummaries(latestCases, liveRuns) {
  const liveRunsBySuite = new Map(liveRuns.map((entry) => [entry.suite, entry]));
  const suites = new Set([
    ...latestCases.map((entry) => entry.suite),
    ...liveRuns.map((entry) => entry.suite),
  ]);

  return Array.from(suites)
    .filter((suite) => typeof suite === "string" && suite.trim())
    .sort((left, right) => {
      const leftIndex = SUITE_ORDER.indexOf(left);
      const rightIndex = SUITE_ORDER.indexOf(right);
      if (leftIndex !== -1 || rightIndex !== -1) {
        const leftRank = leftIndex === -1 ? Number.MAX_SAFE_INTEGER : leftIndex;
        const rightRank = rightIndex === -1 ? Number.MAX_SAFE_INTEGER : rightIndex;
        return leftRank - rightRank || left.localeCompare(right);
      }
      return left.localeCompare(right);
    })
    .map((suite) => {
      const suiteCases = latestCases.filter((entry) => entry.suite === suite);
      const liveRun = liveRunsBySuite.get(suite) ?? null;
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
      suite,
      counts,
      focusCaseId: focusCase?.caseId ?? null,
      focusResult: focusCase?.result ?? "unknown",
      latestRunId: focusCase?.runId ?? liveRun?.runId ?? null,
      liveRun,
    };
  });
}

function collectStudioArtifactParityLoop() {
  const view = collectStudioArtifactParityLoopView({ repoRoot });
  if (!view) {
    return null;
  }

  const summarizeReceipt = (receipt) =>
    receipt && typeof receipt === "object"
      ? {
          createdAt: receipt.createdAt ?? null,
          keepChange:
            typeof receipt.keepChange === "boolean" ? receipt.keepChange : null,
          noImprovementStreak: Number(receipt.noImprovementStreak ?? 0),
          selectedInterventionFamily:
            typeof receipt.selectedInterventionFamily === "string"
              ? receipt.selectedInterventionFamily
              : null,
          allowedInterventionFamilies: Array.isArray(
            receipt.allowedInterventionFamilies,
          )
            ? receipt.allowedInterventionFamilies.filter((value) => typeof value === "string")
            : [],
          decision:
            receipt.decision && typeof receipt.decision === "object"
              ? {
                  kind: receipt.decision.kind ?? "continue",
                  reason: receipt.decision.reason ?? "",
                }
              : { kind: "continue", reason: "" },
          weakestTarget:
            receipt.weakestTarget && typeof receipt.weakestTarget === "object"
              ? {
                  id: receipt.weakestTarget.id ?? null,
                  label: receipt.weakestTarget.label ?? null,
                  summary: receipt.weakestTarget.summary ?? null,
                  family: receipt.weakestTarget.family ?? null,
                  caseIds: Array.isArray(receipt.weakestTarget.caseIds)
                    ? receipt.weakestTarget.caseIds.filter(
                        (value) => typeof value === "string",
                      )
                    : [],
                }
              : null,
          relevantCaseIds: Array.isArray(receipt.relevantCaseIds)
            ? receipt.relevantCaseIds.filter((value) => typeof value === "string")
            : [],
          requiredReceipts: Array.isArray(receipt.requiredReceipts)
            ? receipt.requiredReceipts.filter((value) => typeof value === "string")
            : [],
          comparison:
            receipt.comparison && typeof receipt.comparison === "object"
              ? {
                  improvedMetrics: Array.isArray(receipt.comparison.improvedMetrics)
                    ? receipt.comparison.improvedMetrics.filter(
                        (value) => typeof value === "string",
                      )
                    : [],
                  regressedMetrics: Array.isArray(receipt.comparison.regressedMetrics)
                    ? receipt.comparison.regressedMetrics.filter(
                        (value) => typeof value === "string",
                      )
                    : [],
                  unchangedMetrics: Array.isArray(receipt.comparison.unchangedMetrics)
                    ? receipt.comparison.unchangedMetrics.filter(
                        (value) => typeof value === "string",
                      )
                    : [],
                }
              : null,
        }
      : null;

  return {
    status: view.status,
    receiptCount: Number(view.receiptCount ?? 0),
    summaryPath: toDisplayPath(view.summaryPath),
    summaryHref: toFileHref(view.summaryPath),
    ledgerPath: toDisplayPath(view.ledgerPath),
    ledgerHref: toFileHref(view.ledgerPath),
    latestReceipt: summarizeReceipt(view.latestReceipt),
    currentPlan: summarizeReceipt(view.currentPlan),
  };
}

function collectStudioArtifactDistillation() {
  const view = collectStudioArtifactDistillationView({ repoRoot });
  if (!view) {
    return null;
  }

  return {
    status: view.status,
    ledgerPath: toDisplayPath(view.ledgerPath),
    ledgerHref: toFileHref(view.ledgerPath),
    proposalCount: Number(view.proposalCount ?? 0),
    appliedCount: Number(view.appliedCount ?? 0),
    measuredGain:
      typeof view.measuredGain === "number" ? view.measuredGain : null,
    topProposals: Array.isArray(view.topProposals)
      ? view.topProposals.map((proposal) => ({
          proposalId: proposal.proposalId ?? null,
          sourceKind: proposal.sourceKind ?? null,
          benchmarkId: proposal.benchmarkId ?? null,
          benchmarkTitle: proposal.benchmarkTitle ?? null,
          targetUpgrades: Array.isArray(proposal.targetUpgrades)
            ? proposal.targetUpgrades.filter((value) => typeof value === "string")
            : [],
          typedReasons: Array.isArray(proposal.typedReasons)
            ? proposal.typedReasons.filter((value) => typeof value === "string")
            : [],
          before: proposal.before ?? null,
          after: proposal.after ?? null,
          structuralChanges: proposal.structuralChanges ?? null,
          generalization: proposal.generalization ?? null,
          status: proposal.status ?? "proposed",
        }))
      : [],
  };
}

function collectStudioArtifactArena(corpusSummary = null) {
  const { ledgerPath } = writeStudioArtifactArenaLedger({
    repoRoot,
    corpusSummary: corpusSummary ?? undefined,
  });
  const view = collectStudioArtifactArenaView({ repoRoot, ledgerPath });
  if (!view) {
    return null;
  }

  return {
    status: view.status,
    ledgerPath: toDisplayPath(view.ledgerPath),
    ledgerHref: toFileHref(view.ledgerPath),
    benchmarkCount: Number(view.benchmarkCount ?? 0),
    executedBenchmarkCount: Number(view.executedBenchmarkCount ?? 0),
    comparativeBenchmarkCount: Number(view.comparativeBenchmarkCount ?? 0),
    benchmarksWithBlindWinnerCount: Number(view.benchmarksWithBlindWinnerCount ?? 0),
    internalExecutionCount: Number(view.internalExecutionCount ?? 0),
    internalParticipantCount: Number(view.internalParticipantCount ?? 0),
    externalReferenceCount: Number(view.externalReferenceCount ?? 0),
    pairwiseMatchCount: Number(view.pairwiseMatchCount ?? 0),
    blindMatchCount: Number(view.blindMatchCount ?? 0),
    pendingBlindMatchCount: Number(view.pendingBlindMatchCount ?? 0),
    topCompositeRatings: Array.isArray(view.topCompositeRatings)
      ? view.topCompositeRatings.map((rating) => ({
          participant: rating.participant ?? null,
          label: rating.label ?? null,
          rating:
            typeof rating.rating === "number" ? rating.rating : null,
          matches: Number(rating.matches ?? 0),
          wins: Number(rating.wins ?? 0),
          losses: Number(rating.losses ?? 0),
          draws: Number(rating.draws ?? 0),
        }))
      : [],
    benchmarkLeaders: Array.isArray(view.benchmarkLeaders)
      ? view.benchmarkLeaders.map((leader) => ({
          benchmarkId: leader.benchmarkId ?? null,
          title: leader.title ?? null,
          pairwiseMatchCount: Number(leader.pairwiseMatchCount ?? 0),
          pendingBlindMatchCount: Number(leader.pendingBlindMatchCount ?? 0),
          provisionalLeader: leader.provisionalLeader ?? null,
          blindWinner: leader.blindWinner ?? null,
        }))
      : [],
    pendingBlindMatches: Array.isArray(view.pendingBlindMatches)
      ? view.pendingBlindMatches.map((match) => ({
          matchId: match.matchId ?? null,
          benchmarkId: match.benchmarkId ?? null,
          benchmarkTitle: match.benchmarkTitle ?? null,
          leftLabel: match.leftLabel ?? null,
          rightLabel: match.rightLabel ?? null,
          rationale: match.rationale ?? null,
        }))
      : [],
  };
}

function collectStudioArtifactReleaseGates(corpusSummary = null) {
  const { reportPath } = writeStudioArtifactReleaseGates({
    repoRoot,
    corpusSummary: corpusSummary ?? undefined,
  });
  const view = collectStudioArtifactReleaseGatesView({ repoRoot, reportPath });
  if (!view) {
    return null;
  }

  return {
    status: view.status,
    passing: view.passing === true,
    reportPath: toDisplayPath(view.reportPath),
    reportHref: toFileHref(view.reportPath),
    gateCount: Number(view.gateCount ?? 0),
    passCount: Number(view.passCount ?? 0),
    failCount: Number(view.failCount ?? 0),
    pendingCount: Number(view.pendingCount ?? 0),
    blockingGateIds: Array.isArray(view.blockingGateIds)
      ? view.blockingGateIds.filter((value) => typeof value === "string")
      : [],
    ratchetCandidateIds: Array.isArray(view.ratchetCandidateIds)
      ? view.ratchetCandidateIds.filter((value) => typeof value === "string")
      : [],
    topGates: Array.isArray(view.topGates)
      ? view.topGates.map((gate) => ({
          id: gate.id ?? null,
          label: gate.label ?? null,
          status: gate.status ?? null,
          operator: gate.operator ?? null,
          shipThreshold:
            typeof gate.shipThreshold === "number" ? gate.shipThreshold : null,
          reading: gate.reading ?? null,
          ratchet: gate.ratchet ?? null,
        }))
      : [],
    ratchetCandidates: Array.isArray(view.ratchetCandidates)
      ? view.ratchetCandidates.map((gate) => ({
          id: gate.id ?? null,
          label: gate.label ?? null,
          operator: gate.operator ?? null,
          currentValue:
            typeof gate.currentValue === "number" ? gate.currentValue : null,
          currentFloor:
            typeof gate.currentFloor === "number" ? gate.currentFloor : null,
          candidateFloor:
            typeof gate.candidateFloor === "number" ? gate.candidateFloor : null,
        }))
      : [],
  };
}

function generate() {
  const studioArtifactCorpus = collectStudioArtifactCorpusIndex({ repoRoot });
  const studioArtifactArena = collectStudioArtifactArena(studioArtifactCorpus);
  const studioArtifactReleaseGates =
    collectStudioArtifactReleaseGates(studioArtifactCorpus);
  const studioArtifactDistillation = collectStudioArtifactDistillation();
  const studioArtifactParityLoop = collectStudioArtifactParityLoop();
  const agentModelMatrix = buildAgentModelMatrixView({ repoRoot });
  const latestCases = [
    ...collectLatestCaseDiagnostics(),
    ...collectStudioArtifactCases(studioArtifactCorpus),
  ].sort((left, right) => (right.runSort ?? 0) - (left.runSort ?? 0));
  const liveRuns = collectLiveRunsFromStore();

  const payload = {
    generatedAt: new Date().toISOString(),
    repoRoot,
    liveDataPath,
    liveStorePath,
    suiteSummaries: buildSuiteSummaries(latestCases, liveRuns),
    liveRuns,
    latestCases,
    studioArtifactBenchmarkSuite: studioArtifactCorpus.benchmarkSuite ?? null,
    studioArtifactArena,
    studioArtifactReleaseGates,
    studioArtifactDistillation,
    studioArtifactParityLoop,
    agentModelMatrix,
  };

  writeOutputFiles(payload);
}

generate();
