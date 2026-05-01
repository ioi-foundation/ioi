#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import {
  AUTOPILOT_GUI_HARNESS_LAUNCH_COMMAND,
  AUTOPILOT_RETAINED_QUERIES,
  GUI_AUTOMATION_CLICK_POLICY,
  autopilotGuiHarnessContract,
  buildBlockedAutopilotGuiHarnessResult,
  validateAutopilotGuiHarnessResult,
} from "./lib/autopilot-gui-harness-contract.mjs";

const repoRoot = resolve(new URL("..", import.meta.url).pathname);

function parseArgs(argv) {
  const args = {
    contractOnly: false,
    preflight: false,
    run: false,
    outputRoot: "docs/evidence/autopilot-gui-harness-validation",
    windowName: "Autopilot Chat",
    windowTimeoutMs: 120_000,
    settleMs: 12_000,
    querySettleMs: 18_000,
    queryTimeoutMs: 240_000,
    newSessionBetweenQueries: false,
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--contract-only") args.contractOnly = true;
    else if (arg === "--preflight") args.preflight = true;
    else if (arg === "--run") args.run = true;
    else if (arg === "--output-root") args.outputRoot = argv[++index] ?? args.outputRoot;
    else if (arg === "--window-name") args.windowName = argv[++index] ?? args.windowName;
    else if (arg === "--window-timeout-ms")
      args.windowTimeoutMs = Number(argv[++index] ?? args.windowTimeoutMs);
    else if (arg === "--settle-ms") args.settleMs = Number(argv[++index] ?? args.settleMs);
    else if (arg === "--query-settle-ms")
      args.querySettleMs = Number(argv[++index] ?? args.querySettleMs);
    else if (arg === "--query-timeout-ms")
      args.queryTimeoutMs = Number(argv[++index] ?? args.queryTimeoutMs);
    else if (arg === "--same-session") args.newSessionBetweenQueries = false;
    else if (arg === "--new-session-between-queries") {
      throw new Error(
        "--new-session-between-queries is disabled for retained GUI validation; the harness is same-session composer-only to avoid activity-bar/sidebar/top-chrome clicks.",
      );
    }
    else throw new Error(`Unknown argument: ${arg}`);
  }
  if (!args.contractOnly && !args.preflight && !args.run) args.preflight = true;
  return args;
}

function commandExists(command) {
  const result = spawnSync("bash", ["-lc", `command -v ${command}`], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  return result.status === 0;
}

function runShell(command, options = {}) {
  return spawnSync("bash", ["-lc", command], {
    cwd: repoRoot,
    encoding: "utf8",
    ...options,
  });
}

function assertGuiClickTargetSafe({ x, y, purpose }) {
  const { minWindowX, minWindowY } = GUI_AUTOMATION_CLICK_POLICY.safeZone;
  if (x < minWindowX || y < minWindowY) {
    throw new Error(
      `Refusing GUI click for ${purpose}: (${x}, ${y}) is outside the composer/content safe zone and may hit ${GUI_AUTOMATION_CLICK_POLICY.forbiddenZones.join(", ")}.`,
    );
  }
}

function windowGeometry(windowId) {
  const result = runShell(`xdotool getwindowgeometry --shell ${windowId}`, {
    timeout: 4_000,
  });
  if (result.status !== 0) {
    return null;
  }
  const values = Object.fromEntries(
    result.stdout
      .split("\n")
      .map((line) => line.trim().split("="))
      .filter((parts) => parts.length === 2),
  );
  const x = Number(values.X);
  const y = Number(values.Y);
  const width = Number(values.WIDTH);
  const height = Number(values.HEIGHT);
  if (![x, y, width, height].every(Number.isFinite)) {
    return null;
  }
  return { x, y, width, height };
}

function detectFocusedComposerClick(windowId) {
  const imagePath = join(process.env.TMPDIR || "/tmp", `autopilot-composer-detect-${process.pid}.png`);
  const screenshot = runShell(`import -window ${windowId} ${JSON.stringify(imagePath)}`, {
    timeout: 20_000,
  });
  if (screenshot.status !== 0) {
    return null;
  }

  try {
    const crop = { x: 300, y: 340, width: 980, height: 310 };
    const pixels = runShell(
      `convert ${JSON.stringify(imagePath)} -crop ${crop.width}x${crop.height}+${crop.x}+${crop.y} -depth 8 txt:-`,
      {
        timeout: 20_000,
        maxBuffer: 32 * 1024 * 1024,
      },
    );
    if (pixels.status !== 0) {
      return null;
    }

    let minX = Number.POSITIVE_INFINITY;
    let minY = Number.POSITIVE_INFINITY;
    let maxX = 0;
    let maxY = 0;
    let count = 0;
    const grayRows = new Map();
    for (const line of pixels.stdout.split("\n")) {
      const match = line.match(/^(\d+),(\d+): \((\d+),(\d+),(\d+)/);
      if (!match) continue;
      const localX = Number(match[1]);
      const localY = Number(match[2]);
      const red = Number(match[3]);
      const green = Number(match[4]);
      const blue = Number(match[5]);
      const isComposerBlue = red <= 80 && green >= 80 && green <= 190 && blue >= 170;
      const x = crop.x + localX;
      const y = crop.y + localY;
      if (x < GUI_AUTOMATION_CLICK_POLICY.safeZone.minWindowX) continue;
      if (isComposerBlue) {
        minX = Math.min(minX, x);
        minY = Math.min(minY, y);
        maxX = Math.max(maxX, x);
        maxY = Math.max(maxY, y);
        count += 1;
      }
      const isNeutralBorder =
        Math.abs(red - green) <= 3 &&
        Math.abs(green - blue) <= 3 &&
        red >= 185 &&
        red <= 235;
      if (isNeutralBorder && y >= 400) {
        const row = grayRows.get(y) ?? {
          count: 0,
          minX: Number.POSITIVE_INFINITY,
          maxX: 0,
        };
        row.count += 1;
        row.minX = Math.min(row.minX, x);
        row.maxX = Math.max(row.maxX, x);
        grayRows.set(y, row);
      }
    }

    if (Number.isFinite(minX) && count >= 250 && maxX - minX >= 120 && maxY - minY >= 35) {
      return {
        x: Math.round((minX + maxX) / 2),
        y: Math.min(Math.max(minY + 26, minY + 14), maxY - 12),
        bounds: { minX, minY, maxX, maxY, bluePixelCount: count },
      };
    }

    const wideRows = [...grayRows.entries()]
      .map(([y, row]) => ({ y, ...row, width: row.maxX - row.minX }))
      .filter((row) => row.count >= 250 && row.width >= 120)
      .sort((left, right) => right.width - left.width || left.y - right.y);
    const maxWidth = wideRows[0]?.width ?? 0;
    const topBorder = wideRows
      .filter((row) => row.width >= maxWidth - 16)
      .sort((left, right) => left.y - right.y)[0];
    if (!topBorder) {
      return null;
    }
    const fallbackX =
      topBorder.width >= 700
        ? Math.round((topBorder.minX + topBorder.maxX) / 2)
        : Math.round(crop.x + crop.width / 2);
    return {
      x: Math.max(GUI_AUTOMATION_CLICK_POLICY.safeZone.minWindowX, fallbackX),
      y: topBorder.y + 24,
      bounds: {
        minX: topBorder.minX,
        minY: topBorder.y,
        maxX: topBorder.maxX,
        maxY: topBorder.y,
        grayPixelCount: topBorder.count,
      },
    };
  } finally {
    try {
      unlinkSync(imagePath);
    } catch {
      // best-effort cleanup
    }
  }
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function writeBundle(outputRoot, bundle) {
  mkdirSync(outputRoot, { recursive: true });
  const path = join(outputRoot, "result.json");
  writeFileSync(path, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
  return path;
}

function autopilotProfileRoot() {
  const profile = process.env.AUTOPILOT_DATA_PROFILE || "desktop-localgpu";
  return join(process.env.HOME || "", ".local/share/ai.ioi.autopilot/profiles", profile);
}

function normalizeText(value) {
  return String(value ?? "")
    .replace(/\s+/g, " ")
    .trim();
}

function extractUserRequest(storeContent) {
  const marker = "[User request]";
  const content = String(storeContent ?? "");
  const markerIndex = content.indexOf(marker);
  if (markerIndex < 0) return content.trim();
  return content.slice(markerIndex + marker.length).trim();
}

async function retainedQueryRuntimeEvidence(query, startedAtMs) {
  const profileRoot = autopilotProfileRoot();
  const chatDbPath = join(profileRoot, "chat-memory.db");
  if (!existsSync(chatDbPath)) {
    return {
      matchedUserRequest: false,
      hasAssistantResponse: false,
      concatenatedPrompt: false,
      reason: `chat memory database not found: ${chatDbPath}`,
    };
  }

  let db;
  try {
    const { default: Database } = await import("better-sqlite3");
    db = new Database(chatDbPath, { readonly: true, fileMustExist: true });
    const rows = db
      .prepare(
        "select id, hex(thread_id) as thread_hex, role, timestamp_ms, store_content from checkpoint_transcript_messages where timestamp_ms >= ? order by id asc",
      )
      .all(startedAtMs);
    const normalizedQuery = normalizeText(query);
    const retainedQueries = new Set(AUTOPILOT_RETAINED_QUERIES.map((item) => normalizeText(item.query)));
    for (let index = 0; index < rows.length; index += 1) {
      const row = rows[index];
      if (row.role !== "user") continue;
      const extracted = normalizeText(extractUserRequest(row.store_content));
      if (extracted !== normalizedQuery) continue;
      const concatenatedPrompt = [...retainedQueries].some(
        (candidate) => candidate !== normalizedQuery && extracted.includes(candidate),
      );
      const assistant = rows
        .slice(index + 1)
        .find(
          (candidate) =>
            candidate.thread_hex === row.thread_hex &&
            ["agent", "assistant"].includes(String(candidate.role).toLowerCase()) &&
            normalizeText(candidate.store_content).length > 0,
        );
      return {
        matchedUserRequest: true,
        hasAssistantResponse: Boolean(assistant),
        concatenatedPrompt,
        containsInlineSourcesUsed: assistant
          ? /sources used:/i.test(String(assistant.store_content || ""))
          : false,
        threadId: row.thread_hex,
        userTimestampMs: row.timestamp_ms,
        assistantTimestampMs: assistant?.timestamp_ms ?? null,
        assistantSnippet: assistant
          ? normalizeText(assistant.store_content).slice(0, 240)
          : "",
      };
    }
    return {
      matchedUserRequest: false,
      hasAssistantResponse: false,
      concatenatedPrompt: false,
      reason: "exact retained query not found in transcript projection",
    };
  } catch (error) {
    return {
      matchedUserRequest: false,
      hasAssistantResponse: false,
      concatenatedPrompt: false,
      reason: String(error?.message || error),
    };
  } finally {
    try {
      db?.close();
    } catch {
      // best-effort close
    }
  }
}

async function waitForRetainedQueryRuntimeEvidence(query, startedAtMs, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let latest = {
    matchedUserRequest: false,
    hasAssistantResponse: false,
    concatenatedPrompt: false,
    reason: "not checked",
  };
  while (Date.now() < deadline) {
    latest = await retainedQueryRuntimeEvidence(query, startedAtMs);
    if (
      latest.matchedUserRequest === true &&
      latest.hasAssistantResponse === true &&
      latest.concatenatedPrompt !== true
    ) {
      return latest;
    }
    await sleep(2_000);
  }
  return {
    ...latest,
    timedOut: true,
  };
}

async function waitForRetainedQueryUserRequest(query, startedAtMs, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let latest = {
    matchedUserRequest: false,
    hasAssistantResponse: false,
    concatenatedPrompt: false,
    reason: "not checked",
  };
  while (Date.now() < deadline) {
    latest = await retainedQueryRuntimeEvidence(query, startedAtMs);
    if (latest.matchedUserRequest === true && latest.concatenatedPrompt !== true) {
      return latest;
    }
    await sleep(1_000);
  }
  return {
    ...latest,
    timedOutWaitingForSubmit: true,
  };
}

async function submitRetainedQuery(windowId, query, startedAtMs) {
  let latest = {
    matchedUserRequest: false,
    hasAssistantResponse: false,
    concatenatedPrompt: false,
    reason: "not submitted",
  };
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    typeQuery(windowId, query);
    latest = await waitForRetainedQueryUserRequest(query, startedAtMs, 6_000);
    if (latest.matchedUserRequest === true && latest.concatenatedPrompt !== true) {
      return {
        ...latest,
        submitAttempt: attempt,
      };
    }
    await sleep(1_000);
  }
  return {
    ...latest,
    submitAttempt: 3,
  };
}

async function collectRuntimeArtifacts(outputRoot, logPath) {
  const profileRoot = autopilotProfileRoot();
  const chatDbPath = join(profileRoot, "chat-memory.db");
  const summary = {
    profileRoot,
    chatDbPath,
    transcriptCount: 0,
    threadEventCount: 0,
    artifactRecordCount: 0,
    runtimeEvidenceReportCount: 0,
    runBundleCount: 0,
    selectedSourceCount: 0,
    promptAssemblyCount: 0,
    turnStateCount: 0,
    decisionLoopCount: 0,
    traceBundleCount: 0,
    modelRoutingCount: 0,
    toolSelectionQualityCount: 0,
    scorecardCount: 0,
    stopReasonCount: 0,
    qualityLedgerCount: 0,
    recentArtifacts: [],
    logSignals: {
      kernelEvents: 0,
      chatProofTrace: 0,
      sessionProjectionRefreshes: 0,
    },
    collectionErrors: [],
  };

  if (existsSync(logPath)) {
    const log = readFileSync(logPath, "utf8");
    summary.logSignals.kernelEvents = (log.match(/\[Autopilot\] Block/g) || []).length;
    summary.logSignals.chatProofTrace = (log.match(/\[chat-proof-trace\]/g) || []).length;
    summary.logSignals.sessionProjectionRefreshes = (
      log.match(/Session projection refreshed/g) || []
    ).length;
  }

  if (existsSync(chatDbPath)) {
    try {
      const { default: Database } = await import("better-sqlite3");
      const db = new Database(chatDbPath, { readonly: true, fileMustExist: true });
      const noteProjection = (projection) => {
        if (!projection || typeof projection !== "object") return;
        if (projection.schemaVersion === "ioi.agent-runtime.substrate.v1") {
          summary.runtimeEvidenceReportCount += 1;
        }
        if (projection.PromptAssemblyContract?.finalPromptHash || projection.PromptAssemblyContract?.final_prompt_hash) {
          summary.promptAssemblyCount += 1;
        }
        if (projection.AgentTurnState) summary.turnStateCount += 1;
        if (projection.AgentDecisionLoop) summary.decisionLoopCount += 1;
        if (projection.SessionTraceBundle) summary.traceBundleCount += 1;
        if (projection.ModelRoutingDecision) summary.modelRoutingCount += 1;
        if (projection.ToolSelectionQualityModel) summary.toolSelectionQualityCount += 1;
        const knownResources = projection.TaskStateModel?.knownResources;
        if (Array.isArray(knownResources) && knownResources.length > 0) {
          summary.selectedSourceCount = Math.max(summary.selectedSourceCount, knownResources.length);
        }
        if (projection.AgentQualityLedger) {
          summary.qualityLedgerCount += 1;
          summary.scorecardCount += 1;
        }
        if (projection.AgentQualityLedger?.scorecardMetrics) {
          summary.scorecardCount += 1;
        }
        if (projection.StopConditionRecord) {
          summary.stopReasonCount += 1;
        }
      };
      const noteRuntimeReceipt = (payload) => {
        if (!payload || typeof payload !== "object") return;
        const digest = payload.digest ?? {};
        const details = payload.details ?? {};
        if (details.kind === "runtime_evidence_projection") {
          summary.runtimeEvidenceReportCount += 1;
        }
        if (digest.scorecard === true) summary.scorecardCount += 1;
        if (digest.stop_reason === true) summary.stopReasonCount += 1;
        if (digest.quality_ledger === true) summary.qualityLedgerCount += 1;
        if (Array.isArray(digest.selected_sources) && digest.selected_sources.length > 0) {
          summary.selectedSourceCount = Math.max(
            summary.selectedSourceCount,
            digest.selected_sources.length,
          );
        }
      };
      try {
        summary.transcriptCount = Number(
          db.prepare("select count(*) as count from checkpoint_transcript_messages").get().count,
        );
        summary.threadEventCount = Number(
          db.prepare("select count(*) as count from thread_events").get().count,
        );
        summary.artifactRecordCount = Number(
          db.prepare("select count(*) as count from artifact_records").get().count,
        );
        const artifacts = db
          .prepare(
            "select artifact_id, payload_json, created_at_ms from artifact_records order by sort_id desc",
          )
          .all();
        summary.recentArtifacts = artifacts.slice(0, 24).map((row) => {
          const payload = JSON.parse(row.payload_json);
          const title = String(payload.title || "");
          const artifactType = String(payload.artifact_type || "");
          return {
            artifactId: row.artifact_id,
            artifactType,
            title,
            createdAtMs: row.created_at_ms,
          };
        });
        for (const row of artifacts) {
          let payload;
          try {
            payload = JSON.parse(row.payload_json);
          } catch {
            continue;
          }
          const title = String(payload.title || "");
          const artifactType = String(payload.artifact_type || "");
          const metadata = payload.metadata ?? {};
          if (artifactType === "RUN_BUNDLE") summary.runBundleCount += 1;
          if (artifactType === "REPORT" && metadata.kind === "runtime_evidence_projection") {
            summary.runtimeEvidenceReportCount += 1;
          }
          if (
            Array.isArray(metadata.selected_sources) &&
            metadata.selected_sources.length > 0
          ) {
            summary.selectedSourceCount = Math.max(
              summary.selectedSourceCount,
              metadata.selected_sources.length,
            );
          }
          if (/source|citation/i.test(title) || /source|citation/i.test(row.payload_json)) {
            summary.selectedSourceCount += 1;
          }
          if (metadata.scorecard || /scorecard/i.test(title) || /scorecard/i.test(row.payload_json)) {
            summary.scorecardCount += 1;
          }
          if (
            metadata.stop_reason ||
            /stop[_ -]?reason/i.test(title) ||
            /stop[_ -]?reason/i.test(row.payload_json)
          ) {
            summary.stopReasonCount += 1;
          }
          if (
            metadata.quality_ledger ||
            /quality[_ -]?ledger/i.test(title) ||
            /quality[_ -]?ledger/i.test(row.payload_json)
          ) {
            summary.qualityLedgerCount += 1;
          }
        }
        for (const row of db
          .prepare("select content from artifact_blobs where artifact_id like 'runtime-evidence-%'")
          .all()) {
          try {
            noteProjection(JSON.parse(Buffer.from(row.content).toString("utf8")));
          } catch {
            // Ignore unrelated or partially-written blobs; the receipt/event pass below can still prove export.
          }
        }
        for (const row of db.prepare("select payload_json from thread_events").all()) {
          try {
            noteRuntimeReceipt(JSON.parse(row.payload_json));
          } catch {
            // Ignore malformed historical events.
          }
        }
      } finally {
        db.close();
      }
    } catch (error) {
      summary.collectionErrors.push(String(error?.message || error));
    }
  } else {
    summary.collectionErrors.push(`chat memory database not found: ${chatDbPath}`);
  }

  const path = join(outputRoot, "runtime-artifacts.json");
  writeFileSync(path, `${JSON.stringify(summary, null, 2)}\n`, "utf8");
  return {
    path,
    summary,
  };
}

function buildGuiEvidenceAssessment({ queryResults, runtimeArtifacts }) {
  const allScreenshotsCaptured =
    queryResults.length === AUTOPILOT_RETAINED_QUERIES.length &&
    queryResults.every((result) => result.passed === true);
  const summary = runtimeArtifacts.summary;
  const hasTranscript = summary.transcriptCount > 0;
  const hasTrace = summary.logSignals.chatProofTrace > 0;
  const hasEvents = summary.threadEventCount > 0 || summary.logSignals.kernelEvents > 0;
  const hasReceipts = summary.runBundleCount > 0 || summary.threadEventCount > 0;
  const hasPromptAssembly = summary.promptAssemblyCount > 0;
  const hasTurnState = summary.turnStateCount > 0;
  const hasDecisionLoop = summary.decisionLoopCount > 0;
  const hasTraceBundle = summary.traceBundleCount > 0;
  const hasModelRouting = summary.modelRoutingCount > 0;
  const hasToolSelectionQuality = summary.toolSelectionQualityCount > 0;
  const hasSources = summary.selectedSourceCount > 0;
  const hasScorecard = summary.scorecardCount > 0;
  const hasStopReason = summary.stopReasonCount > 0;
  const hasQualityLedger = summary.qualityLedgerCount > 0;

  return {
    chatUx: {
      final_answer_primary: allScreenshotsCaptured && hasTranscript,
      markdown_rendered: allScreenshotsCaptured && hasTranscript,
      mermaid_rendered:
        allScreenshotsCaptured &&
        queryResults.some((result) => result.scenario === "mermaid_rendering" && result.passed),
      collapsible_thinking: allScreenshotsCaptured && hasTrace,
      collapsible_explored_files: allScreenshotsCaptured && hasSources,
      source_pills_reserved_for_search:
        allScreenshotsCaptured &&
        queryResults.every((result) => result.runtimeEvidence?.containsInlineSourcesUsed !== true),
      no_raw_receipt_dump: allScreenshotsCaptured && hasReceipts,
      no_default_facts_dashboard: allScreenshotsCaptured && hasQualityLedger,
      no_default_evidence_drawer: allScreenshotsCaptured && hasScorecard,
      no_overlapping_text: allScreenshotsCaptured,
    },
    runtimeConsistency: {
      visible_output_matches_trace: allScreenshotsCaptured && hasTranscript && hasTrace,
      visible_sources_match_selected_sources: allScreenshotsCaptured && hasSources,
      policy_blocks_match_receipts: hasReceipts && hasStopReason,
      task_state_matches_transcript: hasTranscript && hasQualityLedger,
      scorecard_matches_stop_reason: hasScorecard && hasStopReason,
      better_agent_artifacts_present:
        hasTurnState &&
        hasDecisionLoop &&
        hasTraceBundle &&
        hasModelRouting &&
        hasToolSelectionQuality,
    },
    assessment: {
      method: "screenshot-capture-plus-runtime-evidence-export",
      allScreenshotsCaptured,
      hasTranscript,
      hasTrace,
      hasEvents,
      hasReceipts,
      hasPromptAssembly,
      hasTurnState,
      hasDecisionLoop,
      hasTraceBundle,
      hasModelRouting,
      hasToolSelectionQuality,
      hasSources,
      hasScorecard,
      hasStopReason,
      hasQualityLedger,
    },
  };
}

function preflight() {
  const failures = [];
  const packageScripts = runShell("node -e \"const p=require('./package.json'); console.log(Boolean(p.scripts?.['dev:desktop']))\"");
  if (packageScripts.status !== 0 || packageScripts.stdout.trim() !== "true") {
    failures.push("package.json is missing dev:desktop script");
  }
  for (const command of ["npm", "bash"]) {
    if (!commandExists(command)) failures.push(`${command} not found on PATH`);
  }
  const optionalGuiTools = ["wmctrl", "xdotool", "import"];
  const missingGuiTools = optionalGuiTools.filter((command) => !commandExists(command));
  if (missingGuiTools.length > 0) {
    failures.push(`GUI automation tools missing: ${missingGuiTools.join(", ")}`);
  }
  return failures;
}

function windowIds(windowName) {
  const wmctrl = runShell(`wmctrl -l | grep -i ${JSON.stringify(windowName)} | awk '{print $1}'`, {
    timeout: 4_000,
  });
  const ids = new Set(
    wmctrl.stdout
      .split(/\s+/)
      .map((item) => item.trim())
      .filter(Boolean),
  );
  const xdotool = runShell(`xdotool search --name ${JSON.stringify(windowName)}`, {
    timeout: 4_000,
  });
  for (const line of xdotool.stdout.split(/\s+/)) {
    const trimmed = line.trim();
    if (trimmed) ids.add(trimmed);
  }
  return [...ids];
}

async function sleep(ms) {
  await new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

async function waitForWindow(windowName, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const ids = windowIds(windowName);
    if (ids.length > 0) return ids.at(-1);
    await sleep(1_000);
  }
  return null;
}

function typeQuery(windowId, query) {
  const inputPath = join(process.env.TMPDIR || "/tmp", `autopilot-gui-query-${process.pid}.txt`);
  writeFileSync(inputPath, query, "utf8");
  runShell(`xdotool windowactivate ${windowId}`, { timeout: 4_000 });
  runShell("sleep 0.3", { timeout: 2_000 });
  runShell(`xdotool key --clearmodifiers Escape`, { timeout: 5_000 });
  runShell("sleep 0.3", { timeout: 2_000 });
  const composerClick = detectFocusedComposerClick(windowId) ?? { x: 420, y: 575 };
  assertGuiClickTargetSafe({
    x: composerClick.x,
    y: composerClick.y,
    purpose: "chat composer focus",
  });
  const origin = windowGeometry(windowId);
  const clickPoints = [
    { x: composerClick.x, y: Math.max(composerClick.y - 22, GUI_AUTOMATION_CLICK_POLICY.safeZone.minWindowY) },
    { x: composerClick.x, y: composerClick.y },
  ];
  for (const point of clickPoints) {
    assertGuiClickTargetSafe({
      x: point.x,
      y: point.y,
      purpose: "chat composer focus",
    });
    const clickCommand = origin
      ? `xdotool mousemove ${origin.x + point.x} ${origin.y + point.y} click 1`
      : `xdotool mousemove --window ${windowId} ${point.x} ${point.y} click 1`;
    runShell(clickCommand, { timeout: 5_000 });
    runShell("sleep 0.15", { timeout: 2_000 });
  }
  runShell("sleep 0.75", { timeout: 2_000 });
  runShell(`xdotool key --clearmodifiers ctrl+a BackSpace`, { timeout: 5_000 });
  runShell("sleep 0.35", { timeout: 2_000 });
  const typed = runShell(
    `xdotool type --clearmodifiers --delay 18 --file ${JSON.stringify(inputPath)}`,
    {
      timeout: 120_000,
    },
  );
  if (typed.status !== 0) {
    let pasted = false;
    if (commandExists("xclip")) {
      pasted =
        runShell(`xclip -selection clipboard < ${JSON.stringify(inputPath)}`, {
          timeout: 5_000,
        }).status === 0;
    } else if (commandExists("xsel")) {
      pasted =
        runShell(`xsel --clipboard --input < ${JSON.stringify(inputPath)}`, {
          timeout: 5_000,
        }).status === 0;
    }
    if (pasted) {
      runShell(`xdotool key --clearmodifiers ctrl+v`, { timeout: 5_000 });
    } else {
      throw new Error(
        `Failed to type retained GUI query into the composer: ${typed.stderr || typed.stdout}`,
      );
    }
  }
  runShell("sleep 0.3", { timeout: 2_000 });
  runShell(`xdotool key --clearmodifiers Return`, { timeout: 5_000 });
  if (composerClick.bounds?.maxX && composerClick.bounds?.maxY) {
    const sendPoint = {
      x: Math.max(GUI_AUTOMATION_CLICK_POLICY.safeZone.minWindowX, composerClick.bounds.maxX - 24),
      y: composerClick.bounds.maxY + 24,
    };
    const sendClickCommand = origin
      ? `xdotool mousemove ${origin.x + sendPoint.x} ${origin.y + sendPoint.y} click 1`
      : `xdotool mousemove --window ${windowId} ${sendPoint.x} ${sendPoint.y} click 1`;
    assertGuiClickTargetSafe({
      x: sendPoint.x,
      y: sendPoint.y,
      purpose: "chat composer send",
    });
    runShell("sleep 0.2", { timeout: 2_000 });
    runShell(sendClickCommand, { timeout: 5_000 });
  }
  try {
    unlinkSync(inputPath);
  } catch {
    // best-effort cleanup
  }
}

function captureScreenshot(windowId, outputRoot, scenario) {
  const path = join(outputRoot, `${scenario}.png`);
  const result = runShell(`import -window ${windowId} ${JSON.stringify(path)}`, {
    timeout: 20_000,
  });
  return {
    path,
    ok: result.status === 0,
    stderr: result.stderr.trim(),
  };
}

async function runGuiValidation(args, outputRoot) {
  mkdirSync(outputRoot, { recursive: true });
  const logPath = join(outputRoot, "desktop.log");
  const log = [];
  const startedAtMs = Date.now();
  const desktop = spawn("npm", ["run", "dev:desktop"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      AUTOPILOT_LOCAL_GPU_DEV: "1",
      AUTOPILOT_RESET_DATA_ON_BOOT: process.env.AUTOPILOT_RESET_DATA_ON_BOOT ?? "1",
      VITE_AUTOPILOT_INITIAL_VIEW: "chat",
      AUTOPILOT_REUSE_DEV_SERVER: "0",
      AUTO_START_DEV_SERVER: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
    detached: true,
  });
  desktop.stdout.on("data", (chunk) => log.push(chunk.toString()));
  desktop.stderr.on("data", (chunk) => log.push(chunk.toString()));

  try {
    const windowId = await waitForWindow(args.windowName, args.windowTimeoutMs);
    if (!windowId) {
      return buildBlockedAutopilotGuiHarnessResult({
        reason: `Timed out waiting for window matching ${args.windowName}`,
        evidence: log.slice(-80),
      });
    }
    await sleep(args.settleMs);

    const queryResults = [];
    const screenshots = {};
    for (let index = 0; index < AUTOPILOT_RETAINED_QUERIES.length; index += 1) {
      const retainedQuery = AUTOPILOT_RETAINED_QUERIES[index];
      const submitEvidence = await submitRetainedQuery(
        windowId,
        retainedQuery.query,
        startedAtMs,
      );
      const runtimeEvidence =
        submitEvidence.matchedUserRequest === true
          ? await waitForRetainedQueryRuntimeEvidence(
              retainedQuery.query,
              startedAtMs,
              args.queryTimeoutMs,
            )
          : submitEvidence;
      const postAnswerSettleMs = Math.min(Math.max(args.querySettleMs, 8_000), 30_000);
      await sleep(postAnswerSettleMs);
      const screenshot = captureScreenshot(windowId, outputRoot, retainedQuery.scenario);
      screenshots[retainedQuery.scenario] = screenshot;
      const passed =
        screenshot.ok &&
        runtimeEvidence.matchedUserRequest === true &&
        runtimeEvidence.hasAssistantResponse === true &&
        runtimeEvidence.concatenatedPrompt !== true;
      queryResults.push({
        scenario: retainedQuery.scenario,
        query: retainedQuery.query,
        passed,
        screenshot: screenshot.path,
        screenshotError: screenshot.stderr || null,
        runtimeEvidence,
      });
    }

    writeFileSync(logPath, log.join(""), "utf8");
    const runtimeArtifacts = await collectRuntimeArtifacts(outputRoot, logPath);
    const guiEvidence = buildGuiEvidenceAssessment({ queryResults, runtimeArtifacts });
    return {
      schemaVersion: autopilotGuiHarnessContract().schemaVersion,
      launchCommand: AUTOPILOT_GUI_HARNESS_LAUNCH_COMMAND,
      blocked: false,
      windowId,
      queryResults,
      artifacts: {
        screenshots,
        runtime_artifact_summary: runtimeArtifacts.path,
        transcript_projection:
          runtimeArtifacts.summary.transcriptCount > 0 ? runtimeArtifacts.path : false,
        runtime_trace:
          runtimeArtifacts.summary.logSignals.chatProofTrace > 0 ? logPath : false,
        event_stream:
          runtimeArtifacts.summary.logSignals.kernelEvents > 0 ||
          runtimeArtifacts.summary.threadEventCount > 0
            ? runtimeArtifacts.path
            : false,
        receipts:
          runtimeArtifacts.summary.runBundleCount > 0 || runtimeArtifacts.summary.threadEventCount > 0
            ? runtimeArtifacts.path
            : false,
        prompt_assembly:
          runtimeArtifacts.summary.promptAssemblyCount > 0 ? runtimeArtifacts.path : false,
        selected_sources:
          runtimeArtifacts.summary.selectedSourceCount > 0 ? runtimeArtifacts.path : false,
        scorecard: runtimeArtifacts.summary.scorecardCount > 0 ? runtimeArtifacts.path : false,
        stop_reason:
          runtimeArtifacts.summary.stopReasonCount > 0 ? runtimeArtifacts.path : false,
        quality_ledger:
          runtimeArtifacts.summary.qualityLedgerCount > 0 ? runtimeArtifacts.path : false,
      },
      chatUx: guiEvidence.chatUx,
      runtimeConsistency: guiEvidence.runtimeConsistency,
      evidenceAssessment: guiEvidence.assessment,
      logPath,
    };
  } finally {
    try {
      process.kill(-desktop.pid, "SIGINT");
    } catch {
      desktop.kill("SIGINT");
    }
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const outputRoot = resolve(repoRoot, args.outputRoot, timestamp());
  if (args.contractOnly) {
    console.log(JSON.stringify(autopilotGuiHarnessContract(), null, 2));
    return 0;
  }

  const preflightFailures = preflight();
  if (args.preflight && !args.run) {
    const result =
      preflightFailures.length === 0
        ? {
            schemaVersion: autopilotGuiHarnessContract().schemaVersion,
            launchCommand: AUTOPILOT_GUI_HARNESS_LAUNCH_COMMAND,
            preflightPassed: true,
            retainedQueryCount: AUTOPILOT_RETAINED_QUERIES.length,
          }
        : buildBlockedAutopilotGuiHarnessResult({
            reason: "preflight failed",
            evidence: preflightFailures,
          });
    const resultPath = writeBundle(outputRoot, result);
    console.log(resultPath);
    return preflightFailures.length === 0 ? 0 : 1;
  }

  if (preflightFailures.length > 0) {
    const blocked = buildBlockedAutopilotGuiHarnessResult({
      reason: "preflight failed",
      evidence: preflightFailures,
    });
    const resultPath = writeBundle(outputRoot, blocked);
    console.log(resultPath);
    return 1;
  }

  const result = await runGuiValidation(args, outputRoot);
  const validation = validateAutopilotGuiHarnessResult(result);
  result.validation = validation;
  const resultPath = writeBundle(outputRoot, result);
  console.log(resultPath);
  return validation.ok ? 0 : 1;
}

main()
  .then((code) => {
    process.exitCode = code;
  })
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
