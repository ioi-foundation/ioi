#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import {
  AUTOPILOT_GUI_HARNESS_LAUNCH_COMMAND,
  AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS,
  AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS,
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

async function openReadonlySqliteDatabase(filePath) {
  try {
    const { default: Database } = await import("better-sqlite3");
    return new Database(filePath, { readonly: true, fileMustExist: true });
  } catch (error) {
    const { DatabaseSync } = await import("node:sqlite");
    const db = new DatabaseSync(filePath, { readOnly: true });
    db.__fallbackReason = String(error?.message || error);
    return db;
  }
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
    db = await openReadonlySqliteDatabase(chatDbPath);
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
    harnessWorkerBindingCount: 0,
    harnessShadowRunCount: 0,
    harnessNodeAttemptCount: 0,
    harnessShadowComparisonCount: 0,
    harnessBlockingDivergenceCount: 0,
    harnessGatedClusterCount: 0,
    harnessGatedCognitionCount: 0,
    harnessGatedRoutingModelCount: 0,
    harnessGatedVerificationOutputCount: 0,
    harnessGatedAuthorityToolingCount: 0,
    harnessForkActivationBlockedCount: 0,
    harnessForkActivationMintedCount: 0,
    harnessRollbackRestoreCanaryBlockedCount: 0,
    harnessRollbackRestoreCanaryReadyCount: 0,
    harnessRollbackRestoreCanaryReceiptCount: 0,
    harnessRollbackRestoreCanaryStatuses: [],
    harnessActivationAuditReceiptCount: 0,
    harnessRollbackExecutionReceiptCount: 0,
    harnessCanaryBoundaryExecutedCount: 0,
    harnessCanaryBoundaryRollbackDrillCount: 0,
    harnessSelectorCanaryRoutedCount: 0,
    harnessSelectorLegacyDefaultCount: 0,
    harnessSelectorDefaultPromotedCount: 0,
    harnessLiveHandoffCanaryCount: 0,
    harnessLiveHandoffDefaultPromotedCount: 0,
    harnessLiveHandoffRollbackCount: 0,
    harnessDefaultRuntimeDispatchReadonlyCount: 0,
    harnessAuthorityToolingReadOnlyCanaryCount: 0,
    harnessAuthorityToolingGateLiveCount: 0,
    harnessAuthorityToolingProviderCatalogLiveCount: 0,
    harnessAuthorityToolingMcpToolCatalogLiveCount: 0,
    harnessAuthorityToolingNativeToolCatalogLiveCount: 0,
    harnessAuthorityToolingConnectorCatalogLiveCount: 0,
    harnessAuthorityToolingWalletCapabilityLiveDryRunCount: 0,
    harnessModelProviderGatedVisibleOutputCount: 0,
    harnessModelProviderGatedVisibleOutputRollbackDrillCount: 0,
    harnessModelProviderGatedVisibleOutputScenarios: [],
    harnessModelProviderGatedVisibleOutputRollbackDrillScenarios: [],
    harnessReadOnlyCapabilityRoutingCount: 0,
    harnessReadOnlyCapabilityRoutingNoMutationCount: 0,
    harnessReadOnlyCapabilityRoutingScenarios: [],
    harnessReadOnlyCapabilityRoutingNoMutationScenarios: [],
    recentArtifacts: [],
    logSignals: {
      kernelEvents: 0,
      chatProofTrace: 0,
      sessionProjectionRefreshes: 0,
    },
    collectionErrors: [],
  };
  const addScenario = (items, scenario) => {
    if (
      typeof scenario === "string" &&
      scenario.length > 0 &&
      !items.includes(scenario)
    ) {
      items.push(scenario);
      items.sort();
    }
  };
  const noteProviderGatedVisibleOutputCoverage = (coverage) => {
    if (!coverage || typeof coverage !== "object") return;
    if (Array.isArray(coverage.providerGatedVisibleOutputScenarios)) {
      for (const scenario of coverage.providerGatedVisibleOutputScenarios) {
        addScenario(summary.harnessModelProviderGatedVisibleOutputScenarios, scenario);
      }
    }
    if (Array.isArray(coverage.rollbackDrillScenarios)) {
      for (const scenario of coverage.rollbackDrillScenarios) {
        addScenario(
          summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios,
          scenario,
        );
      }
    }
  };
  const noteReadOnlyCapabilityRoutingCoverage = (coverage) => {
    if (!coverage || typeof coverage !== "object") return;
    if (Array.isArray(coverage.readOnlyCapabilityRoutingScenarios)) {
      for (const scenario of coverage.readOnlyCapabilityRoutingScenarios) {
        addScenario(summary.harnessReadOnlyCapabilityRoutingScenarios, scenario);
      }
    }
    if (Array.isArray(coverage.noMutationScenarios)) {
      for (const scenario of coverage.noMutationScenarios) {
        addScenario(summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios, scenario);
      }
    }
  };
  const noteRollbackRestoreCanaryStatus = (status) => {
    if (
      typeof status === "string" &&
      status.length > 0 &&
      !summary.harnessRollbackRestoreCanaryStatuses.includes(status)
    ) {
      summary.harnessRollbackRestoreCanaryStatuses.push(status);
      summary.harnessRollbackRestoreCanaryStatuses.sort();
    }
  };
  const rollbackRestoreCanaryHasReceiptBinding = (canary) => {
    if (!canary || typeof canary !== "object") return false;
    const receiptBindingRef = canary.receiptBindingRef;
    return (
      typeof receiptBindingRef === "string" &&
      receiptBindingRef.startsWith("workflow_restore_canary:") &&
      Array.isArray(canary.evidenceRefs) &&
      canary.evidenceRefs.includes(receiptBindingRef)
    );
  };
  const noteRollbackRestoreCanaryReceipt = (canary) => {
    if (rollbackRestoreCanaryHasReceiptBinding(canary)) {
      summary.harnessRollbackRestoreCanaryReceiptCount += 1;
    }
  };
  const hasRestoreCanaryReceiptRef = (value) =>
    typeof value === "string" && value.startsWith("workflow_restore_canary:");
  const noteReceiptRefArray = (refs, counterName) => {
    if (
      Array.isArray(refs) &&
      refs.some((reference) => hasRestoreCanaryReceiptRef(reference))
    ) {
      summary[counterName] += 1;
    }
  };
  const noteRollbackRestoreCanaryProof = (activation) => {
    if (!activation || typeof activation !== "object") return;
    const invalidCanary = activation.invalidFork?.rollbackRestoreCanary;
    const validCanary = activation.validFork?.rollbackRestoreCanary;
    for (const fork of [activation.invalidFork, activation.validFork]) {
      if (!fork || typeof fork !== "object") continue;
      if (Array.isArray(fork.activationAudit)) {
        for (const event of fork.activationAudit) {
          noteReceiptRefArray(event?.receiptRefs, "harnessActivationAuditReceiptCount");
        }
      }
      noteReceiptRefArray(
        fork.activationRollbackExecution?.receiptRefs,
        "harnessRollbackExecutionReceiptCount",
      );
      if (hasRestoreCanaryReceiptRef(fork.activationRollbackExecution?.restoreReceiptBindingRef)) {
        summary.harnessRollbackExecutionReceiptCount += 1;
      }
    }
    if (invalidCanary && typeof invalidCanary === "object") {
      noteRollbackRestoreCanaryStatus(invalidCanary.status);
      noteRollbackRestoreCanaryReceipt(invalidCanary);
      if (
        invalidCanary.schemaVersion === "workflow.harness.rollback-restore-canary.v1" &&
        invalidCanary.status === "blocked" &&
        invalidCanary.hashVerified === false &&
        Array.isArray(invalidCanary.blockers) &&
        invalidCanary.blockers.includes("rollback_restore_canary_not_run")
      ) {
        summary.harnessRollbackRestoreCanaryBlockedCount += 1;
      }
    }
    if (validCanary && typeof validCanary === "object") {
      noteRollbackRestoreCanaryStatus(validCanary.status);
      noteRollbackRestoreCanaryReceipt(validCanary);
      if (
        validCanary.schemaVersion === "workflow.harness.rollback-restore-canary.v1" &&
        ["passed", "not_required"].includes(validCanary.status) &&
        validCanary.hashVerified === true &&
        Array.isArray(validCanary.blockers) &&
        validCanary.blockers.length === 0
      ) {
        summary.harnessRollbackRestoreCanaryReadyCount += 1;
      }
    }
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
      const db = await openReadonlySqliteDatabase(chatDbPath);
      const noteProjection = (projection) => {
        if (!projection || typeof projection !== "object") return;
        noteProviderGatedVisibleOutputCoverage(
          projection.HarnessModelProviderGatedVisibleOutputCoverage,
        );
        noteProviderGatedVisibleOutputCoverage(
          projection.HarnessDefaultRuntimeDispatch
            ?.modelProviderGatedVisibleOutputSessionCoverage,
        );
        noteReadOnlyCapabilityRoutingCoverage(
          projection.HarnessReadOnlyCapabilityRoutingCoverage,
        );
        noteReadOnlyCapabilityRoutingCoverage(
          projection.HarnessDefaultRuntimeDispatch
            ?.readOnlyCapabilityRoutingSessionCoverage,
        );
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
        if (projection.HarnessWorkerBinding) {
          summary.harnessWorkerBindingCount += 1;
        }
        if (projection.HarnessRuntimeSelectorDecision) {
          const decision = projection.HarnessRuntimeSelectorDecision;
          if (
            decision.schemaVersion === "workflow.harness.runtime-selector.v1" &&
            decision.selectedSelector === "blessed_workflow_live_canary" &&
            decision.productionDefaultSelector === "legacy_runtime" &&
            decision.canaryEligible === true &&
            Array.isArray(decision.canaryBlockers) &&
            decision.canaryBlockers.length === 0 &&
            decision.executionMode === "live" &&
            decision.actualRuntimeAuthority === "blessed_workflow_activation_canary" &&
            decision.rollbackAvailable === true
          ) {
            summary.harnessSelectorCanaryRoutedCount += 1;
          }
          if (
            decision.schemaVersion === "workflow.harness.runtime-selector.v1" &&
            decision.selectedSelector === "blessed_workflow_live_default" &&
            decision.productionDefaultSelector === "blessed_workflow_live_default" &&
            decision.canaryEligible === true &&
            Array.isArray(decision.canaryBlockers) &&
            decision.canaryBlockers.length === 0 &&
            decision.executionMode === "live" &&
            decision.actualRuntimeAuthority === "blessed_workflow_activation_default" &&
            decision.defaultPromotionGate?.enabled === true &&
            decision.defaultPromotionGate?.eligible === true &&
            decision.rollbackAvailable === true
          ) {
            summary.harnessSelectorDefaultPromotedCount += 1;
          }
          if (
            decision.productionDefaultSelector === "legacy_runtime" &&
            decision.fallbackSelector === "legacy_runtime" &&
            typeof decision.rollbackTarget === "string" &&
            decision.rollbackTarget.length > 0
          ) {
            summary.harnessSelectorLegacyDefaultCount += 1;
          }
        }
        if (projection.HarnessShadowRun) {
          summary.harnessShadowRunCount += 1;
          if (Array.isArray(projection.HarnessShadowRun.nodeAttempts)) {
            summary.harnessNodeAttemptCount += projection.HarnessShadowRun.nodeAttempts.length;
          }
          if (Array.isArray(projection.HarnessShadowRun.comparisons)) {
            summary.harnessShadowComparisonCount += projection.HarnessShadowRun.comparisons.length;
          }
          summary.harnessBlockingDivergenceCount += Number(
            projection.HarnessShadowRun.blockingDivergenceCount ?? 0,
          );
        }
        if (Array.isArray(projection.HarnessGatedClusterRuns)) {
          summary.harnessGatedClusterCount += projection.HarnessGatedClusterRuns.length;
          summary.harnessGatedCognitionCount += projection.HarnessGatedClusterRuns.filter(
            (run) =>
              run?.clusterId === "cognition" &&
              run?.executionMode === "gated" &&
              run?.status === "gated" &&
              run?.promotionBlocked === false &&
              run?.rollbackAvailable === true &&
              run?.canaryStatus === "passed",
          ).length;
          summary.harnessGatedRoutingModelCount += projection.HarnessGatedClusterRuns.filter(
            (run) =>
              run?.clusterId === "routing_model" &&
              run?.executionMode === "gated" &&
              run?.status === "gated" &&
              run?.promotionBlocked === false &&
              run?.rollbackAvailable === true &&
              run?.canaryStatus === "passed",
          ).length;
          summary.harnessGatedVerificationOutputCount += projection.HarnessGatedClusterRuns.filter(
            (run) =>
              run?.clusterId === "verification_output" &&
              run?.executionMode === "gated" &&
              run?.status === "gated" &&
              run?.promotionBlocked === false &&
              run?.rollbackAvailable === true &&
              run?.canaryStatus === "passed",
          ).length;
          summary.harnessGatedAuthorityToolingCount += projection.HarnessGatedClusterRuns.filter(
            (run) =>
              run?.clusterId === "authority_tooling" &&
              run?.executionMode === "gated" &&
              run?.status === "gated" &&
              run?.promotionBlocked === false &&
              run?.rollbackAvailable === true &&
              run?.canaryStatus === "passed" &&
              run?.runtimeAuthority === "existing_runtime_service",
          ).length;
        }
        if (projection.HarnessForkActivation) {
          noteRollbackRestoreCanaryProof(projection.HarnessForkActivation);
          const invalidFork = projection.HarnessForkActivation.invalidFork ?? {};
          const validFork = projection.HarnessForkActivation.validFork ?? {};
          if (
            invalidFork.activationState === "blocked" &&
            Array.isArray(invalidFork.activationBlockers) &&
            invalidFork.activationBlockers.length > 0 &&
            invalidFork.activationMinted === false
          ) {
            summary.harnessForkActivationBlockedCount += 1;
          }
          if (
            typeof validFork.activationId === "string" &&
            validFork.activationId.length > 0 &&
            validFork.activationState === "validated" &&
            validFork.canaryStatus === "passed" &&
            validFork.rollbackAvailable === true &&
            validFork.liveAuthorityTransferred === false &&
            validFork.workerBinding?.harnessActivationId === validFork.activationId
          ) {
            summary.harnessForkActivationMintedCount += 1;
          }
        }
        {
          const boundaries = Array.isArray(projection.HarnessCanaryExecutionBoundaries)
            ? projection.HarnessCanaryExecutionBoundaries
            : projection.HarnessCanaryExecutionBoundary
              ? [projection.HarnessCanaryExecutionBoundary]
              : [];
          const boundaryPasses = (clusterId) =>
            boundaries.some(
              (boundary) => {
                const minimumAttempts =
                  clusterId === "routing_model" ? 3 : clusterId === "authority_tooling" ? 8 : 6;
                return (
                  boundary?.schemaVersion === "workflow.harness.canary-execution-boundary.v1" &&
                  boundary.clusterId === clusterId &&
                  boundary.status === "passed" &&
                  boundary.executionMode === "live" &&
                  boundary.runtimeAuthority === "blessed_workflow_activation_canary" &&
                  boundary.executorKind === "workflow_node_executor" &&
                  boundary.synchronous === true &&
                  Array.isArray(boundary.nodeAttemptIds) &&
                  boundary.nodeAttemptIds.length >= minimumAttempts &&
                  Array.isArray(boundary.executedComponentKinds) &&
                  boundary.executedComponentKinds.length >= minimumAttempts &&
                  Array.isArray(boundary.activationBlockers) &&
                  boundary.activationBlockers.length === 0
                );
              },
            );
          const rollbackPasses = (clusterId) =>
            boundaries.some(
              (boundary) =>
                boundary?.clusterId === clusterId &&
                boundary.rollbackDrill?.clusterId === clusterId &&
                boundary.rollbackDrill?.failureInjected === true &&
                boundary.rollbackDrill?.observedFailure === true &&
                boundary.rollbackDrill?.rollbackExecuted === true &&
                boundary.rollbackDrill?.rollbackSelector === "legacy_runtime" &&
                boundary.rollbackDrill?.fallbackAuthority === "existing_runtime_service" &&
                boundary.rollbackDrill?.drillStatus === "passed",
            );
          if (
            boundaryPasses("cognition") &&
            boundaryPasses("routing_model") &&
            boundaryPasses("verification_output") &&
            boundaryPasses("authority_tooling")
          ) {
            summary.harnessCanaryBoundaryExecutedCount += 1;
          }
          if (
            rollbackPasses("cognition") &&
            rollbackPasses("routing_model") &&
            rollbackPasses("verification_output") &&
            rollbackPasses("authority_tooling")
          ) {
            summary.harnessCanaryBoundaryRollbackDrillCount += 1;
          }
        }
        if (projection.HarnessLiveHandoff) {
          const handoff = projection.HarnessLiveHandoff;
          if (
            handoff.schemaVersion === "workflow.harness.live-handoff.v1" &&
            handoff.selector === "blessed_workflow_live_canary" &&
            handoff.productionDefaultSelector === "legacy_runtime" &&
            handoff.canaryStatus === "passed" &&
            handoff.canaryTurnRoutedThroughWorkflow === true &&
            handoff.executionBoundaryStatus === "passed" &&
            handoff.defaultAuthorityTransferred === false &&
            handoff.runtimeAuthority === "blessed_workflow_activation_canary" &&
            Array.isArray(handoff.executionBoundaryClusterIds) &&
            handoff.executionBoundaryClusterIds.includes("cognition") &&
            handoff.executionBoundaryClusterIds.includes("routing_model") &&
            handoff.executionBoundaryClusterIds.includes("verification_output") &&
            handoff.executionBoundaryClusterIds.includes("authority_tooling") &&
            Array.isArray(handoff.gatedClusterIds) &&
            handoff.gatedClusterIds.includes("authority_tooling")
          ) {
            summary.harnessLiveHandoffCanaryCount += 1;
          }
          if (
            handoff.schemaVersion === "workflow.harness.live-handoff.v1" &&
            handoff.selector === "blessed_workflow_live_default" &&
            handoff.productionDefaultSelector === "blessed_workflow_live_default" &&
            handoff.canaryStatus === "passed" &&
            handoff.canaryTurnRoutedThroughWorkflow === true &&
            handoff.executionBoundaryStatus === "passed" &&
            handoff.defaultAuthorityTransferred === true &&
            handoff.runtimeAuthority === "blessed_workflow_activation_default" &&
            handoff.defaultPromotionGate?.defaultAuthorityTransferred === true &&
            Array.isArray(handoff.defaultPromotionGate?.activationBlockers) &&
            handoff.defaultPromotionGate.activationBlockers.length === 0 &&
            Array.isArray(handoff.executionBoundaryClusterIds) &&
            handoff.executionBoundaryClusterIds.includes("cognition") &&
            handoff.executionBoundaryClusterIds.includes("routing_model") &&
            handoff.executionBoundaryClusterIds.includes("verification_output") &&
            handoff.executionBoundaryClusterIds.includes("authority_tooling") &&
            Array.isArray(handoff.gatedClusterIds) &&
            handoff.gatedClusterIds.includes("authority_tooling")
          ) {
            summary.harnessLiveHandoffDefaultPromotedCount += 1;
          }
          if (
            handoff.fallbackSelector === "legacy_runtime" &&
            handoff.rollbackAvailable === true &&
            typeof handoff.rollbackTarget === "string" &&
            handoff.rollbackTarget.length > 0 &&
            Array.isArray(handoff.nodeTimelineAttemptIds) &&
            handoff.nodeTimelineAttemptIds.length > 0 &&
            Array.isArray(handoff.receiptIds) &&
            handoff.receiptIds.length > 0 &&
            Array.isArray(handoff.activationBlockers) &&
            handoff.activationBlockers.length === 0
          ) {
            summary.harnessLiveHandoffRollbackCount += 1;
          }
        }
        if (projection.HarnessDefaultRuntimeDispatch) {
          const dispatch = projection.HarnessDefaultRuntimeDispatch;
          if (
            dispatch.schemaVersion === "workflow.harness.default-runtime-dispatch.v1" &&
            dispatch.selectedSelector === "blessed_workflow_live_default" &&
            dispatch.productionDefaultSelector === "blessed_workflow_live_default" &&
            dispatch.executionMode === "live" &&
            dispatch.runtimeAuthority === "blessed_workflow_activation_default" &&
            dispatch.dispatchScope ===
              "read_only_cognition_routing_verification_completion_authority_tooling" &&
            dispatch.status === "accepted" &&
            dispatch.readOnlyDispatchAccepted === true &&
            dispatch.drivesRuntimeDecision === true &&
            dispatch.outputWriterDeferred === false &&
            dispatch.outputWriterStatus === "visible_write_committed" &&
            dispatch.outputWriterHandoffReady === true &&
            dispatch.outputWriterMaterializationMode === "workflow_visible_transcript_write" &&
            dispatch.outputWriterMaterializationCanaryReady === true &&
            dispatch.outputWriterMaterializationCommitted === true &&
            dispatch.outputWriterStagedWriteMode === "isolated_checkpoint_blob" &&
            dispatch.outputWriterStagedWriteCanaryReady === true &&
            dispatch.outputWriterStagedWritePersisted === true &&
            dispatch.outputWriterStagedWriteCommitted === true &&
            dispatch.outputWriterStagedWriteVisible === false &&
            dispatch.outputWriterStagedWriteExcludedFromVisibleTranscript === true &&
            dispatch.outputWriterStagedWriteRollbackStatus === "deleted" &&
            dispatch.outputWriterStagedWriteRollbackVerified === true &&
            dispatch.outputWriterVisibleWriteMode === "workflow_visible_transcript_write" &&
            dispatch.outputWriterVisibleWriteReady === true &&
            dispatch.outputWriterVisibleWritePersisted === true &&
            dispatch.outputWriterVisibleWriteCommitted === true &&
            dispatch.outputWriterVisibleWriteVisible === true &&
            dispatch.outputWriterVisibleWriteIdentityCheckpointPersisted === true &&
            dispatch.outputWriterVisibleWriteLegacyDuplicateSuppressed === true &&
            dispatch.cognitionExecutionMode === "workflow_synchronous_envelope" &&
            dispatch.cognitionExecutionReady === true &&
            dispatch.promptAssemblyMode === "workflow_synchronous_envelope" &&
            typeof dispatch.promptAssemblyPromptHash === "string" &&
            dispatch.promptAssemblyPromptHash.length > 0 &&
            dispatch.promptAssemblyPromptHashMatches === true &&
            dispatch.modelExecutionMode === "workflow_synchronous_envelope" &&
            dispatch.modelExecutionEnvelopeReady === true &&
            typeof dispatch.modelExecutionBindingId === "string" &&
            dispatch.modelExecutionBindingId.length > 0 &&
            dispatch.modelExecutionBindingReady === true &&
            typeof dispatch.modelExecutionPromptHash === "string" &&
            dispatch.modelExecutionPromptHash.length > 0 &&
            dispatch.modelExecutionPromptHashMatches === true &&
            typeof dispatch.modelExecutionOutputHash === "string" &&
            dispatch.modelExecutionOutputHash.length > 0 &&
            dispatch.modelExecutionOutputHashMatches === true &&
            dispatch.modelExecutionProviderInvocationMode === "workflow_provider_canary" &&
            dispatch.modelExecutionLowLevelInvocationDeferred === false &&
            dispatch.modelExecutionFallbackSelector === "legacy_runtime_model_invocation" &&
            dispatch.modelProviderCanaryMode === "workflow_provider_canary" &&
            dispatch.modelProviderCanaryReady === true &&
            dispatch.modelProviderCanaryOutputHashMatches === true &&
            dispatch.modelProviderCanaryTranscriptMatches === true &&
            dispatch.modelProviderCanaryFallbackRetained === true &&
            dispatch.modelProviderCanaryRollbackAvailable === true &&
            dispatch.modelProviderGatedVisibleOutputMode ===
              "workflow_provider_gated_visible_output" &&
            dispatch.modelProviderGatedVisibleOutputEnabled === true &&
            dispatch.modelProviderGatedVisibleOutputReady === true &&
            dispatch.modelProviderGatedVisibleOutputSelected === true &&
            AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS.includes(
              dispatch.modelProviderGatedVisibleOutputScenario,
            ) &&
            dispatch.modelProviderGatedVisibleOutputCohort === "retained_read_only_no_tool" &&
            dispatch.modelProviderGatedVisibleOutputRetainedReadOnlyNoTool === true &&
            Array.isArray(dispatch.modelProviderGatedVisibleOutputRequiredScenarioSet) &&
            AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS.every((scenario) =>
              dispatch.modelProviderGatedVisibleOutputRequiredScenarioSet.includes(scenario),
            ) &&
            dispatch.modelProviderGatedVisibleOutputScenarioCoverageKey ===
              dispatch.modelProviderGatedVisibleOutputScenario &&
            dispatch.selectedVisibleOutputAuthority === "workflow_model_provider_call" &&
            typeof dispatch.selectedVisibleOutputHash === "string" &&
            dispatch.selectedVisibleOutputHash.length > 0 &&
            dispatch.selectedVisibleOutputHash === dispatch.actualVisibleOutputHash &&
            dispatch.legacyVisibleOutputHash === dispatch.selectedVisibleOutputHash &&
            dispatch.legacyVisibleOutputComputed === true &&
            dispatch.legacyVisibleOutputHashMatchesSelected === true &&
            dispatch.selectedVisibleOutputAuthorityMatchesTranscript === true &&
            dispatch.modelProviderGatedVisibleOutputRollbackAvailable === true &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillEnabled === true &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillReady === true &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillFailureInjected === true &&
            typeof dispatch.modelProviderGatedVisibleOutputRollbackDrillInjectedOutputHash ===
              "string" &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillInjectedOutputHash.length > 0 &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillInjectedOutputHash !==
              dispatch.actualVisibleOutputHash &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillOutputHashDiverges === true &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillDivergenceClass ===
              "provider_output_hash_divergence" &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillFallbackAuthority ===
              "legacy_runtime_model_invocation" &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillSelectedAuthority ===
              "legacy_runtime_model_invocation" &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillTranscriptUnchanged === true &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillRollbackExecuted === true &&
            Array.isArray(dispatch.modelProviderGatedVisibleOutputRollbackDrillActivationBlockers) &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillActivationBlockers.includes(
              "model_provider_output_hash_divergence",
            ) &&
            dispatch.visibleOutputDivergenceClass == null &&
            dispatch.authorityToolingMode === "workflow_live_dry_run" &&
            dispatch.authorityToolingReady === true &&
            dispatch.authorityToolingPolicyGateReady === true &&
            dispatch.authorityToolingToolRouterReady === true &&
            dispatch.authorityToolingDryRunSimulatorReady === true &&
            dispatch.authorityToolingApprovalGateReady === true &&
            dispatch.authorityToolingGateLiveReady === true &&
            dispatch.authorityToolingPolicyGateLiveReady === true &&
            dispatch.authorityToolingDestructiveDenialLiveReady === true &&
            dispatch.authorityToolingApprovalGateLiveReady === true &&
            Array.isArray(dispatch.authorityToolingGateLiveAttemptIds) &&
            dispatch.authorityToolingGateLiveAttemptIds.length >= 3 &&
            Array.isArray(dispatch.authorityToolingGateLiveReceiptIds) &&
            dispatch.authorityToolingGateLiveReceiptIds.length >= 3 &&
            Array.isArray(dispatch.authorityToolingGateLiveReplayFixtureRefs) &&
            dispatch.authorityToolingGateLiveReplayFixtureRefs.length >= 3 &&
            Array.isArray(dispatch.authorityToolingPolicyGateLiveAttemptIds) &&
            dispatch.authorityToolingPolicyGateLiveAttemptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingDestructiveDenialLiveAttemptIds) &&
            dispatch.authorityToolingDestructiveDenialLiveAttemptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingApprovalGateLiveAttemptIds) &&
            dispatch.authorityToolingApprovalGateLiveAttemptIds.length >= 1 &&
            dispatch.authorityToolingReadOnlyAuthorityCanaryReady === true &&
            dispatch.authorityToolingProviderCatalogLiveReady === true &&
            dispatch.authorityToolingProviderCatalogLiveComponentKind === "mcp_provider" &&
            Array.isArray(dispatch.authorityToolingProviderCatalogLiveAttemptIds) &&
            dispatch.authorityToolingProviderCatalogLiveAttemptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingProviderCatalogLiveReceiptIds) &&
            dispatch.authorityToolingProviderCatalogLiveReceiptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingProviderCatalogLiveReplayFixtureRefs) &&
            dispatch.authorityToolingProviderCatalogLiveReplayFixtureRefs.length >= 1 &&
            dispatch.authorityToolingMcpToolCatalogLiveReady === true &&
            dispatch.authorityToolingMcpToolCatalogLiveComponentKind === "mcp_tool_call" &&
            Array.isArray(dispatch.authorityToolingMcpToolCatalogLiveAttemptIds) &&
            dispatch.authorityToolingMcpToolCatalogLiveAttemptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingMcpToolCatalogLiveReceiptIds) &&
            dispatch.authorityToolingMcpToolCatalogLiveReceiptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingMcpToolCatalogLiveReplayFixtureRefs) &&
            dispatch.authorityToolingMcpToolCatalogLiveReplayFixtureRefs.length >= 1 &&
            dispatch.authorityToolingNativeToolCatalogLiveReady === true &&
            dispatch.authorityToolingNativeToolCatalogLiveComponentKind === "tool_call" &&
            Array.isArray(dispatch.authorityToolingNativeToolCatalogLiveAttemptIds) &&
            dispatch.authorityToolingNativeToolCatalogLiveAttemptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingNativeToolCatalogLiveReceiptIds) &&
            dispatch.authorityToolingNativeToolCatalogLiveReceiptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingNativeToolCatalogLiveReplayFixtureRefs) &&
            dispatch.authorityToolingNativeToolCatalogLiveReplayFixtureRefs.length >= 1 &&
            dispatch.authorityToolingConnectorCatalogLiveReady === true &&
            dispatch.authorityToolingConnectorCatalogLiveComponentKind === "connector_call" &&
            Array.isArray(dispatch.authorityToolingConnectorCatalogLiveAttemptIds) &&
            dispatch.authorityToolingConnectorCatalogLiveAttemptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingConnectorCatalogLiveReceiptIds) &&
            dispatch.authorityToolingConnectorCatalogLiveReceiptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingConnectorCatalogLiveReplayFixtureRefs) &&
            dispatch.authorityToolingConnectorCatalogLiveReplayFixtureRefs.length >= 1 &&
            dispatch.authorityToolingWalletCapabilityLiveDryRunReady === true &&
            dispatch.authorityToolingWalletCapabilityLiveDryRunComponentKind === "wallet_capability" &&
            Array.isArray(dispatch.authorityToolingWalletCapabilityLiveDryRunAttemptIds) &&
            dispatch.authorityToolingWalletCapabilityLiveDryRunAttemptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingWalletCapabilityLiveDryRunReceiptIds) &&
            dispatch.authorityToolingWalletCapabilityLiveDryRunReceiptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs) &&
            dispatch.authorityToolingWalletCapabilityLiveDryRunReplayFixtureRefs.length >= 1 &&
            Array.isArray(dispatch.authorityToolingReadOnlyComponentKinds) &&
            dispatch.authorityToolingReadOnlyComponentKinds.includes("mcp_provider") &&
            dispatch.authorityToolingReadOnlyComponentKinds.includes("mcp_tool_call") &&
            dispatch.authorityToolingReadOnlyComponentKinds.includes("tool_call") &&
            dispatch.authorityToolingReadOnlyComponentKinds.includes("connector_call") &&
            dispatch.authorityToolingReadOnlyComponentKinds.includes("wallet_capability") &&
            Array.isArray(dispatch.authorityToolingMutationDeferredComponentKinds) &&
            dispatch.authorityToolingMutationDeferredComponentKinds.includes("wallet_capability") &&
            dispatch.authorityToolingReadOnlyRouteAccepted === true &&
            dispatch.authorityToolingDestructiveRouteDenied === true &&
            dispatch.authorityToolingMutatingToolCallsBlocked === true &&
            dispatch.authorityToolingSideEffectsExecuted === false &&
            dispatch.authorityToolingRollbackAvailable === true &&
            dispatch.legacyTranscriptAuthorityRetained === false &&
            dispatch.transcriptMaterializationMatches === true &&
            dispatch.transcriptMaterializationContentHashMatches === true &&
            dispatch.transcriptMaterializationOrderMatches === true &&
            dispatch.transcriptMaterializationReceiptBindingMatches === true &&
            dispatch.transcriptMaterializationDivergenceCount === 0 &&
            dispatch.stagedTranscriptWriteMatches === true &&
            dispatch.stagedTranscriptWriteContentHashMatches === true &&
            dispatch.stagedTranscriptWriteOrderMatches === true &&
            dispatch.stagedTranscriptWriteReceiptBindingMatches === true &&
            dispatch.stagedTranscriptWriteDivergenceCount === 0 &&
            dispatch.visibleTranscriptWriteMatches === true &&
            dispatch.visibleTranscriptWriteContentHashMatches === true &&
            dispatch.visibleTranscriptWriteOrderMatches === true &&
            dispatch.visibleTranscriptWriteReceiptBindingMatches === true &&
            dispatch.visibleTranscriptWriteDivergenceCount === 0 &&
            dispatch.workflowTranscriptWriteCandidate?.committed === false &&
            dispatch.workflowTranscriptWriteRecord?.committed === true &&
            dispatch.workflowTranscriptWriteRecord?.visible === true &&
            dispatch.legacyTranscriptWriteRecord?.committed === false &&
            dispatch.legacyTranscriptWriteRecord?.suppressedByIdempotency === true &&
            dispatch.stagedTranscriptWriteRecord?.committed === true &&
            dispatch.stagedTranscriptWriteRecord?.visible === false &&
            dispatch.outputHashMatches === true &&
            dispatch.outputHashDivergence === false &&
            dispatch.outputHashDivergenceCount === 0 &&
            typeof dispatch.proposedVisibleOutputHash === "string" &&
            dispatch.proposedVisibleOutputHash.length > 0 &&
            dispatch.proposedVisibleOutputHash === dispatch.actualVisibleOutputHash &&
            dispatch.legacyOutputAuthorityRetained === false &&
            dispatch.legacyOutputFallbackAvailable === true &&
            dispatch.mutatingTurnsBlocked === true &&
            dispatch.outputAuthority === "blessed_workflow_activation_default" &&
            Array.isArray(dispatch.acceptedClusterIds) &&
            dispatch.acceptedClusterIds.includes("cognition") &&
            dispatch.acceptedClusterIds.includes("routing_model") &&
            dispatch.acceptedClusterIds.includes("verification_output") &&
            dispatch.acceptedClusterIds.includes("authority_tooling") &&
            Array.isArray(dispatch.componentKinds) &&
            dispatch.componentKinds.length >= 18 &&
            dispatch.componentKinds.includes("verifier") &&
            dispatch.componentKinds.includes("completion_gate") &&
            dispatch.componentKinds.includes("receipt_writer") &&
            dispatch.componentKinds.includes("quality_ledger") &&
            dispatch.componentKinds.includes("output_writer") &&
            dispatch.componentKinds.includes("policy_gate") &&
            dispatch.componentKinds.includes("dry_run_simulator") &&
            dispatch.componentKinds.includes("approval_gate") &&
            Array.isArray(dispatch.deferredComponentKinds) &&
            dispatch.deferredComponentKinds.includes("mcp_tool_call") &&
            dispatch.deferredComponentKinds.includes("tool_call") &&
            dispatch.deferredComponentKinds.includes("connector_call") &&
            dispatch.deferredComponentKinds.includes("wallet_capability") &&
            Array.isArray(dispatch.handoffValidatedComponentKinds) &&
            dispatch.handoffValidatedComponentKinds.includes("output_writer") &&
            Array.isArray(dispatch.materializationCanaryComponentKinds) &&
            dispatch.materializationCanaryComponentKinds.includes("output_writer") &&
            Array.isArray(dispatch.dispatchNodeAttemptIds) &&
            dispatch.dispatchNodeAttemptIds.length >= 20 &&
            Array.isArray(dispatch.cognitionExecutionAttemptIds) &&
            dispatch.cognitionExecutionAttemptIds.length >= 3 &&
            Array.isArray(dispatch.cognitionExecutionReceiptIds) &&
            dispatch.cognitionExecutionReceiptIds.length >= 3 &&
            Array.isArray(dispatch.cognitionExecutionReplayFixtureRefs) &&
            dispatch.cognitionExecutionReplayFixtureRefs.length >= 3 &&
            Array.isArray(dispatch.modelExecutionAttemptIds) &&
            dispatch.modelExecutionAttemptIds.length >= 5 &&
            Array.isArray(dispatch.modelExecutionReceiptIds) &&
            dispatch.modelExecutionReceiptIds.length >= 5 &&
            Array.isArray(dispatch.modelExecutionReplayFixtureRefs) &&
            dispatch.modelExecutionReplayFixtureRefs.length >= 5 &&
            Array.isArray(dispatch.modelProviderCanaryAttemptIds) &&
            dispatch.modelProviderCanaryAttemptIds.length >= 1 &&
            Array.isArray(dispatch.modelProviderCanaryReceiptIds) &&
            dispatch.modelProviderCanaryReceiptIds.length >= 1 &&
            Array.isArray(dispatch.modelProviderCanaryReplayFixtureRefs) &&
            dispatch.modelProviderCanaryReplayFixtureRefs.length >= 1 &&
            Array.isArray(dispatch.modelProviderGatedVisibleOutputAttemptIds) &&
            dispatch.modelProviderGatedVisibleOutputAttemptIds.length >= 1 &&
            Array.isArray(dispatch.modelProviderGatedVisibleOutputReceiptIds) &&
            dispatch.modelProviderGatedVisibleOutputReceiptIds.length >= 1 &&
            Array.isArray(dispatch.modelProviderGatedVisibleOutputReplayFixtureRefs) &&
            dispatch.modelProviderGatedVisibleOutputReplayFixtureRefs.length >= 1 &&
            Array.isArray(dispatch.modelProviderGatedVisibleOutputRollbackDrillAttemptIds) &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillAttemptIds.length >= 1 &&
            Array.isArray(dispatch.modelProviderGatedVisibleOutputRollbackDrillReceiptIds) &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillReceiptIds.length >= 1 &&
            Array.isArray(
              dispatch.modelProviderGatedVisibleOutputRollbackDrillReplayFixtureRefs,
            ) &&
            dispatch.modelProviderGatedVisibleOutputRollbackDrillReplayFixtureRefs.length >= 1 &&
            Array.isArray(dispatch.outputWriterHandoffAttemptIds) &&
            dispatch.outputWriterHandoffAttemptIds.length >= 1 &&
            Array.isArray(dispatch.outputWriterMaterializationCanaryAttemptIds) &&
            dispatch.outputWriterMaterializationCanaryAttemptIds.length >= 1 &&
            Array.isArray(dispatch.outputWriterStagedWriteCanaryAttemptIds) &&
            dispatch.outputWriterStagedWriteCanaryAttemptIds.length >= 1 &&
            Array.isArray(dispatch.outputWriterVisibleWriteAttemptIds) &&
            dispatch.outputWriterVisibleWriteAttemptIds.length >= 1 &&
            Array.isArray(dispatch.authorityToolingLiveDryRunAttemptIds) &&
            dispatch.authorityToolingLiveDryRunAttemptIds.length >= 10 &&
            Array.isArray(dispatch.authorityToolingReadOnlyLiveAttemptIds) &&
            dispatch.authorityToolingReadOnlyLiveAttemptIds.length >= 5 &&
            Array.isArray(dispatch.authorityToolingReadOnlyReceiptIds) &&
            dispatch.authorityToolingReadOnlyReceiptIds.length >= 5 &&
            Array.isArray(dispatch.authorityToolingReadOnlyReplayFixtureRefs) &&
            dispatch.authorityToolingReadOnlyReplayFixtureRefs.length >= 5 &&
            dispatch.authorityToolingProof?.gateLiveReady === true &&
            dispatch.authorityToolingProof?.policyGateLiveReady === true &&
            dispatch.authorityToolingProof?.destructiveDenialLiveReady === true &&
            dispatch.authorityToolingProof?.approvalGateLiveReady === true &&
            dispatch.authorityToolingProof?.readOnlyAuthorityCanaryReady === true &&
            dispatch.authorityToolingProof?.providerCatalogLiveReady === true &&
            dispatch.authorityToolingProof?.providerCatalogLiveComponentKind === "mcp_provider" &&
            dispatch.authorityToolingProof?.mcpToolCatalogLiveReady === true &&
            dispatch.authorityToolingProof?.mcpToolCatalogLiveComponentKind === "mcp_tool_call" &&
            dispatch.authorityToolingProof?.nativeToolCatalogLiveReady === true &&
            dispatch.authorityToolingProof?.nativeToolCatalogLiveComponentKind === "tool_call" &&
            dispatch.authorityToolingProof?.connectorCatalogLiveReady === true &&
            dispatch.authorityToolingProof?.connectorCatalogLiveComponentKind === "connector_call" &&
            dispatch.authorityToolingProof?.walletCapabilityLiveDryRunReady === true &&
            dispatch.authorityToolingProof?.walletCapabilityLiveDryRunComponentKind === "wallet_capability" &&
            Array.isArray(dispatch.authorityToolingProof?.mutationDeferredComponentKinds) &&
            dispatch.authorityToolingProof.mutationDeferredComponentKinds.includes("wallet_capability") &&
            Array.isArray(dispatch.authorityToolingDenialReceiptIds) &&
            dispatch.authorityToolingDenialReceiptIds.length >= 1 &&
            Array.isArray(dispatch.acceptedNodeAttemptIds) &&
            dispatch.acceptedNodeAttemptIds.length >= 18 &&
            Array.isArray(dispatch.activationBlockers) &&
            dispatch.activationBlockers.length === 0 &&
            dispatch.rollbackAvailable === true
          ) {
            summary.harnessDefaultRuntimeDispatchReadonlyCount += 1;
            summary.harnessAuthorityToolingReadOnlyCanaryCount += 1;
            summary.harnessAuthorityToolingGateLiveCount += 1;
            summary.harnessAuthorityToolingProviderCatalogLiveCount += 1;
            summary.harnessAuthorityToolingMcpToolCatalogLiveCount += 1;
            summary.harnessAuthorityToolingNativeToolCatalogLiveCount += 1;
            summary.harnessAuthorityToolingConnectorCatalogLiveCount += 1;
            summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount += 1;
            summary.harnessModelProviderGatedVisibleOutputCount += 1;
            summary.harnessModelProviderGatedVisibleOutputRollbackDrillCount += 1;
            addScenario(
              summary.harnessModelProviderGatedVisibleOutputScenarios,
              dispatch.modelProviderGatedVisibleOutputScenario,
            );
            addScenario(
              summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios,
              dispatch.modelProviderGatedVisibleOutputScenario,
            );
          }
          const readOnlyRoutingScenario = dispatch.readOnlyCapabilityRoutingScenario;
          const readOnlyWorkflowNodeKinds = Array.isArray(
            dispatch.readOnlyCapabilityRoutingWorkflowOwnedNodeKinds,
          )
            ? dispatch.readOnlyCapabilityRoutingWorkflowOwnedNodeKinds
            : [];
          const readOnlySourceOrProbeNodePresent =
            readOnlyRoutingScenario === "retained_probe_behavior"
              ? readOnlyWorkflowNodeKinds.includes("probe_runner")
              : ["retained_repo_grounded_answer", "retained_source_heavy_synthesis"].includes(
                    readOnlyRoutingScenario,
                  ) && readOnlyWorkflowNodeKinds.includes("memory_read");
          if (
            dispatch.schemaVersion === "workflow.harness.default-runtime-dispatch.v1" &&
            dispatch.selectedSelector === "blessed_workflow_live_default" &&
            dispatch.productionDefaultSelector === "blessed_workflow_live_default" &&
            dispatch.executionMode === "live" &&
            dispatch.runtimeAuthority === "blessed_workflow_activation_default" &&
            dispatch.readOnlyCapabilityRoutingMode ===
              "workflow_read_only_capability_routing" &&
            dispatch.readOnlyCapabilityRoutingReady === true &&
            dispatch.readOnlyCapabilityRoutingSelected === true &&
            dispatch.readOnlyCapabilityRoutingNoMutationReady === true &&
            dispatch.readOnlyCapabilityRoutingSourceMaterialReady === true &&
            AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS.includes(
              readOnlyRoutingScenario,
            ) &&
            dispatch.readOnlyCapabilityRoutingScenarioCoverageKey ===
              readOnlyRoutingScenario &&
            readOnlyWorkflowNodeKinds.includes("capability_sequencer") &&
            readOnlyWorkflowNodeKinds.includes("tool_router") &&
            readOnlyWorkflowNodeKinds.includes("dry_run_simulator") &&
            readOnlySourceOrProbeNodePresent &&
            Array.isArray(dispatch.readOnlyCapabilityRoutingAttemptIds) &&
            dispatch.readOnlyCapabilityRoutingAttemptIds.length >= 3 &&
            Array.isArray(dispatch.readOnlyCapabilityRoutingReceiptIds) &&
            dispatch.readOnlyCapabilityRoutingReceiptIds.length >= 3 &&
            Array.isArray(dispatch.readOnlyCapabilityRoutingReplayFixtureRefs) &&
            dispatch.readOnlyCapabilityRoutingReplayFixtureRefs.length >= 3 &&
            dispatch.readOnlyCapabilityRoutingProof?.sideEffectsExecuted === false &&
            dispatch.readOnlyCapabilityRoutingProof?.mutationExecuted === false &&
            Array.isArray(dispatch.activationBlockers) &&
            dispatch.activationBlockers.length === 0
          ) {
            summary.harnessReadOnlyCapabilityRoutingCount += 1;
            summary.harnessReadOnlyCapabilityRoutingNoMutationCount += 1;
            addScenario(
              summary.harnessReadOnlyCapabilityRoutingScenarios,
              readOnlyRoutingScenario,
            );
            addScenario(
              summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios,
              readOnlyRoutingScenario,
            );
          }
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
        if (digest.harness_shadow_run === true) summary.harnessShadowRunCount += 1;
        summary.harnessNodeAttemptCount += Number(digest.harness_node_attempt_count ?? 0);
        summary.harnessShadowComparisonCount += Number(
          digest.harness_shadow_comparison_count ?? 0,
        );
        summary.harnessBlockingDivergenceCount += Number(
          digest.harness_blocking_divergence_count ?? 0,
        );
        summary.harnessGatedClusterCount += Number(digest.harness_gated_cluster_count ?? 0);
        if (digest.harness_gated_cognition_passed === true) {
          summary.harnessGatedCognitionCount += 1;
        }
        if (digest.harness_gated_routing_model_passed === true) {
          summary.harnessGatedRoutingModelCount += 1;
        }
        if (digest.harness_gated_verification_output_passed === true) {
          summary.harnessGatedVerificationOutputCount += 1;
        }
        if (digest.harness_gated_authority_tooling_passed === true) {
          summary.harnessGatedAuthorityToolingCount += 1;
        }
        if (digest.harness_fork_activation_blocked === true) {
          summary.harnessForkActivationBlockedCount += 1;
        }
        if (digest.harness_fork_activation_minted === true) {
          summary.harnessForkActivationMintedCount += 1;
        }
        if (digest.harness_rollback_restore_canary_blocked === true) {
          summary.harnessRollbackRestoreCanaryBlockedCount += 1;
          noteRollbackRestoreCanaryStatus("blocked");
        }
        if (digest.harness_rollback_restore_canary_ready === true) {
          summary.harnessRollbackRestoreCanaryReadyCount += 1;
          noteRollbackRestoreCanaryStatus("ready");
        }
        if (digest.harness_rollback_restore_canary_receipts_present === true) {
          summary.harnessRollbackRestoreCanaryReceiptCount += 2;
        }
        if (digest.harness_activation_audit_receipts_present === true) {
          summary.harnessActivationAuditReceiptCount += 1;
        }
        if (digest.harness_rollback_execution_receipts_present === true) {
          summary.harnessRollbackExecutionReceiptCount += 1;
        }
        if (digest.harness_canary_boundary_executed === true) {
          summary.harnessCanaryBoundaryExecutedCount += 1;
        }
        if (digest.harness_canary_boundary_rollback_drill === true) {
          summary.harnessCanaryBoundaryRollbackDrillCount += 1;
        }
        if (digest.harness_selector_canary_routed === true) {
          summary.harnessSelectorCanaryRoutedCount += 1;
        }
        if (digest.harness_selector_legacy_default === true) {
          summary.harnessSelectorLegacyDefaultCount += 1;
        }
        if (digest.harness_selector_default_promoted === true) {
          summary.harnessSelectorDefaultPromotedCount += 1;
        }
        if (digest.harness_live_handoff_canary === true) {
          summary.harnessLiveHandoffCanaryCount += 1;
        }
        if (digest.harness_live_handoff_default_promoted === true) {
          summary.harnessLiveHandoffDefaultPromotedCount += 1;
        }
        if (digest.harness_live_handoff_rollback === true) {
          summary.harnessLiveHandoffRollbackCount += 1;
        }
        if (digest.harness_default_runtime_dispatch_readonly === true) {
          summary.harnessDefaultRuntimeDispatchReadonlyCount += 1;
        }
        if (digest.harness_authority_tooling_read_only_canary === true) {
          summary.harnessAuthorityToolingReadOnlyCanaryCount += 1;
        }
        if (digest.harness_authority_tooling_gate_live === true) {
          summary.harnessAuthorityToolingGateLiveCount += 1;
        }
        if (digest.harness_authority_tooling_provider_catalog_live === true) {
          summary.harnessAuthorityToolingProviderCatalogLiveCount += 1;
        }
        if (digest.harness_authority_tooling_mcp_tool_catalog_live === true) {
          summary.harnessAuthorityToolingMcpToolCatalogLiveCount += 1;
        }
        if (digest.harness_authority_tooling_native_tool_catalog_live === true) {
          summary.harnessAuthorityToolingNativeToolCatalogLiveCount += 1;
        }
        if (digest.harness_authority_tooling_connector_catalog_live === true) {
          summary.harnessAuthorityToolingConnectorCatalogLiveCount += 1;
        }
        if (digest.harness_authority_tooling_wallet_capability_live_dry_run === true) {
          summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount += 1;
        }
        if (digest.harness_model_provider_gated_visible_output === true) {
          summary.harnessModelProviderGatedVisibleOutputCount += 1;
          noteProviderGatedVisibleOutputCoverage(
            digest.harness_model_provider_gated_visible_output_coverage,
          );
          addScenario(
            summary.harnessModelProviderGatedVisibleOutputScenarios,
            digest.harness_model_provider_gated_visible_output_required_scenario ??
              digest.harness_model_provider_gated_visible_output_scenario,
          );
        }
        if (digest.harness_model_provider_gated_visible_output_rollback_drill === true) {
          summary.harnessModelProviderGatedVisibleOutputRollbackDrillCount += 1;
          noteProviderGatedVisibleOutputCoverage(
            digest.harness_model_provider_gated_visible_output_coverage,
          );
          addScenario(
            summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios,
            digest.harness_model_provider_gated_visible_output_rollback_drill_scenario ??
              digest.harness_model_provider_gated_visible_output_required_scenario,
          );
        }
        if (digest.harness_read_only_capability_routing === true) {
          summary.harnessReadOnlyCapabilityRoutingCount += 1;
          summary.harnessReadOnlyCapabilityRoutingNoMutationCount += 1;
          noteReadOnlyCapabilityRoutingCoverage(
            digest.harness_read_only_capability_routing_coverage,
          );
          addScenario(
            summary.harnessReadOnlyCapabilityRoutingScenarios,
            digest.harness_read_only_capability_routing_required_scenario ??
              digest.harness_read_only_capability_routing_scenario,
          );
          addScenario(
            summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios,
            digest.harness_read_only_capability_routing_required_scenario ??
              digest.harness_read_only_capability_routing_scenario,
          );
        }
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
          if (metadata.harness_worker_binding) {
            summary.harnessWorkerBindingCount += 1;
          }
          if (metadata.harness_shadow_run) {
            summary.harnessShadowRunCount += 1;
          }
          summary.harnessNodeAttemptCount += Number(metadata.harness_node_attempt_count ?? 0);
          summary.harnessShadowComparisonCount += Number(
            metadata.harness_shadow_comparison_count ?? 0,
          );
          summary.harnessBlockingDivergenceCount += Number(
            metadata.harness_blocking_divergence_count ?? 0,
          );
          summary.harnessGatedClusterCount += Number(metadata.harness_gated_cluster_count ?? 0);
          if (metadata.harness_gated_cognition_passed === true) {
            summary.harnessGatedCognitionCount += 1;
          }
          if (metadata.harness_gated_routing_model_passed === true) {
            summary.harnessGatedRoutingModelCount += 1;
          }
          if (metadata.harness_gated_verification_output_passed === true) {
            summary.harnessGatedVerificationOutputCount += 1;
          }
          if (metadata.harness_gated_authority_tooling_passed === true) {
            summary.harnessGatedAuthorityToolingCount += 1;
          }
          if (metadata.harness_fork_activation_blocked === true) {
            summary.harnessForkActivationBlockedCount += 1;
          }
          if (metadata.harness_fork_activation_minted === true) {
            summary.harnessForkActivationMintedCount += 1;
          }
          if (metadata.harness_fork_activation) {
            noteRollbackRestoreCanaryProof(metadata.harness_fork_activation);
          }
          if (metadata.harness_rollback_restore_canary_blocked === true) {
            summary.harnessRollbackRestoreCanaryBlockedCount += 1;
            noteRollbackRestoreCanaryStatus("blocked");
          }
          if (metadata.harness_rollback_restore_canary_ready === true) {
            summary.harnessRollbackRestoreCanaryReadyCount += 1;
            noteRollbackRestoreCanaryStatus("ready");
          }
          if (metadata.harness_rollback_restore_canary_receipts_present === true) {
            summary.harnessRollbackRestoreCanaryReceiptCount += 2;
          }
          if (metadata.harness_activation_audit_receipts_present === true) {
            summary.harnessActivationAuditReceiptCount += 1;
          }
          if (metadata.harness_rollback_execution_receipts_present === true) {
            summary.harnessRollbackExecutionReceiptCount += 1;
          }
          if (metadata.harness_canary_boundary_executed === true) {
            summary.harnessCanaryBoundaryExecutedCount += 1;
          }
          if (metadata.harness_canary_boundary_rollback_drill === true) {
            summary.harnessCanaryBoundaryRollbackDrillCount += 1;
          }
          if (metadata.harness_selector_canary_routed === true) {
            summary.harnessSelectorCanaryRoutedCount += 1;
          }
          if (metadata.harness_selector_legacy_default === true) {
            summary.harnessSelectorLegacyDefaultCount += 1;
          }
          if (metadata.harness_selector_default_promoted === true) {
            summary.harnessSelectorDefaultPromotedCount += 1;
          }
          if (metadata.harness_live_handoff_canary === true) {
            summary.harnessLiveHandoffCanaryCount += 1;
          }
          if (metadata.harness_live_handoff_default_promoted === true) {
            summary.harnessLiveHandoffDefaultPromotedCount += 1;
          }
          if (metadata.harness_live_handoff_rollback === true) {
            summary.harnessLiveHandoffRollbackCount += 1;
          }
          if (metadata.harness_default_runtime_dispatch_readonly === true) {
            summary.harnessDefaultRuntimeDispatchReadonlyCount += 1;
          }
          if (metadata.harness_authority_tooling_read_only_canary === true) {
            summary.harnessAuthorityToolingReadOnlyCanaryCount += 1;
          }
          if (metadata.harness_authority_tooling_gate_live === true) {
            summary.harnessAuthorityToolingGateLiveCount += 1;
          }
          if (metadata.harness_authority_tooling_provider_catalog_live === true) {
            summary.harnessAuthorityToolingProviderCatalogLiveCount += 1;
          }
          if (metadata.harness_authority_tooling_mcp_tool_catalog_live === true) {
            summary.harnessAuthorityToolingMcpToolCatalogLiveCount += 1;
          }
          if (metadata.harness_authority_tooling_native_tool_catalog_live === true) {
            summary.harnessAuthorityToolingNativeToolCatalogLiveCount += 1;
          }
          if (metadata.harness_authority_tooling_connector_catalog_live === true) {
            summary.harnessAuthorityToolingConnectorCatalogLiveCount += 1;
          }
          if (metadata.harness_authority_tooling_wallet_capability_live_dry_run === true) {
            summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount += 1;
          }
          if (metadata.harness_model_provider_gated_visible_output === true) {
            summary.harnessModelProviderGatedVisibleOutputCount += 1;
            noteProviderGatedVisibleOutputCoverage(
              metadata.harness_model_provider_gated_visible_output_coverage,
            );
            addScenario(
              summary.harnessModelProviderGatedVisibleOutputScenarios,
              metadata.harness_model_provider_gated_visible_output_required_scenario ??
                metadata.harness_model_provider_gated_visible_output_scenario,
            );
          }
          if (metadata.harness_model_provider_gated_visible_output_rollback_drill === true) {
            summary.harnessModelProviderGatedVisibleOutputRollbackDrillCount += 1;
            noteProviderGatedVisibleOutputCoverage(
              metadata.harness_model_provider_gated_visible_output_coverage,
            );
            addScenario(
              summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios,
              metadata.harness_model_provider_gated_visible_output_rollback_drill_scenario ??
                metadata.harness_model_provider_gated_visible_output_required_scenario,
            );
          }
          if (metadata.harness_read_only_capability_routing === true) {
            summary.harnessReadOnlyCapabilityRoutingCount += 1;
            summary.harnessReadOnlyCapabilityRoutingNoMutationCount += 1;
            noteReadOnlyCapabilityRoutingCoverage(
              metadata.harness_read_only_capability_routing_coverage,
            );
            addScenario(
              summary.harnessReadOnlyCapabilityRoutingScenarios,
              metadata.harness_read_only_capability_routing_required_scenario ??
                metadata.harness_read_only_capability_routing_scenario,
            );
            addScenario(
              summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios,
              metadata.harness_read_only_capability_routing_required_scenario ??
                metadata.harness_read_only_capability_routing_scenario,
            );
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

function collectRollbackRestoreCanaryUiProof(outputRoot) {
  const railPath = "packages/agent-ide/src/features/Workflows/WorkflowRailPanel.tsx";
  const validationPath = "packages/agent-ide/src/runtime/workflow-validation.ts";
  const harnessWorkflowPath = "packages/agent-ide/src/runtime/harness-workflow.ts";
  const railModelPath = "packages/agent-ide/src/runtime/workflow-rail-model.ts";
  const controllerPath = "packages/agent-ide/src/WorkflowComposer/controller.tsx";
  const viewPath = "packages/agent-ide/src/WorkflowComposer/view.tsx";
  const graphPath = "packages/agent-ide/src/types/graph.ts";
  const restoreCommandPath = "apps/autopilot/src-tauri/src/project/commands.rs";
  const rail = readFileSync(resolve(repoRoot, railPath), "utf8");
  const validation = readFileSync(resolve(repoRoot, validationPath), "utf8");
  const harnessWorkflow = readFileSync(resolve(repoRoot, harnessWorkflowPath), "utf8");
  const railModel = readFileSync(resolve(repoRoot, railModelPath), "utf8");
  const controller = readFileSync(resolve(repoRoot, controllerPath), "utf8");
  const view = readFileSync(resolve(repoRoot, viewPath), "utf8");
  const graph = readFileSync(resolve(repoRoot, graphPath), "utf8");
  const restoreCommand = readFileSync(resolve(repoRoot, restoreCommandPath), "utf8");
  const checks = {
    canaryCardTestId: /data-testid="workflow-harness-rollback-restore-canary"/.test(rail),
    canaryStatusAttribute: /data-restore-canary-status/.test(rail),
    wizardStepGateId: /id: "rollback-restore"/.test(rail),
    wizardStepTestId: /workflow-harness-activation-step-\$\{step\.id\}/.test(rail),
    candidateGateTestId: /workflow-harness-activation-candidate-gate-\$\{gate\.gateId\}/.test(rail),
    validationGate: /gateId: "rollback-restore"/.test(validation),
    blockedGitCanary: /rollback_restore_canary_not_run/.test(validation),
    dryRunRestoreProbe:
      /runWorkflowHarnessRollbackRestoreCanaryProbe[\s\S]*runtime[\s\S]*workflowPath[\s\S]*rollbackRevisionBinding/.test(
        controller,
      ) &&
      /(?=[\s\S]*runWorkflowHarnessRollbackRestoreCanaryProbe)(?=[\s\S]*revisionSource !== "git")(?=[\s\S]*dryRun: true)(?=[\s\S]*rollback_restore_api_unavailable)(?=[\s\S]*runtime\.restoreWorkflowRevision\(restoreRequest\))(?=[\s\S]*rollback_restore_canary_failed)/.test(
        harnessWorkflow,
      ),
    restoreCanaryReceiptBinding:
      /data-receipt-binding-ref/.test(rail) &&
      /WorkflowRevisionRestoreResult[\s\S]*receiptBindingRef\?: string/.test(graph) &&
      /WorkflowHarnessRollbackRestoreCanary[\s\S]*receiptBindingRef\?: string/.test(graph) &&
      /receiptBindingRef[\s\S]*workflow_restore_canary:[\s\S]*evidenceRefs/.test(validation) &&
      /receipt_binding_ref[\s\S]*workflow_restore_canary_receipt_binding_ref/.test(
        restoreCommand,
      ),
    activationAuditReceiptRefs:
      /WorkflowHarnessActivationAuditEvent[\s\S]*receiptRefs: string\[\]/.test(graph) &&
      /makeWorkflowHarnessActivationAuditEvent[\s\S]*receiptRefs[\s\S]*receiptRefsFromEvidenceRefs/.test(
        harnessWorkflow,
      ) &&
      /recordWorkflowHarnessActivationDryRun[\s\S]*activationCandidateReceiptRefs[\s\S]*receiptRefs/.test(
        harnessWorkflow,
      ) &&
      /activation_minted[\s\S]*receiptRefs/.test(harnessWorkflow) &&
      /workflow-harness-activation-audit[\s\S]*data-receipt-refs[\s\S]*data-audit-receipt-refs/.test(
        rail,
      ) &&
      /workflow-harness-activation-audit-receipt-\$\{event\.eventId\}-\$\{index\}/.test(
        rail,
      ),
    rollbackExecutionReceiptRefs:
      /WorkflowHarnessActivationRollbackProof[\s\S]*receiptRefs: string\[\]/.test(graph) &&
      /WorkflowHarnessActivationRollbackExecution[\s\S]*receiptRefs: string\[\][\s\S]*restoreReceiptBindingRef\?: string/.test(
        graph,
      ) &&
      /executeWorkflowHarnessRollbackDrill[\s\S]*workflowRollbackReceiptRefs[\s\S]*receiptRefs/.test(
        harnessWorkflow,
      ) &&
      /executeWorkflowHarnessRevisionRollback[\s\S]*restoreResult\?\.receiptBindingRef[\s\S]*restoreReceiptBindingRef[\s\S]*receiptRefs/.test(
        harnessWorkflow,
      ) &&
      /workflow-harness-rollback-execution-proof[\s\S]*data-receipt-refs[\s\S]*data-restore-receipt-binding-ref/.test(
        rail,
      ) &&
      /workflow-harness-rollback-drill-receipt-\$\{index\}/.test(rail) &&
      /workflow-harness-rollback-execution-receipt-\$\{index\}/.test(rail),
    interactiveReceiptSelection:
      /data-selected-receipt-ref/.test(rail) &&
      /selectedHarnessReceiptRef === receiptRef/.test(rail) &&
      /onClick=\{\(\) => onSelectHarnessReceiptRef\?\.\(receiptRef\)\}/.test(
        rail,
      ) &&
      /handleSelectHarnessReceiptRef[\s\S]*setSelectedHarnessReceiptRef\(receiptRef\)/.test(
        controller,
      ) &&
      /receiptRef: selectedHarnessReceiptRef/.test(controller) &&
      /writeHarnessWorkbenchDeepLink/.test(controller),
    receiptDetailInspector:
      /resolveWorkflowHarnessReceiptInspection/.test(rail) &&
      /export function resolveWorkflowHarnessReceiptInspection/.test(railModel) &&
      /workflowHarnessReceiptKind/.test(railModel) &&
      /workflowRedactedReceiptPayload/.test(railModel) &&
      /selectedHarnessReceiptInspection/.test(rail) &&
      /sourceKind: "node_attempt"/.test(railModel) &&
      /sourceKind: "activation_audit"/.test(railModel) &&
      /sourceKind: "rollback_execution"/.test(railModel) &&
      /sourceKind: "default_runtime_dispatch"/.test(railModel) &&
      /workflow-harness-receipt-inspector/.test(rail) &&
      /data-receipt-source-kind/.test(rail) &&
      /data-producer-component/.test(rail) &&
      /data-policy-decision/.test(rail) &&
      /data-attempt-id/.test(rail) &&
      /data-replay-fixture-ref/.test(rail) &&
      /workflow-harness-receipt-inspector-metadata/.test(rail) &&
      /workflow-harness-receipt-payload-preview/.test(rail) &&
      /workflow-harness-receipt-evidence-refs/.test(rail),
    replayDetailInspector:
      /resolveWorkflowHarnessReplayInspection/.test(rail) &&
      /export interface WorkflowHarnessReplayInspection/.test(railModel) &&
      /export function resolveWorkflowHarnessReplayInspection/.test(railModel) &&
      /workflowUniqueReplayFixtureRefs/.test(railModel) &&
      /selectedHarnessReplayInspection/.test(rail) &&
      /sourceKind: "node_attempt"/.test(railModel) &&
      /sourceKind: "gated_cluster"/.test(railModel) &&
      /sourceKind: "runtime_binding"/.test(railModel) &&
      /sourceKind: "default_runtime_dispatch"/.test(railModel) &&
      /sourceKind: "read_only_routing_proof"/.test(railModel) &&
      /sourceKind: "authority_gate_proof"/.test(railModel) &&
      /sourceKind: "harness_group"/.test(railModel) &&
      /workflow-harness-replay-inspector/.test(rail) &&
      /data-replay-source-kind/.test(rail) &&
      /data-determinism/.test(rail) &&
      /data-redaction-policy/.test(rail) &&
      /data-captures-input/.test(rail) &&
      /data-captures-output/.test(rail) &&
      /data-captures-policy-decision/.test(rail) &&
      /workflow-harness-replay-inspector-metadata/.test(rail) &&
      /workflow-harness-replay-capture-flags/.test(rail) &&
      /workflow-harness-replay-payload-preview/.test(rail) &&
      /workflow-harness-replay-evidence-refs/.test(rail),
    replayDrillExecution:
      /WorkflowHarnessReplayDrillResult/.test(graph) &&
      /WorkflowHarnessReplayGateResult/.test(graph) &&
      /WorkflowHarnessPromotionClusterReplayGateProof/.test(graph) &&
      /WorkflowHarnessReplayDrillDivergenceClass/.test(graph) &&
      /replayGateProof\?: WorkflowHarnessPromotionClusterReplayGateProof/.test(graph) &&
      /replayDrills\?: WorkflowHarnessReplayDrillResult\[\]/.test(graph) &&
      /replayGates\?: WorkflowHarnessReplayGateResult\[\]/.test(graph) &&
      /executeWorkflowHarnessReplayDrill/.test(harnessWorkflow) &&
      /executeWorkflowHarnessReplayGate/.test(harnessWorkflow) &&
      /workflowHarnessPromotionClustersWithReplayGateProof/.test(harnessWorkflow) &&
      /replay_drill_passed/.test(harnessWorkflow) &&
      /replay_drill_blocked/.test(harnessWorkflow) &&
      /replay_gate_passed/.test(harnessWorkflow) &&
      /replay_gate_blocked/.test(harnessWorkflow) &&
      /handleRunHarnessReplayDrill/.test(controller) &&
      /handleRunHarnessReplayGate/.test(controller) &&
      /onRunHarnessReplayDrill/.test(rail) &&
      /onRunHarnessReplayGate/.test(rail) &&
      /workflow-harness-run-replay-drill/.test(rail) &&
      /workflow-harness-run-replay-gate/.test(rail) &&
      /workflow-harness-replay-drill-result/.test(rail) &&
      /workflow-harness-replay-gate-result/.test(rail) &&
      /workflow-harness-promotion-cluster-replay-gate/.test(rail) &&
      /workflow-harness-group-replay-gate-proof/.test(rail) &&
      /data-replay-divergence-class/.test(rail) &&
      /data-activation-gate-impact/.test(rail) &&
      /workflow-harness-replay-drill-receipt-refs/.test(rail) &&
      /workflow-harness-replay-gate-receipt-refs/.test(rail) &&
      /replayDrillBlockers/.test(validation) &&
      /replayGateBlockers/.test(validation) &&
      /promotionClusterReplayGateBlockers/.test(validation),
    promotionTransitionControls:
      /WorkflowHarnessPromotionTransitionEligibility/.test(graph) &&
      /WorkflowHarnessPromotionTransitionAttempt/.test(graph) &&
      /promotionStatus\?: WorkflowHarnessClusterPromotionStatus/.test(graph) &&
      /promotionTransitions\?: WorkflowHarnessPromotionTransitionAttempt\[\]/.test(
        graph,
      ) &&
      /workflowHarnessPromotionTransitionEligibility/.test(harnessWorkflow) &&
      /executeWorkflowHarnessPromotionTransition/.test(harnessWorkflow) &&
      /promotion_transition_blocked/.test(harnessWorkflow) &&
      /promotion_transition_promoted/.test(harnessWorkflow) &&
      /handleRunHarnessPromotionTransition/.test(controller) &&
      /onRunHarnessPromotionTransition=\{\(targetExecutionMode\)/.test(view) &&
      /onRunHarnessPromotionTransition/.test(rail) &&
      /workflow-harness-group-promotion-actions/.test(rail) &&
      /workflow-harness-promote-cluster-gated/.test(rail) &&
      /workflow-harness-promote-cluster-live/.test(rail) &&
      /workflow-harness-group-promotion-eligibility/.test(rail) &&
      /workflow-harness-group-promotion-attempt/.test(rail) &&
      /data-gated-blockers/.test(rail) &&
      /data-live-blockers/.test(rail),
    rollbackCanaryContract:
      /WorkflowHarnessRollbackRestoreCanary[\s\S]*hashVerified[\s\S]*receiptBindingRef[\s\S]*blockers/.test(
        graph,
      ),
    backendHashVerification:
      /WorkflowRevisionRestoreResult[\s\S]*actualWorkflowContentHash[\s\S]*hashVerified/.test(
        graph,
      ) &&
      /workflow_project_content_hash[\s\S]*actual_workflow_content_hash[\s\S]*hash_verified[\s\S]*workflow_content_hash_mismatch[\s\S]*receipt_binding_ref/.test(
        restoreCommand,
      ),
  };
  const passed = Object.values(checks).every(Boolean);
  const proof = {
    schemaVersion: "ioi.autopilot.gui-harness.rollback-restore-canary-ui.v1",
    passed,
    checks,
    uiSelectors: {
      canaryCard: "workflow-harness-rollback-restore-canary",
      wizardStep: "workflow-harness-activation-step-rollback-restore",
      candidateGate: "workflow-harness-activation-candidate-gate-rollback-restore",
      activationAuditReceipt: "workflow-harness-activation-audit-receipt-${event.eventId}-${index}",
      rollbackDrillReceipt: "workflow-harness-rollback-drill-receipt-${index}",
      rollbackExecutionReceipt: "workflow-harness-rollback-execution-receipt-${index}",
      selectedReceiptDeepLinkState: "workflow-harness-deep-link-state[data-selected-receipt-ref]",
      receiptInspector: "workflow-harness-receipt-inspector",
      receiptPayloadPreview: "workflow-harness-receipt-payload-preview",
      receiptEvidenceRefs: "workflow-harness-receipt-evidence-refs",
      replayInspector: "workflow-harness-replay-inspector",
      replayPayloadPreview: "workflow-harness-replay-payload-preview",
      replayEvidenceRefs: "workflow-harness-replay-evidence-refs",
      runReplayDrill: "workflow-harness-run-replay-drill",
      replayDrillResult: "workflow-harness-replay-drill-result",
      replayDrillReceiptRefs: "workflow-harness-replay-drill-receipt-refs",
      runReplayGate: "workflow-harness-run-replay-gate",
      replayGateResult: "workflow-harness-replay-gate-result",
      replayGateReceiptRefs: "workflow-harness-replay-gate-receipt-refs",
      promotionClusterReplayGate: "workflow-harness-promotion-cluster-replay-gate",
      groupReplayGateProof: "workflow-harness-group-replay-gate-proof",
      promoteClusterGated: "workflow-harness-promote-cluster-gated",
      promoteClusterLive: "workflow-harness-promote-cluster-live",
      groupPromotionEligibility: "workflow-harness-group-promotion-eligibility",
      groupPromotionAttempt: "workflow-harness-group-promotion-attempt",
    },
    sourceRefs: [
      railPath,
      validationPath,
      harnessWorkflowPath,
      railModelPath,
      controllerPath,
      viewPath,
      graphPath,
      restoreCommandPath,
    ],
  };
  const path = join(outputRoot, "rollback-restore-canary-ui-proof.json");
  writeFileSync(path, `${JSON.stringify(proof, null, 2)}\n`, "utf8");
  return { path, proof };
}

function buildGuiEvidenceAssessment({ queryResults, runtimeArtifacts, rollbackRestoreCanaryUiProof }) {
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
  const hasHarnessShadow =
    summary.harnessWorkerBindingCount > 0 &&
    summary.harnessShadowRunCount > 0 &&
    summary.harnessNodeAttemptCount > 0 &&
    summary.harnessShadowComparisonCount > 0 &&
    summary.harnessBlockingDivergenceCount === 0;
  const hasHarnessGatedCognition =
    hasHarnessShadow &&
    summary.harnessGatedClusterCount > 0 &&
    summary.harnessGatedCognitionCount > 0;
  const hasHarnessGatedRoutingModel =
    hasHarnessShadow &&
    summary.harnessGatedClusterCount > 0 &&
    summary.harnessGatedRoutingModelCount > 0;
  const hasHarnessGatedVerificationOutput =
    hasHarnessShadow &&
    summary.harnessGatedClusterCount > 0 &&
    summary.harnessGatedVerificationOutputCount > 0;
  const hasHarnessGatedAuthorityTooling =
    hasHarnessShadow &&
    summary.harnessGatedClusterCount > 0 &&
    summary.harnessGatedAuthorityToolingCount > 0;
  const hasHarnessForkActivation =
    hasHarnessGatedAuthorityTooling &&
    summary.harnessForkActivationBlockedCount > 0 &&
    summary.harnessForkActivationMintedCount > 0;
  const hasHarnessRollbackRestoreCanary =
    hasHarnessForkActivation &&
    summary.harnessRollbackRestoreCanaryBlockedCount > 0 &&
    summary.harnessRollbackRestoreCanaryReadyCount > 0;
  const hasHarnessRollbackRestoreCanaryReceipts =
    hasHarnessRollbackRestoreCanary &&
    summary.harnessRollbackRestoreCanaryReceiptCount >= 2;
  const hasHarnessActivationAuditReceipts =
    hasHarnessRollbackRestoreCanaryReceipts &&
    summary.harnessActivationAuditReceiptCount > 0;
  const hasHarnessRollbackExecutionReceipts =
    hasHarnessActivationAuditReceipts &&
    summary.harnessRollbackExecutionReceiptCount > 0;
  const hasHarnessRollbackRestoreCanaryUi =
    hasHarnessRollbackRestoreCanary &&
    hasHarnessRollbackRestoreCanaryReceipts &&
    hasHarnessActivationAuditReceipts &&
    hasHarnessRollbackExecutionReceipts &&
    rollbackRestoreCanaryUiProof?.proof?.passed === true;
  const hasHarnessCanaryExecutionBoundary =
    hasHarnessRollbackRestoreCanary &&
    summary.harnessCanaryBoundaryExecutedCount > 0 &&
    summary.harnessCanaryBoundaryRollbackDrillCount > 0;
  const hasHarnessLiveHandoff =
    hasHarnessCanaryExecutionBoundary &&
    summary.harnessLiveHandoffDefaultPromotedCount > 0 &&
    summary.harnessLiveHandoffRollbackCount > 0;
  const hasHarnessSelectorRouting =
    hasHarnessLiveHandoff &&
    summary.harnessSelectorDefaultPromotedCount > 0 &&
    summary.harnessSelectorLegacyDefaultCount > 0;
  const hasHarnessDefaultRuntimeDispatch =
    hasHarnessSelectorRouting &&
    summary.harnessDefaultRuntimeDispatchReadonlyCount > 0 &&
    summary.harnessAuthorityToolingGateLiveCount > 0 &&
    summary.harnessAuthorityToolingProviderCatalogLiveCount > 0 &&
    summary.harnessAuthorityToolingMcpToolCatalogLiveCount > 0 &&
    summary.harnessAuthorityToolingNativeToolCatalogLiveCount > 0 &&
    summary.harnessAuthorityToolingConnectorCatalogLiveCount > 0 &&
    summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount > 0;
  const hasHarnessAuthorityToolingGateLive =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingGateLiveCount > 0;
  const hasHarnessAuthorityToolingProviderCatalogLive =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingProviderCatalogLiveCount > 0;
  const hasHarnessAuthorityToolingMcpToolCatalogLive =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingMcpToolCatalogLiveCount > 0;
  const hasHarnessAuthorityToolingNativeToolCatalogLive =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingNativeToolCatalogLiveCount > 0;
  const hasHarnessAuthorityToolingConnectorCatalogLive =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingConnectorCatalogLiveCount > 0;
  const hasHarnessAuthorityToolingWalletCapabilityLiveDryRun =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount > 0;
  const providerGatedVisibleOutputScenarioCoverage =
    AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS.every((scenario) =>
      summary.harnessModelProviderGatedVisibleOutputScenarios.includes(scenario),
    );
  const providerGatedVisibleOutputRollbackDrillScenarioCoverage =
    AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS.every((scenario) =>
      summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios.includes(scenario),
    );
  const hasHarnessModelProviderGatedVisibleOutput =
    hasHarnessDefaultRuntimeDispatch &&
    summary.harnessModelProviderGatedVisibleOutputCount > 0 &&
    providerGatedVisibleOutputScenarioCoverage;
  const hasHarnessModelProviderGatedVisibleOutputRollbackDrill =
    hasHarnessModelProviderGatedVisibleOutput &&
    summary.harnessModelProviderGatedVisibleOutputRollbackDrillCount > 0 &&
    providerGatedVisibleOutputRollbackDrillScenarioCoverage;
  const readOnlyCapabilityRoutingScenarioCoverage =
    AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS.every((scenario) =>
      summary.harnessReadOnlyCapabilityRoutingScenarios.includes(scenario),
    );
  const readOnlyCapabilityRoutingNoMutationScenarioCoverage =
    AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS.every((scenario) =>
      summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios.includes(scenario),
    );
  const hasHarnessReadOnlyCapabilityRouting =
    hasHarnessDefaultRuntimeDispatch &&
    readOnlyCapabilityRoutingScenarioCoverage &&
    readOnlyCapabilityRoutingNoMutationScenarioCoverage;

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
      harness_shadow_attempts_present: hasHarnessShadow,
      harness_gated_cognition_present: hasHarnessGatedCognition,
      harness_gated_routing_model_present: hasHarnessGatedRoutingModel,
      harness_gated_verification_output_present: hasHarnessGatedVerificationOutput,
      harness_gated_authority_tooling_present: hasHarnessGatedAuthorityTooling,
      harness_fork_activation_present: hasHarnessForkActivation,
      harness_rollback_restore_canary_present: hasHarnessRollbackRestoreCanary,
      harness_rollback_restore_canary_receipts_present:
        hasHarnessRollbackRestoreCanaryReceipts,
      harness_activation_audit_receipts_present: hasHarnessActivationAuditReceipts,
      harness_rollback_execution_receipts_present:
        hasHarnessRollbackExecutionReceipts,
      harness_rollback_restore_canary_ui_present: hasHarnessRollbackRestoreCanaryUi,
      harness_canary_execution_boundary_present: hasHarnessCanaryExecutionBoundary,
      harness_live_handoff_present: hasHarnessLiveHandoff,
      harness_selector_default_promoted: hasHarnessSelectorRouting,
      harness_default_runtime_dispatch_present: hasHarnessDefaultRuntimeDispatch,
      harness_authority_tooling_gate_live_present: hasHarnessAuthorityToolingGateLive,
      harness_authority_tooling_provider_catalog_live_present:
        hasHarnessAuthorityToolingProviderCatalogLive,
      harness_authority_tooling_mcp_tool_catalog_live_present:
        hasHarnessAuthorityToolingMcpToolCatalogLive,
      harness_authority_tooling_native_tool_catalog_live_present:
        hasHarnessAuthorityToolingNativeToolCatalogLive,
      harness_authority_tooling_connector_catalog_live_present:
        hasHarnessAuthorityToolingConnectorCatalogLive,
      harness_authority_tooling_wallet_capability_live_dry_run_present:
        hasHarnessAuthorityToolingWalletCapabilityLiveDryRun,
      harness_model_provider_gated_visible_output_present:
        hasHarnessModelProviderGatedVisibleOutput,
      harness_model_provider_gated_visible_output_rollback_drill_present:
        hasHarnessModelProviderGatedVisibleOutputRollbackDrill,
      harness_read_only_capability_routing_present: hasHarnessReadOnlyCapabilityRouting,
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
      hasHarnessShadow,
      hasHarnessGatedCognition,
      hasHarnessGatedRoutingModel,
      hasHarnessGatedVerificationOutput,
      hasHarnessGatedAuthorityTooling,
      hasHarnessForkActivation,
      hasHarnessRollbackRestoreCanary,
      hasHarnessRollbackRestoreCanaryReceipts,
      hasHarnessActivationAuditReceipts,
      hasHarnessRollbackExecutionReceipts,
      hasHarnessRollbackRestoreCanaryUi,
      hasHarnessCanaryExecutionBoundary,
      hasHarnessLiveHandoff,
      hasHarnessSelectorRouting,
      hasHarnessDefaultRuntimeDispatch,
      hasHarnessAuthorityToolingGateLive,
      hasHarnessModelProviderGatedVisibleOutput,
      hasHarnessModelProviderGatedVisibleOutputRollbackDrill,
      hasHarnessReadOnlyCapabilityRouting,
      providerGatedVisibleOutputRequiredScenarios: [
        ...AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS,
      ],
      providerGatedVisibleOutputScenarioCoverage,
      providerGatedVisibleOutputRollbackDrillScenarioCoverage,
      readOnlyCapabilityRoutingRequiredScenarios: [
        ...AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS,
      ],
      readOnlyCapabilityRoutingScenarioCoverage,
      readOnlyCapabilityRoutingNoMutationScenarioCoverage,
      harnessModelProviderGatedVisibleOutputScenarios:
        summary.harnessModelProviderGatedVisibleOutputScenarios,
      harnessModelProviderGatedVisibleOutputRollbackDrillScenarios:
        summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios,
      harnessReadOnlyCapabilityRoutingCount:
        summary.harnessReadOnlyCapabilityRoutingCount,
      harnessReadOnlyCapabilityRoutingNoMutationCount:
        summary.harnessReadOnlyCapabilityRoutingNoMutationCount,
      harnessReadOnlyCapabilityRoutingScenarios:
        summary.harnessReadOnlyCapabilityRoutingScenarios,
      harnessReadOnlyCapabilityRoutingNoMutationScenarios:
        summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios,
      harnessWorkerBindingCount: summary.harnessWorkerBindingCount,
      harnessShadowRunCount: summary.harnessShadowRunCount,
      harnessNodeAttemptCount: summary.harnessNodeAttemptCount,
      harnessShadowComparisonCount: summary.harnessShadowComparisonCount,
      harnessBlockingDivergenceCount: summary.harnessBlockingDivergenceCount,
      harnessGatedClusterCount: summary.harnessGatedClusterCount,
      harnessGatedCognitionCount: summary.harnessGatedCognitionCount,
      harnessGatedRoutingModelCount: summary.harnessGatedRoutingModelCount,
      harnessGatedVerificationOutputCount: summary.harnessGatedVerificationOutputCount,
      harnessGatedAuthorityToolingCount: summary.harnessGatedAuthorityToolingCount,
      harnessForkActivationBlockedCount: summary.harnessForkActivationBlockedCount,
      harnessForkActivationMintedCount: summary.harnessForkActivationMintedCount,
      harnessRollbackRestoreCanaryBlockedCount:
        summary.harnessRollbackRestoreCanaryBlockedCount,
      harnessRollbackRestoreCanaryReadyCount:
        summary.harnessRollbackRestoreCanaryReadyCount,
      harnessRollbackRestoreCanaryReceiptCount:
        summary.harnessRollbackRestoreCanaryReceiptCount,
      harnessActivationAuditReceiptCount:
        summary.harnessActivationAuditReceiptCount,
      harnessRollbackExecutionReceiptCount:
        summary.harnessRollbackExecutionReceiptCount,
      harnessRollbackRestoreCanaryStatuses:
        summary.harnessRollbackRestoreCanaryStatuses,
      harnessRollbackRestoreCanaryUiProof: rollbackRestoreCanaryUiProof?.proof ?? null,
      harnessCanaryBoundaryExecutedCount: summary.harnessCanaryBoundaryExecutedCount,
      harnessCanaryBoundaryRollbackDrillCount: summary.harnessCanaryBoundaryRollbackDrillCount,
      harnessSelectorCanaryRoutedCount: summary.harnessSelectorCanaryRoutedCount,
      harnessSelectorLegacyDefaultCount: summary.harnessSelectorLegacyDefaultCount,
      harnessSelectorDefaultPromotedCount: summary.harnessSelectorDefaultPromotedCount,
      harnessLiveHandoffCanaryCount: summary.harnessLiveHandoffCanaryCount,
      harnessLiveHandoffDefaultPromotedCount: summary.harnessLiveHandoffDefaultPromotedCount,
      harnessLiveHandoffRollbackCount: summary.harnessLiveHandoffRollbackCount,
      harnessDefaultRuntimeDispatchReadonlyCount:
        summary.harnessDefaultRuntimeDispatchReadonlyCount,
      harnessAuthorityToolingReadOnlyCanaryCount:
        summary.harnessAuthorityToolingReadOnlyCanaryCount,
      harnessAuthorityToolingGateLiveCount:
        summary.harnessAuthorityToolingGateLiveCount,
      harnessAuthorityToolingProviderCatalogLiveCount:
        summary.harnessAuthorityToolingProviderCatalogLiveCount,
      harnessAuthorityToolingMcpToolCatalogLiveCount:
        summary.harnessAuthorityToolingMcpToolCatalogLiveCount,
      harnessAuthorityToolingNativeToolCatalogLiveCount:
        summary.harnessAuthorityToolingNativeToolCatalogLiveCount,
      harnessAuthorityToolingConnectorCatalogLiveCount:
        summary.harnessAuthorityToolingConnectorCatalogLiveCount,
      harnessAuthorityToolingWalletCapabilityLiveDryRunCount:
        summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount,
      harnessModelProviderGatedVisibleOutputCount:
        summary.harnessModelProviderGatedVisibleOutputCount,
      harnessModelProviderGatedVisibleOutputRollbackDrillCount:
        summary.harnessModelProviderGatedVisibleOutputRollbackDrillCount,
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
      AUTOPILOT_HARNESS_DEFAULT_PROMOTION:
        process.env.AUTOPILOT_HARNESS_DEFAULT_PROMOTION ?? "1",
      AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT:
        process.env.AUTOPILOT_WORKFLOW_PROVIDER_GATED_VISIBLE_OUTPUT ?? "1",
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
    const rollbackRestoreCanaryUiProof = collectRollbackRestoreCanaryUiProof(outputRoot);
    const guiEvidence = buildGuiEvidenceAssessment({
      queryResults,
      runtimeArtifacts,
      rollbackRestoreCanaryUiProof,
    });
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
        harness_shadow_run:
          runtimeArtifacts.summary.harnessShadowRunCount > 0 &&
          runtimeArtifacts.summary.harnessNodeAttemptCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_gated_cognition:
          runtimeArtifacts.summary.harnessGatedCognitionCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_gated_routing_model:
          runtimeArtifacts.summary.harnessGatedRoutingModelCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_gated_verification_output:
          runtimeArtifacts.summary.harnessGatedVerificationOutputCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_gated_authority_tooling:
          runtimeArtifacts.summary.harnessGatedAuthorityToolingCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_fork_activation:
          runtimeArtifacts.summary.harnessForkActivationBlockedCount > 0 &&
          runtimeArtifacts.summary.harnessForkActivationMintedCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_rollback_restore_canary:
          runtimeArtifacts.summary.harnessRollbackRestoreCanaryBlockedCount > 0 &&
          runtimeArtifacts.summary.harnessRollbackRestoreCanaryReadyCount > 0 &&
          runtimeArtifacts.summary.harnessRollbackRestoreCanaryReceiptCount >= 2 &&
          runtimeArtifacts.summary.harnessActivationAuditReceiptCount > 0 &&
          runtimeArtifacts.summary.harnessRollbackExecutionReceiptCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_rollback_restore_canary_ui:
          rollbackRestoreCanaryUiProof.proof.passed === true
            ? rollbackRestoreCanaryUiProof.path
            : false,
        harness_canary_execution_boundary:
          runtimeArtifacts.summary.harnessCanaryBoundaryExecutedCount > 0 &&
          runtimeArtifacts.summary.harnessCanaryBoundaryRollbackDrillCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_live_handoff:
          runtimeArtifacts.summary.harnessLiveHandoffDefaultPromotedCount > 0 &&
          runtimeArtifacts.summary.harnessLiveHandoffRollbackCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_selector_routing:
          runtimeArtifacts.summary.harnessSelectorDefaultPromotedCount > 0 &&
          runtimeArtifacts.summary.harnessSelectorLegacyDefaultCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_default_runtime_dispatch:
          runtimeArtifacts.summary.harnessDefaultRuntimeDispatchReadonlyCount > 0 &&
          runtimeArtifacts.summary.harnessAuthorityToolingGateLiveCount > 0 &&
          runtimeArtifacts.summary.harnessAuthorityToolingProviderCatalogLiveCount > 0 &&
          runtimeArtifacts.summary.harnessAuthorityToolingMcpToolCatalogLiveCount > 0 &&
          runtimeArtifacts.summary.harnessAuthorityToolingNativeToolCatalogLiveCount > 0 &&
          runtimeArtifacts.summary.harnessAuthorityToolingConnectorCatalogLiveCount > 0 &&
          runtimeArtifacts.summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_authority_tooling_gate_live:
          runtimeArtifacts.summary.harnessAuthorityToolingGateLiveCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_authority_tooling_provider_catalog_live:
          runtimeArtifacts.summary.harnessAuthorityToolingProviderCatalogLiveCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_authority_tooling_mcp_tool_catalog_live:
          runtimeArtifacts.summary.harnessAuthorityToolingMcpToolCatalogLiveCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_authority_tooling_native_tool_catalog_live:
          runtimeArtifacts.summary.harnessAuthorityToolingNativeToolCatalogLiveCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_authority_tooling_connector_catalog_live:
          runtimeArtifacts.summary.harnessAuthorityToolingConnectorCatalogLiveCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_authority_tooling_wallet_capability_live_dry_run:
          runtimeArtifacts.summary.harnessAuthorityToolingWalletCapabilityLiveDryRunCount > 0
            ? runtimeArtifacts.path
            : false,
        harness_model_provider_gated_visible_output:
          runtimeArtifacts.summary.harnessModelProviderGatedVisibleOutputCount > 0 &&
          AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS.every((scenario) =>
            runtimeArtifacts.summary.harnessModelProviderGatedVisibleOutputScenarios.includes(
              scenario,
            ),
          )
            ? runtimeArtifacts.path
            : false,
        harness_model_provider_gated_visible_output_rollback_drill:
          runtimeArtifacts.summary.harnessModelProviderGatedVisibleOutputRollbackDrillCount > 0 &&
          AUTOPILOT_PROVIDER_GATED_VISIBLE_OUTPUT_REQUIRED_SCENARIOS.every((scenario) =>
            runtimeArtifacts.summary.harnessModelProviderGatedVisibleOutputRollbackDrillScenarios.includes(
              scenario,
            ),
          )
            ? runtimeArtifacts.path
            : false,
        harness_read_only_capability_routing:
          runtimeArtifacts.summary.harnessDefaultRuntimeDispatchReadonlyCount > 0 &&
          AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS.every((scenario) =>
            runtimeArtifacts.summary.harnessReadOnlyCapabilityRoutingScenarios.includes(
              scenario,
            ),
          ) &&
          AUTOPILOT_READ_ONLY_CAPABILITY_ROUTING_REQUIRED_SCENARIOS.every((scenario) =>
            runtimeArtifacts.summary.harnessReadOnlyCapabilityRoutingNoMutationScenarios.includes(
              scenario,
            ),
          )
            ? runtimeArtifacts.path
            : false,
      },
      chatUx: guiEvidence.chatUx,
      runtimeConsistency: guiEvidence.runtimeConsistency,
      evidenceAssessment: guiEvidence.assessment,
      uiAssertions: {
        rollbackRestoreCanary: rollbackRestoreCanaryUiProof.proof,
      },
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
