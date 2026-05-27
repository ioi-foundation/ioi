#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { createServer as createNetServer } from "node:net";
import {
  appendFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { chromium } from "playwright";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";
import {
  AUTOPILOT_ELECTRON,
  syncWorkbenchExtensionTargets,
} from "./autopilot-electron-app-paths.mjs";
import { applyAutopilotWorkbenchShellPatch } from "./autopilot-workbench-shell-patch.mjs";
import { buildWorkflowSafeModeToolSuppressionPanel } from "../../packages/agent-ide/src/runtime/workflow-safe-mode-tool-suppression.ts";
import { buildWorkflowOnboardingDiagnosticsChecklist } from "../../packages/agent-ide/src/runtime/workflow-onboarding-diagnostics-checklist.ts";
import { buildWorkflowGatewayTokenHygienePanel } from "../../packages/agent-ide/src/runtime/workflow-gateway-token-hygiene.ts";
import { buildWorkflowSandboxResourceLimitPanel } from "../../packages/agent-ide/src/runtime/workflow-sandbox-resource-limits.ts";
import { buildWorkflowParentTrajectoryLinkagePanel } from "../../packages/agent-ide/src/runtime/workflow-parent-trajectory-linkage.ts";
import { buildWorkflowBattleModePermissionImportPanel } from "../../packages/agent-ide/src/runtime/workflow-battle-mode-permission-import.ts";
import { buildWorkflowImportedStopHookGatePanel } from "../../packages/agent-ide/src/runtime/workflow-imported-stop-hook-gates.ts";
import { buildWorkflowImportedBrowserActionEvidencePanel } from "../../packages/agent-ide/src/runtime/workflow-imported-browser-action-evidence.ts";
import { buildWorkflowImportedExecutorConfigPanel } from "../../packages/agent-ide/src/runtime/workflow-imported-executor-config.ts";
import { buildWorkflowImportedPolicyDraft } from "../../packages/agent-ide/src/runtime/workflow-imported-policy-draft.ts";
import { buildWorkflowImportedGenerationMetadataPanel } from "../../packages/agent-ide/src/runtime/workflow-imported-generation-metadata.ts";
import { buildWorkflowImportedErrorRenderInfoPanel } from "../../packages/agent-ide/src/runtime/workflow-imported-error-render-info.ts";

const repoRoot = AUTOPILOT_ELECTRON.repoRoot;
const evidenceRoot =
  "docs/evidence/autopilot-agent-studio-gui-chat-ux-compositor-harness-parity-plus";

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForPredicate(predicate, timeoutMs, intervalMs = 250) {
  const deadline = Date.now() + timeoutMs;
  let latest;
  while (Date.now() < deadline) {
    latest = await predicate();
    if (latest) return latest;
    await wait(intervalMs);
  }
  return latest;
}

function listen(server) {
  return new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => {
      server.off("error", rejectListen);
      resolveListen(server.address());
    });
  });
}

function closeServer(server) {
  return new Promise((resolveClose) => {
    if (!server) {
      resolveClose();
      return;
    }
    server.close(() => resolveClose());
  });
}

async function getFreePort() {
  const server = createNetServer();
  await listen(server);
  const { port } = server.address();
  await closeServer(server);
  return port;
}

async function waitForCdp(port, timeoutMs = 45_000) {
  return waitForPredicate(async () => {
    try {
      const response = await fetch(`http://127.0.0.1:${port}/json/version`);
      return response.ok ? response.json() : null;
    } catch {
      return null;
    }
  }, timeoutMs, 500);
}

function sendJson(response, statusCode, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(statusCode, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
  });
  response.end(body);
}

function readRequestBody(request) {
  return new Promise((resolveBody, rejectBody) => {
    const chunks = [];
    request.on("data", (chunk) => chunks.push(chunk));
    request.on("error", rejectBody);
    request.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      try {
        resolveBody(raw ? JSON.parse(raw) : {});
      } catch (error) {
        rejectBody(error);
      }
    });
  });
}

function bridgeState(daemonEndpoint) {
  return {
    schemaVersion: "ioi.workbench-bridge-state.v1",
    generatedAtMs: Date.now(),
    workspace: {
      name: "ioi",
      path: repoRoot,
      rootPath: repoRoot,
    },
    summary: {
      activeRunCount: 0,
      policyIssueCount: 0,
      connectorCount: 0,
    },
    modelMountingStatus: {
      status: "connected",
      endpoint: daemonEndpoint,
    },
    modelMounting: {
      routes: [
        {
          id: "route.local-first",
          routeId: "route.local-first",
          status: "ready",
          modelId: "autopilot-native-fixture",
          endpointId: "endpoint.agent-studio.native",
          capabilities: ["chat", "responses", "structured_output"],
        },
      ],
      server: {
        status: "running",
        endpoint: daemonEndpoint,
      },
    },
    workflows: [],
    runs: [],
    policy: {
      activeIssueCount: 0,
      issues: [],
    },
    connections: [],
  };
}

function createBridge({ daemonEndpoint, requests, commands, deliveredCommands }) {
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (request.method === "GET" && url.pathname === "/state") {
        sendJson(response, 200, bridgeState(daemonEndpoint));
        return;
      }
      if (request.method === "GET" && url.pathname === "/commands") {
        const next = commands.splice(0);
        deliveredCommands.push(...next);
        sendJson(response, 200, next);
        return;
      }
      if (request.method === "POST" && url.pathname === "/requests") {
        const body = await readRequestBody(request);
        requests.push(body);
        sendJson(response, 200, { ok: true });
        return;
      }
      sendJson(response, 404, { error: "not_found" });
    } catch (error) {
      sendJson(response, 500, { error: String(error?.message ?? error) });
    }
  });
}

function queueCommand(commands, command, payload = {}) {
  const commandId = `${command}:${Date.now()}:${commands.length}`;
  commands.push({ commandId, command, args: [payload] });
  return commandId;
}

async function requireRequest(requests, predicate, label, timeoutMs = 45_000) {
  const request = await waitForPredicate(
    () => requests.find((candidate) => predicate(candidate)),
    timeoutMs,
    300,
  );
  if (!request) throw new Error(`Timed out waiting for bridge request: ${label}`);
  return request;
}

async function findFrameWithTestId(page, testId, timeoutMs = 45_000) {
  const selector = `[data-testid="${testId}"]`;
  const frame = await waitForPredicate(async () => {
    for (const candidate of page.frames()) {
      try {
        if ((await candidate.locator(selector).count()) > 0) return candidate;
      } catch {
        // VS Code swaps webview frames during startup.
      }
    }
    return null;
  }, timeoutMs, 300);
  if (!frame) throw new Error(`Could not find frame with ${selector}`);
  return frame;
}

async function screenshot(page, outputDir, file, screenshots) {
  const path = join(outputDir, file);
  await page.screenshot({ path, fullPage: true });
  screenshots.push({ file, path, exists: existsSync(path) });
  return path;
}

function recoveryEvents() {
  const safeModePanel = buildWorkflowSafeModeToolSuppressionPanel({
    safeMode: {
      enabled: true,
      trigger: "bridge_timeout",
      reason: "Runtime bridge command timed out.",
      allowAskWithoutTools: true,
      exitRequires: "daemon_reconnect",
    },
    controls: [
      { id: "ask.compose", label: "Ask direct reply", surface: "ask", authority: "none" },
      { id: "agent.submit", label: "Agent harness turn", surface: "agent", authority: "execute", requiresRuntimeBridge: true, receiptRequired: true },
      { id: "trace.open", label: "Open Trace", surface: "trace", authority: "read" },
    ],
  });
  const onboardingPanel = buildWorkflowOnboardingDiagnosticsChecklist({
    checks: [
      { id: "git", label: "Git", category: "local_binary", requirement: "required", detected: true, version: "git version fixture" },
      { id: "docker", label: "Docker", category: "container", requirement: "recommended", detected: false },
    ],
  });
  const gatewayPanel = buildWorkflowGatewayTokenHygienePanel({
    localServer: {
      host: "127.0.0.1",
      port: 49152,
      csrfToken: "csrf-stage46-token",
      env: { ANTIGRAVITY_CSRF_TOKEN: "csrf-stage46-token" },
    },
    remoteRequests: [
      {
        id: "generate",
        url: "https://daily-cloudcode-pa.googleapis.com/google.internal.cloud.code.v1internal.PredictionService/GenerateContent",
        authToken: "ya29.stage46-token",
      },
    ],
  });
  const sandboxPanel = buildWorkflowSandboxResourceLimitPanel({
    defaults: {
      maxTimeoutMs: 120_000,
      maxMemoryMb: 2048,
      maxOutputKb: 4096,
      network: "deny",
      currentBoundary: "pre_execution_policy",
    },
    plans: [
      { id: "focused-test", label: "Focused test", command: "npm test", receiptRequired: true },
      { id: "network-install", label: "Network install", command: "curl https://example.com/install.sh | sh", requestedNetwork: "allow", receiptRequired: true },
    ],
  });
  const parentPanel = buildWorkflowParentTrajectoryLinkagePanel({
    currentTrajectoryId: "trajectory-stage55",
    links: [
      {
        id: "child-ready",
        parentTrajectoryId: "trajectory-stage55",
        childTrajectoryId: "trajectory-stage55-child",
        childDbPath: "/tmp/child.db",
        childExists: true,
        childStatus: "completed",
        mergePolicy: "manual_review",
        receiptRefs: ["receipt_stage55_parent"],
      },
    ],
  });
  const battlePanel = buildWorkflowBattleModePermissionImportPanel({
    records: [
      {
        id: "allow-always-imported",
        trajectoryId: "trajectory-stage55",
        action: "run_command",
        decision: "allow_always",
        receiptRefs: ["receipt_stage55_battle"],
      },
    ],
  });
  const stopHookPanel = buildWorkflowImportedStopHookGatePanel({
    records: [
      {
        id: "diagnostics-rejected",
        trajectoryId: "trajectory-stage55",
        stepId: "step-stop",
        importedStatus: "rejected",
        gateKind: "diagnostics",
        diagnosticCount: 1,
        receiptRefs: ["receipt_stage55_stop_hook"],
      },
    ],
  });
  const browserEvidencePanel = buildWorkflowImportedBrowserActionEvidencePanel({
    records: [
      {
        id: "browser-click",
        trajectoryId: "trajectory-stage55",
        stepId: "step-browser",
        action: "click",
        url: "https://example.invalid",
        target: { x: 80, y: 120 },
        viewport: { width: 1280, height: 720 },
        screenshotRef: "artifact:browser:screenshot",
        domSnapshotRef: "artifact:browser:dom",
        accessibilityRef: "artifact:browser:ax",
        postconditionRef: "artifact:browser:postcondition",
        cleanupRef: "artifact:browser:cleanup",
        receiptRefs: ["receipt_stage55_browser"],
      },
    ],
  });
  const executorPanel = buildWorkflowImportedExecutorConfigPanel({
    sourceTable: "executor_metadata",
    sourceRowId: 55,
    trajectoryId: "trajectory-stage55",
    allowedCommands: ["echo", "curl"],
    blockedCommands: ["ssh"],
    ideChecks: { diagnostics: true, tests: true, lint: false },
    memoryLimitMb: 2048,
    networkDefault: "allow",
    receiptRefs: ["receipt_stage55_executor"],
  });
  const policyDraftPanel = buildWorkflowImportedPolicyDraft({
    sourcePanel: executorPanel,
  });
  const generationPanel = buildWorkflowImportedGenerationMetadataPanel({
    trajectoryId: "trajectory-stage55",
    rows: [
      {
        sourceRowId: 1,
        kind: "gateway_request",
        gatewayUrl: "http://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent",
        headers: { Authorization: "Bearer ya29.stage55-token" },
        receiptRefs: ["receipt_stage55_generation"],
      },
    ],
  });
  const errorRenderPanel = buildWorkflowImportedErrorRenderInfoPanel({
    trajectoryId: "trajectory-stage55",
    workspaceRoot: "/workspace/project",
    rows: [
      {
        sourceRowId: 1,
        stepIndex: 1,
        column: "render_info",
        renderKind: "markdown",
        artifactRef: "artifact:render:stage55",
        targetUri: "https://example.invalid/render",
        receiptRefs: ["receipt_stage55_error_render"],
      },
    ],
  });

  return {
    panels: {
      safeModePanel,
      onboardingPanel,
      gatewayPanel,
      sandboxPanel,
      parentPanel,
      battlePanel,
      stopHookPanel,
      browserEvidencePanel,
      executorPanel,
      policyDraftPanel,
      generationPanel,
      errorRenderPanel,
    },
    events: [
      parityEvent("stage46-safe-mode", "safe_mode.tool_suppression", safeModePanel, "Safe Mode suppresses Agent tools while Ask remains available.", ["receipt_stage46_safe_mode"]),
      parityEvent("stage46-onboarding", "onboarding.diagnostics", onboardingPanel, "Onboarding checks show Git ready and Docker recommended setup.", ["receipt_stage46_onboarding"]),
      parityEvent("stage46-gateway", "gateway.token_hygiene", gatewayPanel, "Gateway requests are redacted dry-run plans.", ["receipt_stage46_gateway"]),
      parityEvent("stage46-sandbox", "sandbox.resource_limits", sandboxPanel, "Sandbox resource limits block network install.", ["receipt_stage46_sandbox"]),
      parityEvent("stage55-parent", "imported.parent_trajectory_linkage", parentPanel, "Imported parent links remain audit-only.", ["receipt_stage55_parent"]),
      parityEvent("stage55-battle", "imported.battle_mode_permission", battlePanel, "Imported persistent permission grants are blocked.", ["receipt_stage55_battle"]),
      parityEvent("stage55-stop-hook", "imported.stop_hook_gates", stopHookPanel, "Imported stop hooks require live verification.", ["receipt_stage55_stop_hook"]),
      parityEvent("stage55-browser", "imported.browser_action_evidence", browserEvidencePanel, "Imported browser actions require fresh observation.", ["receipt_stage55_browser"]),
      parityEvent("stage55-executor", "imported.executor_config", executorPanel, "Imported executor config is advisory-only.", ["receipt_stage55_executor"]),
      parityEvent("stage55-policy-draft", "imported.policy_draft", policyDraftPanel, "Imported executor hints become draft-only policy.", ["receipt_stage55_policy_draft"]),
      parityEvent("stage55-generation", "imported.generation_metadata", generationPanel, "Imported generation metadata is redacted and audit-only.", ["receipt_stage55_generation"]),
      parityEvent("stage55-error-render", "imported.error_render_info", errorRenderPanel, "Imported error/render rows are stack-safe and artifact-ref-only.", ["receipt_stage55_error_render"]),
    ],
  };
}

function parityEvent(id, kind, panel, detail, receiptRefs) {
  return {
    id,
    event_id: id,
    event_kind: kind,
    status: panel.status,
    receiptRefs,
    payload_summary: {
      ...panel,
      detail,
      receiptRefs,
    },
  };
}

async function panelEvidence(frame) {
  const panelIds = [
    "studio-safe-mode-tool-suppression",
    "studio-onboarding-diagnostics-checklist",
    "studio-gateway-token-hygiene",
    "studio-sandbox-resource-limits",
    "studio-imported-parent-trajectory-linkage",
    "studio-imported-battle-mode-permission",
    "studio-imported-stop-hook-gates",
    "studio-imported-browser-action-evidence",
    "studio-imported-executor-config",
    "studio-imported-policy-draft",
    "studio-imported-generation-metadata",
    "studio-imported-error-render-info",
  ];
  const evidence = {};
  for (const testId of panelIds) {
    const locator = frame.locator(`[data-testid="${testId}"]`).first();
    evidence[testId] = {
      count: await frame.locator(`[data-testid="${testId}"]`).count().catch(() => 0),
      visible: await locator.isVisible().catch(() => false),
      status: await locator.getAttribute("data-panel-status").catch(() => null),
      kind: await locator.getAttribute("data-panel-kind").catch(() => null),
      text: await locator.textContent().catch(() => ""),
      verifiedBadgeCount: await locator.locator('[data-testid="studio-verified-badge"]').count().catch(() => 0),
    };
  }
  return evidence;
}

async function selectStudioMode(frame, selectionId, label) {
  return frame.evaluate(
    ({ selectionId, label }) =>
      new Promise((resolve) => {
        window.postMessage(
          {
            source: "ioi-autopilot-fork-quickinput",
            type: "ioi.quickInput.result",
            result: {
              kind: "agentMode",
              selectionId,
              label,
            },
          },
          "*",
        );
        window.setTimeout(() => {
          const button = document.querySelector("[data-testid='studio-mode-toggle']");
          resolve({
            mode: button?.dataset?.studioMode || null,
            text: button?.textContent || "",
          });
        }, 100);
      }),
    { selectionId, label },
  );
}

function panelsReady(evidence) {
  return Object.values(evidence).every((entry) => entry.visible && entry.verifiedBadgeCount > 0);
}

async function run(outputDir) {
  ensureDir(outputDir);
  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyAutopilotWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);

  const { panels, events } = recoveryEvents();
  const daemonStateDir = mkdtempSync(join(tmpdir(), "autopilot-stage46-daemon-"));
  const daemon = await startRuntimeDaemonService({ cwd: repoRoot, stateDir: daemonStateDir });
  const requests = [];
  const commands = [];
  const deliveredCommands = [];
  const screenshots = [];
  const consoleLogs = [];
  const pageErrors = [];
  const stdoutPath = join(outputDir, "electron-stdout.log");
  const stderrPath = join(outputDir, "electron-stderr.log");
  let server;
  let app;
  let browser;
  let context;
  let tracingStarted = false;
  let userDataDir;

  try {
    server = createBridge({ daemonEndpoint: daemon.endpoint, requests, commands, deliveredCommands });
    const bridgeAddress = await listen(server);
    const bridgeUrl = `http://127.0.0.1:${bridgeAddress.port}`;
    const cdpPort = await getFreePort();
    userDataDir = mkdtempSync(join(tmpdir(), "autopilot-stage46-user-"));
    const extensionsDir = mkdtempSync(join(tmpdir(), "autopilot-stage46-ext-"));
    writeFileSync(join(outputDir, "bridge-url"), `${bridgeUrl}\n`);
    writeFileSync(join(outputDir, "daemon-endpoint"), `${daemon.endpoint}\n`);
    writeFileSync(join(outputDir, "user-data-dir"), `${userDataDir}\n`);

    app = spawn(
      AUTOPILOT_ELECTRON.binary,
      [
        `--remote-debugging-port=${cdpPort}`,
        `--user-data-dir=${userDataDir}`,
        `--extensions-dir=${extensionsDir}`,
        "--disable-updates",
        "--disable-workspace-trust",
        "--new-window",
        repoRoot,
      ],
      {
        cwd: repoRoot,
        env: {
          ...process.env,
          IOI_WORKSPACE_IDE_BRIDGE_URL: bridgeUrl,
          IOI_DAEMON_ENDPOINT: daemon.endpoint,
          IOI_AUTOPILOT_CANONICAL_SHELL: "vscode-electron-fork",
          IOI_WORKBENCH_NATIVE_SHELL: "1",
          IOI_AUTOPILOT_STUDIO_TEST_HOOKS: "1",
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    app.stdout.on("data", (chunk) => appendFileSync(stdoutPath, chunk));
    app.stderr.on("data", (chunk) => appendFileSync(stderrPath, chunk));
    writeFileSync(join(outputDir, "pid"), `${app.pid}\n`);

    const cdpVersion = await waitForCdp(cdpPort);
    if (!cdpVersion) throw new Error("Electron app did not expose a CDP endpoint.");
    writeFileSync(join(outputDir, "cdp-version.json"), `${JSON.stringify(cdpVersion, null, 2)}\n`);

    browser = await chromium.connectOverCDP(`http://127.0.0.1:${cdpPort}`);
    context = browser.contexts()[0] ?? (await browser.newContext());
    context.on("page", (page) => {
      page.on("console", (message) => {
        consoleLogs.push({ type: message.type(), text: message.text(), location: message.location() });
      });
      page.on("pageerror", (error) => {
        pageErrors.push(String(error?.stack ?? error?.message ?? error));
      });
    });
    await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
    tracingStarted = true;
    const page = await waitForPredicate(
      () => context.pages().find((candidate) => !candidate.isClosed()) ?? null,
      30_000,
      250,
    );
    if (!page) throw new Error("No Playwright page was available for the Electron fork.");
    page.on("console", (message) => {
      consoleLogs.push({ type: message.type(), text: message.text(), location: message.location() });
    });
    page.on("pageerror", (error) => {
      pageErrors.push(String(error?.stack ?? error?.message ?? error));
    });
    await page.setViewportSize({ width: 1600, height: 950 }).catch(() => undefined);

    queueCommand(commands, "ioi.studio.open", { phase: "stage46-recovery-panels" });
    await requireRequest(requests, (request) => request?.requestType === "studio.open", "studio.open");
    let studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat");
    await screenshot(page, outputDir, "studio-recovery-panels-open.png", screenshots);
    const askModeSelection = await selectStudioMode(studioFrame, "ask", "Ask");
    const askModeRequest = await requireRequest(
      requests,
      (request) =>
        request?.requestType === "chat.agentMode.select" &&
        request?.payload?.executionMode === "ask",
      "chat.agentMode.select ask",
    );
    const agentModeSelection = await selectStudioMode(studioFrame, "agent", "Agent");
    const agentModeRequest = await requireRequest(
      requests,
      (request) =>
        request?.requestType === "chat.agentMode.select" &&
        request?.payload?.executionMode === "agent",
      "chat.agentMode.select agent",
    );

    queueCommand(commands, "ioi.studio.injectParityPlusEvents", {
      status: "completed",
      events,
    });
    const injectionRequest = await requireRequest(
      requests,
      (request) => request?.requestType === "studio.parityPlusEvents.injected",
      "studio.parityPlusEvents.injected",
    );

    const readyEvidence = await waitForPredicate(async () => {
      try {
        studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
        await studioFrame.locator('[data-testid="studio-utility-toggle"]').click().catch(() => undefined);
        const evidence = await panelEvidence(studioFrame);
        return panelsReady(evidence) ? evidence : null;
      } catch {
        return null;
      }
    }, 20_000, 300);
    if (!readyEvidence) {
      const latestEvidence = await panelEvidence(studioFrame).catch((error) => ({ error: String(error) }));
      throw new Error(`Recovery parity-plus panels did not hydrate in live GUI: ${JSON.stringify(latestEvidence)}`);
    }

    await screenshot(page, outputDir, "studio-recovery-panels-hydrated.png", screenshots);

    const proof = {
      schemaVersion: "ioi.autopilot.stage46.recovery-panels-live-gui-proof.v1",
      passed: true,
      daemonEndpoint: daemon.endpoint,
      screenshots,
      panels,
      modeSelection: {
        askModeSelection,
        agentModeSelection,
        askModeRequest,
        agentModeRequest,
      },
      injectionRequest,
      panelEvidence: readyEvidence,
      checks: {
        electronLaunched: Boolean(cdpVersion),
        studioOpened: true,
        askModeSelectionVisible: askModeSelection?.mode === "ask",
        agentModeSelectionVisible: agentModeSelection?.mode === "agent",
        askModeBridgeRequestRecorded: Boolean(askModeRequest),
        agentModeBridgeRequestRecorded: Boolean(agentModeRequest),
        injectionBridgeRequestRecorded: Boolean(injectionRequest),
        eventsInjected: injectionRequest?.payload?.eventCount === events.length || injectionRequest?.eventCount === events.length,
        safeModeVisible: readyEvidence["studio-safe-mode-tool-suppression"]?.visible,
        onboardingVisible: readyEvidence["studio-onboarding-diagnostics-checklist"]?.visible,
        gatewayVisible: readyEvidence["studio-gateway-token-hygiene"]?.visible,
        sandboxVisible: readyEvidence["studio-sandbox-resource-limits"]?.visible,
        importedParentVisible: readyEvidence["studio-imported-parent-trajectory-linkage"]?.visible,
        importedBattleVisible: readyEvidence["studio-imported-battle-mode-permission"]?.visible,
        importedStopHookVisible: readyEvidence["studio-imported-stop-hook-gates"]?.visible,
        importedBrowserEvidenceVisible: readyEvidence["studio-imported-browser-action-evidence"]?.visible,
        importedExecutorConfigVisible: readyEvidence["studio-imported-executor-config"]?.visible,
        importedPolicyDraftVisible: readyEvidence["studio-imported-policy-draft"]?.visible,
        importedGenerationMetadataVisible: readyEvidence["studio-imported-generation-metadata"]?.visible,
        importedErrorRenderInfoVisible: readyEvidence["studio-imported-error-render-info"]?.visible,
        allPanelsReceiptBacked: Object.values(readyEvidence).every((entry) => entry.verifiedBadgeCount > 0),
      },
    };
    writeFileSync(join(outputDir, "workflow-recovery-panels-live-gui-proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    return proof;
  } finally {
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    writeFileSync(join(outputDir, "console-logs.json"), `${JSON.stringify(consoleLogs, null, 2)}\n`);
    writeFileSync(join(outputDir, "page-errors.json"), `${JSON.stringify(pageErrors, null, 2)}\n`);
    if (tracingStarted && context) {
      await context.tracing.stop({ path: join(outputDir, "playwright-trace.zip") }).catch(() => undefined);
    }
    await browser?.close().catch(() => undefined);
    if (app && !app.killed) {
      app.kill("SIGTERM");
      await wait(1200);
      if (app.exitCode === null) app.kill("SIGKILL");
    }
    await closeServer(server);
    await daemon.close().catch(() => undefined);
    if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
  }
}

async function main() {
  const outputDir =
    process.argv[2] ||
    join(repoRoot, evidenceRoot, `${timestamp()}-stage46-recovery-panels-live-gui`);
  ensureDir(outputDir);
  const proof = await run(outputDir);
  console.log(JSON.stringify({ ok: proof.passed, outputDir, proof }, null, 2));
}

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
