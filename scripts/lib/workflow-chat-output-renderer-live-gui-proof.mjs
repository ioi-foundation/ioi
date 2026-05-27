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
import { buildWorkflowChatOutputRendererPanel } from "../../packages/agent-ide/src/runtime/workflow-chat-output-renderer.ts";
import {
  AUTOPILOT_ELECTRON,
  syncWorkbenchExtensionTargets,
} from "./autopilot-electron-app-paths.mjs";
import { applyAutopilotWorkbenchShellPatch } from "./autopilot-workbench-shell-patch.mjs";

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
        // VS Code replaces webview frames during mode changes.
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

function sampleMermaidTurn() {
  const source = [
    "flowchart LR",
    "  Prompt[Prompt] --> Route[Daemon route]",
    "  Route --> Tool[Tool receipt]",
    "  Tool --> Trace[Trace card]",
    "  Trace --> Reply[Visible reply]",
  ].join("\n");
  return {
    id: "stage37-mermaid-turn",
    role: "assistant",
    content: `Execution roadmap:\n\n\`\`\`mermaid\n${source}\n\`\`\``,
    outputRenderers: [
      {
        id: "stage37-mermaid-renderer",
        rendererId: "vscode.chatMermaidDiagram",
        mimeType: "text/vnd.mermaid",
        source,
        receiptRefs: ["receipt_stage37_chat_output_renderer"],
      },
    ],
    receiptRefs: ["receipt_stage37_chat_output_renderer"],
  };
}

async function rendererEvidence(frame) {
  const renderer = frame.locator('[data-testid="studio-chat-mermaid-renderer"]').first();
  return {
    count: await frame.locator('[data-testid="studio-chat-mermaid-renderer"]').count(),
    visible: await renderer.isVisible().catch(() => false),
    rendererId: await renderer.getAttribute("data-renderer-id").catch(() => null),
    mimeType: await renderer.getAttribute("data-mime-type").catch(() => null),
    nodeCount: Number(await renderer.getAttribute("data-node-count").catch(() => 0)),
    edgeCount: Number(await renderer.getAttribute("data-edge-count").catch(() => 0)),
    zoomInVisible: await renderer.locator('[data-testid="studio-chat-renderer-zoom-in"]').isVisible().catch(() => false),
    zoomOutVisible: await renderer.locator('[data-testid="studio-chat-renderer-zoom-out"]').isVisible().catch(() => false),
    fitVisible: await renderer.locator('[data-testid="studio-chat-renderer-fit"]').isVisible().catch(() => false),
    clickableNodeCount: await renderer.locator('[data-testid="studio-mermaid-clickable-node"]').count().catch(() => 0),
    sourceVisible: await renderer.locator('[data-testid="studio-chat-output-renderer-source"]').isVisible().catch(() => false),
    verifiedBadgeCount: await renderer.locator('[data-testid="studio-verified-badge"]').count().catch(() => 0),
    text: await renderer.textContent().catch(() => ""),
  };
}

function rendererReady(evidence) {
  return (
    evidence.visible &&
    evidence.rendererId === "vscode.chatMermaidDiagram" &&
    evidence.mimeType === "text/vnd.mermaid" &&
    evidence.nodeCount >= 4 &&
    evidence.edgeCount >= 4 &&
    evidence.zoomInVisible &&
    evidence.zoomOutVisible &&
    evidence.fitVisible &&
    evidence.clickableNodeCount >= 4 &&
    evidence.sourceVisible &&
    evidence.verifiedBadgeCount > 0
  );
}

async function run(outputDir) {
  ensureDir(outputDir);
  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyAutopilotWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);

  const rendererPanel = buildWorkflowChatOutputRendererPanel({
    messages: [sampleMermaidTurn()],
  });
  if (rendererPanel.status !== "ready" || rendererPanel.rendererCount !== 1) {
    throw new Error(`Renderer panel projection failed: ${JSON.stringify(rendererPanel)}`);
  }

  const daemonStateDir = mkdtempSync(join(tmpdir(), "autopilot-stage37-daemon-"));
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
    server = createBridge({
      daemonEndpoint: daemon.endpoint,
      requests,
      commands,
      deliveredCommands,
    });
    const bridgeAddress = await listen(server);
    const bridgeUrl = `http://127.0.0.1:${bridgeAddress.port}`;
    const cdpPort = await getFreePort();
    userDataDir = mkdtempSync(join(tmpdir(), "autopilot-stage37-user-"));
    const extensionsDir = mkdtempSync(join(tmpdir(), "autopilot-stage37-ext-"));
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

    queueCommand(commands, "ioi.studio.open", { phase: "chat" });
    await requireRequest(requests, (request) => request?.requestType === "studio.open", "studio.open");
    let studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat");
    await screenshot(page, outputDir, "studio-chat-output-renderer-open.png", screenshots);

    queueCommand(commands, "ioi.studio.injectParityPlusEvents", {
      status: "completed",
      turns: [sampleMermaidTurn()],
    });
    const injectionRequest = await requireRequest(
      requests,
      (request) => request?.requestType === "studio.parityPlusEvents.injected",
      "studio.parityPlusEvents.injected",
    );
    const readyEvidence = await waitForPredicate(async () => {
      try {
        studioFrame = await findFrameWithTestId(page, "agent-studio-operational-chat", 1000);
        const evidence = await rendererEvidence(studioFrame);
        return rendererReady(evidence) ? evidence : null;
      } catch {
        return null;
      }
    }, 20_000, 300);
    if (!readyEvidence) {
      const latestEvidence = await rendererEvidence(studioFrame).catch((error) => ({ error: String(error) }));
      throw new Error(`Mermaid renderer did not hydrate in the live GUI: ${JSON.stringify(latestEvidence)}`);
    }

    await screenshot(page, outputDir, "studio-chat-output-renderer-hydrated.png", screenshots);

    const proof = {
      schemaVersion: "ioi.autopilot.stage37.chat-output-renderer-live-gui-proof.v1",
      passed: true,
      daemonEndpoint: daemon.endpoint,
      screenshots,
      rendererPanel,
      injectionRequest,
      rendererEvidence: readyEvidence,
      checks: {
        electronLaunched: Boolean(cdpVersion),
        studioOpened: true,
        injectionBridgeRequestRecorded: Boolean(injectionRequest),
        turnInjected: injectionRequest?.payload?.turnCount === 1 || injectionRequest?.turnCount === 1,
        mermaidRendererVisible: readyEvidence.visible,
        rendererUsesMermaidMime: readyEvidence.mimeType === "text/vnd.mermaid",
        zoomControlsVisible: readyEvidence.zoomInVisible && readyEvidence.zoomOutVisible && readyEvidence.fitVisible,
        clickableNodesVisible: readyEvidence.clickableNodeCount >= 4,
        receiptBackedRenderer: readyEvidence.verifiedBadgeCount > 0,
      },
    };
    writeFileSync(join(outputDir, "workflow-chat-output-renderer-live-gui-proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
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
    if (userDataDir) rmSync(userDataDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 150 });
  }
}

async function main() {
  const outputDir =
    process.argv[2] ||
    join(repoRoot, evidenceRoot, `${timestamp()}-stage37-chat-output-renderer-live-gui`);
  ensureDir(outputDir);
  const proof = await run(outputDir);
  console.log(JSON.stringify({ ok: proof.passed, outputDir, proof }, null, 2));
}

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
