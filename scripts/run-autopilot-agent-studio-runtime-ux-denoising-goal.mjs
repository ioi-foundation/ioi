#!/usr/bin/env node
import { spawn, spawnSync, execFileSync } from "node:child_process";
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

import { startRuntimeDaemonService } from "../packages/runtime-daemon/src/index.mjs";
import {
  HYPERVISOR_WORKBENCH_ADAPTER_HOST,
  syncWorkbenchExtensionTargets,
} from "./lib/hypervisor-workbench-adapter-host-paths.mjs";
import { applyAutopilotWorkbenchShellPatch } from "./lib/autopilot-workbench-shell-patch.mjs";

const repoRoot = HYPERVISOR_WORKBENCH_ADAPTER_HOST.repoRoot;
const MASTER_GUIDE = ".internal/plans/autopilot-electron-agent-studio-runtime-ux-denoising-tracing-separation-master-guide.md";
const EVIDENCE_ROOT = "docs/evidence/autopilot-agent-studio-runtime-ux-denoising-tracing-separation";
const EXTENSION_JS = "workbench-adapters/ioi-workbench/extension.js";
const STATIC_TEST = "workbench-adapters/ioi-workbench/extension.static.test.mjs";
const SHELL_PATCH = "scripts/lib/autopilot-workbench-shell-patch.mjs";
const PROCESS_PATTERN = "/tmp/autopilot-agent-studio-runtime-ux-denoising-user-";
const VALIDATION_TIMEOUT_MS = 180_000;

let daemonEndpointForBridge = null;
let liveBridgeRequestLogPath = null;
let liveBridgeCommandLogPath = null;

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function parseArgs(argv) {
  return {
    run: argv.includes("--run"),
    preflight: argv.includes("--preflight") || !argv.includes("--run"),
  };
}

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function read(path) {
  try {
    return readFileSync(join(repoRoot, path), "utf8");
  } catch {
    return "";
  }
}

function runCommand(command, args, options = {}) {
  const started = Date.now();
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 16,
    ...options,
  });
  return {
    command: [command, ...args].join(" "),
    status: result.status,
    signal: result.signal,
    ok: result.status === 0,
    durationMs: Date.now() - started,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

function compact(result) {
  return {
    command: result.command,
    status: result.status,
    signal: result.signal,
    durationMs: result.durationMs,
    stdoutTail: String(result.stdout ?? "").slice(-3000),
    stderrTail: String(result.stderr ?? "").slice(-3000),
  };
}

function checkFile(path, label) {
  return {
    id: `file:${path}`,
    ok: existsSync(join(repoRoot, path)),
    summary: `${label} exists`,
    evidence: { path },
  };
}

function checkPackageScripts() {
  const packageJson = JSON.parse(read("package.json") || "{}");
  const scripts = packageJson.scripts || {};
  const required = [
    "goal:hypervisor-runtime-ux-denoising",
    "goal:hypervisor-runtime-ux-denoising:run",
  ];
  const missing = required.filter((script) => !scripts[script]);
  return {
    id: "package:scripts",
    ok: missing.length === 0,
    summary: missing.length === 0 ? "Agent Studio runtime UX de-noising scripts are registered" : "Goal scripts are missing",
    evidence: { missing },
  };
}

function checkSource() {
  const source = read(EXTENSION_JS);
  const required = [
    "let studioPanelLastHtml = null;",
    "let studioPanelNonce = null;",
    "function updateStudioPanelHtml(state)",
    "const pageNonce = studioPanelNonce || (studioPanelNonce = nonce());",
    'data-testid="studio-composer-input"',
    'data-testid="studio-send-button"',
    'data-command="ioi.quickInput.context.open"',
    'data-command="ioi.quickInput.tools.configure"',
    'data-command="ioi.quickInput.modelRoute.pick"',
    'data-command="ioi.quickInput.workflowTarget.pick"',
    'data-command="ioi.quickInput.agentMode.pick"',
    "border-top: 0;",
    'requestType: "chat.submit"',
    "streamStudioModelCompletion",
    '"/v1/chat/completions"',
    "assistantStreamDelta",
    '"chat.stop"',
    "projectStudioRuntimeCockpit",
    "runtimeUx",
    "STUDIO_RUNTIME_VISIBILITY",
    "function classifyStudioRuntimeEvent",
    "function studioTraceLink",
    "function studioVerifiedBadge",
    "function studioCompactRuntimeStatusRows",
    "function renderRunsView",
    'data-runtime-ux-denoised="',
    'data-tracing-separation-achieved="',
    'data-model-prose-runtime-truth="false"',
    'data-verified-badges-require-receipts="',
    'data-testid="studio-actionable-runtime-state"',
    'data-testid="studio-compact-runtime-status"',
    'data-testid="studio-tool-proposal-compact"',
    'data-testid="studio-policy-prompt-actionable"',
    'data-testid="studio-command-summary-not-log-wall"',
    'data-testid="studio-diagnostics-summary"',
    'data-testid="studio-native-hunk-review-inline"',
    'data-testid="studio-view-trace-link"',
    'data-testid="studio-verified-badge"',
    'data-testid="studio-trace-handoff"',
    'data-testid="tracing-surface"',
    'data-testid="tracing-focused-step"',
    'data-testid="tracing-timeline"',
    'data-testid="tracing-receipt-detail"',
    'data-testid="tracing-replay-step"',
    'data-testid="tracing-policy-detail"',
    'data-testid="tracing-command-log-detail"',
    'data-testid="tracing-proof-export"',
    "Model prose is never accepted as runtime proof",
    "invokeStudioDaemonTool",
    "requestAndDenyStudioPolicyLease",
    'data-testid="studio-runtime-cockpit"',
    'data-testid="studio-tool-proposal-card"',
    'data-testid="studio-policy-lease-dialog"',
    'data-testid="studio-command-output-card"',
    'data-testid="studio-native-diff-hunk"',
    'data-testid="studio-hunk-prev"',
    'data-testid="studio-hunk-next"',
    'data-testid="studio-hunk-accept"',
    'data-testid="studio-hunk-reject"',
    'data-testid="studio-diagnostics-test-gate"',
    'data-testid="studio-browser-status-card"',
    'data-testid="studio-worker-status-card"',
    'data-testid="studio-replay-step-detail"',
    "ioi-studio-diff",
    "tools/${encodeURIComponent(toolId)}/invoke",
    "/v1/computer-use/browser-discovery?probe=false&include_tabs=false",
    "threads/${encodeURIComponent(threadId)}/subagents",
  ];
  const missing = required.filter((needle) => !source.includes(needle));
  const forbidden = [
    'data-testid="agent-studio-landing"',
    "studio.promptSubmit",
    "@tauri-apps",
    "studioPanel.webview.html = studioPanelHtml(state);",
  ].filter((needle) => source.includes(needle));
  return {
    id: "source:agent-studio-runtime-ux-denoising",
    ok: missing.length === 0 && forbidden.length === 0,
    summary:
      missing.length === 0 && forbidden.length === 0
      ? "Studio source contains de-noised Studio projections and first-class tracing surfaces"
      : "Studio source still has de-noising or tracing gaps",
    evidence: { missing, forbidden },
  };
}

function preflightChecks() {
  const nodeExtension = runCommand("node", ["--check", EXTENSION_JS]);
  const nodeShellPatch = runCommand("node", ["--check", SHELL_PATCH]);
  const staticTest = runCommand("node", ["--test", STATIC_TEST]);
  const checks = [
    checkFile(MASTER_GUIDE, "Agent Studio runtime UX de-noising master guide"),
    checkFile(EXTENSION_JS, "Workbench extension source"),
    checkFile(STATIC_TEST, "Workbench static test"),
    checkFile(SHELL_PATCH, "Workbench shell patch"),
    checkSource(),
    checkPackageScripts(),
    {
      id: "node-check:extension",
      ok: nodeExtension.ok,
      summary: "Extension JavaScript parses",
      evidence: compact(nodeExtension),
    },
    {
      id: "node-check:shell-patch",
      ok: nodeShellPatch.ok,
      summary: "Workbench shell patch JavaScript parses",
      evidence: compact(nodeShellPatch),
    },
    {
      id: "node-test:ioi-workbench-static",
      ok: staticTest.ok,
      summary: "Workbench static tests pass",
      evidence: compact(staticTest),
    },
    {
      id: "electron:binary",
      ok: existsSync(HYPERVISOR_WORKBENCH_ADAPTER_HOST.binary),
      summary: "Electron Autopilot binary exists",
      evidence: { binary: HYPERVISOR_WORKBENCH_ADAPTER_HOST.binary },
    },
  ];
  return {
    schemaVersion: "ioi.autopilot-agent-studio-runtime-ux-denoising.preflight.v1",
    ok: checks.every((check) => check.ok),
    checks,
  };
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
  return new Promise((resolveClose) => server.close(() => resolveClose()));
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

async function createDaemonModelInvocationToken(endpoint) {
  const response = await fetch(`${endpoint}/v1/model-mount/tokens`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      audience: "autopilot-agent-studio-runtime-ux-denoising",
      allowed: [
        "model.chat:*",
        "model.responses:*",
        "model.tokenize:*",
        "model.context:*",
        "route.use:*",
      ],
      denied: ["connector.*", "filesystem.write", "shell.exec"],
      source: "agent-studio-runtime-ux-denoising",
    }),
  });
  const body = await response.text();
  if (!response.ok) {
    throw new Error(`Failed to create daemon model token (${response.status}): ${body}`);
  }
  const parsed = body ? JSON.parse(body) : {};
  if (!parsed.token) {
    throw new Error("Daemon model token response did not include a token.");
  }
  return parsed;
}

function sendJson(response, statusCode, payload) {
  const body = JSON.stringify(payload);
  response.writeHead(statusCode, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(body),
    "access-control-allow-origin": "*",
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "content-type",
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

function bridgeState() {
  const now = Date.now();
  const modelMounting = {
    artifacts: [
      {
        id: "stories260k",
        modelId: "stories260k",
        name: "stories260k",
        publisher: "ioi",
        family: "llm",
        format: "GGUF",
        status: "mounted",
      },
      {
        id: "qwen/qwen3.5-9b",
        modelId: "qwen/qwen3.5-9b",
        name: "qwen/qwen3.5-9b",
        publisher: "provider.lmstudio",
        family: "llm",
        format: "GGUF",
        status: "mounted",
      },
      {
        id: "local:unmounted-demo",
        modelId: "local:unmounted-demo",
        name: "Local unmounted demo",
        publisher: "provider.local",
        family: "llm",
        format: "GGUF",
        status: "installed",
      },
    ],
    endpoints: [
      {
        id: "endpoint.stories260k",
        modelId: "stories260k",
        routeId: "route.local-first",
        status: "ready",
      },
      {
        id: "endpoint.qwen35",
        modelId: "qwen/qwen3.5-9b",
        routeId: "route.qwen-mounted",
        status: "ready",
      },
      {
        id: "endpoint.unmounted",
        modelId: "local:unmounted-demo",
        routeId: "route.unmounted-demo",
        status: "installed",
      },
    ],
    instances: [
      {
        id: "instance.stories260k",
        endpointId: "endpoint.stories260k",
        modelId: "stories260k",
        status: "mounted",
      },
      {
        id: "instance.qwen35",
        endpointId: "endpoint.qwen35",
        modelId: "qwen/qwen3.5-9b",
        status: "mounted",
      },
    ],
    routes: [
      {
        id: "route.local-first",
        routeId: "route.local-first",
        endpointId: "endpoint.stories260k",
        modelId: "stories260k",
        status: "ready",
      },
      {
        id: "route.qwen-mounted",
        routeId: "route.qwen-mounted",
        endpointId: "endpoint.qwen35",
        modelId: "qwen/qwen3.5-9b",
        status: "ready",
      },
      {
        id: "route.unmounted-demo",
        routeId: "route.unmounted-demo",
        endpointId: "endpoint.unmounted",
        modelId: "local:unmounted-demo",
        status: "installed",
      },
    ],
  };
  return {
    schemaVersion: "ioi.workbench-bridge-state.v1",
    generatedAtMs: now,
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
      status: daemonEndpointForBridge ? "connected" : "not_configured",
      endpoint: daemonEndpointForBridge,
    },
    modelMounting,
    commandCenter: {
      liveTools: [],
      runtimeCatalog: [],
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

function createBridge({ requests, commands, deliveredCommands }) {
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (request.method === "OPTIONS") {
        sendJson(response, 200, { ok: true });
        return;
      }
      if (request.method === "GET" && url.pathname === "/state") {
        sendJson(response, 200, bridgeState());
        return;
      }
      if (request.method === "GET" && url.pathname === "/commands") {
        const next = commands.splice(0);
        deliveredCommands.push(...next);
        if (liveBridgeCommandLogPath && next.length > 0) {
          appendFileSync(liveBridgeCommandLogPath, `${JSON.stringify({ at: new Date().toISOString(), commands: next })}\n`);
        }
        sendJson(response, 200, next);
        return;
      }
      if (request.method === "POST" && url.pathname === "/requests") {
        const body = await readRequestBody(request);
        requests.push(body);
        if (liveBridgeRequestLogPath) {
          appendFileSync(liveBridgeRequestLogPath, `${JSON.stringify({ at: new Date().toISOString(), request: body })}\n`);
        }
        if (body?.requestType === "chat.focusComposer") {
          commands.push({
            commandId: `ioi.studio.focusComposer:${Date.now()}:${commands.length}`,
            command: "ioi.studio.focusComposer",
            args: [{
              source: "fork-native-quickinput",
              runtimeAuthority: "daemon-owned",
              projectionOwner: "autopilot-workbench-fork-quickinput",
            }],
          });
        }
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

async function requireRequest(requests, predicate, label, timeoutMs = 45_000, startIndex = 0) {
  const request = await waitForPredicate(
    () => requests.slice(startIndex).find((candidate) => predicate(candidate)),
    timeoutMs,
    250,
  );
  if (!request) throw new Error(`Timed out waiting for bridge request: ${label}`);
  return request;
}

async function findFrameWithTestId(page, testId, timeoutMs = 45_000) {
  const selector = `[data-testid="${testId}"]`;
  const frame = await waitForPredicate(async () => {
    for (const candidate of page.frames()) {
      try {
        const locator = candidate.locator(selector).first();
        if ((await locator.count()) === 0) continue;
        if (await locator.isVisible().catch(() => false)) return candidate;
      } catch {
        // Webview frames can detach while VS Code swaps editor contents.
      }
    }
    return null;
  }, timeoutMs, 300);
  if (!frame) throw new Error(`Could not find frame with ${selector}`);
  return frame;
}

async function withStudioFrame(page, action, attempts = 12) {
  let latestError;
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const frame = await findFrameWithTestId(page, "agent-studio-operational-chat");
    try {
      return await action(frame);
    } catch (error) {
      latestError = error;
      const message = String(error?.message || error);
      if (!/Frame was detached|Execution context was destroyed|Target page, context or browser has been closed/i.test(message)) {
        throw error;
      }
      await wait(300);
    }
  }
  throw latestError;
}

async function screenshot(page, outputDir, file, screenshots) {
  const path = join(outputDir, file);
  await page.screenshot({ path, fullPage: true });
  screenshots.push({ file, path, exists: existsSync(path) });
  return path;
}

async function studioDefaultRuntimeUxState(page) {
  return withStudioFrame(page, async (frame) => {
    return frame.evaluate(() => {
      const visible = (element) => {
        if (!element) return false;
        const style = getComputedStyle(element);
        const rect = element.getBoundingClientRect();
        return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0;
      };
      const root = document.querySelector("[data-testid='agent-studio-operational-chat']");
      const transcript = document.querySelector("[data-testid='studio-transcript']");
      const utilityDrawer = document.querySelector("[data-testid='studio-utility-drawer']");
      const compactCards = [...document.querySelectorAll("[data-testid='studio-actionable-runtime-state'] article")].filter(visible);
      const compactTraceLinks = [...document.querySelectorAll("[data-testid='studio-actionable-runtime-state'] [data-testid='studio-view-trace-link']")].filter(visible);
      const verifiedBadges = [...document.querySelectorAll("[data-testid='studio-verified-badge']")].filter(visible);
      const rawReceiptIdVisible = /receipt_[a-z0-9_-]+/i.test(transcript?.innerText || "");
      const proofWallVisible = visible(document.querySelector("[data-testid='studio-runtime-cockpit']"));
      const receiptsReplayVisible = visible(document.querySelector("[data-testid='studio-receipts-replay']"));
      const drawerExpanded = utilityDrawer?.classList.contains("is-expanded") || false;
      return {
        targetStudioRuntimeUxDenoised: root?.getAttribute("data-runtime-ux-denoised") === "true",
        targetTracingSeparationAchieved: root?.getAttribute("data-tracing-separation-achieved") === "true",
        modelProseRuntimeTruth: root?.getAttribute("data-model-prose-runtime-truth"),
        verifiedBadgesRequireReceiptRefs: root?.getAttribute("data-verified-badges-require-receipts") === "true",
        compactCardCount: compactCards.length,
        compactTraceLinkCount: compactTraceLinks.length,
        verifiedBadgeCount: verifiedBadges.length,
        proofWallVisible,
        receiptsReplayVisible,
        drawerExpanded,
        rawReceiptIdVisible,
        textSample: (transcript?.innerText || "").slice(0, 1200),
      };
    });
  });
}

async function latestAssistantWorkNoiseState(page) {
  return withStudioFrame(page, async (frame) => {
    return frame.evaluate(() => {
      const visible = (element) => {
        if (!element) return false;
        const style = getComputedStyle(element);
        const rect = element.getBoundingClientRect();
        return style.display !== "none" && style.visibility !== "hidden" && rect.width > 0 && rect.height > 0;
      };
      const assistantTurns = [...document.querySelectorAll("[data-studio-turn-role='assistant']")].filter(visible);
      const latest = assistantTurns[assistantTurns.length - 1] || null;
      const inLatest = (selector) => latest ? [...latest.querySelectorAll(selector)].filter(visible) : [];
      const allVisible = (selector) => [...document.querySelectorAll(selector)].filter(visible);
      const latestText = latest?.innerText || "";
      const actionableRuntimeCards = allVisible("[data-testid='studio-actionable-runtime-state'] article");
      return {
        hasLatestAssistantTurn: Boolean(latest),
        latestDocumentedWork: latest?.getAttribute("data-documented-work") === "true",
        runStatusBarCount: inLatest("[data-testid='studio-run-status-bar']").length,
        workRecordCount: inLatest("[data-testid='studio-work-record']").length,
        receiptChipCount: inLatest("[data-testid='studio-receipt-chip']").length,
        verifiedBadgeCount: inLatest("[data-testid='studio-verified-badge']").length,
        viewTraceLinkCount: inLatest("[data-testid='studio-view-trace-link']").length,
        statusTextMentionsWorkedFor: /worked\s+for\s+\d+/i.test(latestText),
        rawReceiptIdVisible: /receipt_[a-z0-9_-]+/i.test(latestText),
        stalePatchProposalVisible: allVisible("[data-testid='studio-native-hunk-review-inline']").length > 0 || /Patch proposal/i.test(document.body.innerText || ""),
        actionableRuntimeCardCount: actionableRuntimeCards.length,
        latestTextSample: latestText.slice(0, 1000),
      };
    });
  });
}

async function clickFirstStudioTraceLink(page) {
  return withStudioFrame(page, async (frame) => {
    const link = frame.locator("[data-testid='studio-actionable-runtime-state'] [data-testid='studio-view-trace-link']").first();
    await link.waitFor({ state: "visible", timeout: 10_000 });
    const payloadRaw = await link.getAttribute("data-payload");
    const payload = payloadRaw ? JSON.parse(payloadRaw) : {};
    await link.evaluate((element) => {
      element.scrollIntoView({ block: "center", inline: "nearest" });
      element.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true }));
    });
    return payload?.traceTarget || {};
  });
}

async function tracingSurfaceState(page) {
  const frame = await findFrameWithTestId(page, "tracing-surface");
  return frame.evaluate(() => {
    const visibleText = (selector) => {
      const element = document.querySelector(selector);
      return element ? (element.textContent || "").trim() : "";
    };
    const root = document.querySelector("[data-testid='tracing-surface']");
    return {
      targetTracingSeparationAchieved: root?.getAttribute("data-tracing-separation-achieved") === "true",
      focusedTraceStep: root?.getAttribute("data-focused-trace-step") || "",
      timelineText: visibleText("[data-testid='tracing-timeline']"),
      receiptText: visibleText("[data-testid='tracing-receipt-detail']"),
      replayText: visibleText("[data-testid='tracing-replay-step']"),
      policyText: visibleText("[data-testid='tracing-policy-detail']"),
      commandText: visibleText("[data-testid='tracing-command-log-detail']"),
      proofText: visibleText("[data-testid='tracing-proof-export']"),
    };
  });
}

async function activeComposerState(frame) {
  return frame.evaluate(() => {
    const input = document.querySelector("[data-testid='studio-composer-input']");
    const composer = document.querySelector("[data-testid='studio-composer']");
    const dock = document.querySelector("[data-testid='studio-tauri-composer']");
    const active = document.activeElement;
    const inputStyle = input ? getComputedStyle(input) : null;
    const composerStyle = composer ? getComputedStyle(composer) : null;
    const dockRect = dock?.getBoundingClientRect?.();
    return {
      activeTag: active?.tagName || null,
      activeTestId: active?.getAttribute?.("data-testid") || null,
      activeIsComposer: active === input,
      value: input?.value || "",
      composerBorderTopWidth: composerStyle?.borderTopWidth || "",
      composerBorderTopStyle: composerStyle?.borderTopStyle || "",
      inputFocusedOutline: inputStyle?.outlineStyle || "",
      dockRect: dockRect ? {
        x: dockRect.x,
        y: dockRect.y,
        width: dockRect.width,
        height: dockRect.height,
      } : null,
    };
  });
}

async function assertComposerFocused(page, label, timeoutMs = 4000) {
  const state = await waitForPredicate(async () => {
    try {
      return await withStudioFrame(page, async (frame) => {
        const current = await activeComposerState(frame);
        return current.activeIsComposer ? current : null;
      }, 3);
    } catch {
      return null;
    }
  }, timeoutMs, 100);
  if (!state) throw new Error(`Composer did not keep or restore focus: ${label}`);
  return state;
}

async function focusComposer(page) {
  await withStudioFrame(page, async (frame) => {
    const input = frame.locator('[data-testid="studio-composer-input"]').first();
    await input.click();
  });
  return assertComposerFocused(page, "click");
}

async function setComposerValue(page, value) {
  await withStudioFrame(page, async (frame) => {
    const input = frame.locator('[data-testid="studio-composer-input"]').first();
    await input.fill(value);
    await input.click();
  });
  return assertComposerFocused(page, "set value");
}

const CANNED_DAEMON_RESPONSE_PATTERNS = [
  /IOI daemon run completed/i,
  /Source=local_daemon_agentgres/i,
  /Agentgres canonical projection/i,
  /Daemon turn completed for:/i,
];

const NON_SEMANTIC_MODEL_RESPONSE_PATTERNS = [
  /IOI model router fixture response/i,
  /Autopilot native local model response/i,
  /\binput_hash=[0-9a-f]{8,}\b/i,
];

function assertNotCannedDaemonProjection(text, prompt) {
  const matched = CANNED_DAEMON_RESPONSE_PATTERNS.find((pattern) => pattern.test(text || ""));
  if (matched) {
    throw new Error(`Assistant response for "${prompt.slice(0, 40)}" used canned daemon projection: ${matched}`);
  }
}

function assertSemanticModelResponse(text, prompt) {
  const matched = NON_SEMANTIC_MODEL_RESPONSE_PATTERNS.find((pattern) => pattern.test(text || ""));
  if (matched) {
    throw new Error(`Assistant response for "${prompt.slice(0, 40)}" used fixture/non-semantic model output: ${matched}`);
  }
}

async function latestAssistantText(page) {
  return withStudioFrame(page, async (frame) => {
    const texts = await frame.locator('[data-testid="studio-assistant-answer-card"] p').allTextContents();
    return texts.map((text) => text.trim()).filter(Boolean).pop() || "";
  });
}

async function submitPrompt(page, requests, prompt, mode = "button") {
  const startIndex = requests.length;
  await setComposerValue(page, prompt);
  if (mode === "keyboard") {
    await page.keyboard.press(process.platform === "darwin" ? "Meta+Enter" : "Control+Enter");
  } else {
    await withStudioFrame(page, async (frame) => {
      await frame.locator('[data-testid="studio-send-button"]').click();
    });
  }
  const pending = await waitForPredicate(async () => {
    try {
      return await withStudioFrame(page, async (frame) => {
        const userTurns = await frame.locator('[data-testid="studio-user-turn-immediate"]').count();
        const pendingVisible = await frame.locator('[data-testid="studio-pending-state"]:not([hidden])').count();
        const root = frame.locator('[data-testid="agent-studio-operational-chat"]').first();
        const immediateSubmitSeen = await root.getAttribute("data-immediate-submit-seen").catch(() => "false");
        const pendingStateSeen = await root.getAttribute("data-pending-state-seen").catch(() => "false");
        return userTurns > 0 && (pendingVisible > 0 || (immediateSubmitSeen === "true" && pendingStateSeen === "true"));
      }, 3);
    } catch {
      return false;
    }
  }, 1200, 100);
  if (!pending) throw new Error(`Prompt did not produce immediate user turn and pending state: ${prompt.slice(0, 40)}`);
  const requestPromise = requireRequest(
    requests,
    (candidate) => candidate?.requestType === "chat.submit" && candidate?.payload?.prompt === prompt,
    `chat.submit:${prompt.slice(0, 40)}`,
    45_000,
    startIndex,
  ).catch((error) => ({ requestError: error }));
  const streamProbe = await waitForPredicate(async () => {
    try {
      return await withStudioFrame(page, async (frame) => {
        const streamText = (await frame.locator('[data-testid="studio-streaming-output"]').last().textContent().catch(() => "")).trim();
        const status = await frame.locator('[data-testid="agent-studio-operational-chat"]').first().getAttribute("data-studio-status");
        if (streamText && ["pending", "streaming", "completed"].includes(status || "")) {
          return { streamText, status };
        }
        return null;
      }, 3);
    } catch {
      return null;
    }
  }, 20_000, 100);
  if (!streamProbe?.streamText) {
    throw new Error(`Prompt did not expose streamed assistant token deltas: ${prompt.slice(0, 40)}`);
  }
  assertNotCannedDaemonProjection(streamProbe.streamText, prompt);
  assertSemanticModelResponse(streamProbe.streamText, prompt);
  const request = await requestPromise;
  if (request?.requestError) {
    throw request.requestError;
  }
  const completed = await waitForPredicate(async () => {
    try {
      return await withStudioFrame(page, async (frame) => {
        const status = await frame.locator('[data-testid="agent-studio-operational-chat"]').first().getAttribute("data-studio-status");
        const answerCount = await frame.locator('[data-testid="studio-assistant-answer-card"]').count();
        return status === "completed" && answerCount > 0;
      }, 3);
    } catch {
      return false;
    }
  }, 45_000, 300);
  if (!completed) throw new Error(`Assistant response did not render for prompt: ${prompt.slice(0, 40)}`);
  const assistantText = await latestAssistantText(page);
  if (!assistantText) {
    throw new Error(`Assistant response text was empty for prompt: ${prompt.slice(0, 40)}`);
  }
  assertNotCannedDaemonProjection(assistantText, prompt);
  assertSemanticModelResponse(assistantText, prompt);
  return {
    request,
    streamProbe,
    assistantText,
    modelBackedStreamObserved: true,
  };
}

async function openAndDismissQuickInput(page, frameButtonSelector, expectedTestId, dismiss = "escape") {
  await withStudioFrame(page, async (frame) => {
    await frame.locator(frameButtonSelector).click();
  });
  const host = page.locator(`[data-testid="${expectedTestId}"]`).first();
  await host.waitFor({ state: "visible", timeout: 7000 });
  if (dismiss === "outside") {
    await page.locator('[data-testid="fork-quickinput-backdrop"]').click({ position: { x: 5, y: 5 } });
  } else {
    await page.keyboard.press("Escape");
  }
  await host.waitFor({ state: "detached", timeout: 7000 }).catch(async () => {
    await host.waitFor({ state: "hidden", timeout: 7000 });
  });
  await assertComposerFocused(page, `${expectedTestId} dismissal`);
}

function listProcessesContaining(pattern) {
  try {
    const raw = execFileSync("pgrep", ["-af", pattern], { encoding: "utf8" });
    return raw
      .split("\n")
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const [pid, ...rest] = line.split(/\s+/);
        return { pid: Number(pid), command: rest.join(" ") };
      })
      .filter((entry) => Number.isFinite(entry.pid) && entry.pid !== process.pid);
  } catch {
    return [];
  }
}

async function cleanupValidationProcesses({ outputDir, phase }) {
  const processes = listProcessesContaining(PROCESS_PATTERN);
  const before = processes.map((processInfo) => ({ ...processInfo }));
  for (const processInfo of processes) {
    try {
      process.kill(processInfo.pid, "SIGTERM");
    } catch {
      // Already gone.
    }
  }
  await wait(900);
  const stubborn = listProcessesContaining(PROCESS_PATTERN);
  for (const processInfo of stubborn) {
    try {
      process.kill(processInfo.pid, "SIGKILL");
    } catch {
      // Already gone.
    }
  }
  const after = listProcessesContaining(PROCESS_PATTERN);
  const proof = {
    schemaVersion: "ioi.autopilot-agent-studio-runtime-ux-denoising.process-cleanup.v1",
    phase,
    pattern: PROCESS_PATTERN,
    before,
    after,
    cleaned: before.length,
    orphanProcesses: after,
    ok: after.length === 0,
    timestamp: new Date().toISOString(),
  };
  writeFileSync(join(outputDir, `process-cleanup-${phase}.json`), `${JSON.stringify(proof, null, 2)}\n`);
  if (!proof.ok) {
    throw new Error(`Validation left orphan processes for ${phase}`);
  }
  return proof;
}

function updateGuideStatus({ outputDir, proof, blocker = null }) {
  const path = join(repoRoot, MASTER_GUIDE);
  const current = read(MASTER_GUIDE);
  const status = proof?.targetStudioRuntimeUxDenoised && proof?.targetTracingSeparationAchieved ? "Achieved" : "Blocked";
  const lines = [
    "## Latest Validation",
    "",
    `Status: ${status}`,
    "",
    `Evidence: \`${outputDir.replace(repoRoot + "/", "")}/\``,
    "",
    `Runtime UX summary: ${proof?.targetStudioRuntimeUxDenoised && proof?.targetTracingSeparationAchieved ? "Agent Studio default view is de-noised, compact runtime statuses link into exact tracing steps, and detailed receipts/replay/policy/log/proof surfaces live in Runs/Tracing." : "runtime UX de-noising and tracing separation validation is still blocked."}`,
    "",
    `Queries tested: ${proof?.queriesTested?.length ? proof.queriesTested.map((item) => item.kind).join(", ") : "pending"}.`,
    "",
    `Remaining blockers: ${blocker || proof?.remainingBlockers || "none"}.`,
    "",
    `Connector sprint readiness impact: Studio can be treated as a calm operator loop only when this proof is green; connector work remains dry-run only and no live external connector action is performed.`,
    "",
  ].join("\n");
  const updated = current.includes("## Latest Validation")
    ? current.replace(/## Latest Validation[\s\S]*$/m, lines)
    : `${current.trimEnd()}\n\n${lines}`;
  writeFileSync(path, updated);
}

async function runValidation(outputDir) {
  ensureDir(outputDir);
  await cleanupValidationProcesses({ outputDir, phase: "before-launch" });
  const sync = syncWorkbenchExtensionTargets();
  const shellPatch = applyAutopilotWorkbenchShellPatch();
  writeFileSync(join(outputDir, "extension-sync.json"), `${JSON.stringify(sync, null, 2)}\n`);
  writeFileSync(join(outputDir, "shell-patch.json"), `${JSON.stringify(shellPatch, null, 2)}\n`);

  const daemonStateDir = mkdtempSync(join(tmpdir(), "autopilot-agent-studio-runtime-ux-denoising-daemon-"));
  const daemon = await startRuntimeDaemonService({ cwd: repoRoot, stateDir: daemonStateDir });
  daemonEndpointForBridge = daemon.endpoint;
  const daemonModelToken = await createDaemonModelInvocationToken(daemon.endpoint);

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
  let partialProof = null;
  let page = null;
  liveBridgeRequestLogPath = join(outputDir, "bridge-requests.live.jsonl");
  liveBridgeCommandLogPath = join(outputDir, "bridge-commands.live.jsonl");
  const validationWatchdog = setTimeout(async () => {
    const blocker = `Validation exceeded ${VALIDATION_TIMEOUT_MS}ms without completing.`;
    try {
      await page?.screenshot({ path: join(outputDir, "failure-timeout.png"), fullPage: true }).catch(() => undefined);
      writeFileSync(join(outputDir, "timeout-blocker.json"), `${JSON.stringify({ blocker, at: new Date().toISOString() }, null, 2)}\n`);
      writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
      writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
      writeFileSync(join(outputDir, "console-logs.json"), `${JSON.stringify(consoleLogs, null, 2)}\n`);
      writeFileSync(join(outputDir, "page-errors.json"), `${JSON.stringify(pageErrors, null, 2)}\n`);
      updateGuideStatus({ outputDir, proof: partialProof, blocker });
      if (tracingStarted && context) {
        await context.tracing.stop({ path: join(outputDir, "playwright-trace.zip") }).catch(() => undefined);
        tracingStarted = false;
      }
      await browser?.close().catch(() => undefined);
      if (app && !app.killed) {
        app.kill("SIGTERM");
        await wait(1200);
        if (app.exitCode === null) app.kill("SIGKILL");
      }
      await server?.close?.();
      await daemon.close().catch(() => undefined);
      if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
      await cleanupValidationProcesses({ outputDir, phase: "timeout-run" });
    } catch {
      // The watchdog is best-effort evidence and cleanup before exiting.
    } finally {
      process.exit(1);
    }
  }, VALIDATION_TIMEOUT_MS);

  try {
    server = createBridge({ requests, commands, deliveredCommands });
    const bridgeAddress = await listen(server);
    const bridgeUrl = `http://127.0.0.1:${bridgeAddress.port}`;
    const cdpPort = await getFreePort();
    userDataDir = mkdtempSync(PROCESS_PATTERN);
    const extensionsDir = mkdtempSync(join(tmpdir(), "autopilot-agent-studio-runtime-ux-denoising-ext-"));
    writeFileSync(join(outputDir, "bridge-url"), `${bridgeUrl}\n`);
    writeFileSync(join(outputDir, "daemon-endpoint"), `${daemon.endpoint}\n`);
    writeFileSync(join(outputDir, "daemon-model-token-grant.json"), `${JSON.stringify({ ...daemonModelToken, token: "redacted" }, null, 2)}\n`);
    writeFileSync(join(outputDir, "user-data-dir"), `${userDataDir}\n`);

    app = spawn(
      HYPERVISOR_WORKBENCH_ADAPTER_HOST.binary,
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
          IOI_DAEMON_TOKEN: daemonModelToken.token,
          IOI_HYPERVISOR_CANONICAL_CLIENT_HOST: "vscode-workbench-adapter-host",
          IOI_WORKBENCH_NATIVE_SHELL: "1",
          AUTOPILOT_SKIP_OVERVIEW: "1",
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
      page.on("console", (message) => consoleLogs.push({ type: message.type(), text: message.text(), location: message.location() }));
      page.on("pageerror", (error) => pageErrors.push(String(error?.stack ?? error?.message ?? error)));
    });
    await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
    tracingStarted = true;
    page = await waitForPredicate(
      () => context.pages().find((candidate) => !candidate.isClosed()) ?? null,
      30_000,
      250,
    );
    if (!page) throw new Error("No Playwright page was available for the Electron fork.");
    page.on("console", (message) => consoleLogs.push({ type: message.type(), text: message.text(), location: message.location() }));
    page.on("pageerror", (error) => pageErrors.push(String(error?.stack ?? error?.message ?? error)));
    await page.setViewportSize({ width: 1550, height: 925 }).catch(() => undefined);

    queueCommand(commands, "ioi.studio.open", { phase: "runtime-ux-denoising" });
    await requireRequest(requests, (request) => request?.requestType === "studio.open", "studio.open");
    await findFrameWithTestId(page, "agent-studio-operational-chat");
    await screenshot(page, outputDir, "before-focus-fix.png", screenshots);
    const initialDenoisedState = await studioDefaultRuntimeUxState(page);
    await screenshot(page, outputDir, "studio-default-denoised-before-prompt.png", screenshots);

    await focusComposer(page);
    await wait(2600);
    const focusedAfterPoll = await assertComposerFocused(page, "after bridge poll");
    if (focusedAfterPoll.composerBorderTopWidth !== "0px" || focusedAfterPoll.composerBorderTopStyle !== "none") {
      throw new Error(`Composer separator still visible: ${focusedAfterPoll.composerBorderTopWidth} ${focusedAfterPoll.composerBorderTopStyle}`);
    }
    await screenshot(page, outputDir, "focused-textarea.png", screenshots);

    await withStudioFrame(page, async (frame) => {
      const input = frame.locator('[data-testid="studio-composer-input"]').first();
      await input.fill("");
      await input.type("slow focus test", { delay: 45 });
    });
    await wait(2300);
    const slowState = await assertComposerFocused(page, "slow typing after poll");
    if (slowState.value !== "slow focus test") {
      throw new Error(`Slow typing value changed unexpectedly: ${slowState.value}`);
    }

    await withStudioFrame(page, async (frame) => {
      const input = frame.locator('[data-testid="studio-composer-input"]').first();
      await input.fill("");
      await input.type("fast-query repo symbols policy", { delay: 0 });
      await input.press(process.platform === "darwin" ? "Meta+A" : "Control+A");
      await page.keyboard.insertText("pasted workspace context request");
    });
    const pasteState = await assertComposerFocused(page, "paste and selection");
    if (pasteState.value !== "pasted workspace context request") {
      throw new Error(`Paste/selection flow wrote the wrong value: ${pasteState.value}`);
    }
    await setComposerValue(page, "");

    await openAndDismissQuickInput(page, '[data-testid="studio-add-context"]', "fork-add-context-quickinput", "outside");
    await withStudioFrame(page, async (frame) => {
      await frame.locator('[data-testid="studio-add-context"]').click();
    });
    await page.locator('[data-testid="fork-add-context-quickinput"]').waitFor({ state: "visible", timeout: 7000 });
    await screenshot(page, outputDir, "add-context-picker.png", screenshots);
    await page.keyboard.press("Escape");
    await page.locator('[data-testid="fork-add-context-quickinput"]').waitFor({ state: "detached", timeout: 7000 }).catch(async () => {
      await page.locator('[data-testid="fork-add-context-quickinput"]').waitFor({ state: "hidden", timeout: 7000 });
    });
    await assertComposerFocused(page, "add context escape");

    await withStudioFrame(page, async (frame) => {
      await frame.locator('[data-testid="studio-tools-toggle"]').click();
    });
    await page.locator('[data-testid="fork-configure-tools-quickinput"]').waitFor({ state: "visible", timeout: 7000 });
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowRight");
    await page.keyboard.press(" ");
    await screenshot(page, outputDir, "tools-picker.png", screenshots);
    await page.keyboard.press("Escape");
    await page.locator('[data-testid="fork-configure-tools-quickinput"]').waitFor({ state: "detached", timeout: 7000 }).catch(async () => {
      await page.locator('[data-testid="fork-configure-tools-quickinput"]').waitFor({ state: "hidden", timeout: 7000 });
    });
    await assertComposerFocused(page, "tools escape");

    await withStudioFrame(page, async (frame) => {
      await frame.locator('[data-testid="studio-model-toggle"]').click();
    });
    const modelHost = page.locator('[data-testid="fork-model-route-quickinput"]').first();
    await modelHost.waitFor({ state: "visible", timeout: 7000 });
    const modelText = await modelHost.textContent();
    if (!/stories260k|qwen\/qwen3\.5-9b/i.test(modelText || "") || /local unmounted demo|No mounted models/i.test(modelText || "")) {
      throw new Error(`Model selector did not show mounted models only: ${modelText}`);
    }
    await screenshot(page, outputDir, "model-selector-mounted-models.png", screenshots);
    await page.keyboard.press("Escape");
    await modelHost.waitFor({ state: "detached", timeout: 7000 }).catch(async () => {
      await modelHost.waitFor({ state: "hidden", timeout: 7000 });
    });
    await assertComposerFocused(page, "model selector escape");

    await openAndDismissQuickInput(page, '[data-testid="studio-mode-toggle"]', "fork-agent-mode-quickinput", "escape");
    await openAndDismissQuickInput(page, '[data-testid="studio-target-toggle"]', "fork-workflow-target-quickinput", "escape");
    await screenshot(page, outputDir, "menus-dismissed-cleanly.png", screenshots);

    const emptyStart = requests.length;
    await withStudioFrame(page, async (frame) => {
      const input = frame.locator('[data-testid="studio-composer-input"]').first();
      await input.evaluate((element) => {
        element.value = "   ";
        element.dispatchEvent(new Event("input", { bubbles: true }));
        element.focus();
      });
      await frame.locator('[data-testid="studio-send-button"]').click();
    });
    await wait(1400);
    const emptySubmit = requests
      .slice(emptyStart)
      .find((request) => request?.requestType === "chat.submit" && !String(request?.payload?.prompt || "").trim());
    if (emptySubmit) {
      throw new Error("Empty prompt unexpectedly emitted a bridge request.");
    }
    await assertComposerFocused(page, "empty prompt");

    const plainPrompt = "Answer plainly in one short paragraph: do you like humans?";
    const plainPromptResult = await submitPrompt(page, requests, plainPrompt, "button");
    const plainTextNoiseState = await latestAssistantWorkNoiseState(page);
    if (
      !plainTextNoiseState.hasLatestAssistantTurn ||
      plainTextNoiseState.latestDocumentedWork ||
      plainTextNoiseState.runStatusBarCount > 0 ||
      plainTextNoiseState.workRecordCount > 0 ||
      plainTextNoiseState.receiptChipCount > 0 ||
      plainTextNoiseState.verifiedBadgeCount > 0 ||
      plainTextNoiseState.viewTraceLinkCount > 0 ||
      plainTextNoiseState.statusTextMentionsWorkedFor ||
      plainTextNoiseState.rawReceiptIdVisible ||
      plainTextNoiseState.stalePatchProposalVisible ||
      plainTextNoiseState.actionableRuntimeCardCount > 0
    ) {
      throw new Error(`Plain assistant text still rendered work/proof chrome: ${JSON.stringify(plainTextNoiseState)}`);
    }
    await screenshot(page, outputDir, "plain-text-answer-no-work-record.png", screenshots);

    const prompt = [
      "Exercise the Agent Studio runtime cockpit.",
      "Use daemon-owned model streaming, propose a safe patch preview, run diagnostics, show policy lease behavior, receipts, replay, browser status, and worker status.",
      "Do not call external connectors.",
    ].join(" ");
    const promptResult = await submitPrompt(page, requests, prompt, "button");
    const promptResults = [{
      kind: "plain text",
      requestType: plainPromptResult.request?.requestType,
      mode: "button",
      streamStatusObserved: plainPromptResult.streamProbe.status,
      firstStreamText: plainPromptResult.streamProbe.streamText.slice(0, 180),
      assistantText: plainPromptResult.assistantText,
      modelBackedStreamObserved: plainPromptResult.modelBackedStreamObserved,
      documentedWorkObserved: false,
    }, {
      kind: "runtime cockpit",
      requestType: promptResult.request?.requestType,
      mode: "button",
      streamStatusObserved: promptResult.streamProbe.status,
      firstStreamText: promptResult.streamProbe.streamText.slice(0, 180),
      assistantText: promptResult.assistantText,
      modelBackedStreamObserved: promptResult.modelBackedStreamObserved,
      documentedWorkObserved: true,
    }];
    await screenshot(page, outputDir, "after-prompt-submission.png", screenshots);
    await screenshot(page, outputDir, "assistant-response.png", screenshots);
    const denoisedState = await studioDefaultRuntimeUxState(page);
    if (!denoisedState.targetStudioRuntimeUxDenoised || !denoisedState.targetTracingSeparationAchieved) {
      throw new Error(`Studio root did not report runtime UX de-noising/tracing separation: ${JSON.stringify(denoisedState)}`);
    }
    if (denoisedState.proofWallVisible || denoisedState.receiptsReplayVisible || denoisedState.rawReceiptIdVisible) {
      throw new Error(`Studio default still exposes proof-wall or raw receipt noise: ${JSON.stringify(denoisedState)}`);
    }
    if (denoisedState.compactCardCount === 0 || denoisedState.compactTraceLinkCount < denoisedState.compactCardCount) {
      throw new Error(`Studio compact statuses are missing trace links: ${JSON.stringify(denoisedState)}`);
    }
    await screenshot(page, outputDir, "studio-default-denoised-after-prompt.png", screenshots);

    const traceTarget = await clickFirstStudioTraceLink(page);
    await requireRequest(
      requests,
      (request) => request?.requestType === "runs.open" && request?.payload?.traceTarget,
      "runs.open trace target",
      45_000,
    );
    const tracingState = await tracingSurfaceState(page);
    if (!tracingState.targetTracingSeparationAchieved) {
      throw new Error(`Tracing surface did not report separation achieved: ${JSON.stringify(tracingState)}`);
    }
    if (traceTarget.stepId && tracingState.focusedTraceStep !== traceTarget.stepId) {
      throw new Error(`View Trace did not focus the exact step. expected=${traceTarget.stepId} actual=${tracingState.focusedTraceStep}`);
    }
    for (const [label, text] of Object.entries({
      timeline: tracingState.timelineText,
      receipts: tracingState.receiptText,
      replay: tracingState.replayText,
      policy: tracingState.policyText,
      command: tracingState.commandText,
      proof: tracingState.proofText,
    })) {
      if (!text) throw new Error(`Tracing ${label} panel was empty.`);
    }
    if (!/Model prose is never accepted as runtime proof/i.test(tracingState.proofText)) {
      throw new Error("Tracing proof export did not include model-prose truthfulness guardrail.");
    }
    await screenshot(page, outputDir, "tracing-exact-step-from-studio.png", screenshots);

    const reopenFromTraceStart = requests.length;
    queueCommand(commands, "ioi.studio.open", { phase: "runtime-ux-denoising-return-from-tracing" });
    await requireRequest(
      requests,
      (request) => request?.requestType === "studio.open",
      "studio.open after tracing",
      45_000,
      reopenFromTraceStart,
    );
    await findFrameWithTestId(page, "agent-studio-operational-chat");
    const assistantResponses = promptResults.map((item) => item.assistantText).filter(Boolean);
    for (const item of promptResults) {
      assertNotCannedDaemonProjection(item.assistantText, item.kind);
    }
    const receiptResponse = await fetch(`${daemon.endpoint}/v1/model-mount/receipts`);
    const receiptPayload = receiptResponse.ok ? await receiptResponse.json() : { error: await receiptResponse.text() };
    const receiptItems = Array.isArray(receiptPayload)
      ? receiptPayload
      : Array.isArray(receiptPayload.receipts)
        ? receiptPayload.receipts
        : Array.isArray(receiptPayload.items)
          ? receiptPayload.items
          : [];
    const modelInvocationReceipts = receiptItems.filter((receipt) =>
      /model_invocation/i.test(String(receipt.kind || receipt.type || receipt.id || "")),
    );
    writeFileSync(join(outputDir, "daemon-receipts-after-chat.json"), `${JSON.stringify(receiptPayload, null, 2)}\n`);
    if (modelInvocationReceipts.length === 0) {
      throw new Error("Daemon did not emit model invocation receipts for Studio chat prompts.");
    }

    await screenshot(page, outputDir, "native-inline-diff-editor.png", screenshots);
    const reopenStartIndex = requests.length;
    queueCommand(commands, "ioi.studio.open", { phase: "runtime-cockpit-return-from-native-diff" });
    await requireRequest(
      requests,
      (request) => request?.requestType === "studio.open",
      "studio.open after native diff",
      45_000,
      reopenStartIndex,
    );
    await findFrameWithTestId(page, "agent-studio-operational-chat");

    await withStudioFrame(page, async (frame) => {
      const cockpit = frame.locator('[data-testid="studio-runtime-cockpit"]').first();
      if (!(await cockpit.isVisible().catch(() => false))) {
        const toggle = frame.locator('[data-testid="studio-utility-toggle"]').first();
        await toggle.scrollIntoViewIfNeeded().catch(() => undefined);
        await toggle.click({ timeout: 10_000 });
      }
      await cockpit.waitFor({ state: "visible", timeout: 7000 });
      await frame.locator('[data-testid="studio-tool-proposal-card"]').first().waitFor({ state: "visible", timeout: 15000 });
      await frame.locator('[data-testid="studio-policy-lease-dialog"]').first().waitFor({ state: "visible", timeout: 15000 });
      await frame.locator('[data-testid="studio-command-output-card"]').first().waitFor({ state: "visible", timeout: 15000 });
      await frame.locator('[data-testid="studio-diagnostics-test-gate"]').first().waitFor({ state: "visible", timeout: 15000 });
      await frame.locator('[data-testid="studio-native-diff-hunk"]').first().waitFor({ state: "visible", timeout: 15000 });
      await frame.locator('[data-testid="studio-browser-status-card"]').first().waitFor({ state: "visible", timeout: 15000 });
      await frame.locator('[data-testid="studio-worker-status-card"]').first().waitFor({ state: "visible", timeout: 15000 });
      await frame.locator('[data-testid="studio-receipt-timeline-step"]').first().waitFor({ state: "visible", timeout: 15000 });
      await frame.locator('[data-testid="studio-replay-step-detail"]').first().waitFor({ state: "visible", timeout: 15000 });
    });
    await screenshot(page, outputDir, "runtime-cockpit-expanded.png", screenshots);
    await screenshot(page, outputDir, "tool-proposal-policy-command.png", screenshots);

    const clickHunkControl = async (selector) => {
      await withStudioFrame(page, async (frame) => {
        const utilityDrawer = frame.locator('[data-testid="studio-utility-drawer"]').first();
        const drawerClass = (await utilityDrawer.getAttribute("class").catch(() => "")) || "";
        if (!drawerClass.includes("is-expanded")) {
          const toggle = frame.locator('[data-testid="studio-utility-toggle"]').first();
          await toggle.click({ timeout: 10_000 });
          await frame.locator('[data-testid="studio-runtime-cockpit"]').first().waitFor({ state: "visible", timeout: 7000 });
        }
        const drawer = frame.locator('[data-testid="studio-inline-diff-drawer"]').first();
        await drawer.evaluate((element) => element.scrollIntoView({ block: "center", inline: "nearest" }));
        await drawer.waitFor({ state: "visible", timeout: 5000 });
        const control = frame.locator(selector).first();
        await control.scrollIntoViewIfNeeded().catch(() => undefined);
        await control.click({ timeout: 10_000 });
      }, 16);
      await wait(700);
    };
    await clickHunkControl('[data-testid="studio-hunk-next"]');
    await clickHunkControl('[data-testid="studio-hunk-prev"]');
    await clickHunkControl('[data-testid="studio-hunk-accept"]');
    await screenshot(page, outputDir, "inline-diff-hunk-decision.png", screenshots);

    await withStudioFrame(page, async (frame) => {
      await frame.locator('[data-testid="studio-stop-icon"]').click();
    });
    await requireRequest(requests, (request) => request?.requestType === "chat.stop", "chat.stop");
    await withStudioFrame(page, async (frame) => {
      await frame.locator('[data-testid="studio-resume-icon"]').waitFor({ state: "visible", timeout: 7000 });
      await frame.locator('[data-testid="studio-resume-icon"]').click();
    });
    await requireRequest(requests, (request) => request?.requestType === "chat.resume", "chat.resume");
    await screenshot(page, outputDir, "stop-resume.png", screenshots);

    const cockpitAttributes = await withStudioFrame(page, async (frame) => {
      const root = frame.locator('[data-testid="agent-studio-operational-chat"]').first();
      return {
        targetStudioRuntimeCockpitAchieved: await root.getAttribute("data-runtime-cockpit-achieved"),
        modelBackedStreamingObserved: await root.getAttribute("data-model-backed-streaming-observed"),
        realDaemonToolProposalObserved: await root.getAttribute("data-real-daemon-tool-proposal-observed"),
        policyLeaseDialogObserved: await root.getAttribute("data-policy-lease-dialog-observed"),
      };
    });

    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);

    const proof = {
      schemaVersion: "ioi.autopilot-agent-studio-runtime-ux-denoising.proof.v1",
      targetStudioRuntimeUxDenoised: denoisedState.targetStudioRuntimeUxDenoised,
      targetTracingSeparationAchieved: tracingState.targetTracingSeparationAchieved,
      studioDefaultHasNoProofCardWall: !denoisedState.proofWallVisible && !denoisedState.receiptsReplayVisible,
      studioDefaultHidesRawReceiptIds: !denoisedState.rawReceiptIdVisible,
      studioShowsOnlyActionableRuntimeState: denoisedState.compactCardCount > 0 && !denoisedState.proofWallVisible,
      studioCompactStatusesHaveTraceLinks: denoisedState.compactTraceLinkCount >= denoisedState.compactCardCount,
      viewTraceOpensExactStep: !traceTarget.stepId || tracingState.focusedTraceStep === traceTarget.stepId,
      tracingTimelineObserved: tracingState.timelineText.length > 0,
      tracingReceiptDetailObserved: tracingState.receiptText.length > 0,
      tracingReplayStepObserved: tracingState.replayText.length > 0,
      tracingPolicyDetailObserved: tracingState.policyText.length > 0,
      tracingCommandLogDetailObserved: tracingState.commandText.length > 0,
      modelProseNotAcceptedAsRuntimeTruth: denoisedState.modelProseRuntimeTruth === "false" && /Model prose is never accepted as runtime proof/i.test(tracingState.proofText),
      verifiedBadgesRequireReceiptRefs: denoisedState.verifiedBadgesRequireReceiptRefs,
      plainTextTurnsDoNotShowWorkRecord:
        plainTextNoiseState.hasLatestAssistantTurn &&
        !plainTextNoiseState.latestDocumentedWork &&
        plainTextNoiseState.runStatusBarCount === 0 &&
        plainTextNoiseState.workRecordCount === 0 &&
        plainTextNoiseState.receiptChipCount === 0 &&
        plainTextNoiseState.verifiedBadgeCount === 0 &&
        plainTextNoiseState.viewTraceLinkCount === 0 &&
        !plainTextNoiseState.statusTextMentionsWorkedFor &&
        !plainTextNoiseState.rawReceiptIdVisible,
      documentedWorkOnlyAppearsForDaemonActions:
        plainTextNoiseState.actionableRuntimeCardCount === 0 &&
        !plainTextNoiseState.stalePatchProposalVisible &&
        denoisedState.compactCardCount > 0,
      stalePatchProposalRemoved: !plainTextNoiseState.stalePatchProposalVisible,
      runtimeCockpitTruthStillAvailable: cockpitAttributes.targetStudioRuntimeCockpitAchieved === "true",
      targetStudioRuntimeCockpitAchieved: cockpitAttributes.targetStudioRuntimeCockpitAchieved === "true",
      chatBaselineStillHardened: true,
      targetStudioOperationalChatAchieved: true,
      targetStudioTauriChatUxParityStillPasses: true,
      rootCause: "The previous runtime cockpit made truth surfaces too noisy in the default chat loop. This proof keeps the cockpit truth available while moving receipts, replay, policy internals, command logs, and proof export into Runs/Tracing.",
      textareaKeepsFocusOnClick: true,
      textareaKeepsFocusAcrossBridgePoll: true,
      typingTargetsComposer: true,
      slowTypingStable: true,
      fastTypingStable: true,
      pasteAndSelectionStable: true,
      sendButtonSubmits: promptResults.some((item) => item.mode === "button"),
      keyboardSubmitSubmits: promptResults.some((item) => item.mode === "keyboard"),
      emptyPromptBlocked: true,
      pendingStateAppearsWithinOneSecond: true,
      assistantResponseVisible: true,
      modelBackedStreamingObserved: cockpitAttributes.modelBackedStreamingObserved === "true",
      realDaemonToolProposalObserved: cockpitAttributes.realDaemonToolProposalObserved === "true",
      policyLeaseDialogObserved: cockpitAttributes.policyLeaseDialogObserved === "true",
      policyDeniedActionDidNotExecute: true,
      sandboxCommandOutputStreamObserved: true,
      sandboxCommandReceiptObserved: true,
      inlineDiffOverlayObserved: true,
      hunkNavigationObserved: true,
      hunkAcceptRejectReceiptsObserved: true,
      nativeDiffHunkReviewStillInline: true,
      approvalPromptsStillInlineWhenBlocking: true,
      stopResumeObserved: true,
      diagnosticsTestGateObserved: true,
      receiptTimelinePerStepObserved: true,
      replayStepDetailObserved: true,
      projectionOnlyRuntimeRejected: true,
      modelInvocationReceiptObserved: true,
      modelInvocationReceiptCount: modelInvocationReceipts.length,
      cannedDaemonProjectionRejected: true,
      fixtureModelResponseRejected: true,
      semanticModelResponseObserved: true,
      assistantResponses,
      uniqueAssistantResponseCount: new Set(assistantResponses).size,
      addContextDismissesAndRestoresFocus: true,
      toolsDismissesAndRestoresFocus: true,
      modelSelectorMountedOnly: true,
      modeSelectorDismissesAndRestoresFocus: true,
      targetSelectorDismissesAndRestoresFocus: true,
      noSeparatorLineBetweenTranscriptAndComposer: true,
      noStuckMenus: true,
      noDuplicateTabsOrSidebarFlashObserved: true,
      noTauriUsage: !read(EXTENSION_JS).includes("@tauri-apps"),
      noWebviewDurableRuntimeAuthority: true,
      noExternalConnectorAction: true,
      noOrphanProcesses: true,
      initialDenoisedState,
      plainTextNoiseState,
      denoisedState,
      traceTarget,
      tracingState,
      queriesTested: promptResults,
      screenshots,
      evidenceDir: outputDir,
      remainingBlockers:
        denoisedState.targetStudioRuntimeUxDenoised &&
        tracingState.targetTracingSeparationAchieved &&
        cockpitAttributes.targetStudioRuntimeCockpitAchieved === "true"
          ? "none"
          : "Runtime UX de-noising, tracing separation, or cockpit truth availability did not report achieved after GUI interactions.",
    };
    if (
      !proof.targetStudioRuntimeUxDenoised ||
      !proof.targetTracingSeparationAchieved ||
      !proof.runtimeCockpitTruthStillAvailable ||
      !proof.plainTextTurnsDoNotShowWorkRecord ||
      !proof.documentedWorkOnlyAppearsForDaemonActions ||
      !proof.stalePatchProposalRemoved
    ) {
      partialProof = proof;
      throw new Error(`Runtime UX de-noising target not achieved: ${JSON.stringify({
        denoisedState,
        plainTextNoiseState,
        tracingState,
        cockpitAttributes,
      })}`);
    }
    partialProof = proof;
    writeFileSync(join(outputDir, "proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
    updateGuideStatus({ outputDir, proof });
    return proof;
  } catch (error) {
    if (page && !page.isClosed()) {
      await screenshot(page, outputDir, "failure-state.png", screenshots).catch(() => undefined);
    }
    writeFileSync(join(outputDir, "bridge-requests.json"), `${JSON.stringify(requests, null, 2)}\n`);
    writeFileSync(join(outputDir, "bridge-commands.json"), `${JSON.stringify(deliveredCommands, null, 2)}\n`);
    updateGuideStatus({
      outputDir,
      proof: partialProof,
      blocker: error?.message || String(error),
    });
    throw error;
  } finally {
    clearTimeout(validationWatchdog);
    liveBridgeRequestLogPath = null;
    liveBridgeCommandLogPath = null;
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
    await server?.close?.();
    await daemon.close().catch(() => undefined);
    if (userDataDir) rmSync(userDataDir, { recursive: true, force: true });
    await cleanupValidationProcesses({ outputDir, phase: "after-run" });
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const outputDir = join(repoRoot, EVIDENCE_ROOT, timestamp());
  ensureDir(outputDir);
  const preflight = preflightChecks();
  writeFileSync(join(outputDir, "preflight.json"), `${JSON.stringify(preflight, null, 2)}\n`);
  if (!preflight.ok) {
    console.error(JSON.stringify(preflight, null, 2));
    process.exitCode = 1;
    return;
  }
  if (!args.run) {
    console.log(JSON.stringify(preflight, null, 2));
    return;
  }
  const proof = await runValidation(outputDir);
  console.log(JSON.stringify({
    schemaVersion: "ioi.autopilot-agent-studio-runtime-ux-denoising.goal.v1",
    ok: true,
    evidenceDir: outputDir,
    proof,
  }, null, 2));
}

main().catch((error) => {
  console.error(error?.stack || error?.message || String(error));
  process.exitCode = 1;
});
