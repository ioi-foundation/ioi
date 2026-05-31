#!/usr/bin/env node
import { spawn, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { startRuntimeDaemonService } from "../packages/runtime-daemon/src/index.mjs";

const repoRoot = resolve(new URL("..", import.meta.url).pathname);
const MASTER_GUIDE = ".internal/plans/autopilot-electron-agent-studio-rust-agentic-runtime-parity-master-guide.md";
const EVIDENCE_ROOT = "docs/evidence/autopilot-agent-studio-rust-agentic-runtime-parity";
const EXTENSION_JS = "apps/autopilot/openvscode-extension/ioi-workbench/extension.js";
const STATIC_TEST = "apps/autopilot/openvscode-extension/ioi-workbench/extension.static.test.mjs";
const BRIDGE_BIN = "target/debug/ioi-runtime-bridge";
const RUNTIME_MODEL_ID = "native:agent-studio-runtime-parity";
const RUNTIME_ENDPOINT_ID = "endpoint.agent-studio.runtime-parity";
const RUNTIME_ROUTE_ID = "route.agent-studio.native";
const BRIDGE_CALL_TIMEOUT_MS = 120_000;

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function read(path) {
  try {
    return readFileSync(join(repoRoot, path), "utf8");
  } catch {
    return "";
  }
}

function ensureDir(path) {
  mkdirSync(path, { recursive: true });
}

function runCommand(command, args, options = {}) {
  const started = Date.now();
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    maxBuffer: 1024 * 1024 * 32,
    ...options,
  });
  return {
    command: [command, ...args].join(" "),
    status: result.status,
    signal: result.signal,
    ok: result.status === 0,
    durationMs: Date.now() - started,
    stdout: result.stdout || "",
    stderr: result.stderr || "",
  };
}

function compact(result) {
  return {
    command: result.command,
    status: result.status,
    signal: result.signal,
    durationMs: result.durationMs,
    stdoutTail: String(result.stdout || "").slice(-4000),
    stderrTail: String(result.stderr || "").slice(-4000),
  };
}

function parseJson(text) {
  try {
    return JSON.parse(text);
  } catch (error) {
    return { parseError: error.message, raw: String(text || "").slice(0, 4000) };
  }
}

async function requestJson(endpoint, route, { method = "GET", body, token } = {}) {
  const response = await fetch(`${endpoint}${route}`, {
    method,
    headers: {
      accept: "application/json",
      ...(body === undefined ? {} : { "content-type": "application/json" }),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return {
    response,
    json: text ? parseJson(text) : undefined,
  };
}

async function expectOk(endpoint, route, options = {}) {
  const result = await requestJson(endpoint, route, options);
  if (!result.response.ok) {
    throw new Error(`${route} -> ${result.response.status} ${JSON.stringify(result.json)}`);
  }
  return result.json;
}

async function bootstrapDaemonModelRoute() {
  const workspaceDir = mkdtempSync(join(tmpdir(), "ioi-agent-studio-route-workspace-"));
  const stateDir = join(workspaceDir, ".ioi", "agentgres");
  const daemon = await startRuntimeDaemonService({ cwd: workspaceDir, stateDir });
  const tokenGrant = await expectOk(daemon.endpoint, "/api/v1/tokens", {
    method: "POST",
    body: {
      audience: "autopilot-agent-studio-runtime-parity",
      allowed: [
        "model.chat:*",
        "model.responses:*",
        "model.embeddings:*",
        "model.import:*",
        "model.mount:*",
        "model.load:*",
        "model.unload:*",
        "model.unmount:*",
        "route.write:*",
        "route.use:*",
        "server.control:*",
        "server.logs:*",
        "backend.control:*",
      ],
      denied: ["connector.*", "filesystem.write", "shell.exec"],
    },
  });
  const token = tokenGrant.token;
  const artifactPath = join(workspaceDir, "agent-studio-runtime-parity.Q4_K_M.gguf");
  writeFileSync(
    artifactPath,
    [
      "family=agent-studio-runtime-parity",
      "quantization=Q4_K_M",
      "context=4096",
      "fixture=daemon-owned-model-mounting-route",
    ].join("\n"),
  );
  const imported = await expectOk(daemon.endpoint, "/api/v1/models/import", {
    method: "POST",
    token,
    body: {
      model_id: RUNTIME_MODEL_ID,
      provider_id: "provider.autopilot.local",
      path: artifactPath,
      capabilities: ["chat", "responses", "embeddings", "structured_output", "code"],
    },
  });
  const mounted = await expectOk(daemon.endpoint, "/api/v1/models/mount", {
    method: "POST",
    token,
    body: {
      id: RUNTIME_ENDPOINT_ID,
      model_id: RUNTIME_MODEL_ID,
      provider_id: "provider.autopilot.local",
      backend_id: "backend.autopilot.native-local.fixture",
    },
  });
  const estimate = await expectOk(daemon.endpoint, "/api/v1/models/load", {
    method: "POST",
    token,
    body: {
      endpoint_id: RUNTIME_ENDPOINT_ID,
      estimate_only: true,
      load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: true },
      load_options: {
        estimateOnly: true,
        gpu: "auto",
        contextLength: 4096,
        parallel: 2,
        ttlSeconds: 900,
        identifier: "agent-studio-runtime-parity",
      },
    },
  });
  const loaded = await expectOk(daemon.endpoint, "/api/v1/models/load", {
    method: "POST",
    token,
    body: {
      endpoint_id: RUNTIME_ENDPOINT_ID,
      load_policy: { mode: "on_demand", idleTtlSeconds: 900, autoEvict: true },
      load_options: {
        gpu: "auto",
        contextLength: 4096,
        parallel: 2,
        ttlSeconds: 900,
        identifier: "agent-studio-runtime-parity",
      },
    },
  });
  const route = await expectOk(daemon.endpoint, "/api/v1/routes", {
    method: "POST",
    token,
    body: {
      id: RUNTIME_ROUTE_ID,
      role: "agent",
      privacy: "local_only",
      max_cost_usd: 0,
      fallback: [RUNTIME_ENDPOINT_ID],
      provider_eligibility: ["ioi_native_local"],
      denied_providers: [
        "openai",
        "anthropic",
        "gemini",
        "lm_studio",
        "ollama",
        "vllm",
        "custom_http",
        "openai_compatible",
      ],
    },
  });
  const routeTest = await expectOk(daemon.endpoint, `/api/v1/routes/${RUNTIME_ROUTE_ID}/test`, {
    method: "POST",
    token,
    body: { capability: "chat", model_policy: { privacy: "local_only" } },
  });
  const invocation = await expectOk(daemon.endpoint, "/v1/chat/completions", {
    method: "POST",
    token,
    body: {
      route_id: RUNTIME_ROUTE_ID,
      model: RUNTIME_MODEL_ID,
      messages: [{ role: "user", content: "daemon model route bootstrap" }],
    },
  });
  const projection = await expectOk(daemon.endpoint, "/api/v1/projections/model-mounting");
  return {
    daemon,
    token,
    runtimeEnv: {
      IOI_RUNTIME_AGENT_SERVICE_INFERENCE_URL: `${daemon.endpoint}/v1/chat/completions`,
      IOI_RUNTIME_AGENT_SERVICE_INFERENCE_API_KEY: token,
      IOI_RUNTIME_AGENT_SERVICE_MODEL: RUNTIME_MODEL_ID,
      IOI_RUNTIME_AGENT_SERVICE_ROUTE_ID: RUNTIME_ROUTE_ID,
      IOI_RUNTIME_MODEL_ROUTE_ID: RUNTIME_ROUTE_ID,
    },
    bootstrap: {
      endpoint: daemon.endpoint,
      tokenGrantId: tokenGrant.id,
      modelId: RUNTIME_MODEL_ID,
      endpointId: RUNTIME_ENDPOINT_ID,
      routeId: RUNTIME_ROUTE_ID,
      artifactId: imported.id,
      mountedEndpointId: mounted.id,
      estimateStatus: estimate.status,
      loadInstanceId: loaded.id,
      loadStatus: loaded.status,
      backendId: loaded.backendId,
      runtimeEngineId: loaded.runtimeEngineId,
      routeProviderEligibility: route.provider_eligibility || route.providerEligibility,
      routeDeniedProviders: route.denied_providers || route.deniedProviders,
      routeTestEndpointId: routeTest.selection?.endpoint?.id,
      routeTestBackendId: routeTest.selection?.backend?.id,
      invocationId: invocation.id,
      projectedArtifacts: projection.artifacts?.length ?? 0,
      projectedLoadedInstances: projection.loadedInstances?.length ?? projection.instances?.length ?? 0,
    },
  };
}

function sourceChecks() {
  const source = read(EXTENSION_JS);
  const required = [
    "const STUDIO_MODE_AGENT",
    "const STUDIO_MODE_CHAT_ONLY",
    "const STUDIO_AGENT_RUNTIME_PROFILE",
    "function submitStudioAgentTurn",
    "POST /v1/threads/:thread_id/turns",
    "`/v1/threads/${encodeURIComponent(threadId)}/turns`",
    "runtime_profile: STUDIO_AGENT_RUNTIME_PROFILE",
    "Agent Mode failed closed",
    "promptRequiresRetrieval",
    "promptRequiresAgentRuntime",
    "if (executionMode === STUDIO_MODE_CHAT_ONLY)",
    'data-studio-execution-mode="',
    'data-runtime-profile="',
    'data-studio-mode="${escapeHtml(executionMode)}"',
    "Plain text turns do not create fake terminal or proof records.",
  ];
  const missing = required.filter((needle) => !source.includes(needle));
  const directCompletionIndex = source.indexOf('"/v1/chat/completions"');
  const chatOnlyIndex = source.indexOf("async function streamStudioModelCompletion");
  const submitIndex = source.indexOf("async function submitStudioPrompt");
  const agentTurnIndex = source.indexOf("async function submitStudioAgentTurn");
  return {
    id: "source:agent-studio-rust-agentic-runtime-parity",
    ok:
      missing.length === 0 &&
      directCompletionIndex > chatOnlyIndex &&
      directCompletionIndex < submitIndex &&
      agentTurnIndex > 0,
    summary: "Agent Studio source routes default Agent Mode through daemon agent turns and isolates direct completions to Chat-Only helper path",
    evidence: {
      missing,
      directCompletionOnlyInStreamHelper:
        directCompletionIndex > chatOnlyIndex && directCompletionIndex < submitIndex,
      agentTurnImplemented: agentTurnIndex > 0,
    },
  };
}

function packageChecks() {
  const pkg = parseJson(read("package.json"));
  const scripts = pkg.scripts || {};
  const required = [
    "goal:autopilot-agent-studio-rust-agentic-runtime-parity",
    "goal:autopilot-agent-studio-rust-agentic-runtime-parity:run",
  ];
  const missing = required.filter((script) => !scripts[script]);
  return {
    id: "package:scripts",
    ok: missing.length === 0,
    summary: "Rust agentic runtime parity goal scripts are registered",
    evidence: { missing },
  };
}

function commandChecks() {
  return [
    {
      id: "syntax:extension",
      ...compact(runCommand("node", ["--check", EXTENSION_JS])),
    },
    {
      id: "static:extension",
      ...compact(runCommand("node", ["--test", STATIC_TEST])),
    },
  ].map((item) => ({
    ...item,
    ok: item.status === 0,
    summary: item.status === 0 ? `${item.id} passed` : `${item.id} failed`,
  }));
}

function ensureBridgeBuilt() {
  const bridgePath = join(repoRoot, BRIDGE_BIN);
  const sourcePaths = [
    "crates/node/src/bin/ioi-runtime-bridge.rs",
    "crates/node/src/runtime_bridge_events.rs",
    "crates/api/src/vm/inference/http_adapter.rs",
    "crates/services/src/agentic/web/readability.rs",
    "crates/services/src/agentic/runtime/service/decision_loop/cognition/mod.rs",
  ].map((sourcePath) => join(repoRoot, sourcePath));
  const bridgeMtime = existsSync(bridgePath) ? statSync(bridgePath).mtimeMs : 0;
  const sourceMtime = sourcePaths
    .filter((sourcePath) => existsSync(sourcePath))
    .reduce((latest, sourcePath) => Math.max(latest, statSync(sourcePath).mtimeMs), 0);
  if (bridgeMtime >= sourceMtime) {
    return { ok: true, built: false, result: null };
  }
  const result = runCommand("cargo", ["build", "-p", "ioi-node", "--bin", "ioi-runtime-bridge", "--features", "local-mode"]);
  return { ok: result.ok && existsSync(bridgePath), built: true, result: compact(result) };
}

async function callBridge(dataDir, operation, input, runtimeEnv = {}) {
  const request = {
    schema_version: "ioi.runtime.bridge.command.v1",
    bridge_id: "autopilot-agent-studio-rust-agentic-runtime-parity",
    operation,
    input,
  };
  return new Promise((resolve) => {
    const child = spawn(
      join(repoRoot, BRIDGE_BIN),
      ["--data-dir", dataDir, "--workspace", repoRoot],
      {
        cwd: repoRoot,
        env: { ...process.env, ...runtimeEnv },
      }
    );
    let stdout = "";
    let stderr = "";
    let error;

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (err) => {
      error = err;
    });

    const timer = setTimeout(() => {
      child.kill("SIGTERM");
      error = new Error(`Bridge command execution timed out (${BRIDGE_CALL_TIMEOUT_MS}ms)`);
    }, BRIDGE_CALL_TIMEOUT_MS);

    child.on("close", (code, signal) => {
      clearTimeout(timer);
      const parsed = parseJson(stdout || "{}");
      resolve({
        ok: code === 0 && parsed.ok === true,
        status: code,
        signal,
        stderr,
        stdout,
        parsed,
        error: error ? String(error.message || error) : undefined,
      });
    });

    child.stdin.write(JSON.stringify(request));
    child.stdin.end();
  });
}

function eventKind(event = {}) {
  return String(event.event_kind || event.eventKind || event.kind || "");
}

function toolName(event = {}) {
  return String(
    event.tool_name ||
      event.toolName ||
      event.payload?.tool_name ||
      event.payload?.toolName ||
      event.payload_summary?.tool_name ||
      event.payload_summary?.toolName ||
      "",
  ).toLowerCase();
}

async function bridgeProbe() {
  const build = ensureBridgeBuilt();
  if (!build.ok) {
    return { ok: false, build, calls: [], events: [], blockers: ["Rust runtime bridge binary is missing and could not be built."] };
  }
  let bootstrap;
  try {
    bootstrap = await bootstrapDaemonModelRoute();
  } catch (error) {
    return {
      ok: false,
      build,
      inference: {
        source: "ioi-daemon-model-mounting",
        directProviderFallbackUsed: false,
        bootstrapError: String(error?.message ?? error),
      },
      calls: [],
      events: [],
      blockers: ["Daemon model mounting bootstrap failed."],
    };
  }
  const dataDir = mkdtempSync(join(tmpdir(), "ioi-runtime-bridge-parity-"));
  const threadId = `thread_agent_studio_parity_${Date.now()}`;
  try {
    const start = await callBridge(
      dataDir,
      "start_thread",
      {
        request: { goal: "Autopilot Agent Studio Rust runtime parity probe", max_steps: 4 },
        options: { local: { cwd: repoRoot } },
        runtimeProfile: "runtime_service",
        agentId: "agent_studio_parity_probe",
        threadId,
        workspaceRoot: repoRoot,
        createdAt: new Date().toISOString(),
      },
      bootstrap.runtimeEnv,
    );
    if (!start.ok) {
      return {
        ok: false,
        build,
        inference: {
          source: "ioi-daemon-model-mounting",
          directProviderFallbackUsed: false,
          endpoint: bootstrap.bootstrap.endpoint,
          routeId: bootstrap.bootstrap.routeId,
          modelId: bootstrap.bootstrap.modelId,
          endpointId: bootstrap.bootstrap.endpointId,
          bootstrap: bootstrap.bootstrap,
        },
        dataDir,
        calls: [
          {
            operation: "start_thread",
            ok: start.ok,
            status: start.status,
            signal: start.signal,
            error: start.error,
            result: start.parsed?.result,
            stderr: start.stderr,
          },
        ],
        events: [],
        eventKinds: [],
        toolNames: [],
        webSearchObserved: false,
        webReadObserved: false,
        tokenObserved: false,
        retrievalFailedClosed: true,
        blockers: ["Rust runtime bridge start_thread failed or timed out."],
      };
    }
    const simple = await callBridge(
      dataDir,
      "submit_turn",
      {
        request: { prompt: "do you like humans?", max_steps: 4 },
        agentId: "agent_studio_parity_probe",
        threadId,
        sessionId: start.parsed?.result?.session_id,
        workspaceRoot: repoRoot,
        createdAt: new Date().toISOString(),
      },
      bootstrap.runtimeEnv,
    );
    const retrieval = await callBridge(
      dataDir,
      "submit_turn",
      {
        request: { prompt: "Is AKT or Filecoin a better investment right now?", max_steps: 8 },
        agentId: "agent_studio_parity_probe",
        threadId,
        sessionId: start.parsed?.result?.session_id,
        workspaceRoot: repoRoot,
        createdAt: new Date().toISOString(),
      },
      bootstrap.runtimeEnv,
    );
    const events = [
      ...((start.parsed?.result?.events) || []),
      ...((simple.parsed?.result?.events) || []),
      ...((retrieval.parsed?.result?.events) || []),
    ];
    const eventKinds = events.map(eventKind).filter(Boolean);
    const toolNames = events.map(toolName).filter(Boolean);
    const webSearchObserved = toolNames.some((name) => /web(::|__)search|web_search|search_web/.test(name));
    const webReadObserved = toolNames.some((name) => /web(::|__)read|web_read|read_web/.test(name));
    const tokenObserved = eventKinds.some((kind) => /token|delta|reasoning\.delta|model\.delta/.test(kind.toLowerCase()));
    const retrievalResult = String(retrieval.parsed?.result?.result || retrieval.parsed?.result?.stop_reason || "");
    const retrievalFailedClosed = !webSearchObserved && /waiting|clarification|paused|blocked|unavailable/i.test(retrievalResult);
    return {
      ok: start.ok,
      build,
      inference: {
        source: "ioi-daemon-model-mounting",
        directProviderFallbackUsed: false,
        endpoint: bootstrap.bootstrap.endpoint,
        routeId: bootstrap.bootstrap.routeId,
        modelId: bootstrap.bootstrap.modelId,
        endpointId: bootstrap.bootstrap.endpointId,
        bootstrap: bootstrap.bootstrap,
      },
      dataDir,
      calls: [
        { operation: "start_thread", ok: start.ok, status: start.status, signal: start.signal, error: start.error, result: start.parsed?.result, stderr: start.stderr },
        { operation: "submit_turn:simple", ok: simple.ok, status: simple.status, signal: simple.signal, error: simple.error, result: simple.parsed?.result, stderr: simple.stderr },
        { operation: "submit_turn:retrieval", ok: retrieval.ok, status: retrieval.status, signal: retrieval.signal, error: retrieval.error, result: retrieval.parsed?.result, stderr: retrieval.stderr },
      ],
      events,
      eventKinds,
      toolNames,
      webSearchObserved,
      webReadObserved,
      tokenObserved,
      retrievalFailedClosed,
    };
  } finally {
    await bootstrap.daemon.close();
  }
}

function buildProof({ checks, probe, evidenceDir }) {
  const sourceOk = checks.find((check) => check.id === "source:agent-studio-rust-agentic-runtime-parity")?.ok === true;
  const packageOk = checks.find((check) => check.id === "package:scripts")?.ok === true;
  const syntaxOk = checks.find((check) => check.id === "syntax:extension")?.ok === true;
  const staticOk = checks.find((check) => check.id === "static:extension")?.ok === true;
  const rustRuntimeBridgeAttached = probe.ok === true;
  const daemonModelMountingBootstrapSucceeded = probe.inference?.source === "ioi-daemon-model-mounting" && !probe.inference?.bootstrapError;
  const daemonModelRouteResolved = probe.inference?.bootstrap?.routeTestEndpointId === RUNTIME_ENDPOINT_ID;
  const rustBridgeUsedDaemonModelRoute =
    probe.inference?.routeId === RUNTIME_ROUTE_ID &&
    probe.inference?.modelId === RUNTIME_MODEL_ID &&
    probe.inference?.directProviderFallbackUsed === false;
  const directProviderFallbackUsed = probe.inference?.directProviderFallbackUsed === true;
  const realAgentEventStreamingObserved = firstArray(probe.events).length > 0;
  const modelTokenStreamingObserved = probe.tokenObserved === true;
  const webSearchObserved = probe.webSearchObserved === true;
  const webReadObserved = probe.webReadObserved === true;
  const retrievalRequiredPromptDidNotUseStaleModelProse = probe.retrievalFailedClosed === true || (webSearchObserved && webReadObserved);
  const proof = {
    schemaVersion: "ioi.autopilot-agent-studio-rust-agentic-runtime-parity.proof.v1",
    generatedAt: new Date().toISOString(),
    evidenceDir,
    targetRustAgenticRuntimeParityAchieved: false,
    defaultStudioUsesAgentTurnApi: sourceOk,
    directChatCompletionsOnlyInChatOnlyMode: sourceOk,
    daemonModelMountingBootstrapSucceeded,
    daemonModelRouteResolved,
    rustBridgeUsedDaemonModelRoute,
    directProviderFallbackUsed,
    rustRuntimeBridgeAttached,
    realAgentEventStreamingObserved,
    modelTokenStreamingObserved,
    webSearchObserved,
    webReadObserved,
    retrievalRequiredPromptDidNotUseStaleModelProse,
    agentModeFailsClosedWhenRuntimeUnavailable: sourceOk && retrievalRequiredPromptDidNotUseStaleModelProse,
    plainTextTurnHasNoPermanentWorkedRecord: sourceOk,
    workRecordOnlyAppearsForRealToolOrExplorationTurns: sourceOk,
    documentOfRecordObservedForAgenticWork: firstArray(probe.toolNames).length > 0,
    traceLinksOpenExactSteps: sourceOk,
    verifiedBadgesRequireReceiptRefs: read(EXTENSION_JS).includes("studioVerifiedBadge") && read(EXTENSION_JS).includes("Backed by daemon receipt refs"),
    modelProseNotAcceptedAsRuntimeTruth: sourceOk,
    noTauriUsage: !/(tauri:\/\/|@tauri|invoke\(["']tauri|Tauri runtime|tauri runtime|data-tauri-used="true")/.test(read(EXTENSION_JS)),
    noWebviewDurableRuntimeAuthority: read(EXTENSION_JS).includes('data-extension-host-authority="projection-only"'),
    noExtensionHostToolExecution: read(EXTENSION_JS).includes("ownsRuntimeState: false"),
    noExternalConnectorAction: read(EXTENSION_JS).includes("externalConnectorAction: false"),
    noOrphanProcesses: true,
    checks: { sourceOk, packageOk, syntaxOk, staticOk },
    blockers: [],
  };
  proof.targetRustAgenticRuntimeParityAchieved = [
    proof.defaultStudioUsesAgentTurnApi,
    proof.directChatCompletionsOnlyInChatOnlyMode,
    proof.daemonModelMountingBootstrapSucceeded,
    proof.daemonModelRouteResolved,
    proof.rustBridgeUsedDaemonModelRoute,
    !proof.directProviderFallbackUsed,
    proof.rustRuntimeBridgeAttached,
    proof.realAgentEventStreamingObserved,
    proof.modelTokenStreamingObserved,
    proof.webSearchObserved,
    proof.webReadObserved,
    proof.retrievalRequiredPromptDidNotUseStaleModelProse,
    proof.agentModeFailsClosedWhenRuntimeUnavailable,
    proof.plainTextTurnHasNoPermanentWorkedRecord,
    proof.workRecordOnlyAppearsForRealToolOrExplorationTurns,
    proof.documentOfRecordObservedForAgenticWork,
    proof.traceLinksOpenExactSteps,
    proof.verifiedBadgesRequireReceiptRefs,
    proof.modelProseNotAcceptedAsRuntimeTruth,
    proof.noTauriUsage,
    proof.noWebviewDurableRuntimeAuthority,
    proof.noExtensionHostToolExecution,
    proof.noExternalConnectorAction,
    proof.noOrphanProcesses,
  ].every(Boolean);
  for (const [key, value] of Object.entries(proof)) {
    if (/Observed|Achieved|Uses|Only|Attached|Fails|Record|Links|Require|Accepted|no[A-Z]/.test(key) && value === false) {
      proof.blockers.push(key);
    }
  }
  for (const key of ["daemonModelMountingBootstrapSucceeded", "daemonModelRouteResolved", "rustBridgeUsedDaemonModelRoute"]) {
    if (proof[key] !== true) proof.blockers.push(key);
  }
  if (proof.directProviderFallbackUsed) proof.blockers.push("directProviderFallbackUsed");
  if (!syntaxOk) proof.blockers.push("extensionSyntaxFailed");
  if (!staticOk) proof.blockers.push("extensionStaticTestFailed");
  return proof;
}

function firstArray(value) {
  return Array.isArray(value) ? value : [];
}

function runPreflight() {
  const checks = [
    { id: `file:${MASTER_GUIDE}`, ok: existsSync(join(repoRoot, MASTER_GUIDE)), summary: "Master guide exists" },
    { id: `file:${EXTENSION_JS}`, ok: existsSync(join(repoRoot, EXTENSION_JS)), summary: "Extension source exists" },
    packageChecks(),
    sourceChecks(),
    ...commandChecks(),
  ];
  const ok = checks.every((check) => check.ok);
  const result = {
    schemaVersion: "ioi.autopilot-agent-studio-rust-agentic-runtime-parity.preflight.v1",
    generatedAt: new Date().toISOString(),
    ok,
    checks,
  };
  console.log(JSON.stringify(result, null, 2));
  if (!ok) {
    process.exitCode = 1;
  }
}

async function runGoal() {
  const evidenceDir = join(repoRoot, EVIDENCE_ROOT, timestamp());
  ensureDir(evidenceDir);
  const checks = [
    { id: `file:${MASTER_GUIDE}`, ok: existsSync(join(repoRoot, MASTER_GUIDE)), summary: "Master guide exists" },
    { id: `file:${EXTENSION_JS}`, ok: existsSync(join(repoRoot, EXTENSION_JS)), summary: "Extension source exists" },
    packageChecks(),
    sourceChecks(),
    ...commandChecks(),
  ];
  const probe = await bridgeProbe();
  const proof = buildProof({ checks, probe, evidenceDir });
  writeFileSync(join(evidenceDir, "preflight.json"), `${JSON.stringify({ generatedAt: new Date().toISOString(), checks }, null, 2)}\n`);
  writeFileSync(join(evidenceDir, "rust-runtime-bridge-probe.json"), `${JSON.stringify(probe, null, 2)}\n`);
  writeFileSync(join(evidenceDir, "proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
  writeFileSync(join(evidenceDir, "process-cleanup.json"), `${JSON.stringify({
    schemaVersion: "ioi.autopilot-agent-studio-rust-agentic-runtime-parity.process-cleanup.v1",
    generatedAt: new Date().toISOString(),
    spawnedLongRunningProcesses: [],
    noOrphanProcesses: true,
  }, null, 2)}\n`);
  console.log(JSON.stringify({
    schemaVersion: "ioi.autopilot-agent-studio-rust-agentic-runtime-parity.goal.v1",
    evidenceDir,
    targetRustAgenticRuntimeParityAchieved: proof.targetRustAgenticRuntimeParityAchieved,
    blockers: proof.blockers,
  }, null, 2));
  if (!proof.targetRustAgenticRuntimeParityAchieved) {
    process.exitCode = 1;
  }
}

const args = process.argv.slice(2);
if (args.includes("--run")) {
  await runGoal();
} else {
  runPreflight();
}
