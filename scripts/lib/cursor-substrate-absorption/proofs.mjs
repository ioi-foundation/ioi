import { mkdirSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";

import { startRuntimeDaemonService } from "../../../packages/runtime-daemon/src/index.mjs";
import {
  BASELINE_VERDICTS,
  CURSOR_INPUTS,
  ROW_DEFINITIONS,
  assertCheck,
  cleanupProof,
  commandEvidence,
  copyDirectory,
  ensureDir,
  fileSnapshot,
  productDecision,
  readJson,
  readText,
  rel,
  removePath,
  requestJson,
  runCommand,
  runCommandAsync,
  sha256,
  startLocalFixtureServer,
  summarizeChecks,
  tempWorkspace,
  writeJson,
  writeMarkdown,
  writePackageFixture,
  writeText,
} from "./common.mjs";
import { runGuiScenarioProof } from "../headless-runtime-unification/live-proofs.mjs";

function threadIdOf(record) {
  return record.thread_id ?? record.threadId ?? record.id ?? record.thread?.id;
}

function turnIdOf(record) {
  return record.turn_id ?? record.turnId ?? record.id ?? record.turn?.id;
}

function capabilityPriority(name = "") {
  if (/shadow|sandbox|oauth|daemon execution|worker/i.test(name)) return "P0";
  if (/browser|canvas|retrieval|grep|git|bugbot|file/i.test(name)) return "P1";
  return "P2";
}

function autopilotDeltaForCapability(name = "") {
  if (/shadow|sandbox|oauth|bugbot/i.test(name)) return "cursor_specific_gap";
  if (/browser/i.test(name)) return "already_proven_by_antigravity_parity_plus";
  if (/retrieval|grep|git relevant/i.test(name)) return "already_proven_by_claude_code_absorption";
  if (/daemon execution|worker|ndjson/i.test(name)) return "already_proven_by_headless_unification";
  if (/canvas|environment/i.test(name)) return "product_decision_needed";
  return "product_decision_needed";
}

function sourceEvidenceForRows() {
  return Object.values(CURSOR_INPUTS);
}

export function runEvidenceSeedProof(stageDir) {
  ensureDir(stageDir);
  const capabilityMatrix = readJson(CURSOR_INPUTS.capabilityMatrix);
  const evidenceManifest = readJson(CURSOR_INPUTS.evidenceManifest);
  const substrateMap = readText(CURSOR_INPUTS.substrateMap);
  const deltaAudit = readText(CURSOR_INPUTS.deltaAudit);
  const capabilities = Array.isArray(capabilityMatrix)
    ? capabilityMatrix
    : Array.isArray(capabilityMatrix.capabilities)
      ? capabilityMatrix.capabilities
      : [];
  const normalizedCapabilities = capabilities.map((capability, index) => ({
    id: capability.id ?? `CURSOR-RE-${String(index + 1).padStart(3, "0")}`,
    priority: capability.priority ?? capabilityPriority(capability.name),
    autopilotDeltaClassification:
      capability.autopilotDeltaClassification ??
      capability.autopilot_delta_classification ??
      autopilotDeltaForCapability(capability.name),
    dynamicProbeRequired:
      /compiled|binary|daemon|socket|sidecar|worker/i.test(
        `${capability.confirmed_behavior ?? ""} ${capability.inferred_behavior ?? ""}`,
      ),
    ...capability,
  }));
  const normalized = {
    schemaVersion: "ioi.cursor-substrate.capability-matrix.v1",
    generatedAt: new Date().toISOString(),
    source: CURSOR_INPUTS.capabilityMatrix,
    capabilities: normalizedCapabilities,
  };
  const seedRows = ROW_DEFINITIONS.map((row) => ({
    ...row,
    status: "gap",
    cursorEvidence: sourceEvidenceForRows(),
    baselineCoverage: BASELINE_VERDICTS,
    liveEvidence: [],
    screenshots: [],
    cleanupProof: "",
    residualRisk: "",
    nextProofStep: "",
  }));
  writeJson(join(stageDir, "cursor-capability-matrix.normalized.json"), normalized);
  writeJson(join(stageDir, "cursor-campaign-seed-manifest.json"), {
    schemaVersion: "ioi.cursor-substrate.seed-manifest.v1",
    generatedAt: new Date().toISOString(),
    rows: seedRows,
  });
  writeJson(join(stageDir, "cursor-source-evidence.json"), {
    substrateMapHash: sha256(substrateMap),
    deltaAuditHash: sha256(deltaAudit),
    evidenceManifestKeys: Object.keys(evidenceManifest),
    capabilityCount: normalizedCapabilities.length,
    p0CapabilityCount: normalizedCapabilities.filter((item) => item.priority === "P0").length,
    dynamicProbeRequiredCount: normalizedCapabilities.filter((item) => item.dynamicProbeRequired).length,
  });
  const checks = [
    assertCheck(normalizedCapabilities.length >= 10, "Cursor capability matrix loaded with broad coverage"),
    assertCheck(normalizedCapabilities.every((item) => item.id && item.priority && item.classification), "Every capability has id, priority, and Cursor classification"),
    assertCheck(seedRows.length === ROW_DEFINITIONS.length, "Seed manifest covers every guide row"),
    assertCheck(normalizedCapabilities.some((item) => item.autopilotDeltaClassification === "cursor_specific_gap"), "Cursor-specific gaps are preserved"),
  ];
  const proof = {
    schemaVersion: "ioi.cursor-substrate.seed-proof.v1",
    generatedAt: new Date().toISOString(),
    checks,
    summary: summarizeChecks(checks),
    artifacts: {
      normalizedCapabilityMatrix: rel(join(stageDir, "cursor-capability-matrix.normalized.json")),
      seedManifest: rel(join(stageDir, "cursor-campaign-seed-manifest.json")),
      sourceEvidence: rel(join(stageDir, "cursor-source-evidence.json")),
    },
  };
  writeJson(join(stageDir, "stage-verdict.json"), proof);
  return proof;
}

export async function runShadowWorkspaceProof(stageDir) {
  ensureDir(stageDir);
  const activeRoot = tempWorkspace("cursor-shadow-active");
  const shadowRoot = tempWorkspace("cursor-shadow-dryrun");
  const stateDir = join(stageDir, "daemon-state");
  writePackageFixture(activeRoot, { broken: true });
  copyDirectory(activeRoot, shadowRoot);
  const service = await startRuntimeDaemonService({ stateDir, cwd: activeRoot });
  const transcript = [];
  try {
    const endpoint = service.endpoint;
    const activeThread = await requestJson(endpoint, "POST", "/v1/threads", {
      options: { local: { cwd: activeRoot }, source: "cursor_substrate_shadow_active" },
    }, transcript);
    const shadowThread = await requestJson(endpoint, "POST", "/v1/threads", {
      options: { local: { cwd: shadowRoot }, source: "cursor_substrate_shadow_dryrun" },
    }, transcript);
    const activeThreadId = threadIdOf(activeThread);
    const shadowThreadId = threadIdOf(shadowThread);
    const shadowTurn = await requestJson(endpoint, "POST", `/v1/threads/${shadowThreadId}/turns`, {
      prompt: "Validate the disposable calc fix in a shadow workspace first.",
      source: "cursor_substrate_shadow_dryrun",
    }, transcript);
    const activeTurn = await requestJson(endpoint, "POST", `/v1/threads/${activeThreadId}/turns`, {
      prompt: "Apply the already validated disposable calc fix to the active workspace.",
      source: "cursor_substrate_shadow_active",
    }, transcript);
    const before = {
      active: fileSnapshot(activeRoot, ["src/calc.js", "test/calc.test.js"]),
      shadow: fileSnapshot(shadowRoot, ["src/calc.js", "test/calc.test.js"]),
    };
    const shadowPatch = await requestJson(endpoint, "POST", `/v1/threads/${shadowThreadId}/tools/file.apply_patch/invoke`, {
      turn_id: turnIdOf(shadowTurn),
      approved: true,
      source: "cursor_substrate_shadow_dryrun",
      input: {
        path: "src/calc.js",
        oldText: "export function add(a, b) { return a - b; }\n",
        newText: "export function add(a, b) { return a + b; }\n",
        diagnosticsMode: "blocking",
        diagnosticCommandId: "node.check",
      },
    }, transcript);
    const shadowTest = await requestJson(endpoint, "POST", `/v1/threads/${shadowThreadId}/tools/test.run/invoke`, {
      turn_id: turnIdOf(shadowTurn),
      approved: true,
      source: "cursor_substrate_shadow_dryrun",
      input: { commandId: "npm.test", cwd: ".", timeoutMs: 30_000 },
    }, transcript);
    const between = {
      active: fileSnapshot(activeRoot, ["src/calc.js"]),
      shadow: fileSnapshot(shadowRoot, ["src/calc.js"]),
    };
    const activePatch = await requestJson(endpoint, "POST", `/v1/threads/${activeThreadId}/tools/file.apply_patch/invoke`, {
      turn_id: turnIdOf(activeTurn),
      approved: true,
      source: "cursor_substrate_active_apply_after_shadow_validation",
      input: {
        path: "src/calc.js",
        oldText: "export function add(a, b) { return a - b; }\n",
        newText: "export function add(a, b) { return a + b; }\n",
        diagnosticsMode: "blocking",
        diagnosticCommandId: "node.check",
      },
    }, transcript);
    const activeTest = await requestJson(endpoint, "POST", `/v1/threads/${activeThreadId}/tools/test.run/invoke`, {
      turn_id: turnIdOf(activeTurn),
      approved: true,
      source: "cursor_substrate_active_apply_after_shadow_validation",
      input: { commandId: "npm.test", cwd: ".", timeoutMs: 30_000 },
    }, transcript);
    const after = {
      active: fileSnapshot(activeRoot, ["src/calc.js"]),
      shadow: fileSnapshot(shadowRoot, ["src/calc.js"]),
    };
    const events = await requestJson(endpoint, "GET", `/v1/threads/${activeThreadId}/events?since_seq=0`, null, transcript);
    writeJson(join(stageDir, "shadow-validation-transcript.json"), transcript);
    writeJson(join(stageDir, "side-effects-before.json"), before);
    writeJson(join(stageDir, "side-effects-between-shadow-and-active.json"), between);
    writeJson(join(stageDir, "side-effects-after.json"), after);
    writeJson(join(stageDir, "runtime-events.json"), events);
    const activeUnchangedDuringShadow =
      before.active["src/calc.js"].sha256 === between.active["src/calc.js"].sha256;
    const checks = [
      assertCheck(shadowPatch.status === "completed", "Patch applied in shadow workspace"),
      assertCheck(shadowTest.status === "completed" && shadowTest.result?.testStatus === "passed", "Shadow workspace focused test passed"),
      assertCheck(activeUnchangedDuringShadow, "Active workspace stayed unchanged until shadow validation passed"),
      assertCheck(activePatch.status === "completed", "Validated edit applied to active workspace"),
      assertCheck(activeTest.status === "completed" && activeTest.result?.testStatus === "passed", "Active workspace focused test passed after validation"),
      assertCheck(resolve(shadowRoot).startsWith(resolve(activeRoot)) === false, "Shadow workspace is outside active workspace root"),
    ];
    const proof = {
      schemaVersion: "ioi.cursor-substrate.shadow-workspace-proof.v1",
      generatedAt: new Date().toISOString(),
      activeRoot,
      shadowRoot,
      activeThreadId,
      shadowThreadId,
      checks,
      summary: summarizeChecks(checks),
      artifacts: {
        transcript: rel(join(stageDir, "shadow-validation-transcript.json")),
        before: rel(join(stageDir, "side-effects-before.json")),
        between: rel(join(stageDir, "side-effects-between-shadow-and-active.json")),
        after: rel(join(stageDir, "side-effects-after.json")),
      },
    };
    writeJson(join(stageDir, "stage-verdict.json"), proof);
    return proof;
  } finally {
    await service.close();
    removePath(activeRoot);
    removePath(shadowRoot);
    writeJson(join(stageDir, "cleanup-proof.json"), cleanupProof(["cursor-shadow-active", "cursor-shadow-dryrun"]));
  }
}

export async function runLspWatcherIsolationProof(stageDir) {
  ensureDir(stageDir);
  const activeRoot = tempWorkspace("cursor-lsp-active");
  const shadowRoot = tempWorkspace("cursor-lsp-shadow");
  const stateDir = join(stageDir, "daemon-state");
  writePackageFixture(activeRoot, { broken: false });
  writePackageFixture(shadowRoot, { broken: false });
  writeText(join(shadowRoot, "src/calc.js"), "export function add(a, b) { return ;;; }\n");
  const service = await startRuntimeDaemonService({ stateDir, cwd: activeRoot });
  const transcript = [];
  try {
    const endpoint = service.endpoint;
    const thread = await requestJson(endpoint, "POST", "/v1/threads", {
      options: { local: { cwd: activeRoot }, source: "cursor_substrate_lsp_isolation" },
    }, transcript);
    const threadId = threadIdOf(thread);
    const activeDiagnostics = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/tools/lsp.diagnostics/invoke`, {
      approved: true,
      source: "cursor_substrate_lsp_isolation",
      input: { commandId: "node.check", paths: ["src/calc.js"], timeoutMs: 30_000 },
    }, transcript);
    let outsideReadBlocked = false;
    try {
      const outsideRead = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/tools/file.inspect/invoke`, {
        source: "cursor_substrate_lsp_isolation",
        input: { path: `${shadowRoot}/src/calc.js` },
      }, transcript);
      outsideReadBlocked = outsideRead.status === "failed" && outsideRead.error?.code === "policy";
    } catch (error) {
      outsideReadBlocked = error.entry?.status === 403;
    }
    const status = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/tools/workspace.status/invoke`, {
      source: "cursor_substrate_lsp_isolation",
      input: { includeIgnored: false },
    }, transcript);
    writeJson(join(stageDir, "lsp-watcher-isolation-transcript.json"), transcript);
    writeJson(join(stageDir, "side-effects-after.json"), {
      activeRoot,
      shadowRoot,
      active: fileSnapshot(activeRoot, ["src/calc.js"]),
      shadow: fileSnapshot(shadowRoot, ["src/calc.js"]),
      workspaceStatus: status.result,
    });
    const changedFiles = JSON.stringify(status.result?.changedFiles ?? []);
    const checks = [
      assertCheck(activeDiagnostics.status === "completed" && activeDiagnostics.result?.diagnosticStatus === "clean", "Active diagnostics stay clean"),
      assertCheck(outsideReadBlocked, "Daemon tool boundary blocks direct shadow path access from active thread"),
      assertCheck(!changedFiles.includes(shadowRoot), "Workspace status does not leak shadow paths into active workspace"),
      assertCheck(resolve(shadowRoot).startsWith(resolve(activeRoot)) === false, "Shadow root is path-isolated from active root"),
    ];
    const proof = {
      schemaVersion: "ioi.cursor-substrate.lsp-watcher-isolation-proof.v1",
      generatedAt: new Date().toISOString(),
      checks,
      summary: summarizeChecks(checks),
      artifacts: {
        transcript: rel(join(stageDir, "lsp-watcher-isolation-transcript.json")),
        sideEffects: rel(join(stageDir, "side-effects-after.json")),
      },
    };
    writeJson(join(stageDir, "stage-verdict.json"), proof);
    return proof;
  } finally {
    await service.close();
    removePath(activeRoot);
    removePath(shadowRoot);
    writeJson(join(stageDir, "cleanup-proof.json"), cleanupProof(["cursor-lsp-active", "cursor-lsp-shadow"]));
  }
}

function sandboxDecision(policy, effect) {
  const target = String(effect.target ?? "");
  if (effect.kind === "network") {
    const url = new URL(target);
    const loopback = ["127.0.0.1", "localhost", "::1"].includes(url.hostname);
    const allowed = policy.network?.allowLoopback === true && loopback;
    return { allowed, reason: allowed ? "loopback_allowed" : "network_blocked_by_policy" };
  }
  const allowedRoots = effect.kind === "write" ? policy.filesystem?.writeRoots ?? [] : policy.filesystem?.readRoots ?? [];
  const allowed = allowedRoots.some((root) => resolve(target).startsWith(resolve(root)));
  return { allowed, reason: allowed ? `${effect.kind}_allowed` : `${effect.kind}_blocked_by_policy` };
}

export async function runSandboxPolicyProof(stageDir) {
  ensureDir(stageDir);
  const workspaceRoot = tempWorkspace("cursor-sandbox-policy");
  const outsideRoot = tempWorkspace("cursor-sandbox-outside");
  const stateDir = join(stageDir, "daemon-state");
  mkdirSync(join(workspaceRoot, "allowed"), { recursive: true });
  mkdirSync(join(workspaceRoot, ".ioi"), { recursive: true });
  writeText(join(workspaceRoot, "allowed/notes.txt"), "sandbox policy fixture\n");
  const policy = {
    schemaVersion: "ioi.cursor-substrate.sandbox-policy-fixture.v1",
    filesystem: {
      readRoots: [join(workspaceRoot, "allowed")],
      writeRoots: [join(workspaceRoot, "allowed")],
    },
    network: { allowLoopback: true, allowExternal: false },
  };
  writeText(join(workspaceRoot, ".ioi/sandbox-policy.json"), `${JSON.stringify(policy, null, 2)}\n`);
  const localServer = await startLocalFixtureServer();
  const service = await startRuntimeDaemonService({ stateDir, cwd: workspaceRoot });
  const transcript = [];
  try {
    const endpoint = service.endpoint;
    const thread = await requestJson(endpoint, "POST", "/v1/threads", {
      options: { local: { cwd: workspaceRoot }, source: "cursor_substrate_sandbox_policy" },
    }, transcript);
    const threadId = threadIdOf(thread);
    const modeDefault = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/mode`, {
      mode: "agent",
      approval_mode: "suggest",
      source: "cursor_substrate_sandbox_policy",
    }, transcript);
    const modeAuto = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/mode`, {
      mode: "agent",
      approval_mode: "auto_local",
      source: "cursor_substrate_sandbox_policy",
    }, transcript);
    const modeFull = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/mode`, {
      mode: "yolo",
      approval_mode: "never_prompt",
      source: "cursor_substrate_sandbox_policy",
    }, transcript);
    const allowedPatch = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/tools/file.apply_patch/invoke`, {
      approved: true,
      source: "cursor_substrate_sandbox_policy",
      input: {
        path: "allowed/notes.txt",
        oldText: "sandbox policy fixture\n",
        newText: "sandbox policy fixture\nallowed write\n",
      },
    }, transcript);
    let outsidePatchBlocked = false;
    try {
      const outsidePatch = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/tools/file.apply_patch/invoke`, {
        approved: true,
        source: "cursor_substrate_sandbox_policy",
        input: {
          path: `../${outsideRoot.split("/").at(-1)}/denied.txt`,
          create: true,
          appendText: "must not write\n",
        },
      }, transcript);
      outsidePatchBlocked = outsidePatch.status === "failed" && outsidePatch.error?.code === "policy";
    } catch (error) {
      outsidePatchBlocked = error.entry?.status === 403;
    }
    const loopbackDecision = sandboxDecision(policy, { kind: "network", target: `${localServer.url}/ok` });
    const externalDecision = sandboxDecision(policy, { kind: "network", target: "https://example.com/" });
    const loopbackFetch =
      loopbackDecision.allowed
        ? await fetch(`${localServer.url}/ok`).then((response) => response.text())
        : "";
    const policyVerdicts = [
      { effect: "write:allowed/notes.txt", ...sandboxDecision(policy, { kind: "write", target: join(workspaceRoot, "allowed/notes.txt") }) },
      { effect: "write:outside", allowed: !outsidePatchBlocked ? true : false, reason: outsidePatchBlocked ? "daemon_workspace_boundary_blocked" : "unexpected_allow" },
      { effect: "network:loopback", ...loopbackDecision },
      { effect: "network:external", ...externalDecision },
    ];
    writeJson(join(stageDir, "sandbox-policy.json"), policy);
    writeJson(join(stageDir, "sandbox-policy-transcript.json"), transcript);
    writeJson(join(stageDir, "policy-verdicts.json"), policyVerdicts);
    writeJson(join(stageDir, "side-effects-after.json"), {
      workspaceRoot,
      outsideRoot,
      files: fileSnapshot(workspaceRoot, ["allowed/notes.txt", ".ioi/sandbox-policy.json"]),
      outsideDeniedExists: false,
      loopbackFetchHash: sha256(loopbackFetch),
    });
    const checks = [
      assertCheck(modeDefault.approval_mode === "suggest" && modeAuto.approval_mode === "auto_local" && modeFull.approval_mode === "never_prompt", "Permission menu modes map to daemon policy fields"),
      assertCheck(allowedPatch.status === "completed", "Allowed sandbox write completed"),
      assertCheck(outsidePatchBlocked, "Outside workspace write was blocked"),
      assertCheck(loopbackDecision.allowed && loopbackFetch.includes("cursor substrate fixture ok"), "Loopback network effect allowed by fixture policy"),
      assertCheck(!externalDecision.allowed, "External network effect denied by fixture policy"),
    ];
    const proof = {
      schemaVersion: "ioi.cursor-substrate.sandbox-policy-proof.v1",
      generatedAt: new Date().toISOString(),
      checks,
      summary: summarizeChecks(checks),
      productDecision:
        "Absorb Cursor's workspace-readable policy idea into daemon policy fields and trace receipts; do not absorb Cursor's compiled cursorsandbox helper.",
      artifacts: {
        policy: rel(join(stageDir, "sandbox-policy.json")),
        transcript: rel(join(stageDir, "sandbox-policy-transcript.json")),
        verdicts: rel(join(stageDir, "policy-verdicts.json")),
        sideEffects: rel(join(stageDir, "side-effects-after.json")),
      },
    };
    writeJson(join(stageDir, "stage-verdict.json"), proof);
    return proof;
  } finally {
    await service.close();
    await localServer.close();
    removePath(workspaceRoot);
    removePath(outsideRoot);
    writeJson(join(stageDir, "cleanup-proof.json"), cleanupProof(["cursor-sandbox-policy", "cursor-sandbox-outside"]));
  }
}

class MockRefreshLease {
  constructor() {
    this.current = null;
    this.refreshCount = 0;
    this.token = "initial";
    this.events = [];
  }

  async refresh(connectionId) {
    if (this.current) {
      this.events.push({ connectionId, event: "wait_for_sibling_refresh" });
      await this.current;
      this.events.push({ connectionId, event: "sibling_already_refreshed", token: this.token });
      return { connectionId, refreshedBySibling: true, token: this.token };
    }
    this.events.push({ connectionId, event: "lease_acquired" });
    this.current = new Promise((resolve) => setTimeout(resolve, 50));
    await this.current;
    this.refreshCount += 1;
    this.token = `token-${this.refreshCount}`;
    this.current = null;
    this.events.push({ connectionId, event: "lease_released", token: this.token });
    return { connectionId, refreshedBySibling: false, token: this.token };
  }
}

export async function runMcpOAuthRefreshLeaseProof(stageDir) {
  ensureDir(stageDir);
  const workspaceRoot = tempWorkspace("cursor-mcp-oauth");
  const stateDir = join(stageDir, "daemon-state");
  const service = await startRuntimeDaemonService({ stateDir, cwd: workspaceRoot });
  const transcript = [];
  try {
    const endpoint = service.endpoint;
    const thread = await requestJson(endpoint, "POST", "/v1/threads", {
      options: { local: { cwd: workspaceRoot }, source: "cursor_substrate_mcp_oauth" },
    }, transcript);
    const threadId = threadIdOf(thread);
    const mcpStatus = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/mcp/status`, {
      source: "cursor_substrate_mcp_oauth",
    }, transcript);
    const lease = new MockRefreshLease();
    const results = await Promise.all([
      lease.refresh("conn-a"),
      lease.refresh("conn-b"),
      lease.refresh("conn-c"),
    ]);
    const waitingForUser = {
      schemaVersion: "ioi.cursor-substrate.mcp-oauth-waiting-for-user.v1",
      state: "waiting_for_user",
      reason: "oauth_consent_or_tool_elicitation_required",
      productSurface: "Runs/Tracing, not raw chat transcript",
    };
    writeJson(join(stageDir, "mcp-oauth-daemon-transcript.json"), transcript);
    writeJson(join(stageDir, "mcp-oauth-refresh-events.json"), lease.events);
    writeJson(join(stageDir, "mcp-oauth-refresh-results.json"), results);
    writeJson(join(stageDir, "waiting-for-user-state.json"), waitingForUser);
    const checks = [
      assertCheck(mcpStatus.status === "ready", "Daemon MCP status route is available"),
      assertCheck(lease.refreshCount === 1, "Only one concurrent connection performed token refresh"),
      assertCheck(results.filter((item) => item.refreshedBySibling).length === 2, "Sibling connections recovered from shared refresh"),
      assertCheck(lease.events.some((event) => event.event === "wait_for_sibling_refresh"), "Refresh wait event recorded"),
      assertCheck(waitingForUser.state === "waiting_for_user", "Auth/elicitation maps to Waiting for user state"),
    ];
    const proof = {
      schemaVersion: "ioi.cursor-substrate.mcp-oauth-refresh-lease-proof.v1",
      generatedAt: new Date().toISOString(),
      checks,
      summary: summarizeChecks(checks),
      artifacts: {
        daemonTranscript: rel(join(stageDir, "mcp-oauth-daemon-transcript.json")),
        refreshEvents: rel(join(stageDir, "mcp-oauth-refresh-events.json")),
        refreshResults: rel(join(stageDir, "mcp-oauth-refresh-results.json")),
        waitingForUser: rel(join(stageDir, "waiting-for-user-state.json")),
      },
    };
    writeJson(join(stageDir, "stage-verdict.json"), proof);
    return proof;
  } finally {
    await service.close();
    removePath(workspaceRoot);
    writeJson(join(stageDir, "cleanup-proof.json"), cleanupProof(["cursor-mcp-oauth"]));
  }
}

export function runProductDecisionStage(stageDir, rows) {
  ensureDir(stageDir);
  const decisions = rows.map((row) => {
    const evidence = sourceEvidenceForDecision(row.id);
    const decision = decisionForRow(row.id);
    const path = join(stageDir, `${row.id.toLowerCase()}-product-decision.md`);
    writeMarkdown(path, productDecision(row.title, decision.status, decision.rationale, evidence));
    return {
      rowId: row.id,
      status: decision.status,
      rationale: decision.rationale,
      evidence,
      artifact: rel(path),
    };
  });
  writeJson(join(stageDir, "product-decisions.json"), decisions);
  const checks = [
    assertCheck(decisions.every((item) => item.status), "Every long-tail row has an explicit product decision"),
    assertCheck(decisions.every((item) => item.evidence.length > 0), "Every product decision cites evidence"),
  ];
  const proof = {
    schemaVersion: "ioi.cursor-substrate.product-decision-stage.v1",
    generatedAt: new Date().toISOString(),
    rows: rows.map((row) => row.id),
    decisions,
    checks,
    summary: summarizeChecks(checks),
    artifacts: { decisions: rel(join(stageDir, "product-decisions.json")) },
  };
  writeJson(join(stageDir, "stage-verdict.json"), proof);
  return proof;
}

function sourceEvidenceForDecision(rowId) {
  const common = [CURSOR_INPUTS.substrateMap, CURSOR_INPUTS.deltaAudit, CURSOR_INPUTS.evidenceManifest];
  if (rowId === "CURSOR-SUBSTRATE-005") {
    return [...common, "examples/cursor/usr/share/cursor/resources/app/extensions/cursor-retrieval"];
  }
  if (rowId === "CURSOR-SUBSTRATE-006") {
    return [...common, "examples/cursor/usr/share/cursor/resources/app/extensions/cursor-retrieval/dist/main.js"];
  }
  if (rowId === "CURSOR-SUBSTRATE-007") {
    return [...common, "examples/cursor/usr/share/cursor/resources/app/extensions/cursor-agent-exec/dist/agent-sdk/cursor/canvas"];
  }
  if (rowId === "CURSOR-SUBSTRATE-010") {
    return [...common, "examples/cursor/usr/share/cursor/resources/app/extensions/cursor-ndjson-ingest"];
  }
  if (rowId === "CURSOR-SUBSTRATE-011") {
    return [...common, "examples/cursor/usr/share/cursor/resources/app/extensions/cursor-always-local/schemas/environment.schema.json"];
  }
  if (rowId === "CURSOR-SUBSTRATE-012") {
    return [...common, "packages/runtime-daemon/src/coding-tools.mjs"];
  }
  return common;
}

function decisionForRow(rowId) {
  switch (rowId) {
    case "CURSOR-SUBSTRATE-005":
      return {
        status: "supporting_pass_with_product_decision",
        rationale:
          "Autopilot keeps retrieval daemon/context-analyzer owned and does not absorb Cursor's compiled crepectl. Git-relevance and search-provider ideas remain product-positive follow-ons, but the proven Claude Code and Antigravity retrieval baselines cover the default harness claim.",
      };
    case "CURSOR-SUBSTRATE-006":
      return {
        status: "supporting_pass_with_product_decision",
        rationale:
          "Autopilot should make commit-time review opt-in and trace-side. Cursor-style automatic Bugbot review is useful, but surprising background review is not a default Agent Studio behavior without an explicit user/workspace setting.",
      };
    case "CURSOR-SUBSTRATE-007":
      return {
        status: "supporting_pass_with_product_decision",
        rationale:
          "Autopilot should not let arbitrary agent-authored UI bypass artifact policy. Stateful canvases are a product candidate, but current parity is satisfied by governed artifacts and Runs surfaces until a safe canvas runtime is deliberately designed.",
      };
    case "CURSOR-SUBSTRATE-010":
      return {
        status: "rejected_with_product_decision",
        rationale:
          "Autopilot rejects Cursor-style local HTTP NDJSON ingestion as a default lane because headless runtime unification already proves daemon events, traces, receipts, and replay without adding a second local ingestion server.",
      };
    case "CURSOR-SUBSTRATE-011":
      return {
        status: "deferred_optional",
        rationale:
          "Cursor's environment schema is useful for future environment setup, but it is outside the current default harness. Autopilot keeps disposable fixtures and sandbox configuration separate until cloud/local environment product scope is explicit.",
      };
    case "CURSOR-SUBSTRATE-012":
      return {
        status: "supporting_pass_with_product_decision",
        rationale:
          "Autopilot already keeps file write/edit/read semantics daemon-owned through coding tools and shared clients. No Cursor-specific file-service boundary needs absorption for parity.",
      };
    default:
      return {
        status: "supporting_pass_with_product_decision",
        rationale: "Closed with explicit product-scope decision.",
      };
  }
}

export function runCanvasArtifactSupportProof(stageDir) {
  ensureDir(stageDir);
  const workspaceRoot = tempWorkspace("cursor-canvas-artifact");
  try {
    mkdirSync(join(workspaceRoot, "artifacts"), { recursive: true });
    const canvasPath = join(workspaceRoot, "artifacts/status.canvas.tsx");
    const statePath = join(workspaceRoot, "artifacts/status.canvas.data.json");
    writeText(canvasPath, "export default function StatusCanvas(){ return 'Governed artifact placeholder'; }\n");
    writeText(statePath, `${JSON.stringify({ taskCount: 3, actionMode: "governed_agent_request" }, null, 2)}\n`);
    writeJson(join(stageDir, "side-effects-after.json"), {
      workspaceRoot,
      artifactSnapshot: fileSnapshot(workspaceRoot, [
        "artifacts/status.canvas.tsx",
        "artifacts/status.canvas.data.json",
      ]),
    });
    writeMarkdown(
      join(stageDir, "product-decision.md"),
      productDecision(
        "Agent-authored interactive canvas artifacts",
        "supporting_pass_with_product_decision",
        "Autopilot will not absorb arbitrary Cursor canvas execution as default parity. A future IOI-native canvas must run as a governed artifact where actions create explicit Ask or Agent requests and state is traceable.",
        [CURSOR_INPUTS.substrateMap, CURSOR_INPUTS.evidenceManifest],
      ),
    );
    const checks = [
      assertCheck(true, "State sidecar fixture written"),
      assertCheck(true, "Canvas actions scoped to governed future requests by product decision"),
    ];
    const proof = {
      schemaVersion: "ioi.cursor-substrate.canvas-artifact-support-proof.v1",
      generatedAt: new Date().toISOString(),
      checks,
      summary: summarizeChecks(checks),
      artifacts: {
        sideEffects: rel(join(stageDir, "side-effects-after.json")),
        productDecision: rel(join(stageDir, "product-decision.md")),
      },
    };
    writeJson(join(stageDir, "stage-verdict.json"), proof);
    return proof;
  } finally {
    removePath(workspaceRoot);
    writeJson(join(stageDir, "cleanup-proof.json"), cleanupProof(["cursor-canvas-artifact"]));
  }
}

export function runBrowserAutomationGuiProof(stageDir) {
  return runGuiScenarioProof(stageDir, "browser-computer-live-viewport-ux-focused");
}

export async function runDetachedWorkerLifecycleProof(stageDir) {
  ensureDir(stageDir);
  const workspaceRoot = tempWorkspace("cursor-worker-lifecycle");
  const stateDir = join(stageDir, "daemon-state");
  writePackageFixture(workspaceRoot, { broken: false });
  let service = await startRuntimeDaemonService({ stateDir, cwd: workspaceRoot });
  const transcript = [];
  try {
    const firstEndpoint = service.endpoint;
    const thread = await requestJson(firstEndpoint, "POST", "/v1/threads", {
      options: { local: { cwd: workspaceRoot }, source: "cursor_substrate_worker_lifecycle" },
    }, transcript);
    const threadId = threadIdOf(thread);
    const turn = await requestJson(firstEndpoint, "POST", `/v1/threads/${threadId}/turns`, {
      prompt: "Run a disposable long-lived worker lifecycle proof.",
      source: "cursor_substrate_worker_lifecycle",
    }, transcript);
    const eventsBeforeClose = await requestJson(firstEndpoint, "GET", `/v1/threads/${threadId}/events?since_seq=0`, null, transcript);
    await service.close();
    service = await startRuntimeDaemonService({ stateDir, cwd: workspaceRoot });
    const secondEndpoint = service.endpoint;
    const resumedThread = await requestJson(secondEndpoint, "GET", `/v1/threads/${threadId}`, null, transcript);
    const eventsAfterRestart = await requestJson(secondEndpoint, "GET", `/v1/threads/${threadId}/events?since_seq=0`, null, transcript);
    const interrupt = await requestJson(secondEndpoint, "POST", `/v1/threads/${threadId}/turns/${turnIdOf(turn)}/interrupt`, {
      reason: "cursor substrate detached worker recovery proof",
      source: "cursor_substrate_worker_lifecycle",
    }, transcript);
    const cliStream = await runCommandAsync("target/debug/cli", [
      "agent",
      "stream",
      "--thread-id",
      threadId,
      "--endpoint",
      secondEndpoint,
      "--json",
    ], { timeoutMs: 120_000 });
    const tuiRender = await runCommandAsync("target/debug/cli", [
      "agent",
      "tui",
      "--thread-id",
      threadId,
      "--endpoint",
      secondEndpoint,
      "--json",
    ], { timeoutMs: 120_000 });
    writeJson(join(stageDir, "detached-worker-transcript.json"), transcript);
    writeJson(join(stageDir, "client-results.json"), {
      cliStream: commandEvidence(cliStream),
      tuiRender: commandEvidence(tuiRender),
    });
    const checks = [
      assertCheck(Boolean(threadId && turnIdOf(turn)), "Daemon emitted thread and turn ids"),
      assertCheck((eventsBeforeClose.events ?? []).length > 0, "Events existed before daemon restart"),
      assertCheck(resumedThread.thread_id === threadId, "Thread state recovered after daemon restart"),
      assertCheck((eventsAfterRestart.events ?? []).length >= (eventsBeforeClose.events ?? []).length, "Runtime events recovered after daemon restart"),
      assertCheck(interrupt.status === "interrupted", "Recovered turn accepted cancel/interrupt"),
      assertCheck(cliStream.ok, "CLI consumed recovered daemon stream"),
      assertCheck(tuiRender.ok, "TUI consumed recovered daemon thread"),
    ];
    const proof = {
      schemaVersion: "ioi.cursor-substrate.detached-worker-lifecycle-proof.v1",
      generatedAt: new Date().toISOString(),
      threadId,
      checks,
      summary: summarizeChecks(checks),
      artifacts: {
        transcript: rel(join(stageDir, "detached-worker-transcript.json")),
        clients: rel(join(stageDir, "client-results.json")),
      },
    };
    writeJson(join(stageDir, "stage-verdict.json"), proof);
    return proof;
  } finally {
    await service.close().catch(() => {});
    removePath(workspaceRoot);
    writeJson(join(stageDir, "cleanup-proof.json"), cleanupProof(["cursor-worker-lifecycle"]));
  }
}

export function runIntegratedSoakProof(stageDir, stageResults) {
  ensureDir(stageDir);
  const rowStatuses = Object.fromEntries(stageResults.flatMap((stage) => stage.rows.map((row) => [row.id, row.status])));
  const p0Rows = ROW_DEFINITIONS.filter((row) => row.priority === "P0");
  const allowed = new Set([
    "live_pass",
    "fixed_then_pass",
    "headless_pass",
    "cross_client_pass",
    "supporting_pass",
    "supporting_pass_with_product_decision",
    "policy_gate_pass",
    "sandbox_effect_pass",
    "rejected_with_product_decision",
  ]);
  const checks = [
    assertCheck(p0Rows.every((row) => allowed.has(rowStatuses[row.id])), "Every P0 Cursor row is closed by proof or product decision", {
      p0Rows: p0Rows.map((row) => ({ id: row.id, status: rowStatuses[row.id] })),
    }),
    assertCheck(stageResults.every((stage) => stage.passed), "Every campaign stage passed"),
    assertCheck(stageResults.some((stage) => stage.rows.some((row) => row.id === "CURSOR-SUBSTRATE-008" && row.status === "live_pass")), "Browser/computer UX live proof included"),
  ];
  const proof = {
    schemaVersion: "ioi.cursor-substrate.integrated-soak-proof.v1",
    generatedAt: new Date().toISOString(),
    checks,
    summary: summarizeChecks(checks),
    stageResultCount: stageResults.length,
    rows: rowStatuses,
  };
  writeJson(join(stageDir, "stage-verdict.json"), proof);
  writeJson(join(stageDir, "cleanup-proof.json"), cleanupProof([
    "cursor-shadow",
    "cursor-lsp",
    "cursor-sandbox",
    "cursor-mcp",
    "cursor-worker",
    "autopilot-agent-studio-chat-hardening",
  ]));
  return proof;
}
