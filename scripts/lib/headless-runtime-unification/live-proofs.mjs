import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { startRuntimeDaemonService } from "../../../packages/runtime-daemon/src/index.mjs";
import { createRuntimeSubstrateClient } from "../../../packages/agent-sdk/dist/index.js";
import {
  assertCheck,
  cleanupProof,
  commandEvidence,
  ensureDir,
  newestDirectory,
  parseMaybeJson,
  rel,
  repoRoot,
  requestJson,
  runCommand,
  runCommandAsync,
  summarizeChecks,
  writeJson,
  writeJsonl,
} from "./common.mjs";

function threadIdOf(record) {
  return record.thread_id ?? record.threadId ?? record.id ?? record.thread?.id;
}

function turnIdOf(record) {
  return record.turn_id ?? record.turnId ?? record.id ?? record.turn?.id;
}

function runIdOf(record) {
  return record.request_id ?? record.run_id ?? record.runId ?? record.run?.id;
}

function approvalIdOf(record) {
  const approval = record.approval ?? record.pending_approval ?? record.pendingApproval;
  return record.approval_id ?? record.approvalId ?? approval?.id ?? approval?.approval_id ??
    record.approvals?.at?.(-1)?.approval_id ?? record.approvals?.at?.(-1)?.id;
}

function subagentIdOf(record) {
  return record.subagent_id ?? record.subagentId ?? record.agent_id ?? record.agentId;
}

function taskIdOf(record) {
  return record.taskId ?? record.task_id ?? record.runId ?? record.run_id;
}

function writeTranscript(stageDir, name, rows) {
  writeJson(join(stageDir, `${name}.json`), rows);
}

export async function runHeadlessDaemonProof(stageDir) {
  ensureDir(stageDir);
  const stateDir = join(stageDir, "daemon-state");
  const workspaceRoot = mkdtempSync(join(tmpdir(), "hru-headless-ws-"));
  const sourceDir = join(workspaceRoot, "src");
  ensureDir(sourceDir);
  writeFileSync(join(sourceDir, "calc.js"), "export function add(a,b){ return a+b; }\n");
  writeFileSync(join(workspaceRoot, "delete-me.txt"), "delete me\n");
  writeFileSync(join(workspaceRoot, "package.json"), JSON.stringify({
    type: "module",
    scripts: { check: "node --check src/calc.js" },
  }, null, 2));

  const transcript = [];
  const service = await startRuntimeDaemonService({ stateDir, cwd: workspaceRoot });
  let closed = false;
  const startedAt = Date.now();
  try {
    const endpoint = service.endpoint;
    const thread = await requestJson(endpoint, "POST", "/v1/threads", {
      options: {
        local: { cwd: workspaceRoot },
        source: "headless_runtime_unification",
        title: "Headless runtime unification fixture",
        mode: "agent",
      },
    }, transcript);
    const threadId = threadIdOf(thread);
    const modeSuggest = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/mode`, {
      mode: "agent",
      approval_mode: "suggest",
      source: "headless_runtime_unification",
    }, transcript);
    const modeAuto = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/mode`, {
      mode: "agent",
      approval_mode: "auto_local",
      source: "headless_runtime_unification",
    }, transcript);
    const modeFull = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/mode`, {
      mode: "yolo",
      approval_mode: "never_prompt",
      source: "headless_runtime_unification",
    }, transcript);
    const turn = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/turns`, {
      prompt:
        "Fix the disposable calc.js spacing, verify the syntax check, and summarize the change.",
      input:
        "Fix the disposable calc.js spacing, verify the syntax check, and summarize the change.",
      source: "headless_runtime_unification",
    }, transcript);
    const turnId = turnIdOf(turn);
    const runId = runIdOf(turn);
    const eventsBeforeTools = await requestJson(endpoint, "GET", `/v1/threads/${threadId}/events?since_seq=0`, null, transcript);
    const toolCatalog = await requestJson(endpoint, "GET", "/v1/tools?pack=coding", null, transcript);
    const workspaceStatus = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/tools/workspace.status/invoke`, {
      input: { includeIgnored: false },
      turn_id: turnId,
      source: "headless_runtime_unification",
    }, transcript);
    const patchResult = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/tools/file.apply_patch/invoke`, {
      input: {
        path: "src/calc.js",
        oldText: "export function add(a,b){ return a+b; }\n",
        newText: "export function add(a, b) { return a + b; }\n",
      },
      turn_id: turnId,
      approved: true,
      source: "headless_runtime_unification",
    }, transcript);
    const createResult = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/tools/file.apply_patch/invoke`, {
      input: {
        path: "notes.txt",
        appendText: "headless runtime unification fixture\n",
        create: true,
      },
      turn_id: turnId,
      approved: true,
      source: "headless_runtime_unification",
    }, transcript);
    const testRun = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/tools/test.run/invoke`, {
      input: { commandId: "npm.test", cwd: ".", timeoutMs: 30_000 },
      turn_id: turnId,
      approved: true,
      source: "headless_runtime_unification",
    }, transcript);
    const approval = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/approvals`, {
      summary: "Headless runtime unification disposable policy gate",
      action: "file.apply_patch",
      risk: "low",
      source: "headless_runtime_unification",
    }, transcript);
    const approvalId = approvalIdOf(approval);
    const approvalDecision = approvalId
      ? await requestJson(endpoint, "POST", `/v1/threads/${threadId}/approvals/${approvalId}/decision`, {
          decision: "approve",
          rationale: "disposable fixture mutation",
          source: "headless_runtime_unification",
        }, transcript)
      : null;
    const contextBudget = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/context-budget`, {
      usage: { totalTokens: 3200, maxTotalTokens: 128000 },
      source: "headless_runtime_unification",
    }, transcript);
    const compactionPolicy = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/compaction-policy`, {
      usage: { totalTokens: 3200, maxTotalTokens: 128000 },
      source: "headless_runtime_unification",
    }, transcript);
    const compact = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/compact`, {
      reason: "headless runtime unification compaction proof",
      source: "headless_runtime_unification",
    }, transcript);
    const memoryStatus = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/memory/status`, {
      source: "headless_runtime_unification",
    }, transcript);
    const memoryWrite = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/memory`, {
      fact: "Headless runtime unification fixture memory",
      memoryKey: "hru.fixture",
      source: "headless_runtime_unification",
      approved: true,
    }, transcript);
    const memoryList = await requestJson(endpoint, "GET", `/v1/threads/${threadId}/memory`, null, transcript);
    const memoryRecordId = memoryWrite.record?.id ?? memoryWrite.record_id ?? memoryList.records?.[0]?.id;
    const memoryEdit = memoryRecordId
      ? await requestJson(endpoint, "PATCH", `/v1/threads/${threadId}/memory/${memoryRecordId}`, {
          fact: "Headless runtime unification fixture memory edited",
          source: "headless_runtime_unification",
        }, transcript)
      : null;
    const memoryDelete = memoryRecordId
      ? await requestJson(endpoint, "DELETE", `/v1/threads/${threadId}/memory/${memoryRecordId}`, {
          source: "headless_runtime_unification",
        }, transcript)
      : null;
    const mcpStatus = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/mcp/status`, {
      source: "headless_runtime_unification",
    }, transcript);
    const mcpSearch = await requestJson(endpoint, "GET", `/v1/threads/${threadId}/mcp/tools/search?q=fixture&limit=5`, null, transcript);
    const mcpValidate = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/mcp/validate`, {
      source: "headless_runtime_unification",
    }, transcript);
    const subagent = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/subagents`, {
      role: "verifier",
      prompt: "Verify the disposable calc.js fixture was repaired.",
      output_contract: { type: "summary" },
      source: "headless_runtime_unification",
    }, transcript);
    const subagentId = subagentIdOf(subagent);
    const subagentWait = subagentId
      ? await requestJson(endpoint, "POST", `/v1/threads/${threadId}/subagents/${subagentId}/wait`, {
          timeout_ms: 10_000,
          source: "headless_runtime_unification",
        }, transcript)
      : null;
    const subagentResult = subagentId
      ? await requestJson(endpoint, "GET", `/v1/threads/${threadId}/subagents/${subagentId}/result`, null, transcript)
      : null;
    const task = await requestJson(endpoint, "POST", "/v1/tasks", {
      cwd: workspaceRoot,
      prompt: "Run a disposable headless task for runtime unification proof.",
      mode: "send",
      source: "headless_runtime_unification",
    }, transcript);
    const taskId = taskIdOf(task);
    const taskList = await requestJson(endpoint, "GET", "/v1/tasks", null, transcript);
    const taskCancel = taskId
      ? await requestJson(endpoint, "POST", `/v1/tasks/${taskId}/cancel`, {
          source: "headless_runtime_unification",
        }, transcript)
      : null;
    const jobList = await requestJson(endpoint, "GET", "/v1/jobs", null, transcript);
    const browserDiscovery = await requestJson(endpoint, "GET", "/v1/computer-use/browser-discovery?probe=false&include_tabs=false", null, transcript);
    const providers = await requestJson(endpoint, "GET", "/v1/computer-use/providers", null, transcript);
    const threadBrowserDiscovery = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/tools/ioi.computer_use.browser_discovery/invoke`, {
      input: { probe: false, include_tabs: false },
      source: "headless_runtime_unification",
    }, transcript);
    const computerPause = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/tools/ioi.computer_use.control/invoke`, {
      input: {
        action: "pause",
        lane: "native_browser",
        session_mode: "owned_hermetic_browser",
        reason: "waiting for user handoff proof",
      },
      source: "headless_runtime_unification",
    }, transcript);
    const computerResume = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/tools/ioi.computer_use.control/invoke`, {
      input: {
        action: "resume",
        lane: "native_browser",
        session_mode: "owned_hermetic_browser",
        resume_observation_ref: "observation_hru_fixture_after_user",
      },
      source: "headless_runtime_unification",
    }, transcript);
    const computerObserve = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/tools/ioi.computer_use.visual_gui.observe/invoke`, {
      input: {
        lane: "visual_gui",
        session_mode: "desktop",
        goal: "Observe the disposable GUI state for headless unification proof.",
      },
      source: "headless_runtime_unification",
    }, transcript);
    const steer = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/turns/${turnId}/steer`, {
      guidance: "Keep the proof focused on daemon-owned runtime contracts.",
      source: "headless_runtime_unification",
    }, transcript);
    const interrupt = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/turns/${turnId}/interrupt`, {
      reason: "headless runtime unification stop/cancel proof",
      source: "headless_runtime_unification",
    }, transcript);
    const resume = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/resume`, null, transcript);
    const runEvents = runId
      ? await requestJson(endpoint, "GET", `/v1/runs/${runId}/events`, null, transcript)
      : null;
    const runTrace = runId
      ? await requestJson(endpoint, "GET", `/v1/runs/${runId}/trace`, null, transcript)
      : null;
    const runReplay = runId
      ? await requestJson(endpoint, "GET", `/v1/runs/${runId}/replay`, null, transcript)
      : null;
    const eventsAfter = await requestJson(endpoint, "GET", `/v1/threads/${threadId}/events?since_seq=0`, null, transcript);

    const calcText = readFileSync(join(sourceDir, "calc.js"), "utf8");
    const notesText = readFileSync(join(workspaceRoot, "notes.txt"), "utf8");
    const sideEffects = {
      workspaceRoot,
      calcText,
      notesText,
      deleteMeStillExists: (() => {
        try {
          readFileSync(join(workspaceRoot, "delete-me.txt"), "utf8");
          return true;
        } catch {
          return false;
        }
      })(),
    };
    const allEvents = eventsAfter.events ?? [];
    writeJsonl(join(stageDir, "runtime-events.jsonl"), allEvents);
    writeTranscript(stageDir, "headless-api-transcript", transcript);
    writeJson(join(stageDir, "side-effects-after.json"), sideEffects);

    const checks = [
      assertCheck(Boolean(threadId && turnId && runId), "thread, turn, and run ids emitted", { threadId, turnId, runId }),
      assertCheck((eventsBeforeTools.events ?? []).length > 0 && allEvents.length >= (eventsBeforeTools.events ?? []).length, "thread runtime events stream is readable"),
      assertCheck(modeSuggest.approval_mode === "suggest" && modeAuto.approval_mode === "auto_local" && modeFull.approval_mode === "never_prompt", "permission modes map to daemon approval modes"),
      assertCheck(Array.isArray(toolCatalog) && toolCatalog.some((tool) => tool.stableToolId === "file.apply_patch"), "coding tool catalogue exposed by daemon"),
      assertCheck(workspaceStatus.status === "completed", "workspace status tool completed"),
      assertCheck(patchResult.status === "completed" && calcText.includes("add(a, b)"), "file edit mutation completed inside disposable fixture"),
      assertCheck(createResult.status === "completed" && notesText.includes("headless runtime unification"), "file create mutation completed inside disposable fixture"),
      assertCheck(testRun.status === "completed", "focused syntax test completed"),
      assertCheck(Boolean(approvalId && approvalDecision), "approval gate and decision emitted"),
      assertCheck(Boolean(contextBudget.schema_version || contextBudget.schemaVersion) && Boolean(compactionPolicy.schema_version || compactionPolicy.schemaVersion) && compact.latest_seq >= thread.latest_seq, "context budget and compaction routes completed"),
      assertCheck(memoryStatus.status === "ready" && Boolean(memoryWrite) && Boolean(memoryEdit) && Boolean(memoryDelete), "memory status/write/edit/delete completed"),
      assertCheck(mcpStatus.status === "ready" && Boolean(mcpSearch) && Boolean(mcpValidate), "MCP status/search/validate completed"),
      assertCheck(Boolean(subagentId && subagentWait && subagentResult), "subagent spawn/wait/result completed"),
      assertCheck(Boolean(taskId && taskList && taskCancel && jobList), "task/job list and cancel surfaces completed"),
      assertCheck(Boolean(browserDiscovery.receipt_ref && providers.providers?.length), "computer-use discovery/provider registry completed"),
      assertCheck(threadBrowserDiscovery.status === "completed" && computerPause.status === "completed" && computerResume.status === "completed" && computerObserve.status === "completed", "computer-use thread tools emitted managed-session artifacts"),
      assertCheck(Boolean(computerPause.result?.human_handoff_state || computerPause.result?.humanHandoffState), "computer-use waiting-for-user handoff state emitted"),
      assertCheck(steer.status === "completed" || steer.status === "interrupted" || Boolean(steer.output_item_ids), "steer control accepted"),
      assertCheck(interrupt.status === "interrupted" && Boolean(resume.thread_id), "interrupt and resume controls accepted"),
      assertCheck(Boolean(runEvents && runTrace && runReplay), "run events, trace, and replay routes completed"),
      assertCheck(Date.now() - startedAt < 30_000, "simple headless proof stayed under 30s", { durationMs: Date.now() - startedAt }),
    ];
    const summary = summarizeChecks(checks);
    const proof = {
      schemaVersion: "ioi.autopilot.headless-runtime-unification.headless-daemon-proof.v1",
      generatedAt: new Date().toISOString(),
      endpoint,
      stateDir: rel(stateDir),
      workspaceRoot,
      threadId,
      turnId,
      runId,
      checks,
      summary,
      artifacts: {
        transcript: rel(join(stageDir, "headless-api-transcript.json")),
        runtimeEvents: rel(join(stageDir, "runtime-events.jsonl")),
        sideEffects: rel(join(stageDir, "side-effects-after.json")),
      },
    };
    writeJson(join(stageDir, "stage-verdict.json"), proof);
    return proof;
  } finally {
    if (!closed) {
      await service.close();
      closed = true;
    }
    writeJson(join(stageDir, "cleanup-proof.json"), cleanupProof([
      "hru-headless",
      "autopilot-headless-runtime-unification",
    ]));
  }
}

export async function runSdkClientProof(stageDir) {
  ensureDir(stageDir);
  const stateDir = join(stageDir, "daemon-state");
  const workspaceRoot = mkdtempSync(join(tmpdir(), "hru-sdk-ws-"));
  writeFileSync(join(workspaceRoot, "fixture.js"), "export const value = 1;\n");
  const service = await startRuntimeDaemonService({ stateDir, cwd: workspaceRoot });
  const transcript = [];
  try {
    const client = createRuntimeSubstrateClient({ endpoint: service.endpoint });
    const thread = await client.createThread({
      options: {
        local: { cwd: workspaceRoot },
        source: "headless_runtime_unification_sdk",
      },
    });
    const threadId = threadIdOf(thread);
    transcript.push({ method: "createThread", thread });
    const mode = await client.updateThreadMode(threadId, { approval_mode: "never_prompt", mode: "yolo" });
    transcript.push({ method: "updateThreadMode", mode });
    const turn = await client.submitTurn(threadId, {
      prompt: "Use the disposable SDK fixture and reply briefly.",
      input: "Use the disposable SDK fixture and reply briefly.",
      source: "headless_runtime_unification_sdk",
    });
    transcript.push({ method: "submitTurn", turn });
    const events = [];
    for await (const event of client.streamThreadEvents(threadId, { sinceSeq: 0 })) {
      events.push(event);
    }
    transcript.push({ method: "streamThreadEvents", eventCount: events.length });
    const tools = await client.listTools({ pack: "coding" });
    const patch = await client.invokeThreadTool(threadId, "file.apply_patch", {
      input: {
        path: "fixture.js",
        oldText: "export const value = 1;\n",
        newText: "export const value = 2;\n",
      },
      approved: true,
      turn_id: turnIdOf(turn),
    });
    const mcp = await client.threadMcpStatus(threadId, {});
    const memory = await client.threadMemoryStatus(threadId, {});
    const browser = await client.discoverComputerUseBrowsers({ probe: false, includeTabs: false });
    const providers = await client.discoverComputerUseProviders();
    const compact = await client.compactThread(threadId, { reason: "SDK headless runtime proof" });
    const interrupt = await client.interruptTurn(threadId, turnIdOf(turn), { reason: "SDK interrupt proof" });
    transcript.push({ method: "listTools", count: tools.length });
    transcript.push({ method: "invokeThreadTool", patch });
    transcript.push({ method: "threadMcpStatus", mcp });
    transcript.push({ method: "threadMemoryStatus", memory });
    transcript.push({ method: "computerUse", browser, providers });
    transcript.push({ method: "compactThread", compact });
    transcript.push({ method: "interruptTurn", interrupt });

    writeJson(join(stageDir, "sdk-transcript.json"), transcript);
    const checks = [
      assertCheck(Boolean(threadId && turnIdOf(turn)), "SDK created thread and submitted turn"),
      assertCheck(events.length > 0, "SDK streamed daemon runtime events"),
      assertCheck(tools.some((tool) => tool.stableToolId === "file.apply_patch"), "SDK listed daemon coding tools"),
      assertCheck(patch.status === "completed", "SDK invoked daemon tool route"),
      assertCheck(mcp.status === "ready" && memory.status === "ready", "SDK consumed daemon MCP and memory routes"),
      assertCheck(Boolean(browser.receipt_ref && providers.providers?.length), "SDK consumed daemon computer-use routes"),
      assertCheck(compact.thread_id === threadId && interrupt.status === "interrupted", "SDK compact/interrupt controls reached daemon"),
    ];
    const proof = {
      schemaVersion: "ioi.autopilot.headless-runtime-unification.sdk-proof.v1",
      generatedAt: new Date().toISOString(),
      endpoint: service.endpoint,
      threadId,
      checks,
      summary: summarizeChecks(checks),
      artifacts: { transcript: rel(join(stageDir, "sdk-transcript.json")) },
    };
    writeJson(join(stageDir, "stage-verdict.json"), proof);
    return proof;
  } finally {
    await service.close();
    writeJson(join(stageDir, "cleanup-proof.json"), cleanupProof(["hru-sdk", "autopilot-headless-runtime-unification"]));
  }
}

export async function runCliTuiClientProof(stageDir) {
  ensureDir(stageDir);
  const stateDir = join(stageDir, "daemon-state");
  const workspaceRoot = mkdtempSync(join(tmpdir(), "hru-cli-tui-ws-"));
  writeFileSync(join(workspaceRoot, "index.js"), "console.log('headless runtime unification');\n");
  const service = await startRuntimeDaemonService({ stateDir, cwd: workspaceRoot });
  const transcript = [];
  try {
    const endpoint = service.endpoint;
    const thread = await requestJson(endpoint, "POST", "/v1/threads", {
      options: { local: { cwd: workspaceRoot }, source: "headless_runtime_unification_cli_tui" },
    }, transcript);
    const threadId = threadIdOf(thread);
    const turn = await requestJson(endpoint, "POST", `/v1/threads/${threadId}/turns`, {
      prompt: "Inspect the disposable CLI/TUI fixture and reply briefly.",
      input: "Inspect the disposable CLI/TUI fixture and reply briefly.",
      source: "headless_runtime_unification_cli_tui",
    }, transcript);
    const turnId = turnIdOf(turn);
    const cliCoding = await runCommandAsync("target/debug/cli", ["agent", "tools", "coding", "--endpoint", endpoint, "--json"], { timeoutMs: 120_000 });
    const cliToolRun = await runCommandAsync("target/debug/cli", [
      "agent",
      "tools",
      "run",
      "--thread-id",
      threadId,
      "--path",
      "index.js",
      "--old-text",
      "console.log('headless runtime unification');\n",
      "--new-text",
      "console.log('headless runtime unification via CLI');\n",
      "--endpoint",
      endpoint,
      "--json",
      "file.apply_patch",
    ], { timeoutMs: 120_000 });
    const cliStream = await runCommandAsync("target/debug/cli", ["agent", "stream", "--thread-id", threadId, "--endpoint", endpoint, "--json"], { timeoutMs: 120_000 });
    const cliCompact = await runCommandAsync("target/debug/cli", ["agent", "compact", "--thread-id", threadId, "--endpoint", endpoint, "--json"], { timeoutMs: 120_000 });
    const tuiRender = await runCommandAsync("target/debug/cli", ["agent", "tui", "--thread-id", threadId, "--endpoint", endpoint, "--json"], { timeoutMs: 120_000 });
    const tuiInterrupt = await runCommandAsync("target/debug/cli", [
      "agent",
      "tui",
      "--thread-id",
      threadId,
      "--turn-id",
      turnId,
      "--interrupt",
      "--endpoint",
      endpoint,
      "--json",
    ], { timeoutMs: 120_000 });
    const browserDiscovery = await runCommandAsync("target/debug/cli", ["agent", "tools", "browser-discovery", "--endpoint", endpoint, "--json"], { timeoutMs: 120_000 });

    const commands = {
      cliCoding: commandEvidence(cliCoding),
      cliToolRun: commandEvidence(cliToolRun),
      cliStream: commandEvidence(cliStream),
      cliCompact: commandEvidence(cliCompact),
      tuiRender: commandEvidence(tuiRender),
      tuiInterrupt: commandEvidence(tuiInterrupt),
      browserDiscovery: commandEvidence(browserDiscovery),
    };
    writeJson(join(stageDir, "cli-tui-transcript.json"), {
      daemonTranscript: transcript,
      commands,
    });
    const codingJson = parseMaybeJson(cliCoding.stdout);
    const toolJson = parseMaybeJson(cliToolRun.stdout);
    const streamJson = parseMaybeJson(cliStream.stdout);
    const compactJson = parseMaybeJson(cliCompact.stdout);
    const tuiJson = parseMaybeJson(tuiRender.stdout);
    const interruptJson = parseMaybeJson(tuiInterrupt.stdout);
    const browserJson = parseMaybeJson(browserDiscovery.stdout);
    const checks = [
      assertCheck(cliCoding.ok && Array.isArray(codingJson?.tools) && codingJson.tools.some((tool) => tool.stableToolId === "file.apply_patch"), "CLI listed daemon coding tools"),
      assertCheck(cliToolRun.ok && toolJson?.status === "completed", "CLI invoked daemon tool route"),
      assertCheck(cliStream.ok && (Array.isArray(streamJson?.events) || Array.isArray(streamJson)), "CLI streamed daemon events"),
      assertCheck(cliCompact.ok && compactJson?.thread_id === threadId, "CLI compacted daemon thread"),
      assertCheck(tuiRender.ok && Boolean(tuiJson), "TUI rendered daemon thread in JSON mode"),
      assertCheck(tuiInterrupt.ok && (interruptJson?.thread?.status === "interrupted" || interruptJson?.control?.status === "interrupted"), "TUI interrupted daemon turn"),
      assertCheck(browserDiscovery.ok && Boolean(browserJson?.browser_discovery_report?.receipt_ref || browserJson?.receipt_ref || browserJson?.object), "CLI consumed daemon computer-use discovery route"),
    ];
    const proof = {
      schemaVersion: "ioi.autopilot.headless-runtime-unification.cli-tui-proof.v1",
      generatedAt: new Date().toISOString(),
      endpoint,
      threadId,
      turnId,
      checks,
      summary: summarizeChecks(checks),
      artifacts: { transcript: rel(join(stageDir, "cli-tui-transcript.json")) },
    };
    writeJson(join(stageDir, "stage-verdict.json"), proof);
    return proof;
  } finally {
    await service.close();
    writeJson(join(stageDir, "cleanup-proof.json"), cleanupProof(["hru-cli-tui", "autopilot-headless-runtime-unification"]));
  }
}

export function runRustRetainedShellProof(stageDir) {
  ensureDir(stageDir);
  const command = runCommand("cargo", [
    "test",
    "-p",
    "ioi-cli",
    "--test",
    "reliability_suite_e2e",
    "sys_exec_session_continuity_reset_failure_receipts_and_anti_loop",
    "--",
    "--ignored",
    "--nocapture",
  ], {
    timeoutMs: 420_000,
    maxBuffer: 20 * 1024 * 1024,
  });
  writeJson(join(stageDir, "command-result.json"), commandEvidence(command));
  const checks = [
    assertCheck(command.ok, "ignored retained shell reliability proof passed", {
      status: command.status,
      stderrPreview: command.stderr.slice(0, 1000),
    }),
    assertCheck(/sys_exec_session_continuity_reset_failure_receipts_and_anti_loop.+ok/s.test(command.stdout), "retained shell continuity/receipt/failure test executed"),
  ];
  const proof = {
    schemaVersion: "ioi.autopilot.headless-runtime-unification.retained-shell-proof.v1",
    generatedAt: new Date().toISOString(),
    checks,
    summary: summarizeChecks(checks),
    artifacts: { commandResult: rel(join(stageDir, "command-result.json")) },
  };
  writeJson(join(stageDir, "stage-verdict.json"), proof);
  writeJson(join(stageDir, "cleanup-proof.json"), cleanupProof(["cargo.*reliability_suite", "shell__start"]));
  return proof;
}

export function runGuiScenarioProof(stageDir, scenarioId) {
  ensureDir(stageDir);
  const evidenceRoot = stageDir;
  const beforeDirs = new Set([]);
  const command = runCommand("node", [
    "scripts/run-autopilot-agent-studio-chat-ux-hardening-goal.mjs",
    "--run",
    "--scenario",
    scenarioId,
  ], {
    timeoutMs: 720_000,
    maxBuffer: 30 * 1024 * 1024,
    env: {
      AUTOPILOT_AGENT_STUDIO_EVIDENCE_ROOT: relative(repoRoot, evidenceRoot),
    },
  });
  const newest = newestDirectory(evidenceRoot, beforeDirs);
  writeJson(join(stageDir, "command-result.json"), commandEvidence(command));
  const proofPath = newest ? join(newest, "proof.json") : null;
  const cleanupPath = newest ? join(newest, "process-cleanup-after-run.json") : null;
  const proofJson = proofPath && existsSync(proofPath) ? parseMaybeJson(readFileSync(proofPath, "utf8")) : null;
  const cleanup = cleanupPath && existsSync(cleanupPath) ? parseMaybeJson(readFileSync(cleanupPath, "utf8")) : null;
  const checks = [
    assertCheck(command.ok, `GUI scenario ${scenarioId} command passed`, {
      status: command.status,
      stderrPreview: command.stderr.slice(0, 1000),
    }),
    assertCheck(Boolean(newest), `GUI scenario ${scenarioId} wrote fresh evidence`),
    assertCheck(Boolean(proofJson), `GUI scenario ${scenarioId} wrote proof.json`),
    assertCheck(Boolean(cleanup), `GUI scenario ${scenarioId} wrote cleanup proof`),
  ];
  const proof = {
    schemaVersion: "ioi.autopilot.headless-runtime-unification.gui-scenario-proof.v1",
    generatedAt: new Date().toISOString(),
    scenarioId,
    checks,
    summary: summarizeChecks(checks),
    childEvidenceDir: newest ? rel(newest) : null,
    artifacts: {
      commandResult: rel(join(stageDir, "command-result.json")),
      proof: newest ? rel(join(newest, "proof.json")) : null,
      cleanup: newest ? rel(join(newest, "process-cleanup-after-run.json")) : null,
    },
  };
  writeJson(join(stageDir, "stage-verdict.json"), proof);
  writeJson(join(stageDir, "cleanup-proof.json"), cleanupProof(["autopilot-agent-studio-chat-hardening", "runtime-agent-service", "chrome.*Tool Catalogue Fixture"]));
  return proof;
}
