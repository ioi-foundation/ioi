import { existsSync } from "node:fs";
import { join } from "node:path";
import {
  assertCheck,
  readText,
  rel,
  repoRoot,
  summarizeChecks,
  writeJson,
} from "./common.mjs";

export const REQUIRED_ROWS = [
  {
    id: "HRU-001",
    priority: "P0",
    capability: "Agent turn contract",
    owner: "Runtime daemon / Agent SDK / CLI / TUI / Agent Studio",
  },
  {
    id: "HRU-002",
    priority: "P0",
    capability: "Ask vs Agent separation",
    owner: "Runtime daemon routing and Agent Studio client adapter",
  },
  {
    id: "HRU-003",
    priority: "P0",
    capability: "Tool execution and file mutation",
    owner: "Runtime daemon coding tool pack",
  },
  {
    id: "HRU-004",
    priority: "P0",
    capability: "Runtime events, traces, receipts, replay",
    owner: "Runtime daemon evidence runtime",
  },
  {
    id: "HRU-005",
    priority: "P0",
    capability: "Policy modes and approvals",
    owner: "Runtime daemon policy runtime and Agent Studio approval menu",
  },
  {
    id: "HRU-006",
    priority: "P0",
    capability: "Context analyzer and compaction",
    owner: "Runtime daemon context runtime",
  },
  {
    id: "HRU-007",
    priority: "P1",
    capability: "Hook lifecycle",
    owner: "Runtime daemon hook projection / product decision",
  },
  {
    id: "HRU-008",
    priority: "P0",
    capability: "Delegation, subagents, and tasks",
    owner: "Runtime daemon subagent/task manager",
  },
  {
    id: "HRU-009",
    priority: "P0",
    capability: "Retained shell lifecycle",
    owner: "Headless Rust runtime system executor",
  },
  {
    id: "HRU-010",
    priority: "P0",
    capability: "MCP and deferred tool discovery",
    owner: "Runtime daemon MCP manager",
  },
  {
    id: "HRU-011",
    priority: "P0",
    capability: "Browser/computer managed sessions",
    owner: "Runtime daemon computer-use projection and Agent Studio viewport UX",
  },
  {
    id: "HRU-012",
    priority: "P0",
    capability: "Stop, cancel, recover",
    owner: "Runtime daemon operator controls",
  },
  {
    id: "HRU-013",
    priority: "P0",
    capability: "Latency and simple-turn timing",
    owner: "Runtime daemon / Agent Studio client adapter",
  },
  {
    id: "HRU-014",
    priority: "P0",
    capability: "SDK shared client adapter",
    owner: "Agent SDK",
  },
  {
    id: "HRU-015",
    priority: "P0",
    capability: "CLI client adapter",
    owner: "CLI",
  },
  {
    id: "HRU-016",
    priority: "P0",
    capability: "TUI client adapter",
    owner: "TUI",
  },
  {
    id: "HRU-017",
    priority: "P0",
    capability: "Cross-client golden scenarios",
    owner: "Runtime daemon plus SDK/CLI/TUI/GUI clients",
  },
];

const sources = {
  daemon: "packages/runtime-daemon/src/index.mjs",
  sdk: "packages/agent-sdk/src/substrate-client.ts",
  sdkEvents: "packages/agent-sdk/src/runtime-events.ts",
  cli: "crates/cli/src/commands/agent.rs",
  tui: "crates/cli/src/commands/agent_tui.rs",
  tuiEvents: "crates/cli/src/commands/agent_event_stream.rs",
  gui: "workbench-adapters/ioi-workbench/extension.js",
  workSummary: "workbench-adapters/ioi-workbench/studio-work-summary.js",
  rustToolTypes: "crates/types/src/app/agentic/tools/agent_tool.rs",
  rustShell: "crates/services/src/agentic/runtime/execution/system/sys_exec.rs",
  rustSubstrate: "crates/services/src/agentic/runtime/substrate.rs",
};

function sourceText(key) {
  const path = join(repoRoot, sources[key]);
  return existsSync(path) ? readText(path) : "";
}

function has(text, needle) {
  return text.includes(needle);
}

function every(text, needles) {
  return needles.every((needle) => has(text, needle));
}

function sourceEvidence(key) {
  return existsSync(join(repoRoot, sources[key])) ? sources[key] : `${sources[key]} (missing)`;
}

export function inspectOwnership(outputPath) {
  const daemon = sourceText("daemon");
  const sdk = sourceText("sdk");
  const sdkEvents = sourceText("sdkEvents");
  const cli = sourceText("cli");
  const tui = sourceText("tui");
  const tuiEvents = sourceText("tuiEvents");
  const gui = sourceText("gui");
  const workSummary = sourceText("workSummary");
  const rustToolTypes = sourceText("rustToolTypes");
  const rustShell = sourceText("rustShell");
  const rustSubstrate = sourceText("rustSubstrate");

  const checks = [
    assertCheck(has(daemon, "export async function startRuntimeDaemonService"), "daemon exposes headless service"),
    assertCheck(every(daemon, ["/v1/threads", "/v1/threads/{id}/usage", "/v1/runs/{id}/events", "/v1/runs/{id}/trace"]), "daemon exposes threads/runs evidence routes"),
    assertCheck(every(daemon, ["action === \"tools\"", "invokeThreadToolAsync", "file.apply_patch"]), "daemon owns tool invocation route"),
    assertCheck(every(daemon, ["action === \"approvals\"", "decideThreadApproval", "revokeThreadApproval"]), "daemon owns approvals"),
    assertCheck(every(daemon, ["action === \"subagents\"", "spawnSubagent", "waitSubagent", "cancelSubagent"]), "daemon owns subagents"),
    assertCheck(every(daemon, ["action === \"mcp\"", "searchThreadMcpTools", "invokeThreadMcpTool"]), "daemon owns thread MCP"),
    assertCheck(every(daemon, ["action === \"memory\"", "rememberForThread", "memoryPolicyForThread"]), "daemon owns thread memory"),
    assertCheck(every(daemon, ["ioi.computer_use.browser_discovery", "ioi.computer_use.control", "ioi.computer_use.visual_gui.observe"]), "daemon owns computer-use projections"),
    assertCheck(every(sdk, ["createRuntimeSubstrateClient", "submitTurn", "invokeThreadTool", "threadMcpStatus", "threadMemoryStatus", "discoverComputerUseProviders"]), "SDK exposes canonical daemon client"),
    assertCheck(has(sdkEvents, "runtimeThreadEventFromEnvelope"), "SDK maps runtime event envelope"),
    assertCheck(every(cli, ["CODING_TOOLS_ROUTE", "CODING_TOOL_INVOKE_ROUTE_TEMPLATE", "COMPUTER_USE_BROWSER_DISCOVERY_ROUTE"]), "CLI invokes daemon tool/browser routes"),
    assertCheck(has(tui, "TUI_PRIVATE_RUNTIME_LOOP: bool = false"), "TUI explicitly has no private runtime loop"),
    assertCheck(every(tui, ["TUI_TURN_CREATE_ROUTE_TEMPLATE", "TUI_EVENT_STREAM_ROUTE_TEMPLATE", "TUI_CODING_TOOL_INVOKE_ROUTE_TEMPLATE", "TUI_THREAD_MCP_STATUS_ROUTE_TEMPLATE"]), "TUI consumes daemon routes"),
    assertCheck(every(tuiEvents, ["/v1/threads/{id}/events", "/v1/runs/{id}/events"]), "CLI/TUI event stream command consumes daemon event streams"),
    assertCheck(every(gui, ["ensureStudioDaemonThread", "submitStudioAgentTurn", "invokeStudioDaemonTool", "applyStudioPermissionModeSelection"]), "GUI routes through daemon adapter"),
    assertCheck(every(gui, ["chat__reply", "Agent Mode completed without additional assistant text"]), "GUI enforces Agent final reply contract"),
    assertCheck(every(workSummary, ["chat__reply", "Used ${actionToolNames.length} daemon tool", "summaryParts.push"]), "work-summary capsule filters product chat tool noise"),
    assertCheck(every(rustToolTypes, ["shell__start", "shell__status", "shell__input", "shell__terminate", "shell__reset"]), "Rust tool contract defines retained shell controls"),
    assertCheck(every(rustShell, ["COMMAND_HISTORY", "ToolUnavailable", "TimeoutOrHang"]), "headless Rust runtime owns retained shell executor receipts and failure classes"),
    assertCheck(has(rustSubstrate, "shell__start") && every(rustToolTypes, ["shell__status", "shell__input", "shell__terminate"]), "Rust substrate advertises retained shell tools"),
  ];

  const ownership = {
    "HRU-001": "daemon_owned",
    "HRU-002": "shared_client_adapter",
    "HRU-003": "daemon_owned",
    "HRU-004": "daemon_owned",
    "HRU-005": "daemon_owned",
    "HRU-006": "daemon_owned",
    "HRU-007": "daemon_owned",
    "HRU-008": "daemon_owned",
    "HRU-009": "daemon_owned",
    "HRU-010": "daemon_owned",
    "HRU-011": "daemon_owned",
    "HRU-012": "daemon_owned",
    "HRU-013": "shared_client_adapter",
    "HRU-014": "shared_client_adapter",
    "HRU-015": "shared_client_adapter",
    "HRU-016": "shared_client_adapter",
    "HRU-017": "daemon_owned",
  };

  const evidence = {
    schemaVersion: "ioi.autopilot.headless-runtime-unification.ownership.v1",
    generatedAt: new Date().toISOString(),
    sources: Object.fromEntries(Object.keys(sources).map((key) => [key, sourceEvidence(key)])),
    checks,
    summary: summarizeChecks(checks),
    rows: REQUIRED_ROWS.map((row) => ({
      ...row,
      ownership: ownership[row.id],
      evidence: Object.values(sources).filter((value) => !value.includes("(missing)")),
    })),
  };

  writeJson(outputPath, evidence);
  return {
    passed: evidence.summary.passed,
    outputPath: rel(outputPath),
    checks,
    rows: evidence.rows,
  };
}
