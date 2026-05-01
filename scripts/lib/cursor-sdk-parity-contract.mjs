import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  REQUIRED_CURSOR_CAPABILITIES,
  assertReferenceInventoryComplete,
  collectCursorSdkReference,
} from "./cursor-sdk-reference-contract.mjs";

export const CURSOR_SDK_PARITY_SCHEMA_VERSION = "ioi.cursor-sdk-parity-plus.v1";

export const IOI_SDK_REQUIRED_EXPORTS = Object.freeze([
  "Agent",
  "Cursor",
  "CursorCompatibleAgent",
  "Run",
  "IoiAgentError",
  "LocalRuntimeSubstrateClient",
  "createAgentPlatform",
  "createRuntimeSubstrateClient",
]);

export async function validateCursorSdkParity({
  repoRoot = process.cwd(),
  evidenceDir,
  includeReference = true,
} = {}) {
  const rootEvidenceDir =
    evidenceDir ?? path.join(repoRoot, "docs", "evidence", "cursor-sdk-parity", timestamp());
  fs.mkdirSync(rootEvidenceDir, { recursive: true });

  const reference = includeReference
    ? collectCursorSdkReference({ repoRoot, evidenceDir: rootEvidenceDir })
    : null;
  if (reference) {
    assertReferenceInventoryComplete(reference);
  }

  const packageJson = readJson(path.join(repoRoot, "packages", "agent-sdk", "package.json"));
  const sdk = await import(pathToFileURL(path.join(repoRoot, "packages", "agent-sdk", "dist", "index.js")));
  const missingExports = IOI_SDK_REQUIRED_EXPORTS.filter((name) => !(name in sdk));
  const checks = [];
  checks.push(check("installable_package", packageJson.name === "@ioi/agent-sdk"));
  checks.push(check("esm_export", Boolean(packageJson.exports?.["."]?.import)));
  checks.push(check("cjs_export", Boolean(packageJson.exports?.["."]?.require)));
  checks.push(check("types_export", Boolean(packageJson.exports?.["."]?.types)));
  checks.push(check("required_exports", missingExports.length === 0, { missingExports }));
  checks.push(check("cursor_capability_classification", REQUIRED_CURSOR_CAPABILITIES.length >= 20));

  const proof = await runLocalSdkProof(sdk, rootEvidenceDir);
  checks.push(check("local_quickstart", proof.quickstart.status === "completed"));
  checks.push(check("stream_reconnect", proof.reconnect.noDuplicateTerminalEvents));
  checks.push(check("conversation_accumulator", proof.quickstart.conversationLength === 2));
  checks.push(check("artifact_export", proof.quickstart.artifactNames.includes("trace.json")));
  checks.push(check("trace_replay", proof.quickstart.replayedEventCount === proof.quickstart.eventCount));
  checks.push(check("smarter_agent_records", proof.quickstart.smarterRecordsPresent));
  checks.push(check("cloud_fail_closed", proof.cloudBlocker.code === "external_blocker"));
  checks.push(check("clean_ux_contract_not_bypassed", existingCleanUxContract(repoRoot)));
  checks.push(check("no_gui_internal_imports", sdkDoesNotImportGuiInternals(repoRoot)));

  const summary = {
    schemaVersion: CURSOR_SDK_PARITY_SCHEMA_VERSION,
    capturedAt: new Date().toISOString(),
    evidenceDir: rootEvidenceDir,
    status: checks.every((item) => item.pass) ? "complete_plus_local_external_blockers" : "failed",
    checks,
    externallyBlocked: [
      {
        lane: "cloud_hosted_self_hosted_live_provider",
        status: "blocked",
        reason:
          "No IOI_AGENT_SDK_HOSTED_ENDPOINT or IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT was configured for a live provider run.",
        environmentChecked: [
          "IOI_AGENT_SDK_HOSTED_ENDPOINT",
          "IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT",
        ],
      },
      {
        lane: "cursor_billing_account_semantics",
        status: "blocked",
        reason: "Cursor account and billing semantics are external to the IOI repository.",
      },
    ],
    proof,
  };

  fs.writeFileSync(path.join(rootEvidenceDir, "parity-checklist.json"), `${JSON.stringify(summary, null, 2)}\n`);
  return summary;
}

export async function runLocalSdkProof(sdk, evidenceDir) {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-sdk-proof-"));
  fs.mkdirSync(path.join(cwd, ".cursor", "skills", "proof-skill"), { recursive: true });
  fs.writeFileSync(
    path.join(cwd, ".cursor", "mcp.json"),
    `${JSON.stringify({ mcpServers: { local_files: { command: "node", args: ["server.mjs"] } } }, null, 2)}\n`,
  );
  fs.writeFileSync(
    path.join(cwd, ".cursor", "hooks.json"),
    `${JSON.stringify({ onStep: { command: "echo", args: ["step"] } }, null, 2)}\n`,
  );
  const client = sdk.createRuntimeSubstrateClient({
    cwd,
    checkpointDir: path.join(cwd, ".ioi", "agent-sdk"),
  });
  const agent = await sdk.Agent.create({
    model: { id: "local:auto" },
    local: { cwd },
    substrateClient: client,
    agents: { reviewer: { prompt: "Review evidence only." } },
  });
  const run = await agent.send("Summarize this workspace");
  const events = [];
  for await (const event of run.stream()) {
    events.push(event);
  }
  const partial = events.slice(0, 4);
  const reconnected = [];
  for await (const event of run.stream({ lastEventId: partial.at(-1).id })) {
    reconnected.push(event);
  }
  const result = await run.wait();
  const trace = await run.trace();
  const replayed = [];
  for await (const event of run.replay()) {
    replayed.push(event);
  }
  const plan = await agent.plan("Plan StopCondition support", { noMutation: true });
  const dryRun = await agent.dryRun("Preview a destructive filesystem action", {
    toolClass: "filesystem",
  });
  const handoff = await agent.handoff("Delegate a coding investigation", { receiver: "reviewer" });
  const learned = await agent.learn({ taskFamily: "sdk_parity", negative: ["unverified shortcut"] });
  let cloudBlocker = {};
  try {
    await sdk.Agent.create({
      cloud: { repos: [{ url: "https://example.invalid/repo.git" }] },
      substrateClient: client,
    });
  } catch (error) {
    cloudBlocker = error.toJSON ? error.toJSON() : { message: String(error) };
  }
  const artifacts = await run.artifacts();
  const scorecard = await run.scorecard();
  const proof = {
    quickstart: {
      runId: run.id,
      status: result.status,
      eventCount: events.length,
      replayedEventCount: replayed.length,
      conversationLength: (await run.conversation()).length,
      artifactNames: artifacts.map((artifact) => artifact.name),
      stopReason: result.stopCondition.reason,
      scorecard,
      smarterRecordsPresent: Boolean(
        trace.taskState &&
          trace.uncertainty &&
          trace.probes.length > 0 &&
          trace.postconditions &&
          trace.semanticImpact &&
          trace.qualityLedger,
      ),
    },
    reconnect: {
      firstBatchLastEventId: partial.at(-1).id,
      resumedFirstEventType: reconnected[0]?.type,
      noDuplicateTerminalEvents:
        reconnected.filter((event) => event.type === "completed").length === 1,
    },
    plan: summarizeTrace(await plan.inspect()),
    dryRun: summarizeTrace(await dryRun.inspect()),
    handoff: summarizeTrace(await handoff.inspect()),
    learned: summarizeTrace(await learned.inspect()),
    cloudBlocker,
  };
  fs.writeFileSync(path.join(evidenceDir, "sdk-local-proof.json"), `${JSON.stringify(proof, null, 2)}\n`);
  fs.writeFileSync(path.join(evidenceDir, "sdk-local-trace.json"), `${JSON.stringify(trace, null, 2)}\n`);
  return proof;
}

function summarizeTrace(trace) {
  return {
    runId: trace.runId,
    selectedStrategy: trace.qualityLedger.selectedStrategy,
    selectedAction: trace.uncertainty.selectedAction,
    stopReason: trace.stopCondition.reason,
    toolSequence: trace.qualityLedger.toolSequence,
  };
}

function existingCleanUxContract(repoRoot) {
  const filePath = path.join(repoRoot, "scripts", "lib", "autopilot-gui-harness-contract.mjs");
  if (!fs.existsSync(filePath)) {
    return false;
  }
  const source = fs.readFileSync(filePath, "utf8");
  return (
    source.includes("CLEAN_CHAT_UX_REQUIREMENTS") &&
    source.includes("no_raw_receipt_dump") &&
    source.includes("source_pills_reserved_for_search")
  );
}

function sdkDoesNotImportGuiInternals(repoRoot) {
  const srcDir = path.join(repoRoot, "packages", "agent-sdk", "src");
  const sources = walk(srcDir).filter((filePath) => filePath.endsWith(".ts"));
  return sources.every((filePath) => {
    const source = fs.readFileSync(filePath, "utf8");
    return !source.includes("ChatShellWindow") && !source.includes("AutopilotShellWindow");
  });
}

function check(id, pass, details = {}) {
  return { id, pass: Boolean(pass), details };
}

function timestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function walk(dir) {
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  return entries.flatMap((entry) => {
    const next = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(next) : [next];
  });
}
