import assert from "node:assert/strict";
import { execFile, execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import test from "node:test";
import { promisify } from "node:util";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");
const execFileAsync = promisify(execFile);

async function execFileWithInput(file, args, input, options = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(file, args, options, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
        return;
      }
      resolve({ stdout, stderr });
    });
    child.stdin.end(input);
  });
}

async function importSdk() {
  const bundle = path.join(root, "packages/agent-sdk/dist/index.js");
  const sources = [
    "packages/agent-sdk/src/index.ts",
    "packages/agent-sdk/src/messages.ts",
    "packages/agent-sdk/src/runtime-events.ts",
    "packages/agent-sdk/src/substrate-client.ts",
  ].map((file) => path.join(root, file));
  const bundleMtime = fs.existsSync(bundle) ? fs.statSync(bundle).mtimeMs : 0;
  const sourceIsNewer = sources.some(
    (source) => fs.existsSync(source) && fs.statSync(source).mtimeMs > bundleMtime,
  );
  if (!fs.existsSync(bundle) || sourceIsNewer) {
    execFileSync("npm", ["run", "build", "--workspace=@ioi/agent-sdk"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  }
  return import("../../packages/agent-sdk/dist/index.js");
}

async function importAgentIde() {
  const bundle = path.join(root, "packages/agent-ide/dist/index.es.js");
  const sources = [
    "packages/agent-ide/src/index.ts",
    "packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts",
    "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
  ].map((file) => path.join(root, file));
  const bundleMtime = fs.existsSync(bundle) ? fs.statSync(bundle).mtimeMs : 0;
  const sourceIsNewer = sources.some(
    (source) => fs.existsSync(source) && fs.statSync(source).mtimeMs > bundleMtime,
  );
  if (!fs.existsSync(bundle) || sourceIsNewer) {
    execFileSync("npm", ["run", "build", "--workspace=@ioi/agent-ide"], {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  }
  return import(pathToFileURL(bundle).href);
}

async function collect(iterable) {
  const items = [];
  for await (const item of iterable) items.push(item);
  return items;
}

function terminalCount(events) {
  return events.filter((event) => ["completed", "canceled", "failed", "error"].includes(event.type))
    .length;
}

async function fetchJson(url, options) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}`);
  return response.json();
}

async function fetchSseEvents(url, options = {}) {
  const text = await fetch(url, options).then(async (response) => {
    assert.ok(response.ok, `${response.status} ${response.statusText} for ${url}`);
    return response.text();
  });
  return text
    .trim()
    .split(/\n\n+/)
    .filter(Boolean)
    .map((block) => {
      const data = block
        .split(/\r?\n/)
        .filter((line) => line.startsWith("data:"))
        .map((line) => line.replace(/^data:\s?/, ""))
        .join("\n");
      return JSON.parse(data);
    });
}

function canonicalRuntimeEventCursor(event) {
  return `${event.event_stream_id}:${event.seq}`;
}

function operatorControlContractShape(event) {
  return {
    eventKind: event.event_kind,
    sourceEventKind: event.source_event_kind,
    status: event.status,
    componentKind: event.component_kind,
    workflowNodeId: event.workflow_node_id,
    payloadSchemaVersion: event.payload_schema_version,
  };
}

async function fetchTuiJsonEventRow(cli, endpoint, threadId, eventId) {
  const result = await execFileAsync(
    cli,
    [
      "agent",
      "tui",
      "--thread-id",
      threadId,
      "--since-seq",
      "0",
      "--endpoint",
      endpoint,
      "--json",
    ],
    { cwd: root },
  );
  const payload = JSON.parse(result.stdout);
  const row = payload.event_rows.find((candidate) => candidate.event_id === eventId);
  assert.ok(row, `expected TUI JSON event row for ${eventId}`);
  return row;
}

function assertOperatorControlCrossSurfaceIdentity({
  daemonEvent,
  sdkEvent,
  reactFlowNode,
  tuiRow,
  expected,
}) {
  const cursor = canonicalRuntimeEventCursor(daemonEvent);
  assert.equal(sdkEvent.id, daemonEvent.event_id);
  assert.equal(sdkEvent.cursor, cursor);
  assert.equal(sdkEvent.eventKind, expected.eventKind);
  assert.equal(sdkEvent.sourceEventKind, expected.sourceEventKind);
  assert.equal(sdkEvent.componentKind, expected.componentKind);
  assert.equal(sdkEvent.workflowGraphId, expected.workflowGraphId);
  assert.equal(sdkEvent.workflowNodeId, expected.workflowNodeId);
  assert.equal(sdkEvent.payloadSchemaVersion, expected.payloadSchemaVersion);
  assert.deepEqual(sdkEvent.receiptRefs, daemonEvent.receipt_refs);
  assert.deepEqual(sdkEvent.policyDecisionRefs, daemonEvent.policy_decision_refs);

  assert.equal(reactFlowNode.latestEventId, daemonEvent.event_id);
  assert.equal(reactFlowNode.latestCursor, cursor);
  assert.equal(reactFlowNode.workflowGraphId, expected.workflowGraphId);
  assert.equal(reactFlowNode.workflowNodeId, expected.workflowNodeId);
  assert.equal(reactFlowNode.componentKind, expected.componentKind);
  assert.equal(reactFlowNode.tuiDeepLink.eventId, daemonEvent.event_id);
  assert.equal(reactFlowNode.tuiDeepLink.cursor, cursor);
  assert.equal(reactFlowNode.tuiDeepLink.workflowGraphId, expected.workflowGraphId);
  assert.equal(reactFlowNode.tuiDeepLink.workflowNodeId, expected.workflowNodeId);

  assert.equal(tuiRow.event_id, daemonEvent.event_id);
  assert.equal(tuiRow.cursor, cursor);
  assert.equal(tuiRow.thread_id, daemonEvent.thread_id);
  assert.equal(tuiRow.turn_id, daemonEvent.turn_id);
  assert.equal(tuiRow.workflow_graph_id, expected.workflowGraphId);
  assert.equal(tuiRow.workflow_node_id, expected.workflowNodeId);
  assert.equal(tuiRow.event_kind, expected.eventKind);
  assert.equal(tuiRow.source_event_kind, expected.sourceEventKind);
  assert.equal(tuiRow.component_kind, expected.componentKind);
  assert.deepEqual(tuiRow.tui_reopen.args, [
    "agent",
    "tui",
    "--thread-id",
    daemonEvent.thread_id,
    "--since-seq",
    String(daemonEvent.seq),
  ]);
  assert.equal(tuiRow.tui_reopen.last_event_id, daemonEvent.event_id);
}

async function fetchJsonStatus(url, options) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json" },
    ...options,
  });
  const text = await response.text();
  return {
    status: response.status,
    body: text ? JSON.parse(text) : null,
  };
}

function restoreEnv(name, value) {
  if (value === undefined) {
    delete process.env[name];
  } else {
    process.env[name] = value;
  }
}

function git(cwd, args) {
  return execFileSync("git", ["-C", cwd, ...args], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

let cachedRustRuntimeBridgeBinary;
let cachedCliBinary;

function rustRuntimeBridgeBinary() {
  if (cachedRustRuntimeBridgeBinary) return cachedRustRuntimeBridgeBinary;
  if (process.env.IOI_RUNTIME_BRIDGE_RUST_BIN) {
    const configured = process.env.IOI_RUNTIME_BRIDGE_RUST_BIN;
    const binary = path.isAbsolute(configured) ? configured : path.resolve(root, configured);
    assert.ok(fs.existsSync(binary), `IOI_RUNTIME_BRIDGE_RUST_BIN does not exist: ${binary}`);
    cachedRustRuntimeBridgeBinary = binary;
    return binary;
  }

  execFileSync(
    "cargo",
    ["build", "-p", "ioi-node", "--bin", "ioi-runtime-bridge", "--features", "local-mode"],
    {
      cwd: root,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const binaryName = process.platform === "win32" ? "ioi-runtime-bridge.exe" : "ioi-runtime-bridge";
  const binary = path.join(root, "target", "debug", binaryName);
  assert.ok(fs.existsSync(binary), `expected Rust runtime bridge binary at ${binary}`);
  cachedRustRuntimeBridgeBinary = binary;
  return binary;
}

function cliBinary() {
  if (cachedCliBinary) return cachedCliBinary;
  if (process.env.IOI_CLI_BIN) {
    const configured = process.env.IOI_CLI_BIN;
    const binary = path.isAbsolute(configured) ? configured : path.resolve(root, configured);
    assert.ok(fs.existsSync(binary), `IOI_CLI_BIN does not exist: ${binary}`);
    cachedCliBinary = binary;
    return binary;
  }

  execFileSync("cargo", ["build", "-p", "ioi-cli", "--bin", "cli"], {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  const binaryName = process.platform === "win32" ? "cli.exe" : "cli";
  const binary = path.join(root, "target", "debug", binaryName);
  assert.ok(fs.existsSync(binary), `expected CLI binary at ${binary}`);
  cachedCliBinary = binary;
  return binary;
}

test("local daemon public API persists canonical Agentgres state and replays without terminal duplication", async () => {
  const { Agent, Cursor, createRuntimeSubstrateClient } = await importSdk();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-live-daemon-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-agentgres-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({ local: { cwd }, substrateClient: client });
    const run = await agent.send(
      "Create a local SDK run, cancel it, reconnect, and prove no terminal event was duplicated.",
    );
    const firstBatch = [];
    for await (const event of run.stream()) {
      firstBatch.push(event);
      if (firstBatch.length === 4) break;
    }
    const resumed = await collect(run.stream({ lastEventId: firstBatch.at(-1).id }));
    assert.equal(terminalCount([...firstBatch, ...resumed]), 1);

    const canceled = await run.cancel();
    const canceledReplay = await collect(canceled.replay());
    assert.equal(await canceled.status(), "canceled");
    assert.equal(terminalCount(canceledReplay), 1);
    assert.equal(canceledReplay.at(-1)?.type, "canceled");

    const trace = await canceled.trace();
    assert.equal(trace.canonicalState.source, "agentgres_canonical_operation_log");
    assert.equal(trace.runtimeTask.schemaVersion, "ioi.agent-runtime.task-record.v1");
    assert.equal(trace.runtimeTask.object, "ioi.runtime_task");
    assert.equal(trace.runtimeTask.runId, run.id);
    assert.equal(trace.runtimeTask.status, "canceled");
    assert.equal(trace.runtimeTask.promptIncluded, false);
    assert.equal(trace.runtimeTask.durable, true);
    assert.equal(trace.runtimeTask.replayable, true);
    assert.equal(trace.runtimeJob.schemaVersion, "ioi.agent-runtime.job-record.v1");
    assert.equal(trace.runtimeJob.object, "ioi.runtime_job");
    assert.equal(trace.runtimeJob.runId, run.id);
    assert.equal(trace.runtimeJob.taskId, trace.runtimeTask.taskId);
    assert.equal(trace.runtimeJob.status, "canceled");
    assert.deepEqual(trace.runtimeJob.lifecycle, ["queued", "started", "canceled"]);
    assert.equal(trace.runtimeJob.queueName, "local-agentgres");
    assert.equal(trace.runtimeJob.durable, true);
    assert.equal(trace.runtimeJob.replayable, true);
    assert.equal(trace.runtimeChecklist.schemaVersion, "ioi.agent-runtime.checklist-record.v1");
    assert.equal(trace.runtimeChecklist.object, "ioi.runtime_checklist");
    assert.equal(trace.runtimeChecklist.runId, run.id);
    assert.equal(trace.runtimeChecklist.taskId, trace.runtimeTask.taskId);
    assert.equal(trace.runtimeChecklist.jobId, trace.runtimeJob.jobId);
    assert.equal(trace.runtimeChecklist.status, "canceled");
    assert.ok(trace.runtimeChecklist.itemCount >= 6);
    assert.ok(trace.runtimeChecklist.items.some((item) => item.itemId.endsWith(":job_terminal") && item.status === "canceled"));
    assert.equal(trace.runtimeChecklist.durable, true);
    assert.equal(trace.runtimeChecklist.replayable, true);
    assert.equal(trace.runtimeChecklist.readOnly, true);
    assert.equal(trace.runtimeJob.checklistId, trace.runtimeChecklist.checklistId);
    assert.equal(trace.runtimeJob.checklistStatus, "canceled");
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "agentgres_canonical_write"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "runtime_task"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "runtime_job"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "runtime_checklist"));
    assert.equal((await canceled.scorecard()).verifierIndependence, 1);
    const canceledArtifacts = await canceled.artifacts();
    assert.ok(canceledArtifacts.some((artifact) => artifact.name === "runtime-task.json"));
    assert.ok(canceledArtifacts.some((artifact) => artifact.name === "runtime-job.json"));
    assert.ok(canceledArtifacts.some((artifact) => artifact.name === "runtime-checklist.json"));
    assert.ok(canceledArtifacts.some((artifact) => artifact.name === "agentgres-projection.json"));

    const operationLog = path.join(stateDir, "operation-log.jsonl");
    assert.ok(fs.existsSync(operationLog));
    assert.ok(fs.readFileSync(operationLog, "utf8").includes("run.cancel"));
    for (const relative of [
      ["runs", `${run.id}.json`],
      ["tasks", `${run.id}.json`],
      ["jobs", trace.runtimeJob.jobId + ".json"],
      ["checklists", trace.runtimeChecklist.checklistId + ".json"],
      ["scorecards", `${run.id}.json`],
      ["ledgers", `${run.id}.json`],
      ["projections", `${run.id}.json`],
    ]) {
      assert.ok(fs.existsSync(path.join(stateDir, ...relative)), relative.join("/"));
    }

    const models = await Cursor.models.list({ substrateClient: client });
    assert.equal(models.at(0)?.provider, "ioi-daemon-local");
    const account = await Cursor.account.get({ substrateClient: client });
    assert.equal(account.source, "ioi-daemon-agentgres");
    const nodes = await Cursor.runtimeNodes.list({ substrateClient: client });
    assert.ok(nodes.some((node) => node.id === "local-daemon-agentgres"));

    const jobs = await fetchJson(`${daemon.endpoint}/v1/jobs`);
    assert.equal(jobs.length, 1);
    assert.equal(jobs[0].schemaVersion, "ioi.agent-runtime.job-record.v1");
    assert.equal(jobs[0].jobId, trace.runtimeJob.jobId);
    assert.equal(jobs[0].taskId, trace.runtimeTask.taskId);
    assert.equal(jobs[0].status, "canceled");
    assert.equal(jobs[0].checklistId, trace.runtimeChecklist.checklistId);
    assert.equal(jobs[0].checklistStatus, "canceled");
    assert.equal(jobs[0].endpoints.self, `/v1/jobs/${jobs[0].jobId}`);
    assert.equal(jobs[0].endpoints.cancel, `/v1/jobs/${jobs[0].jobId}/cancel`);
    const job = await fetchJson(`${daemon.endpoint}/v1/jobs/${jobs[0].jobId}`);
    assert.equal(job.jobId, jobs[0].jobId);
    assert.equal(job.runId, run.id);
    const jobCancel = await fetchJson(`${daemon.endpoint}/v1/jobs/${jobs[0].jobId}/cancel`, {
      method: "POST",
      body: "{}",
    });
    assert.equal(jobCancel.jobId, jobs[0].jobId);
    assert.equal(jobCancel.status, "canceled");
    assert.deepEqual(jobCancel.lifecycle, ["queued", "started", "canceled"]);
    assert.equal(jobCancel.cancellation.reason, "operator_cancel");
    assert.equal(jobCancel.checklistId, trace.runtimeChecklist.checklistId);
    assert.equal(jobCancel.checklistStatus, "canceled");
    const traceAfterJobCancel = await fetchJson(`${daemon.endpoint}/v1/runs/${run.id}/trace`);
    assert.equal(terminalCount(traceAfterJobCancel.events), 1);
    assert.equal(traceAfterJobCancel.events.at(-1)?.type, "canceled");
    const threadId = `thread_${agent.id.slice("agent_".length)}`;
    const threadEvents = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${threadId}/events?since_seq=0`);
    const runtimeTaskEvent = threadEvents.find((event) => event.payload_summary?.event_kind === "RuntimeTaskRecord");
    assert.ok(runtimeTaskEvent);
    assert.equal(runtimeTaskEvent.component_kind, "runtime_task");
    assert.equal(runtimeTaskEvent.workflow_node_id, "runtime.runtime-task");
    assert.equal(runtimeTaskEvent.payload_summary.prompt_included, false);
    assert.ok(runtimeTaskEvent.artifact_refs.includes("runtime-task.json"));
    const runtimeChecklistEvent = threadEvents
      .filter((event) => event.payload_summary?.event_kind === "RuntimeChecklistRecord")
      .at(-1);
    assert.ok(runtimeChecklistEvent);
    assert.equal(runtimeChecklistEvent.component_kind, "runtime_checklist");
    assert.equal(runtimeChecklistEvent.workflow_node_id, "runtime.runtime-checklist");
    assert.ok(["completed", "canceled"].includes(runtimeChecklistEvent.payload_summary.status));
    assert.ok(runtimeChecklistEvent.artifact_refs.includes("runtime-checklist.json"));
    const jobQueuedEvent = threadEvents.find((event) => event.payload_summary?.event_kind === "JobQueued");
    const jobStartedEvent = threadEvents.find((event) => event.payload_summary?.event_kind === "JobStarted");
    const jobCompletedEvent = threadEvents.find((event) => event.payload_summary?.event_kind === "JobCompleted");
    const jobCanceledEvent = threadEvents.find((event) => event.payload_summary?.event_kind === "JobCanceled");
    assert.ok(jobQueuedEvent);
    assert.ok(jobStartedEvent);
    assert.ok(jobCanceledEvent);
    if (jobCompletedEvent) assert.ok(jobCompletedEvent.seq < jobCanceledEvent.seq);
    assert.equal(jobQueuedEvent.component_kind, "runtime_job");
    assert.equal(jobStartedEvent.workflow_node_id, "runtime.runtime-job");
    assert.equal(jobCanceledEvent.payload_summary.lifecycle_status, "canceled");
    assert.ok(jobCanceledEvent.artifact_refs.includes("runtime-job.json"));

    const cliView = await fetch(`${daemon.endpoint}/v1/runs/${run.id}/trace`).then((response) =>
      response.json(),
    );
    assert.equal(cliView.canonicalState.runId, run.id);
    assert.equal(cliView.canonicalState.terminalState, "canceled");
  } finally {
    await daemon.close();
  }
});

test("local daemon doctor reports redacted runtime readiness for CLI and workflow activation", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-doctor-daemon-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-doctor-agentgres-state-"));
  const savedOpenAi = process.env.OPENAI_API_KEY;
  const savedHosted = process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
  process.env.OPENAI_API_KEY = "sk-doctor-secret-do-not-print";
  process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT = "https://doctor-secret.example";
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const report = await fetchJson(`${daemon.endpoint}/v1/doctor`);
    assert.equal(report.schemaVersion, "ioi.agent-runtime.doctor.v1");
    assert.equal(report.object, "ioi.agent_runtime_doctor_report");
    assert.equal(report.readiness, "ready");
    assert.ok(["pass", "degraded"].includes(report.status));
    assert.deepEqual(report.blockers, []);
    assert.equal(report.redaction.secretValuesIncluded, false);
    assert.equal(report.redaction.endpointValuesHashed, true);
    assert.equal(report.workflow.doctorNodeType, "runtime_doctor");
    assert.equal(report.workflow.activationConsumesDoctorReport, true);
    assert.ok(report.checks.some((check) => check.id === "daemon.public_api" && check.status === "pass"));
    assert.ok(report.checks.every((check) => !check.required || check.status === "pass"));
    const openAiKey = report.providerKeys.find((key) => key.name === "OPENAI_API_KEY");
    assert.equal(openAiKey.configured, true);
    assert.equal(openAiKey.valueRedacted, true);
    assert.match(openAiKey.valueHash, /^[a-f0-9]{64}$/);
    const hostedNode = report.runtimeNodes.find((node) => node.id === "hosted-provider");
    assert.equal(hostedNode.endpointConfigured, true);
    assert.match(hostedNode.endpointHash, /^[a-f0-9]{64}$/);
    const serialized = JSON.stringify(report);
    assert.ok(!serialized.includes("sk-doctor-secret-do-not-print"));
    assert.ok(!serialized.includes("https://doctor-secret.example"));
  } finally {
    await daemon.close();
    if (savedOpenAi === undefined) delete process.env.OPENAI_API_KEY;
    else process.env.OPENAI_API_KEY = savedOpenAi;
    if (savedHosted === undefined) delete process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
    else process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT = savedHosted;
  }
});

test("local daemon emits read-only repository context for Git workspaces", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-repository-context-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-repository-context-state-"));
  const savedGithubToken = process.env.GITHUB_TOKEN;
  const savedGhToken = process.env.GH_TOKEN;
  process.env.GITHUB_TOKEN = "ghp-secret-do-not-print";
  delete process.env.GH_TOKEN;
  git(cwd, ["init"]);
  git(cwd, ["config", "user.email", "ioi-test@example.invalid"]);
  git(cwd, ["config", "user.name", "IOI Test"]);
  fs.writeFileSync(path.join(cwd, "tracked.txt"), "one\n");
  git(cwd, ["add", "tracked.txt"]);
  git(cwd, ["commit", "-m", "initial"]);
  const branch = git(cwd, ["branch", "--show-current"]);
  git(cwd, ["remote", "add", "origin", "https://user:secret@github.com/ioi-test/ioi.git"]);
  git(cwd, ["update-ref", `refs/remotes/origin/${branch}`, "HEAD"]);
  git(cwd, ["symbolic-ref", "refs/remotes/origin/HEAD", `refs/remotes/origin/${branch}`]);
  git(cwd, ["branch", "--set-upstream-to", `origin/${branch}`]);
  fs.writeFileSync(path.join(cwd, "tracked.txt"), "two\n");
  fs.writeFileSync(path.join(cwd, "staged.txt"), "staged\n");
  git(cwd, ["add", "staged.txt"]);
  fs.writeFileSync(path.join(cwd, "untracked.txt"), "new\n");

  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const repositoryContext = await fetchJson(`${daemon.endpoint}/v1/repository-context`);
    assert.equal(repositoryContext.schemaVersion, "ioi.agent-runtime.repository-context.v1");
    assert.equal(repositoryContext.object, "ioi.repository_context");
    assert.equal(repositoryContext.isGitRepository, true);
    assert.equal(repositoryContext.repoRoot, cwd);
    assert.equal(repositoryContext.branch, branch);
    assert.equal(repositoryContext.defaultBranch, branch);
    assert.match(repositoryContext.headSha, /^[a-f0-9]{40}$/);
    assert.equal(repositoryContext.upstream, `origin/${branch}`);
    assert.equal(repositoryContext.remoteCount, 1);
    assert.equal(repositoryContext.remotes[0].fetchUrl, "https://github.com/ioi-test/ioi.git");
    assert.match(repositoryContext.remotes[0].fetchUrlHash, /^[a-f0-9]{64}$/);
    assert.equal(repositoryContext.remotes[0].provider, "github");
    assert.equal(repositoryContext.remotes[0].host, "github.com");
    assert.equal(repositoryContext.remotes[0].owner, "ioi-test");
    assert.equal(repositoryContext.remotes[0].repo, "ioi");
    assert.equal(repositoryContext.remotes[0].repoFullName, "ioi-test/ioi");
    assert.equal(repositoryContext.status.isDirty, true);
    assert.equal(repositoryContext.status.counts.staged, 1);
    assert.equal(repositoryContext.status.counts.unstaged, 1);
    assert.equal(repositoryContext.status.counts.untracked, 1);
    assert.equal(repositoryContext.readOnly, true);
    assert.equal(repositoryContext.mutationExecuted, false);
    assert.equal(repositoryContext.redaction.remoteCredentialsIncluded, false);

    const repositories = await fetchJson(`${daemon.endpoint}/v1/repositories`);
    assert.equal(repositories[0].contextId, repositoryContext.contextId);
    assert.equal(repositories[0].branch, branch);
    assert.equal(repositories[0].isDirty, true);

    const branchPolicy = await fetchJson(`${daemon.endpoint}/v1/branch-policy`);
    assert.equal(branchPolicy.schemaVersion, "ioi.agent-runtime.branch-policy.v1");
    assert.equal(branchPolicy.object, "ioi.branch_policy_decision");
    assert.equal(branchPolicy.repositoryContextId, repositoryContext.contextId);
    assert.equal(branchPolicy.status, "blocked");
    assert.equal(branchPolicy.branch, branch);
    assert.equal(branchPolicy.defaultBranch, branch);
    assert.equal(branchPolicy.protectedBranch, true);
    assert.equal(branchPolicy.dirty, true);
    assert.equal(branchPolicy.readOnly, true);
    assert.equal(branchPolicy.mutationExecuted, false);
    assert.equal(branchPolicy.mutationAllowed, false);
    assert.equal(branchPolicy.prCreationAllowed, false);
    assert.ok(branchPolicy.blockers.includes("protected_branch"));
    assert.ok(branchPolicy.warnings.includes("dirty_worktree"));
    assert.ok(branchPolicy.warnings.includes("untracked_files"));

    const githubContext = await fetchJson(`${daemon.endpoint}/v1/github-context`);
    assert.equal(githubContext.schemaVersion, "ioi.agent-runtime.github-context.v1");
    assert.equal(githubContext.object, "ioi.github_context");
    assert.equal(githubContext.repositoryContextId, repositoryContext.contextId);
    assert.equal(githubContext.branchPolicyId, branchPolicy.policyId);
    assert.equal(githubContext.status, "blocked");
    assert.equal(githubContext.githubRemotePresent, true);
    assert.equal(githubContext.defaultRemoteName, "origin");
    assert.equal(githubContext.owner, "ioi-test");
    assert.equal(githubContext.repo, "ioi");
    assert.equal(githubContext.repoFullName, "ioi-test/ioi");
    assert.equal(githubContext.htmlUrl, "https://github.com/ioi-test/ioi");
    assert.equal(githubContext.branchPolicyStatus, "blocked");
    assert.equal(githubContext.prCreationEligible, false);
    assert.equal(githubContext.prCreationPreconditions.githubRemotePresent, true);
    assert.equal(githubContext.prCreationPreconditions.branchPolicyAllowsPr, false);
    assert.equal(githubContext.prCreationPreconditions.tokenAvailable, true);
    assert.equal(githubContext.prCreationPreconditions.networkLookupPerformed, false);
    assert.equal(githubContext.prCreationPreconditions.mutationExecuted, false);
    assert.equal(githubContext.credentials.tokenAvailable, true);
    assert.deepEqual(githubContext.credentials.tokenSources, ["GITHUB_TOKEN"]);
    assert.equal(githubContext.credentials.tokenValueIncluded, false);
    assert.equal(githubContext.networkLookupPerformed, false);
    assert.equal(githubContext.mutationExecuted, false);

    const issueContext = await fetchJson(`${daemon.endpoint}/v1/issue-context`);
    assert.equal(issueContext.schemaVersion, "ioi.agent-runtime.issue-context.v1");
    assert.equal(issueContext.object, "ioi.issue_context");
    assert.equal(issueContext.repositoryContextId, repositoryContext.contextId);
    assert.equal(issueContext.githubContextId, githubContext.contextId);
    assert.equal(issueContext.status, "unbound");
    assert.equal(issueContext.repoFullName, "ioi-test/ioi");
    assert.equal(issueContext.bound, false);
    assert.equal(issueContext.issueProvided, false);
    assert.equal(issueContext.issueNumber, null);
    assert.equal(issueContext.title, null);
    assert.equal(issueContext.sourceUrl, null);
    assert.equal(issueContext.sourceKind, "unbound");
    assert.ok(issueContext.warnings.includes("issue_context_unbound"));
    assert.equal(issueContext.noIssuePolicy.allowed, true);
    assert.equal(issueContext.networkLookupPerformed, false);
    assert.equal(issueContext.mutationExecuted, false);
    assert.equal(issueContext.redaction.bodyIncluded, false);

    const prAttempts = await fetchJson(`${daemon.endpoint}/v1/pr-attempts`);
    assert.equal(prAttempts.length, 1);
    const prAttempt = prAttempts[0];
    assert.equal(prAttempt.schemaVersion, "ioi.agent-runtime.pr-attempt.v1");
    assert.equal(prAttempt.object, "ioi.pr_attempt");
    assert.equal(issueContext.prAttemptId, prAttempt.attemptId);
    assert.equal(prAttempt.repositoryContextId, repositoryContext.contextId);
    assert.equal(prAttempt.branchPolicyId, branchPolicy.policyId);
    assert.equal(prAttempt.githubContextId, githubContext.contextId);
    assert.equal(prAttempt.status, "blocked");
    assert.equal(prAttempt.outcome, "failed_precondition");
    assert.equal(prAttempt.repoFullName, "ioi-test/ioi");
    assert.equal(prAttempt.branch, branch);
    assert.equal(prAttempt.defaultBranch, branch);
    assert.match(prAttempt.headSha, /^[a-f0-9]{40}$/);
    assert.deepEqual(prAttempt.authority.requiredScopes, ["github.pr.create"]);
    assert.deepEqual(prAttempt.authority.missingScopes, ["github.pr.create"]);
    assert.equal(prAttempt.authority.scopeGranted, false);
    assert.equal(prAttempt.preconditions.githubRemotePresent, true);
    assert.equal(prAttempt.preconditions.branchPolicyAllowsPr, false);
    assert.equal(prAttempt.preconditions.tokenAvailable, true);
    assert.equal(prAttempt.preconditions.branchArtifactAttached, true);
    assert.equal(prAttempt.preconditions.diffArtifactAttached, true);
    assert.equal(prAttempt.preconditions.networkLookupPerformed, false);
    assert.equal(prAttempt.preconditions.mutationExecuted, false);
    assert.ok(prAttempt.blockers.includes("protected_branch"));
    assert.ok(prAttempt.blockers.includes("branch_policy_not_passed"));
    assert.ok(prAttempt.blockers.includes("missing_authority_scope:github.pr.create"));
    assert.equal(prAttempt.previewOnly, true);
    assert.equal(prAttempt.mutationAttempted, false);
    assert.equal(prAttempt.mutationExecuted, false);
    assert.equal(prAttempt.networkLookupPerformed, false);
    assert.equal(prAttempt.branchArtifact.artifactName, "pr-branch.json");
    assert.equal(prAttempt.diffArtifact.artifactName, "pr-diff.patch");
    assert.equal(prAttempt.diffArtifact.hasDiff, true);
    assert.ok(prAttempt.diffArtifact.fileCount >= 1);
    assert.equal(prAttempt.redaction.diffContentInProjection, false);

    const reviewGate = await fetchJson(`${daemon.endpoint}/v1/review-gate`);
    assert.equal(reviewGate.schemaVersion, "ioi.agent-runtime.review-gate.v1");
    assert.equal(reviewGate.object, "ioi.review_gate_decision");
    assert.equal(issueContext.reviewGateId, reviewGate.gateId);
    assert.equal(reviewGate.repositoryContextId, repositoryContext.contextId);
    assert.equal(reviewGate.branchPolicyId, branchPolicy.policyId);
    assert.equal(reviewGate.githubContextId, githubContext.contextId);
    assert.equal(reviewGate.prAttemptId, prAttempt.attemptId);
    assert.equal(reviewGate.status, "blocked");
    assert.equal(reviewGate.decision, "blocked");
    assert.equal(reviewGate.repoFullName, "ioi-test/ioi");
    assert.equal(reviewGate.branch, branch);
    assert.equal(reviewGate.defaultBranch, branch);
    assert.equal(reviewGate.reviewRequired, true);
    assert.equal(reviewGate.reviewSatisfied, false);
    assert.equal(reviewGate.approvalRequired, true);
    assert.equal(reviewGate.approvalSatisfied, false);
    assert.deepEqual(reviewGate.requiredReviewers, ["code-owner"]);
    assert.ok(reviewGate.requiredChecks.includes("human_review_satisfied"));
    assert.ok(reviewGate.blockers.includes("review_not_satisfied"));
    assert.ok(reviewGate.blockers.includes("pr_attempt_not_ready"));
    assert.ok(reviewGate.blockers.includes("missing_authority_scope:github.pr.create"));
    assert.equal(reviewGate.preconditions.prAttemptReady, false);
    assert.equal(reviewGate.preconditions.diffArtifactAttached, true);
    assert.equal(reviewGate.preconditions.reviewPolicySatisfied, false);
    assert.equal(reviewGate.preconditions.networkLookupPerformed, false);
    assert.equal(reviewGate.preconditions.mutationExecuted, false);
    assert.equal(reviewGate.mutationAllowed, false);
    assert.equal(reviewGate.prCreationAllowed, false);
    assert.equal(reviewGate.mutationExecuted, false);
    assert.equal(reviewGate.networkLookupPerformed, false);

    const githubPrCreatePlan = await fetchJson(`${daemon.endpoint}/v1/github/pr-create-plan`);
    assert.equal(githubPrCreatePlan.schemaVersion, "ioi.agent-runtime.github-pr-create-plan.v1");
    assert.equal(githubPrCreatePlan.object, "ioi.github_pr_create_plan");
    assert.equal(githubPrCreatePlan.repositoryContextId, repositoryContext.contextId);
    assert.equal(githubPrCreatePlan.branchPolicyId, branchPolicy.policyId);
    assert.equal(githubPrCreatePlan.githubContextId, githubContext.contextId);
    assert.equal(githubPrCreatePlan.issueContextId, issueContext.contextId);
    assert.equal(githubPrCreatePlan.prAttemptId, prAttempt.attemptId);
    assert.equal(githubPrCreatePlan.reviewGateId, reviewGate.gateId);
    assert.equal(githubPrCreatePlan.status, "blocked");
    assert.equal(githubPrCreatePlan.decision, "blocked");
    assert.equal(githubPrCreatePlan.dryRun, true);
    assert.equal(githubPrCreatePlan.previewOnly, true);
    assert.equal(githubPrCreatePlan.toolName, "github__pr_create");
    assert.equal(githubPrCreatePlan.action, "pr_create");
    assert.equal(githubPrCreatePlan.repoFullName, "ioi-test/ioi");
    assert.equal(githubPrCreatePlan.baseBranch, branch);
    assert.equal(githubPrCreatePlan.headBranch, branch);
    assert.equal(githubPrCreatePlan.issueNumber, null);
    assert.equal(githubPrCreatePlan.reviewGateStatus, "blocked");
    assert.equal(githubPrCreatePlan.reviewSatisfied, false);
    assert.equal(githubPrCreatePlan.bodyPlan.included, false);
    assert.equal(githubPrCreatePlan.request.method, "POST");
    assert.equal(githubPrCreatePlan.request.path, "/repos/ioi-test/ioi/pulls");
    assert.match(githubPrCreatePlan.request.payloadHash, /^[a-f0-9]{64}$/);
    assert.equal(githubPrCreatePlan.request.bodyIncluded, false);
    assert.equal(githubPrCreatePlan.request.tokenIncluded, false);
    assert.deepEqual(githubPrCreatePlan.authority.requiredScopes, ["github.pr.create"]);
    assert.deepEqual(githubPrCreatePlan.authority.missingScopes, ["github.pr.create"]);
    assert.equal(githubPrCreatePlan.authority.scopeGranted, false);
    assert.ok(githubPrCreatePlan.blockers.includes("review_gate_not_passed"));
    assert.ok(githubPrCreatePlan.blockers.includes("review_not_satisfied"));
    assert.ok(githubPrCreatePlan.blockers.includes("missing_authority_scope:github.pr.create"));
    assert.ok(githubPrCreatePlan.blockers.includes("dry_run_only"));
    assert.equal(githubPrCreatePlan.networkLookupPerformed, false);
    assert.equal(githubPrCreatePlan.mutationAttempted, false);
    assert.equal(githubPrCreatePlan.mutationExecuted, false);
    assert.equal(githubPrCreatePlan.redaction.tokenValueIncluded, false);
    assert.equal(githubPrCreatePlan.redaction.authorizationHeaderIncluded, false);
    assert.equal(githubPrCreatePlan.redaction.requestBodyIncluded, false);
    assert.equal(githubPrCreatePlan.redaction.networkResponseIncluded, false);

    const { Agent, createRuntimeSubstrateClient } = await importSdk();
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const agent = await Agent.create({ local: { cwd }, substrateClient: client });
    const run = await agent.send("Record repository context for branch policy.");
    const trace = await fetchJson(`${daemon.endpoint}/v1/runs/${run.id}/trace`);
    assert.equal(trace.repositoryContext.schemaVersion, "ioi.agent-runtime.repository-context.v1");
    assert.equal(trace.repositoryContext.branch, branch);
    assert.equal(trace.repositoryContext.status.counts.staged, 1);
    assert.equal(trace.repositoryContext.status.counts.unstaged, 1);
    assert.equal(trace.repositoryContext.status.counts.untracked, 1);
    assert.equal(trace.repositoryContext.mutationExecuted, false);
    assert.equal(trace.branchPolicy.schemaVersion, "ioi.agent-runtime.branch-policy.v1");
    assert.equal(trace.branchPolicy.repositoryContextId, trace.repositoryContext.contextId);
    assert.equal(trace.branchPolicy.status, "blocked");
    assert.equal(trace.branchPolicy.protectedBranch, true);
    assert.equal(trace.branchPolicy.mutationAllowed, false);
    assert.ok(trace.branchPolicy.blockers.includes("protected_branch"));
    assert.ok(trace.branchPolicy.warnings.includes("dirty_worktree"));
    assert.equal(trace.githubContext.schemaVersion, "ioi.agent-runtime.github-context.v1");
    assert.equal(trace.githubContext.repoFullName, "ioi-test/ioi");
    assert.equal(trace.githubContext.status, "blocked");
    assert.equal(trace.githubContext.prCreationEligible, false);
    assert.equal(trace.issueContext.schemaVersion, "ioi.agent-runtime.issue-context.v1");
    assert.equal(trace.issueContext.status, "unbound");
    assert.equal(trace.issueContext.repoFullName, "ioi-test/ioi");
    assert.equal(trace.issueContext.bound, false);
    assert.equal(trace.issueContext.prAttemptId, trace.prAttempt.attemptId);
    assert.equal(trace.issueContext.reviewGateId, trace.reviewGate.gateId);
    assert.equal(trace.prAttempt.schemaVersion, "ioi.agent-runtime.pr-attempt.v1");
    assert.equal(trace.prAttempt.repoFullName, "ioi-test/ioi");
    assert.equal(trace.prAttempt.status, "blocked");
    assert.equal(trace.prAttempt.outcome, "failed_precondition");
    assert.equal(trace.prAttempt.mutationExecuted, false);
    assert.equal(trace.prAttempt.branchArtifact.artifactName, "pr-branch.json");
    assert.equal(trace.prAttempt.diffArtifact.artifactName, "pr-diff.patch");
    assert.ok(trace.prAttempt.blockers.includes("missing_authority_scope:github.pr.create"));
    assert.equal(trace.reviewGate.schemaVersion, "ioi.agent-runtime.review-gate.v1");
    assert.equal(trace.reviewGate.status, "blocked");
    assert.equal(trace.reviewGate.decision, "blocked");
    assert.equal(trace.reviewGate.prAttemptId, trace.prAttempt.attemptId);
    assert.equal(trace.reviewGate.reviewRequired, true);
    assert.equal(trace.reviewGate.reviewSatisfied, false);
    assert.ok(trace.reviewGate.blockers.includes("review_not_satisfied"));
    assert.equal(trace.githubPrCreatePlan.schemaVersion, "ioi.agent-runtime.github-pr-create-plan.v1");
    assert.equal(trace.githubPrCreatePlan.status, "blocked");
    assert.equal(trace.githubPrCreatePlan.dryRun, true);
    assert.equal(trace.githubPrCreatePlan.toolName, "github__pr_create");
    assert.equal(trace.githubPrCreatePlan.prAttemptId, trace.prAttempt.attemptId);
    assert.equal(trace.githubPrCreatePlan.reviewGateId, trace.reviewGate.gateId);
    assert.equal(trace.githubPrCreatePlan.issueContextId, trace.issueContext.contextId);
    assert.match(trace.githubPrCreatePlan.request.payloadHash, /^[a-f0-9]{64}$/);
    assert.equal(trace.githubPrCreatePlan.request.bodyIncluded, false);
    assert.equal(trace.githubPrCreatePlan.request.tokenIncluded, false);
    assert.equal(trace.githubPrCreatePlan.mutationExecuted, false);
    assert.equal(trace.githubPrCreatePlan.networkLookupPerformed, false);
    assert.equal(trace.promptAudit.repositoryContextId, trace.repositoryContext.contextId);
    assert.equal(trace.promptAudit.branchPolicyId, trace.branchPolicy.policyId);
    assert.equal(trace.promptAudit.githubContextId, trace.githubContext.contextId);
    assert.equal(trace.promptAudit.issueContextId, trace.issueContext.contextId);
    assert.equal(trace.promptAudit.prAttemptId, trace.prAttempt.attemptId);
    assert.equal(trace.promptAudit.reviewGateId, trace.reviewGate.gateId);
    assert.equal(trace.promptAudit.githubPrCreatePlanId, trace.githubPrCreatePlan.planId);
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "repository_context"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "branch_policy"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "github_context"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "issue_context"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "pr_attempt"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "review_gate"));
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "github_pr_create_plan"));
    const artifacts = await fetchJson(`${daemon.endpoint}/v1/runs/${run.id}/artifacts`);
    assert.ok(artifacts.some((artifact) => artifact.name === "repository-context.json"));
    assert.ok(artifacts.some((artifact) => artifact.name === "branch-policy.json"));
    assert.ok(artifacts.some((artifact) => artifact.name === "github-context.json"));
    assert.ok(artifacts.some((artifact) => artifact.name === "issue-context.json"));
    assert.ok(artifacts.some((artifact) => artifact.name === "pr-attempt.json"));
    assert.ok(artifacts.some((artifact) => artifact.name === "pr-branch.json"));
    const prDiffArtifact = artifacts.find((artifact) => artifact.name === "pr-diff.patch");
    assert.ok(prDiffArtifact);
    assert.equal(prDiffArtifact.mediaType, "text/x-diff");
    assert.match(prDiffArtifact.content, /diff --git/);
    assert.ok(artifacts.some((artifact) => artifact.name === "review-gate.json"));
    assert.ok(artifacts.some((artifact) => artifact.name === "github-pr-create-plan.json"));

    const threadId = `thread_${agent.id.slice("agent_".length)}`;
    const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${threadId}/events?since_seq=0`);
    const repoEvent = events.find((event) => event.payload_summary?.event_kind === "RepositoryContext");
    assert.ok(repoEvent);
    assert.equal(repoEvent.component_kind, "repository_context");
    assert.equal(repoEvent.workflow_node_id, "runtime.repository-context");
    assert.equal(repoEvent.payload_summary.branch, branch);
    assert.equal(repoEvent.payload_summary.is_git_repository, true);
    assert.equal(repoEvent.payload_summary.is_dirty, true);
    assert.equal(repoEvent.payload_summary.staged_count, 1);
    assert.equal(repoEvent.payload_summary.unstaged_count, 1);
    assert.equal(repoEvent.payload_summary.untracked_count, 1);
    assert.equal(repoEvent.payload_summary.mutation_executed, false);
    assert.ok(repoEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_repository_context")));
    assert.ok(repoEvent.artifact_refs.includes("repository-context.json"));
    const branchPolicyEvent = events.find(
      (event) => event.payload_summary?.event_kind === "BranchPolicyDecision",
    );
    assert.ok(branchPolicyEvent);
    assert.equal(branchPolicyEvent.component_kind, "branch_policy");
    assert.equal(branchPolicyEvent.workflow_node_id, "runtime.branch-policy");
    assert.equal(branchPolicyEvent.payload_summary.status, "blocked");
    assert.equal(branchPolicyEvent.payload_summary.branch, branch);
    assert.equal(branchPolicyEvent.payload_summary.default_branch, branch);
    assert.equal(branchPolicyEvent.payload_summary.protected_branch, true);
    assert.equal(branchPolicyEvent.payload_summary.dirty, true);
    assert.equal(branchPolicyEvent.payload_summary.mutation_allowed, false);
    assert.equal(branchPolicyEvent.payload_summary.pr_creation_allowed, false);
    assert.equal(branchPolicyEvent.payload_summary.review_required, true);
    assert.ok(branchPolicyEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_branch_policy")));
    assert.ok(branchPolicyEvent.artifact_refs.includes("branch-policy.json"));
    const githubContextEvent = events.find(
      (event) => event.payload_summary?.event_kind === "GitHubContext",
    );
    assert.ok(githubContextEvent);
    assert.equal(githubContextEvent.component_kind, "github_context");
    assert.equal(githubContextEvent.workflow_node_id, "runtime.github-context");
    assert.equal(githubContextEvent.payload_summary.status, "blocked");
    assert.equal(githubContextEvent.payload_summary.github_remote_present, true);
    assert.equal(githubContextEvent.payload_summary.default_remote_name, "origin");
    assert.equal(githubContextEvent.payload_summary.owner, "ioi-test");
    assert.equal(githubContextEvent.payload_summary.repo, "ioi");
    assert.equal(githubContextEvent.payload_summary.repo_full_name, "ioi-test/ioi");
    assert.equal(githubContextEvent.payload_summary.branch, branch);
    assert.equal(githubContextEvent.payload_summary.default_branch, branch);
    assert.equal(githubContextEvent.payload_summary.branch_policy_status, "blocked");
    assert.equal(githubContextEvent.payload_summary.token_available, true);
    assert.equal(githubContextEvent.payload_summary.pr_creation_eligible, false);
    assert.equal(githubContextEvent.payload_summary.network_lookup_performed, false);
    assert.equal(githubContextEvent.payload_summary.mutation_executed, false);
    assert.ok(githubContextEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_github_context")));
    assert.ok(githubContextEvent.artifact_refs.includes("github-context.json"));
    const issueContextEvent = events.find(
      (event) => event.payload_summary?.event_kind === "IssueContext",
    );
    assert.ok(issueContextEvent);
    assert.equal(issueContextEvent.component_kind, "issue_context");
    assert.equal(issueContextEvent.workflow_node_id, "runtime.issue-context");
    assert.equal(issueContextEvent.payload_summary.status, "unbound");
    assert.equal(issueContextEvent.payload_summary.repo_full_name, "ioi-test/ioi");
    assert.equal(issueContextEvent.payload_summary.bound, false);
    assert.equal(issueContextEvent.payload_summary.issue_provided, false);
    assert.equal(issueContextEvent.payload_summary.issue_number, null);
    assert.equal(issueContextEvent.payload_summary.source_kind, "unbound");
    assert.equal(issueContextEvent.payload_summary.network_lookup_performed, false);
    assert.equal(issueContextEvent.payload_summary.mutation_executed, false);
    assert.ok(issueContextEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_issue_context")));
    assert.ok(issueContextEvent.artifact_refs.includes("issue-context.json"));
    const prAttemptEvent = events.find(
      (event) => event.payload_summary?.event_kind === "PrAttemptRecord",
    );
    assert.ok(prAttemptEvent);
    assert.equal(prAttemptEvent.component_kind, "pr_attempt");
    assert.equal(prAttemptEvent.workflow_node_id, "runtime.pr-attempt");
    assert.equal(prAttemptEvent.payload_summary.status, "blocked");
    assert.equal(prAttemptEvent.payload_summary.outcome, "failed_precondition");
    assert.equal(prAttemptEvent.payload_summary.repo_full_name, "ioi-test/ioi");
    assert.equal(prAttemptEvent.payload_summary.branch, branch);
    assert.equal(prAttemptEvent.payload_summary.default_branch, branch);
    assert.deepEqual(prAttemptEvent.payload_summary.required_authority_scopes, ["github.pr.create"]);
    assert.deepEqual(prAttemptEvent.payload_summary.missing_authority_scopes, ["github.pr.create"]);
    assert.equal(prAttemptEvent.payload_summary.authority_scope_granted, false);
    assert.equal(prAttemptEvent.payload_summary.branch_artifact_name, "pr-branch.json");
    assert.equal(prAttemptEvent.payload_summary.diff_artifact_name, "pr-diff.patch");
    assert.ok(prAttemptEvent.payload_summary.diff_file_count >= 1);
    assert.equal(prAttemptEvent.payload_summary.mutation_attempted, false);
    assert.equal(prAttemptEvent.payload_summary.mutation_executed, false);
    assert.equal(prAttemptEvent.payload_summary.network_lookup_performed, false);
    assert.ok(prAttemptEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_pr_attempt")));
    assert.ok(prAttemptEvent.artifact_refs.includes("pr-attempt.json"));
    assert.ok(prAttemptEvent.artifact_refs.includes("pr-branch.json"));
    assert.ok(prAttemptEvent.artifact_refs.includes("pr-diff.patch"));
    const reviewGateEvent = events.find(
      (event) => event.payload_summary?.event_kind === "ReviewGateDecision",
    );
    assert.ok(reviewGateEvent);
    assert.equal(reviewGateEvent.component_kind, "review_gate");
    assert.equal(reviewGateEvent.workflow_node_id, "runtime.review-gate");
    assert.equal(reviewGateEvent.payload_summary.status, "blocked");
    assert.equal(reviewGateEvent.payload_summary.decision, "blocked");
    assert.equal(reviewGateEvent.payload_summary.repo_full_name, "ioi-test/ioi");
    assert.equal(reviewGateEvent.payload_summary.branch, branch);
    assert.equal(reviewGateEvent.payload_summary.default_branch, branch);
    assert.equal(reviewGateEvent.payload_summary.review_required, true);
    assert.equal(reviewGateEvent.payload_summary.review_satisfied, false);
    assert.equal(reviewGateEvent.payload_summary.approval_required, true);
    assert.equal(reviewGateEvent.payload_summary.approval_satisfied, false);
    assert.deepEqual(reviewGateEvent.payload_summary.required_reviewers, ["code-owner"]);
    assert.ok(reviewGateEvent.payload_summary.required_checks.includes("human_review_satisfied"));
    assert.equal(reviewGateEvent.payload_summary.mutation_allowed, false);
    assert.equal(reviewGateEvent.payload_summary.pr_creation_allowed, false);
    assert.equal(reviewGateEvent.payload_summary.mutation_executed, false);
    assert.equal(reviewGateEvent.payload_summary.network_lookup_performed, false);
    assert.ok(reviewGateEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_review_gate")));
    assert.ok(reviewGateEvent.artifact_refs.includes("review-gate.json"));
    const githubPrCreatePlanEvent = events.find(
      (event) => event.payload_summary?.event_kind === "GitHubPrCreatePlan",
    );
    assert.ok(githubPrCreatePlanEvent);
    assert.equal(githubPrCreatePlanEvent.component_kind, "github_pr_create");
    assert.equal(githubPrCreatePlanEvent.workflow_node_id, "runtime.github-pr-create");
    assert.equal(githubPrCreatePlanEvent.payload_summary.status, "blocked");
    assert.equal(githubPrCreatePlanEvent.payload_summary.decision, "blocked");
    assert.equal(githubPrCreatePlanEvent.payload_summary.dry_run, true);
    assert.equal(githubPrCreatePlanEvent.payload_summary.tool_name, "github__pr_create");
    assert.equal(githubPrCreatePlanEvent.payload_summary.repo_full_name, "ioi-test/ioi");
    assert.equal(githubPrCreatePlanEvent.payload_summary.base_branch, branch);
    assert.equal(githubPrCreatePlanEvent.payload_summary.head_branch, branch);
    assert.equal(githubPrCreatePlanEvent.payload_summary.issue_context_id, trace.issueContext.contextId);
    assert.equal(githubPrCreatePlanEvent.payload_summary.pr_attempt_id, trace.prAttempt.attemptId);
    assert.equal(githubPrCreatePlanEvent.payload_summary.review_gate_id, trace.reviewGate.gateId);
    assert.equal(githubPrCreatePlanEvent.payload_summary.review_gate_status, "blocked");
    assert.equal(githubPrCreatePlanEvent.payload_summary.review_satisfied, false);
    assert.match(githubPrCreatePlanEvent.payload_summary.request_payload_hash, /^[a-f0-9]{64}$/);
    assert.equal(githubPrCreatePlanEvent.payload_summary.request_body_included, false);
    assert.equal(githubPrCreatePlanEvent.payload_summary.request_token_included, false);
    assert.deepEqual(githubPrCreatePlanEvent.payload_summary.required_authority_scopes, ["github.pr.create"]);
    assert.deepEqual(githubPrCreatePlanEvent.payload_summary.missing_authority_scopes, ["github.pr.create"]);
    assert.equal(githubPrCreatePlanEvent.payload_summary.authority_scope_granted, false);
    assert.equal(githubPrCreatePlanEvent.payload_summary.mutation_attempted, false);
    assert.equal(githubPrCreatePlanEvent.payload_summary.mutation_executed, false);
    assert.equal(githubPrCreatePlanEvent.payload_summary.network_lookup_performed, false);
    assert.ok(githubPrCreatePlanEvent.receipt_refs.some((receiptRef) => receiptRef.endsWith("_github_pr_create_plan")));
    assert.ok(githubPrCreatePlanEvent.artifact_refs.includes("github-pr-create-plan.json"));

    const serializedProjection = JSON.stringify({
      repositoryContext,
      repositories,
      branchPolicy,
      githubContext,
      issueContext,
      prAttempt,
      reviewGate,
      githubPrCreatePlan,
      trace,
      events,
    });
    assert.ok(!serializedProjection.includes("user:secret"));
    assert.ok(!serializedProjection.includes("https://user:secret@github.com"));
    assert.ok(!serializedProjection.includes("Authorization"));
    assert.ok(!serializedProjection.includes("ghp-secret-do-not-print"));
  } finally {
    await daemon.close();
    if (savedGithubToken === undefined) delete process.env.GITHUB_TOKEN;
    else process.env.GITHUB_TOKEN = savedGithubToken;
    if (savedGhToken === undefined) delete process.env.GH_TOKEN;
    else process.env.GH_TOKEN = savedGhToken;
  }
});

test("local daemon discovers governed skills and hooks without leaking hook commands", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-skill-hook-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-skill-hook-state-"));
  const cursorSkillDir = path.join(cwd, ".cursor", "skills", "repo-cartographer");
  const agentsDir = path.join(cwd, ".agents");
  fs.mkdirSync(cursorSkillDir, { recursive: true });
  fs.mkdirSync(agentsDir, { recursive: true });
  fs.writeFileSync(
    path.join(cursorSkillDir, "SKILL.md"),
    [
      "---",
      "name: Repo Cartographer",
      "description: Maps likely repo files before edits.",
      "capabilityScopes: repo.read, evidence.read",
      "---",
      "# Repo Cartographer",
      "",
      "Use focused repo discovery before patching.",
    ].join("\n"),
  );
  fs.writeFileSync(
    path.join(agentsDir, "hooks.json"),
    JSON.stringify(
      {
        "pre-model-redaction": {
          eventKinds: ["pre_model"],
          failurePolicy: "warn",
          authorityScopes: ["runtime.read"],
          command: "echo super-secret-hook",
        },
        "post-tool-ledger": {
          eventKinds: ["post_model", "post_tool"],
          failurePolicy: "block",
          authorityScopes: ["runtime.read"],
          toolContracts: ["hook.preview"],
          command: "echo allowed-hook-secret",
        },
        "workflow-activation-observer": {
          eventKinds: ["workflow_activation"],
          failurePolicy: "warn",
          authorityScopes: ["runtime.read"],
        },
      },
      null,
      2,
    ),
  );
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const skills = await fetchJson(`${daemon.endpoint}/v1/skills`);
    assert.equal(skills.schemaVersion, "ioi.agent-runtime.skills.v1");
    assert.equal(skills.status, "pass");
    assert.equal(skills.skillCount, 1);
    assert.equal(skills.skills[0].name, "Repo Cartographer");
    assert.equal(skills.skills[0].compatibility, "cursor");
    assert.equal(skills.skills[0].hasSkillMd, true);
    assert.deepEqual(skills.skills[0].capabilityScopes, ["repo.read", "evidence.read"]);

    const hooks = await fetchJson(`${daemon.endpoint}/v1/hooks`);
    assert.equal(hooks.schemaVersion, "ioi.agent-runtime.hooks.v1");
    assert.equal(hooks.status, "pass");
    assert.equal(hooks.hookCount, 3);
    const blockedHook = hooks.hooks.find((hook) => hook.name === "pre-model-redaction");
    const dryRunHook = hooks.hooks.find((hook) => hook.name === "post-tool-ledger");
    const observerHook = hooks.hooks.find((hook) => hook.name === "workflow-activation-observer");
    assert.ok(blockedHook);
    assert.ok(dryRunHook);
    assert.ok(observerHook);
    assert.equal(blockedHook.failurePolicy, "warn");
    assert.deepEqual(blockedHook.eventKinds, ["pre_model"]);
    assert.deepEqual(blockedHook.authorityScopes, ["runtime.read"]);
    assert.deepEqual(blockedHook.toolContracts, []);
    assert.equal(blockedHook.commandConfigured, true);
    assert.equal(blockedHook.commandRedacted, true);
    assert.match(blockedHook.commandHash, /^[a-f0-9]{64}$/);
    assert.equal(dryRunHook.failurePolicy, "block");
    assert.deepEqual(dryRunHook.eventKinds, ["post_model", "post_tool"]);
    assert.deepEqual(dryRunHook.authorityScopes, ["runtime.read"]);
    assert.deepEqual(dryRunHook.toolContracts, ["hook.preview"]);
    assert.equal(dryRunHook.commandConfigured, true);
    assert.equal(dryRunHook.commandRedacted, true);
    assert.match(dryRunHook.commandHash, /^[a-f0-9]{64}$/);
    assert.deepEqual(observerHook.eventKinds, ["workflow_activation"]);
    assert.equal(observerHook.commandConfigured, false);

    const doctor = await fetchJson(`${daemon.endpoint}/v1/doctor`);
    const skillHookCheck = doctor.checks.find((check) => check.id === "skills.hooks");
    assert.equal(skillHookCheck.status, "pass");
    assert.equal(doctor.skillsHooks.skillCount, 1);
    assert.equal(doctor.skillsHooks.hookCount, 3);
    assert.ok(!doctor.optionalWarnings.includes("skills.hooks"));
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({ options: { local: { cwd } } }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "Use governed skill and hook provenance.", mode: "send" }),
    });
    assert.match(turn.active_skill_hook_manifest_ref, /^skill_hook_manifest_run_/);
    assert.match(turn.active_skill_set_hash, /^[a-f0-9]{64}$/);
    assert.match(turn.active_hook_set_hash, /^[a-f0-9]{64}$/);

    const runId = `run_${turn.turn_id.slice("turn_".length)}`;
    const trace = await fetchJson(`${daemon.endpoint}/v1/runs/${runId}/trace`);
    assert.equal(trace.activeSkillHookManifest.schemaVersion, "ioi.agent-runtime.active-skill-hook-manifest.v1");
    assert.equal(trace.activeSkillHookManifest.selectedSkillIds.length, 1);
    assert.equal(trace.activeSkillHookManifest.selectedHookIds.length, 3);
    assert.equal(trace.activeSkillHookManifest.hookExecution.enabled, false);
    assert.equal(trace.activeSkillHookManifest.hookExecution.mutationBlockedWithoutDeclaredCapabilities, true);
    assert.equal(trace.activeSkillHookManifest.mutationBlockedHookIds.length, 1);
    assert.equal(trace.activeSkillHookManifest.hookExecution.mutationAllowedHookIds.length, 1);
    assert.equal(trace.hookDryRunPlan.schemaVersion, "ioi.agent-runtime.hook-dry-run-plan.v1");
    assert.equal(trace.hookDryRunPlan.decisionCount, 3);
    assert.equal(trace.hookDryRunPlan.wouldRunCount, 1);
    assert.equal(trace.hookDryRunPlan.blockedCount, 1);
    assert.equal(trace.hookDryRunPlan.skippedCount, 1);
    assert.equal(trace.hookDryRunPlan.hookExecutionEnabled, false);
    assert.equal(trace.hookDryRunPlan.commandExecutionEnabled, false);
    assert.equal(trace.hookDryRunPlan.policyDecision.status, "blocked");
    assert.ok(
      trace.hookDryRunPlan.decisions.some(
        (decision) =>
          decision.decision === "blocked" &&
          decision.blockers.includes("missing_tool_contract") &&
          decision.execution.commandExecuted === false,
      ),
    );
    assert.ok(
      trace.hookDryRunPlan.decisions.some(
        (decision) =>
          decision.decision === "would_run" &&
          decision.toolContracts.includes("hook.preview") &&
          decision.execution.previewOnly === true,
      ),
    );
    assert.ok(
      trace.hookDryRunPlan.decisions.some(
        (decision) =>
          decision.decision === "skipped" &&
          decision.reason === "no_command_configured" &&
          decision.execution.commandExecuted === false,
      ),
    );
    assert.equal(trace.hookInvocationLedger.schemaVersion, "ioi.agent-runtime.hook-invocation-ledger.v1");
    assert.equal(trace.hookInvocationLedger.invocationCount, 3);
    assert.equal(trace.hookInvocationLedger.wouldRunCount, 1);
    assert.equal(trace.hookInvocationLedger.blockedCount, 1);
    assert.equal(trace.hookInvocationLedger.skippedCount, 1);
    assert.equal(trace.hookInvocationLedger.escalationCount, 1);
    assert.deepEqual(trace.hookInvocationLedger.emittedEventKinds, [
      "workflow_activation",
      "pre_model",
      "post_model",
    ]);
    const blockedInvocation = trace.hookInvocationLedger.records.find(
      (record) => record.eventKind === "pre_model" && record.state === "blocked",
    );
    assert.ok(blockedInvocation);
    assert.equal(blockedInvocation.escalation.required, true);
    assert.ok(blockedInvocation.escalation.receiptId.endsWith(blockedInvocation.invocationId.slice(-12)));
    assert.deepEqual(blockedInvocation.escalation.missingToolContracts, [
      "declare_at_least_one_tool_contract",
    ]);
    assert.deepEqual(blockedInvocation.escalation.missingAuthorityScopes, []);
    assert.match(blockedInvocation.escalation.recommendedNextAction, /toolContracts/);
    assert.equal(blockedInvocation.escalation.commandExecuted, false);
    assert.equal(trace.hookInvocationLedger.escalations.length, 1);
    assert.equal(
      trace.hookInvocationLedger.escalations[0].receiptId,
      blockedInvocation.escalation.receiptId,
    );
    assert.ok(
      trace.hookInvocationLedger.records.some(
        (record) =>
          record.eventKind === "pre_model" &&
          record.state === "blocked" &&
          record.blockers.includes("missing_tool_contract"),
      ),
    );
    assert.ok(
      trace.hookInvocationLedger.records.some(
        (record) =>
          record.eventKind === "post_model" &&
          record.state === "would_run" &&
          record.execution.commandExecuted === false,
      ),
    );
    assert.ok(
      trace.hookInvocationLedger.records.some(
        (record) =>
          record.eventKind === "workflow_activation" &&
          record.state === "skipped" &&
          record.commandConfigured === false,
      ),
    );
    assert.equal(trace.promptAudit.activeSkillHookManifestId, trace.activeSkillHookManifest.manifestId);
    assert.equal(trace.promptAudit.hookDryRunPlanId, trace.hookDryRunPlan.planId);
    assert.equal(trace.promptAudit.hookInvocationLedgerId, trace.hookInvocationLedger.ledgerId);
    assert.equal(trace.promptAudit.hookExecutionEnabled, false);
    assert.ok(
      trace.receipts.some((receipt) => receipt.kind === "active_skill_hook_manifest"),
    );
    assert.ok(
      trace.receipts.some((receipt) => receipt.kind === "hook_dry_run_plan"),
    );
    assert.ok(
      trace.receipts.some((receipt) => receipt.kind === "hook_policy_decision"),
    );
    assert.ok(
      trace.receipts.some((receipt) => receipt.kind === "hook_invocation_ledger"),
    );
    const escalationReceipt = trace.receipts.find((receipt) => receipt.kind === "hook_escalation");
    assert.ok(escalationReceipt);
    assert.equal(escalationReceipt.id, blockedInvocation.escalation.receiptId);
    assert.equal(escalationReceipt.details.schemaVersion, "ioi.agent-runtime.hook-escalation-receipt.v1");
    assert.equal(escalationReceipt.details.hookId, blockedInvocation.hookId);
    assert.equal(escalationReceipt.details.eventKind, "pre_model");
    assert.deepEqual(escalationReceipt.details.missingToolContracts, [
      "declare_at_least_one_tool_contract",
    ]);
    assert.equal(escalationReceipt.details.commandExecuted, false);
    assert.equal(escalationReceipt.details.approvalGrantCreated, false);
    const artifacts = await fetchJson(`${daemon.endpoint}/v1/runs/${runId}/artifacts`);
    assert.ok(
      artifacts.some((artifact) => artifact.name === "active-skill-hook-manifest.json"),
    );
    assert.ok(
      artifacts.some((artifact) => artifact.name === "hook-dry-run-plan.json"),
    );
    assert.ok(
      artifacts.some((artifact) => artifact.name === "hook-invocations.json"),
    );
    const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    const manifestEvent = events.find(
      (event) => event.payload_summary?.event_kind === "ActiveSkillHookManifest",
    );
    assert.equal(manifestEvent.component_kind, "skill_registry");
    assert.equal(manifestEvent.workflow_node_id, "runtime.skill-hook-manifest");
    assert.equal(manifestEvent.payload_summary.selected_skill_count, 1);
    assert.equal(manifestEvent.payload_summary.selected_hook_count, 3);
    assert.equal(manifestEvent.payload_summary.hook_execution_enabled, false);
    assert.ok(manifestEvent.artifact_refs.includes("active-skill-hook-manifest.json"));
    const hookDryRunEvent = events.find(
      (event) => event.payload_summary?.event_kind === "HookDryRunPlan",
    );
    assert.ok(hookDryRunEvent);
    assert.equal(hookDryRunEvent.component_kind, "hook_policy");
    assert.equal(hookDryRunEvent.workflow_node_id, "runtime.hook-policy");
    assert.equal(hookDryRunEvent.payload_summary.decision_count, 3);
    assert.equal(hookDryRunEvent.payload_summary.would_run_count, 1);
    assert.equal(hookDryRunEvent.payload_summary.blocked_count, 1);
    assert.equal(hookDryRunEvent.payload_summary.skipped_count, 1);
    assert.equal(hookDryRunEvent.payload_summary.policy_status, "blocked");
    assert.equal(hookDryRunEvent.payload_summary.command_execution_enabled, false);
    assert.ok(
      hookDryRunEvent.receipt_refs.some((receiptRef) =>
        receiptRef.endsWith("_hook_dry_run_plan"),
      ),
    );
    assert.ok(
      hookDryRunEvent.receipt_refs.some((receiptRef) =>
        receiptRef.endsWith("_hook_policy_decision"),
      ),
    );
    assert.ok(hookDryRunEvent.artifact_refs.includes("hook-dry-run-plan.json"));
    const hookInvocationEvent = events.find(
      (event) => event.payload_summary?.event_kind === "HookInvocationLedger",
    );
    assert.ok(hookInvocationEvent);
    assert.equal(hookInvocationEvent.component_kind, "hook_runtime");
    assert.equal(hookInvocationEvent.workflow_node_id, "runtime.hook-invocations");
    assert.equal(hookInvocationEvent.payload_summary.invocation_count, 3);
    assert.equal(hookInvocationEvent.payload_summary.would_run_count, 1);
    assert.equal(hookInvocationEvent.payload_summary.blocked_count, 1);
    assert.equal(hookInvocationEvent.payload_summary.skipped_count, 1);
    assert.equal(hookInvocationEvent.payload_summary.escalation_count, 1);
    assert.deepEqual(hookInvocationEvent.payload_summary.emitted_event_kinds, [
      "workflow_activation",
      "pre_model",
      "post_model",
    ]);
    assert.ok(
      hookInvocationEvent.receipt_refs.some((receiptRef) =>
        receiptRef.endsWith("_hook_invocation_ledger"),
      ),
    );
    assert.ok(hookInvocationEvent.receipt_refs.includes(escalationReceipt.id));
    assert.ok(hookInvocationEvent.artifact_refs.includes("hook-invocations.json"));
    const serializedProjection = JSON.stringify({ skills, hooks, doctor, turn, trace, events });
    assert.ok(!serializedProjection.includes("super-secret-hook"));
    assert.ok(!serializedProjection.includes("allowed-hook-secret"));
  } finally {
    await daemon.close();
  }
});

test("local daemon projects Agentgres runs through thread, turn, and monotonic event records", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-tti-daemon-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-tti-agentgres-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        options: {
          local: { cwd },
          model: {
            id: "auto",
            routeId: "route.native-local",
            reasoningEffort: "low",
            workflowGraphId: "tti-parity",
            workflowNodeId: "workflow.model-router",
            workflowNodeType: "Model Router",
          },
        },
      }),
    });
    assert.equal(thread.schema_version, "ioi.runtime.thread.v1");
    assert.match(thread.thread_id, /^thread_/);
    assert.match(thread.session_id, /^agent_/);
    assert.equal(thread.agent_id, thread.session_id);
    assert.equal(thread.event_stream_id, `${thread.thread_id}:events`);
    assert.equal(thread.latest_seq, 1);
    assert.equal(thread.workspace_root, cwd);
    assert.equal(thread.workspace, cwd);
    assert.equal(thread.fixture_profile, "local_daemon_agentgres_projection");
    assert.equal(thread.requested_model, "auto");
    assert.equal(thread.model_route_id, "route.native-local");
    assert.equal(thread.model_route_decision.eventKind, "ModelRouteDecision");
    assert.equal(thread.model_route_decision.requestedModelMode, "auto");
    assert.equal(thread.model_route_decision.selectedModel, "autopilot:native-fixture");
    assert.equal(thread.model_route_decision.neverSendAutoUpstream, true);
    assert.equal(thread.model_route_decision.workflowNodeId, "workflow.model-router");

    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Exercise the public thread turn event projection.",
        mode: "send",
      }),
    });
    assert.equal(turn.schema_version, "ioi.runtime.turn.v1");
    assert.equal(turn.thread_id, thread.thread_id);
    assert.match(turn.turn_id, /^turn_/);
    assert.equal(turn.status, "completed");
    assert.ok(turn.seq_start > 1);
    assert.ok(turn.seq_end >= turn.seq_start);
    assert.equal(turn.stop_reason, "evidence_sufficient");
    assert.ok(turn.quality_ledger_ref);
    assert.equal(turn.model_route_decision.eventKind, "ModelRouteDecision");
    assert.equal(turn.model_route_decision.selectedModel, "autopilot:native-fixture");

    const reloadedThread = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}`);
    assert.equal(reloadedThread.latest_turn_id, turn.turn_id);
    assert.equal(reloadedThread.turns.length, 1);
    assert.ok(reloadedThread.latest_seq > 0);

    const events = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    assert.ok(events.length >= 11);
    assert.deepEqual(
      events.map((event) => event.seq),
      Array.from({ length: events.length }, (_, index) => index + 1),
    );
    assert.equal(events[0].schema_version, "ioi.runtime.event.v1");
    assert.equal(events[0].thread_id, thread.thread_id);
    assert.equal(events[0].event_stream_id, thread.event_stream_id);
    assert.equal(events[0].event_kind, "thread.started");
    assert.equal(events[0].event, "thread.started");
    const turnStartedEvent = events.find((event) => event.event_kind === "turn.started");
    assert.equal(turnStartedEvent.turn_id, turn.turn_id);
    assert.equal(turnStartedEvent.event, "turn.started");
    assert.equal(events[0].workflow_node_id, "runtime.runtime-thread");
    const routeEvent = events.find((event) => event.payload_summary?.event_kind === "ModelRouteDecision");
    assert.equal(routeEvent.event_kind, "item.completed");
    assert.equal(routeEvent.component_kind, "model_router");
    assert.equal(routeEvent.workflow_node_id, "workflow.model-router");
    assert.equal(routeEvent.payload_summary.selected_model, "autopilot:native-fixture");
    assert.equal(routeEvent.payload.selected_model, "autopilot:native-fixture");
    assert.equal(routeEvent.payload_summary.reasoning_effort, "low");
    assert.ok(routeEvent.payload_summary.model_route_decision_id);
    assert.deepEqual(routeEvent.receipt_refs, [thread.model_route_receipt_id]);
    assert.equal(events.at(-1).event, "turn.completed");
    assert.ok(events.some((event) => event.workflow_node_id === "runtime.quality-ledger"));
    assert.ok(events.filter((event) => event.turn_id === turn.turn_id).every((event) => event.payload_summary?.run_id));

    const replayAfterFive = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=5`,
    );
    assert.equal(replayAfterFive[0].seq, 6);
    assert.ok(replayAfterFive.every((event) => event.seq > 5));

    const replayAfterHeaderSeq = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events`,
      { headers: { "last-event-id": "5" } },
    );
    assert.equal(replayAfterHeaderSeq[0].seq, 6);

    const cursorEvent = events[5];
    const replayAfterEventId = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events`,
      { headers: { "last-event-id": cursorEvent.event_id } },
    );
    assert.equal(replayAfterEventId[0].seq, cursorEvent.seq + 1);

    const streamAlias = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events/stream?since_seq=0`,
    );
    assert.deepEqual(streamAlias.map((event) => event.event_id), events.map((event) => event.event_id));

    const owningTurnEvents = events.filter((event) => event.turn_id === turn.turn_id);
    const runEvents = await fetchSseEvents(`${daemon.endpoint}/v1/runs/${turn.request_id}/events`);
    assert.deepEqual(
      runEvents.map((event) => event.event_id),
      owningTurnEvents.map((event) => event.event_id),
    );
    const runReplayAfterEventId = await fetchSseEvents(
      `${daemon.endpoint}/v1/runs/${turn.request_id}/events`,
      { headers: { "last-event-id": owningTurnEvents[0].event_id } },
    );
    assert.deepEqual(
      runReplayAfterEventId.map((event) => event.event_id),
      owningTurnEvents.slice(1).map((event) => event.event_id),
    );
    const legacyReplayAfterEventId = await fetchSseEvents(
      `${daemon.endpoint}/v1/runs/${turn.request_id}/replay`,
      { headers: { "last-event-id": owningTurnEvents[0].event_id } },
    );
    assert.deepEqual(
      legacyReplayAfterEventId.map((event) => event.event_id),
      owningTurnEvents.slice(1).map((event) => event.event_id),
    );

    const futureCursor = await fetchJsonStatus(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=${events.at(-1).seq + 100}`,
    );
    assert.equal(futureCursor.status, 409);
    assert.equal(futureCursor.body.error.code, "event_cursor_out_of_range");
    assert.equal(futureCursor.body.error.details.latestSeq, events.at(-1).seq);
  } finally {
    await daemon.close();
  }
});

test("runtime_service thread creation requires RuntimeApiBridge and preserves bridge events", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-bridge-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-bridge-state-"));
  const unavailable = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const blocked = await fetchJsonStatus(`${unavailable.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    assert.equal(blocked.status, 424);
    assert.equal(blocked.body.error.code, "external_blocker");
    assert.equal(blocked.body.error.details.requiredBridge, "RuntimeApiBridge");
    assert.equal(blocked.body.error.details.syntheticFallbackAllowed, false);
  } finally {
    await unavailable.close();
  }

  const bridgeStateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-bridge-ready-state-"));
  const runtimeSessionId = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
  const runtimeBridge = {
    bridgeId: "test-runtime-agent-service",
    async startThread(input) {
      return {
        bridge_id: "test-runtime-agent-service",
        session_id: runtimeSessionId,
        source: "runtime_service",
        status: "active",
        events: [
          {
            event_stream_id: `${input.threadId}:events`,
            thread_id: input.threadId,
            turn_id: "",
            item_id: `${input.threadId}:item:runtime-thread-started`,
            idempotency_key: `runtime-service:${runtimeSessionId}:thread.started`,
            source: "runtime_service",
            source_event_kind: "AgentState.start",
            event_kind: "thread.started",
            status: "running",
            actor: "runtime",
            created_at: "2026-05-12T00:00:00.000Z",
            workspace_root: input.workspaceRoot,
            component_kind: "runtime_thread",
            workflow_node_id: "runtime.runtime-thread",
            payload_schema_version: "ioi.runtime.thread.v1",
            payload: {
              event_kind: "AgentStateStarted",
              session_id: runtimeSessionId,
              agent_id: input.agentId,
              thread_id: input.threadId,
            },
            fixture_profile: null,
          },
        ],
      };
    },
    async submitTurn(input) {
      const turnId = "turn_runtime_bridge_001";
      return {
        run_id: "run_runtime_bridge_001",
        turn_id: turnId,
        status: "completed",
        result: "Runtime bridge turn completed.",
        stop_reason: "runtime_bridge_completed",
        created_at: "2026-05-12T00:00:01.000Z",
        updated_at: "2026-05-12T00:00:02.000Z",
        events: [
          {
            event_stream_id: `${input.threadId}:events`,
            thread_id: input.threadId,
            turn_id: turnId,
            item_id: `${turnId}:item:user-request`,
            idempotency_key: `runtime-service:${runtimeSessionId}:${turnId}:started`,
            source: "runtime_service",
            source_event_kind: "KernelEvent.AgentStep",
            event_kind: "turn.started",
            status: "running",
            actor: "user",
            created_at: "2026-05-12T00:00:01.000Z",
            workspace_root: input.workspaceRoot,
            component_kind: "runtime_turn",
            workflow_node_id: "runtime.runtime-turn",
            payload_schema_version: "ioi.runtime.event.v1",
            payload: {
              event_kind: "TurnStarted",
              prompt: input.request.prompt,
            },
            fixture_profile: null,
          },
          {
            event_stream_id: `${input.threadId}:events`,
            thread_id: input.threadId,
            turn_id: turnId,
            item_id: `${turnId}:item:assistant-result`,
            idempotency_key: `runtime-service:${runtimeSessionId}:${turnId}:completed`,
            source: "runtime_service",
            source_event_kind: "KernelEvent.AgentActionResult",
            event_kind: "turn.completed",
            status: "completed",
            actor: "assistant",
            created_at: "2026-05-12T00:00:02.000Z",
            workspace_root: input.workspaceRoot,
            component_kind: "runtime_turn",
            workflow_node_id: "runtime.runtime-turn",
            payload_schema_version: "ioi.runtime.event.v1",
            payload: {
              event_kind: "TurnCompleted",
              summary: "Runtime bridge turn completed.",
            },
            fixture_profile: null,
          },
        ],
      };
    },
  };
  const daemon = await startRuntimeDaemonService({ cwd, stateDir: bridgeStateDir, runtimeBridge });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    assert.equal(thread.schema_version, "ioi.runtime.thread.v1");
    assert.equal(thread.session_id, runtimeSessionId);
    assert.equal(thread.fixture_profile, null);
    assert.equal(thread.runtime_profile, "runtime_service");
    assert.equal(thread.runtime_bridge_id, "test-runtime-agent-service");
    assert.equal(thread.latest_seq, 1);

    const events = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    assert.equal(events.length, 1);
    assert.equal(events[0].schema_version, "ioi.runtime.event.v1");
    assert.equal(events[0].source, "runtime_service");
    assert.equal(events[0].source_event_kind, "AgentState.start");
    assert.equal(events[0].fixture_profile, null);
    assert.equal(events[0].payload.session_id, runtimeSessionId);
    assert.equal(events[0].payload.agent_id, thread.agent_id);

    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "This must flow through RuntimeApiBridge." }),
    });
    assert.equal(turn.schema_version, "ioi.runtime.turn.v1");
    assert.equal(turn.turn_id, "turn_runtime_bridge_001");
    assert.equal(turn.request_id, "run_runtime_bridge_001");
    assert.equal(turn.fixture_profile, null);
    assert.equal(turn.status, "completed");
    assert.equal(turn.seq_start, 2);
    assert.equal(turn.seq_end, 3);
    assert.equal(turn.stop_reason, "runtime_bridge_completed");

    const replayed = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    assert.deepEqual(replayed.map((event) => event.seq), [1, 2, 3]);
    assert.ok(replayed.every((event) => event.source === "runtime_service"));
    assert.ok(replayed.every((event) => event.fixture_profile === null));
    const runEvents = await fetchSseEvents(`${daemon.endpoint}/v1/runs/${turn.request_id}/events`);
    assert.deepEqual(runEvents.map((event) => event.event_id), replayed.slice(1).map((event) => event.event_id));
  } finally {
    await daemon.close();
  }
});

test("runtime_service profile auto-wires RuntimeAgentService command bridge from env", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-command-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-command-state-"));
  const bridgeDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-command-bridge-"));
  const bridgeScript = path.join(bridgeDir, "bridge-command.mjs");
  const traceFile = path.join(bridgeDir, "bridge-trace.jsonl");
  const runtimeSessionId = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
  fs.writeFileSync(
    bridgeScript,
    `
import fs from "node:fs";

const request = JSON.parse(fs.readFileSync(0, "utf8"));
fs.appendFileSync(process.env.BRIDGE_TRACE_FILE, JSON.stringify({
  schema_version: request.schema_version,
  bridge_id: request.bridge_id,
  operation: request.operation,
  runtime_profile: request.input?.runtimeProfile,
  thread_id: request.input?.threadId,
  session_id: request.input?.sessionId ?? null,
}) + "\\n");

const input = request.input ?? {};
const sessionId = "${runtimeSessionId}";

if (request.operation === "start_thread") {
  console.log("RuntimeAgentService command bridge accepted start_thread");
  console.log(JSON.stringify({
    ok: true,
    result: {
      bridge_id: request.bridge_id,
      session_id: sessionId,
      source: "runtime_service",
      status: "active",
      events: [{
        item_id: input.threadId + ":item:runtime-command-started",
        idempotency_key: "runtime-command:" + sessionId + ":thread.started",
        source_event_kind: "RuntimeAgentService.handle_service_call.start@v1",
        event_kind: "thread.started",
        status: "running",
        actor: "runtime",
        created_at: "2026-05-12T00:00:03.000Z",
        component_kind: "runtime_thread",
        workflow_node_id: "runtime.runtime-thread",
        payload_schema_version: "ioi.runtime.thread.v1",
        payload: {
          bridge_schema_version: request.schema_version,
          session_id: sessionId,
          runtime_profile: input.runtimeProfile,
        },
        fixture_profile: null,
      }],
    },
  }));
} else if (request.operation === "submit_turn") {
  const turnId = "turn_runtime_command_001";
  console.log(JSON.stringify({
    ok: true,
    result: {
      bridge_id: request.bridge_id,
      run_id: "run_runtime_command_001",
      turn_id: turnId,
      source: "runtime_service",
      status: "completed",
      result: "RuntimeAgentService command bridge turn completed.",
      stop_reason: "runtime_bridge_completed",
      created_at: "2026-05-12T00:00:04.000Z",
      updated_at: "2026-05-12T00:00:05.000Z",
      events: [
        {
          item_id: turnId + ":item:user-message",
          idempotency_key: "runtime-command:" + sessionId + ":" + turnId + ":started",
          source_event_kind: "RuntimeAgentService.handle_service_call.post_message@v1",
          event_kind: "turn.started",
          status: "running",
          actor: "user",
          created_at: "2026-05-12T00:00:04.000Z",
          component_kind: "runtime_turn",
          workflow_node_id: "runtime.runtime-turn",
          payload_schema_version: "ioi.runtime.event.v1",
          payload: {
            prompt: input.request?.prompt,
            session_id: input.sessionId,
          },
          fixture_profile: null,
        },
        {
          item_id: turnId + ":item:assistant-message",
          idempotency_key: "runtime-command:" + sessionId + ":" + turnId + ":completed",
          source_event_kind: "RuntimeAgentService.handle_service_call.step@v1",
          event_kind: "turn.completed",
          status: "completed",
          actor: "assistant",
          created_at: "2026-05-12T00:00:05.000Z",
          component_kind: "runtime_turn",
          workflow_node_id: "runtime.runtime-turn",
          payload_schema_version: "ioi.runtime.event.v1",
          payload: {
            summary: "RuntimeAgentService command bridge turn completed.",
            session_id: input.sessionId,
          },
          fixture_profile: null,
        },
      ],
    },
  }));
} else {
  console.log(JSON.stringify({
    ok: false,
    error: {
      code: "unsupported_operation",
      message: "unsupported operation " + request.operation,
    },
  }));
}
`,
  );

  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
    trace: process.env.BRIDGE_TRACE_FILE,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = process.execPath;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify([bridgeScript]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "env-command-runtime-agent-service";
  process.env.BRIDGE_TRACE_FILE = traceFile;

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    assert.equal(thread.session_id, runtimeSessionId);
    assert.equal(thread.runtime_bridge_id, "env-command-runtime-agent-service");
    assert.equal(thread.fixture_profile, null);

    const startEvents = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    assert.equal(startEvents.length, 1);
    assert.equal(startEvents[0].source_event_kind, "RuntimeAgentService.handle_service_call.start@v1");
    assert.equal(startEvents[0].payload.bridge_schema_version, "ioi.runtime.bridge.command.v1");

    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "Flow through the command bridge." }),
    });
    assert.equal(turn.turn_id, "turn_runtime_command_001");
    assert.equal(turn.request_id, "run_runtime_command_001");
    assert.equal(turn.status, "completed");
    assert.equal(turn.stop_reason, "runtime_bridge_completed");
    assert.equal(turn.fixture_profile, null);
    assert.equal(turn.seq_start, 2);
    assert.equal(turn.seq_end, 3);

    const trace = fs.readFileSync(traceFile, "utf8")
      .trim()
      .split(/\r?\n/)
      .map((line) => JSON.parse(line));
    assert.deepEqual(trace.map((entry) => entry.operation), ["start_thread", "submit_turn"]);
    assert.ok(trace.every((entry) => entry.schema_version === "ioi.runtime.bridge.command.v1"));
    assert.ok(trace.every((entry) => entry.bridge_id === "env-command-runtime-agent-service"));
    assert.equal(trace[0].runtime_profile, "runtime_service");
    assert.equal(trace[1].session_id, runtimeSessionId);
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
    restoreEnv("BRIDGE_TRACE_FILE", previousEnv.trace);
  }
});

test("runtime_service profile auto-wires the Rust RuntimeAgentService bridge executable from env", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-rust-bridge-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-rust-bridge-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-rust-bridge-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-contract";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Start a durable Rust-backed runtime-service thread.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    assert.equal(thread.schema_version, "ioi.runtime.thread.v1");
    assert.match(thread.session_id, /^[a-f0-9]{64}$/);
    assert.equal(thread.runtime_profile, "runtime_service");
    assert.equal(thread.runtime_bridge_id, "rust-runtime-agent-service-contract");
    assert.equal(thread.fixture_profile, null);
    assert.equal(thread.latest_seq, 1);

    const startEvents = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    assert.equal(startEvents.length, 1);
    assert.equal(startEvents[0].source, "runtime_service");
    assert.equal(startEvents[0].source_event_kind, "RuntimeAgentService.handle_service_call.start@v1");
    assert.equal(startEvents[0].event_kind, "thread.started");
    assert.equal(startEvents[0].component_kind, "runtime_thread");
    assert.equal(startEvents[0].workflow_node_id, "runtime.runtime-thread");
    assert.equal(startEvents[0].fixture_profile, null);
    assert.equal(startEvents[0].payload.bridge_schema_version, "ioi.runtime.bridge.command.v1");
    assert.equal(startEvents[0].payload.session_id, thread.session_id);
    assert.equal(startEvents[0].payload.goal, "Start a durable Rust-backed runtime-service thread.");
    assert.equal(Number(startEvents[0].payload.max_steps), 2);

    const prompt = "Exercise the Rust RuntimeAgentService bridge executable.";
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt }),
    });
    assert.equal(turn.schema_version, "ioi.runtime.turn.v1");
    assert.match(turn.turn_id, /^turn_runtime_service_[a-f0-9]{16}_\d+$/);
    assert.match(turn.request_id, /^run_runtime_service_[a-f0-9]{16}_\d+$/);
    assert.equal(turn.fixture_profile, null);
    assert.ok(["completed", "blocked", "failed"].includes(turn.status));
    assert.match(turn.stop_reason, /^runtime_bridge_/);
    assert.equal(turn.seq_start, 2);
    assert.ok(turn.seq_end >= 3);

    const replayed = await fetchSseEvents(`${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`);
    assert.ok(replayed.length >= 4);
    assert.equal(turn.seq_end, replayed.at(-1).seq);
    assert.equal(replayed[0].source_event_kind, "RuntimeAgentService.handle_service_call.start@v1");
    assert.equal(replayed[1].source_event_kind, "RuntimeAgentService.handle_service_call.post_message@v1");
    assert.equal(replayed.at(-1).source_event_kind, "RuntimeAgentService.handle_service_call.step@v1");
    assert.deepEqual(replayed.map((event) => event.event_kind).slice(0, 2), [
      "thread.started",
      "turn.started",
    ]);
    const mappedKernelEvents = replayed.slice(2, -1);
    assert.ok(mappedKernelEvents.length >= 1);
    const actionResultEvent = mappedKernelEvents.find(
      (event) => event.source_event_kind === "KernelEvent::AgentActionResult",
    );
    assert.ok(actionResultEvent);
    assert.ok(["tool.completed", "tool.failed"].includes(actionResultEvent.event_kind));
    assert.equal(actionResultEvent.component_kind, "tool_result");
    assert.equal(actionResultEvent.workflow_node_id, "runtime.tool-result");
    assert.equal(actionResultEvent.payload_schema_version, "ioi.runtime.kernel-event.v1");
    assert.equal(actionResultEvent.payload.event_kind, "KernelEvent::AgentActionResult");
    assert.equal(actionResultEvent.payload.tool_name, "system::intent_clarification");
    assert.equal(actionResultEvent.payload.agent_status, "Paused");
    assert.equal(Number(actionResultEvent.payload.step_index), 0);
    assert.ok(["turn.completed", "turn.failed"].includes(replayed.at(-1).event_kind));
    assert.ok(replayed.every((event) => event.source === "runtime_service"));
    assert.ok(replayed.every((event) => event.fixture_profile === null));
    assert.ok(replayed.every((event) => event.payload.session_id === thread.session_id));
    assert.equal(replayed[1].payload.prompt, prompt);
    assert.equal(typeof replayed.at(-1).payload.agent_status, "string");
    assert.ok(Number.isFinite(Number(replayed.at(-1).payload.step_count)));
    assert.ok(fs.existsSync(path.join(bridgeData, "runtime-state.redb")));
    assert.ok(fs.existsSync(path.join(bridgeData, "desktop-memory.db")));

    const runEvents = await fetchSseEvents(`${daemon.endpoint}/v1/runs/${turn.request_id}/events`);
    assert.deepEqual(
      runEvents.map((event) => event.event_id),
      replayed.slice(1).map((event) => event.event_id),
    );

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkActionResult = sdkEvents.find(
      (event) => event.sourceEventKind === "KernelEvent::AgentActionResult",
    );
    assert.ok(sdkActionResult);
    assert.ok(["tool_completed", "tool_failed"].includes(sdkActionResult.type));
    assert.equal(sdkActionResult.payloadSchemaVersion, "ioi.runtime.kernel-event.v1");
    assert.equal(sdkActionResult.componentKind, "tool_result");
    assert.equal(sdkActionResult.workflowNodeId, "runtime.tool-result");
    assert.equal(sdkActionResult.toolName, "system::intent_clarification");
    assert.equal(sdkActionResult.agentStatus, "Paused");
    assert.equal(sdkActionResult.stepIndex, 0);
    const sdkTurn = await sdkThread.turn(turn.turn_id);
    const sdkTurnEvents = await collect(sdkTurn.events());
    assert.deepEqual(
      sdkTurnEvents.map((event) => event.id),
      replayed.slice(1).map((event) => event.event_id),
    );
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("mapped KernelEvent row keeps one canonical sequence across SDK, CLI, and React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const { projectRuntimeThreadEventsToWorkflowProjection } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-cross-surface-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-cross-surface-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-cross-surface-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-cross-surface";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove one mapped KernelEvent has one cross-surface sequence.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Emit a mapped KernelEvent that every operator surface can inspect.",
      }),
    });

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const daemonKernelEvent = daemonEvents.find(
      (event) => event.source_event_kind === "KernelEvent::AgentActionResult",
    );
    assert.ok(daemonKernelEvent);
    assert.ok(["tool.completed", "tool.failed"].includes(daemonKernelEvent.event_kind));
    assert.equal(daemonKernelEvent.turn_id, turn.turn_id);
    assert.equal(daemonKernelEvent.component_kind, "tool_result");
    assert.equal(daemonKernelEvent.workflow_node_id, "runtime.tool-result");
    assert.equal(daemonKernelEvent.payload_schema_version, "ioi.runtime.kernel-event.v1");

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkKernelEvent = sdkEvents.find((event) => event.id === daemonKernelEvent.event_id);
    assert.ok(sdkKernelEvent);

    const cliResult = await execFileAsync(
      cli,
      [
        "agent",
        "stream",
        "--thread-id",
        thread.thread_id,
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const cliProjection = JSON.parse(cliResult.stdout);
    const cliKernelEvent = cliProjection.events.find(
      (event) => event.event_id === daemonKernelEvent.event_id,
    );
    assert.ok(cliKernelEvent);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(daemonKernelEvent.event_id),
    );
    assert.ok(reactFlowNode);

    const canonicalCursor = `${daemonKernelEvent.event_stream_id}:${daemonKernelEvent.seq}`;
    assert.equal(sdkKernelEvent.id, daemonKernelEvent.event_id);
    assert.equal(sdkKernelEvent.seq, daemonKernelEvent.seq);
    assert.equal(sdkKernelEvent.cursor, canonicalCursor);
    assert.equal(sdkKernelEvent.eventKind, daemonKernelEvent.event_kind);
    assert.equal(sdkKernelEvent.sourceEventKind, daemonKernelEvent.source_event_kind);
    assert.equal(sdkKernelEvent.componentKind, daemonKernelEvent.component_kind);
    assert.equal(sdkKernelEvent.workflowNodeId, daemonKernelEvent.workflow_node_id);
    assert.equal(sdkKernelEvent.payloadSchemaVersion, daemonKernelEvent.payload_schema_version);
    assert.deepEqual(sdkKernelEvent.receiptRefs, daemonKernelEvent.receipt_refs);
    assert.deepEqual(sdkKernelEvent.policyDecisionRefs, daemonKernelEvent.policy_decision_refs);
    assert.deepEqual(sdkKernelEvent.artifactRefs, daemonKernelEvent.artifact_refs);
    assert.deepEqual(sdkKernelEvent.rollbackRefs, daemonKernelEvent.rollback_refs);

    assert.equal(cliProjection.schema_version, "ioi.agent-cli.runtime-event-stream.v1");
    assert.equal(cliKernelEvent.seq, daemonKernelEvent.seq);
    assert.equal(cliKernelEvent.event_stream_id, daemonKernelEvent.event_stream_id);
    assert.equal(cliKernelEvent.event_kind, daemonKernelEvent.event_kind);
    assert.equal(cliKernelEvent.source_event_kind, daemonKernelEvent.source_event_kind);
    assert.equal(cliKernelEvent.component_kind, daemonKernelEvent.component_kind);
    assert.equal(cliKernelEvent.workflow_node_id, daemonKernelEvent.workflow_node_id);
    assert.equal(cliKernelEvent.payload_schema_version, daemonKernelEvent.payload_schema_version);
    assert.deepEqual(cliKernelEvent.receipt_refs, daemonKernelEvent.receipt_refs);
    assert.deepEqual(cliKernelEvent.policy_decision_refs, daemonKernelEvent.policy_decision_refs);
    assert.deepEqual(cliKernelEvent.artifact_refs, daemonKernelEvent.artifact_refs);
    assert.deepEqual(cliKernelEvent.rollback_refs, daemonKernelEvent.rollback_refs);

    assert.equal(reactFlowNode.latestSeq, daemonKernelEvent.seq);
    assert.equal(reactFlowNode.latestCursor, canonicalCursor);
    assert.equal(reactFlowNode.latestEventId, daemonKernelEvent.event_id);
    assert.equal(reactFlowNode.componentKind, daemonKernelEvent.component_kind);
    assert.equal(reactFlowNode.workflowNodeId, daemonKernelEvent.workflow_node_id);
    assert.equal(reactFlowNode.latestPayloadSchemaVersion, daemonKernelEvent.payload_schema_version);
    assert.deepEqual(reactFlowNode.receiptRefs, daemonKernelEvent.receipt_refs);
    assert.deepEqual(reactFlowNode.policyDecisionRefs, daemonKernelEvent.policy_decision_refs);
    assert.deepEqual(reactFlowNode.artifactRefs, daemonKernelEvent.artifact_refs);
    assert.deepEqual(reactFlowNode.rollbackRefs, daemonKernelEvent.rollback_refs);
    assert.ok(reactFlowNode.sourceEventKinds.includes(daemonKernelEvent.source_event_kind));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("operator interrupt keeps one canonical control event across SDK, CLI, and React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const { projectRuntimeThreadEventsToWorkflowProjection } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-interrupt-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-interrupt-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-interrupt-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-interrupt";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove operator interrupt control has one cross-surface event.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare an interruptible turn for operator control validation.",
      }),
    });

    const cliResult = await execFileAsync(
      cli,
      [
        "agent",
        "interrupt",
        "--thread-id",
        thread.thread_id,
        "--turn-id",
        turn.turn_id,
        "--reason",
        "operator validation interrupt",
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const cliTurn = JSON.parse(cliResult.stdout);
    assert.equal(cliTurn.status, "interrupted");
    assert.equal(cliTurn.stop_reason, "operator_interrupt");

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const interruptEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Interrupt",
    );
    assert.ok(interruptEvent);
    assert.equal(interruptEvent.event_kind, "turn.interrupted");
    assert.equal(interruptEvent.status, "interrupted");
    assert.equal(interruptEvent.source, "cli_tui");
    assert.equal(interruptEvent.actor, "user");
    assert.equal(interruptEvent.thread_id, thread.thread_id);
    assert.equal(interruptEvent.turn_id, turn.turn_id);
    assert.equal(interruptEvent.component_kind, "operator_control");
    assert.equal(interruptEvent.workflow_node_id, "runtime.operator-interrupt");
    assert.equal(interruptEvent.payload_schema_version, "ioi.runtime.operator-control.v1");
    assert.equal(interruptEvent.payload.reason, "operator validation interrupt");
    assert.ok(interruptEvent.receipt_refs.includes(`receipt_${turn.request_id}_operator_interrupt`));
    assert.ok(interruptEvent.policy_decision_refs.includes(`policy_${turn.request_id}_operator_interrupt_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkTurn = await sdkThread.turn(turn.turn_id);
    assert.equal(sdkTurn.status, "interrupted");
    const sdkInterrupted = await sdkTurn.interrupt({ reason: "sdk idempotency probe" });
    assert.equal(sdkInterrupted.status, "interrupted");
    const afterSdkInterrupt = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    assert.equal(
      afterSdkInterrupt.filter((event) => event.source_event_kind === "OperatorControl.Interrupt").length,
      1,
    );

    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkInterruptEvent = sdkEvents.find((event) => event.id === interruptEvent.event_id);
    assert.ok(sdkInterruptEvent);
    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(interruptEvent.event_id),
    );
    assert.ok(reactFlowNode);

    const canonicalCursor = `${interruptEvent.event_stream_id}:${interruptEvent.seq}`;
    assert.equal(sdkInterruptEvent.type, "turn_interrupted");
    assert.equal(sdkInterruptEvent.seq, interruptEvent.seq);
    assert.equal(sdkInterruptEvent.cursor, canonicalCursor);
    assert.equal(sdkInterruptEvent.eventKind, interruptEvent.event_kind);
    assert.equal(sdkInterruptEvent.sourceEventKind, interruptEvent.source_event_kind);
    assert.equal(sdkInterruptEvent.componentKind, interruptEvent.component_kind);
    assert.equal(sdkInterruptEvent.workflowNodeId, interruptEvent.workflow_node_id);
    assert.equal(sdkInterruptEvent.payloadSchemaVersion, interruptEvent.payload_schema_version);
    assert.deepEqual(sdkInterruptEvent.receiptRefs, interruptEvent.receipt_refs);
    assert.deepEqual(sdkInterruptEvent.policyDecisionRefs, interruptEvent.policy_decision_refs);

    assert.equal(reactFlowNode.latestSeq, interruptEvent.seq);
    assert.equal(reactFlowNode.latestCursor, canonicalCursor);
    assert.equal(reactFlowNode.latestEventId, interruptEvent.event_id);
    assert.equal(reactFlowNode.componentKind, "operator_control");
    assert.equal(reactFlowNode.workflowNodeId, "runtime.operator-interrupt");
    assert.equal(reactFlowNode.status, "interrupted");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Interrupt"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("React Flow operator interrupt control preserves graph identity across daemon, SDK, and projection", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeOperatorInterruptControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-interrupt-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-interrupt-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-interrupt-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const reason = "pause live turn from React Flow control";
  const workflowGraphId = "workflow.react-flow.operator-interrupt-proof";
  const workflowNodeId = "runtime.operator-interrupt";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-react-flow-interrupt";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove React Flow-originated operator interrupt keeps graph identity.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a React Flow-originated interrupt control validation.",
      }),
    });

    const workflowNode = {
      id: "react-flow-operator-interrupt-control",
      type: "runtime_operator_interrupt",
      config: {
        logic: {
          runtimeOperatorInterruptEndpoint: "/v1/threads/{threadId}/turns/{turnId}/interrupt",
          runtimeOperatorInterruptThreadIdField: "threadId",
          runtimeOperatorInterruptTurnIdField: "turnId",
          runtimeOperatorInterruptReasonField: "reason",
          runtimeOperatorInterruptWorkflowNodeId: workflowNodeId,
          runtimeOperatorInterruptActor: "operator",
        },
        law: { privilegedActions: ["runtime.turn.interrupt"] },
      },
    };
    const control = createRuntimeOperatorInterruptControlRequestFromWorkflowNode(
      workflowNode,
      { threadId: thread.thread_id, turnId: turn.turn_id, reason },
      { workflowGraphId },
    );
    assert.equal(control.nodeType, "runtime_operator_interrupt");
    assert.equal(control.body.source, "react_flow");
    assert.equal(control.body.workflowGraphId, workflowGraphId);
    assert.equal(control.body.workflowNodeId, workflowNodeId);
    assert.equal(control.body.componentKind, "operator_control");

    const interrupted = await fetchJson(`${daemon.endpoint}${control.endpoint}`, {
      method: "POST",
      body: JSON.stringify(control.body),
    });
    assert.equal(interrupted.turn_id, turn.turn_id);
    assert.equal(interrupted.status, "interrupted");
    assert.equal(interrupted.stop_reason, "operator_interrupt");

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const interruptEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Interrupt" && event.source === "react_flow",
    );
    assert.ok(interruptEvent);
    assert.equal(interruptEvent.event_kind, "turn.interrupted");
    assert.equal(interruptEvent.status, "interrupted");
    assert.equal(interruptEvent.source, "react_flow");
    assert.equal(interruptEvent.actor, "user");
    assert.equal(interruptEvent.thread_id, thread.thread_id);
    assert.equal(interruptEvent.turn_id, turn.turn_id);
    assert.equal(interruptEvent.workflow_graph_id, workflowGraphId);
    assert.equal(interruptEvent.workflow_node_id, workflowNodeId);
    assert.equal(interruptEvent.component_kind, "operator_control");
    assert.equal(interruptEvent.payload_schema_version, "ioi.runtime.operator-control.v1");
    assert.equal(interruptEvent.payload.reason, reason);
    assert.equal(interruptEvent.payload.requested_by, "operator");
    assert.ok(interruptEvent.receipt_refs.includes(`receipt_${turn.request_id}_operator_interrupt`));
    assert.ok(interruptEvent.policy_decision_refs.includes(`policy_${turn.request_id}_operator_interrupt_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkInterruptEvent = sdkEvents.find((event) => event.id === interruptEvent.event_id);
    assert.ok(sdkInterruptEvent);
    assert.equal(sdkInterruptEvent.type, "turn_interrupted");
    assert.equal(sdkInterruptEvent.sourceEventKind, "OperatorControl.Interrupt");
    assert.equal(sdkInterruptEvent.componentKind, "operator_control");
    assert.equal(sdkInterruptEvent.workflowGraphId, workflowGraphId);
    assert.equal(sdkInterruptEvent.workflowNodeId, workflowNodeId);
    assert.deepEqual(sdkInterruptEvent.receiptRefs, interruptEvent.receipt_refs);
    assert.deepEqual(sdkInterruptEvent.policyDecisionRefs, interruptEvent.policy_decision_refs);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(interruptEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.ok(reactFlowProjection.workflowGraphIds.includes(workflowGraphId));
    assert.equal(reactFlowNode.nodeKind, "runtime_operator_interrupt");
    assert.equal(reactFlowNode.componentKind, "operator_control");
    assert.equal(reactFlowNode.workflowGraphId, workflowGraphId);
    assert.equal(reactFlowNode.workflowNodeId, workflowNodeId);
    assert.equal(reactFlowNode.status, "interrupted");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Interrupt"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("operator steer keeps one canonical guidance event across SDK, CLI, and React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const { projectRuntimeThreadEventsToWorkflowProjection } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-steer-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-steer-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-steer-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const guidance = "focus on the current failing assertion";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-steer";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove operator steer control has one cross-surface event.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a steerable turn for operator control validation.",
      }),
    });

    const cliResult = await execFileAsync(
      cli,
      [
        "agent",
        "steer",
        "--thread-id",
        thread.thread_id,
        "--turn-id",
        turn.turn_id,
        "--guidance",
        guidance,
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const cliTurn = JSON.parse(cliResult.stdout);
    assert.equal(cliTurn.status, turn.status);
    assert.equal(cliTurn.stop_reason, turn.stop_reason);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const steerEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Steer",
    );
    assert.ok(steerEvent);
    assert.equal(steerEvent.event_kind, "turn.steered");
    assert.equal(steerEvent.status, "completed");
    assert.equal(steerEvent.source, "cli_tui");
    assert.equal(steerEvent.actor, "user");
    assert.equal(steerEvent.thread_id, thread.thread_id);
    assert.equal(steerEvent.turn_id, turn.turn_id);
    assert.equal(steerEvent.component_kind, "operator_control");
    assert.equal(steerEvent.workflow_node_id, "runtime.operator-steer");
    assert.equal(steerEvent.payload_schema_version, "ioi.runtime.operator-control.v1");
    assert.equal(steerEvent.payload.guidance, guidance);
    assert.ok(steerEvent.receipt_refs.some((ref) => ref.startsWith(`receipt_${turn.request_id}_operator_steer_`)));
    assert.ok(steerEvent.policy_decision_refs.includes(`policy_${turn.request_id}_operator_steer_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkTurn = await sdkThread.turn(turn.turn_id);
    assert.equal(sdkTurn.status, cliTurn.status);
    const sdkSteered = await sdkTurn.steer({ guidance });
    assert.equal(sdkSteered.status, cliTurn.status);
    const afterSdkSteer = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    assert.equal(
      afterSdkSteer.filter((event) => event.source_event_kind === "OperatorControl.Steer").length,
      1,
    );

    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkSteerEvent = sdkEvents.find((event) => event.id === steerEvent.event_id);
    assert.ok(sdkSteerEvent);
    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(steerEvent.event_id),
    );
    assert.ok(reactFlowNode);

    const canonicalCursor = `${steerEvent.event_stream_id}:${steerEvent.seq}`;
    assert.equal(sdkSteerEvent.type, "turn_steered");
    assert.equal(sdkSteerEvent.seq, steerEvent.seq);
    assert.equal(sdkSteerEvent.cursor, canonicalCursor);
    assert.equal(sdkSteerEvent.eventKind, steerEvent.event_kind);
    assert.equal(sdkSteerEvent.sourceEventKind, steerEvent.source_event_kind);
    assert.equal(sdkSteerEvent.componentKind, steerEvent.component_kind);
    assert.equal(sdkSteerEvent.workflowNodeId, steerEvent.workflow_node_id);
    assert.equal(sdkSteerEvent.payloadSchemaVersion, steerEvent.payload_schema_version);
    assert.deepEqual(sdkSteerEvent.receiptRefs, steerEvent.receipt_refs);
    assert.deepEqual(sdkSteerEvent.policyDecisionRefs, steerEvent.policy_decision_refs);

    assert.equal(reactFlowNode.latestSeq, steerEvent.seq);
    assert.equal(reactFlowNode.latestCursor, canonicalCursor);
    assert.equal(reactFlowNode.latestEventId, steerEvent.event_id);
    assert.equal(reactFlowNode.componentKind, "operator_control");
    assert.equal(reactFlowNode.workflowNodeId, "runtime.operator-steer");
    assert.equal(reactFlowNode.status, "completed");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Steer"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("React Flow operator steer control preserves graph identity across daemon, SDK, and projection", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeOperatorSteerControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-steer-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-steer-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-steer-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const guidance = "focus live turn from React Flow steer control";
  const workflowGraphId = "workflow.react-flow.operator-steer-proof";
  const workflowNodeId = "runtime.operator-steer";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-react-flow-steer";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove React Flow-originated operator steer keeps graph identity.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a React Flow-originated steer control validation.",
      }),
    });

    const workflowNode = {
      id: "react-flow-operator-steer-control",
      type: "runtime_operator_steer",
      config: {
        logic: {
          runtimeOperatorSteerEndpoint: "/v1/threads/{threadId}/turns/{turnId}/steer",
          runtimeOperatorSteerThreadIdField: "threadId",
          runtimeOperatorSteerTurnIdField: "turnId",
          runtimeOperatorSteerGuidanceField: "guidance",
          runtimeOperatorSteerWorkflowNodeId: workflowNodeId,
          runtimeOperatorSteerActor: "operator",
        },
        law: { privilegedActions: ["runtime.turn.steer"] },
      },
    };
    const control = createRuntimeOperatorSteerControlRequestFromWorkflowNode(
      workflowNode,
      { threadId: thread.thread_id, turnId: turn.turn_id, guidance },
      { workflowGraphId },
    );
    assert.equal(control.nodeType, "runtime_operator_steer");
    assert.equal(control.body.source, "react_flow");
    assert.equal(control.body.workflowGraphId, workflowGraphId);
    assert.equal(control.body.workflowNodeId, workflowNodeId);
    assert.equal(control.body.componentKind, "operator_control");

    const steered = await fetchJson(`${daemon.endpoint}${control.endpoint}`, {
      method: "POST",
      body: JSON.stringify(control.body),
    });
    assert.equal(steered.turn_id, turn.turn_id);
    assert.equal(steered.status, turn.status);
    assert.equal(steered.stop_reason, turn.stop_reason);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const steerEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Steer" && event.source === "react_flow",
    );
    assert.ok(steerEvent);
    assert.equal(steerEvent.event_kind, "turn.steered");
    assert.equal(steerEvent.status, "completed");
    assert.equal(steerEvent.source, "react_flow");
    assert.equal(steerEvent.actor, "user");
    assert.equal(steerEvent.thread_id, thread.thread_id);
    assert.equal(steerEvent.turn_id, turn.turn_id);
    assert.equal(steerEvent.workflow_graph_id, workflowGraphId);
    assert.equal(steerEvent.workflow_node_id, workflowNodeId);
    assert.equal(steerEvent.component_kind, "operator_control");
    assert.equal(steerEvent.payload_schema_version, "ioi.runtime.operator-control.v1");
    assert.equal(steerEvent.payload.guidance, guidance);
    assert.equal(steerEvent.payload.requested_by, "operator");
    assert.ok(steerEvent.receipt_refs.some((ref) => ref.startsWith(`receipt_${turn.request_id}_operator_steer_`)));
    assert.ok(steerEvent.policy_decision_refs.includes(`policy_${turn.request_id}_operator_steer_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkSteerEvent = sdkEvents.find((event) => event.id === steerEvent.event_id);
    assert.ok(sdkSteerEvent);
    assert.equal(sdkSteerEvent.type, "turn_steered");
    assert.equal(sdkSteerEvent.sourceEventKind, "OperatorControl.Steer");
    assert.equal(sdkSteerEvent.componentKind, "operator_control");
    assert.equal(sdkSteerEvent.workflowGraphId, workflowGraphId);
    assert.equal(sdkSteerEvent.workflowNodeId, workflowNodeId);
    assert.deepEqual(sdkSteerEvent.receiptRefs, steerEvent.receipt_refs);
    assert.deepEqual(sdkSteerEvent.policyDecisionRefs, steerEvent.policy_decision_refs);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(steerEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.ok(reactFlowProjection.workflowGraphIds.includes(workflowGraphId));
    assert.equal(reactFlowNode.nodeKind, "runtime_operator_steer");
    assert.equal(reactFlowNode.componentKind, "operator_control");
    assert.equal(reactFlowNode.workflowGraphId, workflowGraphId);
    assert.equal(reactFlowNode.workflowNodeId, workflowNodeId);
    assert.equal(reactFlowNode.status, "completed");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Steer"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("context compact keeps one canonical compaction event across SDK, CLI, and React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const { projectRuntimeThreadEventsToWorkflowProjection } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-compact-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-compact-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-compact-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const reason = "reduce stale context for live validation";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-compact";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove context compact control has one cross-surface event.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a turn with context for compaction validation.",
      }),
    });

    const cliResult = await execFileAsync(
      cli,
      [
        "agent",
        "compact",
        "--thread-id",
        thread.thread_id,
        "--reason",
        reason,
        "--scope",
        "thread",
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const cliThread = JSON.parse(cliResult.stdout);
    assert.equal(cliThread.thread_id, thread.thread_id);
    assert.ok(cliThread.latest_seq > thread.latest_seq);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const compactEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Compact",
    );
    assert.ok(compactEvent);
    assert.equal(compactEvent.event_kind, "context.compacted");
    assert.equal(compactEvent.status, "completed");
    assert.equal(compactEvent.source, "cli_tui");
    assert.equal(compactEvent.actor, "user");
    assert.equal(compactEvent.thread_id, thread.thread_id);
    assert.equal(compactEvent.turn_id, turn.turn_id);
    assert.equal(compactEvent.component_kind, "context_compaction");
    assert.equal(compactEvent.workflow_node_id, "runtime.context-compact");
    assert.equal(compactEvent.payload_schema_version, "ioi.runtime.context-compaction.v1");
    assert.equal(compactEvent.payload.reason, reason);
    assert.equal(compactEvent.payload.scope, "thread");
    assert.ok(compactEvent.receipt_refs.some((ref) =>
      ref.startsWith(`receipt_${turn.request_id}_context_compaction_`),
    ));
    assert.ok(compactEvent.policy_decision_refs.includes(`policy_${turn.request_id}_context_compaction_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkCompacted = await sdkThread.compact({ reason, scope: "thread" });
    assert.equal(sdkCompacted.id, thread.thread_id);
    const afterSdkCompact = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    assert.equal(
      afterSdkCompact.filter((event) => event.source_event_kind === "OperatorControl.Compact").length,
      1,
    );

    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkCompactEvent = sdkEvents.find((event) => event.id === compactEvent.event_id);
    assert.ok(sdkCompactEvent);
    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(compactEvent.event_id),
    );
    assert.ok(reactFlowNode);

    const canonicalCursor = `${compactEvent.event_stream_id}:${compactEvent.seq}`;
    assert.equal(sdkCompactEvent.type, "context_compacted");
    assert.equal(sdkCompactEvent.seq, compactEvent.seq);
    assert.equal(sdkCompactEvent.cursor, canonicalCursor);
    assert.equal(sdkCompactEvent.eventKind, compactEvent.event_kind);
    assert.equal(sdkCompactEvent.sourceEventKind, compactEvent.source_event_kind);
    assert.equal(sdkCompactEvent.componentKind, compactEvent.component_kind);
    assert.equal(sdkCompactEvent.workflowNodeId, compactEvent.workflow_node_id);
    assert.equal(sdkCompactEvent.payloadSchemaVersion, compactEvent.payload_schema_version);
    assert.deepEqual(sdkCompactEvent.receiptRefs, compactEvent.receipt_refs);
    assert.deepEqual(sdkCompactEvent.policyDecisionRefs, compactEvent.policy_decision_refs);

    assert.equal(reactFlowNode.latestSeq, compactEvent.seq);
    assert.equal(reactFlowNode.latestCursor, canonicalCursor);
    assert.equal(reactFlowNode.latestEventId, compactEvent.event_id);
    assert.equal(reactFlowNode.componentKind, "context_compaction");
    assert.equal(reactFlowNode.workflowNodeId, "runtime.context-compact");
    assert.equal(reactFlowNode.status, "completed");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Compact"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("React Flow context compact control preserves graph identity across daemon, SDK, and projection", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeContextCompactControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-compact-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-compact-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-compact-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const reason = "reduce live context from React Flow compact control";
  const scope = "thread";
  const workflowGraphId = "workflow.react-flow.context-compact-proof";
  const workflowNodeId = "runtime.context-compact";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-react-flow-compact";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove React Flow-originated context compact keeps graph identity.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a React Flow-originated context compact validation.",
      }),
    });

    const workflowNode = {
      id: "react-flow-context-compact-control",
      type: "runtime_context_compact",
      config: {
        logic: {
          runtimeContextCompactEndpoint: "/v1/threads/{threadId}/compact",
          runtimeContextCompactThreadIdField: "threadId",
          runtimeContextCompactTurnIdField: "turnId",
          runtimeContextCompactReasonField: "reason",
          runtimeContextCompactScopeField: "scope",
          runtimeContextCompactWorkflowNodeId: workflowNodeId,
          runtimeContextCompactActor: "operator",
        },
        law: { privilegedActions: ["runtime.context.compact"] },
      },
    };
    const control = createRuntimeContextCompactControlRequestFromWorkflowNode(
      workflowNode,
      { threadId: thread.thread_id, turnId: turn.turn_id, reason, scope },
      { workflowGraphId },
    );
    assert.equal(control.nodeType, "runtime_context_compact");
    assert.equal(control.body.source, "react_flow");
    assert.equal(control.body.workflowGraphId, workflowGraphId);
    assert.equal(control.body.workflowNodeId, workflowNodeId);
    assert.equal(control.body.componentKind, "context_compaction");

    const compacted = await fetchJson(`${daemon.endpoint}${control.endpoint}`, {
      method: "POST",
      body: JSON.stringify(control.body),
    });
    assert.equal(compacted.thread_id, thread.thread_id);
    assert.ok(compacted.latest_seq > thread.latest_seq);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const compactEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Compact" && event.source === "react_flow",
    );
    assert.ok(compactEvent);
    assert.equal(compactEvent.event_kind, "context.compacted");
    assert.equal(compactEvent.status, "completed");
    assert.equal(compactEvent.source, "react_flow");
    assert.equal(compactEvent.actor, "user");
    assert.equal(compactEvent.thread_id, thread.thread_id);
    assert.equal(compactEvent.turn_id, turn.turn_id);
    assert.equal(compactEvent.workflow_graph_id, workflowGraphId);
    assert.equal(compactEvent.workflow_node_id, workflowNodeId);
    assert.equal(compactEvent.component_kind, "context_compaction");
    assert.equal(compactEvent.payload_schema_version, "ioi.runtime.context-compaction.v1");
    assert.equal(compactEvent.payload.reason, reason);
    assert.equal(compactEvent.payload.scope, scope);
    assert.equal(compactEvent.payload.requested_by, "operator");
    assert.ok(compactEvent.receipt_refs.some((ref) =>
      ref.startsWith(`receipt_${turn.request_id}_context_compaction_`),
    ));
    assert.ok(compactEvent.policy_decision_refs.includes(`policy_${turn.request_id}_context_compaction_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkCompactEvent = sdkEvents.find((event) => event.id === compactEvent.event_id);
    assert.ok(sdkCompactEvent);
    assert.equal(sdkCompactEvent.type, "context_compacted");
    assert.equal(sdkCompactEvent.sourceEventKind, "OperatorControl.Compact");
    assert.equal(sdkCompactEvent.componentKind, "context_compaction");
    assert.equal(sdkCompactEvent.workflowGraphId, workflowGraphId);
    assert.equal(sdkCompactEvent.workflowNodeId, workflowNodeId);
    assert.deepEqual(sdkCompactEvent.receiptRefs, compactEvent.receipt_refs);
    assert.deepEqual(sdkCompactEvent.policyDecisionRefs, compactEvent.policy_decision_refs);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(compactEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.ok(reactFlowProjection.workflowGraphIds.includes(workflowGraphId));
    assert.equal(reactFlowNode.nodeKind, "runtime_context_compact");
    assert.equal(reactFlowNode.componentKind, "context_compaction");
    assert.equal(reactFlowNode.workflowGraphId, workflowGraphId);
    assert.equal(reactFlowNode.workflowNodeId, workflowNodeId);
    assert.equal(reactFlowNode.status, "completed");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Compact"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("thread fork keeps one canonical source event across SDK, CLI, and React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const { projectRuntimeThreadEventsToWorkflowProjection } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-fork-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-fork-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-fork-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const reason = "branch live context for validation";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-fork";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove thread fork control has one cross-surface event.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a forkable turn for operator control validation.",
      }),
    });

    const cliResult = await execFileAsync(
      cli,
      [
        "agent",
        "fork",
        "--thread-id",
        thread.thread_id,
        "--reason",
        reason,
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const cliFork = JSON.parse(cliResult.stdout);
    assert.equal(cliFork.source_thread_id, thread.thread_id);
    assert.notEqual(cliFork.thread_id, thread.thread_id);
    assert.ok(cliFork.forked_from_seq >= turn.seq_end);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const forkEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Fork",
    );
    assert.ok(forkEvent);
    assert.equal(forkEvent.event_kind, "thread.forked");
    assert.equal(forkEvent.status, "completed");
    assert.equal(forkEvent.source, "cli_tui");
    assert.equal(forkEvent.actor, "user");
    assert.equal(forkEvent.thread_id, thread.thread_id);
    assert.equal(forkEvent.turn_id, turn.turn_id);
    assert.equal(forkEvent.component_kind, "thread_fork");
    assert.equal(forkEvent.workflow_node_id, "runtime.thread-fork");
    assert.equal(forkEvent.payload_schema_version, "ioi.runtime.thread-fork.v1");
    assert.equal(forkEvent.payload.reason, reason);
    assert.equal(forkEvent.payload.source_thread_id, thread.thread_id);
    assert.equal(forkEvent.payload.fork_thread_id, cliFork.thread_id);
    assert.equal(forkEvent.payload.source_latest_turn_id, turn.turn_id);
    assert.equal(forkEvent.payload.source_latest_seq, String(cliFork.forked_from_seq));
    assert.ok(forkEvent.receipt_refs.includes(`receipt_${thread.agent_id}_thread_fork_${cliFork.agent_id}`));
    assert.ok(forkEvent.policy_decision_refs.includes(`policy_${thread.agent_id}_thread_fork_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const openedFork = await Thread.open(cliFork.thread_id, { substrateClient: sdkClient });
    assert.equal(openedFork.id, cliFork.thread_id);
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkForkEvent = sdkEvents.find((event) => event.id === forkEvent.event_id);
    assert.ok(sdkForkEvent);
    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(forkEvent.event_id),
    );
    assert.ok(reactFlowNode);

    const canonicalCursor = `${forkEvent.event_stream_id}:${forkEvent.seq}`;
    assert.equal(sdkForkEvent.type, "thread_forked");
    assert.equal(sdkForkEvent.seq, forkEvent.seq);
    assert.equal(sdkForkEvent.cursor, canonicalCursor);
    assert.equal(sdkForkEvent.eventKind, forkEvent.event_kind);
    assert.equal(sdkForkEvent.sourceEventKind, forkEvent.source_event_kind);
    assert.equal(sdkForkEvent.componentKind, forkEvent.component_kind);
    assert.equal(sdkForkEvent.workflowNodeId, forkEvent.workflow_node_id);
    assert.equal(sdkForkEvent.payloadSchemaVersion, forkEvent.payload_schema_version);
    assert.deepEqual(sdkForkEvent.receiptRefs, forkEvent.receipt_refs);
    assert.deepEqual(sdkForkEvent.policyDecisionRefs, forkEvent.policy_decision_refs);

    assert.equal(reactFlowNode.latestSeq, forkEvent.seq);
    assert.equal(reactFlowNode.latestCursor, canonicalCursor);
    assert.equal(reactFlowNode.latestEventId, forkEvent.event_id);
    assert.equal(reactFlowNode.componentKind, "thread_fork");
    assert.equal(reactFlowNode.workflowNodeId, "runtime.thread-fork");
    assert.equal(reactFlowNode.status, "completed");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Fork"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("React Flow thread fork control preserves graph identity across daemon, SDK, and projection", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeThreadForkControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-fork-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-fork-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-react-flow-fork-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const reason = "branch live context from React Flow control";
  const workflowGraphId = "workflow.react-flow.thread-fork-proof";
  const workflowNodeId = "runtime.thread-fork";
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-react-flow-fork";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove React Flow-originated thread fork control keeps graph identity.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Prepare a React Flow-originated fork control validation.",
      }),
    });

    const workflowNode = {
      id: "react-flow-thread-fork-control",
      type: "runtime_thread_fork",
      config: {
        logic: {
          runtimeThreadForkEndpoint: "/v1/threads/{threadId}/fork",
          runtimeThreadForkThreadIdField: "threadId",
          runtimeThreadForkReasonField: "reason",
          runtimeThreadForkWorkflowNodeId: workflowNodeId,
          runtimeThreadForkActor: "operator",
        },
        law: { privilegedActions: ["runtime.thread.fork"] },
      },
    };
    const control = createRuntimeThreadForkControlRequestFromWorkflowNode(
      workflowNode,
      { threadId: thread.thread_id, reason },
      { workflowGraphId },
    );
    assert.equal(control.nodeType, "runtime_thread_fork");
    assert.equal(control.body.source, "react_flow");
    assert.equal(control.body.workflowGraphId, workflowGraphId);
    assert.equal(control.body.workflowNodeId, workflowNodeId);
    assert.equal(control.body.componentKind, "thread_fork");

    const fork = await fetchJson(`${daemon.endpoint}${control.endpoint}`, {
      method: "POST",
      body: JSON.stringify(control.body),
    });
    assert.equal(fork.source_thread_id, thread.thread_id);
    assert.notEqual(fork.thread_id, thread.thread_id);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const forkEvent = daemonEvents.find(
      (event) => event.source_event_kind === "OperatorControl.Fork" && event.source === "react_flow",
    );
    assert.ok(forkEvent);
    assert.equal(forkEvent.event_kind, "thread.forked");
    assert.equal(forkEvent.status, "completed");
    assert.equal(forkEvent.source, "react_flow");
    assert.equal(forkEvent.actor, "user");
    assert.equal(forkEvent.thread_id, thread.thread_id);
    assert.equal(forkEvent.turn_id, turn.turn_id);
    assert.equal(forkEvent.workflow_graph_id, workflowGraphId);
    assert.equal(forkEvent.workflow_node_id, workflowNodeId);
    assert.equal(forkEvent.component_kind, "thread_fork");
    assert.equal(forkEvent.payload_schema_version, "ioi.runtime.thread-fork.v1");
    assert.equal(forkEvent.payload.reason, reason);
    assert.equal(forkEvent.payload.requested_by, "operator");
    assert.equal(forkEvent.payload.fork_thread_id, fork.thread_id);
    assert.ok(forkEvent.receipt_refs.includes(`receipt_${thread.agent_id}_thread_fork_${fork.agent_id}`));
    assert.ok(forkEvent.policy_decision_refs.includes(`policy_${thread.agent_id}_thread_fork_allow`));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkForkEvent = sdkEvents.find((event) => event.id === forkEvent.event_id);
    assert.ok(sdkForkEvent);
    assert.equal(sdkForkEvent.type, "thread_forked");
    assert.equal(sdkForkEvent.sourceEventKind, "OperatorControl.Fork");
    assert.equal(sdkForkEvent.componentKind, "thread_fork");
    assert.equal(sdkForkEvent.workflowGraphId, workflowGraphId);
    assert.equal(sdkForkEvent.workflowNodeId, workflowNodeId);
    assert.deepEqual(sdkForkEvent.receiptRefs, forkEvent.receipt_refs);
    assert.deepEqual(sdkForkEvent.policyDecisionRefs, forkEvent.policy_decision_refs);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(forkEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.ok(reactFlowProjection.workflowGraphIds.includes(workflowGraphId));
    assert.equal(reactFlowNode.nodeKind, "runtime_thread_fork");
    assert.equal(reactFlowNode.componentKind, "thread_fork");
    assert.equal(reactFlowNode.workflowGraphId, workflowGraphId);
    assert.equal(reactFlowNode.workflowNodeId, workflowNodeId);
    assert.equal(reactFlowNode.status, "completed");
    assert.ok(reactFlowNode.sourceEventKinds.includes("OperatorControl.Fork"));
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("daemon runtime event store is append-only and idempotent per stream", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-event-store-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-event-store-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const first = daemon.store.appendRuntimeEvent({
      event_stream_id: "event-store-contract:events",
      thread_id: "thread_event_store_contract",
      turn_id: "turn_event_store_contract",
      item_id: "item_event_store_contract",
      idempotency_key: "request:first",
      source: "daemon_bridge",
      source_event_kind: "contract.first",
      event_kind: "contract.first",
      status: "completed",
      actor: "runtime",
      created_at: "2026-05-12T00:00:00.000Z",
      workspace_root: cwd,
      payload_schema_version: "ioi.runtime.event.v1",
      payload: { value: "first" },
    });
    const duplicate = daemon.store.appendRuntimeEvent({
      ...first,
      payload: { value: "duplicate" },
    });
    const second = daemon.store.appendRuntimeEvent({
      event_stream_id: "event-store-contract:events",
      thread_id: "thread_event_store_contract",
      turn_id: "turn_event_store_contract",
      item_id: "item_event_store_contract_2",
      idempotency_key: "request:second",
      source: "daemon_bridge",
      source_event_kind: "contract.second",
      event_kind: "contract.second",
      status: "completed",
      actor: "runtime",
      created_at: "2026-05-12T00:00:01.000Z",
      workspace_root: cwd,
      payload_schema_version: "ioi.runtime.event.v1",
      payload: { value: "second" },
    });

    assert.equal(first.seq, 1);
    assert.equal(first.parent_seq, null);
    assert.equal(duplicate.seq, first.seq);
    assert.equal(duplicate.payload.value, "first");
    assert.equal(second.seq, 2);
    assert.equal(second.parent_seq, 1);
    assert.deepEqual(
      daemon.store.runtimeEventsForStream("event-store-contract:events", 0).map((event) => event.seq),
      [1, 2],
    );
    assert.deepEqual(
      daemon.store.runtimeEventsForStream("event-store-contract:events", 1).map((event) => event.seq),
      [2],
    );

    await daemon.close();
    const reloaded = await startRuntimeDaemonService({ cwd, stateDir });
    try {
      assert.deepEqual(
        reloaded.store.runtimeEventsForStream("event-store-contract:events", 0).map((event) => event.seq),
        [1, 2],
      );
      const persistedDuplicate = reloaded.store.appendRuntimeEvent({
        event_stream_id: "event-store-contract:events",
        thread_id: "thread_event_store_contract",
        turn_id: "turn_event_store_contract",
        item_id: "item_event_store_contract",
        idempotency_key: "request:first",
        source: "daemon_bridge",
        source_event_kind: "contract.first",
        event_kind: "contract.first",
        status: "completed",
        actor: "runtime",
        created_at: "2026-05-12T00:00:02.000Z",
        workspace_root: cwd,
        payload_schema_version: "ioi.runtime.event.v1",
        payload: { value: "after-reload" },
      });
      assert.equal(persistedDuplicate.seq, 1);
      assert.equal(persistedDuplicate.payload.value, "first");
    } finally {
      await reloaded.close();
    }
  } finally {
    await daemon.close().catch(() => {});
  }
});

test("local daemon emits deterministic model route fallback decisions with receipts", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-route-fallback-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-route-fallback-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    daemon.store.modelMounting.upsertRoute({
      id: "route.unavailable-primary",
      role: "test_unavailable",
      privacy: "local_or_enterprise",
      providerEligibility: ["openai"],
      fallback: ["endpoint.local.auto"],
      deniedProviders: [],
      status: "active",
    });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        options: {
          local: { cwd },
          model: { id: "auto", routeId: "route.unavailable-primary", reasoningEffort: "high" },
        },
      }),
    });
    assert.equal(thread.model_route_id, "route.local-first");
    assert.equal(thread.model_route_decision.eventKind, "ModelRouteDecision");
    assert.equal(thread.model_route_decision.fallbackTriggered, true);
    assert.equal(thread.model_route_decision.selectedModel, "local:auto");
    assert.equal(thread.model_route_decision.reasoningEffort, "high");
    assert.ok(
      thread.model_route_decision.rejectedCandidates.some(
        (candidate) => candidate.reason === "provider_not_eligible_for_route",
      ),
    );
    assert.ok(thread.model_route_receipt_id);
  } finally {
    await daemon.close();
  }
});

test("local daemon records explicit memory writes and injects provenance into the next turn", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-memory-daemon-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-memory-daemon-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({ options: { local: { cwd } } }),
    });
    const rememberTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "# remember The operator prefers focused runtime slices.",
        mode: "send",
      }),
    });
    assert.equal(rememberTurn.memory_write_receipt_ids.length, 1);

    const memory = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`);
    assert.equal(memory.schemaVersion, "ioi.agent-runtime.memory.v1");
    assert.equal(memory.records.length, 1);
    assert.equal(memory.records[0].fact, "The operator prefers focused runtime slices.");
    assert.equal(memory.policy.injectionEnabled, true);

    await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`, {
      method: "POST",
      body: JSON.stringify({
        text: "The operator wants memory filters validated through workflow nodes.",
        memoryKey: "workflow-preferences",
        scope: "thread",
      }),
    });
    await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`, {
      method: "POST",
      body: JSON.stringify({
        text: "This unrelated note should be filtered away.",
        memoryKey: "scratch",
        scope: "thread",
      }),
    });
    const filteredMemory = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/memory?memoryKey=workflow-preferences&q=workflow&limit=1`,
    );
    assert.equal(filteredMemory.filters.memoryKey, "workflow-preferences");
    assert.equal(filteredMemory.filters.query, "workflow");
    assert.equal(filteredMemory.filters.limit, 1);
    assert.equal(filteredMemory.records.length, 1);
    assert.equal(
      filteredMemory.records[0].fact,
      "The operator wants memory filters validated through workflow nodes.",
    );
    const redactedMemory = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/memory?memoryKey=workflow-preferences&redaction=redacted`,
    );
    assert.equal(redactedMemory.records[0].fact, "[REDACTED]");
    assert.equal(redactedMemory.records[0].redaction, "redacted");
    assert.match(redactedMemory.records[0].factHash, /^[a-f0-9]{64}$/);

    const memoryPath = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/path`);
    assert.match(memoryPath.recordsPath, /memory-records/);
    assert.match(memoryPath.policiesPath, /memory-policies/);

    const edit = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/${memory.records[0].id}`, {
      method: "PATCH",
      body: JSON.stringify({ text: "The operator prefers narrow, validated runtime slices." }),
    });
    assert.equal(edit.receipt.kind, "memory_edit");
    const commandEditTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: `/memory edit ${memory.records[0].id} The operator prefers narrow, command-validated runtime slices.`,
        mode: "send",
      }),
    });
    assert.equal(commandEditTurn.memory_write_receipt_ids.length, 1);
    const editedMemory = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`);
    assert.equal(editedMemory.records[0].fact, "The operator prefers narrow, command-validated runtime slices.");

    const readOnlyPolicy = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/policy`, {
      method: "PATCH",
      body: JSON.stringify({ readOnly: true }),
    });
    assert.equal(readOnlyPolicy.policy.readOnly, true);
    const readOnlyBlockedTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "# remember This should not write.", mode: "send" }),
    });
    const readOnlyBlockedRun = await fetchJson(
      `${daemon.endpoint}/v1/runs/run_${readOnlyBlockedTurn.turn_id.slice("turn_".length)}`,
    );
    assert.match(readOnlyBlockedRun.result, /memory_read_only/);

    await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/policy`, {
      method: "PATCH",
      body: JSON.stringify({ readOnly: false, writeRequiresApproval: true }),
    });
    const approvalBlockedTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "# remember Approval missing.", mode: "send" }),
    });
    const approvalBlockedRun = await fetchJson(
      `${daemon.endpoint}/v1/runs/run_${approvalBlockedTurn.turn_id.slice("turn_".length)}`,
    );
    assert.match(approvalBlockedRun.result, /memory_write_requires_approval/);
    const approvalTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "# remember Approval granted.",
        mode: "send",
        options: { memory: { writeApproved: true } },
      }),
    });
    assert.equal(approvalTurn.memory_write_receipt_ids.length, 1);

    const disableTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "/memory disable", mode: "send" }),
    });
    assert.equal(disableTurn.memory_write_receipt_ids.length, 1);
    const disabledPolicy = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory/policy`);
    assert.equal(disabledPolicy.disabled, true);
    const enableTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({ prompt: "/memory enable", mode: "send" }),
    });
    assert.equal(enableTurn.memory_write_receipt_ids.length, 1);

    const showTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "/memory show",
        mode: "send",
        options: { memory: { writeRequiresApproval: false } },
      }),
    });
    const runId = `run_${showTurn.turn_id.slice("turn_".length)}`;
    const trace = await fetchJson(`${daemon.endpoint}/v1/runs/${runId}/trace`);
    assert.ok(
      trace.taskState.knownFacts.some((fact) =>
        fact.includes("The operator prefers narrow, command-validated runtime slices."),
      ),
    );
    assert.ok(trace.memoryRecords.some((record) => record.id === memory.records[0].id));

    const disabledTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "/memory show",
        mode: "send",
        options: { memory: { disabled: true } },
      }),
    });
    const disabledRunId = `run_${disabledTurn.turn_id.slice("turn_".length)}`;
    const disabledTrace = await fetchJson(`${daemon.endpoint}/v1/runs/${disabledRunId}/trace`);
    assert.equal(disabledTrace.memoryRecords.length, 0);
    assert.ok(
      !disabledTrace.taskState.knownFacts.some((fact) =>
        fact.includes("The operator prefers narrow, command-validated runtime slices."),
      ),
    );

    const events = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const memoryEvent = events.find((event) => event.payload_summary?.event_kind === "MemoryWrite");
    assert.equal(memoryEvent.component_kind, "memory_write");
    assert.equal(memoryEvent.workflow_node_id, "runtime.memory");
    assert.equal(memoryEvent.payload_summary.memory_record_id, memory.records[0].id);
    assert.deepEqual(memoryEvent.receipt_refs, rememberTurn.memory_write_receipt_ids);
    assert.ok(events.some((event) => event.payload_summary?.event_kind === "MemoryEdit"));
    assert.ok(events.some((event) => event.payload_summary?.event_kind === "MemoryPolicy"));
  } finally {
    await daemon.close();
  }
});

test("local daemon projects subagent memory inheritance modes with receipts", async () => {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-subagent-memory-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-subagent-memory-state-"));
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        options: {
          local: { cwd },
          agents: { reviewer: { prompt: "Review inherited memory." } },
        },
      }),
    });
    const targeted = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`, {
      method: "POST",
      body: JSON.stringify({
        text: "The reviewer should inherit the targeted handoff memory.",
        memoryKey: "reviewer-handoff",
        scope: "thread",
      }),
    });
    await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/memory`, {
      method: "POST",
      body: JSON.stringify({
        text: "The reviewer should not inherit scratch memory.",
        memoryKey: "scratch",
        scope: "thread",
      }),
    });

    const explicitTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Delegate with explicit inherited memory.",
        mode: "handoff",
        options: {
          receiver: "reviewer",
          memory: { subagentInheritance: "explicit", memoryKey: "reviewer-handoff" },
        },
      }),
    });
    const explicitRunId = `run_${explicitTurn.turn_id.slice("turn_".length)}`;
    const explicitTrace = await fetchJson(`${daemon.endpoint}/v1/runs/${explicitRunId}/trace`);
    assert.equal(explicitTrace.subagentMemoryInheritance.mode, "explicit");
    assert.equal(explicitTrace.subagentMemoryInheritance.subagentName, "reviewer");
    assert.deepEqual(explicitTrace.subagentMemoryInheritance.inheritedRecordIds, [
      targeted.record.id,
    ]);
    assert.ok(explicitTrace.receipts.some((receipt) => receipt.kind === "subagent_memory_inheritance"));

    const noneTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Delegate with no inherited memory.",
        mode: "handoff",
        options: {
          receiver: "reviewer",
          memory: { subagentInheritance: "none", memoryKey: "reviewer-handoff" },
        },
      }),
    });
    const noneTrace = await fetchJson(
      `${daemon.endpoint}/v1/runs/run_${noneTurn.turn_id.slice("turn_".length)}/trace`,
    );
    assert.equal(noneTrace.subagentMemoryInheritance.mode, "none");
    assert.equal(noneTrace.subagentMemoryInheritance.records.length, 0);
    assert.equal(noneTrace.subagentMemoryInheritance.effectivePolicy.disabled, true);

    const readOnlyTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Delegate with read-only inherited memory.",
        mode: "handoff",
        options: {
          receiver: "reviewer",
          memory: {
            subagentInheritance: "read_only",
            memoryKey: "reviewer-handoff",
            remember: "Reviewer attempted a read-only daemon write.",
          },
        },
      }),
    });
    const readOnlyRun = await fetchJson(
      `${daemon.endpoint}/v1/runs/run_${readOnlyTurn.turn_id.slice("turn_".length)}`,
    );
    const readOnlyTrace = await fetchJson(
      `${daemon.endpoint}/v1/runs/run_${readOnlyTurn.turn_id.slice("turn_".length)}/trace`,
    );
    assert.match(readOnlyRun.result, /memory_read_only/);
    assert.equal(readOnlyTrace.subagentMemoryInheritance.writeBlockReason, "memory_read_only");
    assert.equal(readOnlyTrace.memoryWrites.length, 0);

    const fullTurn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Delegate with full inherited memory.",
        mode: "handoff",
        options: {
          receiver: "reviewer",
          memory: {
            subagentInheritance: "full",
            memoryKey: "reviewer-handoff",
            remember: "Reviewer can persist a daemon full-inheritance note.",
          },
        },
      }),
    });
    assert.equal(fullTurn.memory_write_receipt_ids.length, 1);
    const fullTrace = await fetchJson(
      `${daemon.endpoint}/v1/runs/run_${fullTurn.turn_id.slice("turn_".length)}/trace`,
    );
    assert.equal(fullTrace.subagentMemoryInheritance.mode, "full");
    assert.equal(fullTrace.subagentMemoryInheritance.writeBlockReason, null);
    assert.equal(fullTrace.memoryWrites.length, 1);
    assert.equal(fullTrace.memoryWrites[0].memoryKey, "reviewer-handoff");

    const events = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const inheritanceEvent = events.find(
      (event) => event.payload_summary?.event_kind === "SubagentMemoryInheritance",
    );
    assert.equal(inheritanceEvent.component_kind, "subagent_memory");
    assert.equal(inheritanceEvent.workflow_node_id, "runtime.subagent-memory");
    assert.equal(inheritanceEvent.payload_summary.subagent_inheritance_mode, "explicit");
    assert.equal(inheritanceEvent.payload_summary.inherited_memory_count, 1);
  } finally {
    await daemon.close();
  }
});

test("agent CLI exposes model, thinking, and stream control contracts", () => {
  const source = [
    "crates/cli/src/commands/agent.rs",
    "crates/cli/src/commands/agent_event_stream.rs",
    "crates/cli/src/commands/agent_tui.rs",
    "crates/cli/src/commands/agent_tui_loop.rs",
  ].map((file) => fs.readFileSync(path.join(root, file), "utf8")).join("\n");
  assert.match(source, /AgentCommands::Model/);
  assert.match(source, /AgentCommands::Thinking/);
  assert.match(source, /AgentCommands::Memory/);
  assert.match(source, /AgentCommands::Doctor/);
  assert.match(source, /AgentCommands::Stream/);
  assert.match(source, /AgentCommands::Tui/);
  assert.match(source, /AgentCommands::Interrupt/);
  assert.match(source, /AgentCommands::Steer/);
  assert.match(source, /AgentCommands::Compact/);
  assert.match(source, /AgentCommands::Fork/);
  assert.match(source, /AgentEventStreamArgs/);
  assert.match(source, /\/model/);
  assert.match(source, /\/thinking/);
  assert.match(source, /# remember/);
  assert.match(source, /\/memory show/);
  assert.match(source, /\/memory disable/);
  assert.match(source, /\/memory path/);
  assert.match(source, /memory_policy/);
  assert.match(source, /ModelRouteDecision/);
  assert.match(source, /memory_update/);
  assert.match(source, /\/v1\/doctor/);
  assert.match(source, /\/v1\/skills/);
  assert.match(source, /\/v1\/hooks/);
  assert.match(source, /\/v1\/threads\/\{id\}\/events/);
  assert.match(source, /\/v1\/threads\/\{id\}\/events\/stream/);
  assert.match(source, /\/v1\/runs\/\{id\}\/events/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/turns/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/turns\/\{turn_id\}\/interrupt/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/turns\/\{turn_id\}\/steer/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/approvals\/\{approval_id\}\/decision/);
  assert.match(source, /\/v1\/tools\?pack=coding/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/tools\/\{tool_id\}\/invoke/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/compact/);
  assert.match(source, /\/v1\/threads\/\{thread_id\}\/fork/);
  assert.match(source, /workspace\.status/);
  assert.match(source, /git\.diff/);
  assert.match(source, /file\.inspect/);
  assert.match(source, /OperatorControl\.Interrupt/);
  assert.match(source, /OperatorControl\.Steer/);
  assert.match(source, /OperatorApproval\.Approve/);
  assert.match(source, /OperatorApproval\.Reject/);
  assert.match(source, /OperatorControl\.Compact/);
  assert.match(source, /OperatorControl\.Fork/);
  assert.match(source, /operator_control/);
  assert.match(source, /approval_gate/);
  assert.match(source, /context_compaction/);
  assert.match(source, /thread_fork/);
  assert.match(source, /since_seq/);
  assert.match(source, /Last-Event-ID/);
  assert.match(source, /parse_runtime_event_sse_blocks/);
  assert.match(source, /format_runtime_event_line/);
  assert.match(source, /TUI_PRIVATE_RUNTIME_LOOP: bool = false/);
  assert.match(source, /ioi\.agent-cli\.tui\.v1/);
  assert.match(source, /ioi\.agent-cli\.tui-control-state\.v1/);
  assert.match(source, /ioi\.workflow\.runtime-tui-deeplink\.v1/);
  assert.match(source, /tui_control_state/);
  assert.match(source, /command_history/);
  assert.match(source, /validation_errors/);
  assert.match(source, /mode_status/);
  assert.match(source, /approval_rows/);
  assert.match(source, /approval_decisions/);
  assert.match(source, /tui_event_rows/);
  assert.match(source, /tui_reopen/);
  assert.match(source, /run_tui_interactive_loop/);
  assert.match(source, /parse_tui_line_command/);
  for (const slashCommand of ["/resume", "/events", "/approvals", "/approve", "/reject", "/interrupt", "/steer", "/status", "/diff", "/inspect", "/patch", "/patch-dry-run", "/quit"]) {
    assert.match(source, new RegExp(slashCommand));
  }
  assert.match(source, /event_kind/);
  assert.match(source, /component_kind/);
  assert.match(source, /workflow_node_id/);
  assert.match(source, /receipt_refs/);
  assert.match(source, /policy_decision_refs/);
  assert.match(source, /ioi\.agent-runtime\.doctor\.v1/);
  assert.match(source, /ioi\.agent-runtime\.skills\.v1/);
  assert.match(source, /ioi\.agent-runtime\.hooks\.v1/);
  assert.match(source, /reactflow_workflow_node/);
});

test("agent TUI thin shell is daemon-backed and avoids a private runtime loop", () => {
  const source = [
    "crates/cli/src/commands/agent_tui.rs",
    "crates/cli/src/commands/agent_tui_loop.rs",
  ].map((file) => fs.readFileSync(path.join(root, file), "utf8")).join("\n");
  assert.match(source, /TUI_PRIVATE_RUNTIME_LOOP: bool = false/);
  assert.match(source, /TUI_THREAD_CREATE_ROUTE/);
  assert.match(source, /TUI_EVENT_STREAM_ROUTE_TEMPLATE/);
  assert.match(source, /fetch_runtime_event_stream/);
  assert.match(source, /daemon_request/);
  assert.match(source, /OperatorControl\.Interrupt/);
  assert.match(source, /OperatorControl\.Steer/);
  assert.match(source, /workflow_node_ids/);
  assert.match(source, /tui_event_rows/);
  assert.match(source, /tui_control_state/);
  assert.match(source, /tui_reopen_args/);
  assert.match(source, /line_mode_command=interrupt/);
  assert.match(source, /line_mode_command=events/);
  assert.match(source, /line_mode_error/);
  assert.doesNotMatch(source, /CliAgentRuntimeClient/);
  assert.doesNotMatch(source, /submit_runtime_call/);
  assert.doesNotMatch(source, /StartAgentParams/);
  assert.doesNotMatch(source, /StepAgentParams/);
});

test("coding tool pack invokes status, diff, inspect, and apply patch across daemon, SDK, CLI, TUI, and React Flow", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const { projectRuntimeThreadEventsToWorkflowProjection } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-coding-tools-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-coding-tools-state-"));
  const cli = cliBinary();
  git(cwd, ["init"]);
  git(cwd, ["config", "user.email", "runtime@example.test"]);
  git(cwd, ["config", "user.name", "Runtime Test"]);
  fs.writeFileSync(path.join(cwd, "README.md"), "# Runtime coding tools\n\nInitial line.\n");
  git(cwd, ["add", "README.md"]);
  git(cwd, ["commit", "-m", "seed workspace"]);
  fs.appendFileSync(path.join(cwd, "README.md"), "\nChanged line for diff proof.\n");

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        goal: "Prove structured coding tools without shell-only fallback.",
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });

    const catalog = await fetchJson(`${daemon.endpoint}/v1/tools?pack=coding`);
    assert.deepEqual(
      catalog.map((tool) => tool.stableToolId).sort(),
      ["file.apply_patch", "file.inspect", "git.diff", "workspace.status"],
    );
    assert.ok(catalog.every((tool) => tool.pack === "coding"));
    assert.ok(catalog.every((tool) => tool.workflowNodeType));
    const patchContract = catalog.find((tool) => tool.stableToolId === "file.apply_patch");
    assert.ok(patchContract);
    assert.equal(patchContract.effectClass, "local_write");
    assert.ok(patchContract.authorityScopeRequirements.includes("scope:workspace.write"));

    const statusResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/workspace.status/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.workspace.status",
          input: {},
        }),
      },
    );
    const diffResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/git.diff/invoke`,
      {
        method: "POST",
        body: JSON.stringify({ input: { path: "README.md" } }),
      },
    );
    const inspectResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.inspect/invoke`,
      {
        method: "POST",
        body: JSON.stringify({ input: { path: "README.md" } }),
      },
    );
    const dryRunPatchResult = await fetchJson(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/tools/file.apply_patch/invoke`,
      {
        method: "POST",
        body: JSON.stringify({
          source: "react_flow",
          workflow_graph_id: "workflow-coding-tools",
          workflow_node_id: "workflow.coding.file.apply_patch",
          input: {
            path: "README.md",
            oldText: "Initial line.",
            newText: "Dry-run patched line.",
            dryRun: true,
          },
        }),
      },
    );
    assert.equal(statusResult.status, "completed");
    assert.equal(statusResult.shell_fallback_used, false);
    assert.equal(diffResult.result.paths[0], "README.md");
    assert.match(diffResult.result.diff, /Changed line for diff proof/);
    assert.equal(inspectResult.result.kind, "file");
    assert.match(inspectResult.result.preview, /Runtime coding tools/);
    assert.equal(dryRunPatchResult.status, "completed");
    assert.equal(dryRunPatchResult.result.dryRun, true);
    assert.equal(dryRunPatchResult.result.applied, false);
    assert.match(dryRunPatchResult.result.diff, /Dry-run patched line/);
    assert.match(fs.readFileSync(path.join(cwd, "README.md"), "utf8"), /Initial line\./);

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkCatalog = await sdkClient.listTools({ pack: "coding" });
    assert.deepEqual(
      sdkCatalog.map((tool) => tool.stableToolId).sort(),
      ["file.apply_patch", "file.inspect", "git.diff", "workspace.status"],
    );
    const sdkInvoke = await sdkClient.invokeThreadTool(thread.thread_id, "file.inspect", {
      input: { path: "README.md" },
      workflowNodeId: "runtime.coding-tool.sdk-file-inspect",
    });
    assert.equal(sdkInvoke.status, "completed");
    assert.equal(sdkInvoke.tool_name, "file.inspect");
    const sdkPatch = await sdkClient.invokeThreadTool(thread.thread_id, "file.apply_patch", {
      input: {
        path: "README.md",
        oldText: "Initial line.",
        newText: "SDK patched line.",
      },
      workflowNodeId: "runtime.coding-tool.sdk-file-apply-patch",
    });
    assert.equal(sdkPatch.status, "completed");
    assert.equal(sdkPatch.tool_name, "file.apply_patch");
    assert.equal(sdkPatch.result.applied, true);

    const cliCatalog = JSON.parse(
      (await execFileAsync(cli, ["agent", "tools", "coding", "--endpoint", daemon.endpoint, "--json"], {
        cwd: root,
      })).stdout,
    );
    assert.equal(cliCatalog.schema_version, "ioi.agent-cli.coding-tool-pack.v1");
    assert.deepEqual(
      cliCatalog.tools.map((tool) => tool.stableToolId).sort(),
      ["file.apply_patch", "file.inspect", "git.diff", "workspace.status"],
    );
    const cliInvoke = JSON.parse(
      (await execFileAsync(
        cli,
        [
          "agent",
          "tools",
          "run",
          "file.inspect",
          "--thread-id",
          thread.thread_id,
          "--path",
          "README.md",
          "--endpoint",
          daemon.endpoint,
          "--json",
        ],
        { cwd: root },
      )).stdout,
    );
    assert.equal(cliInvoke.status, "completed");
    assert.equal(cliInvoke.tool_name, "file.inspect");
    const cliPatch = JSON.parse(
      (await execFileAsync(
        cli,
        [
          "agent",
          "tools",
          "run",
          "file.apply_patch",
          "--thread-id",
          thread.thread_id,
          "--path",
          "README.md",
          "--old-text",
          "Changed line for diff proof.",
          "--new-text",
          "CLI patched diff proof.",
          "--endpoint",
          daemon.endpoint,
          "--json",
        ],
        { cwd: root },
      )).stdout,
    );
    assert.equal(cliPatch.status, "completed");
    assert.equal(cliPatch.tool_name, "file.apply_patch");
    assert.equal(cliPatch.result.applied, true);

    const tuiResult = await execFileWithInput(
      cli,
      [
        "agent",
        "tui",
        "--thread-id",
        thread.thread_id,
        "--endpoint",
        daemon.endpoint,
        "--interactive",
      ],
      "/status\n/diff README.md\n/inspect README.md\n/patch README.md SDK patched line. => TUI patched line.\n/patch-dry-run README.md TUI patched line. => TUI dry-run line.\n/quit\n",
      { cwd: root, timeout: 30000 },
    );
    assert.match(tuiResult.stdout, /Line-mode commands: .*\/status .*\/diff \[path\] .*\/inspect <path> .*\/patch <path> <old> => <new> .*\/quit/);
    assert.match(tuiResult.stdout, /line_mode_command=status tool=workspace\.status status=completed/);
    assert.match(tuiResult.stdout, /line_mode_command=diff tool=git\.diff status=completed/);
    assert.match(tuiResult.stdout, /line_mode_command=inspect tool=file\.inspect status=completed/);
    assert.match(tuiResult.stdout, /line_mode_command=patch tool=file\.apply_patch status=completed/);
    assert.match(fs.readFileSync(path.join(cwd, "README.md"), "utf8"), /TUI patched line\./);
    assert.doesNotMatch(fs.readFileSync(path.join(cwd, "README.md"), "utf8"), /TUI dry-run line/);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const codingEvents = daemonEvents.filter((event) => event.component_kind === "coding_tool");
    assert.ok(codingEvents.length >= 11);
    assert.ok(codingEvents.every((event) => event.payload_schema_version === "ioi.runtime.coding-tool-result.v1"));
    assert.ok(codingEvents.every((event) => event.event_kind === "tool.completed"));
    assert.ok(codingEvents.every((event) => event.payload.shell_fallback_used === "false"));
    assert.ok(codingEvents.every((event) => event.receipt_refs.length >= 1));
    const reactFlowStatus = codingEvents.find(
      (event) =>
        event.payload.tool_name === "workspace.status" &&
        event.source === "react_flow",
    );
    assert.ok(reactFlowStatus);
    assert.equal(reactFlowStatus.workflow_graph_id, "workflow-coding-tools");
    assert.equal(reactFlowStatus.workflow_node_id, "workflow.coding.workspace.status");
    const reactFlowPatch = codingEvents.find(
      (event) =>
        event.payload.tool_name === "file.apply_patch" &&
        event.source === "react_flow",
    );
    assert.ok(reactFlowPatch);
    assert.equal(reactFlowPatch.workflow_node_id, "workflow.coding.file.apply_patch");

    const sdkThread = await Thread.open(thread.thread_id, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkStatusEvent = sdkEvents.find((event) => event.id === reactFlowStatus.event_id);
    assert.ok(sdkStatusEvent);
    assert.equal(sdkStatusEvent.toolName, "workspace.status");
    assert.equal(sdkStatusEvent.componentKind, "coding_tool");
    assert.equal(sdkStatusEvent.payloadSchemaVersion, "ioi.runtime.coding-tool-result.v1");
    const sdkPatchEvent = sdkEvents.find((event) => event.id === reactFlowPatch.event_id);
    assert.ok(sdkPatchEvent);
    assert.equal(sdkPatchEvent.toolName, "file.apply_patch");
    assert.equal(sdkPatchEvent.sourceEventKind, "CodingTool.FileApplyPatch");

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const statusNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(reactFlowStatus.event_id),
    );
    assert.ok(statusNode);
    assert.equal(statusNode.workflowNodeId, "workflow.coding.workspace.status");
    assert.equal(statusNode.componentKind, "coding_tool");
    assert.equal(statusNode.label, "Coding tool: workspace.status");
    assert.deepEqual(statusNode.receiptRefs, reactFlowStatus.receipt_refs);
    const patchNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(reactFlowPatch.event_id),
    );
    assert.ok(patchNode);
    assert.equal(patchNode.workflowNodeId, "workflow.coding.file.apply_patch");
    assert.equal(patchNode.label, "Coding tool: file.apply_patch");
    assert.deepEqual(patchNode.receiptRefs, reactFlowPatch.receipt_refs);
  } finally {
    if (daemon) await daemon.close();
  }
});

test("agent TUI thin shell starts a live thread, replays by cursor, and controls through daemon endpoints", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
    projectRuntimeTuiControlStateToWorkflowProjection,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-tui";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const result = await execFileAsync(
      cli,
      [
        "agent",
        "tui",
        "--goal",
        "Prove the thin terminal UI uses the live daemon runtime.",
        "--message",
        "Render canonical events and then accept an operator interrupt.",
        "--runtime-profile",
        "runtime_service",
        "--model",
        "auto",
        "--route-id",
        "route.native-local",
        "--cwd",
        cwd,
        "--interrupt",
        "--reason",
        "tui validation interrupt",
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const payload = JSON.parse(result.stdout);
    assert.equal(payload.schema_version, "ioi.agent-cli.tui.v1");
    assert.equal(payload.surface, "tui");
    assert.equal(payload.private_runtime_loop, false);
    assert.ok(payload.thread.thread_id);
    assert.ok(payload.submitted_turn.turn_id);
    assert.equal(payload.control.status, "interrupted");
    assert.equal(payload.control.stop_reason, "operator_interrupt");
    assert.match(payload.event_route, new RegExp(`/v1/threads/${payload.thread.thread_id}/events\\?since_seq=0`));
    assert.ok(payload.event_count >= 3);
    assert.ok(payload.workflow_node_ids.includes("runtime.operator-interrupt"));
    assert.equal(
      payload.tui_control_state.schema_version,
      "ioi.agent-cli.tui-control-state.v1",
    );
    assert.equal(payload.tui_control_state.thread_id, payload.thread.thread_id);
    assert.equal(payload.tui_control_state.current_turn_id, payload.submitted_turn.turn_id);
    assert.ok(payload.tui_control_state.last_cursor);
    assert.equal(payload.tui_control_state.validation_errors.length, 0);
    assert.deepEqual(
      payload.tui_control_state.command_history.map((entry) => entry.command),
      ["message", "interrupt"],
    );
    const tuiControlStateProjection =
      projectRuntimeTuiControlStateToWorkflowProjection(payload.tui_control_state);
    assert.equal(
      tuiControlStateProjection.schemaVersion,
      WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    );
    assert.equal(tuiControlStateProjection.currentTurnId, payload.submitted_turn.turn_id);
    assert.equal(tuiControlStateProjection.commandCount, 2);
    assert.equal(tuiControlStateProjection.validationErrorCount, 0);
    assert.ok(
      tuiControlStateProjection.rows.some(
        (row) =>
          row.rowKind === "command" &&
          row.command === "interrupt" &&
          row.reactFlowNodeId === "runtime.tui-control-state.command.interrupt",
      ),
    );
    const interruptEvent = payload.events.find(
      (event) => event.source_event_kind === "OperatorControl.Interrupt",
    );
    assert.ok(interruptEvent);
    assert.equal(interruptEvent.source, "cli_tui");
    assert.equal(interruptEvent.workflow_node_id, "runtime.operator-interrupt");
    const canonicalCursor = `${interruptEvent.event_stream_id}:${interruptEvent.seq}`;
    const interruptRow = payload.event_rows.find(
      (row) => row.event_id === interruptEvent.event_id,
    );
    assert.ok(interruptRow);
    assert.equal(
      interruptRow.schema_version,
      WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
    );
    assert.equal(interruptRow.thread_id, payload.thread.thread_id);
    assert.equal(interruptRow.turn_id, payload.submitted_turn.turn_id);
    assert.equal(interruptRow.workflow_node_id, "runtime.operator-interrupt");
    assert.equal(interruptRow.cursor, canonicalCursor);
    assert.deepEqual(interruptRow.tui_reopen.args, [
      "agent",
      "tui",
      "--thread-id",
      payload.thread.thread_id,
      "--since-seq",
      String(interruptEvent.seq),
    ]);
    assert.equal(interruptRow.tui_reopen.command, "ioi agent tui");
    assert.equal(interruptRow.tui_reopen.last_event_id, interruptEvent.event_id);
    assert.equal(interruptRow.react_flow.workflow_node_id, "runtime.operator-interrupt");

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(payload.thread.thread_id, {
      substrateClient: sdkClient,
    });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkInterrupt = sdkEvents.find((event) => event.id === interruptEvent.event_id);
    assert.ok(sdkInterrupt);
    assert.equal(sdkInterrupt.cursor, canonicalCursor);
    assert.equal(sdkInterrupt.workflowNodeId, interruptRow.workflow_node_id);
    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(interruptEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.equal(
      reactFlowNode.tuiDeepLink.schemaVersion,
      WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
    );
    assert.equal(reactFlowNode.tuiDeepLink.threadId, interruptRow.thread_id);
    assert.equal(reactFlowNode.tuiDeepLink.turnId, interruptRow.turn_id);
    assert.equal(reactFlowNode.tuiDeepLink.workflowNodeId, interruptRow.workflow_node_id);
    assert.equal(reactFlowNode.tuiDeepLink.eventId, interruptRow.event_id);
    assert.equal(reactFlowNode.tuiDeepLink.cursor, interruptRow.cursor);
    assert.deepEqual(reactFlowNode.tuiDeepLink.args, interruptRow.tui_reopen.args);

    const replay = await execFileAsync(
      cli,
      [
        "agent",
        "tui",
        "--thread-id",
        payload.thread.thread_id,
        "--last-event-id",
        interruptEvent.event_id,
        "--endpoint",
        daemon.endpoint,
        "--json",
      ],
      { cwd: root },
    );
    const replayPayload = JSON.parse(replay.stdout);
    assert.equal(replayPayload.schema_version, "ioi.agent-cli.tui.v1");
    assert.equal(replayPayload.thread.thread_id, payload.thread.thread_id);
    assert.equal(replayPayload.last_event_id, interruptEvent.event_id);
    assert.equal(replayPayload.event_count, 0);
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("agent TUI line-mode slash commands control daemon turns and keep React Flow identity", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
    projectRuntimeTuiControlStateToWorkflowProjection,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-line-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-line-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-line-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-tui-line";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const result = await execFileWithInput(
      cli,
      [
        "agent",
        "tui",
        "--goal",
        "Prove the line-mode terminal UI uses daemon controls.",
        "--message",
        "Render canonical events before line-mode slash commands.",
        "--runtime-profile",
        "runtime_service",
        "--model",
        "auto",
        "--route-id",
        "route.native-local",
        "--cwd",
        cwd,
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--interactive",
      ],
      "/interrupt line-mode validation interrupt\n/events 0\n/steer\n/quit\n",
      { cwd: root, timeout: 30000 },
    );
    assert.match(result.stdout, /Line-mode commands: .*\/approvals .*\/approve \[approval_id\] \[reason\] .*\/reject \[approval_id\] \[reason\].*\/interrupt \[reason\] .*\/steer <guidance> .*\/quit/);
    assert.match(result.stdout, /line_mode_command=interrupt/);
    assert.match(result.stdout, /line_mode_command=events/);
    assert.match(result.stdout, /line_mode_error=\/steer requires guidance text/);
    assert.match(result.stdout, /line_mode_command=quit/);
    assert.match(result.stdout, /OperatorControl\.Interrupt/);
    assert.match(result.stdout, /node=runtime\.operator-interrupt/);
    const threadId = result.stdout.match(/thread=(thread_[^\s]+)/)?.[1];
    assert.ok(threadId);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${threadId}/events?since_seq=0`,
    );
    const interruptEvent = daemonEvents.find(
      (event) =>
        event.source_event_kind === "OperatorControl.Interrupt" &&
        event.payload?.reason === "line-mode validation interrupt",
    );
    assert.ok(interruptEvent);
    assert.equal(interruptEvent.source, "cli_tui");
    assert.equal(interruptEvent.workflow_node_id, "runtime.operator-interrupt");

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const sdkThread = await Thread.open(threadId, { substrateClient: sdkClient });
    const sdkEvents = await collect(sdkThread.events({ sinceSeq: 0 }));
    const sdkInterrupt = sdkEvents.find((event) => event.id === interruptEvent.event_id);
    assert.ok(sdkInterrupt);
    const canonicalCursor = `${interruptEvent.event_stream_id}:${interruptEvent.seq}`;
    assert.equal(sdkInterrupt.cursor, canonicalCursor);
    assert.equal(sdkInterrupt.workflowNodeId, interruptEvent.workflow_node_id);

    const reactFlowProjection = projectRuntimeThreadEventsToWorkflowProjection(sdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(interruptEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.equal(
      reactFlowNode.tuiDeepLink.schemaVersion,
      WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION,
    );
    assert.equal(reactFlowNode.tuiDeepLink.threadId, threadId);
    assert.equal(reactFlowNode.tuiDeepLink.workflowNodeId, "runtime.operator-interrupt");
    assert.equal(reactFlowNode.tuiDeepLink.eventId, interruptEvent.event_id);
    assert.equal(reactFlowNode.tuiDeepLink.cursor, canonicalCursor);
    assert.deepEqual(reactFlowNode.tuiDeepLink.args, [
      "agent",
      "tui",
      "--thread-id",
      threadId,
      "--since-seq",
      String(interruptEvent.seq),
    ]);

    const controlStates = result.stdout
      .split(/\r?\n/)
      .filter((line) => line.startsWith("tui_control_state="))
      .map((line) => JSON.parse(line.replace(/^tui_control_state=/, "")));
    assert.ok(controlStates.length >= 4);
    const finalControlState = controlStates[controlStates.length - 1];
    assert.equal(
      finalControlState.schema_version,
      "ioi.agent-cli.tui-control-state.v1",
    );
    assert.equal(finalControlState.thread_id, threadId);
    assert.ok(finalControlState.current_turn_id);
    assert.ok(finalControlState.last_cursor);
    assert.ok(
      finalControlState.command_history.some(
        (entry) => entry.command === "interrupt" && entry.status === "applied",
      ),
    );
    assert.ok(
      finalControlState.command_history.some(
        (entry) => entry.command === "events" && entry.status === "applied",
      ),
    );
    assert.ok(
      finalControlState.validation_errors.some(
        (entry) =>
          entry.command === "steer" &&
          entry.message === "/steer requires guidance text",
      ),
    );
    const lineModeControlProjection =
      projectRuntimeTuiControlStateToWorkflowProjection(finalControlState);
    assert.equal(
      lineModeControlProjection.schemaVersion,
      WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    );
    assert.equal(lineModeControlProjection.threadId, threadId);
    assert.ok(
      lineModeControlProjection.rows.some(
        (row) =>
          row.rowKind === "validation_error" &&
          row.command === "steer" &&
          row.reactFlowNodeId === "runtime.tui-control-state.validation.steer",
      ),
    );
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("agent TUI approval slash commands emit receipt-backed React Flow rows", async () => {
  const {
    WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    projectRuntimeTuiControlStateToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-approval-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-tui-approval-state-"));
  const cli = cliBinary();
  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const thread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        goal: "Approve a daemon-backed TUI control.",
        source: "cli_tui",
        options: { local: { cwd } },
      }),
    });
    const turn = await fetchJson(`${daemon.endpoint}/v1/threads/${thread.thread_id}/turns`, {
      method: "POST",
      body: JSON.stringify({
        prompt: "Wait for a synthetic approval gate.",
        source: "cli_tui",
        mode: "tui",
      }),
    });
    daemon.store.appendRuntimeEvent({
      event_stream_id: thread.event_stream_id,
      thread_id: thread.thread_id,
      turn_id: turn.turn_id,
      item_id: `${turn.turn_id}:item:approval-required`,
      idempotency_key: `${turn.turn_id}:approval.required:approval-live`,
      source: "daemon_bridge",
      source_event_kind: "KernelEvent::ApprovalRequired",
      event_kind: "approval.required",
      status: "waiting_for_approval",
      actor: "runtime",
      workspace_root: cwd,
      component_kind: "approval_gate",
      workflow_node_id: "runtime.approval.approval-live",
      approval_id: "approval-live",
      payload_schema_version: "ioi.runtime.approval-request.v1",
      payload: {
        event_kind: "KernelEvent::ApprovalRequired",
        approval_id: "approval-live",
        message: "Approve shell execution",
      },
      receipt_refs: ["receipt_approval_required"],
      policy_decision_refs: ["policy_approval_required"],
      artifact_refs: [],
      rollback_refs: [],
    });

    const result = await execFileWithInput(
      cli,
      [
        "agent",
        "tui",
        "--thread-id",
        thread.thread_id,
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--interactive",
      ],
      "/approvals\n/approve approval-live proceed with validation\n/quit\n",
      { cwd: root, timeout: 30000 },
    );
    assert.match(result.stdout, /line_mode_command=approvals count=1/);
    assert.match(result.stdout, /line_mode_command=approve approval=approval-live status=/);

    const daemonEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=0`,
    );
    const decisionEvent = daemonEvents.find(
      (event) =>
        event.source_event_kind === "OperatorApproval.Approve" &&
        event.approval_id === "approval-live",
    );
    assert.ok(decisionEvent);
    assert.equal(decisionEvent.source, "cli_tui");
    assert.equal(decisionEvent.event_kind, "approval.approved");
    assert.equal(decisionEvent.component_kind, "approval_gate");
    assert.equal(decisionEvent.workflow_node_id, "runtime.approval.approval-live");
    assert.equal(decisionEvent.payload_schema_version, "ioi.runtime.approval-decision.v1");
    assert.ok(decisionEvent.receipt_refs.length > 0);
    assert.ok(decisionEvent.policy_decision_refs.length > 0);

    const controlStates = result.stdout
      .split(/\r?\n/)
      .filter((line) => line.startsWith("tui_control_state="))
      .map((line) => JSON.parse(line.replace(/^tui_control_state=/, "")));
    const finalControlState = controlStates[controlStates.length - 1];
    assert.equal(finalControlState.mode_status.approval_mode, "suggest");
    assert.ok(
      finalControlState.approval_rows.some(
        (row) =>
          row.approval_id === "approval-live" &&
          row.workflow_node_id === "runtime.approval.approval-live",
      ),
    );
    assert.ok(
      finalControlState.approval_decisions.some(
        (row) =>
          row.approval_id === "approval-live" &&
          row.decision === "approve" &&
          row.receipt_refs.length > 0 &&
          row.policy_decision_refs.length > 0,
      ),
    );
    const projection =
      projectRuntimeTuiControlStateToWorkflowProjection(finalControlState);
    assert.equal(
      projection.schemaVersion,
      WORKFLOW_RUNTIME_TUI_CONTROL_STATE_SCHEMA_VERSION,
    );
    assert.equal(projection.approvalCount, 1);
    assert.equal(projection.approvalDecisionCount, 1);
    assert.ok(
      projection.rows.some(
        (row) =>
          row.rowKind === "approval_decision" &&
          row.status === "approved" &&
          row.reactFlowNodeId === "runtime.approval.approval-live" &&
          row.receiptRefs.length > 0,
      ),
    );
  } finally {
    if (daemon) await daemon.close();
  }
});

test("React Flow and line-mode TUI interrupt controls share the operator-control event contract", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeOperatorInterruptControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-control-equivalence-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-control-equivalence-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-control-equivalence-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const workflowGraphId = "workflow.react-flow.tui-control-equivalence";
  const workflowNodeId = "runtime.operator-interrupt";
  const contractShape = {
    eventKind: "turn.interrupted",
    sourceEventKind: "OperatorControl.Interrupt",
    status: "interrupted",
    componentKind: "operator_control",
    workflowNodeId,
    payloadSchemaVersion: "ioi.runtime.operator-control.v1",
  };
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-control-equivalence";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const reactFlowThread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove React Flow and TUI interrupts share the control event contract.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const reactFlowTurn = await fetchJson(
      `${daemon.endpoint}/v1/threads/${reactFlowThread.thread_id}/turns`,
      {
        method: "POST",
        body: JSON.stringify({
          prompt: "Prepare the React Flow side of the control equivalence proof.",
        }),
      },
    );
    const workflowNode = {
      id: "react-flow-tui-equivalence-interrupt-control",
      type: "runtime_operator_interrupt",
      config: {
        logic: {
          runtimeOperatorInterruptEndpoint: "/v1/threads/{threadId}/turns/{turnId}/interrupt",
          runtimeOperatorInterruptThreadIdField: "threadId",
          runtimeOperatorInterruptTurnIdField: "turnId",
          runtimeOperatorInterruptReasonField: "reason",
          runtimeOperatorInterruptWorkflowNodeId: workflowNodeId,
          runtimeOperatorInterruptActor: "operator",
        },
        law: { privilegedActions: ["runtime.turn.interrupt"] },
      },
    };
    const reactFlowControl = createRuntimeOperatorInterruptControlRequestFromWorkflowNode(
      workflowNode,
      {
        threadId: reactFlowThread.thread_id,
        turnId: reactFlowTurn.turn_id,
        reason: "react-flow equivalence interrupt",
      },
      { workflowGraphId },
    );
    await fetchJson(`${daemon.endpoint}${reactFlowControl.endpoint}`, {
      method: "POST",
      body: JSON.stringify(reactFlowControl.body),
    });

    const tuiResult = await execFileWithInput(
      cli,
      [
        "agent",
        "tui",
        "--goal",
        "Prove line-mode TUI shares the React Flow control event contract.",
        "--message",
        "Prepare the TUI side of the control equivalence proof.",
        "--runtime-profile",
        "runtime_service",
        "--model",
        "auto",
        "--route-id",
        "route.native-local",
        "--cwd",
        cwd,
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--interactive",
      ],
      "/interrupt tui equivalence interrupt\n/quit\n",
      { cwd: root, timeout: 30000 },
    );
    const tuiThreadId = tuiResult.stdout.match(/thread=(thread_[^\s]+)/)?.[1];
    assert.ok(tuiThreadId);

    const reactFlowEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${reactFlowThread.thread_id}/events?since_seq=0`,
    );
    const tuiEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${tuiThreadId}/events?since_seq=0`,
    );
    const reactFlowEvent = reactFlowEvents.find(
      (event) =>
        event.source_event_kind === "OperatorControl.Interrupt" &&
        event.source === "react_flow" &&
        event.payload?.reason === "react-flow equivalence interrupt",
    );
    const tuiEvent = tuiEvents.find(
      (event) =>
        event.source_event_kind === "OperatorControl.Interrupt" &&
        event.source === "cli_tui" &&
        event.payload?.reason === "tui equivalence interrupt",
    );
    assert.ok(reactFlowEvent);
    assert.ok(tuiEvent);
    assert.deepEqual(operatorControlContractShape(reactFlowEvent), contractShape);
    assert.deepEqual(operatorControlContractShape(tuiEvent), contractShape);
    assert.equal(reactFlowEvent.workflow_graph_id, workflowGraphId);
    assert.equal(tuiEvent.workflow_graph_id, null);
    assert.ok(reactFlowEvent.receipt_refs.includes(`receipt_${reactFlowTurn.request_id}_operator_interrupt`));
    assert.ok(reactFlowEvent.policy_decision_refs.includes(`policy_${reactFlowTurn.request_id}_operator_interrupt_allow`));
    assert.ok(tuiEvent.receipt_refs.some((ref) => ref.endsWith("_operator_interrupt")));
    assert.ok(tuiEvent.policy_decision_refs.some((ref) => ref.endsWith("_operator_interrupt_allow")));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const reactFlowSdkThread = await Thread.open(reactFlowThread.thread_id, {
      substrateClient: sdkClient,
    });
    const tuiSdkThread = await Thread.open(tuiThreadId, { substrateClient: sdkClient });
    const reactFlowSdkEvents = await collect(reactFlowSdkThread.events({ sinceSeq: 0 }));
    const tuiSdkEvents = await collect(tuiSdkThread.events({ sinceSeq: 0 }));
    const reactFlowSdkEvent = reactFlowSdkEvents.find(
      (event) => event.id === reactFlowEvent.event_id,
    );
    const tuiSdkEvent = tuiSdkEvents.find((event) => event.id === tuiEvent.event_id);
    assert.ok(reactFlowSdkEvent);
    assert.ok(tuiSdkEvent);

    const reactFlowProjection =
      projectRuntimeThreadEventsToWorkflowProjection(reactFlowSdkEvents);
    const tuiProjection = projectRuntimeThreadEventsToWorkflowProjection(tuiSdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(reactFlowEvent.event_id),
    );
    const tuiNode = tuiProjection.nodes.find((node) =>
      node.eventIds.includes(tuiEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.ok(tuiNode);

    const reactFlowTuiRow = await fetchTuiJsonEventRow(
      cli,
      daemon.endpoint,
      reactFlowThread.thread_id,
      reactFlowEvent.event_id,
    );
    const lineModeTuiRow = await fetchTuiJsonEventRow(
      cli,
      daemon.endpoint,
      tuiThreadId,
      tuiEvent.event_id,
    );
    assertOperatorControlCrossSurfaceIdentity({
      daemonEvent: reactFlowEvent,
      sdkEvent: reactFlowSdkEvent,
      reactFlowNode,
      tuiRow: reactFlowTuiRow,
      expected: { ...contractShape, workflowGraphId },
    });
    assertOperatorControlCrossSurfaceIdentity({
      daemonEvent: tuiEvent,
      sdkEvent: tuiSdkEvent,
      reactFlowNode: tuiNode,
      tuiRow: lineModeTuiRow,
      expected: { ...contractShape, workflowGraphId: null },
    });
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("React Flow and line-mode TUI steer controls share the operator-control event contract", async () => {
  const { Thread, createRuntimeSubstrateClient } = await importSdk();
  const {
    createRuntimeOperatorSteerControlRequestFromWorkflowNode,
    projectRuntimeThreadEventsToWorkflowProjection,
  } = await importAgentIde();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-steer-equivalence-workspace-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-steer-equivalence-state-"));
  const bridgeData = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-runtime-steer-equivalence-data-"));
  const bridgeBinary = rustRuntimeBridgeBinary();
  const cli = cliBinary();
  const workflowGraphId = "workflow.react-flow.tui-steer-equivalence";
  const workflowNodeId = "runtime.operator-steer";
  const contractShape = {
    eventKind: "turn.steered",
    sourceEventKind: "OperatorControl.Steer",
    status: "completed",
    componentKind: "operator_control",
    workflowNodeId,
    payloadSchemaVersion: "ioi.runtime.operator-control.v1",
  };
  const previousEnv = {
    command: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND,
    args: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS,
    id: process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID,
  };
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND = bridgeBinary;
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS = JSON.stringify(["--data-dir", bridgeData]);
  process.env.IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID = "rust-runtime-agent-service-steer-equivalence";

  let daemon;
  try {
    daemon = await startRuntimeDaemonService({ cwd, stateDir });
    const reactFlowThread = await fetchJson(`${daemon.endpoint}/v1/threads`, {
      method: "POST",
      body: JSON.stringify({
        runtime_profile: "runtime_service",
        goal: "Prove React Flow and TUI steers share the control event contract.",
        max_steps: 2,
        options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } },
      }),
    });
    const reactFlowTurn = await fetchJson(
      `${daemon.endpoint}/v1/threads/${reactFlowThread.thread_id}/turns`,
      {
        method: "POST",
        body: JSON.stringify({
          prompt: "Prepare the React Flow side of the steer equivalence proof.",
        }),
      },
    );
    const workflowNode = {
      id: "react-flow-tui-equivalence-steer-control",
      type: "runtime_operator_steer",
      config: {
        logic: {
          runtimeOperatorSteerEndpoint: "/v1/threads/{threadId}/turns/{turnId}/steer",
          runtimeOperatorSteerThreadIdField: "threadId",
          runtimeOperatorSteerTurnIdField: "turnId",
          runtimeOperatorSteerGuidanceField: "guidance",
          runtimeOperatorSteerWorkflowNodeId: workflowNodeId,
          runtimeOperatorSteerActor: "operator",
        },
        law: { privilegedActions: ["runtime.turn.steer"] },
      },
    };
    const reactFlowControl = createRuntimeOperatorSteerControlRequestFromWorkflowNode(
      workflowNode,
      {
        threadId: reactFlowThread.thread_id,
        turnId: reactFlowTurn.turn_id,
        guidance: "react-flow equivalence steer",
      },
      { workflowGraphId },
    );
    await fetchJson(`${daemon.endpoint}${reactFlowControl.endpoint}`, {
      method: "POST",
      body: JSON.stringify(reactFlowControl.body),
    });

    const tuiResult = await execFileWithInput(
      cli,
      [
        "agent",
        "tui",
        "--goal",
        "Prove line-mode TUI shares the React Flow steer event contract.",
        "--message",
        "Prepare the TUI side of the steer equivalence proof.",
        "--runtime-profile",
        "runtime_service",
        "--model",
        "auto",
        "--route-id",
        "route.native-local",
        "--cwd",
        cwd,
        "--since-seq",
        "0",
        "--endpoint",
        daemon.endpoint,
        "--interactive",
      ],
      "/steer tui equivalence steer\n/quit\n",
      { cwd: root, timeout: 30000 },
    );
    const tuiThreadId = tuiResult.stdout.match(/thread=(thread_[^\s]+)/)?.[1];
    assert.ok(tuiThreadId);

    const reactFlowEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${reactFlowThread.thread_id}/events?since_seq=0`,
    );
    const tuiEvents = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${tuiThreadId}/events?since_seq=0`,
    );
    const reactFlowEvent = reactFlowEvents.find(
      (event) =>
        event.source_event_kind === "OperatorControl.Steer" &&
        event.source === "react_flow" &&
        event.payload?.guidance === "react-flow equivalence steer",
    );
    const tuiEvent = tuiEvents.find(
      (event) =>
        event.source_event_kind === "OperatorControl.Steer" &&
        event.source === "cli_tui" &&
        event.payload?.guidance === "tui equivalence steer",
    );
    assert.ok(reactFlowEvent);
    assert.ok(tuiEvent);
    assert.deepEqual(operatorControlContractShape(reactFlowEvent), contractShape);
    assert.deepEqual(operatorControlContractShape(tuiEvent), contractShape);
    assert.equal(reactFlowEvent.workflow_graph_id, workflowGraphId);
    assert.equal(tuiEvent.workflow_graph_id, null);
    assert.ok(reactFlowEvent.receipt_refs.some((ref) => ref.startsWith(`receipt_${reactFlowTurn.request_id}_operator_steer_`)));
    assert.ok(reactFlowEvent.policy_decision_refs.includes(`policy_${reactFlowTurn.request_id}_operator_steer_allow`));
    assert.ok(tuiEvent.receipt_refs.some((ref) => ref.includes("_operator_steer_")));
    assert.ok(tuiEvent.policy_decision_refs.some((ref) => ref.endsWith("_operator_steer_allow")));

    const sdkClient = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    const reactFlowSdkThread = await Thread.open(reactFlowThread.thread_id, {
      substrateClient: sdkClient,
    });
    const tuiSdkThread = await Thread.open(tuiThreadId, { substrateClient: sdkClient });
    const reactFlowSdkEvents = await collect(reactFlowSdkThread.events({ sinceSeq: 0 }));
    const tuiSdkEvents = await collect(tuiSdkThread.events({ sinceSeq: 0 }));
    const reactFlowSdkEvent = reactFlowSdkEvents.find(
      (event) => event.id === reactFlowEvent.event_id,
    );
    const tuiSdkEvent = tuiSdkEvents.find((event) => event.id === tuiEvent.event_id);
    assert.ok(reactFlowSdkEvent);
    assert.ok(tuiSdkEvent);

    const reactFlowProjection =
      projectRuntimeThreadEventsToWorkflowProjection(reactFlowSdkEvents);
    const tuiProjection = projectRuntimeThreadEventsToWorkflowProjection(tuiSdkEvents);
    const reactFlowNode = reactFlowProjection.nodes.find((node) =>
      node.eventIds.includes(reactFlowEvent.event_id),
    );
    const tuiNode = tuiProjection.nodes.find((node) =>
      node.eventIds.includes(tuiEvent.event_id),
    );
    assert.ok(reactFlowNode);
    assert.ok(tuiNode);

    const reactFlowTuiRow = await fetchTuiJsonEventRow(
      cli,
      daemon.endpoint,
      reactFlowThread.thread_id,
      reactFlowEvent.event_id,
    );
    const lineModeTuiRow = await fetchTuiJsonEventRow(
      cli,
      daemon.endpoint,
      tuiThreadId,
      tuiEvent.event_id,
    );
    assertOperatorControlCrossSurfaceIdentity({
      daemonEvent: reactFlowEvent,
      sdkEvent: reactFlowSdkEvent,
      reactFlowNode,
      tuiRow: reactFlowTuiRow,
      expected: { ...contractShape, workflowGraphId },
    });
    assertOperatorControlCrossSurfaceIdentity({
      daemonEvent: tuiEvent,
      sdkEvent: tuiSdkEvent,
      reactFlowNode: tuiNode,
      tuiRow: lineModeTuiRow,
      expected: { ...contractShape, workflowGraphId: null },
    });
  } finally {
    if (daemon) await daemon.close();
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_COMMAND", previousEnv.command);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ARGS", previousEnv.args);
    restoreEnv("IOI_RUNTIME_AGENT_SERVICE_BRIDGE_ID", previousEnv.id);
  }
});

test("React Flow memory, authority/tooling, doctor, skill, hook, and package node contracts remain workflow-addressable", () => {
  const workflowContracts = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/deepseek-parity-workflow-contracts.ts"),
    "utf8",
  );
  const graphTypes = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/types/graph.ts"),
    "utf8",
  );
  const workflowDefaults = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-defaults.ts"),
    "utf8",
  );
  const harnessWorkflow = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/harness-workflow/core.ts"),
    "utf8",
  );
  const nodeRegistry = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-node-registry.ts"),
    "utf8",
  );
  const workflowRuntimeUiStrings = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-runtime-ui-strings.ts"),
    "utf8",
  );
  const canvasNode = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Editor/Canvas/Nodes/CanvasNode.tsx"),
    "utf8",
  );
  const graphConfigView = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Editor/Inspector/views/GraphConfigView.tsx"),
    "utf8",
  );
  const agentEditor = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/AgentEditor.tsx"),
    "utf8",
  );
  const workflowComposerView = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/WorkflowComposer/view.tsx"),
    "utf8",
  );
  const workflowComposerController = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/WorkflowComposer/controller.tsx"),
    "utf8",
  );
  const canvas = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Editor/Canvas/Canvas.tsx"),
    "utf8",
  );
  const canvasNodeStyles = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Editor/Canvas/Nodes/CanvasNode.css"),
    "utf8",
  );
  const inspector = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Editor/Inspector/Inspector.tsx"),
    "utf8",
  );
  const workflowRailPanel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/core.tsx"),
    "utf8",
  );
  const workflowSearchPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/searchPanel.tsx",
    ),
    "utf8",
  );
  const workflowRailSearchModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-rail-search-model.ts"),
    "utf8",
  );
  const workflowEntrypointsPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/entrypointsPanel.tsx",
    ),
    "utf8",
  );
  const workflowEntrypointsModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-entrypoints-model.ts"),
    "utf8",
  );
  const workflowFilesPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/filesPanel.tsx",
    ),
    "utf8",
  );
  const workflowFileBundleModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-file-bundle-model.ts"),
    "utf8",
  );
  const workflowSettingsPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-settings-model.ts"),
    "utf8",
  );
  const workflowSettingsHarnessPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessTypes = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessTypes.ts",
    ),
    "utf8",
  );
  const workflowSettingsHarnessActivationPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessActivationGatePanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGatePanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessActivationGateRefsPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateRefsPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessActivationGateTimelinePanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActivationGateTimelinePanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessPackageEvidencePanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidencePanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessPackageEvidenceRowsPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageEvidenceRowsPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessPackageImportReviewPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPackageImportReviewPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessWorkerBindingPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessWorkerBindingPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessActiveRuntimeRollbackPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeRollbackPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessActiveRuntimeBindingPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessActiveRuntimeBindingPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessRollbackRestoreProofPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessRollbackRestoreProofPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessPromotionPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessPromotionReadinessPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/settingsHarnessPromotionReadinessPanel.tsx",
    ),
    "utf8",
  );
  const workflowSettingsHarnessModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-settings-harness-model.ts"),
    "utf8",
  );
  const workflowReadinessPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/readinessPanel.tsx",
    ),
    "utf8",
  );
  const workflowReadinessModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-readiness-model.ts"),
    "utf8",
  );
  const workflowUnitTestsPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/unitTestsPanel.tsx",
    ),
    "utf8",
  );
  const workflowTestReadinessModel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-test-readiness-model.ts",
    ),
    "utf8",
  );
  const workflowRunsPanel = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/features/Workflows/WorkflowRailPanel/runsPanel.tsx",
    ),
    "utf8",
  );
  const workflowRunHistoryModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-run-history-model.ts"),
    "utf8",
  );
  const workflowRuntimeEventProjection = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-runtime-event-projection.ts"),
    "utf8",
  );
  const workflowRailModel = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-rail-model.ts"),
    "utf8",
  );
  const workflowBottomShelf = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/features/Workflows/WorkflowBottomShelf.tsx"),
    "utf8",
  );
  const composerPanelStyles = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/WorkflowComposer/styles/composer-panels.css"),
    "utf8",
  );
  const composerShellStyles = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/WorkflowComposer/styles/composer-shell.css"),
    "utf8",
  );
  const workflowValidation = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-validation.ts"),
    "utf8",
  );
  const workflowSchedulerLaneReadiness = fs.readFileSync(
    path.join(
      root,
      "packages/agent-ide/src/runtime/workflow-scheduler-lane-readiness.ts",
    ),
    "utf8",
  );
  const tauriProjectTypes = fs.readFileSync(
    path.join(root, "apps/autopilot/src-tauri/src/project/types.rs"),
    "utf8",
  );
  const tauriProjectCommands = fs.readFileSync(
    path.join(root, "apps/autopilot/src-tauri/src/project/commands.rs"),
    "utf8",
  );
  const tauriProjectRuntime = fs.readFileSync(
    path.join(root, "apps/autopilot/src-tauri/src/project/runtime.rs"),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerFinalizationLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_finalization_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerTerminalResultLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_terminal_result_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerInterruptLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_interrupt_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerNodeExecutionLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_node_execution_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerNodeOutcomeLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_node_outcome_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerNodeFailureOutcomeLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_node_failure_outcome_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerNodeSuccessEventLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_node_success_event_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerNodeStateUpdateLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_node_state_update_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowSchedulerValidationLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_scheduler_validation_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectPackage = fs.readFileSync(
    path.join(root, "apps/autopilot/src-tauri/src/project/package.rs"),
    "utf8",
  );
  const tauriProjectValidation = fs.readFileSync(
    path.join(root, "apps/autopilot/src-tauri/src/project/validation.rs"),
    "utf8",
  );
  const tauriProjectWorkflowAuthorityToolingLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_authority_tooling_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowApprovalInterruptLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_approval_interrupt_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowBindingLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_binding_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowCheckpointLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_checkpoint_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowStateLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_state_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowNodeContractLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_node_contract_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowNodeMetadataLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_node_metadata_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowRunLifecycleLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_run_lifecycle_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowNodeExecutionLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_node_execution_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowMemoryLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_memory_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowOutputLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_output_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowPackageLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_package_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowCodingRouteLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_coding_route_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowExecutionResultsLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_execution_results_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowGraphExecutionLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_graph_execution_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowHarnessResultsLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_harness_results_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectRepositoryPrLane = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/repository_pr_lane.rs",
    ),
    "utf8",
  );
  const tauriProjectWorkflowValueHelpers = fs.readFileSync(
    path.join(
      root,
      "apps/autopilot/src-tauri/src/project/workflow_value_helpers.rs",
    ),
    "utf8",
  );
  const tauriProjectTemplates = fs.readFileSync(
    path.join(root, "apps/autopilot/src-tauri/src/project/templates.rs"),
    "utf8",
  );
  const tauriRuntimeProjection = fs.readFileSync(
    path.join(root, "apps/autopilot/src-tauri/src/runtime_projection.rs"),
    "utf8",
  );
  const workflowHarnessTools = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-harness-tools.ts"),
    "utf8",
  );
  const runtimeProjectionAdapter = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/runtime-projection-adapter.ts"),
    "utf8",
  );
  const runtimeActionSchema = fs.readFileSync(
    path.join(root, "docs/implementation/runtime-action-schema.json"),
    "utf8",
  );
  const generatedActionSchema = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/generated/action-schema.ts"),
    "utf8",
  );
  const generatedRustActionSchema = fs.readFileSync(
    path.join(root, "apps/autopilot/src-tauri/src/generated/runtime_action_schema.rs"),
    "utf8",
  );
  assert.match(workflowContracts, /memory\.scope/);
  assert.match(workflowContracts, /memory\.remember/);
  assert.match(workflowContracts, /memory\.search/);
  assert.match(workflowContracts, /memory\.list/);
  assert.match(workflowContracts, /memory\.policy/);
  assert.match(workflowContracts, /memory\.path/);
  assert.match(workflowContracts, /memory\.subagentInheritance/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_memory_lane/);
  assert.match(tauriProjectWorkflowMemoryLane, /workflow_memory_send_options/);
  assert.match(tauriProjectWorkflowMemoryLane, /workflow_memory_query_output/);
  assert.match(tauriProjectWorkflowMemoryLane, /memory_search/);
  assert.match(tauriProjectWorkflowMemoryLane, /memory_list/);
  assert.match(tauriProjectWorkflowMemoryLane, /workflow_redacted_memory_record/);
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /workflow_authority_tooling_lane/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_mcp_provider_catalog/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_mcp_tool_catalog/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_native_tool_catalog/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_connector_catalog_describe/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_wallet_capability_dry_run/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_authority_policy_gate/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_authority_approval_gate/,
  );
  assert.match(
    tauriProjectWorkflowAuthorityToolingLane,
    /workflow_live_authority_destructive_denial/,
  );
  assert.match(tauriProjectRuntime, /workflow_scheduler_lane/);
  assert.match(
    workflowSchedulerLaneReadiness,
    /EXPECTED_WORKFLOW_SCHEDULER_LANE_CAPABILITY_IDS/,
  );
  assert.match(workflowSchedulerLaneReadiness, /WORKFLOW_SCHEDULER_LANE_CAPABILITIES/);
  for (const capabilityId of [
    "scheduler",
    "scheduler.finalization",
    "terminalResult",
    "nodeExecution",
    "nodeOutcome",
    "nodeStateUpdate",
    "nodeSuccessEvent",
    "nodeFailureOutcome",
    "interrupt",
    "validation",
  ]) {
    assert.match(workflowSchedulerLaneReadiness, new RegExp(`"${capabilityId}"`));
  }
  for (const proofKey of [
    "workflowSchedulerRuntimeLane",
    "workflowSchedulerFinalizationRuntimeLane",
    "workflowSchedulerTerminalResultRuntimeLane",
    "workflowSchedulerNodeExecutionRuntimeLane",
    "workflowSchedulerNodeOutcomeRuntimeLane",
    "workflowSchedulerNodeStateUpdateRuntimeLane",
    "workflowSchedulerNodeSuccessEventRuntimeLane",
    "workflowSchedulerNodeFailureOutcomeRuntimeLane",
    "workflowSchedulerInterruptRuntimeLane",
    "workflowSchedulerValidationRuntimeLane",
  ]) {
    assert.match(workflowSchedulerLaneReadiness, new RegExp(proofKey));
  }
  assert.match(workflowValidation, /schedulerLaneReadiness/);
  assert.match(workflowValidation, /gateId: "scheduler-lanes"/);
  assert.match(workflowRailPanel, /WorkflowReadinessPanel/);
  assert.match(workflowReadinessPanel, /workflowReadinessModel/);
  assert.match(workflowReadinessModel, /workflowSchedulerLaneReadiness/);
  assert.match(workflowReadinessModel, /readinessItems/);
  assert.match(workflowReadinessPanel, /workflow-readiness-scheduler-lanes/);
  assert.match(workflowReadinessPanel, /data-proof-check/);
  assert.match(workflowRailPanel, /WorkflowUnitTestsPanel/);
  assert.match(workflowRailPanel, /workflowTestReadinessModel/);
  assert.match(workflowUnitTestsPanel, /workflow-unit-test-list/);
  assert.match(workflowUnitTestsPanel, /workflow-unit-test-uncovered/);
  assert.match(workflowTestReadinessModel, /coveredNodeIds/);
  assert.match(workflowTestReadinessModel, /uncoveredNodes/);
  assert.match(workflowRailPanel, /WorkflowRunsPanel/);
  assert.match(workflowRailPanel, /workflowRunHistoryModel/);
  assert.match(workflowRunsPanel, /workflow-runs-list/);
  assert.match(workflowRunsPanel, /workflow-run-inspector/);
  assert.match(workflowRunsPanel, /workflow-run-timeline/);
  assert.match(workflowRunsPanel, /workflow-run-runtime-event-graph/);
  assert.match(workflowRunsPanel, /workflow-run-runtime-event-node-/);
  assert.match(workflowRunsPanel, /data-event-cursor/);
  assert.match(workflowRunsPanel, /data-thread-id/);
  assert.match(workflowRunsPanel, /data-tui-reopen-command/);
  assert.match(workflowRunsPanel, /workflow-run-runtime-event-tui-reopen/);
  assert.match(workflowRunsPanel, /data-receipt-refs/);
  assert.match(workflowRunsPanel, /data-policy-decision-refs/);
  assert.match(workflowRuntimeEventProjection, /WORKFLOW_RUNTIME_TUI_DEEP_LINK_SCHEMA_VERSION/);
  assert.match(workflowRuntimeEventProjection, /WorkflowRuntimeTuiDeepLinkDescriptor/);
  assert.match(workflowRuntimeEventProjection, /tuiDeepLinkForRuntimeThreadEvent/);
  assert.match(workflowComposerController, /loadWorkflowRuntimeThreadEvents/);
  assert.match(workflowComposerController, /setRuntimeThreadEvents/);
  assert.match(workflowComposerView, /runtimeThreadEvents=\{runtimeThreadEvents\}/);
  assert.match(workflowRunHistoryModel, /visibleRows/);
  assert.match(workflowRunHistoryModel, /timelineEvents/);
  assert.match(workflowRunHistoryModel, /comparison/);
  assert.match(workflowRunHistoryModel, /runtimeEventProjection/);
  assert.match(workflowRunHistoryModel, /projectRuntimeThreadEventsToWorkflowProjection/);
  assert.doesNotMatch(tauriProjectRuntime, /fn execute_workflow_project\(/);
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /fn execute_workflow_project\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_scheduler_node_execution_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_scheduler_finalization_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_scheduler_finalized_result/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerLane,
    /workflow_finalize_run_result/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /fn workflow_scheduler_execute_node\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /enum WorkflowSchedulerNodeExecutionFlow/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /execute_workflow_node/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_max_attempts/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_scheduler_node_outcome_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_scheduler_handle_node_outcome/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_node_lifecycle_steps/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_push_event/,
  );
  assert.match(tauriProjectWorkflowSchedulerNodeExecutionLane, /node_started/);
  assert.match(tauriProjectWorkflowSchedulerNodeExecutionLane, /retrying/);
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_selected_output/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_node_logic/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_next_ready_nodes/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /workflow_checkpoint_state/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /node_succeeded/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /child_run_completed/,
  );
  assert.doesNotMatch(tauriProjectWorkflowSchedulerNodeExecutionLane, /output_created/);
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeExecutionLane,
    /asset_materialized/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /fn workflow_scheduler_handle_node_outcome\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /WorkflowSchedulerNodeExecutionFlow/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_scheduler_node_state_update_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_scheduler_apply_node_state_update/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_scheduler_node_success_event_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_scheduler_emit_node_success_events/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_scheduler_node_failure_outcome_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_scheduler_handle_node_failure_outcome/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_next_ready_nodes/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_checkpoint_state/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_node_lifecycle_steps/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_selected_output/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_node_logic/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /pending_writes/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /workflow_push_event/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /node_succeeded/,
  );
  assert.doesNotMatch(tauriProjectWorkflowSchedulerNodeOutcomeLane, /node_failed/);
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /child_run_completed/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /output_created/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerNodeOutcomeLane,
    /asset_materialized/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /fn workflow_scheduler_handle_node_failure_outcome\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /WorkflowSchedulerNodeExecutionFlow/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /workflow_checkpoint_state/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /workflow_node_lifecycle_steps/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /workflow_node_name/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /workflow_push_event/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeFailureOutcomeLane,
    /blocked_node_ids/,
  );
  assert.match(tauriProjectWorkflowSchedulerNodeFailureOutcomeLane, /node_failed/);
  assert.match(tauriProjectWorkflowSchedulerNodeFailureOutcomeLane, /error/);
  assert.match(
    tauriProjectWorkflowSchedulerNodeSuccessEventLane,
    /fn workflow_scheduler_emit_node_success_events\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeSuccessEventLane,
    /WorkflowStateUpdate/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeSuccessEventLane,
    /workflow_push_event/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeSuccessEventLane,
    /workflow_node_name/,
  );
  assert.match(tauriProjectWorkflowSchedulerNodeSuccessEventLane, /node_succeeded/);
  assert.match(
    tauriProjectWorkflowSchedulerNodeSuccessEventLane,
    /child_run_completed/,
  );
  assert.match(tauriProjectWorkflowSchedulerNodeSuccessEventLane, /output_created/);
  assert.match(
    tauriProjectWorkflowSchedulerNodeSuccessEventLane,
    /asset_materialized/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /fn workflow_scheduler_apply_node_state_update\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /WorkflowStateUpdate/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /workflow_next_ready_nodes/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /workflow_selected_output/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /workflow_node_logic/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /branch_decisions/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /pending_writes/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /completed_node_ids/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /interrupted_node_ids/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerNodeStateUpdateLane,
    /node_outputs/,
  );
  assert.match(tauriProjectWorkflowSchedulerNodeStateUpdateLane, /merge/);
  assert.match(tauriProjectWorkflowSchedulerNodeStateUpdateLane, /append/);
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /fn workflow_scheduler_finalized_result\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_completion_has_missing/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_completion_requirements/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_checkpoint_state/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_scheduler_terminal_result_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_scheduler_terminal_result/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_scheduler_terminal_summary/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /WorkflowSchedulerTerminalResultParts/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /struct WorkflowSchedulerTerminalResultParts/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /fn workflow_scheduler_terminal_summary\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /fn workflow_scheduler_terminal_result\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /workflow_completion_requirements/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /workflow_push_event/,
  );
  assert.match(tauriProjectWorkflowSchedulerTerminalResultLane, /run_completed/);
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /save_workflow_thread/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /workflow_attach_harness_run_artifacts/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /workflow_finalize_run_result/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /WorkflowRunResultParts/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_scheduler_interrupt_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /fn workflow_scheduler_interrupted_result\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_runtime_interrupt/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_runtime_interrupt_notice/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_checkpoint_state/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_node_lifecycle_steps/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_interrupt_path/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_scheduler_terminal_result_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_scheduler_terminal_result/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_scheduler_terminal_summary/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /WorkflowSchedulerTerminalResultParts/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_finalize_run_result/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_attach_harness_run_artifacts/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerInterruptLane,
    /workflow_push_event/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_scheduler_validation_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerValidationLane,
    /fn workflow_scheduler_validation_blocked_result\(/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_checkpoint_state/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_scheduler_terminal_result_lane/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_scheduler_terminal_result/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_scheduler_terminal_summary/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerValidationLane,
    /WorkflowSchedulerTerminalResultParts/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_finalize_run_result/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_attach_harness_run_artifacts/,
  );
  assert.doesNotMatch(
    tauriProjectWorkflowSchedulerValidationLane,
    /workflow_push_event/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_approval_interrupt_lane/,
  );
  assert.match(
    tauriProjectWorkflowApprovalInterruptLane,
    /fn workflow_runtime_approval_binding\(/,
  );
  assert.match(
    tauriProjectWorkflowApprovalInterruptLane,
    /fn workflow_runtime_approval_preview\(/,
  );
  assert.match(
    tauriProjectWorkflowApprovalInterruptLane,
    /fn workflow_runtime_interrupt_prompt\(/,
  );
  assert.match(
    tauriProjectWorkflowApprovalInterruptLane,
    /fn workflow_runtime_interrupt_notice\(/,
  );
  assert.match(
    tauriProjectWorkflowApprovalInterruptLane,
    /fn workflow_runtime_interrupt\(/,
  );
  assert.match(tauriProjectWorkflowApprovalInterruptLane, /WorkflowInterrupt/);
  assert.match(tauriProjectWorkflowApprovalInterruptLane, /requiresApproval/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_binding_lane/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_node_schema/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_function_binding/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_tool_binding/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_parser_binding/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_model_binding/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_connector_binding/);
  assert.match(tauriProjectWorkflowBindingLane, /workflow_sandbox_policy/);
  assert.match(
    tauriProjectWorkflowBindingLane,
    /workflow_function_sandbox_precheck/,
  );
  assert.match(
    tauriProjectWorkflowBindingLane,
    /workflow_function_dependency_precheck/,
  );
  assert.match(
    tauriProjectWorkflowBindingLane,
    /workflow_function_input_schema/,
  );
  assert.match(
    tauriProjectWorkflowBindingLane,
    /workflow_function_output_schema/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerFinalizationLane,
    /workflow_checkpoint_lane/,
  );
  assert.match(
    tauriProjectWorkflowCheckpointLane,
    /fn workflow_checkpoint_state\(/,
  );
  assert.match(tauriProjectWorkflowCheckpointLane, /WorkflowCheckpoint/);
  assert.match(tauriProjectWorkflowCheckpointLane, /WorkflowStateSnapshot/);
  assert.match(tauriProjectWorkflowCheckpointLane, /save_workflow_checkpoint/);
  assert.match(tauriProjectWorkflowCheckpointLane, /unique_runtime_id/);
  assert.match(tauriProjectWorkflowCheckpointLane, /active_node_ids\.sort/);
  assert.match(tauriProjectWorkflowSchedulerLane, /workflow_state_lane/);
  assert.match(tauriProjectWorkflowStateLane, /fn workflow_predecessor_output\(/);
  assert.match(tauriProjectWorkflowStateLane, /fn workflow_mapped_node_input\(/);
  assert.match(
    tauriProjectWorkflowStateLane,
    /fn workflow_first_expression_source\(/,
  );
  assert.match(tauriProjectWorkflowStateLane, /fn workflow_selected_output\(/);
  assert.match(
    tauriProjectWorkflowStateLane,
    /fn validate_workflow_expression_refs\(/,
  );
  assert.match(tauriProjectWorkflowStateLane, /fn workflow_schema_from_sample\(/);
  assert.match(tauriProjectWorkflowStateLane, /fn workflow_schema_is_object_like\(/);
  assert.match(
    tauriProjectWorkflowStateLane,
    /fn workflow_node_declared_output_schema\(/,
  );
  assert.match(tauriProjectWorkflowStateLane, /workflow_value_at_path/);
  assert.match(tauriProjectWorkflowStateLane, /workflow_edge_from_port/);
  assert.match(
    tauriProjectWorkflowNodeContractLane,
    /fn workflow_action_frame\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeContractLane,
    /fn workflow_node_port_connection_class\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeContractLane,
    /fn workflow_default_port_connection_class\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeContractLane,
    /fn validate_workflow_edge_ports\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeContractLane,
    /fn workflow_max_attempts\(/,
  );
  assert.match(tauriProjectWorkflowNodeContractLane, /ActionFrame/);
  assert.match(tauriProjectWorkflowNodeContractLane, /ActionBindingRef/);
  assert.match(tauriProjectWorkflowNodeContractLane, /workflow_edge_connection_class/);
  assert.match(tauriProjectWorkflowNodeContractLane, /validate_workflow_connection_class/);
  assert.match(tauriProjectWorkflowNodeContractLane, /workflow_logic_string/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_action_frame/);
  assert.match(tauriProjectWorkflowSchedulerNodeExecutionLane, /workflow_max_attempts/);
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_node_metadata_lane/,
  );
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_value_string\(/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_node_id\(/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_node_type\(/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_node_name\(/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_node_logic\(/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_node_law\(/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /fn workflow_node_by_id/);
  assert.match(tauriProjectWorkflowNodeMetadataLane, /WorkflowProject/);
  assert.match(tauriProjectWorkflowRunLifecycleLane, /workflow_node_metadata_lane/);
  assert.doesNotMatch(tauriProjectWorkflowRunLifecycleLane, /use super::runtime::/);
  assert.match(tauriProjectWorkflowNodeContractLane, /workflow_node_metadata_lane/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_node_metadata_lane/);
  assert.match(tauriProjectWorkflowStateLane, /workflow_node_metadata_lane/);
  assert.match(tauriProjectWorkflowApprovalInterruptLane, /workflow_node_metadata_lane/);
  assert.match(tauriProjectValidation, /workflow_node_metadata_lane/);
  assert.match(tauriProjectPackage, /workflow_node_metadata_lane/);
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_run_lifecycle_lane/,
  );
  assert.match(tauriProjectWorkflowRunLifecycleLane, /fn workflow_push_event\(/);
  assert.match(tauriProjectWorkflowRunLifecycleLane, /fn new_workflow_thread\(/);
  assert.match(
    tauriProjectWorkflowRunLifecycleLane,
    /fn initial_workflow_state\(/,
  );
  assert.match(
    tauriProjectWorkflowRunLifecycleLane,
    /fn workflow_single_node_result\(/,
  );
  assert.match(tauriProjectWorkflowRunLifecycleLane, /WorkflowStreamEvent/);
  assert.match(tauriProjectWorkflowRunLifecycleLane, /WorkflowStateSnapshot/);
  assert.match(tauriProjectWorkflowRunLifecycleLane, /execute_workflow_node/);
  assert.match(
    tauriProjectWorkflowRunLifecycleLane,
    /workflow_finalize_run_result/,
  );
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /fn execute_workflow_tool_binding\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /fn execute_workflow_function_node\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /fn execute_workflow_node\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /fn execute_workflow_harness_canary_node\(/,
  );
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /fn execute_workflow_harness_live_default_node\(/,
  );
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_output_lane/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /ActionKind::GithubPrCreate/);
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /ActionKind::WorkflowPackageExport/,
  );
  assert.match(
    tauriProjectWorkflowNodeExecutionLane,
    /ActionKind::WorkflowPackageImport/,
  );
  assert.match(
    tauriProjectWorkflowOutputLane,
    /workflow_output_satisfies_schema/,
  );
  assert.match(tauriProjectWorkflowOutputLane, /workflow_truncate_output/);
  assert.match(tauriProjectWorkflowOutputLane, /workflow_output_bundle/);
  assert.match(tauriProjectWorkflowOutputLane, /WorkflowOutputBundle/);
  assert.match(tauriProjectWorkflowOutputLane, /WorkflowMaterializedAsset/);
  assert.match(tauriProjectWorkflowOutputLane, /WorkflowRendererRef/);
  assert.match(tauriProjectWorkflowOutputLane, /WorkflowDeliveryTarget/);
  assert.match(tauriProjectWorkflowSchedulerLane, /workflow_coding_route_lane/);
  assert.match(tauriProjectWorkflowCodingRouteLane, /struct WorkflowSkillResolver/);
  assert.match(tauriProjectWorkflowCodingRouteLane, /resolve_skill_context/);
  assert.match(
    tauriProjectWorkflowCodingRouteLane,
    /workflow_coding_route_evidence_from_run/,
  );
  assert.match(
    tauriProjectWorkflowCodingRouteLane,
    /workflow_coding_route_benchmark_results/,
  );
  assert.match(
    tauriProjectWorkflowCodingRouteLane,
    /workflow_coding_route_promotion_decisions/,
  );
  assert.match(
    tauriProjectWorkflowCodingRouteLane,
    /workflow_coding_route_run_summary/,
  );
  assert.match(
    tauriProjectWorkflowCodingRouteLane,
    /workflow_route_verification_evidence/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /workflow_execution_results_lane/,
  );
  assert.match(
    tauriProjectWorkflowExecutionResultsLane,
    /struct WorkflowRunResultParts/,
  );
  assert.match(
    tauriProjectWorkflowExecutionResultsLane,
    /workflow_finalize_run_result/,
  );
  assert.match(
    tauriProjectWorkflowExecutionResultsLane,
    /workflow_run_result_from_parts/,
  );
  assert.match(
    tauriProjectWorkflowExecutionResultsLane,
    /workflow_completion_requirements/,
  );
  assert.match(
    tauriProjectWorkflowExecutionResultsLane,
    /workflow_verification_evidence_from_node_runs/,
  );
  assert.match(
    tauriProjectWorkflowExecutionResultsLane,
    /workflow_coding_route_evidence_from_run/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerLane,
    /workflow_graph_execution_lane/,
  );
  assert.match(tauriProjectWorkflowGraphExecutionLane, /workflow_edge_from/);
  assert.match(tauriProjectWorkflowGraphExecutionLane, /workflow_edge_to/);
  assert.match(
    tauriProjectWorkflowGraphExecutionLane,
    /workflow_edge_connection_class/,
  );
  assert.match(
    tauriProjectWorkflowGraphExecutionLane,
    /workflow_has_incoming_connection_class/,
  );
  assert.match(
    tauriProjectWorkflowGraphExecutionLane,
    /workflow_edge_is_selected/,
  );
  assert.match(tauriProjectWorkflowGraphExecutionLane, /workflow_node_ready/);
  assert.match(
    tauriProjectWorkflowGraphExecutionLane,
    /workflow_next_ready_nodes/,
  );
  assert.match(
    tauriProjectWorkflowGraphExecutionLane,
    /workflow_node_lifecycle_steps/,
  );
  assert.match(
    tauriProjectWorkflowSchedulerTerminalResultLane,
    /workflow_harness_results_lane/,
  );
  assert.match(
    tauriProjectWorkflowHarnessResultsLane,
    /workflow_attach_harness_run_artifacts/,
  );
  assert.match(
    tauriProjectWorkflowHarnessResultsLane,
    /workflow_harness_attempt_for_node_run/,
  );
  assert.match(
    tauriProjectWorkflowHarnessResultsLane,
    /workflow_harness_shadow_comparison_records_for_attempt_records/,
  );
  assert.match(
    tauriProjectWorkflowHarnessResultsLane,
    /workflow_harness_gated_cluster_runs_for_attempt_records/,
  );
  assert.match(
    tauriProjectWorkflowHarnessResultsLane,
    /DEFAULT_AGENT_HARNESS_ACTIVATION_ID/,
  );
  assert.match(tauriProjectWorkflowHarnessResultsLane, /workflow_hash_value/);
  assert.match(workflowContracts, /runtime\.task/);
  assert.match(workflowContracts, /runtime\.job/);
  assert.match(workflowContracts, /runtime\.checklist/);
  assert.match(workflowContracts, /runtime\.ui_string_catalog/);
  assert.match(workflowContracts, /runtime\.accessible_status/);
  assert.match(workflowContracts, /workflow\.package_export/);
  assert.match(workflowContracts, /workflow\.package_import/);
  assert.match(graphTypes, /workflowChromeLocale\?: string/);
  assert.match(workflowDefaults, /workflowChromeLocale: "en-US"/);
  assert.match(workflowDefaults, /config\?\.workflowChromeLocale/);
  assert.match(graphTypes, /workflowChromeLocale\?: string \| null/);
  assert.match(graphTypes, /workflowPackageExportEndpoint\?: string/);
  assert.match(graphTypes, /workflowPackageImportEndpoint\?: string/);
  assert.match(graphTypes, /consumesWorkflowPackageExport\?: boolean/);
  assert.match(graphTypes, /consumesWorkflowPackageImportReview\?: boolean/);
  assert.match(graphTypes, /\| "workflow_package_export"/);
  assert.match(graphTypes, /\| "workflow_package_import"/);
  assert.match(graphTypes, /workflowPackageImportLocalePreservedField\?: string/);
  assert.match(workflowComposerController, /sourceWorkflowChromeLocale/);
  assert.match(workflowComposerController, /portableManifest\?\.workflowChromeLocale/);
  assert.match(workflowComposerController, /workflowChromeLocalePreserved/);
  assert.match(workflowRailPanel, /data-workflow-chrome-locale/);
  assert.match(workflowRailPanel, /data-package-import-source-chrome-locale/);
  assert.match(workflowRailPanel, /data-package-import-imported-chrome-locale/);
  assert.match(workflowSettingsHarnessPackageImportReviewPanel, /data-package-import-chrome-locale-preserved/);
  assert.match(workflowRailModel, /manifest\.workflowChromeLocale/);
  assert.match(workflowRailModel, /workflowPackageNodeOutputSummary/);
  assert.match(workflowRailModel, /workflowPackageNodeOutputStatus/);
  assert.match(workflowRailModel, /workflow\.package\.export/);
  assert.match(workflowRailModel, /workflow\.package\.import/);
  assert.match(workflowRailModel, /workflowChromeLocalePreserved/);
  assert.match(workflowRailModel, /WorkflowGithubPrCreatePlanSummary/);
  assert.match(workflowRailModel, /workflowGithubPrCreatePlanSummary/);
  assert.match(workflowRailModel, /workflowGithubPrCreatePlanStatus/);
  assert.match(workflowRailModel, /github__pr_create/);
  assert.match(workflowRailModel, /requestPayloadHash/);
  assert.match(workflowRailModel, /missingScopes/);
  assert.match(workflowRailPanel, /workflow-selected-node-package-output-summary/);
  assert.match(workflowRailPanel, /workflowPackageNodeOutputSummary/);
  assert.match(workflowRailPanel, /data-package-node-kind/);
  assert.match(workflowRailPanel, /data-package-path/);
  assert.match(workflowRailPanel, /data-imported-workflow-path/);
  assert.match(workflowRailPanel, /data-workflow-chrome-locale-preserved/);
  assert.match(workflowRailPanel, /WorkflowGithubPrCreateOutputSummaryCard/);
  assert.match(workflowRailPanel, /workflow-selected-node-github-pr-create-output-summary/);
  assert.match(workflowRailPanel, /data-github-pr-create-request-hash/);
  assert.match(workflowRailPanel, /data-github-pr-create-dry-run/);
  assert.match(workflowRailPanel, /data-github-pr-create-mutation-executed/);
  assert.match(workflowRailPanel, /data-github-pr-create-missing-scopes/);
  assert.match(workflowRailPanel, /data-github-pr-create-review-gate-status/);
  assert.match(workflowRailPanel, /data-github-pr-create-receipt-refs/);
  assert.match(workflowRailPanel, /data-github-pr-create-replay-fixture-ref/);
  assert.match(workflowBottomShelf, /workflow-selection-package-output-summary/);
  assert.match(workflowBottomShelf, /workflowPackageNodeOutputSummary/);
  assert.match(workflowBottomShelf, /workflow-selection-github-pr-create-output-summary/);
  assert.match(workflowBottomShelf, /workflowGithubPrCreatePlanSummary/);
  assert.match(workflowBottomShelf, /workflowGithubPrCreatePlanStatus/);
  assert.match(tauriProjectTypes, /workflow_chrome_locale: Option<String>/);
  assert.match(tauriProjectCommands, /get\("workflowChromeLocale"\)/);
  assert.match(tauriProjectCommands, /manifest\.workflow_chrome_locale/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /ActionKind::WorkflowPackageExport/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /ActionKind::WorkflowPackageImport/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /ActionKind::GithubPrCreate/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /workflow_package_lane/);
  assert.match(tauriProjectWorkflowPackageLane, /execute_workflow_package_export_node/);
  assert.match(tauriProjectWorkflowPackageLane, /execute_workflow_package_import_node/);
  assert.match(tauriProjectWorkflowNodeExecutionLane, /repository_pr_lane/);
  assert.match(tauriProjectWorkflowNodeContractLane, /workflow_value_helpers/);
  assert.match(tauriProjectWorkflowPackageLane, /workflow_value_helpers/);
  assert.match(tauriProjectRepositoryPrLane, /workflow_value_helpers/);
  assert.match(tauriProjectRepositoryPrLane, /workflow_github_pr_create_output/);
  assert.match(tauriProjectWorkflowValueHelpers, /workflow_value_at_path/);
  assert.match(tauriProjectWorkflowValueHelpers, /workflow_hash_value_raw_hex/);
  assert.match(tauriProjectWorkflowPackageLane, /workflow_package_export/);
  assert.match(tauriProjectWorkflowPackageLane, /workflow_package_import/);
  assert.match(tauriProjectRepositoryPrLane, /github_pr_create/);
  assert.match(tauriProjectWorkflowPackageLane, /workflowPackageImportReview/);
  assert.match(tauriProjectTemplates, /workflow_package_export/);
  assert.match(tauriProjectTemplates, /workflow_package_import/);
  assert.match(tauriProjectTemplates, /github_pr_create/);
  assert.match(tauriProjectTemplates, /workflow_package_export_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_package_import_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_runtime_thread_fork_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_runtime_operator_interrupt_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_runtime_operator_steer_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_runtime_context_compact_output_schema/);
  assert.match(tauriProjectTemplates, /workflow_github_pr_create_output_schema/);
  assert.match(tauriRuntimeProjection, /WorkflowPackageExport/);
  assert.match(tauriRuntimeProjection, /WorkflowPackageImport/);
  assert.match(tauriRuntimeProjection, /RuntimeThreadFork/);
  assert.match(tauriRuntimeProjection, /RuntimeOperatorInterrupt/);
  assert.match(tauriRuntimeProjection, /RuntimeOperatorSteer/);
  assert.match(tauriRuntimeProjection, /RuntimeContextCompact/);
  assert.match(tauriRuntimeProjection, /GithubPrCreate/);
  assert.match(tauriRuntimeProjection, /output_bundle/);
  assert.match(workflowContracts, /repository\.context/);
  assert.match(workflowContracts, /repository\.branch_policy/);
  assert.match(workflowContracts, /repository\.github_context/);
  assert.match(workflowContracts, /repository\.issue/);
  assert.match(workflowContracts, /repository\.pr_attempt/);
  assert.match(workflowContracts, /repository\.review_gate/);
  assert.match(workflowContracts, /repository\.github_pr_create/);
  assert.match(workflowContracts, /runtime\.doctor/);
  assert.match(nodeRegistry, /runtime_doctor/);
  assert.match(nodeRegistry, /RuntimeDoctorNode/);
  assert.match(nodeRegistry, /\/v1\/doctor/);
  assert.match(nodeRegistry, /blockOnRequiredFailures/);
  assert.match(nodeRegistry, /runtimeUiStringCatalogRef/);
  assert.match(nodeRegistry, /workflowChromeLocale/);
  assert.match(nodeRegistry, /localeKey/);
  assert.match(nodeRegistry, /ariaLabelKey/);
  assert.match(nodeRegistry, /statusAnnouncementKey/);
  assert.match(nodeRegistry, /accessibleStatusField/);
  assert.match(nodeRegistry, /colorIndependentStatus/);
  assert.match(nodeRegistry, /runtime_task/);
  assert.match(nodeRegistry, /RuntimeTaskNode/);
  assert.match(nodeRegistry, /runtimeTaskStatusField/);
  assert.match(nodeRegistry, /runtime_job/);
  assert.match(nodeRegistry, /RuntimeJobNode/);
  assert.match(nodeRegistry, /\/v1\/jobs/);
  assert.match(nodeRegistry, /\/v1\/jobs\/\{jobId\}\/cancel/);
  assert.match(nodeRegistry, /runtimeJobLifecycleField/);
  assert.match(nodeRegistry, /runtimeJobCancelEndpoint/);
  assert.match(nodeRegistry, /runtime_checklist/);
  assert.match(nodeRegistry, /RuntimeChecklistNode/);
  assert.match(nodeRegistry, /runtimeChecklistStatusField/);
  assert.match(nodeRegistry, /\/v1\/runs\/\{runId\}\/trace/);
  assert.match(nodeRegistry, /runtime_thread_fork/);
  assert.match(nodeRegistry, /RuntimeThreadForkNode/);
  assert.match(nodeRegistry, /runtimeThreadForkWorkflowNodeId/);
  assert.match(nodeRegistry, /\/v1\/threads\/\{threadId\}\/fork/);
  assert.match(nodeRegistry, /runtime_operator_interrupt/);
  assert.match(nodeRegistry, /RuntimeOperatorInterruptNode/);
  assert.match(nodeRegistry, /runtimeOperatorInterruptWorkflowNodeId/);
  assert.match(nodeRegistry, /\/v1\/threads\/\{threadId\}\/turns\/\{turnId\}\/interrupt/);
  assert.match(nodeRegistry, /runtime_operator_steer/);
  assert.match(nodeRegistry, /RuntimeOperatorSteerNode/);
  assert.match(nodeRegistry, /runtimeOperatorSteerWorkflowNodeId/);
  assert.match(nodeRegistry, /\/v1\/threads\/\{threadId\}\/turns\/\{turnId\}\/steer/);
  assert.match(nodeRegistry, /runtime_context_compact/);
  assert.match(nodeRegistry, /RuntimeContextCompactNode/);
  assert.match(nodeRegistry, /runtimeContextCompactWorkflowNodeId/);
  assert.match(nodeRegistry, /\/v1\/threads\/\{threadId\}\/compact/);
  assert.match(nodeRegistry, /workflow_package_export/);
  assert.match(nodeRegistry, /WorkflowPackageExportNode/);
  assert.match(nodeRegistry, /workflow\.package\.export/);
  assert.match(nodeRegistry, /workflowPackageExport\.manifest\.workflowChromeLocale/);
  assert.match(nodeRegistry, /workflowPackageExport\.manifest\.harnessPackageManifest/);
  assert.match(nodeRegistry, /workflow_package_import/);
  assert.match(nodeRegistry, /WorkflowPackageImportNode/);
  assert.match(nodeRegistry, /workflow\.package\.import/);
  assert.match(nodeRegistry, /workflowPackageImportReview\.evidence\.packageEvidenceReady/);
  assert.match(nodeRegistry, /workflowPackageImportReview\.evidence\.workflowChromeLocalePreserved/);
  assert.match(nodeRegistry, /repository_context/);
  assert.match(nodeRegistry, /RepositoryContextNode/);
  assert.match(nodeRegistry, /\/v1\/repository-context/);
  assert.match(nodeRegistry, /repositoryDirtyField/);
  assert.match(nodeRegistry, /branch_policy/);
  assert.match(nodeRegistry, /BranchPolicyNode/);
  assert.match(nodeRegistry, /branchPolicyStatusField/);
  assert.match(nodeRegistry, /protectedBranchNames/);
  assert.match(nodeRegistry, /github_context/);
  assert.match(nodeRegistry, /GitHubContextNode/);
  assert.match(nodeRegistry, /\/v1\/github-context/);
  assert.match(nodeRegistry, /githubPrPreconditionsField/);
  assert.match(nodeRegistry, /issue_context/);
  assert.match(nodeRegistry, /IssueContextNode/);
  assert.match(nodeRegistry, /\/v1\/issue-context/);
  assert.match(nodeRegistry, /issueContextBoundField/);
  assert.match(nodeRegistry, /pr_attempt/);
  assert.match(nodeRegistry, /PrAttemptNode/);
  assert.match(nodeRegistry, /\/v1\/pr-attempts/);
  assert.match(nodeRegistry, /prAttemptAuthorityField/);
  assert.match(nodeRegistry, /review_gate/);
  assert.match(nodeRegistry, /ReviewGateNode/);
  assert.match(nodeRegistry, /\/v1\/review-gate/);
  assert.match(nodeRegistry, /reviewGateReviewersField/);
  assert.match(nodeRegistry, /github_pr_create/);
  assert.match(nodeRegistry, /GitHubPrCreateNode/);
  assert.match(nodeRegistry, /\/v1\/github\/pr-create-plan/);
  assert.match(nodeRegistry, /githubPrCreatePlanRequestHashField/);
  assert.match(nodeRegistry, /SkillNode/);
  assert.match(nodeRegistry, /SkillPackNode/);
  assert.match(nodeRegistry, /HookNode/);
  assert.match(nodeRegistry, /HookPolicyNode/);
  assert.match(nodeRegistry, /\/v1\/skills/);
  assert.match(nodeRegistry, /\/v1\/hooks/);
  assert.match(nodeRegistry, /failurePolicy/);
  assert.match(nodeRegistry, /consumesSkillHookManifest/);
  assert.match(nodeRegistry, /hookDryRunOnly/);
  assert.match(nodeRegistry, /hookDryRunPlan/);
  assert.match(nodeRegistry, /hookPolicyPassedRoute/);
  assert.match(nodeRegistry, /hookPolicyBlockedRoute/);
  assert.match(nodeRegistry, /hookInvocationLedger/);
  assert.match(nodeRegistry, /hookInvocationStateField/);
  assert.match(nodeRegistry, /hookEscalationCountField/);
  assert.match(nodeRegistry, /hookEscalationDetailsField/);
  assert.match(nodeRegistry, /hookEscalationReceiptField/);
  assert.match(nodeRegistry, /activeSkillSetHash/);
  assert.match(nodeRegistry, /activeHookSetHash/);
  assert.match(workflowRuntimeUiStrings, /resolveWorkflowRuntimeUiString/);
  assert.match(workflowRuntimeUiStrings, /workflowRuntimeNodeChrome/);
  assert.match(workflowRuntimeUiStrings, /normalizeWorkflowRuntimeLocale/);
  assert.match(workflowRuntimeUiStrings, /workflowRuntimeAccessibleStatusLabel/);
  assert.match(workflowRuntimeUiStrings, /modelOutputLocalized: false/);
  assert.match(workflowRuntimeUiStrings, /workflow_package_export/);
  assert.match(workflowRuntimeUiStrings, /workflow_package_import/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.workflow_package_export\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.workflow_package_import\.status/);
  assert.match(canvas, /onKeyboardSelect/);
  assert.match(canvas, /nodesFocusable/);
  assert.match(canvas, /node-enter-space-selects-inspector/);
  assert.match(canvas, /workflowChromeLocale/);
  assert.match(canvas, /data-workflow-chrome-locale/);
  assert.match(canvasNode, /workflowRuntimeNodeChrome/);
  assert.match(canvasNode, /aria-label=\{chrome\.ariaLabel\}/);
  assert.match(canvasNode, /tabIndex=\{0\}/);
  assert.match(canvasNode, /aria-keyshortcuts="Enter Space"/);
  assert.match(canvasNode, /data-keyboard-selectable="true"/);
  assert.match(canvasNode, /handleNodeKeyDown/);
  assert.match(canvasNode, /event\.key !== "Enter" && event\.key !== " "/);
  assert.match(canvasNode, /locale: workflowChromeLocale/);
  assert.match(canvasNode, /data-accessible-status-text=\{chrome\.statusText\}/);
  assert.match(canvasNode, /workflow-canvas-node-accessible-status/);
  assert.match(canvasNodeStyles, /\.canvas-node:focus-visible/);
  assert.match(canvasNodeStyles, /\.react-flow__node:focus-visible \.canvas-node/);
  assert.match(graphConfigView, /workflow-global-chrome-locale/);
  assert.match(graphConfigView, /normalizeWorkflowRuntimeLocale/);
  assert.match(agentEditor, /workflowChromeLocale=\{globalConfig\.workflowChromeLocale\}/);
  assert.match(workflowComposerView, /workflowChromeLocale=\{globalConfig\.workflowChromeLocale\}/);
  assert.match(workflowComposerView, /onUpdateWorkflowChromeLocale/);
  assert.match(workflowComposerController, /handleUpdateWorkflowChromeLocale/);
  assert.match(inspector, /workflow-runtime-chrome-locale/);
  assert.match(inspector, /workflowChromeLocale/);
  assert.match(inspector, /data-model-output-localized/);
  assert.match(workflowRailPanel, /workflowRuntimeAccessibleStatusLabel/);
  assert.match(workflowRailPanel, /workflowRuntimeNodeChrome/);
  assert.match(workflowRailPanel, /WorkflowSearchPanel/);
  assert.match(workflowRailPanel, /workflowRailSearchModel/);
  assert.match(workflowSearchPanel, /workflow-rail-search-results/);
  assert.match(workflowSearchPanel, /workflow-rail-search-index-summary/);
  assert.match(workflowSearchPanel, /data-result-kind/);
  assert.match(workflowRailSearchModel, /workflowRailSearchModel/);
  assert.match(workflowRailSearchModel, /visibleResults/);
  assert.match(workflowRailSearchModel, /resultGroups/);
  assert.match(workflowRailSearchModel, /resultKindCounts/);
  assert.match(workflowRailPanel, /WorkflowEntrypointsPanel/);
  assert.match(workflowRailPanel, /workflowEntrypointsModel/);
  assert.match(workflowEntrypointsPanel, /workflow-sources-list/);
  assert.match(workflowEntrypointsPanel, /workflow-schedules-list/);
  assert.match(workflowEntrypointsPanel, /workflow-source-node-/);
  assert.match(workflowEntrypointsPanel, /workflow-schedule-node-/);
  assert.match(workflowEntrypointsModel, /workflowEntrypointsModel/);
  assert.match(workflowEntrypointsModel, /readyStartPoints/);
  assert.match(workflowEntrypointsModel, /readyTriggers/);
  assert.match(workflowEntrypointsModel, /blockedTriggers/);
  assert.match(workflowRailPanel, /WorkflowFilesPanel/);
  assert.match(workflowRailPanel, /workflowFileBundleModel/);
  assert.match(workflowFilesPanel, /workflow-files-list/);
  assert.match(workflowFilesPanel, /workflow-file-/);
  assert.match(workflowFilesPanel, /data-file-ready/);
  assert.match(workflowFileBundleModel, /workflowFileBundleModel/);
  assert.match(workflowFileBundleModel, /readyItems/);
  assert.match(workflowFileBundleModel, /pendingItems/);
  assert.match(workflowFileBundleModel, /portablePackageExported/);
  assert.match(workflowRailPanel, /WorkflowSettingsPanel/);
  assert.match(workflowRailPanel, /WorkflowSettingsHarnessPanel/);
  assert.match(workflowRailPanel, /workflowSettingsModel/);
  assert.match(workflowRailPanel, /workflowSettingsHarnessModel/);
  assert.match(workflowSettingsPanel, /workflow-settings-summary/);
  assert.match(workflowSettingsPanel, /workflow-settings-chrome-locale-select/);
  assert.match(workflowSettingsPanel, /workflow-environment-profile/);
  assert.match(workflowSettingsPanel, /workflow-settings-binding-registry/);
  assert.match(workflowSettingsPanel, /workflow-settings-production-profile/);
  assert.match(workflowSettingsModel, /workflowSettingsModel/);
  assert.match(workflowSettingsModel, /productionSummary/);
  assert.match(workflowSettingsModel, /packageReadinessStatus/);
  assert.match(workflowSettingsHarnessPanel, /workflow-settings-harness-summary/);
  assert.match(workflowSettingsHarnessPanel, /WorkflowSettingsHarnessActivationPanel/);
  assert.match(workflowSettingsHarnessPanel, /WorkflowSettingsHarnessWorkerBindingPanel/);
  assert.match(workflowSettingsHarnessPanel, /WorkflowSettingsHarnessPromotionPanel/);
  assert.match(workflowSettingsHarnessPanel, /settingsHarnessTypes/);
  assert.match(workflowSettingsHarnessTypes, /WorkflowSettingsHarnessPanelProps/);
  assert.match(workflowSettingsHarnessTypes, /WorkflowSettingsHarnessActivationProps/);
  assert.match(workflowSettingsHarnessActivationPanel, /WorkflowSettingsHarnessActivationGatePanel/);
  assert.match(workflowSettingsHarnessActivationGatePanel, /workflow-harness-activation-gate-inspector/);
  assert.match(workflowSettingsHarnessActivationGatePanel, /WorkflowSettingsHarnessActivationGateRefsPanel/);
  assert.match(workflowSettingsHarnessActivationGatePanel, /WorkflowSettingsHarnessActivationGateTimelinePanel/);
  assert.match(workflowSettingsHarnessActivationGateRefsPanel, /workflow-harness-activation-gate-evidence-refs/);
  assert.match(workflowSettingsHarnessActivationGateRefsPanel, /workflow-harness-activation-gate-receipt-refs/);
  assert.match(workflowSettingsHarnessActivationGateRefsPanel, /workflow-harness-activation-gate-replay-refs/);
  assert.match(workflowSettingsHarnessActivationGateTimelinePanel, /workflow-harness-activation-gate-node-attempt-refs/);
  assert.match(workflowSettingsHarnessActivationGateTimelinePanel, /workflow-harness-activation-gate-node-timeline/);
  assert.match(workflowSettingsHarnessActivationGatePanel, /WorkflowSettingsHarnessPackageEvidencePanel/);
  assert.match(workflowSettingsHarnessPackageEvidencePanel, /workflow-harness-package-evidence-review/);
  assert.match(workflowSettingsHarnessPackageEvidencePanel, /WorkflowSettingsHarnessPackageEvidenceRowsPanel/);
  assert.match(workflowSettingsHarnessPackageEvidencePanel, /WorkflowSettingsHarnessPackageImportReviewPanel/);
  assert.match(workflowSettingsHarnessPackageEvidenceRowsPanel, /workflow-harness-package-evidence-row-/);
  assert.match(workflowSettingsHarnessPackageEvidenceRowsPanel, /workflow-harness-package-evidence-row-ref-/);
  assert.match(workflowSettingsHarnessPackageImportReviewPanel, /workflow-harness-package-import-review/);
  assert.match(workflowSettingsHarnessPackageImportReviewPanel, /workflow-harness-package-import-handoff/);
  assert.doesNotMatch(workflowSettingsHarnessActivationPanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessActivationGatePanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessActivationGateRefsPanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessActivationGateTimelinePanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessPackageEvidencePanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessPackageEvidenceRowsPanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessPackageImportReviewPanel, /settingsHarnessPanel/);
  assert.match(workflowSettingsHarnessWorkerBindingPanel, /WorkflowSettingsHarnessActiveRuntimeRollbackPanel/);
  assert.match(workflowSettingsHarnessActiveRuntimeRollbackPanel, /WorkflowSettingsHarnessActiveRuntimeBindingPanel/);
  assert.match(workflowSettingsHarnessActiveRuntimeBindingPanel, /data-worker-binding-registry-bound/);
  assert.match(workflowSettingsHarnessActiveRuntimeBindingPanel, /workflow-harness-active-runtime-binding-deep-links/);
  assert.match(workflowSettingsHarnessActiveRuntimeRollbackPanel, /workflow-harness-active-runtime-rollback-proof/);
  assert.match(workflowSettingsHarnessActiveRuntimeRollbackPanel, /WorkflowSettingsHarnessRollbackRestoreProofPanel/);
  assert.doesNotMatch(workflowSettingsHarnessActiveRuntimeBindingPanel, /settingsHarnessPanel/);
  assert.match(workflowSettingsHarnessRollbackRestoreProofPanel, /workflow-harness-git-restore-proof/);
  assert.doesNotMatch(workflowSettingsHarnessRollbackRestoreProofPanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessActiveRuntimeRollbackPanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessWorkerBindingPanel, /settingsHarnessPanel/);
  assert.match(workflowSettingsHarnessPromotionPanel, /WorkflowSettingsHarnessPromotionReadinessPanel/);
  assert.match(workflowSettingsHarnessPromotionPanel, /workflow-harness-promotion-clusters/);
  assert.match(workflowSettingsHarnessPromotionReadinessPanel, /workflow-harness-selector-live-promotion-readiness/);
  assert.match(workflowSettingsHarnessPromotionReadinessPanel, /workflow-harness-authority-gate-live/);
  assert.doesNotMatch(workflowSettingsHarnessPromotionReadinessPanel, /settingsHarnessPanel/);
  assert.doesNotMatch(workflowSettingsHarnessPromotionPanel, /settingsHarnessPanel/);
  assert.match(workflowSettingsHarnessModel, /workflowSettingsHarnessModel/);
  assert.match(workflowSettingsHarnessModel, /gatedClustersLabel/);
  assert.match(workflowRailPanel, /globalWorkflowChromeLocale/);
  assert.match(workflowRailPanel, /onUpdateWorkflowChromeLocale/);
  assert.match(workflowRailPanel, /workflow-selected-node-status-announcement/);
  assert.match(workflowRailPanel, /data-accessible-status-text/);
  assert.match(workflowRunsPanel, /workflow-run-timeline/);
  assert.match(workflowRunsPanel, /tabIndex=\{0\}/);
  assert.match(workflowRailPanel, /workflow-selected-node-inspector/);
  assert.match(workflowBottomShelf, /workflow-bottom-run-timeline/);
  assert.match(workflowBottomShelf, /workflow-run-event-snapshot/);
  assert.match(workflowBottomShelf, /tabIndex=\{0\}/);
  assert.match(composerPanelStyles, /\.workflow-run-timeline li:focus-visible/);
  assert.match(composerPanelStyles, /\.workflow-run-card:focus-visible/);
  assert.match(composerShellStyles, /\.workflow-node-inspector:focus-visible/);
  assert.match(composerShellStyles, /\.workflow-search-result:focus-visible/);
  assert.match(composerShellStyles, /\.workflow-harness-ref-button:focus-visible/);
  assert.match(harnessWorkflow, /memory_read/);
  assert.match(harnessWorkflow, /memory_search/);
  assert.match(harnessWorkflow, /memory_list/);
  assert.match(harnessWorkflow, /memory_write/);
  assert.match(harnessWorkflow, /memory_policy/);
  assert.match(harnessWorkflow, /memory_subagent_inheritance/);
  assert.match(harnessWorkflow, /SubagentMemoryInheritance/);
  assert.match(harnessWorkflow, /memory\.writeRequiresApproval/);
  assert.match(harnessWorkflow, /subagent inheritance/);
  assert.match(harnessWorkflow, /runtime_doctor/);
  assert.match(harnessWorkflow, /RuntimeDoctorReport/);
  assert.match(harnessWorkflow, /runtime\.doctor\.read/);
  assert.match(harnessWorkflow, /runtimeNodeChromeLogic/);
  assert.match(harnessWorkflow, /accessibleStatusField/);
  assert.match(harnessWorkflow, /colorIndependentStatus/);
  assert.match(harnessWorkflow, /runtime_task/);
  assert.match(harnessWorkflow, /RuntimeTaskRecord/);
  assert.match(harnessWorkflow, /runtime\.task\.read/);
  assert.match(harnessWorkflow, /runtime_job/);
  assert.match(harnessWorkflow, /JobQueued/);
  assert.match(harnessWorkflow, /runtime\.job\.read/);
  assert.match(harnessWorkflow, /\/v1\/jobs\/\{jobId\}\/cancel/);
  assert.match(harnessWorkflow, /runtimeJobCancelable/);
  assert.match(harnessWorkflow, /runtime_checklist/);
  assert.match(harnessWorkflow, /RuntimeChecklistRecord/);
  assert.match(harnessWorkflow, /runtime\.checklist\.read/);
  assert.match(harnessWorkflow, /runtimeChecklistStatusField/);
  assert.match(harnessWorkflow, /workflow_package_export/);
  assert.match(harnessWorkflow, /workflow_package_import/);
  assert.match(harnessWorkflow, /WorkflowPortablePackageManifest/);
  assert.match(harnessWorkflow, /WorkflowPackageImportReview/);
  assert.match(harnessWorkflow, /workflow\.package\.export/);
  assert.match(harnessWorkflow, /workflow\.package\.import/);
  assert.match(harnessWorkflow, /workflowPackageImportReview\.evidence\.workflowChromeLocalePreserved/);
  assert.match(harnessWorkflow, /repository_context/);
  assert.match(harnessWorkflow, /RepositoryContext/);
  assert.match(harnessWorkflow, /repository\.context\.read/);
  assert.match(harnessWorkflow, /branch_policy/);
  assert.match(harnessWorkflow, /BranchPolicyDecision/);
  assert.match(harnessWorkflow, /repository\.branch_policy\.read/);
  assert.match(harnessWorkflow, /github_context/);
  assert.match(harnessWorkflow, /GitHubContext/);
  assert.match(harnessWorkflow, /github\.context\.read/);
  assert.match(harnessWorkflow, /issue_context/);
  assert.match(harnessWorkflow, /IssueContext/);
  assert.match(harnessWorkflow, /github\.issue\.read/);
  assert.match(harnessWorkflow, /pr_attempt/);
  assert.match(harnessWorkflow, /PrAttemptRecord/);
  assert.match(harnessWorkflow, /github\.pr\.preview/);
  assert.match(harnessWorkflow, /review_gate/);
  assert.match(harnessWorkflow, /ReviewGateDecision/);
  assert.match(harnessWorkflow, /review\.gate\.evaluate/);
  assert.match(harnessWorkflow, /github_pr_create/);
  assert.match(harnessWorkflow, /GitHubPrCreatePlan/);
  assert.match(harnessWorkflow, /github\.pr\.create/);
  assert.match(harnessWorkflow, /githubPrCreatePlanRequestHashField/);
  assert.match(harnessWorkflow, /authority_tooling_github_pr_create_envelope/);
  assert.match(
    harnessWorkflow,
    /DEFAULT_AUTHORITY_TOOLING_NODE_AUTHORITY_COMPONENT_KINDS[\s\S]*"github_pr_create"/,
  );
  assert.match(
    harnessWorkflow,
    /HARNESS_LIVE_SHADOW_COMPARISON_GATE_COMPONENTS[\s\S]*"github_pr_create"/,
  );
  assert.match(harnessWorkflow, /skill_registry/);
  assert.match(harnessWorkflow, /hook_registry/);
  assert.match(harnessWorkflow, /hook_policy/);
  assert.match(harnessWorkflow, /SkillRegistryProjection/);
  assert.match(harnessWorkflow, /HookRegistryProjection/);
  assert.match(harnessWorkflow, /HookDryRunPlan/);
  assert.match(harnessWorkflow, /active_skill_hook_manifest/);
  assert.match(harnessWorkflow, /hook_dry_run_plan/);
  assert.match(harnessWorkflow, /hook_policy_decision/);
  assert.match(harnessWorkflow, /hook_invocation_ledger/);
  assert.match(harnessWorkflow, /hook_escalation_receipt/);
  assert.match(workflowValidation, /workflowNodeIsHookPolicy/);
  assert.match(workflowValidation, /hook_policy_dry_run_blocked/);
  assert.match(workflowValidation, /hook_policy_dry_run_plan_missing/);
  assert.match(workflowValidation, /hook_policy_routes_missing/);
  assert.match(workflowRuntimeUiStrings, /ioi\.workflow\.runtime-ui-string-catalog\.v1/);
  assert.match(workflowRuntimeUiStrings, /workflow_chrome/);
  assert.match(workflowRuntimeUiStrings, /supportedLocales: \["en-US", "es-ES"\]/);
  assert.match(workflowRuntimeUiStrings, /modelOutputLocalized: false/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_task\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_job\.aria/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_checklist\.status/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_thread_fork\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_operator_interrupt\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_operator_steer\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.runtime_context_compact\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.workflow_package_export\.label/);
  assert.match(workflowRuntimeUiStrings, /runtime\.node\.workflow_package_import\.status/);
  assert.match(workflowRuntimeUiStrings, /runtime\.status\.blocked/);
  assert.match(workflowRuntimeUiStrings, /WORKFLOW_RUNTIME_ACCESSIBLE_STATUS_TEXT/);
  assert.match(workflowHarnessTools, /workflow\.package\.export/);
  assert.match(workflowHarnessTools, /workflow\.package\.import/);
  assert.match(workflowHarnessTools, /workflowChromeLocale/);
  assert.match(workflowHarnessTools, /packageEvidenceReady/);
  assert.match(runtimeProjectionAdapter, /case "workflow_package_export"/);
  assert.match(runtimeProjectionAdapter, /return "workflow_package_export"/);
  assert.match(runtimeProjectionAdapter, /case "runtime_thread_fork"/);
  assert.match(runtimeProjectionAdapter, /return "runtime_thread_fork"/);
  assert.match(runtimeProjectionAdapter, /case "runtime_operator_interrupt"/);
  assert.match(runtimeProjectionAdapter, /return "runtime_operator_interrupt"/);
  assert.match(runtimeProjectionAdapter, /case "runtime_operator_steer"/);
  assert.match(runtimeProjectionAdapter, /return "runtime_operator_steer"/);
  assert.match(runtimeProjectionAdapter, /case "runtime_context_compact"/);
  assert.match(runtimeProjectionAdapter, /return "runtime_context_compact"/);
  assert.match(runtimeProjectionAdapter, /case "workflow_package_import"/);
  assert.match(runtimeProjectionAdapter, /return "workflow_package_import"/);
  assert.match(runtimeActionSchema, /"skill_context"/);
  assert.match(runtimeActionSchema, /"workflow_package_export"/);
  assert.match(runtimeActionSchema, /"workflow_package_import"/);
  assert.match(runtimeActionSchema, /"runtime_operator_steer"/);
  assert.match(runtimeActionSchema, /"runtime_context_compact"/);
  assert.match(generatedActionSchema, /"skill_context"/);
  assert.match(generatedActionSchema, /"workflow_package_export"/);
  assert.match(generatedActionSchema, /"workflow_package_import"/);
  assert.match(generatedActionSchema, /"runtime_operator_steer"/);
  assert.match(generatedActionSchema, /"runtime_context_compact"/);
  assert.match(generatedRustActionSchema, /"skill_context"/);
  assert.match(generatedRustActionSchema, /"workflow_package_export"/);
  assert.match(generatedRustActionSchema, /"workflow_package_import"/);
  assert.match(generatedRustActionSchema, /"runtime_operator_steer"/);
  assert.match(generatedRustActionSchema, /"runtime_context_compact"/);
});

test("local daemon hosted and self-hosted modes fail closed without provider endpoints", async () => {
  const { Agent, createRuntimeSubstrateClient, IoiAgentError } = await importSdk();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-live-daemon-blocker-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-agentgres-blocker-"));
  const savedHosted = process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
  const savedSelfHosted = process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
  delete process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
  delete process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
  const daemon = await startRuntimeDaemonService({ cwd, stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });
    await assert.rejects(
      Agent.create({
        local: { cwd },
        hosted: {
          repos: [{ url: "https://example.invalid/ioi.git" }],
          provider: { providerId: "missing-hosted-provider" },
        },
        substrateClient: client,
      }),
      (error) =>
        error instanceof IoiAgentError &&
        error.code === "external_blocker" &&
        error.status === 424,
    );
  } finally {
    await daemon.close();
    if (savedHosted === undefined) delete process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT;
    else process.env.IOI_AGENT_SDK_HOSTED_ENDPOINT = savedHosted;
    if (savedSelfHosted === undefined) delete process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT;
    else process.env.IOI_AGENT_SDK_SELF_HOSTED_ENDPOINT = savedSelfHosted;
  }
});
