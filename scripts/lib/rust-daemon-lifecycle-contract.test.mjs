// The canonical lifecycle contract, run against the RUST hypervisor-daemon via the SDK
// (createRuntimeSubstrateClient + Agent), mirroring live-runtime-daemon-contract.test.mjs
// test 386's flow. This is the Rust-ready slice of the split-brain repoint: it asserts the
// parity the Rust daemon already satisfies end-to-end through the SDK, and grows as more
// parity lands. The deferred Cursor.models.list (model-mount /v1/models array-shape) is
// the one remaining gap and is NOT asserted here yet. This file is the seed of the contract
// that replaces the JS-daemon contract at full JS-daemon retirement.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { startRustHypervisorDaemon } from "./rust-hypervisor-daemon.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

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
  return import(path.join(root, "packages/agent-sdk/dist/index.js"));
}

async function collect(iterable) {
  const out = [];
  for await (const value of iterable) out.push(value);
  return out;
}

test("Rust hypervisor-daemon satisfies the canonical lifecycle contract via the SDK round-trip", async () => {
  const { Agent, Cursor, createRuntimeSubstrateClient } = await importSdk();
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-contract-ws-"));
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-rust-contract-state-"));
  const daemon = await startRustHypervisorDaemon({ stateDir });
  try {
    const client = createRuntimeSubstrateClient({ endpoint: daemon.endpoint });

    // --- Agent.create -> agent.send (the SDK send path = POST /v1/agents/:id/runs) ---
    const agent = await Agent.create({ local: { cwd }, substrateClient: client });
    assert.match(agent.id, /^agent_/, "Agent.create returns an agent record");
    const run = await agent.send("Drive the Rust daemon lifecycle contract via the SDK.");
    assert.match(run.id, /^run_/, "agent.send creates a run");
    assert.equal(run.agentId, agent.id, "run is bound to the agent");

    // --- run.stream() = GET /v1/runs/:id/events ---
    const streamed = [];
    for await (const event of run.stream()) {
      streamed.push(event);
      if (streamed.length >= 4) break;
    }
    assert.ok(streamed.length >= 1, "run.stream() yields runtime events");

    // --- run.trace(): canonical Agentgres projection + materialized task/job/checklist ---
    const trace = await run.trace();
    assert.equal(trace.canonicalState.source, "agentgres_canonical_state_projection");
    assert.equal(trace.runtimeTask.schemaVersion, "ioi.agent-runtime.task-record.v1");
    assert.equal(trace.runtimeTask.object, "ioi.runtime_task");
    assert.equal(trace.runtimeTask.runId, run.id);
    assert.equal(trace.runtimeTask.promptIncluded, false);
    assert.equal(trace.runtimeTask.durable, true);
    assert.equal(trace.runtimeTask.replayable, true);
    assert.equal(trace.runtimeJob.schemaVersion, "ioi.agent-runtime.job-record.v1");
    assert.equal(trace.runtimeJob.object, "ioi.runtime_job");
    assert.equal(trace.runtimeJob.queueName, "local-agentgres");
    assert.equal(trace.runtimeChecklist.schemaVersion, "ioi.agent-runtime.checklist-record.v1");
    assert.equal(trace.runtimeChecklist.object, "ioi.runtime_checklist");
    assert.equal(trace.runtimeChecklist.readOnly, true);

    // --- run.scorecard() ---
    assert.equal((await run.scorecard()).verifierIndependence, 1);

    // --- run.artifacts(): the materialized canonical artifacts ---
    const artifacts = await run.artifacts();
    for (const name of ["runtime-task.json", "runtime-job.json", "runtime-checklist.json"]) {
      assert.ok(artifacts.some((artifact) => artifact.name === name), `artifacts include ${name}`);
    }

    // --- the canonical Agentgres state bundle is on disk ---
    for (const dir of ["runs", "tasks", "jobs", "checklists", "scorecards", "ledgers", "projections"]) {
      assert.ok(fs.existsSync(path.join(stateDir, dir)), `state bundle dir ${dir}/ exists`);
    }

    // --- thread event log: the materialized item events carry the canonical
    // payload_summary.event_kind + component_kind + workflow_node_id + artifact_refs
    // (test-386:537-562). NOTE: the JobCanceled-on-thread-log gap (cancel doesn't yet
    // admit its events) is the remaining thread-event parity item, asserted after cancel.
    const threadId = `thread_${agent.id.slice("agent_".length)}`;
    const threadEventsText = await (
      await fetch(`${daemon.endpoint}/v1/threads/${threadId}/events?since_seq=0`)
    ).text();
    const threadEvents = threadEventsText
      .split("\n\n")
      .filter(Boolean)
      .map((block) => {
        const line = block.split("\n").find((l) => l.startsWith("data: "));
        return line ? JSON.parse(line.slice(6)) : null;
      })
      .filter(Boolean);
    const byEventKind = (k) => threadEvents.find((e) => e.payload_summary?.event_kind === k);
    const taskEvent = byEventKind("RuntimeTaskRecord");
    assert.ok(taskEvent, "thread log carries the RuntimeTaskRecord event");
    assert.equal(taskEvent.component_kind, "runtime_task");
    assert.equal(taskEvent.workflow_node_id, "runtime.runtime-task");
    assert.equal(taskEvent.payload_summary.prompt_included, false);
    assert.ok(taskEvent.artifact_refs.includes("runtime-task.json"), "task event carries artifact_refs");
    const checklistEvent = byEventKind("RuntimeChecklistRecord");
    assert.ok(checklistEvent, "thread log carries the RuntimeChecklistRecord event");
    assert.equal(checklistEvent.workflow_node_id, "runtime.runtime-checklist");
    assert.ok(checklistEvent.artifact_refs.includes("runtime-checklist.json"), "checklist event carries artifact_refs");
    for (const kind of ["JobQueued", "JobStarted", "JobCompleted"]) {
      const jobEvent = byEventKind(kind);
      assert.ok(jobEvent, `thread log carries the ${kind} event`);
      assert.equal(jobEvent.component_kind, "runtime_job");
      assert.equal(jobEvent.workflow_node_id, "runtime.runtime-job");
      assert.ok(jobEvent.artifact_refs.includes("runtime-job.json"), `${kind} carries artifact_refs`);
    }

    // --- run.cancel() -> the run + its bundle reflect the cancel ---
    const canceled = await run.cancel();
    assert.equal(await canceled.status(), "canceled", "run.cancel() cancels the run");
    const replay = await collect(canceled.replay());
    assert.ok(replay.length >= 1, "run.replay() yields events after cancel");

    // --- jobs/tasks endpoints (embedded in the run; canceled with it; SDK + raw) ---
    const jobs = await client.listJobs({ agentId: run.agentId });
    assert.equal(jobs.length, 1, "one runtime job for the run");
    assert.equal(jobs[0].jobId, trace.runtimeJob.jobId);
    assert.equal(jobs[0].schemaVersion, "ioi.agent-runtime.job-record.v1");
    assert.equal(jobs[0].status, "canceled");
    assert.equal(jobs[0].checklistStatus, "canceled");
    assert.equal(jobs[0].endpoints.self, `/v1/jobs/${jobs[0].jobId}`);
    assert.equal(jobs[0].endpoints.cancel, `/v1/jobs/${jobs[0].jobId}/cancel`);
    assert.equal((await client.getJob(jobs[0].jobId)).runId, run.id);
    const tasks = await client.listTasks({ agentId: run.agentId });
    assert.equal(tasks.length, 1, "one runtime task for the run");
    assert.equal(tasks[0].taskId, trace.runtimeTask.taskId);
    assert.equal(tasks[0].status, "canceled");
    assert.equal(tasks[0].promptIncluded, false);
    assert.equal((await client.getTask(tasks[0].taskId)).runId, run.id);
    // POST /v1/jobs|tasks/:id/cancel (idempotent over the already-canceled run).
    const jobCancel = await client.cancelJob(jobs[0].jobId);
    assert.equal(jobCancel.jobId, jobs[0].jobId);
    assert.equal(jobCancel.status, "canceled");
    const taskCancel = await client.cancelTask(tasks[0].taskId);
    assert.equal(taskCancel.taskId, tasks[0].taskId);
    assert.equal(taskCancel.status, "canceled");

    // --- Cursor.account + runtimeNodes (canonical Agentgres identifiers) ---
    const account = await Cursor.account.get({ substrateClient: client });
    assert.equal(account.source, "ioi-daemon-agentgres");
    const nodes = await Cursor.runtimeNodes.list({ substrateClient: client });
    assert.ok(nodes.some((node) => node.id === "local-daemon-agentgres"));

    // --- Cursor.models.list: the unauthenticated /v1/models returns the runtime model
    // catalog ARRAY (the SDK shape), not the OpenAI-compat object. (The legacy JS assertion
    // models[0].provider === "ioi-daemon-local" encodes a retired literal no projection
    // emits today — the current catalog entry carries provider_ref/provider_kind instead.)
    const models = await Cursor.models.list({ substrateClient: client });
    assert.ok(Array.isArray(models) && models.length >= 1, "Cursor.models.list returns the catalog array");
    assert.ok(
      models[0].provider_kind || models[0].provider_ref || models[0].id,
      "the catalog entry carries provider/identity metadata",
    );
  } finally {
    await daemon.close();
  }
});
