import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import {
  Agent,
  Cursor,
  IoiAgentError,
  createRuntimeSubstrateClient,
} from "../dist/index.js";

function tempClient() {
  const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-agent-sdk-"));
  return {
    cwd,
    client: createRuntimeSubstrateClient({
      cwd,
      checkpointDir: path.join(cwd, ".ioi", "agent-sdk"),
    }),
  };
}

test("local quickstart streams, waits, inspects, scores, and exports trace", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({
    model: { id: "local:auto" },
    local: { cwd },
    substrateClient: client,
  });
  const run = await agent.send("Summarize this repository");
  const events = [];
  for await (const event of run.stream()) {
    events.push(event);
  }
  assert.equal(events.at(-1)?.type, "completed");
  assert.equal(events.filter((event) => event.type === "completed").length, 1);
  const result = await run.wait();
  assert.equal(result.stopCondition.reason, "evidence_sufficient");
  const trace = await run.inspect();
  assert.equal(trace.events.length, events.length);
  assert.equal(trace.taskState.currentObjective, "Summarize this repository");
  assert.ok(trace.probes.length > 0);
  assert.equal((await run.scorecard()).verifierIndependence, 1);
  assert.ok((await run.artifacts()).some((artifact) => artifact.name === "trace.json"));
});

test("stream reconnect starts after the supplied cursor without duplicating terminal events", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({ local: { cwd }, substrateClient: client });
  const run = await agent.send("Reconnect test");
  const firstBatch = [];
  for await (const event of run.stream()) {
    firstBatch.push(event);
    if (firstBatch.length === 4) break;
  }
  const secondBatch = [];
  for await (const event of run.stream({ lastEventId: firstBatch.at(-1).id })) {
    secondBatch.push(event);
  }
  assert.equal(secondBatch[0].type, "postcondition_synthesized");
  assert.equal(secondBatch.filter((event) => event.type === "completed").length, 1);
});

test("per-send onStep and onDelta callbacks receive substrate event projections", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({ local: { cwd }, substrateClient: client });
  const steps = [];
  const deltas = [];
  await agent.send("Callback test", {
    onStep: (event) => steps.push(event.type),
    onDelta: (delta) => deltas.push(delta),
  });
  assert.ok(steps.includes("task_state"));
  assert.ok(steps.includes("completed"));
  assert.equal(deltas.length, 1);
  assert.match(deltas[0], /IOI SDK local run completed/);
});

test("plan dry-run handoff and learn expose smarter-agent records", async () => {
  const { cwd, client } = tempClient();
  const agent = await Agent.create({ local: { cwd }, substrateClient: client });
  const plan = await agent.plan("Plan StopCondition support", { noMutation: true });
  assert.equal((await plan.inspect()).qualityLedger.selectedStrategy, "plan_only_with_postconditions");
  const preview = await agent.dryRun("Preview filesystem delete", { toolClass: "filesystem" });
  assert.equal((await preview.inspect()).uncertainty.selectedAction, "dry_run");
  const handoff = await agent.handoff("Delegate investigation", { receiver: "worker" });
  assert.ok((await handoff.inspect()).qualityLedger.toolSequence.includes("handoff_quality"));
  const learned = await agent.learn({ taskFamily: "sdk_parity", positive: ["traceable SDK run"] });
  assert.ok((await learned.inspect()).qualityLedger.toolSequence.includes("memory_quality_gate"));
});

test("cloud and self-hosted modes fail closed without configured providers", async () => {
  const { cwd, client } = tempClient();
  await assert.rejects(
    Agent.create({
      cloud: { repos: [{ url: "https://example.invalid/repo.git" }] },
      local: { cwd },
      substrateClient: client,
    }),
    (error) => error instanceof IoiAgentError && error.code === "external_blocker",
  );
});

test("Cursor facade exposes operator, model, and repository catalogs", async () => {
  const { cwd, client } = tempClient();
  const models = await Cursor.models.list({ local: { cwd }, substrateClient: client });
  assert.ok(models.some((model) => model.id === "local:auto"));
  const repositories = await Cursor.repositories.list({ local: { cwd }, substrateClient: client });
  assert.equal(repositories[0].url, cwd);
  assert.equal((await Cursor.me()).source, "ioi-agent-sdk");
});
