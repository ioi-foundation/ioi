import assert from "node:assert/strict";
import test from "node:test";
import type { WorkflowProject } from "../types/graph";
import { workflowEntrypointsModel } from "./workflow-entrypoints-model";

function workflow(nodes: unknown[]): WorkflowProject {
  return {
    version: "1",
    nodes,
    edges: [],
    global_config: {
      env: "test",
      modelBindings: {},
      requiredCapabilities: {},
      policy: {
        maxBudget: 1,
        maxSteps: 4,
        timeoutMs: 1_000,
      },
      contract: {
        developerBond: 1,
        adjudicationRubric: "test",
      },
      meta: {
        name: "Entrypoints workflow",
        description: "Entrypoints workflow",
      },
    },
    metadata: {
      id: "workflow",
      name: "Workflow",
      slug: "workflow",
      workflowKind: "agent_workflow",
      executionMode: "mock",
    },
  } as unknown as WorkflowProject;
}

test("workflow entrypoints model summarizes source and trigger readiness", () => {
  const model = workflowEntrypointsModel(
    workflow([
      {
        id: "source-ready",
        type: "source",
        name: "Ready source",
        x: 0,
        y: 0,
        config: {
          logic: {
            payload: "hello",
          },
        },
      },
      {
        id: "source-blocked",
        type: "source",
        name: "Blocked source",
        x: 0,
        y: 0,
      },
      {
        id: "manual-trigger",
        type: "trigger",
        name: "Manual trigger",
        x: 0,
        y: 0,
        config: {
          logic: {
            triggerKind: "manual",
          },
        },
      },
    ]),
  );

  assert.equal(model.totalStartPoints, 3);
  assert.equal(model.readyStartPoints, 2);
  assert.equal(model.blockedStartPoints, 1);
  assert.deepEqual(
    model.sourceRows.map((row) => [row.node.id, row.status, row.detail, row.ready]),
    [
      ["source-ready", "payload ready", "hello", true],
      ["source-blocked", "needs payload", "No payload configured", false],
      ["manual-trigger", "manual", "manual", true],
    ],
  );
});

test("workflow entrypoints model reports scheduled and event trigger readiness", () => {
  const model = workflowEntrypointsModel(
    workflow([
      {
        id: "cron-ready",
        type: "trigger",
        name: "Cron trigger",
        x: 0,
        y: 0,
        config: {
          logic: {
            triggerKind: "scheduled",
            cronSchedule: "0 9 * * 1",
          },
        },
      },
      {
        id: "cron-blocked",
        type: "trigger",
        name: "Missing cron",
        x: 0,
        y: 0,
        config: {
          logic: {
            triggerKind: "scheduled",
          },
        },
      },
      {
        id: "event-ready",
        type: "trigger",
        name: "Event trigger",
        x: 0,
        y: 0,
        config: {
          logic: {
            triggerKind: "event",
            eventSourceRef: "github.issue.opened",
          },
        },
      },
      {
        id: "event-blocked",
        type: "trigger",
        name: "Missing event",
        x: 0,
        y: 0,
        config: {
          logic: {
            triggerKind: "event",
          },
        },
      },
    ]),
  );

  assert.equal(model.totalTriggers, 4);
  assert.equal(model.readyTriggers, 2);
  assert.equal(model.blockedTriggers, 2);
  assert.deepEqual(
    model.triggerRows.map((row) => [
      row.node.id,
      row.triggerKind,
      row.status,
      row.detail,
    ]),
    [
      ["cron-ready", "scheduled", "ready", "0 9 * * 1"],
      ["cron-blocked", "scheduled", "blocked", "No schedule"],
      ["event-ready", "event", "ready", "github.issue.opened"],
      ["event-blocked", "event", "blocked", "No event source"],
    ],
  );
  assert.deepEqual(
    model.sourceRows.map((row) => [row.node.id, row.status]),
    [
      ["cron-ready", "scheduled"],
      ["cron-blocked", "needs schedule"],
      ["event-ready", "event"],
      ["event-blocked", "needs event source"],
    ],
  );
});

test("workflow entrypoints model ignores non-entrypoint nodes", () => {
  const model = workflowEntrypointsModel(
    workflow([
      {
        id: "model",
        type: "model_call",
        name: "Model",
        x: 0,
        y: 0,
      },
      {
        id: "output",
        type: "output",
        name: "Output",
        x: 0,
        y: 0,
      },
    ]),
  );

  assert.equal(model.totalStartPoints, 0);
  assert.equal(model.totalTriggers, 0);
  assert.deepEqual(model.sourceRows, []);
  assert.deepEqual(model.triggerRows, []);
});
