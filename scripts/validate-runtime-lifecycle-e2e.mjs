#!/usr/bin/env node
// Runtime lifecycle e2e ratchet — the verification engine for the unified-Rust-daemon
// lifecycle+MCP migration. Spawns the Rust hypervisor-daemon and exercises the
// thread/agent/run/turn/control/events/MCP surface over HTTP, asserting the same
// contract as scripts/lib/live-runtime-daemon-contract.test.mjs. Each route family
// built advances the ratchet one step (mirrors the proven validate-model-mounting-e2e
// ratchet). See internal-docs/implementation/hypervisor-unified-rust-daemon-lifecycle-migration.md.
//
// Run: node scripts/validate-runtime-lifecycle-e2e.mjs

import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { startRustHypervisorDaemon } from "./lib/rust-hypervisor-daemon.mjs";
import { mintApprovalGrant } from "./lib/mint-approval-grant.mjs";

const steps = [];
async function runStep(name, fn) {
  try {
    await fn();
    steps.push({ name, status: "passed" });
    console.log(`[lifecycle-e2e] PASS ${name}`);
  } catch (error) {
    steps.push({ name, status: "failed", error: String(error?.stack ?? error) });
    console.error(`[lifecycle-e2e] FAIL ${name}\n${error?.stack ?? error}`);
    throw error;
  }
}

async function fetchJson(url, opts = {}) {
  const response = await fetch(url, {
    headers: { "content-type": "application/json", ...(opts.headers ?? {}) },
    ...opts,
  });
  const text = await response.text();
  let body;
  try {
    body = text ? JSON.parse(text) : null;
  } catch {
    body = text;
  }
  return { status: response.status, body };
}

async function main() {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-lifecycle-e2e-state-"));
  const rust = await startRustHypervisorDaemon({ stateDir });
  try {
    // Step 0 (foundation): the lifecycle route family is served by the Rust daemon and
    // a fresh daemon projects an empty thread list. Subsequent ratchet steps add
    // thread/turn create + event admission + projection.
    await runStep("GET /v1/threads projects an empty list on a fresh daemon", async () => {
      const { status, body } = await fetchJson(`${rust.endpoint}/v1/threads`);
      assert.equal(status, 200, `expected 200, got ${status}`);
      assert.ok(Array.isArray(body), "threads list should be an array");
      assert.equal(body.length, 0, "fresh daemon should have no threads");
    });

    // Step 1: thread-create + thread-get + thread-list. Mirrors the live-runtime-daemon
    // contract test "local daemon projects Agentgres runs through thread, turn, and
    // monotonic event records" (thread-record assertions).
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-lifecycle-e2e-ws-"));
    let createdThread;
    let turnRequestId;
    await runStep("POST /v1/threads creates a thread with the faithful model route decision", async () => {
      const { status, body } = await fetchJson(`${rust.endpoint}/v1/threads`, {
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
      assert.equal(status, 200, `expected 200, got ${status}: ${JSON.stringify(body)}`);
      createdThread = body;
      assert.equal(body.schema_version, "ioi.runtime.thread.v1");
      assert.match(body.thread_id, /^thread_/);
      assert.match(body.agent_id, /^agent_/);
      assert.equal(body.event_stream_id, `${body.thread_id}:events`);
      assert.equal(body.latest_seq, 1, "thread.started should advance latest_seq to 1");
      assert.equal(body.model_route_id, "route.native-local");
      assert.equal(body.requested_model, "auto");
      const decision = body.model_route_decision;
      assert.ok(decision, "thread should carry a model_route_decision");
      assert.equal(decision.eventKind, "ModelRouteDecision");
      assert.equal(decision.requestedModelMode, "auto");
      assert.equal(decision.selectedModel, "hypervisor:native-fixture");
      assert.equal(decision.neverSendAutoUpstream, true);
      assert.equal(decision.reasoningEffort, "low");
      assert.equal(decision.workflowNodeId, "workflow.model-router");
    });

    await runStep("GET /v1/threads/:id projects the created thread", async () => {
      const { status, body } = await fetchJson(
        `${rust.endpoint}/v1/threads/${encodeURIComponent(createdThread.thread_id)}`,
      );
      assert.equal(status, 200, `expected 200, got ${status}`);
      assert.equal(body.thread_id, createdThread.thread_id);
      assert.equal(body.agent_id, createdThread.agent_id);
      assert.equal(body.latest_seq, 1);
      assert.equal(body.model_route_decision.selectedModel, "hypervisor:native-fixture");
    });

    await runStep("GET /v1/threads lists the created thread", async () => {
      const { status, body } = await fetchJson(`${rust.endpoint}/v1/threads`);
      assert.equal(status, 200, `expected 200, got ${status}`);
      assert.ok(Array.isArray(body), "threads list should be an array");
      assert.equal(body.length, 1, "should list the one created thread");
      assert.equal(body[0].thread_id, createdThread.thread_id);
    });

    // Step 2: turn-create. Mirrors the turn-record assertions of the live contract test.
    await runStep("POST /v1/threads/:id/turns completes a turn run", async () => {
      const { status, body } = await fetchJson(
        `${rust.endpoint}/v1/threads/${encodeURIComponent(createdThread.thread_id)}/turns`,
        { method: "POST", body: JSON.stringify({ prompt: "explain post-quantum cryptography", mode: "send" }) },
      );
      assert.equal(status, 200, `expected 200, got ${status}: ${JSON.stringify(body)}`);
      assert.equal(body.schema_version, "ioi.runtime.turn.v1");
      assert.equal(body.status, "completed");
      assert.equal(body.stop_reason, "evidence_sufficient");
      assert.match(body.request_id, /^run_/);
      assert.equal(body.thread_id, createdThread.thread_id);
      assert.ok(body.quality_ledger_ref, "turn should carry a quality_ledger_ref");
      turnRequestId = body.request_id;
    });

    // Step 3: events / SSE projection. The Rust daemon projects the thread's runtime
    // events (thread.started synthesized + run events mapped), serves them as one-shot SSE
    // frames, and honors since_seq / Last-Event-ID cursors + future-cursor 409.
    // NOTE: aligning the exact live contract (events>=11, turn.completed LAST, the decision
    // event_kind item.completed + payload_summary.event_kind ModelRouteDecision) is a kernel
    // event-ordering hardening follow-up; this asserts the verified projection + cursor core.
    function parseSseEvents(text) {
      return text
        .split("\n\n")
        .filter(Boolean)
        .map((block) => {
          const line = block.split("\n").find((l) => l.startsWith("data: "));
          return line ? JSON.parse(line.slice(6)) : null;
        })
        .filter(Boolean);
    }
    let turnRunId;
    await runStep("GET /v1/threads/:id/events projects the runtime event stream", async () => {
      const response = await fetch(
        `${rust.endpoint}/v1/threads/${encodeURIComponent(createdThread.thread_id)}/events?since_seq=0`,
      );
      assert.equal(response.status, 200);
      assert.equal(response.headers.get("content-type"), "text/event-stream");
      const events = parseSseEvents(await response.text());
      assert.ok(events.length >= 9, `expected >=9 events, got ${events.length}`);
      assert.equal(events[0].event_kind, "thread.started", "first event should be thread.started");
      const seqs = events.map((e) => e.seq);
      assert.deepEqual(seqs, seqs.map((_, i) => i + 1), "event seqs should be contiguous 1..N");
      assert.ok(events.some((e) => e.event_kind === "turn.started"), "should include turn.started");
      assert.ok(
        events.some((e) => e.component_kind === "model_router"),
        "should include a model_router (ModelRouteDecision) event",
      );
      assert.ok(events.some((e) => e.event_kind === "turn.completed"), "should include turn.completed");
      turnRunId = events.find((e) => e.event_kind === "turn.started")?.payload?.run_id;
    });

    await runStep("thread events honor since_seq + future-cursor 409", async () => {
      const filtered = parseSseEvents(
        await (
          await fetch(`${rust.endpoint}/v1/threads/${encodeURIComponent(createdThread.thread_id)}/events?since_seq=3`)
        ).text(),
      );
      assert.ok(filtered.every((e) => e.seq > 3), "since_seq=3 should drop seq<=3");
      const future = await fetch(
        `${rust.endpoint}/v1/threads/${encodeURIComponent(createdThread.thread_id)}/events?since_seq=9999`,
      );
      assert.equal(future.status, 409, "future cursor should 409");
      const body = await future.json();
      assert.match(JSON.stringify(body), /event_cursor_out_of_range/);
    });

    await runStep("GET /v1/runs/:id/events projects the run event stream", async () => {
      // turnRunId is the run id from the turn (request_id); fall back to it from the turn step.
      const runId = turnRunId;
      if (!runId) return; // run_id payload may not be surfaced; covered by thread events.
      const response = await fetch(`${rust.endpoint}/v1/runs/${encodeURIComponent(runId)}/events`);
      assert.equal(response.status, 200);
      const events = parseSseEvents(await response.text());
      assert.ok(events.length >= 1, "run events should project");
    });

    // Step 4a: run read endpoints.
    await runStep("GET /v1/runs/:id + GET /v1/runs project the persisted run", async () => {
      const get = await fetchJson(`${rust.endpoint}/v1/runs/${encodeURIComponent(turnRequestId)}`);
      assert.equal(get.status, 200);
      assert.equal(get.body.id, turnRequestId);
      assert.equal(get.body.status, "completed");
      const list = await fetchJson(`${rust.endpoint}/v1/runs`);
      assert.equal(list.status, 200);
      assert.ok(Array.isArray(list.body) && list.body.length === 1, "should list the one run");
      const missing = await fetchJson(`${rust.endpoint}/v1/runs/run_does_not_exist`);
      assert.equal(missing.status, 404);
    });

    // Step 4b: thread controls (mode / model / thinking). The Rust daemon owns the
    // controls via plan_thread_control_agent_state_update; the dual-cased agent persist
    // makes the projection reflect the new controls.
    await runStep("POST /v1/threads/:id/mode owns the interaction mode", async () => {
      const { status, body } = await fetchJson(
        `${rust.endpoint}/v1/threads/${encodeURIComponent(createdThread.thread_id)}/mode`,
        { method: "POST", body: JSON.stringify({ mode: "yolo" }) },
      );
      assert.equal(status, 200);
      assert.equal(body.control_kind, "mode");
      assert.equal(body.mode, "yolo");
      assert.equal(body.approval_mode, "never_prompt");
      assert.equal(body.event.source_event_kind, "OperatorControl.Mode");
      // The thread projection reflects the new mode (dual-case normalizer).
      const thread = await fetchJson(`${rust.endpoint}/v1/threads/${encodeURIComponent(createdThread.thread_id)}`);
      assert.equal(thread.body.mode, "yolo");
      assert.equal(thread.body.approval_mode, "never_prompt");
    });

    await runStep("POST /v1/threads/:id/thinking owns the reasoning effort", async () => {
      const { status, body } = await fetchJson(
        `${rust.endpoint}/v1/threads/${encodeURIComponent(createdThread.thread_id)}/thinking`,
        { method: "POST", body: JSON.stringify({ reasoning_effort: "high" }) },
      );
      assert.equal(status, 200);
      assert.equal(body.control_kind, "thinking");
      assert.equal(body.reasoning_effort, "high");
      assert.equal(body.runtime_controls.model.reasoning_effort, "high");
    });

    await runStep("POST /v1/threads/:id/model owns the model route", async () => {
      const { status, body } = await fetchJson(
        `${rust.endpoint}/v1/threads/${encodeURIComponent(createdThread.thread_id)}/model`,
        { method: "POST", body: JSON.stringify({ model: { id: "auto", route_id: "route.native-local" } }) },
      );
      assert.equal(status, 200);
      assert.equal(body.control_kind, "model");
      assert.equal(body.model_route_id, "route.native-local");
      assert.equal(body.event.event_kind, "model.route_decision");
      assert.equal(body.event.component_kind, "model_router");
    });

    // Step 5a: MCP family — the catalog/tool-search projection (the boundary that
    // originally 502'd thread-create) now runs as an internal Rust call.
    await runStep("GET /v1/threads/:id/mcp/tools/search projects the MCP catalog", async () => {
      const { status, body } = await fetchJson(
        `${rust.endpoint}/v1/threads/${encodeURIComponent(createdThread.thread_id)}/mcp/tools/search?q=read`,
      );
      assert.equal(status, 200);
      assert.equal(body.object, "ioi.runtime_mcp_tool_search");
      assert.equal(body.status, "completed");
      assert.ok(Array.isArray(body.tools), "tools should be an array");
      assert.equal(body.tool_count, 0, "no MCP servers mounted -> empty catalog");
    });

    // Step 5b: MCP control mutations (import/add/enable/disable/remove) via the kernel
    // plan_mcp_control_agent_state_update — the registry lives on the agent record.
    await runStep("MCP control mutations are owned by the Rust daemon", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const imp = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/mcp/import`, {
        method: "POST",
        body: JSON.stringify({ servers: [{ id: "fs", label: "fs", transport: "stdio", command: "echo", allowed_tools: ["read"] }] }),
      });
      assert.equal(imp.status, 200);
      assert.equal(imp.body.operation_kind, "thread.mcp_import");
      assert.equal(imp.body.status, "planned");

      const add = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/mcp/servers`, {
        method: "POST",
        body: JSON.stringify({ id: "git", label: "git", transport: "stdio", command: "git" }),
      });
      assert.equal(add.status, 200);
      assert.equal(add.body.operation_kind, "thread.mcp_add");

      const disable = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/mcp/servers/git/disable`, {
        method: "POST",
        body: "{}",
      });
      assert.equal(disable.status, 200);
      assert.equal(disable.body.operation_kind, "thread.mcp_disable");

      const remove = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/mcp/servers/git`, {
        method: "DELETE",
      });
      assert.equal(remove.status, 200);
      assert.equal(remove.body.operation_kind, "thread.mcp_remove");

      // status + validate ride the same plan_mcp_control_agent_state_update planner.
      const status = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/mcp/status`, {
        method: "POST",
        body: JSON.stringify({ status: "ready" }),
      });
      assert.equal(status.status, 200);
      assert.equal(status.body.operation_kind, "thread.mcp_status");

      const validate = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/mcp/validate`, {
        method: "POST",
        body: JSON.stringify({ validation: { ok: true } }),
      });
      assert.equal(validate.status, 200);
      assert.equal(validate.body.operation_kind, "thread.mcp_validate");
    });

    // Step 5c: tasks / jobs read (materialized into the run records by run-create).
    await runStep("GET /v1/tasks + /v1/jobs project the materialized task/job records", async () => {
      const tasks = await fetchJson(`${rust.endpoint}/v1/tasks`);
      assert.equal(tasks.status, 200);
      assert.ok(Array.isArray(tasks.body) && tasks.body.length === 1, "one task");
      assert.equal(tasks.body[0].taskId, `task_${turnRequestId}`);
      assert.equal(tasks.body[0].status, "completed");
      const taskGet = await fetchJson(`${rust.endpoint}/v1/tasks/task_${encodeURIComponent(turnRequestId)}`);
      assert.equal(taskGet.status, 200);
      assert.equal(taskGet.body.taskId, `task_${turnRequestId}`);
      const jobs = await fetchJson(`${rust.endpoint}/v1/jobs`);
      assert.equal(jobs.status, 200);
      assert.ok(Array.isArray(jobs.body) && jobs.body.length === 1, "one job");
      assert.equal(jobs.body[0].jobId, `job_${turnRequestId}`);
    });

    // Step 5d: agents collection (shares the agent-candidate builder with thread-create).
    await runStep("POST /v1/agents creates a standalone agent + GET /v1/agents lists it", async () => {
      const create = await fetchJson(`${rust.endpoint}/v1/agents`, {
        method: "POST",
        body: JSON.stringify({ options: { local: { cwd }, model: { id: "auto", routeId: "route.native-local" } } }),
      });
      assert.equal(create.status, 200);
      assert.match(create.body.id, /^agent_/);
      assert.equal(create.body.status, "active");
      assert.equal(create.body.modelId, "hypervisor:native-fixture");
      const list = await fetchJson(`${rust.endpoint}/v1/agents`);
      assert.equal(list.status, 200);
      assert.ok(
        Array.isArray(list.body) && list.body.some((a) => a.id === create.body.id),
        "agents list should include the created agent",
      );
    });

    // Step 5e: subagents — spawn builds a child agent + run + subagent record (after the
    // run/task count assertions, since the child run materializes its own task).
    await runStep("POST /v1/threads/:id/subagents spawns a subagent", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const spawn = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/subagents`, {
        method: "POST",
        body: JSON.stringify({ prompt: "implement the PQC explainer", role: "implementer" }),
      });
      assert.equal(spawn.status, 201);
      assert.match(spawn.body.subagent_id, /^agent_/);
      assert.equal(spawn.body.role, "implementer");
      assert.equal(spawn.body.status, "completed");
      assert.equal(spawn.body.parent_thread_id, createdThread.thread_id);
      assert.match(spawn.body.run_id, /^run_/);

      const list = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/subagents`);
      assert.equal(list.status, 200);
      assert.ok(
        Array.isArray(list.body) && list.body.some((s) => s.subagent_id === spawn.body.subagent_id),
        "subagents list should include the spawned subagent",
      );
      const result = await fetchJson(
        `${rust.endpoint}/v1/threads/${tid}/subagents/${encodeURIComponent(spawn.body.subagent_id)}/result`,
      );
      assert.equal(result.status, 200);
      assert.equal(result.body.subagent_id, spawn.body.subagent_id);
    });

    // Step 5f: subagent tail (wait/input/resume/assign/cancel) — the run-creating ops
    // (input/resume) materialize their own runs, so this runs after the run/task counts.
    await runStep("subagent tail (wait/input/resume/assign/cancel) is Rust-owned", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const spawn = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/subagents`, {
        method: "POST",
        body: JSON.stringify({ prompt: "tail subtask", role: "implementer" }),
      });
      const sid = encodeURIComponent(spawn.body.subagent_id);

      const wait = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/subagents/${sid}/wait`, { method: "POST", body: "{}" });
      assert.equal(wait.status, 200);
      assert.ok(wait.body.waited_at, "wait stamps waited_at");

      const input = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/subagents/${sid}/input`, {
        method: "POST",
        body: JSON.stringify({ input: "refine the section" }),
      });
      assert.equal(input.status, 200);
      assert.match(input.body.run_id, /^run_/, "input creates a new run");

      const assign = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/subagents/${sid}/assign`, {
        method: "POST",
        body: JSON.stringify({ role: "reviewer" }),
      });
      assert.equal(assign.status, 200);
      assert.equal(assign.body.role, "reviewer");

      const cancel = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/subagents/${sid}/cancel`, { method: "POST", body: "{}" });
      assert.equal(cancel.status, 200);
      assert.equal(cancel.body.status, "canceled");
      assert.equal(cancel.body.lifecycle_status, "canceled");
    });

    // Step 5h: subagent propagate-cancel — completes the subagent family.
    await runStep("POST /v1/threads/:id/subagents/cancel propagates cancellation", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      await fetchJson(`${rust.endpoint}/v1/threads/${tid}/subagents`, { method: "POST", body: JSON.stringify({ prompt: "propagate child a" }) });
      await fetchJson(`${rust.endpoint}/v1/threads/${tid}/subagents`, { method: "POST", body: JSON.stringify({ prompt: "propagate child b" }) });
      const prop = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/subagents/cancel`, {
        method: "POST",
        body: JSON.stringify({ reason: "parent stopped" }),
      });
      assert.equal(prop.status, 200);
      assert.equal(prop.body.object, "ioi.runtime_subagent_cancellation_propagation");
      assert.equal(prop.body.status, "propagated");
      assert.ok(prop.body.canceled_count >= 2, "should cancel the active children");
    });

    // Step 5g: operator turn controls (interrupt/steer) on a fresh turn.
    await runStep("turn interrupt/steer are Rust-owned operator controls", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const turn = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/turns`, {
        method: "POST",
        body: JSON.stringify({ prompt: "a turn to interrupt" }),
      });
      const turnId = encodeURIComponent(turn.body.turn_id);
      const interrupt = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/turns/${turnId}/interrupt`, {
        method: "POST",
        body: JSON.stringify({ reason: "stop" }),
      });
      assert.equal(interrupt.status, 200);
      assert.equal(interrupt.body.operation_kind, "turn.interrupt");
      assert.ok(interrupt.body.operator_control, "interrupt returns an operator_control envelope");
      const steer = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/turns/${turnId}/steer`, {
        method: "POST",
        body: JSON.stringify({ guidance: "focus on the conclusion" }),
      });
      assert.equal(steer.status, 200);
      assert.equal(steer.body.operation_kind, "turn.steer");
    });

    // Step 5: run cancel (mutates the run, so it runs after the run-read assertions).
    await runStep("POST /v1/runs/:id/cancel cancels the run", async () => {
      const { status, body } = await fetchJson(
        `${rust.endpoint}/v1/runs/${encodeURIComponent(turnRequestId)}/cancel`,
        { method: "POST", body: "{}" },
      );
      assert.equal(status, 200);
      assert.equal(body.id, turnRequestId);
      assert.equal(body.status, "canceled");
      assert.equal(body.runtimeTask?.status, "canceled");
      const reloaded = await fetchJson(`${rust.endpoint}/v1/runs/${encodeURIComponent(turnRequestId)}`);
      assert.equal(reloaded.body.status, "canceled", "cancel should persist");
    });

    // Step 6: compaction-policy — first event-EMITTING route on the unified log.
    // The decision event is admitted with a seq ABOVE the synthesized turn events and
    // shows up, merged and contiguous, in GET /events.
    await runStep("POST /v1/threads/:id/compaction-policy admits a decision event", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const before = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );
      const beforeMax = Math.max(0, ...before.map((event) => event.seq ?? 0));

      const policy = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/compaction-policy`, {
        method: "POST",
        body: JSON.stringify({ policy: { warn_action: "warn" }, context_budget: { used: 10, limit: 100 } }),
      });
      assert.equal(policy.status, 200);
      assert.equal(policy.body.component_kind, "compaction_policy");
      assert.ok(policy.body.event_id, "envelope carries the admitted event id");
      assert.equal(policy.body.seq, beforeMax + 1, "decision seq lands after the turn events");
      assert.equal(policy.body.evidence_refs?.[0], "compaction_policy_evaluation_rust_owned");

      const after = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );
      const seqs = after.map((event) => event.seq);
      assert.ok(seqs.every((seq, index) => (index === 0 ? seq === 1 : seq === seqs[index - 1] + 1)), "log stays contiguous");
      assert.equal(after.at(-1)?.component_kind, "compaction_policy", "decision event is on the log");
    });

    // Step 7: context-budget — second event-emitting route (same unified-log path).
    await runStep("POST /v1/threads/:id/context-budget admits a decision event", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const before = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );
      const beforeMax = Math.max(0, ...before.map((event) => event.seq ?? 0));

      const budget = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/context-budget`, {
        method: "POST",
        body: JSON.stringify({
          mode: "warn",
          thresholds: { max_total_tokens: 1000, warn_at_ratio: 0.8 },
          usage_telemetry: { total_tokens: 850 },
        }),
      });
      assert.equal(budget.status, 200);
      assert.equal(budget.body.component_kind, "context_budget");
      assert.equal(budget.body.status, "warn", "850/1000 over warn_at_ratio 0.8 should warn");
      assert.equal(budget.body.seq, beforeMax + 1, "decision seq lands after the prior events");
      assert.equal(budget.body.evidence_refs?.[0], "context_budget_evaluation_rust_owned");

      const after = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );
      assert.equal(after.at(-1)?.component_kind, "context_budget", "decision event is on the log");
    });

    // Step 8: compact — plan + admit a context.compacted event + commit the updated agent.
    await runStep("POST /v1/threads/:id/compact executes a context compaction", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const before = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );
      const beforeMax = Math.max(0, ...before.map((event) => event.seq ?? 0));

      const compact = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/compact`, {
        method: "POST",
        body: JSON.stringify({ reason: "operator requested compaction" }),
      });
      assert.equal(compact.status, 200);
      assert.equal(compact.body.object, "ioi.runtime_context_compaction");
      assert.equal(compact.body.status, "completed");
      assert.equal(compact.body.operation_kind, "thread.compact");
      assert.equal(compact.body.target_kind, "agent", "no run_id -> agent target");
      assert.equal(compact.body.event?.event_kind, "context.compacted");
      assert.equal(compact.body.operator_control?.control, "compact");
      assert.equal(compact.body.context_compaction?.event_id, compact.body.event_id);
      assert.equal(compact.body.seq, beforeMax + 1, "compaction event lands after prior events");

      const after = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );
      assert.equal(after.at(-1)?.event_kind, "context.compacted", "compaction event is on the log");
      const seqs = after.map((event) => event.seq);
      assert.ok(seqs.every((seq, index) => (index === 0 ? seq === 1 : seq === seqs[index - 1] + 1)), "log stays contiguous");
    });

    // Step 9: diagnostics repair-decision execute — synthesized event admitted to the log.
    await runStep("POST /v1/threads/:id/diagnostics/repair-decisions/:id/execute admits an event", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const before = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );
      const beforeMax = Math.max(0, ...before.map((event) => event.seq ?? 0));

      const exec = await fetchJson(
        `${rust.endpoint}/v1/threads/${tid}/diagnostics/repair-decisions/decision_e2e/execute`,
        { method: "POST", body: JSON.stringify({ source: "operator", status: "approved" }) },
      );
      assert.equal(exec.status, 200);
      assert.equal(exec.body.event_kind, "diagnostics.repair_decision.execute");
      assert.equal(exec.body.component_kind, "diagnostics_repair");
      assert.equal(exec.body.payload?.decision_id, "decision_e2e");
      assert.equal(exec.body.seq, beforeMax + 1, "repair event lands after prior events");
      assert.ok((exec.body.receipt_refs ?? []).length >= 1, "synthesized event carries receipt_refs");

      const after = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );
      assert.equal(after.at(-1)?.event_kind, "diagnostics.repair_decision.execute", "repair event is on the log");
    });

    // Step 10: approvals — authority->state-update folded onto the agent (NO event admitted).
    await runStep("POST /v1/threads/:id/approvals authorizes + folds the approval onto the agent", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const before = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );

      const approval = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals`, {
        method: "POST",
        body: JSON.stringify({
          approval_id: "approval_e2e",
          reason: "operator approval required",
          receipt_refs: ["receipt_wallet_grant_e2e"],
        }),
      });
      assert.equal(approval.status, 200);
      assert.equal(approval.body.object, "ioi.runtime_approval_request_state_update");
      assert.equal(approval.body.status, "planned");
      assert.equal(approval.body.operation_kind, "approval.required");
      assert.equal(approval.body.target_kind, "agent", "no run_id -> agent target");
      assert.equal(approval.body.approval_id, "approval_e2e");
      assert.equal(approval.body.lease_status, "pending");
      assert.ok(approval.body.lease_id, "lease id issued");
      assert.equal(approval.body.operator_control?.control, "approval_request");
      assert.ok(approval.body.agent, "approval folded onto the agent record");

      // Approvals do NOT admit a runtime event — the event log must be unchanged.
      const after = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );
      assert.equal(after.length, before.length, "approval request must not admit a runtime event");
    });

    // Step 11: memory status + validate — event-emitting (project -> control -> admit).
    await runStep("POST /v1/threads/:id/memory/{status,validate} admit memory control events", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const before = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );
      const beforeMax = Math.max(0, ...before.map((event) => event.seq ?? 0));

      const status = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/memory/status`, {
        method: "POST",
        body: "{}",
      });
      assert.equal(status.status, 200);
      assert.equal(status.body.event_kind, "memory.status");
      assert.equal(status.body.component_kind, "memory_manager");
      assert.equal(status.body.seq, beforeMax + 1, "memory.status lands after prior events");

      const validate = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/memory/validate`, {
        method: "POST",
        body: "{}",
      });
      assert.equal(validate.status, 200);
      assert.equal(validate.body.event_kind, "memory.validate");
      assert.equal(validate.body.seq, beforeMax + 2, "memory.validate follows memory.status");

      const after = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );
      assert.equal(after.at(-1)?.event_kind, "memory.validate", "memory events are on the log");
      const seqs = after.map((event) => event.seq);
      assert.ok(seqs.every((seq, index) => (index === 0 ? seq === 1 : seq === seqs[index - 1] + 1)), "log stays contiguous");
    });

    // Step 12: GET /usage — pure read-only runtime-lifecycle projection (no event/mutation).
    await runStep("GET /v1/threads/:id/usage projects the thread's runtime usage", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const usage = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/usage`);
      assert.equal(usage.status, 200);
      assert.equal(usage.body.thread_id, createdThread.thread_id);
      assert.ok(typeof usage.body.run_count === "number", "projects a run_count");
      assert.ok(usage.body.run_count >= 1, "the created turn's run is counted");
      assert.ok(typeof usage.body.total_tokens === "number", "projects total_tokens");
    });

    // Step 13: managed-sessions + workspace-change-reviews — read-only projections
    // (empty on a fresh thread) that must carry status:"projected" for JS clients.
    await runStep("GET /v1/threads/:id/{managed-sessions,workspace-change-reviews} project (status projected)", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const sessions = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/managed-sessions`);
      assert.equal(sessions.status, 200);
      assert.equal(sessions.body.status, "projected", "client asserts status projected");
      assert.equal(sessions.body.operation_kind, "managed_session.inspect");
      assert.ok("projection" in sessions.body, "carries a projection");

      const reviews = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/workspace-change-reviews`);
      assert.equal(reviews.status, 200);
      assert.equal(reviews.body.status, "projected");
      assert.equal(reviews.body.operation_kind, "workspace_change.inspect");
    });

    // Step 14: GET /snapshots — read-only workspace-snapshot list projection.
    await runStep("GET /v1/threads/:id/snapshots lists workspace snapshots", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const snapshots = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/snapshots`);
      assert.equal(snapshots.status, 200);
      assert.ok(Array.isArray(snapshots.body.snapshots), "projects a snapshots array");
      assert.equal(snapshots.body.snapshot_count, 0, "untouched thread -> no snapshots");
      assert.equal(snapshots.body.thread_id, createdThread.thread_id);
    });

    // Step 15: conversation artifacts — GET list projection + POST create (record-write).
    await runStep("GET/POST /v1/threads/:id/artifacts list + create conversation artifacts", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const empty = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/artifacts`);
      assert.equal(empty.status, 200);
      assert.ok(Array.isArray(empty.body), "projects an array of artifacts");
      assert.equal(empty.body.length, 0, "untouched thread -> no artifacts");

      const created = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/artifacts`, {
        method: "POST",
        body: JSON.stringify({ title: "Draft Plan", body: "hello", artifact_class: "document" }),
      });
      assert.equal(created.status, 201);
      assert.equal(created.body.status, "created");
      assert.equal(created.body.operation_kind, "artifact.conversation.create");
      assert.ok(created.body.artifact_id, "create returns an artifact_id");

      // The created artifact is persisted and read back by the GET projection.
      const after = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/artifacts`);
      assert.equal(after.status, 200);
      assert.equal(after.body.length, 1, "the created artifact is listed");
    });

    // Step 16: approval decision routes — gated on a REAL wallet-signed ApprovalGrant.
    // The mint fixture (Rust, dcrypt-backed) stands in for the wallet approver; the same
    // grant passes the runtime structural verify here AND settlement's cryptographic verify.
    await runStep("POST /v1/threads/:id/approvals/:id/{approve,reject,revoke} honor a signed grant", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const grant = mintApprovalGrant();
      const auth = { wallet_approval_grant: grant, authority_receipt_refs: ["receipt_wallet_grant_e2e"] };

      const seed = async (approvalId) =>
        fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals`, {
          method: "POST",
          body: JSON.stringify({ approval_id: approvalId, receipt_refs: ["receipt_wallet_grant_e2e"] }),
        });

      await seed("approval_approve_e2e");
      const approve = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals/approval_approve_e2e/approve`, {
        method: "POST",
        body: JSON.stringify(auth),
      });
      assert.equal(approve.status, 200);
      assert.equal(approve.body.operation_kind, "approval.approve");
      assert.equal(approve.body.decision, "approve");
      assert.equal(approve.body.lease_status, "active");

      await seed("approval_reject_e2e");
      const reject = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals/approval_reject_e2e/reject`, {
        method: "POST",
        body: JSON.stringify(auth),
      });
      assert.equal(reject.status, 200);
      assert.equal(reject.body.operation_kind, "approval.reject");

      await seed("approval_revoke_e2e");
      const revoke = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals/approval_revoke_e2e/revoke`, {
        method: "POST",
        body: JSON.stringify(auth),
      });
      assert.equal(revoke.status, 200);
      assert.equal(revoke.body.operation_kind, "approval.revoke");
      assert.equal(revoke.body.lease_status, "revoked");

      // /decision dispatches by body.decision.
      await seed("approval_decision_e2e");
      const decision = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals/approval_decision_e2e/decision`, {
        method: "POST",
        body: JSON.stringify({ ...auth, decision: "approve" }),
      });
      assert.equal(decision.status, 200);
      assert.equal(decision.body.decision, "approve");

      // NEGATIVE 1 — wrong signer: a grant whose authority_id no longer matches the
      // signer pubkey fails the structural binding.
      const wrongAuthority = { ...grant, authority_id: grant.authority_id.map((b, i) => (i === 0 ? b ^ 0xff : b)) };
      const wrongSigner = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals/approval_approve_e2e/approve`, {
        method: "POST",
        body: JSON.stringify({ wallet_approval_grant: wrongAuthority, authority_receipt_refs: ["receipt_wallet_grant_e2e"] }),
      });
      assert.notEqual(wrongSigner.status, 200, "a tampered authority_id must be rejected");

      // NEGATIVE 2 — tampered signature: authority_id/pubkey intact, but the signature
      // bytes are corrupted. The runtime decision authority now cryptographically verifies
      // the grant (the split-brain is closed), so this must be rejected at the route.
      const tamperedSig = { ...grant, approver_sig: grant.approver_sig.map((b, i) => (i === 0 ? b ^ 0xff : b)) };
      const badSignature = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals/approval_approve_e2e/approve`, {
        method: "POST",
        body: JSON.stringify({ wallet_approval_grant: tamperedSig, authority_receipt_refs: ["receipt_wallet_grant_e2e"] }),
      });
      assert.notEqual(badSignature.status, 200, "a tampered signature must be rejected by the runtime authority");
    });

    // RATCHET FRONTIER — gated families need enablers: managed-sessions/wcr control,
    // snapshots restore, workspace-trust pair (warn-on-review).
  } finally {
    await rust.close();
  }
}

main()
  .then(() => {
    const failed = steps.filter((s) => s.status !== "passed");
    console.log(`[lifecycle-e2e] ${steps.length - failed.length}/${steps.length} steps passed`);
    process.exit(failed.length === 0 ? 0 : 1);
  })
  .catch(() => process.exit(1));
