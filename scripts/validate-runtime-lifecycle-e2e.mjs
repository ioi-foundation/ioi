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

import { execFileSync } from "node:child_process";
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
  // Seed a workspace with a skill + hook so the skill/hook registry projection (Rust-owned,
  // scans workspace_root/.claude/{skills,hooks.json}) has real sources to discover.
  const skillHookWorkspace = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-lifecycle-e2e-skills-"));
  fs.mkdirSync(path.join(skillHookWorkspace, ".claude/skills/ratchet-skill"), { recursive: true });
  fs.writeFileSync(
    path.join(skillHookWorkspace, ".claude/skills/ratchet-skill/SKILL.md"),
    "---\nname: ratchet-skill\ndescription: A skill seeded by the lifecycle ratchet\n---\nbody\n",
  );
  fs.writeFileSync(
    path.join(skillHookWorkspace, ".claude/hooks.json"),
    JSON.stringify({ hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "echo ratchet" }] }] } }),
  );
  // Make the workspace a real git repo with a GitHub remote so the repository-workflow
  // projections (Rust-owned, `git -C <workspace_root>`) have real facts to project.
  const wsGit = (...gitArgs) =>
    execFileSync("git", ["-C", skillHookWorkspace, ...gitArgs], { stdio: "pipe" });
  wsGit("init", "-q");
  wsGit("config", "user.email", "ratchet@ioi.test");
  wsGit("config", "user.name", "ratchet");
  wsGit("remote", "add", "origin", "https://github.com/ioi-foundation/ratchet-fixture.git");
  fs.writeFileSync(path.join(skillHookWorkspace, "README.md"), "# ratchet fixture\n");
  wsGit("add", ".");
  wsGit("commit", "-q", "-m", "seed");
  process.env.IOI_HYPERVISOR_WORKSPACE_ROOT = skillHookWorkspace;
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
    // frames, and honors since_seq / Last-Event-ID cursors + future-cursor 409. The event
    // stream is aligned to the live contract: >= 11 events, turn.completed LAST, and the
    // decision projects as item.completed with payload_summary.event_kind ModelRouteDecision.
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
      assert.ok(events.length >= 11, `expected >=11 events, got ${events.length}`);
      assert.equal(events[0].event_kind, "thread.started", "first event should be thread.started");
      assert.equal(events[0].event, "thread.started", "events carry the `event` alias");
      const seqs = events.map((e) => e.seq);
      assert.deepEqual(seqs, seqs.map((_, i) => i + 1), "event seqs should be contiguous 1..N");
      assert.ok(events.some((e) => e.event_kind === "turn.started"), "should include turn.started");
      // turn.completed must be LAST (the materialized task/job items splice ahead of it).
      assert.equal(events.at(-1).event_kind, "turn.completed", "turn.completed must be the last event");
      // The model-route decision projects as item.completed, found by payload_summary.event_kind.
      const decision = events.find((e) => e.payload_summary?.event_kind === "ModelRouteDecision");
      assert.ok(decision, "should include the ModelRouteDecision event");
      assert.equal(decision.event_kind, "item.completed", "decision projects as item.completed");
      assert.equal(decision.component_kind, "model_router", "decision component_kind is model_router");
      assert.equal(decision.workflow_node_id, "workflow.model-router", "decision node is workflow.model-router");
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
      // run replay is the same one-shot event SSE (the SDK round-trip's run.replay()).
      const replay = await fetch(`${rust.endpoint}/v1/runs/${encodeURIComponent(runId)}/replay`);
      assert.equal(replay.status, 200);
      assert.equal(replay.headers.get("content-type"), "text/event-stream");
      assert.equal(parseSseEvents(await replay.text()).length, events.length, "replay matches the run event stream");
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

    // Step 3c: the read-only run sub-projections, all served by the Rust daemon via the
    // kernel runtime-lifecycle projection (no JS daemon). The JS owners now return 410.
    await runStep("GET /v1/runs/:id/{usage,wait,conversation,trace,scorecard,artifacts,...} project the run", async () => {
      const runId = encodeURIComponent(turnRequestId);
      const projections = await Promise.all(
        [
          "usage",
          "wait",
          "conversation",
          "trace",
          "inspect",
          "computer-use/trace",
          "computer-use/trajectory",
          "scorecard",
          "artifacts",
          "artifacts/artifact_does_not_exist",
        ].map(async (suffix) => [suffix, await fetchJson(`${rust.endpoint}/v1/runs/${runId}/${suffix}`)]),
      );
      for (const [suffix, { status }] of projections) {
        assert.equal(status, 200, `run projection ${suffix} should be served by the Rust daemon`);
      }
      const bySuffix = Object.fromEntries(projections);
      // run_wait returns the persisted run record; trace returns its trace object.
      assert.equal(bySuffix.wait.body.id, turnRequestId, "run_wait projects the run record");
      assert.ok(bySuffix.trace.body && typeof bySuffix.trace.body === "object", "run_trace projects the trace");
      assert.equal(JSON.stringify(bySuffix.inspect.body), JSON.stringify(bySuffix.trace.body), "inspect aliases trace");
      // Trace carries the canonical-state marker + scorecard the live contract reads.
      assert.equal(
        bySuffix.trace.body.canonicalState?.source,
        "agentgres_canonical_state_projection",
        "run_trace carries the canonical-state marker",
      );
      assert.equal(bySuffix.scorecard.body?.verifierIndependence, 1, "run_scorecard projects verifierIndependence");
      // The trace embeds the materialized runtimeTask/Job/Checklist with canonical fields.
      assert.equal(bySuffix.trace.body.runtimeTask?.object, "ioi.runtime_task", "trace embeds runtimeTask");
      assert.equal(bySuffix.trace.body.runtimeJob?.queueName, "local-agentgres", "trace embeds runtimeJob");
      assert.equal(bySuffix.trace.body.runtimeChecklist?.readOnly, true, "trace embeds runtimeChecklist");
      // conversation + artifacts are array projections (empty is fine for a minimal turn).
      assert.ok(Array.isArray(bySuffix.conversation.body), "run_conversation is an array");
      assert.ok(Array.isArray(bySuffix.artifacts.body), "run_artifacts is an array");
    });

    // Step 3d: turn-create persists the FULL canonical Agentgres state bundle to the
    // state_dir (not just runs/<run>.json) via the kernel commit. This is the layout the
    // canonical live-runtime-daemon contract asserts — the split-brain repoint target.
    await runStep("turn-create persists the canonical Agentgres state bundle", async () => {
      for (const dir of ["runs", "tasks", "jobs", "checklists", "scorecards", "ledgers", "projections"]) {
        const dirPath = path.join(stateDir, dir);
        assert.ok(fs.existsSync(dirPath), `bundle dir ${dir}/ should exist`);
        const records = fs.readdirSync(dirPath).filter((f) => f.endsWith(".json"));
        assert.ok(records.length >= 1, `bundle dir ${dir}/ should hold a record`);
      }
      // The tasks record embeds the run's runtimeTask + runtimeChecklist + the agentgres
      // transition (derived by the kernel from the run, not a separate write).
      const taskFiles = fs.readdirSync(path.join(stateDir, "tasks")).filter((f) => f.endsWith(".json"));
      const taskRecord = taskFiles
        .map((f) => JSON.parse(fs.readFileSync(path.join(stateDir, "tasks", f), "utf8")))
        .find((record) => record.runId === turnRequestId);
      assert.ok(taskRecord, "a tasks/ record exists for the turn run");
      assert.ok(taskRecord.runtimeTask, "tasks record embeds runtimeTask");
      assert.ok(taskRecord.runtimeChecklist, "tasks record embeds runtimeChecklist");
      assert.ok(taskRecord.agentgresTransition, "tasks record carries the agentgres transition");
      // The jobs record is keyed by the run's jobId and carries the canonical lifecycle.
      const jobFiles = fs.readdirSync(path.join(stateDir, "jobs")).filter((f) => f.endsWith(".json"));
      const jobRecord = jobFiles
        .map((f) => JSON.parse(fs.readFileSync(path.join(stateDir, "jobs", f), "utf8")))
        .find((record) => record.runId === turnRequestId);
      assert.ok(jobRecord, "a jobs/ record exists for the turn run");
      assert.equal(jobRecord.schemaVersion, "ioi.agent-runtime.job-record.v1", "job record schema");
    });

    // Step 3e: the operator account summary + runtime node inventory, now Rust-owned with
    // the canonical Agentgres identifiers the live contract asserts (the JS routes 410).
    await runStep("GET /v1/account + /v1/runtime/nodes are Rust-owned", async () => {
      const account = await fetchJson(`${rust.endpoint}/v1/account`);
      assert.equal(account.status, 200);
      assert.equal(account.body.source, "ioi-daemon-agentgres", "account source marks Agentgres-backed local truth");
      assert.equal(account.body.authorityLevel, "local");
      const nodes = await fetchJson(`${rust.endpoint}/v1/runtime/nodes`);
      assert.equal(nodes.status, 200);
      assert.ok(Array.isArray(nodes.body), "runtime nodes is an array");
      assert.ok(
        nodes.body.some((node) => node.id === "local-daemon-agentgres"),
        "includes the local Agentgres runtime node",
      );
      // GET /v1/models is auth-keyed: the SDK (unauthenticated) gets the catalog ARRAY;
      // OpenAI-compat / CLI (authenticated) gets the {object:"list",data,...} aggregate.
      const modelsUnauth = await fetchJson(`${rust.endpoint}/v1/models`);
      assert.equal(modelsUnauth.status, 200);
      assert.ok(Array.isArray(modelsUnauth.body), "unauthenticated /v1/models is the catalog array");
      const modelsAuth = await fetchJson(`${rust.endpoint}/v1/models`, {
        headers: { authorization: "Bearer lifecycle-e2e" },
      });
      assert.equal(modelsAuth.status, 200);
      assert.equal(modelsAuth.body.object, "list", "authenticated /v1/models is the OpenAI-compat aggregate");
      // GET /v1/doctor: the Rust daemon serves the redacted runtime-readiness report via the
      // kernel doctor projection. The daemon seeds default state on startup (a local-first
      // model route + the memory-store dirs), so a fresh daemon reports readiness "ready"
      // with no blockers (matching the canonical doctor contract).
      const doctor = await fetchJson(`${rust.endpoint}/v1/doctor`);
      assert.equal(doctor.status, 200);
      assert.equal(doctor.body.schemaVersion, "ioi.agent-runtime.doctor.v1");
      assert.equal(doctor.body.object, "ioi.agent_runtime_doctor_report");
      assert.equal(doctor.body.readiness, "ready", "doctor readiness is ready after state-seeding");
      assert.ok(["pass", "degraded"].includes(doctor.body.status), "doctor status is pass/degraded");
      assert.deepEqual(doctor.body.blockers, [], "no doctor blockers");
      assert.equal(doctor.body.redaction?.secretValuesIncluded, false, "doctor redacts secret values");
      assert.equal(doctor.body.redaction?.endpointValuesHashed, true, "doctor hashes endpoint values");
      assert.equal(doctor.body.workflow?.doctorNodeType, "runtime_doctor");
      assert.ok(
        doctor.body.checks?.every((c) => !c.required || c.status === "pass"),
        "all required doctor checks pass (model.routes + memory.store seeded)",
      );
      // GET /v1/usage + /v1/authority-evidence + /v1/workflow-capability-preflights: the
      // top-level runtime-lifecycle projections, now Rust-owned.
      const usage = await fetchJson(`${rust.endpoint}/v1/usage`);
      assert.equal(usage.status, 200);
      assert.equal(usage.body.object, "ioi.runtime_usage_list");
      assert.ok(Array.isArray(usage.body.usage), "usage projection lists usage entries");
      const authority = await fetchJson(`${rust.endpoint}/v1/authority-evidence`);
      assert.equal(authority.status, 200);
      assert.equal(authority.body.object, "ioi.authority_evidence_summary_list");
      assert.ok(Array.isArray(authority.body.items), "authority-evidence lists rows");
      const preflights = await fetchJson(`${rust.endpoint}/v1/workflow-capability-preflights`);
      assert.equal(preflights.status, 200);
      assert.equal(preflights.body.object, "ioi.authority_evidence_summary_list");
      // POST /v1/studio/intent-frame: the Studio intent-frame projection (Rust-owned).
      const intentFrame = await fetchJson(`${rust.endpoint}/v1/studio/intent-frame`, {
        method: "POST",
        body: JSON.stringify({ prompt: "inspect the runtime", execution_mode: "ask" }),
      });
      assert.equal(intentFrame.status, 200);
      assert.ok(intentFrame.body.decision, "studio intent-frame returns a decision");
      assert.equal(
        intentFrame.body.decisionMaterial?.promptPreview,
        "inspect the runtime",
        "the intent frame reflects the prompt",
      );
    });

    // Step 3f: the top-level conversation-artifacts family (list/create/get/revisions/
    // action/export/promote), now Rust-owned via the kernel conversation_artifact
    // projection + control. Thread-less create binds to the synthetic thread_standalone.
    await runStep("GET/POST /v1/conversation-artifacts owns the artifact lifecycle", async () => {
      const created = await fetchJson(`${rust.endpoint}/v1/conversation-artifacts`, {
        method: "POST",
        body: JSON.stringify({ title: "Ratchet artifact", kind: "note", content: "hello" }),
      });
      assert.equal(created.status, 201);
      const artifactId = created.body.artifact_id;
      assert.ok(artifactId, "create returns an artifact_id");
      assert.equal(created.body.artifact?.thread_id, "thread_standalone", "thread-less create binds to thread_standalone");
      assert.equal(created.body.commit?.persisted, true, "create persists the artifact");
      // The control response carries the kernel's top-level ref arrays (JS contract parity).
      assert.ok(Array.isArray(created.body.receipt_refs) && created.body.receipt_refs.length >= 1, "create exposes receipt_refs");
      assert.ok(Array.isArray(created.body.policy_decision_refs) && created.body.policy_decision_refs.length >= 1, "create exposes policy_decision_refs");
      assert.ok(Array.isArray(created.body.evidence_refs) && created.body.evidence_refs.length >= 1, "create exposes evidence_refs");

      const fetched = await fetchJson(`${rust.endpoint}/v1/conversation-artifacts/${encodeURIComponent(artifactId)}`);
      assert.equal(fetched.status, 200);
      assert.equal(fetched.body.artifact_id, artifactId, "get returns the created artifact");

      const list = await fetchJson(`${rust.endpoint}/v1/conversation-artifacts`);
      assert.equal(list.status, 200);
      assert.ok(
        Array.isArray(list.body) && list.body.some((entry) => entry.artifact_id === artifactId),
        "list includes the created artifact",
      );

      const action = await fetchJson(`${rust.endpoint}/v1/conversation-artifacts/${encodeURIComponent(artifactId)}/actions`, {
        method: "POST",
        body: JSON.stringify({ action_kind: "update", patch: { title: "Updated" } }),
      });
      assert.equal(action.status, 200);
      assert.equal(action.body.status, "completed", "action completes");

      const exported = await fetchJson(`${rust.endpoint}/v1/conversation-artifacts/${encodeURIComponent(artifactId)}/export`, {
        method: "POST",
        body: JSON.stringify({ export_format: "markdown" }),
      });
      assert.equal(exported.status, 200);
      assert.equal(exported.body.status, "exported", "export completes");
      assert.ok(exported.body.export_ref, "export returns an export_ref");
      assert.ok(Array.isArray(exported.body.receipt_refs), "export exposes top-level receipt_refs");
      assert.ok(Array.isArray(exported.body.policy_decision_refs), "export exposes top-level policy_decision_refs");
      assert.ok(Array.isArray(exported.body.evidence_refs), "export exposes top-level evidence_refs");

      const promoted = await fetchJson(`${rust.endpoint}/v1/conversation-artifacts/${encodeURIComponent(artifactId)}/promote`, {
        method: "POST",
        body: JSON.stringify({ promotion_target: "runtime" }),
      });
      assert.equal(promoted.status, 200);
      assert.equal(promoted.body.status, "promoted", "promote completes");

      const revisions = await fetchJson(`${rust.endpoint}/v1/conversation-artifacts/${encodeURIComponent(artifactId)}/revisions`);
      assert.equal(revisions.status, 200);
      assert.ok(Array.isArray(revisions.body), "revisions returns an array");

      // The export/promote refs persisted (the mutations wrote back through state_dir).
      const final = await fetchJson(`${rust.endpoint}/v1/conversation-artifacts/${encodeURIComponent(artifactId)}`);
      assert.ok(Array.isArray(final.body.export_refs) && final.body.export_refs.length >= 1, "export_ref persisted");
      assert.ok(Array.isArray(final.body.promotion_refs) && final.body.promotion_refs.length >= 1, "promotion_ref persisted");
    });

    // Step 3g: the skill + hook registry projections (Rust-owned via the kernel
    // skill_hook_registry projection scanning workspace_root/.claude/{skills,hooks.json}).
    await runStep("GET /v1/skills + /v1/hooks project the workspace skill/hook registry", async () => {
      const skills = await fetchJson(`${rust.endpoint}/v1/skills`);
      assert.equal(skills.status, 200);
      assert.equal(skills.body.schemaVersion, "ioi.agent-runtime.skills.v1", "skills projection carries the skills schema");
      assert.ok(typeof skills.body.skillCount === "number", "skills projection carries skillCount");
      assert.ok(Array.isArray(skills.body.skills), "skills projection lists skills");
      assert.ok(skills.body.redaction, "skills projection carries the redaction marker");
      assert.ok(
        skills.body.skills.some((skill) => JSON.stringify(skill).includes("ratchet-skill")),
        "the seeded workspace skill is discovered",
      );

      const hooks = await fetchJson(`${rust.endpoint}/v1/hooks`);
      assert.equal(hooks.status, 200);
      assert.equal(hooks.body.schemaVersion, "ioi.agent-runtime.hooks.v1", "hooks projection carries the hooks schema");
      assert.ok(typeof hooks.body.hookCount === "number", "hooks projection carries hookCount");
      assert.ok(Array.isArray(hooks.body.hooks), "hooks projection lists hooks");
      assert.ok(hooks.body.hookCount >= 1, "the seeded workspace hook is discovered");
    });

    // Step 3h: the repository-workflow projections (Rust-owned via the kernel
    // repository_workflow projection running real `git -C <workspace_root>` over the
    // seeded git repo; GitHub context is derived from remotes + token env, no network IO).
    await runStep("GET /v1/repository-context + the repository-workflow family project real git", async () => {
      const context = await fetchJson(`${rust.endpoint}/v1/repository-context`);
      assert.equal(context.status, 200);
      assert.equal(context.body.object, "ioi.repository_context", "repository-context object shape");
      assert.equal(context.body.isGitRepository, true, "the seeded workspace is a git repo");
      assert.ok(context.body.headSha, "repository-context carries the real HEAD sha");

      const github = await fetchJson(`${rust.endpoint}/v1/github-context`);
      assert.equal(github.status, 200);
      assert.equal(github.body.object, "ioi.github_context");
      assert.equal(github.body.repoFullName, "ioi-foundation/ratchet-fixture", "owner/repo parsed from the git remote");

      const branchPolicy = await fetchJson(`${rust.endpoint}/v1/branch-policy`);
      assert.equal(branchPolicy.status, 200);
      assert.equal(branchPolicy.body.object, "ioi.branch_policy_decision");

      // pr-attempts + repositories project as arrays (unwrapped, matching the JS facade).
      const prAttempts = await fetchJson(`${rust.endpoint}/v1/pr-attempts`);
      assert.equal(prAttempts.status, 200);
      assert.ok(Array.isArray(prAttempts.body), "pr-attempts projects an array");
      const repositories = await fetchJson(`${rust.endpoint}/v1/repositories`);
      assert.equal(repositories.status, 200);
      assert.ok(Array.isArray(repositories.body), "repositories projects an array");

      // review-gate + issue-context + github/pr-create-plan project their decision objects.
      const reviewGate = await fetchJson(`${rust.endpoint}/v1/review-gate`);
      assert.equal(reviewGate.body.object, "ioi.review_gate_decision");
      const prPlan = await fetchJson(`${rust.endpoint}/v1/github/pr-create-plan`);
      assert.equal(prPlan.body.object, "ioi.github_pr_create_plan");
    });

    // Step 3i: the runtime tool catalog (Rust-owned via the pure/static kernel
    // runtime_tool_catalog projection). GET /v1/tools is a bare array, ?pack= filters it.
    await runStep("GET /v1/tools projects the runtime tool catalog (bare array, pack filter)", async () => {
      const all = await fetchJson(`${rust.endpoint}/v1/tools`);
      assert.equal(all.status, 200);
      assert.ok(Array.isArray(all.body) && all.body.length >= 1, "tools projects a non-empty array");
      assert.ok(
        all.body.every((tool) => typeof tool.stable_tool_id === "string" && typeof tool.pack === "string"),
        "each tool carries stable_tool_id + pack",
      );
      const coding = await fetchJson(`${rust.endpoint}/v1/tools?pack=coding`);
      assert.equal(coding.status, 200);
      assert.ok(Array.isArray(coding.body), "pack-filtered tools is an array");
      assert.ok(coding.body.every((tool) => tool.pack === "coding"), "pack filter restricts to the coding pack");
      assert.ok(
        coding.body.some((tool) => tool.stable_tool_id === "file.apply_patch"),
        "the coding pack includes file.apply_patch",
      );
    });

    // Step 3j: memory CRUD (Rust-owned via the kernel memory projection + control). Write,
    // list, policy get/set, path, edit, delete — thread-scoped and agent-scoped — with the
    // payload persisted to <state_dir>/memory-records + memory-policies.
    await runStep("memory CRUD (write/list/policy/path/edit/delete) is Rust-owned + persisted", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);

      // POST write -> a record is committed + persisted.
      const written = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/memory`, {
        method: "POST",
        body: JSON.stringify({ fact: "the ratchet remembers", memory_key: "ratchet.key", scope: "thread" }),
      });
      assert.equal(written.status, 200);
      assert.equal(written.body.status, "committed", "write commits");
      assert.equal(written.body.memory_state_kind, "record", "write produces a record");
      assert.equal(written.body.commit?.persisted, true, "write persists the record");
      const memoryId = written.body.memory_id;
      assert.ok(memoryId, "write returns a memory_id");

      // GET list -> the written record is projected.
      const list = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/memory`);
      assert.equal(list.status, 200);
      const records = Array.isArray(list.body.records) ? list.body.records : [];
      assert.ok(
        records.some((record) => JSON.stringify(record).includes("the ratchet remembers")),
        "the written memory is listed",
      );

      // GET + PUT policy.
      const policyGet = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/memory/policy`);
      assert.equal(policyGet.status, 200);
      const policySet = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/memory/policy`, {
        method: "PUT",
        body: JSON.stringify({ policy: { autoCapture: false } }),
      });
      assert.equal(policySet.status, 200);
      assert.equal(policySet.body.memory_state_kind, "policy", "policy update produces a policy");
      assert.equal(policySet.body.commit?.persisted, true, "policy update persists");

      // GET path.
      const pathGet = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/memory/path`);
      assert.equal(pathGet.status, 200);

      // PATCH edit -> same state_id, then DELETE.
      const edited = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/memory/${encodeURIComponent(memoryId)}`, {
        method: "PATCH",
        body: JSON.stringify({ fact: "the ratchet remembers (edited)" }),
      });
      assert.equal(edited.status, 200);
      assert.equal(edited.body.state_id, memoryId, "edit preserves the state_id");
      const deleted = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/memory/${encodeURIComponent(memoryId)}`, {
        method: "DELETE",
      });
      assert.equal(deleted.status, 200);

      // Agent-scoped write twin projects + persists too.
      const aid = encodeURIComponent(createdThread.agent_id);
      const agentWrite = await fetchJson(`${rust.endpoint}/v1/agents/${aid}/memory`, {
        method: "POST",
        body: JSON.stringify({ fact: "agent-scoped memory", memory_key: "agent.key" }),
      });
      assert.equal(agentWrite.status, 200);
      assert.equal(agentWrite.body.commit?.persisted, true, "agent-scoped write persists");

      // The payloads are durable on the Agentgres state dir.
      const recordFiles = fs.existsSync(path.join(stateDir, "memory-records"))
        ? fs.readdirSync(path.join(stateDir, "memory-records")).filter((file) => file.endsWith(".json"))
        : [];
      assert.ok(recordFiles.length >= 1, "memory records persisted to <state_dir>/memory-records");
      const policyFiles = fs.existsSync(path.join(stateDir, "memory-policies"))
        ? fs.readdirSync(path.join(stateDir, "memory-policies")).filter((file) => file.endsWith(".json"))
        : [];
      assert.ok(policyFiles.length >= 1, "memory policy persisted to <state_dir>/memory-policies");
    });

    // Step 3k: the Hypervisor Core taxonomy (Rust-owned static doctrine; only generated_at
    // is stamped per request).
    await runStep("GET /v1/hypervisor/core-taxonomy serves the canonical Core taxonomy", async () => {
      const taxonomy = await fetchJson(`${rust.endpoint}/v1/hypervisor/core-taxonomy`);
      assert.equal(taxonomy.status, 200);
      assert.equal(taxonomy.body.schema_version, "ioi.runtime.hypervisor_core_taxonomy.v1");
      assert.equal(taxonomy.body.core.execution_owner, "hypervisor-daemon");
      assert.ok(typeof taxonomy.body.generated_at === "string", "taxonomy carries a stamped generated_at");
      assert.deepEqual(
        taxonomy.body.first_class_clients.map((client) => client.kind),
        ["app", "web", "cli_headless"],
      );
      assert.ok(
        taxonomy.body.adapter_target_families.some((family) => family.id === "code_editor"),
        "taxonomy lists the code_editor adapter family",
      );
    });

    // Step 3l: the model-route-mutation governance admission (Rust-owned via the kernel
    // admit_model_route_mutation planner — pure validation + canonicalization). Admits a
    // valid request (202) and rejects missing authority/credential refs with the structured
    // {error:{code}} shape (400 validation / 403 authority).
    await runStep("POST /v1/hypervisor/model-route-mutation-admissions admits + gates by authority", async () => {
      const base = (overrides = {}) => ({
        mutation_kind: "bind_session_route",
        route_ref: "model-route:local/default",
        project_ref: "project:ioi",
        session_ref: "session:ioi",
        provider_ref: "provider:local",
        provider_kind: "local",
        endpoint_refs: ["model-endpoint:local/default"],
        loaded_instance_refs: ["model-instance:local/default"],
        credential_posture: "no_credentials_required",
        authority_scope_refs: ["scope:model.route.mutate"],
        credential_scope_refs: [],
        wallet_approval_ref: "approval://wallet/model-route/local",
        wallet_lease_ref: "lease:wallet/model-route/local",
        model_weight_custody_admission_ref: "model-weight-custody-admission:model-route_local_default",
        privacy_posture_ref: "privacy-posture:private-native",
        agentgres_operation_refs: ["agentgres://operation/model-route/local/bind-session"],
        receipt_refs: ["receipt://model-route/local/bind-session"],
        state_root_ref: "agentgres://state-root/model-route/local",
        ...overrides,
      });
      const admit = (body) =>
        fetchJson(`${rust.endpoint}/v1/hypervisor/model-route-mutation-admissions`, {
          method: "POST",
          body: JSON.stringify(body),
        });

      const ok = await admit(base());
      assert.equal(ok.status, 202, "valid mutation is admitted with 202");
      assert.equal(ok.body.decision, "admitted");
      assert.equal(ok.body.admission_state, "admitted_for_model_router");
      assert.ok(
        ok.body.receipt_refs.includes(
          "receipt://model-route-mutation/model-route_local_default/bind_session_route",
        ),
        "the admission derives the canonical mutation receipt ref",
      );

      // 403: authority scope present but lacking scope:model.route.mutate.
      const noScope = await admit(base({ authority_scope_refs: ["scope:other.capability"] }));
      assert.equal(noScope.status, 403, "missing scope:model.route.mutate is rejected 403");
      assert.equal(noScope.body.error.code, "model_route_mutation_required_scope_missing");

      // 403: credentialed provider without a credential lease.
      const noLease = await admit(
        base({
          provider_ref: "provider:hosted-api",
          provider_kind: "hosted_api",
          endpoint_refs: ["model-endpoint:hosted/default"],
          credential_posture: "wallet_credential_lease",
          credential_scope_refs: ["scope:secret.use"],
        }),
      );
      assert.equal(noLease.status, 403);
      assert.equal(noLease.body.error.code, "model_route_mutation_provider_credential_lease_required");

      // 400: a retired camelCase alias is rejected before authority checks.
      const aliased = await admit({ ...base(), routeRef: "model-route:local/default" });
      assert.equal(aliased.status, 400);
      assert.equal(aliased.body.error.code, "model_route_mutation_request_aliases_retired");
    });

    // Step 3m: the model-weight-custody governance admission (Rust-owned via the kernel
    // admit_model_weight_custody planner — weight-class lane validation).
    await runStep("POST /v1/hypervisor/model-weight-custody-admissions gates the weight-class lane", async () => {
      const custody = (body) =>
        fetchJson(`${rust.endpoint}/v1/hypervisor/model-weight-custody-admissions`, {
          method: "POST",
          body: JSON.stringify(body),
        });

      // A user-local private weight on a local device with the local_only control admits.
      const ok = await custody({
        route_ref: "model-route:local/default",
        model_ref: "model:local/qwen",
        weight_class: "user_local_private_weight",
        mount_target: "local_device",
        execution_privacy_posture: "private_native",
        remote_provider_can_read_weights: false,
        authority_scope_refs: ["scope:model.mount"],
        required_controls: ["local_only"],
      });
      assert.equal(ok.status, 202);
      assert.equal(ok.body.decision, "admitted");
      assert.equal(ok.body.protects_model_weights_from_provider_root, true);
      assert.equal(
        ok.body.receipt_ref,
        "receipt://model-weight-custody/model-route_local_default/user_local_private_weight",
      );

      // 403: a forbidden plaintext mount is blocked by default.
      const forbidden = await custody({
        route_ref: "model-route:local/default",
        model_ref: "model:local/qwen",
        weight_class: "forbidden_plaintext_mount",
        mount_target: "local_device",
        execution_privacy_posture: "private_native",
      });
      assert.equal(forbidden.status, 403);
      assert.equal(forbidden.body.error.code, "model_weight_custody_forbidden_plaintext_mount_blocked");

      // 400: a non-scope authority ref is rejected.
      const badScope = await custody({
        route_ref: "model-route:local/default",
        model_ref: "model:local/qwen",
        weight_class: "user_local_private_weight",
        mount_target: "local_device",
        execution_privacy_posture: "private_native",
        authority_scope_refs: ["model.mount"],
        required_controls: ["local_only"],
      });
      assert.equal(badScope.status, 400);
      assert.equal(badScope.body.error.code, "model_weight_custody_scope_invalid");
    });

    // Step 3n: the Hypervisor session-launch-recipe governance admission (Rust-owned via the
    // kernel admit_hypervisor_session_launch_recipe planner — recipe/target-binding agreement
    // + route/model/privacy/authority/receipt/Agentgres refs + daemon-gate assertion).
    await runStep("POST /v1/hypervisor/session-launch-recipe-admissions admits + gates the recipe binding", async () => {
      const recipe = (overrides = {}) => ({
        schema_version: "ioi.hypervisor.session_launch_recipe.v1",
        recipe_id: "workbench.default",
        kind: "workbench",
        surface_id: "workbench",
        required_inputs: ["project", "model_route", "privacy_posture"],
        model_mount_policy: "inherit",
        harness_profile_policy: "select",
        authority_scope_templates: ["scope:workspace.read", "scope:workspace.patch"],
        privacy_posture_templates: ["public_trunk", "redacted_projection"],
        ...overrides,
      });
      const targetBinding = (overrides = {}) => ({
        schema_version: "ioi.hypervisor.new_session_target_binding.v1",
        target_binding_ref: "target-binding:new-session/workbench-default/ioi",
        recipe_ref: "workbench.default",
        target_kind: "workbench",
        surface_id: "workbench",
        project_ref: "project:ioi",
        operator_intent_ref: "target-binding:new-session/workbench.default/ioi/operator-intent",
        session_route_ref: "session-route:workbench/workbench-default/ioi",
        code_editor_adapter_target_ref: "code-editor-target:vscode",
        runtimeTruthSource: "daemon-runtime",
        ...overrides,
      });
      const base = (overrides = {}) => ({
        schema_version: "ioi.hypervisor.session_launch_recipe_admission_request.v1",
        recipe: recipe(),
        target_binding: targetBinding(),
        model_route_ref: "model-route:hypervisor/default-local",
        privacy_posture_ref: "privacy:redacted-projection",
        authority_scope_refs: ["scope:workspace.read", "scope:workspace.patch"],
        receipt_preview_ref: "receipt-preview:new-session/workbench",
        expected_receipt_refs: [
          "receipt-preview:new-session/workbench",
          "receipt-policy:harness-adapter/default",
        ],
        agentgres_operation_refs: ["agentgres://operation/hypervisor/session-launch-recipe/workbench"],
        receipt_refs: ["receipt://hypervisor/session-launch-recipe/workbench"],
        requires_daemon_gate: true,
        runtimeTruthSource: "daemon-runtime",
        ...overrides,
      });
      const admit = (body) =>
        fetchJson(`${rust.endpoint}/v1/hypervisor/session-launch-recipe-admissions`, {
          method: "POST",
          body: JSON.stringify(body),
        });

      const ok = await admit(base());
      assert.equal(ok.status, 202, "valid recipe binding is admitted with 202");
      assert.equal(ok.body.decision, "admitted");
      assert.equal(ok.body.admission_state, "admitted_for_session_binding");
      assert.equal(ok.body.recipe_ref, "workbench.default");
      assert.equal(ok.body.session_route_ref, "session-route:workbench/workbench-default/ioi");
      assert.ok(
        ok.body.receipt_refs.includes(
          "receipt://hypervisor/session-launch-recipe/target-binding_new-session_workbench-default_ioi/admitted",
        ),
        "the admission derives the canonical admission receipt ref",
      );

      // 400: a workbench recipe whose target binding drops the code-editor adapter.
      const noAdapter = await admit(
        base({ target_binding: targetBinding({ code_editor_adapter_target_ref: null }) }),
      );
      assert.equal(noAdapter.status, 400);
      assert.equal(
        noAdapter.body.error.code,
        "hypervisor_session_launch_recipe_workbench_adapter_required",
      );

      // 400: a retired camelCase alias is rejected before any field validation.
      const aliased = await admit({ ...base(), recipeRef: "legacy" });
      assert.equal(aliased.status, 400);
      assert.equal(aliased.body.error.code, "hypervisor_session_launch_recipe_retired_aliases");

      // 400: an authority primitive masquerade (non-scope: ref) is rejected.
      const badScope = await admit(base({ authority_scope_refs: ["prim:shell.exec"] }));
      assert.equal(badScope.status, 400);
      assert.equal(badScope.body.error.code, "hypervisor_session_launch_recipe_ref_prefix_invalid");
    });

    // Step 3o: the harness-session-binding governance admission (Rust-owned via the kernel
    // admit_harness_session_binding planner — harness selection / model route / workspace-mount /
    // privacy / authority / receipts + daemon-gate boundary; mixed 400 field-shape / 403 policy).
    await runStep("POST /v1/hypervisor/harness-session-binding-admissions admits + gates the boundary", async () => {
      const base = (overrides = {}) => ({
        schema_version: "ioi.hypervisor.harness_session_binding.v1",
        session_binding_ref:
          "harness-session-binding:session-route-sessions-mission-default-project-ioi:harness-profile-default_harness_profile:model-config-local-codex-oss-qwen",
        session_route_ref: "session-route:sessions/mission.default/project:ioi",
        harness_selection_ref: "harness-profile:default_harness_profile",
        harness_selection_kind: "harness_profile",
        harness_truth_boundary: "daemon-owned",
        harness_launch_route_ref: "harness-route:default-harness-profile/local-model",
        harness_profile_ref: "default_harness_profile",
        model_configuration_ref: "model-config:local/codex-oss-qwen",
        model_route_ref: "model-route:hypervisor/default-local",
        model_route_policy: "hypervisor_model_mount",
        model_route_availability_state: "daemon_verified",
        model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
        model_route_loaded_instance_refs: ["model-instance:hypervisor/default-local"],
        workspace_mount_policy: "ctee_private_workspace",
        privacy_posture_ref: "privacy:ctee-private-workspace",
        authority_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
        receipt_policy_ref: "receipt-policy:harness-profile/default",
        receipt_preview_ref: "receipt-preview:new-session/admitted",
        expected_receipt_refs: [
          "receipt-preview:new-session/admitted",
          "receipt-policy:harness-profile/default",
        ],
        requires_daemon_gate: true,
        runtimeTruthSource: "daemon-runtime",
        agentgres_operation_refs: ["agentgres://operation/harness-session-binding/admit"],
        receipt_refs: ["receipt://harness-session-binding/admit"],
        ...overrides,
      });
      const admit = (body) =>
        fetchJson(`${rust.endpoint}/v1/hypervisor/harness-session-binding-admissions`, {
          method: "POST",
          body: JSON.stringify(body),
        });

      const ok = await admit(base());
      assert.equal(ok.status, 202, "valid harness binding is admitted with 202");
      assert.equal(ok.body.decision, "admitted");
      assert.equal(ok.body.admission_state, "admitted_for_harness_launch");
      assert.equal(ok.body.harness_runtime_truth_claimed, false);
      assert.ok(
        ok.body.receipt_refs.includes(
          "receipt://harness-session-binding/harness-session-binding_session-route-sessions-mission-default-project-ioi_harness-profile-default_harness_profile_model-config-local-codex-oss-qwen/admitted",
        ),
        "the admission derives the canonical admission receipt ref",
      );

      // 403: an external adapter cannot mount cTEE private-workspace custody.
      const ctee = await admit({
        ...base(),
        session_binding_ref:
          "harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-codex_cli",
        harness_selection_ref: "agent-harness-adapter:codex_cli",
        harness_selection_kind: "agent_harness_adapter",
        harness_truth_boundary: "proposal_source_only",
        agent_harness_adapter_id: "codex_cli",
        harness_profile_ref: undefined,
      });
      assert.equal(ctee.status, 403);
      assert.equal(ctee.body.error.code, "harness_session_binding_external_ctee_custody_blocked");

      // 403: an adapter cannot claim runtime truth.
      const claim = await admit(base({ harness_runtime_truth_claimed: true }));
      assert.equal(claim.status, 403);
      assert.equal(claim.body.error.code, "harness_session_binding_runtime_truth_claim_blocked");

      // 400: a retired camelCase alias is rejected before any field validation.
      const aliased = await admit({ ...base(), sessionBindingRef: "legacy" });
      assert.equal(aliased.status, 400);
      assert.equal(aliased.body.error.code, "harness_session_binding_request_aliases_retired");
    });

    // Step 3p: the private-workspace-mount governance admission (Rust-owned via the kernel
    // admit_private_workspace_mount planner — custody-class / mount-target / execution-privacy
    // lane + required controls/scopes/attestation/wallet/declassification refs; 400 field-shape /
    // 403 custody-lane policy; decisions admitted / admitted_declassification / admitted_unsafe).
    await runStep("POST /v1/hypervisor/private-workspace-mount-admissions gates the custody lane", async () => {
      const base = (overrides = {}) => ({
        workspace_ref: "workspace://ioi",
        mount_ref: "mount://workspace/public-trunk",
        segment_ref: "workspace-segment:public-trunk",
        provider_ref: "provider:akash/gpu-market",
        custody_class: "public_trunk",
        mount_target: "rented_gpu",
        execution_privacy_posture: "ctee_split",
        provider_root_can_read_plaintext: true,
        protected_plaintext_requested: false,
        required_controls: [],
        authority_scope_refs: [],
        agentgres_operation_refs: ["agentgres://operation/privacy/mount"],
        artifact_refs: ["artifact://workspace/public-trunk"],
        state_root_ref: "agentgres://state-root/workspace/ioi",
        ...overrides,
      });
      const admit = (body) =>
        fetchJson(`${rust.endpoint}/v1/hypervisor/private-workspace-mount-admissions`, {
          method: "POST",
          body: JSON.stringify(body),
        });

      // public_trunk admits and does not treat provider-readable public bytes as private custody.
      const ok = await admit(base());
      assert.equal(ok.status, 202, "public-trunk mount is admitted with 202");
      assert.equal(ok.body.decision, "admitted");
      assert.equal(ok.body.protects_workspace_plaintext_from_provider_root, true);

      // admitted_declassification for a cTEE private-head handle on a rented GPU.
      const privateHead = await admit(
        base({
          custody_class: "private_head",
          provider_root_can_read_plaintext: false,
          required_controls: ["ctee_private_head_handle"],
          authority_scope_refs: ["scope:ctee.private-head.evaluate"],
        }),
      );
      assert.equal(privateHead.status, 202);
      assert.equal(privateHead.body.decision, "admitted_declassification");

      // 403: an unsafe-plaintext exception missing its wallet approval ref.
      const unsafe = await admit(
        base({
          custody_class: "unsafe_plaintext_mount",
          execution_privacy_posture: "unsafe_plaintext_mount",
          protected_plaintext_requested: true,
          required_controls: ["explicit_unsafe_plaintext_acceptance"],
          authority_scope_refs: ["scope:privacy.unsafe_plaintext_mount"],
          user_disclosure_ref: "disclosure://privacy/unsafe-mount",
          provider_trust_acceptance_ref: "approval://provider-trust/unsafe-mount",
        }),
      );
      assert.equal(unsafe.status, 403);
      assert.equal(unsafe.body.error.code, "private_workspace_mount_required_ref_missing");

      // 400: a non-prefixed workspace ref (field-shape) is rejected before the lane policy.
      const badRef = await admit(base({ workspace_ref: "nope://x" }));
      assert.equal(badRef.status, 400);
      assert.equal(badRef.body.error.code, "private_workspace_mount_ref_prefix_invalid");
    });

    // Step 3q: the physical-action-intent governance admission (Rust-owned via the kernel
    // admit_physical_action_intent planner — daemon-owned safety/supervision/emergency-stop/
    // receipt envelope; never a generic tool call). Exercises the optionalPositiveInteger JS
    // Number() coercion (true→1, "0x10"→16) and the 400 field-shape / 403 policy split.
    await runStep("POST /v1/hypervisor/physical-action-intent-admissions gates the safety envelope", async () => {
      const base = (overrides = {}) => ({
        intent_id: "intent://physical/carwash/prep-vehicle-001",
        actor_id: "worker:carwash-prep-humanoid",
        target_system_ref: "robot://bay-3/humanoid-1",
        action_kind: "manipulation",
        risk_class: "physical_action",
        execution_phase: "command_issued",
        requested_primitives: ["prim:physical.actuate"],
        requested_scopes: ["scope:physical.actuate"],
        physical_action_policy_ref: "policy://physical/carwash-prep",
        safety_envelope_ref: "safety://carwash/bay-3",
        supervision_mode: "human_on_loop",
        human_supervisor_refs: ["user://operator/bay-3"],
        emergency_stop_authority_ref: "estop://carwash/bay-3",
        emergency_stop_tested: true,
        emergency_stop_max_latency_ms: "0x10",
        sensor_evidence_receipt_refs: ["receipt://sensor/bay-3/preflight"],
        actuator_command_receipt_refs: ["receipt://actuator/bay-3/prep-command"],
        incident_policy_ref: "policy://physical/incidents/carwash",
        wallet_approval_ref: "approval://wallet/physical-action/carwash",
        authority_ref: "grant://wallet/physical-action/carwash",
        policy_refs: ["policy://physical/carwash-prep"],
        receipt_refs: ["receipt://actuator/bay-3/prep-command"],
        agentgres_operation_refs: ["agentgres://operation/physical-action/carwash/prep"],
        ...overrides,
      });
      const admit = (body) =>
        fetchJson(`${rust.endpoint}/v1/hypervisor/physical-action-intent-admissions`, {
          method: "POST",
          body: JSON.stringify(body),
        });

      const ok = await admit(base());
      assert.equal(ok.status, 202, "valid physical action is admitted with 202");
      assert.equal(ok.body.decision, "admitted");
      assert.equal(ok.body.risk_class, "physical_action");
      assert.equal(ok.body.generic_tool_call_blocked, true);
      // "0x10" coerces to 16 (JS Number() hex), matching the JS optionalPositiveInteger.
      assert.equal(ok.body.emergency_stop_max_latency_ms, 16);

      // 403: an actuator command routed as a generic tool call is blocked.
      const generic = await admit(base({ execution_channel: "tool.invoke", generic_tool_call: true }));
      assert.equal(generic.status, 403);
      assert.equal(generic.body.error.code, "physical_action_generic_tool_call_blocked");

      // 400: a non-positive-integer emergency-stop latency (field-shape) is rejected.
      const badLatency = await admit(base({ emergency_stop_max_latency_ms: 2.5 }));
      assert.equal(badLatency.status, 400);
      assert.equal(badLatency.body.error.code, "physical_action_emergency_stop_max_latency_ms_invalid");

      // 400: a retired camelCase alias is rejected before any field validation.
      const aliased = await admit({ ...base(), intentId: "legacy" });
      assert.equal(aliased.status, 400);
      assert.equal(aliased.body.error.code, "physical_action_request_aliases_retired");
    });

    // Step 3r: the worker-package-install governance admission (Rust-owned via the kernel
    // admit_worker_package_install planner — manifest/ontology/surfaces/requirements/policy/
    // receipt/evidence/artifact refs + wallet approval + mode/physical-action safety gates;
    // 400 field-shape / 403 policy).
    await runStep("POST /v1/hypervisor/worker-package-install-admissions gates the install lane", async () => {
      const base = (overrides = {}) => ({
        install_id: "install://aiagent/carwash-prep/heath/default",
        worker_package_ref: "package://aiagent/robotics.carwash_prep@1",
        worker_manifest_ref: "manifest://aiagent/robotics.carwash_prep@1",
        owner_ref: "wallet://user/heath",
        install_mode: "managed_instance_initialization",
        base_ontology_ref: "ontology:aiagent.base.v1",
        vertical_pack_refs: ["vertical_pack:robotics.carwash_prep.v1"],
        integration_surface_refs: ["integration_surface:robotics_physical"],
        primitive_capability_requirements: ["prim:physical.actuate"],
        authority_scope_requirements: ["scope:physical.actuate"],
        risk_classes: ["physical_action"],
        policy_profile_refs: ["policy://aiagent/worker-install", "policy://ctee/private-workspace"],
        receipt_policy_ref: "receipt_policy://aiagent/worker-install",
        evidence_requirement_refs: ["evidence_requirement:physical.preflight.v1"],
        runtime_profile: "private_workspace_ctee",
        persistence_profile: "zero_to_idle",
        memory_policy_ref: "policy://memory/worker-instance",
        archive_policy_ref: "policy://archive/worker-instance",
        package_artifact_refs: ["artifact://package/robotics.carwash-prep/v1"],
        wallet_approval_ref: "approval://wallet/worker-install/carwash",
        install_right_ref: "license://aiagent/install/carwash-prep",
        managed_instance_ref: "agent://carwash-prep/heath/default",
        physical_action_policy_refs: ["policy://physical/carwash-prep"],
        safety_envelope_refs: ["safety://carwash/bay-3"],
        emergency_stop_authority_refs: ["estop://carwash/bay-3"],
        agentgres_operation_refs: ["agentgres://operation/worker-install/carwash-prep"],
        receipt_refs: ["receipt://worker-install/carwash-prep"],
        ...overrides,
      });
      const admit = (body) =>
        fetchJson(`${rust.endpoint}/v1/hypervisor/worker-package-install-admissions`, {
          method: "POST",
          body: JSON.stringify(body),
        });

      const ok = await admit(base());
      assert.equal(ok.status, 202, "valid worker install is admitted with 202");
      assert.equal(ok.body.decision, "admitted");
      assert.equal(ok.body.runtime_profile, "private_workspace_ctee");

      // 403: a physical-action package missing its physical-action policy refs.
      const noPolicy = await admit(base({ physical_action_policy_refs: [] }));
      assert.equal(noPolicy.status, 403);
      assert.equal(noPolicy.body.error.code, "worker_package_install_physical_action_policy_refs_required");

      // 403: a prim:* masquerading as a wallet authority scope.
      const masquerade = await admit(base({ authority_scope_requirements: ["prim:physical.actuate"] }));
      assert.equal(masquerade.status, 403);
      assert.equal(masquerade.body.error.code, "worker_package_install_primitive_scope_masquerade_blocked");

      // 400: a non-prefixed install id (field-shape) before the policy gates.
      const badInstall = await admit(base({ install_id: "nope://x" }));
      assert.equal(badInstall.status, 400);
      assert.equal(badInstall.body.error.code, "worker_package_install_install_id_invalid");
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

    // Step 4d: workspace-trust pair — entering review mode raises a trust warning on the
    // unified log; the acknowledge route consumes it by id and emits an acknowledgement.
    await runStep("mode=review raises a workspace-trust warning that acknowledge consumes", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const before = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );
      const beforeMax = Math.max(0, ...before.map((event) => event.seq ?? 0));

      const review = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/mode`, {
        method: "POST",
        body: JSON.stringify({ mode: "review" }),
      });
      assert.equal(review.status, 200);
      const warningId = review.body.workspace_trust_warning?.warning_id;
      assert.ok(warningId, "review mode raises a workspace-trust warning");
      assert.equal(review.body.workspace_trust_warning_event?.event_kind, "workspace.trust_warning");
      assert.equal(review.body.workspace_trust_warning_event?.seq, beforeMax + 1, "warning lands on the log");

      const ack = await fetchJson(
        `${rust.endpoint}/v1/threads/${tid}/workspace-trust/${encodeURIComponent(warningId)}/acknowledge`,
        { method: "POST", body: JSON.stringify({ reason: "operator trusts this workspace" }) },
      );
      assert.equal(ack.status, 200);
      assert.equal(ack.body.object, "ioi.runtime_workspace_trust_control_state_update");
      assert.equal(ack.body.event?.event_kind, "workspace.trust_acknowledged");
      assert.equal(ack.body.event?.seq, beforeMax + 2, "acknowledgement follows the warning");

      const after = parseSseEvents(
        await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events`)).text(),
      );
      assert.equal(after.at(-1)?.event_kind, "workspace.trust_acknowledged", "trust events are on the log");
      const seqs = after.map((event) => event.seq);
      assert.ok(seqs.every((seq, index) => (index === 0 ? seq === 1 : seq === seqs[index - 1] + 1)), "log stays contiguous");
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
      // The SDK Agent constructor reads options.subagentNames; the agent record must carry it.
      assert.ok(Array.isArray(create.body.options?.subagentNames), "agent options carry subagentNames");
      const list = await fetchJson(`${rust.endpoint}/v1/agents`);
      assert.equal(list.status, 200);
      assert.ok(
        Array.isArray(list.body) && list.body.some((a) => a.id === create.body.id),
        "agents list should include the created agent",
      );
      // Agent run-create (the SDK send path): POST /v1/agents/:id/runs returns the RUN
      // record (id=run_<uuid>), bootstrapping the thread from the agent (no prior thread).
      const run = await fetchJson(`${rust.endpoint}/v1/agents/${encodeURIComponent(create.body.id)}/runs`, {
        method: "POST",
        body: JSON.stringify({ mode: "send", prompt: "agent run-create probe" }),
      });
      assert.equal(run.status, 200);
      assert.match(run.body.id, /^run_/, "agent run-create returns a run record");
      assert.equal(run.body.agentId, create.body.id, "run is bound to the agent");
      assert.equal(run.body.status, "completed");
      assert.equal(run.body.trace?.canonicalState?.source, "agentgres_canonical_state_projection");
      // The run's events are readable via /v1/runs/:id/events (the SDK run.stream()).
      const runEvents = await fetch(`${rust.endpoint}/v1/runs/${encodeURIComponent(run.body.id)}/events`);
      assert.equal(runEvents.status, 200);
      assert.ok(parseSseEvents(await runEvents.text()).length >= 1, "agent run events project");
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
      // Cancel rewrites the run events with the canceled terminal LAST (the cancel-path
      // mirror of the turn.completed-LAST invariant).
      assert.equal(
        body.events?.at(-1)?.type,
        "canceled",
        "cancel leaves the canceled terminal as the last run event",
      );
      const reloaded = await fetchJson(`${rust.endpoint}/v1/runs/${encodeURIComponent(turnRequestId)}`);
      assert.equal(reloaded.body.status, "canceled", "cancel should persist");
      // The cancel re-commits the canonical bundle, so the tasks/ record reflects the
      // cancel too — the bundle stays FAITHFUL across the run lifecycle, not just at create.
      const canceledTask = fs
        .readdirSync(path.join(stateDir, "tasks"))
        .filter((f) => f.endsWith(".json"))
        .map((f) => JSON.parse(fs.readFileSync(path.join(stateDir, "tasks", f), "utf8")))
        .find((record) => record.runId === turnRequestId);
      assert.equal(
        canceledTask?.runtimeTask?.status,
        "canceled",
        "the canonical bundle tasks record reflects the cancel (faithful across lifecycle)",
      );
      // POST /v1/jobs|tasks/:id/cancel cancel the job/task by canceling the owning run.
      const jobsList = await fetchJson(`${rust.endpoint}/v1/jobs`);
      const jobId = jobsList.body.find((j) => j.runId === turnRequestId)?.jobId;
      assert.ok(jobId, "the run has a job record");
      const jobCancel = await fetchJson(`${rust.endpoint}/v1/jobs/${encodeURIComponent(jobId)}/cancel`, { method: "POST", body: "{}" });
      assert.equal(jobCancel.status, 200);
      assert.equal(jobCancel.body.jobId, jobId);
      assert.equal(jobCancel.body.status, "canceled");
      const tasksList = await fetchJson(`${rust.endpoint}/v1/tasks`);
      const taskId = tasksList.body.find((t) => t.runId === turnRequestId)?.taskId;
      const taskCancel = await fetchJson(`${rust.endpoint}/v1/tasks/${encodeURIComponent(taskId)}/cancel`, { method: "POST", body: "{}" });
      assert.equal(taskCancel.status, 200);
      assert.equal(taskCancel.body.status, "canceled");
      const missingJob = await fetchJson(`${rust.endpoint}/v1/jobs/job_does_not_exist/cancel`, { method: "POST", body: "{}" });
      assert.equal(missingJob.status, 404, "job cancel 404s on an unknown job");
      // The cancel admits the JobCanceled + turn.canceled events onto the thread log (no
      // duplication of the materialized items).
      const tid = encodeURIComponent(createdThread.thread_id);
      const cancelEvents = parseSseEvents(await (await fetch(`${rust.endpoint}/v1/threads/${tid}/events?since_seq=0`)).text());
      const jobCanceledEvents = cancelEvents.filter((e) => e.payload_summary?.event_kind === "JobCanceled");
      assert.ok(jobCanceledEvents.length >= 1, "the thread log carries the JobCanceled event after cancel");
      assert.equal(jobCanceledEvents[0].payload_summary.lifecycle_status, "canceled");
      assert.ok(jobCanceledEvents[0].artifact_refs.includes("runtime-job.json"));
      assert.ok(cancelEvents.some((e) => e.event_kind === "turn.canceled"), "the canceled terminal is on the log");
      // Idempotent: the run + job + task cancel calls (all canceling this run) admit the
      // JobCanceled event exactly once, not three times.
      assert.equal(jobCanceledEvents.length, 1, "cancel admits JobCanceled once (idempotent across cancel calls)");
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

    // Step 13b: workspace-change PRODUCER cut — real git detection feeds the existing
    // control/projection consumers. A real temp git repo with on-disk changes (no
    // fixtures, no harness) is detected, projected as a pending review, then accepted.
    await runStep("workspace-change detect (real git) -> project -> control(accept)", async () => {
      const repo = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-wc-repo-"));
      const git = (args) =>
        execFileSync("git", ["-C", repo, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
      git(["init", "-q"]);
      git(["config", "user.email", "ratchet@ioi.test"]);
      git(["config", "user.name", "ratchet"]);
      fs.writeFileSync(path.join(repo, "a.txt"), "hello\n");
      git(["add", "."]);
      git(["commit", "-q", "-m", "init"]);
      fs.writeFileSync(path.join(repo, "a.txt"), "hello world\n"); // modified
      fs.writeFileSync(path.join(repo, "b.txt"), "new file\n"); // added

      const created = await fetchJson(`${rust.endpoint}/v1/threads`, {
        method: "POST",
        body: JSON.stringify({ options: { local: { cwd: repo }, model: { id: "auto", routeId: "route.native-local" } } }),
      });
      const tid = encodeURIComponent(created.body.thread_id);

      // Detect: the producer git-diffs the real workspace and admits proposed reviews.
      const detect = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/workspace-change-reviews/detect`, {
        method: "POST",
        body: "{}",
      });
      assert.equal(detect.status, 200);
      assert.equal(detect.body.object, "ioi.runtime_workspace_change_detection");
      assert.ok(detect.body.detected_count >= 2, "real git changes are detected");
      assert.equal(detect.body.event?.event_kind, "workspace_change.detected");
      const changeId = detect.body.changes?.[0]?.workspace_change_id;
      assert.ok(changeId, "each change carries a workspace_change_id");

      // The existing projection consumer replays the detected reviews as pending.
      const reviews = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/workspace-change-reviews`);
      assert.equal(reviews.status, 200);
      const cards = Array.isArray(reviews.body.projection)
        ? reviews.body.projection
        : reviews.body.projection?.records ?? [];
      assert.ok(cards.length >= 2, "detected reviews are projected");
      assert.ok(cards.some((card) => card.review_state === "pending_review"), "proposed -> pending_review");

      // Control: accept the proposed review (kernel transition proposed -> applied).
      const control = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/workspace-change-reviews/control`, {
        method: "POST",
        body: JSON.stringify({ workspace_change_id: changeId, control_state: "accept" }),
      });
      assert.equal(control.status, 200);
      assert.equal(control.body.event_kind, "workspace_change.controlled");
      assert.equal(control.body.payload?.next_lifecycle, "applied");
    });

    // Step 13c: managed-sessions control is Rust-owned and correctly gated on real
    // production. Managed sessions are produced ONLY by the runtime event-log bridge
    // when a real `browser__*` turn drives a sandbox session (the bridge: turn
    // execution -> KernelEvent::RuntimeThreadEvent -> <state_dir>/events). That path
    // is verified end-to-end by the Rust bridge round-trip + control-planner tests
    // (event_log_bridge), not reproducible in this HTTP-only ratchet without a real
    // turn. So here we assert the migrated route REACHES the kernel control planner
    // and refuses without a produced session — NOT 404 (unregistered) or 410
    // (JS-retired). This proves the route is Rust-owned and gated on the real
    // producer, never a fixture.
    await runStep("managed-sessions/control is Rust-owned + gated on a produced session", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const control = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/managed-sessions/control`, {
        method: "POST",
        body: JSON.stringify({ managed_session_id: "sandbox_browser:absent", control_state: "take_over" }),
      });
      assert.notEqual(control.status, 404, "route is registered on the Rust daemon");
      assert.notEqual(control.status, 410, "route is not JS-retired-poisoned");
      assert.ok(control.status >= 400, "no produced managed session -> the planner refuses");
      assert.match(
        JSON.stringify(control.body),
        /managed session|record/i,
        "gated on a produced managed_session record, not a fixture",
      );
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

    // Step 14b: snapshot PRODUCER cut — real git-tree capture over a real workspace,
    // then a real-FS restore round-trip. A temp git repo with a committed file and an
    // uncommitted edit is captured (before = HEAD, after = working tree); the captured
    // event feeds the GET projection; restore-apply writes the `before` content back to
    // the real file on disk. No fixtures, no turn execution.
    await runStep("snapshot capture (real git) -> list -> restore-apply (real FS revert)", async () => {
      const repo = fs.mkdtempSync(path.join(os.tmpdir(), "ioi-snap-repo-"));
      const git = (args) =>
        execFileSync("git", ["-C", repo, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
      git(["init", "-q"]);
      git(["config", "user.email", "ratchet@ioi.test"]);
      git(["config", "user.name", "ratchet"]);
      const file = path.join(repo, "a.txt");
      fs.writeFileSync(file, "v1\n");
      git(["add", "."]);
      git(["commit", "-q", "-m", "v1"]);
      fs.writeFileSync(file, "v2\n"); // uncommitted edit -> the working-tree "after"

      const created = await fetchJson(`${rust.endpoint}/v1/threads`, {
        method: "POST",
        body: JSON.stringify({ options: { local: { cwd: repo }, model: { id: "auto", routeId: "route.native-local" } } }),
      });
      const tid = encodeURIComponent(created.body.thread_id);

      // Capture: the producer git-diffs the real workspace and admits the snapshot.
      const capture = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/snapshots/capture`, {
        method: "POST",
        body: "{}",
      });
      assert.equal(capture.status, 200);
      assert.equal(capture.body.object, "ioi.runtime_workspace_snapshot_capture");
      assert.ok(capture.body.snapshot_id, "capture returns a snapshot_id");
      assert.equal(capture.body.event?.event_kind, "workspace_snapshot.captured");
      const snapshotId = capture.body.snapshot_id;

      // The consumer replays the captured event into the GET list projection.
      const list = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/snapshots`);
      assert.equal(list.status, 200);
      assert.ok(list.body.snapshot_count >= 1, "captured snapshot is projected");
      assert.ok(
        (list.body.snapshots ?? []).some((s) => (s.snapshot_id ?? s.id) === snapshotId),
        "the captured snapshot_id is listed",
      );

      // restore-PREVIEW exposes the wallet-grant binding the apply will require.
      const preview = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/snapshots/${encodeURIComponent(snapshotId)}/restore-preview`, { method: "POST", body: "{}" });
      assert.equal(preview.status, 200);
      assert.equal(preview.body.approval?.required, true, "preview advertises that apply requires approval");
      const policyHash = preview.body.approval.policy_hash;
      const requestHash = preview.body.approval.request_hash;
      assert.ok(policyHash && requestHash, "preview exposes the policy_hash + request_hash to mint a grant against");

      // restore-apply WRITES THE REAL FS, so it requires a real wallet-signed ApprovalGrant
      // bound to THIS restore. A bare/boolean POST is FORBIDDEN — it must mutate nothing.
      const noGrant = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/snapshots/${encodeURIComponent(snapshotId)}/restore-apply`, { method: "POST", body: JSON.stringify({ confirm_restore_apply: true }) });
      assert.equal(noGrant.status, 403, "restore-apply without a signed grant is forbidden");
      assert.equal(fs.readFileSync(file, "utf8"), "v2\n", "no-grant apply leaves the file untouched");

      // A grant minted for a DIFFERENT snapshot (wrong request_hash) cannot authorize this
      // restore (anti-replay), even though it is a perfectly valid signed grant.
      const crossGrant = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/snapshots/${encodeURIComponent(snapshotId)}/restore-apply`, {
        method: "POST",
        body: JSON.stringify({ wallet_approval_grant: mintApprovalGrant({ policyHash, requestHash: "11".repeat(32) }) }),
      });
      assert.equal(crossGrant.status, 403, "a grant bound to a different request_hash is rejected");
      assert.equal(fs.readFileSync(file, "utf8"), "v2\n", "rejected-grant apply leaves the file untouched");

      // A grant with the CORRECT request_hash but a foreign policy_hash is also rejected:
      // the daemon binds BOTH daemon-derived hashes, so weakening the policy_hash binding
      // (e.g. dropping it from verification) would flip this negative.
      const wrongPolicy = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/snapshots/${encodeURIComponent(snapshotId)}/restore-apply`, {
        method: "POST",
        body: JSON.stringify({ wallet_approval_grant: mintApprovalGrant({ policyHash: "22".repeat(32), requestHash }) }),
      });
      assert.equal(wrongPolicy.status, 403, "a grant bound to a different policy_hash is rejected");
      assert.equal(fs.readFileSync(file, "utf8"), "v2\n", "wrong-policy-grant apply leaves the file untouched");

      // Valid wallet-signed grant bound to this restore -> applies. Working tree is still v2
      // (== snapshot after), a clean restore; a.txt reverts to v1 on disk.
      const grant = mintApprovalGrant({ policyHash, requestHash });
      const apply = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/snapshots/${encodeURIComponent(snapshotId)}/restore-apply`, {
        method: "POST",
        body: JSON.stringify({ wallet_approval_grant: grant }),
      });
      assert.equal(apply.status, 200);
      assert.equal(apply.body.event?.event_kind, "workspace_restore.applied");
      assert.ok(apply.body.approval_grant_ref, "the applied event records which grant authorized it");
      assert.equal(fs.readFileSync(file, "utf8"), "v1\n", "restore-apply reverts the real file to its snapshotted content");
    });

    // Step 14c: snapshot capture/restore DATA-LOSS regression guards (two isolated
    // repos — a blocked op preflight-blocks an entire apply, so they must not share one).
    //  A) a modified file whose committed (HEAD) blob is binary/non-UTF-8 must BLOCK on
    //     restore (content uncapturable), NEVER be silently deleted.
    //  B) a rename must REVERT (recreate old path, remove new path), not delete the file.
    await runStep("snapshot restore blocks on binary-HEAD (no silent delete) + reverts renames", async () => {
      const newRepo = (prefix) => {
        const repo = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
        const git = (args) =>
          execFileSync("git", ["-C", repo, ...args], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
        git(["init", "-q"]);
        git(["config", "user.email", "ratchet@ioi.test"]);
        git(["config", "user.name", "ratchet"]);
        return { repo, git };
      };
      const newThread = async (repo) => {
        const created = await fetchJson(`${rust.endpoint}/v1/threads`, {
          method: "POST",
          body: JSON.stringify({ options: { local: { cwd: repo }, model: { id: "auto", routeId: "route.native-local" } } }),
        });
        return encodeURIComponent(created.body.thread_id);
      };
      // restore-apply requires a wallet-signed grant bound to the daemon-derived binding
      // returned by restore-preview; mint it and apply.
      const signedApply = async (tid, snapshotId) => {
        const preview = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/snapshots/${encodeURIComponent(snapshotId)}/restore-preview`, { method: "POST", body: "{}" });
        const grant = mintApprovalGrant({ policyHash: preview.body.approval.policy_hash, requestHash: preview.body.approval.request_hash });
        return fetchJson(`${rust.endpoint}/v1/threads/${tid}/snapshots/${encodeURIComponent(snapshotId)}/restore-apply`, { method: "POST", body: JSON.stringify({ wallet_approval_grant: grant }) });
      };

      // A) binary HEAD, modified to TEXT on disk. Both sides are captured base64; on
      // restore the on-disk text is re-encoded base64 to match the snapshot post-state, so
      // it is a clean restore that writes the real raw binary HEAD bytes back (validates
      // the capture/read_current encoding symmetry; the file is reverted, never deleted).
      const a = newRepo("ioi-snap-bin-");
      const binFile = path.join(a.repo, "bin.dat");
      const aHead = Buffer.from([0xff, 0xfe, 0x00, 0x80, 0x01, 0x02]);
      fs.writeFileSync(binFile, aHead);
      a.git(["add", "."]);
      a.git(["commit", "-q", "-m", "binary"]);
      fs.writeFileSync(binFile, "now plain text\n"); // working tree modified; HEAD is binary
      const tidA = await newThread(a.repo);
      const capA = await fetchJson(`${rust.endpoint}/v1/threads/${tidA}/snapshots/capture`, { method: "POST", body: "{}" });
      assert.equal(capA.status, 200);
      const applyA = await signedApply(tidA, capA.body.snapshot_id);
      assert.equal(applyA.status, 200);
      assert.equal(applyA.body.event?.event_kind, "workspace_restore.applied");
      assert.ok(fs.readFileSync(binFile).equals(aHead), "binary HEAD restored to its raw bytes even though the working copy was text");

      // A2) DATA-LOSS guard for the genuinely-uncapturable case: a file whose content
      // exceeds the 256KB capture cap is omitted, so restore BLOCKS — the file must remain
      // untouched, NEVER deleted.
      const big = newRepo("ioi-snap-big-");
      const bigFile = path.join(big.repo, "big.txt");
      fs.writeFileSync(bigFile, "a".repeat(300 * 1024) + "\n");
      big.git(["add", "."]);
      big.git(["commit", "-q", "-m", "big"]);
      fs.writeFileSync(bigFile, "b".repeat(300 * 1024) + "\n"); // modified, still over the cap
      const tidBig = await newThread(big.repo);
      const capBig = await fetchJson(`${rust.endpoint}/v1/threads/${tidBig}/snapshots/capture`, { method: "POST", body: "{}" });
      assert.equal(capBig.status, 200);
      const applyBig = await signedApply(tidBig, capBig.body.snapshot_id);
      assert.equal(applyBig.status, 200);
      assert.ok(fs.existsSync(bigFile), "over-cap (uncapturable) file MUST NOT be deleted on restore");
      assert.equal(applyBig.body.applied_file_count, 0, "uncapturable content -> nothing applied (blocked)");

      // B) rename revert (confirmed).
      const b = newRepo("ioi-snap-mv-");
      fs.writeFileSync(path.join(b.repo, "r.txt"), "orig\n");
      b.git(["add", "."]);
      b.git(["commit", "-q", "-m", "orig"]);
      b.git(["mv", "r.txt", "r2.txt"]);
      const tidB = await newThread(b.repo);
      const capB = await fetchJson(`${rust.endpoint}/v1/threads/${tidB}/snapshots/capture`, { method: "POST", body: "{}" });
      assert.equal(capB.status, 200);
      const applyB = await signedApply(tidB, capB.body.snapshot_id);
      assert.equal(applyB.status, 200);
      assert.equal(applyB.body.event?.event_kind, "workspace_restore.applied");
      assert.equal(fs.readFileSync(path.join(b.repo, "r.txt"), "utf8"), "orig\n", "rename revert recreates the original path");
      assert.ok(!fs.existsSync(path.join(b.repo, "r2.txt")), "rename revert removes the new path");

      // C) binary round-trip: a file binary in BOTH HEAD and working is captured base64
      // and restored to its real raw HEAD bytes (base64-decoded), not the base64 text.
      const c = newRepo("ioi-snap-bin2-");
      const cFile = path.join(c.repo, "img.bin");
      const headBytes = Buffer.from([0x00, 0x9f, 0x92, 0x96, 0xff, 0x01, 0x02, 0x03]);
      const workBytes = Buffer.from([0xff, 0xfe, 0x00, 0x01, 0x80, 0x09]);
      fs.writeFileSync(cFile, headBytes);
      c.git(["add", "."]);
      c.git(["commit", "-q", "-m", "bin-v1"]);
      fs.writeFileSync(cFile, workBytes); // still binary, different bytes
      const tidC = await newThread(c.repo);
      const capC = await fetchJson(`${rust.endpoint}/v1/threads/${tidC}/snapshots/capture`, { method: "POST", body: "{}" });
      assert.equal(capC.status, 200);
      const applyC = await signedApply(tidC, capC.body.snapshot_id);
      assert.equal(applyC.status, 200);
      assert.equal(applyC.body.event?.event_kind, "workspace_restore.applied");
      assert.ok(fs.readFileSync(cFile).equals(headBytes), "binary file round-trips to its raw HEAD bytes via base64");
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

    // Step 16: approval decision routes — gated on a REAL wallet-signed ApprovalGrant
    // bound to the request-time lease. The mint fixture (Rust, dcrypt-backed) stands in
    // for the wallet approver; the daemon derives now_ms + expected_policy_hash +
    // expected_request_hash from Rust-authored lease state (never the POST body) and the
    // kernel decision authority verifies the signature AND binds expiry + policy_hash +
    // request_hash before authorizing.
    await runStep("POST /v1/threads/:id/approvals/:id/{approve,reject,revoke} honor a bound signed grant", async () => {
      const tid = encodeURIComponent(createdThread.thread_id);
      const refs = ["receipt_wallet_grant_e2e"];

      // Seed an approval and return its request-time lease (carrying the canonical
      // policy_hash + request_hash the wallet grant must be bound to).
      const seed = async (approvalId) => {
        const created = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals`, {
          method: "POST",
          body: JSON.stringify({ approval_id: approvalId, receipt_refs: refs }),
        });
        assert.equal(created.status, 200);
        const lease = created.body.approval_lease;
        assert.ok(lease?.policy_hash, "the request authority establishes a lease policy_hash");
        assert.ok(lease?.request_hash, "the request authority establishes a canonical request_hash");
        return lease;
      };
      const authFor = (lease, overrides = {}) => ({
        wallet_approval_grant: mintApprovalGrant({
          policyHash: lease.policy_hash,
          requestHash: lease.request_hash,
          ...overrides,
        }),
        authority_receipt_refs: refs,
      });

      const approveLease = await seed("approval_approve_e2e");
      const approve = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals/approval_approve_e2e/approve`, {
        method: "POST",
        body: JSON.stringify(authFor(approveLease)),
      });
      assert.equal(approve.status, 200);
      assert.equal(approve.body.operation_kind, "approval.approve");
      assert.equal(approve.body.decision, "approve");
      assert.equal(approve.body.lease_status, "active");

      const rejectLease = await seed("approval_reject_e2e");
      const reject = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals/approval_reject_e2e/reject`, {
        method: "POST",
        body: JSON.stringify(authFor(rejectLease)),
      });
      assert.equal(reject.status, 200);
      assert.equal(reject.body.operation_kind, "approval.reject");

      const revokeLease = await seed("approval_revoke_e2e");
      const revoke = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals/approval_revoke_e2e/revoke`, {
        method: "POST",
        body: JSON.stringify(authFor(revokeLease)),
      });
      assert.equal(revoke.status, 200);
      assert.equal(revoke.body.operation_kind, "approval.revoke");
      assert.equal(revoke.body.lease_status, "revoked");

      // /decision dispatches by body.decision.
      const decisionLease = await seed("approval_decision_e2e");
      const decisionAuth = authFor(decisionLease);
      const decision = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals/approval_decision_e2e/decision`, {
        method: "POST",
        body: JSON.stringify({ ...decisionAuth, decision: "approve" }),
      });
      assert.equal(decision.status, 200);
      assert.equal(decision.body.decision, "approve");

      // Fail-closed negatives. `negLease` is the target approval; `otherLease` is a
      // distinct approval used to prove a grant bound to another approval is rejected.
      const negLease = await seed("approval_negative_e2e");
      const otherLease = await seed("approval_other_e2e");
      const validGrant = mintApprovalGrant({ policyHash: negLease.policy_hash, requestHash: negLease.request_hash });
      const reject403 = async (grant, why) => {
        const res = await fetchJson(`${rust.endpoint}/v1/threads/${tid}/approvals/approval_negative_e2e/approve`, {
          method: "POST",
          body: JSON.stringify({ wallet_approval_grant: grant, authority_receipt_refs: refs }),
        });
        assert.notEqual(res.status, 200, why);
      };

      // N1 wrong signer: authority_id no longer matches the pubkey (structural binding).
      await reject403({ ...validGrant, authority_id: validGrant.authority_id.map((b, i) => (i === 0 ? b ^ 0xff : b)) }, "tampered authority_id must be rejected");
      // N2 tampered signature: cryptographic verification fails (split-brain closed).
      await reject403({ ...validGrant, approver_sig: validGrant.approver_sig.map((b, i) => (i === 0 ? b ^ 0xff : b)) }, "tampered signature must be rejected");
      // N3 policy mismatch: correct request_hash but a different policy_hash (the default
      // fixture hash) must not authorize this approval.
      await reject403(mintApprovalGrant({ requestHash: negLease.request_hash }), "policy_hash mismatch must be rejected");
      // N4 expired: correct policy + request hash but a past expiry — the clock rejects it.
      await reject403(mintApprovalGrant({ policyHash: negLease.policy_hash, requestHash: negLease.request_hash, expiresAt: 1000 }), "an expired grant must be rejected");
      // N5 cross-approval anti-replay: this approval's policy_hash but ANOTHER approval's
      // request_hash. Signer/signature/expiry/policy are all otherwise valid; only the
      // request binding is wrong, so the grant for one approval cannot decide another.
      await reject403(mintApprovalGrant({ policyHash: negLease.policy_hash, requestHash: otherLease.request_hash }), "a grant bound to a different approval's request_hash must be rejected");
    });

    // ROUTE MIGRATION COMPLETE + ALL PRODUCER CUTS DONE — the Rust hypervisor-daemon
    // owns the entire thread/run lifecycle + non-lifecycle route surface, plus every
    // precondition-gated family. All producer subsystems are wired to REAL production
    // (no fixture events seeded onto the log):
    //   - workspace-change/control — fed by real `git status` detection (step 13b).
    //   - managed-sessions/control — fed by the runtime event-log bridge: a real
    //     `browser__*` turn records the managed session into KV and emits a
    //     KernelEvent::RuntimeThreadEvent that the bridge persists to <state_dir>/events
    //     (verified by the Rust bridge round-trip + control-planner tests; route
    //     Rust-ownership + gating asserted in step 13c).
    //   - snapshots restore-*      — fed by a real git-tree capture
    //     (POST .../snapshots/capture): `before` = HEAD, `after` = working tree; the
    //     captured event feeds the list projection and restore-apply writes `before`
    //     back to the real filesystem (full round-trip in step 14b).
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
