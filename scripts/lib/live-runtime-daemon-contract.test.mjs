import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { startRuntimeDaemonService } from "../../packages/runtime-daemon/src/index.mjs";

const root = path.resolve(path.dirname(new URL(import.meta.url).pathname), "../..");

async function importSdk() {
  return import("../../packages/agent-sdk/dist/index.js");
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

async function fetchSseEvents(url) {
  const text = await fetch(url).then(async (response) => {
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
    assert.ok(trace.receipts.some((receipt) => receipt.kind === "agentgres_canonical_write"));
    assert.equal((await canceled.scorecard()).verifierIndependence, 1);
    assert.ok((await canceled.artifacts()).some((artifact) => artifact.name === "agentgres-projection.json"));

    const operationLog = path.join(stateDir, "operation-log.jsonl");
    assert.ok(fs.existsSync(operationLog));
    assert.ok(fs.readFileSync(operationLog, "utf8").includes("run.cancel"));
    for (const relative of [
      ["runs", `${run.id}.json`],
      ["tasks", `${run.id}.json`],
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
    assert.deepEqual(trace.hookInvocationLedger.emittedEventKinds, [
      "workflow_activation",
      "pre_model",
      "post_model",
    ]);
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
    assert.equal(thread.schema_version, "ioi.agent-runtime.tti.v1");
    assert.match(thread.thread_id, /^thread_/);
    assert.match(thread.session_id, /^agent_/);
    assert.equal(thread.latest_seq, 0);
    assert.equal(thread.workspace, cwd);
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
    assert.equal(turn.schema_version, "ioi.agent-runtime.tti.v1");
    assert.equal(turn.thread_id, thread.thread_id);
    assert.match(turn.turn_id, /^turn_/);
    assert.equal(turn.status, "completed");
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
    assert.equal(events[0].schema_version, "ioi.agent-runtime.event-envelope.v1");
    assert.equal(events[0].thread_id, thread.thread_id);
    assert.equal(events[0].turn_id, turn.turn_id);
    assert.equal(events[0].event, "turn.started");
    assert.equal(events[0].workflow_node_id, "runtime.runtime-thread");
    const routeEvent = events.find((event) => event.payload_summary?.event_kind === "ModelRouteDecision");
    assert.equal(routeEvent.component_kind, "model_router");
    assert.equal(routeEvent.workflow_node_id, "workflow.model-router");
    assert.equal(routeEvent.payload_summary.selected_model, "autopilot:native-fixture");
    assert.equal(routeEvent.payload_summary.reasoning_effort, "low");
    assert.ok(routeEvent.payload_summary.model_route_decision_id);
    assert.deepEqual(routeEvent.receipt_refs, [thread.model_route_receipt_id]);
    assert.equal(events.at(-1).event, "turn.completed");
    assert.ok(events.some((event) => event.workflow_node_id === "runtime.quality-ledger"));
    assert.ok(events.every((event) => event.payload_summary?.run_id));

    const replayAfterFive = await fetchSseEvents(
      `${daemon.endpoint}/v1/threads/${thread.thread_id}/events?since_seq=5`,
    );
    assert.equal(replayAfterFive[0].seq, 6);
    assert.ok(replayAfterFive.every((event) => event.seq > 5));
  } finally {
    await daemon.close();
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

test("agent CLI exposes model and thinking control contracts", () => {
  const source = fs.readFileSync(path.join(root, "crates/cli/src/commands/agent.rs"), "utf8");
  assert.match(source, /AgentCommands::Model/);
  assert.match(source, /AgentCommands::Thinking/);
  assert.match(source, /AgentCommands::Memory/);
  assert.match(source, /AgentCommands::Doctor/);
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
  assert.match(source, /ioi\.agent-runtime\.doctor\.v1/);
  assert.match(source, /ioi\.agent-runtime\.skills\.v1/);
  assert.match(source, /ioi\.agent-runtime\.hooks\.v1/);
  assert.match(source, /reactflow_workflow_node/);
});

test("React Flow memory, doctor, skill, and hook node contracts remain workflow-addressable", () => {
  const workflowContracts = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/deepseek-parity-workflow-contracts.ts"),
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
  const workflowValidation = fs.readFileSync(
    path.join(root, "packages/agent-ide/src/runtime/workflow-validation.ts"),
    "utf8",
  );
  assert.match(workflowContracts, /memory\.scope/);
  assert.match(workflowContracts, /memory\.remember/);
  assert.match(workflowContracts, /memory\.search/);
  assert.match(workflowContracts, /memory\.list/);
  assert.match(workflowContracts, /memory\.policy/);
  assert.match(workflowContracts, /memory\.path/);
  assert.match(workflowContracts, /memory\.subagentInheritance/);
  assert.match(workflowContracts, /runtime\.doctor/);
  assert.match(nodeRegistry, /runtime_doctor/);
  assert.match(nodeRegistry, /RuntimeDoctorNode/);
  assert.match(nodeRegistry, /\/v1\/doctor/);
  assert.match(nodeRegistry, /blockOnRequiredFailures/);
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
  assert.match(nodeRegistry, /activeSkillSetHash/);
  assert.match(nodeRegistry, /activeHookSetHash/);
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
  assert.match(workflowValidation, /workflowNodeIsHookPolicy/);
  assert.match(workflowValidation, /hook_policy_dry_run_blocked/);
  assert.match(workflowValidation, /hook_policy_dry_run_plan_missing/);
  assert.match(workflowValidation, /hook_policy_routes_missing/);
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
