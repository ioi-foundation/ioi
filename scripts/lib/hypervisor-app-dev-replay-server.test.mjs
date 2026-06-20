import assert from "node:assert/strict";
import test from "node:test";

// Pin an unreachable model upstream and ensure replay mode is OFF before the
// server module is evaluated, so the session-turn "no model route" assertions
// are deterministic regardless of whether a local Ollama happens to be
// listening on :11434.
process.env.IOI_HYPERVISOR_MODEL_UPSTREAM = "http://127.0.0.1:1/v1";
delete process.env.IOI_HYPERVISOR_REPLAY_MODE;

const { startHypervisorAppDevReplayServer } = await import(
  "../hypervisor-app-dev-replay-server.mjs"
);

async function readSessionTurnStream(endpoint, body) {
  const response = await fetch(`${endpoint}/v1/hypervisor/session-turns`, {
    method: "POST",
    headers: { "content-type": "application/json", accept: "text/event-stream" },
    body: JSON.stringify(body),
  });
  assert.equal(response.status, 200);
  return await response.text();
}

test("Hypervisor app dev replay server exposes route-backed demo families", async () => {
  const replay = await startHypervisorAppDevReplayServer({ port: 0 });
  try {
    const status = await fetch(`${replay.endpoint}/v1/hypervisor/dev-replay/status`).then(
      (response) => response.json(),
    );
    assert.equal(status.status, "ready");
    assert.match(status.boundary, /development replay scaffold/);

    const modelSnapshot = await fetch(`${replay.endpoint}/v1/model-mount/snapshot`).then(
      (response) => response.json(),
    );
    assert.equal(modelSnapshot.routes[0].id, "model-route:hypervisor/default-local");

    const authorityEvidence = await fetch(`${replay.endpoint}/v1/authority-evidence`).then(
      (response) => response.json(),
    );
    assert.equal(authorityEvidence.summaries[0].status, "admitted");

    const workbenchSnapshot = await fetch(
      `${replay.endpoint}/v1/hypervisor/workbench/snapshot`,
    ).then((response) => response.json());
    assert.equal(workbenchSnapshot.project_id, "hypervisor-core");
    assert.ok(workbenchSnapshot.snapshot.tree.length > 0);

    const coldProjects = await fetch(`${replay.endpoint}/v1/hypervisor/projects`).then(
      (response) => response.json(),
    );
    assert.equal(coldProjects.selected_project_id, "");
    assert.equal(coldProjects.records.length, 0);
    assert.match(coldProjects.project_boundary_invariant, /Core is runtime substrate, not a user project/);

    const createResponse = await fetch(`${replay.endpoint}/v1/hypervisor/projects`, {
      body: JSON.stringify({
        repository_url: "https://github.com/teamioitest/ioi",
        project_name: "ioi",
        source: "manual_url",
        environment_class_refs: ["environment-class:local-dev-replay"],
      }),
      headers: { "content-type": "application/json" },
      method: "POST",
    });
    assert.equal(createResponse.status, 201);
    const createdProjects = await createResponse.json();
    assert.equal(createdProjects.selected_project_id, "ioi");
    assert.equal(createdProjects.records.length, 1);
    assert.equal(createdProjects.records[0].name, "ioi");
    assert.equal(
      createdProjects.records[0].repository_url,
      "https://github.com/teamioitest/ioi",
    );

    const bridgeSnapshot = await fetch(
      `${replay.endpoint}/v1/hypervisor/dev-host-bridge/invoke`,
      {
        body: JSON.stringify({
          command: "chat_workspace_inspect",
          args: { root: "/workspace/ioi" },
        }),
        headers: { "content-type": "application/json" },
        method: "POST",
      },
    ).then((response) => response.json());
    assert.equal(bridgeSnapshot.displayName, "Hypervisor Core");

    const sessionEvents = await fetch(
      `${replay.endpoint}/v1/hypervisor/sessions/dev-replay/events`,
    ).then((response) => response.text());
    assert.match(sessionEvents, /event: session_state/);
    assert.match(sessionEvents, /event: terminal_chunk/);

    const evidence = await fetch(
      `${replay.endpoint}/v1/hypervisor/dev-replay/evidence`,
    ).then((response) => response.json());
    assert.ok(evidence.route_families.models >= 1);
    assert.ok(evidence.route_families.workbench >= 1);
    assert.ok(evidence.route_families.sessions >= 1);
  } finally {
    await replay.close();
  }
});

test("session turn returns an honest no-model-route error (no silent prose) when no model is reachable and replay mode is off", async () => {
  const replay = await startHypervisorAppDevReplayServer({ port: 0 });
  try {
    const stream = await readSessionTurnStream(replay.endpoint, {
      session_ref: "session:test",
      model_name: "qwen",
      harness_selection_ref: "agent-harness-adapter:codex_cli",
      messages: [
        {
          role: "user",
          content: "create a website that explains post-quantum computers",
        },
      ],
    });
    // No silent prose: the deterministic "Plan:" turn must NOT be streamed.
    assert.doesNotMatch(stream, /Plan:/);
    assert.doesNotMatch(stream, /governed dev-replay turn/);
    // An actionable error event is emitted instead.
    assert.match(stream, /event: error/);
    assert.match(stream, /"code":"no_model_route"/);
    assert.match(stream, /IOI_HYPERVISOR_REPLAY_MODE/);
    // turn_start advertises the honest source and replay_mode=false.
    assert.match(stream, /"source":"no_model_route"/);
    assert.match(stream, /"replay_mode":false/);
  } finally {
    await replay.close();
  }
});

test("session turn streams the deterministic replay turn only when replay mode is explicitly enabled", async () => {
  process.env.IOI_HYPERVISOR_REPLAY_MODE = "1";
  // Re-evaluate the module with replay mode on (query string busts the cache).
  const { startHypervisorAppDevReplayServer: startReplayModeServer } =
    await import("../hypervisor-app-dev-replay-server.mjs?replay=on");
  const replay = await startReplayModeServer({ port: 0 });
  try {
    const stream = await readSessionTurnStream(replay.endpoint, {
      session_ref: "session:test",
      model_name: "qwen",
      harness_selection_ref: "agent-harness-adapter:codex_cli",
      messages: [
        {
          role: "user",
          content: "create a website that explains post-quantum computers",
        },
      ],
    });
    // With replay mode explicitly enabled the deterministic turn streams.
    assert.match(stream, /Plan:/);
    assert.match(stream, /"source":"deterministic_replay"/);
    assert.doesNotMatch(stream, /"code":"no_model_route"/);
  } finally {
    delete process.env.IOI_HYPERVISOR_REPLAY_MODE;
    await replay.close();
  }
});
