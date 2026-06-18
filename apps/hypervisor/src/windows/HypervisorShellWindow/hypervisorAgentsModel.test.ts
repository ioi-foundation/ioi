import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_AGENTS_PROJECTION_FIXTURE,
  loadHypervisorAgentsProjection,
  normalizeHypervisorAgentsProjection,
} from "./hypervisorAgentsModel.ts";

test("agents projection models configured runtime actors over Hypervisor Core", () => {
  const projection = HYPERVISOR_AGENTS_PROJECTION_FIXTURE;

  assert.equal(projection.schema_version, "ioi.hypervisor.agents_projection.v1");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.match(projection.boundary_invariant, /Hypervisor Daemon remains runtime truth/);
  assert.match(projection.memory_invariant, /Agent Wiki \/ ioi-memory owns semantic memory/);
  assert.match(projection.capability_invariant, /wallet.network capability leases/);
  assert.equal(projection.records.length, 3);

  const quant = projection.records.find(
    (agent) => agent.agent_ref === "agent:quant-research-private",
  );
  assert.ok(quant);
  assert.equal(quant.runtime.truth_boundary, "daemon_owned");
  assert.equal(quant.runtime.privacy_posture_ref, "privacy:ctee-private-workspace");
  assert.ok(
    quant.memory_bindings.some(
      (memory) =>
        memory.owner === "agent_wiki_ioi_memory" &&
        memory.scope === "workspace_bound",
    ),
  );
  assert.ok(
    quant.capability_leases.every((lease) =>
      lease.wallet_authority_scope_refs.every((scope) =>
        scope.startsWith("scope:"),
      ),
    ),
  );
  assert.match(quant.state_root_ref, /^agentgres:\/\/state-root\//);
  assert.ok(quant.latest_receipt_refs.length > 0);
});

test("agents projection preserves external harnesses as proposal sources", () => {
  const projection = HYPERVISOR_AGENTS_PROJECTION_FIXTURE;
  const externalAgents = projection.records.filter(
    (agent) => agent.runtime.truth_boundary === "proposal_source_only",
  );

  assert.ok(externalAgents.length >= 2);
  assert.ok(
    externalAgents.every((agent) =>
      agent.runtime.harness_selection_ref.startsWith("agent-harness-adapter:"),
    ),
  );
  assert.ok(
    externalAgents.every((agent) =>
      agent.agentgres_operation_refs.every((ref) =>
        ref.startsWith("agentgres://operation/"),
      ),
    ),
  );
});

test("agents projection normalizes Rust lifecycle agent rows", () => {
  const projection = normalizeHypervisorAgentsProjection(
    [
      {
        id: "agent_one",
        title: "Repair failing build",
        status: "running",
        workspace: "/workspace/ioi",
        thread_id: "thread:agent_one",
        model_route_id: "model-route:hypervisor/default-local",
        runtime_profile: "Default Harness Profile",
        memory_count: 4,
        evidence_refs: ["receipt://agent/one/latest"],
      },
    ],
    {
      source: "daemon-agents-projection",
      selectedProjectRef: "project:ioi",
    },
  );

  assert.equal(projection.source, "daemon-agents-projection");
  assert.equal(projection.selected_project_ref, "project:ioi");
  assert.equal(projection.records.length, 1);
  assert.equal(projection.records[0]?.agent_ref, "agent_one");
  assert.equal(projection.records[0]?.status, "running");
  assert.equal(projection.records[0]?.workspace_ref, "/workspace/ioi");
  assert.equal(
    projection.records[0]?.runtime.model_route_ref,
    "model-route:hypervisor/default-local",
  );
  assert.equal(
    projection.records[0]?.memory_bindings[0]?.label,
    "4 daemon memory records",
  );
  assert.deepEqual(projection.records[0]?.latest_receipt_refs, [
    "receipt://agent/one/latest",
  ]);
});

test("agents projection loader calls the Hypervisor daemon route", async () => {
  const requests: Array<{ input: string; init?: unknown }> = [];
  const projection = await loadHypervisorAgentsProjection({
    endpoint: "http://daemon.test/",
    projectId: "project:ioi",
    fetchImpl: async (input, init) => {
      requests.push({ input, init });
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            projection_id: "agents:daemon/test",
            selected_project_ref: "project:ioi",
            records: [
              {
                agent_ref: "agent:daemon",
                label: "Daemon agent",
                status: "idle",
              },
            ],
          });
        },
      };
    },
  });

  assert.equal(
    requests[0]?.input,
    "http://daemon.test/v1/hypervisor/agents?project_id=project%3Aioi",
  );
  assert.equal(projection.projection_id, "agents:daemon/test");
  assert.equal(projection.records[0]?.agent_ref, "agent:daemon");
});
