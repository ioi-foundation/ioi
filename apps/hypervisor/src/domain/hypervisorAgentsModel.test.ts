import assert from "node:assert/strict";
import test from "node:test";

import {
  buildWorkerPackageInstallAdmissionRequest,
  HYPERVISOR_AGENTS_PROJECTION_FIXTURE,
  HYPERVISOR_WORKER_PACKAGE_INSTALL_ADMISSION_PATH,
  loadHypervisorAgentsProjection,
  normalizeHypervisorAgentsProjection,
  requestWorkerPackageInstallAdmission,
} from "./hypervisorAgentsModel.ts";

test("agents projection models configured workers without product-surface doctrine", () => {
  const projection = HYPERVISOR_AGENTS_PROJECTION_FIXTURE;

  assert.equal(projection.schema_version, "ioi.hypervisor.agents_projection.v1");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.equal(projection.projection_id, "agents:hypervisor/default");
  assert.equal(projection.selected_project_ref, "project:hypervisor");
  assert.match(projection.boundary_invariant, /Hypervisor admits sessions, gates, receipts, and replay/);
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
    "4 memory records",
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
                agent_ref: "agent:hypervisor/test",
                label: "Managed agent",
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
  assert.equal(projection.records[0]?.agent_ref, "agent:hypervisor/test");
  assert.doesNotMatch(
    JSON.stringify(projection.records),
    /Daemon agent|Daemon worker|runtime truth/i,
  );
});

test("worker package install admission request preserves prim and scope boundaries", () => {
  const agent = HYPERVISOR_AGENTS_PROJECTION_FIXTURE.records[0];
  assert.ok(agent);

  const request = buildWorkerPackageInstallAdmissionRequest(agent, {
    ownerRef: "wallet://user/test",
  });

  assert.equal(request.install_id, "install://aiagent/quant-research-private/managed");
  assert.equal(request.owner_ref, "wallet://user/test");
  assert.equal(request.install_mode, "managed_instance_initialization");
  assert.equal(request.base_ontology_ref, "ontology:aiagent.base.v1");
  assert.equal(request.runtime_profile, "private_workspace_ctee");
  assert.ok(request.policy_profile_refs.includes("policy://ctee/private-workspace"));
  assert.ok(
    request.primitive_capability_requirements.every((capability) =>
      capability.startsWith("prim:"),
    ),
  );
  assert.ok(
    request.authority_scope_requirements.every((scope) =>
      scope.startsWith("scope:"),
    ),
  );
  assert.ok(
    request.agentgres_operation_refs.every((ref) =>
      ref.startsWith("agentgres://operation/"),
    ),
  );
  assert.ok(request.receipt_refs.length > 0);
  assert.equal(request.managed_instance_ref, "agent://quant-research-private");
});

test("worker package install admission client posts to daemon route", async () => {
  const agent = HYPERVISOR_AGENTS_PROJECTION_FIXTURE.records[1];
  assert.ok(agent);
  const requests: Array<{ input: string; init?: { body?: string } }> = [];

  const admission = await requestWorkerPackageInstallAdmission({
    agent,
    endpoint: "http://daemon.test/",
    fetchImpl: async (input, init) => {
      requests.push({ input, init });
      return {
        ok: true,
        status: 202,
        async text() {
          return JSON.stringify({
            schema_version: "ioi.runtime.worker_package_install_admission.v1",
            admission_id: "worker-package-install:test",
            install_id: "install://aiagent/discord-community-steward/managed",
            worker_package_ref: "package://aiagent/discord-community-steward@1",
            decision: "admitted",
            requiresDaemonGate: true,
            runtimeTruthSource: "daemon-runtime",
          });
        },
      };
    },
  });

  assert.equal(
    requests[0]?.input,
    `http://daemon.test${HYPERVISOR_WORKER_PACKAGE_INSTALL_ADMISSION_PATH}`,
  );
  const body = JSON.parse(requests[0]?.init?.body ?? "{}");
  assert.equal(body.install_id, "install://aiagent/discord-community-steward/managed");
  assert.equal(body.runtime_profile, "local");
  assert.deepEqual(body.physical_action_policy_refs, []);
  assert.equal(admission.decision, "admitted");
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");
});
