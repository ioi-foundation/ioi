import assert from "node:assert/strict";
import test from "node:test";

import {
  HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE,
  HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_PATH,
  loadHypervisorAutomationCompositorProjection,
  normalizeHypervisorAutomationCompositorProjection,
} from "./hypervisorAutomationCompositorModel.ts";

test("automation compositor projection binds templates, graphs, runs, and receipts", () => {
  const projection = HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE;

  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.automation_compositor_projection.v1",
  );
  assert.equal(projection.source, "fixture");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.match(projection.compositor_boundary_invariant, /edits and proposes/);
  assert.match(projection.compositor_boundary_invariant, /Hypervisor Core admits execution/);
  assert.match(projection.compositor_boundary_invariant, /Agentgres records/);
  assert.ok(projection.workflow_template_refs.length >= 3);
  assert.ok(projection.run_recipe_refs.length >= 3);
  assert.ok(projection.graph_refs.length >= 3);
  assert.ok(projection.latest_receipt_refs.length >= 3);
  assert.ok(
    projection.agentgres_operation_refs.every((ref) =>
      ref.startsWith("agentgres://operation/workflow/"),
    ),
  );
  assert.match(projection.state_root_ref, /^agentgres:\/\/state-root\/workflow-compositor\//);
});

test("automation compositor fixture keeps run recipes authority scoped and receipt bound", () => {
  const projection = HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE;

  for (const template of projection.templates) {
    assert.ok(template.template_ref.startsWith("workflow-template:"));
    assert.ok(template.graph_ref.startsWith("workflow://graph/"));
    assert.ok(template.recipe_ref.startsWith("run-recipe:"));
    assert.ok(
      template.required_scope_refs.every((scopeRef) =>
        scopeRef.startsWith("scope:"),
      ),
    );
    assert.ok(template.receipt_policy_ref.startsWith("receipt-policy:"));
    assert.ok(template.latest_receipt_refs.length >= 1);
  }

  for (const recipe of projection.run_recipes) {
    assert.ok(recipe.run_recipe_ref.startsWith("run-recipe:"));
    assert.ok(recipe.launch_action_ref.startsWith("action://workflow/"));
    assert.ok(
      recipe.authority_scope_refs.every((scopeRef) =>
        scopeRef.startsWith("scope:"),
      ),
    );
    assert.ok(recipe.receipt_refs.every((ref) => ref.startsWith("receipt://")));
  }
});

test("automation compositor normalization preserves daemon refs", () => {
  const projection = normalizeHypervisorAutomationCompositorProjection(
    {
      projection_id: "automation-compositor:daemon/normalized",
      selected_project_id: "project:ioi",
      compositor_boundary_invariant:
        "Workflow Compositor proposes and daemon admits execution.",
      workflow_template_refs: ["workflow-template:normalized"],
      run_recipe_refs: ["run-recipe:normalized/manual"],
      graph_refs: ["workflow://graph/normalized"],
      templates: [
        {
          template_ref: "workflow-template:normalized",
          label: "Normalized",
          description: "Daemon-projected template",
          graph_ref: "workflow://graph/normalized",
          recipe_ref: "run-recipe:normalized/manual",
          required_scope_refs: ["scope:workflow.run"],
          model_route_policy_ref: "model-route-policy:daemon",
          receipt_policy_ref: "receipt-policy:workflow/daemon",
          latest_receipt_refs: ["receipt://workflow/daemon"],
        },
      ],
      run_recipes: [
        {
          run_recipe_ref: "run-recipe:normalized/manual",
          template_ref: "workflow-template:normalized",
          label: "Manual",
          schedule_ref: "schedule:manual",
          launch_action_ref: "action://workflow/normalized/launch",
          authority_scope_refs: ["scope:workflow.run"],
          receipt_refs: ["receipt://workflow/daemon"],
        },
      ],
      graphs: [
        {
          graph_ref: "workflow://graph/normalized",
          label: "Graph",
          node_count: 2,
          edge_count: 1,
          context_chamber_refs: ["chamber://workflow/normalized"],
          artifact_refs: ["artifact://workflow/normalized/graph"],
          receipt_refs: ["receipt://workflow/daemon"],
        },
      ],
      runs: [
        {
          run_ref: "workflow-run:normalized/latest",
          template_ref: "workflow-template:normalized",
          status: "running",
          action_proposal_ref: "action://workflow/normalized/launch",
          agentgres_operation_ref:
            "agentgres://operation/workflow/normalized/run",
          state_root_ref: "agentgres://state-root/workflow/normalized",
          latest_receipt_ref: "receipt://workflow/daemon",
        },
      ],
      latest_receipt_refs: ["receipt://workflow/daemon"],
      agentgres_operation_refs: [
        "agentgres://operation/workflow/normalized/run",
      ],
      state_root_ref: "agentgres://state-root/workflow/normalized",
    },
    { source: "daemon-automation-compositor-projection" },
  );

  assert.equal(projection.source, "daemon-automation-compositor-projection");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.equal(
    projection.projection_id,
    "automation-compositor:daemon/normalized",
  );
  assert.equal(projection.selected_project_id, "project:ioi");
  assert.equal(projection.templates[0]?.template_ref, "workflow-template:normalized");
  assert.equal(projection.run_recipes[0]?.launch_action_ref, "action://workflow/normalized/launch");
  assert.equal(projection.graphs[0]?.node_count, 2);
  assert.equal(projection.runs[0]?.status, "running");
  assert.equal(
    projection.agentgres_operation_refs[0],
    "agentgres://operation/workflow/normalized/run",
  );
});

test("automation compositor loader calls the daemon projection route with selected project", async () => {
  const calls: Array<{ input: string; method?: string }> = [];
  const projection = await loadHypervisorAutomationCompositorProjection({
    endpoint: "http://daemon.test/",
    projectId: "project:ioi",
    fetchImpl: async (input, init) => {
      calls.push({ input, method: init?.method });
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            projection_id: "automation-compositor:daemon/loaded",
            selected_project_id: "project:ioi",
            templates: [
              {
                template_ref: "workflow-template:loaded",
                label: "Loaded",
                latest_receipt_refs: ["receipt://workflow/loaded"],
              },
            ],
            latest_receipt_refs: ["receipt://workflow/loaded"],
          });
        },
      };
    },
  });

  assert.deepEqual(calls, [
    {
      input:
        `http://daemon.test${HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_PATH}?project_id=project%3Aioi`,
      method: "GET",
    },
  ]);
  assert.equal(projection.source, "daemon-automation-compositor-projection");
  assert.equal(projection.projection_id, "automation-compositor:daemon/loaded");
  assert.equal(projection.selected_project_id, "project:ioi");
  assert.equal(projection.templates[0]?.template_ref, "workflow-template:loaded");
  assert.deepEqual(projection.latest_receipt_refs, [
    "receipt://workflow/loaded",
  ]);
});
