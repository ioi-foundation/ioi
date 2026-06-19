import assert from "node:assert/strict";
import test from "node:test";

import {
  buildHypervisorAutomationRunProposal,
  HYPERVISOR_AUTOMATION_COMPOSITOR_CLEAN_BOOT_PROJECTION,
  HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE,
  HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_PATH,
  HYPERVISOR_AUTOMATION_RUN_PROPOSAL_PATH,
  loadHypervisorAutomationCompositorProjection,
  normalizeHypervisorAutomationCompositorProjection,
  normalizeHypervisorAutomationRunProposal,
  proposeHypervisorAutomationRun,
} from "./hypervisorAutomationCompositorModel.ts";

test("automation compositor clean boot starts with no admitted automations", () => {
  const projection = HYPERVISOR_AUTOMATION_COMPOSITOR_CLEAN_BOOT_PROJECTION;

  assert.equal(
    projection.schema_version,
    "ioi.hypervisor.automation_compositor_projection.v1",
  );
  assert.equal(projection.source, "fixture");
  assert.equal(projection.projection_id, "automation-compositor:clean-boot/empty");
  assert.equal(projection.runtimeTruthSource, "daemon-runtime");
  assert.equal(projection.templates.length, 0);
  assert.equal(projection.run_recipes.length, 0);
  assert.equal(projection.graphs.length, 0);
  assert.equal(projection.runs.length, 0);
  assert.equal(projection.latest_receipt_refs.length, 0);
  assert.match(projection.compositor_boundary_invariant, /edits and proposes/);
});

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

test("automation compositor normalization preserves explicit empty daemon arrays", () => {
  const projection = normalizeHypervisorAutomationCompositorProjection(
    {
      projection_id: "automation-compositor:daemon/empty",
      selected_project_id: "project:empty",
      templates: [],
      run_recipes: [],
      graphs: [],
      runs: [],
    },
    { source: "daemon-automation-compositor-projection" },
  );

  assert.equal(projection.projection_id, "automation-compositor:daemon/empty");
  assert.equal(projection.source, "daemon-automation-compositor-projection");
  assert.equal(projection.templates.length, 0);
  assert.equal(projection.run_recipes.length, 0);
  assert.equal(projection.graphs.length, 0);
  assert.equal(projection.runs.length, 0);
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

test("automation run proposal binds recipe execution to wallet and Agentgres refs", () => {
  const projection = HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE;
  const template = projection.templates[0]!;
  const recipe = projection.run_recipes[0]!;
  const graph = projection.graphs[0]!;
  const proposal = buildHypervisorAutomationRunProposal(
    projection,
    template,
    recipe,
    graph,
  );

  assert.equal(
    proposal.schema_version,
    "ioi.hypervisor.automation_run_proposal.v1",
  );
  assert.equal(proposal.source, "fixture");
  assert.equal(proposal.selected_project_id, projection.selected_project_id);
  assert.equal(proposal.template_ref, template.template_ref);
  assert.equal(proposal.run_recipe_ref, recipe.run_recipe_ref);
  assert.equal(proposal.graph_ref, graph.graph_ref);
  assert.equal(proposal.launch_action_ref, recipe.launch_action_ref);
  assert.equal(proposal.operation_kind, "run_now");
  assert.equal(proposal.admission_state, "ready_for_daemon_admission");
  assert.ok(proposal.wallet_lease_ref.startsWith("lease:wallet/automation/"));
  assert.deepEqual(proposal.required_scope_refs, recipe.authority_scope_refs);
  assert.equal(proposal.action_proposal_ref, recipe.launch_action_ref);
  assert.ok(
    proposal.agentgres_operation_ref.startsWith(
      "agentgres://operation/automation/",
    ),
  );
  assert.ok(proposal.receipt_ref.startsWith("receipt://automation/"));
  assert.equal(proposal.state_root_ref, projection.state_root_ref);
  assert.deepEqual(proposal.context_chamber_refs, graph.context_chamber_refs);
  assert.deepEqual(proposal.artifact_refs, graph.artifact_refs);
  assert.match(proposal.run_boundary_invariant, /not execution/);
});

test("automation run proposal normalization preserves daemon admission envelope", () => {
  const projection = HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE;
  const template = projection.templates[1]!;
  const recipe = projection.run_recipes[1]!;
  const graph = projection.graphs[1]!;
  const proposal = normalizeHypervisorAutomationRunProposal(
    {
      proposal_ref: "automation-run:daemon/private-backtest",
      source: "daemon-automation-run-proposal",
      selected_project_id: "project:ioi",
      template_ref: template.template_ref,
      run_recipe_ref: recipe.run_recipe_ref,
      graph_ref: graph.graph_ref,
      launch_action_ref: recipe.launch_action_ref,
      operation_kind: "schedule_run",
      admission_state: "requires_wallet_lease",
      wallet_lease_ref: "lease:wallet/automation/private-backtest",
      required_scope_refs: ["scope:workflow.run", "scope:provider.spend"],
      action_proposal_ref: recipe.launch_action_ref,
      agentgres_operation_ref:
        "agentgres://operation/automation/private-backtest/schedule",
      receipt_ref: "receipt://automation/private-backtest/schedule",
      state_root_ref: "agentgres://state-root/automation/private-backtest",
      context_chamber_refs: ["chamber://automation/private-backtest"],
      artifact_refs: ["artifact://automation/private-backtest/graph"],
      latest_receipt_refs: ["receipt://automation/private-backtest"],
      run_boundary_invariant:
        "Workflow compositor proposes; daemon admits; Agentgres records.",
    },
    {
      projection,
      template,
      recipe,
      graph,
      operationKind: "schedule_run",
    },
  );

  assert.equal(proposal.source, "daemon-automation-run-proposal");
  assert.equal(proposal.proposal_ref, "automation-run:daemon/private-backtest");
  assert.equal(proposal.operation_kind, "schedule_run");
  assert.equal(proposal.admission_state, "requires_wallet_lease");
  assert.deepEqual(proposal.required_scope_refs, [
    "scope:workflow.run",
    "scope:provider.spend",
  ]);
  assert.equal(
    proposal.agentgres_operation_ref,
    "agentgres://operation/automation/private-backtest/schedule",
  );
});

test("automation run proposal client posts canonical request to daemon", async () => {
  const projection = HYPERVISOR_AUTOMATION_COMPOSITOR_PROJECTION_FIXTURE;
  const template = projection.templates[0]!;
  const recipe = projection.run_recipes[0]!;
  const graph = projection.graphs[0]!;
  const calls: Array<{ input: string; method?: string; body?: string }> = [];
  const proposal = await proposeHypervisorAutomationRun({
    endpoint: "http://daemon.test/",
    projection,
    template,
    recipe,
    graph,
    fetchImpl: async (input, init) => {
      calls.push({ input, method: init?.method, body: init?.body });
      return {
        ok: true,
        status: 200,
        async text() {
          return JSON.stringify({
            proposal_ref: "automation-run:daemon/mission",
            source: "daemon-automation-run-proposal",
            selected_project_id: projection.selected_project_id,
            template_ref: template.template_ref,
            run_recipe_ref: recipe.run_recipe_ref,
            graph_ref: graph.graph_ref,
            launch_action_ref: recipe.launch_action_ref,
            operation_kind: "run_now",
            admission_state: "ready_for_daemon_admission",
            wallet_lease_ref: "lease:wallet/automation/mission",
            required_scope_refs: recipe.authority_scope_refs,
            action_proposal_ref: recipe.launch_action_ref,
            agentgres_operation_ref:
              "agentgres://operation/automation/mission/run",
            receipt_ref: "receipt://automation/mission/run",
            state_root_ref: projection.state_root_ref,
            context_chamber_refs: graph.context_chamber_refs,
            artifact_refs: graph.artifact_refs,
            latest_receipt_refs: recipe.receipt_refs,
            run_boundary_invariant:
              "Workflow compositor proposes; daemon admits; Agentgres records.",
          });
        },
      };
    },
  });

  assert.equal(calls.length, 1);
  assert.equal(
    calls[0]?.input,
    `http://daemon.test${HYPERVISOR_AUTOMATION_RUN_PROPOSAL_PATH}`,
  );
  assert.equal(calls[0]?.method, "POST");
  assert.deepEqual(JSON.parse(calls[0]?.body ?? "{}"), {
    selected_project_id: projection.selected_project_id,
    template_ref: template.template_ref,
    run_recipe_ref: recipe.run_recipe_ref,
    graph_ref: graph.graph_ref,
    launch_action_ref: recipe.launch_action_ref,
    operation_kind: "run_now",
    required_scope_refs: recipe.authority_scope_refs,
    model_route_policy_ref: template.model_route_policy_ref,
    receipt_policy_ref: template.receipt_policy_ref,
    context_chamber_refs: graph.context_chamber_refs,
    artifact_refs: graph.artifact_refs,
    latest_receipt_refs: [
      ...recipe.receipt_refs,
      ...template.latest_receipt_refs,
    ].filter((ref, index, refs) => refs.indexOf(ref) === index),
    state_root_ref: projection.state_root_ref,
  });
  assert.equal(proposal.source, "daemon-automation-run-proposal");
  assert.equal(proposal.proposal_ref, "automation-run:daemon/mission");
  assert.equal(proposal.operation_kind, "run_now");
});
