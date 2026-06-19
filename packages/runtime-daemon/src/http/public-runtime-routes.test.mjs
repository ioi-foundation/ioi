import assert from "node:assert/strict";
import test from "node:test";

import { createPublicRuntimeRequestHandler } from "./public-runtime-routes.mjs";

function responseRecorder() {
  return {
    headers: {},
    statusCode: 200,
    ended: false,
    body: null,
    setHeader(name, value) {
      this.headers[name.toLowerCase()] = value;
    },
    end(value = "") {
      this.ended = true;
      this.body = value;
    },
  };
}

function request({ method = "GET", url = "/", body = {} } = {}) {
  return {
    method,
    url,
    headers: {},
    body,
  };
}

function retiredRouteWrapper() {
  throw new Error("retired public runtime route wrapper must not be routed");
}

function routeHarness(overrides = {}) {
  const calls = [];
  const deps = {
    RUNTIME_USAGE_TELEMETRY_SCHEMA_VERSION: "usage.v.test",
    baseUrlForRequest: () => "http://daemon.test",
    handleAgentRoute: async () => calls.push("agent"),
    handleModelMountingNativeRoute: async () => calls.push("model-native"),
    handleOpenAiCompatibilityRoute: async () => calls.push("openai"),
    handleRunRoute: async () => calls.push("run"),
    handleThreadRoute: async () => calls.push("thread"),
    isOpenAiCompatibilityRoute: () => false,
    normalizeBooleanOption: (value, fallback) => (value == null ? fallback : value !== "false" && value !== "0"),
    notFound: (message, details) => {
      const error = new Error(message);
      error.details = details;
      throw error;
    },
    optionalString: (value) => {
      const text = typeof value === "string" ? value.trim() : "";
      return text || null;
    },
    readBody: async (req) => req.body ?? {},
    runtimeError: (error) => Object.assign(new Error(error.message), error),
    usageRequestMetadataFromUrl: () => ({ requestMetadata: true }),
    usageTelemetryWithRequestMetadata: (payload, metadata) => ({ payload, metadata }),
    writeError: (response, error) => {
      response.statusCode = error.status ?? 500;
      response.error = error;
      response.end(JSON.stringify({ error: error.code ?? error.message }));
    },
    writeJsonResponse: (response, payload, status = 200) => {
      response.statusCode = status;
      response.setHeader("content-type", "application/json");
      response.end(JSON.stringify(payload));
    },
    writeMcpJsonRpcResponse: (response, payload) => {
      response.statusCode = 200;
      response.end(JSON.stringify(payload));
    },
    ...overrides,
  };
  return {
    calls,
    handleRequest: createPublicRuntimeRequestHandler(deps),
  };
}

test("public runtime routes answer CORS preflight without store access", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({ request: request({ method: "OPTIONS", url: "/v1/doctor" }), response, store: null });

  assert.equal(response.statusCode, 204);
  assert.equal(response.ended, true);
  assert.equal(response.headers["access-control-allow-origin"], "*");
  assert.match(response.headers["x-request-id"], /^req_/);
});

test("public runtime routes dispatch top-level daemon projections", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const contextPolicyCore = {
    projectRuntimeDoctorReport(request) {
      calls.push({ method: "projectRuntimeDoctorReport", request });
      return { report: { ok: true, baseUrl: request.base_url } };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    runtimeDoctorReport: retiredRouteWrapper,
    doctorReport: retiredRouteWrapper,
  };

  await handleRequest({ request: request({ url: "/v1/doctor" }), response, store, contextPolicyCore });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), { ok: true, baseUrl: "http://daemon.test" });
  assert.deepEqual(calls, [{
    method: "projectRuntimeDoctorReport",
    request: {
      operation: "runtime_doctor_report_projection",
      operation_kind: "runtime.doctor_report.projection",
      base_url: "http://daemon.test",
      workspace_root: "/workspace",
      state_dir: "/state",
      home_dir: "/home/operator",
      runtime_schema_version: "ioi.agentgres.runtime.v0",
      source: "public_runtime_routes./v1/doctor",
    },
  }]);
});

test("public runtime routes dispatch Hypervisor home cockpit through lifecycle projection", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const cockpitProjection = {
    schema_version: "ioi.hypervisor.home_cockpit_projection.v1",
    projection_id: "home-cockpit:daemon/test",
    source: "daemon-home-cockpit-projection",
    selected_project_id: "project:ioi",
    runtimeTruthSource: "daemon-runtime",
    boundary_invariant:
      "Home renders daemon evidence projections and does not become runtime truth.",
    metrics: [
      {
        metric_ref: "home-cockpit:session",
        label: "Active session",
        value: "active",
        detail: "session:test",
        surface_ref: "surface:sessions",
        evidence_refs: ["receipt://session/test"],
      },
    ],
  };
  const contextPolicyCore = {
    projectRuntimeLifecycle(request) {
      calls.push({ method: "projectRuntimeLifecycle", request });
      return {
        projection: cockpitProjection,
        record: {
          operation_kind: "runtime.lifecycle_projection.hypervisor_home_cockpit",
          projection_kind: "hypervisor_home_cockpit",
          projection: cockpitProjection,
        },
      };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({ url: "/v1/hypervisor/home-cockpit?project_id=project:ioi" }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), cockpitProjection);
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeLifecycle",
      request: {
        operation: "hypervisor_home_cockpit_projection",
        operation_kind: "runtime.lifecycle_projection.hypervisor_home_cockpit",
        projection_kind: "hypervisor_home_cockpit",
        base_url: "http://daemon.test",
        workspace_root: "/workspace",
        state_dir: "/state",
        home_dir: "/home/operator",
        runtime_schema_version: "ioi.agentgres.runtime.v0",
        project_id: "project:ioi",
        source: "public_runtime_routes./v1/hypervisor/home-cockpit",
      },
    },
  ]);
});

test("public runtime routes dispatch Hypervisor session operations through lifecycle projection", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const sessionProjection = {
    schema_version: "ioi.hypervisor.session_operations_projection.v1",
    projection_id: "hypervisor-session-operations:daemon/test",
    source: "daemon-session-operations-projection",
    selected_session_ref: "session:test",
    lifecycle_state: "active",
    project_ref: "project:ioi",
    environment_ref: "environment:test",
    provider_candidate_ref: "provider:local",
    selected_adapter_ref: "code-editor-adapter:test",
    authority_scope_refs: ["scope:workspace.read"],
    access_lease_ref: "lease:access/test",
    log_lease_ref: "lease:logs/test",
    archive_ref: "artifact://archive/test",
    restore_ref: "agentgres://restore/test",
    session_rail: [],
    detail_tabs: [],
    right_inspector_panels: [],
    bottom_inspector_panels: [],
    ports_services: [],
    tasks: [],
    terminal_events: [],
    latest_receipt_refs: ["receipt://session/test"],
    runtimeTruthSource: "daemon-runtime",
  };
  const contextPolicyCore = {
    projectRuntimeLifecycle(request) {
      calls.push({ method: "projectRuntimeLifecycle", request });
      return {
        projection: sessionProjection,
        record: {
          operation_kind:
            "runtime.lifecycle_projection.hypervisor_session_operations",
          projection_kind: "hypervisor_session_operations",
          projection: sessionProjection,
        },
      };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      url: "/v1/hypervisor/session-operations?project_id=project:ioi&session_ref=session:test",
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), sessionProjection);
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeLifecycle",
      request: {
        operation: "hypervisor_session_operations_projection",
        operation_kind:
          "runtime.lifecycle_projection.hypervisor_session_operations",
        projection_kind: "hypervisor_session_operations",
        base_url: "http://daemon.test",
        workspace_root: "/workspace",
        state_dir: "/state",
        home_dir: "/home/operator",
        runtime_schema_version: "ioi.agentgres.runtime.v0",
        project_id: "project:ioi",
        session_ref: "session:test",
        source: "public_runtime_routes./v1/hypervisor/session-operations",
      },
    },
  ]);
});

test("public runtime routes dispatch Hypervisor project state through lifecycle projection", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const projectStateProjection = {
    schema_version: "ioi.hypervisor.project_state_projection.v1",
    projection_id: "project-state:daemon/test",
    source: "daemon-project-state-projection",
    selected_project_id: "project:ioi",
    records: [
      {
        project_id: "project:ioi",
        name: "IOI",
        description: "Runtime project",
        environment: "local",
        root_path: "/workspace",
        workspace_ref: "workspace://ioi",
        current_session_ref: "session:test",
        environment_ref: "environment:test",
        provider_candidate_ref: "provider:local",
        adapter_preference_ref: "code-editor-adapter:test",
        custody_posture: "local_private",
        restore_state: "active",
        agentgres_object_head_ref: "agentgres://object-head/project:ioi",
        state_root_ref: "agentgres://state-root/project:ioi",
        artifact_refs: ["artifact://project/ioi/workspace-summary"],
        archive_ref: "artifact://agentgres/archive/ioi/latest",
        restore_ref: "agentgres://restore/ioi/latest",
        latest_receipt_refs: ["receipt://project/ioi/state"],
      },
    ],
    project_boundary_invariant:
      "Project state is an admitted Agentgres projection, not client truth.",
    runtimeTruthSource: "daemon-runtime",
  };
  const contextPolicyCore = {
    projectRuntimeLifecycle(request) {
      calls.push({ method: "projectRuntimeLifecycle", request });
      return {
        projection: projectStateProjection,
        record: {
          operation_kind: "runtime.lifecycle_projection.hypervisor_project_state",
          projection_kind: "hypervisor_project_state",
          projection: projectStateProjection,
        },
      };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({ url: "/v1/hypervisor/project-state?project_id=project:ioi" }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), projectStateProjection);
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeLifecycle",
      request: {
        operation: "hypervisor_project_state_projection",
        operation_kind: "runtime.lifecycle_projection.hypervisor_project_state",
        projection_kind: "hypervisor_project_state",
        base_url: "http://daemon.test",
        workspace_root: "/workspace",
        state_dir: "/state",
        home_dir: "/home/operator",
        runtime_schema_version: "ioi.agentgres.runtime.v0",
        project_id: "project:ioi",
        source: "public_runtime_routes./v1/hypervisor/project-state",
      },
    },
  ]);
});

test("public runtime routes expose Hypervisor Core taxonomy", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({ url: "/v1/hypervisor/core-taxonomy" }),
    response,
    store: {
      defaultCwd: "/workspace",
      homeDir: "/home/operator",
      schemaVersion: "ioi.agentgres.runtime.v0",
      stateDir: "/state",
      projectRuntimeLifecycleProjection: retiredRouteWrapper,
    },
  });

  assert.equal(response.statusCode, 200);
  const taxonomy = JSON.parse(response.body);
  assert.equal(
    taxonomy.schema_version,
    "ioi.runtime.hypervisor_core_taxonomy.v1",
  );
  assert.equal(taxonomy.core.execution_owner, "hypervisor-daemon");
  assert.deepEqual(
    taxonomy.first_class_clients.map((client) => client.kind),
    ["app", "web", "cli_headless"],
  );
  assert.ok(
    taxonomy.application_surfaces.some((surface) => surface.id === "workbench"),
  );
  assert.ok(
    taxonomy.adapter_target_families.some(
      (family) => family.id === "code_editor",
    ),
  );
  assert.deepEqual(taxonomy.retired_surface_aliases, [
    {
      alias: "fleet",
      replacement: "sessions/providers/environments",
      reason:
        "Fleet posture is folded into Hypervisor session, provider, and environment management instead of a separate app surface.",
    },
  ]);
  assert.equal(
    taxonomy.agent_harness_adapters[0].authority,
    "proposal_source_only",
  );
});

test("public runtime routes dispatch Hypervisor automation compositor through lifecycle projection", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const automationCompositorProjection = {
    schema_version: "ioi.hypervisor.automation_compositor_projection.v1",
    projection_id: "automation-compositor:daemon/test",
    source: "daemon-automation-compositor-projection",
    selected_project_id: "project:ioi",
    runtimeTruthSource: "daemon-runtime",
    compositor_boundary_invariant:
      "Workflow Compositor proposes graphs; daemon admits execution; Agentgres records truth.",
    workflow_template_refs: ["workflow-template:test"],
    run_recipe_refs: ["run-recipe:test/manual"],
    graph_refs: ["workflow://graph/test"],
    templates: [
      {
        template_ref: "workflow-template:test",
        label: "Test template",
        description: "Test workflow template",
        graph_ref: "workflow://graph/test",
        recipe_ref: "run-recipe:test/manual",
        required_scope_refs: ["scope:workflow.run"],
        model_route_policy_ref: "model-route-policy:test",
        receipt_policy_ref: "receipt-policy:workflow/test",
        latest_receipt_refs: ["receipt://workflow/test"],
      },
    ],
    run_recipes: [
      {
        run_recipe_ref: "run-recipe:test/manual",
        template_ref: "workflow-template:test",
        label: "Manual",
        schedule_ref: "schedule:manual",
        launch_action_ref: "action://workflow/test/launch",
        authority_scope_refs: ["scope:workflow.run"],
        receipt_refs: ["receipt://workflow/test"],
      },
    ],
    graphs: [
      {
        graph_ref: "workflow://graph/test",
        label: "Test graph",
        node_count: 2,
        edge_count: 1,
        context_chamber_refs: ["chamber://workflow/test"],
        artifact_refs: ["artifact://workflow/test/graph"],
        receipt_refs: ["receipt://workflow/test"],
      },
    ],
    runs: [
      {
        run_ref: "workflow-run:test/latest",
        template_ref: "workflow-template:test",
        status: "ready",
        action_proposal_ref: "action://workflow/test/launch",
        agentgres_operation_ref: "agentgres://operation/workflow/test",
        state_root_ref: "agentgres://state-root/workflow/test",
        latest_receipt_ref: "receipt://workflow/test",
      },
    ],
    latest_receipt_refs: ["receipt://workflow/test"],
    agentgres_operation_refs: ["agentgres://operation/workflow/test"],
    state_root_ref: "agentgres://state-root/workflow/test",
  };
  const contextPolicyCore = {
    projectRuntimeLifecycle(request) {
      calls.push({ method: "projectRuntimeLifecycle", request });
      return {
        projection: automationCompositorProjection,
        record: {
          operation_kind:
            "runtime.lifecycle_projection.hypervisor_automation_compositor",
          projection_kind: "hypervisor_automation_compositor",
          projection: automationCompositorProjection,
        },
      };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      url: "/v1/hypervisor/automation-compositor?project_id=project:ioi",
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), automationCompositorProjection);
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeLifecycle",
      request: {
        operation: "hypervisor_automation_compositor_projection",
        operation_kind:
          "runtime.lifecycle_projection.hypervisor_automation_compositor",
        projection_kind: "hypervisor_automation_compositor",
        base_url: "http://daemon.test",
        workspace_root: "/workspace",
        state_dir: "/state",
        home_dir: "/home/operator",
        runtime_schema_version: "ioi.agentgres.runtime.v0",
        project_id: "project:ioi",
        source:
          "public_runtime_routes./v1/hypervisor/automation-compositor",
      },
    },
  ]);
});

test("public runtime routes dispatch Hypervisor automation run proposals through lifecycle admission proposal", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const automationRunProposal = {
    schema_version: "ioi.hypervisor.automation_run_proposal.v1",
    proposal_ref: "automation-run:daemon/mission",
    source: "daemon-automation-run-proposal",
    selected_project_id: "project:ioi",
    template_ref: "workflow-template:test",
    run_recipe_ref: "run-recipe:test/manual",
    graph_ref: "workflow://graph/test",
    launch_action_ref: "action://workflow/test/launch",
    operation_kind: "run_now",
    admission_state: "ready_for_daemon_admission",
    wallet_lease_ref: "lease:wallet/automation/test",
    required_scope_refs: ["scope:workflow.run", "scope:receipt.write"],
    action_proposal_ref: "action://workflow/test/launch",
    agentgres_operation_ref: "agentgres://operation/automation/test/run",
    receipt_ref: "receipt://automation/test/run",
    state_root_ref: "agentgres://state-root/automation/test",
    context_chamber_refs: ["chamber://workflow/test"],
    artifact_refs: ["artifact://workflow/test/graph"],
    latest_receipt_refs: ["receipt://workflow/test"],
    run_boundary_invariant:
      "Workflow compositor proposes; daemon admits; Agentgres records.",
  };
  const contextPolicyCore = {
    projectRuntimeLifecycle(request) {
      calls.push({ method: "projectRuntimeLifecycle", request });
      return { proposal: automationRunProposal };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/automation-runs/proposals",
      body: {
        selected_project_id: "project:ioi",
        template_ref: "workflow-template:test",
        run_recipe_ref: "run-recipe:test/manual",
        graph_ref: "workflow://graph/test",
        launch_action_ref: "action://workflow/test/launch",
        operation_kind: "run_now",
        required_scope_refs: ["scope:workflow.run", "scope:receipt.write"],
        model_route_policy_ref: "model-route-policy:test",
        receipt_policy_ref: "receipt-policy:workflow/test",
        context_chamber_refs: ["chamber://workflow/test"],
        artifact_refs: ["artifact://workflow/test/graph"],
        latest_receipt_refs: ["receipt://workflow/test"],
        state_root_ref: "agentgres://state-root/automation/test",
      },
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), automationRunProposal);
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeLifecycle",
      request: {
        operation: "hypervisor_automation_run_proposal",
        operation_kind:
          "runtime.lifecycle_operation.hypervisor_automation_run_proposal",
        projection_kind: "hypervisor_automation_run_proposal",
        base_url: "http://daemon.test",
        workspace_root: "/workspace",
        state_dir: "/state",
        home_dir: "/home/operator",
        runtime_schema_version: "ioi.agentgres.runtime.v0",
        project_id: "project:ioi",
        template_ref: "workflow-template:test",
        run_recipe_ref: "run-recipe:test/manual",
        graph_ref: "workflow://graph/test",
        launch_action_ref: "action://workflow/test/launch",
        requested_operation: "run_now",
        required_scope_refs: ["scope:workflow.run", "scope:receipt.write"],
        model_route_policy_ref: "model-route-policy:test",
        receipt_policy_ref: "receipt-policy:workflow/test",
        context_chamber_refs: ["chamber://workflow/test"],
        artifact_refs: ["artifact://workflow/test/graph"],
        latest_receipt_refs: ["receipt://workflow/test"],
        state_root_ref: "agentgres://state-root/automation/test",
        source:
          "public_runtime_routes./v1/hypervisor/automation-runs/proposals",
      },
    },
  ]);
});

test("public runtime routes dispatch Hypervisor agents through lifecycle projection", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const agentsProjection = {
    schema_version: "ioi.hypervisor.agents_projection.v1",
    projection_id: "agents:daemon/test",
    source: "daemon-agents-projection",
    selected_project_ref: "project:ioi",
    runtimeTruthSource: "daemon-runtime",
    records: [
      {
        agent_ref: "agent:daemon",
        label: "Daemon agent",
        status: "running",
      },
    ],
  };
  const contextPolicyCore = {
    projectRuntimeLifecycle(request) {
      calls.push({ method: "projectRuntimeLifecycle", request });
      return {
        projection: agentsProjection,
        record: {
          operation_kind: "runtime.lifecycle_projection.hypervisor_agents",
          projection_kind: "agents",
          projection: agentsProjection,
        },
      };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      url: "/v1/hypervisor/agents?project_id=project:ioi",
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), agentsProjection);
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeLifecycle",
      request: {
        operation: "hypervisor_agents_projection",
        operation_kind: "runtime.lifecycle_projection.hypervisor_agents",
        projection_kind: "agents",
        base_url: "http://daemon.test",
        workspace_root: "/workspace",
        state_dir: "/state",
        home_dir: "/home/operator",
        runtime_schema_version: "ioi.agentgres.runtime.v0",
        project_id: "project:ioi",
        source: "public_runtime_routes./v1/hypervisor/agents",
      },
    },
  ]);
});

test("public runtime routes dispatch Hypervisor model infrastructure through lifecycle projection", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const modelInfrastructureProjection = {
    schema_version: "ioi.hypervisor.model_infrastructure_projection.v1",
    projection_id: "model-infrastructure:daemon/test",
    source: "daemon-model-infrastructure-projection",
    selected_project_id: "project:ioi",
    selected_session_ref: "session:ioi",
    runtimeTruthSource: "daemon-runtime",
    infrastructure_boundary_invariant:
      "Models renders daemon model-route projections; daemon admits execution; Agentgres records truth.",
    inventory_source: "daemon-model-mount-inventory",
    checked_at: "2026-06-17T00:00:00.000Z",
    model_route_refs: ["model-route:daemon/default"],
    endpoint_refs: ["model-endpoint:daemon/default"],
    loaded_instance_refs: ["model-instance:daemon/default"],
    provider_refs: ["provider:daemon-local"],
    routes: [
      {
        route_ref: "model-route:daemon/default",
        role: "default",
        status: "active",
        privacy_posture: "local",
        provider_ref: "provider:daemon-local",
        endpoint_refs: ["model-endpoint:daemon/default"],
        loaded_instance_refs: ["model-instance:daemon/default"],
        model_weight_custody_lane: "local_or_open_weight",
        authority_scope_refs: ["scope:model.invoke"],
        receipt_refs: ["receipt://model/daemon"],
      },
    ],
    providers: [
      {
        provider_ref: "provider:daemon-local",
        label: "Daemon local provider",
        provider_kind: "local",
        privacy_posture: "local",
        credential_scope_refs: ["scope:secret.use"],
        receipt_ref: "receipt://provider/daemon-local",
      },
    ],
    session_bindings: [
      {
        session_ref: "session:ioi",
        selected_model_route_ref: "model-route:daemon/default",
        selected_endpoint_ref: "model-endpoint:daemon/default",
        selected_instance_ref: "model-instance:daemon/default",
        custody_profile_ref: "custody-profile:model/local",
        policy_ref: "policy:model-route/session-default",
        receipt_ref: "receipt://model/session",
      },
    ],
    model_weight_custody_policy_refs: [
      "model-weight-custody:local_or_open_weight",
    ],
    latest_receipt_refs: ["receipt://model/session"],
  };
  const contextPolicyCore = {
    projectRuntimeLifecycle(request) {
      calls.push({ method: "projectRuntimeLifecycle", request });
      return {
        projection: modelInfrastructureProjection,
        record: {
          operation_kind:
            "runtime.lifecycle_projection.hypervisor_model_infrastructure",
          projection_kind: "hypervisor_model_infrastructure",
          projection: modelInfrastructureProjection,
        },
      };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      url: "/v1/hypervisor/model-infrastructure?project_id=project:ioi&session_ref=session:ioi",
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), modelInfrastructureProjection);
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeLifecycle",
      request: {
        operation: "hypervisor_model_infrastructure_projection",
        operation_kind:
          "runtime.lifecycle_projection.hypervisor_model_infrastructure",
        projection_kind: "hypervisor_model_infrastructure",
        base_url: "http://daemon.test",
        workspace_root: "/workspace",
        state_dir: "/state",
        home_dir: "/home/operator",
        runtime_schema_version: "ioi.agentgres.runtime.v0",
        project_id: "project:ioi",
        session_ref: "session:ioi",
        source:
          "public_runtime_routes./v1/hypervisor/model-infrastructure",
      },
    },
  ]);
});

test("public runtime routes dispatch Hypervisor provider placement through lifecycle projection", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const providerPlacementProjection = {
    schema_version: "ioi.hypervisor.provider_placement_projection.v1",
    projection_id: "provider-placement:daemon/test",
    source: "daemon-provider-placement-projection",
    selected_project_ref: "project:ioi",
    anti_gateway_invariant:
      "Hypervisor integrates providers directly; wallet.network authorizes spend and Agentgres records admitted truth.",
    candidates: [
      {
        candidate_ref: "provider-candidate:local-workstation",
        label: "Local workstation",
        integration_kind: "local_machine",
        direct_provider_ref: "provider:local-workstation",
        workload_fit: "Private local work",
        privacy_posture: "local_custody",
        wallet_authority_scope_refs: ["scope:workspace.read"],
        agentgres_receipt_ref: "receipt://provider/local/placement",
        storage_policy_ref: "storage-policy:local",
        restore_policy_ref: "agentgres://restore/local/latest",
        risk_labels: ["Local custody"],
      },
    ],
    runtimeTruthSource: "daemon-runtime",
  };
  const contextPolicyCore = {
    projectRuntimeLifecycle(request) {
      calls.push({ method: "projectRuntimeLifecycle", request });
      return {
        projection: providerPlacementProjection,
        record: {
          operation_kind:
            "runtime.lifecycle_projection.hypervisor_provider_placement",
          projection_kind: "hypervisor_provider_placement",
          projection: providerPlacementProjection,
        },
      };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      url: "/v1/hypervisor/provider-placement?project_id=project:ioi",
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), providerPlacementProjection);
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeLifecycle",
      request: {
        operation: "hypervisor_provider_placement_projection",
        operation_kind:
          "runtime.lifecycle_projection.hypervisor_provider_placement",
        projection_kind: "hypervisor_provider_placement",
        base_url: "http://daemon.test",
        workspace_root: "/workspace",
        state_dir: "/state",
        home_dir: "/home/operator",
        runtime_schema_version: "ioi.agentgres.runtime.v0",
        project_id: "project:ioi",
        source: "public_runtime_routes./v1/hypervisor/provider-placement",
      },
    },
  ]);
});

test("public runtime routes dispatch Hypervisor privacy posture through lifecycle projection", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const privacyPostureProjection = {
    schema_version: "ioi.hypervisor.execution_privacy_posture_projection.v1",
    projection_id: "privacy-posture:daemon/test",
    source: "daemon-privacy-posture-projection",
    project_ref: "project:ioi",
    selected_session_ref: "session:ioi",
    selected_privacy_ref: "privacy:ctee-private-workspace",
    default_model_route_ref: "model-route:hypervisor/default-local",
    invariant:
      "Daemon projection separates workspace privacy from model-weight custody.",
    workspace_segments: [
      {
        segment_ref: "workspace-segment:daemon/encrypted",
        label: "Daemon encrypted state",
        custody_class: "encrypted_blob_ref",
        node_plaintext_allowed: false,
        owner: "agentgres",
        evidence_refs: ["artifact://daemon/encrypted"],
      },
    ],
    model_weight_policies: [
      {
        lane: "forbidden_plaintext_mount",
        label: "No provider-readable weights",
        protects_workspace_state: true,
        protects_model_weights_from_provider_root: false,
        allowed_postures: ["ctee_split"],
        admission_summary: "Remote nodes receive no protected plaintext.",
        authority_scope_refs: ["scope:privacy.enforce_no_plaintext_custody"],
      },
    ],
    provider_candidates: [
      {
        candidate_ref: "provider-candidate:akash-gpu",
        label: "Akash GPU provider",
        posture: "ctee_split",
        model_weight_lane: "forbidden_plaintext_mount",
        provider_root_plaintext_risk: "bounded",
        admission_summary: "Public/redacted only.",
        receipt_ref: "receipt://privacy/akash",
      },
    ],
    admission_controls: [
      {
        control_ref: "privacy-control:daemon",
        label: "Daemon admission",
        owner: "hypervisor_daemon",
        blocks_unsafe_plaintext: true,
        receipt_ref: "receipt://privacy/daemon",
      },
    ],
    unsafe_mount_receipt_ref: "receipt://privacy/unsafe-mount-blocked/daemon",
    runtimeTruthSource: "daemon-runtime",
  };
  const contextPolicyCore = {
    projectRuntimeLifecycle(request) {
      calls.push({ method: "projectRuntimeLifecycle", request });
      return {
        projection: privacyPostureProjection,
        record: {
          operation_kind:
            "runtime.lifecycle_projection.hypervisor_privacy_posture",
          projection_kind: "hypervisor_privacy_posture",
          projection: privacyPostureProjection,
        },
      };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      url: "/v1/hypervisor/privacy-posture?project_id=project:ioi&session_ref=session:ioi",
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), privacyPostureProjection);
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeLifecycle",
      request: {
        operation: "hypervisor_privacy_posture_projection",
        operation_kind:
          "runtime.lifecycle_projection.hypervisor_privacy_posture",
        projection_kind: "hypervisor_privacy_posture",
        base_url: "http://daemon.test",
        workspace_root: "/workspace",
        state_dir: "/state",
        home_dir: "/home/operator",
        runtime_schema_version: "ioi.agentgres.runtime.v0",
        project_id: "project:ioi",
        session_ref: "session:ioi",
        source: "public_runtime_routes./v1/hypervisor/privacy-posture",
      },
    },
  ]);
});

test("public runtime routes dispatch Hypervisor receipt evidence through lifecycle projection", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const receiptEvidenceProjection = {
    schema_version: "ioi.hypervisor.receipt_evidence_projection.v1",
    projection_id: "receipt-evidence:daemon/test",
    source: "daemon-receipt-evidence-projection",
    page_cursor: "cursor:receipt/current",
    next_page_cursor: "cursor:receipt/next",
    page_size: 10,
    has_more: true,
    records: [
      {
        receipt_ref: "receipt://session/test",
        kind: "session_lifecycle",
        summary: "Session transition receipt evidence.",
        source_projection_ref: "session-operations:daemon/test",
        agentgres_operation_refs: ["agentgres://operation/session/test"],
        artifact_refs: ["artifact://receipt-evidence/session/test"],
        trace_refs: ["trace://hypervisor/session/test"],
        state_root_ref: "agentgres://state-root/session/test",
        replay_ref: "agentgres://replay/session/test",
        status: "admitted",
      },
    ],
    receipt_boundary_invariant:
      "Agentgres admits receipt truth; Hypervisor clients render evidence.",
    runtimeTruthSource: "daemon-runtime",
  };
  const contextPolicyCore = {
    projectRuntimeLifecycle(request) {
      calls.push({ method: "projectRuntimeLifecycle", request });
      return {
        projection: receiptEvidenceProjection,
        record: {
          operation_kind:
            "runtime.lifecycle_projection.hypervisor_receipt_evidence",
          projection_kind: "hypervisor_receipt_evidence",
          projection: receiptEvidenceProjection,
        },
      };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      url: "/v1/hypervisor/receipt-evidence?project_id=project:ioi&session_ref=session:ioi&page_cursor=cursor:receipt/current&page_size=10",
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), receiptEvidenceProjection);
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeLifecycle",
      request: {
        operation: "hypervisor_receipt_evidence_projection",
        operation_kind:
          "runtime.lifecycle_projection.hypervisor_receipt_evidence",
        projection_kind: "hypervisor_receipt_evidence",
        base_url: "http://daemon.test",
        workspace_root: "/workspace",
        state_dir: "/state",
        home_dir: "/home/operator",
        runtime_schema_version: "ioi.agentgres.runtime.v0",
        project_id: "project:ioi",
        session_ref: "session:ioi",
        receipt_page_cursor: "cursor:receipt/current",
        receipt_page_size: "10",
        source: "public_runtime_routes./v1/hypervisor/receipt-evidence",
      },
    },
  ]);
});

test("public runtime routes dispatch Hypervisor provider operations through lifecycle admission proposal", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const providerOperationProposal = {
    schema_version: "ioi.hypervisor.provider_operation_proposal.v1",
    proposal_ref: "provider-operation:daemon/zero-to-idle",
    source: "daemon-provider-operation-proposal",
    project_ref: "project:ioi",
    candidate_ref: "provider-candidate:akash-gpu",
    direct_provider_ref: "provider:akash/gpu-market",
    operation_kind: "zero_to_idle",
    admission_state: "requires_wallet_lease",
    wallet_lease_ref: "lease:wallet/provider/akash/zero-to-idle",
    required_scope_refs: ["scope:provider.spend", "scope:receipt.write"],
    agentgres_operation_ref:
      "agentgres://operation/provider/akash/zero-to-idle",
    receipt_ref: "receipt://provider/akash/zero-to-idle",
    state_root_ref: "agentgres://state-root/provider/akash",
    archive_ref: "storage-policy:agentgres-encrypted-refs-only",
    restore_ref: "agentgres://restore/akash/latest",
    custody_invariant:
      "wallet.network grants; Agentgres admits provider lifecycle truth.",
  };
  const contextPolicyCore = {
    projectRuntimeLifecycle(request) {
      calls.push({ method: "projectRuntimeLifecycle", request });
      return { proposal: providerOperationProposal };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/provider-operations",
      body: {
        project_ref: "project:ioi",
        candidate_ref: "provider-candidate:akash-gpu",
        direct_provider_ref: "provider:akash/gpu-market",
        operation_kind: "zero_to_idle",
        wallet_authority_scope_refs: [
          "scope:provider.spend",
          "scope:receipt.write",
        ],
        storage_policy_ref: "storage-policy:agentgres-encrypted-refs-only",
        restore_policy_ref: "agentgres://restore/akash/latest",
      },
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), providerOperationProposal);
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeLifecycle",
      request: {
        operation: "hypervisor_provider_operation_proposal",
        operation_kind:
          "runtime.lifecycle_operation.hypervisor_provider_operation_proposal",
        projection_kind: "hypervisor_provider_operation_proposal",
        base_url: "http://daemon.test",
        workspace_root: "/workspace",
        state_dir: "/state",
        home_dir: "/home/operator",
        runtime_schema_version: "ioi.agentgres.runtime.v0",
        project_id: "project:ioi",
        candidate_ref: "provider-candidate:akash-gpu",
        direct_provider_ref: "provider:akash/gpu-market",
        requested_operation: "zero_to_idle",
        wallet_authority_scope_refs: [
          "scope:provider.spend",
          "scope:receipt.write",
        ],
        storage_policy_ref: "storage-policy:agentgres-encrypted-refs-only",
        restore_policy_ref: "agentgres://restore/akash/latest",
        source: "public_runtime_routes./v1/hypervisor/provider-operations",
      },
    },
  ]);
});

test("public runtime routes dispatch Hypervisor session operations through lifecycle admission proposal", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const sessionOperationProposal = {
    schema_version: "ioi.hypervisor.session_operation_proposal.v1",
    proposal_ref: "session-operation:daemon/restore",
    source: "daemon-session-operation-proposal",
    project_ref: "project:ioi",
    session_ref: "session:ioi",
    environment_ref: "environment:ioi",
    provider_candidate_ref: "provider:local-workstation",
    operation_kind: "restore_session",
    target_ref: "agentgres://restore/ioi/latest",
    admission_state: "requires_wallet_lease",
    wallet_lease_ref: "lease:wallet/session/restore",
    required_scope_refs: ["scope:restore.apply"],
    agentgres_operation_ref: "agentgres://operation/session/ioi/restore",
    receipt_ref: "receipt://session/ioi/restore",
    state_root_ref: "agentgres://state-root/session/ioi",
    archive_ref: "artifact://agentgres/archive/ioi/latest",
    restore_ref: "agentgres://restore/ioi/latest",
    custody_invariant:
      "wallet.network grants; Agentgres admits session lifecycle truth.",
  };
  const contextPolicyCore = {
    projectRuntimeLifecycle(request) {
      calls.push({ method: "projectRuntimeLifecycle", request });
      return { proposal: sessionOperationProposal };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/session-operations/proposals",
      body: {
        project_ref: "project:ioi",
        session_ref: "session:ioi",
        environment_ref: "environment:ioi",
        provider_candidate_ref: "provider:local-workstation",
        operation_kind: "restore_session",
        target_ref: "agentgres://restore/ioi/latest",
        authority_scope_refs: ["scope:restore.apply"],
        access_lease_ref: "lease:access/ioi",
        log_lease_ref: "lease:logs/ioi",
        archive_ref: "artifact://agentgres/archive/ioi/latest",
        restore_ref: "agentgres://restore/ioi/latest",
      },
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), sessionOperationProposal);
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeLifecycle",
      request: {
        operation: "hypervisor_session_operation_proposal",
        operation_kind:
          "runtime.lifecycle_operation.hypervisor_session_operation_proposal",
        projection_kind: "hypervisor_session_operation_proposal",
        base_url: "http://daemon.test",
        workspace_root: "/workspace",
        state_dir: "/state",
        home_dir: "/home/operator",
        runtime_schema_version: "ioi.agentgres.runtime.v0",
        project_id: "project:ioi",
        session_ref: "session:ioi",
        environment_ref: "environment:ioi",
        provider_candidate_ref: "provider:local-workstation",
        requested_operation: "restore_session",
        target_ref: "agentgres://restore/ioi/latest",
        authority_scope_refs: ["scope:restore.apply"],
        access_lease_ref: "lease:access/ioi",
        log_lease_ref: "lease:logs/ioi",
        archive_ref: "artifact://agentgres/archive/ioi/latest",
        restore_ref: "agentgres://restore/ioi/latest",
        source:
          "public_runtime_routes./v1/hypervisor/session-operations/proposals",
      },
    },
  ]);
});

test("public runtime routes dispatch Hypervisor project operations through lifecycle admission proposal", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const projectOperationProposal = {
    schema_version: "ioi.hypervisor.project_operation_proposal.v1",
    proposal_ref: "project-operation:daemon/restore",
    source: "daemon-project-operation-proposal",
    project_id: "project:ioi",
    workspace_ref: "workspace://ioi",
    operation_kind: "restore",
    admission_state: "requires_wallet_lease",
    wallet_lease_ref: "lease:wallet/project/ioi/restore",
    required_scope_refs: ["scope:agentgres.restore", "scope:artifact.decrypt"],
    agentgres_operation_ref: "agentgres://operation/project/ioi/restore",
    receipt_ref: "receipt://project/ioi/restore",
    state_root_ref: "agentgres://state-root/project:ioi",
    archive_ref: "artifact://agentgres/archive/ioi/latest",
    restore_ref: "agentgres://restore/ioi/latest",
    custody_invariant:
      "wallet.network grants; Agentgres admits project archive/restore truth.",
  };
  const contextPolicyCore = {
    projectRuntimeLifecycle(request) {
      calls.push({ method: "projectRuntimeLifecycle", request });
      return { proposal: projectOperationProposal };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/project-operations",
      body: {
        project_id: "project:ioi",
        workspace_ref: "workspace://ioi",
        operation_kind: "restore",
        agentgres_object_head_ref: "agentgres://object-head/project:ioi",
        state_root_ref: "agentgres://state-root/project:ioi",
        archive_ref: "artifact://agentgres/archive/ioi/latest",
        restore_ref: "agentgres://restore/ioi/latest",
        latest_receipt_refs: ["receipt://project/ioi/state"],
      },
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), projectOperationProposal);
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeLifecycle",
      request: {
        operation: "hypervisor_project_operation_proposal",
        operation_kind:
          "runtime.lifecycle_operation.hypervisor_project_operation_proposal",
        projection_kind: "hypervisor_project_operation_proposal",
        base_url: "http://daemon.test",
        workspace_root: "/workspace",
        state_dir: "/state",
        home_dir: "/home/operator",
        runtime_schema_version: "ioi.agentgres.runtime.v0",
        project_id: "project:ioi",
        workspace_ref: "workspace://ioi",
        requested_operation: "restore",
        agentgres_object_head_ref: "agentgres://object-head/project:ioi",
        state_root_ref: "agentgres://state-root/project:ioi",
        archive_ref: "artifact://agentgres/archive/ioi/latest",
        restore_ref: "agentgres://restore/ioi/latest",
        latest_receipt_refs: ["receipt://project/ioi/state"],
        source: "public_runtime_routes./v1/hypervisor/project-operations",
      },
    },
  ]);
});

test("public runtime routes admit approved Hypervisor operations after wallet and Agentgres refs", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/approved-operations",
      body: {
        operation_family: "session",
        proposal_ref: "session-operation:daemon/restore",
        proposal_schema_version: "ioi.hypervisor.session_operation_proposal.v1",
        proposal_source: "daemon-session-operation-proposal",
        project_ref: "project:ioi",
        session_ref: "session:ioi",
        environment_ref: "environment:ioi",
        provider_candidate_ref: "provider:local-workstation",
        operation_kind: "restore_session",
        target_ref: "agentgres://restore/ioi/latest",
        wallet_approval_ref: "approval://wallet/session/restore",
        wallet_lease_ref: "lease:wallet/session/restore",
        required_scope_refs: ["scope:restore.apply"],
        authority_receipt_refs: ["receipt://wallet/session/restore"],
        agentgres_operation_ref: "agentgres://operation/session/ioi/restore",
        receipt_ref: "receipt://session/ioi/restore",
        state_root_ref: "agentgres://state-root/session/ioi",
        archive_ref: "artifact://agentgres/archive/ioi/latest",
        restore_ref: "agentgres://restore/ioi/latest",
      },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 202);
  const result = JSON.parse(response.body);
  assert.equal(
    result.schema_version,
    "ioi.runtime.hypervisor_approved_operation_admission.v1",
  );
  assert.equal(result.decision, "admitted");
  assert.equal(result.execution_status, "admitted_for_execution");
  assert.equal(result.executor_kind, "session_lifecycle_adapter");
  assert.match(result.execution_plan_ref, /^execution-plan:\/\/hypervisor\/session\//);
  assert.match(result.execution_dispatch_ref, /^dispatch:\/\/hypervisor\/session\//);
  assert.equal(
    result.execution_plan.schema_version,
    "ioi.runtime.hypervisor_approved_operation_execution_plan.v1",
  );
  assert.equal(result.execution_plan.dispatch_status, "awaiting_executor");
  assert.equal(result.execution_plan.executor_kind, "session_lifecycle_adapter");
  assert.equal(result.execution_plan.wallet_lease_ref, result.wallet_lease_ref);
  assert.equal(result.wallet_approval_ref, "approval://wallet/session/restore");
  assert.deepEqual(result.agentgres_operation_refs, [
    "agentgres://operation/session/ioi/restore",
  ]);
  assert.equal(result.runtimeTruthSource, "daemon-runtime");
});

test("public runtime routes reject fixture Hypervisor operation execution admission", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    homeDir: "/home/operator",
    schemaVersion: "ioi.agentgres.runtime.v0",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/approved-operations",
      body: {
        operation_family: "provider",
        proposal_ref: "provider-operation:fixture/archive",
        proposal_schema_version: "ioi.hypervisor.provider_operation_proposal.v1",
        proposal_source: "fixture",
        project_ref: "project:ioi",
        candidate_ref: "provider-candidate:akash-gpu",
        direct_provider_ref: "provider:akash/gpu-market",
        operation_kind: "archive",
        wallet_approval_ref: "approval://wallet/provider/archive",
        wallet_lease_ref: "lease:wallet/provider/archive",
        required_scope_refs: ["scope:archive.write"],
        agentgres_operation_ref: "agentgres://operation/provider/archive",
        receipt_ref: "receipt://provider/archive",
        state_root_ref: "agentgres://state-root/provider/archive",
        archive_ref: "artifact://agentgres/archive/provider/latest",
      },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 403);
  assert.equal(
    response.error.code,
    "hypervisor_approved_operation_proposal_source_not_admissible",
  );
});

test("public runtime routes expose daemon-planned harness container lane receipts", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-container-lanes",
      body: {
        selection_ref: "agent-harness-adapter:deepseek_tui",
        adapter_id: "deepseek_tui",
        runtime: "docker",
        container_image_ref: "container-image:deepseek-tui:local",
        command_argv: [
          "harness-adapter",
          "run",
          "deepseek_tui",
          "--fixture",
          "harness-testbed:public-code-edit-fixture",
        ],
        mounts: [
          {
            mount_ref: "mount:public-trunk",
            source_ref: "artifact://workspace/public-trunk",
            target_path: "/workspace",
            access: "read_only",
            custody: "public_trunk",
          },
        ],
        network_policy: "disabled",
        env_policy_ref: "env-policy:harness-adapter/no-plaintext-env",
        authority_scope_refs: ["scope:workspace.read", "scope:workspace.patch"],
        privacy_posture_ref: "privacy-posture:public-trunk",
      },
    }),
    response,
    store,
  });

  const payload = JSON.parse(response.body);
  assert.equal(response.statusCode, 202);
  assert.equal(
    payload.schema_version,
    "ioi.hypervisor.harness_container_lane_plan.v1",
  );
  assert.equal(payload.selection_ref, "agent-harness-adapter:deepseek_tui");
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
  assert.equal(payload.requiresDaemonGate, true);
  assert.match(payload.command_argv_hash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(
    payload.receipt.schema_version,
    "ioi.hypervisor.harness_container_lane_receipt.v1",
  );
  assert.equal(payload.receipt.exit_status, "not_executed");
  assert.deepEqual(payload.receipt.mounts, payload.mounts);
});

test("public runtime routes expose harness public fixture comparison under daemon gates", async () => {
  const executed = [];
  const { handleRequest } = routeHarness({
    executeHarnessContainerLane: async ({ plan, fixture_id, task_ref }) => {
      executed.push({ plan_id: plan.plan_id, fixture_id, task_ref });
      return {
        exit_status: "success",
        exit_code: 0,
        agentgres_operation_refs: [
          `agentgres://operation/${plan.adapter_id}/public-fixture`,
        ],
        artifact_refs: [`artifact://harness-fixture/${plan.adapter_id}/stdout`],
        created_at: "2026-06-17T13:01:00.000Z",
      };
    },
  });
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-public-fixture-runs",
      body: {
        installed_adapter_ids: ["deepseek_tui", "generic_cli"],
        candidate_lanes: [
          {
            adapter_id: "deepseek_tui",
            selection_ref: "agent-harness-adapter:deepseek_tui",
            runtime: "docker",
            container_image_ref: "container-image:deepseek-tui:local",
          },
          {
            adapter_id: "generic_cli",
            selection_ref: "agent-harness-adapter:generic_cli",
            runtime: "docker",
            container_image_ref: "container-image:generic-cli:local",
          },
        ],
      },
    }),
    response,
    store,
  });

  const payload = JSON.parse(response.body);
  assert.equal(response.statusCode, 202);
  assert.equal(payload.schema_version, "ioi.hypervisor.harness_public_fixture_run.v1");
  assert.equal(payload.requiresDaemonGate, true);
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
  assert.deepEqual(payload.candidate_selection_refs, [
    "agent-harness-adapter:deepseek_tui",
    "agent-harness-adapter:generic_cli",
  ]);
  assert.deepEqual(
    payload.attempts.map((attempt) => attempt.exit_status),
    ["success", "success"],
  );
  assert.equal(executed.length, 2);
  assert.ok(
    payload.attempts.every((attempt) =>
      attempt.mounts.every((mount) =>
        ["public_trunk", "redacted_projection"].includes(mount.custody),
      ),
    ),
  );
  assert.equal(
    payload.attempts[0].receipt.agentgres_operation_refs[0],
    "agentgres://operation/deepseek_tui/public-fixture",
  );
});

test("public runtime harness fixture route preserves private workspace mount guard", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/harness-public-fixture-runs",
      body: {
        installed_adapter_ids: ["deepseek_tui", "generic_cli"],
        candidate_lanes: [
          {
            adapter_id: "deepseek_tui",
            runtime: "docker",
            container_image_ref: "container-image:deepseek-tui:local",
            mounts: [
              {
                source_ref: "artifact://workspace/private",
                target_path: "/workspace",
                access: "read_only",
                custody: "ctee_private_workspace",
              },
            ],
          },
          {
            adapter_id: "generic_cli",
            runtime: "docker",
            container_image_ref: "container-image:generic-cli:local",
          },
        ],
      },
    }),
    response,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  assert.equal(response.statusCode, 403);
  assert.deepEqual(JSON.parse(response.body), {
    error: "harness_container_lane_private_mount_blocked",
  });
});

test("public runtime routes expose model-weight custody admissions", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/model-weight-custody-admissions",
      body: {
        route_ref: "model-route:confidential/h100",
        model_ref: "model:org/private",
        provider_ref: "provider:customer-cloud",
        weight_class: "tee_or_customer_cloud_mount",
        mount_target: "tee_session",
        execution_privacy_posture: "confidential_compute",
        remote_provider_can_read_weights: false,
        required_controls: ["tee_attestation"],
        authority_scope_refs: ["scope:cloud.deploy", "scope:secret.release"],
        tee_attestation_ref: "attestation://confidential-gpu/session",
        agentgres_operation_refs: ["agentgres://operation/model-weight/admit"],
        artifact_refs: ["artifact://model-weight/admission"],
      },
    }),
    response,
    store,
  });

  const payload = JSON.parse(response.body);
  assert.equal(response.statusCode, 202);
  assert.equal(
    payload.schema_version,
    "ioi.runtime.model_weight_custody_admission.v1",
  );
  assert.equal(payload.route_ref, "model-route:confidential/h100");
  assert.equal(payload.weight_class, "tee_or_customer_cloud_mount");
  assert.equal(payload.mount_target, "tee_session");
  assert.equal(payload.decision, "admitted");
  assert.equal(payload.protects_model_weights_from_provider_root, true);
  assert.equal(payload.protects_workspace_state, true);
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
  assert.deepEqual(payload.authority_scope_refs, [
    "scope:cloud.deploy",
    "scope:secret.release",
  ]);
  assert.equal(
    payload.receipt_ref,
    "receipt://model-weight-custody/model-route_confidential_h100/tee_or_customer_cloud_mount",
  );
});

test("public runtime model-weight custody route blocks provider-readable private weights", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/model-weight-custody-admissions",
      body: {
        route_ref: "model-route:rented-gpu/private",
        model_ref: "model:org/private",
        provider_ref: "provider:rented-gpu",
        weight_class: "user_local_private_weight",
        mount_target: "rented_gpu",
        execution_privacy_posture: "ctee_split",
        remote_provider_can_read_weights: true,
        required_controls: ["local_only"],
        authority_scope_refs: ["scope:model.local_mount"],
      },
    }),
    response,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  assert.equal(response.statusCode, 403);
  assert.deepEqual(JSON.parse(response.body), {
    error: "model_weight_custody_plaintext_private_weight_blocked",
  });
});

test("public runtime routes expose managed worker lifecycle admissions", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/managed-worker-lifecycle-admissions",
      body: {
        lifecycle_id: "lifecycle:agent_123",
        worker_instance_id: "agent://agent_123",
        worker_package_ref: "package://worker/researcher@1",
        owner_ref: "wallet://user_123",
        from_state: "active",
        to_state: "payment_past_due",
        persistence_profile: "persistent",
        payment_status: "past_due",
        transition_reason: "payment_lapse",
        authority_scope_refs: ["scope:worker.lifecycle"],
        authority_grant_refs: ["grant://wallet/worker-lifecycle"],
        policy_refs: ["policy://worker-lifecycle"],
        latest_state_root: "state_root:worker:123",
        receipt_refs: ["receipt://worker-lifecycle/payment-past-due"],
        agentgres_operation_refs: [
          "agentgres://operation/worker-lifecycle/payment-past-due",
        ],
        required_controls: [
          "freeze_new_billable_work",
          "pause_high_risk_standing_orders",
        ],
        new_billable_work_blocked: true,
        high_risk_orders_paused: true,
      },
    }),
    response,
    store,
  });

  const payload = JSON.parse(response.body);
  assert.equal(response.statusCode, 202);
  assert.equal(
    payload.schema_version,
    "ioi.runtime.managed_worker_instance_lifecycle_admission.v1",
  );
  assert.equal(
    payload.transition_id,
    "managed-worker-lifecycle:lifecycle_agent_123:active-payment_past_due",
  );
  assert.equal(payload.state, "payment_past_due");
  assert.equal(payload.freezes_new_billable_work, true);
  assert.equal(payload.pauses_high_risk_standing_orders, true);
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
});

test("public runtime managed worker lifecycle route blocks payment-lapse deletion", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/managed-worker-lifecycle-admissions",
      body: {
        lifecycle_id: "lifecycle:agent_123",
        worker_instance_id: "agent://agent_123",
        owner_ref: "wallet://user_123",
        from_state: "payment_past_due",
        to_state: "deleted",
        persistence_profile: "persistent",
        payment_status: "past_due",
        transition_reason: "payment_lapse",
        authority_scope_refs: ["scope:worker.lifecycle", "scope:worker.delete"],
        wallet_approval_ref: "approval://wallet/delete",
        receipt_refs: ["receipt://worker-lifecycle/delete"],
        agentgres_operation_refs: [
          "agentgres://operation/worker-lifecycle/delete",
        ],
        deletion_policy: {
          delete_runtime_state: true,
          delete_archives: false,
          forget_semantic_memory: false,
        },
      },
    }),
    response,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  assert.equal(response.statusCode, 403);
  assert.deepEqual(JSON.parse(response.body), {
    error: "managed_worker_lifecycle_lapse_delete_blocked",
  });
});

test("public runtime routes expose physical action intent admissions", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/physical-action-intent-admissions",
      body: {
        intent_id: "intent://physical/carwash/prep-vehicle-001",
        actor_id: "worker:carwash-prep-humanoid",
        task_id: "task://carwash/prep-vehicle-001",
        domain_ref: "domain://carwash/vehicle-prep",
        target_system_ref: "robot://bay-3/humanoid-1",
        action_kind: "manipulation",
        risk_class: "physical_action",
        execution_phase: "command_issued",
        requested_primitives: ["prim:physical.actuate"],
        requested_scopes: ["scope:physical.actuate"],
        physical_action_policy_ref: "policy://physical/carwash-prep",
        safety_envelope_ref: "safety://carwash/bay-3",
        human_supervision_policy_ref: "supervision://carwash/on-loop",
        supervision_mode: "human_on_loop",
        human_supervisor_refs: ["user://operator/bay-3"],
        emergency_stop_authority_ref: "estop://carwash/bay-3",
        emergency_stop_tested: true,
        emergency_stop_max_latency_ms: 250,
        sensor_evidence_receipt_refs: ["receipt://sensor/bay-3/preflight"],
        actuator_command_receipt_refs: [
          "receipt://actuator/bay-3/prep-command",
        ],
        incident_policy_ref: "policy://physical/incidents/carwash",
        wallet_approval_ref: "approval://wallet/physical-action/carwash",
        authority_ref: "grant://wallet/physical-action/carwash",
        policy_refs: [
          "policy://physical/carwash-prep",
          "policy://physical/incidents/carwash",
        ],
        receipt_refs: [
          "receipt://sensor/bay-3/preflight",
          "receipt://actuator/bay-3/prep-command",
        ],
        agentgres_operation_refs: [
          "agentgres://operation/physical-action/carwash/prep-vehicle-001",
        ],
        artifact_refs: ["artifact://sensor-video/bay-3/preflight"],
        state_root: "state_root:physical:carwash:001",
        execution_channel: "physical_action_adapter",
      },
    }),
    response,
    store,
  });

  const payload = JSON.parse(response.body);
  assert.equal(response.statusCode, 202);
  assert.equal(
    payload.schema_version,
    "ioi.runtime.physical_action_intent_admission.v1",
  );
  assert.equal(payload.risk_class, "physical_action");
  assert.equal(payload.decision, "admitted");
  assert.equal(payload.requiresDaemonGate, true);
  assert.equal(payload.generic_tool_call_blocked, true);
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
});

test("public runtime physical action route blocks generic actuator tool calls", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/physical-action-intent-admissions",
      body: {
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
        emergency_stop_max_latency_ms: 250,
        sensor_evidence_receipt_refs: ["receipt://sensor/bay-3/preflight"],
        actuator_command_receipt_refs: [
          "receipt://actuator/bay-3/prep-command",
        ],
        incident_policy_ref: "policy://physical/incidents/carwash",
        wallet_approval_ref: "approval://wallet/physical-action/carwash",
        authority_ref: "grant://wallet/physical-action/carwash",
        policy_refs: ["policy://physical/carwash-prep"],
        receipt_refs: ["receipt://actuator/bay-3/prep-command"],
        agentgres_operation_refs: [
          "agentgres://operation/physical-action/carwash/prep-vehicle-001",
        ],
        execution_channel: "tool.invoke",
        generic_tool_call: true,
      },
    }),
    response,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  assert.equal(response.statusCode, 403);
  assert.deepEqual(JSON.parse(response.body), {
    error: "physical_action_generic_tool_call_blocked",
  });
});

test("public runtime routes expose worker package install admissions", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/worker-package-install-admissions",
      body: {
        install_id: "install://aiagent/carwash-prep/heath/default",
        worker_package_ref: "package://aiagent/robotics.carwash_prep@1",
        worker_manifest_ref: "manifest://aiagent/robotics.carwash_prep@1",
        owner_ref: "wallet://user/heath",
        install_mode: "managed_instance_initialization",
        base_ontology_ref: "ontology:aiagent.base.v1",
        vertical_pack_refs: ["vertical_pack:robotics.carwash_prep.v1"],
        integration_surface_refs: [
          "integration_surface:robotics_physical",
          "integration_surface:embodied_humanoid",
        ],
        primitive_capability_requirements: [
          "prim:physical.actuate",
          "prim:sensor.stream",
        ],
        authority_scope_requirements: [
          "scope:physical.actuate",
          "scope:worker.lifecycle",
        ],
        risk_classes: ["physical_action"],
        policy_profile_refs: [
          "policy://aiagent/worker-install",
          "policy://ctee/private-workspace",
        ],
        receipt_policy_ref: "receipt_policy://aiagent/worker-install",
        evidence_requirement_refs: [
          "evidence_requirement:physical.preflight.v1",
        ],
        benchmark_profile_refs: [
          "benchmark://aiagent/robotics.carwash_prep.v1",
        ],
        runtime_profile: "private_workspace_ctee",
        persistence_profile: "zero_to_idle",
        memory_policy_ref: "policy://memory/worker-instance",
        archive_policy_ref: "policy://archive/worker-instance",
        package_artifact_refs: [
          "artifact://package/robotics.carwash-prep/v1",
        ],
        wallet_approval_ref: "approval://wallet/worker-install/carwash",
        install_right_ref: "license://aiagent/install/carwash-prep",
        managed_instance_ref: "agent://carwash-prep/heath/default",
        physical_action_policy_refs: ["policy://physical/carwash-prep"],
        safety_envelope_refs: ["safety://carwash/bay-3"],
        emergency_stop_authority_refs: ["estop://carwash/bay-3"],
        agentgres_operation_refs: [
          "agentgres://operation/worker-install/carwash-prep",
        ],
        receipt_refs: ["receipt://worker-install/carwash-prep"],
        state_root: "state_root:worker-install:carwash-prep",
      },
    }),
    response,
    store,
  });

  const payload = JSON.parse(response.body);
  assert.equal(response.statusCode, 202);
  assert.equal(
    payload.schema_version,
    "ioi.runtime.worker_package_install_admission.v1",
  );
  assert.equal(payload.worker_package_ref, "package://aiagent/robotics.carwash_prep@1");
  assert.equal(payload.base_ontology_ref, "ontology:aiagent.base.v1");
  assert.equal(payload.runtime_profile, "private_workspace_ctee");
  assert.equal(payload.decision, "admitted");
  assert.equal(payload.requiresDaemonGate, true);
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
});

test("public runtime worker package install route blocks physical packages without safety refs", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/worker-package-install-admissions",
      body: {
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
        policy_profile_refs: [
          "policy://aiagent/worker-install",
          "policy://ctee/private-workspace",
        ],
        receipt_policy_ref: "receipt_policy://aiagent/worker-install",
        evidence_requirement_refs: [
          "evidence_requirement:physical.preflight.v1",
        ],
        runtime_profile: "private_workspace_ctee",
        persistence_profile: "zero_to_idle",
        memory_policy_ref: "policy://memory/worker-instance",
        archive_policy_ref: "policy://archive/worker-instance",
        package_artifact_refs: [
          "artifact://package/robotics.carwash-prep/v1",
        ],
        wallet_approval_ref: "approval://wallet/worker-install/carwash",
        install_right_ref: "license://aiagent/install/carwash-prep",
        managed_instance_ref: "agent://carwash-prep/heath/default",
        physical_action_policy_refs: [],
        safety_envelope_refs: ["safety://carwash/bay-3"],
        emergency_stop_authority_refs: ["estop://carwash/bay-3"],
        agentgres_operation_refs: [
          "agentgres://operation/worker-install/carwash-prep",
        ],
        receipt_refs: ["receipt://worker-install/carwash-prep"],
      },
    }),
    response,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  assert.equal(response.statusCode, 403);
  assert.deepEqual(JSON.parse(response.body), {
    error: "worker_package_install_physical_action_policy_refs_required",
  });
});

test("public runtime routes expose code editor adapter launch plan admissions", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/code-editor-adapter-launch-plans",
      body: {
        launch_plan_ref: "code-editor-adapter:external_editor/launch-plan",
        adapter_ref: "code-editor-adapter:external_editor",
        target_ref: "adapter-target:external-editor",
        launch_mode: "external",
        connection_kind: "desktop_editor",
        connection_contract_ref:
          "connection-contract:code-editor-adapter/desktop-context",
        executor_lane: "desktop_editor",
        control_action: "open_desktop_editor",
        control_channel_ref:
          "control-channel:code-editor-adapter/desktop-context",
        required_access_lease_refs: [
          "lease:code-editor-adapter/desktop-context",
        ],
        required_authority_scope_refs: [
          "scope:workspace.read",
          "scope:workspace.patch",
          "scope:receipt.write",
        ],
        required_receipt_refs: [
          "receipt-policy:code-editor-adapter/desktop-context",
        ],
        custody_posture: "redacted_projection",
        secret_release_policy: "no_durable_secret_release",
        agentgres_operation_refs: [
          "agentgres://operation/code-editor-adapter/admit",
        ],
        receipt_refs: ["receipt://code-editor-adapter/admit"],
      },
    }),
    response,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  const payload = JSON.parse(response.body);
  assert.equal(response.statusCode, 202);
  assert.equal(
    payload.schema_version,
    "ioi.runtime.code_editor_adapter_launch_plan_admission.v1",
  );
  assert.equal(payload.connection_kind, "desktop_editor");
  assert.equal(payload.executor_lane, "desktop_editor");
  assert.equal(payload.control_action, "open_desktop_editor");
  assert.equal(
    payload.control_channel_ref,
    "control-channel:code-editor-adapter/desktop-context",
  );
  assert.equal(payload.secret_release_policy, "no_durable_secret_release");
  assert.equal(payload.requiresDaemonGate, true);
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
});

test("public runtime code editor adapter launch route rejects provider workspace targets", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/code-editor-adapter-launch-plans",
      body: {
        launch_plan_ref: "code-editor-adapter:remote_vm/launch-plan",
        adapter_ref: "code-editor-adapter:remote_vm",
        target_ref: "adapter-target:remote-vm-workspace",
        launch_mode: "remote_url",
        connection_kind: "provider_workspace",
        connection_contract_ref:
          "connection-contract:code-editor-adapter/provider-workspace",
        executor_lane: "provider_environment",
        control_action: "attach_provider_workspace",
        control_channel_ref:
          "control-channel:code-editor-adapter/provider-workspace",
        required_access_lease_refs: ["lease:provider/workspace-access"],
        required_authority_scope_refs: ["scope:provider.workspace.attach"],
        required_receipt_refs: ["receipt-policy:code-editor-adapter/provider"],
        custody_posture: "provider_session",
        secret_release_policy: "no_durable_secret_release",
      },
    }),
    response,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  assert.equal(response.statusCode, 400);
  assert.deepEqual(JSON.parse(response.body), {
    error: "code_editor_adapter_launch_connection_kind_invalid",
  });
});

test("public runtime routes expose service composition receipt bundle admissions", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/service-composition-receipt-bundles",
      body: {
        service_ref: "service://sas/reporting",
        delivery_ref: "delivery://sas/reporting/123",
        composition_graph_ref: "workflow://service-composition/reporting",
        delivery_status: "delivered",
        private_data_posture: "ctee_private_workspace",
        contribution_receipt_refs: ["receipt://contribution/worker-1"],
        verifier_receipt_refs: ["receipt://verifier/quality-1"],
        policy_receipt_refs: ["receipt://policy/service-1"],
        routing_receipt_refs: ["receipt://routing/service-1"],
        dispute_evidence_refs: ["evidence://dispute/service-1"],
        provider_log_refs: ["log://provider/supporting"],
        agentgres_operation_refs: [
          "agentgres://operation/service-composition/123",
        ],
        artifact_refs: ["artifact://delivery/report"],
        receipt_refs: ["receipt://service-composition/bundle-123"],
        state_root: "state_root:service-composition:123",
        settlement_requested: true,
      },
    }),
    response,
    store,
  });

  const payload = JSON.parse(response.body);
  assert.equal(response.statusCode, 202);
  assert.equal(
    payload.schema_version,
    "ioi.runtime.service_composition_receipt_bundle.v1",
  );
  assert.equal(payload.service_ref, "service://sas/reporting");
  assert.equal(payload.private_data_posture, "ctee_private_workspace");
  assert.equal(payload.settlement_ready, true);
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
});

test("public runtime service composition route blocks unsafe plaintext settlement", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/service-composition-receipt-bundles",
      body: {
        service_ref: "service://sas/reporting",
        delivery_ref: "delivery://sas/reporting/unsafe",
        composition_graph_ref: "workflow://service-composition/reporting",
        delivery_status: "delivered",
        private_data_posture: "unsafe_plaintext_exception",
        contribution_receipt_refs: ["receipt://contribution/worker-1"],
        verifier_receipt_refs: ["receipt://verifier/quality-1"],
        policy_receipt_refs: ["receipt://policy/service-1"],
        routing_receipt_refs: ["receipt://routing/service-1"],
        dispute_evidence_refs: ["evidence://dispute/service-1"],
        agentgres_operation_refs: [
          "agentgres://operation/service-composition/unsafe",
        ],
        artifact_refs: ["artifact://delivery/report"],
        receipt_refs: ["receipt://service-composition/unsafe"],
        state_root: "state_root:service-composition:unsafe",
        wallet_approval_ref: "approval://wallet/unsafe-service",
        unsafe_plaintext_exception_ref: "receipt://unsafe-plaintext/service",
        settlement_requested: true,
      },
    }),
    response,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  assert.equal(response.statusCode, 403);
  assert.deepEqual(JSON.parse(response.body), {
    error: "service_composition_unsafe_plaintext_settlement_blocked",
  });
});

test("public runtime routes expose artifact availability incident admissions", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const store = {
    defaultCwd: "/workspace",
    stateDir: "/state",
    projectRuntimeLifecycleProjection: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/artifact-availability-incidents",
      body: {
        artifact_ref: "artifact://evidence/report",
        payload_ref: "payload://evidence/report/bytes",
        backend_ref: "storage://filecoin/mainnet",
        incident_kind: "invalid_hash",
        lifecycle_state: "opened",
        expected_hash: "sha256:expected",
        observed_hash: "sha256:observed",
        agentgres_operation_refs: [
          "agentgres://operation/artifact-incident/open",
        ],
        incident_receipt_refs: ["receipt://artifact-incident/open"],
        affected_object_refs: ["agentgres://object/delivery/report"],
      },
    }),
    response,
    store,
  });

  const payload = JSON.parse(response.body);
  assert.equal(response.statusCode, 202);
  assert.equal(
    payload.schema_version,
    "ioi.runtime.artifact_availability_incident.v1",
  );
  assert.equal(payload.artifact_ref, "artifact://evidence/report");
  assert.equal(payload.incident_kind, "invalid_hash");
  assert.equal(payload.expected_hash, "sha256:expected");
  assert.equal(payload.observed_hash, "sha256:observed");
  assert.equal(payload.runtimeTruthSource, "daemon-runtime");
});

test("public runtime artifact availability route blocks silent payload mutation", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/hypervisor/artifact-availability-incidents",
      body: {
        artifact_ref: "artifact://evidence/report",
        payload_ref: "payload://evidence/report/bytes",
        backend_ref: "storage://filecoin/mainnet",
        incident_kind: "missing",
        lifecycle_state: "opened",
        agentgres_operation_refs: [
          "agentgres://operation/artifact-incident/open",
        ],
        incident_receipt_refs: ["receipt://artifact-incident/open"],
        affected_object_refs: ["agentgres://object/delivery/report"],
        payload_bytes_mutated: true,
      },
    }),
    response,
    store: { defaultCwd: "/workspace", stateDir: "/state" },
  });

  assert.equal(response.statusCode, 403);
  assert.deepEqual(JSON.parse(response.body), {
    error: "artifact_availability_silent_payload_mutation_blocked",
  });
});

test("public runtime computer-use routes dispatch through Rust daemon-core projection", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const contextPolicyCore = {
    projectRuntimeComputerUse(request) {
      calls.push({ method: "projectRuntimeComputerUse", request });
      if (request.projection_kind === "provider_registry") {
        return {
          provider_registry: {
            object: "ioi.computer_use.provider_registry_report",
            providers: [{ provider_id: "ioi.computer_use.native_browser.task_scoped_profile" }],
          },
        };
      }
      return {
        browser_discovery: {
          object: "ioi.computer_use.browser_discovery_report",
          browser_process_count: 0,
          cdp_endpoint_count: 0,
        },
      };
    },
  };
  const store = {
    defaultCwd: "/workspace",
    stateDir: "/state",
  };

  const providersResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/computer-use/providers" }),
    response: providersResponse,
    store,
    contextPolicyCore,
  });

  assert.equal(providersResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(providersResponse.body), {
    object: "ioi.computer_use.provider_registry_report",
    providers: [{ provider_id: "ioi.computer_use.native_browser.task_scoped_profile" }],
  });

  const browserResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/computer-use/browser-discovery?probe=false&include_tabs=true&reveal_tab_titles=true" }),
    response: browserResponse,
    store,
    contextPolicyCore,
  });

  assert.equal(browserResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(browserResponse.body), {
    object: "ioi.computer_use.browser_discovery_report",
    browser_process_count: 0,
    cdp_endpoint_count: 0,
  });
  assert.deepEqual(calls, [
    {
      method: "projectRuntimeComputerUse",
      request: {
        operation: "runtime_computer_use_projection",
        operation_kind: "runtime.computer_use.projection.provider_registry",
        projection_kind: "provider_registry",
        workspace_root: "/workspace",
        state_dir: "/state",
        source: "public_runtime_routes./v1/computer-use/providers",
      },
    },
    {
      method: "projectRuntimeComputerUse",
      request: {
        operation: "runtime_computer_use_projection",
        operation_kind: "runtime.computer_use.projection.browser_discovery",
        projection_kind: "browser_discovery",
        workspace_root: "/workspace",
        state_dir: "/state",
        include_cdp_probe: false,
        include_tab_metadata: true,
        reveal_tab_titles: true,
        source: "public_runtime_routes./v1/computer-use/browser-discovery",
      },
    },
  ]);
});

test("public runtime repository workflow routes use mounted repository API", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const repositoryApi = {
    listRepositories(apiStore) {
      calls.push({ method: "listRepositories", apiStore });
      return { repositories: [] };
    },
    repositoryContext(apiStore) {
      calls.push({ method: "repositoryContext", apiStore });
      return { context_id: "repo_context" };
    },
    branchPolicy(apiStore) {
      calls.push({ method: "branchPolicy", apiStore });
      return { policy_id: "branch_policy" };
    },
    githubContext(apiStore) {
      calls.push({ method: "githubContext", apiStore });
      return { context_id: "github_context" };
    },
    prAttempts(apiStore) {
      calls.push({ method: "prAttempts", apiStore });
      return { attempts: [] };
    },
    issueContext(apiStore) {
      calls.push({ method: "issueContext", apiStore });
      return { issue_id: "issue_context" };
    },
    reviewGate(apiStore) {
      calls.push({ method: "reviewGate", apiStore });
      return { gate_id: "review_gate" };
    },
    githubPrCreatePlan(apiStore) {
      calls.push({ method: "githubPrCreatePlan", apiStore });
      return { plan_id: "pr_plan" };
    },
  };
  const store = {
    repositoryApi,
    listRepositories: retiredRouteWrapper,
    repositoryContext: retiredRouteWrapper,
    branchPolicy: retiredRouteWrapper,
    githubContext: retiredRouteWrapper,
    prAttempts: retiredRouteWrapper,
    issueContext: retiredRouteWrapper,
    reviewGate: retiredRouteWrapper,
    githubPrCreatePlan: retiredRouteWrapper,
  };
  const routes = [
    ["/v1/repositories", "listRepositories"],
    ["/v1/repository-context", "repositoryContext"],
    ["/v1/branch-policy", "branchPolicy"],
    ["/v1/github-context", "githubContext"],
    ["/v1/pr-attempts", "prAttempts"],
    ["/v1/issue-context", "issueContext"],
    ["/v1/review-gate", "reviewGate"],
    ["/v1/github/pr-create-plan", "githubPrCreatePlan"],
  ];

  for (const [url] of routes) {
    const response = responseRecorder();
    await handleRequest({ request: request({ url }), response, store });
    assert.equal(response.statusCode, 200);
  }

  assert.deepEqual(calls.map((call) => call.method), routes.map(([, method]) => method));
  assert.equal(calls.every((call) => call.apiStore === store), true);
});

test("public runtime skill and hook routes use mounted skill hook API", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    defaultCwd: "/workspace/canonical",
    skillHookApi: {
      listSkills(request) {
        calls.push({ method: "listSkills", request });
        return {
          skills: [{ id: "skill.route" }],
          rust_core_boundary: "runtime.skill_hook_registry",
        };
      },
      listHooks(request) {
        calls.push({ method: "listHooks", request });
        return {
          hooks: [{ id: "hook.route" }],
          rust_core_boundary: "runtime.skill_hook_registry",
        };
      },
    },
    listSkills: retiredRouteWrapper,
    listHooks: retiredRouteWrapper,
  };

  const skillsResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/skills" }), response: skillsResponse, store });
  assert.equal(skillsResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(skillsResponse.body), {
    skills: [{ id: "skill.route" }],
    rust_core_boundary: "runtime.skill_hook_registry",
  });

  const hooksResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/hooks" }), response: hooksResponse, store });
  assert.equal(hooksResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(hooksResponse.body), {
    hooks: [{ id: "hook.route" }],
    rust_core_boundary: "runtime.skill_hook_registry",
  });

  assert.deepEqual(calls, [
    { method: "listSkills", request: { cwd: "/workspace/canonical" } },
    { method: "listHooks", request: { cwd: "/workspace/canonical" } },
  ]);
});

test("public runtime model catalog routes use mounted model projection surface", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    modelMounting: {
      runtimeModelCatalogList() {
        calls.push({ method: "runtimeModelCatalogList" });
        return {
          object: "list",
          data: [{ id: "model.route" }],
        };
      },
      listModelCapabilities() {
        calls.push({ method: "listModelCapabilities" });
        return {
          capabilities: [{ model: "model.route", features: ["chat"] }],
        };
      },
      listArtifacts() {
        calls.push({ method: "listArtifacts" });
        return [{ id: "artifact.route" }];
      },
      listEndpoints() {
        calls.push({ method: "listEndpoints" });
        return [{ id: "endpoint.route" }];
      },
      listProviders() {
        calls.push({ method: "listProviders" });
        return [{ id: "provider.route" }];
      },
      listRoutes() {
        calls.push({ method: "listRoutes" });
        return [{ id: "route.route" }];
      },
      getModel(id) {
        calls.push({ method: "getModel", id });
        return { id, object: "model.artifact" };
      },
      snapshot(baseUrl) {
        calls.push({ method: "snapshot", baseUrl });
        return { id: "snapshot.route", baseUrl };
      },
      projection() {
        calls.push({ method: "projection" });
        return { id: "projection.route" };
      },
      listMcpServers() {
        calls.push({ method: "listMcpServers" });
        return [{ id: "mcp.route" }];
      },
      importMcpJson(body) {
        calls.push({ method: "importMcpJson", body });
        return { id: "mcp.import", object: "mcp.import" };
      },
      invokeMcpTool({ authorization, body }) {
        calls.push({ method: "invokeMcpTool", authorization, body });
        return { id: "mcp.invoke", object: "mcp.invoke" };
      },
      executeWorkflowNode({ authorization, body }) {
        calls.push({ method: "executeWorkflowNode", authorization, body });
        return { id: "workflow.node", object: "workflow.node" };
      },
      validateReceiptGate(body) {
        calls.push({ method: "validateReceiptGate", body });
        return { id: "receipt.gate", object: "receipt.gate" };
      },
      upsertRoute(body) {
        calls.push({ method: "upsertRoute", body });
        return { id: "route.write", object: "route.upsert" };
      },
      testRoute(id, body) {
        calls.push({ method: "testRoute", id, body });
        return { id, object: "route.test" };
      },
      catalogSearch(query) {
        calls.push({ method: "catalogSearch", query });
        return [{ id: "catalog.route", query: query.query }];
      },
      catalogImportUrl(body) {
        calls.push({ method: "catalogImportUrl", body });
        return { id: "catalog.import", object: "catalog.import" };
      },
      importModel(body) {
        calls.push({ method: "importModel", body });
        return { id: "artifact.imported", object: "model.artifact" };
      },
      deleteModelArtifact(id, body) {
        calls.push({ method: "deleteModelArtifact", id, body });
        return { id, object: "model.artifact.deleted" };
      },
      mountEndpoint(body) {
        calls.push({ method: "mountEndpoint", body });
        return { id: "endpoint.route", object: "model.endpoint" };
      },
      downloadModel(body) {
        calls.push({ method: "downloadModel", body });
        return { id: "download.route", object: "model.download" };
      },
      downloadStatus(id) {
        calls.push({ method: "downloadStatus", id });
        return { id, status: "completed" };
      },
      cancelDownload(id, body) {
        calls.push({ method: "cancelDownload", id, body });
        return { id, status: "canceled" };
      },
      cleanupModelStorage(body) {
        calls.push({ method: "cleanupModelStorage", body });
        return { status: "cleaned" };
      },
      unmountEndpoint(body) {
        calls.push({ method: "unmountEndpoint", body });
        return { id: body.endpoint_id, object: "model.endpoint.unmounted" };
      },
      loadModel(body) {
        calls.push({ method: "loadModel", body });
        return { id: "instance.loaded", object: "model.instance.loaded", ...body };
      },
      unloadModel(body) {
        calls.push({ method: "unloadModel", body });
        return { id: body.instance_id ?? body.endpoint_id ?? "instance.unloaded", object: "model.instance.unloaded" };
      },
      authorize(authorization, scope) {
        calls.push({ method: "authorize", authorization, scope });
      },
      serverStatus(baseUrl) {
        calls.push({ method: "serverStatus", baseUrl });
        return { id: "server.status", baseUrl };
      },
      serverStart(baseUrl) {
        calls.push({ method: "serverStart", baseUrl });
        return { id: "server.start", baseUrl };
      },
      serverStop(baseUrl) {
        calls.push({ method: "serverStop", baseUrl });
        return { id: "server.stop", baseUrl };
      },
      serverRestart(baseUrl) {
        calls.push({ method: "serverRestart", baseUrl });
        return { id: "server.restart", baseUrl };
      },
      serverLogs(query) {
        calls.push({ method: "serverLogs", query });
        return { id: "server.logs", limit: query.limit };
      },
      serverEvents(query) {
        calls.push({ method: "serverEvents", query });
        return { id: "server.events", limit: query.limit };
      },
      listBackends() {
        calls.push({ method: "listBackends" });
        return [{ id: "backend.route" }];
      },
      backendHealth(id) {
        calls.push({ method: "backendHealth", id });
        return { id, object: "backend.health" };
      },
      startBackend(id, body) {
        calls.push({ method: "startBackend", id, body });
        return { id, object: "backend.start" };
      },
      stopBackend(id) {
        calls.push({ method: "stopBackend", id });
        return { id, object: "backend.stop" };
      },
      backendLogs(id) {
        calls.push({ method: "backendLogs", id });
        return { id, object: "backend.logs" };
      },
      listRuntimeEngines() {
        calls.push({ method: "listRuntimeEngines" });
        return [{ id: "engine.route" }];
      },
      runtimeEngine(id) {
        calls.push({ method: "runtimeEngine", id });
        return { id, object: "runtime.engine" };
      },
      runtimeSurvey() {
        calls.push({ method: "runtimeSurvey" });
        return { object: "runtime.survey" };
      },
      selectRuntimeEngine(body) {
        calls.push({ method: "selectRuntimeEngine", body });
        return { selectedEngineId: body.engine_id };
      },
      updateRuntimeEngine(id, body) {
        calls.push({ method: "updateRuntimeEngine", id, body });
        return { id, object: "runtime.engine.update" };
      },
      removeRuntimeEngineOverride(id) {
        calls.push({ method: "removeRuntimeEngineOverride", id });
        return { id, removed: true };
      },
      listInstances() {
        calls.push({ method: "listInstances" });
        return [{ id: "instance.loaded", status: "loaded" }, { id: "instance.idle", status: "idle" }];
      },
      authoritySnapshot(baseUrl) {
        calls.push({ method: "authoritySnapshot", baseUrl });
        return { id: "authority.snapshot", baseUrl };
      },
      listReceipts() {
        calls.push({ method: "listReceipts" });
        return [{ id: "receipt.route" }];
      },
      getReceipt(id) {
        calls.push({ method: "getReceipt", id });
        return { id };
      },
      receiptReplay(id) {
        calls.push({ method: "receiptReplay", id });
        return { receipt_id: id, replayed: true };
      },
    },
    listModels: retiredRouteWrapper,
    listModelCapabilities: retiredRouteWrapper,
  };

  const modelsResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/models" }), response: modelsResponse, store });
  assert.equal(modelsResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(modelsResponse.body), {
    object: "list",
    data: [{ id: "model.route" }],
  });

  const capabilitiesResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/model-capabilities" }),
    response: capabilitiesResponse,
    store,
  });
  assert.equal(capabilitiesResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(capabilitiesResponse.body), {
    capabilities: [{ model: "model.route", features: ["chat"] }],
  });

  for (const [path, expected] of [
    ["/v1/models/artifacts", [{ id: "artifact.route" }]],
    ["/v1/models/endpoints", [{ id: "endpoint.route" }]],
    ["/v1/models/providers", [{ id: "provider.route" }]],
    ["/v1/models/routes", [{ id: "route.route" }]],
    ["/v1/models/model.route", { id: "model.route", object: "model.artifact" }],
    ["/v1/model-mount/snapshot", { id: "snapshot.route", baseUrl: "http://daemon.test" }],
    ["/v1/model-mount/projection", { id: "projection.route" }],
    ["/v1/model-mount/mcp", [{ id: "mcp.route" }]],
    ["POST /v1/model-mount/mcp/import", { id: "mcp.import", object: "mcp.import" }],
    ["POST /v1/model-mount/mcp/invoke", { id: "mcp.invoke", object: "mcp.invoke" }],
    ["POST /v1/model-mount/workflows/nodes/execute", { id: "workflow.node", object: "workflow.node" }],
    ["POST /v1/model-mount/workflows/receipt-gate", { id: "receipt.gate", object: "receipt.gate" }],
    ["POST /v1/model-mount/routes", { id: "route.write", object: "route.upsert" }],
    ["POST /v1/model-mount/routes/route.route/test", { id: "route.route", object: "route.test" }],
    ["/v1/models/catalog/search?query=qwen", [{ id: "catalog.route", query: "qwen" }]],
    ["POST /v1/model-mount/catalog/import-url", { id: "catalog.import", object: "catalog.import" }],
    ["POST /v1/model-mount/artifacts/import", { id: "artifact.imported", object: "model.artifact" }],
    ["DELETE /v1/model-mount/artifacts/artifact.route", { id: "artifact.route", object: "model.artifact.deleted" }],
    ["POST /v1/model-mount/endpoints", { id: "endpoint.route", object: "model.endpoint" }],
    ["POST /v1/model-mount/downloads", { id: "download.route", object: "model.download" }],
    ["/v1/model-mount/downloads/download.route/status", { id: "download.route", status: "completed" }],
    ["POST /v1/model-mount/downloads/download.route/cancel", { id: "download.route", status: "canceled" }],
    ["POST /v1/model-mount/storage/cleanup", { status: "cleaned" }],
    ["POST /v1/model-mount/endpoints/endpoint.route/load", { id: "instance.loaded", object: "model.instance.loaded", endpoint_id: "endpoint.route" }],
    ["POST /v1/model-mount/endpoints/endpoint.route/unload", { id: "endpoint.route", object: "model.instance.unloaded" }],
    ["DELETE /v1/model-mount/endpoints/endpoint.route", { id: "endpoint.route", object: "model.endpoint.unmounted" }],
    ["/v1/model-mount/server/status", { id: "server.status", baseUrl: "http://daemon.test" }],
    ["POST /v1/model-mount/server/start", { id: "server.start", baseUrl: "http://daemon.test" }],
    ["POST /v1/model-mount/server/stop", { id: "server.stop", baseUrl: "http://daemon.test" }],
    ["POST /v1/model-mount/server/restart", { id: "server.restart", baseUrl: "http://daemon.test" }],
    ["/v1/model-mount/server/logs?limit=5", { id: "server.logs", limit: "5" }],
    ["/v1/model-mount/server/events?limit=6", { id: "server.events", limit: "6" }],
    ["/v1/model-mount/backends", [{ id: "backend.route" }]],
    ["POST /v1/model-mount/backends/backend.route/health", { id: "backend.route", object: "backend.health" }],
    ["POST /v1/model-mount/backends/backend.route/start", { id: "backend.route", object: "backend.start" }],
    ["POST /v1/model-mount/backends/backend.route/stop", { id: "backend.route", object: "backend.stop" }],
    ["/v1/model-mount/backends/backend.route/logs", { id: "backend.route", object: "backend.logs" }],
    ["/v1/model-mount/runtime/engines", [{ id: "engine.route" }]],
    ["/v1/model-mount/runtime/engines/engine.route", { id: "engine.route", object: "runtime.engine" }],
    ["POST /v1/model-mount/runtime/survey", { object: "runtime.survey" }],
    ["POST /v1/model-mount/runtime/select", {}],
    ["POST /v1/model-mount/runtime/engines/engine.route/select", { selectedEngineId: "engine.route" }],
    ["PATCH /v1/model-mount/runtime/engines/engine.route", { id: "engine.route", object: "runtime.engine.update" }],
    ["DELETE /v1/model-mount/runtime/engines/engine.route", { id: "engine.route", removed: true }],
    ["/v1/model-mount/instances", [{ id: "instance.loaded", status: "loaded" }, { id: "instance.idle", status: "idle" }]],
    ["/v1/model-mount/instances/loaded", [{ id: "instance.loaded", status: "loaded" }]],
    ["POST /v1/model-mount/instances/load", { id: "instance.loaded", object: "model.instance.loaded" }],
    ["POST /v1/model-mount/instances/unload", { id: "instance.unloaded", object: "model.instance.unloaded" }],
    ["POST /v1/model-mount/instances/instance.loaded/unload", { id: "instance.loaded", object: "model.instance.unloaded" }],
    ["/v1/model-mount/authority", { id: "authority.snapshot", baseUrl: "http://daemon.test" }],
    ["/v1/model-mount/receipts", [{ id: "receipt.route" }]],
    ["/v1/model-mount/receipts/receipt.route", { id: "receipt.route" }],
    ["/v1/model-mount/receipts/receipt.route/replay", { receipt_id: "receipt.route", replayed: true }],
  ]) {
    const methodMatch = path.match(/^(GET|POST|PATCH|DELETE) (.+)$/);
    const [method, routePath] = methodMatch ? [methodMatch[1], methodMatch[2]] : ["GET", path];
    const body = method === "PATCH" ? { label: "Engine route" } : {};
    const routeResponse = responseRecorder();
    await handleRequest({ request: request({ method, url: routePath, body }), response: routeResponse, store });
    const acceptedRoutes = new Set(["/v1/model-mount/catalog/import-url", "/v1/model-mount/downloads"]);
    const createdRoutes = new Set([
      "/v1/model-mount/routes",
      "/v1/model-mount/mcp/import",
      "/v1/model-mount/artifacts/import",
      "/v1/model-mount/endpoints",
      "/v1/model-mount/endpoints/endpoint.route/load",
      "/v1/model-mount/instances/load",
    ]);
    assert.equal(
      routeResponse.statusCode,
      acceptedRoutes.has(routePath) ? 202 : createdRoutes.has(routePath) ? 201 : 200,
    );
    assert.deepEqual(JSON.parse(routeResponse.body), expected);
  }

  assert.deepEqual(calls, [
    { method: "runtimeModelCatalogList" },
    { method: "listModelCapabilities" },
    { method: "listArtifacts" },
    { method: "listEndpoints" },
    { method: "listProviders" },
    { method: "listRoutes" },
    { method: "getModel", id: "model.route" },
    { method: "snapshot", baseUrl: "http://daemon.test" },
    { method: "projection" },
    { method: "listMcpServers" },
    { method: "importMcpJson", body: {} },
    { method: "invokeMcpTool", authorization: undefined, body: {} },
    { method: "executeWorkflowNode", authorization: undefined, body: {} },
    { method: "validateReceiptGate", body: {} },
    { method: "authorize", authorization: undefined, scope: "route.write:*" },
    { method: "upsertRoute", body: {} },
    { method: "authorize", authorization: undefined, scope: "route.use:route.route" },
    { method: "testRoute", id: "route.route", body: {} },
    { method: "catalogSearch", query: { query: "qwen" } },
    { method: "authorize", authorization: undefined, scope: "model.download:*" },
    { method: "authorize", authorization: undefined, scope: "model.import:*" },
    { method: "catalogImportUrl", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.import:*" },
    { method: "importModel", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.delete:*" },
    { method: "deleteModelArtifact", id: "artifact.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.mount:*" },
    { method: "mountEndpoint", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.download:*" },
    { method: "downloadModel", body: {} },
    { method: "downloadStatus", id: "download.route" },
    { method: "authorize", authorization: undefined, scope: "model.download:*" },
    { method: "cancelDownload", id: "download.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.delete:*" },
    { method: "cleanupModelStorage", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.load:*" },
    { method: "loadModel", body: { endpoint_id: "endpoint.route" } },
    { method: "authorize", authorization: undefined, scope: "model.unload:*" },
    { method: "unloadModel", body: { endpoint_id: "endpoint.route" } },
    { method: "authorize", authorization: undefined, scope: "model.unmount:*" },
    { method: "unmountEndpoint", body: { endpoint_id: "endpoint.route" } },
    { method: "serverStatus", baseUrl: "http://daemon.test" },
    { method: "authorize", authorization: undefined, scope: "server.control:*" },
    { method: "serverStart", baseUrl: "http://daemon.test" },
    { method: "authorize", authorization: undefined, scope: "server.control:*" },
    { method: "serverStop", baseUrl: "http://daemon.test" },
    { method: "authorize", authorization: undefined, scope: "server.control:*" },
    { method: "serverRestart", baseUrl: "http://daemon.test" },
    { method: "authorize", authorization: undefined, scope: "server.logs:*" },
    { method: "serverLogs", query: { limit: "5" } },
    { method: "authorize", authorization: undefined, scope: "server.logs:*" },
    { method: "serverEvents", query: { limit: "6" } },
    { method: "listBackends" },
    { method: "backendHealth", id: "backend.route" },
    { method: "authorize", authorization: undefined, scope: "backend.control:backend.route" },
    { method: "startBackend", id: "backend.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "backend.control:backend.route" },
    { method: "stopBackend", id: "backend.route" },
    { method: "backendLogs", id: "backend.route" },
    { method: "listRuntimeEngines" },
    { method: "runtimeEngine", id: "engine.route" },
    { method: "runtimeSurvey" },
    { method: "selectRuntimeEngine", body: {} },
    { method: "selectRuntimeEngine", body: { engine_id: "engine.route" } },
    { method: "updateRuntimeEngine", id: "engine.route", body: { label: "Engine route" } },
    { method: "removeRuntimeEngineOverride", id: "engine.route" },
    { method: "listInstances" },
    { method: "listInstances" },
    { method: "authorize", authorization: undefined, scope: "model.load:*" },
    { method: "loadModel", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.unload:*" },
    { method: "unloadModel", body: {} },
    { method: "authorize", authorization: undefined, scope: "model.unload:*" },
    { method: "unloadModel", body: { instance_id: "instance.loaded" } },
    { method: "authoritySnapshot", baseUrl: "http://daemon.test" },
    { method: "listReceipts" },
    { method: "getReceipt", id: "receipt.route" },
    { method: "receiptReplay", id: "receipt.route" },
  ]);
});

test("public runtime provider vault token and catalog controls use stable model mount protocol routes", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    modelMounting: {
      authorize(authorization, scope) {
        calls.push({ method: "authorize", authorization, scope });
      },
      getCatalogProviderConfig(id) {
        calls.push({ method: "getCatalogProviderConfig", id });
        return { id, object: "catalog.provider" };
      },
      configureCatalogProvider(id, body) {
        calls.push({ method: "configureCatalogProvider", id, body });
        return { id, object: "catalog.provider.configured" };
      },
      startCatalogProviderOAuth(id, body) {
        calls.push({ method: "startCatalogProviderOAuth", id, body });
        return { id, object: "catalog.oauth.start" };
      },
      completeCatalogProviderOAuth(id, body) {
        calls.push({ method: "completeCatalogProviderOAuth", id, body });
        return { id, object: "catalog.oauth.callback" };
      },
      exchangeCatalogProviderOAuth(id, body) {
        calls.push({ method: "exchangeCatalogProviderOAuth", id, body });
        return { id, object: "catalog.oauth.exchange" };
      },
      refreshCatalogProviderOAuth(id) {
        calls.push({ method: "refreshCatalogProviderOAuth", id });
        return { id, object: "catalog.oauth.refresh" };
      },
      revokeCatalogProviderOAuth(id) {
        calls.push({ method: "revokeCatalogProviderOAuth", id });
        return { id, object: "catalog.oauth.revoke" };
      },
      listTokens() {
        calls.push({ method: "listTokens" });
        return [{ id: "token.route" }];
      },
      createToken(body) {
        calls.push({ method: "createToken", body });
        return { id: "token.created", object: "token" };
      },
      tokenizeModel({ authorization, requiredScope, body }) {
        calls.push({ method: "tokenizeModel", authorization, requiredScope, body });
        return { tokens: [{ text: "route" }], token_count: 1 };
      },
      countModelTokens({ authorization, requiredScope, body }) {
        calls.push({ method: "countModelTokens", authorization, requiredScope, body });
        return { token_count: 7 };
      },
      fitModelContext({ authorization, requiredScope, body }) {
        calls.push({ method: "fitModelContext", authorization, requiredScope, body });
        return { fits: true, context_window: 2048 };
      },
      revokeToken(id) {
        calls.push({ method: "revokeToken", id });
        return { id, revoked: true };
      },
      listVaultRefs() {
        calls.push({ method: "listVaultRefs" });
        return [{ vault_ref: "vault://route" }];
      },
      bindVaultRef(body) {
        calls.push({ method: "bindVaultRef", body });
        return { vault_ref: "vault://route", bound: true };
      },
      removeVaultRef(body) {
        calls.push({ method: "removeVaultRef", body });
        return { vault_ref: body.vault_ref, removed: true };
      },
      vaultRefMetadata(body) {
        calls.push({ method: "vaultRefMetadata", body });
        return { vault_ref: body.vault_ref, redacted: true };
      },
      vaultStatus() {
        calls.push({ method: "vaultStatus" });
        return { status: "ready" };
      },
      vaultHealth() {
        calls.push({ method: "vaultHealth" });
        return { status: "healthy" };
      },
      latestVaultHealth() {
        calls.push({ method: "latestVaultHealth" });
        return { status: "latest" };
      },
      listProviders() {
        calls.push({ method: "listProviders" });
        return [{ id: "provider.route" }];
      },
      upsertProvider(body) {
        calls.push({ method: "upsertProvider", body });
        return { id: body.id ?? "provider.created", object: "provider" };
      },
      latestProviderHealth(id) {
        calls.push({ method: "latestProviderHealth", id });
        return { id, status: "latest" };
      },
      providerHealth(id) {
        calls.push({ method: "providerHealth", id });
        return { id, status: "healthy" };
      },
      listProviderModels(id) {
        calls.push({ method: "listProviderModels", id });
        return [{ id: "provider.model", provider_id: id }];
      },
      listProviderLoaded(id) {
        calls.push({ method: "listProviderLoaded", id });
        return [{ id: "provider.loaded", provider_id: id }];
      },
      startProvider(id) {
        calls.push({ method: "startProvider", id });
        return { id, status: "started" };
      },
      stopProvider(id) {
        calls.push({ method: "stopProvider", id });
        return { id, status: "stopped" };
      },
    },
  };

  for (const [path, expected, status = 200] of [
    ["/v1/model-mount/catalog/providers/catalog.route", { id: "catalog.route", object: "catalog.provider" }],
    ["PATCH /v1/model-mount/catalog/providers/catalog.route", { id: "catalog.route", object: "catalog.provider.configured" }],
    ["POST /v1/model-mount/catalog/providers/catalog.route/oauth/start", { id: "catalog.route", object: "catalog.oauth.start" }, 201],
    ["POST /v1/model-mount/catalog/providers/catalog.route/oauth/callback", { id: "catalog.route", object: "catalog.oauth.callback" }, 201],
    ["POST /v1/model-mount/catalog/providers/catalog.route/oauth/exchange", { id: "catalog.route", object: "catalog.oauth.exchange" }, 201],
    ["POST /v1/model-mount/catalog/providers/catalog.route/oauth/refresh", { id: "catalog.route", object: "catalog.oauth.refresh" }],
    ["POST /v1/model-mount/catalog/providers/catalog.route/oauth/revoke", { id: "catalog.route", object: "catalog.oauth.revoke" }],
    ["/v1/model-mount/tokens", [{ id: "token.route" }]],
    ["POST /v1/model-mount/tokens", { id: "token.created", object: "token" }, 201],
    ["POST /v1/model-mount/tokens/tokenize", { tokens: [{ text: "route" }], token_count: 1 }],
    ["POST /v1/model-mount/tokens/count", { token_count: 7 }],
    ["POST /v1/model-mount/context/fit", { fits: true, context_window: 2048 }],
    ["DELETE /v1/model-mount/tokens/token.route", { id: "token.route", revoked: true }],
    ["/v1/model-mount/vault/refs", [{ vault_ref: "vault://route" }]],
    ["POST /v1/model-mount/vault/refs", { vault_ref: "vault://route", bound: true }, 201],
    ["DELETE /v1/model-mount/vault/refs", { vault_ref: "vault://route", removed: true }],
    ["POST /v1/model-mount/vault/refs/meta", { vault_ref: "vault://route", redacted: true }],
    ["/v1/model-mount/vault/status", { status: "ready" }],
    ["POST /v1/model-mount/vault/health", { status: "healthy" }],
    ["/v1/model-mount/vault/health/latest", { status: "latest" }],
    ["/v1/model-mount/providers", [{ id: "provider.route" }]],
    ["POST /v1/model-mount/providers", { id: "provider.created", object: "provider" }, 201],
    ["PATCH /v1/model-mount/providers/provider.route", { id: "provider.route", object: "provider" }],
    ["/v1/model-mount/providers/provider.route/health/latest", { id: "provider.route", status: "latest" }],
    ["POST /v1/model-mount/providers/provider.route/health", { id: "provider.route", status: "healthy" }],
    ["/v1/model-mount/providers/provider.route/models", [{ id: "provider.model", provider_id: "provider.route" }]],
    ["/v1/model-mount/providers/provider.route/loaded", [{ id: "provider.loaded", provider_id: "provider.route" }]],
    ["POST /v1/model-mount/providers/provider.route/start", { id: "provider.route", status: "started" }],
    ["POST /v1/model-mount/providers/provider.route/stop", { id: "provider.route", status: "stopped" }],
  ]) {
    const methodMatch = path.match(/^(GET|POST|PATCH|DELETE) (.+)$/);
    const [method, routePath] = methodMatch ? [methodMatch[1], methodMatch[2]] : ["GET", path];
    const body = routePath.includes("/vault/") ? { vault_ref: "vault://route" } : {};
    const routeResponse = responseRecorder();
    await handleRequest({ request: request({ method, url: routePath, body }), response: routeResponse, store });
    assert.equal(routeResponse.statusCode, status);
    assert.deepEqual(JSON.parse(routeResponse.body), expected);
  }

  assert.deepEqual(calls, [
    { method: "getCatalogProviderConfig", id: "catalog.route" },
    { method: "authorize", authorization: undefined, scope: "provider.write:catalog.route" },
    { method: "configureCatalogProvider", id: "catalog.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "provider.write:catalog.route" },
    { method: "authorize", authorization: undefined, scope: "vault.write:*" },
    { method: "startCatalogProviderOAuth", id: "catalog.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "provider.write:catalog.route" },
    { method: "authorize", authorization: undefined, scope: "vault.write:*" },
    { method: "completeCatalogProviderOAuth", id: "catalog.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "provider.write:catalog.route" },
    { method: "authorize", authorization: undefined, scope: "vault.write:*" },
    { method: "exchangeCatalogProviderOAuth", id: "catalog.route", body: {} },
    { method: "authorize", authorization: undefined, scope: "provider.write:catalog.route" },
    { method: "authorize", authorization: undefined, scope: "vault.write:*" },
    { method: "refreshCatalogProviderOAuth", id: "catalog.route" },
    { method: "authorize", authorization: undefined, scope: "provider.write:catalog.route" },
    { method: "authorize", authorization: undefined, scope: "vault.delete:*" },
    { method: "revokeCatalogProviderOAuth", id: "catalog.route" },
    { method: "listTokens" },
    { method: "createToken", body: {} },
    { method: "tokenizeModel", authorization: undefined, requiredScope: "model.tokenize:*", body: {} },
    { method: "countModelTokens", authorization: undefined, requiredScope: "model.tokenize:*", body: {} },
    { method: "fitModelContext", authorization: undefined, requiredScope: "model.context:*", body: {} },
    { method: "revokeToken", id: "token.route" },
    { method: "authorize", authorization: undefined, scope: "vault.read:*" },
    { method: "listVaultRefs" },
    { method: "authorize", authorization: undefined, scope: "vault.write:*" },
    { method: "bindVaultRef", body: { vault_ref: "vault://route" } },
    { method: "authorize", authorization: undefined, scope: "vault.delete:*" },
    { method: "removeVaultRef", body: { vault_ref: "vault://route" } },
    { method: "authorize", authorization: undefined, scope: "vault.read:*" },
    { method: "vaultRefMetadata", body: { vault_ref: "vault://route" } },
    { method: "authorize", authorization: undefined, scope: "vault.read:*" },
    { method: "vaultStatus" },
    { method: "authorize", authorization: undefined, scope: "vault.read:*" },
    { method: "vaultHealth" },
    { method: "authorize", authorization: undefined, scope: "vault.read:*" },
    { method: "latestVaultHealth" },
    { method: "listProviders" },
    { method: "authorize", authorization: undefined, scope: "provider.write:*" },
    { method: "upsertProvider", body: {} },
    { method: "authorize", authorization: undefined, scope: "provider.write:provider.route" },
    { method: "upsertProvider", body: { id: "provider.route" } },
    { method: "latestProviderHealth", id: "provider.route" },
    { method: "providerHealth", id: "provider.route" },
    { method: "listProviderModels", id: "provider.route" },
    { method: "listProviderLoaded", id: "provider.route" },
    { method: "authorize", authorization: undefined, scope: "provider.control:provider.route" },
    { method: "startProvider", id: "provider.route" },
    { method: "authorize", authorization: undefined, scope: "provider.control:provider.route" },
    { method: "stopProvider", id: "provider.route" },
  ]);
});

test("public runtime studio intent route uses Rust daemon-core projection", async () => {
  const calls = [];
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const contextPolicyCore = {
    projectStudioIntentFrame(request) {
      calls.push({ method: "projectStudioIntentFrame", request });
      return {
        frame: {
          object: "ioi.studio_intent_frame",
          route_directive: "agent",
          target: request.prompt,
        },
      };
    },
  };
  const store = {
    resolveStudioIntentFrame: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/studio/intent-frame",
      body: { prompt: "inspect the runtime", execution_mode: "ask" },
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(calls, [
    {
      method: "projectStudioIntentFrame",
      request: {
        operation: "studio_intent_frame_projection",
        operation_kind: "studio.intent_frame.projection",
        prompt: "inspect the runtime",
        input: undefined,
        query: undefined,
        execution_mode: "ask",
        source: "public_runtime_routes./v1/studio/intent-frame",
      },
    },
  ]);
  assert.deepEqual(JSON.parse(response.body), {
    object: "ioi.studio_intent_frame",
    route_directive: "agent",
    target: "inspect the runtime",
  });
});

test("public runtime account node and tool routes use mounted tool API", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    toolApi: {
      getAccount() {
        calls.push({ method: "getAccount" });
        return { account_id: "acct_route" };
      },
      listRuntimeNodes() {
        calls.push({ method: "listRuntimeNodes" });
        return { nodes: [] };
      },
      listTools(options) {
        calls.push({ method: "listTools", options });
        return { tools: [], pack: options.pack };
      },
    },
    getAccount: retiredRouteWrapper,
    listRuntimeNodes: retiredRouteWrapper,
    listTools: retiredRouteWrapper,
  };

  const accountResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/account" }), response: accountResponse, store });
  assert.deepEqual(JSON.parse(accountResponse.body), { account_id: "acct_route" });

  const nodesResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/runtime/nodes" }), response: nodesResponse, store });
  assert.deepEqual(JSON.parse(nodesResponse.body), { nodes: [] });

  const toolsResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/tools?pack=coding" }), response: toolsResponse, store });
  assert.deepEqual(JSON.parse(toolsResponse.body), { tools: [], pack: "coding" });

  assert.deepEqual(calls, [
    { method: "getAccount" },
    { method: "listRuntimeNodes" },
    { method: "listTools", options: { pack: "coding" } },
  ]);
});

test("public runtime routes delegate thread subroutes unchanged", async () => {
  const { calls, handleRequest } = routeHarness();
  const response = responseRecorder();

  await handleRequest({ request: request({ url: "/v1/threads/thread_123/events" }), response, store: {} });

  assert.deepEqual(calls, ["thread"]);
  assert.equal(response.ended, false);
});

test("public runtime agent and thread list routes use store-owned lifecycle projection API", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    projectRuntimeLifecycleProjection(projectionKind, facts = {}) {
      calls.push({ projectionKind, facts });
      if (projectionKind === "agents") {
        return [{ id: "agent_route" }];
      }
      if (projectionKind === "threads") {
        return [{ thread_id: "thread_route" }];
      }
      return null;
    },
  };

  const agentsResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/agents" }), response: agentsResponse, store });
  assert.equal(agentsResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(agentsResponse.body), [{ id: "agent_route" }]);

  const threadsResponse = responseRecorder();
  await handleRequest({ request: request({ url: "/v1/threads" }), response: threadsResponse, store });
  assert.equal(threadsResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(threadsResponse.body), [{ thread_id: "thread_route" }]);
  assert.deepEqual(calls, [
    { projectionKind: "agents", facts: {} },
    { projectionKind: "threads", facts: {} },
  ]);
});

test("public runtime run list route uses store-owned lifecycle projection API", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const store = {
    projectRuntimeLifecycleProjection(projectionKind, facts = {}) {
      calls.push({ projectionKind, facts });
      return [{ id: "run_route", agent_id: facts.agent_id ?? null }];
    },
  };

  await handleRequest({
    request: request({ url: "/v1/runs?agent_id=agent-canonical" }),
    response,
    store,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), [
    { id: "run_route", agent_id: "agent-canonical" },
  ]);
  assert.deepEqual(calls, [{ projectionKind: "agent_runs", facts: { agent_id: "agent-canonical" } }]);

  const unfilteredResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/runs" }),
    response: unfilteredResponse,
    store,
  });

  assert.deepEqual(calls.at(-1), { projectionKind: "runs", facts: {} });
  assert.equal(unfilteredResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(unfilteredResponse.body), [
    { id: "run_route", agent_id: null },
  ]);
});

test("public runtime agent create route uses direct Rust lifecycle API", async () => {
  const calls = [];
  const { handleRequest } = routeHarness({
    createLifecycleAgent(surfaceStore, options, deps) {
      calls.push({ surfaceStore, options, deps });
      const error = new Error("agent creation requires Rust core");
      error.status = 501;
      error.code = "runtime_agent_create_rust_core_required";
      error.details = { rust_core_boundary: "runtime.agent_create", requested_cwd: options.local?.cwd };
      throw error;
    },
  });
  const response = responseRecorder();
  const contextPolicyCore = { direct: true };
  const store = {
    createAgent: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/agents",
      body: { options: { local: { cwd: "/workspace/project" } } },
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 501);
  assert.equal(response.error.code, "runtime_agent_create_rust_core_required");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].surfaceStore, store);
  assert.deepEqual(calls[0].options, { local: { cwd: "/workspace/project" } });
  assert.equal(calls[0].deps.lifecycleAdmissionRunner, contextPolicyCore);
  assert.equal(Object.hasOwn(store, "agentRunLifecycleSurface"), false);
});

test("public runtime thread create route uses direct Rust lifecycle API", async () => {
  const calls = [];
  const { handleRequest } = routeHarness({
    async createLifecycleThread(surfaceStore, body, deps) {
      calls.push({ surfaceStore, body, deps });
      return {
        thread_id: "thread_route",
        status: "active",
      };
    },
  });
  const response = responseRecorder();
  const contextPolicyCore = { direct: true };
  const store = {
    createThread: retiredRouteWrapper,
  };

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/threads",
      body: { options: { local: { cwd: "/workspace/project" } } },
    }),
    response,
    store,
    contextPolicyCore,
  });

  assert.equal(response.statusCode, 200);
  assert.deepEqual(JSON.parse(response.body), {
    thread_id: "thread_route",
    status: "active",
  });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].surfaceStore, store);
  assert.deepEqual(calls[0].body, { options: { local: { cwd: "/workspace/project" } } });
  assert.equal(calls[0].deps.lifecycleAdmissionRunner, contextPolicyCore);
  assert.equal(Object.hasOwn(store, "agentRunLifecycleSurface"), false);
});

test("public runtime usage and authority evidence routes use store-owned lifecycle projection API", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    projectRuntimeLifecycleProjection(projectionKind, facts = {}) {
      calls.push({ projectionKind, facts });
      if (projectionKind === "usage_list") {
        return {
          schema_version: "runtime.usage.telemetry.v1",
          items: [{ run_id: "run_route" }],
        };
      }
      if (projectionKind === "authority_evidence_summary") {
        return {
          schema_version: "authority.evidence.summary.v1",
          filters: facts,
        };
      }
      return null;
    },
    listUsage: retiredRouteWrapper,
    authorityEvidenceSummary: retiredRouteWrapper,
  };

  const usageResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/usage?group_by=thread&agent_id=agent_route" }),
    response: usageResponse,
    store,
  });

  assert.equal(usageResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(usageResponse.body), {
    payload: {
      schema_version: "runtime.usage.telemetry.v1",
      items: [{ run_id: "run_route" }],
    },
    metadata: { requestMetadata: true },
  });

  const evidenceResponse = responseRecorder();
  await handleRequest({
    request: request({ url: "/v1/authority-evidence?thread_id=thread_route" }),
    response: evidenceResponse,
    store,
  });

  assert.equal(evidenceResponse.statusCode, 200);
  assert.deepEqual(JSON.parse(evidenceResponse.body), {
    schema_version: "authority.evidence.summary.v1",
    filters: { thread_id: "thread_route" },
  });
  assert.deepEqual(calls, [
    {
      projectionKind: "usage_list",
      facts: { group_by: "thread", agent_id: "agent_route" },
    },
    {
      projectionKind: "authority_evidence_summary",
      facts: { thread_id: "thread_route" },
    },
  ]);
});

test("public runtime top-level memory context routes are retired", async () => {
  const { handleRequest } = routeHarness({
    notFound(message, details) {
      throw Object.assign(new Error(message), {
        status: 404,
        code: "route_not_found",
        details,
      });
    },
  });
  const store = {
    threadMemorySurface: {
      publicMemoryStatus() {
        assert.fail("retired top-level memory status route must not reach the memory surface");
      },
      publicMemoryProjectionForContext() {
        assert.fail("retired top-level memory records route must not reach the memory surface");
      },
      publicMemoryPolicyForContext() {
        assert.fail("retired top-level memory policy route must not reach the memory surface");
      },
      publicMemoryPathForContext() {
        assert.fail("retired top-level memory path route must not reach the memory surface");
      },
      publicValidateMemory() {
        assert.fail("retired top-level memory validation route must not reach the memory surface");
      },
    },
  };

  for (const route of [
    { method: "GET", url: "/v1/memory?thread_id=thread_route", path: "/v1/memory" },
    { method: "GET", url: "/v1/memory/records?thread_id=thread_route", path: "/v1/memory/records" },
    { method: "GET", url: "/v1/memory/policy?agent_id=agent_route", path: "/v1/memory/policy" },
    { method: "GET", url: "/v1/memory/path?thread_id=thread_route", path: "/v1/memory/path" },
    { method: "POST", url: "/v1/memory/validate", path: "/v1/memory/validate", body: { thread_id: "thread_route" } },
  ]) {
    const response = responseRecorder();
    await handleRequest({
      request: request({ method: route.method, url: route.url, body: route.body }),
      response,
      store,
    });
    assert.equal(response.statusCode, 404);
    assert.equal(response.error.code, "route_not_found");
    assert.deepEqual(response.error.details, { method: route.method, path: route.path });
  }
});

test("public conversation artifact routes use store-owned Rust artifact API", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    listConversationArtifacts(query) {
      calls.push({ method: "listConversationArtifacts", query });
      return [{ id: "artifact_route", thread_id: query.thread_id }];
    },
    createConversationArtifact(threadId, input) {
      calls.push({ method: "createConversationArtifact", threadId, input });
      return { artifact_id: "artifact_created", thread_id: threadId, input, commit_hash: "commit-created" };
    },
    getConversationArtifact(artifactId) {
      calls.push({ method: "getConversationArtifact", artifactId });
      return { id: artifactId, thread_id: "thread_route" };
    },
    listConversationArtifactRevisions(artifactId) {
      calls.push({ method: "listConversationArtifactRevisions", artifactId });
      return [{ revision_id: "revision_route", artifact_id: artifactId }];
    },
    performConversationArtifactAction(artifactId, input) {
      calls.push({ method: "performConversationArtifactAction", artifactId, input });
      return { artifact_id: artifactId, action_kind: input.action_kind, commit_hash: "commit-action" };
    },
    exportConversationArtifact(artifactId, input) {
      calls.push({ method: "exportConversationArtifact", artifactId, input });
      return { artifact_id: artifactId, export_format: input.export_format, commit_hash: "commit-export" };
    },
    promoteConversationArtifact(artifactId, input) {
      calls.push({ method: "promoteConversationArtifact", artifactId, input });
      return { artifact_id: artifactId, promotion_target: input.promotion_target, commit_hash: "commit-promote" };
    },
  };

  const requests = [
    {
      req: request({ url: "/v1/conversation-artifacts?thread_id=thread_route" }),
      status: 200,
      body: [{ id: "artifact_route", thread_id: "thread_route" }],
    },
    {
      req: request({
      method: "POST",
      url: "/v1/conversation-artifacts",
      body: { thread_id: "thread_route", title: "Draft" },
      }),
      status: 201,
      body: { artifact_id: "artifact_created", thread_id: "thread_route", input: { thread_id: "thread_route", title: "Draft" }, commit_hash: "commit-created" },
    },
    {
      req: request({ url: "/v1/conversation-artifacts/artifact_route" }),
      status: 200,
      body: { id: "artifact_route", thread_id: "thread_route" },
    },
    {
      req: request({ url: "/v1/conversation-artifacts/artifact_route/revisions" }),
      status: 200,
      body: [{ revision_id: "revision_route", artifact_id: "artifact_route" }],
    },
    {
      req: request({
      method: "POST",
      url: "/v1/conversation-artifacts/artifact_route/actions",
      body: { action_kind: "edit" },
      }),
      status: 200,
      body: { artifact_id: "artifact_route", action_kind: "edit", commit_hash: "commit-action" },
    },
    {
      req: request({
      method: "POST",
      url: "/v1/conversation-artifacts/artifact_route/export",
      body: { export_format: "zip" },
      }),
      status: 200,
      body: { artifact_id: "artifact_route", export_format: "zip", commit_hash: "commit-export" },
    },
    {
      req: request({
      method: "POST",
      url: "/v1/conversation-artifacts/artifact_route/promote",
      body: { promotion_target: "canvas" },
      }),
      status: 200,
      body: { artifact_id: "artifact_route", promotion_target: "canvas", commit_hash: "commit-promote" },
    },
  ];

  for (const { req, status, body } of requests) {
    const response = responseRecorder();
    await handleRequest({ request: req, response, store });
    assert.equal(response.statusCode, status);
    assert.deepEqual(JSON.parse(response.body), body);
  }

  assert.deepEqual(
    calls.map(({ method, query, threadId, artifactId, input }) => ({
      method,
      query,
      threadId,
      artifactId,
      input,
    })),
    [
      {
        method: "listConversationArtifacts",
        query: { thread_id: "thread_route" },
        threadId: undefined,
        artifactId: undefined,
        input: undefined,
      },
      {
        method: "createConversationArtifact",
        query: undefined,
        threadId: "thread_route",
        artifactId: undefined,
        input: { thread_id: "thread_route", title: "Draft" },
      },
      {
        method: "getConversationArtifact",
        query: undefined,
        threadId: undefined,
        artifactId: "artifact_route",
        input: undefined,
      },
      {
        method: "listConversationArtifactRevisions",
        query: undefined,
        threadId: undefined,
        artifactId: "artifact_route",
        input: undefined,
      },
      {
        method: "performConversationArtifactAction",
        query: undefined,
        threadId: undefined,
        artifactId: "artifact_route",
        input: { action_kind: "edit" },
      },
      {
        method: "exportConversationArtifact",
        query: undefined,
        threadId: undefined,
        artifactId: "artifact_route",
        input: { export_format: "zip" },
      },
      {
        method: "promoteConversationArtifact",
        query: undefined,
        threadId: undefined,
        artifactId: "artifact_route",
        input: { promotion_target: "canvas" },
      },
    ],
  );
});

test("public runtime task and job routes use store-owned task job API directly", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const body = { prompt: "plan the cutover" };
  const apiResult = (method, args) => ({
    status: "blocked",
    method,
    args,
  });
  const store = {
    createRuntimeTask(requestBody) {
      calls.push({ method: "createRuntimeTask", args: [requestBody] });
      return apiResult("createRuntimeTask", [requestBody]);
    },
    listRuntimeTasks(options) {
      calls.push({ method: "listRuntimeTasks", args: [options] });
      return apiResult("listRuntimeTasks", [options]);
    },
    getRuntimeTask(taskId) {
      calls.push({ method: "getRuntimeTask", args: [taskId] });
      return apiResult("getRuntimeTask", [taskId]);
    },
    cancelRuntimeTask(taskId) {
      calls.push({ method: "cancelRuntimeTask", args: [taskId] });
      return apiResult("cancelRuntimeTask", [taskId]);
    },
    listRuntimeJobs(options) {
      calls.push({ method: "listRuntimeJobs", args: [options] });
      return apiResult("listRuntimeJobs", [options]);
    },
    getRuntimeJob(jobId) {
      calls.push({ method: "getRuntimeJob", args: [jobId] });
      return apiResult("getRuntimeJob", [jobId]);
    },
    cancelRuntimeJob(jobId) {
      calls.push({ method: "cancelRuntimeJob", args: [jobId] });
      return apiResult("cancelRuntimeJob", [jobId]);
    },
  };
  const cases = [
    {
      method: "POST",
      path: "/v1/tasks",
      apiMethod: "createRuntimeTask",
      expectedArgs: [body],
    },
    {
      method: "GET",
      path: "/v1/tasks?agent_id=agent-canonical",
      apiMethod: "listRuntimeTasks",
      expectedArgs: [{ agent_id: "agent-canonical" }],
    },
    {
      method: "GET",
      path: "/v1/tasks/task_1",
      apiMethod: "getRuntimeTask",
      expectedArgs: ["task_1"],
    },
    {
      method: "POST",
      path: "/v1/tasks/task_1/cancel",
      apiMethod: "cancelRuntimeTask",
      expectedArgs: ["task_1"],
    },
    {
      method: "GET",
      path: "/v1/jobs?agent_id=agent-canonical",
      apiMethod: "listRuntimeJobs",
      expectedArgs: [{ agent_id: "agent-canonical" }],
    },
    {
      method: "GET",
      path: "/v1/jobs/job_1",
      apiMethod: "getRuntimeJob",
      expectedArgs: ["job_1"],
    },
    {
      method: "POST",
      path: "/v1/jobs/job_1/cancel",
      apiMethod: "cancelRuntimeJob",
      expectedArgs: ["job_1"],
    },
  ];

  for (const testCase of cases) {
    const response = responseRecorder();
    await handleRequest({
      request: request({
        method: testCase.method,
        url: testCase.path,
        body,
      }),
      response,
      store,
    });
    const call = calls.pop();
    assert.equal(response.statusCode, 200);
    assert.equal(call.method, testCase.apiMethod);
    assert.deepEqual(call.args, testCase.expectedArgs);
    assert.deepEqual(JSON.parse(response.body), {
      status: "blocked",
      method: testCase.apiMethod,
      args: testCase.expectedArgs,
    });
  }
});

test("public runtime context budget route uses store-owned context policy API", async () => {
  const { handleRequest } = routeHarness();
  const response = responseRecorder();
  const calls = [];
  const body = { request_id: "public-context-budget-route-test" };
  const store = {
    contextPolicySurface: {
      evaluateContextBudget: retiredRouteWrapper,
    },
    evaluateContextBudget(input) {
      calls.push({ input });
      return {
        status: "rust_core_required",
        input,
        direct_truth_write_allowed: false,
      };
    },
  };

  await handleRequest({
    request: request({ method: "POST", url: "/v1/context-budget", body }),
    response,
    store,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].input, { request: body });
  assert.deepEqual(JSON.parse(response.body), {
    status: "rust_core_required",
    input: { request: body },
    direct_truth_write_allowed: false,
  });
});

test("public runtime top-level MCP route family is retired", async () => {
  const { handleRequest } = routeHarness({
    notFound(message, details) {
      throw Object.assign(new Error(message), {
        status: 404,
        code: "route_not_found",
        details,
      });
    },
  });
  const failRetiredRoute = () => assert.fail("retired top-level MCP route must not reach an MCP surface");
  const store = {
    mcpCatalogApi: {
      mcpStatus: failRetiredRoute,
      listMcpServers: failRetiredRoute,
      listMcpTools: failRetiredRoute,
      searchMcpTools: failRetiredRoute,
      getMcpTool: failRetiredRoute,
      listMcpResources: failRetiredRoute,
      listMcpPrompts: failRetiredRoute,
      validateMcp: failRetiredRoute,
    },
    mcpControlApi: {
      importMcp: failRetiredRoute,
      addMcpServer: failRetiredRoute,
      setMcpServerEnabled: failRetiredRoute,
      removeMcpServer: failRetiredRoute,
      invokeMcpTool: failRetiredRoute,
    },
    mcpServeApi: {
      mcpServeStatus: failRetiredRoute,
      handleMcpServeJsonRpc: failRetiredRoute,
    },
  };
  const cases = [
    { method: "GET", path: "/v1/mcp?thread_id=thread_route" },
    { method: "GET", path: "/v1/mcp/servers?thread_id=thread_route" },
    { method: "GET", path: "/v1/mcp/tools" },
    { method: "GET", path: "/v1/mcp/tools/search?query=diff" },
    { method: "GET", path: "/v1/mcp/tools/mcp.tool" },
    { method: "GET", path: "/v1/mcp/resources" },
    { method: "GET", path: "/v1/mcp/prompts" },
    { method: "POST", path: "/v1/mcp/validate" },
    { method: "POST", path: "/v1/mcp/import?thread_id=thread_route" },
    { method: "POST", path: "/v1/mcp/servers" },
    { method: "POST", path: "/v1/mcp/servers/mcp.docs/enable" },
    { method: "POST", path: "/v1/mcp/servers/mcp.docs/disable" },
    { method: "DELETE", path: "/v1/mcp/servers/mcp.docs" },
    { method: "POST", path: "/v1/mcp/servers/mcp.docs/remove" },
    { method: "POST", path: "/v1/mcp/tools/mcp.tool/invoke" },
    { method: "GET", path: "/v1/mcp/serve?thread_id=thread-retired" },
    { method: "POST", path: "/v1/mcp/serve?thread_id=thread-retired" },
  ];

  for (const { method, path } of cases) {
    const response = responseRecorder();
    await handleRequest({
      request: request({
        method,
        url: path,
        body: { request_id: "public-mcp-route-test" },
      }),
      response,
      store,
    });

    assert.equal(response.statusCode, 404);
    assert.equal(response.error.code, "route_not_found");
    assert.deepEqual(response.error.details, { method, path: new URL(path, "http://daemon.test").pathname });
  }
});

test("public runtime MCP serve route accepts stable protocol admission envelope", async () => {
  const { handleRequest } = routeHarness();
  const calls = [];
  const store = {
    mcpServeApi: {
      handleMcpServeJsonRpc: retiredRouteWrapper,
    },
    handleMcpServeJsonRpc(threadId, message, options) {
      calls.push({ thisArg: this, threadId, message, options });
      return { jsonrpc: "2.0", id: message.id, result: { ok: true } };
    },
  };
  const admission = {
    authority_grant_refs: ["wallet.network://grant/mcp-serve/git.diff"],
    authority_receipt_refs: ["receipt://wallet.network/mcp-serve/git.diff"],
    custody_ref: "ctee://workspace/thread-route",
    containment_ref: "containment://mcp-serve/thread-route/git.diff",
  };
  const response = responseRecorder();

  await handleRequest({
    request: request({
      method: "POST",
      url: "/v1/threads/thread_route/mcp/serve",
      body: {
        schema_version: "ioi.runtime.mcp-serve-client.v1",
        source: "sdk_client",
        ...admission,
        message: {
          jsonrpc: "2.0",
          id: 31,
          method: "tools/call",
          params: { name: "git.diff", arguments: { includeStat: true } },
        },
      },
    }),
    response,
    store,
  });

  assert.equal(response.statusCode, 200);
  assert.equal(calls[0].thisArg, store);
  assert.equal(calls[0].threadId, "thread_route");
  assert.equal(calls[0].message.method, "tools/call");
  assert.deepEqual(calls[0].options.authority_grant_refs, admission.authority_grant_refs);
  assert.deepEqual(calls[0].options.authority_receipt_refs, admission.authority_receipt_refs);
  assert.equal(calls[0].options.custody_ref, admission.custody_ref);
  assert.equal(calls[0].options.containment_ref, admission.containment_ref);
  assert.equal(calls[0].options.thread_id, "thread_route");
  assert.deepEqual(JSON.parse(response.body), { jsonrpc: "2.0", id: 31, result: { ok: true } });
});

test("public runtime MCP serve route rejects query or raw JSON-RPC compatibility transport", async () => {
  const { handleRequest } = routeHarness();
  const store = {
    mcpServeStatus: retiredRouteWrapper,
    handleMcpServeJsonRpc: retiredRouteWrapper,
    mcpServeApi: {
      mcpServeStatus: retiredRouteWrapper,
      handleMcpServeJsonRpc: retiredRouteWrapper,
    },
  };

  for (const { method, url, body, code } of [
    {
      method: "GET",
      url: "/v1/threads/thread_route/mcp/serve?server_id=mcp.docs",
      body: {},
      code: "runtime_mcp_serve_query_context_retired",
    },
    {
      method: "POST",
      url: "/v1/threads/thread_route/mcp/serve?server_id=mcp.docs",
      body: {
        schema_version: "ioi.runtime.mcp-serve-client.v1",
        message: { jsonrpc: "2.0", id: 32, method: "tools/list" },
      },
      code: "runtime_mcp_serve_query_context_retired",
    },
    {
      method: "POST",
      url: "/v1/threads/thread_route/mcp/serve",
      body: { jsonrpc: "2.0", id: 33, method: "tools/list" },
      code: "runtime_mcp_serve_protocol_envelope_required",
    },
  ]) {
    const response = responseRecorder();
    await handleRequest({
      request: request({ method, url, body }),
      response,
      store,
    });

    assert.equal(response.statusCode, 400);
    assert.equal(response.error.code, code);
  }
});
