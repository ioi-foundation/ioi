import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  DEFAULT_HARNESS_PROFILE_OPTION,
  HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES,
  HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
  HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE,
  HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE,
  HYPERVISOR_HARNESS_PUBLIC_FIXTURE_RUN_PATH,
  HYPERVISOR_HARNESS_SELECTION_OPTIONS,
  HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  buildHarnessAdapterReceiptDraft,
  buildHarnessCompatibilityVerdict,
  buildHarnessPublicFixtureRunRequest,
  getHarnessSelectionRef,
  isAgentHarnessAdapterOption,
  modelRouteSupportsHypervisorMountFromInventory,
  normalizeHarnessComparisonRunFromPublicFixtureRun,
  requestHarnessPublicFixtureRun,
} from "./harnessAdapterModel.ts";
import {
  HYPERVISOR_SESSION_LAUNCH_RECIPES,
  HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES,
  buildHypervisorLaunchedSessionProjection,
  buildHypervisorNewSessionLaunchSummary,
  buildHypervisorWorkbenchAdapterAdmissionFailure,
  buildWorkbenchAdapterLaunchPlan,
  requestWorkbenchAdapterLaunchPlanAdmission,
  WorkbenchAdapterLaunchAdmissionError,
} from "./hypervisorShellNavigationModel.ts";

test("default harness profile is the IOI reference scaffold, not an external adapter", () => {
  assert.equal(DEFAULT_HARNESS_PROFILE_OPTION.selection_kind, "harness_profile");
  assert.equal(
    DEFAULT_HARNESS_PROFILE_OPTION.role,
    "reference_scaffold_fallback",
  );
  assert.equal(
    getHarnessSelectionRef(DEFAULT_HARNESS_PROFILE_OPTION),
    "harness-profile:default_harness_profile",
  );
  assert.equal(
    HYPERVISOR_HARNESS_SELECTION_OPTIONS[0],
    DEFAULT_HARNESS_PROFILE_OPTION,
  );
  assert.equal(
    isAgentHarnessAdapterOption(DEFAULT_HARNESS_PROFILE_OPTION),
    false,
  );
});

test("external coding tools are proposal-source AgentHarnessAdapters", () => {
  const adapterIds = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.map(
    (profile) => profile.adapter_id,
  );

  assert.deepEqual(adapterIds, [
    "codex_cli",
    "codex_desktop_linux",
    "claude_code_cli",
    "grok_build_cli",
    "deepseek_tui",
    "aider_cli",
    "openhands",
    "shell_tmux_agent",
    "generic_cli",
  ]);

  for (const profile of HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES) {
    assert.equal(profile.selection_kind, "agent_harness_adapter");
    assert.equal(profile.truth_boundary, "proposal_source_only");
    assert.equal(profile.runtimeTruthSource, "daemon-runtime");
    assert.ok(profile.required_authority_scopes.length > 0);
    assert.match(profile.receipt_policy_ref, /^receipt-policy:harness-adapter\//);
  }
});

test("compatibility verdicts expose provider trust and local-route gaps", () => {
  const claude = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
    (profile) => profile.adapter_id === "claude_code_cli",
  );
  const deepseek = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
    (profile) => profile.adapter_id === "deepseek_tui",
  );
  const codex = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
    (profile) => profile.adapter_id === "codex_cli",
  );
  const shellTmux = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
    (profile) => profile.adapter_id === "shell_tmux_agent",
  );
  assert.ok(claude);
  assert.ok(deepseek);
  assert.ok(codex);
  assert.ok(shellTmux);

  assert.deepEqual(
    buildHarnessCompatibilityVerdict(claude, true),
    {
      selection_ref: "agent-harness-adapter:claude_code_cli",
      state: "provider_trust",
      summary:
        "Adapter-native model execution is a provider-trust lane and must be disclosed before launch.",
      requiresDaemonGate: true,
      privacyWarning:
        "Do not route protected workspace state into this adapter without a redacted projection or explicit unsafe-mount approval.",
    },
  );
  assert.equal(
    buildHarnessCompatibilityVerdict(deepseek, false).state,
    "local_route_unavailable",
  );
  assert.equal(
    buildHarnessCompatibilityVerdict(codex, true).state,
    "adapter_native_only",
  );
  assert.equal(
    buildHarnessCompatibilityVerdict(shellTmux, true).state,
    "blocked",
  );
  assert.deepEqual(
    buildHarnessCompatibilityVerdict(
      deepseek,
      true,
      "privacy:ctee-private-workspace",
    ),
    {
      selection_ref: "agent-harness-adapter:deepseek_tui",
      state: "blocked",
      summary:
        "External harness adapters cannot mount or claim cTEE private workspace custody; choose a redacted/public projection or use the Default Harness Profile.",
      requiresDaemonGate: true,
      privacyWarning:
        "cTEE private workspace state stays behind Hypervisor custody unless an explicit private-workspace policy grants a compatible path.",
    },
  );
  assert.equal(
    buildHarnessCompatibilityVerdict(
      DEFAULT_HARNESS_PROFILE_OPTION,
      true,
      "privacy:ctee-private-workspace",
    ).state,
    "compatible",
  );
});

test("model route availability comes from model-mount inventory, not route labels", () => {
  assert.deepEqual(
    modelRouteSupportsHypervisorMountFromInventory(
      HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    ),
    {
      model_route_ref: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
      state: "unverified",
      available: false,
      summary:
        "Hypervisor model mount inventory has not been verified.",
      route_refs: [],
      endpoint_refs: [],
      loaded_instance_refs: [],
      requiresDaemonInventory: true,
    },
  );

  const fixtureAvailability = modelRouteSupportsHypervisorMountFromInventory(
    HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  );
  assert.equal(fixtureAvailability.state, "fixture_available");
  assert.equal(fixtureAvailability.available, true);
  assert.deepEqual(fixtureAvailability.route_refs, [
    HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
  ]);

  const daemonInventory = {
    ...HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
    source: "daemon-model-mount-inventory" as const,
  };
  assert.equal(
    modelRouteSupportsHypervisorMountFromInventory(
      HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
      daemonInventory,
    ).state,
    "daemon_verified",
  );
  assert.equal(
    modelRouteSupportsHypervisorMountFromInventory(
      "model-route:adapter-native",
      daemonInventory,
    ).available,
    false,
  );
  assert.equal(
    modelRouteSupportsHypervisorMountFromInventory(
      HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
      { ...daemonInventory, endpoints: [], loadedInstances: [] },
    ).summary,
    "Default-local route has no mounted endpoint or loaded instance.",
  );
});

test("receipt drafts bind adapter execution through daemon truth and workspace posture", () => {
  const deepseek = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
    (profile) => profile.adapter_id === "deepseek_tui",
  );
  assert.ok(deepseek);

  const adapterReceipt = buildHarnessAdapterReceiptDraft(deepseek);
  assert.equal(
    adapterReceipt.schema_version,
    "ioi.hypervisor.harness_adapter_receipt.v1",
  );
  assert.equal(
    adapterReceipt.selection_ref,
    "agent-harness-adapter:deepseek_tui",
  );
  assert.equal(adapterReceipt.execution_lane, "docker_container");
  assert.equal(adapterReceipt.runtimeTruthSource, "daemon-runtime");
  assert.deepEqual(adapterReceipt.agentgres_operation_refs, []);

  const defaultReceipt = buildHarnessAdapterReceiptDraft(
    DEFAULT_HARNESS_PROFILE_OPTION,
  );
  assert.equal(
    defaultReceipt.selection_ref,
    "harness-profile:default_harness_profile",
  );
  assert.equal(defaultReceipt.workspace_mount_policy, "ctee_private_workspace");
});

test("foundry public fixture request only targets container adapters under daemon gates", () => {
  const request = buildHarnessPublicFixtureRunRequest();

  assert.equal(
    request.source,
    "hypervisor_foundry.harness_comparison_dashboard",
  );
  assert.equal(request.min_installed_adapters, 2);
  assert.deepEqual(request.installed_adapter_ids, [
    "deepseek_tui",
    "generic_cli",
  ]);
  assert.deepEqual(
    request.candidate_lanes.map((lane) => lane.selection_ref),
    [
      "agent-harness-adapter:deepseek_tui",
      "agent-harness-adapter:generic_cli",
    ],
  );
  assert.deepEqual(
    request.candidate_lanes.map((lane) => lane.runtime),
    ["docker", "docker"],
  );
  assert.ok(
    request.candidate_lanes.every((lane) =>
      lane.container_image_ref.startsWith("container-image:"),
    ),
  );
  assert.doesNotMatch(JSON.stringify(request), /default_harness_profile/);
});

test("foundry public fixture daemon response normalizes into comparison dashboard rows", async () => {
  const daemonResponse = {
    schema_version: "ioi.hypervisor.harness_public_fixture_run.v1",
    run_id: "harness-public-fixture-runs:test",
    task_ref: "task:fixture/public-code-edit-fixture",
    candidate_selection_refs: [
      "agent-harness-adapter:deepseek_tui",
      "agent-harness-adapter:generic_cli",
    ],
    receipt_refs: [
      "receipt://harness-container/deepseek",
      "receipt://harness-container/generic",
    ],
    attempts: [
      {
        selection_ref: "agent-harness-adapter:deepseek_tui",
        adapter_id: "deepseek_tui",
        exit_status: "success",
        receipt_id: "receipt://harness-container/deepseek",
        command_argv_hash: "sha256:deepseek",
        receipt: {
          agentgres_operation_refs: [
            "agentgres://operation/deepseek/public-fixture",
          ],
          artifact_refs: ["artifact://harness-fixture/deepseek/stdout"],
        },
      },
      {
        selection_ref: "agent-harness-adapter:generic_cli",
        adapter_id: "generic_cli",
        exit_status: "not_executed",
        receipt_id: "receipt://harness-container/generic",
        command_argv_hash: "sha256:generic",
        receipt: { agentgres_operation_refs: [], artifact_refs: [] },
      },
    ],
  };

  const normalized =
    normalizeHarnessComparisonRunFromPublicFixtureRun(daemonResponse);
  assert.equal(
    normalized.schema_version,
    "ioi.hypervisor.harness_comparison_run.v1",
  );
  assert.equal(normalized.run_id, "harness-public-fixture-runs:test");
  assert.equal(normalized.runtimeTruthSource, "daemon-runtime");
  assert.deepEqual(
    normalized.candidate_reports.map((report) => report.verification_status),
    ["passed", "requires_review"],
  );
  assert.match(
    normalized.candidate_reports[0].output_summary,
    /Fixture completed/,
  );
  assert.deepEqual(normalized.candidate_reports[0].evidence_refs, [
    "agentgres://operation/deepseek/public-fixture",
    "artifact://harness-fixture/deepseek/stdout",
  ]);

  const calls: Array<{
    url: string;
    init: Record<string, unknown> | undefined;
  }> = [];
  const requested = await requestHarnessPublicFixtureRun({
    endpoint: "http://daemon.local",
    request: buildHarnessPublicFixtureRunRequest(),
    fetchImpl: async (url, init) => {
      calls.push({ url, init });
      return {
        ok: true,
        status: 202,
        text: async () => JSON.stringify(daemonResponse),
      };
    },
  });

  assert.equal(
    calls[0]?.url,
    `http://daemon.local${HYPERVISOR_HARNESS_PUBLIC_FIXTURE_RUN_PATH}`,
  );
  assert.equal(calls[0]?.init?.method, "POST");
  assert.equal(
    JSON.parse(String(calls[0]?.init?.body)).source,
    "hypervisor_foundry.harness_comparison_dashboard",
  );
  assert.equal(requested.candidate_reports[0].verification_status, "passed");
});

test("new session launch summary binds harness, model route, adapter target, privacy, and receipt", () => {
  const recipe = HYPERVISOR_SESSION_LAUNCH_RECIPES.find(
    (candidate) => candidate.recipe_id === "mission.default",
  );
  const workbenchAdapter = HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES.find(
    (candidate) => candidate.adapter_id === "external_editor",
  );
  const deepseek = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
    (profile) => profile.adapter_id === "deepseek_tui",
  );
  assert.ok(recipe);
  assert.ok(workbenchAdapter);
  assert.ok(deepseek);

  const routeAvailability = modelRouteSupportsHypervisorMountFromInventory(
    HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    {
      ...HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
      source: "daemon-model-mount-inventory",
    },
  );
  const harnessVerdict = buildHarnessCompatibilityVerdict(
    deepseek,
    routeAvailability.available,
    "privacy:redacted-projection",
  );
  const summary = buildHypervisorNewSessionLaunchSummary({
    recipe,
    seedIntent: "Fix flaky receipts",
    projectId: "project:ioi",
    workbenchAdapter,
    harness: deepseek,
    harnessVerdict,
    modelRouteAvailability: routeAvailability,
    modelRouteRef: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    privacyPostureRef: "privacy:redacted-projection",
    authorityScopeRefs: ["scope:workspace.read", "scope:receipt.write"],
    receiptPreviewRef: "receipt-preview:new-session/test",
  });

  assert.deepEqual(summary, {
    schema_version: "ioi.hypervisor.new_session_launch_summary.v1",
    recipe_ref: "mission.default",
    seed_intent: "Fix flaky receipts",
    target_binding_ref:
      "target-binding:new-session/mission-default/project-ioi",
    target_binding: {
      schema_version: "ioi.hypervisor.new_session_target_binding.v1",
      target_binding_ref:
        "target-binding:new-session/mission-default/project-ioi",
      recipe_ref: "mission.default",
      target_kind: "mission",
      surface_id: "sessions",
      project_ref: "project:ioi",
      operator_intent_ref:
        "target-binding:new-session/mission-default/project-ioi/operator-intent",
      session_route_ref: "session-route:sessions/mission-default/project-ioi",
      workbench_adapter_target_ref: null,
      automation_recipe_ref: null,
      agent_template_ref: null,
      foundry_job_ref: null,
      provider_candidate_ref: null,
      environment_ref: null,
      private_workspace_ref: null,
      runtimeTruthSource: "daemon-runtime",
    },
    project_ref: "project:ioi",
    workbench_adapter_ref: "workbench-adapter:external_editor",
    workbench_adapter_target_ref: "adapter-target:external-editor",
    workbench_adapter_custody_posture: "redacted_projection",
    workbench_adapter_launch_plan_ref:
      "workbench-adapter:external_editor/launch-plan",
    workbench_adapter_connection_contract_ref:
      "connection-contract:workbench-adapter/desktop-bridge",
    workbench_adapter_executor_lane: "desktop_bridge",
    workbench_adapter_control_action: "request_desktop_bridge",
    workbench_adapter_control_channel_ref:
      "control-channel:workbench-adapter/desktop-bridge",
    workbench_adapter_access_lease_refs: [
      "lease:workbench-adapter/desktop-bridge",
    ],
    workbench_adapter_authority_scope_refs: [
      "scope:workspace.read",
      "scope:workspace.patch",
      "scope:receipt.write",
    ],
    workbench_adapter_receipt_refs: [
      "receipt-policy:workbench-adapter/desktop-bridge",
    ],
    workbench_adapter_provider_posture_required: false,
    harness_selection_ref: "agent-harness-adapter:deepseek_tui",
    harness_selection_kind: "agent_harness_adapter",
    harness_label: "DeepSeek TUI",
    harness_runtime_truth_source: "daemon-runtime",
    harness_truth_boundary: "proposal_source_only",
    harness_verdict_state: "compatible",
    model_route_ref: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    model_route_availability_state: "daemon_verified",
    model_route_available: true,
    model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
    privacy_posture_ref: "privacy:redacted-projection",
    authority_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
    receipt_preview_ref: "receipt-preview:new-session/test",
    requires_daemon_gate: true,
    runtimeTruthSource: "daemon-runtime",
  });

  const launchedSession = buildHypervisorLaunchedSessionProjection({
    request: {
      recipe_id: recipe.recipe_id,
      seed_intent: "Fix flaky receipts",
      project_id: "project:ioi",
      adapter_preference_ref: "workbench-adapter:external_editor",
      harness_selection_ref: "agent-harness-adapter:deepseek_tui",
      model_route_ref: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
      privacy_posture_ref: "privacy:redacted-projection",
      authority_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
      receipt_preview_ref: "receipt-preview:new-session/test",
      launch_summary: summary,
    },
    recipe,
    projectLabel: "IOI",
    launchedAtMs: 1_718_000,
  });

  assert.equal(
    launchedSession.schema_version,
    "ioi.hypervisor.launched_session_projection.v1",
  );
  assert.equal(
    launchedSession.session_ref,
    "session:launch/mission/project-ioi/mission-default/1718000",
  );
  assert.equal(launchedSession.surface_id, "sessions");
  assert.equal(launchedSession.admission_state, "pending_daemon_admission");
  assert.equal(launchedSession.workbench_adapter_admission, null);
  assert.equal(launchedSession.workbench_adapter_admission_ref, null);
  assert.equal(launchedSession.launch_summary, summary);
  assert.equal(launchedSession.runtimeTruthSource, "daemon-runtime");
});

test("new session target bindings preserve recipe-specific destinations", () => {
  const workbenchAdapter = HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES.find(
    (candidate) => candidate.adapter_id === "embedded_workbench",
  );
  assert.ok(workbenchAdapter);

  const summaries = Object.fromEntries(
    HYPERVISOR_SESSION_LAUNCH_RECIPES.map((recipe) => {
      const summary = buildHypervisorNewSessionLaunchSummary({
        recipe,
        projectId: "project:ioi",
        workbenchAdapter,
        harness: DEFAULT_HARNESS_PROFILE_OPTION,
        harnessVerdict: buildHarnessCompatibilityVerdict(
          DEFAULT_HARNESS_PROFILE_OPTION,
          true,
        ),
        modelRouteAvailability: modelRouteSupportsHypervisorMountFromInventory(
          HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
          HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
        ),
        modelRouteRef: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
        privacyPostureRef: recipe.privacy_posture_templates[0] ?? "privacy:public-trunk",
        authorityScopeRefs: recipe.authority_scope_templates,
        receiptPreviewRef: `receipt-preview:new-session/${recipe.recipe_id}`,
      });
      assert.equal(
        summary.target_binding.schema_version,
        "ioi.hypervisor.new_session_target_binding.v1",
      );
      assert.equal(summary.target_binding.recipe_ref, recipe.recipe_id);
      assert.equal(summary.target_binding.surface_id, recipe.surface_id);
      assert.equal(summary.target_binding.project_ref, "project:ioi");
      assert.equal(summary.target_binding.runtimeTruthSource, "daemon-runtime");
      assert.equal(
        summary.target_binding_ref,
        summary.target_binding.target_binding_ref,
      );
      return [recipe.recipe_id, summary.target_binding];
    }),
  );

  assert.equal(
    summaries["workbench.default"]?.workbench_adapter_target_ref,
    "adapter-target:vscode-embedded",
  );
  assert.equal(
    summaries["automation.default"]?.automation_recipe_ref,
    "automation-recipe:automation-default/project-ioi",
  );
  assert.equal(
    summaries["agent.default"]?.agent_template_ref,
    "agent-template:agent-default/project-ioi",
  );
  assert.equal(
    summaries["foundry.eval"]?.foundry_job_ref,
    "foundry-job:foundry-eval/project-ioi",
  );
  assert.equal(
    summaries["environment.provider"]?.provider_candidate_ref,
    "provider-candidate:environment-provider/project-ioi",
  );
  assert.equal(
    summaries["environment.provider"]?.environment_ref,
    "environment:environment-provider/project-ioi",
  );
  assert.equal(
    summaries["privacy.workspace"]?.private_workspace_ref,
    "private-workspace:privacy-workspace/project-ioi",
  );
});

test("workbench adapter launch plans bind connection contracts and leases", () => {
  const plans = Object.fromEntries(
    HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES.map((preference) => [
      preference.adapter_id,
      buildWorkbenchAdapterLaunchPlan(preference),
    ]),
  );

  assert.equal(
    plans.embedded_workbench?.connection_kind,
    "embedded_host",
  );
  assert.equal(
    plans.embedded_workbench?.executor_lane,
    "embedded_workbench_host",
  );
  assert.equal(
    plans.embedded_workbench?.control_action,
    "open_embedded_workbench",
  );
  assert.deepEqual(plans.embedded_workbench?.required_access_lease_refs, [
    "lease:workbench-adapter/embedded-host",
  ]);
  assert.equal(
    plans.external_editor?.connection_contract_ref,
    "connection-contract:workbench-adapter/desktop-bridge",
  );
  assert.equal(plans.cursor?.connection_kind, "desktop_bridge");
  assert.equal(plans.cursor?.control_channel_ref, "control-channel:workbench-adapter/desktop-bridge");
  assert.equal(plans.windsurf?.connection_kind, "desktop_bridge");
  assert.equal(plans.jetbrains_idea?.connection_kind, "desktop_bridge");
  assert.equal(plans.jetbrains_clion?.connection_kind, "desktop_bridge");
  assert.equal(plans.jetbrains_rustrover?.connection_kind, "desktop_bridge");
  assert.equal(plans.jetbrains_rider?.connection_kind, "desktop_bridge");
  assert.equal(plans.vscode_browser?.connection_kind, "browser_workspace_url");
  assert.equal(plans.vscode_browser?.executor_lane, "browser_workspace");
  assert.equal(plans.vscode_browser?.control_action, "open_browser_workspace");
  assert.equal(plans.devin?.provider_posture_required, true);
  assert.equal(plans.terminal_workspace?.connection_kind, "terminal_session");
  assert.equal(plans.terminal_workspace?.control_action, "attach_terminal_session");
  assert.equal(plans.browser_workspace?.provider_posture_required, true);
  assert.equal(plans.remote_vm?.restore_archive_policy, "required_for_remote_persistence");
  assert.equal(plans.remote_vm?.executor_lane, "provider_environment");
  assert.equal(
    plans.hypervisor_node?.connection_kind,
    "hypervisor_node_session",
  );
  assert.equal(plans.hypervisor_node?.control_action, "attach_hypervisor_node");

  for (const plan of Object.values(plans)) {
    assert.equal(plan?.schema_version, "ioi.hypervisor.workbench_adapter_launch_plan.v1");
    assert.equal(plan?.runtimeTruthSource, "daemon-runtime");
    assert.equal(plan?.requires_daemon_gate, true);
    assert.equal(plan?.secret_release_policy, "no_durable_secret_release");
    assert.ok(plan?.required_receipt_refs.length);
  }
});

test("workbench adapter launch admission posts canonical plans to the daemon", async () => {
  const preference = HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES.find(
    (candidate) => candidate.adapter_id === "embedded_workbench",
  );
  assert.ok(preference);
  const plan = buildWorkbenchAdapterLaunchPlan(preference);
  const admission = await requestWorkbenchAdapterLaunchPlanAdmission(plan, {
    endpoint: "http://daemon.local",
    fetchImpl: async (input, init) => {
      assert.equal(
        input,
        "http://daemon.local/v1/hypervisor/workbench-adapter-launch-plans",
      );
      assert.equal(init?.method, "POST");
      assert.equal(init?.headers?.["content-type"], "application/json");
      const request = JSON.parse(init?.body ?? "{}");
      assert.equal(request.launch_plan_ref, plan.launch_plan_ref);
      assert.equal(request.adapter_ref, plan.adapter_ref);
      assert.equal(request.requires_daemon_gate, true);
      assert.equal(request.runtimeTruthSource, "daemon-runtime");
      return {
        ok: true,
        status: 202,
        text: async () =>
          JSON.stringify({
            ...plan,
            schema_version:
              "ioi.runtime.workbench_adapter_launch_plan_admission.v1",
            admission_id: "workbench-adapter-launch:embedded-host",
            provider_posture_ref: null,
            wallet_approval_ref: null,
            archive_ref: null,
            restore_ref: null,
            agentgres_operation_refs: [
              "agentgres://operation/workbench-adapter-launch",
            ],
            receipt_refs: ["receipt://workbench-adapter-launch/admitted"],
            state_root: "state-root:workbench-adapter-launch",
            adapter_runtime_truth_claimed: false,
            decision: "admitted",
            admitted_at: "2026-06-17T00:00:00.000Z",
          }),
      };
    },
  });

  assert.equal(
    admission.schema_version,
    "ioi.runtime.workbench_adapter_launch_plan_admission.v1",
  );
  assert.equal(admission.decision, "admitted");
  assert.equal(admission.admission_id, "workbench-adapter-launch:embedded-host");
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");

  const recipe = HYPERVISOR_SESSION_LAUNCH_RECIPES[0]!;
  const summary = buildHypervisorNewSessionLaunchSummary({
    recipe,
    projectId: "project:ioi",
    workbenchAdapter: preference,
    harness: DEFAULT_HARNESS_PROFILE_OPTION,
    harnessVerdict: buildHarnessCompatibilityVerdict(
      DEFAULT_HARNESS_PROFILE_OPTION,
      true,
    ),
    modelRouteAvailability: modelRouteSupportsHypervisorMountFromInventory(
      HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
      HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
    ),
    modelRouteRef: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    privacyPostureRef: "privacy:ctee-private-workspace",
    authorityScopeRefs: recipe.authority_scope_templates,
    receiptPreviewRef: "receipt-preview:new-session/admitted",
  });
  const launchedSession = buildHypervisorLaunchedSessionProjection({
    request: {
      recipe_id: recipe.recipe_id,
      seed_intent: null,
      project_id: "project:ioi",
      adapter_preference_ref: plan.adapter_ref,
      harness_selection_ref: "harness-profile:default_harness_profile",
      model_route_ref: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
      privacy_posture_ref: "privacy:ctee-private-workspace",
      authority_scope_refs: recipe.authority_scope_templates,
      receipt_preview_ref: "receipt-preview:new-session/admitted",
      launch_summary: summary,
    },
    recipe,
    projectLabel: "IOI",
    launchedAtMs: 1_718_001,
    workbenchAdapterAdmission: admission,
  });

  assert.equal(launchedSession.admission_state, "daemon_admitted");
  assert.equal(
    launchedSession.workbench_adapter_admission_ref,
    "workbench-adapter-launch:embedded-host",
  );
  assert.equal(launchedSession.workbench_adapter_admission, admission);
});

test("workbench adapter launch admission failures are explicit session state", async () => {
  const preference = HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES.find(
    (candidate) => candidate.adapter_id === "remote_vm",
  );
  assert.ok(preference);
  const plan = buildWorkbenchAdapterLaunchPlan(preference);
  let error: unknown = null;
  try {
    await requestWorkbenchAdapterLaunchPlanAdmission(plan, {
      endpoint: "http://daemon.local",
      fetchImpl: async () => ({
        ok: false,
        status: 400,
        text: async () =>
          JSON.stringify({
            code: "workbench_adapter_provider_posture_ref_required",
          }),
      }),
    });
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof WorkbenchAdapterLaunchAdmissionError);
  const failure = buildHypervisorWorkbenchAdapterAdmissionFailure({
    error,
    launchPlan: plan,
  });
  assert.equal(failure.decision, "blocked");
  assert.equal(failure.http_status, 400);
  assert.equal(failure.runtimeTruthSource, "daemon-runtime");
});

test("harness testbed fixture compares adapters without granting runtime truth", () => {
  const selectionRefs = HYPERVISOR_HARNESS_SELECTION_OPTIONS.map((option) =>
    getHarnessSelectionRef(option),
  );

  assert.equal(
    HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE.schema_version,
    "ioi.hypervisor.harness_adapter_testbed_fixture.v1",
  );
  assert.equal(
    HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE.workspace_mount_policy,
    "public_trunk",
  );
  assert.deepEqual(
    HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE.candidate_selection_refs,
    selectionRefs,
  );
  assert.equal(HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE.requiresDaemonGate, true);
  assert.equal(
    HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE.expected_receipt_schema,
    "ioi.hypervisor.harness_adapter_receipt.v1",
  );

  assert.equal(
    HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.schema_version,
    "ioi.hypervisor.harness_comparison_run.v1",
  );
  assert.equal(
    HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.comparison_mode,
    "same_fixture",
  );
  assert.deepEqual(
    HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.candidate_selection_refs,
    selectionRefs,
  );
  assert.deepEqual(
    HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.receipt_refs,
    selectionRefs.map((selectionRef) => `receipt:draft:${selectionRef}`),
  );
  assert.equal(
    HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.candidate_reports.length,
    selectionRefs.length,
  );
  assert.deepEqual(
    HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.candidate_reports.map(
      (candidate) => candidate.selection_ref,
    ),
    selectionRefs,
  );
  assert.equal(
    HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.candidate_reports[0]?.verification_status,
    "passed",
  );
  assert.match(
    HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.candidate_reports[0]?.receipt_ref ?? "",
    /^receipt:draft:/,
  );
  assert.equal(
    HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE.runtimeTruthSource,
    "daemon-runtime",
  );
});

test("source text rejects legacy external-harness-as-runtime shortcuts", () => {
  const source = readFileSync(
    "apps/hypervisor/src/windows/HypervisorShellWindow/harnessAdapterModel.ts",
    "utf8",
  );

  assert.match(source, /HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE/);
  assert.match(source, /HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE/);
  assert.match(source, /truth_boundary: "proposal_source_only"/);
  assert.match(source, /runtimeTruthSource: "daemon-runtime"/);
  assert.doesNotMatch(source, /Codex = Default Harness/);
  assert.doesNotMatch(source, /Claude Code = Default Harness/);
  assert.doesNotMatch(source, /external harness.*runtime truth/i);
});
