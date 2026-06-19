import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  DEFAULT_HARNESS_PROFILE_OPTION,
  HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES,
  HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
  HYPERVISOR_FIRST_SESSION_AGENT_ADAPTER_IDS,
  HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE,
  HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE,
  HYPERVISOR_HARNESS_PUBLIC_FIXTURE_RUN_PATH,
  HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION_REF,
  HYPERVISOR_HARNESS_SELECTION_OPTIONS,
  HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  buildHypervisorHarnessSessionBinding,
  buildHarnessAdapterReceiptDraft,
  buildHarnessCompatibilityVerdict,
  buildHarnessPublicFixtureRunRequest,
  getHarnessSelectionRef,
  HarnessSessionBindingAdmissionError,
  isAgentHarnessAdapterOption,
  modelRouteSupportsHypervisorMountFromInventory,
  normalizeHarnessComparisonRunFromPublicFixtureRun,
  requestHarnessSessionBindingAdmission,
  requestHarnessSessionLaunch,
  requestHarnessSessionReadiness,
  requestHarnessSessionSpawn,
  requestHarnessPublicFixtureRun,
} from "./harnessAdapterModel.ts";
import {
  HYPERVISOR_SESSION_LAUNCH_RECIPES,
  HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES,
  buildHypervisorHarnessSessionBindingAdmissionFailure,
  buildHypervisorLaunchedSessionProjection,
  buildHypervisorNewSessionLaunchSummary,
  buildHypervisorCodeEditorAdapterAdmissionFailure,
  buildCodeEditorAdapterLaunchPlan,
  requestCodeEditorAdapterLaunchPlanAdmission,
  CodeEditorAdapterLaunchAdmissionError,
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
  const grok = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
    (profile) => profile.adapter_id === "grok_build_cli",
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
  assert.ok(grok);
  assert.ok(deepseek);
  assert.ok(codex);
  assert.ok(shellTmux);

  for (const adapterId of HYPERVISOR_FIRST_SESSION_AGENT_ADAPTER_IDS) {
    const profile = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
      (candidate) => candidate.adapter_id === adapterId,
    );
    assert.ok(profile);
    assert.equal(profile.model_route_policy, "hypervisor_model_mount");
    assert.equal(
      buildHarnessCompatibilityVerdict(profile, true).state,
      "compatible",
    );
  }
  assert.deepEqual(buildHarnessCompatibilityVerdict(grok, true), {
    selection_ref: "agent-harness-adapter:grok_build_cli",
    state: "provider_trust",
    summary:
      "Adapter-native model execution is a provider-trust lane and must be disclosed before launch.",
    requiresDaemonGate: true,
    privacyWarning:
      "Do not route protected workspace state into this adapter without a redacted projection or explicit unsafe-mount approval.",
  });
  assert.equal(
    buildHarnessCompatibilityVerdict(deepseek, false).state,
    "local_route_unavailable",
  );
  assert.equal(
    buildHarnessCompatibilityVerdict(codex, true).state,
    "compatible",
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

test("first session harnesses bind local model configuration before external auth", () => {
  const availability = modelRouteSupportsHypervisorMountFromInventory(
    HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  );

  const bindings = HYPERVISOR_FIRST_SESSION_AGENT_ADAPTER_IDS.map((adapterId) => {
    const harness = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
      (profile) => profile.adapter_id === adapterId,
    );
    assert.ok(harness);
    return buildHypervisorHarnessSessionBinding({
      sessionRouteRef: `session-route:sessions/${adapterId}`,
      harness,
      modelRouteAvailability: availability,
      modelRouteRef: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
      privacyPostureRef: "privacy:redacted-projection",
      authorityScopeRefs: harness.required_authority_scopes,
      receiptPreviewRef: `receipt-preview:new-session/${adapterId}`,
    });
  });

  assert.deepEqual(
    bindings.map((binding) => binding.agent_harness_adapter_id),
    ["codex_cli", "claude_code_cli", "deepseek_tui"],
  );
  assert.ok(
    bindings.every(
      (binding) =>
        binding.model_configuration_ref ===
          HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION_REF &&
        binding.model_route_policy === "hypervisor_model_mount" &&
        binding.requires_daemon_gate === true &&
        binding.runtimeTruthSource === "daemon-runtime",
    ),
  );
  assert.equal(bindings[1]?.example_root_ref, "examples/claude-code-main");
  assert.equal(bindings[2]?.workspace_mount_policy, "public_trunk");
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
  const codeEditorAdapter = HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES.find(
    (candidate) => candidate.adapter_id === "external_editor",
  );
  const deepseek = HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES.find(
    (profile) => profile.adapter_id === "deepseek_tui",
  );
  assert.ok(recipe);
  assert.ok(codeEditorAdapter);
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
    codeEditorAdapter,
    harness: deepseek,
    harnessVerdict,
    modelRouteAvailability: routeAvailability,
    modelRouteRef: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    privacyPostureRef: "privacy:redacted-projection",
    authorityScopeRefs: ["scope:workspace.read", "scope:receipt.write"],
    receiptPreviewRef: "receipt-preview:new-session/test",
  });

  assert.deepEqual(
    { ...summary, harness_session_binding: undefined },
    {
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
      code_editor_adapter_target_ref: null,
      automation_recipe_ref: null,
      agent_template_ref: null,
      foundry_job_ref: null,
      provider_candidate_ref: null,
      environment_ref: null,
      private_workspace_ref: null,
      runtimeTruthSource: "daemon-runtime",
    },
    project_ref: "project:ioi",
    code_editor_adapter_ref: "code-editor-adapter:external_editor",
    code_editor_adapter_target_ref: "adapter-target:external-editor",
    code_editor_adapter_custody_posture: "redacted_projection",
    code_editor_adapter_launch_plan_ref:
      "code-editor-adapter:external_editor/launch-plan",
    code_editor_adapter_connection_contract_ref:
      "connection-contract:code-editor-adapter/desktop-context",
    code_editor_adapter_executor_lane: "desktop_editor",
    code_editor_adapter_control_action: "open_desktop_editor",
    code_editor_adapter_control_channel_ref:
      "control-channel:code-editor-adapter/desktop-context",
    code_editor_adapter_access_lease_refs: [
      "lease:code-editor-adapter/desktop-context",
    ],
    code_editor_adapter_authority_scope_refs: [
      "scope:workspace.read",
      "scope:workspace.patch",
      "scope:receipt.write",
    ],
    code_editor_adapter_receipt_refs: [
      "receipt-policy:code-editor-adapter/desktop-context",
    ],
    harness_selection_ref: "agent-harness-adapter:deepseek_tui",
    harness_selection_kind: "agent_harness_adapter",
    harness_label: "DeepSeek TUI",
    harness_runtime_truth_source: "daemon-runtime",
    harness_truth_boundary: "proposal_source_only",
    harness_verdict_state: "compatible",
    harness_session_binding_ref:
      "harness-session-binding:session-route-sessions-mission-default-project-ioi:agent-harness-adapter-deepseek_tui:model-config-local-codex-oss-qwen",
    harness_session_binding: undefined,
    model_route_ref: HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
    model_route_availability_state: "daemon_verified",
    model_route_available: true,
    model_route_endpoint_refs: ["model-endpoint:hypervisor/default-local"],
    privacy_posture_ref: "privacy:redacted-projection",
    authority_scope_refs: ["scope:workspace.read", "scope:receipt.write"],
    receipt_preview_ref: "receipt-preview:new-session/test",
    requires_daemon_gate: true,
    runtimeTruthSource: "daemon-runtime",
    },
  );
  assert.equal(
    summary.harness_session_binding.schema_version,
    "ioi.hypervisor.harness_session_binding.v1",
  );
  assert.equal(
    summary.harness_session_binding.model_configuration_ref,
    HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION_REF,
  );
  assert.equal(
    summary.harness_session_binding.harness_launch_route_ref,
    "harness-route:deepseek-tui/local-model-container",
  );

  const launchedSession = buildHypervisorLaunchedSessionProjection({
    request: {
      recipe_id: recipe.recipe_id,
      seed_intent: "Fix flaky receipts",
      project_id: "project:ioi",
      adapter_preference_ref: "code-editor-adapter:external_editor",
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
  assert.equal(launchedSession.code_editor_adapter_admission, null);
  assert.equal(launchedSession.code_editor_adapter_admission_ref, null);
  assert.equal(launchedSession.harness_session_binding_admission, null);
  assert.equal(launchedSession.harness_session_binding_admission_ref, null);
  assert.equal(launchedSession.harness_session_launch, null);
  assert.equal(launchedSession.harness_session_launch_ref, null);
  assert.equal(
    launchedSession.harness_session_binding_ref,
    summary.harness_session_binding_ref,
  );
  assert.equal(
    launchedSession.harness_session_binding,
    summary.harness_session_binding,
  );
  assert.equal(launchedSession.launch_summary, summary);
  assert.equal(launchedSession.runtimeTruthSource, "daemon-runtime");
});

test("new session target bindings preserve recipe-specific destinations", () => {
  const codeEditorAdapter = HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES.find(
    (candidate) => candidate.adapter_id === "embedded_code_editor",
  );
  assert.ok(codeEditorAdapter);

  const summaries = Object.fromEntries(
    HYPERVISOR_SESSION_LAUNCH_RECIPES.map((recipe) => {
      const summary = buildHypervisorNewSessionLaunchSummary({
        recipe,
        projectId: "project:ioi",
        codeEditorAdapter,
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
    summaries["workbench.default"]?.code_editor_adapter_target_ref,
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

test("code editor adapter launch plans bind connection contracts and leases", () => {
  const plans = Object.fromEntries(
    HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES.map((preference) => [
      preference.adapter_id,
      buildCodeEditorAdapterLaunchPlan(preference),
    ]),
  );

  assert.equal(
    plans.embedded_code_editor?.connection_kind,
    "embedded_host",
  );
  assert.equal(
    plans.embedded_code_editor?.executor_lane,
    "embedded_code_editor_host",
  );
  assert.equal(
    plans.embedded_code_editor?.control_action,
    "open_embedded_code_editor",
  );
  assert.deepEqual(plans.embedded_code_editor?.required_access_lease_refs, [
    "lease:code-editor-adapter/embedded-host",
  ]);
  assert.equal(
    plans.external_editor?.connection_contract_ref,
    "connection-contract:code-editor-adapter/desktop-context",
  );
  assert.equal(plans.cursor?.connection_kind, "desktop_editor");
  assert.equal(plans.cursor?.control_channel_ref, "control-channel:code-editor-adapter/desktop-context");
  assert.equal(plans.windsurf?.connection_kind, "desktop_editor");
  assert.equal(plans.jetbrains_idea?.connection_kind, "desktop_editor");
  assert.equal(plans.jetbrains_clion?.connection_kind, "desktop_editor");
  assert.equal(plans.jetbrains_rustrover?.connection_kind, "desktop_editor");
  assert.equal(plans.jetbrains_rider?.connection_kind, "desktop_editor");
  assert.equal(plans.vscode_browser?.connection_kind, "browser_editor_url");
  assert.equal(plans.vscode_browser?.executor_lane, "browser_code_editor");
  assert.equal(plans.vscode_browser?.control_action, "open_browser_editor");

  for (const plan of Object.values(plans)) {
    assert.equal(plan?.schema_version, "ioi.hypervisor.code_editor_adapter_launch_plan.v1");
    assert.equal(plan?.runtimeTruthSource, "daemon-runtime");
    assert.equal(plan?.requires_daemon_gate, true);
    assert.equal(plan?.secret_release_policy, "no_durable_secret_release");
    assert.ok(plan?.required_receipt_refs.length);
  }
});

test("code editor adapter launch admission posts canonical plans to the daemon", async () => {
  const preference = HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES.find(
    (candidate) => candidate.adapter_id === "embedded_code_editor",
  );
  assert.ok(preference);
  const plan = buildCodeEditorAdapterLaunchPlan(preference);
  const admission = await requestCodeEditorAdapterLaunchPlanAdmission(plan, {
    endpoint: "http://daemon.local",
    fetchImpl: async (input, init) => {
      assert.equal(
        input,
        "http://daemon.local/v1/hypervisor/code-editor-adapter-launch-plans",
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
              "ioi.runtime.code_editor_adapter_launch_plan_admission.v1",
            admission_id: "code-editor-adapter-launch:embedded-host",
            wallet_approval_ref: null,
            agentgres_operation_refs: [
              "agentgres://operation/code-editor-adapter-launch",
            ],
            receipt_refs: ["receipt://code-editor-adapter-launch/admitted"],
            state_root: "state-root:code-editor-adapter-launch",
            adapter_runtime_truth_claimed: false,
            decision: "admitted",
            admitted_at: "2026-06-17T00:00:00.000Z",
          }),
      };
    },
  });

  assert.equal(
    admission.schema_version,
    "ioi.runtime.code_editor_adapter_launch_plan_admission.v1",
  );
  assert.equal(admission.decision, "admitted");
  assert.equal(admission.admission_id, "code-editor-adapter-launch:embedded-host");
  assert.equal(admission.runtimeTruthSource, "daemon-runtime");

  const recipe = HYPERVISOR_SESSION_LAUNCH_RECIPES[0]!;
  const summary = buildHypervisorNewSessionLaunchSummary({
    recipe,
    projectId: "project:ioi",
    codeEditorAdapter: preference,
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
  const harnessAdmission = await requestHarnessSessionBindingAdmission(
    summary.harness_session_binding,
    {
      endpoint: "http://daemon.local",
      fetchImpl: async (input, init) => {
        assert.equal(
          input,
          "http://daemon.local/v1/hypervisor/harness-session-binding-admissions",
        );
        assert.equal(init?.method, "POST");
        assert.equal(init?.headers?.["content-type"], "application/json");
        const request = JSON.parse(init?.body ?? "{}");
        assert.equal(
          request.session_binding_ref,
          summary.harness_session_binding_ref,
        );
        assert.equal(
          request.model_configuration_ref,
          HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION_REF,
        );
        assert.equal(request.requires_daemon_gate, true);
        assert.equal(request.runtimeTruthSource, "daemon-runtime");
        return {
          ok: true,
          status: 202,
          text: async () =>
            JSON.stringify({
              schema_version:
                "ioi.runtime.harness_session_binding_admission.v1",
              admission_id: "harness-session-binding-admission:local-codex",
              decision: "admitted",
              admission_state: "admitted_for_harness_launch",
              session_binding_ref:
                summary.harness_session_binding.session_binding_ref,
              session_route_ref:
                summary.harness_session_binding.session_route_ref,
              harness_selection_ref:
                summary.harness_session_binding.harness_selection_ref,
              harness_selection_kind:
                summary.harness_session_binding.harness_selection_kind,
              harness_truth_boundary:
                summary.harness_session_binding.harness_truth_boundary,
              harness_launch_route_ref:
                summary.harness_session_binding.harness_launch_route_ref,
              agent_harness_adapter_id: null,
              harness_profile_ref: "default_harness_profile",
              model_configuration_ref:
                summary.harness_session_binding.model_configuration_ref,
              model_route_ref: summary.harness_session_binding.model_route_ref,
              model_route_policy:
                summary.harness_session_binding.model_route_policy,
              model_route_availability_state:
                summary.harness_session_binding.model_route_availability_state,
              model_route_endpoint_refs:
                summary.harness_session_binding.model_route_endpoint_refs,
              model_route_loaded_instance_refs:
                summary.harness_session_binding
                  .model_route_loaded_instance_refs,
              workspace_mount_policy:
                summary.harness_session_binding.workspace_mount_policy,
              privacy_posture_ref:
                summary.harness_session_binding.privacy_posture_ref,
              authority_scope_refs:
                summary.harness_session_binding.authority_scope_refs,
              receipt_policy_ref:
                summary.harness_session_binding.receipt_policy_ref,
              receipt_preview_ref:
                summary.harness_session_binding.receipt_preview_ref,
              expected_receipt_refs:
                summary.harness_session_binding.expected_receipt_refs,
              agentgres_operation_refs: [
                "agentgres://operation/harness-session-binding",
              ],
              receipt_refs: ["receipt://harness-session-binding/admitted"],
              state_root: "agentgres://state-root/harness-session-binding",
              harness_runtime_truth_claimed: false,
              requiresDaemonGate: true,
              runtimeTruthSource: "daemon-runtime",
              admitted_at: "2026-06-18T12:00:00.000Z",
            }),
        };
      },
    },
  );

  assert.equal(
    harnessAdmission.schema_version,
    "ioi.runtime.harness_session_binding_admission.v1",
  );
  assert.equal(harnessAdmission.decision, "admitted");
  assert.equal(
    harnessAdmission.model_configuration_ref,
    HYPERVISOR_LOCAL_CODEX_OSS_QWEN_MODEL_CONFIGURATION_REF,
  );
  const harnessLaunch = await requestHarnessSessionLaunch(harnessAdmission, {
    endpoint: "http://daemon.local",
    workspaceRef: "workspace:project:ioi",
    terminalSessionRef: "terminal-session:project:ioi/mission.default",
    fetchImpl: async (input, init) => {
      assert.equal(
        input,
        "http://daemon.local/v1/hypervisor/harness-session-launches",
      );
      assert.equal(init?.method, "POST");
      assert.equal(init?.headers?.["content-type"], "application/json");
      const request = JSON.parse(init?.body ?? "{}");
      assert.equal(
        request.binding_admission.admission_id,
        harnessAdmission.admission_id,
      );
      assert.equal(request.workspace_ref, "workspace:project:ioi");
      return {
        ok: true,
        status: 202,
        text: async () =>
          JSON.stringify({
            schema_version: "ioi.runtime.harness_session_launch.v1",
            launch_id: "harness-session-launch:local-codex",
            decision: "admitted",
            launch_state: "ready_to_spawn",
            launch_lane: "host_dev_pty",
            session_binding_ref: harnessAdmission.session_binding_ref,
            session_route_ref: harnessAdmission.session_route_ref,
            binding_admission_id: harnessAdmission.admission_id,
            harness_selection_ref: harnessAdmission.harness_selection_ref,
            harness_selection_kind: harnessAdmission.harness_selection_kind,
            harness_truth_boundary: harnessAdmission.harness_truth_boundary,
            harness_launch_route_ref: harnessAdmission.harness_launch_route_ref,
            agent_harness_adapter_id: harnessAdmission.agent_harness_adapter_id,
            harness_profile_ref: harnessAdmission.harness_profile_ref,
            model_configuration_ref: harnessAdmission.model_configuration_ref,
            model_route_ref: harnessAdmission.model_route_ref,
            model_route_policy: harnessAdmission.model_route_policy,
            model_route_endpoint_refs: harnessAdmission.model_route_endpoint_refs,
            model_route_loaded_instance_refs:
              harnessAdmission.model_route_loaded_instance_refs,
            model_mount_contract: {
              provider: "ollama",
              api_format: "openai_compatible",
              model_env: "HYPERVISOR_LOCAL_CODEX_OSS_MODEL",
              model_default: "qwen",
              endpoint_refs: harnessAdmission.model_route_endpoint_refs,
              loaded_instance_refs:
                harnessAdmission.model_route_loaded_instance_refs,
            },
            workspace_ref: "workspace:project:ioi",
            workspace_mount_policy: harnessAdmission.workspace_mount_policy,
            privacy_posture_ref: harnessAdmission.privacy_posture_ref,
            terminal_session_ref: "terminal-session:project:ioi/mission.default",
            command_contract: {
              command_ref: "host-command:codex-cli/local-ollama-qwen",
              binary_name: "codex",
              argv_template: [
                "codex",
                "--oss",
                "--local-provider",
                "ollama",
                "--model",
                "${HYPERVISOR_LOCAL_CODEX_OSS_MODEL:-qwen}",
                "--sandbox",
                "workspace-write",
                "--ask-for-approval",
                "on-request",
                "--cd",
                "${HYPERVISOR_SESSION_WORKSPACE}",
              ],
              env_policy_ref: "env-policy:harness-session/codex-oss-local-qwen",
              secret_release_policy: "none",
              requires_pty: true,
              workspace_env: "HYPERVISOR_SESSION_WORKSPACE",
              model_env: "HYPERVISOR_LOCAL_CODEX_OSS_MODEL",
            },
            authority_scope_refs: harnessAdmission.authority_scope_refs,
            receipt_policy_ref: harnessAdmission.receipt_policy_ref,
            receipt_refs: ["receipt://harness-session-launch/local-codex"],
            agentgres_operation_refs: [
              "agentgres://operation/harness-session-launch/local-codex",
            ],
            state_root:
              "agentgres://state-root/harness-session-launch/local-codex",
            launched_at: "2026-06-18T12:30:00.000Z",
            requiresDaemonGate: true,
            runtimeTruthSource: "daemon-runtime",
          }),
      };
    },
  });

  assert.equal(harnessLaunch.decision, "admitted");
  assert.equal(harnessLaunch.launch_state, "ready_to_spawn");
  assert.equal(
    harnessLaunch.command_contract.command_ref,
    "host-command:codex-cli/local-ollama-qwen",
  );
  const harnessSpawn = await requestHarnessSessionSpawn(harnessLaunch, {
    endpoint: "http://daemon.local",
    workspaceRoot: ".",
    modelName: "qwen2.5-coder:7b",
    fetchImpl: async (input, init) => {
      assert.equal(
        input,
        "http://daemon.local/v1/hypervisor/harness-session-spawns",
      );
      assert.equal(init?.method, "POST");
      assert.equal(init?.headers?.["content-type"], "application/json");
      const request = JSON.parse(init?.body ?? "{}");
      assert.equal(request.session_launch.launch_id, harnessLaunch.launch_id);
      assert.equal(request.workspace_root, ".");
      assert.equal(request.model_name, "qwen2.5-coder:7b");
      return {
        ok: true,
        status: 202,
        text: async () =>
          JSON.stringify({
            schema_version: "ioi.runtime.harness_session_spawn.v1",
            spawn_id: "harness-session-spawn:local-codex",
            decision: "admitted",
            spawn_state: "ready_for_client_pty_attach",
            spawn_lane: "host_terminal_session",
            launch_id: harnessLaunch.launch_id,
            session_binding_ref: harnessLaunch.session_binding_ref,
            session_route_ref: harnessLaunch.session_route_ref,
            harness_selection_ref: harnessLaunch.harness_selection_ref,
            agent_harness_adapter_id: harnessLaunch.agent_harness_adapter_id,
            model_configuration_ref: harnessLaunch.model_configuration_ref,
            model_route_ref: harnessLaunch.model_route_ref,
            model_name: "qwen2.5-coder:7b",
            workspace_ref: harnessLaunch.workspace_ref,
            workspace_root: "/home/heathledger/Documents/ioi/repos/ioi",
            terminal_session_ref: harnessLaunch.terminal_session_ref,
            command_contract_ref: harnessLaunch.command_contract.command_ref,
            command_contract: {
              ...harnessLaunch.command_contract,
              resolved_argv: [
                "codex",
                "--oss",
                "--local-provider",
                "ollama",
                "--model",
                "qwen2.5-coder:7b",
                "--sandbox",
                "workspace-write",
                "--ask-for-approval",
                "on-request",
                "--cd",
                "/home/heathledger/Documents/ioi/repos/ioi",
              ],
              resolved_command_line:
                "codex --oss --local-provider ollama --model qwen2.5-coder:7b --sandbox workspace-write --ask-for-approval on-request --cd /home/heathledger/Documents/ioi/repos/ioi",
              pty_transport: "hypervisor_client_terminal_adapter",
              process_custody: "client_host_pty_after_daemon_spawn_admission",
            },
            terminal_attach_contract: {
              root: "/home/heathledger/Documents/ioi/repos/ioi",
              cols: 120,
              rows: 32,
              command_line:
                "codex --oss --local-provider ollama --model qwen2.5-coder:7b --sandbox workspace-write --ask-for-approval on-request --cd /home/heathledger/Documents/ioi/repos/ioi",
              requires_pty: true,
              launch_after_attach: true,
            },
            model_mount_contract: harnessLaunch.model_mount_contract,
            workspace_mount_policy: harnessLaunch.workspace_mount_policy,
            privacy_posture_ref: harnessLaunch.privacy_posture_ref,
            authority_scope_refs: harnessLaunch.authority_scope_refs,
            receipt_policy_ref: harnessLaunch.receipt_policy_ref,
            receipt_refs: ["receipt://harness-session-spawn/local-codex"],
            agentgres_operation_refs: [
              "agentgres://operation/harness-session-spawn/local-codex",
            ],
            state_root:
              "agentgres://state-root/harness-session-spawn/local-codex",
            spawned_at: "2026-06-18T12:35:00.000Z",
            requiresDaemonGate: true,
            runtimeTruthSource: "daemon-runtime",
          }),
      };
    },
  });
  assert.equal(harnessSpawn.decision, "admitted");
  assert.equal(harnessSpawn.spawn_state, "ready_for_client_pty_attach");
  assert.equal(harnessSpawn.model_name, "qwen2.5-coder:7b");
  const harnessReadiness = await requestHarnessSessionReadiness(harnessSpawn, {
    endpoint: "http://daemon.local",
    fetchImpl: async (input, init) => {
      assert.equal(
        input,
        "http://daemon.local/v1/hypervisor/harness-session-readiness",
      );
      assert.equal(init?.method, "POST");
      assert.equal(init?.headers?.["content-type"], "application/json");
      const request = JSON.parse(init?.body ?? "{}");
      assert.equal(request.session_spawn.spawn_id, harnessSpawn.spawn_id);
      return {
        ok: true,
        status: 202,
        text: async () =>
          JSON.stringify({
            schema_version: "ioi.runtime.harness_session_readiness.v1",
            readiness_id: "harness-session-readiness:local-codex",
            decision: "ready",
            readiness_state: "ready_for_harness_pty_attach",
            spawn_id: harnessSpawn.spawn_id,
            launch_id: harnessSpawn.launch_id,
            session_binding_ref: harnessSpawn.session_binding_ref,
            session_route_ref: harnessSpawn.session_route_ref,
            harness_selection_ref: harnessSpawn.harness_selection_ref,
            agent_harness_adapter_id: harnessSpawn.agent_harness_adapter_id,
            model_configuration_ref: harnessSpawn.model_configuration_ref,
            model_route_ref: harnessSpawn.model_route_ref,
            model_name: "qwen2.5-coder:7b",
            provider: "ollama",
            codex_binary: "codex",
            provider_binary: "ollama",
            available_model_names: ["qwen2.5-coder:7b"],
            checks: [
              {
                id: "codex_binary",
                status: "pass",
                required: true,
                summary: "Codex binary resolved.",
                evidence_refs: ["host-command:codex:--help"],
              },
              {
                id: "codex_oss_flags",
                status: "pass",
                required: true,
                summary: "Codex OSS flags resolved.",
                evidence_refs: ["host-command:codex:oss-flags"],
              },
              {
                id: "ollama_provider",
                status: "pass",
                required: true,
                summary: "Ollama provider answered.",
                evidence_refs: ["host-command:ollama:list"],
              },
              {
                id: "qwen_model_available",
                status: "pass",
                required: true,
                summary: "Qwen model is available.",
                evidence_refs: ["model:qwen2.5-coder:7b"],
              },
            ],
            operator_next_action:
              "Attach the client PTY using the daemon-resolved command contract.",
            receipt_refs: ["receipt://harness-session-readiness/local-codex"],
            agentgres_operation_refs: [
              "agentgres://operation/harness-session-readiness/local-codex",
            ],
            state_root:
              "agentgres://state-root/harness-session-readiness/local-codex",
            checked_at: "2026-06-18T12:40:00.000Z",
            requiresDaemonGate: true,
            runtimeTruthSource: "daemon-runtime",
          }),
      };
    },
  });
  assert.equal(harnessReadiness.decision, "ready");
  assert.equal(
    harnessReadiness.readiness_state,
    "ready_for_harness_pty_attach",
  );
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
    codeEditorAdapterAdmission: admission,
    harnessSessionBindingAdmission: harnessAdmission,
    harnessSessionLaunch: harnessLaunch,
    harnessSessionSpawn: harnessSpawn,
    harnessSessionReadiness: harnessReadiness,
  });

  assert.equal(launchedSession.admission_state, "daemon_admitted");
  assert.equal(
    launchedSession.code_editor_adapter_admission_ref,
    "code-editor-adapter-launch:embedded-host",
  );
  assert.equal(launchedSession.code_editor_adapter_admission, admission);
  assert.equal(
    launchedSession.harness_session_binding_admission_ref,
    "harness-session-binding-admission:local-codex",
  );
  assert.equal(
    launchedSession.harness_session_binding_admission,
    harnessAdmission,
  );
  assert.equal(
    launchedSession.harness_session_launch_ref,
    "harness-session-launch:local-codex",
  );
  assert.equal(launchedSession.harness_session_launch, harnessLaunch);
  assert.equal(
    launchedSession.harness_session_spawn_ref,
    "harness-session-spawn:local-codex",
  );
  assert.equal(launchedSession.harness_session_spawn, harnessSpawn);
  assert.equal(
    launchedSession.harness_session_readiness_ref,
    "harness-session-readiness:local-codex",
  );
  assert.equal(launchedSession.harness_session_readiness, harnessReadiness);
});

test("harness session binding admission failures are explicit session state", async () => {
  const recipe = HYPERVISOR_SESSION_LAUNCH_RECIPES[0]!;
  const preference = HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES[0]!;
  const summary = buildHypervisorNewSessionLaunchSummary({
    recipe,
    projectId: "project:ioi",
    codeEditorAdapter: preference,
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
  let error: unknown = null;
  try {
    await requestHarnessSessionBindingAdmission(summary.harness_session_binding, {
      endpoint: "http://daemon.local",
      fetchImpl: async () => ({
        ok: false,
        status: 403,
        text: async () =>
          JSON.stringify({
            code: "harness_session_binding_external_ctee_custody_blocked",
          }),
      }),
    });
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof HarnessSessionBindingAdmissionError);
  const failure = buildHypervisorHarnessSessionBindingAdmissionFailure({
    binding: summary.harness_session_binding,
    error,
  });
  assert.equal(failure.decision, "blocked");
  assert.equal(failure.http_status, 403);
  assert.equal(failure.runtimeTruthSource, "daemon-runtime");
});

test("code editor adapter launch admission failures are explicit session state", async () => {
  const preference = HYPERVISOR_CODE_EDITOR_ADAPTER_PREFERENCES.find(
    (candidate) => candidate.adapter_id === "vscode_browser",
  );
  assert.ok(preference);
  const plan = buildCodeEditorAdapterLaunchPlan(preference);
  let error: unknown = null;
  try {
    await requestCodeEditorAdapterLaunchPlanAdmission(plan, {
      endpoint: "http://daemon.local",
      fetchImpl: async () => ({
        ok: false,
        status: 400,
        text: async () =>
          JSON.stringify({
            code: "code_editor_adapter_control_contract_mismatch",
          }),
      }),
    });
  } catch (caught) {
    error = caught;
  }
  assert.ok(error instanceof CodeEditorAdapterLaunchAdmissionError);
  const failure = buildHypervisorCodeEditorAdapterAdmissionFailure({
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

test("source text rejects external-harness-as-runtime shortcuts", () => {
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
