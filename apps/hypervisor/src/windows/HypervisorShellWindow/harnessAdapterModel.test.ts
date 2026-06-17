import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import {
  DEFAULT_HARNESS_PROFILE_OPTION,
  HYPERVISOR_AGENT_HARNESS_ADAPTER_PROFILES,
  HYPERVISOR_DEFAULT_LOCAL_MODEL_ROUTE_REF,
  HYPERVISOR_HARNESS_ADAPTER_TESTBED_FIXTURE,
  HYPERVISOR_HARNESS_COMPARISON_RUN_FIXTURE,
  HYPERVISOR_HARNESS_SELECTION_OPTIONS,
  HYPERVISOR_NEW_SESSION_MODEL_MOUNT_INVENTORY_FIXTURE,
  buildHarnessAdapterReceiptDraft,
  buildHarnessCompatibilityVerdict,
  getHarnessSelectionRef,
  isAgentHarnessAdapterOption,
  modelRouteSupportsHypervisorMountFromInventory,
} from "./harnessAdapterModel.ts";
import {
  HYPERVISOR_SESSION_LAUNCH_RECIPES,
  HYPERVISOR_WORKBENCH_ADAPTER_PREFERENCES,
  buildHypervisorNewSessionLaunchSummary,
  buildWorkbenchAdapterLaunchPlan,
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
        "Hypervisor model mount inventory has not been verified by the daemon.",
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
    project_ref: "project:ioi",
    workbench_adapter_ref: "workbench-adapter:external_editor",
    workbench_adapter_target_ref: "adapter-target:external-editor",
    workbench_adapter_custody_posture: "redacted_projection",
    workbench_adapter_launch_plan_ref:
      "workbench-adapter:external_editor/launch-plan",
    workbench_adapter_connection_contract_ref:
      "connection-contract:workbench-adapter/desktop-bridge",
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
  assert.deepEqual(plans.embedded_workbench?.required_access_lease_refs, [
    "lease:workbench-adapter/embedded-host",
  ]);
  assert.equal(
    plans.external_editor?.connection_contract_ref,
    "connection-contract:workbench-adapter/desktop-bridge",
  );
  assert.equal(plans.terminal_workspace?.connection_kind, "terminal_session");
  assert.equal(plans.browser_workspace?.provider_posture_required, true);
  assert.equal(plans.remote_vm?.restore_archive_policy, "required_for_remote_persistence");
  assert.equal(
    plans.hypervisor_node?.connection_kind,
    "hypervisor_node_session",
  );

  for (const plan of Object.values(plans)) {
    assert.equal(plan?.schema_version, "ioi.hypervisor.workbench_adapter_launch_plan.v1");
    assert.equal(plan?.runtimeTruthSource, "daemon-runtime");
    assert.equal(plan?.requires_daemon_gate, true);
    assert.equal(plan?.secret_release_policy, "no_durable_secret_release");
    assert.ok(plan?.required_receipt_refs.length);
  }
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
