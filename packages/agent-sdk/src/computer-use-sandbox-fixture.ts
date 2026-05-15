import type {
  AffordanceGraph,
  CleanupReceipt,
  ComputerActionKind,
  ComputerControlAdapterContract,
  ComputerUseObservationBundle,
  ComputerUseSessionMode,
  ObservationRetentionMode,
  TargetIndex,
} from "./computer-use.js";

export interface SandboxFixtureContracts {
  providerReceipt: Record<string, unknown>;
  observationBundle: Partial<ComputerUseObservationBundle>;
  targetIndex: Partial<TargetIndex>;
  affordanceGraph: Partial<AffordanceGraph>;
  adapterContract: Partial<ComputerControlAdapterContract> & Record<string, unknown>;
  cleanupReceipt: Partial<CleanupReceipt>;
}

export function sandboxFixtureRequested(input: Record<string, unknown> | null | undefined): boolean {
  const provider = cleanString(
    input?.computerUseSandboxProvider ??
      input?.computer_use_sandbox_provider ??
      input?.sandboxProvider ??
      input?.sandbox_provider,
  );
  const fixture = booleanValue(
    input?.computerUseSandboxFixture ??
      input?.computer_use_sandbox_fixture ??
      input?.sandboxFixture ??
      input?.sandbox_fixture,
  );
  return fixture === true || ["local_fixture", "fixture", "deterministic_fixture", "mock"].includes(provider ?? "");
}

export function computerUseContractsFromSandboxFixture({
  metadata,
  runId,
  leaseId,
  observationRef,
  targetIndexRef,
  affordanceGraphRef,
  retentionMode,
  sessionMode,
  actionKind,
}: {
  metadata: Record<string, unknown> | null | undefined;
  runId: string;
  leaseId: string;
  observationRef: string;
  targetIndexRef: string;
  affordanceGraphRef: string;
  retentionMode: ObservationRetentionMode;
  sessionMode: ComputerUseSessionMode;
  actionKind: ComputerActionKind;
}): SandboxFixtureContracts | null {
  if (!sandboxFixtureRequested(metadata)) return null;
  const providerId = "ioi.sandboxed_hosted.local_fixture";
  const sandboxImageRef =
    cleanString(
      metadata?.computerUseSandboxImageRef ??
        metadata?.computer_use_sandbox_image_ref ??
        metadata?.sandboxImageRef ??
        metadata?.sandbox_image_ref,
    ) ?? "ioi/sandbox-fixture:local";
  const sandboxTaskRef =
    cleanString(
      metadata?.computerUseSandboxTaskRef ??
        metadata?.computer_use_sandbox_task_ref ??
        metadata?.sandboxTaskRef ??
        metadata?.sandbox_task_ref,
    ) ?? `sandbox_task_${safeId(runId)}`;
  const coordinateSpaceId = `sandbox_${safeId(runId)}_viewport`;
  const targetRef = `target_${safeId(runId)}_sandbox_workspace`;
  const providerReceipt = {
    object: "ioi.runtime_sandboxed_computer_provider",
    provider_id: providerId,
    provider_kind: "local_fixture",
    lane: "sandboxed_hosted",
    session_mode: sessionMode,
    image_ref: sandboxImageRef,
    task_ref: sandboxTaskRef,
    authority_scope: "computer_use.sandboxed_hosted.read",
    external_credentials_required: false,
    network_policy: "disabled",
    persistence_policy: "ephemeral_fixture",
    fail_closed_when_unavailable: true,
  };
  const observationBundle: Partial<ComputerUseObservationBundle> = {
    observation_ref: observationRef,
    lease_id: leaseId,
    lane: "sandboxed_hosted",
    session_mode: sessionMode,
    url: null,
    title: "IOI deterministic sandbox fixture",
    app_name: "IOI Local Sandbox Fixture",
    window_title: "Deterministic sandbox computer session",
    screenshot_ref: `artifact:${runId}:sandbox_fixture_screen_redacted`,
    som_ref: `artifact:${runId}:sandbox_fixture_som`,
    dom_ref: null,
    ax_ref: `artifact:${runId}:sandbox_fixture_ax_tree`,
    selector_map_ref: null,
    target_index_ref: targetIndexRef,
    redaction_report_ref: `artifact:${runId}:sandbox_fixture_redaction_report`,
    freshness_ms: 0,
    retention_mode: retentionMode,
    detected_patterns: ["sandbox", "terminal", "file_browser", "task_panel"],
  };
  const targetIndex: Partial<TargetIndex> = {
    target_index_ref: targetIndexRef,
    observation_ref: observationRef,
    coordinate_space_id: coordinateSpaceId,
    drift_state: "fresh",
    targets: [
      {
        target_ref: targetRef,
        label: "Sandbox workspace",
        role: "application",
        semantic_ids: ["sandbox", "workspace", "terminal", "task-panel"],
        selectors: [],
        som_id: 1,
        ax_ref: `${observationBundle.ax_ref}#workspace`,
        bounds: {
          x: 0,
          y: 0,
          width: 1280,
          height: 720,
          coordinate_space_id: coordinateSpaceId,
        },
        confidence: 94,
        available_actions: uniqueComputerActionKinds(["inspect", "wait", "shell", actionKind]),
      },
    ],
  };
  const readOnly = actionKind === "inspect" || actionKind === "wait";
  const affordanceGraph: Partial<AffordanceGraph> = {
    graph_ref: affordanceGraphRef,
    target_index_ref: targetIndexRef,
    observation_ref: observationRef,
    affordances: [
      {
        target_ref: targetRef,
        possible_action: actionKind,
        action_preconditions: ["fixture_lease_active", "fresh_observation", "target_index_present"],
        confidence: readOnly ? 95 : 86,
        expected_state_transition: readOnly
          ? "The sandbox fixture yields deterministic observation and target evidence without external side effects."
          : "The sandbox fixture records the proposed action and requires policy authority before side effects.",
        risk_class: readOnly ? "read_only" : "possible_external_effect",
        required_authority: readOnly
          ? "computer_use.sandboxed_hosted.read"
          : "computer_use.sandboxed_hosted.act",
        confirmation_required: !readOnly,
        fallback_action_paths: ["reobserve", "terminate_safely", "switch_to_native_browser"],
        invalidation_conditions: ["fixture_reset", "sandbox_unavailable", "policy_block"],
      },
    ],
  };
  const adapterContract: SandboxFixtureContracts["adapterContract"] = {
    schema_version: "ioi.computer-use.harness.v1",
    adapter_id: providerId,
    lane: "sandboxed_hosted",
    supported_session_modes: ["local_sandbox", "hosted_sandbox"],
    capabilities: [
      "lease.local_fixture",
      "observe.screenshot",
      "observe.ax",
      "observe.som",
      "act.inspect",
      "act.wait",
      "act.shell",
      "verify.postcondition",
      "cleanup.ephemeral_workspace",
    ],
    emits_observation_bundle: true,
    emits_action_receipts: true,
    emits_cleanup_receipts: true,
    fail_closed_when_unavailable: true,
    provider_receipt: providerReceipt,
  };
  const cleanupReceipt: Partial<CleanupReceipt> = {
    cleanup_ref: `cleanup_${runId}_sandbox_fixture`,
    lease_id: leaseId,
    status: "completed",
    closed_process_refs: [`sandbox_fixture:${safeId(runId)}`],
    deleted_profile_refs: [`sandbox_fixture_workspace:${safeId(runId)}`],
    retained_artifact_refs: compactStrings(["computer-use-trace.json", observationBundle.screenshot_ref]),
    warnings: [],
  };
  return {
    providerReceipt,
    observationBundle,
    targetIndex,
    affordanceGraph,
    adapterContract,
    cleanupReceipt,
  };
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function booleanValue(value: unknown): boolean | null {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value.toLowerCase() === "true") return true;
    if (value.toLowerCase() === "false") return false;
  }
  return null;
}

function uniqueComputerActionKinds(values: ComputerActionKind[]): ComputerActionKind[] {
  return [...new Set(values)];
}

function compactStrings(values: unknown[]): string[] {
  return values.map((value) => cleanString(value)).filter(Boolean) as string[];
}

function safeId(value: unknown): string {
  return String(value ?? "sandbox").replace(/[^a-zA-Z0-9_.-]+/g, "_");
}
