const COMPUTER_USE_CONTRACT_SCHEMA_VERSION = "ioi.computer-use.harness.v1";

export function computerUseContractsFromVisualObservation({
  request = {},
  runId = "run_visual_gui",
  leaseId = `lease_${runId}_visual`,
  observationRef = `observation_${runId}_visual_initial`,
  targetIndexRef = `target_index_${runId}_visual_initial`,
  affordanceGraphRef = `affordance_${runId}_visual_initial`,
  retentionMode = "local_redacted_artifacts",
  sessionMode = "visual_fallback",
} = {}) {
  const metadata = request.options?.metadata ?? request.metadata ?? request;
  const visualObservation =
    objectValue(metadata.computer_use_visual_observation) ??
    objectValue(metadata.visual_gui_observation) ??
    objectValue(metadata.visual_observation) ??
    {};
  const screenshotRef = cleanString(
    visualObservation.screenshot_ref ??
      metadata.screenshot_ref,
  );
  const somRef = cleanString(
    visualObservation.som_ref ??
      visualObservation.set_of_marks_ref ??
      metadata.som_ref,
  );
  const axRef = cleanString(
    visualObservation.ax_ref ??
      visualObservation.accessibility_tree_ref ??
      metadata.ax_ref ??
      metadata.accessibility_tree_ref,
  );
  const rawTargets = arrayValue(
    visualObservation.targets ??
      visualObservation.visual_targets ??
      metadata.visual_targets,
  );
  const appName = cleanString(
    visualObservation.app_name ??
      metadata.app_name,
  );
  const windowTitle = cleanString(
    visualObservation.window_title ??
      metadata.window_title,
  );

  if (!screenshotRef && !somRef && !axRef && !appName && !windowTitle && rawTargets.length === 0) {
    return null;
  }

  const coordinateSpaceId =
    cleanString(
      visualObservation.coordinate_space_id ??
        metadata.coordinate_space_id,
    ) ?? `screen_${safeId(runId)}_visual`;
  const viewportWidth = finiteNumber(
    visualObservation.viewport_width ??
      metadata.viewport_width,
  );
  const viewportHeight = finiteNumber(
    visualObservation.viewport_height ??
      metadata.viewport_height,
  );
  const targets = normalizeVisualTargets({
    rawTargets,
    runId,
    appName,
    windowTitle,
    coordinateSpaceId,
    viewportWidth,
    viewportHeight,
  });
  const observationBundle = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    observation_ref: observationRef,
    lease_id: leaseId,
    lane: "visual_gui",
    session_mode: sessionMode,
    url: null,
    title: null,
    app_name: appName,
    window_title: windowTitle,
    screenshot_ref: screenshotRef,
    som_ref: somRef,
    dom_ref: null,
    ax_ref: axRef,
    selector_map_ref: null,
    target_index_ref: targetIndexRef,
    redaction_report_ref:
      cleanString(
        visualObservation.redaction_report_ref ??
          metadata.redaction_report_ref,
      ) ?? null,
    freshness_ms:
      finiteNumber(visualObservation.freshness_ms) ?? null,
    retention_mode: retentionMode,
    detected_patterns: uniqueStrings([
      ...stringArray(visualObservation.detected_patterns),
      ...stringArray(metadata.detected_patterns),
      ...(targets.some((target) => target.role === "canvas") ? ["canvas"] : []),
      ...(somRef ? ["som"] : []),
      ...(axRef ? ["accessibility_tree"] : []),
    ]),
  };
  const targetIndex = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    target_index_ref: targetIndexRef,
    observation_ref: observationRef,
    coordinate_space_id: coordinateSpaceId,
    drift_state: "fresh",
    targets,
  };
  const affordanceGraph = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    graph_ref: affordanceGraphRef,
    target_index_ref: targetIndexRef,
    observation_ref: observationRef,
    affordances: normalizeVisualAffordances({
      rawAffordances:
        visualObservation.affordances ??
        visualObservation.visual_affordances ??
        metadata.visual_affordances,
      targets,
      runId,
    }),
  };
  const adapterContract = {
    schema_version: COMPUTER_USE_CONTRACT_SCHEMA_VERSION,
    adapter_id: "ioi.visual_gui.local_observation",
    lane: "visual_gui",
    supported_session_modes: [sessionMode],
    capabilities: uniqueStrings([
      screenshotRef ? "observe.screenshot" : null,
      somRef ? "observe.som" : null,
      axRef ? "observe.accessibility_tree" : null,
      "build.target_index",
      "build.affordance_graph",
      "verify.postcondition",
      "cleanup",
    ]),
    emits_observation_bundle: true,
    emits_action_receipts: true,
    emits_cleanup_receipts: true,
    fail_closed_when_unavailable: true,
  };
  const cleanupReceipt = {
    cleanup_ref: `cleanup_${safeId(runId)}_visual_observation`,
    lease_id: leaseId,
    status: "completed",
    closed_process_refs: [],
    deleted_profile_refs: [],
    retained_artifact_refs: uniqueStrings([
      "computer-use-trace.json",
      screenshotRef,
      somRef,
      axRef,
    ]),
    warnings: [],
  };
  return {
    observationBundle,
    targetIndex,
    affordanceGraph,
    adapterContract,
    cleanupReceipt,
  };
}

function normalizeVisualTargets({
  rawTargets,
  runId,
  appName,
  windowTitle,
  coordinateSpaceId,
  viewportWidth,
  viewportHeight,
}) {
  const targets = rawTargets
    .map((target, index) => objectValue(target) ? normalizeVisualTarget(target, index, coordinateSpaceId) : null)
    .filter(Boolean);
  if (targets.length > 0) return targets;
  const bounds =
    viewportWidth && viewportHeight
      ? {
          coordinate_space_id: coordinateSpaceId,
          x: 0,
          y: 0,
          width: viewportWidth,
          height: viewportHeight,
        }
      : null;
  return [
    {
      target_ref: `target_${safeId(runId)}_visual_surface`,
      label: windowTitle ?? appName ?? "Visual surface",
      role: appName || windowTitle ? "application" : "screen",
      semantic_ids: [],
      selectors: [],
      som_id: null,
      confidence: 0.5,
      available_actions: ["inspect"],
      ...(bounds ? { bounds } : {}),
    },
  ];
}

function normalizeVisualTarget(target, index, coordinateSpaceId) {
  const bounds = objectValue(target.bounds) ? normalizeBounds(target.bounds, coordinateSpaceId) : null;
  return {
    target_ref:
      cleanString(target.target_ref) ??
      `target_visual_${index + 1}`,
    label: cleanString(target.label ?? target.name) ?? `Visual target ${index + 1}`,
    role: cleanString(target.role) ?? "region",
    semantic_ids: stringArray(target.semantic_ids),
    selectors: stringArray(target.selectors),
    som_id: finiteNumber(target.som_id),
    confidence: finiteNumber(target.confidence) ?? 0.5,
    available_actions: stringArray(target.available_actions).length > 0
      ? stringArray(target.available_actions)
      : ["inspect"],
    ...(bounds ? { bounds } : {}),
  };
}

function normalizeVisualAffordances({ rawAffordances, targets, runId }) {
  const explicit = arrayValue(rawAffordances)
    .map((affordance, index) => objectValue(affordance) ? normalizeAffordance(affordance, index, runId) : null)
    .filter(Boolean);
  if (explicit.length > 0) return explicit;
  return targets.map((target, index) => ({
    affordance_ref: `affordance_${safeId(runId)}_visual_${index + 1}_inspect`,
    target_ref: target.target_ref,
    possible_action: "inspect",
    action_preconditions: ["read_only_visual_observation_available"],
    action_confidence: target.confidence ?? 0.5,
    expected_state_transition: "no_external_effect",
    risk_class: "read_only",
    required_authority: "computer_use.visual_gui.read",
    required_confirmation: false,
    fallback_action_paths: ["reobserve", "ask_user_to_select_target"],
    invalidation_conditions: [
      "screenshot_hash_changed",
      "accessibility_tree_changed",
    ],
  }));
}

function normalizeAffordance(affordance, index, runId) {
  const targetRef = cleanString(affordance.target_ref);
  return {
    affordance_ref:
      cleanString(affordance.affordance_ref) ??
      `affordance_${safeId(runId)}_visual_${index + 1}`,
    target_ref: targetRef ?? "target_visual_1",
    possible_action: cleanString(affordance.possible_action) ?? "inspect",
    action_preconditions: stringArray(affordance.action_preconditions),
    action_confidence: finiteNumber(affordance.action_confidence) ?? 0.5,
    expected_state_transition:
      cleanString(affordance.expected_state_transition) ??
      "no_external_effect",
    risk_class: cleanString(affordance.risk_class) ?? "read_only",
    required_authority:
      cleanString(affordance.required_authority) ??
      "computer_use.visual_gui.read",
    required_confirmation:
      Boolean(affordance.required_confirmation ?? false),
    fallback_action_paths: stringArray(affordance.fallback_action_paths),
    invalidation_conditions: stringArray(
      affordance.invalidation_conditions,
    ),
  };
}

function normalizeBounds(bounds, coordinateSpaceId) {
  const x = finiteNumber(bounds.x);
  const y = finiteNumber(bounds.y);
  const width = finiteNumber(bounds.width);
  const height = finiteNumber(bounds.height);
  if (x === null || y === null || width === null || height === null) return null;
  return {
    coordinate_space_id:
      cleanString(bounds.coordinate_space_id) ?? coordinateSpaceId,
    x,
    y,
    width,
    height,
  };
}

function objectValue(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : null;
}

function arrayValue(value) {
  return Array.isArray(value) ? value : [];
}

function stringArray(value) {
  if (!Array.isArray(value)) return [];
  return value.map((item) => cleanString(item)).filter(Boolean);
}

function cleanString(value) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function uniqueStrings(values) {
  return [...new Set(values.map((value) => cleanString(value)).filter(Boolean))];
}

function finiteNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function safeId(value) {
  return String(value ?? "id")
    .replace(/[^a-zA-Z0-9_.-]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 80) || "id";
}
