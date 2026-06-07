import path from "node:path";

export function nativeBrowserActionKindForInput(input = {}, prompt = "") {
  const explicit = nativeBrowserActionKindValue(
    input.action_kind ??
      input.computer_use_action_kind,
  );
  if (explicit) return explicit;
  return nativeBrowserActionKindFromText(prompt) ?? "inspect";
}

export function nativeBrowserApprovalRefForInput(input = {}) {
  return optionalString(
    input.approval_ref ??
      input.computer_use_approval_ref,
  );
}

export function nativeBrowserControlledRelaunchApprovalRefForInput(input = {}) {
  return optionalString(
    input.controlled_relaunch_approval_ref ??
      input.host_browser_launch_approval_ref ??
      input.browser_launch_approval_ref,
  );
}

export function nativeBrowserExecutionUnavailableFromControlledRelaunchLaunch({
  launchReceipt,
  actionKind,
  approvalRef,
  uniqueStrings = defaultUniqueStrings,
} = {}) {
  return {
    schema_version: "ioi.runtime.native-browser-cdp-executor.v1",
    object: "ioi.runtime_native_browser_cdp_execution",
    executor_ref: `${launchReceipt?.launch_ref ?? "controlled_relaunch"}_executor_unavailable`,
    adapter_id: launchReceipt?.adapter_id ?? "ioi.native_browser.controlled_relaunch_broker",
    session_ref: launchReceipt?.session_ref ?? null,
    endpoint_ref: launchReceipt?.endpoint_ref ?? null,
    endpoint_source: launchReceipt?.endpoint_source ?? null,
    action_kind: actionKind,
    approval_ref: approvalRef ?? null,
    status: "unavailable",
    error_class: launchReceipt?.error_class ?? "ControlledRelaunchLaunchUnavailable",
    error_summary:
      launchReceipt?.error_summary ??
      "Controlled browser relaunch did not produce an attachable CDP endpoint.",
    evidence_refs: uniqueStrings([
      launchReceipt?.launch_ref,
      launchReceipt?.broker_ref,
      launchReceipt?.profile_dir_ref,
      ...(launchReceipt?.evidence_refs ?? []),
    ]),
  };
}

export function nativeBrowserCdpTimeoutMs(input = {}) {
  const value = Number(
    input.cdp_timeout_ms ??
      input.timeout_ms,
  );
  if (Number.isFinite(value) && value >= 100 && value <= 120_000) {
    return Math.round(value);
  }
  return 3_000;
}

export function nativeBrowserSessionModeForInput(input = {}) {
  const explicit = optionalString(
    input.session_mode ??
      input.computer_use_session_mode,
  );
  if (explicit) return explicit;
  if (nativeBrowserHasExplicitCdpEndpoint(input)) return "attached_cdp";
  if (input.controlled_relaunch === true) {
    return "controlled_relaunch";
  }
  return "owned_hermetic_browser";
}

export function visualGuiSessionModeForInput(input = {}) {
  const explicit = optionalString(
    input.session_mode ??
      input.computer_use_session_mode,
  );
  if (
    ["visual_fallback", "foreground_desktop", "background_desktop", "app_scoped_desktop"].includes(explicit)
  ) {
    return explicit;
  }
  return "visual_fallback";
}

export function sandboxedHostedSessionModeForInput(input = {}) {
  const explicit = optionalString(
    input.session_mode ??
      input.computer_use_session_mode,
  );
  if (["local_sandbox", "hosted_sandbox", "mobile_device"].includes(explicit)) {
    return explicit;
  }
  return "local_sandbox";
}

export function visualGuiObservationMetadataForInput(input = {}) {
  const visualObservation = objectRecord(
    input.computer_use_visual_observation ??
      input.visual_gui_observation ??
      input.visual_observation,
  );
  const metadata = {};
  const stringFields = [
    "screenshot_ref",
    "som_ref",
    "ax_ref",
    "accessibility_tree_ref",
    "app_name",
    "window_title",
    "coordinate_space_id",
    "redaction_report_ref",
  ];
  for (const snakeKey of stringFields) {
    const value = optionalString(
      input[snakeKey] ??
        visualObservation?.[snakeKey],
    );
    if (value) metadata[snakeKey] = value;
  }
  const width = visualGuiFiniteNumber(
    input.viewport_width ??
      visualObservation?.viewport_width,
  );
  const height = visualGuiFiniteNumber(
    input.viewport_height ??
      visualObservation?.viewport_height,
  );
  if (width !== null) metadata.viewport_width = width;
  if (height !== null) metadata.viewport_height = height;
  const visualTargets = normalizeArray(
    input.visual_targets ??
      visualObservation?.visual_targets ??
      visualObservation?.targets,
  );
  const visualAffordances = normalizeArray(
    input.visual_affordances ??
      visualObservation?.visual_affordances ??
      visualObservation?.affordances,
  );
  const detectedPatterns = normalizeArray(
    input.detected_patterns ??
      visualObservation?.detected_patterns,
  );
  if (visualTargets.length > 0) metadata.visual_targets = visualTargets;
  if (visualAffordances.length > 0) metadata.visual_affordances = visualAffordances;
  if (detectedPatterns.length > 0) metadata.detected_patterns = detectedPatterns;
  if (Object.keys(visualObservation).length > 0) {
    metadata.computer_use_visual_observation = visualObservation;
  }
  return metadata;
}

export function visualGuiFiniteNumber(value) {
  const numeric = typeof value === "number" ? value : Number(value);
  return Number.isFinite(numeric) ? numeric : null;
}

export function visualGuiMediaTypeForPath(filePath) {
  const ext = path.extname(String(filePath ?? "")).toLowerCase();
  if (ext === ".png") return "image/png";
  if (ext === ".jpg" || ext === ".jpeg") return "image/jpeg";
  if (ext === ".webp") return "image/webp";
  if (ext === ".json") return "application/json";
  if (ext === ".txt") return "text/plain";
  if (ext === ".svg") return "image/svg+xml";
  return null;
}

export function firstOptionalString(values) {
  for (const value of values) {
    const text = optionalString(value);
    if (text) return text;
  }
  return null;
}

export function snakeCaseKey(value) {
  return String(value ?? "")
    .replace(/([a-z0-9])([A-Z])/g, "$1_$2")
    .toLowerCase();
}

export function nativeBrowserActionShouldUseCdpExecutor(actionKind, approvalRef, input = {}) {
  if (!nativeBrowserActionKindIsReadOnly(actionKind) && approvalRef) return true;
  return actionKind === "scroll" && nativeBrowserHasExplicitCdpEndpoint(input);
}

export function computerUseControlActionForInput(input = {}) {
  const explicit = optionalString(
    input.controlAction ??
      input.control_action ??
      input.action ??
      input.command,
  )?.toLowerCase().replace(/[\s-]+/g, "_");
  if (explicit === "resume" || explicit === "continue") return "resume";
  if (explicit === "abort" || explicit === "cancel" || explicit === "stop") return "abort";
  if (explicit === "cleanup" || explicit === "clean_up" || explicit === "clean") return "cleanup";
  return "pause";
}

export function nativeBrowserHasExplicitCdpEndpoint(input = {}) {
  return Boolean(optionalString(
    input.cdp_endpoint_url ??
      input.cdp_endpoint ??
      input.cdp_websocket_url ??
      input.cdp_ws_url ??
      input.web_socket_debugger_url,
  ));
}

export function nativeBrowserActionKindValue(value) {
  const normalized = optionalString(value)?.toLowerCase().replace(/[\s-]+/g, "_");
  if (!normalized) return null;
  if (normalized === "type" || normalized === "input_text") return "type_text";
  if (normalized === "keypress") return "key_press";
  if (normalized === "mouse_move") return "hover";
  return nativeBrowserActionKinds().has(normalized) ? normalized : null;
}

export function nativeBrowserActionKindFromText(value) {
  const normalized = String(value ?? "").trim().toLowerCase();
  if (/^click\b|\bclick\s+/.test(normalized)) return "click";
  if (/^type\b|\btype\s+|type_text|input\s+text/.test(normalized)) return "type_text";
  if (/^key\b|\bkey\s+|key_press|keypress|^press\b|\bpress\s+/.test(normalized)) return "key_press";
  if (/^scroll\b|\bscroll\s+/.test(normalized)) return "scroll";
  if (/^hover\b|\bhover\s+|mouse_move/.test(normalized)) return "hover";
  if (/^wait\b|\bwait\s+/.test(normalized)) return "wait";
  if (/^navigate\b|\bnavigate\s+|open\s+url/.test(normalized)) return "navigate";
  if (/^select\b|\bselect\s+/.test(normalized)) return "select";
  if (/^upload\b|\bupload\s+/.test(normalized)) return "upload";
  return null;
}

export function nativeBrowserActionKinds() {
  return new Set([
    "click",
    "type_text",
    "key_press",
    "scroll",
    "drag",
    "hover",
    "select",
    "upload",
    "clipboard",
    "wait",
    "shell",
    "mobile_gesture",
    "navigate",
    "inspect",
  ]);
}

export function nativeBrowserActionKindIsReadOnly(actionKind) {
  return ["inspect", "hover", "wait", "scroll"].includes(actionKind);
}

function normalizeArray(value) {
  return Array.isArray(value) ? value.filter(Boolean) : [];
}

function objectRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function optionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed ? trimmed : null;
}

function defaultUniqueStrings(values) {
  return [...new Set(normalizeArray(values).map((value) => String(value)).filter(Boolean))];
}
