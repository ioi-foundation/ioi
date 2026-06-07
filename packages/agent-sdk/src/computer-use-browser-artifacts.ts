import type {
  AffordanceGraph,
  ComputerActionKind,
  ComputerUseObservationBundle,
  ComputerUseTargetEntry,
  ObservationRetentionMode,
  TargetIndex,
} from "./computer-use.js";

export interface BrowserObservationArtifacts {
  url?: unknown;
  page_title?: unknown;
  browser_use_selector_map_text?: unknown;
  browsergym_dom_text?: unknown;
  browsergym_axtree_text?: unknown;
  browsergym_focused_bid?: unknown;
  screenshot_ref?: unknown;
  som_ref?: unknown;
  redaction_report_ref?: unknown;
}

export function computerUseContractsFromBrowserObservationArtifacts({
  artifacts,
  leaseId,
  observationRef,
  targetIndexRef,
  affordanceGraphRef,
  retentionMode,
}: {
  artifacts: BrowserObservationArtifacts | null;
  leaseId: string;
  observationRef: string;
  targetIndexRef: string;
  affordanceGraphRef: string;
  retentionMode: ObservationRetentionMode;
}): {
  observationBundle: Partial<ComputerUseObservationBundle>;
  targetIndex: Partial<TargetIndex>;
  affordanceGraph: Partial<AffordanceGraph>;
} | null {
  if (!artifacts) return null;
  const selectorMapText = cleanString(artifacts.browser_use_selector_map_text);
  const domText = cleanString(artifacts.browsergym_dom_text);
  const axText = cleanString(artifacts.browsergym_axtree_text);
  const focusedBid = cleanString(artifacts.browsergym_focused_bid);
  const title = cleanString(artifacts.page_title);
  const observationBundle: Partial<ComputerUseObservationBundle> = {
    observation_ref: observationRef,
    lease_id: leaseId,
    lane: "native_browser",
    session_mode: "owned_hermetic_browser",
    url: cleanString(artifacts.url),
    title,
    app_name: "Chromium",
    window_title: title ?? "IOI browser-use harness",
    screenshot_ref: cleanString(artifacts.screenshot_ref),
    som_ref: cleanString(artifacts.som_ref),
    dom_ref: artifactRef(observationRef, "browsergym_dom", Boolean(domText)),
    ax_ref: artifactRef(observationRef, "browsergym_ax", Boolean(axText)),
    selector_map_ref: artifactRef(observationRef, "selector_map", Boolean(selectorMapText)),
    target_index_ref: targetIndexRef,
    redaction_report_ref: cleanString(artifacts.redaction_report_ref),
    freshness_ms: 0,
    retention_mode: retentionMode,
    detected_patterns: inferInterfacePatternsFromBrowserArtifacts({
      selectorMapText,
      domText,
      axText,
    }),
  };
  const targetIndex = targetIndexFromBrowserObservationArtifacts({
    observation: observationBundle,
    selectorMapText,
    focusedBid,
    targetIndexRef,
  });
  const affordanceGraph = affordanceGraphFromTargetIndex({
    targetIndex,
    graphRef: affordanceGraphRef,
  });
  return {
    observationBundle,
    targetIndex,
    affordanceGraph,
  };
}

function artifactRef(
  observationRef: string,
  suffix: string,
  present: boolean,
): string | null {
  return present ? `${observationRef}:${suffix}` : null;
}

function targetIndexFromBrowserObservationArtifacts({
  observation,
  selectorMapText,
  focusedBid,
  targetIndexRef,
}: {
  observation: Partial<ComputerUseObservationBundle>;
  selectorMapText: string | null;
  focusedBid: string | null;
  targetIndexRef: string;
}): Partial<TargetIndex> {
  const observationRef = cleanString(observation.observation_ref) ?? "observation:browser";
  const coordinateSpaceId = `viewport:${observationRef}`;
  const targets = selectorMapText
    ? selectorMapTargets(selectorMapText, observationRef, observation.ax_ref)
    : [];
  return {
    target_index_ref: targetIndexRef,
    observation_ref: observationRef,
    coordinate_space_id: coordinateSpaceId,
    drift_state: "fresh",
    targets: targets.length > 0
      ? targets
      : [documentTarget(observation, coordinateSpaceId, focusedBid)],
  };
}

function selectorMapTargets(
  selectorMapText: string,
  observationRef: string,
  axRef: unknown,
): ComputerUseTargetEntry[] {
  return selectorMapText
    .split(/\r?\n/)
    .map((line) => selectorMapTarget(line, observationRef, axRef))
    .filter((target): target is ComputerUseTargetEntry => Boolean(target));
}

function selectorMapTarget(
  line: string,
  observationRef: string,
  axRef: unknown,
): ComputerUseTargetEntry | null {
  const trimmed = cleanString(line);
  if (!trimmed) return null;
  const backendId = trimmed.match(/^\[([^\]]+)\]/)?.[1]?.trim();
  if (!backendId) return null;
  const tag = trimmed
    .match(/<\s*\/?\s*([^\s>/]+)/)?.[1]
    ?.trim()
    .toLowerCase() ?? "element";
  const targetId = attrValue(trimmed, "target_id");
  const label =
    attrValue(trimmed, "name") ??
    attrValue(trimmed, "aria-label") ??
    attrValue(trimmed, "placeholder") ??
    tag;
  const semanticIds = [`browser-use.backend-node:${backendId}`];
  if (targetId) semanticIds.push(`browser-use.target:${targetId}`);
  const cleanedAxRef = cleanString(axRef);
  return {
    target_ref: targetId
      ? `target:${observationRef}:${targetId}`
      : `target:${observationRef}:backend:${backendId}`,
    label,
    role: roleForTag(tag),
    semantic_ids: semanticIds,
    selectors: [`browser-use://backend-node/${backendId}`],
    som_id: null,
    ax_ref: cleanedAxRef ? `${cleanedAxRef}#backend-${backendId}` : null,
    bounds: null,
    confidence: confidenceForTag(tag),
    available_actions: actionsForTag(tag),
  };
}

function documentTarget(
  observation: Partial<ComputerUseObservationBundle>,
  coordinateSpaceId: string,
  focusedBid: string | null,
): ComputerUseTargetEntry {
  const observationRef = cleanString(observation.observation_ref) ?? "observation:browser";
  const semanticIds = ["document", "page-root"];
  if (focusedBid) semanticIds.push(`browsergym.bid:${focusedBid}`);
  const axRef = cleanString(observation.ax_ref);
  return {
    target_ref: `target:${observationRef}:document`,
    label: cleanString(observation.title) ?? "Current page",
    role: "document",
    semantic_ids: semanticIds,
    selectors: ["html", "body"],
    som_id: null,
    ax_ref: axRef ? `${axRef}#document` : null,
    bounds: {
      x: 0,
      y: 0,
      width: 1280,
      height: 720,
      coordinate_space_id: coordinateSpaceId,
    },
    confidence: 90,
    available_actions: ["inspect", "scroll"],
  };
}

function affordanceGraphFromTargetIndex({
  targetIndex,
  graphRef,
}: {
  targetIndex: Partial<TargetIndex>;
  graphRef: string;
}): Partial<AffordanceGraph> {
  const targets = Array.isArray(targetIndex.targets) ? targetIndex.targets : [];
  return {
    graph_ref: graphRef,
    target_index_ref: cleanString(targetIndex.target_index_ref) ?? "target_index:browser",
    observation_ref: cleanString(targetIndex.observation_ref) ?? "observation:browser",
    affordances: targets.flatMap((target) =>
      target.available_actions.map((action) => ({
        target_ref: target.target_ref,
        possible_action: action,
        action_preconditions: [
          "fresh_observation",
          "target_index_present",
          "grounded_target_ref",
        ],
        confidence: target.confidence,
        expected_state_transition: expectedTransitionForAction(action),
        risk_class: riskClassForAction(action),
        required_authority: authorityForAction(action),
        confirmation_required: confirmationRequiredForAction(action),
        fallback_action_paths: ["reobserve", "switch_to_visual_lane"],
        invalidation_conditions: ["navigation", "modal_interruption", "target_drift"],
      })),
    ),
  };
}

function attrValue(line: string, attr: string): string | null {
  const escapedAttr = attr.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const quoted = line.match(new RegExp(`\\b${escapedAttr}=["']([^"']+)["']`));
  if (quoted?.[1]) return quoted[1].trim();
  const bare = line.match(new RegExp(`\\b${escapedAttr}=([^\\s/>]+)`));
  return bare?.[1]?.trim() || null;
}

function roleForTag(tag: string): string {
  switch (tag) {
    case "a":
      return "link";
    case "button":
      return "button";
    case "input":
    case "textarea":
      return "textbox";
    case "select":
      return "combobox";
    case "form":
      return "form";
    case "table":
      return "table";
    case "canvas":
      return "canvas";
    default:
      return "element";
  }
}

function actionsForTag(tag: string): ComputerActionKind[] {
  switch (tag) {
    case "button":
    case "a":
      return ["inspect", "click"];
    case "input":
    case "textarea":
      return ["inspect", "type_text"];
    case "select":
      return ["inspect", "select"];
    default:
      return ["inspect"];
  }
}

function confidenceForTag(tag: string): number {
  return ["button", "a", "input", "textarea", "select"].includes(tag) ? 94 : 82;
}

function authorityForAction(action: ComputerActionKind): string {
  return ["inspect", "scroll", "hover", "wait"].includes(action)
    ? "computer_use.native_browser.read"
    : "computer_use.native_browser.act";
}

function riskClassForAction(action: ComputerActionKind): string {
  return ["inspect", "scroll", "hover", "wait"].includes(action)
    ? "read_only"
    : "possible_external_effect";
}

function confirmationRequiredForAction(action: ComputerActionKind): boolean {
  return !["inspect", "scroll", "hover", "wait"].includes(action);
}

function expectedTransitionForAction(action: ComputerActionKind): string {
  switch (action) {
    case "inspect":
      return "A read-only inspection summary can be produced without external side effects.";
    case "scroll":
      return "The viewport position changes after a grounded scroll.";
    case "click":
      return "The selected element may activate navigation, submit, or open UI state.";
    case "type_text":
      return "The selected field receives text input.";
    case "select":
      return "The selected option changes form state.";
    default:
      return "The target state changes according to the grounded browser action.";
  }
}

function inferInterfacePatternsFromBrowserArtifacts({
  selectorMapText,
  domText,
  axText,
}: {
  selectorMapText: string | null;
  domText: string | null;
  axText: string | null;
}): string[] {
  const haystack = `${selectorMapText ?? ""}\n${domText ?? ""}\n${axText ?? ""}`.toLowerCase();
  const patterns: string[] = [];
  if (/<form\b|\btype=["']?password\b|\btype=["']?email\b|\binput\b|textarea\b|select\b/.test(haystack)) {
    patterns.push("form");
  }
  if (/<table\b|\bgrid\b|\brow\b|\bcolumn\b/.test(haystack)) {
    patterns.push("table");
  }
  if (/<dialog\b|\bmodal\b|\bdialog\b/.test(haystack)) {
    patterns.push("modal");
  }
  if (/<canvas\b|\bcanvas\b/.test(haystack)) {
    patterns.push("canvas");
  }
  if (/\btoolbar\b|<nav\b|<header\b/.test(haystack)) {
    patterns.push("toolbar");
  }
  if (/\bauth\b|\blogin\b|\bsign in\b|\bpassword\b/.test(haystack)) {
    patterns.push("auth_wall");
  }
  return patterns.length > 0 ? patterns : ["browser_page"];
}

function cleanString(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}
