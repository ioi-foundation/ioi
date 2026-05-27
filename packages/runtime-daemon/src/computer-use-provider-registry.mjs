export const COMPUTER_USE_PROVIDER_REGISTRY_SCHEMA_VERSION = "ioi.computer-use.provider-registry.v1";

const PROVIDERS = [
  {
    provider_id: "ioi.computer_use.native_browser.task_scoped_profile",
    provider_kind: "task_scoped_browser_profile",
    lane: "native_browser",
    status: "available",
    implementation_status: "concrete_with_fail_closed_adapters",
    thread_tool_name: "ioi.computer_use.native_browser",
    supported_session_modes: ["owned_hermetic_browser", "attached_browser", "controlled_relaunch"],
    capabilities: ["browser_discovery", "observation", "target_index", "action_proposal", "verification", "cleanup"],
    authority_scopes: ["computer_use.native_browser.read", "computer_use.native_browser.act"],
    retention_modes: ["prompt_visible_summary_only", "local_redacted_artifacts", "local_raw_artifacts"],
    cleanup_required: true,
    fixture: false,
  },
  {
    provider_id: "ioi.computer_use.visual_gui.local",
    provider_kind: "local_visual_gui",
    lane: "visual_gui",
    status: "available",
    implementation_status: "concrete_when_observation_or_executor_available",
    thread_tool_name: "ioi.computer_use.visual_gui",
    supported_session_modes: ["visual_fallback", "foreground_desktop", "background_desktop", "app_scoped_desktop"],
    capabilities: ["visual_observation", "target_index", "action_proposal", "verification", "cleanup"],
    authority_scopes: ["computer_use.visual_gui.read", "computer_use.visual_gui.act"],
    retention_modes: ["prompt_visible_summary_only", "local_redacted_artifacts", "local_raw_artifacts"],
    cleanup_required: true,
    fixture: false,
  },
  {
    provider_id: "ioi.computer_use.sandboxed_hosted.local_fixture",
    provider_kind: "local_fixture",
    lane: "sandboxed_hosted",
    status: "available",
    implementation_status: "deterministic_fixture",
    thread_tool_name: "ioi.computer_use.sandboxed_hosted",
    supported_session_modes: ["local_sandbox"],
    capabilities: ["observation", "target_index", "action_proposal", "verification", "cleanup"],
    authority_scopes: ["computer_use.sandboxed_hosted.read", "computer_use.sandboxed_hosted.act"],
    retention_modes: ["no_persistence", "prompt_visible_summary_only"],
    cleanup_required: true,
    fixture: true,
  },
  {
    provider_id: "ioi.computer_use.sandboxed_hosted.local_container",
    provider_kind: "local_container",
    lane: "sandboxed_hosted",
    status: "unavailable",
    implementation_status: "planned_fail_closed",
    thread_tool_name: null,
    supported_session_modes: ["local_sandbox", "hosted_sandbox"],
    capabilities: ["provider_discovery", "lease_request"],
    authority_scopes: ["computer_use.sandboxed_hosted.read", "computer_use.sandboxed_hosted.act"],
    retention_modes: ["no_persistence", "local_redacted_artifacts"],
    cleanup_required: true,
    fixture: false,
    unavailable_reason: "Local container provider is registered as a planned parity-plus provider; no container runtime adapter is mounted yet.",
  },
];

export function computerUseProviderRegistryReport() {
  const providers = PROVIDERS.map((provider) => cloneProvider(provider));
  return {
    schema_version: COMPUTER_USE_PROVIDER_REGISTRY_SCHEMA_VERSION,
    object: "ioi.computer_use.provider_registry_report",
    providers,
    available_provider_ids: providers
      .filter((provider) => provider.status === "available")
      .map((provider) => provider.provider_id),
    unavailable_provider_ids: providers
      .filter((provider) => provider.status !== "available")
      .map((provider) => provider.provider_id),
    fail_closed_when_unavailable: true,
  };
}

export function computerUseProviderForLane(lane, options = {}) {
  const requestedLane = normalizeLane(lane);
  const providerHint = cleanString(options.providerHint ?? options.provider_id ?? options.providerKind);
  const sessionMode = cleanString(options.sessionMode ?? options.session_mode);
  const registry = computerUseProviderRegistryReport();
  const laneProviders = registry.providers.filter((provider) => provider.lane === requestedLane);
  const hinted = laneProviders.find((provider) =>
    provider.provider_id === providerHint ||
    provider.provider_kind === providerHint ||
    provider.provider_id.endsWith(`.${providerHint}`) ||
    provider.provider_id.endsWith(`_${providerHint}`),
  );
  const matchingSession = laneProviders.find((provider) =>
    provider.status === "available" &&
    (!sessionMode || provider.supported_session_modes.includes(sessionMode)),
  );
  return hinted ?? matchingSession ?? laneProviders.find((provider) => provider.status === "available") ?? laneProviders[0] ?? null;
}

export function computerUseThreadToolNameForProvider(provider) {
  return cleanString(provider?.thread_tool_name) ?? null;
}

function normalizeLane(lane) {
  const value = cleanString(lane);
  if (value === "visual_gui" || value === "sandboxed_hosted") return value;
  return "native_browser";
}

function cleanString(value) {
  const text = typeof value === "string" ? value.trim() : "";
  return text ? text : null;
}

function cloneProvider(provider) {
  return {
    ...provider,
    supported_session_modes: [...provider.supported_session_modes],
    capabilities: [...provider.capabilities],
    authority_scopes: [...provider.authority_scopes],
    retention_modes: [...provider.retention_modes],
  };
}
