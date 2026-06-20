import {
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

// Canonical environment status object (see
// docs/architecture/components/hypervisor/providers-and-environments.md ->
// Environment Status Object). The shape follows established
// remote-development environment status conventions and is IOI-native: the
// truth is Agentgres, the authority is wallet.network, and the bytes are
// encrypted-blob storage. The daemon projects this object; it is never the
// authoritative state.
export const HYPERVISOR_ENVIRONMENT_STATUS_SCHEMA_VERSION =
  "ioi.hypervisor.environment_status.v1";

export const HYPERVISOR_WORKSPACE_INITIALIZER_SCHEMA_VERSION =
  "ioi.hypervisor.workspace_initializer.v1";

// Per-component sub-phase taxonomy. Distinct from the top-level environment
// phase; every component lifecycle walks this set.
export const ENVIRONMENT_COMPONENT_PHASES = Object.freeze([
  "pending",
  "creating",
  "initializing",
  "ready",
  "degraded",
  "failed",
]);

// The ordered component sub-objects the status carries. provisioner ->
// workspace_content -> sandbox -> secrets -> model_mount -> harness mirror the
// real provisioning transitions; automations rides alongside.
export const ENVIRONMENT_COMPONENT_KEYS = Object.freeze([
  "provisioner",
  "workspace_content",
  "sandbox",
  "secrets",
  "automations",
  "model_mount",
  "harness",
]);

const TERMINAL_FAILED_PHASE = "failed";

function coerceComponentPhase(value, fallback = "ready") {
  const phase = optionalString(value);
  return phase && ENVIRONMENT_COMPONENT_PHASES.includes(phase)
    ? phase
    : fallback;
}

// Derive the aggregate environment phase from the component sub-phases.
function aggregateEnvironmentPhase(components) {
  const phases = ENVIRONMENT_COMPONENT_KEYS.map(
    (key) => components[key]?.phase ?? "ready",
  );
  if (phases.includes(TERMINAL_FAILED_PHASE)) return "failed";
  if (phases.some((phase) => phase === "degraded")) return "updating";
  if (
    phases.some((phase) =>
      ["pending", "creating", "initializing"].includes(phase),
    )
  ) {
    return "starting";
  }
  return "running";
}

/**
 * Build a typed HypervisorWorkspaceInitializer. specs is an ordered list of
 * {context_url} or {git:{remote_uri,clone_target,target_mode}} entries; an
 * empty specs list means a fresh scratch workspace. custody_posture passes
 * through the daemon workspace_mount_policy (public_trunk / redacted_projection
 * / plain_workspace / ctee_private_workspace). Pure: no I/O.
 */
export function deriveWorkspaceInitializer({
  contextUrl,
  gitSpec,
  workspaceMountPolicy,
  authorityScopeRefs,
  initializerRef,
} = {}) {
  const specs = [];
  const context = optionalString(contextUrl);
  if (context) {
    specs.push({ context_url: context });
  }
  const git = objectRecord(gitSpec);
  if (git && optionalString(git.remote_uri)) {
    specs.push({
      git: {
        remote_uri: optionalString(git.remote_uri),
        clone_target: optionalString(git.clone_target) ?? ".",
        target_mode: optionalString(git.target_mode) ?? "remote_branch",
      },
    });
  }
  const custodyPosture = optionalString(workspaceMountPolicy) ?? "public_trunk";
  return {
    schema_version: HYPERVISOR_WORKSPACE_INITIALIZER_SCHEMA_VERSION,
    initializer_ref:
      optionalString(initializerRef) ??
      `workspace-initializer:${safeId(custodyPosture)}-${specs.length}`,
    specs,
    custody_posture: custodyPosture,
    authority_scope_refs: uniqueStrings(normalizeArray(authorityScopeRefs)),
  };
}

/**
 * Build a wallet-gated HypervisorEnvironmentPort. access_policy is one of
 * private | session_lease | shared; exposure_state is closed | lease_required
 * | open. Port exposure is authorized by a wallet capability lease, never an
 * owner token. Pure: no I/O.
 */
export function buildEnvironmentPort({
  port,
  protocol,
  accessPolicy,
  capabilityLeaseRef,
  url,
  exposureState,
} = {}) {
  return {
    port: Number.isFinite(port) ? port : null,
    protocol: optionalString(protocol) ?? "http",
    access_policy: optionalString(accessPolicy) ?? "session_lease",
    capability_lease_ref: optionalString(capabilityLeaseRef) ?? null,
    url: optionalString(url) ?? null,
    exposure_state: optionalString(exposureState) ?? "lease_required",
  };
}

function componentEvidence(environmentRef, component) {
  return `agentgres://evidence/environment-status/${safeId(
    environmentRef,
  )}/${component}`;
}

// Map real readiness checks (harness_binary, ollama_provider,
// qwen_model_available) onto the model_mount / harness component phases.
function phasesFromReadinessChecks(readinessChecks) {
  const checks = normalizeArray(readinessChecks)
    .map(objectRecord)
    .filter(Boolean);
  if (checks.length === 0) return {};
  const statusFor = (id) => {
    const check = checks.find((entry) => optionalString(entry.id) === id);
    if (!check) return null;
    return optionalString(check.status);
  };
  const toPhase = (status) => {
    if (status === "pass") return "ready";
    if (status === "fail") return "degraded";
    if (status == null) return null;
    return "initializing";
  };
  const result = {};
  const harnessPhase = toPhase(statusFor("harness_binary"));
  if (harnessPhase) result.harness = harnessPhase;
  const providerPhase =
    toPhase(statusFor("qwen_model_available")) ??
    toPhase(statusFor("ollama_provider"));
  if (providerPhase) result.model_mount = providerPhase;
  return result;
}

/**
 * Project a canonical HypervisorEnvironmentStatus from real transitions. The
 * componentPhases map (e.g. from the workspace provisioner) and readinessChecks
 * (from buildHarnessSessionReadiness) drive the real sub-phases; anything not
 * supplied defaults to ready so the object is always renderable. Pure: no I/O.
 */
export function buildHypervisorEnvironmentStatus({
  environmentRef,
  providerPlacementRef,
  workspaceRoot,
  workspaceMountPolicy,
  initializerRef,
  modelRouteRef,
  harnessSessionRef,
  stateRootRef,
  workspaceArtifactRef,
  componentPhases,
  readinessChecks,
  ports,
  capabilityLeaseRefs,
  failureMessage,
  warningMessage,
} = {}) {
  const envRef =
    optionalString(environmentRef) ?? "environment:hypervisor-session";
  const overrides = objectRecord(componentPhases) ?? {};
  const readinessPhases = phasesFromReadinessChecks(readinessChecks);
  const phaseFor = (component, fallback = "ready") =>
    coerceComponentPhase(
      overrides[component] ?? readinessPhases[component],
      fallback,
    );

  const custodyPosture =
    optionalString(workspaceMountPolicy) ?? "public_trunk";
  const components = {
    provisioner: {
      phase: phaseFor("provisioner"),
      evidence_ref: componentEvidence(envRef, "provisioner"),
    },
    workspace_content: {
      phase: phaseFor("workspace_content"),
      initializer_ref: optionalString(initializerRef) ?? null,
      custody_posture: custodyPosture,
      workspace_root: optionalString(workspaceRoot) ?? null,
      evidence_ref: componentEvidence(envRef, "workspace_content"),
    },
    sandbox: {
      phase: phaseFor("sandbox"),
      evidence_ref: componentEvidence(envRef, "sandbox"),
    },
    secrets: {
      phase: phaseFor("secrets"),
      capability_lease_refs: uniqueStrings(normalizeArray(capabilityLeaseRefs)),
      evidence_ref: componentEvidence(envRef, "secrets"),
    },
    automations: {
      phase: phaseFor("automations"),
      evidence_ref: componentEvidence(envRef, "automations"),
    },
    model_mount: {
      phase: phaseFor("model_mount"),
      model_route_ref: optionalString(modelRouteRef) ?? null,
      evidence_ref: componentEvidence(envRef, "model_mount"),
    },
    harness: {
      phase: phaseFor("harness"),
      harness_session_ref: optionalString(harnessSessionRef) ?? null,
      evidence_ref: componentEvidence(envRef, "harness"),
    },
  };

  return {
    schema_version: HYPERVISOR_ENVIRONMENT_STATUS_SCHEMA_VERSION,
    environment_ref: envRef,
    provider_placement_ref: optionalString(providerPlacementRef) ?? null,
    phase: aggregateEnvironmentPhase(components),
    components,
    ports: normalizeArray(ports)
      .map(objectRecord)
      .filter(Boolean)
      .map((port) =>
        buildEnvironmentPort({
          port: port.port,
          protocol: port.protocol,
          accessPolicy: port.access_policy,
          capabilityLeaseRef: port.capability_lease_ref,
          url: port.url,
          exposureState: port.exposure_state,
        }),
      ),
    failure_message: optionalString(failureMessage) ?? null,
    warning_message: optionalString(warningMessage) ?? null,
    state_root_ref:
      optionalString(stateRootRef) ??
      `agentgres://state-root/environment-status/${safeId(envRef)}`,
    workspace_artifact_ref: optionalString(workspaceArtifactRef) ?? null,
    runtimeTruthSource: "daemon-runtime",
  };
}
