import { createRuntimeAgentServiceCommandAdapterFromEnv } from "./runtime-agent-service-adapter.mjs";

const RUNTIME_SERVICE_PROFILES = new Set(["runtime", "runtime_service", "live", "production"]);
const FIXTURE_RUNTIME_PROFILES = new Set(["fixture", "agentgres_fixture", "local_daemon_agentgres_projection"]);

export function runtimeProfileForRequest(request = {}, options = {}) {
  return normalizeRuntimeProfile(
    request.runtime_profile ??
      request.runtimeProfile ??
      options.runtime_profile ??
      options.runtimeProfile ??
      process.env.IOI_RUNTIME_DAEMON_PROFILE ??
      "fixture",
  );
}

export function normalizeRuntimeProfile(value) {
  const profile = String(value ?? "fixture").trim().toLowerCase();
  if (!profile || FIXTURE_RUNTIME_PROFILES.has(profile)) return "fixture";
  if (RUNTIME_SERVICE_PROFILES.has(profile)) return "runtime_service";
  return profile;
}

export function isRuntimeServiceProfile(profile) {
  return normalizeRuntimeProfile(profile) === "runtime_service";
}

export function isFixtureRuntimeProfile(profile) {
  return normalizeRuntimeProfile(profile) === "fixture";
}

export function createRuntimeApiBridge(adapter = null) {
  return new RuntimeApiBridge(adapter ?? createRuntimeAgentServiceCommandAdapterFromEnv());
}

export class RuntimeApiBridge {
  constructor(adapter = null) {
    this.adapter = adapter;
    this.bridgeId = adapter?.bridgeId ?? adapter?.bridge_id ?? "runtime_api_bridge";
  }

  get canStartThread() {
    return typeof this.adapter?.startThread === "function";
  }

  get canSubmitTurn() {
    return typeof this.adapter?.submitTurn === "function";
  }

  async startThread(input) {
    if (!this.canStartThread) {
      throw new RuntimeApiBridgeUnavailableError("RuntimeApiBridge startThread is not configured.", {
        operation: "start_thread",
      });
    }
    return this.adapter.startThread(input);
  }

  async submitTurn(input, options = {}) {
    if (!this.canSubmitTurn) {
      throw new RuntimeApiBridgeUnavailableError("RuntimeApiBridge submitTurn is not configured.", {
        operation: "submit_turn",
      });
    }
    return this.adapter.submitTurn(input, options);
  }
}

export class RuntimeApiBridgeUnavailableError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = "RuntimeApiBridgeUnavailableError";
    this.details = details;
  }
}
