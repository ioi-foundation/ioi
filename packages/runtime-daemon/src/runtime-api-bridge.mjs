const RUNTIME_SERVICE_PROFILES = new Set(["runtime", "runtime_service", "live", "production"]);
const FIXTURE_RUNTIME_PROFILES = new Set(["fixture", "agentgres_fixture", "local_daemon_agentgres_projection"]);

export function runtimeProfileForRequest(request = {}, options = {}) {
  return normalizeRuntimeProfile(
    request.runtime_profile ??
      options.runtime_profile ??
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
