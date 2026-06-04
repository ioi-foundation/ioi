import path from "node:path";

export function runtimeSurvey(state, deps = {}) {
  const { hardwareSnapshot, schemaVersion } = deps;
  const checkedAt = state.nowIso();
  const hardware = hardwareSnapshot();
  const engines = state.listRuntimeEngines();
  const lmStudio = state.lmStudioRuntimeSurvey(checkedAt);
  const runtimePreference = state.runtimePreference();
  const selectedEngines = engines.filter((engine) => engine.selected).map((engine) => engine.id);
  const receipt = state.receipt("runtime_survey", {
    summary: `Runtime survey captured ${engines.length} engine profile${engines.length === 1 ? "" : "s"}.`,
    redaction: "redacted",
    evidenceRefs: [
      "runtime_engine_registry",
      "hardware_snapshot",
      ...(lmStudio.status === "available" ? ["lm_studio_public_lms_runtime_survey"] : []),
    ],
    details: {
      checkedAt,
      engineCount: engines.length,
      selectedEngines,
      runtimePreference,
      hardware,
      lmStudio,
    },
  });
  return {
    schemaVersion,
    checkedAt,
    engines,
    hardware,
    lmStudio,
    runtimePreference,
    receiptId: receipt.id,
  };
}

export function latestRuntimeSurvey(state, deps = {}) {
  const { hardwareSnapshot } = deps;
  const receipt = [...state.listReceipts()].reverse().find((item) => item.kind === "runtime_survey");
  if (!receipt) {
    return {
      status: "not_checked",
      receiptId: "none",
      checkedAt: null,
      engineCount: state.listRuntimeEngines().length,
      selectedEngines: [],
      runtimePreference: state.runtimePreference(),
      hardware: hardwareSnapshot(),
      lmStudio: { status: "not_checked", evidenceRefs: ["runtime_survey_not_checked"] },
    };
  }
  return {
    status: "checked",
    receiptId: receipt.id,
    checkedAt: receipt.details?.checkedAt ?? receipt.createdAt,
    engineCount: receipt.details?.engineCount ?? 0,
    selectedEngines: receipt.details?.selectedEngines ?? [],
    runtimePreference: receipt.details?.runtimePreference ?? state.runtimePreference(),
    hardware: receipt.details?.hardware ?? hardwareSnapshot(),
    lmStudio: receipt.details?.lmStudio ?? { status: "unknown" },
  };
}

export function lmStudioRuntimeEngines(state, checkedAt, deps = {}) {
  const {
    env = process.env,
    isExecutable,
    lmStudioRuntimeDiscoveryEnabled,
    parseLmStudioRuntimeEngines,
    runPublicCommand,
    stableHash,
  } = deps;
  if (!lmStudioRuntimeDiscoveryEnabled()) return [];
  const lmsPath = lmStudioRuntimeLmsPath(state, env);
  if (!lmsPath || !isExecutable(lmsPath)) return [];
  const result = runPublicCommand(lmsPath, ["runtime", "ls"], { timeout: 2500 });
  if (result.status !== 0) return [];
  return parseLmStudioRuntimeEngines(result.stdout).map((engine) => ({
    ...engine,
    checkedAt,
    lmsPathHash: stableHash(lmsPath).slice(0, 16),
    outputHash: stableHash(result.stdout),
    evidenceRefs: ["lm_studio_public_lms_runtime_ls"],
  }));
}

export function lmStudioRuntimeSurvey(state, checkedAt, deps = {}) {
  const {
    env = process.env,
    isExecutable,
    lmStudioRuntimeDiscoveryEnabled,
    parseLmStudioRuntimeSurvey,
    runPublicCommand,
    stableHash,
  } = deps;
  if (!lmStudioRuntimeDiscoveryEnabled()) {
    return {
      status: "absent",
      checkedAt,
      evidenceRefs: ["lm_studio_public_runtime_discovery_disabled"],
    };
  }
  const lmsPath = lmStudioRuntimeLmsPath(state, env);
  if (!lmsPath || !isExecutable(lmsPath)) {
    return { status: "absent", checkedAt, evidenceRefs: ["lm_studio_public_lms_absent"] };
  }
  const result = runPublicCommand(lmsPath, ["runtime", "survey"], { timeout: 3000 });
  const parsed = parseLmStudioRuntimeSurvey(result.stdout);
  return {
    status: result.status === 0 ? "available" : "blocked",
    checkedAt,
    selectedRuntime: parsed.selectedRuntime,
    accelerators: parsed.accelerators,
    cpu: parsed.cpu,
    ram: parsed.ram,
    outputHash: stableHash(`${result.stdout}\n${result.stderr}`),
    exitCode: result.status,
    lmsPathHash: stableHash(lmsPath).slice(0, 16),
    evidenceRefs: ["lm_studio_public_lms_runtime_survey"],
    errorHash: result.status === 0 ? null : stableHash(result.stderr || result.error || "runtime survey failed"),
  };
}

function lmStudioRuntimeLmsPath(state, env) {
  const provider = state.providers.get("provider.lmstudio");
  return (
    provider?.discovery?.publicCli?.path ??
    env.IOI_LMS_PATH ??
    path.join(state.homeDir, ".lmstudio/bin/lms")
  );
}
