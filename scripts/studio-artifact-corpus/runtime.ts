import { spawnSync } from "node:child_process";

import {
  DEFAULT_OLLAMA_CHAT_ENDPOINT,
  DEFAULT_OLLAMA_HEALTH_ENDPOINT,
  OLLAMA_SINGLE_MODEL_LANE_OVERRIDES,
  PREFERRED_OLLAMA_ACCEPTANCE_MODELS,
  PREFERRED_FAST_OLLAMA_ACCEPTANCE_MODELS,
  PREFERRED_FAST_OLLAMA_PRODUCTION_MODELS,
  PREFERRED_OLLAMA_PRODUCTION_MODELS,
  cliBinary,
  repoRoot,
  studioProofBinary,
} from "./config";
import type { CommandCapture, RendererKind, StudioRuntimeEnv } from "./types";

let cachedArtifactCommandEnv: NodeJS.ProcessEnv | null = null;
let cachedAutoConfiguredRuntime: StudioRuntimeEnv | null = null;
let cachedAvailableOllamaModels: string[] | null = null;
type CommandEnvOverrides = Record<string, string | null | undefined>;
type ProofLane = "contract" | "live";
const DEFAULT_OLLAMA_CONTEXT_LENGTH = "8192";
const LIVE_HTML_OLLAMA_CONTEXT_LENGTH = "4096";

export function chooseAvailableOllamaModel(
  availableModels: string[],
  preferredModels: string[],
): string | null {
  for (const model of preferredModels) {
    if (availableModels.includes(model)) {
      return model;
    }
  }
  return availableModels[0] ?? null;
}

export function ollamaContextLengthForRenderer(
  renderer: RendererKind,
  lane: ProofLane,
  env: NodeJS.ProcessEnv = process.env,
): string {
  const explicit = env.OLLAMA_CONTEXT_LENGTH?.trim();
  if (explicit) {
    return explicit;
  }

  return renderer === "html_iframe" && lane === "live"
    ? LIVE_HTML_OLLAMA_CONTEXT_LENGTH
    : DEFAULT_OLLAMA_CONTEXT_LENGTH;
}

function buildStudioRuntimeEnv(
  availableModels: string[],
  productionPreferences: string[],
  acceptancePreferences: string[],
): StudioRuntimeEnv | null {
  const productionModel = chooseAvailableOllamaModel(
    availableModels,
    productionPreferences,
  );
  if (!productionModel) {
    return null;
  }

  const acceptanceModel =
    acceptancePreferences.find(
      (model) => model !== productionModel && availableModels.includes(model),
    ) ??
    chooseAvailableOllamaModel(availableModels, acceptancePreferences) ??
    productionModel;

  return {
    endpoint: DEFAULT_OLLAMA_CHAT_ENDPOINT,
    healthEndpoint: DEFAULT_OLLAMA_HEALTH_ENDPOINT,
    productionModel,
    acceptanceEndpoint: `${DEFAULT_OLLAMA_CHAT_ENDPOINT}?lane=acceptance`,
    acceptanceHealthEndpoint: DEFAULT_OLLAMA_HEALTH_ENDPOINT,
    acceptanceModel,
  };
}

function buildStudioRuntimeEnvFromModels(
  productionModel: string,
  acceptanceModel: string,
): StudioRuntimeEnv {
  return {
    endpoint: DEFAULT_OLLAMA_CHAT_ENDPOINT,
    healthEndpoint: DEFAULT_OLLAMA_HEALTH_ENDPOINT,
    productionModel,
    acceptanceEndpoint: `${DEFAULT_OLLAMA_CHAT_ENDPOINT}?lane=acceptance`,
    acceptanceHealthEndpoint: DEFAULT_OLLAMA_HEALTH_ENDPOINT,
    acceptanceModel,
  };
}

function chooseSingleModelLaneOverrideRuntime(
  renderer: RendererKind,
  lane: ProofLane,
  availableModels: string[],
): StudioRuntimeEnv | null {
  const override = OLLAMA_SINGLE_MODEL_LANE_OVERRIDES.find(
    (entry) => entry.renderer === renderer && entry.lane === lane,
  );
  if (!override) {
    return null;
  }

  const model = override.modelPreferences.find((entry) =>
    availableModels.includes(entry),
  );
  if (model) {
    return buildStudioRuntimeEnvFromModels(model, model);
  }

  return null;
}

function rendererUsesFastDocumentProofLane(renderer: RendererKind): boolean {
  return (
    process.env.STUDIO_ARTIFACT_CORPUS_USE_FAST_DOC_LANE === "1" &&
    (renderer === "markdown" ||
      renderer === "mermaid" ||
      renderer === "pdf_embed" ||
      renderer === "download_card")
  );
}

export function chooseAvailableOllamaRuntime(
  availableModels: string[],
): StudioRuntimeEnv | null {
  return buildStudioRuntimeEnv(
    availableModels,
    PREFERRED_OLLAMA_PRODUCTION_MODELS,
    PREFERRED_OLLAMA_ACCEPTANCE_MODELS,
  );
}

export function chooseAvailableOllamaRuntimeForRenderer(
  renderer: RendererKind,
  availableModels: string[],
): StudioRuntimeEnv | null {
  const singleModelLaneOverride = chooseSingleModelLaneOverrideRuntime(
    renderer,
    "live",
    availableModels,
  );
  if (singleModelLaneOverride) {
    return singleModelLaneOverride;
  }

  if (rendererUsesFastDocumentProofLane(renderer)) {
    return buildStudioRuntimeEnv(
      availableModels,
      PREFERRED_FAST_OLLAMA_PRODUCTION_MODELS,
      PREFERRED_FAST_OLLAMA_ACCEPTANCE_MODELS,
    );
  }

  return chooseAvailableOllamaRuntime(availableModels);
}

function chooseAvailableOllamaContractRuntimeForRenderer(
  renderer: RendererKind,
  availableModels: string[],
): StudioRuntimeEnv | null {
  const singleModelLaneOverride = chooseSingleModelLaneOverrideRuntime(
    renderer,
    "contract",
    availableModels,
  );
  if (singleModelLaneOverride) {
    return singleModelLaneOverride;
  }

  const documentRenderer =
    renderer === "markdown" ||
    renderer === "mermaid" ||
    renderer === "pdf_embed" ||
    renderer === "download_card";
  const productionPreferences =
    documentRenderer && rendererUsesFastDocumentProofLane(renderer)
      ? PREFERRED_FAST_OLLAMA_PRODUCTION_MODELS
      : PREFERRED_OLLAMA_PRODUCTION_MODELS;
  const productionModel = chooseAvailableOllamaModel(
    availableModels,
    productionPreferences,
  );
  if (!productionModel) {
    return null;
  }

  if (documentRenderer && rendererUsesFastDocumentProofLane(renderer)) {
    const acceptanceModel =
      chooseAvailableOllamaModel(
        availableModels.filter((model) => model !== productionModel),
        PREFERRED_FAST_OLLAMA_ACCEPTANCE_MODELS,
      ) ?? productionModel;
    return buildStudioRuntimeEnvFromModels(productionModel, acceptanceModel);
  }

  return buildStudioRuntimeEnvFromModels(productionModel, productionModel);
}

export function chooseAvailableOllamaRuntimeForProofLane(
  renderer: RendererKind,
  lane: ProofLane,
  availableModels: string[],
): StudioRuntimeEnv | null {
  return lane === "contract"
    ? chooseAvailableOllamaContractRuntimeForRenderer(renderer, availableModels)
    : chooseAvailableOllamaRuntimeForRenderer(renderer, availableModels);
}

function detectAvailableOllamaModels(): string[] {
  if (cachedAvailableOllamaModels) {
    return cachedAvailableOllamaModels;
  }

  const tags = spawnSync("curl", ["-fsS", DEFAULT_OLLAMA_HEALTH_ENDPOINT], {
    cwd: repoRoot,
    encoding: "utf8",
  });
  if (tags.status !== 0 || !tags.stdout.trim()) {
    cachedAvailableOllamaModels = [];
    return cachedAvailableOllamaModels;
  }

  const parsed = JSON.parse(tags.stdout) as {
    models?: Array<{ name?: string | null }>;
  };
  cachedAvailableOllamaModels = (parsed.models ?? [])
    .map((model) => model.name?.trim())
    .filter((model): model is string => Boolean(model));
  return cachedAvailableOllamaModels;
}

export function detectLocalOllamaRuntime(): StudioRuntimeEnv | null {
  return chooseAvailableOllamaRuntime(detectAvailableOllamaModels());
}

export function artifactCommandEnv(): NodeJS.ProcessEnv {
  if (cachedArtifactCommandEnv) {
    return cachedArtifactCommandEnv;
  }

  const env: NodeJS.ProcessEnv = { ...process.env };
  const runtimeConfigured =
    Boolean(env.AUTOPILOT_LOCAL_RUNTIME_URL) || Boolean(env.LOCAL_LLM_URL);

  if (!runtimeConfigured) {
    cachedAutoConfiguredRuntime = detectLocalOllamaRuntime();
    if (cachedAutoConfiguredRuntime) {
      env.AUTOPILOT_LOCAL_RUNTIME_URL = cachedAutoConfiguredRuntime.endpoint;
      env.LOCAL_LLM_URL = cachedAutoConfiguredRuntime.endpoint;
      env.AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL =
        cachedAutoConfiguredRuntime.healthEndpoint;
      env.AUTOPILOT_LOCAL_RUNTIME_MODEL =
        env.AUTOPILOT_LOCAL_RUNTIME_MODEL ??
        cachedAutoConfiguredRuntime.productionModel;
      env.LOCAL_LLM_MODEL =
        env.LOCAL_LLM_MODEL ?? env.AUTOPILOT_LOCAL_RUNTIME_MODEL;
      env.OPENAI_MODEL = env.OPENAI_MODEL ?? env.AUTOPILOT_LOCAL_RUNTIME_MODEL;
      env.AUTOPILOT_ACCEPTANCE_RUNTIME_URL =
        env.AUTOPILOT_ACCEPTANCE_RUNTIME_URL ??
        cachedAutoConfiguredRuntime.acceptanceEndpoint;
      env.AUTOPILOT_ACCEPTANCE_RUNTIME_HEALTH_URL =
        env.AUTOPILOT_ACCEPTANCE_RUNTIME_HEALTH_URL ??
        cachedAutoConfiguredRuntime.acceptanceHealthEndpoint;
      env.AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL =
        env.AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL ??
        cachedAutoConfiguredRuntime.acceptanceModel;
      env.AUTOPILOT_INFERENCE_HTTP_TIMEOUT_SECS =
        env.AUTOPILOT_INFERENCE_HTTP_TIMEOUT_SECS ?? "600";
      env.OLLAMA_CONTEXT_LENGTH =
        env.OLLAMA_CONTEXT_LENGTH ?? DEFAULT_OLLAMA_CONTEXT_LENGTH;
    }
  }

  cachedArtifactCommandEnv = env;
  return env;
}

export function runtimeEnvOverridesForRenderer(
  renderer: RendererKind,
  lane: ProofLane = "live",
): CommandEnvOverrides | undefined {
  const explicitRuntimeConfigured =
    Boolean(process.env.AUTOPILOT_LOCAL_RUNTIME_URL) ||
    Boolean(process.env.LOCAL_LLM_URL);
  if (explicitRuntimeConfigured) {
    return undefined;
  }

  const availableModels = detectAvailableOllamaModels();
  if (availableModels.length === 0) {
    return undefined;
  }

  const runtime = chooseAvailableOllamaRuntimeForProofLane(
    renderer,
    lane,
    availableModels,
  );
  if (!runtime) {
    return undefined;
  }

  const env = artifactCommandEnv();
  return {
    AUTOPILOT_LOCAL_RUNTIME_URL: runtime.endpoint,
    LOCAL_LLM_URL: runtime.endpoint,
    AUTOPILOT_LOCAL_RUNTIME_HEALTH_URL: runtime.healthEndpoint,
    AUTOPILOT_LOCAL_RUNTIME_MODEL: runtime.productionModel,
    LOCAL_LLM_MODEL: runtime.productionModel,
    OPENAI_MODEL: runtime.productionModel,
    AUTOPILOT_ACCEPTANCE_RUNTIME_URL: runtime.acceptanceEndpoint,
    AUTOPILOT_ACCEPTANCE_RUNTIME_HEALTH_URL: runtime.acceptanceHealthEndpoint,
    AUTOPILOT_ACCEPTANCE_RUNTIME_MODEL: runtime.acceptanceModel,
    AUTOPILOT_INFERENCE_HTTP_TIMEOUT_SECS:
      env.AUTOPILOT_INFERENCE_HTTP_TIMEOUT_SECS ?? "600",
    OLLAMA_CONTEXT_LENGTH: ollamaContextLengthForRenderer(renderer, lane, env),
  };
}

function commandEnv(options?: {
  disableAutoRuntime?: boolean;
  envOverrides?: CommandEnvOverrides;
}): NodeJS.ProcessEnv {
  const env = options?.disableAutoRuntime
    ? { ...process.env }
    : { ...artifactCommandEnv() };
  for (const [key, value] of Object.entries(options?.envOverrides ?? {})) {
    if (value == null) {
      delete env[key];
    } else {
      env[key] = value;
    }
  }
  return env;
}

export function runCommand(
  command: string,
  args: string[],
  options: {
    cwd?: string;
    allowFailure?: boolean;
    disableAutoRuntime?: boolean;
    envOverrides?: CommandEnvOverrides;
  } = {},
): CommandCapture {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? repoRoot,
    encoding: "utf8",
    env: commandEnv(options),
  });
  const capture: CommandCapture = {
    args,
    status: result.status ?? 1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
  if (capture.status !== 0 && !options.allowFailure) {
    throw new Error(
      `${command} ${args.join(" ")} failed with status ${capture.status}\n${capture.stdout}\n${capture.stderr}`.trim(),
    );
  }
  return capture;
}

export function runCliJson(
  args: string[],
  cwd?: string,
  options?: {
    disableAutoRuntime?: boolean;
    envOverrides?: CommandEnvOverrides;
  },
): unknown {
  const capture = runCommand(cliBinary, args, { cwd, ...options });
  return JSON.parse(capture.stdout);
}

export function ensureStudioProofBinary() {
  if (
    spawnSync(
      process.platform === "win32" ? "where" : "test",
      process.platform === "win32" ? [studioProofBinary] : ["-x", studioProofBinary],
      { encoding: "utf8" },
    ).status === 0
  ) {
    return;
  }
  runCommand("cargo", [
    "build",
    "-p",
    "autopilot",
    "--bin",
    "studio_artifact_proof",
    "--quiet",
  ]);
}

export function runStudioProofJson(
  args: string[],
  options?: {
    cwd?: string;
    allowFailure?: boolean;
    disableAutoRuntime?: boolean;
    envOverrides?: CommandEnvOverrides;
  },
): unknown {
  ensureStudioProofBinary();
  const capture = runCommand(studioProofBinary, [...args, "--json"], options);
  return JSON.parse(capture.stdout);
}

export function configuredLiveRuntimeEndpoint(): string | null {
  return (
    artifactCommandEnv().AUTOPILOT_LOCAL_RUNTIME_URL ??
    artifactCommandEnv().LOCAL_LLM_URL ??
    null
  );
}

export function autoConfiguredRuntime(): StudioRuntimeEnv | null {
  return cachedAutoConfiguredRuntime;
}
