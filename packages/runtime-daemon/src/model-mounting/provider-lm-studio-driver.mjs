import path from "node:path";

import { lmStudioLoadOptionArgs, normalizeLoadOptions } from "./load-policy.mjs";
import {
  lmStudioArtifact,
  parseLmStudioList,
  parseLmStudioProcessList,
  runPublicCommand,
} from "./local-system-probes.mjs";
import { providerCommandError } from "./provider-transport.mjs";
import { truncate } from "./provider-protocol.mjs";
import { isExecutable, runtimeError, stableHash } from "./io.mjs";
import { OpenAICompatibleModelProviderDriver } from "./provider-openai-compatible-driver.mjs";

export class LmStudioModelProviderDriver {
  constructor({ state }) {
    this.state = state;
    this.openAi = new OpenAICompatibleModelProviderDriver({ label: "lm_studio" });
  }

  async health(provider) {
    const lmsPath = this.lmsPath(provider);
    if (!lmsPath) {
      return { status: "absent", evidenceRefs: ["lm_studio_public_cli_absent"] };
    }
    const result = runPublicCommand(lmsPath, ["server", "status"]);
    const statusText = `${result?.stdout ?? ""}\n${result?.stderr ?? ""}`;
    return {
      status: statusText.match(/\b(ON|RUNNING|STARTED)\b/i) ? "running" : "stopped",
      evidenceRefs: ["lm_studio_public_lms_server_status"],
      publicCli: {
        path: lmsPath,
        serverStatus: truncate(statusText),
        exitCode: result?.status ?? null,
      },
    };
  }

  async listModels({ provider }) {
    const lmsPath = this.lmsPath(provider);
    if (!lmsPath) return [];
    const result = runPublicCommand(lmsPath, ["ls"]);
    if (!result || result.status !== 0) return [];
    return parseLmStudioList(result.stdout).map((model) => lmStudioArtifact(provider, model, this.state.nowIso()));
  }

  async listLoaded({ provider }) {
    const lmsPath = this.lmsPath(provider);
    if (!lmsPath) return [];
    const result = runPublicCommand(lmsPath, ["ps"]);
    if (!result || result.status !== 0) return [];
    return parseLmStudioProcessList(result.stdout).map((model) => ({
      providerId: provider.id,
      modelId: model.modelId,
      backend: "lm_studio",
      status: "loaded",
      capabilities: String(model.modelId).match(/embed/i) ? ["embeddings"] : ["chat", "responses"],
      privacyClass: "local_private",
      evidenceRefs: ["lm_studio_public_lms_ps"],
    }));
  }

  async start({ provider }) {
    const lmsPath = this.requireLmsPath(provider);
    const result = runPublicCommand(lmsPath, ["server", "start"], { timeout: 10000 });
    if (result.status !== 0) throw providerCommandError(provider, "LM Studio server start failed.", result);
    return { status: "running", evidenceRefs: ["lm_studio_public_lms_server_start"] };
  }

  async stop({ provider }) {
    const lmsPath = this.requireLmsPath(provider);
    const result = runPublicCommand(lmsPath, ["server", "stop"], { timeout: 10000 });
    if (result.status !== 0) throw providerCommandError(provider, "LM Studio server stop failed.", result);
    return { status: "stopped", evidenceRefs: ["lm_studio_public_lms_server_stop"] };
  }

  async load({ provider, endpoint, body = {} }) {
    const lmsPath = this.requireLmsPath(provider);
    const loadOptions = normalizeLoadOptions(body.load_options ?? body.loadOptions ?? body, endpoint.loadPolicy);
    const args = ["load", endpoint.modelId, ...lmStudioLoadOptionArgs(loadOptions)];
    const result = runPublicCommand(lmsPath, args, { timeout: 20000 });
    if (result.status !== 0) {
      const alreadyLoaded = await this.listLoaded({ provider });
      if (alreadyLoaded.some((model) => model.modelId === endpoint.modelId)) {
        return {
          status: "loaded",
          backend: "lm_studio",
          backendId: endpoint.backendId ?? "backend.lmstudio",
          evidenceRefs: ["lm_studio_public_lms_load_already_loaded", "lm_studio_public_lms_ps"],
          commandExitCode: result.status,
          commandArgsHash: stableHash(args.join("\0")),
        };
      }
      throw providerCommandError(provider, "LM Studio model load failed.", result);
    }
    return {
      status: "loaded",
      backend: "lm_studio",
      backendId: endpoint.backendId ?? "backend.lmstudio",
      evidenceRefs: ["lm_studio_public_lms_load"],
      commandExitCode: result.status,
      commandArgsHash: stableHash(args.join("\0")),
    };
  }

  async unload({ provider, instance, endpoint }) {
    const lmsPath = this.requireLmsPath(provider);
    const result = runPublicCommand(lmsPath, ["unload", instance?.modelId ?? endpoint?.modelId], { timeout: 10000 });
    if (result.status !== 0) throw providerCommandError(provider, "LM Studio model unload failed.", result);
    return {
      status: "unloaded",
      backend: "lm_studio",
      backendId: endpoint?.backendId ?? "backend.lmstudio",
      evidenceRefs: ["lm_studio_public_lms_unload"],
      commandExitCode: result.status,
    };
  }

  async invoke(args) {
    const result = await this.openAi.invoke({ ...args, providerLabel: "lm_studio" });
    return { ...result, backend: "lm_studio", backendId: args.endpoint?.backendId ?? "backend.lmstudio" };
  }

  supportsStream(kind) {
    return this.openAi.supportsStream(kind);
  }

  async streamInvoke(args) {
    const result = await this.openAi.streamInvoke({ ...args, providerLabel: "lm_studio" });
    if (!result) return null;
    return {
      ...result,
      backend: "lm_studio",
      backendId: args.endpoint?.backendId ?? "backend.lmstudio",
      backendEvidenceRefs: [
        "lm_studio_provider_native_stream",
        ...(result.backendEvidenceRefs ?? []),
      ],
    };
  }

  lmsPath(provider) {
    return (
      provider.discovery?.publicCli?.path ??
      process.env.IOI_LMS_PATH ??
      [
        path.join(this.state.homeDir, ".lmstudio/bin/lms"),
        path.join(this.state.homeDir, ".local/bin/lms"),
      ].find((candidate) => isExecutable(candidate)) ??
      null
    );
  }

  requireLmsPath(provider) {
    const lmsPath = this.lmsPath(provider);
    if (!lmsPath) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "LM Studio public lms CLI is not available.",
        details: { providerId: provider.id, evidenceRefs: ["lm_studio_public_cli_absent"] },
      });
    }
    return lmsPath;
  }
}
