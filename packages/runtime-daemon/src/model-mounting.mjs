import crypto from "node:crypto";
import childProcess from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

const MODEL_MOUNT_SCHEMA_VERSION = "ioi.model-mounting.runtime.v1";
const SECRET_REDACTION = "[REDACTED]";

class AgentgresModelMountingStore {
  constructor({ stateDir, appendOperation }) {
    this.stateDir = path.resolve(stateDir);
    this.appendOperation = appendOperation;
  }

  ensureDirs() {
    for (const dir of [
      "model-artifacts",
      "model-endpoints",
      "model-instances",
      "model-routes",
      "model-providers",
      "model-backends",
      "model-downloads",
      "provider-health",
      "models",
      "backend-logs",
      "projections",
      "lifecycle-events",
      "tokens",
      "mcp-servers",
      "workflow-bindings",
      "receipts",
    ]) {
      fs.mkdirSync(path.join(this.stateDir, dir), { recursive: true });
    }
  }

  writeMap(dir, map) {
    for (const record of map.values()) {
      writeJson(path.join(this.stateDir, dir, `${safeFileName(record.id)}.json`), record);
    }
  }

  writeReceipt(receipt) {
    writeJson(path.join(this.stateDir, "receipts", `${receipt.id}.json`), receipt);
    this.appendOperation?.(receipt.kind, {
      objectId: receipt.id,
      receiptId: receipt.id,
      kind: receipt.kind,
      evidenceRefs: receipt.evidenceRefs,
      details: receipt.details,
    });
  }

  listReceipts() {
    const receiptFiles = listJson(path.join(this.stateDir, "receipts"));
    return receiptFiles
      .map((filePath) => readJson(filePath))
      .sort((left, right) => String(left.createdAt ?? "").localeCompare(String(right.createdAt ?? "")));
  }

  getReceipt(receiptId) {
    const receipt = this.listReceipts().find((item) => item.id === receiptId);
    if (!receipt) throw notFound(`Receipt not found: ${receiptId}`, { receiptId });
    return receipt;
  }

  writeProjection(name, projection) {
    writeJson(path.join(this.stateDir, "projections", `${safeFileName(name)}.json`), projection);
  }

  readProjection(name) {
    const filePath = path.join(this.stateDir, "projections", `${safeFileName(name)}.json`);
    if (!fs.existsSync(filePath)) {
      throw notFound(`Projection not found: ${name}`, { projection: name });
    }
    return readJson(filePath);
  }

  adapterStatus() {
    return {
      port: "AgentgresModelMountingStorePort",
      implementation: "local_operation_log",
      remoteAdapter: process.env.IOI_AGENTGRES_URL
        ? { configured: true, urlHash: stableHash(process.env.IOI_AGENTGRES_URL) }
        : { configured: false, failClosed: true },
      evidenceRefs: ["agentgres_canonical_operation_log", "typed_agentgres_projection_boundary"],
    };
  }
}

class AgentgresWalletAuthority {
  constructor({ now, appendOperation }) {
    this.now = now;
    this.appendOperation = appendOperation;
  }

  createGrant(token) {
    const grant = {
      ...token,
      authority: "agentgres_wallet_authority",
      walletNetworkShape: {
        grantId: token.grantId,
        revocationEpoch: token.revocationEpoch,
        vaultRefs: token.vaultRefs ?? {},
        auditReceiptIds: [],
      },
    };
    this.auditEvent("grant.create", {
      objectId: grant.id,
      grantId: grant.grantId,
      allowed: grant.allowed,
      denied: grant.denied,
      expiresAt: grant.expiresAt,
    });
    return grant;
  }

  authorizeScope(token, requiredScope) {
    if (token.revokedAt) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Capability token has been revoked.",
        details: { requiredScope, grantId: token.grantId, revocationEpoch: token.revocationEpoch },
      });
    }
    if (Date.parse(token.expiresAt) <= this.now().getTime()) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Capability token has expired.",
        details: { requiredScope, grantId: token.grantId },
      });
    }
    if (matchesAny(requiredScope, token.denied) || !matchesAny(requiredScope, token.allowed)) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Capability token does not grant the required scope.",
        details: { requiredScope, grantId: token.grantId },
      });
    }
    this.auditEvent("scope.authorize", {
      objectId: token.id,
      grantId: token.grantId,
      requiredScope,
      revocationEpoch: token.revocationEpoch,
    });
    return this.recordLastUsed(token, requiredScope);
  }

  recordLastUsed(token, requiredScope) {
    return {
      ...token,
      lastUsedAt: new Date(this.now().getTime()).toISOString(),
      lastUsedScope: requiredScope,
    };
  }

  revokeGrant(token) {
    const revoked = {
      ...token,
      revokedAt: new Date(this.now().getTime()).toISOString(),
      revocationEpoch: Number(token.revocationEpoch ?? 0) + 1,
    };
    this.auditEvent("grant.revoke", {
      objectId: revoked.id,
      grantId: revoked.grantId,
      revocationEpoch: revoked.revocationEpoch,
    });
    return revoked;
  }

  resolveVaultRef(vaultRef) {
    if (typeof vaultRef !== "string" || !vaultRef.startsWith("vault://")) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Secrets must be referenced through wallet.network vault refs.",
        details: { vaultRef: SECRET_REDACTION },
      });
    }
    this.auditEvent("vault.resolve", {
      objectId: vaultRef,
      vaultRefHash: stableHash(vaultRef),
      resolvedMaterial: false,
    });
    return { vaultRefHash: stableHash(vaultRef), resolvedMaterial: false };
  }

  auditEvent(kind, payload) {
    const objectId = String(payload.objectId ?? payload.grantId ?? kind);
    const safeObjectId = objectId.startsWith("vault://")
      ? `vault_ref_${stableHash(objectId).slice(0, 16)}`
      : objectId;
    const safePayload = redact({ ...payload, objectId: safeObjectId });
    this.appendOperation?.(`wallet.${kind}`, {
      ...safePayload,
      details: safePayload,
    });
  }

  adapterStatus() {
    return {
      port: "WalletAuthorityPort",
      implementation: "agentgres_wallet_authority",
      methods: ["createGrant", "authorizeScope", "revokeGrant", "resolveVaultRef", "auditEvent", "recordLastUsed"],
      remoteAdapter: process.env.IOI_WALLET_NETWORK_URL
        ? { configured: true, urlHash: stableHash(process.env.IOI_WALLET_NETWORK_URL) }
        : { configured: false, failClosed: true },
      evidenceRefs: ["wallet.network.capability_grant", "wallet.network.vault_ref_boundary"],
    };
  }
}

class AgentgresVaultPort {
  constructor({ now, appendOperation, secrets = {} }) {
    this.now = now;
    this.appendOperation = appendOperation;
    this.secrets = new Map(Object.entries(secrets ?? {}).map(([vaultRef, material]) => [vaultRef, String(material)]));
  }

  resolveVaultRef(vaultRef, purpose = "provider.auth") {
    if (typeof vaultRef !== "string" || !vaultRef.startsWith("vault://")) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Vault material must be referenced through wallet.network vault refs.",
        details: { vaultRef: SECRET_REDACTION, purpose },
      });
    }
    const material = this.materialFor(vaultRef);
    const result = {
      vaultRefHash: stableHash(vaultRef),
      resolvedMaterial: typeof material === "string" && material.length > 0,
      purpose,
      evidenceRefs: ["VaultPort.resolveVaultRef", `vault_ref_${stableHash(vaultRef).slice(0, 16)}`],
    };
    this.auditEvent("vault.resolve", {
      objectId: vaultRef,
      purpose,
      vaultRefHash: result.vaultRefHash,
      resolvedMaterial: result.resolvedMaterial,
    });
    return { ...result, material: result.resolvedMaterial ? material : null };
  }

  materialFor(vaultRef) {
    if (this.secrets.has(vaultRef)) return this.secrets.get(vaultRef);
    const envName = vaultRefEnvironmentAlias(vaultRef);
    if (envName && process.env[envName]) return process.env[envName];
    return null;
  }

  auditEvent(kind, payload) {
    const objectId = String(payload.objectId ?? kind);
    const safeObjectId = objectId.startsWith("vault://")
      ? `vault_ref_${stableHash(objectId).slice(0, 16)}`
      : objectId;
    const safePayload = redact({ ...payload, objectId: safeObjectId });
    this.appendOperation?.(`vault.${kind}`, {
      ...safePayload,
      details: safePayload,
    });
  }

  adapterStatus() {
    return {
      port: "VaultPort",
      implementation: "agentgres_local_vault_port",
      methods: ["resolveVaultRef"],
      remoteAdapter: process.env.IOI_WALLET_NETWORK_URL
        ? { configured: true, urlHash: stableHash(process.env.IOI_WALLET_NETWORK_URL) }
        : { configured: false, failClosed: true },
      materialSources: {
        inMemoryFixtureCount: this.secrets.size,
        environmentAliases: ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "IOI_CUSTOM_MODEL_API_KEY"],
      },
      evidenceRefs: ["wallet.network.vault_ref_boundary", "provider_request_time_secret_resolution"],
    };
  }
}

class NativeLocalModelProviderDriver {
  async health(provider) {
    return {
      status: provider.status === "blocked" ? "blocked" : "available",
      evidenceRefs: ["autopilot_native_local_backend_registry", "deterministic_native_local_fixture"],
    };
  }

  async listModels({ state, provider }) {
    return state.listArtifacts().filter((artifact) => artifact.providerId === provider.id);
  }

  async listLoaded({ state, provider }) {
    return state
      .listInstances()
      .filter((instance) => instance.providerId === provider.id && instance.status === "loaded")
      .map((instance) => ({
        ...instance,
        backendEvidenceRefs: ["autopilot_native_local_process_supervisor", "deterministic_native_local_fixture"],
      }));
  }

  async load({ state, endpoint }) {
    const artifact = state.getModel(endpoint.modelId);
    const estimate = estimateNativeLocalResources(artifact);
    const backendId = endpoint.backendId ?? "backend.autopilot.native-local.fixture";
    state.writeBackendLog(endpoint.id, {
      backendId,
      event: "load",
      modelId: endpoint.modelId,
      estimate,
      backend: "autopilot.native_local.fixture",
    });
    return {
      backend: "autopilot.native_local.fixture",
      backendId,
      driver: "native_local",
      status: "loaded",
      estimate,
      evidenceRefs: [
        "autopilot_native_local_backend_registry",
        "autopilot_native_local_process_supervisor",
        "deterministic_native_local_fixture",
      ],
    };
  }

  async unload({ state, endpoint }) {
    const backendId = endpoint.backendId ?? "backend.autopilot.native-local.fixture";
    state.writeBackendLog(endpoint.id, {
      backendId,
      event: "unload",
      modelId: endpoint.modelId,
      backend: "autopilot.native_local.fixture",
    });
    return {
      driver: "native_local",
      status: "unloaded",
      backend: "autopilot.native_local.fixture",
      backendId,
      evidenceRefs: ["autopilot_native_local_process_supervisor", "deterministic_native_local_fixture"],
    };
  }

  async invoke({ kind, input, endpoint, state }) {
    const backendId = endpoint.backendId ?? "backend.autopilot.native-local.fixture";
    const digest = stableHash(input).slice(0, 12);
    const outputText =
      kind === "embeddings"
        ? `native-local-embedding:${endpoint.modelId}:${digest}`
        : `Autopilot native local model response from ${endpoint.modelId}. input_hash=${digest}`;
    state.writeBackendLog(endpoint.id, {
      backendId,
      event: "invoke",
      modelId: endpoint.modelId,
      kind,
      inputHash: stableHash(input),
      outputHash: stableHash(outputText),
      backend: "autopilot.native_local.fixture",
    });
    return {
      outputText,
      tokenCount: estimateTokens(input, outputText),
      providerResponse: null,
      providerResponseKind: "native_local",
      backend: "autopilot.native_local.fixture",
      backendId,
      backendEvidenceRefs: ["autopilot_native_local_openai_compatible_serving", "deterministic_native_local_fixture"],
    };
  }
}

class FixtureModelProviderDriver {
  async health(provider) {
    return {
      status: provider.status === "blocked" ? "blocked" : "available",
      evidenceRefs: ["agentgres_model_registry_fixture"],
    };
  }

  async listModels({ state, provider }) {
    return state.listArtifacts().filter((artifact) => artifact.providerId === provider.id);
  }

  async listLoaded({ state, provider }) {
    return state
      .listInstances()
      .filter((instance) => instance.providerId === provider.id && instance.status === "loaded");
  }

  async load({ endpoint }) {
    return { backend: endpoint.apiFormat, backendId: endpoint.backendId ?? "backend.fixture", driver: "fixture", status: "loaded" };
  }

  async unload() {
    return { driver: "fixture", status: "unloaded" };
  }

  async invoke({ kind, input, endpoint }) {
    const outputText = deterministicOutput({ kind, input, modelId: endpoint.modelId });
    return {
      outputText,
      tokenCount: estimateTokens(input, outputText),
      providerResponse: null,
      backend: endpoint.apiFormat,
      backendId: endpoint.backendId ?? "backend.fixture",
    };
  }
}

class LmStudioModelProviderDriver {
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

  async load({ provider, endpoint }) {
    const lmsPath = this.requireLmsPath(provider);
    const result = runPublicCommand(lmsPath, ["load", endpoint.modelId], { timeout: 20000 });
    if (result.status !== 0) {
      const alreadyLoaded = await this.listLoaded({ provider });
      if (alreadyLoaded.some((model) => model.modelId === endpoint.modelId)) {
        return {
          status: "loaded",
          backend: "lm_studio",
          backendId: endpoint.backendId ?? "backend.lmstudio",
          evidenceRefs: ["lm_studio_public_lms_load_already_loaded", "lm_studio_public_lms_ps"],
          commandExitCode: result.status,
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
    const result = await this.openAi.invoke({ ...args, providerLabel: "lm_studio", allowResponsesFallback: true });
    return { ...result, backend: "lm_studio", backendId: args.endpoint?.backendId ?? "backend.lmstudio" };
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

class OpenAICompatibleModelProviderDriver {
  constructor({ label = "openai_compatible" } = {}) {
    this.label = label;
  }

  async health(provider, { state } = {}) {
    const result = await fetchProviderJson(provider, "/models", { method: "GET", tolerateHttpError: true, state });
    return {
      status: result.ok ? "available" : "degraded",
      evidenceRefs: [`${this.label}_models_probe`],
      httpStatus: result.status,
      authEvidence: result.authEvidence ?? null,
    };
  }

  async listModels({ state, provider }) {
    const result = await fetchProviderJson(provider, "/models", { method: "GET", tolerateHttpError: true, state });
    if (!result.ok) return [];
    const models = Array.isArray(result.body?.data) ? result.body.data : Array.isArray(result.body) ? result.body : [];
    return models
      .map((model) => String(model.id ?? model.model ?? ""))
      .filter(Boolean)
      .map((modelId) => ({
        id: `${safeId(provider.id)}.${safeId(modelId)}`,
        providerId: provider.id,
        modelId,
        displayName: modelId,
        family: this.label,
        quantization: null,
        sizeBytes: null,
        contextWindow: null,
        capabilities: provider.capabilities ?? ["chat", "responses", "embeddings"],
        privacyClass: provider.privacyClass,
        source: `${this.label}_models_endpoint`,
        state: "available",
        discoveredAt: new Date().toISOString(),
      }));
  }

  async listLoaded() {
    return [];
  }

  async load({ endpoint }) {
    return { status: "loaded", backend: endpoint.apiFormat, evidenceRefs: [`${this.label}_stateless_load`] };
  }

  async unload({ endpoint }) {
    return { status: "unloaded", backend: endpoint.apiFormat, evidenceRefs: [`${this.label}_stateless_unload`] };
  }

  async invoke({ state, provider, endpoint, kind, body, input, allowResponsesFallback = true }) {
    if (kind === "embeddings") {
      const requestBody = { ...body, model: body.model ?? endpoint.modelId };
      const result = await fetchProviderJson(provider, "/embeddings", { method: "POST", body: requestBody, state });
      const outputText = `embedding:${endpoint.modelId}:${stableHash(result.body?.data ?? input).slice(0, 12)}`;
      return {
        outputText,
        tokenCount: normalizeUsage(result.body?.usage, estimateTokens(input, outputText)),
        providerResponse: result.body,
        providerResponseKind: "embeddings",
        backend: endpoint.apiFormat,
        backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
        authVaultRefHash: result.authEvidence?.vaultRefHash ?? null,
        providerAuthEvidenceRefs: result.authEvidence?.evidenceRefs ?? [],
      };
    }

    if (kind === "responses") {
      const responseBody = { ...body, model: body.model ?? endpoint.modelId };
      const result = await fetchProviderJson(provider, "/responses", {
        method: "POST",
        body: responseBody,
        tolerateHttpError: allowResponsesFallback,
        state,
      });
      if (result.ok) {
        const outputText = outputTextFromResponse(result.body);
        return {
          outputText,
          tokenCount: normalizeUsage(result.body?.usage, estimateTokens(input, outputText)),
          providerResponse: result.body,
          providerResponseKind: "responses",
          backend: endpoint.apiFormat,
          backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
          authVaultRefHash: result.authEvidence?.vaultRefHash ?? null,
          providerAuthEvidenceRefs: result.authEvidence?.evidenceRefs ?? [],
        };
      }
      if (!allowResponsesFallback || ![404, 405, 501].includes(result.status)) {
        throw providerHttpError(provider, "OpenAI-compatible responses call failed.", result);
      }
      const fallback = await this.invoke({
        provider,
        endpoint,
        kind: "chat.completions",
        body: responseBody,
        input,
        state,
      });
      return {
        ...fallback,
        compatTranslation: "chat_completions",
      };
    }

    const requestBody = chatCompletionRequestBody(body, endpoint.modelId);
    const result = await fetchProviderJson(provider, "/chat/completions", {
      method: "POST",
      body: requestBody,
      state,
    });
    const outputText = outputTextFromChat(result.body);
    return {
      outputText,
      tokenCount: normalizeUsage(result.body?.usage, estimateTokens(input, outputText)),
      providerResponse: result.body,
      providerResponseKind: "chat.completions",
      backend: endpoint.apiFormat,
      backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
      authVaultRefHash: result.authEvidence?.vaultRefHash ?? null,
      providerAuthEvidenceRefs: result.authEvidence?.evidenceRefs ?? [],
    };
  }
}

class OllamaModelProviderDriver {
  async health(provider) {
    const result = await fetchProviderJson(provider, "/api/tags", { method: "GET", tolerateHttpError: true });
    return {
      status: result.ok ? "available" : "degraded",
      evidenceRefs: ["ollama_api_tags_probe"],
      httpStatus: result.status,
    };
  }

  async listModels({ provider }) {
    const result = await fetchProviderJson(provider, "/api/tags", { method: "GET", tolerateHttpError: true });
    if (!result.ok) return [];
    const models = Array.isArray(result.body?.models) ? result.body.models : [];
    return models
      .map((model) => String(model.name ?? model.model ?? ""))
      .filter(Boolean)
      .map((modelId) => ({
        id: `ollama.${safeId(modelId)}`,
        providerId: provider.id,
        modelId,
        displayName: modelId,
        family: "ollama",
        quantization: null,
        sizeBytes: null,
        contextWindow: null,
        capabilities: ["chat", "embeddings"],
        privacyClass: "local_private",
        source: "ollama_api_tags",
        state: "available",
        discoveredAt: new Date().toISOString(),
      }));
  }

  async listLoaded() {
    return [];
  }

  async load({ endpoint }) {
    return { status: "loaded", backend: "ollama", backendId: endpoint.backendId ?? "backend.ollama", evidenceRefs: ["ollama_lazy_model_load"] };
  }

  async unload() {
    return { status: "unloaded", backend: "ollama", backendId: "backend.ollama", evidenceRefs: ["ollama_stateless_unload"] };
  }

  async invoke({ provider, endpoint, kind, body, input }) {
    if (kind === "embeddings") {
      const result = await fetchProviderJson(provider, "/api/embeddings", {
        method: "POST",
        body: { model: endpoint.modelId, prompt: Array.isArray(body.input) ? body.input.join("\n") : String(body.input ?? "") },
      });
      const outputText = `embedding:${endpoint.modelId}:${stableHash(result.body?.embedding ?? input).slice(0, 12)}`;
      return {
        outputText,
        tokenCount: estimateTokens(input, outputText),
        providerResponse: {
          object: "list",
          data: [{ object: "embedding", index: 0, embedding: result.body?.embedding ?? [] }],
        },
        providerResponseKind: "embeddings",
        backend: "ollama",
        backendId: endpoint.backendId ?? "backend.ollama",
      };
    }
    const result = await fetchProviderJson(provider, "/api/chat", {
      method: "POST",
      body: chatCompletionRequestBody({ ...body, stream: false }, endpoint.modelId),
    });
    const outputText = String(result.body?.message?.content ?? result.body?.response ?? "");
    return {
      outputText,
      tokenCount: estimateTokens(input, outputText),
      providerResponse: result.body,
      providerResponseKind: "ollama.chat",
      backend: "ollama",
      backendId: endpoint.backendId ?? "backend.ollama",
    };
  }
}

export class ModelMountingState {
  constructor({ stateDir, cwd, appendOperation, homeDir, now = () => new Date(), vaultSecrets = {} }) {
    this.stateDir = path.resolve(stateDir);
    this.cwd = path.resolve(cwd ?? process.cwd());
    this.homeDir = path.resolve(homeDir ?? process.env.HOME ?? this.cwd);
    this.modelRoot = path.join(this.stateDir, "models");
    this.appendOperation = appendOperation;
    this.now = now;
    this.store = new AgentgresModelMountingStore({
      stateDir: this.stateDir,
      appendOperation: (kind, payload) => this.appendOperation?.(kind, payload),
    });
    this.walletAuthority = new AgentgresWalletAuthority({
      now: this.now,
      appendOperation: (kind, payload) => this.appendOperation?.(kind, payload),
    });
    this.vault = new AgentgresVaultPort({
      now: this.now,
      appendOperation: (kind, payload) => this.appendOperation?.(kind, payload),
      secrets: vaultSecrets,
    });
    this.providers = new Map();
    this.backends = new Map();
    this.artifacts = new Map();
    this.endpoints = new Map();
    this.instances = new Map();
    this.routes = new Map();
    this.downloads = new Map();
    this.tokens = new Map();
    this.mcpServers = new Map();
    this.ensureDirs();
    this.load();
    this.seedDefaults();
    this.writeAll();
  }

  ensureDirs() {
    this.store.ensureDirs();
  }

  writeSchemaRelationSchemas() {
    return {
      modelArtifacts: [
        "id",
        "providerId",
        "modelId",
        "capabilities",
        "privacyClass",
        "contextWindow",
      ],
      modelEndpoints: [
        "id",
        "providerId",
        "apiFormat",
        "baseUrl",
        "capabilities",
        "loadPolicy",
      ],
      modelInstances: ["id", "endpointId", "modelId", "status", "loadedAt", "expiresAt"],
      modelRoutes: ["id", "role", "fallback", "privacy", "maxCostUsd"],
      modelProviders: ["id", "kind", "status", "privacyClass", "baseUrl"],
      modelBackends: [
        "id",
        "kind",
        "status",
        "binaryPath",
        "baseUrl",
        "capabilities",
        "supportedFormats",
        "processStatus",
        "lastReceiptId",
      ],
      providerHealth: ["id", "providerId", "status", "checkedAt", "evidenceRefs"],
      modelDownloads: ["id", "artifactId", "status", "source", "progress", "bytesTotal", "bytesCompleted", "targetPath"],
      permissionTokens: ["id", "audience", "allowed", "denied", "expiresAt", "revokedAt", "grantId", "lastUsedAt"],
      walletGrants: ["grantId", "revocationEpoch", "allowed", "denied", "expiry", "vaultRefs", "auditReceiptIds"],
      mcpServers: ["id", "transport", "allowedTools", "secretRefs", "status"],
      workflowModelBindings: ["node", "modelId", "routeId", "modelPolicy", "capability", "receiptRequired"],
      modelMountingProjection: ["artifacts", "backends", "endpoints", "instances", "routes", "providers", "receipts", "watermark"],
    };
  }

  load() {
    this.loadMap("model-providers", this.providers);
    this.loadMap("model-backends", this.backends);
    this.loadMap("model-artifacts", this.artifacts);
    this.loadMap("model-endpoints", this.endpoints);
    this.loadMap("model-instances", this.instances);
    this.loadMap("model-routes", this.routes);
    this.loadMap("model-downloads", this.downloads);
    this.loadMap("tokens", this.tokens);
    this.loadMap("mcp-servers", this.mcpServers);
  }

  loadMap(dir, map) {
    for (const filePath of listJson(path.join(this.stateDir, dir))) {
      const record = readJson(filePath);
      if (typeof record.id === "string") {
        map.set(record.id, record);
      }
    }
  }

  seedDefaults() {
    const checkedAt = this.nowIso();
    const localProvider = {
      id: "provider.local.folder",
      kind: "local_folder",
      label: "Local model folder",
      apiFormat: "fixture",
      driver: "fixture",
      baseUrl: "local://models",
      status: "available",
      privacyClass: "local_private",
      capabilities: ["chat", "embeddings", "structured_output", "rerank"],
      discovery: {
        checkedAt,
        evidenceRefs: ["agentgres_model_registry_fixture"],
      },
    };
    this.upsertDefault(this.providers, localProvider);

    const nativeLocalProvider = {
      id: "provider.autopilot.local",
      kind: "ioi_native_local",
      label: "Autopilot native local",
      apiFormat: "ioi_native",
      driver: "native_local",
      baseUrl: "local://ioi-native/model-server",
      status: "available",
      privacyClass: "local_private",
      capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
      discovery: {
        checkedAt,
        evidenceRefs: ["autopilot_native_local_backend_registry", "deterministic_native_local_fixture"],
      },
    };
    this.upsertDefault(this.providers, nativeLocalProvider);

    const lmStudioProvider = this.discoverLmStudioProvider(checkedAt);
    this.upsertDefault(this.providers, lmStudioProvider);

    for (const provider of [
      {
        id: "provider.ollama",
        kind: "ollama",
        label: "Ollama",
        apiFormat: "ollama",
        driver: "ollama",
        baseUrl: process.env.OLLAMA_HOST ?? "http://127.0.0.1:11434",
        status: process.env.OLLAMA_HOST ? "configured" : "blocked",
        privacyClass: "local_private",
        capabilities: ["chat", "embeddings"],
        discovery: { checkedAt, evidenceRefs: ["OLLAMA_HOST"] },
      },
      {
        id: "provider.llama-cpp",
        kind: "llama_cpp",
        label: "llama.cpp",
        apiFormat: "openai_compatible",
        driver: "openai_compatible",
        baseUrl: process.env.IOI_LLAMA_CPP_BASE_URL ?? null,
        status: process.env.IOI_LLAMA_CPP_BASE_URL ? "configured" : "blocked",
        privacyClass: "local_private",
        capabilities: ["chat", "responses", "embeddings"],
        discovery: { checkedAt, evidenceRefs: ["IOI_LLAMA_CPP_BASE_URL", "IOI_LLAMA_CPP_SERVER_PATH"] },
      },
      {
        id: "provider.vllm",
        kind: "vllm",
        label: "vLLM",
        apiFormat: "openai_compatible",
        driver: "openai_compatible",
        baseUrl: process.env.VLLM_BASE_URL ?? "http://127.0.0.1:8000/v1",
        status: process.env.VLLM_BASE_URL ? "configured" : "blocked",
        privacyClass: "workspace",
        capabilities: ["chat", "embeddings"],
        discovery: { checkedAt, evidenceRefs: ["VLLM_BASE_URL"] },
      },
      {
        id: "provider.openai-compatible",
        kind: "openai_compatible",
        label: "OpenAI-compatible endpoint",
        apiFormat: "openai_compatible",
        driver: "openai_compatible",
        baseUrl: process.env.OPENAI_COMPATIBLE_BASE_URL ?? "http://127.0.0.1:1234/v1",
        status: process.env.OPENAI_COMPATIBLE_BASE_URL ? "configured" : "blocked",
        privacyClass: "workspace",
        capabilities: ["chat", "responses", "embeddings"],
        discovery: { checkedAt, evidenceRefs: ["OPENAI_COMPATIBLE_BASE_URL"] },
      },
      hostedProvider("provider.openai", "OpenAI", "openai", process.env.OPENAI_API_KEY),
      hostedProvider("provider.anthropic", "Anthropic", "anthropic", process.env.ANTHROPIC_API_KEY),
      hostedProvider("provider.gemini", "Gemini", "gemini", process.env.GEMINI_API_KEY),
      {
        id: "provider.custom-http",
        kind: "custom_http",
        label: "Custom HTTP endpoint",
        apiFormat: "custom",
        driver: "openai_compatible",
        baseUrl: process.env.IOI_CUSTOM_MODEL_ENDPOINT ?? null,
        status: process.env.IOI_CUSTOM_MODEL_ENDPOINT ? "configured" : "blocked",
        privacyClass: "workspace",
        capabilities: ["chat"],
        discovery: { checkedAt, evidenceRefs: ["IOI_CUSTOM_MODEL_ENDPOINT"] },
      },
      {
        id: "provider.depin-tee",
        kind: "depin_tee",
        label: "DePIN / TEE runtime",
        apiFormat: "runtime_contract",
        driver: "fixture",
        baseUrl: null,
        status: "future",
        privacyClass: "remote_confidential",
        capabilities: ["chat", "code", "receipts"],
        discovery: { checkedAt, evidenceRefs: ["future_runtime_profile"] },
      },
    ]) {
      this.upsertDefault(this.providers, provider);
    }

    this.seedBackends(checkedAt);

    this.upsertDefault(this.artifacts, {
      id: "local.auto",
      providerId: localProvider.id,
      modelId: "local:auto",
      displayName: "IOI local fixture model",
      family: "fixture",
      quantization: "fixture",
      sizeBytes: 0,
      contextWindow: 8192,
      capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
      privacyClass: "local_private",
      source: "deterministic_fixture",
      state: "installed",
      discoveredAt: checkedAt,
    });
    this.upsertDefault(this.artifacts, {
      id: "local.embedding.fixture",
      providerId: localProvider.id,
      modelId: "local:embedding-fixture",
      displayName: "IOI local embedding fixture",
      family: "fixture",
      quantization: "fixture",
      sizeBytes: 0,
      contextWindow: 2048,
      capabilities: ["embeddings"],
      privacyClass: "local_private",
      source: "deterministic_fixture",
      state: "installed",
      discoveredAt: checkedAt,
    });
    const nativeArtifact = this.ensureNativeLocalFixtureArtifact(checkedAt);
    this.upsertDefault(this.artifacts, nativeArtifact);
    const lmStudioArtifacts = this.discoverLmStudioArtifacts(lmStudioProvider, checkedAt);
    if (lmStudioArtifacts.length > 0) {
      for (const artifact of lmStudioArtifacts) {
        this.upsertDefault(this.artifacts, artifact);
      }
    } else if (lmStudioProvider.status !== "absent") {
      this.upsertDefault(this.artifacts, {
        id: "lmstudio.detected",
        providerId: lmStudioProvider.id,
        modelId: "lmstudio:detected",
        displayName: "LM Studio detected model slot",
        family: "lm-studio",
        quantization: "unknown",
        sizeBytes: null,
        contextWindow: null,
        capabilities: ["chat", "responses", "embeddings"],
        privacyClass: "local_private",
        source: "lm_studio_public_discovery",
        state: lmStudioProvider.status === "running" ? "available" : "provider_stopped",
        discoveredAt: checkedAt,
      });
    }

    this.upsertDefault(this.endpoints, {
      id: "endpoint.local.auto",
      providerId: localProvider.id,
      modelId: "local:auto",
      apiFormat: "ioi_fixture",
      driver: "fixture",
      baseUrl: "local://ioi-daemon/model-fixture",
      capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
      privacyClass: "local_private",
      loadPolicy: {
        mode: "on_demand",
        idleTtlSeconds: 900,
        autoEvict: true,
      },
      status: "mounted",
      mountedAt: checkedAt,
    });
    this.upsertDefault(this.endpoints, {
      id: "endpoint.autopilot.native-fixture",
      providerId: nativeLocalProvider.id,
      modelId: nativeArtifact.modelId,
      apiFormat: "ioi_native",
      driver: "native_local",
      baseUrl: "local://ioi-native/model-server",
      capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
      privacyClass: "local_private",
      loadPolicy: {
        mode: "on_demand",
        idleTtlSeconds: 900,
        autoEvict: true,
      },
      status: "mounted",
      mountedAt: checkedAt,
      backendRegistry: this.backendRegistry(),
    });

    this.upsertDefault(this.routes, {
      id: "route.local-first",
      role: "default",
      description: "Local/private first route with hosted fallback blocked unless policy allows it.",
      privacy: "local_or_enterprise",
      quality: "adaptive",
      maxCostUsd: 0.25,
      maxLatencyMs: 30000,
      providerEligibility: ["local_folder", "lm_studio", "ollama", "vllm", "openai_compatible"],
      fallback: ["endpoint.local.auto"],
      deniedProviders: ["openai", "anthropic", "gemini"],
      status: "active",
      lastSelectedModel: null,
      lastReceiptId: null,
    });
    this.upsertDefault(this.routes, {
      id: "route.native-local",
      role: "default",
      description: "Autopilot-native local route that does not require LM Studio.",
      privacy: "local_only",
      quality: "deterministic",
      maxCostUsd: 0,
      maxLatencyMs: 30000,
      providerEligibility: ["ioi_native_local"],
      fallback: ["endpoint.autopilot.native-fixture"],
      deniedProviders: ["openai", "anthropic", "gemini", "lm_studio"],
      status: "active",
      lastSelectedModel: null,
      lastReceiptId: null,
    });
  }

  ensureNativeLocalFixtureArtifact(checkedAt) {
    const fixtureDir = path.join(this.modelRoot, "native-fixture");
    const fixturePath = path.join(fixtureDir, "autopilot-native-fixture.Q4_K_M.gguf");
    fs.mkdirSync(fixtureDir, { recursive: true });
    if (!fs.existsSync(fixturePath)) {
      fs.writeFileSync(
        fixturePath,
        [
          "IOI deterministic native-local model fixture",
          "format=gguf",
          "family=autopilot-native",
          "quantization=Q4_K_M",
          "context=8192",
        ].join("\n"),
      );
    }
    const stats = fs.statSync(fixturePath);
    const metadata = parseLocalModelMetadata(fixturePath);
    return {
      id: "autopilot.native.fixture",
      providerId: "provider.autopilot.local",
      modelId: "autopilot:native-fixture",
      displayName: "Autopilot native local fixture",
      family: metadata.family ?? "autopilot-native",
      format: metadata.format ?? "gguf",
      quantization: metadata.quantization ?? "Q4_K_M",
      sizeBytes: stats.size,
      checksum: fileSha256(fixturePath),
      contextWindow: metadata.contextWindow ?? 8192,
      capabilities: ["chat", "responses", "embeddings", "structured_output", "rerank"],
      privacyClass: "local_private",
      source: "autopilot_native_local_fixture",
      state: "installed",
      artifactPath: fixturePath,
      backendRegistry: this.backendRegistry(),
      discoveredAt: checkedAt,
    };
  }

  upsertDefault(map, record) {
    if (!map.has(record.id)) {
      map.set(record.id, record);
    }
  }

  discoverLmStudioProvider(checkedAt) {
    const candidates = [
      process.env.IOI_LMS_PATH,
      path.join(this.homeDir, ".local/bin/lm-studio"),
      path.join(this.homeDir, ".local/bin/lm-studio.AppImage"),
      path.join(this.homeDir, ".lmstudio/bin/lms"),
    ].filter(Boolean);
    const executables = candidates.filter((candidate) => isExecutable(candidate));
    const lmsPath = candidates.find((candidate) => path.basename(candidate) === "lms" && isExecutable(candidate));
    const serverStatus = lmsPath ? runPublicCommand(lmsPath, ["server", "status"]) : null;
    const serverStatusText = serverStatus?.stdout ?? serverStatus?.stderr ?? "";
    const baseUrl = process.env.LM_STUDIO_BASE_URL ?? process.env.LM_STUDIO_URL ?? "http://127.0.0.1:1234/v1";
    const status = serverStatusText.match(/\b(ON|RUNNING|STARTED)\b/i)
      ? "running"
      : process.env.LM_STUDIO_BASE_URL || process.env.LM_STUDIO_URL
        ? "configured"
        : executables.length > 0
        ? "stopped"
        : "absent";
    return {
      id: "provider.lmstudio",
      kind: "lm_studio",
      label: "LM Studio",
      apiFormat: "openai_compatible",
      driver: "lm_studio",
      baseUrl,
      status,
      privacyClass: "local_private",
      capabilities: ["chat", "responses", "embeddings"],
      discovery: {
        checkedAt,
        evidenceRefs: ["lm_studio_public_cli_or_server_probe"],
        executableCandidates: candidates,
        foundExecutables: executables,
        publicCli: lmsPath
          ? {
              path: lmsPath,
              serverStatus: truncate(serverStatusText),
              exitCode: serverStatus?.status ?? null,
            }
          : null,
      },
    };
  }

  discoverLmStudioArtifacts(provider, checkedAt) {
    const lmsPath = provider.discovery?.publicCli?.path;
    if (!lmsPath) return [];
    const result = runPublicCommand(lmsPath, ["ls"]);
    if (!result || result.status !== 0) return [];
    return parseLmStudioList(result.stdout).map((model) => lmStudioArtifact(provider, model, checkedAt));
  }

  writeAll() {
    this.writeMap("model-providers", this.providers);
    this.writeMap("model-backends", this.backends);
    this.writeMap("model-artifacts", this.artifacts);
    this.writeMap("model-endpoints", this.endpoints);
    this.writeMap("model-instances", this.instances);
    this.writeMap("model-routes", this.routes);
    this.writeMap("model-downloads", this.downloads);
    this.writeMap("tokens", this.tokens);
    this.writeMap("mcp-servers", this.mcpServers);
    this.writeProjection();
  }

  writeMap(dir, map) {
    this.store.writeMap(dir, map);
  }

  serverStatus(baseUrl) {
    this.evictExpiredInstances();
    const runningInstances = [...this.instances.values()].filter((instance) => instance.status === "loaded");
    const degradedProviders = [...this.providers.values()].filter((provider) =>
      ["blocked", "absent", "stopped"].includes(provider.status),
    );
    const backends = this.listBackends();
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      status: runningInstances.length > 0 ? "running" : "stopped",
      nativeBaseUrl: baseUrl ? `${baseUrl}/api/v1` : "/api/v1",
      openAiCompatibleBaseUrl: baseUrl ? `${baseUrl}/v1` : "/v1",
      loadedInstances: runningInstances.length,
      mountedEndpoints: this.endpoints.size,
      providerStates: {
        available: [...this.providers.values()].filter((provider) =>
          ["available", "configured", "running"].includes(provider.status),
        ).length,
        degraded: degradedProviders.length,
      },
      backendStates: {
        available: backends.filter((backend) => ["available", "configured", "running"].includes(backend.status)).length,
        degraded: backends.filter((backend) => ["blocked", "absent", "stopped", "degraded"].includes(backend.status)).length,
      },
      idleTtlSeconds: 900,
      autoEvict: true,
      checkedAt: this.nowIso(),
    };
  }

  legacyModelList() {
    return this.listArtifacts()
      .sort((left, right) => {
        if (left.modelId === "local:auto") return -1;
        if (right.modelId === "local:auto") return 1;
        return left.modelId.localeCompare(right.modelId);
      })
      .map((artifact) => ({
      id: artifact.modelId,
      provider: artifact.providerId === "provider.local.folder" ? "ioi-daemon-local" : artifact.providerId,
      cost: artifact.privacyClass === "local_private" ? "local" : "metered",
      quality: artifact.family === "fixture" ? "adaptive" : "provider",
      capabilities: artifact.capabilities,
      privacyClass: artifact.privacyClass,
      route: "route.local-first",
    }));
  }

  openAiModelList() {
    return {
      object: "list",
      data: this.listArtifacts().map((artifact) => ({
        id: artifact.modelId,
        object: "model",
        created: Math.floor(Date.parse(artifact.discoveredAt ?? this.nowIso()) / 1000),
        owned_by: artifact.providerId,
        permission: [],
        root: artifact.modelId,
        parent: null,
      })),
    };
  }

  listArtifacts() {
    return [...this.artifacts.values()].sort((left, right) => left.id.localeCompare(right.id));
  }

  listProviders() {
    return [...this.providers.values()].map(publicProvider).sort((left, right) => left.id.localeCompare(right.id));
  }

  listEndpoints() {
    return [...this.endpoints.values()].sort((left, right) => left.id.localeCompare(right.id));
  }

  listInstances() {
    this.evictExpiredInstances();
    return [...this.instances.values()].sort((left, right) => left.loadedAt.localeCompare(right.loadedAt));
  }

  listRoutes() {
    return [...this.routes.values()].sort((left, right) => left.id.localeCompare(right.id));
  }

  listDownloads() {
    return [...this.downloads.values()].sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  snapshot(baseUrl) {
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      server: this.serverStatus(baseUrl),
      artifacts: this.listArtifacts(),
      backends: this.listBackends(),
      endpoints: this.listEndpoints(),
      instances: this.listInstances(),
      providers: this.listProviders(),
      routes: this.listRoutes(),
      downloads: this.listDownloads(),
      tokens: this.listTokens(),
      mcpServers: this.listMcpServers(),
      workflowNodes: this.workflowNodeBindings(),
      receipts: this.listReceipts().slice(-25),
      projection: this.projectionSummary(),
    };
  }

  projectionSummary() {
    const projection = this.projection();
    return {
      schemaVersion: projection.schemaVersion,
      source: projection.source,
      watermark: projection.watermark,
      receiptCount: projection.receipts.length,
      generatedAt: projection.generatedAt,
    };
  }

  projection() {
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      source: "agentgres_model_mounting_projection",
      generatedAt: this.nowIso(),
      watermark: operationCount(this.stateDir),
      artifacts: this.listArtifacts(),
      endpoints: this.listEndpoints(),
      instances: this.listInstances(),
      routes: this.listRoutes(),
      backends: this.listBackends(),
      providers: this.listProviders(),
      downloads: this.listDownloads(),
      grants: this.listTokens(),
      mcpServers: this.listMcpServers(),
      workflowBindings: this.workflowNodeBindings(),
      adapterBoundaries: {
        wallet: this.walletAuthority.adapterStatus(),
        vault: this.vault.adapterStatus(),
        agentgres: this.store.adapterStatus(),
      },
      lifecycleEvents: this.listReceipts().filter((receipt) => receipt.kind === "model_lifecycle"),
      routeReceipts: this.listReceipts().filter((receipt) => receipt.kind === "model_route_selection"),
      invocationReceipts: this.listReceipts().filter((receipt) => receipt.kind === "model_invocation"),
      toolReceipts: this.listReceipts().filter((receipt) => receipt.kind === "mcp_tool_invocation"),
      receipts: this.listReceipts(),
    };
  }

  writeProjection() {
    if (this.writingProjection) return;
    this.writingProjection = true;
    try {
      this.store.writeProjection("model-mounting-canonical", this.projection());
    } finally {
      this.writingProjection = false;
    }
  }

  receiptReplay(receiptId) {
    const receipt = this.getReceipt(receiptId);
    const projection = this.projection();
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      source: "agentgres_model_mounting_projection_replay",
      receipt,
      route: receipt.details?.routeId ? projection.routes.find((route) => route.id === receipt.details.routeId) ?? null : null,
      endpoint: receipt.details?.endpointId
        ? projection.endpoints.find((endpoint) => endpoint.id === receipt.details.endpointId) ?? null
        : null,
      instance: receipt.details?.instanceId
        ? projection.instances.find((instance) => instance.id === receipt.details.instanceId) ?? null
        : null,
      provider: receipt.details?.providerId
        ? projection.providers.find((provider) => provider.id === receipt.details.providerId) ?? null
        : null,
      toolReceipts: normalizeScopes(receipt.details?.toolReceiptIds, []).map((toolReceiptId) => this.getReceipt(toolReceiptId)),
      projectionWatermark: projection.watermark,
    };
  }

  workflowNodeBindings() {
    return [
      "Model Call",
      "Structured Output",
      "Verifier",
      "Planner",
      "Embedding",
      "Reranker",
      "Vision",
      "Local Tool/MCP",
      "Model Router",
      "Receipt Gate",
    ].map((node) => ({
      node,
      modelId: null,
      supportsExplicitModelId: true,
      supportsModelPolicy: true,
      capability: capabilityForWorkflowNode(node),
      receiptRequired: true,
      routeId: "route.local-first",
      daemonApi: node === "Receipt Gate" ? "/api/v1/workflows/receipt-gate" : "/api/v1/workflows/nodes/execute",
    }));
  }

  getModel(id) {
    const artifact = [...this.artifacts.values()].find((item) => item.id === id || item.modelId === id);
    if (!artifact) {
      throw notFound(`Model not found: ${id}`, { modelId: id });
    }
    return artifact;
  }

  importModel(body = {}) {
    const now = this.nowIso();
    const modelId = requiredString(body.model_id ?? body.modelId, "model_id");
    const sourcePath = body.path ?? body.source_path ?? body.sourcePath ?? body.local_path ?? body.localPath ?? null;
    const sourceInfo = sourcePath ? inspectLocalArtifact(sourcePath) : null;
    const metadata = sourceInfo ? parseLocalModelMetadata(sourceInfo.path) : {};
    const artifact = {
      id: body.id ?? `import.${safeId(modelId)}`,
      providerId: body.provider_id ?? body.providerId ?? (sourceInfo ? "provider.autopilot.local" : "provider.local.folder"),
      modelId,
      displayName: body.display_name ?? body.displayName ?? modelId,
      family: body.family ?? metadata.family ?? "imported",
      format: body.format ?? metadata.format ?? null,
      quantization: body.quantization ?? metadata.quantization ?? null,
      sizeBytes: body.size_bytes ?? body.sizeBytes ?? sourceInfo?.sizeBytes ?? null,
      checksum: body.checksum ?? sourceInfo?.checksum ?? null,
      contextWindow: body.context_window ?? body.contextWindow ?? metadata.contextWindow ?? null,
      capabilities: normalizeScopes(body.capabilities, ["chat"]),
      privacyClass: body.privacy_class ?? body.privacyClass ?? "local_private",
      source: body.source ?? (sourceInfo ? "local_path_import" : "operator_import"),
      artifactPath: sourceInfo?.path ?? null,
      metadata,
      backendRegistry: this.backendRegistry(),
      state: "installed",
      discoveredAt: now,
    };
    this.artifacts.set(artifact.id, artifact);
    this.writeMap("model-artifacts", this.artifacts);
    this.lifecycleReceipt("model_import", {
      artifactId: artifact.id,
      modelId: artifact.modelId,
      providerId: artifact.providerId,
      state: artifact.state,
      artifactPathHash: artifact.artifactPath ? stableHash(artifact.artifactPath) : null,
      checksum: artifact.checksum,
    });
    this.writeProjection();
    return artifact;
  }

  mountEndpoint(body = {}) {
    const now = this.nowIso();
    const modelId = body.model_id ?? body.modelId ?? "local:auto";
    const artifact = this.getModel(modelId);
    const providerId = body.provider_id ?? body.providerId ?? artifact.providerId;
    const provider = this.provider(providerId);
    const endpoint = {
      id: body.id ?? `endpoint.${safeId(providerId)}.${safeId(artifact.modelId)}`,
      providerId,
      modelId: artifact.modelId,
      apiFormat: body.api_format ?? body.apiFormat ?? provider.apiFormat,
      driver: body.driver ?? provider.driver ?? driverForProviderKind(provider.kind),
      baseUrl: body.base_url ?? body.baseUrl ?? provider.baseUrl ?? "local://ioi-daemon/model-fixture",
      capabilities: normalizeScopes(body.capabilities, artifact.capabilities),
      privacyClass: body.privacy_class ?? body.privacyClass ?? provider.privacyClass,
      artifactId: artifact.id,
      artifactPath: artifact.artifactPath ?? null,
      backendId: body.backend_id ?? body.backendId ?? defaultBackendForProvider(provider),
      loadPolicy: normalizeLoadPolicy(body.load_policy ?? body.loadPolicy),
      status: "mounted",
      mountedAt: now,
    };
    this.endpoints.set(endpoint.id, endpoint);
    this.writeMap("model-endpoints", this.endpoints);
    this.lifecycleReceipt("model_mount", {
      endpointId: endpoint.id,
      modelId: endpoint.modelId,
      providerId: endpoint.providerId,
      loadPolicy: endpoint.loadPolicy,
    });
    return endpoint;
  }

  unmountEndpoint(body = {}) {
    const endpointId = requiredString(body.endpoint_id ?? body.endpointId ?? body.id, "endpoint_id");
    const endpoint = this.endpoint(endpointId);
    const updated = {
      ...endpoint,
      status: "unmounted",
      unmountedAt: this.nowIso(),
    };
    this.endpoints.set(endpointId, updated);
    this.writeMap("model-endpoints", this.endpoints);
    this.lifecycleReceipt("model_unmount", {
      endpointId,
      modelId: endpoint.modelId,
      providerId: endpoint.providerId,
    });
    return updated;
  }

  async loadModel(body = {}) {
    const endpoint = this.resolveEndpoint(body.endpoint_id ?? body.endpointId, body.model_id ?? body.modelId);
    const provider = this.provider(endpoint.providerId);
    const driverResult = await this.driverForProvider(provider).load({ state: this, provider, endpoint, body });
    const now = this.nowIso();
    const loadPolicy = normalizeLoadPolicy(body.load_policy ?? body.loadPolicy ?? endpoint.loadPolicy);
    const instance = {
      id: body.id ?? `instance.${safeId(endpoint.id)}.${Date.now()}`,
      endpointId: endpoint.id,
      providerId: endpoint.providerId,
      modelId: endpoint.modelId,
      status: "loaded",
      backend: driverResult.backend ?? endpoint.apiFormat,
      backendId: driverResult.backendId ?? endpoint.backendId ?? defaultBackendForProvider(provider),
      driver: driverNameForProvider(provider),
      loadPolicy,
      loadedAt: now,
      lastUsedAt: now,
      expiresAt: expiresAt(now, loadPolicy),
      workflowScope: body.workflow_scope ?? body.workflowScope ?? null,
      agentScope: body.agent_scope ?? body.agentScope ?? null,
      providerEvidenceRefs: driverResult.evidenceRefs ?? [],
    };
    this.instances.set(instance.id, instance);
    this.writeMap("model-instances", this.instances);
    this.lifecycleReceipt("model_load", {
      instanceId: instance.id,
      endpointId: endpoint.id,
      modelId: endpoint.modelId,
      providerId: endpoint.providerId,
      loadPolicy,
      providerEvidenceRefs: driverResult.evidenceRefs ?? [],
    });
    return instance;
  }

  async unloadModel(body = {}) {
    const instanceId = body.instance_id ?? body.instanceId ?? body.id;
    const instance = instanceId
      ? this.instance(instanceId)
      : this.loadedInstanceForEndpoint(this.resolveEndpoint(body.endpoint_id ?? body.endpointId, body.model_id ?? body.modelId).id);
    const endpoint = this.endpoint(instance.endpointId);
    const provider = this.provider(instance.providerId);
    const driverResult = await this.driverForProvider(provider).unload({ state: this, provider, endpoint, instance, body });
    const updated = {
      ...instance,
      status: "unloaded",
      unloadedAt: this.nowIso(),
      providerEvidenceRefs: driverResult.evidenceRefs ?? instance.providerEvidenceRefs ?? [],
    };
    this.instances.set(instance.id, updated);
    this.writeMap("model-instances", this.instances);
    this.lifecycleReceipt("model_unload", {
      instanceId: instance.id,
      endpointId: instance.endpointId,
      modelId: instance.modelId,
      providerId: instance.providerId,
      providerEvidenceRefs: driverResult.evidenceRefs ?? [],
    });
    return updated;
  }

  downloadModel(body = {}) {
    const now = this.nowIso();
    const modelId = requiredString(body.model_id ?? body.modelId, "model_id");
    const providerId = body.provider_id ?? body.providerId ?? "provider.autopilot.local";
    const source = body.source_url ?? body.sourceUrl ?? body.source ?? "deterministic_fixture_download";
    const targetDir = path.join(this.modelRoot, "downloads", safeFileName(modelId));
    const targetPath = path.join(targetDir, body.file_name ?? body.fileName ?? `${safeFileName(modelId)}.gguf`);
    const fixtureContent = String(body.fixture_content ?? body.fixtureContent ?? `deterministic model bytes for ${modelId}\n`);
    const bytesTotal = Number(body.bytes_total ?? body.bytesTotal ?? Buffer.byteLength(fixtureContent));
    const jobBase = {
      id: `download_job_${crypto.randomUUID()}`,
      modelId,
      providerId,
      source,
      targetPath,
      bytesTotal,
      bytesCompleted: 0,
      progress: 0,
      createdAt: now,
      updatedAt: now,
      receiptIds: [],
      receiptId: null,
    };
    const queuedReceipt = this.lifecycleReceipt("model_download_queued", {
      jobId: jobBase.id,
      modelId,
      providerId,
      sourceHash: stableHash(source),
      targetPathHash: stableHash(targetPath),
    });
    if (truthy(body.fail ?? body.simulate_failure ?? body.simulateFailure)) {
      const failed = {
        ...jobBase,
        artifactId: null,
        status: "failed",
        failureReason: body.failure_reason ?? body.failureReason ?? "deterministic_fixture_failure",
        updatedAt: this.nowIso(),
        receiptIds: [queuedReceipt.id],
        receiptId: queuedReceipt.id,
      };
      const failedReceipt = this.lifecycleReceipt("model_download_failed", {
        jobId: failed.id,
        modelId,
        providerId,
        failureReason: failed.failureReason,
      });
      const storedFailed = { ...failed, receiptIds: [...failed.receiptIds, failedReceipt.id], receiptId: failedReceipt.id };
      this.downloads.set(storedFailed.id, storedFailed);
      this.writeMap("model-downloads", this.downloads);
      this.writeProjection();
      return storedFailed;
    }
    if (truthy(body.queued_only ?? body.queuedOnly)) {
      const queued = {
        ...jobBase,
        artifactId: null,
        status: "queued",
        receiptIds: [queuedReceipt.id],
        receiptId: queuedReceipt.id,
      };
      this.downloads.set(queued.id, queued);
      this.writeMap("model-downloads", this.downloads);
      this.writeProjection();
      return queued;
    }
    fs.mkdirSync(targetDir, { recursive: true });
    fs.writeFileSync(targetPath, fixtureContent);
    const runningReceipt = this.lifecycleReceipt("model_download_running", {
      jobId: jobBase.id,
      modelId,
      providerId,
      bytesTotal,
      bytesCompleted: bytesTotal,
    });
    const checksum = fileSha256(targetPath);
    const metadata = parseLocalModelMetadata(targetPath);
    const artifact = this.artifacts.get(`download.${safeId(modelId)}`) ?? {
      id: `download.${safeId(modelId)}`,
      providerId,
      modelId,
      displayName: body.display_name ?? body.displayName ?? modelId,
      family: body.family ?? metadata.family ?? "download",
      format: body.format ?? metadata.format ?? "gguf",
      quantization: body.quantization ?? metadata.quantization ?? null,
      sizeBytes: bytesTotal,
      checksum,
      contextWindow: body.context_window ?? body.contextWindow ?? metadata.contextWindow ?? null,
      capabilities: normalizeScopes(body.capabilities, ["chat"]),
      privacyClass: body.privacy_class ?? body.privacyClass ?? "local_private",
      source,
      artifactPath: targetPath,
      metadata,
      state: "installed",
      discoveredAt: now,
    };
    const job = {
      ...jobBase,
      artifactId: artifact.id,
      status: "completed",
      checksum,
      progress: 1,
      bytesCompleted: bytesTotal,
      updatedAt: this.nowIso(),
      receiptIds: [queuedReceipt.id, runningReceipt.id],
      receiptId: runningReceipt.id,
    };
    this.artifacts.set(artifact.id, artifact);
    this.downloads.set(job.id, job);
    const receipt = this.lifecycleReceipt("model_download_completed", {
      jobId: job.id,
      artifactId: artifact.id,
      modelId,
      providerId: artifact.providerId,
      bytesTotal,
      checksum,
    });
    const completed = { ...job, receiptId: receipt.id, receiptIds: [...job.receiptIds, receipt.id] };
    this.downloads.set(completed.id, completed);
    this.writeMap("model-artifacts", this.artifacts);
    this.writeMap("model-downloads", this.downloads);
    this.writeProjection();
    return completed;
  }

  cancelDownload(jobId) {
    const job = this.downloadStatus(jobId);
    if (["completed", "failed", "canceled"].includes(job.status)) {
      return job;
    }
    const receipt = this.lifecycleReceipt("model_download_canceled", {
      jobId,
      modelId: job.modelId,
      providerId: job.providerId,
      bytesCompleted: job.bytesCompleted,
      bytesTotal: job.bytesTotal,
    });
    const canceled = {
      ...job,
      status: "canceled",
      updatedAt: this.nowIso(),
      receiptId: receipt.id,
      receiptIds: [...(job.receiptIds ?? []), receipt.id],
    };
    if (job.targetPath) {
      try {
        fs.rmSync(job.targetPath, { force: true });
      } catch {
        // Cleanup is best-effort; the cancellation receipt records the state transition.
      }
    }
    this.downloads.set(jobId, canceled);
    this.writeMap("model-downloads", this.downloads);
    this.writeProjection();
    return canceled;
  }

  downloadStatus(jobId) {
    const job = this.downloads.get(jobId);
    if (!job) throw notFound(`Download job not found: ${jobId}`, { jobId });
    return job;
  }

  createToken(body = {}) {
    const now = this.nowIso();
    const tokenValue = `ioi_mnt_${crypto.randomBytes(24).toString("base64url")}`;
    const token = this.walletAuthority.createGrant({
      id: `grant_${crypto.randomUUID()}`,
      audience: body.audience ?? "autopilot-local-server",
      allowed: normalizeScopes(body.allowed, ["model.chat:*", "model.responses:*", "model.embeddings:*", "route.use:*"]),
      denied: normalizeScopes(body.denied, ["connector.gmail.send", "filesystem.write", "shell.exec"]),
      expiresAt: body.expires_at ?? body.expiresAt ?? new Date(this.now().getTime() + 24 * 60 * 60 * 1000).toISOString(),
      revocationEpoch: Number(body.revocation_epoch ?? body.revocationEpoch ?? 0),
      grantId: body.grant_id ?? body.grantId ?? `wallet.grant.${crypto.randomUUID()}`,
      vaultRefs: sanitizeVaultRefs(body.vault_refs ?? body.vaultRefs ?? {}),
      auditReceiptIds: [],
      tokenHash: hashToken(tokenValue),
      createdAt: now,
      lastUsedAt: null,
      lastUsedScope: null,
      revokedAt: null,
      receiptId: null,
    });
    const receipt = this.receipt("permission_token", {
      summary: `Capability token ${token.id} created for ${token.audience}.`,
      redaction: "redacted",
      evidenceRefs: ["wallet.network.capability_grant", token.grantId],
      details: publicToken(token),
    });
    const stored = { ...token, receiptId: receipt.id };
    this.tokens.set(stored.id, stored);
    this.writeMap("tokens", this.tokens);
    return { ...publicToken(stored), token: tokenValue };
  }

  listTokens() {
    return [...this.tokens.values()]
      .map(publicToken)
      .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  }

  revokeToken(tokenId) {
    const token = this.tokens.get(tokenId);
    if (!token) throw notFound(`Token not found: ${tokenId}`, { tokenId });
    const revoked = this.walletAuthority.revokeGrant(token);
    this.tokens.set(tokenId, revoked);
    this.writeMap("tokens", this.tokens);
    this.receipt("permission_token_revocation", {
      summary: `Capability token ${tokenId} revoked.`,
      redaction: "redacted",
      evidenceRefs: ["wallet.network.revocation", token.grantId],
      details: publicToken(revoked),
    });
    return publicToken(revoked);
  }

  authorize(authorization, requiredScope) {
    if (!authorization || !authorization.startsWith("Bearer ")) {
      throw runtimeError({
        status: 401,
        code: "auth",
        message: "Bearer capability token is required for this model mounting operation.",
        details: { requiredScope },
      });
    }
    const tokenHash = hashToken(authorization.slice("Bearer ".length).trim());
    const token = [...this.tokens.values()].find((candidate) => candidate.tokenHash === tokenHash);
    if (!token) {
      throw runtimeError({
        status: 401,
        code: "auth",
        message: "Capability token was not recognized.",
        details: { requiredScope },
      });
    }
    const authorized = this.walletAuthority.authorizeScope(token, requiredScope);
    this.tokens.set(authorized.id, authorized);
    this.writeMap("tokens", this.tokens);
    return authorized;
  }

  upsertProvider(body = {}) {
    const checkedAt = this.nowIso();
    const id = body.id ?? `provider.${safeId(body.kind ?? body.label ?? "custom")}`;
    const existing = this.providers.get(id) ?? {};
    const kind = body.kind ?? existing.kind ?? "custom_http";
    const secretRef = this.normalizeProviderSecretRef(kind, body, existing.secretRef ?? null);
    const requestedStatus = body.status ?? existing.status ?? "configured";
    const provider = {
      id,
      kind,
      label: body.label ?? existing.label ?? id,
      apiFormat: body.api_format ?? body.apiFormat ?? existing.apiFormat ?? "custom",
      driver: body.driver ?? existing.driver ?? driverForProviderKind(kind),
      baseUrl: body.base_url ?? body.baseUrl ?? existing.baseUrl ?? null,
      status: providerRequiresVaultSecret(kind) && !secretRef ? "blocked" : requestedStatus,
      privacyClass: body.privacy_class ?? body.privacyClass ?? existing.privacyClass ?? "workspace",
      capabilities: normalizeScopes(body.capabilities, existing.capabilities ?? ["chat"]),
      discovery: {
        ...existing.discovery,
        checkedAt,
        evidenceRefs: normalizeScopes(body.evidence_refs ?? body.evidenceRefs, existing.discovery?.evidenceRefs ?? ["operator_provider_config"]),
      },
      secretRef,
    };
    this.providers.set(provider.id, provider);
    this.writeMap("model-providers", this.providers);
    return publicProvider(provider);
  }

  normalizeProviderSecretRef(kind, body = {}, existingSecretRef = null) {
    assertNoPlaintextProviderSecret(body);
    const secretRef = providerSecretInput(body);
    const normalized = secretRef === undefined ? existingSecretRef : secretRef || null;
    if (normalized) this.walletAuthority.resolveVaultRef(normalized);
    if (providerRequiresVaultSecret(kind) && !normalized) return null;
    return normalized;
  }

  async providerHealth(providerId) {
    const provider = this.provider(providerId);
    const checkedAt = this.nowIso();
    const driverResult = await this.driverForProvider(provider).health(provider, { state: this });
    const status = driverResult.status ?? (provider.status === "configured" ? "available" : provider.status);
    const updated = {
      ...provider,
      status,
      discovery: {
        ...provider.discovery,
        checkedAt,
        lastHealthCheck: {
          status,
          evidenceRefs: driverResult.evidenceRefs ?? provider.discovery?.evidenceRefs ?? [],
          httpStatus: driverResult.httpStatus ?? null,
          authVaultRefHash: driverResult.authEvidence?.vaultRefHash ?? null,
        },
        ...(driverResult.publicCli ? { publicCli: driverResult.publicCli } : {}),
      },
    };
    this.providers.set(providerId, updated);
    this.writeMap("model-providers", this.providers);
    writeJson(path.join(this.stateDir, "provider-health", `${safeFileName(providerId)}.json`), {
      id: `health.${safeId(providerId)}`,
      providerId,
      status,
      checkedAt,
      evidenceRefs: driverResult.evidenceRefs ?? [],
    });
    return publicProvider(updated);
  }

  async listProviderModels(providerId) {
    const provider = this.provider(providerId);
    const models = await this.driverForProvider(provider).listModels({ state: this, provider });
    for (const artifact of models) {
      this.artifacts.set(artifact.id, artifact);
    }
    if (models.length > 0) this.writeMap("model-artifacts", this.artifacts);
    return models.length > 0
      ? models
      : this.listArtifacts().filter((artifact) => artifact.providerId === providerId);
  }

  async listProviderLoaded(providerId) {
    const provider = this.provider(providerId);
    const loaded = await this.driverForProvider(provider).listLoaded({ state: this, provider });
    return loaded.length > 0
      ? loaded
      : this.listInstances().filter((instance) => instance.providerId === providerId && instance.status === "loaded");
  }

  async startProvider(providerId) {
    const provider = this.provider(providerId);
    const driver = this.driverForProvider(provider);
    const result = typeof driver.start === "function"
      ? await driver.start({ state: this, provider })
      : { status: provider.status === "blocked" ? "blocked" : "available", evidenceRefs: ["provider_stateless_start"] };
    const updated = {
      ...provider,
      status: result.status ?? "available",
      discovery: {
        ...provider.discovery,
        checkedAt: this.nowIso(),
        lastStart: {
          status: result.status ?? "available",
          evidenceRefs: result.evidenceRefs ?? [],
        },
      },
    };
    this.providers.set(providerId, updated);
    this.writeMap("model-providers", this.providers);
    this.lifecycleReceipt("provider_start", {
      providerId,
      modelId: provider.label,
      state: updated.status,
      evidenceRefs: result.evidenceRefs ?? [],
    });
    return publicProvider(updated);
  }

  async stopProvider(providerId) {
    const provider = this.provider(providerId);
    const driver = this.driverForProvider(provider);
    const result = typeof driver.stop === "function"
      ? await driver.stop({ state: this, provider })
      : { status: "stopped", evidenceRefs: ["provider_stateless_stop"] };
    const updated = {
      ...provider,
      status: result.status ?? "stopped",
      discovery: {
        ...provider.discovery,
        checkedAt: this.nowIso(),
        lastStop: {
          status: result.status ?? "stopped",
          evidenceRefs: result.evidenceRefs ?? [],
        },
      },
    };
    this.providers.set(providerId, updated);
    this.writeMap("model-providers", this.providers);
    this.lifecycleReceipt("provider_stop", {
      providerId,
      modelId: provider.label,
      state: updated.status,
      evidenceRefs: result.evidenceRefs ?? [],
    });
    return publicProvider(updated);
  }

  upsertRoute(body = {}) {
    const id = body.id ?? `route.${safeId(body.role ?? "custom")}`;
    const route = {
      id,
      role: body.role ?? "custom",
      description: body.description ?? "Operator-defined model route.",
      privacy: body.privacy ?? "local_or_enterprise",
      quality: body.quality ?? "adaptive",
      maxCostUsd: Number(body.max_cost_usd ?? body.maxCostUsd ?? 0.25),
      maxLatencyMs: Number(body.max_latency_ms ?? body.maxLatencyMs ?? 30000),
      providerEligibility: normalizeScopes(body.provider_eligibility ?? body.providerEligibility, []),
      fallback: normalizeScopes(body.fallback, ["endpoint.local.auto"]),
      deniedProviders: normalizeScopes(body.denied_providers ?? body.deniedProviders, []),
      status: body.status ?? "active",
      lastSelectedModel: body.last_selected_model ?? body.lastSelectedModel ?? null,
      lastReceiptId: body.last_receipt_id ?? body.lastReceiptId ?? null,
    };
    this.routes.set(route.id, route);
    this.writeMap("model-routes", this.routes);
    return route;
  }

  testRoute(routeId, body = {}) {
    const route = this.route(routeId);
    const selection = this.selectRoute({
      modelId: body.model ?? body.model_id ?? body.modelId,
      routeId,
      capability: body.capability ?? "chat",
      policy: body.model_policy ?? body.modelPolicy ?? {},
    });
    const receipt = this.receipt("model_route_selection", {
      summary: `Route ${routeId} selected ${selection.endpoint.modelId}.`,
      redaction: "none",
      evidenceRefs: ["model_router", routeId, selection.endpoint.id],
      details: {
        routeId,
        selectedModel: selection.endpoint.modelId,
        endpointId: selection.endpoint.id,
        providerId: selection.endpoint.providerId,
        policyHash: stableHash(body.model_policy ?? body.modelPolicy ?? {}),
      },
    });
    const updatedRoute = {
      ...route,
      lastSelectedModel: selection.endpoint.modelId,
      lastReceiptId: receipt.id,
    };
    this.routes.set(routeId, updatedRoute);
    this.writeMap("model-routes", this.routes);
    return { route: updatedRoute, selection, receipt };
  }

  async invokeModel({ authorization, requiredScope, kind, body = {} }) {
    const token = this.authorize(authorization, requiredScope);
    const started = this.now().getTime();
    const input = inputText(body);
    const capability =
      kind === "embeddings"
        ? "embeddings"
        : kind === "rerank"
          ? "rerank"
          : kind === "responses"
            ? "responses"
            : "chat";
    const selection = this.selectRoute({
      modelId: body.model,
      routeId: body.route_id ?? body.routeId,
      capability,
      policy: body.model_policy ?? body.modelPolicy ?? {},
    });
    const routeReceipt = this.receipt("model_route_selection", {
      summary: `Route ${selection.route.id} selected ${selection.endpoint.modelId}.`,
      redaction: "none",
      evidenceRefs: ["model_router", selection.route.id, selection.endpoint.id],
      details: {
        routeId: selection.route.id,
        selectedModel: selection.endpoint.modelId,
        endpointId: selection.endpoint.id,
        providerId: selection.endpoint.providerId,
        policyHash: stableHash(body.model_policy ?? body.modelPolicy ?? {}),
      },
    });
    const instance = await this.ensureLoaded(selection.endpoint);
    const ephemeralMcp = this.compileEphemeralMcpIntegrations({ authorization, body, input });
    const providerResult = await this.driverForProvider(selection.provider).invoke({
      state: this,
      provider: selection.provider,
      endpoint: selection.endpoint,
      instance,
      kind,
      body,
      input,
      token,
    });
    const outputText = providerResult.outputText;
    const latencyMs = Math.max(1, this.now().getTime() - started);
    const tokenCount = providerResult.tokenCount ?? estimateTokens(input, outputText);
    const receipt = this.receipt("model_invocation", {
      summary: `${kind} invocation routed through ${selection.route.id} to ${selection.endpoint.modelId}.`,
      redaction: "redacted",
      evidenceRefs: [
        "model_router",
        routeReceipt.id,
        selection.route.id,
        selection.endpoint.id,
        instance.id,
        token.grantId,
        ...ephemeralMcp.evidenceRefs,
        ...(providerResult.providerAuthEvidenceRefs ?? []),
      ],
      details: {
        routeId: selection.route.id,
        routeReceiptId: routeReceipt.id,
        selectedModel: selection.endpoint.modelId,
        endpointId: selection.endpoint.id,
        providerId: selection.endpoint.providerId,
        instanceId: instance.id,
        backend: providerResult.backend ?? selection.endpoint.apiFormat,
        backendId: providerResult.backendId ?? instance.backendId ?? selection.endpoint.backendId ?? null,
        selectedBackend: providerResult.backendId ?? instance.backendId ?? selection.endpoint.backendId ?? null,
        policyHash: stableHash(body.model_policy ?? body.modelPolicy ?? {}),
        grantId: token.grantId,
        tokenCount,
        latencyMs,
        inputHash: stableHash(input),
        outputHash: stableHash(outputText),
        compatTranslation: providerResult.compatTranslation ?? null,
        providerResponseKind: providerResult.providerResponseKind ?? null,
        backendEvidenceRefs: providerResult.backendEvidenceRefs ?? [],
        authVaultRefHash: providerResult.authVaultRefHash ?? null,
        providerAuthEvidenceRefs: providerResult.providerAuthEvidenceRefs ?? [],
        toolReceiptIds: ephemeralMcp.toolReceiptIds,
        ephemeralMcpServerIds: ephemeralMcp.serverIds,
      },
    });
    const route = {
      ...selection.route,
      lastSelectedModel: selection.endpoint.modelId,
      lastReceiptId: receipt.id,
    };
    this.routes.set(route.id, route);
    this.writeMap("model-routes", this.routes);
    return {
      kind,
      outputText,
      model: selection.endpoint.modelId,
      route,
      endpoint: selection.endpoint,
      instance,
      receipt,
      routeReceipt,
      tokenCount,
      providerResponse: providerResult.providerResponse ?? null,
      providerResponseKind: providerResult.providerResponseKind ?? null,
      compatTranslation: providerResult.compatTranslation ?? null,
      toolReceiptIds: ephemeralMcp.toolReceiptIds,
    };
  }

  compileEphemeralMcpIntegrations({ authorization, body = {}, input }) {
    const integrations = Array.isArray(body.integrations) ? body.integrations : [];
    const ephemeral = integrations.filter((integration) => integration?.type === "ephemeral_mcp");
    const toolReceiptIds = [];
    const serverIds = [];
    const evidenceRefs = [];
    for (const integration of ephemeral) {
      const label = requiredString(integration.server_label ?? integration.serverLabel, "server_label");
      const server = this.normalizeMcpServer(label, {
        ...integration,
        url: integration.server_url ?? integration.serverUrl,
        allowed_tools: integration.allowed_tools ?? integration.allowedTools,
        source: "ephemeral_mcp",
      });
      const stored = {
        ...server,
        id: `mcp.ephemeral.${safeId(label)}.${stableHash(integration.server_url ?? integration.serverUrl ?? label).slice(0, 10)}`,
        status: "ephemeral_registered",
      };
      this.mcpServers.set(stored.id, stored);
      serverIds.push(stored.id);
      const serverReceipt = this.receipt("mcp_ephemeral_registration", {
        summary: `Ephemeral MCP server ${label} registered for one model request.`,
        redaction: "redacted",
        evidenceRefs: ["ephemeral_mcp", "RuntimeToolContract", stored.id],
        details: stored,
      });
      evidenceRefs.push(serverReceipt.id, stored.id);
      const allowedTools = stored.allowedTools.length > 0 ? stored.allowedTools : [];
      for (const tool of allowedTools) {
        const result = this.invokeMcpTool({
          authorization,
          body: {
            server_id: stored.id,
            tool,
            input: {
              source: "ephemeral_mcp",
              requestInputHash: stableHash(input),
            },
          },
        });
        toolReceiptIds.push(result.receipt.id);
        evidenceRefs.push(result.receipt.id);
      }
    }
    if (ephemeral.length > 0) {
      this.writeMap("mcp-servers", this.mcpServers);
    }
    return { toolReceiptIds, serverIds, evidenceRefs };
  }

  importMcpJson(body = {}) {
    const raw = body.mcp_json ?? body.mcpJson ?? body;
    const servers = raw.mcpServers ?? raw.servers ?? {};
    const imported = [];
    for (const [label, config] of Object.entries(servers)) {
      const server = this.normalizeMcpServer(label, config);
      this.mcpServers.set(server.id, server);
      imported.push(server);
      this.receipt("mcp_server_import", {
        summary: `MCP server ${label} imported with governed tool narrowing.`,
        redaction: "redacted",
        evidenceRefs: ["mcp.json", "RuntimeToolContract", server.id],
        details: server,
      });
    }
    this.writeMap("mcp-servers", this.mcpServers);
    return {
      imported,
      count: imported.length,
      empty: imported.length === 0,
    };
  }

  normalizeMcpServer(label, config = {}) {
    const id = `mcp.${safeId(label)}`;
    const allowedTools = normalizeScopes(
      config.allowed_tools ?? config.allowedTools,
      config.tools ? Object.keys(config.tools) : [],
    );
    for (const [key, value] of Object.entries(config.headers ?? config.env ?? {})) {
      this.walletAuthority.resolveVaultRef(String(value));
      if (!String(value).startsWith("vault://")) {
        throw runtimeError({
          status: 403,
          code: "policy",
          message: "MCP secrets must be vault refs.",
          details: { header: key },
        });
      }
    }
    const secretRefs = Object.fromEntries(
      Object.entries(config.headers ?? config.env ?? {}).map(([key]) => [key, `vault://${id}/${safeId(key)}`]),
    );
    return {
      id,
      label,
      transport: config.url || config.server_url || config.serverUrl ? "remote" : "stdio",
      command: config.command ?? null,
      args: Array.isArray(config.args) ? config.args : [],
      serverUrl: config.url ?? config.server_url ?? config.serverUrl ?? null,
      allowedTools,
      secretRefs,
      redactedHeaders: Object.fromEntries(Object.keys(config.headers ?? {}).map((key) => [key, SECRET_REDACTION])),
      status: "registered",
      source: config.source ?? "mcp.json",
      importedAt: this.nowIso(),
    };
  }

  listMcpServers() {
    return [...this.mcpServers.values()]
      .map(publicMcpServer)
      .sort((left, right) => left.id.localeCompare(right.id));
  }

  invokeMcpTool({ authorization, body = {} }) {
    const serverId = body.server_id ?? body.serverId ?? `mcp.${safeId(body.server_label ?? body.serverLabel ?? "")}`;
    const server = this.mcpServers.get(serverId);
    if (!server) throw notFound(`MCP server not found: ${serverId}`, { serverId });
    const tool = requiredString(body.tool, "tool");
    this.authorize(authorization, `mcp.call:${server.label}.${tool}`);
    if (server.allowedTools.length > 0 && !server.allowedTools.includes(tool)) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "MCP tool is not included in allowed_tools.",
        details: { serverId, tool },
      });
    }
    const receipt = this.receipt("mcp_tool_invocation", {
      summary: `MCP tool ${server.label}.${tool} executed through governed RuntimeToolContract path.`,
      redaction: "redacted",
      evidenceRefs: ["RuntimeToolContract", server.id, `tool:${tool}`],
      details: {
        serverId,
        tool,
        inputHash: stableHash(body.input ?? {}),
        outputHash: stableHash({ ok: true, tool }),
      },
    });
    return {
      server: server.label,
      tool,
      result: { ok: true, fixture: true, tool },
      receipt,
    };
  }

  async executeWorkflowNode({ authorization, body = {} }) {
    const node = requiredString(body.node ?? body.node_type ?? body.nodeType, "node");
    const capability = body.capability ?? capabilityForWorkflowNode(node);
    const base = {
      model: body.model_id ?? body.modelId ?? body.model,
      route_id: body.route_id ?? body.routeId,
      model_policy: body.model_policy ?? body.modelPolicy ?? {},
      input: body.input ?? body.prompt ?? "",
      messages: body.messages,
    };
    if (node === "Model Router") {
      const routeId = base.route_id ?? "route.local-first";
      this.authorize(authorization, `route.use:${routeId}`);
      return {
        node,
        status: "selected",
        ...(this.testRoute(routeId, { capability, model: base.model, model_policy: base.model_policy })),
      };
    }
    if (node === "Local Tool/MCP" || node === "Local Tool / MCP") {
      return {
        node,
        status: "executed",
        ...(this.invokeMcpTool({ authorization, body: body.mcp ?? body })),
      };
    }
    if (node === "Receipt Gate") {
      return this.validateReceiptGate(body);
    }
    const kind = workflowKindForNode(node);
    const requiredScope =
      kind === "embeddings"
        ? "model.embeddings:*"
        : kind === "rerank"
          ? "model.rerank:*"
          : kind === "responses"
            ? "model.responses:*"
            : "model.chat:*";
    const invocation = await this.invokeModel({
      authorization,
      requiredScope,
      kind,
      body: base,
    });
    return {
      node,
      status: "executed",
      capability,
      invocation: nativeInvocationResponseShape(invocation),
      receipt: invocation.receipt,
      routeReceipt: invocation.routeReceipt,
    };
  }

  validateReceiptGate(body = {}) {
    const receiptId = requiredString(body.receipt_id ?? body.receiptId, "receipt_id");
    const receipt = this.getReceipt(receiptId);
    const requiredRedaction = body.redaction ?? body.redaction_class ?? body.redactionClass;
    const requiredRouteId = body.route_id ?? body.routeId;
    const requiredSelectedModel = body.selected_model ?? body.selectedModel;
    const requiredSelectedEndpoint = body.selected_endpoint ?? body.selectedEndpoint ?? body.endpoint_id ?? body.endpointId;
    const requiredSelectedBackend = body.selected_backend ?? body.selectedBackend ?? body.backend_id ?? body.backendId;
    const requiredToolReceiptIds = normalizeScopes(
      body.required_tool_receipt_ids ?? body.requiredToolReceiptIds,
      [],
    );
    const failures = [];
    if (requiredRedaction && receipt.redaction !== requiredRedaction) {
      failures.push(`redaction:${receipt.redaction}`);
    }
    if (requiredRouteId && receipt.details?.routeId !== requiredRouteId) {
      failures.push(`route:${receipt.details?.routeId ?? "missing"}`);
    }
    if (requiredSelectedModel && receipt.details?.selectedModel !== requiredSelectedModel) {
      failures.push(`selected_model:${receipt.details?.selectedModel ?? "missing"}`);
    }
    if (requiredSelectedEndpoint && receipt.details?.endpointId !== requiredSelectedEndpoint) {
      failures.push(`endpoint:${receipt.details?.endpointId ?? "missing"}`);
    }
    if (requiredSelectedBackend && receipt.details?.backendId !== requiredSelectedBackend && receipt.details?.selectedBackend !== requiredSelectedBackend) {
      failures.push(`backend:${receipt.details?.backendId ?? receipt.details?.selectedBackend ?? "missing"}`);
    }
    const linkedToolReceiptIds = new Set(normalizeScopes(receipt.details?.toolReceiptIds, []));
    for (const toolReceiptId of requiredToolReceiptIds) {
      const toolReceipt = this.getReceipt(toolReceiptId);
      if (toolReceipt.kind !== "mcp_tool_invocation") {
        failures.push(`tool_receipt_kind:${toolReceiptId}`);
      }
      if (!linkedToolReceiptIds.has(toolReceiptId)) {
        failures.push(`tool_receipt_link:${toolReceiptId}`);
      }
    }
    if (failures.length > 0) {
      throw runtimeError({
        status: 412,
        code: "policy",
        message: "Receipt Gate blocked downstream workflow execution.",
        details: { receiptId, failures },
      });
    }
    const gateReceipt = this.receipt("workflow_receipt_gate", {
      summary: `Receipt Gate accepted ${receiptId}.`,
      redaction: "redacted",
      evidenceRefs: ["workflow_canvas", "Receipt Gate", receiptId, ...requiredToolReceiptIds],
      details: {
        receiptId,
        routeId: receipt.details?.routeId ?? null,
        selectedModel: receipt.details?.selectedModel ?? null,
        endpointId: receipt.details?.endpointId ?? null,
        backendId: receipt.details?.backendId ?? receipt.details?.selectedBackend ?? null,
        requiredToolReceiptIds,
      },
    });
    return {
      node: "Receipt Gate",
      status: "passed",
      receipt,
      gateReceipt,
    };
  }

  listReceipts() {
    return this.store.listReceipts();
  }

  getReceipt(receiptId) {
    return this.store.getReceipt(receiptId);
  }

  lifecycleReceipt(operation, details) {
    return this.receipt("model_lifecycle", {
      summary: `${operation} recorded for ${details.modelId ?? details.endpointId ?? "model registry"}.`,
      redaction: "redacted",
      evidenceRefs: ["model_registry", "agentgres_canonical_operation_log", operation],
      details: { operation, ...details },
    });
  }

  receipt(kind, { summary, redaction, evidenceRefs, details }) {
    const receipt = {
      id: `receipt_${kind}_${crypto.randomUUID()}`,
      runId: null,
      kind,
      summary,
      redaction,
      evidenceRefs,
      createdAt: this.nowIso(),
      details: redact(details),
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    };
    this.store.writeReceipt(receipt);
    this.writeProjection();
    return receipt;
  }

  provider(providerId) {
    const provider = this.providers.get(providerId);
    if (!provider) throw notFound(`Provider not found: ${providerId}`, { providerId });
    return provider;
  }

  endpoint(endpointId) {
    const endpoint = this.endpoints.get(endpointId);
    if (!endpoint || endpoint.status === "unmounted") {
      throw notFound(`Endpoint not found: ${endpointId}`, { endpointId });
    }
    return endpoint;
  }

  instance(instanceId) {
    const instance = this.instances.get(instanceId);
    if (!instance) throw notFound(`Model instance not found: ${instanceId}`, { instanceId });
    return instance;
  }

  route(routeId) {
    const route = this.routes.get(routeId);
    if (!route) throw notFound(`Route not found: ${routeId}`, { routeId });
    return route;
  }

  resolveEndpoint(endpointId, modelId) {
    if (endpointId) return this.endpoint(endpointId);
    if (modelId) {
      const endpoint = [...this.endpoints.values()].find(
        (candidate) => candidate.status !== "unmounted" && candidate.modelId === modelId,
      );
      if (endpoint) return endpoint;
      return this.mountEndpoint({ model_id: modelId });
    }
    return this.endpoint("endpoint.local.auto");
  }

  selectRoute({ modelId, routeId, capability, policy }) {
    const route = this.routes.get(routeId ?? "route.local-first") ?? this.route("route.local-first");
    const fallback = modelId
      ? [this.resolveEndpoint(undefined, modelId).id]
      : route.fallback.length > 0
        ? route.fallback
        : ["endpoint.local.auto"];
    for (const endpointId of fallback) {
      const endpoint = this.endpoint(endpointId);
      const provider = this.provider(endpoint.providerId);
      if (route.deniedProviders.includes(provider.kind)) continue;
      if (route.providerEligibility.length > 0 && !route.providerEligibility.includes(provider.kind)) continue;
      if (policy?.privacy === "local_only" && provider.privacyClass !== "local_private") continue;
      if (
        provider.privacyClass === "hosted" &&
        route.privacy === "local_or_enterprise" &&
        !truthy(policy?.allow_hosted_fallback ?? policy?.allowHostedFallback)
      ) {
        continue;
      }
      const costCeiling = Number(policy?.max_cost_usd ?? policy?.maxCostUsd ?? route.maxCostUsd ?? Infinity);
      const estimatedCost = Number(endpoint.estimatedCostUsd ?? provider.estimatedCostUsd ?? (provider.privacyClass === "hosted" ? 0.01 : 0));
      if (Number.isFinite(costCeiling) && estimatedCost > costCeiling) continue;
      if (!endpoint.capabilities.includes(capability) && capability !== "chat") continue;
      return { route, endpoint, provider };
    }
    throw runtimeError({
      status: 424,
      code: "external_blocker",
      message: "No model endpoint satisfied the route policy.",
      details: { routeId: route.id, capability, policy },
    });
  }

  async ensureLoaded(endpoint) {
    this.evictExpiredInstances();
    const existing = this.loadedInstanceForEndpoint(endpoint.id, false);
    if (existing) {
      const updated = {
        ...existing,
        lastUsedAt: this.nowIso(),
        expiresAt: expiresAt(this.nowIso(), existing.loadPolicy),
      };
      this.instances.set(updated.id, updated);
      this.writeMap("model-instances", this.instances);
      return updated;
    }
    return this.loadModel({ endpoint_id: endpoint.id, load_policy: endpoint.loadPolicy });
  }

  loadedInstanceForEndpoint(endpointId, failIfMissing = true) {
    const instance = [...this.instances.values()].find(
      (candidate) => candidate.endpointId === endpointId && candidate.status === "loaded",
    );
    if (!instance && failIfMissing) {
      throw notFound(`No loaded model instance for endpoint: ${endpointId}`, { endpointId });
    }
    return instance ?? null;
  }

  evictExpiredInstances() {
    const nowMs = this.now().getTime();
    let changed = false;
    for (const instance of this.instances.values()) {
      if (instance.status !== "loaded" || !instance.expiresAt || Date.parse(instance.expiresAt) > nowMs) {
        continue;
      }
      const evicted = {
        ...instance,
        status: "evicted",
        evictedAt: this.nowIso(),
        evictionReason: "idle_ttl",
      };
      this.instances.set(instance.id, evicted);
      changed = true;
      this.lifecycleReceipt("model_idle_evict", {
        instanceId: instance.id,
        endpointId: instance.endpointId,
        modelId: instance.modelId,
        providerId: instance.providerId,
      });
    }
    if (changed) {
      this.writeMap("model-instances", this.instances);
    }
  }

  nowIso() {
    return this.now().toISOString();
  }

  seedBackends(checkedAt) {
    for (const backend of this.deriveBackendRegistry(checkedAt)) {
      this.upsertDefault(this.backends, backend);
    }
  }

  backendRegistry() {
    const derived = new Map(this.deriveBackendRegistry(this.nowIso()).map((backend) => [backend.id, backend]));
    for (const [id, backend] of this.backends.entries()) {
      derived.set(id, {
        ...derived.get(id),
        ...backend,
        hardware: backend.hardware ?? derived.get(id)?.hardware,
        evidenceRefs: backend.evidenceRefs ?? derived.get(id)?.evidenceRefs ?? [],
      });
    }
    return [...derived.values()].sort((left, right) => left.id.localeCompare(right.id));
  }

  deriveBackendRegistry(checkedAt) {
    const hardware = hardwareSnapshot();
    const llamaBinary = process.env.IOI_LLAMA_CPP_SERVER_PATH ?? findExecutable("llama-server");
    const ollamaBinary = process.env.IOI_OLLAMA_BINARY ?? findExecutable("ollama");
    const vllmBinary = process.env.IOI_VLLM_BINARY ?? findExecutable("vllm");
    return [
      {
        id: "backend.fixture",
        kind: "fixture",
        label: "Deterministic fixture backend",
        status: "available",
        processStatus: "stateless",
        binaryPath: null,
        baseUrl: "local://ioi-daemon/model-fixture",
        capabilities: ["chat", "responses", "embeddings", "rerank"],
        supportedFormats: ["fixture"],
        hardware,
        checkedAt,
        evidenceRefs: ["deterministic_fixture"],
      },
      {
        id: "backend.autopilot.native-local.fixture",
        kind: "native_local",
        label: "Autopilot native-local fixture",
        status: "available",
        processStatus: "supervised_fixture",
        binaryPath: null,
        baseUrl: "local://ioi-native/model-server",
        capabilities: ["chat", "responses", "embeddings", "rerank"],
        supportedFormats: ["gguf", "fixture"],
        processLifecycle: ["estimate", "load", "unload", "health", "logs", "invoke"],
        hardware,
        checkedAt,
        evidenceRefs: ["autopilot_native_local_backend_registry", "deterministic_native_local_fixture"],
      },
      {
        id: "backend.llama-cpp",
        kind: "llama_cpp",
        label: "llama.cpp native GGUF server",
        status: llamaBinary || process.env.IOI_LLAMA_CPP_BASE_URL ? "configured" : "blocked",
        processStatus: llamaBinary ? "binary_configured" : "binary_absent",
        binaryPath: llamaBinary,
        baseUrl: process.env.IOI_LLAMA_CPP_BASE_URL ?? "http://127.0.0.1:8080/v1",
        capabilities: ["chat", "responses", "embeddings"],
        supportedFormats: ["gguf"],
        processLifecycle: ["estimate", "start", "stop", "health", "logs", "invoke"],
        hardware,
        checkedAt,
        evidenceRefs: ["IOI_LLAMA_CPP_SERVER_PATH", "llama_cpp_openai_compatible_server"],
      },
      {
        id: "backend.lmstudio",
        kind: "lm_studio",
        label: "LM Studio public provider",
        status: this.providers.get("provider.lmstudio")?.status ?? "unknown",
        processStatus: "external_provider",
        binaryPath: this.providers.get("provider.lmstudio")?.discovery?.publicCli?.path ?? null,
        baseUrl: this.providers.get("provider.lmstudio")?.baseUrl ?? "http://127.0.0.1:1234/v1",
        capabilities: ["chat", "responses", "embeddings"],
        supportedFormats: ["lm_studio_catalog"],
        hardware,
        checkedAt,
        evidenceRefs: ["lm_studio_public_cli_or_server_probe"],
      },
      {
        id: "backend.openai-compatible",
        kind: "openai_compatible",
        label: "Generic OpenAI-compatible HTTP backend",
        status: this.providers.get("provider.openai-compatible")?.status ?? "configured_if_provider_available",
        processStatus: "stateless_http",
        binaryPath: null,
        baseUrl: this.providers.get("provider.openai-compatible")?.baseUrl ?? null,
        capabilities: ["chat", "responses", "embeddings"],
        supportedFormats: ["http_endpoint"],
        hardware,
        checkedAt,
        evidenceRefs: ["openai_compatible_provider_profile"],
      },
      {
        id: "backend.ollama",
        kind: "ollama",
        label: "Ollama local backend",
        status: this.providers.get("provider.ollama")?.status ?? "blocked",
        processStatus: ollamaBinary ? "binary_configured" : "external_or_absent",
        binaryPath: ollamaBinary,
        baseUrl: this.providers.get("provider.ollama")?.baseUrl ?? "http://127.0.0.1:11434",
        capabilities: ["chat", "embeddings"],
        supportedFormats: ["ollama_manifest"],
        hardware,
        checkedAt,
        evidenceRefs: ["OLLAMA_HOST"],
      },
      {
        id: "backend.vllm",
        kind: "vllm",
        label: "vLLM OpenAI-compatible backend",
        status: this.providers.get("provider.vllm")?.status ?? "blocked",
        processStatus: vllmBinary ? "binary_configured" : "external_or_absent",
        binaryPath: vllmBinary,
        baseUrl: this.providers.get("provider.vllm")?.baseUrl ?? "http://127.0.0.1:8000/v1",
        capabilities: ["chat", "responses", "embeddings"],
        supportedFormats: ["safetensors", "hf_repository"],
        hardware,
        checkedAt,
        evidenceRefs: ["VLLM_BASE_URL"],
      },
    ];
  }

  listBackends() {
    return this.backendRegistry();
  }

  backend(backendId) {
    const backend = this.backendRegistry().find((item) => item.id === backendId);
    if (!backend) throw notFound(`Model backend not found: ${backendId}`, { backendId });
    return backend;
  }

  backendHealth(backendId) {
    const backend = this.backend(backendId);
    const checkedAt = this.nowIso();
    const status = backend.status === "blocked" || backend.status === "absent" ? backend.status : "available";
    const hardware = hardwareSnapshot();
    const receipt = this.lifecycleReceipt("backend_health", {
      backendId,
      modelId: backend.label,
      state: status,
      evidenceRefs: backend.evidenceRefs ?? [],
      hardware,
    });
    const updated = {
      ...backend,
      status,
      checkedAt,
      lastReceiptId: receipt.id,
      lastHealthReceiptId: receipt.id,
    };
    this.backends.set(backendId, updated);
    this.writeMap("model-backends", this.backends);
    return updated;
  }

  startBackend(backendId) {
    const backend = this.backend(backendId);
    if (backend.status === "blocked" && !backend.binaryPath && !String(backend.baseUrl ?? "").startsWith("local://")) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "Backend cannot be started until its binary path or base URL is configured.",
        details: { backendId, backendKind: backend.kind, evidenceRefs: backend.evidenceRefs ?? [] },
      });
    }
    const receipt = this.lifecycleReceipt("backend_start", {
      backendId,
      modelId: backend.label,
      state: "available",
      evidenceRefs: backend.evidenceRefs ?? [],
    });
    const updated = {
      ...backend,
      status: "available",
      processStatus: backend.processStatus === "stateless_http" ? "stateless_http" : "started",
      startedAt: this.nowIso(),
      lastReceiptId: receipt.id,
    };
    this.backends.set(backendId, updated);
    this.writeMap("model-backends", this.backends);
    this.writeBackendLog(backendId, {
      backendId,
      event: "backend_start",
      backendKind: backend.kind,
      receiptId: receipt.id,
    });
    return updated;
  }

  stopBackend(backendId) {
    const backend = this.backend(backendId);
    const receipt = this.lifecycleReceipt("backend_stop", {
      backendId,
      modelId: backend.label,
      state: "stopped",
      evidenceRefs: backend.evidenceRefs ?? [],
    });
    const updated = {
      ...backend,
      status: backend.kind === "fixture" ? "available" : "stopped",
      processStatus: backend.kind === "fixture" ? "stateless" : "stopped",
      stoppedAt: this.nowIso(),
      lastReceiptId: receipt.id,
    };
    this.backends.set(backendId, updated);
    this.writeMap("model-backends", this.backends);
    this.writeBackendLog(backendId, {
      backendId,
      event: "backend_stop",
      backendKind: backend.kind,
      receiptId: receipt.id,
    });
    return updated;
  }

  backendLogs(backendId) {
    this.backend(backendId);
    const logDir = path.join(this.stateDir, "backend-logs");
    const records = [];
    for (const filePath of listFiles(logDir, ".jsonl")) {
      for (const line of readLines(filePath)) {
        const record = parseJsonMaybe(line);
        if (record?.backendId === backendId || record?.backend === backendId || filePath.endsWith(`${safeFileName(backendId)}.jsonl`)) {
          records.push(record);
        }
      }
    }
    return records.sort((left, right) => String(left.createdAt ?? "").localeCompare(String(right.createdAt ?? ""))).slice(-200);
  }

  writeBackendLog(endpointId, event) {
    const record = {
      id: `backend_log_${crypto.randomUUID()}`,
      endpointId,
      backendId: event.backendId ?? event.backend ?? endpointId,
      createdAt: this.nowIso(),
      ...redact(event),
    };
    const filePath = path.join(this.stateDir, "backend-logs", `${safeFileName(endpointId)}.jsonl`);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.appendFileSync(filePath, `${JSON.stringify(record)}\n`);
    if (record.backendId && record.backendId !== endpointId) {
      const backendPath = path.join(this.stateDir, "backend-logs", `${safeFileName(record.backendId)}.jsonl`);
      fs.appendFileSync(backendPath, `${JSON.stringify(record)}\n`);
    }
    return record;
  }

  driverForProvider(provider) {
    const driver = driverNameForProvider(provider);
    if (driver === "native_local") return new NativeLocalModelProviderDriver();
    if (driver === "lm_studio") return new LmStudioModelProviderDriver({ state: this });
    if (driver === "ollama") return new OllamaModelProviderDriver();
    if (driver === "openai_compatible") return new OpenAICompatibleModelProviderDriver({ label: provider.kind });
    return new FixtureModelProviderDriver();
  }
}

export function openAiChatCompletion(invocation, body = {}) {
  if (invocation.providerResponseKind === "chat.completions" && invocation.providerResponse) {
    return {
      ...invocation.providerResponse,
      receipt_id: invocation.receipt.id,
      route_id: invocation.route.id,
      tool_receipt_ids: invocation.toolReceiptIds ?? [],
      request_model: body.model ?? null,
    };
  }
  return {
    id: `chatcmpl_${crypto.randomUUID()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: invocation.model,
    choices: [
      {
        index: 0,
        message: { role: "assistant", content: invocation.outputText },
        finish_reason: "stop",
      },
    ],
    usage: invocation.tokenCount,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    request_model: body.model ?? null,
  };
}

export function openAiResponse(invocation) {
  if (invocation.providerResponseKind === "responses" && invocation.providerResponse) {
    return {
      ...invocation.providerResponse,
      receipt_id: invocation.receipt.id,
      route_id: invocation.route.id,
      tool_receipt_ids: invocation.toolReceiptIds ?? [],
    };
  }
  return {
    id: `resp_${crypto.randomUUID()}`,
    object: "response",
    created_at: Math.floor(Date.now() / 1000),
    model: invocation.model,
    output_text: invocation.outputText,
    output: [
      {
        id: `msg_${crypto.randomUUID()}`,
        type: "message",
        role: "assistant",
        content: [{ type: "output_text", text: invocation.outputText }],
      },
    ],
    usage: invocation.tokenCount,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
  };
}

export function openAiEmbedding(invocation, body = {}) {
  if (invocation.providerResponseKind === "embeddings" && invocation.providerResponse) {
    return {
      ...invocation.providerResponse,
      receipt_id: invocation.receipt.id,
      route_id: invocation.route.id,
      tool_receipt_ids: invocation.toolReceiptIds ?? [],
    };
  }
  const inputs = Array.isArray(body.input) ? body.input : [body.input ?? ""];
  return {
    object: "list",
    model: invocation.model,
    data: inputs.map((item, index) => ({
      object: "embedding",
      index,
      embedding: deterministicVector(String(item)),
    })),
    usage: invocation.tokenCount,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
  };
}

export function openAiCompletion(invocation) {
  return {
    id: `cmpl_${crypto.randomUUID()}`,
    object: "text_completion",
    created: Math.floor(Date.now() / 1000),
    model: invocation.model,
    choices: [{ text: invocation.outputText, index: 0, finish_reason: "stop" }],
    usage: invocation.tokenCount,
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
  };
}

function runPublicCommand(command, args, options = {}) {
  try {
    const result = childProcess.spawnSync(command, args, {
      encoding: "utf8",
      timeout: options.timeout ?? 1500,
      windowsHide: true,
    });
    return {
      status: result.status,
      stdout: result.stdout ?? "",
      stderr: result.stderr ?? "",
      error: result.error ? String(result.error.message ?? result.error) : null,
    };
  } catch (error) {
    return {
      status: null,
      stdout: "",
      stderr: "",
      error: String(error?.message ?? error),
    };
  }
}

function parseLmStudioList(text) {
  const models = [];
  let section = null;
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    if (/^LLM\s+/i.test(line)) {
      section = "llm";
      continue;
    }
    if (/^EMBEDDING\s+/i.test(line)) {
      section = "embedding";
      continue;
    }
    if (!section || /^You have /i.test(line) || /^PARAMS\s+/i.test(line)) continue;
    const columns = line.split(/\s{2,}/).map((item) => item.trim()).filter(Boolean);
    if (columns.length < 2) continue;
    const displayName = columns[0];
    const modelId = displayName.replace(/\s+\(\d+\s+variants?\)$/i, "");
    models.push({
      kind: section,
      modelId,
      displayName,
      params: columns[1] ?? null,
      arch: columns[2] ?? null,
      size: columns[3] ?? null,
    });
  }
  return models;
}

function parseLmStudioProcessList(text) {
  const models = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || /^MODEL\b/i.test(line) || /^No loaded/i.test(line)) continue;
    const columns = line.split(/\s{2,}|\t+/).map((item) => item.trim()).filter(Boolean);
    const modelId = columns[0] ?? line.split(/\s+/)[0];
    if (!modelId || /^(pid|port|identifier)$/i.test(modelId)) continue;
    models.push({ modelId, raw: line });
  }
  return models;
}

function lmStudioArtifact(provider, model, checkedAt) {
  return {
    id: `lmstudio.${safeId(model.modelId)}`,
    providerId: provider.id,
    modelId: model.modelId,
    displayName: model.displayName,
    family: model.kind === "embedding" ? "embedding" : "lm-studio",
    quantization: model.arch,
    sizeBytes: null,
    contextWindow: null,
    capabilities: model.kind === "embedding" ? ["embeddings"] : ["chat", "responses"],
    privacyClass: "local_private",
    source: "lm_studio_public_lms_ls",
    state: provider.status === "running" ? "available" : "installed",
    discoveredAt: checkedAt,
  };
}

function driverForProviderKind(kind) {
  if (kind === "ioi_native_local") return "native_local";
  if (kind === "lm_studio") return "lm_studio";
  if (kind === "ollama") return "ollama";
  if (["openai_compatible", "vllm", "llama_cpp", "custom_http", "openai", "anthropic", "gemini"].includes(kind)) {
    return "openai_compatible";
  }
  return "fixture";
}

function driverNameForProvider(provider) {
  return provider.driver ?? driverForProviderKind(provider.kind);
}

function defaultBackendForProvider(provider) {
  if (provider.kind === "ioi_native_local") return "backend.autopilot.native-local.fixture";
  if (provider.kind === "lm_studio") return "backend.lmstudio";
  if (provider.kind === "ollama") return "backend.ollama";
  if (provider.kind === "vllm") return "backend.vllm";
  if (provider.kind === "llama_cpp") return "backend.llama-cpp";
  if (["openai_compatible", "custom_http", "openai", "anthropic", "gemini"].includes(provider.kind)) {
    return "backend.openai-compatible";
  }
  return "backend.fixture";
}

async function fetchProviderJson(provider, route, { method = "GET", body, tolerateHttpError = false, state } = {}) {
  assertProviderVaultBoundary(provider);
  if (!provider.baseUrl || String(provider.baseUrl).startsWith("local://")) {
    throw runtimeError({
      status: 424,
      code: "external_blocker",
      message: "Provider does not expose an HTTP model endpoint.",
      details: { providerId: provider.id, providerKind: provider.kind },
    });
  }
  const controller = new AbortController();
  const timeoutMs = providerRequestTimeoutMs();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  const url = `${String(provider.baseUrl).replace(/\/+$/, "")}/${route.replace(/^\/+/, "")}`;
  const auth = providerAuthHeaders(provider, state);
  try {
    const response = await fetch(url, {
      method,
      signal: controller.signal,
      headers: {
        accept: "application/json",
        ...auth.headers,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    const parsed = text.trim() ? parseJsonMaybe(text) : null;
    const result = { ok: response.ok, status: response.status, body: parsed, authEvidence: auth.evidence };
    if (!response.ok && !tolerateHttpError) {
      throw providerHttpError(provider, "OpenAI-compatible provider request failed.", result);
    }
    return result;
  } catch (error) {
    if (error?.status || error?.code === "external_blocker") throw error;
    throw runtimeError({
      status: 424,
      code: "external_blocker",
      message: "OpenAI-compatible provider request failed.",
      details: {
        providerId: provider.id,
        providerKind: provider.kind,
        error: String(error?.name ?? error?.message ?? error),
      },
    });
  } finally {
    clearTimeout(timeout);
  }
}

function providerRequestTimeoutMs() {
  const configured = Number(process.env.IOI_PROVIDER_HTTP_TIMEOUT_MS ?? "");
  if (Number.isFinite(configured) && configured >= 1000) return configured;
  return 30000;
}

function providerHttpError(provider, message, result) {
  return runtimeError({
    status: 424,
    code: "external_blocker",
    message,
    details: {
      providerId: provider.id,
      providerKind: provider.kind,
      httpStatus: result.status ?? null,
      providerErrorHash: stableHash(result.body ?? {}),
    },
  });
}

function providerCommandError(provider, message, result) {
  return runtimeError({
    status: 424,
    code: "external_blocker",
    message,
    details: {
      providerId: provider.id,
      providerKind: provider.kind,
      commandExitCode: result.status ?? null,
      stderrHash: stableHash(result.stderr ?? ""),
    },
  });
}

function parseJsonMaybe(text) {
  try {
    return JSON.parse(text);
  } catch {
    return { text: truncate(text) };
  }
}

function chatCompletionRequestBody(body, modelId) {
  if (Array.isArray(body.messages)) {
    return { ...body, model: body.model ?? modelId };
  }
  const content = body.input ?? body.prompt ?? "";
  return {
    ...body,
    model: body.model ?? modelId,
    messages: [{ role: "user", content: String(content) }],
  };
}

function outputTextFromChat(body) {
  return String(body?.choices?.[0]?.message?.content ?? body?.choices?.[0]?.text ?? body?.output_text ?? "");
}

function outputTextFromResponse(body) {
  if (typeof body?.output_text === "string") return body.output_text;
  const content = body?.output?.[0]?.content;
  if (Array.isArray(content)) {
    const text = content.find((item) => typeof item?.text === "string")?.text;
    if (text) return text;
  }
  return outputTextFromChat(body);
}

function normalizeUsage(usage, fallback) {
  if (!usage || typeof usage !== "object") return fallback;
  return {
    prompt_tokens: Number(usage.prompt_tokens ?? usage.input_tokens ?? fallback.prompt_tokens),
    completion_tokens: Number(usage.completion_tokens ?? usage.output_tokens ?? fallback.completion_tokens),
    total_tokens: Number(usage.total_tokens ?? fallback.total_tokens),
  };
}

function capabilityForWorkflowNode(node) {
  if (node === "Embedding") return "embeddings";
  if (node === "Reranker") return "rerank";
  if (node === "Vision") return "vision";
  if (node === "Structured Output") return "responses";
  if (node === "Local Tool/MCP" || node === "Local Tool / MCP") return "mcp";
  if (node === "Receipt Gate") return "receipt_gate";
  return "chat";
}

function workflowKindForNode(node) {
  if (node === "Embedding") return "embeddings";
  if (node === "Reranker") return "rerank";
  if (node === "Structured Output") return "responses";
  return "chat";
}

function nativeInvocationResponseShape(invocation) {
  return {
    model: invocation.model,
    route_id: invocation.route.id,
    endpoint_id: invocation.endpoint.id,
    instance_id: invocation.instance.id,
    backend_id: invocation.instance.backendId ?? invocation.receipt.details?.backendId ?? null,
    receipt_id: invocation.receipt.id,
    route_receipt_id: invocation.routeReceipt.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
    output_text: invocation.outputText,
    usage: invocation.tokenCount,
  };
}

function truncate(value, limit = 1000) {
  const text = String(value ?? "");
  return text.length > limit ? `${text.slice(0, limit)}...` : text;
}

function hostedProvider(id, label, apiFormat, secret) {
  return {
    id,
    kind: apiFormat,
    label,
    apiFormat,
    driver: "openai_compatible",
    baseUrl: null,
    status: secret ? "configured" : "blocked",
    privacyClass: "hosted",
    capabilities: ["chat", "responses", "embeddings"],
    discovery: {
      checkedAt: new Date().toISOString(),
      evidenceRefs: [`${label.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}_API_KEY`],
    },
    secretRef: secret ? `vault://${id}/api-key` : null,
    estimatedCostUsd: 0.01,
  };
}

function normalizeLoadPolicy(value = {}) {
  if (typeof value === "string") {
    return { mode: value, idleTtlSeconds: 900, autoEvict: value === "idle_evict" };
  }
  return {
    mode: value.mode ?? "on_demand",
    idleTtlSeconds: Number(value.idle_ttl_seconds ?? value.idleTtlSeconds ?? 900),
    autoEvict: value.auto_evict ?? value.autoEvict ?? true,
    memoryPressureEvict: value.memory_pressure_evict ?? value.memoryPressureEvict ?? true,
  };
}

function expiresAt(nowIso, loadPolicy) {
  if (!loadPolicy.autoEvict && loadPolicy.mode !== "idle_evict") return null;
  return new Date(Date.parse(nowIso) + Number(loadPolicy.idleTtlSeconds ?? 900) * 1000).toISOString();
}

function normalizeScopes(value, fallback) {
  if (!value) return [...fallback];
  if (Array.isArray(value)) return value.map(String);
  return [String(value)];
}

function sanitizeVaultRefs(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value).map(([key, vaultRef]) => [
      key,
      typeof vaultRef === "string" && vaultRef.startsWith("vault://") ? vaultRef : SECRET_REDACTION,
    ]),
  );
}

function providerSecretInput(body = {}) {
  for (const key of ["secret_ref", "secretRef", "auth_vault_ref", "authVaultRef", "api_key_vault_ref", "apiKeyVaultRef"]) {
    if (Object.prototype.hasOwnProperty.call(body, key)) return body[key];
  }
  return undefined;
}

function providerRequiresVaultSecret(providerOrKind) {
  const kind = typeof providerOrKind === "string" ? providerOrKind : providerOrKind?.kind;
  return ["openai", "anthropic", "gemini", "custom_http"].includes(kind);
}

function assertNoPlaintextProviderSecret(body = {}) {
  for (const key of Object.keys(body)) {
    if (isPlaintextProviderSecretKey(key)) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Provider secrets and auth headers must be configured through wallet.network vault refs.",
        details: { field: key, secret: SECRET_REDACTION },
      });
    }
  }
}

function isPlaintextProviderSecretKey(key) {
  return /^(api_?key|authorization|auth|headers?|bearer_?token|access_?token|provider_?key)$/i.test(String(key));
}

function assertProviderVaultBoundary(provider) {
  if (!providerRequiresVaultSecret(provider)) return;
  if (typeof provider.secretRef === "string" && provider.secretRef.startsWith("vault://")) return;
  throw runtimeError({
    status: 403,
    code: "policy",
    message: "Hosted and custom HTTP providers fail closed until auth is bound to a wallet.network vault ref.",
    details: {
      providerId: provider.id,
      providerKind: provider.kind,
      vaultRefConfigured: false,
    },
  });
}

function providerAuthHeaders(provider, state) {
  if (!providerRequiresVaultSecret(provider)) return { headers: {}, evidence: null };
  assertProviderVaultBoundary(provider);
  const resolved = state?.vault?.resolveVaultRef(provider.secretRef, `provider.auth:${provider.id}`);
  if (!resolved?.material) {
    throw runtimeError({
      status: 403,
      code: "policy",
      message: "Provider vault ref is configured, but no runtime vault material is available.",
      details: {
        providerId: provider.id,
        providerKind: provider.kind,
        vaultRefHash: stableHash(provider.secretRef),
        resolvedMaterial: false,
      },
    });
  }
  return {
    headers: {
      authorization: providerAuthorizationHeaderValue(provider, resolved.material),
    },
    evidence: {
      vaultRefHash: resolved.vaultRefHash,
      resolvedMaterial: true,
      evidenceRefs: resolved.evidenceRefs ?? ["VaultPort.resolveVaultRef"],
      headerNames: ["authorization"],
    },
  };
}

function providerAuthorizationHeaderValue(provider, material) {
  const scheme = provider.authScheme ?? provider.auth_scheme ?? "bearer";
  if (scheme === "raw") return material;
  if (scheme === "api_key") return material;
  return `Bearer ${material}`;
}

function publicProvider(provider) {
  const hasVaultRef = typeof provider.secretRef === "string" && provider.secretRef.startsWith("vault://");
  const requiresVault = providerRequiresVaultSecret(provider);
  return {
    ...provider,
    status: requiresVault && !hasVaultRef ? "blocked" : provider.status,
    secretRef: hasVaultRef ? { redacted: true, hash: stableHash(provider.secretRef) } : provider.secretRef ? SECRET_REDACTION : null,
    secretConfigured: hasVaultRef,
    vaultBoundary: {
      required: requiresVault,
      failClosed: requiresVault && !hasVaultRef,
      resolvedMaterial: false,
    },
  };
}

function vaultRefEnvironmentAlias(vaultRef) {
  const aliases = new Map([
    ["vault://provider.openai/api-key", "OPENAI_API_KEY"],
    ["vault://provider.anthropic/api-key", "ANTHROPIC_API_KEY"],
    ["vault://provider.gemini/api-key", "GEMINI_API_KEY"],
    ["vault://provider.custom-http/api-key", "IOI_CUSTOM_MODEL_API_KEY"],
  ]);
  return aliases.get(vaultRef) ?? null;
}

function publicVaultRefs(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value).map(([key, vaultRef]) => [
      key,
      typeof vaultRef === "string" && vaultRef.startsWith("vault://")
        ? { redacted: true, hash: stableHash(vaultRef) }
        : SECRET_REDACTION,
    ]),
  );
}

function truthy(value) {
  return value === true || value === "true" || value === 1 || value === "1";
}

function requiredString(value, field) {
  if (typeof value !== "string" || value.trim() === "") {
    throw runtimeError({
      status: 400,
      code: "runtime",
      message: `${field} is required.`,
      details: { field },
    });
  }
  return value;
}

function inputText(body) {
  if (typeof body.input === "string") return body.input;
  if (Array.isArray(body.input)) return body.input.map((item) => String(item)).join("\n");
  if (typeof body.prompt === "string") return body.prompt;
  if (Array.isArray(body.messages)) {
    return body.messages
      .map((message) => `${message.role ?? "user"}: ${message.content ?? ""}`)
      .join("\n");
  }
  return JSON.stringify(body);
}

function deterministicOutput({ kind, input, modelId }) {
  const digest = stableHash(input).slice(0, 12);
  if (kind === "embeddings") return `embedding:${modelId}:${digest}`;
  if (kind === "rerank") return `rerank:${modelId}:${digest}`;
  return `IOI model router fixture response from ${modelId}. input_hash=${digest}`;
}

function estimateTokens(input, output) {
  const inputTokens = Math.max(1, Math.ceil(String(input).length / 4));
  const outputTokens = Math.max(1, Math.ceil(String(output).length / 4));
  return {
    prompt_tokens: inputTokens,
    completion_tokens: outputTokens,
    total_tokens: inputTokens + outputTokens,
  };
}

function deterministicVector(input) {
  const digest = crypto.createHash("sha256").update(input).digest();
  return Array.from({ length: 8 }, (_, index) => Number(((digest[index] / 255) * 2 - 1).toFixed(6)));
}

function inspectLocalArtifact(sourcePath) {
  const absolutePath = path.resolve(String(sourcePath));
  if (!fs.existsSync(absolutePath)) {
    throw notFound(`Local model artifact path not found: ${sourcePath}`, { sourcePath: absolutePath });
  }
  const stats = fs.statSync(absolutePath);
  const filePath = stats.isDirectory() ? firstModelFile(absolutePath) : absolutePath;
  const fileStats = fs.statSync(filePath);
  return {
    path: filePath,
    sizeBytes: fileStats.size,
    checksum: fileSha256(filePath),
  };
}

function firstModelFile(dir) {
  const candidates = fs
    .readdirSync(dir)
    .map((file) => path.join(dir, file))
    .filter((filePath) => fs.statSync(filePath).isFile())
    .sort((left, right) => {
      const leftScore = modelFileScore(left);
      const rightScore = modelFileScore(right);
      if (leftScore !== rightScore) return rightScore - leftScore;
      return left.localeCompare(right);
    });
  if (candidates.length === 0) {
    throw notFound(`No model artifact files found in ${dir}`, { dir });
  }
  return candidates[0];
}

function modelFileScore(filePath) {
  const name = path.basename(filePath).toLowerCase();
  if (name.endsWith(".gguf")) return 3;
  if (name.endsWith(".safetensors")) return 2;
  if (name.endsWith(".onnx") || name.endsWith(".bin")) return 1;
  return 0;
}

function parseLocalModelMetadata(filePath) {
  const name = path.basename(String(filePath));
  const lower = name.toLowerCase();
  const format = lower.endsWith(".gguf")
    ? "gguf"
    : lower.endsWith(".safetensors")
      ? "safetensors"
      : lower.endsWith(".onnx")
        ? "onnx"
        : null;
  const quantization =
    name.match(/\b(Q[0-9]_[A-Za-z0-9_]+|Q[0-9]+|F16|BF16|IQ[0-9]_[A-Za-z0-9_]+)\b/)?.[1] ?? null;
  let text = "";
  try {
    const fd = fs.openSync(filePath, "r");
    const buffer = Buffer.alloc(Math.min(4096, fs.statSync(filePath).size));
    fs.readSync(fd, buffer, 0, buffer.length, 0);
    fs.closeSync(fd);
    text = buffer.toString("utf8");
  } catch {
    text = "";
  }
  const family =
    text.match(/family=([^\n\r]+)/)?.[1]?.trim() ??
    lower.replace(/\.(gguf|safetensors|onnx|bin)$/i, "").split(/[._-]+/).filter(Boolean).slice(0, 3).join("-");
  const contextWindow = Number(text.match(/context(?:Window)?=([0-9]+)/i)?.[1] ?? 0) || null;
  return {
    format,
    family: family || null,
    quantization,
    contextWindow,
  };
}

function hardwareSnapshot() {
  return {
    cpuCount: os.cpus().length,
    totalMemoryBytes: os.totalmem(),
    freeMemoryBytes: os.freemem(),
    platform: os.platform(),
    arch: os.arch(),
    nvidiaSmi: commandProbe("nvidia-smi", ["--query-gpu=name,memory.total", "--format=csv,noheader"]),
    vulkanInfo: commandProbe("vulkaninfo", ["--summary"]),
    memoryPressure: os.freemem() / Math.max(1, os.totalmem()) < 0.15 ? "high" : "normal",
  };
}

function commandProbe(command, args) {
  const executable = findExecutable(command);
  if (!executable) return { available: false };
  const result = runPublicCommand(executable, args, { timeout: 1200 });
  return {
    available: result.status === 0,
    path: executable,
    exitCode: result.status,
    outputHash: stableHash(`${result.stdout}\n${result.stderr}`),
  };
}

function findExecutable(command) {
  if (!command) return null;
  if (command.includes(path.sep) && isExecutable(command)) return command;
  for (const dir of String(process.env.PATH ?? "").split(path.delimiter).filter(Boolean)) {
    const candidate = path.join(dir, command);
    if (isExecutable(candidate)) return candidate;
  }
  return null;
}

function listFiles(dir, suffix) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .map((file) => path.join(dir, file))
    .filter((filePath) => fs.statSync(filePath).isFile() && (!suffix || filePath.endsWith(suffix)))
    .sort();
}

function readLines(filePath) {
  if (!fs.existsSync(filePath)) return [];
  return fs.readFileSync(filePath, "utf8").split(/\r?\n/).filter(Boolean);
}

function estimateNativeLocalResources(artifact) {
  const sizeBytes = Number(artifact.sizeBytes ?? 0);
  const contextWindow = Number(artifact.contextWindow ?? 8192);
  return {
    sizeBytes,
    contextWindow,
    estimatedVramBytes: Math.max(sizeBytes, 64 * 1024 * 1024) + Math.min(contextWindow, 32768) * 1024,
    backend: "autopilot.native_local.fixture",
    realInference: false,
  };
}

function fileSha256(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return `sha256:${hash.digest("hex")}`;
}

function matchesAny(scope, patterns) {
  return patterns.some((pattern) => {
    if (pattern === scope) return true;
    if (pattern.endsWith("*")) return scope.startsWith(pattern.slice(0, -1));
    return false;
  });
}

function publicToken(token) {
  return {
    id: token.id,
    audience: token.audience,
    allowed: token.allowed,
    denied: token.denied,
    expiresAt: token.expiresAt,
    revocationEpoch: token.revocationEpoch,
    grantId: token.grantId,
    createdAt: token.createdAt,
    revokedAt: token.revokedAt,
    lastUsedAt: token.lastUsedAt ?? null,
    lastUsedScope: token.lastUsedScope ?? null,
    vaultRefs: publicVaultRefs(token.vaultRefs ?? {}),
    auditReceiptIds: Array.isArray(token.auditReceiptIds) ? token.auditReceiptIds : [],
    receiptId: token.receiptId,
  };
}

function publicMcpServer(server) {
  return {
    ...server,
    secretRefs: Object.fromEntries(
      Object.entries(server.secretRefs ?? {}).map(([key, vaultRef]) => [
        key,
        typeof vaultRef === "string" && vaultRef.startsWith("vault://")
          ? { redacted: true, hash: stableHash(vaultRef) }
          : SECRET_REDACTION,
      ]),
    ),
    redactedHeaders: Object.fromEntries(Object.keys(server.redactedHeaders ?? {}).map((key) => [key, SECRET_REDACTION])),
  };
}

function hashToken(tokenValue) {
  return crypto.createHash("sha256").update(tokenValue).digest("hex");
}

function stableHash(value) {
  return crypto.createHash("sha256").update(stableStringify(value)).digest("hex");
}

function stableStringify(value) {
  if (typeof value === "string") return value;
  if (!value || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableStringify(value[key])}`)
    .join(",")}}`;
}

function operationCount(stateDir) {
  const logPath = path.join(stateDir, "operation-log.jsonl");
  if (!fs.existsSync(logPath)) return 0;
  const text = fs.readFileSync(logPath, "utf8").trim();
  return text ? text.split(/\n/).length : 0;
}

function redact(value) {
  if (typeof value === "string" && value.startsWith("vault://")) return SECRET_REDACTION;
  if (!value || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(redact);
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [
      key,
      shouldRedactKey(key) ? SECRET_REDACTION : redact(item),
    ]),
  );
}

function shouldRedactKey(key) {
  if (["tokenCount", "toolReceiptIds", "input_tokens", "output_tokens", "total_tokens"].includes(key)) {
    return false;
  }
  return /tokenHash|tokenValue|secret|apiKey|authorization|header|privateKey|accessToken|refreshToken/i.test(key);
}

function safeId(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9]+/g, ".").replace(/^\.+|\.+$/g, "") || "item";
}

function safeFileName(value) {
  return String(value).replace(/[^a-z0-9._-]+/gi, "_");
}

function isExecutable(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function writeJson(filePath, value) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function listJson(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((file) => file.endsWith(".json"))
    .map((file) => path.join(dir, file));
}

function notFound(message, details) {
  return runtimeError({ status: 404, code: "not_found", message, details });
}

function runtimeError({ status, code, message, details }) {
  const error = new Error(message);
  error.status = status;
  error.code = code;
  error.details = details;
  return error;
}
