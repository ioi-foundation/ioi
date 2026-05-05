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
      "backend-processes",
      "model-downloads",
      "runtime-preferences",
      "runtime-engine-profiles",
      "provider-health",
      "models",
      "backend-logs",
      "server-logs",
      "projections",
      "lifecycle-events",
      "tokens",
      "vault-refs",
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

class EncryptedKeychainVaultMaterialAdapter {
  constructor({ filePath, keyMaterial, now }) {
    this.filePath = filePath ? path.resolve(filePath) : null;
    this.keyMaterial = keyMaterial ?? "";
    this.now = now;
  }

  get configured() {
    return Boolean(this.filePath && this.keyMaterial);
  }

  get requested() {
    return Boolean(this.filePath || this.keyMaterial);
  }

  bind(vaultRef, material, { purpose = "provider.auth", label = null } = {}) {
    this.assertConfigured();
    const store = this.readStore();
    const vaultRefHash = stableHash(vaultRef);
    const encrypted = this.encrypt(material);
    store.refs[vaultRefHash] = {
      schemaVersion: "ioi.keychain-vault.adapter.v1",
      vaultRefHash,
      label,
      purpose,
      updatedAt: this.now().toISOString(),
      material: encrypted,
    };
    this.writeStore(store);
    return {
      materialSource: "encrypted_keychain_vault_adapter",
      evidenceRefs: ["VaultMaterialAdapter.encryptedKeychain.bind", `vault_ref_${vaultRefHash.slice(0, 16)}`],
    };
  }

  resolve(vaultRef) {
    this.assertConfigured();
    const store = this.readStore();
    const vaultRefHash = stableHash(vaultRef);
    const record = store.refs[vaultRefHash];
    if (!record?.material) {
      return {
        material: null,
        materialSource: "encrypted_keychain_vault_adapter",
        evidenceRefs: ["VaultMaterialAdapter.encryptedKeychain.resolve_missing", `vault_ref_${vaultRefHash.slice(0, 16)}`],
      };
    }
    return {
      material: this.decrypt(record.material),
      materialSource: "encrypted_keychain_vault_adapter",
      evidenceRefs: ["VaultMaterialAdapter.encryptedKeychain.resolve", `vault_ref_${vaultRefHash.slice(0, 16)}`],
    };
  }

  remove(vaultRef) {
    this.assertConfigured();
    const store = this.readStore();
    const vaultRefHash = stableHash(vaultRef);
    const removed = Boolean(store.refs[vaultRefHash]);
    delete store.refs[vaultRefHash];
    this.writeStore(store);
    return {
      removed,
      materialSource: "encrypted_keychain_vault_adapter",
      evidenceRefs: ["VaultMaterialAdapter.encryptedKeychain.remove", `vault_ref_${vaultRefHash.slice(0, 16)}`],
    };
  }

  status() {
    return {
      implementation: "encrypted_keychain_vault_adapter",
      configured: this.configured,
      requested: this.requested,
      failClosed: this.requested && !this.configured,
      pathHash: this.filePath ? stableHash(this.filePath) : null,
      keyConfigured: Boolean(this.keyMaterial),
      plaintextPersistence: false,
      evidenceRefs: ["VaultMaterialAdapter.encryptedKeychain", "wallet.network.remote_adapter_boundary"],
    };
  }

  health() {
    const status = this.status();
    const result = {
      ...status,
      status: this.configured ? "healthy" : "unavailable",
      readAvailable: false,
      writeAvailable: false,
      checkedAt: this.now().toISOString(),
      evidenceRefs: [...status.evidenceRefs, "VaultMaterialAdapter.encryptedKeychain.health"],
    };
    this.assertConfigured();
    const store = this.readStore();
    result.readAvailable = true;
    this.writeStore(store);
    result.writeAvailable = true;
    return result;
  }

  readStore() {
    this.assertConfigured();
    if (!fs.existsSync(this.filePath)) return { schemaVersion: "ioi.keychain-vault.adapter.v1", refs: {} };
    try {
      const parsed = readJson(this.filePath);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid keychain document");
      return { schemaVersion: parsed.schemaVersion ?? "ioi.keychain-vault.adapter.v1", refs: parsed.refs && typeof parsed.refs === "object" ? parsed.refs : {} };
    } catch (error) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "Vault material adapter is configured but unavailable.",
        details: { adapter: "encrypted_keychain_vault_adapter", pathHash: stableHash(this.filePath), error: String(error?.message ?? error) },
      });
    }
  }

  writeStore(store) {
    this.assertConfigured();
    try {
      writeJson(this.filePath, store);
    } catch (error) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "Vault material adapter is configured but unavailable.",
        details: { adapter: "encrypted_keychain_vault_adapter", pathHash: stableHash(this.filePath), error: String(error?.message ?? error) },
      });
    }
  }

  assertConfigured() {
    if (!this.configured) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "Vault material adapter is configured but unavailable.",
        details: {
          adapter: "encrypted_keychain_vault_adapter",
          pathConfigured: Boolean(this.filePath),
          keyConfigured: Boolean(this.keyMaterial),
        },
      });
    }
  }

  encrypt(material) {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", this.key(), iv);
    const ciphertext = Buffer.concat([cipher.update(String(material), "utf8"), cipher.final()]);
    const tag = cipher.getAuthTag();
    return {
      algorithm: "aes-256-gcm",
      iv: iv.toString("base64url"),
      ciphertext: ciphertext.toString("base64url"),
      tag: tag.toString("base64url"),
    };
  }

  decrypt(payload) {
    try {
      const decipher = crypto.createDecipheriv("aes-256-gcm", this.key(), Buffer.from(payload.iv, "base64url"));
      decipher.setAuthTag(Buffer.from(payload.tag, "base64url"));
      return Buffer.concat([decipher.update(Buffer.from(payload.ciphertext, "base64url")), decipher.final()]).toString("utf8");
    } catch (error) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "Vault material adapter could not decrypt the configured secret.",
        details: { adapter: "encrypted_keychain_vault_adapter", error: String(error?.message ?? error) },
      });
    }
  }

  key() {
    return crypto.createHash("sha256").update(String(this.keyMaterial)).digest();
  }
}

class AgentgresVaultPort {
  constructor({ now, appendOperation, secrets = {}, metadata = [], materialAdapter = null }) {
    this.now = now;
    this.appendOperation = appendOperation;
    this.materialAdapter = materialAdapter;
    this.secrets = new Map(Object.entries(secrets ?? {}).map(([vaultRef, material]) => [vaultRef, String(material)]));
    this.metadata = new Map();
    this.loadMetadata(metadata);
    for (const vaultRef of this.secrets.keys()) {
      const hash = this.vaultRefHash(vaultRef);
      if (this.metadata.has(hash)) continue;
      this.metadata.set(
        hash,
        this.metadataRecord(vaultRef, {
          purpose: "bootstrap",
          source: "in_memory_fixture",
          createdAt: this.now().toISOString(),
          updatedAt: this.now().toISOString(),
          configured: true,
        }),
      );
    }
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
    const materialResult = this.materialFor(vaultRef);
    const material = materialResult.material;
    const result = {
      vaultRefHash: stableHash(vaultRef),
      resolvedMaterial: typeof material === "string" && material.length > 0,
      purpose,
      materialSource: materialResult.materialSource,
      evidenceRefs: ["VaultPort.resolveVaultRef", `vault_ref_${stableHash(vaultRef).slice(0, 16)}`, ...normalizeScopes(materialResult.evidenceRefs, [])],
    };
    const existing = this.metadataForVaultRef(vaultRef);
    if (existing) {
      this.metadata.set(result.vaultRefHash, {
        ...existing,
        lastResolvedAt: this.now().toISOString(),
        resolvedMaterial: result.resolvedMaterial,
        runtimeBound: result.resolvedMaterial,
        materialSource: result.materialSource,
        requiresRebind: Boolean(existing.configured) && !result.resolvedMaterial,
      });
    }
    this.auditEvent("vault.resolve", {
      objectId: vaultRef,
      purpose,
      vaultRefHash: result.vaultRefHash,
      resolvedMaterial: result.resolvedMaterial,
      materialSource: result.materialSource,
    });
    return { ...result, material: result.resolvedMaterial ? material : null };
  }

  materialFor(vaultRef) {
    const vaultRefHash = stableHash(vaultRef);
    if (this.secrets.has(vaultRef)) {
      return {
        material: this.secrets.get(vaultRef),
        materialSource: "runtime_memory",
        evidenceRefs: ["VaultMaterialAdapter.runtimeMemory", `vault_ref_${vaultRefHash.slice(0, 16)}`],
      };
    }
    const envName = vaultRefEnvironmentAlias(vaultRef);
    if (envName && process.env[envName]) {
      return {
        material: process.env[envName],
        materialSource: "environment_alias",
        evidenceRefs: ["VaultMaterialAdapter.environmentAlias", envName, `vault_ref_${vaultRefHash.slice(0, 16)}`],
      };
    }
    const adapterResult = this.materialAdapter?.resolve(vaultRef);
    if (adapterResult) return adapterResult;
    return {
      material: null,
      materialSource: "unbound",
      evidenceRefs: ["VaultMaterialAdapter.unbound", `vault_ref_${vaultRefHash.slice(0, 16)}`],
    };
  }

  bindVaultRef({ vaultRef, material, purpose = "operator_binding", label = null }) {
    this.assertVaultRef(vaultRef);
    if (typeof material !== "string" || material.length === 0) {
      throw runtimeError({
        status: 400,
        code: "validation",
        message: "Vault material is required for local vault binding.",
        details: { vaultRef: SECRET_REDACTION, material: SECRET_REDACTION },
      });
    }
    const now = this.now().toISOString();
    const adapterBind = this.materialAdapter?.bind(vaultRef, material, { purpose, label });
    if (!adapterBind) {
      this.secrets.set(vaultRef, material);
    }
    const existing = this.metadataForVaultRef(vaultRef);
    const metadata = this.metadataRecord(vaultRef, {
      purpose,
      label,
      source: existing?.source ?? "agentgres_local_vault_metadata",
      materialSource: adapterBind?.materialSource ?? "runtime_memory",
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      lastResolvedAt: existing?.lastResolvedAt ?? null,
      configured: true,
      resolvedMaterial: true,
      evidenceRefs: adapterBind?.evidenceRefs,
    });
    this.metadata.set(metadata.vaultRefHash, metadata);
    this.auditEvent("vault.bind", {
      objectId: vaultRef,
      purpose,
      vaultRefHash: metadata.vaultRefHash,
      materialBound: true,
      material: SECRET_REDACTION,
    });
    return publicVaultRefMetadata(metadata);
  }

  removeVaultRef(vaultRef, purpose = "operator_remove") {
    this.assertVaultRef(vaultRef);
    const existed = this.secrets.delete(vaultRef);
    const adapterRemove = this.materialAdapter?.remove(vaultRef);
    const existing = this.metadataForVaultRef(vaultRef);
    const now = this.now().toISOString();
    const metadata = this.metadataRecord(vaultRef, {
      purpose: existing?.purpose ?? purpose,
      label: existing?.label ?? null,
      source: existing?.source ?? "agentgres_local_vault_metadata",
      materialSource: adapterRemove?.materialSource ?? "unbound",
      createdAt: existing?.createdAt ?? now,
      updatedAt: now,
      lastResolvedAt: existing?.lastResolvedAt ?? null,
      removedAt: now,
      configured: false,
      resolvedMaterial: false,
    });
    this.metadata.set(metadata.vaultRefHash, metadata);
    this.auditEvent("vault.remove", {
      objectId: vaultRef,
      purpose,
      vaultRefHash: metadata.vaultRefHash,
      materialBound: false,
      existed: existed || Boolean(adapterRemove?.removed),
    });
    return publicVaultRefMetadata(metadata);
  }

  listVaultRefs() {
    return [...this.metadata.values()].map(publicVaultRefMetadata).sort((left, right) => left.vaultRefHash.localeCompare(right.vaultRefHash));
  }

  vaultRefMetadata(vaultRef) {
    this.assertVaultRef(vaultRef);
    const existing = this.metadataForVaultRef(vaultRef);
    if (existing) return publicVaultRefMetadata(existing);
    return publicVaultRefMetadata(
      this.metadataRecord(vaultRef, {
        purpose: "lookup",
        source: "none",
        createdAt: null,
        updatedAt: null,
        configured: false,
      }),
    );
  }

  loadMetadata(records = []) {
    for (const record of records) {
      const vaultRefHash = record?.vaultRefHash ?? record?.id?.replace(/^vault_ref\./, "");
      if (!vaultRefHash || typeof vaultRefHash !== "string") continue;
      const sanitized = this.metadataRecord(vaultRefHash, {
        ...record,
        vaultRefHash,
        source: record.source ?? "agentgres_local_vault_metadata",
        resolvedMaterial: false,
        runtimeBound: false,
        materialBound: false,
        requiresRebind: Boolean(record.configured),
      });
      this.metadata.set(vaultRefHash, sanitized);
    }
  }

  metadataRecords() {
    return [...this.metadata.values()].map((record) => {
      const publicRecord = publicVaultRefMetadata(record);
      return {
        id: `vault_ref.${record.vaultRefHash}`,
        vaultRefHash: record.vaultRefHash,
        label: publicRecord.label,
        purpose: publicRecord.purpose,
        source: "agentgres_local_vault_metadata",
        materialSource: record.materialSource === "runtime_memory" ? "runtime_memory_not_persisted" : (record.materialSource ?? "unbound"),
        configured: publicRecord.configured,
        resolvedMaterial: false,
        runtimeBound: false,
        materialBound: false,
        requiresRebind: publicRecord.configured,
        createdAt: publicRecord.createdAt,
        updatedAt: publicRecord.updatedAt,
        removedAt: publicRecord.removedAt,
        lastResolvedAt: publicRecord.lastResolvedAt,
        evidenceRefs: publicRecord.evidenceRefs,
      };
    });
  }

  metadataForVaultRef(vaultRef) {
    return this.metadata.get(this.vaultRefHash(vaultRef));
  }

  metadataRecord(vaultRef, fields = {}) {
    const vaultRefHash = fields.vaultRefHash ?? (String(vaultRef).startsWith("vault://") ? stableHash(vaultRef) : String(vaultRef));
    const resolvedMaterial = Boolean(fields.resolvedMaterial ?? (String(vaultRef).startsWith("vault://") && this.secrets.has(vaultRef)));
    const configured = Boolean(fields.configured ?? resolvedMaterial);
    return {
      vaultRefHash,
      label: fields.label ?? null,
      purpose: fields.purpose ?? "provider.auth",
      source: fields.source ?? "agentgres_local_vault_metadata",
      materialSource: fields.materialSource ?? (resolvedMaterial ? "runtime_memory" : "unbound"),
      configured,
      resolvedMaterial,
      runtimeBound: Boolean(fields.runtimeBound ?? resolvedMaterial),
      materialBound: Boolean(fields.materialBound ?? resolvedMaterial),
      requiresRebind: Boolean(fields.requiresRebind ?? (configured && !resolvedMaterial)),
      createdAt: fields.createdAt ?? null,
      updatedAt: fields.updatedAt ?? null,
      removedAt: fields.removedAt ?? null,
      lastResolvedAt: fields.lastResolvedAt ?? null,
      evidenceRefs: normalizeScopes(fields.evidenceRefs, ["VaultPort.localBinding", "agentgres_local_vault_metadata", `vault_ref_${vaultRefHash.slice(0, 16)}`]),
    };
  }

  vaultRefHash(vaultRef) {
    this.assertVaultRef(vaultRef);
    return stableHash(vaultRef);
  }

  assertVaultRef(vaultRef) {
    if (typeof vaultRef !== "string" || !vaultRef.startsWith("vault://")) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "Vault material must be referenced through wallet.network vault refs.",
        details: { vaultRef: SECRET_REDACTION },
      });
    }
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
      methods: ["bindVaultRef", "resolveVaultRef", "listVaultRefs", "vaultRefMetadata", "removeVaultRef"],
      remoteAdapter: process.env.IOI_WALLET_NETWORK_URL
        ? { configured: true, urlHash: stableHash(process.env.IOI_WALLET_NETWORK_URL) }
        : { configured: false, failClosed: true },
      materialSources: {
        runtimeBoundCount: this.secrets.size,
        durableMetadataCount: this.metadata.size,
        environmentAliases: ["OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GEMINI_API_KEY", "IOI_CUSTOM_MODEL_API_KEY"],
        plaintextPersistence: false,
      },
      materialAdapter: this.materialAdapter?.status() ?? {
        implementation: "runtime_memory",
        configured: false,
        plaintextPersistence: false,
        evidenceRefs: ["VaultMaterialAdapter.runtimeMemory"],
      },
      evidenceRefs: ["wallet.network.vault_ref_boundary", "provider_request_time_secret_resolution"],
    };
  }

  health() {
    const status = this.adapterStatus();
    const adapterHealth = this.materialAdapter?.health() ?? {
      implementation: "runtime_memory",
      configured: false,
      requested: false,
      failClosed: false,
      status: "session_only",
      readAvailable: true,
      writeAvailable: true,
      plaintextPersistence: false,
      checkedAt: this.now().toISOString(),
      evidenceRefs: ["VaultMaterialAdapter.runtimeMemory.health"],
    };
    return {
      port: "VaultPort",
      implementation: status.implementation,
      status: adapterHealth.status,
      materialAdapter: adapterHealth,
      materialSources: status.materialSources,
      remoteAdapter: status.remoteAdapter,
      evidenceRefs: ["VaultPort.health", ...normalizeScopes(adapterHealth.evidenceRefs, [])],
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

  async load({ state, endpoint, body = {} }) {
    const artifact = state.getModel(endpoint.modelId);
    const estimate = estimateNativeLocalResources(artifact);
    const backendId = endpoint.backendId ?? "backend.autopilot.native-local.fixture";
    const loadOptions = normalizeLoadOptions(body.load_options ?? body.loadOptions ?? body, endpoint.loadPolicy);
    const processRecord = state.ensureBackendProcess(backendId, {
      endpoint,
      loadOptions,
      reason: "model_load",
    });
    const processSnapshot = state.backendProcessSnapshot(processRecord);
    state.writeBackendLog(endpoint.id, {
      backendId,
      event: "load",
      modelId: endpoint.modelId,
      estimate,
      loadOptions,
      backend: "autopilot.native_local.fixture",
      processId: processRecord?.id ?? null,
      pidHash: processRecord?.pidHash ?? null,
      argsHash: processRecord?.argsHash ?? null,
    });
    return {
      backend: "autopilot.native_local.fixture",
      backendId,
      driver: "native_local",
      status: "loaded",
      estimate,
      process: processSnapshot,
      evidenceRefs: [
        "autopilot_native_local_backend_registry",
        "autopilot_native_local_process_supervisor",
        "deterministic_native_local_fixture",
        ...normalizeScopes(processSnapshot.evidenceRefs, []),
      ],
    };
  }

  async unload({ state, endpoint }) {
    const backendId = endpoint.backendId ?? "backend.autopilot.native-local.fixture";
    const processRecord = state.backendProcessForBackend(backendId);
    state.writeBackendLog(endpoint.id, {
      backendId,
      event: "unload",
      modelId: endpoint.modelId,
      backend: "autopilot.native_local.fixture",
      processId: processRecord?.id ?? null,
      pidHash: processRecord?.pidHash ?? null,
    });
    return {
      driver: "native_local",
      status: "unloaded",
      backend: "autopilot.native_local.fixture",
      backendId,
      process: state.backendProcessSnapshot(processRecord),
      evidenceRefs: ["autopilot_native_local_process_supervisor", "deterministic_native_local_fixture"],
    };
  }

  async invoke({ kind, input, endpoint, state }) {
    const backendId = endpoint.backendId ?? "backend.autopilot.native-local.fixture";
    const processRecord = state.ensureBackendProcess(backendId, {
      endpoint,
      loadOptions: state.loadedInstanceForEndpoint(endpoint.id, false)?.loadOptions ?? {},
      reason: "model_invoke",
    });
    const processSnapshot = state.backendProcessSnapshot(processRecord);
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
      processId: processRecord?.id ?? null,
      pidHash: processRecord?.pidHash ?? null,
    });
    return {
      outputText,
      tokenCount: estimateTokens(input, outputText),
      providerResponse: null,
      providerResponseKind: "native_local",
      backend: "autopilot.native_local.fixture",
      backendId,
      backendProcess: processSnapshot,
      backendEvidenceRefs: [
        "autopilot_native_local_openai_compatible_serving",
        "deterministic_native_local_fixture",
        ...normalizeScopes(processSnapshot.evidenceRefs, []),
      ],
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
        providerAuthHeaderNames: result.authEvidence?.headerNames ?? [],
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
          providerAuthHeaderNames: result.authEvidence?.headerNames ?? [],
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
      providerAuthHeaderNames: result.authEvidence?.headerNames ?? [],
    };
  }
}

class VllmModelProviderDriver {
  constructor({ state }) {
    this.state = state;
    this.openAi = new OpenAICompatibleModelProviderDriver({ label: "vllm" });
  }

  providerWithBackendBaseUrl(provider) {
    const backend = this.state.backend(defaultBackendForProvider(provider));
    return {
      ...provider,
      baseUrl: provider.baseUrl ?? backend.baseUrl,
      status: provider.status === "blocked" && (backend.binaryPath || backend.baseUrl) ? "configured" : provider.status,
    };
  }

  async health(provider, { state } = {}) {
    const effectiveProvider = this.providerWithBackendBaseUrl(provider);
    const result = await this.openAi.health(effectiveProvider, { state });
    const backend = state.backend(defaultBackendForProvider(provider));
    return {
      ...result,
      status: result.status === "available" ? "available" : backend.binaryPath ? "degraded" : result.status,
      evidenceRefs: [
        "vllm_openai_compatible_models_probe",
        ...(result.evidenceRefs ?? []),
        ...(backend.binaryPath ? ["vllm_binary_configured"] : []),
      ],
      binaryPathHash: backend.binaryPath ? stableHash(backend.binaryPath) : null,
    };
  }

  async listModels({ state, provider }) {
    const effectiveProvider = this.providerWithBackendBaseUrl(provider);
    const models = await this.openAi.listModels({ state, provider: effectiveProvider });
    return models.map((model) => ({
      ...model,
      providerId: provider.id,
      family: "vllm",
      source: "vllm_openai_compatible_models_endpoint",
      compatibility: ["vllm", "safetensors", "hf_repository"],
    }));
  }

  async listLoaded({ state, provider }) {
    const backendId = defaultBackendForProvider(provider);
    return state
      .listInstances()
      .filter((instance) => instance.providerId === provider.id && instance.status === "loaded")
      .map((instance) => ({
        ...instance,
        backend: "vllm",
        backendId,
        backendProcess: state.backendProcessSnapshot(state.backendProcessForBackend(backendId)),
        evidenceRefs: ["vllm_agentgres_loaded_instance_projection"],
      }));
  }

  async load({ state, provider, endpoint, body = {} }) {
    const loadOptions = normalizeLoadOptions(body.load_options ?? body.loadOptions ?? body, endpoint.loadPolicy);
    const backendId = endpoint.backendId ?? defaultBackendForProvider(provider);
    const backend = state.backend(backendId);
    const processRecord =
      provider.id === "provider.vllm" && backend.binaryPath
        ? state.ensureBackendProcess(backendId, { endpoint, loadOptions, reason: "vllm_model_load" })
        : null;
    return {
      status: "loaded",
      backend: "vllm",
      backendId,
      process: state.backendProcessSnapshot(processRecord),
      evidenceRefs: [
        ...(processRecord ? ["vllm_process_supervisor", "vllm_openai_compatible_server"] : ["vllm_stateless_http_load"]),
      ],
    };
  }

  async unload({ state, provider, endpoint }) {
    const backendId = endpoint?.backendId ?? defaultBackendForProvider(provider);
    const backend = state.backend(backendId);
    const stopped = provider.id === "provider.vllm" && backend.binaryPath ? state.stopBackendProcess(backend, { reason: "vllm_model_unload" }) : null;
    const processSnapshot = state.backendProcessSnapshot(stopped);
    return {
      status: "unloaded",
      backend: "vllm",
      backendId,
      process: processSnapshot,
      evidenceRefs: [
        ...(stopped ? ["vllm_process_supervisor", "clean_backend_stop", ...normalizeScopes(processSnapshot.evidenceRefs, [])] : ["vllm_stateless_http_unload"]),
      ],
    };
  }

  async invoke(args) {
    const provider = this.providerWithBackendBaseUrl(args.provider);
    const backendId = args.endpoint?.backendId ?? defaultBackendForProvider(provider);
    const backend = args.state.backend(backendId);
    const processRecord =
      provider.id === "provider.vllm" && backend.binaryPath
        ? args.state.ensureBackendProcess(backendId, {
            endpoint: args.endpoint,
            loadOptions: args.instance?.loadOptions ?? {},
            reason: "vllm_model_invoke",
          })
        : null;
    const processSnapshot = args.state.backendProcessSnapshot(processRecord);
    const result = await this.openAi.invoke({ ...args, provider, allowResponsesFallback: true });
    return {
      ...result,
      backend: "vllm",
      backendId,
      backendProcess: processSnapshot,
      backendEvidenceRefs: [
        "vllm_openai_compatible_server",
        ...(processRecord ? ["vllm_process_supervisor", ...normalizeScopes(processSnapshot.evidenceRefs, [])] : []),
        ...(result.backendEvidenceRefs ?? []),
      ],
    };
  }
}

class LlamaCppModelProviderDriver {
  constructor({ state }) {
    this.state = state;
    this.openAi = new OpenAICompatibleModelProviderDriver({ label: "llama_cpp" });
  }

  providerWithBackendBaseUrl(provider) {
    const backend = this.state.backend(defaultBackendForProvider(provider));
    return {
      ...provider,
      baseUrl: provider.baseUrl ?? backend.baseUrl,
      status: provider.status === "blocked" && (backend.binaryPath || backend.baseUrl) ? "configured" : provider.status,
    };
  }

  async health(provider, { state } = {}) {
    const effectiveProvider = this.providerWithBackendBaseUrl(provider);
    const backend = state.backend(defaultBackendForProvider(provider));
    if (!effectiveProvider.baseUrl) {
      return {
        status: backend.binaryPath ? "configured" : "blocked",
        evidenceRefs: ["llama_cpp_binary_configured_without_server_probe"],
      };
    }
    const result = await this.openAi.health(effectiveProvider, { state });
    return {
      ...result,
      status: result.status === "available" ? "available" : backend.binaryPath ? "degraded" : result.status,
      evidenceRefs: [
        "llama_cpp_openai_compatible_models_probe",
        ...(result.evidenceRefs ?? []),
        ...(backend.binaryPath ? ["llama_cpp_binary_configured"] : []),
      ],
      binaryPathHash: backend.binaryPath ? stableHash(backend.binaryPath) : null,
    };
  }

  async listModels({ state, provider }) {
    const effectiveProvider = this.providerWithBackendBaseUrl(provider);
    const models = await this.openAi.listModels({ state, provider: effectiveProvider });
    return models.map((model) => ({
      ...model,
      providerId: provider.id,
      family: "llama_cpp",
      source: "llama_cpp_openai_compatible_models_endpoint",
      compatibility: ["llama_cpp", "gguf"],
    }));
  }

  async listLoaded({ state, provider }) {
    const backendId = defaultBackendForProvider(provider);
    return state
      .listInstances()
      .filter((instance) => instance.providerId === provider.id && instance.status === "loaded")
      .map((instance) => ({
        ...instance,
        backend: "llama_cpp",
        backendId,
        backendProcess: state.backendProcessSnapshot(state.backendProcessForBackend(backendId)),
        evidenceRefs: ["llama_cpp_agentgres_loaded_instance_projection"],
      }));
  }

  async load({ state, provider, endpoint, body = {} }) {
    const loadOptions = normalizeLoadOptions(body.load_options ?? body.loadOptions ?? body, endpoint.loadPolicy);
    const backendId = endpoint.backendId ?? defaultBackendForProvider(provider);
    const processRecord = state.ensureBackendProcess(backendId, {
      endpoint,
      loadOptions,
      reason: "llama_cpp_model_load",
    });
    const processSnapshot = state.backendProcessSnapshot(processRecord);
    return {
      status: "loaded",
      backend: "llama_cpp",
      backendId,
      process: processSnapshot,
      evidenceRefs: [
        "llama_cpp_process_supervisor",
        "llama_cpp_openai_compatible_server",
        ...normalizeScopes(processSnapshot.evidenceRefs, []),
      ],
    };
  }

  async unload({ state, provider, endpoint }) {
    const backend = state.backend(endpoint?.backendId ?? defaultBackendForProvider(provider));
    const stopped = state.stopBackendProcess(backend, { reason: "llama_cpp_model_unload" });
    const processSnapshot = state.backendProcessSnapshot(stopped);
    return {
      status: "unloaded",
      backend: "llama_cpp",
      backendId: backend.id,
      process: processSnapshot,
      evidenceRefs: ["llama_cpp_process_supervisor", "clean_backend_stop", ...normalizeScopes(processSnapshot.evidenceRefs, [])],
    };
  }

  async invoke(args) {
    const provider = this.providerWithBackendBaseUrl(args.provider);
    const backendId = args.endpoint?.backendId ?? defaultBackendForProvider(provider);
    const processRecord = args.state.ensureBackendProcess(backendId, {
      endpoint: args.endpoint,
      loadOptions: args.instance?.loadOptions ?? {},
      reason: "llama_cpp_model_invoke",
    });
    const processSnapshot = args.state.backendProcessSnapshot(processRecord);
    const result = await this.openAi.invoke({ ...args, provider, allowResponsesFallback: true });
    return {
      ...result,
      backend: "llama_cpp",
      backendId,
      backendProcess: processSnapshot,
      backendEvidenceRefs: [
        "llama_cpp_openai_compatible_server",
        "llama_cpp_process_supervisor",
        ...normalizeScopes(processSnapshot.evidenceRefs, []),
        ...(result.backendEvidenceRefs ?? []),
      ],
    };
  }
}

class OllamaModelProviderDriver {
  async health(provider, { state } = {}) {
    const result = await fetchProviderJson(provider, "/api/tags", { method: "GET", tolerateHttpError: true, state });
    return {
      status: result.ok ? "available" : "degraded",
      evidenceRefs: ["ollama_api_tags_probe"],
      httpStatus: result.status,
    };
  }

  async listModels({ provider, state }) {
    const result = await fetchProviderJson(provider, "/api/tags", { method: "GET", tolerateHttpError: true, state });
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

  async listLoaded({ provider, state }) {
    const result = await fetchProviderJson(provider, "/api/ps", { method: "GET", tolerateHttpError: true, state });
    const backendId = defaultBackendForProvider(provider);
    if (result.ok) {
      const models = Array.isArray(result.body?.models) ? result.body.models : [];
      return models
        .map((model) => ({
          modelId: String(model.name ?? model.model ?? ""),
          sizeBytes: Number(model.size ?? 0) || null,
          processor: model.processor ?? null,
          until: model.expires_at ?? null,
        }))
        .filter((model) => model.modelId)
        .map((model) => ({
          id: `ollama.loaded.${safeId(model.modelId)}`,
          providerId: provider.id,
          modelId: model.modelId,
          displayName: model.modelId,
          backend: "ollama",
          backendId,
          sizeBytes: model.sizeBytes,
          processor: model.processor,
          until: model.until,
          backendProcess: state.backendProcessSnapshot(state.backendProcessForBackend(backendId)),
          evidenceRefs: ["ollama_api_ps_loaded_projection"],
        }));
    }
    return state
      .listInstances()
      .filter((instance) => instance.providerId === provider.id && instance.status === "loaded")
      .map((instance) => ({
        ...instance,
        backend: "ollama",
        backendId,
        backendProcess: state.backendProcessSnapshot(state.backendProcessForBackend(backendId)),
        evidenceRefs: ["ollama_agentgres_loaded_instance_projection"],
      }));
  }

  async load({ state, provider, endpoint, body = {} }) {
    const loadOptions = normalizeLoadOptions(body.load_options ?? body.loadOptions ?? body, endpoint.loadPolicy);
    const backendId = endpoint.backendId ?? defaultBackendForProvider(provider);
    const backend = state.backend(backendId);
    const processRecord =
      provider.id === "provider.ollama" && backend.binaryPath
        ? state.ensureBackendProcess(backendId, { endpoint, loadOptions, reason: "ollama_model_load" })
        : null;
    const generate = await fetchProviderJson(provider, "/api/generate", {
      method: "POST",
      body: {
        model: endpoint.modelId,
        prompt: "",
        stream: false,
        keep_alive: loadOptions.ttlSeconds ? `${loadOptions.ttlSeconds}s` : "5m",
      },
      tolerateHttpError: true,
      state,
    });
    return {
      status: "loaded",
      backend: "ollama",
      backendId,
      process: state.backendProcessSnapshot(processRecord),
      providerStatus: generate.ok ? "warmed" : "load_probe_degraded",
      evidenceRefs: [
        "ollama_generate_keep_alive_load",
        ...(processRecord ? ["ollama_process_supervisor"] : ["ollama_http_provider_load"]),
      ],
    };
  }

  async unload({ state, provider, endpoint }) {
    const backendId = endpoint?.backendId ?? defaultBackendForProvider(provider);
    const result = endpoint
      ? await fetchProviderJson(provider, "/api/generate", {
          method: "POST",
          body: { model: endpoint.modelId, prompt: "", stream: false, keep_alive: 0 },
          tolerateHttpError: true,
          state,
        })
      : { ok: false };
    return {
      status: "unloaded",
      backend: "ollama",
      backendId,
      providerStatus: result.ok ? "evicted" : "unload_probe_degraded",
      evidenceRefs: ["ollama_generate_keep_alive_zero_unload"],
    };
  }

  async invoke({ state, provider, endpoint, kind, body, input }) {
    if (kind === "embeddings") {
      const result = await fetchProviderJson(provider, "/api/embeddings", {
        method: "POST",
        body: { model: endpoint.modelId, prompt: Array.isArray(body.input) ? body.input.join("\n") : String(body.input ?? "") },
        state,
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
      state,
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
    this.bootId = `daemon_boot_${crypto.randomUUID()}`;
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
      materialAdapter: configuredVaultMaterialAdapter({ now: this.now }),
    });
    this.providers = new Map();
    this.backends = new Map();
    this.backendChildProcesses = new Map();
    this.backendProcesses = new Map();
    this.artifacts = new Map();
    this.endpoints = new Map();
    this.instances = new Map();
    this.routes = new Map();
    this.downloads = new Map();
    this.lastCatalogSearch = null;
    this.runtimeSelections = new Map();
    this.runtimeEngineProfiles = new Map();
    this.tokens = new Map();
    this.vaultRefs = new Map();
    this.mcpServers = new Map();
    this.ensureDirs();
    this.load();
    this.vault.loadMetadata([...this.vaultRefs.values()]);
    this.seedDefaults();
    this.writeAll();
  }

  close() {
    for (const [processId, child] of this.backendChildProcesses.entries()) {
      try {
        if (!child.killed) child.kill("SIGTERM");
      } catch {
        // Best-effort cleanup for subprocesses owned by this daemon boot.
      }
      this.backendChildProcesses.delete(processId);
    }
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
      modelBackendProcesses: [
        "id",
        "backendId",
        "backendKind",
        "status",
        "pidHash",
        "startedAt",
        "stoppedAt",
        "argsHash",
        "lastReceiptId",
      ],
      providerHealth: ["id", "providerId", "status", "checkedAt", "receiptId", "failureCode", "evidenceRefs"],
      runtimeEngines: ["id", "kind", "label", "status", "selected", "modelFormat", "source"],
      runtimeEngineProfiles: ["id", "engineId", "disabled", "priority", "defaultLoadOptions", "receiptId"],
      runtimePreferences: ["id", "selectedEngineId", "selectedAt", "receiptId", "defaultLoadOptions"],
      modelCatalogEntries: ["id", "providerId", "modelId", "format", "quantization", "sourceUrlHash", "license"],
      modelDownloads: ["id", "artifactId", "status", "source", "progress", "bytesTotal", "bytesCompleted", "targetPath"],
      modelCatalogProviders: ["id", "status", "gate", "formats", "baseUrlHash", "evidenceRefs"],
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
    this.loadMap("backend-processes", this.backendProcesses);
    this.loadMap("model-artifacts", this.artifacts);
    this.loadMap("model-endpoints", this.endpoints);
    this.loadMap("model-instances", this.instances);
    this.loadMap("model-routes", this.routes);
    this.loadMap("model-downloads", this.downloads);
    this.loadMap("runtime-preferences", this.runtimeSelections);
    this.loadMap("runtime-engine-profiles", this.runtimeEngineProfiles);
    this.loadMap("tokens", this.tokens);
    this.loadMap("vault-refs", this.vaultRefs);
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

    const vllmBinary = process.env.IOI_VLLM_BINARY ?? findExecutable("vllm");
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
        driver: "llama_cpp",
        baseUrl: process.env.IOI_LLAMA_CPP_BASE_URL ?? "http://127.0.0.1:8080/v1",
        status: process.env.IOI_LLAMA_CPP_BASE_URL || process.env.IOI_LLAMA_CPP_SERVER_PATH ? "configured" : "blocked",
        privacyClass: "local_private",
        capabilities: ["chat", "responses", "embeddings"],
        discovery: { checkedAt, evidenceRefs: ["IOI_LLAMA_CPP_BASE_URL", "IOI_LLAMA_CPP_SERVER_PATH"] },
      },
      {
        id: "provider.vllm",
        kind: "vllm",
        label: "vLLM",
        apiFormat: "openai_compatible",
        driver: "vllm",
        baseUrl: process.env.VLLM_BASE_URL ?? "http://127.0.0.1:8000/v1",
        status: process.env.VLLM_BASE_URL || vllmBinary ? "configured" : "blocked",
        privacyClass: "workspace",
        capabilities: ["chat", "responses", "embeddings"],
        discovery: { checkedAt, evidenceRefs: ["VLLM_BASE_URL", vllmBinary ? "vllm_binary_detected" : "IOI_VLLM_BINARY"] },
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
    this.writeMap("backend-processes", this.backendProcesses);
    this.writeMap("model-artifacts", this.artifacts);
    this.writeMap("model-endpoints", this.endpoints);
    this.writeMap("model-instances", this.instances);
    this.writeMap("model-routes", this.routes);
    this.writeMap("model-downloads", this.downloads);
    this.writeMap("runtime-preferences", this.runtimeSelections);
    this.writeMap("runtime-engine-profiles", this.runtimeEngineProfiles);
    this.writeMap("tokens", this.tokens);
    this.writeVaultRefs();
    this.writeMap("mcp-servers", this.mcpServers);
    this.writeProjection();
  }

  writeMap(dir, map) {
    this.store.writeMap(dir, map);
  }

  writeVaultRefs() {
    this.vaultRefs = new Map(this.vault.metadataRecords().map((record) => [record.id, record]));
    this.writeMap("vault-refs", this.vaultRefs);
  }

  serverStatus(baseUrl) {
    this.evictExpiredInstances();
    const runningInstances = [...this.instances.values()].filter((instance) => instance.status === "loaded");
    const degradedProviders = [...this.providers.values()].filter((provider) =>
      ["blocked", "absent", "stopped"].includes(provider.status),
    );
    const backends = this.listBackends();
    const controlState = this.serverControlState();
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      status: runningInstances.length > 0 ? "running" : "stopped",
      gatewayStatus: "running",
      controlStatus: controlState.status,
      lastServerOperation: controlState.operation,
      lastServerOperationAt: controlState.updatedAt,
      lastServerReceiptId: controlState.receiptId,
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

  serverControlState() {
    const statePath = path.join(this.stateDir, "server-state.json");
    if (fs.existsSync(statePath)) {
      return readJson(statePath);
    }
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      status: "running",
      gatewayStatus: "running",
      operation: "server_status",
      updatedAt: null,
      receiptId: null,
      evidenceRefs: ["ioi_daemon_public_runtime_api"],
    };
  }

  writeServerControlState(state) {
    writeJson(path.join(this.stateDir, "server-state.json"), state);
    return state;
  }

  serverStart(baseUrl) {
    return this.recordServerOperation("server_start", "running", baseUrl, {
      requestedAction: "start",
      compatibilitySurface: "lms server start",
    });
  }

  serverStop(baseUrl) {
    return this.recordServerOperation("server_stop", "stopped", baseUrl, {
      requestedAction: "stop",
      compatibilitySurface: "lms server stop",
      note: "The daemon process remains reachable so governed clients can restart the model gateway.",
    });
  }

  serverRestart(baseUrl) {
    const previousState = this.serverControlState();
    return this.recordServerOperation("server_restart", "running", baseUrl, {
      requestedAction: "restart",
      compatibilitySurface: "lms server start|stop",
      previousControlStatus: previousState.status,
      previousReceiptId: previousState.receiptId,
    });
  }

  recordServerOperation(operation, status, baseUrl, details = {}) {
    const occurredAt = this.nowIso();
    const receipt = this.lifecycleReceipt(operation, {
      modelId: "ioi-local-server",
      state: status,
      gatewayStatus: "running",
      nativeBaseUrl: baseUrl ? `${baseUrl}/api/v1` : "/api/v1",
      openAiCompatibleBaseUrl: baseUrl ? `${baseUrl}/v1` : "/v1",
      evidenceRefs: ["ioi_daemon_public_runtime_api", "server_log_ring_buffer", operation],
      ...details,
    });
    const state = this.writeServerControlState({
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      status,
      gatewayStatus: "running",
      operation,
      updatedAt: occurredAt,
      receiptId: receipt.id,
      evidenceRefs: ["ioi_daemon_public_runtime_api", "server_log_ring_buffer", operation],
    });
    const log = this.writeServerLog({
      event: operation,
      status,
      gatewayStatus: "running",
      receiptId: receipt.id,
      details,
    });
    return {
      ...this.serverStatus(baseUrl),
      controlStatus: state.status,
      lastServerOperation: operation,
      lastServerOperationAt: occurredAt,
      lastServerReceiptId: receipt.id,
      receiptId: receipt.id,
      logId: log.id,
    };
  }

  serverLogs(query = {}) {
    const limit = normalizeLimit(query.limit, 80, 200);
    const receipt = this.lifecycleReceipt("server_logs_read", {
      modelId: "ioi-local-server",
      state: "read",
      limit,
      evidenceRefs: ["ioi_daemon_public_runtime_api", "server_log_ring_buffer", "redacted_log_access"],
    });
    this.writeServerLog({
      event: "server_logs_read",
      status: "read",
      receiptId: receipt.id,
      limit,
    });
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      kind: "server_logs",
      redaction: "redacted",
      receiptId: receipt.id,
      records: this.serverLogRecords({ limit }),
    };
  }

  serverEvents(query = {}) {
    const limit = normalizeLimit(query.limit, 80, 200);
    const receipt = this.lifecycleReceipt("server_events_read", {
      modelId: "ioi-local-server",
      state: "read",
      limit,
      evidenceRefs: ["ioi_daemon_public_runtime_api", "server_log_ring_buffer", "event_tail"],
    });
    this.writeServerLog({
      event: "server_events_read",
      status: "read",
      receiptId: receipt.id,
      limit,
    });
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      kind: "server_events",
      redaction: "redacted",
      receiptId: receipt.id,
      events: this.serverLogRecords({ limit }),
    };
  }

  serverLogRecords({ limit = 80 } = {}) {
    const filePath = path.join(this.stateDir, "server-logs", "server.jsonl");
    return readLines(filePath)
      .map((line) => parseJsonMaybe(line))
      .filter(Boolean)
      .sort((left, right) => String(left.createdAt ?? "").localeCompare(String(right.createdAt ?? "")))
      .slice(-normalizeLimit(limit, 80, 200));
  }

  writeServerLog(event) {
    const record = {
      id: `server_log_${crypto.randomUUID()}`,
      createdAt: this.nowIso(),
      source: "ioi-local-server",
      ...redact(event),
    };
    const filePath = path.join(this.stateDir, "server-logs", "server.jsonl");
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.appendFileSync(filePath, `${JSON.stringify(record)}\n`);
    return record;
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
    return [...this.providers.values()]
      .map((provider) => publicProvider(provider, providerHasVaultRef(provider) ? this.vault.vaultRefMetadata(provider.secretRef) : null))
      .sort((left, right) => left.id.localeCompare(right.id));
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

  listProviderHealth() {
    return listJson(path.join(this.stateDir, "provider-health"))
      .map((filePath) => readJson(filePath))
      .sort((left, right) => String(left.checkedAt ?? "").localeCompare(String(right.checkedAt ?? "")));
  }

  snapshot(baseUrl) {
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      server: this.serverStatus(baseUrl),
      catalog: this.catalogStatus(),
      artifacts: this.listArtifacts(),
      backends: this.listBackends(),
      backendProcesses: this.listBackendProcesses(),
      endpoints: this.listEndpoints(),
      instances: this.listInstances(),
      providers: this.listProviders(),
      routes: this.listRoutes(),
      downloads: this.listDownloads(),
      providerHealth: this.listProviderHealth(),
      runtimeEngines: this.listRuntimeEngines(),
      runtimeEngineProfiles: this.listRuntimeEngineProfiles(),
      runtimePreference: this.runtimePreference(),
      runtimeSurvey: this.latestRuntimeSurvey(),
      tokens: this.listTokens(),
      vaultRefs: this.listVaultRefs(),
      mcpServers: this.listMcpServers(),
      workflowNodes: this.workflowNodeBindings(),
      receipts: this.listReceipts().slice(-25),
      projection: this.projectionSummary(),
      adapterBoundaries: this.adapterBoundaries(),
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
      backendProcesses: this.listBackendProcesses(),
      providers: this.listProviders(),
      catalog: this.catalogStatus(),
      downloads: this.listDownloads(),
      providerHealth: this.listProviderHealth(),
      runtimeEngines: this.listRuntimeEngines(),
      runtimeEngineProfiles: this.listRuntimeEngineProfiles(),
      runtimePreference: this.runtimePreference(),
      runtimeSurvey: this.latestRuntimeSurvey(),
      grants: this.listTokens(),
      vaultRefs: this.listVaultRefs(),
      mcpServers: this.listMcpServers(),
      workflowBindings: this.workflowNodeBindings(),
      adapterBoundaries: this.adapterBoundaries(),
      lifecycleEvents: this.listReceipts().filter((receipt) => receipt.kind === "model_lifecycle"),
      routeReceipts: this.listReceipts().filter((receipt) => receipt.kind === "model_route_selection"),
      providerHealthReceipts: this.listReceipts().filter((receipt) => receipt.kind === "provider_health"),
      runtimeSurveyReceipts: this.listReceipts().filter((receipt) => receipt.kind === "runtime_survey"),
      invocationReceipts: this.listReceipts().filter((receipt) => receipt.kind === "model_invocation"),
      toolReceipts: this.listReceipts().filter((receipt) => receipt.kind === "mcp_tool_invocation"),
      receipts: this.listReceipts(),
    };
  }

  adapterBoundaries() {
    return {
      wallet: this.walletAuthority.adapterStatus(),
      vault: this.vault.adapterStatus(),
      agentgres: this.store.adapterStatus(),
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

  latestProviderHealth(providerId) {
    this.provider(providerId);
    const health = this.listProviderHealth()
      .filter((record) => record.providerId === providerId)
      .at(-1);
    if (!health?.receiptId) {
      throw notFound(`Provider health has not been checked: ${providerId}`, { providerId });
    }
    const receipt = this.getReceipt(health.receiptId);
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      source: "agentgres_provider_health_latest",
      providerId,
      health,
      receipt,
      replay: this.receiptReplay(receipt.id),
      projectionWatermark: operationCount(this.stateDir),
    };
  }

  latestVaultHealth() {
    const receipt = this.listReceipts()
      .filter((item) => item.kind === "vault_adapter_health")
      .at(-1);
    if (!receipt) {
      throw notFound("Vault adapter health has not been checked.", { receiptKind: "vault_adapter_health" });
    }
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      source: "agentgres_vault_health_latest",
      health: receipt.details,
      receipt,
      replay: this.receiptReplay(receipt.id),
      projectionWatermark: operationCount(this.stateDir),
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

  catalogStatus() {
    const hfBaseUrl = huggingFaceCatalogBaseUrl();
    const lastSearch = this.lastCatalogSearch;
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      checkedAt: this.nowIso(),
      providers: [
        {
          id: "catalog.fixture",
          label: "Fixture catalog",
          status: "available",
          gate: "always_on",
          formats: ["gguf"],
          evidenceRefs: ["fixture_model_catalog"],
        },
        {
          id: "catalog.huggingface",
          label: "Hugging Face-compatible catalog",
          status: liveModelCatalogEnabled() ? "configured" : "gated",
          gate: "IOI_LIVE_MODEL_CATALOG",
          formats: ["gguf", "mlx", "safetensors"],
          baseUrlHash: stableHash(hfBaseUrl),
          liveDownloadStatus: liveModelDownloadEnabled() ? "configured" : "gated",
          downloadGate: "IOI_LIVE_MODEL_DOWNLOAD",
          evidenceRefs: ["huggingface_catalog_adapter_boundary", "network_access_opt_in"],
        },
      ],
      filters: {
        formats: ["gguf", "mlx", "safetensors"],
        quantization: ["Q2", "Q3", "Q4", "Q5", "Q6", "Q8", "F16", "BF16", "IQ"],
        compatibility: ["native_local_fixture", "llama_cpp", "vllm", "mlx"],
      },
      storage: this.storageSummary(),
      lastSearch: lastSearch
        ? {
            searchedAt: lastSearch.searchedAt,
            query: lastSearch.query,
            filters: lastSearch.filters,
            resultCount: lastSearch.results.length,
          }
        : null,
      results: lastSearch?.results ?? [],
    };
  }

  storageSummary() {
    const files = listModelFiles(this.modelRoot);
    const totalBytes = files.reduce((total, filePath) => total + fs.statSync(filePath).size, 0);
    const knownPaths = new Set([...this.artifacts.values()].map((artifact) => artifact.artifactPath).filter(Boolean));
    const orphanCount = files.filter((filePath) => !knownPaths.has(filePath)).length;
    const quotaBytes = Number(process.env.IOI_MODEL_STORAGE_QUOTA_BYTES ?? 0) || null;
    return {
      rootHash: stableHash(this.modelRoot),
      totalBytes,
      quotaBytes,
      quotaStatus: quotaBytes && totalBytes > quotaBytes ? "over_quota" : "ok",
      fileCount: files.length,
      orphanCount,
      destructiveActionsRequireUnload: true,
      evidenceRefs: ["model_storage_quota_boundary", "artifact_delete_unload_guard"],
    };
  }

  async catalogSearch(query = {}) {
    const searchedAt = this.nowIso();
    const text = String(query.q ?? query.query ?? "autopilot").trim().toLowerCase();
    const requestedFormat = query.format === undefined || query.format === "" ? null : String(query.format).toLowerCase();
    const requestedQuantization = query.quantization === undefined || query.quantization === "" ? null : String(query.quantization).toLowerCase();
    const limit = normalizeLimit(query.limit, 20, 100);
    const catalog = fixtureModelCatalog(searchedAt);
    const results = catalog.filter((entry) => {
      const haystack = [entry.modelId, entry.family, entry.format, entry.quantization, ...(entry.tags ?? [])].join(" ").toLowerCase();
      if (text && !haystack.includes(text)) return false;
      if (requestedFormat && entry.format !== requestedFormat) return false;
      if (requestedQuantization && !String(entry.quantization ?? "").toLowerCase().includes(requestedQuantization)) return false;
      return true;
    });
    const live = await this.searchHuggingFaceCatalog({ query: text, format: requestedFormat, quantization: requestedQuantization, limit, searchedAt });
    const search = {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      searchedAt,
      query: text,
      filters: {
        format: requestedFormat,
        quantization: requestedQuantization,
        limit,
      },
      providers: [
        { id: "catalog.fixture", status: "available", evidenceRefs: ["fixture_model_catalog"] },
        {
          id: "catalog.huggingface",
          status: live.status,
          gate: "IOI_LIVE_MODEL_CATALOG",
          baseUrlHash: live.baseUrlHash,
          errorHash: live.errorHash ?? null,
          evidenceRefs: live.evidenceRefs,
        },
      ],
      results: [...results, ...live.results].slice(0, limit),
    };
    this.lastCatalogSearch = search;
    return search;
  }

  async searchHuggingFaceCatalog({ query, format, quantization, limit, searchedAt }) {
    const baseUrl = huggingFaceCatalogBaseUrl();
    const evidenceRefs = ["huggingface_catalog_adapter_boundary", "network_access_opt_in"];
    if (!liveModelCatalogEnabled()) {
      return { status: "gated", baseUrlHash: stableHash(baseUrl), evidenceRefs, results: [] };
    }
    try {
      const url = new URL("/api/models", baseUrl);
      if (query) url.searchParams.set("search", query);
      url.searchParams.set("limit", String(limit));
      const response = await fetchWithTimeout(url, { timeoutMs: modelCatalogTimeoutMs() });
      if (!response.ok) {
        return {
          status: "degraded",
          baseUrlHash: stableHash(baseUrl),
          evidenceRefs,
          errorHash: stableHash(`http:${response.status}`),
          results: [],
        };
      }
      const payload = await response.json();
      const records = Array.isArray(payload) ? payload : Array.isArray(payload?.models) ? payload.models : Array.isArray(payload?.results) ? payload.results : [];
      const results = records
        .flatMap((record) => huggingFaceCatalogEntries(record, { baseUrl, searchedAt }))
        .filter((entry) => {
          if (format && entry.format !== format) return false;
          if (quantization && !String(entry.quantization ?? "").toLowerCase().includes(quantization)) return false;
          return true;
        })
        .slice(0, limit);
      return {
        status: "available",
        baseUrlHash: stableHash(baseUrl),
        evidenceRefs: [...evidenceRefs, "huggingface_catalog_search"],
        results,
      };
    } catch (error) {
      return {
        status: "degraded",
        baseUrlHash: stableHash(baseUrl),
        evidenceRefs,
        errorHash: stableHash(error?.message ?? "catalog search failed"),
        results: [],
      };
    }
  }

  async catalogImportUrl(body = {}) {
    const sourceUrl = requiredString(body.source_url ?? body.sourceUrl ?? body.url, "source_url");
    const isFixture = sourceUrl.startsWith("fixture://");
    if (!isFixture && !liveModelCatalogEnabled()) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "Live catalog imports are gated. Use fixture:// URLs or set IOI_LIVE_MODEL_CATALOG=1.",
        details: { sourceUrlHash: stableHash(sourceUrl), evidenceRefs: ["network_access_opt_in"] },
      });
    }
    if (!isFixture && !liveModelDownloadEnabled()) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "Live catalog downloads are gated. Set IOI_LIVE_MODEL_DOWNLOAD=1 to materialize remote artifacts.",
        details: { sourceUrlHash: stableHash(sourceUrl), evidenceRefs: ["network_download_opt_in"] },
      });
    }
    const modelId = body.model_id ?? body.modelId ?? modelIdFromSourceUrl(sourceUrl);
    const variant = catalogVariantForSource(sourceUrl, body);
    const receipt = this.lifecycleReceipt("model_catalog_import_url", {
      modelId,
      providerId: body.provider_id ?? body.providerId ?? "provider.autopilot.local",
      sourceUrlHash: stableHash(sourceUrl),
      sourceLabel: variant.sourceLabel,
      format: variant.format,
      quantization: variant.quantization,
      license: variant.license,
      compatibility: variant.compatibility,
      liveDownloadGate: isFixture ? "fixture" : "IOI_LIVE_MODEL_DOWNLOAD",
    });
    const download = await this.downloadModel({
      ...body,
      model_id: modelId,
      provider_id: body.provider_id ?? body.providerId ?? "provider.autopilot.local",
      source_url: sourceUrl,
      source_label: variant.sourceLabel,
      file_name: body.file_name ?? body.fileName ?? `${safeFileName(modelId)}.${variant.format}`,
      ...(isFixture
        ? {
            fixture_content:
              body.fixture_content ??
              body.fixtureContent ??
              [`family=${variant.family}`, `quantization=${variant.quantization}`, `context=${variant.contextWindow}`, ""].join("\n"),
          }
        : {}),
      format: variant.format,
      quantization: variant.quantization,
      family: variant.family,
      context_window: variant.contextWindow,
      license: variant.license,
      compatibility: variant.compatibility,
      variant_id: variant.id,
      catalog_receipt_id: receipt.id,
    });
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      status: download.status,
      catalogReceiptId: receipt.id,
      download,
    };
  }

  importModel(body = {}) {
    const now = this.nowIso();
    const modelId = requiredString(body.model_id ?? body.modelId, "model_id");
    const sourcePath = body.path ?? body.source_path ?? body.sourcePath ?? body.local_path ?? body.localPath ?? null;
    const sourceInfo = sourcePath ? inspectLocalArtifact(sourcePath) : null;
    const importMode = normalizeImportMode(body.import_mode ?? body.importMode ?? body.mode ?? (sourceInfo ? "reference" : "operator"));
    if (importMode === "dry_run") {
      const targetPreview = sourceInfo ? importTargetPath(this.modelRoot, modelId, sourceInfo.path) : null;
      const metadata = sourceInfo ? parseLocalModelMetadata(sourceInfo.path) : {};
      const receipt = this.lifecycleReceipt("model_import_dry_run", {
        modelId,
        providerId: body.provider_id ?? body.providerId ?? (sourceInfo ? "provider.autopilot.local" : "provider.local.folder"),
        sourcePathHash: sourceInfo?.path ? stableHash(sourceInfo.path) : null,
        targetPathHash: targetPreview ? stableHash(targetPreview) : null,
        importMode,
      });
      return {
        schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
        status: "dry_run",
        modelId,
        importMode,
        sourcePathHash: sourceInfo?.path ? stableHash(sourceInfo.path) : null,
        targetPathHash: targetPreview ? stableHash(targetPreview) : null,
        metadata,
        receiptId: receipt.id,
      };
    }
    const importedPath = sourceInfo ? materializeImportArtifact(this.modelRoot, modelId, sourceInfo.path, importMode) : null;
    const inspectedPath = importedPath ?? sourceInfo?.path ?? null;
    const importedInfo = inspectedPath ? inspectLocalArtifact(inspectedPath) : sourceInfo;
    const metadata = inspectedPath ? parseLocalModelMetadata(inspectedPath) : {};
    const artifact = {
      id: body.id ?? `import.${safeId(modelId)}`,
      providerId: body.provider_id ?? body.providerId ?? (sourceInfo ? "provider.autopilot.local" : "provider.local.folder"),
      modelId,
      displayName: body.display_name ?? body.displayName ?? modelId,
      family: body.family ?? metadata.family ?? "imported",
      format: body.format ?? metadata.format ?? null,
      quantization: body.quantization ?? metadata.quantization ?? null,
      sizeBytes: body.size_bytes ?? body.sizeBytes ?? importedInfo?.sizeBytes ?? null,
      checksum: body.checksum ?? importedInfo?.checksum ?? null,
      contextWindow: body.context_window ?? body.contextWindow ?? metadata.contextWindow ?? null,
      capabilities: normalizeScopes(body.capabilities, ["chat"]),
      privacyClass: body.privacy_class ?? body.privacyClass ?? "local_private",
      source: body.source ?? (sourceInfo ? "local_path_import" : "operator_import"),
      importMode,
      artifactPath: inspectedPath,
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
      sourcePathHash: sourceInfo?.path ? stableHash(sourceInfo.path) : null,
      importMode,
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
    const loadPolicy = normalizeLoadPolicy(body.load_policy ?? body.loadPolicy ?? endpoint.loadPolicy);
    const runtimePreference = this.runtimePreference();
    const requestLoadOptions = body.load_options ?? body.loadOptions ?? {};
    const runtimeDefaults = { ...this.runtimeDefaultLoadOptions(runtimePreference.selectedEngineId) };
    if ((body.load_policy ?? body.loadPolicy) && !hasExplicitTtlOption(body) && !hasExplicitTtlOption(requestLoadOptions)) {
      delete runtimeDefaults.ttlSeconds;
    }
    const loadOptions = normalizeLoadOptions(
      { ...runtimeDefaults, ...body, ...requestLoadOptions },
      loadPolicy,
    );
    if (loadOptions.ttlSeconds !== null) loadPolicy.idleTtlSeconds = loadOptions.ttlSeconds;
    const estimate = this.loadEstimate(endpoint, loadOptions, runtimePreference);
    if (loadOptions.estimateOnly) {
      const receipt = this.lifecycleReceipt("model_load_estimate", {
        endpointId: endpoint.id,
        modelId: endpoint.modelId,
        providerId: endpoint.providerId,
        backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
        runtimeEngineId: runtimePreference.selectedEngineId,
        runtimeEngineProfile: this.runtimeEngineProfile(runtimePreference.selectedEngineId) ?? null,
        loadPolicy,
        loadOptions,
        estimate,
      });
      return {
        schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
        status: "estimate_only",
        endpointId: endpoint.id,
        modelId: endpoint.modelId,
        providerId: endpoint.providerId,
        backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
        runtimeEngineId: runtimePreference.selectedEngineId,
        runtimeEngineProfile: this.runtimeEngineProfile(runtimePreference.selectedEngineId) ?? null,
        loadPolicy,
        loadOptions,
        estimate,
        receiptId: receipt.id,
      };
    }
    const driverResult = await this.driverForProvider(provider).load({
      state: this,
      provider,
      endpoint,
      body: { ...body, loadOptions, load_policy: loadPolicy },
    });
    const now = this.nowIso();
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
      loadOptions,
      runtimeEngineId: runtimePreference.selectedEngineId,
      runtimeEngineProfile: this.runtimeEngineProfile(runtimePreference.selectedEngineId) ?? null,
      identifier: loadOptions.identifier ?? null,
      contextLength: loadOptions.contextLength ?? endpoint.contextWindow ?? null,
      parallelism: loadOptions.parallel ?? null,
      gpuOffload: loadOptions.gpu ?? null,
      estimate: driverResult.estimate ?? estimate,
      backendProcess: driverResult.process ?? null,
      backendProcessId: driverResult.process?.id ?? null,
      backendProcessPidHash: driverResult.process?.pidHash ?? null,
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
      backendId: instance.backendId,
      runtimeEngineId: runtimePreference.selectedEngineId,
      loadPolicy,
      loadOptions,
      estimate: instance.estimate,
      providerEvidenceRefs: driverResult.evidenceRefs ?? [],
      backendProcess: driverResult.process ?? null,
      commandArgsHash: driverResult.commandArgsHash ?? null,
    });
    return instance;
  }

  loadEstimate(endpoint, loadOptions = {}, runtimePreference = this.runtimePreference()) {
    const provider = this.provider(endpoint.providerId);
    const artifact = this.getModel(endpoint.modelId);
    const nativeEstimate = estimateNativeLocalResources({
      ...artifact,
      contextWindow: loadOptions.contextLength ?? artifact.contextWindow,
    });
    return {
      endpointId: endpoint.id,
      modelId: endpoint.modelId,
      providerId: endpoint.providerId,
      backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
      runtimeEngineId: runtimePreference.selectedEngineId,
      contextLength: loadOptions.contextLength ?? nativeEstimate.contextWindow,
      parallelism: loadOptions.parallel ?? 1,
      gpuOffload: loadOptions.gpu ?? "auto",
      identifier: loadOptions.identifier ?? null,
      estimatedVramBytes: nativeEstimate.estimatedVramBytes,
      estimatedSizeBytes: nativeEstimate.sizeBytes,
      realInference: provider.kind !== "ioi_native_local" ? null : nativeEstimate.realInference,
      evidenceRefs: ["model_load_option_estimate", "runtime_engine_preference"],
    };
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
      backendProcess: driverResult.process ?? null,
    });
    return updated;
  }

  async downloadModel(body = {}) {
    const now = this.nowIso();
    const modelId = requiredString(body.model_id ?? body.modelId, "model_id");
    const providerId = body.provider_id ?? body.providerId ?? "provider.autopilot.local";
    const source = body.source_url ?? body.sourceUrl ?? body.source ?? "deterministic_fixture_download";
    const isFixture = String(source).startsWith("fixture://") || source === "deterministic_fixture_download";
    if (!isFixture && !liveModelDownloadEnabled()) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "Live model downloads are gated. Set IOI_LIVE_MODEL_DOWNLOAD=1.",
        details: { sourceUrlHash: stableHash(source), evidenceRefs: ["network_download_opt_in"] },
      });
    }
    const sourceLabel = body.source_label ?? body.sourceLabel ?? sourceLabelForUrl(source);
    const variantMetadata = catalogVariantForSource(source, body);
    const targetDir = path.join(this.modelRoot, "downloads", safeFileName(modelId));
    const targetPath = path.join(targetDir, body.file_name ?? body.fileName ?? `${safeFileName(modelId)}.gguf`);
    const fixtureContent = String(body.fixture_content ?? body.fixtureContent ?? `deterministic model bytes for ${modelId}\n`);
    const bytesTotal = Number(body.bytes_total ?? body.bytesTotal ?? (isFixture ? Buffer.byteLength(fixtureContent) : 0));
    const maxBytes = normalizeOptionalBytes(body.max_bytes ?? body.maxBytes ?? process.env.IOI_MODEL_DOWNLOAD_MAX_BYTES);
    const jobBase = {
      id: `download_job_${crypto.randomUUID()}`,
      modelId,
      providerId,
      source: publicDownloadSource(source),
      sourceHash: stableHash(source),
      sourceUrlHash: stableHash(source),
      sourceLabel,
      variant: variantMetadata,
      targetPath,
      targetPathHash: stableHash(targetPath),
      bytesTotal,
      bytesCompleted: 0,
      progress: 0,
      maxBytes,
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
      sourceLabel,
      variant: variantMetadata,
      targetPathHash: stableHash(targetPath),
      maxBytes,
      downloadMode: isFixture ? "fixture" : "live_network",
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
    const runningReceipt = this.lifecycleReceipt("model_download_running", {
      jobId: jobBase.id,
      modelId,
      providerId,
      bytesTotal,
      bytesCompleted: 0,
      maxBytes,
      sourceHash: stableHash(source),
      sourceLabel,
      downloadMode: isFixture ? "fixture" : "live_network",
    });
    let materialized;
    try {
      materialized = isFixture
        ? materializeFixtureDownload({ targetPath, fixtureContent })
        : await materializeLiveDownload({
            source,
            targetPath,
            expectedChecksum: body.checksum ?? body.expected_checksum ?? body.expectedChecksum ?? null,
            maxBytes,
            resume: truthy(body.resume ?? body.resume_download ?? body.resumeDownload ?? true),
            timeoutMs: modelDownloadTimeoutMs(),
          });
    } catch (error) {
      const failureReason = downloadFailureReason(error);
      const failedReceipt = this.lifecycleReceipt("model_download_failed", {
        jobId: jobBase.id,
        modelId,
        providerId,
        failureReason,
        sourceHash: stableHash(source),
        sourceLabel,
        errorHash: stableHash(error?.message ?? "download failed"),
        cleanupState: cleanupPartialDownload(targetPath),
      });
      const failed = {
        ...jobBase,
        artifactId: null,
        status: "failed",
        failureReason,
        updatedAt: this.nowIso(),
        receiptIds: [queuedReceipt.id, runningReceipt.id, failedReceipt.id],
        receiptId: failedReceipt.id,
      };
      this.downloads.set(failed.id, failed);
      this.writeMap("model-downloads", this.downloads);
      this.writeProjection();
      return failed;
    }
    const checksum = materialized.checksum;
    const completedBytes = materialized.bytesCompleted;
    const metadata = parseLocalModelMetadata(targetPath);
    const artifact = this.artifacts.get(`download.${safeId(modelId)}`) ?? {
      id: `download.${safeId(modelId)}`,
      providerId,
      modelId,
      displayName: body.display_name ?? body.displayName ?? modelId,
      family: body.family ?? metadata.family ?? "download",
      format: body.format ?? variantMetadata.format ?? metadata.format ?? "gguf",
      quantization: body.quantization ?? variantMetadata.quantization ?? metadata.quantization ?? null,
      sizeBytes: completedBytes,
      checksum,
      contextWindow: body.context_window ?? body.contextWindow ?? metadata.contextWindow ?? null,
      capabilities: normalizeScopes(body.capabilities, ["chat"]),
      privacyClass: body.privacy_class ?? body.privacyClass ?? "local_private",
      source: publicDownloadSource(source),
      sourceLabel,
      sourceUrlHash: stableHash(source),
      license: body.license ?? variantMetadata.license ?? null,
      compatibility: body.compatibility ?? variantMetadata.compatibility ?? [],
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
      bytesTotal: materialized.bytesTotal || completedBytes,
      bytesCompleted: completedBytes,
      resumeOffset: materialized.resumeOffset ?? 0,
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
      bytesTotal: materialized.bytesTotal || completedBytes,
      bytesCompleted: completedBytes,
      maxBytes,
      checksum,
      sourceHash: stableHash(source),
      sourceLabel,
      variant: variantMetadata,
      resumeOffset: materialized.resumeOffset ?? 0,
      downloadMode: isFixture ? "fixture" : "live_network",
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

  deleteModelArtifact(id) {
    const artifact = this.getModel(id);
    const endpointIds = [...this.endpoints.values()].filter((endpoint) => endpoint.artifactId === artifact.id).map((endpoint) => endpoint.id);
    const instanceIds = [...this.instances.values()]
      .filter((instance) => endpointIds.includes(instance.endpointId) && instance.status === "loaded")
      .map((instance) => instance.id);
    if (instanceIds.length > 0) {
      throw runtimeError({
        status: 409,
        code: "conflict",
        message: "Model artifact is loaded. Unload linked instances before deleting it.",
        details: { artifactId: artifact.id, instanceIds },
      });
    }
    for (const endpointId of endpointIds) {
      const endpoint = this.endpoints.get(endpointId);
      this.endpoints.set(endpointId, { ...endpoint, status: "deleted_with_artifact", deletedAt: this.nowIso() });
    }
    this.artifacts.delete(artifact.id);
    fs.rmSync(path.join(this.stateDir, "model-artifacts", `${safeFileName(artifact.id)}.json`), { force: true });
    let cleanupState = "not_applicable";
    if (artifact.artifactPath && artifact.artifactPath.startsWith(this.modelRoot)) {
      try {
        fs.rmSync(artifact.artifactPath, { force: true });
        cleanupState = "removed";
      } catch {
        cleanupState = "failed";
      }
    }
    const receipt = this.lifecycleReceipt("model_artifact_delete", {
      artifactId: artifact.id,
      modelId: artifact.modelId,
      providerId: artifact.providerId,
      artifactPathHash: artifact.artifactPath ? stableHash(artifact.artifactPath) : null,
      endpointIds,
      cleanupState,
    });
    this.writeMap("model-artifacts", this.artifacts);
    this.writeMap("model-endpoints", this.endpoints);
    this.writeProjection();
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      status: "deleted",
      artifactId: artifact.id,
      modelId: artifact.modelId,
      cleanupState,
      receiptId: receipt.id,
    };
  }

  cleanupModelStorage() {
    const knownPaths = new Set([...this.artifacts.values()].map((artifact) => artifact.artifactPath).filter(Boolean));
    const files = listModelFiles(this.modelRoot);
    const orphans = files.filter((filePath) => !knownPaths.has(filePath));
    const receipt = this.lifecycleReceipt("model_storage_cleanup", {
      modelId: "model-storage",
      scannedFileCount: files.length,
      orphanCount: orphans.length,
      orphanPathHashes: orphans.map((filePath) => stableHash(filePath)),
      cleanupState: "scan_only",
    });
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      status: "scanned",
      scannedFileCount: files.length,
      orphanCount: orphans.length,
      receiptId: receipt.id,
    };
  }

  bindVaultRef(body = {}) {
    const vaultRef = requiredString(body.vault_ref ?? body.vaultRef, "vault_ref");
    const material = requiredString(body.material ?? body.secret ?? body.value, "material");
    const metadata = this.vault.bindVaultRef({
      vaultRef,
      material,
      purpose: body.purpose ?? "operator_provider_auth_binding",
      label: body.label ?? null,
    });
    this.writeVaultRefs();
    const receipt = this.receipt("vault_ref_binding", {
      summary: `Vault material bound for ${metadata.vaultRefHash}.`,
      redaction: "redacted",
      evidenceRefs: ["VaultPort.bindVaultRef", metadata.vaultRefHash],
      details: metadata,
    });
    this.writeProjection();
    return { ...metadata, receiptId: receipt.id };
  }

  listVaultRefs() {
    return this.vault.listVaultRefs();
  }

  vaultRefMetadata(body = {}) {
    const vaultRef = requiredString(body.vault_ref ?? body.vaultRef, "vault_ref");
    return this.vault.vaultRefMetadata(vaultRef);
  }

  vaultStatus() {
    return this.vault.adapterStatus();
  }

  vaultHealth() {
    const health = this.vault.health();
    const receipt = this.receipt("vault_adapter_health", {
      summary: `Vault adapter health is ${health.status}.`,
      redaction: "redacted",
      evidenceRefs: health.evidenceRefs,
      details: health,
    });
    return { ...health, receiptId: receipt.id };
  }

  removeVaultRef(body = {}) {
    const vaultRef = requiredString(body.vault_ref ?? body.vaultRef, "vault_ref");
    const metadata = this.vault.removeVaultRef(vaultRef, body.purpose ?? "operator_provider_auth_remove");
    this.writeVaultRefs();
    const receipt = this.receipt("vault_ref_removal", {
      summary: `Vault material removed for ${metadata.vaultRefHash}.`,
      redaction: "redacted",
      evidenceRefs: ["VaultPort.removeVaultRef", metadata.vaultRefHash],
      details: metadata,
    });
    this.writeProjection();
    return { ...metadata, receiptId: receipt.id };
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
    const authScheme = normalizeProviderAuthScheme(body.auth_scheme ?? body.authScheme ?? existing.authScheme);
    const authHeaderName = normalizeProviderAuthHeaderName(
      body.auth_header_name ?? body.authHeaderName ?? existing.authHeaderName,
    );
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
      authScheme,
      authHeaderName,
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
    try {
      const driverResult = await this.driverForProvider(provider).health(provider, { state: this });
      const status = driverResult.status ?? (provider.status === "configured" ? "available" : provider.status);
      const receipt = this.receipt("provider_health", {
        summary: `Provider ${providerId} health is ${status}.`,
        redaction: "redacted",
        evidenceRefs: driverResult.evidenceRefs ?? provider.discovery?.evidenceRefs ?? [],
        details: {
          providerId,
          providerKind: provider.kind,
          status,
          httpStatus: driverResult.httpStatus ?? null,
          authVaultRefHash: driverResult.authEvidence?.vaultRefHash ?? null,
          providerAuthEvidenceRefs: driverResult.authEvidence?.evidenceRefs ?? [],
          providerAuthHeaderNames: driverResult.authEvidence?.headerNames ?? [],
        },
      });
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
            receiptId: receipt.id,
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
        receiptId: receipt.id,
        evidenceRefs: driverResult.evidenceRefs ?? [],
      });
      this.writeProjection();
      return publicProvider(updated, providerHasVaultRef(updated) ? this.vault.vaultRefMetadata(updated.secretRef) : null);
    } catch (error) {
      const status = providerHealthFailureStatus(error);
      const failureDetails = error?.details && typeof error.details === "object" ? error.details : {};
      const evidenceRefs = normalizeScopes(failureDetails.evidenceRefs, [`provider_health_${error?.code ?? "runtime_error"}`]);
      const receipt = this.receipt("provider_health", {
        summary: `Provider ${providerId} health failed closed as ${status}.`,
        redaction: "redacted",
        evidenceRefs,
        details: {
          providerId,
          providerKind: provider.kind,
          status,
          failureCode: error?.code ?? "runtime",
          failureStatus: error?.status ?? 500,
          httpStatus: failureDetails.httpStatus ?? null,
          providerErrorHash: failureDetails.providerErrorHash ?? null,
          vaultRefConfigured: failureDetails.vaultRefConfigured ?? providerHasVaultRef(provider),
          authVaultRefHash: failureDetails.vaultRefHash ?? null,
          resolvedMaterial: failureDetails.resolvedMaterial ?? null,
        },
      });
      const updated = {
        ...provider,
        status,
        discovery: {
          ...provider.discovery,
          checkedAt,
          lastHealthCheck: {
            status,
            evidenceRefs,
            httpStatus: failureDetails.httpStatus ?? null,
            authVaultRefHash: failureDetails.vaultRefHash ?? null,
            failureCode: error?.code ?? "runtime",
            failureStatus: error?.status ?? 500,
            resolvedMaterial: failureDetails.resolvedMaterial ?? null,
            receiptId: receipt.id,
          },
        },
      };
      this.providers.set(providerId, updated);
      this.writeMap("model-providers", this.providers);
      writeJson(path.join(this.stateDir, "provider-health", `${safeFileName(providerId)}.json`), {
        id: `health.${safeId(providerId)}`,
        providerId,
        status,
        checkedAt,
        receiptId: receipt.id,
        failureCode: error?.code ?? "runtime",
        failureStatus: error?.status ?? 500,
        evidenceRefs,
      });
      this.writeProjection();
      error.details = {
        ...failureDetails,
        providerHealthStatus: status,
        providerHealthReceiptId: receipt.id,
      };
      throw error;
    }
  }

  async listProviderModels(providerId) {
    const provider = this.provider(providerId);
    const models = await this.driverForProvider(provider).listModels({ state: this, provider });
    for (const artifact of models) {
      this.artifacts.set(artifact.id, artifact);
    }
    if (models.length > 0) this.writeMap("model-artifacts", this.artifacts);
    const resolved = models.length > 0
      ? models
      : this.listArtifacts().filter((artifact) => artifact.providerId === providerId);
    this.lifecycleReceipt("provider_models_list", {
      providerId,
      modelId: provider.label,
      state: provider.status,
      modelCount: resolved.length,
      evidenceRefs: provider.discovery?.evidenceRefs ?? [],
    });
    return resolved;
  }

  async listProviderLoaded(providerId) {
    const provider = this.provider(providerId);
    const loaded = await this.driverForProvider(provider).listLoaded({ state: this, provider });
    const resolved = loaded.length > 0
      ? loaded
      : this.listInstances().filter((instance) => instance.providerId === providerId && instance.status === "loaded");
    this.lifecycleReceipt("provider_loaded_list", {
      providerId,
      modelId: provider.label,
      state: provider.status,
      loadedCount: resolved.length,
      evidenceRefs: provider.discovery?.evidenceRefs ?? [],
    });
    return resolved;
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
        backendProcess: providerResult.backendProcess ?? instance.backendProcess ?? null,
        backendProcessId: providerResult.backendProcess?.id ?? instance.backendProcessId ?? null,
        backendProcessPidHash: providerResult.backendProcess?.pidHash ?? instance.backendProcessPidHash ?? null,
        backendEvidenceRefs: providerResult.backendEvidenceRefs ?? [],
        authVaultRefHash: providerResult.authVaultRefHash ?? null,
        providerAuthEvidenceRefs: providerResult.providerAuthEvidenceRefs ?? [],
        providerAuthHeaderNames: providerResult.providerAuthHeaderNames ?? [],
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
      const blockedReceipt = this.receipt("workflow_receipt_gate_blocked", {
        summary: `Receipt Gate blocked ${receiptId}.`,
        redaction: "redacted",
        evidenceRefs: ["workflow_canvas", "Receipt Gate", receiptId, ...requiredToolReceiptIds],
        details: {
          receiptId,
          failures,
          routeId: receipt.details?.routeId ?? null,
          selectedModel: receipt.details?.selectedModel ?? null,
          endpointId: receipt.details?.endpointId ?? null,
          backendId: receipt.details?.backendId ?? receipt.details?.selectedBackend ?? null,
          requiredToolReceiptIds,
        },
      });
      throw runtimeError({
        status: 412,
        code: "policy",
        message: "Receipt Gate blocked downstream workflow execution.",
        details: { receiptId, failures, gateReceiptId: blockedReceipt.id },
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
    return [...derived.values()]
      .map((backend) => {
        const processRecord = this.backendProcessForBackend(backend.id);
        return {
          ...backend,
          processStatus: processRecord?.processStatus ?? processRecord?.status ?? backend.processStatus,
          process: processRecord
            ? {
                id: processRecord.id,
                status: processRecord.status,
                processStatus: processRecord.processStatus ?? processRecord.status,
                pidHash: processRecord.pidHash ?? null,
                supervisorKind: processRecord.supervisorKind ?? null,
                spawned: Boolean(processRecord.spawned),
                spawnStatus: processRecord.spawnStatus ?? null,
                startedAt: processRecord.startedAt ?? null,
                stoppedAt: processRecord.stoppedAt ?? null,
                lastHealthAt: processRecord.lastHealthAt ?? null,
                argsHash: processRecord.argsHash ?? null,
                argsRedacted: processRecord.argsRedacted ?? [],
                startupTimeoutMs: processRecord.startupTimeoutMs ?? null,
                stale: Boolean(processRecord.stale),
                staleReason: processRecord.staleReason ?? null,
                receiptId: processRecord.lastReceiptId ?? null,
              }
            : null,
        };
      })
      .sort((left, right) => left.id.localeCompare(right.id));
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

  listBackendProcesses() {
    return [...this.backendProcesses.values()]
      .map((processRecord) => this.reconciledBackendProcess(processRecord))
      .sort((left, right) => String(left.startedAt ?? "").localeCompare(String(right.startedAt ?? "")));
  }

  backendProcessForBackend(backendId) {
    const processes = this.listBackendProcesses().filter((processRecord) => processRecord.backendId === backendId);
    return processes.at(-1) ?? null;
  }

  reconciledBackendProcess(processRecord) {
    if (!processRecord) return null;
    if (processRecord.status === "started" && processRecord.bootId && processRecord.bootId !== this.bootId) {
      return {
        ...processRecord,
        status: "stale_recovered",
        processStatus: "stale_recovered",
        stale: true,
        staleReason: "daemon_boot_mismatch",
        evidenceRefs: [
          ...normalizeScopes(processRecord.evidenceRefs, []),
          "supervisor_stale_process_detection",
          "agentgres_process_projection_replay",
        ],
      };
    }
    return {
      stale: false,
      ...processRecord,
    };
  }

  runtimePreference() {
    const preference =
      this.runtimeSelections.get("default") ?? {
        id: "default",
        selectedEngineId: "backend.autopilot.native-local.fixture",
        selectedAt: null,
        receiptId: "none",
        source: "default_native_local_runtime",
      };
    return {
      ...preference,
      defaultLoadOptions: this.runtimeDefaultLoadOptions(preference.selectedEngineId),
    };
  }

  runtimeEngineProfile(engineId) {
    return this.runtimeEngineProfiles.get(engineId) ?? null;
  }

  listRuntimeEngineProfiles() {
    return [...this.runtimeEngineProfiles.values()].sort((left, right) => left.id.localeCompare(right.id));
  }

  runtimeDefaultLoadOptions(engineId) {
    const profile = this.runtimeEngineProfile(engineId);
    return profile?.defaultLoadOptions ?? {};
  }

  runtimeEngine(engineId) {
    const engine = this.listRuntimeEngines().find((item) => item.id === engineId);
    if (!engine) throw notFound(`Runtime engine not found: ${engineId}`, { engineId });
    return {
      ...engine,
      profile: this.runtimeEngineProfile(engineId),
      preference: this.runtimePreference().selectedEngineId === engineId ? this.runtimePreference() : null,
      loadedInstances: this.listInstances().filter((instance) => instance.runtimeEngineId === engineId || instance.backendId === engineId),
      latestReceipts: this.listReceipts()
        .filter((receipt) => receipt.details?.runtimeEngineId === engineId || receipt.details?.engineId === engineId || receipt.details?.backendId === engineId)
        .slice(-8),
    };
  }

  selectRuntimeEngine(body = {}) {
    const engineId = requiredString(body.engine_id ?? body.engineId ?? body.id, "engine_id");
    const checkedAt = this.nowIso();
    const engines = this.listRuntimeEngines();
    const engine = engines.find((item) => item.id === engineId);
    if (!engine) throw notFound(`Runtime engine not found: ${engineId}`, { engineId });
    if (engine.operatorProfile?.disabled) {
      throw runtimeError({
        status: 409,
        code: "runtime_engine_disabled",
        message: "Runtime engine is disabled by its operator profile.",
        details: { engineId, receiptId: engine.operatorProfile.receiptId ?? null },
      });
    }
    const receipt = this.lifecycleReceipt("runtime_engine_select", {
      engineId,
      engineKind: engine.kind,
      engineStatus: engine.status,
      source: engine.source,
      modelFormat: engine.modelFormat,
      defaultLoadOptions: engine.operatorProfile?.defaultLoadOptions ?? {},
      checkedAt,
    });
    const preference = {
      id: "default",
      selectedEngineId: engineId,
      selectedAt: checkedAt,
      receiptId: receipt.id,
      source: "operator_runtime_select",
      engineKind: engine.kind,
      engineLabel: engine.label,
      modelFormat: engine.modelFormat,
      defaultLoadOptions: engine.operatorProfile?.defaultLoadOptions ?? {},
    };
    this.runtimeSelections.set(preference.id, preference);
    this.writeMap("runtime-preferences", this.runtimeSelections);
    this.writeProjection();
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      ...preference,
    };
  }

  updateRuntimeEngine(engineId, body = {}) {
    const engine = this.runtimeEngine(engineId);
    const now = this.nowIso();
    const existing = this.runtimeEngineProfile(engineId) ?? {};
    const disabledValue = body.disabled ?? body.disable ?? existing.disabled ?? false;
    const defaultLoadOptions = normalizeRuntimeEngineDefaultLoadOptions(
      body.default_load_options ?? body.defaultLoadOptions ?? body.load_options ?? body.loadOptions ?? existing.defaultLoadOptions ?? {},
    );
    const receipt = this.lifecycleReceipt("runtime_engine_update", {
      engineId,
      engineKind: engine.kind,
      previousProfileHash: stableHash(existing),
      disabled: Boolean(disabledValue),
      priority: body.priority ?? existing.priority ?? null,
      defaultLoadOptions,
      evidenceRefs: ["operator_runtime_engine_profile", "runtime_engine_default_load_options"],
    });
    const profile = {
      id: engineId,
      engineId,
      label: body.label ?? body.operator_label ?? body.operatorLabel ?? existing.label ?? null,
      disabled: Boolean(disabledValue),
      priority: body.priority === undefined || body.priority === null || body.priority === ""
        ? existing.priority ?? null
        : Number(body.priority),
      defaultLoadOptions,
      updatedAt: now,
      receiptId: receipt.id,
      source: "operator_runtime_engine_profile",
    };
    this.runtimeEngineProfiles.set(engineId, profile);
    this.writeMap("runtime-engine-profiles", this.runtimeEngineProfiles);
    if (profile.disabled && this.runtimePreference().selectedEngineId === engineId) {
      this.runtimeSelections.set("default", {
        id: "default",
        selectedEngineId: "backend.autopilot.native-local.fixture",
        selectedAt: now,
        receiptId: receipt.id,
        source: "operator_runtime_disable_reset",
        engineKind: "native_local",
        engineLabel: "Autopilot native-local fixture",
        modelFormat: "gguf,fixture",
        defaultLoadOptions: this.runtimeDefaultLoadOptions("backend.autopilot.native-local.fixture"),
      });
      this.writeMap("runtime-preferences", this.runtimeSelections);
    }
    this.writeProjection();
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      profile,
      engine: this.runtimeEngine(engineId),
      receiptId: receipt.id,
    };
  }

  removeRuntimeEngineOverride(engineId) {
    this.runtimeEngine(engineId);
    const existing = this.runtimeEngineProfile(engineId);
    const receipt = this.lifecycleReceipt("runtime_engine_profile_remove", {
      engineId,
      hadProfile: Boolean(existing),
      previousProfileHash: stableHash(existing ?? {}),
      evidenceRefs: ["operator_runtime_engine_profile_remove"],
    });
    this.runtimeEngineProfiles.delete(engineId);
    fs.rmSync(path.join(this.stateDir, "runtime-engine-profiles", `${safeFileName(engineId)}.json`), { force: true });
    this.writeMap("runtime-engine-profiles", this.runtimeEngineProfiles);
    if (this.runtimePreference().selectedEngineId === engineId && existing?.disabled) {
      this.runtimeSelections.set("default", {
        id: "default",
        selectedEngineId: "backend.autopilot.native-local.fixture",
        selectedAt: this.nowIso(),
        receiptId: receipt.id,
        source: "operator_runtime_profile_remove_reset",
        engineKind: "native_local",
        engineLabel: "Autopilot native-local fixture",
        modelFormat: "gguf,fixture",
        defaultLoadOptions: this.runtimeDefaultLoadOptions("backend.autopilot.native-local.fixture"),
      });
      this.writeMap("runtime-preferences", this.runtimeSelections);
    }
    this.writeProjection();
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      engineId,
      removed: Boolean(existing),
      engine: this.runtimeEngine(engineId),
      receiptId: receipt.id,
    };
  }

  listRuntimeEngines() {
    const checkedAt = this.nowIso();
    const activeBackendIds = new Set(this.listInstances().map((instance) => instance.backendId).filter(Boolean));
    const runtimePreference = this.runtimePreference();
    const hasExplicitPreference = runtimePreference.receiptId !== "none";
    const backendEngines = this.backendRegistry().map((backend) => ({
      id: backend.id,
      kind: backend.kind,
      label: backend.label,
      status: backend.status,
      selected:
        runtimePreference.selectedEngineId === backend.id ||
        (!hasExplicitPreference &&
          (activeBackendIds.has(backend.id) ||
            (activeBackendIds.size === 0 && backend.id === "backend.autopilot.native-local.fixture"))),
      modelFormat: (backend.supportedFormats ?? []).join(",") || "unknown",
      source: "autopilot_backend_registry",
      processStatus: backend.processStatus ?? "unknown",
      checkedAt,
      evidenceRefs: backend.evidenceRefs ?? [],
    })).map((engine) => this.applyRuntimeEngineProfile(engine));
    const lmStudioEngines = this.lmStudioRuntimeEngines(checkedAt).map((engine) => ({
      ...engine,
      selected: runtimePreference.selectedEngineId === engine.id || (!hasExplicitPreference && engine.selected),
    })).map((engine) => this.applyRuntimeEngineProfile(engine));
    return [...backendEngines, ...lmStudioEngines].sort((left, right) => {
      const leftPriority = left.operatorProfile?.priority ?? 1000;
      const rightPriority = right.operatorProfile?.priority ?? 1000;
      if (leftPriority !== rightPriority) return leftPriority - rightPriority;
      return left.id.localeCompare(right.id);
    });
  }

  applyRuntimeEngineProfile(engine) {
    const profile = this.runtimeEngineProfile(engine.id);
    if (!profile) {
      return {
        ...engine,
        operatorProfile: {
          configured: false,
          disabled: false,
          priority: null,
          defaultLoadOptions: {},
          receiptId: null,
        },
      };
    }
    const disabled = Boolean(profile.disabled);
    return {
      ...engine,
      label: profile.label || engine.label,
      status: disabled ? "disabled" : engine.status,
      selected: disabled ? false : engine.selected,
      operatorProfile: {
        configured: true,
        disabled,
        priority: profile.priority ?? null,
        defaultLoadOptions: profile.defaultLoadOptions ?? {},
        updatedAt: profile.updatedAt ?? null,
        receiptId: profile.receiptId ?? null,
        source: profile.source ?? "operator_runtime_engine_profile",
      },
    };
  }

  runtimeSurvey() {
    const checkedAt = this.nowIso();
    const hardware = hardwareSnapshot();
    const engines = this.listRuntimeEngines();
    const lmStudio = this.lmStudioRuntimeSurvey(checkedAt);
    const runtimePreference = this.runtimePreference();
    const selectedEngines = engines.filter((engine) => engine.selected).map((engine) => engine.id);
    const receipt = this.receipt("runtime_survey", {
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
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      checkedAt,
      engines,
      hardware,
      lmStudio,
      runtimePreference,
      receiptId: receipt.id,
    };
  }

  latestRuntimeSurvey() {
    const receipt = [...this.listReceipts()].reverse().find((item) => item.kind === "runtime_survey");
    if (!receipt) {
      return {
        status: "not_checked",
        receiptId: "none",
        checkedAt: null,
        engineCount: this.listRuntimeEngines().length,
        selectedEngines: [],
        runtimePreference: this.runtimePreference(),
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
      runtimePreference: receipt.details?.runtimePreference ?? this.runtimePreference(),
      hardware: receipt.details?.hardware ?? hardwareSnapshot(),
      lmStudio: receipt.details?.lmStudio ?? { status: "unknown" },
    };
  }

  lmStudioRuntimeEngines(checkedAt) {
    const provider = this.providers.get("provider.lmstudio");
    const lmsPath =
      provider?.discovery?.publicCli?.path ??
      process.env.IOI_LMS_PATH ??
      path.join(this.homeDir, ".lmstudio/bin/lms");
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

  lmStudioRuntimeSurvey(checkedAt) {
    const provider = this.providers.get("provider.lmstudio");
    const lmsPath =
      provider?.discovery?.publicCli?.path ??
      process.env.IOI_LMS_PATH ??
      path.join(this.homeDir, ".lmstudio/bin/lms");
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

  backend(backendId) {
    const backend = this.backendRegistry().find((item) => item.id === backendId);
    if (!backend) throw notFound(`Model backend not found: ${backendId}`, { backendId });
    return backend;
  }

  backendProcessSnapshot(processRecord) {
    if (!processRecord) {
      return {
        status: "not_started",
        processStatus: "not_started",
        evidenceRefs: ["supervisor_process_not_started"],
      };
    }
    return {
      id: processRecord.id,
      backendId: processRecord.backendId,
      backendKind: processRecord.backendKind,
      status: processRecord.status,
      processStatus: processRecord.processStatus ?? processRecord.status,
      pidHash: processRecord.pidHash ?? null,
      pidTracked: processRecord.pidTracked ?? "process_ref_hash",
      supervisorKind: processRecord.supervisorKind ?? null,
      spawned: Boolean(processRecord.spawned),
      spawnStatus: processRecord.spawnStatus ?? null,
      startedAt: processRecord.startedAt ?? null,
      stoppedAt: processRecord.stoppedAt ?? null,
      lastHealthAt: processRecord.lastHealthAt ?? null,
      argsHash: processRecord.argsHash ?? null,
      argsRedacted: processRecord.argsRedacted ?? [],
      startupTimeoutMs: processRecord.startupTimeoutMs ?? null,
      healthProbe: processRecord.healthProbe ?? null,
      stale: Boolean(processRecord.stale),
      staleReason: processRecord.staleReason ?? null,
      evidenceRefs: processRecord.evidenceRefs ?? [],
    };
  }

  backendProcessArgs(backend, { endpoint = null, loadOptions = {} } = {}) {
    const artifactPathHash = endpoint?.artifactPath ? stableHash(endpoint.artifactPath).slice(0, 16) : null;
    const modelArg = endpoint?.modelId ?? "runtime-engine-profile";
    const contextLength = loadOptions.contextLength ?? this.runtimeDefaultLoadOptions(backend.id).contextLength ?? null;
    const parallel = loadOptions.parallel ?? this.runtimeDefaultLoadOptions(backend.id).parallel ?? null;
    const gpu = loadOptions.gpu ?? this.runtimeDefaultLoadOptions(backend.id).gpu ?? null;
    const identifier = loadOptions.identifier ?? this.runtimeDefaultLoadOptions(backend.id).identifier ?? null;
    const args = [];
    if (backend.kind === "llama_cpp") {
      args.push("llama-server", "--model", artifactPathHash ? `artifact:${artifactPathHash}` : modelArg);
      if (contextLength) args.push("--ctx-size", String(contextLength));
      if (parallel) args.push("--parallel", String(parallel));
      if (gpu) args.push("--gpu-layers", gpu === "max" ? "999" : String(gpu));
    } else if (backend.kind === "vllm") {
      args.push("vllm", "serve", artifactPathHash ? `artifact:${artifactPathHash}` : modelArg);
      if (contextLength) args.push("--max-model-len", String(contextLength));
      if (parallel) args.push("--tensor-parallel-size", String(parallel));
      if (loadOptions.dtype) args.push("--dtype", String(loadOptions.dtype));
      if (loadOptions.gpuMemoryUtilization) args.push("--gpu-memory-utilization", String(loadOptions.gpuMemoryUtilization));
    } else if (backend.kind === "ollama") {
      args.push("ollama", "serve");
    } else if (backend.kind === "native_local") {
      args.push("ioi-native-local-fixture", "--model", modelArg);
      if (contextLength) args.push("--context", String(contextLength));
      if (parallel) args.push("--parallel", String(parallel));
      if (gpu) args.push("--gpu", String(gpu));
    } else {
      args.push(String(backend.kind ?? "backend"), "--model", modelArg);
    }
    if (identifier) args.push("--identifier", stableHash(identifier).slice(0, 12));
    return args;
  }

  backendProcessSpawnArgs(backend, { endpoint = null, loadOptions = {} } = {}) {
    if (backend.kind === "ollama") return ["serve"];
    if (backend.kind === "vllm") {
      const args = ["serve", endpoint?.artifactPath ?? loadOptions.modelPath ?? loadOptions.model_path ?? endpoint?.modelId ?? loadOptions.model ?? "runtime-engine-profile"];
      const bind = backendBindAddress(backend.baseUrl);
      if (bind.host) args.push("--host", bind.host);
      if (bind.port) args.push("--port", String(bind.port));
      const contextLength = loadOptions.contextLength ?? loadOptions.maxModelLen ?? this.runtimeDefaultLoadOptions(backend.id).contextLength ?? null;
      const parallel = loadOptions.parallel ?? loadOptions.tensorParallelSize ?? this.runtimeDefaultLoadOptions(backend.id).parallel ?? null;
      if (contextLength) args.push("--max-model-len", String(contextLength));
      if (parallel) args.push("--tensor-parallel-size", String(parallel));
      if (loadOptions.dtype) args.push("--dtype", String(loadOptions.dtype));
      if (loadOptions.gpuMemoryUtilization) args.push("--gpu-memory-utilization", String(loadOptions.gpuMemoryUtilization));
      return args;
    }
    if (backend.kind !== "llama_cpp") return this.backendProcessArgs(backend, { endpoint, loadOptions }).slice(1);
    const args = [];
    const modelPath = endpoint?.artifactPath ?? loadOptions.modelPath ?? loadOptions.model_path ?? null;
    if (modelPath) args.push("--model", modelPath);
    const contextLength = loadOptions.contextLength ?? this.runtimeDefaultLoadOptions(backend.id).contextLength ?? null;
    const parallel = loadOptions.parallel ?? this.runtimeDefaultLoadOptions(backend.id).parallel ?? null;
    const gpu = loadOptions.gpu ?? this.runtimeDefaultLoadOptions(backend.id).gpu ?? null;
    if (contextLength) args.push("--ctx-size", String(contextLength));
    if (parallel) args.push("--parallel", String(parallel));
    if (gpu) args.push("--n-gpu-layers", gpu === "max" ? "999" : gpu === "off" ? "0" : String(gpu));
    const embeddingEnabled = loadOptions.embeddings ?? endpoint?.capabilities?.includes?.("embeddings") ?? true;
    if (embeddingEnabled) args.push("--embedding");
    const bind = backendBindAddress(backend.baseUrl);
    if (bind.host) args.push("--host", bind.host);
    if (bind.port) args.push("--port", String(bind.port));
    return args;
  }

  ensureBackendProcess(backendId, { endpoint = null, loadOptions = {}, reason = "runtime_control" } = {}) {
    const backend = this.backend(backendId);
    if (!this.backendSupportsSupervision(backend)) {
      return null;
    }
    const existing = this.backendProcessForBackend(backendId);
    if (existing?.status === "started") {
      return this.touchBackendProcess(existing, { endpoint, loadOptions, reason });
    }
    return this.startBackendProcess(backend, { endpoint, loadOptions, reason });
  }

  backendSupportsSupervision(backend) {
    return ["native_local", "llama_cpp", "ollama", "vllm"].includes(backend.kind);
  }

  touchBackendProcess(processRecord, { endpoint = null, loadOptions = {}, reason = "health_probe" } = {}) {
    const backend = this.backend(processRecord.backendId);
    const argsRedacted = this.backendProcessArgs(backend, { endpoint, loadOptions });
    const updated = {
      ...processRecord,
      status: processRecord.stale ? "stale_recovered" : processRecord.status,
      processStatus: processRecord.stale ? "stale_recovered" : processRecord.processStatus ?? processRecord.status,
      lastHealthAt: this.nowIso(),
      updatedAt: this.nowIso(),
      argsHash: stableHash(argsRedacted.join("\0")),
      argsRedacted,
      reason,
    };
    this.backendProcesses.set(updated.id, updated);
    this.writeMap("backend-processes", this.backendProcesses);
    return this.reconciledBackendProcess(updated);
  }

  startBackendProcess(backend, { endpoint = null, loadOptions = {}, reason = "runtime_control" } = {}) {
    const now = this.nowIso();
    const argsRedacted = this.backendProcessArgs(backend, { endpoint, loadOptions });
    const processRef = `supervised://${safeId(backend.id)}/${crypto.randomUUID()}`;
    const childProcessInfo = this.spawnBackendChildProcess(backend, {
      endpoint,
      loadOptions,
      reason,
      processRef,
      argsRedacted,
    });
    const startupTimeoutMs = Number(loadOptions.startupTimeoutMs ?? process.env.IOI_MODEL_BACKEND_STARTUP_TIMEOUT_MS ?? 15000);
    const processRecord = {
      id: `backend_process_${safeId(backend.id)}_${Date.now()}`,
      backendId: backend.id,
      backendKind: backend.kind,
      status: "started",
      processStatus: "started",
      supervisorKind: backend.kind === "native_local" ? "deterministic_fixture_process" : "external_process",
      bootId: this.bootId,
      processRefHash: stableHash(processRef),
      pidHash: childProcessInfo.pidHash ?? stableHash(processRef).slice(0, 16),
      pidTracked: backend.kind === "native_local" ? "deterministic_fixture_process_ref" : "process_ref_hash",
      spawned: childProcessInfo.spawned,
      spawnStatus: childProcessInfo.status,
      spawnErrorHash: childProcessInfo.errorHash ?? null,
      childProcessKey: childProcessInfo.childProcessKey ?? null,
      baseUrl: backend.baseUrl ?? null,
      binaryPathHash: backend.binaryPath ? stableHash(backend.binaryPath) : null,
      argsRedacted,
      argsHash: stableHash(argsRedacted.join("\0")),
      loadOptions: redact(loadOptions),
      endpointId: endpoint?.id ?? null,
      modelId: endpoint?.modelId ?? null,
      startupTimeoutMs,
      healthProbe: backend.baseUrl ? `${backend.baseUrl}/health`.replace(/\/v1\/health$/, "/health") : "local://health",
      startedAt: now,
      updatedAt: now,
      lastHealthAt: now,
      stoppedAt: null,
      stale: false,
      reason,
      evidenceRefs: [
        "ModelBackendDriver.process_supervision",
        backend.kind === "native_local" ? "deterministic_native_local_fixture_process" : `${backend.kind}_process_supervisor`,
        "bounded_backend_log_capture",
        "startup_timeout_guard",
        ...childProcessInfo.evidenceRefs,
      ],
    };
    this.backendProcesses.set(processRecord.id, processRecord);
    this.writeMap("backend-processes", this.backendProcesses);
    this.writeBackendLog(backend.id, {
      backendId: backend.id,
      event: "backend_process_start",
      backendKind: backend.kind,
      processId: processRecord.id,
      pidHash: processRecord.pidHash,
      argsHash: processRecord.argsHash,
      reason,
    });
    return processRecord;
  }

  spawnBackendChildProcess(backend, { endpoint = null, loadOptions = {}, reason = "runtime_control", processRef, argsRedacted = [] } = {}) {
    if (!["llama_cpp", "ollama", "vllm"].includes(backend.kind)) {
      return { spawned: false, status: "not_required", evidenceRefs: [] };
    }
    if (!backend.binaryPath) {
      return { spawned: false, status: "binary_absent", evidenceRefs: [`${backend.kind}_binary_absent`] };
    }
    if (backend.kind === "llama_cpp" && !endpoint?.artifactPath && !loadOptions.modelPath && !loadOptions.model_path) {
      return {
        spawned: false,
        status: "waiting_for_model",
        evidenceRefs: ["llama_cpp_start_requires_model_artifact"],
      };
    }
    const spawnArgs = this.backendProcessSpawnArgs(backend, { endpoint, loadOptions });
    try {
      const child = childProcess.spawn(backend.binaryPath, spawnArgs, {
        cwd: this.cwd,
        env: {
          ...process.env,
          IOI_MODEL_BACKEND_BASE_URL: backend.baseUrl ?? "",
          IOI_MODEL_BACKEND_REASON: reason,
          ...(backend.kind === "ollama" ? { OLLAMA_HOST: backend.baseUrl ?? "http://127.0.0.1:11434" } : {}),
        },
        stdio: ["ignore", "pipe", "pipe"],
      });
      const pidHash = stableHash(`${processRef}:${child.pid ?? "unknown"}`).slice(0, 16);
      const processKey = stableHash(`${backend.id}:${pidHash}:${Date.now()}`).slice(0, 16);
      this.backendChildProcesses.set(processKey, child);
      const recordOutput = (stream, chunk) => {
        this.writeBackendLog(backend.id, {
          backendId: backend.id,
          event: `backend_process_${stream}`,
          backendKind: backend.kind,
          pidHash,
          bytes: Buffer.byteLength(chunk),
          outputHash: stableHash(String(chunk)),
          argsHash: stableHash(argsRedacted.join("\0")),
        });
      };
      child.stdout?.on("data", (chunk) => recordOutput("stdout", chunk));
      child.stderr?.on("data", (chunk) => recordOutput("stderr", chunk));
      child.once("exit", (code, signal) => {
        this.backendChildProcesses.delete(processKey);
        const existing = this.backendProcessForBackend(backend.id);
        if (existing?.pidHash !== pidHash || existing.status === "stopped") return;
        const updated = {
          ...existing,
          status: code === 0 ? "exited" : "degraded",
          processStatus: code === 0 ? "exited" : "degraded",
          exitCode: code,
          signal,
          stoppedAt: this.nowIso(),
          updatedAt: this.nowIso(),
          evidenceRefs: [...normalizeScopes(existing.evidenceRefs, []), `${backend.kind}_process_exit_observed`],
        };
        this.backendProcesses.set(updated.id, updated);
        this.writeMap("backend-processes", this.backendProcesses);
        this.writeBackendLog(backend.id, {
          backendId: backend.id,
          event: "backend_process_exit",
          backendKind: backend.kind,
          pidHash,
          exitCode: code,
          signal,
        });
      });
      child.once("error", (error) => {
        this.writeBackendLog(backend.id, {
          backendId: backend.id,
          event: "backend_process_spawn_error",
          backendKind: backend.kind,
          pidHash,
          errorHash: stableHash(error?.message ?? "spawn error"),
        });
      });
      return {
        spawned: true,
        status: "spawned",
        pidHash,
        childProcessKey: processKey,
        evidenceRefs: [`${backend.kind}_binary_spawn`, `${backend.kind}_spawn_args_redacted`],
      };
    } catch (error) {
      return {
        spawned: false,
        status: "spawn_failed",
        errorHash: stableHash(error?.message ?? "spawn failed"),
        evidenceRefs: [`${backend.kind}_binary_spawn_failed`],
      };
    }
  }

  stopBackendProcess(backend, { reason = "runtime_control" } = {}) {
    const existing = this.backendProcessForBackend(backend.id);
    if (!existing) return null;
    const child = existing.childProcessKey ? this.backendChildProcesses.get(existing.childProcessKey) : null;
    if (child && !child.killed) {
      try {
        child.kill("SIGTERM");
      } catch {
        // Stop receipts record intent even if the subprocess has already exited.
      }
    }
    const updated = {
      ...existing,
      status: "stopped",
      processStatus: "stopped",
      stoppedAt: this.nowIso(),
      updatedAt: this.nowIso(),
      reason,
      evidenceRefs: [...normalizeScopes(existing.evidenceRefs, []), "clean_backend_stop"],
    };
    this.backendProcesses.set(updated.id, updated);
    this.writeMap("backend-processes", this.backendProcesses);
    this.writeBackendLog(backend.id, {
      backendId: backend.id,
      event: "backend_process_stop",
      backendKind: backend.kind,
      processId: updated.id,
      pidHash: updated.pidHash,
      reason,
    });
    return updated;
  }

  backendHealth(backendId) {
    const backend = this.backend(backendId);
    const checkedAt = this.nowIso();
    const processRecord = this.backendProcessForBackend(backendId);
    const status =
      backend.status === "blocked" || backend.status === "absent"
        ? backend.status
        : processRecord?.status === "stale_recovered"
          ? "degraded"
          : "available";
    const hardware = hardwareSnapshot();
    const processSnapshot = this.backendProcessSnapshot(processRecord);
    const receipt = this.lifecycleReceipt("backend_health", {
      backendId,
      modelId: backend.label,
      state: status,
      evidenceRefs: backend.evidenceRefs ?? [],
      hardware,
      process: processSnapshot,
    });
    const updated = {
      ...backend,
      status,
      checkedAt,
      lastReceiptId: receipt.id,
      lastHealthReceiptId: receipt.id,
      processStatus: processSnapshot.processStatus,
      process: { ...backend.process, ...processSnapshot, receiptId: receipt.id },
    };
    this.backends.set(backendId, updated);
    this.writeMap("model-backends", this.backends);
    return updated;
  }

  startBackend(backendId, body = {}) {
    const backend = this.backend(backendId);
    if (backend.status === "blocked" && !backend.binaryPath && !String(backend.baseUrl ?? "").startsWith("local://")) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "Backend cannot be started until its binary path or base URL is configured.",
        details: { backendId, backendKind: backend.kind, evidenceRefs: backend.evidenceRefs ?? [] },
      });
    }
    const loadOptions = normalizeLoadOptions(body.load_options ?? body.loadOptions ?? this.runtimeDefaultLoadOptions(backendId) ?? {});
    const processRecord = this.ensureBackendProcess(backendId, { loadOptions, reason: "backend_start" });
    const processSnapshot = this.backendProcessSnapshot(processRecord);
    const receipt = this.lifecycleReceipt("backend_start", {
      backendId,
      modelId: backend.label,
      state: "available",
      evidenceRefs: backend.evidenceRefs ?? [],
      process: processSnapshot,
    });
    const updated = {
      ...backend,
      status: "available",
      processStatus: processSnapshot.processStatus ?? (backend.processStatus === "stateless_http" ? "stateless_http" : "started"),
      process: { ...backend.process, ...processSnapshot, receiptId: receipt.id },
      startedAt: this.nowIso(),
      lastReceiptId: receipt.id,
    };
    if (processRecord?.id) {
      this.backendProcesses.set(processRecord.id, { ...processRecord, lastReceiptId: receipt.id });
      this.writeMap("backend-processes", this.backendProcesses);
    }
    this.backends.set(backendId, updated);
    this.writeMap("model-backends", this.backends);
    this.writeBackendLog(backendId, {
      backendId,
      event: "backend_start",
      backendKind: backend.kind,
      receiptId: receipt.id,
      processId: processRecord?.id ?? null,
      pidHash: processRecord?.pidHash ?? null,
    });
    return updated;
  }

  stopBackend(backendId) {
    const backend = this.backend(backendId);
    const processRecord = this.stopBackendProcess(backend, { reason: "backend_stop" });
    const processSnapshot = this.backendProcessSnapshot(processRecord);
    const receipt = this.lifecycleReceipt("backend_stop", {
      backendId,
      modelId: backend.label,
      state: "stopped",
      evidenceRefs: backend.evidenceRefs ?? [],
      process: processSnapshot,
    });
    const updated = {
      ...backend,
      status: backend.kind === "fixture" ? "available" : "stopped",
      processStatus: backend.kind === "fixture" ? "stateless" : processSnapshot.processStatus ?? "stopped",
      process: { ...backend.process, ...processSnapshot, receiptId: receipt.id },
      stoppedAt: this.nowIso(),
      lastReceiptId: receipt.id,
    };
    if (processRecord?.id) {
      this.backendProcesses.set(processRecord.id, { ...processRecord, lastReceiptId: receipt.id });
      this.writeMap("backend-processes", this.backendProcesses);
    }
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
    const resolved = records.sort((left, right) => String(left.createdAt ?? "").localeCompare(String(right.createdAt ?? ""))).slice(-200);
    this.lifecycleReceipt("backend_logs_read", {
      backendId,
      modelId: this.backend(backendId).label,
      state: "read",
      logCount: resolved.length,
      evidenceRefs: ["backend_log_projection"],
    });
    return resolved;
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
    if (driver === "llama_cpp") return new LlamaCppModelProviderDriver({ state: this });
    if (driver === "ollama") return new OllamaModelProviderDriver();
    if (driver === "vllm") return new VllmModelProviderDriver({ state: this });
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
  if (kind === "llama_cpp") return "llama_cpp";
  if (kind === "ollama") return "ollama";
  if (kind === "vllm") return "vllm";
  if (["openai_compatible", "custom_http", "openai", "anthropic", "gemini"].includes(kind)) {
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

function backendBindAddress(baseUrl) {
  try {
    const parsed = new URL(baseUrl ?? "http://127.0.0.1:8080/v1");
    return {
      host: parsed.hostname || "127.0.0.1",
      port: parsed.port ? Number(parsed.port) : parsed.protocol === "https:" ? 443 : 80,
    };
  } catch {
    return { host: null, port: null };
  }
}

function providerHealthFailureStatus(error) {
  if (error?.status === 403 || error?.code === "policy") return "blocked";
  if (error?.status === 404) return "absent";
  return "degraded";
}

function configuredVaultMaterialAdapter({ now }) {
  if (process.env.IOI_KEYCHAIN_VAULT_PATH || process.env.IOI_KEYCHAIN_VAULT_KEY) {
    return new EncryptedKeychainVaultMaterialAdapter({
      filePath: process.env.IOI_KEYCHAIN_VAULT_PATH,
      keyMaterial: process.env.IOI_KEYCHAIN_VAULT_KEY,
      now,
    });
  }
  return null;
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

function normalizeLimit(value, fallback = 80, maximum = 200) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return Math.min(Math.floor(parsed), maximum);
}

function normalizeOptionalBytes(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed <= 0) return null;
  return Math.floor(parsed);
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
  const ttlSeconds = value.ttl_seconds ?? value.ttlSeconds ?? value.ttl ?? value.idle_ttl_seconds ?? value.idleTtlSeconds ?? 900;
  return {
    mode: value.mode ?? "on_demand",
    idleTtlSeconds: Number(ttlSeconds),
    autoEvict: value.auto_evict ?? value.autoEvict ?? true,
    memoryPressureEvict: value.memory_pressure_evict ?? value.memoryPressureEvict ?? true,
  };
}

function normalizeLoadOptions(value = {}, loadPolicy = {}) {
  const source = typeof value === "object" && value ? value : {};
  const ttl = source.ttl_seconds ?? source.ttlSeconds ?? source.ttl ?? loadPolicy.idleTtlSeconds ?? null;
  const gpu = source.gpu_offload ?? source.gpuOffload ?? source.gpu ?? null;
  const contextLength = source.context_length ?? source.contextLength ?? null;
  const parallel = source.parallelism ?? source.parallel ?? null;
  const identifier = source.identifier ?? source.instance_identifier ?? source.instanceIdentifier ?? null;
  return {
    estimateOnly: truthy(source.estimate_only ?? source.estimateOnly ?? false),
    gpu: gpu === null || gpu === undefined || gpu === "" ? null : String(gpu),
    contextLength: contextLength === null || contextLength === undefined || contextLength === "" ? null : Number(contextLength),
    parallel: parallel === null || parallel === undefined || parallel === "" ? null : Number(parallel),
    ttlSeconds: ttl === null || ttl === undefined || ttl === "" ? null : Number(ttl),
    identifier: identifier === null || identifier === undefined || identifier === "" ? null : String(identifier),
    modelPath: source.model_path ?? source.modelPath ?? null,
    model: source.model ?? null,
    dtype: source.dtype ?? null,
    tensorParallelSize:
      source.tensor_parallel_size === null || source.tensor_parallel_size === undefined || source.tensor_parallel_size === ""
        ? source.tensorParallelSize === null || source.tensorParallelSize === undefined || source.tensorParallelSize === ""
          ? null
          : Number(source.tensorParallelSize)
        : Number(source.tensor_parallel_size),
    gpuMemoryUtilization:
      source.gpu_memory_utilization === null || source.gpu_memory_utilization === undefined || source.gpu_memory_utilization === ""
        ? source.gpuMemoryUtilization === null || source.gpuMemoryUtilization === undefined || source.gpuMemoryUtilization === ""
          ? null
          : Number(source.gpuMemoryUtilization)
        : Number(source.gpu_memory_utilization),
    maxModelLen:
      source.max_model_len === null || source.max_model_len === undefined || source.max_model_len === ""
        ? source.maxModelLen === null || source.maxModelLen === undefined || source.maxModelLen === ""
          ? null
          : Number(source.maxModelLen)
        : Number(source.max_model_len),
  };
}

function normalizeRuntimeEngineDefaultLoadOptions(value = {}) {
  const normalized = normalizeLoadOptions(value, {});
  const defaults = {};
  if (normalized.gpu !== null) defaults.gpu = normalized.gpu;
  if (normalized.contextLength !== null) defaults.contextLength = normalized.contextLength;
  if (normalized.parallel !== null) defaults.parallel = normalized.parallel;
  if (normalized.ttlSeconds !== null) defaults.ttlSeconds = normalized.ttlSeconds;
  if (normalized.identifier !== null) defaults.identifier = normalized.identifier;
  return defaults;
}

function hasExplicitTtlOption(value = {}) {
  if (!value || typeof value !== "object") return false;
  return (
    value.ttl_seconds !== undefined ||
    value.ttlSeconds !== undefined ||
    value.ttl !== undefined ||
    value.idle_ttl_seconds !== undefined ||
    value.idleTtlSeconds !== undefined
  );
}

function lmStudioLoadOptionArgs(loadOptions = {}) {
  const args = [];
  if (loadOptions.gpu !== null && loadOptions.gpu !== undefined) args.push("--gpu", String(loadOptions.gpu));
  if (loadOptions.contextLength) args.push("--context-length", String(loadOptions.contextLength));
  if (loadOptions.parallel) args.push("--parallel", String(loadOptions.parallel));
  if (loadOptions.ttlSeconds) args.push("--ttl", String(loadOptions.ttlSeconds));
  if (loadOptions.identifier) args.push("--identifier", String(loadOptions.identifier));
  return args;
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
  if (providerHasVaultRef(provider)) return;
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

function providerHasVaultRef(provider) {
  return typeof provider.secretRef === "string" && provider.secretRef.startsWith("vault://");
}

function providerAuthHeaders(provider, state) {
  const requiresVault = providerRequiresVaultSecret(provider);
  const hasVaultRef = providerHasVaultRef(provider);
  if (!requiresVault && !hasVaultRef) return { headers: {}, evidence: null };
  if (requiresVault) assertProviderVaultBoundary(provider);
  const resolved = state?.vault?.resolveVaultRef(provider.secretRef, `provider.auth:${provider.id}`);
  const headerName = normalizeProviderAuthHeaderName(provider.authHeaderName ?? provider.auth_header_name);
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
      [headerName]: providerAuthorizationHeaderValue(provider, resolved.material),
    },
    evidence: {
      vaultRefHash: resolved.vaultRefHash,
      resolvedMaterial: true,
      evidenceRefs: resolved.evidenceRefs ?? ["VaultPort.resolveVaultRef"],
      headerNames: [headerName],
      authScheme: normalizeProviderAuthScheme(provider.authScheme ?? provider.auth_scheme),
    },
  };
}

function providerAuthorizationHeaderValue(provider, material) {
  const scheme = normalizeProviderAuthScheme(provider.authScheme ?? provider.auth_scheme);
  if (scheme === "raw") return material;
  if (scheme === "api_key") return material;
  return `Bearer ${material}`;
}

function normalizeProviderAuthScheme(value) {
  const scheme = String(value ?? "bearer").toLowerCase().replace(/[-\s]+/g, "_");
  if (["bearer", "raw", "api_key"].includes(scheme)) return scheme;
  throw runtimeError({
    status: 400,
    code: "validation",
    message: "Provider auth scheme must be bearer, raw, or api_key.",
    details: { authScheme: scheme },
  });
}

function normalizeProviderAuthHeaderName(value) {
  const headerName = String(value ?? "authorization").trim().toLowerCase();
  if (!/^[a-z0-9!#$%&'*+.^_`|~-]+$/.test(headerName)) {
    throw runtimeError({
      status: 400,
      code: "validation",
      message: "Provider auth header name must be a valid HTTP header token.",
      details: { authHeaderName: SECRET_REDACTION },
    });
  }
  const forbidden = new Set([
    "connection",
    "content-length",
    "cookie",
    "host",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
  ]);
  if (forbidden.has(headerName)) {
    throw runtimeError({
      status: 400,
      code: "validation",
      message: "Provider auth header name is not allowed for vault-backed auth injection.",
      details: { authHeaderName: headerName },
    });
  }
  return headerName;
}

function publicProvider(provider, vaultMetadata = null) {
  const hasVaultRef = providerHasVaultRef(provider);
  const requiresVault = providerRequiresVaultSecret(provider);
  const runtimeBound = Boolean(vaultMetadata?.resolvedMaterial);
  const configured = hasVaultRef || Boolean(vaultMetadata?.configured);
  return {
    ...provider,
    status: requiresVault && !hasVaultRef ? "blocked" : provider.status,
    secretRef: hasVaultRef ? { redacted: true, hash: stableHash(provider.secretRef) } : provider.secretRef ? SECRET_REDACTION : null,
    secretConfigured: configured,
    authScheme: provider.authScheme ?? "bearer",
    authHeaderName: provider.authHeaderName ?? "authorization",
    vaultBoundary: {
      required: requiresVault,
      failClosed: requiresVault && !hasVaultRef,
      configured,
      resolvedMaterial: runtimeBound,
      runtimeBound,
      requiresRuntimeBinding: configured && !runtimeBound,
      vaultRefHash: hasVaultRef ? stableHash(provider.secretRef) : vaultMetadata?.vaultRefHash ?? null,
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

function publicVaultRefMetadata(metadata) {
  return {
    vaultRef: { redacted: true, hash: metadata.vaultRefHash },
    vaultRefHash: metadata.vaultRefHash,
    label: metadata.label ?? null,
    purpose: metadata.purpose ?? "provider.auth",
    source: metadata.source ?? "agentgres_local_vault_metadata",
    materialSource: metadata.materialSource ?? (metadata.resolvedMaterial ? "runtime_memory" : "unbound"),
    configured: Boolean(metadata.configured),
    resolvedMaterial: Boolean(metadata.resolvedMaterial),
    runtimeBound: Boolean(metadata.runtimeBound ?? metadata.resolvedMaterial),
    materialBound: Boolean(metadata.materialBound ?? metadata.resolvedMaterial),
    requiresRebind: Boolean(metadata.requiresRebind ?? (metadata.configured && !metadata.resolvedMaterial)),
    createdAt: metadata.createdAt ?? null,
    updatedAt: metadata.updatedAt ?? null,
    removedAt: metadata.removedAt ?? null,
    lastResolvedAt: metadata.lastResolvedAt ?? null,
    evidenceRefs: normalizeScopes(metadata.evidenceRefs, ["VaultPort.localBinding"]),
  };
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
  const quantization = parseModelQuantization(name);
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

function parseModelQuantization(value) {
  return String(value ?? "").match(/\b(Q[0-9]_[A-Za-z0-9_]+|Q[0-9]+|F16|BF16|IQ[0-9]_[A-Za-z0-9_]+)\b/i)?.[1] ?? null;
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

function parseLmStudioRuntimeEngines(text) {
  return String(text ?? "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("LLM ENGINE"))
    .map((line) => {
      const columns = line.split(/\s{2,}/).filter(Boolean);
      const name = columns[0] ?? "";
      if (!name) return null;
      const selected = columns.some((column) => column === "yes" || column === "selected" || column.includes("\u2713"));
      const modelFormat = columns.at(-1) ?? "unknown";
      return {
        id: `lmstudio.runtime.${safeId(name)}`,
        kind: "lm_studio_runtime",
        label: name,
        status: "installed",
        selected,
        modelFormat,
        source: "lm_studio_public_lms_runtime_ls",
        processStatus: selected ? "selected" : "installed",
      };
    })
    .filter(Boolean);
}

function parseLmStudioRuntimeSurvey(text) {
  const lines = String(text ?? "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  const selectedRuntime = lines.find((line) => line.startsWith("Survey by "))?.replace(/^Survey by\s+/, "") ?? null;
  const cpu = lines.find((line) => line.startsWith("CPU:"))?.replace(/^CPU:\s*/, "") ?? null;
  const ram = lines.find((line) => line.startsWith("RAM:"))?.replace(/^RAM:\s*/, "") ?? null;
  const accelerators = lines
    .filter((line) => !line.startsWith("Survey by ") && !line.startsWith("GPU/") && !line.startsWith("CPU:") && !line.startsWith("RAM:"))
    .map((line) => {
      const match = line.match(/^(.+?)\s{2,}([0-9.]+\s+[A-Za-z]+)$/);
      if (!match) return null;
      return {
        label: match[1].trim(),
        vram: match[2].trim(),
      };
    })
    .filter(Boolean);
  return { selectedRuntime, cpu, ram, accelerators };
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

function fixtureModelCatalog(searchedAt) {
  return [
    {
      id: "catalog.fixture.autopilot-native-3b-q4",
      providerId: "provider.autopilot.local",
      modelId: "autopilot/native-fixture-3b",
      family: "autopilot-native-fixture",
      format: "gguf",
      quantization: "Q4_K_M",
      sizeBytes: 96 * 1024 * 1024,
      contextWindow: 4096,
      sourceUrl: "fixture://catalog/autopilot-native-3b-q4",
      sourceUrlHash: stableHash("fixture://catalog/autopilot-native-3b-q4"),
      sourceLabel: "Fixture catalog / native local 3B Q4",
      license: "fixture-local-dev",
      compatibility: ["native_local_fixture", "llama_cpp"],
      tags: ["chat", "code", "local"],
      discoveredAt: searchedAt,
    },
    {
      id: "catalog.fixture.embedding-nomic-q8",
      providerId: "provider.autopilot.local",
      modelId: "autopilot/nomic-embed-fixture",
      family: "nomic-embed-fixture",
      format: "gguf",
      quantization: "Q8_0",
      sizeBytes: 32 * 1024 * 1024,
      contextWindow: 2048,
      sourceUrl: "fixture://catalog/nomic-embed-q8",
      sourceUrlHash: stableHash("fixture://catalog/nomic-embed-q8"),
      sourceLabel: "Fixture catalog / embedding Q8",
      license: "fixture-local-dev",
      compatibility: ["native_local_fixture", "embeddings"],
      tags: ["embedding", "local"],
      discoveredAt: searchedAt,
    },
  ];
}

function liveModelCatalogEnabled() {
  return process.env.IOI_LIVE_MODEL_CATALOG === "1";
}

function liveModelDownloadEnabled() {
  return process.env.IOI_LIVE_MODEL_DOWNLOAD === "1";
}

function huggingFaceCatalogBaseUrl() {
  return process.env.IOI_MODEL_CATALOG_HF_BASE_URL ?? "https://huggingface.co";
}

function modelCatalogTimeoutMs() {
  return Number(process.env.IOI_MODEL_CATALOG_TIMEOUT_MS ?? 5000) || 5000;
}

function modelDownloadTimeoutMs() {
  return Number(process.env.IOI_MODEL_DOWNLOAD_TIMEOUT_MS ?? 30000) || 30000;
}

async function fetchWithTimeout(url, { timeoutMs, headers = {} } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs ?? 5000);
  try {
    return await fetch(url, { headers, signal: controller.signal });
  } finally {
    clearTimeout(timeout);
  }
}

function huggingFaceCatalogEntries(record, { baseUrl, searchedAt }) {
  const repoId = String(record.modelId ?? record.id ?? record.repo_id ?? record.repoId ?? "").trim();
  if (!repoId) return [];
  const files = huggingFaceFileCandidates(record);
  const candidates = files.length > 0 ? files : [{ path: null, sizeBytes: Number(record.size ?? record.downloadsSize ?? 0) || null }];
  return candidates
    .map((file) => huggingFaceCatalogEntry(record, file, { baseUrl, repoId, searchedAt }))
    .filter(Boolean);
}

function huggingFaceFileCandidates(record) {
  const rawFiles = [
    ...(Array.isArray(record.siblings) ? record.siblings : []),
    ...(Array.isArray(record.files) ? record.files : []),
    ...(Array.isArray(record.downloads) ? record.downloads : []),
  ];
  return rawFiles
    .map((file) => ({
      path: file.rfilename ?? file.path ?? file.name ?? file.file ?? file.filename ?? null,
      sizeBytes: Number(file.size ?? file.sizeBytes ?? file.lfs?.size ?? 0) || null,
      downloadUrl: file.downloadUrl ?? file.download_url ?? file.url ?? null,
    }))
    .filter((file) => file.path && modelCatalogFileFormat(file.path));
}

function huggingFaceCatalogEntry(record, file, { baseUrl, repoId, searchedAt }) {
  const filePath = file.path ?? `${safeId(repoId)}.gguf`;
  const format = modelCatalogFileFormat(filePath);
  if (!format) return null;
  const quantization = parseModelQuantization(filePath) ?? parseModelQuantization(record.modelId ?? record.id ?? "") ?? null;
  const sourceUrl = file.downloadUrl ?? huggingFaceResolveUrl(baseUrl, repoId, filePath);
  const tags = normalizeScopes(record.tags, []);
  return {
    id: `catalog.huggingface.${safeId(repoId)}.${safeId(filePath)}`,
    providerId: "provider.autopilot.local",
    catalogProviderId: "catalog.huggingface",
    modelId: repoId,
    family: String(record.pipeline_tag ?? record.pipelineTag ?? record.library_name ?? "huggingface"),
    format,
    quantization,
    sizeBytes: file.sizeBytes,
    contextWindow: Number(record.contextWindow ?? record.context_window ?? 0) || null,
    sourceUrl,
    sourceUrlHash: stableHash(sourceUrl),
    sourceLabel: `Hugging Face / ${repoId}${filePath ? ` / ${filePath}` : ""}`,
    license: record.cardData?.license ?? record.license ?? null,
    compatibility: catalogCompatibilityForFormat(format),
    tags: [...new Set([...tags, format, quantization].filter(Boolean))],
    variantPath: filePath,
    gatedBy: ["IOI_LIVE_MODEL_CATALOG", "IOI_LIVE_MODEL_DOWNLOAD"],
    discoveredAt: searchedAt,
  };
}

function modelCatalogFileFormat(filePath) {
  const lower = String(filePath ?? "").toLowerCase();
  if (lower.endsWith(".gguf")) return "gguf";
  if (lower.includes("mlx")) return "mlx";
  if (lower.endsWith(".safetensors")) return "safetensors";
  return null;
}

function catalogCompatibilityForFormat(format) {
  if (format === "gguf") return ["native_local_fixture", "llama_cpp"];
  if (format === "mlx") return ["mlx", "local_import"];
  if (format === "safetensors") return ["vllm", "openai_compatible"];
  return ["local_import"];
}

function huggingFaceResolveUrl(baseUrl, repoId, filePath) {
  const base = String(baseUrl).replace(/\/+$/, "");
  const pathPart = String(filePath)
    .split("/")
    .map((part) => encodeURIComponent(part))
    .join("/");
  return `${base}/${repoId}/resolve/main/${pathPart}`;
}

function catalogVariantForSource(source, body = {}) {
  const catalogEntry = fixtureModelCatalog(new Date(0).toISOString()).find((entry) => entry.sourceUrl === source);
  const publicSource = publicDownloadSource(source);
  return {
    id: body.variant_id ?? body.variantId ?? catalogEntry?.id ?? `variant.${safeId(publicSource)}`,
    family: body.family ?? catalogEntry?.family ?? modelIdFromSourceUrl(publicSource),
    format: body.format ?? catalogEntry?.format ?? modelCatalogFileFormat(publicSource) ?? "gguf",
    quantization: body.quantization ?? catalogEntry?.quantization ?? parseModelQuantization(publicSource) ?? "Q4_K_M",
    sizeBytes: Number(body.size_bytes ?? body.sizeBytes ?? catalogEntry?.sizeBytes ?? 0),
    contextWindow: Number(body.context_window ?? body.contextWindow ?? catalogEntry?.contextWindow ?? 4096),
    sourceLabel: body.source_label ?? body.sourceLabel ?? catalogEntry?.sourceLabel ?? sourceLabelForUrl(source),
    license: body.license ?? catalogEntry?.license ?? null,
    compatibility: normalizeScopes(body.compatibility, catalogEntry?.compatibility ?? ["native_local_fixture"]),
  };
}

function modelIdFromSourceUrl(sourceUrl) {
  return safeId(String(sourceUrl).split(/[/?#]/).filter(Boolean).at(-1) ?? "catalog-model").replaceAll(".", "-");
}

function sourceLabelForUrl(source) {
  if (String(source).startsWith("fixture://")) return "Fixture catalog";
  if (String(source).includes("huggingface.co")) return "Hugging Face";
  return "Model catalog";
}

function normalizeImportMode(value) {
  const mode = String(value ?? "reference").toLowerCase().replaceAll("-", "_");
  if (["reference", "operator"].includes(mode)) return mode;
  if (["copy", "move", "hardlink", "symlink", "dry_run"].includes(mode)) return mode;
  throw runtimeError({
    status: 400,
    code: "bad_request",
    message: "Import mode must be copy, move, hardlink, symlink, dry_run, or reference.",
    details: { importMode: mode },
  });
}

function importTargetPath(modelRoot, modelId, sourcePath) {
  const extension = path.extname(sourcePath) || ".gguf";
  return path.join(modelRoot, "imports", safeFileName(modelId), `${safeFileName(modelId)}${extension}`);
}

function materializeImportArtifact(modelRoot, modelId, sourcePath, importMode) {
  if (["reference", "operator"].includes(importMode)) return sourcePath;
  const targetPath = importTargetPath(modelRoot, modelId, sourcePath);
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.rmSync(targetPath, { force: true });
  if (importMode === "copy") fs.copyFileSync(sourcePath, targetPath);
  if (importMode === "move") fs.renameSync(sourcePath, targetPath);
  if (importMode === "hardlink") fs.linkSync(sourcePath, targetPath);
  if (importMode === "symlink") fs.symlinkSync(sourcePath, targetPath);
  return targetPath;
}

function listModelFiles(root) {
  if (!fs.existsSync(root)) return [];
  const results = [];
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const entryPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      results.push(...listModelFiles(entryPath));
    } else if (entry.isFile() && modelFileScore(entryPath) > 0) {
      results.push(entryPath);
    }
  }
  return results.sort();
}

function fileSha256(filePath) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(filePath));
  return `sha256:${hash.digest("hex")}`;
}

function materializeFixtureDownload({ targetPath, fixtureContent }) {
  fs.writeFileSync(targetPath, fixtureContent);
  const bytesCompleted = fs.statSync(targetPath).size;
  return {
    bytesTotal: bytesCompleted,
    bytesCompleted,
    checksum: fileSha256(targetPath),
    resumeOffset: 0,
  };
}

async function materializeLiveDownload({ source, targetPath, expectedChecksum, maxBytes, resume, timeoutMs }) {
  const partialPath = `${targetPath}.part`;
  const resumeOffset = resume && fs.existsSync(partialPath) ? fs.statSync(partialPath).size : 0;
  const headers = resumeOffset > 0 ? { range: `bytes=${resumeOffset}-` } : {};
  const response = await fetchWithTimeout(source, { timeoutMs, headers });
  if (!response.ok) {
    throw new Error(`live_download_http_${response.status}`);
  }
  const contentLength = Number(response.headers.get("content-length") ?? 0) || 0;
  const bytesTotal = response.status === 206 ? resumeOffset + contentLength : contentLength || 0;
  if (maxBytes && bytesTotal && bytesTotal > maxBytes) {
    throw new Error("live_download_size_limit_exceeded");
  }
  const appending = resumeOffset > 0 && response.status === 206;
  const writePath = appending ? partialPath : partialPath;
  if (!appending) fs.rmSync(partialPath, { force: true });
  const stream = fs.createWriteStream(writePath, { flags: appending ? "a" : "w" });
  let bytesCompleted = appending ? resumeOffset : 0;
  try {
    for await (const chunk of response.body) {
      const buffer = Buffer.from(chunk);
      bytesCompleted += buffer.length;
      if (maxBytes && bytesCompleted > maxBytes) {
        throw new Error("live_download_size_limit_exceeded");
      }
      if (!stream.write(buffer)) {
        await new Promise((resolve) => stream.once("drain", resolve));
      }
    }
  } finally {
    await new Promise((resolve, reject) => stream.end((error) => (error ? reject(error) : resolve())));
  }
  fs.renameSync(partialPath, targetPath);
  const checksum = fileSha256(targetPath);
  if (expectedChecksum && checksum !== expectedChecksum) {
    throw new Error("live_download_checksum_mismatch");
  }
  return {
    bytesTotal: bytesTotal || bytesCompleted,
    bytesCompleted,
    checksum,
    resumeOffset: appending ? resumeOffset : 0,
  };
}

function cleanupPartialDownload(targetPath) {
  let cleanupState = "not_needed";
  for (const filePath of [targetPath, `${targetPath}.part`]) {
    if (!fs.existsSync(filePath)) continue;
    try {
      fs.rmSync(filePath, { force: true });
      cleanupState = "removed_partial";
    } catch {
      cleanupState = "cleanup_failed";
    }
  }
  return cleanupState;
}

function downloadFailureReason(error) {
  const message = String(error?.message ?? error ?? "download_failed");
  if (message.includes("checksum")) return "checksum_mismatch";
  if (message.includes("size_limit_exceeded")) return "size_limit_exceeded";
  if (message.includes("AbortError") || message.includes("aborted")) return "network_timeout";
  const http = message.match(/live_download_http_([0-9]+)/)?.[1];
  if (http) return `http_${http}`;
  return "network_download_failed";
}

function publicDownloadSource(source) {
  const text = String(source ?? "");
  if (text.startsWith("fixture://")) return text.split("?")[0];
  try {
    const url = new URL(text);
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return url.toString();
  } catch {
    return text;
  }
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
  if (
    [
      "tokenCount",
      "toolReceiptIds",
      "input_tokens",
      "output_tokens",
      "total_tokens",
      "providerAuthHeaderNames",
      "resolvedMaterial",
      "runtimeBound",
      "materialBound",
      "materialSource",
    ].includes(key)
  ) {
    return false;
  }
  return /tokenHash|tokenValue|secret|material|apiKey|authorization|header|privateKey|accessToken|refreshToken/i.test(key);
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
