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
      "model-catalog-providers",
      "oauth-sessions",
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

class OAuthCredentialProvider {
  constructor({ now, vault }) {
    this.now = now;
    this.vault = vault;
  }

  async exchangeAuthorizationCode({ providerId, body = {} }) {
    const sessionId = body.session_id ?? body.sessionId ?? `oauth_session.${safeId(providerId)}.${crypto.randomUUID()}`;
    const tokenEndpointInput = requiredString(body.token_endpoint ?? body.tokenEndpoint, "token_endpoint");
    const authorizationCode = requiredString(body.authorization_code ?? body.authorizationCode ?? body.code, "authorization_code");
    const scopes = normalizeOAuthScopes(body.scopes ?? body.scope, []);
    const redirectUri = body.redirect_uri ?? body.redirectUri ?? null;
    const clientIdInput = body.client_id ?? body.clientId ?? null;
    const clientSecretVaultRef = body.client_secret_vault_ref ?? body.clientSecretVaultRef ?? null;
    if (body.client_secret || body.clientSecret) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth client secrets must be provided through vault refs.",
        details: { clientSecret: SECRET_REDACTION },
      });
    }
    const tokenEndpointVaultRef = body.token_endpoint_vault_ref ?? body.tokenEndpointVaultRef ?? oauthSessionVaultRef(providerId, sessionId, "token-endpoint");
    const tokenEndpointBinding = this.vault.bindVaultRef({
      vaultRef: tokenEndpointVaultRef,
      material: tokenEndpointInput,
      purpose: `oauth.token_endpoint:${providerId}`,
      label: `OAuth token endpoint for ${providerId}`,
    });
    let clientIdVaultRef = body.client_id_vault_ref ?? body.clientIdVaultRef ?? null;
    let clientIdBinding = null;
    if (typeof clientIdInput === "string" && clientIdInput.trim()) {
      clientIdVaultRef = clientIdVaultRef ?? oauthSessionVaultRef(providerId, sessionId, "client-id");
      clientIdBinding = this.vault.bindVaultRef({
        vaultRef: clientIdVaultRef,
        material: clientIdInput.trim(),
        purpose: `oauth.client_id:${providerId}`,
        label: `OAuth client id for ${providerId}`,
      });
    }
    const clientSecret = clientSecretVaultRef
      ? this.vault.resolveVaultRef(clientSecretVaultRef, `oauth.client_secret:${providerId}`)
      : null;
    if (clientSecretVaultRef && !clientSecret?.material) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth client secret vault ref is configured, but no runtime vault material is available.",
        details: {
          clientSecretVaultRefHash: clientSecret?.vaultRefHash ?? stableHash(clientSecretVaultRef),
          evidenceRefs: normalizeScopes(clientSecret?.evidenceRefs, ["VaultPort.resolveVaultRef", "oauth_client_secret_fail_closed"]),
        },
      });
    }
    const payload = {
      grant_type: "authorization_code",
      code: authorizationCode,
      ...(redirectUri ? { redirect_uri: String(redirectUri) } : {}),
      ...(clientIdInput ? { client_id: String(clientIdInput) } : {}),
      ...(clientSecret?.material ? { client_secret: clientSecret.material } : {}),
      ...(scopes.length > 0 ? { scope: scopes.join(" ") } : {}),
    };
    const response = await fetchOAuthToken(tokenEndpointInput, payload);
    const tokenPayload = await parseOAuthTokenResponse(response);
    const now = this.now().toISOString();
    const expiresAt = oauthExpiresAt(this.now(), tokenPayload.expires_in ?? tokenPayload.expiresIn);
    const accessVaultRef = body.access_vault_ref ?? body.accessVaultRef ?? oauthSessionVaultRef(providerId, sessionId, "access-token");
    const accessBinding = this.vault.bindVaultRef({
      vaultRef: accessVaultRef,
      material: requiredString(tokenPayload.access_token ?? tokenPayload.accessToken, "access_token"),
      purpose: `oauth.access_token:${providerId}`,
      label: `OAuth access token for ${providerId}`,
    });
    const refreshToken = tokenPayload.refresh_token ?? tokenPayload.refreshToken ?? null;
    const refreshVaultRef = refreshToken
      ? body.refresh_vault_ref ?? body.refreshVaultRef ?? oauthSessionVaultRef(providerId, sessionId, "refresh-token")
      : null;
    const refreshBinding = refreshToken
      ? this.vault.bindVaultRef({
          vaultRef: refreshVaultRef,
          material: String(refreshToken),
          purpose: `oauth.refresh_token:${providerId}`,
          label: `OAuth refresh token for ${providerId}`,
        })
      : null;
    const session = {
      id: sessionId,
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      providerId,
      status: "active",
      accessVaultRef,
      accessVaultRefHash: accessBinding.vaultRefHash,
      accessTokenHash: stableHash(String(tokenPayload.access_token ?? tokenPayload.accessToken)),
      refreshVaultRef,
      refreshVaultRefHash: refreshBinding?.vaultRefHash ?? null,
      refreshTokenHash: refreshToken ? stableHash(String(refreshToken)) : null,
      tokenEndpointVaultRef,
      tokenEndpointVaultRefHash: tokenEndpointBinding.vaultRefHash,
      tokenEndpointHash: stableHash(tokenEndpointInput),
      clientIdVaultRef,
      clientIdVaultRefHash: clientIdBinding?.vaultRefHash ?? (clientIdVaultRef ? stableHash(clientIdVaultRef) : null),
      clientIdHash: clientIdInput ? stableHash(String(clientIdInput)) : null,
      clientSecretVaultRef: clientSecretVaultRef ?? null,
      clientSecretVaultRefHash: clientSecret?.vaultRefHash ?? (clientSecretVaultRef ? stableHash(clientSecretVaultRef) : null),
      scopes: normalizeOAuthScopes(tokenPayload.scope, scopes),
      expiresAt,
      issuedAt: now,
      lastRefreshedAt: null,
      refreshCount: 0,
      revokedAt: null,
      evidenceRefs: [
        "OAuthCredentialProvider.exchangeAuthorizationCode",
        "VaultOAuthSession",
        "VaultPort.bindVaultRef",
        "oauth_tokens_not_persisted",
      ],
    };
    return { session, evidence: publicOAuthSession(session), tokenResponseKind: "authorization_code" };
  }

  async refreshAccessToken(session) {
    if (!session || session.status !== "active") {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth session is not active.",
        details: { oauthSessionHash: session?.id ? stableHash(session.id) : null, status: session?.status ?? "missing" },
      });
    }
    if (!session.refreshVaultRef) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth session has no refresh token vault ref.",
        details: { oauthSessionHash: stableHash(session.id), evidenceRefs: ["oauth_refresh_fail_closed", "refresh_vault_ref_required"] },
      });
    }
    const refresh = this.vault.resolveVaultRef(session.refreshVaultRef, `oauth.refresh_token:${session.providerId}`);
    const tokenEndpoint = this.vault.resolveVaultRef(session.tokenEndpointVaultRef, `oauth.token_endpoint:${session.providerId}`);
    const clientId = session.clientIdVaultRef
      ? this.vault.resolveVaultRef(session.clientIdVaultRef, `oauth.client_id:${session.providerId}`)
      : null;
    const clientSecret = session.clientSecretVaultRef
      ? this.vault.resolveVaultRef(session.clientSecretVaultRef, `oauth.client_secret:${session.providerId}`)
      : null;
    const missing = [
      !refresh?.material ? "refresh_token" : null,
      !tokenEndpoint?.material ? "token_endpoint" : null,
      session.clientIdVaultRef && !clientId?.material ? "client_id" : null,
      session.clientSecretVaultRef && !clientSecret?.material ? "client_secret" : null,
    ].filter(Boolean);
    if (missing.length > 0) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth refresh requires vault material that is not currently available.",
        details: {
          oauthSessionHash: stableHash(session.id),
          missing,
          evidenceRefs: ["oauth_refresh_fail_closed", "VaultPort.resolveVaultRef"],
        },
      });
    }
    const payload = {
      grant_type: "refresh_token",
      refresh_token: refresh.material,
      ...(clientId?.material ? { client_id: clientId.material } : {}),
      ...(clientSecret?.material ? { client_secret: clientSecret.material } : {}),
        ...(session.scopes?.length ? { scope: session.scopes.join(" ") } : {}),
    };
    const response = await fetchOAuthToken(tokenEndpoint.material, payload);
    const tokenPayload = await parseOAuthTokenResponse(response);
    const accessToken = requiredString(tokenPayload.access_token ?? tokenPayload.accessToken, "access_token");
    const accessBinding = this.vault.bindVaultRef({
      vaultRef: session.accessVaultRef,
      material: accessToken,
      purpose: `oauth.access_token:${session.providerId}`,
      label: `OAuth access token for ${session.providerId}`,
    });
    const nextRefreshToken = tokenPayload.refresh_token ?? tokenPayload.refreshToken ?? null;
    let refreshBinding = null;
    if (nextRefreshToken) {
      refreshBinding = this.vault.bindVaultRef({
        vaultRef: session.refreshVaultRef,
        material: String(nextRefreshToken),
        purpose: `oauth.refresh_token:${session.providerId}`,
        label: `OAuth refresh token for ${session.providerId}`,
      });
    }
    return {
      ...session,
      status: "active",
      accessVaultRefHash: accessBinding.vaultRefHash,
      accessTokenHash: stableHash(accessToken),
      refreshVaultRefHash: refreshBinding?.vaultRefHash ?? session.refreshVaultRefHash ?? null,
      refreshTokenHash: nextRefreshToken ? stableHash(String(nextRefreshToken)) : session.refreshTokenHash ?? null,
      scopes: normalizeOAuthScopes(tokenPayload.scope, session.scopes ?? []),
      expiresAt: oauthExpiresAt(this.now(), tokenPayload.expires_in ?? tokenPayload.expiresIn),
      lastRefreshedAt: this.now().toISOString(),
      refreshCount: Number(session.refreshCount ?? 0) + 1,
      evidenceRefs: normalizeScopes(
        [
          ...normalizeScopes(session.evidenceRefs, []),
          "OAuthCredentialProvider.refreshAccessToken",
          "VaultOAuthSession",
          "oauth_refresh_tokens_not_persisted",
        ],
        [],
      ),
    };
  }

  revokeSession(session) {
    if (!session) {
      throw runtimeError({ status: 404, code: "not_found", message: "OAuth session not found.", details: {} });
    }
    for (const vaultRef of [session.accessVaultRef, session.refreshVaultRef].filter(Boolean)) {
      this.vault.removeVaultRef(vaultRef, `oauth.revoke:${session.providerId}`);
    }
    return {
      ...session,
      status: "revoked",
      revokedAt: this.now().toISOString(),
      evidenceRefs: normalizeScopes([...normalizeScopes(session.evidenceRefs, []), "OAuthCredentialProvider.revokeSession"], []),
    };
  }

  async resolveAccessHeader(session, { headerName = "authorization" } = {}) {
    let current = session;
    let refreshed = false;
    if (!current || current.status !== "active") {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth session is not active.",
        details: {
          oauthSessionHash: current?.id ? stableHash(current.id) : null,
          status: current?.status ?? "missing",
          catalogAuthScheme: "oauth2",
          catalogAuthHeaderNameHash: stableHash(headerName),
          oauthBoundary: oauthBoundaryForSession(current),
          evidenceRefs: ["OAuthCredentialProvider.resolveAccessHeader", "oauth_session_inactive"],
        },
      });
    }
    if (oauthSessionNeedsRefresh(current, this.now())) {
      current = await this.refreshAccessToken(current);
      refreshed = true;
    }
    const access = this.vault.resolveVaultRef(current.accessVaultRef, `oauth.access_token:${current.providerId}`);
    if (!access?.material) {
      throw runtimeError({
        status: 403,
        code: "policy",
        message: "OAuth access token vault ref is configured, but no runtime vault material is available.",
        details: {
          oauthSessionHash: stableHash(current.id),
          authVaultRefHash: access?.vaultRefHash ?? current.accessVaultRefHash ?? null,
          resolvedMaterial: false,
          catalogAuthScheme: "oauth2",
          catalogAuthHeaderNameHash: stableHash(headerName),
          oauthBoundary: oauthBoundaryForSession(current),
          evidenceRefs: normalizeScopes(access?.evidenceRefs, ["OAuthCredentialProvider.resolveAccessHeader", "oauth_access_fail_closed"]),
        },
      });
    }
    return {
      session: current,
      refreshed,
      headerValue: `Bearer ${access.material}`,
      evidence: {
        authVaultRefHash: access.vaultRefHash,
        oauthSessionHash: stableHash(current.id),
        resolvedMaterial: true,
        catalogAuthResolved: true,
        catalogAuthScheme: "oauth2",
        catalogAuthHeaderNameHash: stableHash(headerName),
        oauthBoundary: oauthBoundaryForSession(current, { refreshed }),
        evidenceRefs: normalizeScopes(
          [
            ...normalizeScopes(access.evidenceRefs, []),
            "OAuthCredentialProvider.resolveAccessHeader",
            refreshed ? "OAuthCredentialProvider.refreshAccessToken" : "oauth_access_token_active",
          ],
          [],
        ),
      },
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

  supportsStream(kind) {
    return kind === "chat.completions" || kind === "chat" || kind === "responses";
  }

  async streamInvoke({ kind, input, endpoint, state }) {
    if (!this.supportsStream(kind)) return null;
    const backendId = endpoint.backendId ?? "backend.autopilot.native-local.fixture";
    const processRecord = state.ensureBackendProcess(backendId, {
      endpoint,
      loadOptions: state.loadedInstanceForEndpoint(endpoint.id, false)?.loadOptions ?? {},
      reason: "model_stream",
    });
    const processSnapshot = state.backendProcessSnapshot(processRecord);
    const outputText = nativeLocalOutput({ kind, input, modelId: endpoint.modelId });
    const tokenCount = estimateTokens(input, outputText);
    state.writeBackendLog(endpoint.id, {
      backendId,
      event: "stream",
      modelId: endpoint.modelId,
      kind,
      inputHash: stableHash(input),
      outputHash: stableHash(outputText),
      backend: "autopilot.native_local.fixture",
      processId: processRecord?.id ?? null,
      pidHash: processRecord?.pidHash ?? null,
    });
    const streamHandle = jsonLineReadableStream(nativeLocalStreamRecords(outputText, tokenCount), {
      delayMs: providerStreamFrameDelayMs(),
      onAbort: (reason) => {
        state.writeBackendLog(endpoint.id, {
          backendId,
          event: "stream_abort",
          modelId: endpoint.modelId,
          kind,
          reason,
          inputHash: stableHash(input),
          outputHash: stableHash(outputText),
          backend: "autopilot.native_local.fixture",
          processId: processRecord?.id ?? null,
          pidHash: processRecord?.pidHash ?? null,
        });
      },
    });
    return {
      stream: streamHandle.stream,
      abort: () => streamHandle.abort("client_disconnect"),
      status: 200,
      streamFormat: "ioi_jsonl",
      streamKind: kind === "responses" ? "openai_responses_native_local" : "openai_chat_completions_native_local",
      providerResponseKind: kind === "responses" ? "native_local.responses.stream" : "native_local.chat.stream",
      backend: "autopilot.native_local.fixture",
      backendId,
      backendProcess: processSnapshot,
      backendEvidenceRefs: [
        "autopilot_native_local_provider_native_stream",
        "autopilot_native_local_openai_compatible_serving",
        "deterministic_native_local_fixture",
        ...normalizeScopes(processSnapshot.evidenceRefs, []),
      ],
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
    const outputText = nativeLocalOutput({ kind, input, modelId: endpoint.modelId });
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

  supportsStream(kind) {
    return kind === "chat.completions" || kind === "chat" || kind === "responses";
  }

  async streamInvoke({ state, provider, endpoint, kind, body, input }) {
    if (!this.supportsStream(kind)) return null;
    if (kind === "responses") {
      const responseBody = { ...body, model: body.model ?? endpoint.modelId, stream: true };
      try {
        const result = await fetchProviderStream(provider, "/responses", {
          method: "POST",
          body: responseBody,
          state,
        });
        return {
          stream: result.stream,
          abort: result.abort,
          status: result.status,
          providerResponseKind: "responses.stream",
          backend: endpoint.apiFormat,
          backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
          authVaultRefHash: result.authEvidence?.vaultRefHash ?? null,
          providerAuthEvidenceRefs: result.authEvidence?.evidenceRefs ?? [],
          providerAuthHeaderNames: result.authEvidence?.headerNames ?? [],
          backendEvidenceRefs: [`${this.label}_responses_provider_native_stream`],
        };
      } catch (error) {
        if ([404, 405, 501].includes(error?.details?.httpStatus)) return null;
        throw error;
      }
    }
    const requestBody = chatCompletionRequestBody({ ...body, stream: true }, endpoint.modelId);
    const result = await fetchProviderStream(provider, "/chat/completions", {
      method: "POST",
      body: requestBody,
      state,
    });
    return {
      stream: result.stream,
      abort: result.abort,
      status: result.status,
      providerResponseKind: "chat.completions.stream",
      backend: endpoint.apiFormat,
      backendId: endpoint.backendId ?? defaultBackendForProvider(provider),
      authVaultRefHash: result.authEvidence?.vaultRefHash ?? null,
      providerAuthEvidenceRefs: result.authEvidence?.evidenceRefs ?? [],
      providerAuthHeaderNames: result.authEvidence?.headerNames ?? [],
      backendEvidenceRefs: [`${this.label}_provider_native_stream`],
    };
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

  supportsStream(kind) {
    return this.openAi.supportsStream(kind);
  }

  async streamInvoke(args) {
    const provider = this.providerWithBackendBaseUrl(args.provider);
    const backendId = args.endpoint?.backendId ?? defaultBackendForProvider(provider);
    const backend = args.state.backend(backendId);
    const processRecord =
      provider.id === "provider.vllm" && backend.binaryPath
        ? args.state.ensureBackendProcess(backendId, {
            endpoint: args.endpoint,
            loadOptions: args.instance?.loadOptions ?? {},
            reason: "vllm_model_stream",
          })
        : null;
    const processSnapshot = args.state.backendProcessSnapshot(processRecord);
    const result = await this.openAi.streamInvoke({ ...args, provider });
    if (!result) return null;
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

  supportsStream(kind) {
    return this.openAi.supportsStream(kind);
  }

  async streamInvoke(args) {
    const provider = this.providerWithBackendBaseUrl(args.provider);
    const backendId = args.endpoint?.backendId ?? defaultBackendForProvider(provider);
    const processRecord = args.state.ensureBackendProcess(backendId, {
      endpoint: args.endpoint,
      loadOptions: args.instance?.loadOptions ?? {},
      reason: "llama_cpp_model_stream",
    });
    const processSnapshot = args.state.backendProcessSnapshot(processRecord);
    const result = await this.openAi.streamInvoke({ ...args, provider });
    if (!result) return null;
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
        capabilities: ["chat", "responses", "embeddings"],
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

  supportsStream(kind) {
    return kind === "chat.completions" || kind === "chat" || kind === "responses";
  }

  async streamInvoke({ state, provider, endpoint, kind, body }) {
    if (!this.supportsStream(kind)) return null;
    const result = await fetchProviderStream(provider, "/api/chat", {
      method: "POST",
      body: chatCompletionRequestBody({ ...body, stream: true }, endpoint.modelId),
      state,
    });
    return {
      stream: result.stream,
      abort: result.abort,
      status: result.status,
      streamFormat: "ollama_jsonl",
      providerResponseKind: kind === "responses" ? "ollama.responses.stream" : "ollama.chat.stream",
      backend: "ollama",
      backendId: endpoint.backendId ?? "backend.ollama",
      backendEvidenceRefs: ["ollama_api_chat_native_stream"],
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
    this.oauthCredentialProvider = new OAuthCredentialProvider({
      now: this.now,
      vault: this.vault,
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
    this.catalogProviderConfigs = new Map();
    this.catalogProviderRuntimeMaterials = new Map();
    this.oauthSessions = new Map();
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
      modelCatalogProviders: [
        "id",
        "status",
        "gate",
        "formats",
        "enabled",
        "configHash",
        "baseUrlHash",
        "manifestPathHash",
        "authVaultRefHash",
        "materialConfigured",
        "materialPersistence",
        "runtimeMaterialStatus",
        "evidenceRefs",
      ],
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
    this.loadMap("model-catalog-providers", this.catalogProviderConfigs);
    this.loadMap("oauth-sessions", this.oauthSessions);
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
        capabilities: ["chat", "responses", "embeddings"],
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
    this.writeMap("model-catalog-providers", this.catalogProviderConfigs);
    this.writeMap("oauth-sessions", this.oauthSessions);
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

  listOAuthSessions() {
    return [...this.oauthSessions.values()]
      .map(publicOAuthSession)
      .sort((left, right) => left.id.localeCompare(right.id));
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
      catalogProviderConfigs: this.listCatalogProviderConfigs(),
      oauthSessions: this.listOAuthSessions(),
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
      catalogProviderConfigs: this.listCatalogProviderConfigs(),
      oauthSessions: this.listOAuthSessions(),
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
      oauth: {
        port: "OAuthCredentialProvider",
        implementation: "agentgres_vault_oauth_session",
        methods: ["exchangeAuthorizationCode", "refreshAccessToken", "revokeSession", "resolveAccessHeader"],
        plaintextPersistence: false,
        evidenceRefs: ["OAuthCredentialProvider", "VaultOAuthSession", "oauth_tokens_not_persisted"],
      },
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
    const lastSearch = this.lastCatalogSearch;
    const providers = this.catalogProviderPorts().map((port) => catalogProviderStatus(port));
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      checkedAt: this.nowIso(),
      providers,
      adapterBoundary: {
        port: "ModelCatalogProviderPort",
        operations: ["search", "resolveVariant", "importUrl", "download", "health"],
        evidenceRefs: ["provider_neutral_model_catalog_adapter_boundary"],
      },
      filters: {
        formats: ["gguf", "mlx", "safetensors"],
        quantization: ["Q2", "Q3", "Q4", "Q5", "Q6", "Q8", "F16", "BF16", "IQ"],
        compatibility: ["native_local_fixture", "llama_cpp", "ollama", "vllm", "mlx"],
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

  catalogProviderPorts() {
    return modelCatalogProviderPorts(this);
  }

  listCatalogProviderConfigs() {
    return MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS.map((providerId) =>
      publicCatalogProviderConfig(
        providerId,
        this.catalogProviderConfigs.get(providerId),
        this.catalogProviderRuntimeMaterial(providerId),
      ),
    );
  }

  getCatalogProviderConfig(providerId) {
    assertConfigurableCatalogProvider(providerId);
    const port = this.catalogProviderPorts().find((candidate) => candidate.id === providerId) ?? null;
    return {
      ...publicCatalogProviderConfig(
        providerId,
        this.catalogProviderConfigs.get(providerId),
        this.catalogProviderRuntimeMaterial(providerId),
      ),
      provider: port ? catalogProviderStatus(port) : null,
    };
  }

  configureCatalogProvider(providerId, body = {}) {
    assertConfigurableCatalogProvider(providerId);
    const existing = this.catalogProviderConfigs.get(providerId);
    const update = catalogProviderConfigUpdate(providerId, body, existing, this.nowIso(), this);
    const { record, runtimeMaterial, evidenceRefs } = update;
    this.catalogProviderConfigs.set(providerId, record);
    if (runtimeMaterial) this.catalogProviderRuntimeMaterials.set(providerId, runtimeMaterial);
    else this.catalogProviderRuntimeMaterials.delete(providerId);
    this.writeMap("model-catalog-providers", this.catalogProviderConfigs);
    const publicRecord = publicCatalogProviderConfig(providerId, record, this.catalogProviderRuntimeMaterial(providerId));
    const receipt = this.receipt("model_catalog_provider_configuration", {
      summary: `${providerId} catalog configuration updated through the governed catalog provider path.`,
      redaction: "redacted",
      evidenceRefs: ["ModelCatalogProviderPort.configure", providerId, ...evidenceRefs],
      details: publicRecord,
    });
    this.writeProjection();
    return {
      ...publicRecord,
      receiptId: receipt.id,
      provider: catalogProviderStatus(this.catalogProviderPorts().find((port) => port.id === providerId)),
    };
  }

  async exchangeCatalogProviderOAuth(providerId, body = {}) {
    assertConfigurableCatalogProvider(providerId);
    const { session, evidence } = await this.oauthCredentialProvider.exchangeAuthorizationCode({ providerId, body });
    this.oauthSessions.set(session.id, session);
    const existing = this.catalogProviderConfigs.get(providerId);
    const update = catalogProviderConfigUpdate(
      providerId,
      {
        enabled: body.enabled ?? existing?.enabled ?? true,
        auth_scheme: "oauth2",
        auth_header_name: body.auth_header_name ?? body.authHeaderName ?? existing?.catalogAuthHeaderName ?? "authorization",
        auth_vault_ref: session.accessVaultRef,
        oauth_session_id: session.id,
      },
      existing,
      this.nowIso(),
      this,
    );
    this.catalogProviderConfigs.set(providerId, update.record);
    if (update.runtimeMaterial) this.catalogProviderRuntimeMaterials.set(providerId, update.runtimeMaterial);
    this.writeMap("oauth-sessions", this.oauthSessions);
    this.writeMap("model-catalog-providers", this.catalogProviderConfigs);
    this.writeVaultRefs();
    const publicRecord = publicCatalogProviderConfig(providerId, update.record, this.catalogProviderRuntimeMaterial(providerId));
    const receipt = this.receipt("catalog_oauth_exchange", {
      summary: `${providerId} OAuth session exchanged and bound through vault refs.`,
      redaction: "redacted",
      evidenceRefs: ["OAuthCredentialProvider.exchangeAuthorizationCode", "VaultOAuthSession", providerId],
      details: {
        providerId,
        oauthSession: evidence,
        catalogProvider: publicRecord,
      },
    });
    this.writeProjection();
    return {
      ...publicRecord,
      oauthSession: evidence,
      receiptId: receipt.id,
      provider: catalogProviderStatus(this.catalogProviderPorts().find((port) => port.id === providerId)),
    };
  }

  async refreshCatalogProviderOAuth(providerId) {
    assertConfigurableCatalogProvider(providerId);
    const config = this.catalogProviderConfigs.get(providerId);
    const session = config?.oauthSessionId ? this.oauthSessions.get(config.oauthSessionId) : null;
    if (!session) {
      throw runtimeError({
        status: 404,
        code: "not_found",
        message: `OAuth session not found for catalog provider: ${providerId}`,
        details: { providerId, oauthSessionHash: config?.oauthSessionId ? stableHash(config.oauthSessionId) : null },
      });
    }
    const refreshed = await this.oauthCredentialProvider.refreshAccessToken(session);
    this.oauthSessions.set(refreshed.id, refreshed);
    this.catalogProviderConfigs.set(providerId, {
      ...config,
      oauthBoundary: oauthBoundaryForSession(refreshed, { refreshed: true }),
      updatedAt: this.nowIso(),
    });
    this.writeMap("oauth-sessions", this.oauthSessions);
    this.writeMap("model-catalog-providers", this.catalogProviderConfigs);
    this.writeVaultRefs();
    const receipt = this.receipt("catalog_oauth_refresh", {
      summary: `${providerId} OAuth session refreshed through vault refs.`,
      redaction: "redacted",
      evidenceRefs: ["OAuthCredentialProvider.refreshAccessToken", "VaultOAuthSession", providerId],
      details: {
        providerId,
        oauthSession: publicOAuthSession(refreshed),
      },
    });
    this.writeProjection();
    return { oauthSession: publicOAuthSession(refreshed), receiptId: receipt.id };
  }

  revokeCatalogProviderOAuth(providerId) {
    assertConfigurableCatalogProvider(providerId);
    const config = this.catalogProviderConfigs.get(providerId);
    const session = config?.oauthSessionId ? this.oauthSessions.get(config.oauthSessionId) : null;
    if (!session) {
      throw runtimeError({
        status: 404,
        code: "not_found",
        message: `OAuth session not found for catalog provider: ${providerId}`,
        details: { providerId, oauthSessionHash: config?.oauthSessionId ? stableHash(config.oauthSessionId) : null },
      });
    }
    const revoked = this.oauthCredentialProvider.revokeSession(session);
    this.oauthSessions.set(revoked.id, revoked);
    this.catalogProviderConfigs.set(providerId, {
      ...config,
      oauthBoundary: oauthBoundaryForSession(revoked),
      updatedAt: this.nowIso(),
    });
    this.writeMap("oauth-sessions", this.oauthSessions);
    this.writeMap("model-catalog-providers", this.catalogProviderConfigs);
    this.writeVaultRefs();
    const receipt = this.receipt("catalog_oauth_revoke", {
      summary: `${providerId} OAuth session revoked through vault refs.`,
      redaction: "redacted",
      evidenceRefs: ["OAuthCredentialProvider.revokeSession", "VaultOAuthSession", providerId],
      details: {
        providerId,
        oauthSession: publicOAuthSession(revoked),
      },
    });
    this.writeProjection();
    return { oauthSession: publicOAuthSession(revoked), receiptId: receipt.id };
  }

  catalogProviderConfig(providerId) {
    return this.catalogProviderConfigs.get(providerId) ?? null;
  }

  catalogProviderRuntimeMaterial(providerId) {
    const existing = this.catalogProviderRuntimeMaterials.get(providerId) ?? null;
    if (catalogProviderHasSourceMaterial(existing)) return existing;
    if (existing?.runtimeMaterialStatus === "missing_runtime_material" || existing?.runtimeMaterialStatus === "vault_material_unavailable") {
      return existing;
    }
    const config = this.catalogProviderConfigs.get(providerId) ?? null;
    if (!config?.materialConfigured && !config?.materialVaultRefHash) return existing;
    const vaultRef = catalogProviderMaterialVaultRef(providerId);
    const purpose = catalogProviderMaterialPurpose(providerId);
    try {
      const resolved = this.vault.resolveVaultRef(vaultRef, purpose);
      this.writeVaultRefs();
      if (!resolved.resolvedMaterial || typeof resolved.material !== "string" || !resolved.material.trim()) {
        const missing = {
          runtimeMaterialStatus: "missing_runtime_material",
          materialSource: resolved.materialSource ?? "unbound",
          materialVaultRefHash: resolved.vaultRefHash,
          evidenceRefs: normalizeScopes(resolved.evidenceRefs, ["VaultPort.resolveVaultRef", "catalog_provider_source_material_unbound"]),
        };
        this.catalogProviderRuntimeMaterials.set(providerId, missing);
        return missing;
      }
      const material = {
        ...catalogProviderRuntimeMaterialFromValue(providerId, resolved.material),
        runtimeMaterialStatus: "resolved_from_vault",
        materialSource: resolved.materialSource ?? "vault_material_adapter",
        materialVaultRefHash: resolved.vaultRefHash,
        evidenceRefs: normalizeScopes(resolved.evidenceRefs, ["VaultPort.resolveVaultRef", "catalog_provider_source_material_resolved"]),
      };
      this.catalogProviderRuntimeMaterials.set(providerId, material);
      return material;
    } catch (error) {
      const failed = {
        runtimeMaterialStatus: "vault_material_unavailable",
        materialSource: "unavailable",
        materialVaultRefHash: config.materialVaultRefHash ?? stableHash(vaultRef),
        errorHash: stableHash(error?.message ?? "catalog source vault resolution failed"),
        evidenceRefs: ["VaultPort.resolveVaultRef", "catalog_provider_source_material_fail_closed"],
      };
      this.catalogProviderRuntimeMaterials.set(providerId, failed);
      return failed;
    }
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
    const providerResults = [];
    for (const port of this.catalogProviderPorts()) {
      const result = await port.search({
        state: this,
        query: text,
        format: requestedFormat,
        quantization: requestedQuantization,
        limit,
        searchedAt,
      });
      providerResults.push({
        ...catalogProviderStatus(port, result),
        results: (Array.isArray(result.results) ? result.results : []).map((entry) => this.enrichCatalogEntry(entry)),
      });
    }
    const results = providerResults.flatMap((provider) => provider.results).slice(0, limit);
    const search = {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      searchedAt,
      query: text,
      filters: {
        format: requestedFormat,
        quantization: requestedQuantization,
        limit,
      },
      adapterBoundary: {
        port: "ModelCatalogProviderPort",
        operations: ["search", "resolveVariant", "importUrl", "download", "health"],
        evidenceRefs: ["provider_neutral_model_catalog_adapter_boundary"],
      },
      providers: providerResults.map(({ results: _results, ...provider }) => provider),
      results,
    };
    this.lastCatalogSearch = search;
    return search;
  }

  enrichCatalogEntry(entry, options = {}) {
    const storage = this.storageSummary();
    const artifacts = [...this.artifacts.values()];
    return enrichCatalogEntry(entry, {
      storage,
      artifacts,
      maxBytes: options.maxBytes ?? null,
    });
  }

  async searchHuggingFaceCatalog({ query, format, quantization, limit, searchedAt }) {
    const baseUrl = huggingFaceCatalogBaseUrl();
    const evidenceRefs = ["huggingface_catalog_adapter_boundary", "network_access_opt_in"];
    if (!liveModelCatalogEnabled()) {
      const config = this.catalogProviderConfig("catalog.huggingface");
      return {
        ...catalogProviderConfigHealthFields("catalog.huggingface", config, null),
        status: "gated",
        baseUrlHash: stableHash(baseUrl),
        evidenceRefs,
        results: [],
      };
    }
    try {
      const auth = await catalogProviderAuthHeaders("catalog.huggingface", this);
      const url = new URL("/api/models", baseUrl);
      if (query) url.searchParams.set("search", query);
      url.searchParams.set("limit", String(limit));
      const response = await fetchWithTimeout(url, { timeoutMs: modelCatalogTimeoutMs(), headers: auth.headers });
      if (!response.ok) {
        return {
          status: "degraded",
          baseUrlHash: stableHash(baseUrl),
          ...catalogAuthProviderFields(auth.evidence),
          evidenceRefs: [...evidenceRefs, ...normalizeScopes(auth.evidence?.evidenceRefs, [])],
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
        ...catalogAuthProviderFields(auth.evidence),
        evidenceRefs: [...evidenceRefs, "huggingface_catalog_search", ...normalizeScopes(auth.evidence?.evidenceRefs, [])],
        results: results.map((entry) => catalogEntryWithAuth(entry, auth.evidence)),
      };
    } catch (error) {
      return {
        status: catalogAuthFailureStatus(error),
        baseUrlHash: stableHash(baseUrl),
        evidenceRefs,
        ...catalogAuthFailureFields(error),
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
    const lastCatalogEntry = this.lastCatalogSearch?.results?.find((entry) => entry.sourceUrl === sourceUrl || entry.sourceUrlHash === stableHash(sourceUrl));
    const variant = catalogVariantForSource(sourceUrl, { ...(lastCatalogEntry ?? {}), ...body });
    const receipt = this.lifecycleReceipt("model_catalog_import_url", {
      modelId,
      providerId: body.provider_id ?? body.providerId ?? "provider.autopilot.local",
      sourceUrlHash: stableHash(sourceUrl),
      sourceLabel: variant.sourceLabel,
      format: variant.format,
      quantization: variant.quantization,
      license: variant.license,
      compatibility: variant.compatibility,
      architecture: variant.architecture,
      parameterCount: variant.parameterCount,
      recommendation: variant.recommendation,
      backendCompatibility: variant.backendCompatibility,
      downloadRisk: variant.downloadRisk,
      benchmarkReadiness: variant.benchmarkReadiness,
      selectionReceiptFields: variant.selectionReceiptFields,
      catalogProviderId: variant.catalogProviderId,
      catalogAuth: publicCatalogAuthEvidence(variant.catalogAuth),
      approvalDecision: catalogApprovalDecision({ isFixture, body }),
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
      architecture: variant.architecture,
      parameter_count: variant.parameterCount,
      recommendation_score: variant.recommendation?.score,
      download_risk_status: variant.downloadRisk?.status,
      backend_compatibility: variant.backendCompatibility,
      benchmark_readiness: variant.benchmarkReadiness,
      selection_receipt_fields: variant.selectionReceiptFields,
      transfer_approved: Boolean(body.transfer_approved ?? body.transferApproved ?? isFixture),
      variant_id: variant.id,
      catalog_provider_id: variant.catalogProviderId,
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
    const catalogProviderId = body.catalog_provider_id ?? body.catalogProviderId ?? variantMetadata.catalogProviderId ?? null;
    const catalogAuth = !isFixture && catalogProviderId
      ? await catalogProviderAuthHeaders(catalogProviderId, this)
      : { headers: {}, evidence: null };
    const catalogAuthReceipt = publicCatalogAuthEvidence(catalogAuth.evidence);
    const targetDir = path.join(this.modelRoot, "downloads", safeFileName(modelId));
    const targetPath = path.join(targetDir, body.file_name ?? body.fileName ?? `${safeFileName(modelId)}.gguf`);
    const fixtureContent = String(body.fixture_content ?? body.fixtureContent ?? `deterministic model bytes for ${modelId}\n`);
    const bytesTotal = Number(body.bytes_total ?? body.bytesTotal ?? (isFixture ? Buffer.byteLength(fixtureContent) : 0));
    const maxBytes = normalizeOptionalBytes(body.max_bytes ?? body.maxBytes ?? process.env.IOI_MODEL_DOWNLOAD_MAX_BYTES);
    const downloadPolicy = normalizeDownloadPolicy(body, { isFixture, maxBytes, source });
    assertDownloadPolicyAllowed(downloadPolicy, source);
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
      downloadPolicy,
      bandwidthLimitBps: downloadPolicy.bandwidthLimitBps,
      retryLimit: downloadPolicy.retryLimit,
      resumeDownload: downloadPolicy.resume,
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
      catalogProviderId,
      catalogAuth: catalogAuthReceipt,
      recommendation: variantMetadata.recommendation,
      backendCompatibility: variantMetadata.backendCompatibility,
      downloadRisk: variantMetadata.downloadRisk,
      benchmarkReadiness: variantMetadata.benchmarkReadiness,
      selectionReceiptFields: variantMetadata.selectionReceiptFields,
      approvalDecision: downloadPolicy.approvalDecision,
      downloadPolicy,
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
        downloadPolicy,
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
      downloadPolicy,
      catalogProviderId,
      catalogAuth: catalogAuthReceipt,
    });
    const transferReceiptIds = [];
    const recordTransferEvent = (operation, details = {}) => {
      const receipt = this.lifecycleReceipt(operation, {
        jobId: jobBase.id,
        modelId,
        providerId,
        sourceHash: stableHash(source),
        sourceLabel,
        targetPathHash: stableHash(targetPath),
        downloadMode: isFixture ? "fixture" : "live_network",
        downloadPolicy,
        catalogProviderId,
        catalogAuth: catalogAuthReceipt,
        ...details,
      });
      transferReceiptIds.push(receipt.id);
      return receipt;
    };
    let materialized;
    try {
      materialized = isFixture
        ? materializeFixtureDownload({ targetPath, fixtureContent })
        : await materializeLiveDownload({
            source,
            targetPath,
            expectedChecksum: body.checksum ?? body.expected_checksum ?? body.expectedChecksum ?? null,
            maxBytes,
            resume: downloadPolicy.resume,
            bandwidthLimitBps: downloadPolicy.bandwidthLimitBps,
            retryLimit: downloadPolicy.retryLimit,
            timeoutMs: modelDownloadTimeoutMs(),
            headers: catalogAuth.headers,
            onTransferEvent: recordTransferEvent,
          });
    } catch (error) {
      const failureReason = downloadFailureReason(error);
      const transfer = error?.downloadTransfer ?? null;
      const cleanupState = failedDownloadCleanupState(targetPath, {
        retainPartial: shouldRetainFailedDownloadPartial(downloadPolicy, failureReason),
      });
      const failedReceipt = this.lifecycleReceipt("model_download_failed", {
        jobId: jobBase.id,
        modelId,
        providerId,
        failureReason,
        sourceHash: stableHash(source),
        sourceLabel,
        errorHash: stableHash(error?.message ?? "download failed"),
        cleanupState,
        transfer,
        catalogProviderId,
        catalogAuth: catalogAuthReceipt,
        attemptCount: transfer?.attemptCount ?? null,
        retryCount: transfer?.retryCount ?? null,
        resumeMetadataPathHash: transfer?.resumeMetadataPathHash ?? stableHash(`${targetPath}.part.json`),
        downloadPolicy,
      });
      const failed = {
        ...jobBase,
        artifactId: null,
        status: "failed",
        failureReason,
        cleanupState,
        transfer,
        attemptCount: transfer?.attemptCount ?? null,
        retryCount: transfer?.retryCount ?? null,
        resumeMetadataPathHash: transfer?.resumeMetadataPathHash ?? stableHash(`${targetPath}.part.json`),
        updatedAt: this.nowIso(),
        receiptIds: [queuedReceipt.id, runningReceipt.id, ...transferReceiptIds, failedReceipt.id],
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
      attemptCount: materialized.attemptCount ?? 1,
      retryCount: materialized.retryCount ?? 0,
      resumeMetadataPathHash: materialized.resumeMetadataPathHash ?? stableHash(`${targetPath}.part.json`),
      transfer: materialized.transfer ?? null,
      updatedAt: this.nowIso(),
      receiptIds: [queuedReceipt.id, runningReceipt.id, ...transferReceiptIds],
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
      recommendation: variantMetadata.recommendation,
      backendCompatibility: variantMetadata.backendCompatibility,
      downloadRisk: variantMetadata.downloadRisk,
      benchmarkReadiness: variantMetadata.benchmarkReadiness,
      selectionReceiptFields: variantMetadata.selectionReceiptFields,
      approvalDecision: downloadPolicy.approvalDecision,
      downloadPolicy,
      resumeOffset: materialized.resumeOffset ?? 0,
      attemptCount: materialized.attemptCount ?? 1,
      retryCount: materialized.retryCount ?? 0,
      resumeMetadataPathHash: materialized.resumeMetadataPathHash ?? stableHash(`${targetPath}.part.json`),
      transfer: materialized.transfer ?? null,
      downloadMode: isFixture ? "fixture" : "live_network",
      catalogProviderId,
      catalogAuth: catalogAuthReceipt,
    });
    const completed = { ...job, receiptId: receipt.id, receiptIds: [...job.receiptIds, receipt.id] };
    this.downloads.set(completed.id, completed);
    this.writeMap("model-artifacts", this.artifacts);
    this.writeMap("model-downloads", this.downloads);
    this.writeProjection();
    return completed;
  }

  cancelDownload(jobId, body = {}) {
    const job = this.downloadStatus(jobId);
    if (["completed", "failed", "canceled"].includes(job.status)) {
      return job;
    }
    const cleanupPartial = truthy(body.cleanup_partial ?? body.cleanupPartial ?? true);
    const destructiveConfirmation = destructiveConfirmationState(body, { required: cleanupPartial, action: "download_cancel_cleanup" });
    const partialPath = job.targetPath ? `${job.targetPath}.part` : null;
    const metadataPath = partialPath ? `${partialPath}.json` : null;
    const projectedFreedBytes = cleanupPartial
      ? fileSizeIfExists(job.targetPath) + fileSizeIfExists(partialPath) + fileSizeIfExists(metadataPath)
      : 0;
    let cleanupState = cleanupPartial ? "not_needed" : "retained_partial";
    if (cleanupPartial && job.targetPath) {
      cleanupState = cleanupPartialDownload(job.targetPath);
    }
    const receipt = this.lifecycleReceipt("model_download_canceled", {
      jobId,
      modelId: job.modelId,
      providerId: job.providerId,
      bytesCompleted: job.bytesCompleted,
      bytesTotal: job.bytesTotal,
      cleanupPartial,
      cleanupState,
      projectedFreedBytes,
      destructiveConfirmation,
      downloadPolicy: job.downloadPolicy ?? null,
    });
    const canceled = {
      ...job,
      status: "canceled",
      cleanupState,
      projectedFreedBytes,
      destructiveConfirmation,
      updatedAt: this.nowIso(),
      receiptId: receipt.id,
      receiptIds: [...(job.receiptIds ?? []), receipt.id],
    };
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

  deleteModelArtifact(id, body = {}) {
    const artifact = this.getModel(id);
    const endpointIds = [...this.endpoints.values()].filter((endpoint) => endpoint.artifactId === artifact.id).map((endpoint) => endpoint.id);
    const instanceIds = [...this.instances.values()]
      .filter((instance) => endpointIds.includes(instance.endpointId) && instance.status === "loaded")
      .map((instance) => instance.id);
    const projectedFreedBytes = fileSizeIfExists(artifact.artifactPath);
    const destructiveConfirmation = destructiveConfirmationState(body, { required: projectedFreedBytes > 0 || endpointIds.length > 0, action: "model_artifact_delete" });
    if (truthy(body.dry_run ?? body.dryRun)) {
      const receipt = this.lifecycleReceipt("model_artifact_delete_dry_run", {
        artifactId: artifact.id,
        modelId: artifact.modelId,
        providerId: artifact.providerId,
        artifactPathHash: artifact.artifactPath ? stableHash(artifact.artifactPath) : null,
        affectedEndpointIds: endpointIds,
        affectedInstanceIds: instanceIds,
        projectedFreedBytes,
        destructiveConfirmation,
      });
      return {
        schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
        status: "dry_run",
        artifactId: artifact.id,
        modelId: artifact.modelId,
        affectedEndpointIds: endpointIds,
        affectedInstanceIds: instanceIds,
        projectedFreedBytes,
        destructiveConfirmation,
        receiptId: receipt.id,
      };
    }
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
      affectedEndpointIds: endpointIds,
      affectedInstanceIds: instanceIds,
      projectedFreedBytes,
      cleanupState,
      destructiveConfirmation,
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
      affectedEndpointIds: endpointIds,
      affectedInstanceIds: instanceIds,
      projectedFreedBytes,
      destructiveConfirmation,
      receiptId: receipt.id,
    };
  }

  cleanupModelStorage(body = {}) {
    const knownPaths = new Set([...this.artifacts.values()].map((artifact) => artifact.artifactPath).filter(Boolean));
    const files = listModelFiles(this.modelRoot);
    const orphans = files.filter((filePath) => !knownPaths.has(filePath));
    const orphanBytes = orphans.reduce((total, filePath) => total + fileSizeIfExists(filePath), 0);
    const removeOrphans = truthy(body.remove_orphans ?? body.removeOrphans ?? false);
    const destructiveConfirmation = destructiveConfirmationState(body, { required: removeOrphans && orphans.length > 0, action: "model_storage_cleanup" });
    if (removeOrphans && destructiveConfirmation.required && !destructiveConfirmation.confirmed) {
      throw runtimeError({
        status: 409,
        code: "destructive_confirmation_required",
        message: "Confirm destructive cleanup before removing orphan model files.",
        details: { orphanCount: orphans.length, projectedFreedBytes: orphanBytes },
      });
    }
    let cleanupState = "scan_only";
    let cleanedBytes = 0;
    let removedOrphanCount = 0;
    if (removeOrphans) {
      cleanupState = "removed_orphans";
      for (const orphan of orphans) {
        const size = fileSizeIfExists(orphan);
        try {
          fs.rmSync(orphan, { force: true });
          cleanedBytes += size;
          removedOrphanCount += 1;
        } catch {
          cleanupState = "partial_cleanup_failed";
        }
      }
    }
    const receipt = this.lifecycleReceipt("model_storage_cleanup", {
      modelId: "model-storage",
      scannedFileCount: files.length,
      orphanCount: orphans.length,
      orphanPathHashes: orphans.map((filePath) => stableHash(filePath)),
      orphanBytes,
      removeOrphans,
      cleanedBytes,
      removedOrphanCount,
      projectedFreedBytes: orphanBytes,
      cleanupState,
      destructiveConfirmation,
    });
    return {
      schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
      status: removeOrphans ? "cleaned" : "scanned",
      scannedFileCount: files.length,
      orphanCount: orphans.length,
      orphanBytes,
      removeOrphans,
      cleanedBytes,
      removedOrphanCount,
      projectedFreedBytes: orphanBytes,
      cleanupState,
      destructiveConfirmation,
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

  async startModelStream({ authorization, requiredScope, kind, body = {} }) {
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
    const driver = this.driverForProvider(selection.provider);
    if (typeof driver.streamInvoke !== "function" || (typeof driver.supportsStream === "function" && !driver.supportsStream(kind))) {
      return {
        native: false,
        invocation: await this.invokeModel({ authorization, requiredScope, kind, body }),
      };
    }
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
    const providerResult = await driver.streamInvoke({
      state: this,
      provider: selection.provider,
      endpoint: selection.endpoint,
      instance,
      kind,
      body,
      input,
      token,
    });
    if (!providerResult?.stream) {
      return {
        native: false,
        invocation: await this.invokeModel({ authorization, requiredScope, kind, body }),
      };
    }
    const outputText = "";
    const latencyMs = Math.max(1, this.now().getTime() - started);
    const tokenCount = providerResult.tokenCount ?? estimateTokens(input, outputText);
    const receipt = this.receipt("model_invocation", {
      summary: `${kind} invocation stream started through ${selection.route.id} to ${selection.endpoint.modelId}.`,
      redaction: "redacted",
      evidenceRefs: [
        "model_router",
        "provider_native_stream",
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
        streamStatus: "started",
        streamSource: "provider_native",
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
    const invocation = {
      kind,
      input,
      outputText,
      model: selection.endpoint.modelId,
      route,
      endpoint: selection.endpoint,
      instance,
      receipt,
      routeReceipt,
      tokenCount,
      providerResponse: null,
      providerResponseKind: providerResult.providerResponseKind ?? null,
      compatTranslation: providerResult.compatTranslation ?? null,
      toolReceiptIds: ephemeralMcp.toolReceiptIds,
    };
    return {
      native: true,
      invocation,
      providerStream: providerResult.stream,
      abort: providerResult.abort,
      providerResult,
    };
  }

  recordModelStreamCompleted({ invocation, streamKind, outputText = "", providerUsage = null, chunksForwarded = 0, finishReason = null, providerResult = {} }) {
    const tokenCount = normalizeUsage(providerUsage, estimateTokens(invocation.input ?? "", outputText));
    return this.receipt("model_invocation_stream_completed", {
      summary: `${streamKind} stream completed for ${invocation.model}.`,
      redaction: "redacted",
      evidenceRefs: ["model_stream", streamKind, invocation.receipt.id, invocation.route.id, invocation.endpoint.id],
      details: {
        streamKind,
        streamSource: "provider_native",
        invocationReceiptId: invocation.receipt.id,
        routeId: invocation.route.id,
        selectedModel: invocation.model,
        endpointId: invocation.endpoint.id,
        providerId: invocation.endpoint.providerId,
        instanceId: invocation.instance.id,
        backendId: invocation.instance.backendId ?? invocation.receipt.details?.backendId ?? null,
        selectedBackend: invocation.receipt.details?.selectedBackend ?? null,
        providerResponseKind: providerResult.providerResponseKind ?? invocation.providerResponseKind ?? null,
        backendEvidenceRefs: providerResult.backendEvidenceRefs ?? [],
        toolReceiptIds: invocation.toolReceiptIds ?? [],
        tokenCount,
        outputHash: stableHash(outputText),
        chunksForwarded,
        finishReason,
      },
    });
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

export function anthropicMessage(invocation) {
  return {
    id: `msg_${crypto.randomUUID().replace(/-/g, "").slice(0, 24)}`,
    type: "message",
    role: "assistant",
    content: [{ type: "text", text: invocation.outputText }],
    model: invocation.model,
    stop_reason: "end_turn",
    stop_sequence: null,
    usage: {
      input_tokens: Number(invocation.tokenCount?.prompt_tokens ?? 0),
      output_tokens: Number(invocation.tokenCount?.completion_tokens ?? 0),
      cache_read_input_tokens: 0,
    },
    receipt_id: invocation.receipt.id,
    route_id: invocation.route.id,
    tool_receipt_ids: invocation.toolReceiptIds ?? [],
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

async function fetchProviderStream(provider, route, { method = "GET", body, state } = {}) {
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
        accept: "text/event-stream",
        ...auth.headers,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    clearTimeout(timeout);
    if (!response.ok) {
      const text = await response.text();
      const parsed = text.trim() ? parseJsonMaybe(text) : null;
      throw providerHttpError(provider, "OpenAI-compatible provider stream failed.", {
        ok: false,
        status: response.status,
        body: parsed,
        authEvidence: auth.evidence,
      });
    }
    if (!response.body) {
      throw runtimeError({
        status: 424,
        code: "external_blocker",
        message: "OpenAI-compatible provider did not return a stream body.",
        details: { providerId: provider.id, providerKind: provider.kind },
      });
    }
    return {
      ok: true,
      status: response.status,
      stream: response.body,
      abort: () => controller.abort(),
      authEvidence: auth.evidence,
    };
  } catch (error) {
    if (error?.status || error?.code === "external_blocker") throw error;
    throw runtimeError({
      status: 424,
      code: "external_blocker",
      message: "OpenAI-compatible provider stream failed.",
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

function normalizeNonNegativeInteger(value, fallback = 0) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || parsed < 0) return fallback;
  return Math.floor(parsed);
}

function fileSizeIfExists(filePath) {
  if (!filePath || !fs.existsSync(filePath)) return 0;
  try {
    return fs.statSync(filePath).size;
  } catch {
    return 0;
  }
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

function normalizeOAuthScopes(value, fallback = []) {
  if (!value) return [...fallback];
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  return String(value).split(/\s+/).map((scope) => scope.trim()).filter(Boolean);
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

function nativeLocalOutput({ kind, input, modelId }) {
  const digest = stableHash(input).slice(0, 12);
  if (kind === "embeddings") return `native-local-embedding:${modelId}:${digest}`;
  return `Autopilot native local model response from ${modelId}. input_hash=${digest}`;
}

function nativeLocalStreamRecords(outputText, tokenCount) {
  const chunks = String(outputText).match(/.{1,64}(?:\s+|$)/gs) ?? [String(outputText)];
  return [
    ...chunks.map((chunk) => ({ delta: chunk, done: false })),
    {
      delta: "",
      done: true,
      done_reason: "stop",
      prompt_eval_count: tokenCount.prompt_tokens,
      eval_count: tokenCount.completion_tokens,
    },
  ];
}

function jsonLineReadableStream(records, { delayMs = 0, onAbort = null } = {}) {
  const encoder = new TextEncoder();
  const chunks = records.map((record) => encoder.encode(`${JSON.stringify(record)}\n`));
  let controllerRef = null;
  let timer = null;
  let closed = false;
  let abortRecorded = false;
  const clearTimer = () => {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
  };
  const close = () => {
    if (closed) return;
    closed = true;
    clearTimer();
    try {
      controllerRef?.close();
    } catch {
      // The consumer may already have canceled the stream.
    }
  };
  const abort = (reason = "aborted") => {
    if (closed) return;
    if (!abortRecorded) {
      abortRecorded = true;
      onAbort?.(String(reason));
    }
    close();
  };
  const stream = new ReadableStream({
    start(controller) {
      controllerRef = controller;
      if (delayMs <= 0) {
        for (const chunk of chunks) {
          controller.enqueue(chunk);
        }
        close();
        return;
      }
      let index = 0;
      const pump = () => {
        if (closed) return;
        if (index >= chunks.length) {
          close();
          return;
        }
        try {
          controller.enqueue(chunks[index]);
        } catch {
          abort("enqueue_failed");
          return;
        }
        index += 1;
        if (index >= chunks.length) {
          close();
          return;
        }
        timer = setTimeout(pump, delayMs);
      };
      timer = setTimeout(pump, delayMs);
    },
    cancel(reason) {
      abort(reason ?? "consumer_cancel");
    },
  });
  return { stream, abort };
}

function providerStreamFrameDelayMs() {
  const configured = Number(
    process.env.IOI_DETERMINISTIC_PROVIDER_STREAM_DELAY_MS ?? process.env.IOI_DETERMINISTIC_SSE_FRAME_DELAY_MS ?? "",
  );
  if (Number.isFinite(configured) && configured >= 0) return Math.min(configured, 1000);
  return 0;
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
      architecture: "llama",
      parameterCount: "3B",
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
      architecture: "nomic",
      parameterCount: "fixture",
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

const MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS = ["catalog.local_manifest", "catalog.custom_http", "catalog.huggingface"];

function assertConfigurableCatalogProvider(providerId) {
  if (!MODEL_CATALOG_CONFIGURABLE_PROVIDER_IDS.includes(providerId)) {
    throw runtimeError({
      status: 404,
      code: "not_found",
      message: `Catalog provider is not configurable: ${providerId}`,
      details: { providerId },
    });
  }
}

function catalogProviderConfigUpdate(providerId, body, existing = null, updatedAt, state) {
  const enabled = body.enabled === undefined ? existing?.enabled ?? true : truthy(body.enabled);
  const materialFromBody = catalogProviderRuntimeMaterialFromBody(providerId, body);
  let runtimeMaterial = catalogProviderHasSourceMaterial(materialFromBody)
    ? materialFromBody
    : state.catalogProviderRuntimeMaterials.get(providerId) ?? null;
  let materialPersistence = existing?.materialPersistence ?? "metadata_only";
  let materialVaultRefHash = existing?.materialVaultRefHash ?? null;
  let runtimeMaterialStatus = existing?.runtimeMaterialStatus ?? (existing?.materialConfigured ? "missing_runtime_material" : "unconfigured");
  let materialSource = existing?.vaultMaterialSource ?? runtimeMaterial?.materialSource ?? null;
  const evidenceRefs = ["catalog_provider_config_metadata", "no_plaintext_catalog_material_persisted"];
  if (catalogProviderHasSourceMaterial(materialFromBody)) {
    const sourceValue = catalogProviderSourceValue(providerId, materialFromBody);
    const binding = state.vault.bindVaultRef({
      vaultRef: catalogProviderMaterialVaultRef(providerId),
      material: sourceValue,
      purpose: catalogProviderMaterialPurpose(providerId),
      label: catalogProviderMaterialLabel(providerId),
    });
    state.writeVaultRefs();
    runtimeMaterial = {
      ...materialFromBody,
      runtimeMaterialStatus: "bound_runtime_session",
      materialSource: binding.materialSource ?? "runtime_memory",
      materialVaultRefHash: binding.vaultRefHash,
      evidenceRefs: normalizeScopes(binding.evidenceRefs, ["VaultPort.bindVaultRef", "catalog_provider_source_material_vault_bound"]),
    };
    materialVaultRefHash = binding.vaultRefHash;
    materialSource = binding.materialSource ?? "runtime_memory";
    materialPersistence =
      binding.materialSource === "encrypted_keychain_vault_adapter"
        ? "vault_material_adapter"
        : "runtime_vault_binding";
    runtimeMaterialStatus = "bound_runtime_session";
    evidenceRefs.push("VaultPort.bindVaultRef", "catalog_provider_source_material_vault_bound");
  } else if (existing?.materialConfigured || existing?.materialVaultRefHash) {
    runtimeMaterial = state.catalogProviderRuntimeMaterial(providerId);
    materialVaultRefHash = runtimeMaterial?.materialVaultRefHash ?? existing?.materialVaultRefHash ?? stableHash(catalogProviderMaterialVaultRef(providerId));
    materialSource = runtimeMaterial?.materialSource ?? existing?.vaultMaterialSource ?? null;
    runtimeMaterialStatus =
      runtimeMaterial?.runtimeMaterialStatus ??
      (catalogProviderHasSourceMaterial(runtimeMaterial) ? "resolved_from_vault" : "missing_runtime_material");
    if (materialSource === "encrypted_keychain_vault_adapter") materialPersistence = "vault_material_adapter";
    evidenceRefs.push("VaultPort.resolveVaultRef", "catalog_provider_source_material_vault_resolve");
  }
  const material = catalogProviderHasSourceMaterial(runtimeMaterial) ? runtimeMaterial : {};
  const materialHash =
    providerId === "catalog.local_manifest"
      ? material.manifestPath
        ? stableHash(path.resolve(material.manifestPath))
        : existing?.manifestPathHash ?? null
      : providerId === "catalog.custom_http" && material.baseUrl
        ? stableHash(material.baseUrl)
        : providerId === "catalog.custom_http"
          ? existing?.baseUrlHash ?? null
          : null;
  const authConfig = catalogProviderAuthConfig(providerId, body, existing, state);
  const authVaultRefHash = authConfig.authVaultRefHash;
  if (authVaultRefHash) evidenceRefs.push("wallet.network.vault_ref_boundary", "catalog_provider_auth_vault_ref");
  if (!materialVaultRefHash && (materialHash || existing?.materialConfigured)) {
    materialVaultRefHash = stableHash(catalogProviderMaterialVaultRef(providerId));
  }
  const record = {
    id: providerId,
    schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    enabled,
    configHash: stableHash({
      providerId,
      enabled,
      materialHash,
      materialVaultRefHash,
      authVaultRefHash,
      catalogAuthScheme: authConfig.catalogAuthScheme,
      catalogAuthHeaderNameHash: authConfig.catalogAuthHeaderNameHash,
      oauthSessionHash: authConfig.oauthSessionHash,
    }),
    manifestPathHash: providerId === "catalog.local_manifest" ? materialHash : null,
    baseUrlHash: providerId === "catalog.custom_http" ? materialHash : null,
    authVaultRef: authConfig.authVaultRef,
    authVaultRefHash,
    catalogAuthConfigured: authConfig.catalogAuthConfigured,
    catalogAuthScheme: authConfig.catalogAuthScheme,
    catalogAuthHeaderName: authConfig.catalogAuthHeaderName,
    catalogAuthHeaderNameHash: authConfig.catalogAuthHeaderNameHash,
    oauthSessionId: authConfig.oauthSessionId,
    oauthSessionHash: authConfig.oauthSessionHash,
    oauthBoundary: authConfig.oauthBoundary,
    materialVaultRefHash,
    materialConfigured: Boolean(materialHash),
    materialPersistence: materialHash ? materialPersistence : "metadata_only",
    runtimeMaterialStatus: materialHash ? runtimeMaterialStatus : "unconfigured",
    vaultMaterialSource: materialSource,
    updatedAt,
    evidenceRefs: normalizeScopes(evidenceRefs, ["catalog_provider_config_metadata", "no_plaintext_catalog_material_persisted"]),
  };
  return {
    record,
    runtimeMaterial: materialHash ? runtimeMaterial : null,
    evidenceRefs: record.evidenceRefs,
  };
}

function catalogProviderRuntimeMaterialFromBody(providerId, body) {
  if (providerId === "catalog.local_manifest") {
    const manifestPath = body.manifest_path ?? body.manifestPath ?? body.path ?? null;
    return catalogProviderRuntimeMaterialFromValue(providerId, manifestPath);
  }
  if (providerId === "catalog.custom_http") {
    const baseUrl = body.base_url ?? body.baseUrl ?? body.url ?? null;
    return catalogProviderRuntimeMaterialFromValue(providerId, baseUrl);
  }
  return {};
}

function catalogProviderAuthConfig(providerId, body, existing = null, state) {
  const authVaultInput = firstOwn(body, ["auth_vault_ref", "authVaultRef", "vault_ref", "vaultRef", "api_key_vault_ref", "apiKeyVaultRef"]);
  const authVaultRef =
    authVaultInput.has
      ? typeof authVaultInput.value === "string" && authVaultInput.value.trim()
        ? authVaultInput.value.trim()
        : null
      : existing?.authVaultRef ?? null;
  const authVaultRefHash = authVaultRef
    ? state.walletAuthority.resolveVaultRef(authVaultRef).vaultRefHash
    : authVaultInput.has
      ? null
      : existing?.authVaultRefHash ?? null;
  const rawScheme = body.auth_scheme ?? body.authScheme ?? existing?.catalogAuthScheme ?? existing?.authScheme ?? "bearer";
  const catalogAuthScheme = normalizeCatalogAuthScheme(rawScheme);
  const rawHeaderName = body.auth_header_name ?? body.authHeaderName ?? existing?.catalogAuthHeaderName ?? existing?.authHeaderName ?? "authorization";
  const catalogAuthHeaderName = normalizeProviderAuthHeaderName(rawHeaderName);
  const catalogAuthHeaderNameHash = stableHash(catalogAuthHeaderName);
  const oauthSessionInput = firstOwn(body, ["oauth_session_id", "oauthSessionId"]);
  const oauthSessionId =
    oauthSessionInput.has
      ? typeof oauthSessionInput.value === "string" && oauthSessionInput.value.trim()
        ? oauthSessionInput.value.trim()
        : null
      : existing?.oauthSessionId ?? null;
  const oauthSessionHash = oauthSessionId ? stableHash(oauthSessionId) : oauthSessionInput.has ? null : existing?.oauthSessionHash ?? null;
  const oauthSession = oauthSessionId ? state?.oauthSessions?.get(oauthSessionId) ?? null : null;
  const catalogAuthConfigured = Boolean(authVaultRefHash || oauthSessionHash);
  const oauthBoundary =
    catalogAuthScheme === "oauth2"
      ? oauthSession
        ? oauthBoundaryForSession(oauthSession)
        : {
            configured: catalogAuthConfigured,
            status: catalogAuthConfigured ? "vault_token_passthrough" : "requires_oauth_exchange",
            tokenExchange: catalogAuthConfigured ? "vault_token_passthrough" : "OAuthCredentialProvider.exchangeAuthorizationCode",
            oauthSessionHash,
            evidenceRefs: ["catalog_oauth_boundary", "vault_ref_oauth_token_material"],
          }
      : null;
  return {
    authVaultRef,
    authVaultRefHash,
    catalogAuthConfigured,
    catalogAuthScheme,
    catalogAuthHeaderName,
    catalogAuthHeaderNameHash,
    oauthSessionId,
    oauthSessionHash,
    oauthBoundary,
  };
}

function firstOwn(value, keys) {
  if (!value || typeof value !== "object") return { has: false, value: undefined };
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(value, key)) {
      return { has: true, value: value[key] };
    }
  }
  return { has: false, value: undefined };
}

function normalizeCatalogAuthScheme(value) {
  const scheme = String(value ?? "bearer").toLowerCase().replace(/[-\s]+/g, "_");
  if (["bearer", "raw", "api_key", "oauth2"].includes(scheme)) return scheme;
  throw runtimeError({
    status: 400,
    code: "validation",
    message: "Catalog auth scheme must be bearer, raw, api_key, or oauth2.",
    details: { authScheme: scheme },
  });
}

function catalogProviderRuntimeMaterialFromValue(providerId, value) {
  if (providerId === "catalog.local_manifest") {
    return {
      manifestPath: typeof value === "string" && value.trim() ? path.resolve(value.trim()) : null,
    };
  }
  if (providerId === "catalog.custom_http") {
    return {
      baseUrl: typeof value === "string" && value.trim() ? value.trim().replace(/\/+$/, "") : null,
    };
  }
  return {};
}

function catalogProviderHasSourceMaterial(material) {
  return Boolean(material?.manifestPath || material?.baseUrl);
}

function catalogProviderSourceValue(providerId, material) {
  if (providerId === "catalog.local_manifest") return path.resolve(material.manifestPath);
  if (providerId === "catalog.custom_http") return material.baseUrl;
  return "";
}

function catalogProviderMaterialVaultRef(providerId) {
  return `vault://ioi/model-catalog/${safeId(providerId)}/source`;
}

function catalogProviderMaterialPurpose(providerId) {
  return `catalog.source:${providerId}`;
}

function catalogProviderMaterialLabel(providerId) {
  return providerId === "catalog.local_manifest" ? "Local manifest catalog source" : "Custom HTTP catalog source";
}

async function catalogProviderAuthHeaders(providerId, state) {
  const config = state?.catalogProviderConfig?.(providerId) ?? null;
  if (!config?.authVaultRef && !config?.authVaultRefHash && !config?.oauthSessionId) return { headers: {}, evidence: null };
  const headerName = normalizeProviderAuthHeaderName(config.catalogAuthHeaderName ?? "authorization");
  const authScheme = normalizeCatalogAuthScheme(config.catalogAuthScheme ?? "bearer");
  if (authScheme === "oauth2" && config.oauthSessionId) {
    const session = state?.oauthSessions?.get(config.oauthSessionId) ?? null;
    const resolved = await state.oauthCredentialProvider.resolveAccessHeader(session, { providerId, headerName });
    if (resolved.refreshed) {
      state.oauthSessions.set(resolved.session.id, resolved.session);
      state.writeMap?.("oauth-sessions", state.oauthSessions);
      if (config?.id && state.catalogProviderConfigs?.has(config.id)) {
        state.catalogProviderConfigs.set(config.id, {
          ...config,
          oauthBoundary: oauthBoundaryForSession(resolved.session, { refreshed: true }),
          updatedAt: state.nowIso?.() ?? config.updatedAt,
        });
        state.writeMap?.("model-catalog-providers", state.catalogProviderConfigs);
      }
    }
    state?.writeVaultRefs?.();
    return {
      headers: { [headerName]: resolved.headerValue },
      evidence: resolved.evidence,
    };
  }
  if (!config.authVaultRef) {
    throw runtimeError({
      status: 403,
      code: "policy",
      message: "Catalog auth is configured by hash only; request-time vault ref resolution requires a vault ref.",
      details: {
        catalogProviderId: providerId,
        authVaultRefHash: config.authVaultRefHash ?? null,
        resolvedMaterial: false,
        evidenceRefs: ["catalog_auth_fail_closed", "vault_ref_required"],
      },
    });
  }
  const resolved = state?.vault?.resolveVaultRef(config.authVaultRef, `catalog.auth:${providerId}`);
  state?.writeVaultRefs?.();
  if (!resolved?.material) {
    throw runtimeError({
      status: 403,
      code: "policy",
      message: "Catalog auth vault ref is configured, but no runtime vault material is available.",
      details: {
        catalogProviderId: providerId,
        authVaultRefHash: resolved?.vaultRefHash ?? config.authVaultRefHash ?? stableHash(config.authVaultRef),
        resolvedMaterial: false,
        catalogAuthScheme: authScheme,
        catalogAuthHeaderNameHash: stableHash(headerName),
        evidenceRefs: normalizeScopes(resolved?.evidenceRefs, ["VaultPort.resolveVaultRef", "catalog_auth_fail_closed"]),
      },
    });
  }
  return {
    headers: {
      [headerName]: catalogAuthorizationHeaderValue(authScheme, resolved.material),
    },
    evidence: {
      authVaultRefHash: resolved.vaultRefHash,
      resolvedMaterial: true,
      catalogAuthResolved: true,
      catalogAuthScheme: authScheme,
      catalogAuthHeaderNameHash: stableHash(headerName),
      headerNames: [headerName],
      oauthBoundary:
        authScheme === "oauth2"
          ? {
              configured: true,
              status: "vault_token_passthrough",
              tokenExchange: "not_local",
              evidenceRefs: ["catalog_oauth_boundary", "vault_ref_oauth_token_material"],
            }
          : null,
      evidenceRefs: normalizeScopes(resolved.evidenceRefs, ["VaultPort.resolveVaultRef", "catalog_auth_resolved"]),
    },
  };
}

function catalogAuthorizationHeaderValue(authScheme, material) {
  if (authScheme === "raw" || authScheme === "api_key") return material;
  return `Bearer ${material}`;
}

function oauthSessionVaultRef(providerId, sessionId, kind) {
  return `vault://ioi/oauth/${safeId(providerId)}/${safeId(sessionId)}/${safeId(kind)}`;
}

function oauthExpiresAt(now, expiresIn) {
  const seconds = Number(expiresIn);
  const ttlMs = Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : 3600 * 1000;
  return new Date(now.getTime() + ttlMs).toISOString();
}

function oauthSessionNeedsRefresh(session, now) {
  if (!session?.expiresAt) return false;
  const expiresAt = Date.parse(session.expiresAt);
  if (!Number.isFinite(expiresAt)) return true;
  return expiresAt <= now.getTime() + 30_000;
}

function oauthBoundaryForSession(session, options = {}) {
  if (!session) {
    return {
      configured: false,
      status: "requires_oauth_exchange",
      tokenExchange: "OAuthCredentialProvider.exchangeAuthorizationCode",
      evidenceRefs: ["catalog_oauth_boundary"],
    };
  }
  return {
    configured: session.status === "active",
    status: session.status === "active" ? (options.refreshed ? "refreshed" : "active") : session.status ?? "unknown",
    tokenExchange: "OAuthCredentialProvider",
    oauthSessionHash: stableHash(session.id),
    expiresAt: session.expiresAt ?? null,
    scopes: normalizeOAuthScopes(session.scopes, []),
    refreshCount: Number(session.refreshCount ?? 0),
    evidenceRefs: normalizeScopes(session.evidenceRefs, ["catalog_oauth_boundary", "VaultOAuthSession"]),
  };
}

function publicOAuthSession(session) {
  return {
    id: session.id,
    providerId: session.providerId,
    status: session.status,
    oauthSessionHash: stableHash(session.id),
    accessVaultRefHash: session.accessVaultRefHash ?? (session.accessVaultRef ? stableHash(session.accessVaultRef) : null),
    refreshVaultRefHash: session.refreshVaultRefHash ?? (session.refreshVaultRef ? stableHash(session.refreshVaultRef) : null),
    tokenEndpointVaultRefHash: session.tokenEndpointVaultRefHash ?? (session.tokenEndpointVaultRef ? stableHash(session.tokenEndpointVaultRef) : null),
    tokenEndpointHash: session.tokenEndpointHash ?? null,
    clientIdVaultRefHash: session.clientIdVaultRefHash ?? (session.clientIdVaultRef ? stableHash(session.clientIdVaultRef) : null),
    clientIdHash: session.clientIdHash ?? null,
    clientSecretVaultRefHash: session.clientSecretVaultRefHash ?? (session.clientSecretVaultRef ? stableHash(session.clientSecretVaultRef) : null),
    accessTokenHash: session.accessTokenHash ?? null,
    refreshTokenHash: session.refreshTokenHash ?? null,
    scopes: normalizeOAuthScopes(session.scopes, []),
    expiresAt: session.expiresAt ?? null,
    issuedAt: session.issuedAt ?? null,
    lastRefreshedAt: session.lastRefreshedAt ?? null,
    refreshCount: Number(session.refreshCount ?? 0),
    revokedAt: session.revokedAt ?? null,
    evidenceRefs: normalizeScopes(session.evidenceRefs, ["VaultOAuthSession"]),
  };
}

async function fetchOAuthToken(tokenEndpoint, payload) {
  const response = await fetchWithTimeout(tokenEndpoint, {
    method: "POST",
    timeoutMs: modelCatalogTimeoutMs(),
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(payload),
  });
  if (!response.ok) {
    throw runtimeError({
      status: 403,
      code: "policy",
      message: "OAuth token endpoint rejected the credential exchange.",
      details: {
        tokenEndpointHash: stableHash(tokenEndpoint),
        errorHash: stableHash(`oauth:${response.status}`),
        evidenceRefs: ["OAuthCredentialProvider.tokenEndpoint", "oauth_exchange_fail_closed"],
      },
    });
  }
  return response;
}

async function parseOAuthTokenResponse(response) {
  const payload = await response.json();
  if (!payload || typeof payload !== "object" || !payload.access_token) {
    throw runtimeError({
      status: 502,
      code: "provider_error",
      message: "OAuth token endpoint did not return an access token.",
      details: { evidenceRefs: ["OAuthCredentialProvider.tokenEndpoint", "oauth_access_token_required"] },
    });
  }
  return payload;
}

function catalogAuthProviderFields(evidence = null) {
  if (!evidence) return {};
  return {
    authVaultRefHash: evidence.authVaultRefHash ?? null,
    catalogAuthConfigured: true,
    catalogAuthResolved: Boolean(evidence.resolvedMaterial ?? evidence.catalogAuthResolved),
    catalogAuthScheme: evidence.catalogAuthScheme ?? "bearer",
    catalogAuthHeaderNameHash: evidence.catalogAuthHeaderNameHash ?? null,
    catalogAuthEvidenceRefs: normalizeScopes(evidence.evidenceRefs, []),
    oauthBoundary: evidence.oauthBoundary ?? null,
  };
}

function publicCatalogAuthEvidence(evidence = null) {
  if (!evidence) return null;
  return {
    authVaultRefHash: evidence.authVaultRefHash ?? null,
    resolvedMaterial: Boolean(evidence.resolvedMaterial ?? evidence.catalogAuthResolved),
    catalogAuthScheme: evidence.catalogAuthScheme ?? "bearer",
    catalogAuthHeaderNameHash: evidence.catalogAuthHeaderNameHash ?? null,
    evidenceRefs: normalizeScopes(evidence.evidenceRefs, []),
    oauthBoundary: evidence.oauthBoundary ?? null,
  };
}

function catalogEntryWithAuth(entry, evidence = null) {
  if (!evidence) return entry;
  return {
    ...entry,
    catalogAuth: publicCatalogAuthEvidence(evidence),
  };
}

function catalogAuthFailureStatus(error) {
  if (error?.status === 403 || error?.code === "policy") return "blocked";
  return "degraded";
}

function catalogAuthFailureFields(error) {
  const details = error?.details && typeof error.details === "object" ? error.details : {};
  if (!details.authVaultRefHash && !details.catalogAuthHeaderNameHash && !details.catalogAuthScheme && !details.oauthSessionHash) return {};
  return {
    authVaultRefHash: details.authVaultRefHash ?? null,
    catalogAuthConfigured: true,
    catalogAuthResolved: false,
    catalogAuthScheme: details.catalogAuthScheme ?? "bearer",
    catalogAuthHeaderNameHash: details.catalogAuthHeaderNameHash ?? null,
    catalogAuthEvidenceRefs: normalizeScopes(details.evidenceRefs, ["catalog_auth_fail_closed"]),
    oauthSessionHash: details.oauthSessionHash ?? details.oauthBoundary?.oauthSessionHash ?? null,
    oauthBoundary: details.oauthBoundary ?? null,
  };
}

function publicCatalogProviderConfig(providerId, record = null, material = null) {
  const materialConfigured = Boolean(record?.materialConfigured ?? material?.manifestPath ?? material?.baseUrl);
  return {
    id: providerId,
    enabled: record?.enabled ?? true,
    configHash: record?.configHash ?? null,
    manifestPathHash: record?.manifestPathHash ?? (material?.manifestPath ? stableHash(path.resolve(material.manifestPath)) : null),
    baseUrlHash: record?.baseUrlHash ?? (material?.baseUrl ? stableHash(material.baseUrl) : null),
    authVaultRefHash: record?.authVaultRefHash ?? material?.authVaultRefHash ?? null,
    catalogAuthConfigured: Boolean(record?.catalogAuthConfigured ?? record?.authVaultRefHash ?? false),
    catalogAuthScheme: record?.catalogAuthScheme ?? "bearer",
    catalogAuthHeaderNameHash: record?.catalogAuthHeaderNameHash ?? null,
    oauthSessionHash: record?.oauthSessionHash ?? (record?.oauthSessionId ? stableHash(record.oauthSessionId) : null),
    oauthBoundary: record?.oauthBoundary ?? null,
    materialVaultRefHash: record?.materialVaultRefHash ?? material?.materialVaultRefHash ?? null,
    materialConfigured,
    materialPersistence: record?.materialPersistence ?? "metadata_only",
    runtimeMaterialStatus: materialConfigured
      ? material?.runtimeMaterialStatus
        ? material.runtimeMaterialStatus
        : material?.manifestPath || material?.baseUrl
          ? "bound_runtime_session"
          : record?.runtimeMaterialStatus ?? "missing_runtime_material"
      : "unconfigured",
    vaultMaterialSource: material?.materialSource ?? record?.vaultMaterialSource ?? null,
    errorHash: material?.errorHash ?? record?.errorHash ?? null,
    updatedAt: record?.updatedAt ?? null,
    evidenceRefs: normalizeScopes(
      [...normalizeScopes(record?.evidenceRefs, ["catalog_provider_config_metadata", "no_plaintext_catalog_material_persisted"]), ...normalizeScopes(material?.evidenceRefs, [])],
      ["catalog_provider_config_metadata", "no_plaintext_catalog_material_persisted"],
    ),
  };
}

function catalogProviderConfigHealthFields(providerId, config = null, material = null) {
  const publicConfig = publicCatalogProviderConfig(providerId, config, material);
  return {
    enabled: publicConfig.enabled,
    configHash: publicConfig.configHash,
    manifestPathHash: publicConfig.manifestPathHash,
    baseUrlHash: publicConfig.baseUrlHash,
    authVaultRefHash: publicConfig.authVaultRefHash,
    catalogAuthConfigured: publicConfig.catalogAuthConfigured,
    catalogAuthScheme: publicConfig.catalogAuthScheme,
    catalogAuthHeaderNameHash: publicConfig.catalogAuthHeaderNameHash,
    oauthSessionHash: publicConfig.oauthSessionHash,
    oauthBoundary: publicConfig.oauthBoundary,
    materialVaultRefHash: publicConfig.materialVaultRefHash,
    materialConfigured: publicConfig.materialConfigured,
    materialPersistence: publicConfig.materialPersistence,
    runtimeMaterialStatus: publicConfig.runtimeMaterialStatus,
    vaultMaterialSource: publicConfig.vaultMaterialSource,
    errorHash: publicConfig.errorHash,
  };
}

function modelCatalogProviderPorts(state) {
  return [
    fixtureCatalogProviderPort(),
    localManifestCatalogProviderPort(state),
    ollamaCatalogProviderPort(state),
    huggingFaceCatalogProviderPort(state),
    customHttpCatalogProviderPort(state),
  ];
}

function catalogProviderStatus(port, result = null) {
  const health = typeof port.health === "function" ? port.health() : {};
  return {
    id: port.id,
    label: port.label,
    status: result?.status ?? health.status ?? port.status ?? "unknown",
    gate: port.gate ?? health.gate ?? null,
    downloadGate: port.downloadGate ?? health.downloadGate ?? null,
    liveDownloadStatus: result?.liveDownloadStatus ?? health.liveDownloadStatus ?? null,
    formats: port.formats ?? [],
    enabled: result?.enabled ?? health.enabled ?? null,
    configHash: result?.configHash ?? health.configHash ?? null,
    baseUrlHash: result?.baseUrlHash ?? health.baseUrlHash ?? null,
    manifestPathHash: result?.manifestPathHash ?? health.manifestPathHash ?? null,
    authVaultRefHash: result?.authVaultRefHash ?? health.authVaultRefHash ?? null,
    catalogAuthConfigured: result?.catalogAuthConfigured ?? health.catalogAuthConfigured ?? null,
    catalogAuthResolved: result?.catalogAuthResolved ?? health.catalogAuthResolved ?? null,
    catalogAuthScheme: result?.catalogAuthScheme ?? health.catalogAuthScheme ?? null,
    catalogAuthHeaderNameHash: result?.catalogAuthHeaderNameHash ?? health.catalogAuthHeaderNameHash ?? null,
    catalogAuthEvidenceRefs: result?.catalogAuthEvidenceRefs ?? health.catalogAuthEvidenceRefs ?? [],
    oauthBoundary: result?.oauthBoundary ?? health.oauthBoundary ?? null,
    oauthSessionHash: result?.oauthSessionHash ?? health.oauthSessionHash ?? result?.oauthBoundary?.oauthSessionHash ?? health.oauthBoundary?.oauthSessionHash ?? null,
    materialVaultRefHash: result?.materialVaultRefHash ?? health.materialVaultRefHash ?? null,
    materialConfigured: result?.materialConfigured ?? health.materialConfigured ?? null,
    materialPersistence: result?.materialPersistence ?? health.materialPersistence ?? null,
    runtimeMaterialStatus: result?.runtimeMaterialStatus ?? health.runtimeMaterialStatus ?? null,
    vaultMaterialSource: result?.vaultMaterialSource ?? health.vaultMaterialSource ?? null,
    providerId: port.providerId ?? null,
    errorHash: result?.errorHash ?? health.errorHash ?? null,
    adapterPort: "ModelCatalogProviderPort",
    operations: ["search", "resolveVariant", "importUrl", "download", "health"],
    evidenceRefs: result?.evidenceRefs ?? health.evidenceRefs ?? port.evidenceRefs ?? [],
  };
}

function fixtureCatalogProviderPort() {
  const evidenceRefs = ["fixture_model_catalog", "model_catalog_provider_port"];
  return {
    id: "catalog.fixture",
    label: "Fixture catalog",
    gate: "always_on",
    formats: ["gguf"],
    evidenceRefs,
    health: () => ({ status: "available", evidenceRefs }),
    search: async ({ query, format, quantization, searchedAt }) => ({
      status: "available",
      evidenceRefs,
      results: fixtureModelCatalog(searchedAt).filter((entry) => catalogEntryMatches(entry, { query, format, quantization })),
    }),
  };
}

function localManifestCatalogProviderPort(state) {
  const evidenceRefs = ["local_manifest_catalog_adapter", "model_catalog_provider_port"];
  return {
    id: "catalog.local_manifest",
    label: "Local manifest catalog",
    gate: "IOI_MODEL_CATALOG_MANIFEST_PATH or catalog provider setup",
    formats: ["gguf", "mlx", "safetensors"],
    evidenceRefs,
    health: () => localManifestCatalogHealth(state, evidenceRefs),
    search: async ({ query, format, quantization, searchedAt }) => {
      const health = localManifestCatalogHealth(state, evidenceRefs);
      if (health.status !== "configured" && health.status !== "available") {
        return { ...health, results: [] };
      }
      try {
        const manifestPath = localManifestCatalogPath(state);
        const results = localManifestCatalogEntries(manifestPath, searchedAt).filter((entry) => catalogEntryMatches(entry, { query, format, quantization }));
        return { ...health, status: "available", results };
      } catch (error) {
        return {
          ...health,
          status: "degraded",
          errorHash: stableHash(error?.message ?? "manifest catalog failed"),
          results: [],
        };
      }
    },
  };
}

function ollamaCatalogProviderPort(state) {
  const evidenceRefs = ["ollama_catalog_list_bridge", "model_catalog_provider_port"];
  const provider = state.providers.get("provider.ollama");
  return {
    id: "catalog.ollama",
    label: "Ollama catalog bridge",
    providerId: "provider.ollama",
    gate: "OLLAMA_HOST",
    formats: ["ollama"],
    evidenceRefs,
    health: () => ({
      status: provider && provider.status !== "blocked" ? "configured" : "gated",
      baseUrlHash: provider?.baseUrl ? stableHash(provider.baseUrl) : null,
      evidenceRefs,
    }),
    search: async ({ query, format, quantization, searchedAt }) => {
      if (format && format !== "ollama") return { ...catalogProviderStatus({ id: "catalog.ollama", label: "Ollama catalog bridge", evidenceRefs }), status: "configured", results: [] };
      if (!provider || provider.status === "blocked") {
        return { status: "gated", baseUrlHash: provider?.baseUrl ? stableHash(provider.baseUrl) : null, evidenceRefs, results: [] };
      }
      try {
        const artifacts = await state.driverForProvider(provider).listModels({ state, provider });
        const results = artifacts
          .map((artifact) => ollamaArtifactCatalogEntry(artifact, searchedAt))
          .filter((entry) => catalogEntryMatches(entry, { query, format, quantization }));
        return { status: "available", baseUrlHash: stableHash(provider.baseUrl), evidenceRefs, results };
      } catch (error) {
        return {
          status: "degraded",
          baseUrlHash: provider?.baseUrl ? stableHash(provider.baseUrl) : null,
          errorHash: stableHash(error?.message ?? "ollama catalog failed"),
          evidenceRefs,
          results: [],
        };
      }
    },
  };
}

function huggingFaceCatalogProviderPort(state) {
  const baseUrl = huggingFaceCatalogBaseUrl();
  const evidenceRefs = ["huggingface_catalog_adapter_boundary", "network_access_opt_in", "model_catalog_provider_port"];
  const config = state?.catalogProviderConfig?.("catalog.huggingface") ?? null;
  const configFields = catalogProviderConfigHealthFields("catalog.huggingface", config, null);
  return {
    id: "catalog.huggingface",
    label: "Hugging Face-compatible catalog",
    gate: "IOI_LIVE_MODEL_CATALOG",
    downloadGate: "IOI_LIVE_MODEL_DOWNLOAD",
    formats: ["gguf", "mlx", "safetensors"],
    evidenceRefs,
    health: () => ({
      ...configFields,
      status: liveModelCatalogEnabled() ? "configured" : "gated",
      baseUrlHash: stableHash(baseUrl),
      liveDownloadStatus: liveModelDownloadEnabled() ? "configured" : "gated",
      evidenceRefs,
    }),
    search: async ({ query, format, quantization, limit, searchedAt }) => state.searchHuggingFaceCatalog({ query, format, quantization, limit, searchedAt }),
  };
}

function customHttpCatalogProviderPort(state) {
  const evidenceRefs = ["custom_http_catalog_adapter", "model_catalog_provider_port"];
  return {
    id: "catalog.custom_http",
    label: "Custom HTTP catalog",
    gate: "IOI_MODEL_CATALOG_CUSTOM_BASE_URL or catalog provider setup",
    formats: ["gguf", "mlx", "safetensors"],
    evidenceRefs,
    health: () => customHttpCatalogHealth(state, evidenceRefs),
    search: async ({ query, format, quantization, limit, searchedAt }) => {
      const health = customHttpCatalogHealth(state, evidenceRefs);
      const baseUrl = customHttpCatalogBaseUrl(state);
      if (!baseUrl) return { ...health, results: [] };
      try {
        const auth = await catalogProviderAuthHeaders("catalog.custom_http", state);
        const url = new URL("/catalog/search", baseUrl);
        if (query) url.searchParams.set("q", query);
        if (format) url.searchParams.set("format", format);
        if (quantization) url.searchParams.set("quantization", quantization);
        url.searchParams.set("limit", String(limit));
        const response = await fetchWithTimeout(url, { timeoutMs: modelCatalogTimeoutMs(), headers: auth.headers });
        if (!response.ok) {
          return {
            ...health,
            ...catalogAuthProviderFields(auth.evidence),
            status: "degraded",
            baseUrlHash: stableHash(baseUrl),
            errorHash: stableHash(`http:${response.status}`),
            evidenceRefs: [...evidenceRefs, ...normalizeScopes(auth.evidence?.evidenceRefs, [])],
            results: [],
          };
        }
        const payload = await response.json();
        const records = catalogRecordsFromPayload(payload);
        const results = records
          .map((record) =>
            genericCatalogEntry(record, {
              catalogProviderId: "catalog.custom_http",
              sourceLabelPrefix: "Custom catalog",
              searchedAt,
            }),
          )
          .filter(Boolean)
          .map((entry) => catalogEntryWithAuth(entry, auth.evidence))
          .filter((entry) => catalogEntryMatches(entry, { query, format, quantization }))
          .slice(0, limit);
        return {
          ...health,
          ...catalogAuthProviderFields(auth.evidence),
          status: "available",
          baseUrlHash: stableHash(baseUrl),
          evidenceRefs: [...evidenceRefs, "custom_http_catalog_search", ...normalizeScopes(auth.evidence?.evidenceRefs, [])],
          results,
        };
      } catch (error) {
        return {
          ...health,
          ...catalogAuthFailureFields(error),
          status: catalogAuthFailureStatus(error),
          baseUrlHash: stableHash(baseUrl),
          errorHash: stableHash(error?.message ?? "custom catalog failed"),
          evidenceRefs,
          results: [],
        };
      }
    },
  };
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

function localManifestCatalogPath(state) {
  const config = state?.catalogProviderConfig?.("catalog.local_manifest") ?? null;
  if (config && config.enabled === false) return "";
  return state?.catalogProviderRuntimeMaterial?.("catalog.local_manifest")?.manifestPath ?? process.env.IOI_MODEL_CATALOG_MANIFEST_PATH ?? "";
}

function customHttpCatalogBaseUrl(state) {
  const config = state?.catalogProviderConfig?.("catalog.custom_http") ?? null;
  if (config && config.enabled === false) return "";
  return state?.catalogProviderRuntimeMaterial?.("catalog.custom_http")?.baseUrl ?? process.env.IOI_MODEL_CATALOG_CUSTOM_BASE_URL ?? "";
}

function localManifestCatalogHealth(state, evidenceRefs) {
  const config = state?.catalogProviderConfig?.("catalog.local_manifest") ?? null;
  const material = state?.catalogProviderRuntimeMaterial?.("catalog.local_manifest") ?? null;
  const manifestPath = localManifestCatalogPath(state);
  const configFields = catalogProviderConfigHealthFields("catalog.local_manifest", config, material);
  if (config?.enabled === false) {
    return { ...configFields, status: "disabled", gate: "catalog provider setup", evidenceRefs };
  }
  if (!manifestPath) {
    return {
      ...configFields,
      status: config?.materialConfigured ? "metadata_only" : "unconfigured",
      gate: "IOI_MODEL_CATALOG_MANIFEST_PATH or catalog provider setup",
      evidenceRefs,
    };
  }
  const resolved = path.resolve(manifestPath);
  return {
    ...configFields,
    status: fs.existsSync(resolved) ? "configured" : "degraded",
    gate: material?.manifestPath ? "vault-backed catalog provider setup" : "IOI_MODEL_CATALOG_MANIFEST_PATH",
    manifestPathHash: stableHash(resolved),
    materialConfigured: true,
    runtimeMaterialStatus: material?.manifestPath ? material.runtimeMaterialStatus ?? "bound_runtime_session" : "env_gate",
    materialVaultRefHash: material?.materialVaultRefHash ?? configFields.materialVaultRefHash,
    vaultMaterialSource: material?.materialSource ?? configFields.vaultMaterialSource,
    evidenceRefs,
  };
}

function customHttpCatalogHealth(state, evidenceRefs) {
  const config = state?.catalogProviderConfig?.("catalog.custom_http") ?? null;
  const material = state?.catalogProviderRuntimeMaterial?.("catalog.custom_http") ?? null;
  const baseUrl = customHttpCatalogBaseUrl(state);
  const configFields = catalogProviderConfigHealthFields("catalog.custom_http", config, material);
  if (config?.enabled === false) {
    return { ...configFields, status: "disabled", gate: "catalog provider setup", evidenceRefs };
  }
  if (!baseUrl) {
    return {
      ...configFields,
      status: config?.materialConfigured ? "metadata_only" : "unconfigured",
      gate: "IOI_MODEL_CATALOG_CUSTOM_BASE_URL or catalog provider setup",
      evidenceRefs,
    };
  }
  return {
    ...configFields,
    status: "configured",
    gate: material?.baseUrl ? "vault-backed catalog provider setup" : "IOI_MODEL_CATALOG_CUSTOM_BASE_URL",
    baseUrlHash: stableHash(baseUrl),
    materialConfigured: true,
    runtimeMaterialStatus: material?.baseUrl ? material.runtimeMaterialStatus ?? "bound_runtime_session" : "env_gate",
    materialVaultRefHash: material?.materialVaultRefHash ?? configFields.materialVaultRefHash,
    vaultMaterialSource: material?.materialSource ?? configFields.vaultMaterialSource,
    evidenceRefs,
  };
}

function localManifestCatalogEntries(manifestPath, searchedAt) {
  const payload = readJson(path.resolve(manifestPath));
  return catalogRecordsFromPayload(payload)
    .map((record) =>
      genericCatalogEntry(record, {
        catalogProviderId: "catalog.local_manifest",
        sourceLabelPrefix: "Local manifest",
        searchedAt,
      }),
    )
    .filter(Boolean);
}

function catalogRecordsFromPayload(payload) {
  if (Array.isArray(payload)) return payload;
  if (Array.isArray(payload?.models)) return payload.models;
  if (Array.isArray(payload?.results)) return payload.results;
  if (Array.isArray(payload?.entries)) return payload.entries;
  if (Array.isArray(payload?.catalog)) return payload.catalog;
  return [];
}

function modelCatalogTimeoutMs() {
  return Number(process.env.IOI_MODEL_CATALOG_TIMEOUT_MS ?? 5000) || 5000;
}

function modelDownloadTimeoutMs() {
  return Number(process.env.IOI_MODEL_DOWNLOAD_TIMEOUT_MS ?? 30000) || 30000;
}

async function fetchWithTimeout(url, { timeoutMs, headers = {}, method = "GET", body = undefined } = {}) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs ?? 5000);
  try {
    return await fetch(url, { method, headers, body, signal: controller.signal });
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
    architecture: record.config?.architectures?.[0] ?? record.architecture ?? inferModelArchitecture([repoId, filePath, ...(tags ?? [])].join(" ")),
    parameterCount: inferParameterCount([repoId, filePath].join(" ")),
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

function genericCatalogEntry(record, { catalogProviderId, sourceLabelPrefix, searchedAt }) {
  const modelId = String(record.model_id ?? record.modelId ?? record.id ?? record.name ?? "").trim();
  const sourceUrl = String(record.source_url ?? record.sourceUrl ?? record.download_url ?? record.downloadUrl ?? record.url ?? "").trim();
  if (!modelId || !sourceUrl) return null;
  const format = String(record.format ?? modelCatalogFileFormat(sourceUrl) ?? "").toLowerCase() || "gguf";
  const quantization = record.quantization ?? parseModelQuantization([sourceUrl, modelId].join(" ")) ?? null;
  const tags = normalizeScopes(record.tags, []);
  return {
    id: String(record.catalog_id ?? record.catalogId ?? `catalog.${safeId(catalogProviderId)}.${safeId(modelId)}.${safeId(sourceUrl)}`),
    providerId: String(record.provider_id ?? record.providerId ?? "provider.autopilot.local"),
    catalogProviderId,
    modelId,
    family: String(record.family ?? record.pipeline_tag ?? record.pipelineTag ?? sourceLabelPrefix.toLowerCase().replace(/\s+/g, "_")),
    architecture: record.architecture ?? inferModelArchitecture([modelId, sourceUrl, ...tags].join(" ")),
    parameterCount: record.parameter_count ?? record.parameterCount ?? inferParameterCount([modelId, sourceUrl].join(" ")),
    format,
    quantization,
    sizeBytes: Number(record.size_bytes ?? record.sizeBytes ?? record.size ?? 0) || null,
    contextWindow: Number(record.context_window ?? record.contextWindow ?? 0) || null,
    sourceUrl,
    sourceUrlHash: stableHash(sourceUrl),
    sourceLabel: String(record.source_label ?? record.sourceLabel ?? `${sourceLabelPrefix} / ${modelId}`),
    license: record.license ?? null,
    compatibility: normalizeScopes(record.compatibility, catalogCompatibilityForFormat(format)),
    tags: [...new Set([...tags, format, quantization].filter(Boolean))],
    variantPath: record.variant_path ?? record.variantPath ?? null,
    discoveredAt: searchedAt,
  };
}

function ollamaArtifactCatalogEntry(artifact, searchedAt) {
  const sourceUrl = `ollama://models/${encodeURIComponent(artifact.modelId)}`;
  return {
    id: `catalog.ollama.${safeId(artifact.modelId)}`,
    providerId: artifact.providerId ?? "provider.ollama",
    catalogProviderId: "catalog.ollama",
    modelId: artifact.modelId,
    family: artifact.family ?? "ollama",
    architecture: inferModelArchitecture(artifact.modelId),
    parameterCount: inferParameterCount(artifact.modelId),
    format: "ollama",
    quantization: artifact.quantization ?? null,
    sizeBytes: artifact.sizeBytes ?? null,
    contextWindow: artifact.contextWindow ?? null,
    sourceUrl,
    sourceUrlHash: stableHash(sourceUrl),
    sourceLabel: `Ollama / ${artifact.modelId}`,
    license: null,
    compatibility: ["ollama"],
    tags: ["ollama", ...(artifact.capabilities ?? [])],
    discoveredAt: searchedAt,
  };
}

function catalogEntryMatches(entry, { query, format, quantization }) {
  const haystack = [entry.modelId, entry.family, entry.format, entry.quantization, entry.sourceLabel, ...(entry.tags ?? [])].join(" ").toLowerCase();
  if (query && !haystack.includes(query)) return false;
  if (format && entry.format !== format) return false;
  if (quantization && !String(entry.quantization ?? "").toLowerCase().includes(quantization)) return false;
  return true;
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
  if (format === "ollama") return ["ollama"];
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
  const variant = {
    id: body.variant_id ?? body.variantId ?? catalogEntry?.id ?? `variant.${safeId(publicSource)}`,
    catalogProviderId: body.catalog_provider_id ?? body.catalogProviderId ?? catalogEntry?.catalogProviderId ?? null,
    family: body.family ?? catalogEntry?.family ?? modelIdFromSourceUrl(publicSource),
    architecture: body.architecture ?? catalogEntry?.architecture ?? inferModelArchitecture(publicSource),
    parameterCount: body.parameter_count ?? body.parameterCount ?? catalogEntry?.parameterCount ?? inferParameterCount(publicSource),
    format: body.format ?? catalogEntry?.format ?? modelCatalogFileFormat(publicSource) ?? "gguf",
    quantization: body.quantization ?? catalogEntry?.quantization ?? parseModelQuantization(publicSource) ?? "Q4_K_M",
    sizeBytes: Number(body.size_bytes ?? body.sizeBytes ?? catalogEntry?.sizeBytes ?? 0),
    contextWindow: Number(body.context_window ?? body.contextWindow ?? catalogEntry?.contextWindow ?? 4096),
    sourceLabel: body.source_label ?? body.sourceLabel ?? catalogEntry?.sourceLabel ?? sourceLabelForUrl(source),
    sourceUrl: publicSource,
    sourceUrlHash: stableHash(source),
    license: body.license ?? catalogEntry?.license ?? null,
    compatibility: normalizeScopes(body.compatibility, catalogEntry?.compatibility ?? ["native_local_fixture"]),
    catalogAuth: publicCatalogAuthEvidence(body.catalogAuth ?? catalogEntry?.catalogAuth ?? null),
  };
  return enrichCatalogEntry(variant, { maxBytes: body.max_bytes ?? body.maxBytes ?? null });
}

function enrichCatalogEntry(entry, { storage = {}, artifacts = [], maxBytes = null } = {}) {
  const architecture = entry.architecture ?? inferModelArchitecture([entry.modelId, entry.family, entry.variantPath, ...(entry.tags ?? [])].join(" "));
  const parameterCount = entry.parameterCount ?? inferParameterCount([entry.modelId, entry.variantPath, entry.sourceLabel].join(" "));
  const compatibility = normalizeScopes(entry.compatibility, catalogCompatibilityForFormat(entry.format));
  const backendCompatibility = catalogBackendCompatibility({ ...entry, architecture, parameterCount, compatibility });
  const benchmarkReadiness = catalogBenchmarkReadiness({ ...entry, compatibility });
  const downloadRisk = catalogDownloadRisk(entry, { storage, artifacts, maxBytes });
  const recommendation = catalogRecommendation({ backendCompatibility, benchmarkReadiness, downloadRisk });
  return {
    ...entry,
    architecture,
    parameterCount,
    compatibility,
    backendCompatibility,
    downloadRisk,
    benchmarkReadiness,
    recommendation,
    selectionReceiptFields: [
      "variant_id",
      "source_url_hash",
      "source_label",
      "format",
      "quantization",
      "architecture",
      "parameter_count",
      "backend_compatibility",
      "download_risk",
      "benchmark_readiness",
      "approval_decision",
    ],
  };
}

function catalogBackendCompatibility(entry) {
  const format = String(entry.format ?? "").toLowerCase();
  const compatibility = new Set(normalizeScopes(entry.compatibility, []));
  const rows = [
    backendCompatibilityRow("native_local_fixture", compatibility.has("native_local_fixture") || format === "gguf", format === "gguf" ? 92 : 70, "Autopilot native-local can import deterministic local artifacts."),
    backendCompatibilityRow("llama_cpp", compatibility.has("llama_cpp") || format === "gguf", format === "gguf" ? 90 : 25, "llama.cpp expects GGUF artifacts."),
    backendCompatibilityRow("ollama", compatibility.has("ollama") || format === "gguf", format === "ollama" ? 88 : format === "gguf" ? 62 : 20, "Ollama can run catalog-listed Ollama models and local GGUF through import/create workflows when configured."),
    backendCompatibilityRow("vllm", compatibility.has("vllm") || format === "safetensors", format === "safetensors" ? 88 : 18, "vLLM expects Hugging Face/safetensors-style artifacts."),
  ];
  return rows;
}

function backendCompatibilityRow(backendKind, compatible, score, reason) {
  return {
    backendKind,
    score: compatible ? score : Math.min(score, 20),
    status: compatible ? (score >= 80 ? "ready" : "compatible") : "unsupported",
    reason,
  };
}

function catalogBenchmarkReadiness(entry) {
  const text = [entry.modelId, entry.family, entry.sourceLabel, ...(entry.tags ?? []), ...(entry.compatibility ?? [])].join(" ").toLowerCase();
  const embeddings = /embed|embedding|nomic|bge|e5/.test(text);
  const rerank = /rerank|cross-encoder/.test(text);
  const vision = /vision|llava|vlm|multimodal|image/.test(text);
  const chat = !embeddings && !rerank;
  return {
    chat,
    embeddings,
    rerank,
    vision,
    structuredOutput: chat,
    hints: [
      chat ? "chat-ready" : null,
      embeddings ? "embedding-ready" : null,
      rerank ? "rerank-ready" : null,
      vision ? "vision-ready" : null,
      entry.format === "gguf" ? "local-gguf-benchmark" : null,
      entry.format === "safetensors" ? "vllm-benchmark" : null,
    ].filter(Boolean),
  };
}

function catalogDownloadRisk(entry, { storage = {}, artifacts = [], maxBytes = null } = {}) {
  const reasons = [];
  const sizeBytes = Number(entry.sizeBytes ?? 0);
  const byteCap = normalizeOptionalBytes(maxBytes);
  const existingArtifactCollision = artifacts.some((artifact) => artifact.modelId === entry.modelId || artifact.displayName === entry.modelId || artifact.id === entry.id);
  const quotaBytes = Number(storage.quotaBytes ?? 0) || null;
  const totalBytes = Number(storage.totalBytes ?? 0) || 0;
  let score = 10;
  let byteCapStatus = "not_set";
  if (byteCap) {
    byteCapStatus = sizeBytes && sizeBytes > byteCap ? "over_cap" : "within_cap";
    if (byteCapStatus === "over_cap") {
      score += 80;
      reasons.push("variant exceeds configured byte cap");
    }
  }
  if (quotaBytes && sizeBytes && totalBytes + sizeBytes > quotaBytes) {
    score += 55;
    reasons.push("download would exceed storage quota");
  }
  if (existingArtifactCollision) {
    score += 20;
    reasons.push("model id collides with an existing artifact");
  }
  if (!sizeBytes) {
    score += 15;
    reasons.push("variant size is unknown");
  }
  if (String(storage.quotaStatus ?? "") === "over_quota") {
    score += 40;
    reasons.push("storage is already over quota");
  }
  if (reasons.length === 0) reasons.push("size and storage projection are acceptable");
  const bounded = Math.min(100, score);
  return {
    score: bounded,
    status: bounded >= 85 ? "blocked" : bounded >= 55 ? "high" : bounded >= 30 ? "medium" : "low",
    reasons,
    existingArtifactCollision,
    byteCapStatus,
    storageStatus: String(storage.quotaStatus ?? "unknown"),
  };
}

function catalogRecommendation({ backendCompatibility, benchmarkReadiness, downloadRisk }) {
  const primary = [...backendCompatibility].sort((left, right) => right.score - left.score)[0] ?? null;
  const readinessBoost = benchmarkReadiness.chat || benchmarkReadiness.embeddings ? 8 : 0;
  const riskPenalty = downloadRisk.status === "blocked" ? 80 : downloadRisk.status === "high" ? 35 : downloadRisk.status === "medium" ? 15 : 0;
  const score = Math.max(0, Math.min(100, (primary?.score ?? 0) + readinessBoost - riskPenalty));
  const label = downloadRisk.status === "blocked" ? "blocked" : score >= 80 ? "recommended" : "review";
  return {
    score,
    label,
    primaryBackend: primary?.backendKind ?? null,
    reasons: [
      primary ? `${primary.backendKind} ${primary.status}` : "no compatible backend",
      ...downloadRisk.reasons.slice(0, 2),
      ...benchmarkReadiness.hints.slice(0, 2),
    ],
  };
}

function catalogApprovalDecision({ isFixture, body = {} }) {
  const approved = Boolean(body.transfer_approved ?? body.transferApproved ?? isFixture);
  return {
    required: !isFixture,
    approved,
    source: approved ? "operator_or_fixture" : "not_provided",
  };
}

function normalizeDownloadPolicy(body = {}, { isFixture, maxBytes, source } = {}) {
  const bandwidthLimitBps = normalizeOptionalBytes(
    body.bandwidth_bps ??
      body.bandwidthBps ??
      body.bandwidth_limit_bps ??
      body.bandwidthLimitBps ??
      process.env.IOI_MODEL_DOWNLOAD_BANDWIDTH_BPS,
  );
  const retryLimit = normalizeNonNegativeInteger(body.retry_limit ?? body.retryLimit ?? body.retries ?? 0, 0);
  const resume = truthy(body.resume ?? body.resume_download ?? body.resumeDownload ?? true);
  const cleanupPartialOnCancel = truthy(body.cleanup_partial ?? body.cleanupPartial ?? true);
  const approvalDecision = catalogApprovalDecision({ isFixture, body });
  return {
    maxBytes,
    bandwidthLimitBps,
    retryLimit,
    resume,
    cleanupPartialOnCancel,
    externalTransferRequired: approvalDecision.required,
    externalTransferApproved: approvalDecision.approved,
    approvalDecision,
    sourceHash: stableHash(source),
    status: approvalDecision.required && !approvalDecision.approved ? "blocked_approval_required" : "ready",
    evidenceRefs: ["model_download_transfer_policy", "external_transfer_approval_receipt"],
  };
}

function assertDownloadPolicyAllowed(policy, source) {
  if (!policy.externalTransferRequired || policy.externalTransferApproved) return;
  throw runtimeError({
    status: 403,
    code: "external_transfer_approval_required",
    message: "External model transfers require explicit operator approval.",
    details: {
      sourceHash: stableHash(source),
      approvalDecision: policy.approvalDecision,
      evidenceRefs: policy.evidenceRefs,
    },
  });
}

function destructiveConfirmationState(body = {}, { required = true, action = "destructive_action" } = {}) {
  const confirmed = Boolean(body.confirm_destructive ?? body.confirmDestructive ?? body.destructive_confirmed ?? body.destructiveConfirmed ?? false);
  return {
    required,
    confirmed: required ? confirmed : true,
    action,
    source: confirmed ? "operator_confirmation" : required ? "not_provided" : "not_required",
  };
}

function inferModelArchitecture(value) {
  const text = String(value ?? "").toLowerCase();
  if (/qwen/.test(text)) return "qwen";
  if (/llama|mistral|mixtral|vicuna|alpaca/.test(text)) return "llama";
  if (/nomic/.test(text)) return "nomic";
  if (/bge/.test(text)) return "bge";
  if (/gemma/.test(text)) return "gemma";
  if (/phi/.test(text)) return "phi";
  if (/bert|e5/.test(text)) return "bert";
  return "unknown";
}

function inferParameterCount(value) {
  const match = String(value ?? "").match(/(?:^|[^a-z0-9])(\d+(?:\.\d+)?)\s?([bBmMkK])(?:[^a-z0-9]|$)/);
  if (!match) return null;
  return `${match[1]}${match[2].toUpperCase()}`;
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
  const fd = fs.openSync(filePath, "r");
  try {
    const buffer = Buffer.allocUnsafe(8 * 1024 * 1024);
    while (true) {
      const bytesRead = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (bytesRead === 0) break;
      hash.update(buffer.subarray(0, bytesRead));
    }
  } finally {
    fs.closeSync(fd);
  }
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

async function materializeLiveDownload({
  source,
  targetPath,
  expectedChecksum,
  maxBytes,
  resume,
  bandwidthLimitBps,
  retryLimit = 0,
  timeoutMs,
  headers = {},
  onTransferEvent,
}) {
  const partialPath = `${targetPath}.part`;
  const metadataPath = `${partialPath}.json`;
  const maxAttempts = Math.max(1, normalizeNonNegativeInteger(retryLimit, 0) + 1);
  const transferBase = {
    sourceHash: stableHash(source),
    partialPathHash: stableHash(partialPath),
    targetPathHash: stableHash(targetPath),
    resumeMetadataPathHash: stableHash(metadataPath),
    retryLimit: maxAttempts - 1,
    resume,
    bandwidthLimitBps: bandwidthLimitBps ?? null,
  };
  let lastError;
  for (let attemptIndex = 0; attemptIndex < maxAttempts; attemptIndex += 1) {
    try {
      const result = await materializeLiveDownloadAttempt({
        source,
        targetPath,
        partialPath,
        metadataPath,
        expectedChecksum,
        maxBytes,
        resume,
        bandwidthLimitBps,
        timeoutMs,
        headers,
        attemptIndex,
        maxAttempts,
        transferBase,
        onTransferEvent,
      });
      return {
        ...result,
        attemptCount: attemptIndex + 1,
        retryCount: attemptIndex,
        resumeMetadataPathHash: transferBase.resumeMetadataPathHash,
        transfer: {
          ...transferBase,
          status: "completed",
          attemptCount: attemptIndex + 1,
          retryCount: attemptIndex,
          bytesCompleted: result.bytesCompleted,
          bytesTotal: result.bytesTotal,
          resumed: result.resumeOffset > 0,
        },
      };
    } catch (error) {
      lastError = error;
      const failureReason = downloadFailureReason(error);
      const canRetry = attemptIndex + 1 < maxAttempts && isRetriableDownloadFailure(failureReason);
      const transfer = {
        ...transferBase,
        status: canRetry ? "retry_pending" : "failed",
        attemptCount: attemptIndex + 1,
        retryCount: attemptIndex,
        failureReason,
        bytesCompleted: error?.downloadTransfer?.bytesCompleted ?? fileSizeIfExists(partialPath),
        bytesTotal: error?.downloadTransfer?.bytesTotal ?? 0,
        resumed: Boolean(error?.downloadTransfer?.resumeOffset),
      };
      writeDownloadResumeMetadata(metadataPath, transfer);
      error.downloadTransfer = transfer;
      if (!canRetry) break;
      onTransferEvent?.("model_download_retry", {
        attempt: attemptIndex + 1,
        nextAttempt: attemptIndex + 2,
        retryLimit: maxAttempts - 1,
        failureReason,
        bytesCompleted: transfer.bytesCompleted,
        bytesTotal: transfer.bytesTotal,
        partialPathHash: transferBase.partialPathHash,
        resumeMetadataPathHash: transferBase.resumeMetadataPathHash,
        resumeEnabled: resume,
      });
      if (!resume) fs.rmSync(partialPath, { force: true });
      await sleep(downloadRetryBackoffMs(attemptIndex));
    }
  }
  throw lastError;
}

async function materializeLiveDownloadAttempt({
  source,
  targetPath,
  partialPath,
  metadataPath,
  expectedChecksum,
  maxBytes,
  resume,
  bandwidthLimitBps,
  timeoutMs,
  headers = {},
  attemptIndex,
  maxAttempts,
  transferBase,
  onTransferEvent,
}) {
  const resumeOffset = resume && fs.existsSync(partialPath) ? fs.statSync(partialPath).size : 0;
  const requestHeaders = { ...headers, ...(resumeOffset > 0 ? { Range: `bytes=${resumeOffset}-` } : {}) };
  writeDownloadResumeMetadata(metadataPath, {
    ...transferBase,
    status: "running",
    attemptCount: attemptIndex + 1,
    retryLimit: maxAttempts - 1,
    resumeOffset,
    bytesCompleted: resumeOffset,
  });
  if (resumeOffset > 0) {
    onTransferEvent?.("model_download_resume", {
      attempt: attemptIndex + 1,
      retryLimit: maxAttempts - 1,
      resumeOffset,
      partialPathHash: transferBase.partialPathHash,
      resumeMetadataPathHash: transferBase.resumeMetadataPathHash,
    });
  }
  const response = await fetchWithTimeout(source, { timeoutMs, headers: requestHeaders });
  if (!response.ok) {
    throw new Error(`live_download_http_${response.status}`);
  }
  const contentLength = Number(response.headers.get("content-length") ?? 0) || 0;
  const bytesTotal = response.status === 206 ? resumeOffset + contentLength : contentLength || 0;
  if (maxBytes && bytesTotal && bytesTotal > maxBytes) {
    throw new Error("live_download_size_limit_exceeded");
  }
  const appending = resumeOffset > 0 && response.status === 206;
  if (!appending) fs.rmSync(partialPath, { force: true });
  const stream = fs.createWriteStream(partialPath, { flags: appending ? "a" : "w" });
  let bytesCompleted = appending ? resumeOffset : 0;
  let lastMetadataWrite = Date.now();
  const startedAt = Date.now();
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
      if (Date.now() - lastMetadataWrite > 250) {
        writeDownloadResumeMetadata(metadataPath, {
          ...transferBase,
          status: "running",
          attemptCount: attemptIndex + 1,
          retryLimit: maxAttempts - 1,
          resumeOffset,
          bytesCompleted,
          bytesTotal,
        });
        lastMetadataWrite = Date.now();
      }
      if (bandwidthLimitBps) {
        const elapsedMs = Math.max(1, Date.now() - startedAt);
        const expectedElapsedMs = ((bytesCompleted - resumeOffset) / bandwidthLimitBps) * 1000;
        if (expectedElapsedMs > elapsedMs) {
          await sleep(Math.min(250, expectedElapsedMs - elapsedMs));
        }
      }
    }
  } catch (error) {
    error.downloadTransfer = {
      ...transferBase,
      status: "attempt_failed",
      attemptCount: attemptIndex + 1,
      retryLimit: maxAttempts - 1,
      resumeOffset,
      bytesCompleted,
      bytesTotal,
    };
    throw error;
  } finally {
    await new Promise((resolve, reject) => stream.end((error) => (error ? reject(error) : resolve())));
  }
  fs.renameSync(partialPath, targetPath);
  const checksum = fileSha256(targetPath);
  if (expectedChecksum && checksum !== expectedChecksum) {
    fs.rmSync(targetPath, { force: true });
    throw new Error("live_download_checksum_mismatch");
  }
  fs.rmSync(metadataPath, { force: true });
  return {
    bytesTotal: bytesTotal || bytesCompleted,
    bytesCompleted,
    checksum,
    resumeOffset: appending ? resumeOffset : 0,
  };
}

function writeDownloadResumeMetadata(metadataPath, metadata) {
  const safeMetadata = {
    schemaVersion: MODEL_MOUNT_SCHEMA_VERSION,
    status: metadata.status,
    sourceHash: metadata.sourceHash,
    partialPathHash: metadata.partialPathHash,
    targetPathHash: metadata.targetPathHash,
    resumeMetadataPathHash: metadata.resumeMetadataPathHash,
    attemptCount: metadata.attemptCount ?? null,
    retryCount: metadata.retryCount ?? null,
    retryLimit: metadata.retryLimit ?? null,
    resume: Boolean(metadata.resume),
    resumeOffset: metadata.resumeOffset ?? null,
    resumed: Boolean(metadata.resumed),
    bytesCompleted: metadata.bytesCompleted ?? 0,
    bytesTotal: metadata.bytesTotal ?? 0,
    bandwidthLimitBps: metadata.bandwidthLimitBps ?? null,
    failureReason: metadata.failureReason ?? null,
    updatedAt: new Date().toISOString(),
  };
  fs.mkdirSync(path.dirname(metadataPath), { recursive: true });
  writeJson(metadataPath, safeMetadata);
}

function isRetriableDownloadFailure(failureReason) {
  if (failureReason === "network_download_failed" || failureReason === "network_timeout") return true;
  const httpStatus = Number(String(failureReason).match(/^http_([0-9]+)$/)?.[1] ?? 0);
  return httpStatus === 408 || httpStatus === 409 || httpStatus === 425 || httpStatus === 429 || httpStatus >= 500;
}

function downloadRetryBackoffMs(attemptIndex) {
  const configured = Number(process.env.IOI_MODEL_DOWNLOAD_RETRY_BACKOFF_MS ?? 25);
  return Math.max(0, configured || 0) * Math.max(1, attemptIndex + 1);
}

function shouldRetainFailedDownloadPartial(downloadPolicy, failureReason) {
  if (!downloadPolicy?.resume) return false;
  return isRetriableDownloadFailure(failureReason);
}

function failedDownloadCleanupState(targetPath, { retainPartial } = {}) {
  if (!retainPartial) return cleanupPartialDownload(targetPath);
  if (fs.existsSync(targetPath)) {
    try {
      fs.rmSync(targetPath, { force: true });
    } catch {
      return "cleanup_failed";
    }
  }
  return fs.existsSync(`${targetPath}.part`) ? "retained_partial" : "not_needed";
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, Math.max(0, ms)));
}

function cleanupPartialDownload(targetPath) {
  let cleanupState = "not_needed";
  for (const filePath of [targetPath, `${targetPath}.part`, `${targetPath}.part.json`]) {
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
      "catalogAuth",
      "catalogAuthConfigured",
      "catalogAuthResolved",
      "catalogAuthScheme",
      "catalogAuthHeaderNameHash",
      "catalogAuthEvidenceRefs",
      "oauthBoundary",
      "resolvedMaterial",
      "runtimeBound",
      "materialBound",
      "materialSource",
      "materialConfigured",
      "materialPersistence",
      "materialVaultRefHash",
      "vaultMaterialSource",
      "runtimeMaterialStatus",
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
