import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

import {
  emitRemoteBoundaryEvent,
  normalizeScopes,
  publicVaultRefMetadata,
  readJson,
  redact,
  runtimeError,
  stableHash,
  writeJson,
} from "./io.mjs";

const SECRET_REDACTION = "[REDACTED]";

export class EncryptedKeychainVaultMaterialAdapter {
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

export class AgentgresVaultPort {
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
    emitRemoteBoundaryEvent(process.env.IOI_WALLET_NETWORK_URL, "/audit", {
      port: "VaultPort",
      kind,
      ...safePayload,
    });
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

export function configuredVaultMaterialAdapter({ now }) {
  if (process.env.IOI_KEYCHAIN_VAULT_PATH || process.env.IOI_KEYCHAIN_VAULT_KEY) {
    return new EncryptedKeychainVaultMaterialAdapter({
      filePath: process.env.IOI_KEYCHAIN_VAULT_PATH,
      keyMaterial: process.env.IOI_KEYCHAIN_VAULT_KEY,
      now,
    });
  }
  return null;
}

export function vaultRefEnvironmentAlias(vaultRef) {
  const aliases = new Map([
    ["vault://provider.openai/api-key", "OPENAI_API_KEY"],
    ["vault://provider.anthropic/api-key", "ANTHROPIC_API_KEY"],
    ["vault://provider.gemini/api-key", "GEMINI_API_KEY"],
    ["vault://provider.custom-http/api-key", "IOI_CUSTOM_MODEL_API_KEY"],
  ]);
  return aliases.get(vaultRef) ?? null;
}
