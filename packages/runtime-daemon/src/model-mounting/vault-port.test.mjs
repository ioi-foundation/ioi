import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";

import {
  AgentgresVaultPort,
  EncryptedKeychainVaultMaterialAdapter,
  configuredVaultMaterialAdapter,
  vaultRefEnvironmentAlias,
} from "./vault-port.mjs";

const FIXED_NOW = new Date("2026-06-03T00:00:00.000Z");

function now() {
  return new Date(FIXED_NOW.getTime());
}

test("encrypted keychain vault adapter persists material without plaintext", () => {
  const dir = mkdtempSync(join(tmpdir(), "ioi-vault-port-keychain-"));
  const filePath = join(dir, "vault-material.json");
  const adapter = new EncryptedKeychainVaultMaterialAdapter({
    filePath,
    keyMaterial: "test key material",
    now,
  });
  try {
    const bind = adapter.bind("vault://provider/custom/api-key", "super-secret-material", {
      purpose: "provider.auth:test",
      label: "Custom provider auth",
    });
    assert.equal(bind.materialSource, "encrypted_keychain_vault_adapter");

    const disk = readFileSync(filePath, "utf8");
    assert.equal(disk.includes("super-secret-material"), false);

    const resolved = adapter.resolve("vault://provider/custom/api-key");
    assert.equal(resolved.material, "super-secret-material");
    assert.equal(resolved.materialSource, "encrypted_keychain_vault_adapter");

    const removed = adapter.remove("vault://provider/custom/api-key");
    assert.equal(removed.removed, true);
    assert.equal(adapter.resolve("vault://provider/custom/api-key").material, null);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("configured vault material adapter fails closed when only partial env is present", () => {
  const priorPath = process.env.IOI_KEYCHAIN_VAULT_PATH;
  const priorKey = process.env.IOI_KEYCHAIN_VAULT_KEY;
  try {
    process.env.IOI_KEYCHAIN_VAULT_PATH = "/tmp/ioi-keychain-vault-test.json";
    delete process.env.IOI_KEYCHAIN_VAULT_KEY;

    const adapter = configuredVaultMaterialAdapter({ now });
    assert.equal(adapter.configured, false);
    assert.equal(adapter.requested, true);
    assert.equal(adapter.status().failClosed, true);
    assert.throws(() => adapter.health(), /Vault material adapter is configured but unavailable/);
  } finally {
    if (priorPath === undefined) delete process.env.IOI_KEYCHAIN_VAULT_PATH;
    else process.env.IOI_KEYCHAIN_VAULT_PATH = priorPath;
    if (priorKey === undefined) delete process.env.IOI_KEYCHAIN_VAULT_KEY;
    else process.env.IOI_KEYCHAIN_VAULT_KEY = priorKey;
  }
});

test("vault port resolves environment aliases and keeps metadata public", () => {
  const priorOpenAi = process.env.OPENAI_API_KEY;
  try {
    process.env.OPENAI_API_KEY = "openai-env-secret";
    assert.equal(vaultRefEnvironmentAlias("vault://provider.openai/api-key"), "OPENAI_API_KEY");

    const operations = [];
    const vault = new AgentgresVaultPort({
      now,
      appendOperation(kind, payload) {
        operations.push({ kind, payload });
      },
    });
    const resolved = vault.resolveVaultRef("vault://provider.openai/api-key", "provider.auth:provider.openai");
    assert.equal(resolved.material, "openai-env-secret");
    assert.equal(resolved.materialSource, "environment_alias");
    assert.equal(JSON.stringify(resolved).includes("vault://provider.openai/api-key"), false);

    const audit = operations.find((operation) => operation.kind === "vault.vault.resolve");
    assert.match(audit.payload.objectId, /^vault_ref_[a-f0-9]+$/);
    assert.equal(JSON.stringify(audit).includes("openai-env-secret"), false);
  } finally {
    if (priorOpenAi === undefined) delete process.env.OPENAI_API_KEY;
    else process.env.OPENAI_API_KEY = priorOpenAi;
  }
});

test("vault port binds, lists, removes, and serializes redacted metadata", () => {
  const operations = [];
  const vault = new AgentgresVaultPort({
    now,
    appendOperation(kind, payload) {
      operations.push({ kind, payload });
    },
  });
  const vaultRef = "vault://provider/custom/api-key";
  const bound = vault.bindVaultRef({
    vaultRef,
    material: "custom-secret",
    purpose: "provider.auth:custom",
    label: "Custom auth",
  });
  assert.equal(bound.configured, true);
  assert.equal(bound.vaultRef.redacted, true);
  assert.equal(JSON.stringify(bound).includes(vaultRef), false);
  assert.equal(JSON.stringify(vault.listVaultRefs()).includes("custom-secret"), false);

  const metadata = vault.metadataRecords()[0];
  assert.equal(metadata.materialSource, "runtime_memory_not_persisted");
  assert.equal(metadata.resolvedMaterial, false);
  assert.equal(JSON.stringify(metadata).includes(vaultRef), false);

  const removed = vault.removeVaultRef(vaultRef);
  assert.equal(removed.configured, false);
  assert.equal(vault.resolveVaultRef(vaultRef, "provider.auth:custom").resolvedMaterial, false);
  assert.equal(JSON.stringify(operations).includes("custom-secret"), false);
  assert.equal(JSON.stringify(operations).includes(vaultRef), false);
});
