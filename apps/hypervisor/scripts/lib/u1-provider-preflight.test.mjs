import assert from "node:assert/strict";
import test from "node:test";
import { qualifyU1Provider, U1_MINIMUM_PROVIDER_CAPACITY } from "./u1-provider-preflight.mjs";

const address = "akash1ggfvyhr9sar4uxjs4hth3p4kzrwk7lysnenj3g";
const valid = {
  owner: address,
  name: "provider.cpu.phl.aes.akash.pub",
  hostUri: "https://provider.cpu.phl.aes.akash.pub:8443",
  isOnline: true,
  isAudited: true,
  isValidVersion: true,
  hardwareCpuArch: "x86-64",
  lastCheckDate: "2026-08-22T18:38:26.000Z",
  uptime1d: 1,
  uptime7d: 1,
  stats: {
    cpu: { available: U1_MINIMUM_PROVIDER_CAPACITY.cpu_units },
    memory: { available: U1_MINIMUM_PROVIDER_CAPACITY.memory_bytes },
    storage: { ephemeral: { available: U1_MINIMUM_PROVIDER_CAPACITY.ephemeral_storage_bytes } },
  },
};

test("qualifies only the exact provider at every adopted floor", () => {
  const decision = qualifyU1Provider(valid, address);
  assert.equal(decision.qualified, true);
  assert.deepEqual(decision.refusal_codes, []);
  assert.equal(decision.bare_metal_attested, false);
});

test("reports every failed floor without silently selecting a fallback", () => {
  const changed = structuredClone(valid);
  changed.owner = "akash1aaul837r7en7hpk9wv2svg8u78fdq0t2j2e82z";
  changed.isOnline = false;
  changed.isAudited = false;
  changed.isValidVersion = false;
  changed.hardwareCpuArch = "arm64";
  changed.uptime1d = 0.5;
  changed.uptime7d = 0.5;
  changed.stats.cpu.available -= 1;
  changed.stats.memory.available -= 1;
  changed.stats.storage.ephemeral.available -= 1;
  const decision = qualifyU1Provider(changed, address);
  assert.equal(decision.qualified, false);
  assert.equal(decision.refusal_codes.length, 10);
  assert.ok(decision.refusal_codes.includes("provider_address_mismatch"));
  assert.ok(decision.refusal_codes.includes("provider_storage_capacity_insufficient"));
});
