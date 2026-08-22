import crypto from "node:crypto";

export const U1_MINIMUM_PROVIDER_CAPACITY = Object.freeze({
  cpu_units: 8_000,
  memory_bytes: 16 * 1024 ** 3,
  ephemeral_storage_bytes: 20 * 1024 ** 3,
});

export const sha256Bytes = (bytes) => `sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`;

/** Convert one public Console provider response into the exact pre-spend decision. */
export function qualifyU1Provider(record, expectedAddress) {
  if (!/^akash1[02-9ac-hj-np-z]{38}$/u.test(String(expectedAddress || ""))) {
    throw new Error("expected provider address is invalid");
  }
  const failures = [];
  const require = (condition, code) => { if (!condition) failures.push(code); };
  require(record?.owner === expectedAddress, "provider_address_mismatch");
  require(record?.isOnline === true, "provider_offline");
  require(record?.isAudited === true, "provider_not_audited");
  require(record?.isValidVersion === true, "provider_version_invalid");
  require(record?.hardwareCpuArch === "x86-64", "provider_cpu_architecture_mismatch");
  require(Number(record?.stats?.cpu?.available) >= U1_MINIMUM_PROVIDER_CAPACITY.cpu_units, "provider_cpu_capacity_insufficient");
  require(Number(record?.stats?.memory?.available) >= U1_MINIMUM_PROVIDER_CAPACITY.memory_bytes, "provider_memory_capacity_insufficient");
  require(Number(record?.stats?.storage?.ephemeral?.available) >= U1_MINIMUM_PROVIDER_CAPACITY.ephemeral_storage_bytes, "provider_storage_capacity_insufficient");
  require(Number(record?.uptime1d) >= 0.99, "provider_one_day_uptime_below_floor");
  require(Number(record?.uptime7d) >= 0.99, "provider_seven_day_uptime_below_floor");

  return {
    provider_address: expectedAddress,
    provider_name: record?.name ?? null,
    provider_host_uri: record?.hostUri ?? null,
    provider_last_checked_at: record?.lastCheckDate ?? null,
    qualified: failures.length === 0,
    refusal_codes: failures,
    observed: {
      online: record?.isOnline === true,
      audited: record?.isAudited === true,
      valid_version: record?.isValidVersion === true,
      cpu_architecture: record?.hardwareCpuArch ?? null,
      cpu_units_available: Number(record?.stats?.cpu?.available ?? 0),
      memory_bytes_available: Number(record?.stats?.memory?.available ?? 0),
      ephemeral_storage_bytes_available: Number(record?.stats?.storage?.ephemeral?.available ?? 0),
      uptime_1d: Number(record?.uptime1d ?? 0),
      uptime_7d: Number(record?.uptime7d ?? 0),
    },
    required: U1_MINIMUM_PROVIDER_CAPACITY,
    placement_class: "same_exact_audited_provider_container_allocation_physical_host_unproven",
    bare_metal_attested: false,
  };
}
