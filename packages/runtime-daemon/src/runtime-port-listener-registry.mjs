import { optionalString, safeId } from "./runtime-value-helpers.mjs";
import { buildEnvironmentPort } from "./runtime-environment-status-projection.mjs";

export const PORT_REGISTRY_SCHEMA_VERSION =
  "ioi.hypervisor.environment_port_registry.v1";

/**
 * Per-session registry of HypervisorEnvironmentPorts. A port surfaced by a
 * session (e.g. a preview server the harness started) is closed until a wallet
 * capability lease authorizes its exposure — port exposure is capability-gated,
 * never owner-token shared. The registry holds projection state only; wallet
 * authority and Agentgres truth live elsewhere.
 */
export function createPortListenerRegistry() {
  const bySession = new Map();

  function register(sessionRef, descriptor = {}) {
    const key = optionalString(sessionRef) ?? "session";
    const port = Number(descriptor.port);
    const capabilityLeaseRef = optionalString(descriptor.capability_lease_ref);
    // Exposure is gated on a wallet capability lease. No lease -> lease_required
    // (closed to clients) regardless of what the process is listening on.
    const exposureState = capabilityLeaseRef
      ? (optionalString(descriptor.exposure_state) ?? "open")
      : "lease_required";
    const entry = buildEnvironmentPort({
      port: Number.isFinite(port) ? port : null,
      protocol: descriptor.protocol,
      accessPolicy: descriptor.access_policy ?? "session_lease",
      capabilityLeaseRef,
      url: descriptor.url,
      exposureState,
    });
    const list = bySession.get(key) ?? [];
    // De-dupe by port number.
    const next = list.filter((existing) => existing.port !== entry.port);
    next.push(entry);
    bySession.set(key, next);
    return entry;
  }

  // Grant a wallet capability lease to a registered port, opening its exposure.
  function grantLease(sessionRef, port, capabilityLeaseRef, url) {
    const key = optionalString(sessionRef) ?? "session";
    const list = bySession.get(key) ?? [];
    const lease = optionalString(capabilityLeaseRef);
    const next = list.map((entry) =>
      entry.port === Number(port)
        ? {
            ...entry,
            capability_lease_ref: lease,
            url: optionalString(url) ?? entry.url,
            exposure_state: lease ? "open" : entry.exposure_state,
          }
        : entry,
    );
    bySession.set(key, next);
    return next.find((entry) => entry.port === Number(port)) ?? null;
  }

  function list(sessionRef) {
    return [...(bySession.get(optionalString(sessionRef) ?? "session") ?? [])];
  }

  function clear(sessionRef) {
    bySession.delete(optionalString(sessionRef) ?? "session");
  }

  return {
    schema_version: PORT_REGISTRY_SCHEMA_VERSION,
    register,
    grantLease,
    list,
    clear,
    registry_ref: `environment-port-registry:${safeId("session-default")}`,
  };
}
