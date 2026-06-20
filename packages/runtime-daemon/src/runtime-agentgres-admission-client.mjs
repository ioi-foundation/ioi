import { createHash } from "node:crypto";

import { runtimeError } from "./runtime-http-utils.mjs";
import {
  normalizeArray,
  objectRecord,
  optionalString,
  safeId,
  uniqueStrings,
} from "./runtime-value-helpers.mjs";

export const AGENTGRES_ADMITTED_OPERATION_SCHEMA_VERSION =
  "ioi.agentgres.admitted_operation.v1";

// Consequential operation kinds and the wallet capability scope each requires.
// Authority is wallet.network's: an operation without its lease is blocked
// (step-up), never silently admitted. Agentgres records the admitted truth.
export const OPERATION_REQUIRED_SCOPE = Object.freeze({
  workspace_write: "scope:workspace.patch",
  command_exec: "scope:workspace.exec",
  port_expose: "scope:network.expose",
  model_invoke: "scope:model.invoke",
  secret_release: "scope:wallet.secret",
});

function hashPayload(payload) {
  return createHash("sha256")
    .update(typeof payload === "string" ? payload : JSON.stringify(payload ?? {}))
    .digest("hex");
}

/**
 * Decide whether a consequential operation is authorized by the wallet
 * capability leases carried on the admitted launch/spawn (authority_scope_refs).
 * Returns an authorization verdict; a missing scope blocks with step_up_required
 * rather than letting the operation proceed.
 */
export function requireCapabilityLease({
  operationKind,
  authorityScopeRefs,
  requiredScope,
} = {}) {
  const kind = optionalString(operationKind) ?? "unknown";
  const required =
    optionalString(requiredScope) ?? OPERATION_REQUIRED_SCOPE[kind] ?? null;
  const scopes = uniqueStrings(normalizeArray(authorityScopeRefs));
  if (!required) {
    // No scope requirement for this kind: authorized but recorded as ungated.
    return { authorized: true, operation_kind: kind, required_scope: null, gated: false };
  }
  const authorized = scopes.includes(required);
  return {
    authorized,
    operation_kind: kind,
    required_scope: required,
    gated: true,
    missing_scope: authorized ? null : required,
    step_up_required: !authorized,
    available_scope_refs: scopes,
  };
}

export function assertCapabilityLease(input) {
  const verdict = requireCapabilityLease(input);
  if (!verdict.authorized) {
    throw runtimeError({
      status: 403,
      code: "harness_operation_capability_lease_required",
      message: `Operation ${verdict.operation_kind} requires wallet capability ${verdict.required_scope}.`,
      details: {
        operation_kind: verdict.operation_kind,
        required_scope: verdict.required_scope,
        step_up_required: true,
      },
    });
  }
  return verdict;
}

/**
 * Create an Agentgres admission client. admitOperation records a consequential
 * operation as admitted truth — an admitted operation object with stable
 * operation/receipt/state-root refs derived from the payload — after the wallet
 * capability lease is verified. deps.admit can inject a real Agentgres backend;
 * the default is a deterministic local admission (no faked remote call).
 */
export function createAgentgresAdmissionClient(deps = {}) {
  const nowIso = deps.nowIso ?? (() => new Date().toISOString());
  const admitImpl = typeof deps.admit === "function" ? deps.admit : null;

  async function admitOperation(descriptor = {}) {
    const operationKind = optionalString(descriptor.operation_kind) ?? "unknown";
    const sessionRef = optionalString(descriptor.session_ref) ?? "session";
    const authorityScopeRefs = uniqueStrings(
      normalizeArray(descriptor.authority_scope_refs),
    );
    // Authority gate first: never admit an operation the wallet did not lease.
    const verdict = assertCapabilityLease({
      operationKind,
      authorityScopeRefs,
      requiredScope: descriptor.required_scope,
    });

    const payloadHash = hashPayload(descriptor.payload);
    const ref = `${safeId(sessionRef)}/${operationKind}/${payloadHash.slice(0, 16)}`;
    const admitted = {
      schema_version: AGENTGRES_ADMITTED_OPERATION_SCHEMA_VERSION,
      operation_ref: `agentgres://operation/${ref}`,
      operation_kind: operationKind,
      session_ref: sessionRef,
      payload_hash: payloadHash,
      authority_scope_refs: authorityScopeRefs,
      capability_verdict: verdict,
      receipt_ref: `receipt://agentgres/${ref}`,
      state_root: `agentgres://state-root/${ref}`,
      admitted_at: nowIso(),
      decision: "admitted",
      runtimeTruthSource: "daemon-runtime",
    };
    if (admitImpl) {
      // Let a real Agentgres backend stamp/override the admitted record.
      const remote = objectRecord(await admitImpl(admitted));
      return remote ? { ...admitted, ...remote } : admitted;
    }
    return admitted;
  }

  return { admitOperation, requireCapabilityLease, assertCapabilityLease };
}
