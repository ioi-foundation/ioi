import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord, optionalString } from "./runtime-value-helpers.mjs";

export const EXTERNAL_CAPABILITY_AUTHORITY_RESPONSE_SCHEMA_VERSION =
  "ioi.runtime.external_capability_authority.v1";

const RETIRED_EXTERNAL_CAPABILITY_AUTHORITY_REQUEST_ALIASES = [
  "authorityRequest",
  "authority_request",
  "capabilityExit",
  "capability_exit",
];

const CANONICAL_EXTERNAL_CAPABILITY_AUTHORITY_REQUEST_FIELDS = [
  "request",
];

export function createRuntimeExternalCapabilityAuthoritySurface(deps = {}) {
  const {
    runtimeError: runtimeErrorDep = runtimeError,
  } = deps;

  function authorityRequestForRequest(request = {}) {
    const body = objectRecord(request) ?? {};
    assertCanonicalExternalCapabilityAuthorityRequestBody(body);
    const nested = objectRecord(body.request) ?? {};
    const authorityRequest = Object.keys(nested).length > 0 ? nested : body;
    if (Object.keys(authorityRequest).length === 0) {
      throw runtimeErrorDep({
        status: 400,
        code: "external_capability_authority_request_required",
        message: "External capability exit authority requires a request payload.",
      });
    }
    return authorityRequest;
  }

  function assertCanonicalExternalCapabilityAuthorityRequestBody(body = {}) {
    const retiredAliases = RETIRED_EXTERNAL_CAPABILITY_AUTHORITY_REQUEST_ALIASES.filter((field) =>
      Object.hasOwn(body, field),
    );
    if (retiredAliases.length === 0) return;
    throw runtimeErrorDep({
      status: 400,
      code: "external_capability_authority_request_aliases_retired",
      message: "External capability authority request aliases are retired; use request.",
      details: {
        retired_aliases: retiredAliases,
        canonical_fields: CANONICAL_EXTERNAL_CAPABILITY_AUTHORITY_REQUEST_FIELDS,
      },
    });
  }

  function authorizeExternalCapabilityExit(store, threadId, request = {}) {
    const authorityRequest = authorityRequestForRequest(request);
    const agent = store.agentForThread(threadId);
    const authorization = store.externalCapabilityAuthorityRunner.authorizeExit(authorityRequest);
    const authority = objectRecord(authorization.authority) ?? {};
    return {
      schema_version: EXTERNAL_CAPABILITY_AUTHORITY_RESPONSE_SCHEMA_VERSION,
      object: "ioi.runtime_external_capability_authority",
      status: "authorized",
      exit_authorized: true,
      direct_truth_write_allowed: false,
      thread_id: threadId,
      agent_id: agent.id,
      exit_ref:
        authorization.exit_ref ?? authority.exit_ref ?? optionalString(authorityRequest.exit_ref),
      capability_ref:
        authorization.capability_ref ??
        authority.capability_ref ??
        optionalString(authorityRequest.capability_ref),
      target_ref:
        authorization.target_ref ?? authority.target_ref ?? optionalString(authorityRequest.target_ref),
      policy_hash:
        authorization.policy_hash ?? authority.policy_hash ?? optionalString(authorityRequest.policy_hash),
      idempotency_key:
        authorization.idempotency_key ??
        authority.idempotency_key ??
        optionalString(authorityRequest.idempotency_key),
      wallet_network_grant_refs:
        authorization.wallet_network_grant_refs ?? authority.wallet_network_grant_refs ?? [],
      authority_receipt_refs:
        authorization.authority_receipt_refs ?? authority.authority_receipt_refs ?? [],
      authority_hash: authorization.authority_hash ?? authority.authority_hash ?? null,
      authorization,
      authority,
    };
  }

  return {
    authorizeExternalCapabilityExit,
    authorityRequestForRequest,
  };
}
