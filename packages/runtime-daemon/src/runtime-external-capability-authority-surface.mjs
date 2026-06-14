import { runtimeError } from "./runtime-http-utils.mjs";
import { objectRecord } from "./runtime-value-helpers.mjs";

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
    return store.externalCapabilityAuthorityCore.authorizeExit(authorityRequest, {
      thread_id: threadId,
      agent_id: agent.id,
    });
  }

  return {
    authorizeExternalCapabilityExit,
    authorityRequestForRequest,
  };
}
