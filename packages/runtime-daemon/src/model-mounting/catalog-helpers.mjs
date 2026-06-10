import {
  runtimeError,
} from "./io.mjs";

const RETIRED_DESTRUCTIVE_CONFIRMATION_REQUEST_ALIASES = [
  "confirmDestructive",
  "destructiveConfirmed",
  "destructive_confirmed",
];

const CANONICAL_DESTRUCTIVE_CONFIRMATION_REQUEST_FIELDS = [
  "confirm_destructive",
];

export function destructiveConfirmationState(body = {}, { required = true, action = "destructive_action" } = {}) {
  assertCanonicalDestructiveConfirmationRequestBody(body);
  const confirmed = Boolean(body.confirm_destructive ?? false);
  return {
    required,
    confirmed: required ? confirmed : true,
    action,
    source: confirmed ? "operator_confirmation" : required ? "not_provided" : "not_required",
  };
}

function assertCanonicalDestructiveConfirmationRequestBody(body = {}) {
  const retiredAliases = RETIRED_DESTRUCTIVE_CONFIRMATION_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw runtimeError({
    status: 400,
    code: "destructive_confirmation_request_aliases_retired",
    message: "Destructive confirmation request aliases are retired; use canonical snake_case request fields.",
    details: {
      retired_aliases: retiredAliases,
      canonical_fields: CANONICAL_DESTRUCTIVE_CONFIRMATION_REQUEST_FIELDS,
    },
  });
}
