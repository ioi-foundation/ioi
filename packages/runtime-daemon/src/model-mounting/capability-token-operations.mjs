import {
  hashToken,
  notFound,
  publicToken,
  runtimeError,
} from "./io.mjs";

export function createToken(state, body = {}, deps = {}) {
  void state;
  throwCapabilityTokenRustCoreRequired(
    "model_mount.capability_token.create",
    {
      ...(body.audience ? { audience: body.audience } : {}),
      ...(body.grant_id ? { grant_id: body.grant_id } : {}),
    },
    deps,
  );
}

export function listTokens(state, deps = {}) {
  const { publicToken: publicTokenDep = publicToken } = deps;
  return [...state.tokens.values()]
    .map(publicTokenDep)
    .sort((left, right) => left.createdAt.localeCompare(right.createdAt));
}

export function revokeToken(state, tokenId, deps = {}) {
  const { notFound: notFoundDep = notFound } = deps;
  if (!state.tokens.has(tokenId)) throw notFoundDep(`Token not found: ${tokenId}`, { token_id: tokenId });
  throwCapabilityTokenRustCoreRequired(
    "model_mount.capability_token.revoke",
    { token_id: tokenId },
    deps,
  );
}

export function authorize(state, authorization, requiredScope, deps = {}) {
  const {
    hashToken: hashTokenDep = hashToken,
    runtimeError: runtimeErrorDep = runtimeError,
  } = deps;
  if (!authorization || !authorization.startsWith("Bearer ")) {
    throw runtimeErrorDep({
      status: 401,
      code: "auth",
      message: "Bearer capability token is required for this model mounting operation.",
      details: { required_scope: requiredScope },
    });
  }
  const tokenHash = hashTokenDep(authorization.slice("Bearer ".length).trim());
  const token = [...state.tokens.values()].find((candidate) => candidate.tokenHash === tokenHash);
  if (!token) {
    throw runtimeErrorDep({
      status: 401,
      code: "auth",
      message: "Capability token was not recognized.",
      details: { required_scope: requiredScope },
    });
  }
  throwCapabilityTokenRustCoreRequired(
    "model_mount.capability_token.authorize",
    {
      token_id: token.id,
      grant_id: token.grantId ?? null,
      required_scope: requiredScope,
    },
    deps,
  );
}

function throwCapabilityTokenRustCoreRequired(operation_kind, details = {}, deps = {}) {
  throw (deps.runtimeError ?? defaultRuntimeError)({
    status: 501,
    code: "model_mount_capability_token_rust_core_required",
    message:
      "Capability token mutation and authorization facades require Rust daemon-core wallet authority ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.capability_token",
      evidence_refs: [
        "public_capability_token_js_facade_retired",
        "rust_daemon_core_wallet_authority_required",
      ],
      ...details,
    },
  });
}

function defaultRuntimeError({ code, message, details, status }) {
  return Object.assign(new Error(message), { code, details, status });
}
