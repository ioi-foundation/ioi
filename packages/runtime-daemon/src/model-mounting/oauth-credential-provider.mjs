import { normalizeScopes, stableHash } from "./io.mjs";

export class OAuthCredentialProvider {
  constructor({ now, vault } = {}) {
    this.now = now;
    this.vault = vault;
  }

  startAuthorization({ providerId, body = {} } = {}) {
    throwOAuthCredentialProviderRustCoreRequired("model_mount.catalog_provider_oauth.start_authorization", {
      provider_id: providerId ?? null,
      request_field_count: Object.keys(body ?? {}).length,
    });
  }

  async completeAuthorization({ providerId, stateRecord = null, body = {} } = {}) {
    throwOAuthCredentialProviderRustCoreRequired("model_mount.catalog_provider_oauth.complete_authorization", {
      provider_id: providerId ?? null,
      oauth_state_hash: stateRecord?.id ? stableHash(stateRecord.id) : null,
      request_field_count: Object.keys(body ?? {}).length,
    });
  }

  async exchangeAuthorizationCode({ providerId, body = {} } = {}) {
    throwOAuthCredentialProviderRustCoreRequired("model_mount.catalog_provider_oauth.exchange_authorization_code", {
      provider_id: providerId ?? null,
      request_field_count: Object.keys(body ?? {}).length,
    });
  }

  async refreshAccessToken(session = null) {
    throwOAuthCredentialProviderRustCoreRequired("model_mount.catalog_provider_oauth.refresh_access_token", {
      provider_id: session?.providerId ?? null,
      oauth_session_hash: session?.id ? stableHash(session.id) : null,
      status: session?.status ?? "missing",
    });
  }

  revokeSession(session = null) {
    throwOAuthCredentialProviderRustCoreRequired("model_mount.catalog_provider_oauth.revoke_session", {
      provider_id: session?.providerId ?? null,
      oauth_session_hash: session?.id ? stableHash(session.id) : null,
      status: session?.status ?? "missing",
    });
  }

  async resolveAccessHeader(session = null, { headerName = "authorization" } = {}) {
    throwOAuthCredentialProviderRustCoreRequired("model_mount.catalog_provider_oauth.resolve_access_header", {
      provider_id: session?.providerId ?? null,
      oauth_session_hash: session?.id ? stableHash(session.id) : null,
      catalog_auth_scheme: "oauth2",
      catalog_auth_header_name_hash: stableHash(headerName),
      status: session?.status ?? "missing",
    });
  }
}

export function throwOAuthCredentialProviderRustCoreRequired(operation_kind, details = {}) {
  const error = new Error(
    "OAuth credential provider custody is retired in JS; use Rust daemon-core wallet/cTEE custody.",
  );
  error.status = 501;
  error.code = "model_mount_oauth_credential_provider_js_retired";
  error.details = {
    operation_kind,
    rust_core_boundary: "model_mount.catalog_provider_oauth_custody",
    evidence_refs: normalizeScopes(
      [
        "oauth_credential_provider_js_retired",
        "rust_daemon_core_catalog_provider_oauth_required",
        "rust_daemon_core_wallet_ctee_custody_required",
      ],
      [],
    ),
    ...details,
  };
  throw error;
}
