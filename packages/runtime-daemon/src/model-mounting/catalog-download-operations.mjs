import crypto from "node:crypto";

const RETIRED_CATALOG_IMPORT_URL_REQUEST_ALIASES = [
  "sourceUrl",
  "modelId",
  "providerId",
  "fileName",
  "fixtureContent",
  "transferApproved",
];

const CANONICAL_CATALOG_IMPORT_URL_REQUEST_FIELDS = [
  "source_url",
  "model_id",
  "provider_id",
  "file_name",
  "fixture_content",
  "transfer_approved",
];

const RETIRED_MODEL_DOWNLOAD_IDENTITY_REQUEST_ALIASES = [
  "modelId",
  "providerId",
  "sourceUrl",
  "sourceLabel",
  "catalogProviderId",
  "fileName",
  "fixtureContent",
];

const CANONICAL_MODEL_DOWNLOAD_IDENTITY_REQUEST_FIELDS = [
  "model_id",
  "provider_id",
  "source_url",
  "source_label",
  "catalog_provider_id",
  "file_name",
  "fixture_content",
];

const RETIRED_MODEL_DOWNLOAD_CONTROL_REQUEST_ALIASES = [
  "bytesTotal",
  "maxBytes",
  "simulateFailure",
  "failureReason",
  "queuedOnly",
  "expectedChecksum",
];

const CANONICAL_MODEL_DOWNLOAD_CONTROL_REQUEST_FIELDS = [
  "bytes_total",
  "max_bytes",
  "simulate_failure",
  "failure_reason",
  "queued_only",
  "expected_checksum",
];

const RETIRED_MODEL_DOWNLOAD_METADATA_REQUEST_ALIASES = [
  "displayName",
  "contextWindow",
  "privacyClass",
];

const CANONICAL_MODEL_DOWNLOAD_METADATA_REQUEST_FIELDS = [
  "display_name",
  "context_window",
  "privacy_class",
];

export async function catalogImportUrl(state, body = {}, deps = {}) {
  void state;
  assertCanonicalCatalogImportUrlRequestBody(body);
  const sourceUrl = (deps.requiredString ?? defaultRequiredString)(body.source_url ?? body.url, "source_url");
  throwCatalogDownloadRustCoreRequired(
    "model_mount.catalog.import_url",
    {
      source_url_hash: (deps.stableHash ?? defaultStableHash)(sourceUrl),
      ...(body.model_id ? { model_id: body.model_id } : {}),
      ...(body.provider_id ? { provider_id: body.provider_id } : {}),
    },
    deps,
  );
}

export async function downloadModel(state, body = {}, deps = {}) {
  void state;
  assertCanonicalModelDownloadIdentityRequestBody(body);
  assertCanonicalModelDownloadControlRequestBody(body);
  assertCanonicalModelDownloadMetadataRequestBody(body);
  const modelId = (deps.requiredString ?? defaultRequiredString)(body.model_id, "model_id");
  throwCatalogDownloadRustCoreRequired(
    "model_mount.download.queue",
    {
      model_id: modelId,
      ...(body.provider_id ? { provider_id: body.provider_id } : {}),
      ...(body.source_url ? { source_url_hash: (deps.stableHash ?? defaultStableHash)(body.source_url) } : {}),
    },
    deps,
  );
}

function throwCatalogDownloadRustCoreRequired(operation_kind, details = {}, deps = {}) {
  throw (deps.runtimeError ?? defaultRuntimeError)({
    status: 501,
    code: "model_mount_catalog_download_rust_core_required",
    message:
      "Catalog import and download mutation facades require Rust daemon-core model_mount catalog/download ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.catalog_download",
      evidence_refs: [
        "public_catalog_download_js_facade_retired",
        "rust_daemon_core_catalog_download_required",
      ],
      ...details,
    },
  });
}

function assertCanonicalCatalogImportUrlRequestBody(body = {}) {
  const retiredAliases = RETIRED_CATALOG_IMPORT_URL_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw requestAliasError({
    code: "model_catalog_import_url_request_aliases_retired",
    message: "Model catalog import URL request aliases are retired; use canonical snake_case request fields.",
    retiredAliases,
    canonicalFields: CANONICAL_CATALOG_IMPORT_URL_REQUEST_FIELDS,
  });
}

function assertCanonicalModelDownloadIdentityRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_DOWNLOAD_IDENTITY_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw requestAliasError({
    code: "model_download_identity_request_aliases_retired",
    message: "Model download identity request aliases are retired; use canonical snake_case request fields.",
    retiredAliases,
    canonicalFields: CANONICAL_MODEL_DOWNLOAD_IDENTITY_REQUEST_FIELDS,
  });
}

function assertCanonicalModelDownloadControlRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_DOWNLOAD_CONTROL_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw requestAliasError({
    code: "model_download_control_request_aliases_retired",
    message: "Model download control request aliases are retired; use canonical snake_case request fields.",
    retiredAliases,
    canonicalFields: CANONICAL_MODEL_DOWNLOAD_CONTROL_REQUEST_FIELDS,
  });
}

function assertCanonicalModelDownloadMetadataRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_DOWNLOAD_METADATA_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  throw requestAliasError({
    code: "model_download_metadata_request_aliases_retired",
    message: "Model download metadata request aliases are retired; use canonical snake_case request fields.",
    retiredAliases,
    canonicalFields: CANONICAL_MODEL_DOWNLOAD_METADATA_REQUEST_FIELDS,
  });
}

function requestAliasError({ code, message, retiredAliases, canonicalFields }) {
  const error = new Error(message);
  error.status = 400;
  error.code = code;
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: canonicalFields,
  };
  return error;
}

function defaultRuntimeError({ code, message, details, status }) {
  return Object.assign(new Error(message), { code, details, status });
}

function defaultRequiredString(value, field) {
  if (typeof value !== "string" || !value.trim()) {
    const error = new Error(`${field} required`);
    error.status = 400;
    error.code = `${field}_required`;
    error.details = { field };
    throw error;
  }
  return value;
}

function defaultStableHash(value) {
  return `sha256:${crypto.createHash("sha256").update(String(value)).digest("hex")}`;
}
