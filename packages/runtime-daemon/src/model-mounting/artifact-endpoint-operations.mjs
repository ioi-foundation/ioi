const RETIRED_MODEL_IMPORT_REQUEST_ALIASES = [
  "modelId",
  "sourcePath",
  "localPath",
  "importMode",
  "providerId",
  "displayName",
  "sizeBytes",
  "contextWindow",
  "privacyClass",
];

const CANONICAL_MODEL_IMPORT_REQUEST_FIELDS = [
  "model_id",
  "source_path",
  "local_path",
  "import_mode",
  "provider_id",
  "display_name",
  "size_bytes",
  "context_window",
  "privacy_class",
];

const RETIRED_ENDPOINT_MOUNT_REQUEST_ALIASES = [
  "modelId",
  "providerId",
  "apiFormat",
  "baseUrl",
  "privacyClass",
  "backendId",
  "loadPolicy",
];

const CANONICAL_ENDPOINT_MOUNT_REQUEST_FIELDS = [
  "model_id",
  "provider_id",
  "api_format",
  "base_url",
  "privacy_class",
  "backend_id",
  "load_policy",
];

const RETIRED_ENDPOINT_UNMOUNT_REQUEST_ALIASES = ["endpointId"];
const CANONICAL_ENDPOINT_UNMOUNT_REQUEST_FIELDS = ["endpoint_id"];

export function importModel(state, body = {}, deps = {}) {
  void state;
  assertCanonicalModelImportRequestBody(body);
  const { requiredString } = deps;
  const modelId = requiredString(body.model_id, "model_id");
  throwArtifactEndpointRustCoreRequired("model_mount.artifact.import", { model_id: modelId }, deps);
}

export function mountEndpoint(state, body = {}, deps = {}) {
  void state;
  assertCanonicalEndpointMountRequestBody(body);
  const modelId = body.model_id;
  if (!modelId) {
    throw (deps.runtimeError ?? defaultRuntimeError)({
      status: 400,
      code: "model_id_required",
      message: "Mounting a model endpoint requires an explicit model id.",
    });
  }
  throwArtifactEndpointRustCoreRequired("model_mount.endpoint.mount", { model_id: modelId }, deps);
}

export function unmountEndpoint(state, body = {}, deps = {}) {
  void state;
  const { requiredString } = deps;
  assertCanonicalEndpointUnmountRequestBody(body);
  const endpointId = requiredString(body.endpoint_id ?? body.id, "endpoint_id");
  throwArtifactEndpointRustCoreRequired("model_mount.endpoint.unmount", { endpoint_id: endpointId }, deps);
}

function throwArtifactEndpointRustCoreRequired(operation_kind, details = {}, deps = {}) {
  throw (deps.runtimeError ?? defaultRuntimeError)({
    status: 501,
    code: "model_mount_artifact_endpoint_rust_core_required",
    message:
      "Artifact and endpoint mutation facades require Rust daemon-core model_mount artifact/endpoint ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.artifact_endpoint",
      evidence_refs: [
        "public_artifact_endpoint_js_facade_retired",
        "rust_daemon_core_artifact_endpoint_required",
      ],
      ...details,
    },
  });
}

function defaultRuntimeError({ code, message, details, status }) {
  return Object.assign(new Error(message), { code, details, status });
}

function assertCanonicalModelImportRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_IMPORT_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model import request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_import_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_MODEL_IMPORT_REQUEST_FIELDS,
  };
  throw error;
}

function assertCanonicalEndpointMountRequestBody(body = {}) {
  const retiredAliases = RETIRED_ENDPOINT_MOUNT_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model endpoint mount request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_mount_endpoint_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_ENDPOINT_MOUNT_REQUEST_FIELDS,
  };
  throw error;
}

function assertCanonicalEndpointUnmountRequestBody(body = {}) {
  const retiredAliases = RETIRED_ENDPOINT_UNMOUNT_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model endpoint unmount request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_unmount_endpoint_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_ENDPOINT_UNMOUNT_REQUEST_FIELDS,
  };
  throw error;
}
