const RETIRED_MODEL_STORAGE_REQUEST_ALIASES = [
  "cleanupPartial",
  "dryRun",
  "removeOrphans",
];

const CANONICAL_MODEL_STORAGE_REQUEST_FIELDS = [
  "cleanup_partial",
  "dry_run",
  "remove_orphans",
];

export function cancelDownload(state, jobId, body = {}, deps = {}) {
  void state;
  assertCanonicalModelStorageRequestBody(body);
  throwStorageRustCoreRequired("model_mount.download.cancel", { job_id: jobId }, deps);
}

export function downloadStatus(state, jobId, deps = {}) {
  const { notFound } = deps;
  const job = state.downloads.get(jobId);
  if (!job) throw notFound(`Download job not found: ${jobId}`, { job_id: jobId });
  return job;
}

export function deleteModelArtifact(state, id, body = {}, deps = {}) {
  void state;
  assertCanonicalModelStorageRequestBody(body);
  throwStorageRustCoreRequired("model_mount.artifact.delete", { artifact_id: id }, deps);
}

export function cleanupModelStorage(state, body = {}, deps = {}) {
  void state;
  assertCanonicalModelStorageRequestBody(body);
  throwStorageRustCoreRequired("model_mount.storage.cleanup", {}, deps);
}

function throwStorageRustCoreRequired(operation_kind, details = {}, deps = {}) {
  throw (deps.runtimeError ?? defaultRuntimeError)({
    status: 501,
    code: "model_mount_storage_rust_core_required",
    message:
      "Model storage mutation facades require Rust daemon-core model_mount storage ownership.",
    details: {
      operation_kind,
      rust_core_boundary: "model_mount.storage",
      evidence_refs: [
        "public_model_storage_js_facade_retired",
        "rust_daemon_core_model_storage_required",
      ],
      ...details,
    },
  });
}

function defaultRuntimeError({ code, message, details, status }) {
  return Object.assign(new Error(message), { code, details, status });
}

function assertCanonicalModelStorageRequestBody(body = {}) {
  const retiredAliases = RETIRED_MODEL_STORAGE_REQUEST_ALIASES.filter((field) =>
    Object.hasOwn(body, field),
  );
  if (retiredAliases.length === 0) return;
  const error = new Error(
    "Model storage request aliases are retired; use canonical snake_case request fields.",
  );
  error.status = 400;
  error.code = "model_storage_request_aliases_retired";
  error.details = {
    retired_aliases: retiredAliases,
    canonical_fields: CANONICAL_MODEL_STORAGE_REQUEST_FIELDS,
  };
  throw error;
}
