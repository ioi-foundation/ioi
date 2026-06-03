function defaultOptionalString(value) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  return trimmed || null;
}

function defaultNormalizeArray(value) {
  return Array.isArray(value) ? value : [];
}

export function artifact(runId, name, mediaType, receiptId, value, redaction) {
  return {
    id: `artifact_${runId}_${name.replace(/[^a-z0-9]+/gi, "_").replace(/_$/, "")}`,
    runId,
    name,
    mediaType,
    redaction,
    receiptId,
    content: typeof value === "string" ? value : JSON.stringify(value, null, 2),
  };
}

export function createRunArtifactResolver(deps = {}) {
  const normalizeArray = deps.normalizeArray || defaultNormalizeArray;
  const optionalString = deps.optionalString || defaultOptionalString;

  function resolveRunArtifact(run = {}, artifactRef) {
    const ref = optionalString(artifactRef);
    if (!ref) return null;
    const artifacts = normalizeArray(run.artifacts);
    const normalizedRef = ref.replace(/^artifact:/, "");
    const lastSegment = normalizedRef.split(":").filter(Boolean).at(-1) ?? normalizedRef;
    const slugRef = normalizedRef.replace(/[^a-z0-9]+/gi, "_").replace(/^_+|_+$/g, "");
    const candidates = new Set([
      ref,
      normalizedRef,
      lastSegment,
      slugRef,
      `artifact_${slugRef}`,
    ]);
    return artifacts.find((item) =>
      candidates.has(item?.id) ||
      candidates.has(item?.name) ||
      candidates.has(item?.artifactRef) ||
      candidates.has(item?.artifact_ref),
    ) ?? null;
  }

  return {
    resolveRunArtifact,
  };
}
