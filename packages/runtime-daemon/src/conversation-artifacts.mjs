import fs from "node:fs";
import path from "node:path";

export const CONVERSATION_ARTIFACT_SCHEMA_VERSION = "ioi.conversation_artifact.v1";
export const CONVERSATION_ARTIFACT_REVISION_SCHEMA_VERSION = "ioi.conversation_artifact_revision.v1";
export const CONVERSATION_ARTIFACT_ACTION_SCHEMA_VERSION = "ioi.conversation_artifact_action.v1";

const conversationArtifactStoreWriterRetirementEvidenceRefs = [
  "runtime_conversation_artifact_store_js_writers_retired",
  "conversation_artifact_create_js_store_writer_retired",
  "conversation_artifact_action_js_store_writer_retired",
  "conversation_artifact_export_js_store_writer_retired",
  "conversation_artifact_promote_js_store_writer_retired",
  "rust_daemon_core_conversation_artifact_control_required",
  "agentgres_conversation_artifact_truth_required",
];

function ensureDir(targetPath) {
  fs.mkdirSync(targetPath, { recursive: true });
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function listJson(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((file) => file.endsWith(".json")).map((file) => path.join(dir, file));
}

function safeReadInlinePreview(rootDir, ref = {}) {
  const relativePath = String(ref.path || "");
  const mediaType = String(ref.media_type || "");
  if (!relativePath || !/^(text\/html|text\/markdown|text\/csv|application\/json|text\/x-diff|text\/plain)/i.test(mediaType)) {
    return null;
  }
  const resolved = path.resolve(rootDir, relativePath);
  const root = path.resolve(rootDir);
  if (resolved !== root && !resolved.startsWith(`${root}${path.sep}`)) {
    return null;
  }
  if (!fs.existsSync(resolved)) {
    return null;
  }
  const maxBytes = 128 * 1024;
  const stat = fs.statSync(resolved);
  const text = fs.readFileSync(resolved, "utf8").slice(0, maxBytes);
  return {
    media_type: mediaType,
    text,
    truncated: stat.size > maxBytes,
    source_ref: ref.ref || null,
  };
}

function conversationArtifactStoreRustCoreRequiredError({ operation, operationKind, artifactId = null }) {
  const error = new Error(
    "ConversationArtifactStore mutations require direct Rust daemon-core admission and persistence.",
  );
  error.status = 501;
  error.code = "runtime_conversation_artifact_store_rust_core_required";
  error.details = {
    rust_core_boundary: "runtime.conversation_artifact_control",
    operation,
    operation_kind: operationKind,
    ...(artifactId ? { artifact_id: artifactId } : {}),
    evidence_refs: [
      ...conversationArtifactStoreWriterRetirementEvidenceRefs,
      `${operation}_js_store_writer_retired`,
    ],
  };
  return error;
}

export class ConversationArtifactStore {
  constructor(stateDir, options = {}) {
    this.stateDir = path.resolve(stateDir);
    this.rootDir = path.join(this.stateDir, "conversation-artifacts");
    this.recordsDir = path.join(this.rootDir, "records");
    this.assetsDir = path.join(this.rootDir, "assets");
    this.receiptsDir = path.join(this.rootDir, "receipts");
    this.commitRuntimeArtifactState = options.commitRuntimeArtifactState;
    this.records = new Map();
    this.ensureDirs();
    this.load();
  }

  ensureDirs() {
    for (const dir of [this.rootDir, this.recordsDir, this.assetsDir, this.receiptsDir]) {
      ensureDir(dir);
    }
  }

  load() {
    for (const file of listJson(path.join(this.stateDir, "artifacts"))) {
      const record = readJson(file);
      if (record?.object === "ioi.conversation_artifact" && record?.id) this.records.set(record.id, record);
    }
  }

  create(input = {}) {
    void input;
    throw conversationArtifactStoreRustCoreRequiredError({
      operation: "conversation_artifact_create",
      operationKind: "artifact.conversation.create",
    });
  }

  list(query = {}) {
    const threadId = query.thread_id ?? null;
    return [...this.records.values()]
      .filter((record) => !threadId || record.thread_id === threadId)
      .sort((left, right) => String(right.updated_at).localeCompare(String(left.updated_at)))
      .map((record) => this.#withInlinePreview(record));
  }

  get(artifactId) {
    const record = this.records.get(artifactId);
    if (!record) return null;
    return this.#withInlinePreview(record);
  }

  revisions(artifactId) {
    return this.get(artifactId)?.revisions ?? [];
  }

  action(artifactId, input = {}) {
    void input;
    throw conversationArtifactStoreRustCoreRequiredError({
      operation: "conversation_artifact_action",
      operationKind: "artifact.conversation.action",
      artifactId,
    });
  }

  exportArtifact(artifactId, input = {}) {
    void input;
    throw conversationArtifactStoreRustCoreRequiredError({
      operation: "conversation_artifact_export",
      operationKind: "artifact.conversation.export",
      artifactId,
    });
  }

  promoteArtifact(artifactId, input = {}) {
    void input;
    throw conversationArtifactStoreRustCoreRequiredError({
      operation: "conversation_artifact_promote",
      operationKind: "artifact.conversation.promote",
      artifactId,
    });
  }

  #withInlinePreview(record) {
    if (!record) return record;
    const previewRefs = record.preview_refs ?? [];
    const inline = safeReadInlinePreview(this.rootDir, previewRefs[0]);
    if (!inline) return { ...record };
    return {
      ...record,
      preview_inline: inline,
    };
  }
}
