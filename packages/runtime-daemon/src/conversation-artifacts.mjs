import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const CONVERSATION_ARTIFACT_SCHEMA_VERSION = "ioi.conversation_artifact.v1";
export const CONVERSATION_ARTIFACT_REVISION_SCHEMA_VERSION = "ioi.conversation_artifact_revision.v1";
export const CONVERSATION_ARTIFACT_ACTION_SCHEMA_VERSION = "ioi.conversation_artifact_action.v1";

const DEFAULT_POLICY_REFS = [
  "policy:artifact.renderer.sandbox",
  "policy:artifact.actions.daemon_typed",
  "policy:artifact.chat.hide_raw_refs",
];

const CLASS_RENDERERS = new Map([
  ["markdown_html_report", { kind: "document_preview", label: "Markdown/HTML report" }],
  ["static_html_js", { kind: "sandboxed_web_preview", label: "Static HTML/CSS/JS" }],
  ["react_vite_app", { kind: "sandboxed_app_preview", label: "React/Vite app" }],
  ["imported_document", { kind: "document_projection", label: "Editable document" }],
  ["pdf_preview", { kind: "readonly_document", label: "PDF preview" }],
  ["diff_patch", { kind: "patch_preview", label: "Diff/Patch" }],
  ["dataset_chart", { kind: "dataset_chart", label: "Dataset/Chart" }],
  ["browser_observation", { kind: "managed_session_observation", label: "Browser/Computer observation" }],
]);

function ensureDir(targetPath) {
  fs.mkdirSync(targetPath, { recursive: true });
}

function writeText(filePath, content) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, String(content));
}

function writeBuffer(filePath, content) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, Buffer.isBuffer(content) ? content : Buffer.from(String(content)));
}

function writeJson(filePath, value) {
  writeText(filePath, `${JSON.stringify(value, null, 2)}\n`);
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function listJson(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((file) => file.endsWith(".json")).map((file) => path.join(dir, file));
}

function slug(value, fallback = "artifact") {
  return (
    String(value ?? "")
      .trim()
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-+|-+$/g, "")
      .slice(0, 64) || fallback
  );
}

function hash(value) {
  return crypto.createHash("sha256").update(String(value ?? "")).digest("hex").slice(0, 12);
}

function artifactClass(value) {
  const normalized = slug(value, "markdown-html-report").replace(/-/g, "_");
  return CLASS_RENDERERS.has(normalized) ? normalized : "markdown_html_report";
}

function nowIso() {
  return new Date().toISOString();
}

function relativeRef(root, targetPath) {
  return path.relative(root, targetPath).replace(/\\/g, "/");
}

function dataRef({ artifactId, revisionId, role, filePath, root }) {
  return {
    ref: `artifact://${artifactId}/${revisionId}/${role}/${path.basename(filePath)}`,
    role,
    path: relativeRef(root, filePath),
    fileName: path.basename(filePath),
    mediaType: mediaTypeForFile(filePath),
  };
}

function safeReadInlinePreview(rootDir, ref = {}) {
  const relativePath = String(ref.path || "");
  const mediaType = String(ref.mediaType || ref.media_type || "");
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
    mediaType,
    text,
    truncated: stat.size > maxBytes,
    source_ref: ref.ref || null,
    sourceRef: ref.ref || null,
  };
}

function mediaTypeForFile(filePath) {
  const ext = path.extname(filePath).toLowerCase();
  if (ext === ".html") return "text/html";
  if (ext === ".md") return "text/markdown";
  if (ext === ".json") return "application/json";
  if (ext === ".csv") return "text/csv";
  if (ext === ".diff" || ext === ".patch") return "text/x-diff";
  if (ext === ".pdf") return "application/pdf";
  if (ext === ".odt") return "application/vnd.oasis.opendocument.text";
  if (ext === ".docx") return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
  if (ext === ".js" || ext === ".jsx") return "text/javascript";
  if (ext === ".css") return "text/css";
  return "text/plain";
}

function generatedText(value, fallback = "") {
  return String(value ?? fallback ?? "").trim();
}

function generatedWebFilesFromInput(value = {}) {
  const source = value && typeof value === "object" ? value : {};
  const html = generatedText(source.html || source.indexHtml || source.index_html);
  if (!html) return null;
  return {
    html,
    css: generatedText(source.css),
    js: generatedText(source.js || source.javascript),
    title: generatedText(source.title),
    summary: generatedText(source.summary),
  };
}

function generatedArtifactInput(input = {}) {
  return input.generatedFiles || input.generated_files || input.generatedWeb || input.generated_web || null;
}

function artifactSourceRequiredError(message) {
  const error = new Error(message);
  error.code = "artifact_source_required";
  error.status = 422;
  return error;
}

function assertStaticWebsiteGeneratedSource(classId, generatedFiles) {
  if (classId !== "static_html_js") return;
  if (generatedWebFilesFromInput(generatedFiles)) return;
  throw artifactSourceRequiredError("Static website artifacts require model-authored HTML/CSS/JS source.");
}

function htmlPage(title, body, { script = "", style = "" } = {}) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${escapeHtml(title)}</title>
    <style>
      :root { color-scheme: light; font-family: Inter, system-ui, sans-serif; }
      body { margin: 0; background: #f8fafc; color: #172033; }
      main { padding: 24px; max-width: 960px; margin: 0 auto; }
      h1 { font-size: 28px; margin: 0 0 12px; }
      h2 { font-size: 18px; margin: 22px 0 8px; }
      p, li { line-height: 1.55; }
      table { border-collapse: collapse; width: 100%; background: white; }
      th, td { border: 1px solid #d8dee8; padding: 8px 10px; text-align: left; }
      .chart { height: 160px; display: flex; align-items: end; gap: 10px; margin: 18px 0; }
      .bar { width: 48px; background: #3b82f6; border-radius: 4px 4px 0 0; }
      .compare { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
      .panel { background: white; border: 1px solid #d8dee8; border-radius: 8px; padding: 14px; }
      .muted { color: #64748b; }
      ${style}
    </style>
  </head>
  <body>
    <main>${body}</main>
    ${script ? `<script>${script}</script>` : ""}
  </body>
</html>`;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function defaultTitleForClass(classId) {
  return CLASS_RENDERERS.get(classId)?.label ?? "Conversation artifact";
}

function actionListForClass(classId) {
  const shared = ["ask", "fork", "promote"];
  switch (classId) {
    case "imported_document":
      return ["edit", "compare", "apply", "export", "rollback", ...shared];
    case "react_vite_app":
      return ["edit", "rebuild", "export", "promote", "rollback"];
    case "static_html_js":
      return ["edit", "rebuild", "export", "promote", "rollback"];
    case "diff_patch":
      return ["approve", "apply", "rollback", "export", ...shared];
    case "pdf_preview":
      return ["summarize", "export_summary", ...shared];
    case "browser_observation":
      return ["ask", "capture", "promote", "export"];
    default:
      return ["edit", "export", ...shared];
  }
}

function reportFiles({ dir, title, prompt }) {
  const md = path.join(dir, "report.md");
  const html = path.join(dir, "report.html");
  writeText(md, `# ${title}\n\n## Summary\n\n${prompt || "Generated report artifact."}\n\n## Recommendation\n\nUse the artifact preview for the reader-facing version and tracing for receipts.\n`);
  writeText(html, htmlPage(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(prompt || "Generated report artifact.")}</p><h2>Recommendation</h2><p>Use this preview as the reader-facing report. Build details and receipts stay in tracing.</p>`));
  return { sources: [md], projections: [md], previews: [html] };
}

function staticWebFiles({ dir, title, prompt, generatedFiles }) {
  const html = path.join(dir, "index.html");
  const css = path.join(dir, "style.css");
  const js = path.join(dir, "app.js");
  const generated = generatedWebFilesFromInput(generatedFiles);
  if (!generated) {
    throw artifactSourceRequiredError("Static website artifacts require model-authored HTML/CSS/JS source.");
  }
  let htmlText = /<html[\s>]/i.test(generated.html)
    ? generated.html
    : `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(generated.title || title)}</title></head><body>${generated.html}</body></html>`;
  if (generated.css && !/<style[\s>]/i.test(htmlText)) {
    htmlText = /<\/head>/i.test(htmlText)
      ? htmlText.replace(/<\/head>/i, `<style>${generated.css}</style></head>`)
      : htmlText.replace(/<body[^>]*>/i, (match) => `${match}<style>${generated.css}</style>`);
  }
  if (generated.js && !/<script[\s>]/i.test(htmlText)) {
    htmlText = /<\/body>/i.test(htmlText)
      ? htmlText.replace(/<\/body>/i, `<script>${generated.js}</script></body>`)
      : `${htmlText}<script>${generated.js}</script>`;
  }
  writeText(css, generated.css);
  writeText(js, generated.js);
  writeText(html, htmlText);
  return { sources: [html, css, js], projections: [html, css, js], previews: [html] };
}

function reactViteFiles({ dir, title, dense = false }) {
  const packageJson = path.join(dir, "package.json");
  const index = path.join(dir, "index.html");
  const srcDir = path.join(dir, "src");
  const app = path.join(srcDir, "App.jsx");
  const dist = path.join(dir, "dist", "index.html");
  const buildLog = path.join(dir, "build.log");
  ensureDir(srcDir);
  writeJson(packageJson, {
    scripts: { dev: "vite", build: "vite build", preview: "vite preview" },
    dependencies: { "@vitejs/plugin-react": "latest", vite: "latest", react: "latest", "react-dom": "latest" },
    devDependencies: {},
  });
  writeText(index, "<!doctype html><div id=\"root\"></div><script type=\"module\" src=\"/src/App.jsx\"></script>");
  writeText(app, `export default function App(){return <main className="${dense ? "dense" : "roomy"}"><aside>Revenue<br/>Latency<br/>Quality</aside><section><h1>${title}</h1><p>Disposable React/Vite artifact preview.</p><strong>Build green</strong></section></main>}`);
  writeText(dist, htmlPage(title, `<h1>${escapeHtml(title)}</h1><p>${dense ? "Dense sidebar edit applied." : "Disposable React/Vite artifact preview."}</p><section class="panel"><strong>Build green</strong><p class="muted">Vite build was simulated by the daemon retained artifact process for this hermetic fixture.</p></section>`));
  writeText(buildLog, "vite build\n✓ 8 modules transformed\n✓ built in 317ms\n");
  return { sources: [packageJson, index, app], projections: [app], previews: [dist], logs: [buildLog] };
}

function importedDocumentFiles({ dir, title, prompt, edited = false }) {
  const original = path.join(dir, "original.odt");
  const projection = path.join(dir, "projection.md");
  const preview = path.join(dir, "preview.html");
  const compare = path.join(dir, "compare.html");
  writeBuffer(original, Buffer.from(`ODT_FIXTURE_ORIGINAL_BYTES\n${title}\n${prompt || ""}\n`));
  writeText(projection, `# ${title}\n\n${edited ? "Tightened intro: " : ""}${prompt || "Imported document projection."}\n\nOriginal bytes are preserved separately.\n`);
  writeText(preview, htmlPage(title, `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(edited ? "Tightened intro prepared." : "Imported document projection ready.")}</p><p class="muted">Original ODT bytes preserved; editable projection is reversible.</p>`));
  writeText(compare, htmlPage(`${title} compare`, `<h1>Compare changes</h1><div class="compare"><section class="panel"><h2>Before</h2><p>${escapeHtml(prompt || "Imported document projection.")}</p></section><section class="panel"><h2>After</h2><p>Tightened intro: ${escapeHtml(prompt || "Imported document projection.")}</p></section></div>`));
  return { originals: [original], sources: [original], projections: [projection], previews: [preview, compare] };
}

function pdfFiles({ dir, title }) {
  const pdf = path.join(dir, "source.pdf");
  const summary = path.join(dir, "summary.md");
  const preview = path.join(dir, "pdf-preview.html");
  writeBuffer(pdf, Buffer.from("%PDF-1.4\n% IOI fixture PDF\n1 0 obj <<>> endobj\ntrailer <<>>\n%%EOF\n"));
  writeText(summary, `# ${title} summary\n\nRead-only PDF artifact with editable summary projection.\n`);
  writeText(preview, htmlPage(title, `<h1>${escapeHtml(title)}</h1><p>Read-only PDF preview fixture.</p><section class="panel"><strong>Editable summary artifact available</strong><p>The source PDF remains immutable.</p></section>`));
  return { originals: [pdf], sources: [pdf], projections: [summary], previews: [preview] };
}

function diffPatchFiles({ dir, title }) {
  const patch = path.join(dir, "change.diff");
  const preview = path.join(dir, "patch-preview.html");
  const rollback = path.join(dir, "rollback.diff");
  writeText(patch, "diff --git a/status.js b/status.js\n@@\n-export const label = 'old';\n+export const label = 'reviewed';\n");
  writeText(rollback, "diff --git a/status.js b/status.js\n@@\n-export const label = 'reviewed';\n+export const label = 'old';\n");
  writeText(preview, htmlPage(title, `<h1>${escapeHtml(title)}</h1><p>Patch artifact awaiting approval.</p><pre>${escapeHtml(fs.readFileSync(patch, "utf8"))}</pre>`));
  return { sources: [patch], projections: [patch], previews: [preview], rollbackRefs: [rollback] };
}

function datasetChartFiles({ dir, title }) {
  const csv = path.join(dir, "results.csv");
  const json = path.join(dir, "results.json");
  const preview = path.join(dir, "chart.html");
  const rows = [
    ["Stage", "LatencyMs", "Status"],
    ["Report", "480", "pass"],
    ["React", "920", "pass"],
    ["Document", "760", "pass"],
  ];
  writeText(csv, rows.map((row) => row.join(",")).join("\n") + "\n");
  writeJson(json, rows.slice(1).map(([stage, latencyMs, status]) => ({ stage, latencyMs: Number(latencyMs), status })));
  writeText(preview, htmlPage(title, `<h1>${escapeHtml(title)}</h1><div class="chart"><div class="bar" style="height:48px"></div><div class="bar" style="height:92px"></div><div class="bar" style="height:76px"></div></div><table><thead><tr><th>Stage</th><th>Latency</th><th>Status</th></tr></thead><tbody><tr><td>Report</td><td>480ms</td><td>pass</td></tr><tr><td>React</td><td>920ms</td><td>pass</td></tr><tr><td>Document</td><td>760ms</td><td>pass</td></tr></tbody></table>`));
  return { sources: [csv, json], projections: [json], previews: [preview] };
}

function browserObservationFiles({ dir, title }) {
  const observation = path.join(dir, "observation.json");
  const preview = path.join(dir, "browser-observation.html");
  writeJson(observation, {
    sessionKind: "sandbox_browser",
    status: "complete",
    url: "http://127.0.0.1/fixture",
    title: "Tool Catalogue Fixture",
    actions: ["observe", "take_over", "return_agent"],
  });
  writeText(preview, htmlPage(title, `<h1>${escapeHtml(title)}</h1><section class="panel"><strong>Sandbox browser</strong><p>Observation captured from a managed live session artifact.</p><p>Controls: Observe / Take over / Return control.</p></section>`));
  return { sources: [observation], projections: [observation], previews: [preview] };
}

function filesForClass({ classId, dir, title, prompt, revisionIndex, generatedFiles }) {
  if (classId === "static_html_js") return staticWebFiles({ dir, title, prompt, generatedFiles });
  if (classId === "react_vite_app") return reactViteFiles({ dir, title, dense: revisionIndex > 1 });
  if (classId === "imported_document") return importedDocumentFiles({ dir, title, prompt, edited: revisionIndex > 1 });
  if (classId === "pdf_preview") return pdfFiles({ dir, title });
  if (classId === "diff_patch") return diffPatchFiles({ dir, title });
  if (classId === "dataset_chart") return datasetChartFiles({ dir, title });
  if (classId === "browser_observation") return browserObservationFiles({ dir, title });
  return reportFiles({ dir, title, prompt });
}

export class ConversationArtifactStore {
  constructor(stateDir) {
    this.stateDir = path.resolve(stateDir);
    this.rootDir = path.join(this.stateDir, "conversation-artifacts");
    this.recordsDir = path.join(this.rootDir, "records");
    this.assetsDir = path.join(this.rootDir, "assets");
    this.receiptsDir = path.join(this.rootDir, "receipts");
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
    for (const file of listJson(this.recordsDir)) {
      const record = readJson(file);
      if (record?.id) this.records.set(record.id, record);
    }
  }

  create(input = {}) {
    const classId = artifactClass(input.artifactClass ?? input.artifact_class ?? input.class);
    const title = String(input.title || defaultTitleForClass(classId));
    const generatedFiles = generatedArtifactInput(input);
    assertStaticWebsiteGeneratedSource(classId, generatedFiles);
    const artifactId = `artifact_${slug(classId)}_${hash(`${title}:${Date.now()}:${crypto.randomUUID()}`)}`;
    const revision = this.#createRevisionFiles({
      artifactId,
      classId,
      title,
      prompt: input.prompt || input.summary || "",
      generatedFiles,
      revisionIndex: 1,
      summary: input.summary || "Initial artifact revision.",
    });
    const createdAt = nowIso();
    const renderer = CLASS_RENDERERS.get(classId) ?? CLASS_RENDERERS.get("markdown_html_report");
    const receipt = this.#receipt({
      artifactId,
      action: "create",
      summary: `Created ${renderer.label} artifact.`,
      policyRefs: DEFAULT_POLICY_REFS,
    });
    const record = {
      schema_version: CONVERSATION_ARTIFACT_SCHEMA_VERSION,
      schemaVersion: CONVERSATION_ARTIFACT_SCHEMA_VERSION,
      object: "ioi.conversation_artifact",
      id: artifactId,
      artifact_id: artifactId,
      artifactId,
      thread_id: input.threadId ?? input.thread_id ?? null,
      threadId: input.threadId ?? input.thread_id ?? null,
      turn_id: input.turnId ?? input.turn_id ?? null,
      turnId: input.turnId ?? input.turn_id ?? null,
      artifact_class: classId,
      artifactClass: classId,
      output_modality: input.outputModality ?? input.output_modality ?? input.intentFrame?.artifact?.outputModality ?? null,
      outputModality: input.outputModality ?? input.output_modality ?? input.intentFrame?.artifact?.outputModality ?? null,
      title,
      status: classId === "diff_patch" ? "approval_required" : "preview_ready",
      state_label: classId === "diff_patch" ? "Approval required" : "Preview ready",
      stateLabel: classId === "diff_patch" ? "Approval required" : "Preview ready",
      summary: input.summary || `${renderer.label} is ready.`,
      generated_files: generatedFiles,
      generatedFiles,
      renderer: {
        ...renderer,
        sandboxed: true,
        network: "deny_by_default",
        filesystem: "no_ambient_access",
        actions: "typed_daemon_requests",
      },
      source_refs: revision.source_refs,
      sourceRefs: revision.source_refs,
      original_refs: revision.original_refs,
      originalRefs: revision.original_refs,
      projection_refs: revision.projection_refs,
      projectionRefs: revision.projection_refs,
      preview_refs: revision.preview_refs,
      previewRefs: revision.preview_refs,
      trace_refs: [`trace:conversation-artifact:${artifactId}`],
      traceRefs: [`trace:conversation-artifact:${artifactId}`],
      policy_refs: DEFAULT_POLICY_REFS,
      policyRefs: DEFAULT_POLICY_REFS,
      receipt_refs: [receipt.id],
      receiptRefs: [receipt.id],
      action_schema_version: CONVERSATION_ARTIFACT_ACTION_SCHEMA_VERSION,
      actionSchemaVersion: CONVERSATION_ARTIFACT_ACTION_SCHEMA_VERSION,
      actions: actionListForClass(classId),
      revisions: [revision],
      latest_revision_id: revision.id,
      latestRevisionId: revision.id,
      export_refs: [],
      exportRefs: [],
      promotion_refs: [],
      promotionRefs: [],
      fidelity: classId === "imported_document"
        ? {
            status: "projection_ready",
            exactLayoutFidelity: "not_claimed",
            message: "Original bytes are preserved; editable projection, compare, and export use a reproducible converter path.",
          }
        : null,
      created_at: createdAt,
      createdAt,
      updated_at: createdAt,
      updatedAt: createdAt,
      evidence: {
        runtimeOwned: true,
        guiOwnsExecutionSemantics: false,
        rawRefsHiddenFromChat: true,
      },
    };
    this.records.set(artifactId, record);
    this.#write(record);
    return { artifact: this.#withInlinePreview(record), receipt };
  }

  list(query = {}) {
    const threadId = query.threadId ?? query.thread_id ?? null;
    return [...this.records.values()]
      .filter((record) => !threadId || record.thread_id === threadId || record.threadId === threadId)
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
    const record = this.records.get(artifactId);
    if (!record) return null;
    const action = slug(input.action ?? input.type ?? "ask", "ask").replace(/-/g, "_");
    const allowedActions = new Set(record.actions ?? []);
    if (!allowedActions.has(action)) {
      const receipt = this.#receipt({
        artifactId,
        action,
        summary: `Rejected unsupported artifact action ${action}.`,
        policyRefs: DEFAULT_POLICY_REFS,
      });
      record.receipt_refs = [...new Set([...(record.receipt_refs ?? []), receipt.id])];
      record.receiptRefs = record.receipt_refs;
      record.updated_at = nowIso();
      record.updatedAt = record.updated_at;
      this.#write(record);
      return {
        schema_version: CONVERSATION_ARTIFACT_ACTION_SCHEMA_VERSION,
        schemaVersion: CONVERSATION_ARTIFACT_ACTION_SCHEMA_VERSION,
        object: "ioi.conversation_artifact_action_result",
        action,
        status: "rejected",
        code: "unsupported_artifact_action",
        policy_verdict: {
          allowed: false,
          reason: "Artifact actions must be declared typed daemon requests.",
        },
        policyVerdict: {
          allowed: false,
          reason: "Artifact actions must be declared typed daemon requests.",
        },
        artifact: this.#withInlinePreview(record),
        receipt,
      };
    }
    const suppliedGeneratedFiles = generatedArtifactInput(input);
    const generatedFilesForRevision = suppliedGeneratedFiles || record.generated_files || record.generatedFiles;
    if (["edit", "rebuild", "compare"].includes(action)) {
      assertStaticWebsiteGeneratedSource(record.artifact_class, generatedFilesForRevision);
    }
    const receipt = this.#receipt({
      artifactId,
      action,
      summary: `Artifact action ${action} completed through daemon contract.`,
      policyRefs: DEFAULT_POLICY_REFS,
    });
    const now = nowIso();
    if (["edit", "rebuild", "compare"].includes(action)) {
      const revision = this.#createRevisionFiles({
        artifactId,
        classId: record.artifact_class,
        title: record.title,
        prompt: input.instruction || input.prompt || record.summary,
        generatedFiles: generatedFilesForRevision,
        revisionIndex: record.revisions.length + 1,
        summary: action === "rebuild" ? "Rebuilt preview after Agent edit." : "Prepared editable revision and compare preview.",
      });
      if (suppliedGeneratedFiles) {
        record.generated_files = suppliedGeneratedFiles;
        record.generatedFiles = record.generated_files;
      }
      record.revisions.push(revision);
      record.latest_revision_id = revision.id;
      record.latestRevisionId = revision.id;
      record.source_refs = revision.source_refs;
      record.sourceRefs = revision.source_refs;
      record.original_refs = revision.original_refs;
      record.originalRefs = revision.original_refs;
      record.projection_refs = revision.projection_refs;
      record.projectionRefs = revision.projection_refs;
      record.preview_refs = revision.preview_refs;
      record.previewRefs = revision.preview_refs;
      record.status = action === "compare" || record.artifact_class === "imported_document" ? "compare_ready" : "preview_ready";
      record.state_label = action === "rebuild" ? "Preview rebuilt" : "Compare ready";
      record.stateLabel = record.state_label;
    } else if (action === "export" || action === "export_summary") {
      const exportDir = path.join(this.assetsDir, artifactId, "exports");
      let exportFile = path.join(exportDir, `${slug(record.title)}-${hash(now)}.html`);
      if (record.artifact_class === "imported_document") {
        exportFile = path.join(exportDir, `${slug(record.title)}-${hash(now)}.odt`);
        writeBuffer(exportFile, Buffer.from(`ODT_FIXTURE_REVISED_BYTES\n${record.title}\n${record.latest_revision_id}\n`));
      } else if (record.artifact_class === "pdf_preview" || action === "export_summary") {
        exportFile = path.join(exportDir, `${slug(record.title)}-summary-${hash(now)}.md`);
        writeText(exportFile, `# ${record.title} summary\n\nEditable summary export.\n`);
      } else if (record.artifact_class === "diff_patch") {
        exportFile = path.join(exportDir, `${slug(record.title)}-${hash(now)}.patch`);
        writeText(exportFile, "diff --git a/status.js b/status.js\n@@\n-export const label = 'old';\n+export const label = 'reviewed';\n");
      } else if (record.artifact_class === "dataset_chart") {
        exportFile = path.join(exportDir, `${slug(record.title)}-${hash(now)}.csv`);
        writeText(exportFile, "Stage,LatencyMs,Status\nReport,480,pass\nReact,920,pass\nDocument,760,pass\n");
      } else if (record.artifact_class === "browser_observation") {
        exportFile = path.join(exportDir, `${slug(record.title)}-${hash(now)}.json`);
        writeJson(exportFile, {
          sessionKind: "sandbox_browser",
          status: "captured",
          controls: ["observe", "take_over", "return_agent"],
        });
      } else {
        writeText(exportFile, htmlPage(`${record.title} export`, `<h1>${escapeHtml(record.title)}</h1><p>Exported artifact revision.</p>`));
      }
      const ref = dataRef({ artifactId, revisionId: record.latest_revision_id, role: "export", filePath: exportFile, root: this.rootDir });
      record.export_refs.push(ref);
      record.exportRefs = record.export_refs;
      record.status = "export_ready";
      record.state_label = "Export ready";
      record.stateLabel = "Export ready";
    } else if (action === "promote") {
      const promotion = {
        ref: `promotion://${artifactId}/${hash(now)}`,
        target: input.target || "workspace",
        status: "promoted",
        created_at: now,
        createdAt: now,
      };
      record.promotion_refs.push(promotion);
      record.promotionRefs = record.promotion_refs;
      record.status = "promoted";
      record.state_label = "Promoted";
      record.stateLabel = "Promoted";
    } else if (action === "apply" || action === "approve") {
      record.status = "applied";
      record.state_label = action === "approve" ? "Approved" : "Applied";
      record.stateLabel = record.state_label;
    } else if (action === "rollback") {
      const revision = record.revisions[Math.max(0, record.revisions.length - 2)] ?? record.revisions[0];
      record.latest_revision_id = revision.id;
      record.latestRevisionId = revision.id;
      record.source_refs = revision.source_refs;
      record.sourceRefs = revision.source_refs;
      record.original_refs = revision.original_refs;
      record.originalRefs = revision.original_refs;
      record.projection_refs = revision.projection_refs;
      record.projectionRefs = revision.projection_refs;
      record.preview_refs = revision.preview_refs;
      record.previewRefs = revision.preview_refs;
      record.status = "rolled_back";
      record.state_label = "Rolled back";
      record.stateLabel = "Rolled back";
    } else if (action === "capture") {
      record.status = "captured";
      record.state_label = "Observation captured";
      record.stateLabel = "Observation captured";
    }
    record.receipt_refs = [...new Set([...(record.receipt_refs ?? []), receipt.id])];
    record.receiptRefs = record.receipt_refs;
    record.updated_at = now;
    record.updatedAt = now;
    this.#write(record);
    return {
      schema_version: CONVERSATION_ARTIFACT_ACTION_SCHEMA_VERSION,
      schemaVersion: CONVERSATION_ARTIFACT_ACTION_SCHEMA_VERSION,
      object: "ioi.conversation_artifact_action_result",
      action,
      status: "completed",
      artifact: this.#withInlinePreview(record),
      receipt,
    };
  }

  exportArtifact(artifactId, input = {}) {
    return this.action(artifactId, { ...input, action: "export" });
  }

  promoteArtifact(artifactId, input = {}) {
    return this.action(artifactId, { ...input, action: "promote" });
  }

  #createRevisionFiles({ artifactId, classId, title, prompt, generatedFiles, revisionIndex, summary }) {
    const revisionId = `rev_${String(revisionIndex).padStart(3, "0")}_${hash(`${artifactId}:${revisionIndex}`)}`;
    const dir = path.join(this.assetsDir, artifactId, revisionId);
    ensureDir(dir);
    const files = filesForClass({ classId, dir, title, prompt, generatedFiles, revisionIndex });
    const toRefs = (role, values = []) => values.map((filePath) => dataRef({ artifactId, revisionId, role, filePath, root: this.rootDir }));
    const createdAt = nowIso();
    return {
      schema_version: CONVERSATION_ARTIFACT_REVISION_SCHEMA_VERSION,
      schemaVersion: CONVERSATION_ARTIFACT_REVISION_SCHEMA_VERSION,
      object: "ioi.conversation_artifact_revision",
      id: revisionId,
      revision_id: revisionId,
      revisionId,
      artifact_id: artifactId,
      artifactId,
      status: "ready",
      summary,
      source_refs: toRefs("source", files.sources),
      sourceRefs: toRefs("source", files.sources),
      original_refs: toRefs("original", files.originals),
      originalRefs: toRefs("original", files.originals),
      projection_refs: toRefs("projection", files.projections),
      projectionRefs: toRefs("projection", files.projections),
      preview_refs: toRefs("preview", files.previews),
      previewRefs: toRefs("preview", files.previews),
      log_refs: toRefs("log", files.logs),
      logRefs: toRefs("log", files.logs),
      rollback_refs: toRefs("rollback", files.rollbackRefs),
      rollbackRefs: toRefs("rollback", files.rollbackRefs),
      created_at: createdAt,
      createdAt,
    };
  }

  #withInlinePreview(record) {
    if (!record) return record;
    const previewRefs = record.preview_refs ?? record.previewRefs ?? [];
    const inline = safeReadInlinePreview(this.rootDir, previewRefs[0]);
    if (!inline) return { ...record };
    return {
      ...record,
      preview_inline: inline,
      previewInline: inline,
    };
  }

  #receipt({ artifactId, action, summary, policyRefs = [] }) {
    const receipt = {
      id: `receipt_artifact_${slug(action)}_${hash(`${artifactId}:${action}:${Date.now()}:${crypto.randomUUID()}`)}`,
      kind: "conversation_artifact",
      artifact_id: artifactId,
      artifactId,
      action,
      summary,
      policy_refs: policyRefs,
      policyRefs,
      redaction: "trace_only",
      created_at: nowIso(),
      createdAt: nowIso(),
    };
    writeJson(path.join(this.receiptsDir, `${receipt.id}.json`), receipt);
    return receipt;
  }

  #write(record) {
    const { preview_inline, previewInline, ...persisted } = record;
    this.records.set(persisted.id, persisted);
    writeJson(path.join(this.recordsDir, `${persisted.id}.json`), persisted);
  }
}
