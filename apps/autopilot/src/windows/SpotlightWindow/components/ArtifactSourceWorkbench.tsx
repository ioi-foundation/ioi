import { type ComponentType, useEffect, useMemo, useRef, useState } from "react";
import { Editor, loader } from "@monaco-editor/react";
import type { editor as MonacoEditorApi } from "monaco-editor";
import type {
  ArtifactContentPayload,
  StudioArtifactManifestFile,
} from "../../../types";

const MonacoEditor = Editor as unknown as ComponentType<any>;

let configuredBasePath: string | null = null;
let configuredWorkerBaseUrl: string | null = null;
let monacoWorkerBootstrapUrl: string | null = null;

function ensureStudioMonacoWorkerEnvironment(basePath: string) {
  if (typeof window === "undefined") {
    return;
  }

  const normalizedVsUrl = new URL(
    `${basePath.replace(/\/+$/, "")}/`,
    window.location.href,
  ).toString();
  const normalizedBaseUrl = new URL("../", normalizedVsUrl).toString();

  if (!monacoWorkerBootstrapUrl || configuredWorkerBaseUrl !== normalizedBaseUrl) {
    const workerBootstrap = [
      "self.MonacoEnvironment = self.MonacoEnvironment || {};",
      `self.MonacoEnvironment.baseUrl = ${JSON.stringify(normalizedBaseUrl)};`,
      `importScripts(${JSON.stringify(`${normalizedBaseUrl}vs/base/worker/workerMain.js`)});`,
    ].join("\n");
    monacoWorkerBootstrapUrl = URL.createObjectURL(
      new Blob([workerBootstrap], { type: "text/javascript" }),
    );
    configuredWorkerBaseUrl = normalizedBaseUrl;
  }

  const globalEnvironment = (globalThis as any).MonacoEnvironment ?? {};
  (globalThis as any).MonacoEnvironment = {
    ...globalEnvironment,
    baseUrl: normalizedBaseUrl,
    getWorkerUrl: () => monacoWorkerBootstrapUrl!,
    getWorker: (_moduleId: string, label: string) =>
      new Worker(monacoWorkerBootstrapUrl!, {
        name: `monaco-${label || "worker"}`,
      }),
  };
}

function configureStudioMonacoLoader(basePath = "/monaco/vs") {
  if (!basePath || configuredBasePath === basePath) {
    return;
  }

  loader.config({
    paths: {
      vs: basePath,
    },
  });
  ensureStudioMonacoWorkerEnvironment(basePath);
  configuredBasePath = basePath;
}

function defineStudioMonacoTheme(monaco: any) {
  monaco.editor.defineTheme("autopilot-dark", {
    base: "vs-dark",
    inherit: true,
    rules: [],
    colors: {
      "editor.background": "#0c0f13",
      "editor.foreground": "#e4e7ed",
      "editor.lineHighlightBackground": "#141922",
      "editorCursor.foreground": "#a8d0ff",
      "editor.selectionBackground": "#244260",
      "editor.selectionHighlightBackground": "#1a2f46",
      "editorIndentGuide.background1": "#1d2330",
      "editorIndentGuide.activeBackground1": "#37516f",
      "editorLineNumber.foreground": "#596273",
      "editorLineNumber.activeForeground": "#9eafc5",
      "editorWhitespace.foreground": "#2b3442",
      "editorGutter.background": "#0c0f13",
      "minimap.background": "#0f1318",
      "scrollbar.shadow": "#00000000",
    },
  });
}

function languageFromHint(hint: string): string | null {
  const normalized = hint.trim().toLowerCase();
  if (!normalized) {
    return null;
  }

  switch (normalized) {
    case "tsx":
    case "typescript":
      return "typescript";
    case "jsx":
    case "javascript":
      return "javascript";
    case "json":
    case "markdown":
    case "rust":
    case "css":
    case "html":
    case "yaml":
    case "xml":
    case "shell":
      return normalized;
    case "toml":
      return "ini";
    default:
      break;
  }

  const mime = normalized.split(";")[0].trim();
  if (!mime.includes("/")) {
    return null;
  }

  if (mime.includes("html")) {
    return "html";
  }
  if (mime.includes("css")) {
    return "css";
  }
  if (mime.includes("json")) {
    return "json";
  }
  if (mime.includes("markdown")) {
    return "markdown";
  }
  if (mime.includes("yaml") || mime.includes("yml")) {
    return "yaml";
  }
  if (mime.includes("xml") || mime.includes("svg")) {
    return "xml";
  }
  if (mime.includes("javascript") || mime.includes("ecmascript")) {
    return "javascript";
  }
  if (mime.includes("typescript")) {
    return "typescript";
  }
  if (mime.includes("shell") || mime.includes("bash") || mime.includes("sh")) {
    return "shell";
  }
  if (mime.includes("toml")) {
    return "ini";
  }
  if (mime.includes("rust")) {
    return "rust";
  }

  return null;
}

function languageForSourcePath(path: string, hint?: string | null): string {
  if (hint) {
    const language = languageFromHint(hint);
    if (language) {
      return language;
    }
  }

  const extension = path.split(".").pop()?.toLowerCase();
  switch (extension) {
    case "ts":
    case "tsx":
      return "typescript";
    case "js":
    case "jsx":
      return "javascript";
    case "json":
      return "json";
    case "md":
      return "markdown";
    case "rs":
      return "rust";
    case "css":
      return "css";
    case "html":
    case "htm":
      return "html";
    case "yaml":
    case "yml":
      return "yaml";
    case "sh":
    case "bash":
      return "shell";
    case "toml":
      return "ini";
    default:
      return "plaintext";
  }
}

interface ArtifactSourceWorkbenchProps {
  artifactId: string;
  files: StudioArtifactManifestFile[];
  selectedFile: StudioArtifactManifestFile | null;
  payload: ArtifactContentPayload | null;
  loading: boolean;
  error: string | null;
  onSelectPath: (path: string) => void;
  onAttachSelection?: (payload: { path: string; selection: string }) => void;
  showExplorer?: boolean;
  sourceTextOverride?: string | null;
  binaryOverride?: boolean;
  tooLargeOverride?: boolean;
}

function decodePayloadText(
  payload: ArtifactContentPayload | null,
  sourceTextOverride?: string | null,
): string {
  if (typeof sourceTextOverride === "string") {
    return sourceTextOverride;
  }
  if (!payload) {
    return "";
  }
  if (payload.encoding === "base64") {
    try {
      return window.atob(payload.content);
    } catch {
      return "";
    }
  }
  return payload.content;
}

function decodeExternalUrlText(url?: string | null): string | null {
  if (!url || !url.startsWith("data:")) {
    return null;
  }
  const commaIndex = url.indexOf(",");
  if (commaIndex < 0) {
    return null;
  }
  const meta = url.slice(5, commaIndex);
  const content = url.slice(commaIndex + 1);
  try {
    if (meta.includes(";base64")) {
      return window.atob(content);
    }
    return decodeURIComponent(content);
  } catch {
    return null;
  }
}

function isBinaryMime(mime: string): boolean {
  const normalized = mime.trim().toLowerCase();
  if (!normalized) {
    return false;
  }

  if (normalized.startsWith("text/")) {
    return false;
  }

  if (
    normalized.includes("json") ||
    normalized.includes("javascript") ||
    normalized.includes("typescript") ||
    normalized.includes("xml") ||
    normalized.includes("yaml") ||
    normalized.includes("svg") ||
    normalized.includes("html") ||
    normalized.includes("markdown")
  ) {
    return false;
  }

  return true;
}

function syncSelectionText(setSelectionText: (value: string) => void) {
  const nextSelection = window.getSelection()?.toString().trim() ?? "";
  setSelectionText(nextSelection);
}

function describeMonacoLoadError(error: unknown): string {
  if (error instanceof Error) {
    return error.message || "Monaco editor failed to initialize.";
  }

  if (typeof ErrorEvent !== "undefined" && error instanceof ErrorEvent) {
    return error.message || `Monaco editor failed during ${error.type || "load"}.`;
  }

  if (typeof Event !== "undefined" && error instanceof Event) {
    const target = error.target as HTMLScriptElement | null;
    const source =
      target?.getAttribute?.("src") ||
      (target && "src" in target ? String((target as { src?: string }).src || "") : "");
    if (source) {
      return `Monaco editor failed to load required runtime assets from ${source}.`;
    }
    return `Monaco editor failed during ${error.type || "load"}.`;
  }

  if (
    error &&
    typeof error === "object" &&
    "message" in error &&
    typeof (error as { message?: unknown }).message === "string"
  ) {
    return ((error as { message: string }).message || "").trim() ||
      "Monaco editor failed to initialize.";
  }

  const text = String(error ?? "").trim();
  return text || "Monaco editor failed to initialize.";
}

export function ArtifactSourceWorkbench({
  artifactId,
  files,
  selectedFile,
  payload,
  loading,
  error,
  onAttachSelection,
  sourceTextOverride,
  binaryOverride,
  tooLargeOverride,
}: ArtifactSourceWorkbenchProps) {
  const [selectionText, setSelectionText] = useState("");
  const [monacoReady, setMonacoReady] = useState(false);
  const [monacoLoadError, setMonacoLoadError] = useState<string | null>(null);
  const editorRef = useRef<MonacoEditorApi.IStandaloneCodeEditor | null>(null);

  useEffect(() => {
    configureStudioMonacoLoader();
    let cancelled = false;

    loader
      .init()
      .then(() => {
        if (cancelled) {
          return;
        }
        setMonacoLoadError(null);
        setMonacoReady(true);
      })
      .catch((error) => {
        if (cancelled) {
          return;
        }
        setMonacoReady(false);
        setMonacoLoadError(describeMonacoLoadError(error));
      });

    return () => {
      cancelled = true;
    };
  }, []);

  configureStudioMonacoLoader();

  const sourceText = useMemo(
    () =>
      decodePayloadText(
        payload,
        sourceTextOverride ?? decodeExternalUrlText(selectedFile?.externalUrl),
      ),
    [payload, selectedFile?.externalUrl, sourceTextOverride],
  );
  const fileCount = files.length;
  const mime = selectedFile?.mime ?? "text/plain";
  const sourceLanguage = selectedFile
    ? languageForSourcePath(selectedFile.path, mime)
    : "plaintext";
  const isBinary = binaryOverride ?? (selectedFile ? isBinaryMime(mime) : false);
  const canAttachSelection =
    Boolean(onAttachSelection) &&
    Boolean(selectedFile?.path) &&
    !isBinary &&
    !tooLargeOverride &&
    selectionText.trim().length > 0;
  const pathSegments = selectedFile?.path.split("/").filter(Boolean) ?? [];

  const syncEditorSelection = () => {
    const editor = editorRef.current;
    const model = editor?.getModel();
    const selection = editor?.getSelection();
    if (!editor || !model || !selection) {
      syncSelectionText(setSelectionText);
      return;
    }
    const selected = model.getValueInRange(selection).trim();
    setSelectionText(selected || window.getSelection()?.toString().trim() || "");
  };

  return (
    <section className="studio-artifact-source-workbench">
      <div className="studio-artifact-source-surface">
        <div className="studio-artifact-source-editor-shell">
          <header className="studio-artifact-source-editor-tabs" aria-label="Source tabs">
            <div className="studio-artifact-source-editor-tab is-active">
              <span className="studio-artifact-source-editor-tab-icon">&lt;&gt;</span>
              <span className="studio-artifact-source-editor-tab-label">
                {selectedFile?.path ?? "Source unavailable"}
              </span>
            </div>
            {onAttachSelection ? (
              <button
                type="button"
                className="studio-artifact-source-action"
                onClick={() => {
                  if (!selectedFile || !selectionText.trim()) {
                    return;
                  }
                  onAttachSelection({
                    path: selectedFile.path,
                    selection: selectionText.trim(),
                  });
                }}
                disabled={!canAttachSelection}
              >
                Attach selection
              </button>
            ) : null}
          </header>

          <div className="studio-artifact-source-breadcrumbs" aria-label="Source breadcrumbs">
            {pathSegments.length ? (
              pathSegments.map((segment, index) => (
                <span key={`${segment}-${index}`} className="studio-artifact-source-breadcrumb">
                  {segment}
                </span>
              ))
            ) : (
              <span className="studio-artifact-source-breadcrumb">Source</span>
            )}
          </div>

          <div className="studio-artifact-source-surface-main">
            {error ? (
              <div className="studio-artifact-banner is-error">{error}</div>
            ) : loading ? (
              <div className="studio-artifact-renderer-empty">
                <strong>Loading source…</strong>
              </div>
            ) : !selectedFile ? (
              <div className="studio-artifact-renderer-empty">
                <strong>No source file selected.</strong>
              </div>
            ) : isBinary ? (
              <div className="studio-artifact-renderer-empty">
                <strong>Binary source</strong>
                <p>{selectedFile.path} is binary, so Studio keeps it as metadata only.</p>
              </div>
            ) : tooLargeOverride ? (
              <div className="studio-artifact-renderer-empty">
                <strong>Source preview too large</strong>
                <p>{selectedFile.path} is too large for inline viewing in Studio.</p>
              </div>
            ) : monacoLoadError ? (
              <div className="studio-artifact-banner is-error">
                {monacoLoadError}
              </div>
            ) : !monacoReady ? (
              <div className="studio-artifact-renderer-empty">
                <strong>Preparing source editor…</strong>
              </div>
            ) : (
              <div className="studio-artifact-source-editor-stage">
                <MonacoEditor
                  path={selectedFile.path}
                  value={sourceText}
                  language={sourceLanguage}
                  theme="autopilot-dark"
                  beforeMount={defineStudioMonacoTheme}
                  options={{
                    automaticLayout: true,
                    readOnly: true,
                    fontSize: 13,
                    lineHeight: 21,
                    colorDecorators: true,
                    defaultColorDecorators: "always",
                    colorDecoratorsActivatedOn: "clickAndHover",
                    wordWrap: "off",
                    minimap: {
                      enabled: true,
                      side: "right",
                    },
                    scrollBeyondLastLine: false,
                    renderWhitespace: "selection",
                    smoothScrolling: true,
                    glyphMargin: false,
                    folding: true,
                    rulers: [],
                    padding: {
                      top: 12,
                      bottom: 12,
                    },
                    stickyScroll: {
                      enabled: false,
                    },
                  }}
                  onMount={(editor: MonacoEditorApi.IStandaloneCodeEditor) => {
                    editorRef.current = editor;
                    editor.onDidChangeCursorSelection(() => {
                      syncEditorSelection();
                    });
                    editor.onDidBlurEditorWidget(() => {
                      syncEditorSelection();
                    });
                  }}
                />
              </div>
            )}
          </div>

          <footer className="studio-artifact-source-statusbar">
            <span>{artifactId.slice(0, 12)}</span>
            <span>{mime}</span>
            <span>
              {fileCount} {fileCount === 1 ? "file" : "files"}
            </span>
          </footer>
        </div>
      </div>
    </section>
  );
}
