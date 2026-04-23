import {
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
  type CSSProperties,
} from "react";
import type { CodeOssMonaco } from "../codeOss";

type CodeOssDisposer = { dispose: () => void };

interface SharedProps {
  className?: string;
  style?: CSSProperties;
  theme?: string;
  loadingLabel?: string;
}

export interface CodeOssEditorProps extends SharedProps {
  path: string;
  value: string;
  language: string;
  options?: Record<string, unknown>;
  onChange?: (value: string) => void;
  onMount?: (
    editor: any,
    monaco: CodeOssMonaco,
  ) => void | CodeOssDisposer | (() => void);
}

export interface CodeOssDiffEditorProps extends SharedProps {
  path: string;
  original: string;
  modified: string;
  language: string;
  options?: Record<string, unknown>;
}

interface CodeOssRuntime {
  monaco: CodeOssMonaco;
  toUri: (path: string) => ReturnType<CodeOssMonaco["Uri"]["file"]>;
}

function toDisposer(
  disposer: void | CodeOssDisposer | (() => void),
): (() => void) | undefined {
  if (!disposer) {
    return undefined;
  }

  if (typeof disposer === "function") {
    return disposer;
  }

  if ("dispose" in disposer && typeof disposer.dispose === "function") {
    return () => {
      disposer.dispose();
    };
  }

  return undefined;
}

async function loadCodeOssRuntime(): Promise<CodeOssRuntime> {
  const runtime = await import("../codeOss");
  await runtime.ensureCodeOssReady();
  return {
    monaco: runtime.codeOssMonaco,
    toUri: runtime.toCodeOssUri,
  };
}

export function CodeOssEditor({
  path,
  value,
  language,
  onChange,
  onMount,
  options,
  className,
  style,
  theme = "autopilot-dark",
  loadingLabel = "Loading editor",
}: CodeOssEditorProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const editorRef = useRef<any>(null);
  const modelRef = useRef<any>(null);
  const runtimeRef = useRef<CodeOssRuntime | null>(null);
  const [ready, setReady] = useState(false);
  const changeGuardRef = useRef(false);
  const serializedOptions = useMemo(
    () => JSON.stringify(options ?? {}),
    [options],
  );

  useEffect(() => {
    let cancelled = false;

    void loadCodeOssRuntime()
      .then((runtime) => {
        if (!cancelled) {
          runtimeRef.current = runtime;
          setReady(true);
        }
      })
      .catch((error) => {
        console.error(
          "[WorkspaceSubstrate] Failed to load Code OSS editor runtime",
          error,
        );
      });

    return () => {
      cancelled = true;
    };
  }, []);

  useLayoutEffect(() => {
    const runtime = runtimeRef.current;
    if (!ready || !containerRef.current || !runtime) {
      return;
    }

    const model = runtime.monaco.editor.createModel(
      value,
      language,
      runtime.toUri(path),
    );
    modelRef.current = model;
    runtime.monaco.editor.setTheme(theme);

    const editor = runtime.monaco.editor.create(containerRef.current, {
      automaticLayout: true,
      fontSize: 13,
      lineHeight: 21,
      smoothScrolling: true,
      ...options,
      model,
    });
    editorRef.current = editor;

    const disposables: CodeOssDisposer[] = [];
    if (onChange) {
      disposables.push(
        editor.onDidChangeModelContent(() => {
          if (changeGuardRef.current) {
            return;
          }
          onChange(editor.getValue());
        }),
      );
    }

    const mountDisposer = toDisposer(onMount?.(editor, runtime.monaco));

    return () => {
      for (const disposable of disposables) {
        disposable.dispose();
      }
      mountDisposer?.();
      editor.dispose();
      model.dispose();
      editorRef.current = null;
      modelRef.current = null;
    };
  }, [language, onChange, onMount, options, path, ready, theme, value]);

  useEffect(() => {
    const model = modelRef.current;
    const editor = editorRef.current;
    const runtime = runtimeRef.current;
    if (!model || !editor || !runtime) {
      return;
    }

    if (model.getLanguageId() !== language) {
      runtime.monaco.editor.setModelLanguage(model, language);
    }

    if (model.getValue() !== value) {
      changeGuardRef.current = true;
      model.pushEditOperations(
        [],
        [
          {
            range: model.getFullModelRange(),
            text: value,
          },
        ],
        () => null,
      );
      changeGuardRef.current = false;
    }

    if (editor.getModel() !== model) {
      editor.setModel(model);
    }
  }, [language, value]);

  useEffect(() => {
    const editor = editorRef.current;
    if (!editor) {
      return;
    }
    editor.updateOptions(JSON.parse(serializedOptions));
  }, [serializedOptions]);

  return (
    <div
      className={className}
      style={style}
      data-editor-runtime="code-oss"
      data-editor-ready={ready ? "true" : "false"}
    >
      <div ref={containerRef} className="workspace-code-oss-surface" />
      {!ready ? (
        <div className="workspace-code-oss-loading" aria-live="polite">
          <div className="workspace-code-oss-loading__pulse" aria-hidden="true" />
          <span>{loadingLabel}</span>
        </div>
      ) : null}
    </div>
  );
}

export function CodeOssDiffEditor({
  path,
  original,
  modified,
  language,
  options,
  className,
  style,
  theme = "autopilot-dark",
  loadingLabel = "Loading diff editor",
}: CodeOssDiffEditorProps) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [ready, setReady] = useState(false);
  const diffEditorRef = useRef<any>(null);
  const originalModelRef = useRef<any>(null);
  const modifiedModelRef = useRef<any>(null);
  const runtimeRef = useRef<CodeOssRuntime | null>(null);
  const serializedOptions = useMemo(
    () => JSON.stringify(options ?? {}),
    [options],
  );

  useEffect(() => {
    let cancelled = false;

    void loadCodeOssRuntime()
      .then((runtime) => {
        if (!cancelled) {
          runtimeRef.current = runtime;
          setReady(true);
        }
      })
      .catch((error) => {
        console.error(
          "[WorkspaceSubstrate] Failed to load Code OSS diff runtime",
          error,
        );
      });

    return () => {
      cancelled = true;
    };
  }, []);

  const diffUris = useMemo(() => {
    const runtime = runtimeRef.current;
    if (!runtime) {
      return null;
    }

    return {
      original: runtime.toUri(`${path}.original`),
      modified: runtime.toUri(`${path}.modified`),
    };
  }, [path, ready]);

  useLayoutEffect(() => {
    const runtime = runtimeRef.current;
    if (!ready || !containerRef.current || !runtime || !diffUris) {
      return;
    }

    const originalModel = runtime.monaco.editor.createModel(
      original,
      language,
      diffUris.original,
    );
    const modifiedModel = runtime.monaco.editor.createModel(
      modified,
      language,
      diffUris.modified,
    );
    originalModelRef.current = originalModel;
    modifiedModelRef.current = modifiedModel;

    runtime.monaco.editor.setTheme(theme);

    const diffEditor = runtime.monaco.editor.createDiffEditor(
      containerRef.current,
      {
        automaticLayout: true,
        fontSize: 13,
        lineHeight: 21,
        smoothScrolling: true,
        ...options,
      },
    );
    diffEditorRef.current = diffEditor;
    diffEditor.setModel({
      original: originalModel,
      modified: modifiedModel,
    });

    return () => {
      diffEditor.dispose();
      originalModel.dispose();
      modifiedModel.dispose();
      diffEditorRef.current = null;
      originalModelRef.current = null;
      modifiedModelRef.current = null;
    };
  }, [diffUris, language, modified, options, original, path, ready, theme]);

  useEffect(() => {
    const originalModel = originalModelRef.current;
    const modifiedModel = modifiedModelRef.current;
    const runtime = runtimeRef.current;
    if (!originalModel || !modifiedModel || !runtime) {
      return;
    }

    if (originalModel.getLanguageId() !== language) {
      runtime.monaco.editor.setModelLanguage(originalModel, language);
    }
    if (modifiedModel.getLanguageId() !== language) {
      runtime.monaco.editor.setModelLanguage(modifiedModel, language);
    }

    if (originalModel.getValue() !== original) {
      originalModel.setValue(original);
    }
    if (modifiedModel.getValue() !== modified) {
      modifiedModel.setValue(modified);
    }
  }, [language, modified, original]);

  useEffect(() => {
    const diffEditor = diffEditorRef.current;
    if (!diffEditor) {
      return;
    }
    diffEditor.updateOptions(JSON.parse(serializedOptions));
  }, [serializedOptions]);

  return (
    <div
      className={className}
      style={style}
      data-editor-runtime="code-oss-diff"
      data-editor-ready={ready ? "true" : "false"}
    >
      <div ref={containerRef} className="workspace-code-oss-surface" />
      {!ready ? (
        <div className="workspace-code-oss-loading" aria-live="polite">
          <div className="workspace-code-oss-loading__pulse" aria-hidden="true" />
          <span>{loadingLabel}</span>
        </div>
      ) : null}
    </div>
  );
}
