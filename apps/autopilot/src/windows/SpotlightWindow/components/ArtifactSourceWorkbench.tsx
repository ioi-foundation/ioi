import { useEffect, useMemo, useState } from "react";
import {
  WorkspaceEditorPane,
  WorkspaceExplorerPane,
  type WorkspaceFileDocument,
  type WorkspaceGitSummary,
  type WorkspaceOpenRequest,
} from "@ioi/workspace-substrate";
import type {
  ArtifactContentPayload,
  StudioArtifactManifestFile,
} from "../../../types";
import {
  buildArtifactTree,
  expandArtifactAncestors,
} from "./studioArtifactSurfaceModel";

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
}

type SourceDocumentTab = WorkspaceFileDocument & {
  id: string;
  kind: "file";
  loading: boolean;
  saving: boolean;
  error: string | null;
  savedContent: string;
};

const EMPTY_GIT_SUMMARY: WorkspaceGitSummary = {
  isRepo: false,
  branch: null,
  dirty: false,
  lastCommit: null,
};

function decodePayloadText(payload: ArtifactContentPayload | null): string {
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

function documentId(path: string): string {
  return `artifact-source:${path}`;
}

function rootLabel(artifactId: string): string {
  return `artifact://${artifactId}`;
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

function createDocument(
  artifactId: string,
  file: StudioArtifactManifestFile,
  state?: Partial<SourceDocumentTab>,
): SourceDocumentTab {
  const path = file.path;
  return {
    id: documentId(path),
    kind: "file",
    name: path.split("/").pop() || path,
    path,
    absolutePath: `${rootLabel(artifactId)}/${path}`,
    languageHint: null,
    content: "",
    savedContent: "",
    sizeBytes: 0,
    modifiedAtMs: null,
    isBinary: isBinaryMime(file.mime),
    isTooLarge: false,
    readOnly: true,
    loading: false,
    saving: false,
    error: null,
    ...state,
  };
}

function upsertDocument(
  documents: SourceDocumentTab[],
  artifactId: string,
  file: StudioArtifactManifestFile,
  state?: Partial<SourceDocumentTab>,
): SourceDocumentTab[] {
  const id = documentId(file.path);
  const existing = documents.find((document) => document.id === id);
  if (!existing) {
    return [...documents, createDocument(artifactId, file, state)];
  }

  return documents.map((document) =>
    document.id === id
      ? {
          ...document,
          ...state,
        }
      : document,
  );
}

export function ArtifactSourceWorkbench({
  artifactId,
  files,
  selectedFile,
  payload,
  loading,
  error,
  onSelectPath,
  onAttachSelection,
  showExplorer = true,
}: ArtifactSourceWorkbenchProps) {
  const [expandedPaths, setExpandedPaths] = useState<Record<string, boolean>>({});
  const [documents, setDocuments] = useState<SourceDocumentTab[]>([]);
  const [activeDocumentId, setActiveDocumentId] = useState<string | null>(null);
  const [revealRequest, setRevealRequest] = useState<WorkspaceOpenRequest | null>(null);

  const tree = useMemo(() => buildArtifactTree(files), [files]);
  const activeDocument =
    documents.find((document) => document.id === activeDocumentId) ?? null;

  useEffect(() => {
    if (!selectedFile) {
      return;
    }

    setExpandedPaths((current) => expandArtifactAncestors(current, selectedFile.path));
    setActiveDocumentId(documentId(selectedFile.path));
    setRevealRequest({ path: selectedFile.path });
    setDocuments((current) =>
      upsertDocument(current, artifactId, selectedFile, {
        loading,
        error: error ?? null,
      }),
    );
  }, [artifactId, error, loading, selectedFile]);

  useEffect(() => {
    if (!selectedFile || loading || error) {
      return;
    }

    const content = decodePayloadText(payload);
    setDocuments((current) =>
      upsertDocument(current, artifactId, selectedFile, {
        content,
        savedContent: content,
        sizeBytes: content.length,
        loading: false,
        saving: false,
        error: null,
      }),
    );
  }, [artifactId, error, loading, payload, selectedFile]);

  useEffect(() => {
    setDocuments((current) =>
      current.filter((document) => files.some((file) => file.path === document.path)),
    );
  }, [files]);

  const handleOpenFile = (path: string) => {
    setExpandedPaths((current) => expandArtifactAncestors(current, path));
    setActiveDocumentId(documentId(path));
    setRevealRequest({ path });
    onSelectPath(path);
  };

  return (
    <section className="studio-artifact-source-workbench workspace-host workspace-host--embedded">
      <div
        className={`studio-artifact-source-shell ${
          showExplorer ? "" : "studio-artifact-source-shell--editor-only"
        }`}
      >
        {showExplorer ? (
          <div className="workspace-host-sidebar">
            <WorkspaceExplorerPane
              tree={tree}
              activePath={selectedFile?.path ?? null}
              expandedPaths={expandedPaths}
              loadingDirectories={{}}
              git={EMPTY_GIT_SUMMARY}
              rootPath={rootLabel(artifactId)}
              eyebrow="Artifact"
              title="Source explorer"
              readOnly={true}
              showGitSummary={false}
              showRefreshButton={false}
              onToggleDirectory={(node) =>
                setExpandedPaths((current) => ({
                  ...current,
                  [node.path]: !current[node.path],
                }))
              }
              onOpenFile={handleOpenFile}
              onRefresh={() => undefined}
              onCreateFile={() => undefined}
              onCreateDirectory={() => undefined}
              onRenamePath={(_path: string) => undefined}
              onDeletePath={(_path: string) => undefined}
            />
          </div>
        ) : null}

        <div className="workspace-main">
          <WorkspaceEditorPane
            monacoBasePath="/monaco/vs"
            documents={documents}
            activeDocument={activeDocument}
            activeDocumentId={activeDocumentId}
            revealRequest={revealRequest}
            onConsumeRevealRequest={() => setRevealRequest(null)}
            onSelectDocument={(id) => {
              setActiveDocumentId(id);
              const document = documents.find((entry) => entry.id === id);
              if (document) {
                onSelectPath(document.path);
              }
            }}
            onCloseDocument={(id) => {
              const remaining = documents.filter((document) => document.id !== id);
              setDocuments(remaining);
              if (activeDocumentId === id) {
                const next = remaining[remaining.length - 1] ?? null;
                setActiveDocumentId(next?.id ?? null);
                if (next) {
                  onSelectPath(next.path);
                }
              }
            }}
            onChangeFileContent={(_path: string, _content: string) => undefined}
            onSaveFile={(_path: string) => undefined}
            onAttachSelection={onAttachSelection}
          />
        </div>
      </div>
    </section>
  );
}
