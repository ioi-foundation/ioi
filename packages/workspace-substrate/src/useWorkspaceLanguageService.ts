import { useEffect, useMemo, useState } from "react";
import type {
  WorkspaceAdapter,
  WorkspaceLanguageServiceSnapshot,
  WorkspaceProblemEntry,
} from "./types";
import type { WorkspaceDocumentTab } from "./useWorkspaceSession";

interface UseWorkspaceLanguageServiceOptions {
  adapter: WorkspaceAdapter;
  root: string;
  activeDocument: WorkspaceDocumentTab | null;
}

function isFileDocument(
  document: WorkspaceDocumentTab | null,
): document is Extract<WorkspaceDocumentTab, { kind: "file" }> {
  return !!document && document.kind === "file";
}

export function useWorkspaceLanguageService({
  adapter,
  root,
  activeDocument,
}: UseWorkspaceLanguageServiceOptions) {
  const [snapshot, setSnapshot] = useState<WorkspaceLanguageServiceSnapshot | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (
      !isFileDocument(activeDocument) ||
      activeDocument.error ||
      activeDocument.isBinary ||
      activeDocument.isTooLarge
    ) {
      setSnapshot(null);
      setLoading(false);
      return;
    }

    let cancelled = false;
    const timeout = window.setTimeout(() => {
      setLoading(true);
      void adapter
        .getLanguageServiceSnapshot(root, activeDocument.path, activeDocument.content)
        .then((nextSnapshot) => {
          if (cancelled) {
            return;
          }
          setSnapshot(nextSnapshot);
        })
        .catch(() => {
          if (cancelled) {
            return;
          }
          setSnapshot(null);
        })
        .finally(() => {
          if (cancelled) {
            return;
          }
          setLoading(false);
        });
    }, 260);

    return () => {
      cancelled = true;
      window.clearTimeout(timeout);
    };
  }, [adapter, activeDocument, root]);

  const problems = useMemo<WorkspaceProblemEntry[]>(() => {
    if (!snapshot) {
      return [];
    }

    const diagnosticProblems = snapshot.diagnostics.map((diagnostic, index) => ({
      id: `language:${snapshot.path}:${index}:${diagnostic.line}:${diagnostic.column}`,
      severity: diagnostic.severity,
      source: snapshot.serverLabel ?? snapshot.serviceLabel,
      title: diagnostic.title,
      detail: diagnostic.detail,
      path: diagnostic.path,
      line: diagnostic.line,
      column: diagnostic.column,
    }));

    if (snapshot.availability === "error" && snapshot.detail) {
      diagnosticProblems.unshift({
        id: `language:error:${snapshot.path}`,
        severity: "warning",
        source: snapshot.serverLabel ?? snapshot.serviceLabel,
        title: `${snapshot.serviceLabel} unavailable`,
        detail: snapshot.detail,
        path: snapshot.path,
        line: 1,
        column: 1,
      });
    }

    return diagnosticProblems.slice(0, 80);
  }, [snapshot]);

  return {
    snapshot,
    loading,
    problems,
  };
}
