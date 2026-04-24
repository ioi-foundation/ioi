export type CodeAwareSelectionContext = {
  startLineNumber: number;
  startColumn: number;
  endLineNumber: number;
  endColumn: number;
  selectedText?: string | null;
};

export type CodeAwareActionContext = {
  workspaceRoot: string | null;
  filePath?: string | null;
  selection?: CodeAwareSelectionContext | null;
  artifactId?: string | null;
  evidenceThreadId?: string | null;
  runId?: string | null;
  connectorId?: string | null;
  source?:
    | "palette"
    | "editor"
    | "explorer"
    | "workbench-view"
    | "workspace-runtime"
    | "artifact-source"
    | "artifact-render"
    | "validation";
};

export type CodeAwareBridgeRequestPayload = Record<string, unknown>;

function formatCodeAwareLocation(context: CodeAwareActionContext | null | undefined) {
  const parts = [
    context?.workspaceRoot ? `workspace ${context.workspaceRoot}` : null,
    context?.filePath ?? null,
    context?.artifactId ? `artifact ${context.artifactId}` : null,
    context?.runId ? `run ${context.runId}` : null,
  ].filter((value): value is string => Boolean(value));

  if (parts.length === 0) {
    return "the current workspace context";
  }

  return parts.join(" · ");
}

export function summarizeCodeAwareActionContext(
  context: CodeAwareActionContext | null | undefined,
) {
  if (!context) {
    return null;
  }

  return {
    workspaceRoot: context.workspaceRoot ?? null,
    filePath: context.filePath ?? null,
    runId: context.runId ?? null,
    artifactId: context.artifactId ?? null,
    evidenceThreadId: context.evidenceThreadId ?? null,
    connectorId: context.connectorId ?? null,
    hasSelection: Boolean(context.selection),
    source: context.source ?? null,
  };
}

export function buildExplainSelectionIntent(
  context: CodeAwareActionContext | null | undefined,
  selectedText?: string | null,
) {
  const selection = selectedText?.trim() ?? context?.selection?.selectedText?.trim() ?? "";
  if (selection) {
    return `Explain the selected code from ${formatCodeAwareLocation(context)}:\n\n${selection}`;
  }

  if (context?.filePath) {
    return `Review the current file: ${context.filePath}`;
  }

  return "Explain the current code selection.";
}

export function buildReviewFileIntent(
  context: CodeAwareActionContext | null | undefined,
) {
  if (context?.filePath) {
    const workspace = context.workspaceRoot
      ? ` in workspace ${context.workspaceRoot}`
      : "";
    return `Review the current file${workspace}: ${context.filePath}`;
  }

  return `Review ${formatCodeAwareLocation(context)}.`;
}

export function buildContextReviewIntent(
  context: CodeAwareActionContext | null | undefined,
) {
  if (context?.artifactId && context?.runId) {
    return `Review artifact ${context.artifactId} from run ${context.runId}.`;
  }

  if (context?.artifactId) {
    return `Review artifact ${context.artifactId}.`;
  }

  if (context?.runId) {
    return `Review run ${context.runId}.`;
  }

  return buildReviewFileIntent(context);
}

export function buildArtifactReviewIntent(
  context: CodeAwareActionContext | null | undefined,
) {
  if (context?.artifactId && context?.connectorId) {
    return `Review artifact ${context.artifactId} in the context of connector ${context.connectorId}.`;
  }

  if (context?.artifactId) {
    return `Review artifact ${context.artifactId}.`;
  }

  return buildContextReviewIntent(context);
}

export function buildRunReviewIntent(
  context: CodeAwareActionContext | null | undefined,
) {
  if (context?.runId && context?.artifactId) {
    return `Review run ${context.runId} and its linked artifact ${context.artifactId}.`;
  }

  if (context?.runId) {
    return `Review run ${context.runId}.`;
  }

  return buildContextReviewIntent(context);
}

export function buildArtifactSelectionIntent(
  target: {
    sourceSurface: string;
    path?: string | null;
    snippet: string;
  },
  context: CodeAwareActionContext | null | undefined,
) {
  const scope = target.path ?? context?.filePath ?? formatCodeAwareLocation(context);
  return `Edit only this artifact selection from ${target.sourceSurface}${scope ? ` (${scope})` : ""}:\n\n${target.snippet}`;
}

export function buildBrowserAutomationIntent(
  context: CodeAwareActionContext | null | undefined,
) {
  const scope = formatCodeAwareLocation(context);
  const selectedText = context?.selection?.selectedText?.trim();
  if (selectedText) {
    return `Use governed browser/computer-use to validate or remediate the selected code from ${scope}:\n\n${selectedText}`;
  }

  if (context?.filePath) {
    return `Use governed browser/computer-use to validate or remediate work related to ${context.filePath}.`;
  }

  return `Use governed browser/computer-use to validate or remediate ${scope}.`;
}
