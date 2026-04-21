import type {
  ArtifactHubViewKey,
  RunPresentation,
  SourceSummary,
} from "../../../types";
import type { TurnContext } from "../hooks/useTurnContexts";

export function formatLifecycleLabel(value: string | null | undefined): string {
  if (!value) {
    return "Pending";
  }

  return value
    .split(/[-_]+/g)
    .filter(Boolean)
    .map((part) => part[0]?.toUpperCase() + part.slice(1))
    .join(" ");
}

export function compactArtifactClassLabel(value: string): string {
  switch (value) {
    case "workspace_project":
    case "interactive_single_file":
    case "code_patch":
      return "Code";
    case "document":
      return "Document";
    case "visual":
      return "Visual";
    case "downloadable_file":
      return "File";
    case "compound_bundle":
    case "report_bundle":
      return "Bundle";
    default:
      return "Artifact";
  }
}

export function compactRendererLabel(value: string): string {
  switch (value) {
    case "html_iframe":
      return "HTML";
    case "jsx_sandbox":
      return "JSX";
    case "workspace_surface":
      return "Workspace";
    case "bundle_manifest":
      return "Bundle";
    case "download_card":
      return "Download";
    case "pdf_embed":
      return "PDF";
    default:
      return value
        .replace(/[_-]+/g, " ")
        .replace(/\b\w/g, (character) => character.toUpperCase());
  }
}

function preferredSourceLabels(sourceSummary: SourceSummary | null): string[] {
  if (!sourceSummary) {
    return [];
  }

  const seen = new Set<string>();
  const labels: string[] = [];
  const push = (value: string | null | undefined) => {
    const compact = String(value || "").replace(/\s+/g, " ").trim();
    if (!compact) {
      return;
    }
    const key = compact.toLowerCase();
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    labels.push(compact);
  };

  for (const browse of sourceSummary.browses) {
    const title = browse.title?.trim() || "";
    const titleSuffix = title.split(" - ").at(-1)?.trim() || "";
    push(titleSuffix && titleSuffix.length <= 48 ? titleSuffix : null);
    push(
      browse.domain
        .replace(/^www\./i, "")
        .replace(/^science\./i, "")
        .replace(/^news\./i, ""),
    );
    if (labels.length >= 3) {
      break;
    }
  }

  if (labels.length < 3) {
    for (const domain of sourceSummary.domains) {
      push(
        domain.domain
          .replace(/^www\./i, "")
          .replace(/^science\./i, "")
          .replace(/^news\./i, ""),
      );
      if (labels.length >= 3) {
        break;
      }
    }
  }

  return labels.slice(0, 3);
}

function joinLabels(labels: string[]): string | null {
  if (labels.length === 0) {
    return null;
  }
  if (labels.length === 1) {
    return labels[0] || null;
  }
  if (labels.length === 2) {
    return `${labels[0]} and ${labels[1]}`;
  }
  return `${labels[0]}, ${labels[1]}, and ${labels[2]}`;
}

function artifactSummaryLooksOperational(summary: string): boolean {
  const normalized = summary.trim().toLowerCase();
  if (!normalized) {
    return false;
  }
  return (
    normalized.includes("chat materialized")
    || normalized.includes("final acceptance validation")
    || normalized.includes("primary artifact view")
    || normalized.includes("lifecycle")
    || normalized.includes("verification cleared")
    || normalized.includes("candidate-")
    || normalized.includes("artifact view")
  );
}

export function artifactReplyText(turnContext: TurnContext | null): string | null {
  if (
    !turnContext ||
    turnContext.hasPendingArtifact ||
    turnContext.artifacts.length === 0
  ) {
    return null;
  }

  if (turnContext.artifacts.length === 1) {
    const artifact = turnContext.artifacts[0];
    if (!artifact) {
      return null;
    }
    const rawSummary =
      artifact.chatSession.verifiedReply.summary.trim() ||
      artifact.summary.trim();
    const summary = artifactSummaryLooksOperational(rawSummary) ? "" : rawSummary;
    const lifecycleState = String(artifact.lifecycleState || "")
      .trim()
      .toLowerCase();
    const failedLifecycle =
      lifecycleState === "blocked" || lifecycleState === "failed";

    if (failedLifecycle) {
      return summary.length > 0
        ? `I wasn’t able to land **${artifact.title}**. ${summary}`
        : `I wasn’t able to land **${artifact.title}**. Inspect the blocked artifact card below for details.`;
    }

    const sourceAttribution = joinLabels(preferredSourceLabels(turnContext.sourceSummary));
    if (summary.length > 0 && sourceAttribution) {
      return `I put together **${artifact.title}**. ${summary} It’s grounded in ${sourceAttribution}.`;
    }
    if (summary.length > 0) {
      return `I put together **${artifact.title}**. ${summary}`;
    }
    if (sourceAttribution) {
      return `I put together **${artifact.title}** and grounded it in ${sourceAttribution}.`;
    }
    return `I put together **${artifact.title}**. It’s ready in the artifact card below.`;
  }

  const failedArtifacts = turnContext.artifacts.filter((artifact) => {
    const lifecycleState = String(artifact.lifecycleState || "")
      .trim()
      .toLowerCase();
    return lifecycleState === "blocked" || lifecycleState === "failed";
  });
  if (failedArtifacts.length === turnContext.artifacts.length) {
    const previewTitles = failedArtifacts
      .slice(0, 3)
      .map((artifact) => `**${artifact.title}**`)
      .join(", ");
    const overflowCount =
      failedArtifacts.length - Math.min(failedArtifacts.length, 3);
    const overflowSuffix =
      overflowCount > 0 ? `, and ${overflowCount} more` : "";
    return `I wasn’t able to finish the requested artifacts: ${previewTitles}${overflowSuffix}. Inspect the artifact cards below for failure details.`;
  }

  const previewTitles = turnContext.artifacts
    .slice(0, 3)
    .map((artifact) => `**${artifact.title}**`)
    .join(", ");
  const overflowCount =
    turnContext.artifacts.length - Math.min(turnContext.artifacts.length, 3);
  const overflowSuffix = overflowCount > 0 ? `, and ${overflowCount} more` : "";

  return `I created ${turnContext.artifacts.length} artifacts for this request: ${previewTitles}${overflowSuffix}. Open one from the cards below.`;
}

export function operatorRunIsPending(turnContext: TurnContext | null): boolean {
  const status = turnContext?.chatSession?.activeOperatorRun?.status;
  const normalized = String(status || "")
    .trim()
    .toLowerCase();
  return (
    normalized === "active"
    || normalized === "pending"
    || normalized === "other"
  );
}

export function artifactTurnMetaLabel(
  artifact: NonNullable<TurnContext>["artifacts"][number],
): string {
  const lifecycleLabel = formatLifecycleLabel(
    artifact.lifecycleState || artifact.status,
  );
  const fileCountLabel = `${artifact.fileCount} ${
    artifact.fileCount === 1 ? "file" : "files"
  }`;
  const lifecycleState = String(artifact.lifecycleState || "")
    .trim()
    .toLowerCase();

  if (lifecycleState === "blocked" || lifecycleState === "failed") {
    return `${lifecycleLabel} · ${fileCountLabel}`;
  }

  return fileCountLabel;
}

export function inlineAnswerText(
  answer: NonNullable<RunPresentation["finalAnswer"]>,
): string {
  const display = answer.displayText.trim();
  if (display.length > 0) {
    return display;
  }
  return answer.message.text;
}

export type { ArtifactHubViewKey };
