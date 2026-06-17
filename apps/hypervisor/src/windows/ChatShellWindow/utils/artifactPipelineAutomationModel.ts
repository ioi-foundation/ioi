import type {
  ArtifactHubViewKey,
  LocalEngineStagedOperation,
} from "../../../types";
import type { DurabilityEvidenceOverview } from "./durabilityEvidenceModel";
import type { PrivacyEvidenceOverview } from "./privacyEvidenceModel";
import type { PromotionTarget } from "./promotionStageModel";
import type { RetainedPortfolioDossier } from "./retainedPortfolioDossierModel";
import type { SavedBundleProofOverview } from "./savedBundleProofModel";

export type ArtifactPipelineAutomationTone = "ready" | "review" | "setup";
export type ArtifactPipelineAutomationActionKind =
  | "export_recommended_pack"
  | "review_privacy"
  | "review_durability"
  | "stage_promotion"
  | "none";

export interface ArtifactPipelineAutomationQueuedAction {
  kind: Exclude<ArtifactPipelineAutomationActionKind, "none">;
  label: string;
  recommendedView: ArtifactHubViewKey | null;
  promotionTarget: PromotionTarget | null;
  detail: string;
}

export interface ArtifactPipelineAutomationPlan {
  tone: ArtifactPipelineAutomationTone;
  statusLabel: string;
  detail: string;
  actionKind: ArtifactPipelineAutomationActionKind;
  primaryActionLabel: string | null;
  recommendedView: ArtifactHubViewKey | null;
  promotionTarget: PromotionTarget | null;
  checklist: string[];
  queuedActions: ArtifactPipelineAutomationQueuedAction[];
}

function isReviewLabel(value: string): boolean {
  return /review pending|local-only|degraded|stale|recommended/i.test(value);
}

function stagedPromotionCount(
  stagedOperations: LocalEngineStagedOperation[],
  target: PromotionTarget,
): number {
  const subjectKind =
    target === "sas.xyz" ? "service_candidate" : "ioi_cli_domain_release";
  return stagedOperations.filter(
    (operation) =>
      operation.subjectKind === subjectKind ||
      operation.subjectId === target,
  ).length;
}

export function buildArtifactPipelineAutomationPlan(input: {
  dossier: RetainedPortfolioDossier;
  savedBundleProof: SavedBundleProofOverview;
  privacyOverview: PrivacyEvidenceOverview;
  durabilityOverview: DurabilityEvidenceOverview;
  stagedOperations?: LocalEngineStagedOperation[];
}): ArtifactPipelineAutomationPlan {
  const stagedOperations = input.stagedOperations ?? [];
  const sasStagedCount = stagedPromotionCount(stagedOperations, "sas.xyz");
  const cliStagedCount = stagedPromotionCount(stagedOperations, "IOI CLI");
  const checklist = [
    `Recommended pack: ${input.dossier.recommendedVariantLabel}`,
    `Saved proof: ${input.savedBundleProof.statusLabel}`,
    `Privacy: ${input.privacyOverview.statusLabel}`,
    `Durability: ${input.durabilityOverview.statusLabel}`,
    `${sasStagedCount} sas.xyz staged`,
    `${cliStagedCount} IOI CLI staged`,
  ];

  if (
    input.savedBundleProof.tone !== "ready" ||
    !input.dossier.latestExportMatchesRecommendation
  ) {
    const queuedActions: ArtifactPipelineAutomationQueuedAction[] = [
      {
        kind: "export_recommended_pack",
        label: input.dossier.latestExportMatchesRecommendation
          ? "Refresh recommended pack"
          : "Export recommended pack",
        recommendedView: null,
        promotionTarget: null,
        detail:
          input.savedBundleProof.tone === "setup"
            ? `Export the ${input.dossier.recommendedVariantLabel.toLowerCase()} so the saved bundle proof catches up with the dossier recommendation.`
            : `The latest saved pack does not match the dossier recommendation, so refreshing the ${input.dossier.recommendedVariantLabel.toLowerCase()} is the next safest artifact move.`,
      },
    ];
    return {
      tone: input.savedBundleProof.tone === "setup" ? "setup" : "review",
      statusLabel: "Recommended pack should be refreshed",
      detail: queuedActions[0].detail,
      actionKind: queuedActions[0].kind,
      primaryActionLabel: queuedActions[0].label,
      recommendedView: null,
      promotionTarget: null,
      checklist,
      queuedActions,
    };
  }

  if (
    input.dossier.recommendedVariant === "redacted_share" ||
    isReviewLabel(input.privacyOverview.statusLabel)
  ) {
    const queuedActions: ArtifactPipelineAutomationQueuedAction[] = [
      {
        kind: "review_privacy",
        label: "Review privacy posture",
        recommendedView: "privacy",
        promotionTarget: null,
        detail:
          "The current dossier still points at a redacted or privacy-constrained share path, so review privacy posture before wider promotion or operator packaging.",
      },
    ];
    return {
      tone: "review",
      statusLabel: "Privacy review should lead the next artifact move",
      detail: queuedActions[0].detail,
      actionKind: queuedActions[0].kind,
      primaryActionLabel: queuedActions[0].label,
      recommendedView: queuedActions[0].recommendedView,
      promotionTarget: null,
      checklist,
      queuedActions,
    };
  }

  if (
    input.dossier.readiness === "review" ||
    isReviewLabel(input.durabilityOverview.statusLabel)
  ) {
    const queuedActions: ArtifactPipelineAutomationQueuedAction[] = [
      {
        kind: "review_durability",
        label: "Review durability posture",
        recommendedView: "compact",
        promotionTarget: null,
        detail:
          "Saved bundle proof is present, but retained durability posture still needs review before the artifact path should automatically advance toward promotion.",
      },
    ];
    return {
      tone: "review",
      statusLabel: "Durability review should lead the next artifact move",
      detail: queuedActions[0].detail,
      actionKind: queuedActions[0].kind,
      primaryActionLabel: queuedActions[0].label,
      recommendedView: queuedActions[0].recommendedView,
      promotionTarget: null,
      checklist,
      queuedActions,
    };
  }

  if (
    input.dossier.readiness === "ready" &&
    input.savedBundleProof.tone === "ready"
  ) {
    const queuedActions: ArtifactPipelineAutomationQueuedAction[] = [];
    if (sasStagedCount === 0) {
      queuedActions.push({
        kind: "stage_promotion",
        label: "Stage sas.xyz candidate",
        recommendedView: "review",
        promotionTarget: "sas.xyz",
        detail:
          "Replay evidence, retained portfolio posture, and saved bundle proof are aligned, so the artifact path can now stage a `sas.xyz` candidate without leaving the canonical export flow.",
      });
    }
    if (cliStagedCount === 0) {
      queuedActions.push({
        kind: "stage_promotion",
        label: "Stage IOI CLI promotion",
        recommendedView: "review",
        promotionTarget: "IOI CLI",
        detail:
          "The same retained dossier and saved bundle proof are strong enough to carry an IOI CLI domain productionization review once the promotion queue advances past the service-candidate lane.",
      });
    }

    const [primaryAction] = queuedActions;
    if (primaryAction) {
      return {
        tone: "ready",
        statusLabel:
          queuedActions.length > 1
            ? "Promotion queue ready"
            : primaryAction.promotionTarget === "IOI CLI"
              ? "IOI CLI staging is now the next safe move"
              : "Service-candidate staging is now the next safe move",
        detail:
          queuedActions.length > 1
            ? `There are ${queuedActions.length} evidence-preserving promotion steps ready. Start with ${primaryAction.label.toLowerCase()} and keep the same dossier attached as the queue advances toward IOI CLI.`
            : primaryAction.detail,
        actionKind: primaryAction.kind,
        primaryActionLabel: primaryAction.label,
        recommendedView: primaryAction.recommendedView,
        promotionTarget: primaryAction.promotionTarget,
        checklist,
        queuedActions,
      };
    }

    return {
      tone: "ready",
      statusLabel: "Promotion queue is already staged",
      detail:
        "Replay evidence, retained portfolio posture, and saved bundle proof are already staged into both promotion lanes, so artifact automation does not need another queue step right now.",
      actionKind: "none",
      primaryActionLabel: null,
      recommendedView: "thoughts",
      promotionTarget: null,
      checklist,
      queuedActions,
    };
  }

  return {
    tone: "ready",
    statusLabel: "Artifact automation has no pending action",
    detail:
      "The artifact path is already aligned enough that no automatic export, review, or promotion step is being recommended right now.",
    actionKind: "none",
    primaryActionLabel: null,
    recommendedView: null,
    promotionTarget: null,
    checklist,
    queuedActions: [],
  };
}
