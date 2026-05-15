import {
  workflowGithubPrCreatePlanStatus,
  workflowPackageNodeOutputStatus,
  workflowUniqueReceiptRefs,
  type WorkflowGithubPrCreatePlanSummary,
  type WorkflowPackageNodeOutputSummary,
} from "../../../runtime/workflow-rail-model";

function workflowPackageSummaryBoolean(value: boolean | null): string {
  if (value === true) return "true";
  if (value === false) return "false";
  return "";
}

function workflowPrCreateSummaryBoolean(value: boolean | null): string {
  if (value === true) return "true";
  if (value === false) return "false";
  return "";
}

export function WorkflowPackageOutputSummaryCard({
  summary,
  testId,
}: {
  summary: WorkflowPackageNodeOutputSummary;
  testId: string;
}) {
  const evidenceLabel =
    summary.packageEvidenceReady === true
      ? "evidence ready"
      : summary.packageEvidenceReady === false
        ? "evidence pending"
        : "evidence unknown";
  const localeLabel =
    summary.kind === "import"
      ? `${summary.sourceWorkflowChromeLocale ?? "default"} -> ${
          summary.importedWorkflowChromeLocale ?? "default"
        }`
      : (summary.workflowChromeLocale ?? "default");
  return (
    <article
      className={`workflow-output-row is-${workflowPackageNodeOutputStatus(
        summary,
      )}`}
      data-testid={testId}
      data-package-node-kind={summary.kind}
      data-package-tool-name={summary.toolName}
      data-package-status={summary.status}
      data-package-path={summary.packagePath ?? ""}
      data-package-manifest-path={summary.manifestPath ?? ""}
      data-package-readiness-status={summary.readinessStatus ?? ""}
      data-package-portable={workflowPackageSummaryBoolean(summary.portable)}
      data-package-evidence-ready={workflowPackageSummaryBoolean(
        summary.packageEvidenceReady,
      )}
      data-imported-workflow-path={summary.importedWorkflowPath ?? ""}
      data-workflow-chrome-locale={summary.workflowChromeLocale ?? ""}
      data-package-import-source-chrome-locale={
        summary.sourceWorkflowChromeLocale ?? ""
      }
      data-package-import-imported-chrome-locale={
        summary.importedWorkflowChromeLocale ?? ""
      }
      data-workflow-chrome-locale-preserved={workflowPackageSummaryBoolean(
        summary.workflowChromeLocalePreserved,
      )}
    >
      <strong>
        {summary.kind === "export"
          ? "Package export output"
          : "Package import output"}
      </strong>
      <span>
        {summary.status} · {summary.readinessStatus ?? "readiness pending"} ·{" "}
        {evidenceLabel}
      </span>
      <small>
        {summary.kind === "import"
          ? (summary.importedWorkflowPath ?? "imported workflow pending")
          : (summary.packagePath ?? "package path pending")}
      </small>
      <small>
        locale {localeLabel}
        {summary.kind === "import"
          ? ` · preserved ${
              summary.workflowChromeLocalePreserved === true ? "yes" : "review"
            }`
          : ` · portable ${
              summary.portable === true
                ? "yes"
                : summary.portable === false
                  ? "no"
                  : "unknown"
            }`}
      </small>
    </article>
  );
}

export function WorkflowGithubPrCreateOutputSummaryCard({
  summary,
  testId,
  receiptRefs = [],
  replayFixtureRef = null,
}: {
  summary: WorkflowGithubPrCreatePlanSummary;
  testId: string;
  receiptRefs?: string[];
  replayFixtureRef?: string | null;
}) {
  const allReceiptRefs = workflowUniqueReceiptRefs([
    summary.receiptId,
    ...receiptRefs,
  ]);
  const scopeLabel =
    summary.missingScopes.length > 0
      ? `missing ${summary.missingScopes.join(", ")}`
      : summary.scopeGranted === true
        ? "scope granted"
        : "scope pending";
  const mutationLabel =
    summary.mutationExecuted === true
      ? "mutation executed"
      : summary.mutationExecuted === false
        ? "mutation blocked"
        : "mutation pending";
  return (
    <article
      className={`workflow-output-row is-${workflowGithubPrCreatePlanStatus(
        summary,
      )}`}
      data-testid={testId}
      data-github-pr-create-tool-name={summary.toolName}
      data-github-pr-create-action={summary.action}
      data-github-pr-create-status={summary.status}
      data-github-pr-create-decision={summary.decision}
      data-github-pr-create-dry-run={workflowPrCreateSummaryBoolean(
        summary.dryRun,
      )}
      data-github-pr-create-preview-only={workflowPrCreateSummaryBoolean(
        summary.previewOnly,
      )}
      data-github-pr-create-mutation-attempted={workflowPrCreateSummaryBoolean(
        summary.mutationAttempted,
      )}
      data-github-pr-create-mutation-executed={workflowPrCreateSummaryBoolean(
        summary.mutationExecuted,
      )}
      data-github-pr-create-network-lookup={workflowPrCreateSummaryBoolean(
        summary.networkLookupPerformed,
      )}
      data-github-pr-create-request-method={summary.requestMethod ?? ""}
      data-github-pr-create-request-path={summary.requestPath ?? ""}
      data-github-pr-create-request-hash={summary.requestPayloadHash ?? ""}
      data-github-pr-create-request-body-included={workflowPrCreateSummaryBoolean(
        summary.requestBodyIncluded,
      )}
      data-github-pr-create-request-token-included={workflowPrCreateSummaryBoolean(
        summary.requestTokenIncluded,
      )}
      data-github-pr-create-repo={summary.repoFullName ?? ""}
      data-github-pr-create-base-branch={summary.baseBranch ?? ""}
      data-github-pr-create-head-branch={summary.headBranch ?? ""}
      data-github-pr-create-review-gate-status={
        summary.reviewGateStatus ?? ""
      }
      data-github-pr-create-review-satisfied={workflowPrCreateSummaryBoolean(
        summary.reviewSatisfied,
      )}
      data-github-pr-create-required-scopes={summary.requiredScopes.join("|")}
      data-github-pr-create-missing-scopes={summary.missingScopes.join("|")}
      data-github-pr-create-scope-granted={workflowPrCreateSummaryBoolean(
        summary.scopeGranted,
      )}
      data-github-pr-create-plan-id={summary.planId ?? ""}
      data-github-pr-create-receipt-id={summary.receiptId ?? ""}
      data-github-pr-create-receipt-refs={allReceiptRefs.join("|")}
      data-github-pr-create-replay-fixture-ref={replayFixtureRef ?? ""}
      data-github-pr-create-blockers={summary.blockers.join("|")}
      data-github-pr-create-evidence-refs={summary.evidenceRefs.join("|")}
    >
      <strong>GitHub PR create dry-run</strong>
      <span>
        {summary.status} · {mutationLabel} · {scopeLabel}
      </span>
      <small>
        {summary.requestPayloadHash ?? "request hash pending"}
        {" · "}
        {summary.reviewGateStatus ?? "review gate pending"}
        {" · "}
        {allReceiptRefs.length} receipt{allReceiptRefs.length === 1 ? "" : "s"}
      </small>
    </article>
  );
}
