import { workflowUniqueReceiptRefs } from "../../../runtime/workflow-rail-model";
import { workflowHarnessPackageDeepLinkTarget } from "./statusPrimitives";
import type {
  WorkflowSettingsHarnessActivationProps,
  WorkflowSettingsHarnessCallbacks,
  WorkflowSettingsHarnessPackageRestoreProps,
} from "./settingsHarnessTypes";

export interface WorkflowSettingsHarnessPackageEvidenceRowsPanelProps
  extends
    Pick<
      WorkflowSettingsHarnessActivationProps,
      | "selectedHarnessActivationGateEvidenceRef"
      | "selectedHarnessActivationGateNodeAttemptId"
      | "selectedHarnessActivationGateReceiptRef"
      | "selectedHarnessActivationGateReplayFixtureRef"
    >,
    Pick<
      WorkflowSettingsHarnessPackageRestoreProps,
      | "harnessPackageDeepLinks"
      | "harnessPackageEvidenceReviewRows"
      | "harnessPackageForkMutationCanary"
      | "harnessPackageForkMutationCanaryNodeAttemptIds"
      | "harnessPackageForkMutationCanaryReceiptRefs"
      | "harnessPackageForkMutationCanaryReplayFixtureRefs"
    >,
    Pick<
      WorkflowSettingsHarnessCallbacks,
      | "onCopyHarnessDeepLink"
      | "onSelectHarnessReceiptRef"
      | "onSelectHarnessReplayFixtureRef"
    > {}

export function WorkflowSettingsHarnessPackageEvidenceRowsPanel({
  harnessPackageDeepLinks,
  harnessPackageEvidenceReviewRows,
  harnessPackageForkMutationCanary,
  harnessPackageForkMutationCanaryNodeAttemptIds,
  harnessPackageForkMutationCanaryReceiptRefs,
  harnessPackageForkMutationCanaryReplayFixtureRefs,
  selectedHarnessActivationGateEvidenceRef,
  selectedHarnessActivationGateNodeAttemptId,
  selectedHarnessActivationGateReceiptRef,
  selectedHarnessActivationGateReplayFixtureRef,
  onCopyHarnessDeepLink,
  onSelectHarnessReceiptRef,
  onSelectHarnessReplayFixtureRef,
}: WorkflowSettingsHarnessPackageEvidenceRowsPanelProps) {
  return (
    <>
      <h4>Package evidence</h4>
      {harnessPackageEvidenceReviewRows.map((row) => {
        const rowRefs = workflowUniqueReceiptRefs(row.refs);
        return (
          <article
            key={row.id}
            className={`workflow-test-row is-${
              row.ready ? "passed" : "blocked"
            }`}
            data-testid={`workflow-harness-package-evidence-row-${row.id}`}
            data-package-evidence-row-id={row.id}
            data-package-evidence-row-status={row.ready ? "passed" : "blocked"}
            data-package-evidence-ref-kind={row.kind}
            data-package-evidence-ref-count={rowRefs.length}
          >
            <strong>{row.label}</strong>
            <span>
              {row.ready ? "ready" : "missing"} · {row.value}
            </span>
            <small>{row.detail}</small>
            <div
              className="workflow-harness-authority-gate-actions"
              data-testid={`workflow-harness-package-evidence-row-refs-${row.id}`}
              data-package-evidence-refs={rowRefs.join("|")}
            >
              {rowRefs.slice(0, 6).map((ref, index) => {
                const packageLink =
                  row.kind === "package_deep_link"
                    ? (harnessPackageDeepLinks.find(
                        (link) => link?.ref === ref,
                      ) ?? null)
                    : null;
                return (
                  <button
                    type="button"
                    key={`${row.id}-${ref}-${index}`}
                    className={`workflow-harness-ref-button ${
                      selectedHarnessActivationGateEvidenceRef === ref ||
                      selectedHarnessActivationGateReceiptRef === ref ||
                      selectedHarnessActivationGateReplayFixtureRef === ref ||
                      selectedHarnessActivationGateNodeAttemptId === ref
                        ? "is-active"
                        : ""
                    }`}
                    data-testid={`workflow-harness-package-evidence-row-ref-${row.id}-${index}`}
                    data-package-evidence-ref-kind={row.kind}
                    data-package-evidence-ref={ref}
                    data-harness-package-deep-link-kind={
                      packageLink?.kind ?? ""
                    }
                    data-harness-package-deep-link-hash={
                      packageLink?.hash ?? ""
                    }
                    disabled={
                      !onCopyHarnessDeepLink &&
                      row.kind !== "receipt" &&
                      row.kind !== "replay"
                    }
                    onClick={() => {
                      if (row.kind === "mutation_canary") {
                        onCopyHarnessDeepLink?.({
                          panel: "settings",
                          activationGateId: "mutation-canary",
                          activationGateEvidenceRef:
                            harnessPackageForkMutationCanary?.canaryId ?? ref,
                          activationGateReceiptRef:
                            harnessPackageForkMutationCanaryReceiptRefs[0],
                          receiptRef:
                            harnessPackageForkMutationCanaryReceiptRefs[0],
                          activationGateReplayFixtureRef:
                            harnessPackageForkMutationCanaryReplayFixtureRefs[0],
                          replayFixtureRef:
                            harnessPackageForkMutationCanaryReplayFixtureRefs[0],
                          activationGateNodeAttemptId:
                            harnessPackageForkMutationCanaryNodeAttemptIds[0],
                          nodeAttemptId:
                            harnessPackageForkMutationCanaryNodeAttemptIds[0],
                        });
                        return;
                      }
                      if (row.kind === "receipt") {
                        onCopyHarnessDeepLink
                          ? onCopyHarnessDeepLink({
                              panel: "settings",
                              activationGateId: "package-evidence",
                              activationGateReceiptRef: ref,
                              receiptRef: ref,
                            })
                          : onSelectHarnessReceiptRef?.(ref);
                        return;
                      }
                      if (row.kind === "replay") {
                        onCopyHarnessDeepLink
                          ? onCopyHarnessDeepLink({
                              panel: "settings",
                              activationGateId: "package-evidence",
                              activationGateReplayFixtureRef: ref,
                              replayFixtureRef: ref,
                            })
                          : onSelectHarnessReplayFixtureRef?.(ref);
                        return;
                      }
                      if (row.kind === "node_attempt") {
                        onCopyHarnessDeepLink?.({
                          panel: "settings",
                          activationGateId: "package-evidence",
                          activationGateNodeAttemptId: ref,
                          nodeAttemptId: ref,
                        });
                        return;
                      }
                      if (row.kind === "package_deep_link") {
                        const target =
                          workflowHarnessPackageDeepLinkTarget(packageLink);
                        if (target) {
                          onCopyHarnessDeepLink?.(target);
                        }
                        return;
                      }
                      onCopyHarnessDeepLink?.({
                        panel: "settings",
                        activationGateId: "package-evidence",
                        activationGateEvidenceRef: ref,
                      });
                    }}
                  >
                    <code>{ref}</code>
                  </button>
                );
              })}
              {rowRefs.length === 0 ? (
                <span
                  data-testid={`workflow-harness-package-evidence-row-missing-${row.id}`}
                >
                  Missing {row.label.toLowerCase()}
                </span>
              ) : null}
            </div>
          </article>
        );
      })}
    </>
  );
}
