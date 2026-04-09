import type {
  SessionClarificationRequest as ClarificationRequest,
  SessionCredentialRequest as CredentialRequest,
  SessionGateInfo as GateInfo,
} from "@ioi/agent-ide";
import { SpotlightApprovalCard } from "./SpotlightApprovalCard";
import { SpotlightPasswordCard } from "./SpotlightPasswordCard";
import { SpotlightClarificationCard } from "./SpotlightClarificationCard";

type SpotlightGateDockProps = {
  inline?: boolean;
  isGated: boolean;
  gateInfo?: GateInfo;
  isPiiGate: boolean;
  gateDeadlineMs?: number;
  gateActionError: string | null;
  onApprove: () => void;
  onGrantScopedException: () => void;
  onDeny: () => void;
  showPasswordPrompt: boolean;
  credentialRequest?: CredentialRequest;
  onSubmitRuntimePassword: (password: string) => Promise<void>;
  onCancelRuntimePassword: () => void;
  showClarificationPrompt: boolean;
  clarificationRequest?: ClarificationRequest;
  onSubmitClarification: (optionId: string, otherText: string) => Promise<void>;
  onCancelClarification: () => void;
};

export function SpotlightGateDock({
  inline = false,
  isGated,
  gateInfo,
  isPiiGate,
  gateDeadlineMs,
  gateActionError,
  onApprove,
  onGrantScopedException,
  onDeny,
  showPasswordPrompt,
  credentialRequest,
  onSubmitRuntimePassword,
  onCancelRuntimePassword,
  showClarificationPrompt,
  clarificationRequest,
  onSubmitClarification,
  onCancelClarification,
}: SpotlightGateDockProps) {
  const dockClassName = inline ? "spot-gate-stack" : "spot-gate-dock";

  return (
    <>
      {isGated && gateInfo && (
        <div className={dockClassName}>
          <SpotlightApprovalCard
            title={gateInfo.title}
            description={gateInfo.description}
            risk={gateInfo.risk}
            approveLabel={gateInfo.approve_label || (isPiiGate ? "Approve Transform" : "Approve action")}
            showDeny={true}
            denyLabel={gateInfo.deny_label || "Deny action"}
            deadlineMs={gateDeadlineMs}
            surfaceLabel={gateInfo.surface_label}
            scopeLabel={gateInfo.scope_label}
            operationLabel={gateInfo.operation_label}
            targetLabel={gateInfo.target_label || gateInfo.pii?.target_label}
            operatorNote={gateInfo.operator_note}
            spanSummary={gateInfo.pii?.span_summary}
            classCounts={gateInfo.pii?.class_counts}
            severityCounts={gateInfo.pii?.severity_counts}
            stage2Prompt={gateInfo.pii?.stage2_prompt}
            targetId={
              (gateInfo.pii?.target_id as Record<string, unknown> | null) ??
              null
            }
            errorMessage={gateActionError}
            onApproveTransform={onApprove}
            onGrantScopedException={isPiiGate ? onGrantScopedException : undefined}
            onDeny={onDeny}
          />
        </div>
      )}

      {showPasswordPrompt && (
        <div className={dockClassName}>
          <SpotlightPasswordCard
            prompt={
              credentialRequest?.prompt ||
              "A one-time sudo password is required to continue."
            }
            onSubmit={onSubmitRuntimePassword}
            onCancel={onCancelRuntimePassword}
          />
        </div>
      )}

      {showClarificationPrompt && clarificationRequest && (
        <div className={dockClassName}>
          <SpotlightClarificationCard
            request={clarificationRequest}
            onSubmit={onSubmitClarification}
            onCancel={onCancelClarification}
          />
        </div>
      )}
    </>
  );
}
