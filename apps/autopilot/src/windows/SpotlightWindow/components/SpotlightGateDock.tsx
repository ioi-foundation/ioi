import type {
  ClarificationRequest,
  CredentialRequest,
  GateInfo,
} from "../../../types";
import { SpotlightApprovalCard } from "./SpotlightApprovalCard";
import { SpotlightPasswordCard } from "./SpotlightPasswordCard";
import { SpotlightClarificationCard } from "./SpotlightClarificationCard";

type SpotlightGateDockProps = {
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
  return (
    <>
      {isGated && gateInfo && (
        <div className="spot-gate-dock">
          <SpotlightApprovalCard
            title={gateInfo.title}
            description={gateInfo.description}
            risk={gateInfo.risk}
            approveLabel={gateInfo.approve_label || (isPiiGate ? "Approve Transform" : "Approve action")}
            showDeny={true}
            denyLabel={gateInfo.deny_label || "Deny action"}
            deadlineMs={gateDeadlineMs}
            targetLabel={gateInfo.pii?.target_label}
            spanSummary={gateInfo.pii?.span_summary}
            classCounts={gateInfo.pii?.class_counts}
            severityCounts={gateInfo.pii?.severity_counts}
            stage2Prompt={gateInfo.pii?.stage2_prompt}
            targetId={(gateInfo.pii?.target_id as Record<string, unknown> | null) ?? null}
            errorMessage={gateActionError}
            onApproveTransform={onApprove}
            onGrantScopedException={isPiiGate ? onGrantScopedException : undefined}
            onDeny={onDeny}
          />
        </div>
      )}

      {showPasswordPrompt && (
        <div className="spot-gate-dock">
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
        <div className="spot-gate-dock">
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
