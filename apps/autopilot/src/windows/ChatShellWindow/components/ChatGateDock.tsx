import type {
  SessionClarificationRequest as ClarificationRequest,
  SessionCredentialRequest as CredentialRequest,
  SessionGateInfo as GateInfo,
} from "@ioi/agent-ide";
import { ChatApprovalCard } from "./ChatApprovalCard";
import { ChatPasswordCard } from "./ChatPasswordCard";
import { ChatClarificationCard } from "./ChatClarificationCard";

type ChatGateDockProps = {
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

export function ChatGateDock({
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
}: ChatGateDockProps) {
  const dockClassName = inline ? "spot-gate-stack" : "spot-gate-dock";

  return (
    <>
      {isGated && gateInfo && (
        <div className={dockClassName}>
          <ChatApprovalCard
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
          <ChatPasswordCard
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
          <ChatClarificationCard
            request={clarificationRequest}
            onSubmit={onSubmitClarification}
            onCancel={onCancelClarification}
          />
        </div>
      )}
    </>
  );
}
