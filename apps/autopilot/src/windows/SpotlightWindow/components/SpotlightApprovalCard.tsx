import React, { useEffect, useState } from "react";
import { icons } from "./Icons";
import "../styles/Chat.css";

interface ApprovalProps {
  title: string;
  description: string;
  risk: "low" | "medium" | "high";
  onApproveTransform: () => void;
  onDeny: () => void;
  onGrantScopedException?: () => void;
  approveLabel?: string;
  denyLabel?: string;
  showDeny?: boolean;
  deadlineMs?: number;
  targetLabel?: string;
  spanSummary?: string;
  classCounts?: Record<string, number>;
  severityCounts?: Record<string, number>;
  stage2Prompt?: string;
  targetId?: Record<string, unknown> | null;
  errorMessage?: string | null;
}

export function SpotlightApprovalCard({
  title,
  description,
  risk,
  onApproveTransform,
  onDeny,
  onGrantScopedException,
  approveLabel = "Approve",
  denyLabel = "Deny",
  showDeny = true,
  deadlineMs,
  targetLabel,
  spanSummary,
  classCounts,
  severityCounts,
  stage2Prompt,
  targetId,
  errorMessage,
}: ApprovalProps) {
  const riskConfig = {
    high: { color: "#EF4444", bg: "rgba(239, 68, 68, 0.08)", label: "HIGH RISK" },
    medium: { color: "#F59E0B", bg: "rgba(245, 158, 11, 0.08)", label: "MEDIUM" },
    low: { color: "#10B981", bg: "rgba(16, 185, 129, 0.08)", label: "LOW RISK" },
  }[risk] || { color: "#6B7280", bg: "rgba(107, 114, 128, 0.08)", label: "UNKNOWN" };
  const [remainingMs, setRemainingMs] = useState<number | null>(
    typeof deadlineMs === "number" ? Math.max(deadlineMs - Date.now(), 0) : null,
  );
  const [showDetails, setShowDetails] = useState(false);

  useEffect(() => {
    if (typeof deadlineMs !== "number") {
      setRemainingMs(null);
      return;
    }
    const tick = () => setRemainingMs(Math.max(deadlineMs - Date.now(), 0));
    tick();
    const handle = window.setInterval(tick, 1000);
    return () => window.clearInterval(handle);
  }, [deadlineMs]);

  return (
    <div className="spot-gate-card" style={{ "--gate-color": riskConfig.color, "--gate-bg": riskConfig.bg } as React.CSSProperties}>
      <div className="gate-indicator" />
      <div className="gate-content">
        <div className="gate-header">
          <div className="gate-title-row">
            <span className="gate-icon">{icons.alert}</span>
            <span className="gate-title">{title}</span>
          </div>
          <span className="gate-badge">{riskConfig.label}</span>
        </div>
        <p className="gate-desc">{description}</p>
        {remainingMs !== null && (
          <p className="gate-desc"><strong>Deadline:</strong> {Math.ceil(remainingMs / 1000)}s</p>
        )}
        {(targetLabel || spanSummary || stage2Prompt || targetId || classCounts || severityCounts) && (
          <>
            <button
              className="gate-details-toggle"
              onClick={() => setShowDetails((prev) => !prev)}
            >
              {showDetails ? "Hide details" : "Show details"}
            </button>
            {showDetails && (
              <div className="gate-details">
                {targetLabel && <p className="gate-desc"><strong>Target:</strong> {targetLabel}</p>}
                {spanSummary && <p className="gate-desc"><strong>Evidence:</strong> {spanSummary}</p>}
                {stage2Prompt && <p className="gate-desc"><strong>Prompt:</strong> {stage2Prompt}</p>}
                {classCounts && Object.keys(classCounts).length > 0 && (
                  <p className="gate-desc">
                    <strong>Classes:</strong>{" "}
                    {Object.entries(classCounts)
                      .map(([k, v]) => `${k}:${v}`)
                      .join(", ")}
                  </p>
                )}
                {severityCounts && Object.keys(severityCounts).length > 0 && (
                  <p className="gate-desc">
                    <strong>Severities:</strong>{" "}
                    {Object.entries(severityCounts)
                      .map(([k, v]) => `${k}:${v}`)
                      .join(", ")}
                  </p>
                )}
                {targetId && (
                  <pre className="gate-details-json">
                    {JSON.stringify(targetId, null, 2)}
                  </pre>
                )}
              </div>
            )}
          </>
        )}
        {errorMessage && <p className="gate-error">{errorMessage}</p>}
        <div className="gate-actions">
          <button onClick={onApproveTransform} className="gate-btn primary">{icons.check}<span>{approveLabel}</span></button>
          {onGrantScopedException && (
            <button onClick={onGrantScopedException} className="gate-btn secondary"><span>Grant Scoped Exception</span></button>
          )}
          {showDeny && (
            <button onClick={onDeny} className="gate-btn secondary">{icons.x}<span>{denyLabel}</span></button>
          )}
        </div>
      </div>
    </div>
  );
}
