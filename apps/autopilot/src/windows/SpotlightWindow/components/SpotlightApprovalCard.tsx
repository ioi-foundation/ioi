import React from "react";
import { icons } from "./Icons";
import "../styles/Chat.css";

interface ApprovalProps {
  title: string;
  description: string;
  risk: "low" | "medium" | "high";
  onApprove: () => void;
  onDeny: () => void;
}

export function SpotlightApprovalCard({ title, description, risk, onApprove, onDeny }: ApprovalProps) {
  const riskConfig = {
    high: { color: "#EF4444", bg: "rgba(239, 68, 68, 0.08)", label: "HIGH RISK" },
    medium: { color: "#F59E0B", bg: "rgba(245, 158, 11, 0.08)", label: "MEDIUM" },
    low: { color: "#10B981", bg: "rgba(16, 185, 129, 0.08)", label: "LOW RISK" },
  }[risk] || { color: "#6B7280", bg: "rgba(107, 114, 128, 0.08)", label: "UNKNOWN" };

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
        <div className="gate-actions">
          <button onClick={onApprove} className="gate-btn primary">{icons.check}<span>Authorize</span></button>
          <button onClick={onDeny} className="gate-btn secondary">{icons.x}<span>Deny</span></button>
        </div>
      </div>
    </div>
  );
}