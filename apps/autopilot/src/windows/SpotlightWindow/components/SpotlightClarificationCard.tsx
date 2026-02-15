import { useMemo, useState } from "react";
import { icons } from "./Icons";
import type { ClarificationRequest } from "../../../types";
import "../styles/Chat.css";

interface ClarificationCardProps {
  request: ClarificationRequest;
  onSubmit: (optionId: string, otherText: string) => Promise<void>;
  onCancel: () => void;
}

export function SpotlightClarificationCard({
  request,
  onSubmit,
  onCancel,
}: ClarificationCardProps) {
  const defaultOption = useMemo(
    () => request.options.find((option) => option.recommended)?.id || request.options[0]?.id || "",
    [request.options],
  );
  const [selectedOptionId, setSelectedOptionId] = useState(defaultOption);
  const [otherText, setOtherText] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const normalizeOtherInput = (value: string) =>
    value
      .trim()
      // Accept user shorthand like "#4: gnome-calculator" and keep only the payload.
      .replace(/^#?\d+\s*[:)\].-]?\s*/u, "")
      .trim();

  const handleSubmit = async () => {
    if (!selectedOptionId || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const normalizedOther = normalizeOtherInput(otherText);
      const hasCustomInput = request.allow_other && normalizedOther.length > 0;
      // If user provides custom text, treat it as an exact identifier flow by default.
      const effectiveOptionId =
        hasCustomInput && request.options.some((option) => option.id === "provide_exact")
          ? "provide_exact"
          : selectedOptionId;
      await onSubmit(effectiveOptionId, normalizedOther);
      setOtherText("");
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancel = () => {
    setOtherText("");
    setError(null);
    onCancel();
  };

  return (
    <div className="spot-clarification-card">
      <div className="gate-indicator" />
      <div className="gate-content">
        <div className="gate-header">
          <div className="gate-title-row">
            <span className="gate-icon">{icons.sparkles}</span>
            <span className="gate-title">Clarification Needed</span>
          </div>
          <span className="gate-badge">3 OPTIONS</span>
        </div>

        <p className="gate-desc">{request.question}</p>

        <div className="clarification-option-list">
          {request.options.map((option) => {
            const selected = selectedOptionId === option.id;
            return (
              <label
                key={option.id}
                className={`clarification-option ${selected ? "selected" : ""}`}
              >
                <input
                  type="radio"
                  name="clarification-option"
                  value={option.id}
                  checked={selected}
                  onChange={() => setSelectedOptionId(option.id)}
                  disabled={submitting}
                />
                <div className="clarification-option-content">
                  <div className="clarification-option-label-row">
                    <span className="clarification-option-label">{option.label}</span>
                    {option.recommended && (
                      <span className="clarification-option-recommended">Recommended</span>
                    )}
                  </div>
                  <div className="clarification-option-description">
                    {option.description}
                  </div>
                </div>
              </label>
            );
          })}
        </div>

        {request.allow_other && (
          <textarea
            className="spot-clarification-other"
            value={otherText}
            onChange={(e) => setOtherText(e.target.value)}
            placeholder="Optional: provide the exact app/package name or extra context."
            disabled={submitting}
            rows={3}
          />
        )}

        {error && <div className="spot-password-error">{error}</div>}

        <div className="gate-actions">
          <button
            onClick={() => void handleSubmit()}
            className="gate-btn primary"
            disabled={!selectedOptionId || submitting}
          >
            {icons.check}
            <span>{submitting ? "Submitting..." : "Submit Choice"}</span>
          </button>
          <button onClick={handleCancel} className="gate-btn secondary" disabled={submitting}>
            {icons.x}
            <span>Cancel</span>
          </button>
        </div>
      </div>
    </div>
  );
}
