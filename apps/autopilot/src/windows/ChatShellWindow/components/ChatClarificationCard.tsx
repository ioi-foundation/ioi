import { useEffect, useMemo, useState } from "react";
import type { SessionClarificationRequest as ClarificationRequest } from "@ioi/agent-ide";
import { icons } from "../../../components/ui/icons";
import "../../ChatShellWindow/styles/Chat.css";

interface ClarificationCardProps {
  request: ClarificationRequest;
  onSubmit: (optionId: string, otherText: string) => Promise<void>;
  onCancel: () => void;
}

export function ChatClarificationCard({
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
    if (submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      const normalizedOther = normalizeOtherInput(otherText);
      const hasCustomInput = request.allow_other && normalizedOther.length > 0;
      const canUseSelected = selectedOptionId.length > 0;
      if (!canUseSelected && !hasCustomInput) {
        setSubmitting(false);
        return;
      }
      // If user provides custom text, treat it as an exact identifier flow by default.
      const effectiveOptionId = hasCustomInput
        ? request.options.some((option) => option.id === "provide_exact")
          ? "provide_exact"
          : "custom_input"
        : canUseSelected
          ? selectedOptionId
          : "custom_input";
      await onSubmit(effectiveOptionId, normalizedOther);
      setOtherText("");
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  };

  const canSubmit =
    !!selectedOptionId || (request.allow_other && normalizeOtherInput(otherText).length > 0);

  const handleCancel = () => {
    setOtherText("");
    setError(null);
    onCancel();
  };

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (submitting) {
        return;
      }

      const target = event.target;
      const targetIsTextarea = target instanceof HTMLTextAreaElement;
      const submitWithModifier =
        event.key === "Enter" && (event.metaKey || event.ctrlKey);
      const submitWithoutModifier =
        event.key === "Enter" &&
        !event.shiftKey &&
        !event.metaKey &&
        !event.ctrlKey &&
        !event.altKey &&
        !targetIsTextarea;

      if ((submitWithModifier || submitWithoutModifier) && canSubmit) {
        event.preventDefault();
        void handleSubmit();
        return;
      }

      if (event.key === "Escape") {
        event.preventDefault();
        handleCancel();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [canSubmit, submitting, handleCancel, handleSubmit]);

  return (
    <div className="spot-clarification-card">
      <div className="gate-indicator" />
      <div className="gate-content">
        <div className="gate-header">
          <div className="gate-title-row">
            <span className="gate-icon">{icons.sparkles}</span>
            <span className="gate-title">Clarification Needed</span>
          </div>
          <span className="gate-badge">
            {request.options.length > 0
              ? `${request.options.length} OPTIONS`
              : "CUSTOM INPUT"}
          </span>
        </div>

        <p className="gate-desc">{request.question}</p>

        {request.options.length > 0 && (
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
        )}

        {request.allow_other && (
          <textarea
            className="spot-clarification-other"
            value={otherText}
            onChange={(e) => setOtherText(e.target.value)}
            placeholder="Provide the exact target identifier or extra context."
            disabled={submitting}
            rows={3}
          />
        )}

        {error && <div className="spot-password-error">{error}</div>}

        <div className="gate-actions">
          <button
            onClick={() => void handleSubmit()}
            className="gate-btn primary"
            disabled={!canSubmit || submitting}
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
