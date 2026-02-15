import { useState } from "react";
import { icons } from "./Icons";
import "../styles/Chat.css";

interface PasswordCardProps {
  prompt: string;
  onSubmit: (password: string) => Promise<void>;
  onCancel: () => void;
}

export function SpotlightPasswordCard({
  prompt,
  onSubmit,
  onCancel,
}: PasswordCardProps) {
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async () => {
    if (!password || submitting) return;
    setSubmitting(true);
    setError(null);
    try {
      await onSubmit(password);
      setPassword("");
    } catch (e) {
      setError(String(e));
    } finally {
      setSubmitting(false);
    }
  };

  const handleCancel = () => {
    setPassword("");
    setError(null);
    onCancel();
  };

  return (
    <div className="spot-password-card">
      <div className="gate-indicator" />
      <div className="gate-content">
        <div className="gate-header">
          <div className="gate-title-row">
            <span className="gate-icon">{icons.lock}</span>
            <span className="gate-title">Sudo Password Required</span>
          </div>
          <span className="gate-badge">ONE-TIME</span>
        </div>
        <p className="gate-desc">{prompt}</p>
        <input
          type="password"
          className="spot-password-input"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          placeholder="Enter sudo password"
          autoComplete="off"
          disabled={submitting}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              void handleSubmit();
            }
          }}
        />
        {error && <div className="spot-password-error">{error}</div>}
        <div className="gate-actions">
          <button
            onClick={() => void handleSubmit()}
            className="gate-btn primary"
            disabled={!password || submitting}
          >
            {icons.check}
            <span>{submitting ? "Submitting..." : "Submit Password"}</span>
          </button>
          <button onClick={handleCancel} className="gate-btn secondary">
            {icons.x}
            <span>Cancel</span>
          </button>
        </div>
      </div>
    </div>
  );
}
