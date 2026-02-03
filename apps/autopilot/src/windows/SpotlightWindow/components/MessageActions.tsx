import React, { useState } from "react";
import { icons } from "./Icons";
import "../styles/Chat.css";

export function MessageActions({ text, onRetry, showRetry = false }: { text: string; onRetry?: () => void; showRetry?: boolean }) {
  const [copied, setCopied] = useState(false);
  const [feedback, setFeedback] = useState<'up' | 'down' | null>(null);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="message-actions">
      <button className={`message-action-btn ${copied ? "success" : ""}`} onClick={handleCopy} title="Copy (⌘C)">
        {copied ? icons.check : icons.copy}
      </button>
      {showRetry && onRetry && (
        <button className="message-action-btn" onClick={onRetry} title="Retry (⌘R)">
          {icons.retry}
        </button>
      )}
      <button 
        className={`message-action-btn ${feedback === 'up' ? "active" : ""}`} 
        onClick={() => setFeedback(f => f === 'up' ? null : 'up')}
        title="Good response"
      >
        {icons.thumbUp}
      </button>
      <button 
        className={`message-action-btn ${feedback === 'down' ? "active" : ""}`}
        onClick={() => setFeedback(f => f === 'down' ? null : 'down')}
        title="Bad response"
      >
        {icons.thumbDown}
      </button>
    </div>
  );
}