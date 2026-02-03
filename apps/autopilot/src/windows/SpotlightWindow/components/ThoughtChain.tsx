import React, { useState, useEffect } from "react";
import { ChatMessage } from "../../../types";
import { ThinkingOrb } from "./ThinkingOrb";
import { icons } from "./Icons";
import "../styles/Chat.css";

export function ThoughtChain({ messages, isThinking = false }: { messages: ChatMessage[]; isThinking?: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const hasError = messages.some((m) => m.text.toLowerCase().includes("error") || m.text.toLowerCase().includes("fail"));

  useEffect(() => { if (hasError) setExpanded(true); }, [hasError]);

  return (
    <div className={`thought-chain ${expanded ? "expanded" : ""} ${hasError ? "has-error" : ""} ${isThinking ? "thinking" : ""}`}>
      <button className="thought-header" onClick={() => setExpanded(!expanded)} type="button">
        <div className="thought-title-group">
          {isThinking ? <ThinkingOrb isActive /> : hasError ? <span className="thought-icon error">{icons.alert}</span> : <span className="thought-icon success">{icons.check}</span>}
          <span className="thought-title">{isThinking ? "Thinking..." : hasError ? "Error" : "Reasoning"}</span>
        </div>
        <div className="thought-meta-group">
          <span className="thought-meta">{messages.length} steps</span>
          <span className={`thought-chevron ${expanded ? "open" : ""}`}>{icons.chevron}</span>
        </div>
      </button>
      <div className="thought-content">
        <div className="thought-timeline">
          {messages.map((m, i) => (
            <div key={i} className="thought-step">
              <div className="step-connector">
                <div className="step-dot" />
                {i < messages.length - 1 && <div className="step-line" />}
              </div>
              <div className="step-content">
                <span className="step-role">{m.role}</span>
                <span className="step-text">{m.text}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}