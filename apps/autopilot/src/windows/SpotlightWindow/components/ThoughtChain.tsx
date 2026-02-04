// apps/autopilot/src/windows/SpotlightWindow/components/ThoughtChain.tsx

import React, { useState, useEffect } from "react";
import { ChatMessage } from "../../../types";

interface ThoughtChainProps {
  messages: ChatMessage[];
  activeStep?: string | null;
  agentName?: string;
  generation?: number;
  progress?: number;
  totalSteps?: number;
}

// Chevron icon component
const ChevronIcon = () => (
  <svg 
    width="12" 
    height="12" 
    viewBox="0 0 20 20" 
    fill="currentColor" 
    xmlns="http://www.w3.org/2000/svg"
    aria-hidden="true"
  >
    <path d="M14.128 7.16482C14.3126 6.95983 14.6298 6.94336 14.835 7.12771C15.0402 7.31242 15.0567 7.62952 14.8721 7.83477L10.372 12.835L10.2939 12.9053C10.2093 12.9667 10.1063 13 9.99995 13C9.85833 12.9999 9.72264 12.9402 9.62788 12.835L5.12778 7.83477L5.0682 7.75273C4.95072 7.55225 4.98544 7.28926 5.16489 7.12771C5.34445 6.96617 5.60969 6.95939 5.79674 7.09744L5.87193 7.16482L9.99995 11.7519L14.128 7.16482Z" />
  </svg>
);

// Pulsing dot for active state
const PulsingDot = () => (
  <span className="thought-pulse" />
);

// Generate a summary of what the agent is doing/did
function generateSummary(
  messages: ChatMessage[], 
  activeStep?: string | null,
  isActive?: boolean
): string {
  if (isActive && activeStep) {
    const step = activeStep.toLowerCase();
    if (step.includes("search") || step.includes("brows")) {
      return "Searching the web...";
    }
    if (step.includes("read") || step.includes("analyz")) {
      return "Analyzing information...";
    }
    if (step.includes("writ") || step.includes("generat")) {
      return "Generating response...";
    }
    if (step.includes("code") || step.includes("script")) {
      return "Writing code...";
    }
    if (step.includes("think") || step.includes("reason")) {
      return "Thinking through the problem...";
    }
    if (step.includes("plan")) {
      return "Planning approach...";
    }
    return activeStep;
  }

  // Completed state - summarize what was done
  if (messages.length === 0) {
    return "Processing...";
  }

  const toolCalls = messages.filter(m => m.role === "tool");
  
  if (toolCalls.length > 0) {
    if (toolCalls.length === 1) {
      const toolText = toolCalls[0].text || "";
      if (toolText.toLowerCase().includes("search")) return "Searched the web";
      if (toolText.toLowerCase().includes("code")) return "Executed code";
      if (toolText.toLowerCase().includes("file")) return "Processed file";
      return "Completed task";
    }
    return `Completed ${toolCalls.length} steps`;
  }

  return `Processed ${messages.length} operations`;
}

export function ThoughtChain({ 
  messages, 
  activeStep, 
  agentName,
  generation,
  progress,
  totalSteps 
}: ThoughtChainProps) {
  const [isExpanded, setIsExpanded] = useState(false);
  const isActive = !!activeStep;
  
  // Auto-expand on error
  useEffect(() => {
    const hasError = messages.some(m => 
      m.text?.toLowerCase().includes("error") || 
      m.text?.toLowerCase().includes("failed")
    );
    if (hasError) setIsExpanded(true);
  }, [messages]);

  const summary = generateSummary(messages, activeStep, isActive);
  
  // Format metadata string
  const metadata = [
    agentName || "Agent",
    generation !== undefined ? `Gen ${generation}` : null,
    totalSteps ? `${progress || 0}/${totalSteps}` : null,
  ].filter(Boolean).join(" · ");

  return (
    <div className="thought-chain">
      {/* Minimal Header Button */}
      <button 
        className="thought-header"
        onClick={() => setIsExpanded(!isExpanded)}
        type="button"
      >
        <div className="thought-header-inner">
          {isActive && <PulsingDot />}
          <span className={`thought-summary ${isActive ? "active" : ""}`}>
            {summary}
          </span>
          <span className={`thought-chevron ${isExpanded ? "expanded" : ""}`}>
            <ChevronIcon />
          </span>
        </div>
      </button>

      {/* Expandable Content */}
      <div className={`thought-content ${isExpanded ? "open" : ""}`}>
        {/* Metadata row */}
        <div className="thought-meta">
          {metadata}
        </div>
        
        {/* Steps list */}
        <div className="thought-steps">
          {messages.map((msg, i) => (
            <div key={i} className="thought-step">
              <span className="thought-step-indicator" />
              <span className="thought-step-text">
                {msg.text || `Step ${i + 1}`}
              </span>
            </div>
          ))}
          
          {isActive && activeStep && (
            <div className="thought-step current">
              <span className="thought-step-indicator current" />
              <span className="thought-step-text">
                {activeStep}
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}