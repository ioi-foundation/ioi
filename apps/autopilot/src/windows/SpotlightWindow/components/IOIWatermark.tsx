import React from "react";
import { icons } from "./Icons";
import "../styles/Components.css";

interface WatermarkProps {
  onSuggestionClick?: (text: string) => void;
}

const suggestions = [
  { 
    icon: icons.globe, 
    text: "Search the web for...",
    description: "Find information online"
  },
  { 
    icon: icons.laptop, 
    text: "Open an app...",
    description: "Launch applications"
  },
  { 
    icon: icons.cube, 
    text: "Analyze this data...",
    description: "Process & understand data"
  },
];

export const IOIWatermark = ({ onSuggestionClick }: WatermarkProps) => {
  return (
    <div className="spot-watermark-container">
      {/* Logo Mark */}
      <svg className="spot-watermark" viewBox="108.97 89.47 781.56 706.06" fill="none">
        <g stroke="currentColor" strokeWidth="1" strokeLinejoin="round" strokeLinecap="round">
          <path d="M295.299 434.631L295.299 654.116 485.379 544.373z" />
          <path d="M500 535.931L697.39 421.968 500 308.005 302.61 421.968z" />
          <path d="M514.621 544.373L704.701 654.115 704.701 434.631z" />
          <path d="M280.678 662.557L280.678 425.086 123.957 695.903 145.513 740.594z" />
          <path d="M719.322 662.557L854.487 740.594 876.043 695.903 719.322 425.085z" />
          <path d="M287.988 675.22L151.883 753.8 164.878 780.741 470.757 780.741 287.988 675.22z" />
          <path d="M712.012 675.219L529.242 780.741 835.122 780.741 848.117 753.8 712.012 675.219z" />
          <path d="M492.689 295.343L492.689 104.779 466.038 104.779 287.055 414.066z" />
          <path d="M507.31 295.342L712.945 414.066 533.962 104.779 507.31 104.779z" />
          <path d="M302.61 666.778L500 780.741 500 552.815z" />
          <path d="M500 552.815L500 780.741 697.39 666.778z" />
        </g>
      </svg>
      
      {/* Greeting */}
      <span className="spot-watermark-hint">What can I help you with?</span>
      
      {/* Suggestion Pills */}
      {onSuggestionClick && (
        <div className="spot-suggestions">
          {suggestions.map((s, i) => (
            <button 
              key={i} 
              className="spot-suggestion" 
              onClick={() => onSuggestionClick(s.text)}
            >
              <span className="suggestion-icon">{s.icon}</span>
              <span className="suggestion-text">{s.text}</span>
            </button>
          ))}
        </div>
      )}
      
      {/* Keyboard Hint */}
      <div className="spot-shortcut-hint">
        <kbd>⌘</kbd><kbd>K</kbd> to toggle sidebar
      </div>
    </div>
  );
};