import React, { useState, useEffect } from "react";
import { icons } from "./Icons";
import "../styles/Visuals.css";

interface VisualArtifactProps {
  url?: string;
  title?: string;
  isActive?: boolean;
  screenshot?: string;
}

export function VisualArtifact({ url = "browsing...", title, isActive = false, screenshot }: VisualArtifactProps) {
  const [cursorPos, setCursorPos] = useState({ x: 50, y: 40 });
  const [isClicking, setIsClicking] = useState(false);

  useEffect(() => {
    if (!isActive) return;
    const interval = setInterval(() => {
      setCursorPos({ x: 25 + Math.random() * 55, y: 25 + Math.random() * 50 });
      if (Math.random() > 0.6) {
        setIsClicking(true);
        setTimeout(() => setIsClicking(false), 150);
      }
    }, 1200);
    return () => clearInterval(interval);
  }, [isActive]);

  return (
    <div className={`visual-artifact ${isActive ? "active" : ""}`}>
      {/* Browser Chrome */}
      <div className="artifact-browser-bar">
        <div className="artifact-traffic-dots">
          <span className="dot close" />
          <span className="dot minimize" />
          <span className="dot maximize" />
        </div>
        <div className="artifact-url-bar">
          <span className="artifact-lock">{icons.lock}</span>
          <span className="artifact-url">{url}</span>
        </div>
        <button className="artifact-external" title="Open in browser">
          {icons.externalLink}
        </button>
      </div>

      {/* Viewport */}
      <div className="artifact-viewport">
        {screenshot ? (
          <img src={screenshot} alt="Page screenshot" className="artifact-screenshot" />
        ) : (
          <div className="artifact-skeleton">
            <div className="skel-header">
              <div className="skel-logo" />
              <div className="skel-nav"><span /><span /><span /></div>
            </div>
            <div className="skel-hero">
              <div className="skel-title" />
              <div className="skel-subtitle" />
              <div className="skel-cta" />
            </div>
            <div className="skel-cards"><span /><span /><span /></div>
          </div>
        )}

        {/* Animated Cursor */}
        {isActive && (
          <svg
            className={`artifact-cursor ${isClicking ? "clicking" : ""}`}
            style={{ left: `${cursorPos.x}%`, top: `${cursorPos.y}%` }}
            width="20" height="20" viewBox="0 0 24 24" fill="none"
          >
            <path d="M5.5 3.2L11.5 19.5L14.5 13L21 12L5.5 3.2Z" fill="#000" stroke="#fff" strokeWidth="1.5"/>
          </svg>
        )}
      </div>

      {/* Activity Footer */}
      {isActive && title && (
        <div className="artifact-activity">
          <div className="activity-pulse" />
          <span>{title}</span>
        </div>
      )}
    </div>
  );
}