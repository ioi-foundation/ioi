import React from "react";
import "../styles/Components.css";

export const ThinkingOrb = ({ isActive = false }: { isActive?: boolean }) => (
  <div className={`thinking-orb ${isActive ? "active" : ""}`}>
    <div className="orb-ring" />
    <div className="orb-ring" />
    <div className="orb-ring" />
    <div className="orb-core" />
  </div>
);