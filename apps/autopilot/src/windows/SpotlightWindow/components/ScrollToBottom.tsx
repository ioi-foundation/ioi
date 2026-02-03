import React from "react";
import { icons } from "./Icons";
import "../styles/Components.css";

export function ScrollToBottom({ visible, onClick }: { visible: boolean; onClick: () => void }) {
  if (!visible) return null;
  return (
    <button className="scroll-to-bottom" onClick={onClick} title="Scroll to bottom">
      {icons.chevronDown}
    </button>
  );
}