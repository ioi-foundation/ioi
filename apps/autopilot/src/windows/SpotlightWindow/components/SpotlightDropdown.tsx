import React from "react";
import { icons } from "./Icons";
import "../styles/Components.css";

export interface DropdownOption { value: string; label: string; desc?: string; icon?: React.ReactNode; }

interface DropdownProps { 
    icon: React.ReactNode; 
    options: DropdownOption[]; 
    selected: string; 
    onSelect: (val: string) => void; 
    isOpen: boolean; 
    onToggle: () => void;
    footer?: {
        label: string;
        onClick: () => void;
    };
}

export function Dropdown({ icon, options, selected, onSelect, isOpen, onToggle, footer }: DropdownProps) {
  const selectedOption = options.find((opt) => opt.value === selected);
  
  return (
    <div className="spot-dropdown">
      <button 
        className={`spot-toggle ${isOpen ? "open" : ""}`} 
        onClick={(e) => { e.stopPropagation(); onToggle(); }} 
        type="button"
      >
        <span className="toggle-icon">{selectedOption?.icon || icon}</span>
        <span className="toggle-label">{selectedOption?.label}</span>
        <span className="toggle-chevron">{icons.chevron}</span>
      </button>
      
      {isOpen && (
        <div className="spot-dropdown-menu">
          {/* Scrollable list wrapper */}
          <div className="spot-dropdown-list">
            {options.map((opt) => (
                <button 
                    key={opt.value} 
                    className={`spot-dropdown-item ${selected === opt.value ? "selected" : ""}`} 
                    onClick={(e) => { 
                        e.stopPropagation(); 
                        onSelect(opt.value); 
                        onToggle(); 
                    }} 
                    type="button"
                >
                    {opt.icon && <span className="spot-dropdown-icon">{opt.icon}</span>}
                    <div className="spot-dropdown-content">
                        <span className="spot-dropdown-label">{opt.label}</span>
                        {opt.desc && <span className="spot-dropdown-desc">{opt.desc}</span>}
                    </div>
                    {selected === opt.value && <span className="spot-dropdown-check">{icons.check}</span>}
                </button>
            ))}
          </div>
          
          {/* Footer Section - This logic was missing in your DOM */}
          {footer && (
            <div className="spot-dropdown-footer">
                <button 
                    className="spot-dropdown-footer-btn" 
                    onClick={(e) => { 
                        e.stopPropagation(); 
                        footer.onClick(); 
                        onToggle(); 
                    }}
                    type="button"
                >
                    {footer.label}
                </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}