// apps/autopilot/src/windows/StudioWindow/components/SharedUI.tsx
import React from "react";

// --- Icons ---
export const CubeIcon = () => (<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><path d="M3.27 6.96L12 12.01l8.73-5.05M12 22.08V12"/></svg>);
export const GlobeIcon = () => (<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>);
export const AppsIcon = () => (<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7" rx="2" /><rect x="14" y="3" width="7" height="7" rx="2" /><rect x="14" y="14" width="7" height="7" rx="2" /><rect x="3" y="14" width="7" height="7" rx="2" /></svg>);
export const MessageIcon = () => (<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>);
export const BotIcon = () => (<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="10" rx="2"/><circle cx="12" cy="5" r="2"/><path d="M12 7v4"/><circle cx="8" cy="16" r="1" fill="currentColor"/><circle cx="16" cy="16" r="1" fill="currentColor"/></svg>);
export const SwarmIcon = () => (<svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor"><circle cx="12" cy="12" r="2.5"/><circle cx="6" cy="6" r="2"/><circle cx="18" cy="6" r="2"/><circle cx="6" cy="18" r="2"/><circle cx="18" cy="18" r="2"/><path d="M12 9.5V7M12 14.5V17M9.5 12H7M14.5 12H17M9.88 9.88L7.5 7.5M14.12 9.88L16.5 7.5M9.88 14.12L7.5 16.5M14.12 14.12L16.5 16.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" fill="none"/></svg>);
export const SidebarIcon = () => (<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="2" /><path d="M9 3v18" /></svg>);
export const PlusIcon = () => (<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>);
export const SearchIcon = () => (<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>);
export const ChevronIcon = () => (<svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M6 9l6 6 6-6"/></svg>);
export const ShieldIcon = () => (<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>);

// --- Dropdown ---
interface StudioDropdownProps {
  icon: React.ReactNode;
  label: string;
  options: string[];
  selected?: string;
  onSelect?: (val: string) => void;
  isOpen: boolean;
  onToggle: () => void;
  footer?: { label: string; onClick: () => void };
}

export function StudioDropdown({ icon, label, options, selected, onSelect, isOpen, onToggle, footer }: StudioDropdownProps) {
  return (
    <div className="studio-dropdown">
      <button className={`studio-dropdown-trigger ${isOpen ? 'open' : ''}`} onClick={(e) => { e.stopPropagation(); onToggle(); }}>
        {icon}<span>{label}</span><span className="chevron"><ChevronIcon /></span>
      </button>
      {isOpen && (
        <div className="studio-dropdown-menu">
          {options.map(opt => (
            <button key={opt} className={`studio-dropdown-item ${selected === opt ? 'selected' : ''}`} onClick={() => { if (onSelect) onSelect(opt); onToggle(); }}>
              {opt}
            </button>
          ))}
          {footer && (
            <>
              <div className="studio-dropdown-separator" />
              <button className="studio-dropdown-footer" onClick={(e) => { e.stopPropagation(); footer.onClick(); onToggle(); }}>
                {footer.label}
              </button>
            </>
          )}
        </div>
      )}
    </div>
  );
}

// --- [NEW] Approval Card Component ---
interface ApprovalCardProps {
    title: string;
    description: string;
    risk: "low" | "medium" | "high";
    onApprove: () => void;
    onDeny: () => void;
}

export function ApprovalCard({ title, description, risk, onApprove, onDeny }: ApprovalCardProps) {
    const riskColor = risk === 'high' ? '#EF4444' : risk === 'medium' ? '#F59E0B' : '#10B981';
    
    return (
        <div style={{
            background: 'rgba(23, 26, 32, 0.95)',
            border: `1px solid ${riskColor}40`, // 25% opacity border
            borderRadius: 8,
            padding: 16,
            marginTop: 8,
            marginBottom: 8,
            maxWidth: '90%',
            boxShadow: '0 4px 20px rgba(0,0,0,0.3)',
            display: 'flex',
            flexDirection: 'column',
            gap: 12,
            borderLeft: `4px solid ${riskColor}`
        }}>
            <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start'}}>
                <div style={{display: 'flex', alignItems: 'center', gap: 8}}>
                    <div style={{color: riskColor}}><ShieldIcon /></div>
                    <span style={{fontSize: 13, fontWeight: 600, color: '#E5E7EB'}}>{title}</span>
                </div>
                <span style={{fontSize: 10, fontWeight: 700, textTransform: 'uppercase', color: riskColor, letterSpacing: '0.05em', background: `${riskColor}15`, padding: '2px 6px', borderRadius: 4}}>
                    {risk.toUpperCase()} RISK
                </span>
            </div>
            
            <div style={{fontSize: 12, color: '#9CA3AF', lineHeight: 1.5}}>
                {description}
            </div>

            <div style={{display: 'flex', gap: 8, marginTop: 4}}>
                <button 
                    onClick={onApprove}
                    style={{
                        flex: 1,
                        background: riskColor,
                        color: '#FFFFFF',
                        border: 'none',
                        borderRadius: 4,
                        padding: '6px 12px',
                        fontSize: 12,
                        fontWeight: 600,
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: 6
                    }}
                >
                    Authorize
                </button>
                <button 
                    onClick={onDeny}
                    style={{
                        padding: '6px 12px',
                        background: 'transparent',
                        border: '1px solid #3F4652',
                        color: '#9CA3AF',
                        borderRadius: 4,
                        fontSize: 12,
                        fontWeight: 500,
                        cursor: 'pointer'
                    }}
                >
                    Deny
                </button>
            </div>
        </div>
    );
}