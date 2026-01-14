import React, { useState } from "react";
import "./AgentInstallModal.css";

interface AgentInstallModalProps {
  isOpen: boolean;
  onClose: () => void;
  agent: { name: string; requirements: string; image: string };
}

export function AgentInstallModal({ isOpen, onClose, agent }: AgentInstallModalProps) {
  const [selectedProvider, setSelectedProvider] = useState("akash");

  if (!isOpen) return null;

  return (
    <div className="install-modal-overlay" onClick={onClose}>
      <div className="install-modal" onClick={(e) => e.stopPropagation()}>
        
        {/* Header */}
        <div className="install-header">
          <div className="agent-preview">
            <div className="agent-icon-large" style={{ background: agent.image }}>
              {agent.name[0]}
            </div>
            <div>
              <h2>Configure {agent.name}</h2>
              <p className="subtext">Select execution environment</p>
            </div>
          </div>
          <button className="close-btn" onClick={onClose}>×</button>
        </div>

        <div className="install-content">
          
          {/* Requirements Warning */}
          <div className="req-banner">
            <span className="req-icon">⚡</span>
            <span>Requires: <strong>{agent.requirements}</strong></span>
          </div>

          <h3>Compute Providers</h3>
          <div className="provider-options">
            
            {/* Option 1: Local (Disabled/Warning if insufficient) */}
            <div className="provider-option disabled">
              <div className="radio-circle" />
              <div className="provider-detail">
                <span className="p-name">Local Device (Mac Studio)</span>
                <span className="p-meta">Insufficient VRAM (Avail: 8GB, Req: 24GB)</span>
              </div>
            </div>

            {/* Option 2: DePIN (Recommended) */}
            <div 
              className={`provider-option ${selectedProvider === 'akash' ? 'selected' : ''}`}
              onClick={() => setSelectedProvider('akash')}
            >
              <div className="radio-circle" />
              <div className="provider-detail">
                <div className="p-row">
                  <span className="p-name">Akash Network</span>
                  <span className="p-tag recommended">Best Value</span>
                </div>
                <span className="p-meta">NVIDIA A100 • $0.45/hr • Decentralized</span>
              </div>
            </div>

            {/* Option 3: Hyperscale */}
            <div 
              className={`provider-option ${selectedProvider === 'aws' ? 'selected' : ''}`}
              onClick={() => setSelectedProvider('aws')}
            >
              <div className="radio-circle" />
              <div className="provider-detail">
                <span className="p-name">AWS Nitro Enclave</span>
                <span className="p-meta">H100 • $2.80/hr • SOC2 Compliant</span>
              </div>
            </div>

          </div>

          {/* Policy Config (Mini) */}
          <div className="policy-mini">
            <h3>Safety Policy</h3>
            <div className="policy-row">
              <span>Spend Limit</span>
              <select>
                <option>$5.00 / day</option>
                <option>$10.00 / day</option>
                <option>Unlimited</option>
              </select>
            </div>
          </div>

        </div>

        <div className="install-footer">
          <div className="cost-summary">
            <span>Est. Cost:</span>
            <strong>$0.45/hr</strong>
          </div>
          <button className="install-btn" onClick={onClose}>
            Deploy & Run
          </button>
        </div>

      </div>
    </div>
  );
}