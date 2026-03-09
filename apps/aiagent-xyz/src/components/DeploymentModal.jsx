// src/components/DeploymentModal.jsx
import React, { useState } from 'react';

export default function DeploymentModal({ isOpen, onClose, agent }) {
  if (!isOpen) return null;

  const [optimization, setOptimization] = useState(50);
  const [useTEE, setUseTEE] = useState(true);
  const [step, setStep] = useState(1);

  // Dynamic matching logic
  const getMatch = () => {
    if (optimization < 30) return { provider: 'DePIN Swarm', price: '$0.04/hr', type: 'Economy' };
    if (optimization > 70) return { provider: 'AWS Nitro Enclave', price: '$0.45/hr', type: 'Enterprise' };
    return { provider: 'IOI Hybrid Cloud', price: '$0.12/hr', type: 'Balanced' };
  };

  const match = getMatch();

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose}></div>
      
      {/* Modal Content */}
      <div className="relative bg-white rounded-2xl shadow-2xl w-full max-w-lg overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        
        {/* Header */}
        <div className="bg-slate-900 px-6 py-4 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-white font-bold text-sm">
              {agent.name[0]}
            </div>
            <div>
              <h3 className="text-white font-bold text-sm">Deploy {agent.name}</h3>
              <p className="text-slate-400 text-xs">v{agent.manifest.version}</p>
            </div>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-white transition-colors">
            <svg className="w-5 h-5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" /></svg>
          </button>
        </div>

        {/* Body */}
        <div className="p-6">
          
          {step === 1 ? (
            <div className="space-y-6">
              {/* Requirements Warning */}
              <div className="bg-amber-50 border border-amber-200 rounded-lg p-3 flex gap-3 items-start">
                <span className="text-amber-500 mt-0.5">⚠️</span>
                <div>
                  <p className="text-amber-900 text-xs font-bold uppercase">Hardware Requirement</p>
                  <p className="text-amber-700 text-sm">This agent requires {agent.manifest.hardware || "GPU acceleration"}. Local execution may be slow.</p>
                </div>
              </div>

              {/* Policy Slider */}
              <div>
                <label className="flex justify-between text-sm font-bold text-slate-700 mb-4">
                  <span>Execution Policy</span>
                  <span className="text-blue-600">{match.type}</span>
                </label>
                <input 
                  type="range" 
                  min="0" max="100" 
                  value={optimization} 
                  onChange={(e) => setOptimization(Number(e.target.value))}
                  className="w-full h-2 bg-slate-100 rounded-lg appearance-none cursor-pointer accent-slate-900"
                />
                <div className="flex justify-between text-xs text-slate-400 mt-2 font-medium">
                  <span>Cost Optimized</span>
                  <span>Performance Optimized</span>
                </div>
              </div>

              {/* TEE Toggle */}
              <label className="flex items-center justify-between p-3 border border-gray-200 rounded-lg cursor-pointer hover:bg-slate-50 transition-colors">
                <div className="flex items-center gap-3">
                  <div className={`w-4 h-4 rounded border flex items-center justify-center ${useTEE ? 'bg-green-500 border-green-500' : 'border-gray-300'}`}>
                    {useTEE && <svg className="w-3 h-3 text-white" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>}
                  </div>
                  <div>
                    <div className="font-semibold text-slate-900 text-sm">Confidential Computing (TEE)</div>
                    <div className="text-xs text-slate-500">Encrypted memory. Provider cannot see data.</div>
                  </div>
                </div>
                <input type="checkbox" className="hidden" checked={useTEE} onChange={() => setUseTEE(!useTEE)} />
              </label>

              {/* Selected Route Preview */}
              <div className="bg-slate-50 rounded-lg p-4 border border-slate-100">
                <div className="flex justify-between items-center text-sm mb-1">
                  <span className="text-slate-500">Routing to:</span>
                  <span className="font-bold text-slate-900">{match.provider}</span>
                </div>
                <div className="flex justify-between items-center text-sm">
                  <span className="text-slate-500">Spot Rate:</span>
                  <span className="font-mono text-green-600 font-bold">{match.price}</span>
                </div>
              </div>

            </div>
          ) : (
            <div className="py-8 text-center space-y-4">
              <div className="w-12 h-12 border-4 border-blue-100 border-t-blue-600 rounded-full animate-spin mx-auto"></div>
              <h3 className="text-slate-900 font-bold">Provisioning Container...</h3>
              <p className="text-slate-500 text-sm">Verifying manifest signature and acquiring lease.</p>
            </div>
          )}

        </div>

        {/* Footer */}
        {step === 1 && (
          <div className="p-4 border-t border-gray-100 bg-gray-50 flex justify-end gap-3">
            <button onClick={onClose} className="px-4 py-2 text-sm font-semibold text-slate-600 hover:text-slate-900">Cancel</button>
            <button onClick={() => setStep(2)} className="px-6 py-2 text-sm font-bold text-white bg-blue-600 rounded-lg hover:bg-blue-700 shadow-sm transition-all active:scale-95">
              Confirm & Deploy
            </button>
          </div>
        )}
      </div>
    </div>
  );
}