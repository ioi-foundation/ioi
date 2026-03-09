// src/components/WalletModal.jsx
import React, { useState } from 'react';

export default function WalletModal({ isOpen, onClose, onConnect }) {
  if (!isOpen) return null;

  const [connecting, setConnecting] = useState(null);

  const handleConnect = (walletType) => {
    setConnecting(walletType);
    
    // Simulate network delay
    setTimeout(() => {
      onConnect(walletType);
      setConnecting(null);
    }, 1500);
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4">
      {/* Backdrop */}
      <div 
        className="absolute inset-0 bg-black/60 backdrop-blur-sm animate-in fade-in duration-200" 
        onClick={onClose}
      ></div>
      
      {/* Modal */}
      <div className="relative bg-white rounded-2xl shadow-2xl w-full max-w-sm overflow-hidden animate-in zoom-in-95 duration-200">
        
        <div className="p-6 border-b border-gray-100 flex justify-between items-center">
          <h2 className="text-lg font-bold text-slate-900">Connect Identity</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 transition-colors">✕</button>
        </div>

        <div className="p-4 space-y-3">
          
          {/* IOI Passport (Preferred) */}
          <button 
            onClick={() => handleConnect('passport')}
            disabled={connecting !== null}
            className="w-full flex items-center justify-between p-4 rounded-xl border-2 border-slate-900 bg-slate-900 text-white hover:bg-slate-800 transition-all group relative overflow-hidden"
          >
            <div className="flex items-center gap-3 relative z-10">
              <div className="w-8 h-8 bg-white/10 rounded-full flex items-center justify-center text-lg">🆔</div>
              <div className="text-left">
                <div className="font-bold text-sm">IOI Passport</div>
                <div className="text-[10px] text-slate-300">Wallet.Network (FaceID)</div>
              </div>
            </div>
            {connecting === 'passport' ? (
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
            ) : (
              <span className="text-xs bg-white/20 px-2 py-0.5 rounded text-white font-medium">Recommended</span>
            )}
          </button>

          <div className="relative py-2">
             <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-gray-100"></div></div>
             <div className="relative flex justify-center text-xs font-medium text-slate-400 bg-white px-2">OR</div>
          </div>

          {/* Standard Wallets */}
          <WalletOption 
            name="Metamask" 
            icon="🦊" 
            onClick={() => handleConnect('metamask')}
            loading={connecting === 'metamask'}
            disabled={connecting !== null}
          />
          <WalletOption 
            name="Phantom" 
            icon="👻" 
            onClick={() => handleConnect('phantom')}
            loading={connecting === 'phantom'}
            disabled={connecting !== null}
          />
          <WalletOption 
            name="Rabby" 
            icon="🐰" 
            onClick={() => handleConnect('rabby')}
            loading={connecting === 'rabby'}
            disabled={connecting !== null}
          />

        </div>

        <div className="p-4 bg-slate-50 text-center text-[10px] text-slate-400 border-t border-gray-100">
          By connecting, you agree to the <a href="#" className="underline hover:text-slate-600">Terms of Service</a>.
        </div>
      </div>
    </div>
  );
}

function WalletOption({ name, icon, onClick, loading, disabled }) {
  return (
    <button 
      onClick={onClick}
      disabled={disabled}
      className="w-full flex items-center justify-between p-3 rounded-xl border border-gray-200 hover:border-blue-400 hover:bg-blue-50 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
    >
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 bg-white rounded-full flex items-center justify-center text-lg shadow-sm border border-gray-100">{icon}</div>
        <span className="font-semibold text-slate-700">{name}</span>
      </div>
      {loading && <div className="w-4 h-4 border-2 border-blue-200 border-t-blue-600 rounded-full animate-spin"></div>}
    </button>
  );
}