// src/components/ConsoleModal.jsx
import React, { useEffect, useRef, useState } from 'react';

export default function ConsoleModal({ isOpen, onClose, agentName }) {
  if (!isOpen) return null;

  const [logs, setLogs] = useState([]);
  const bottomRef = useRef(null);

  // Simulation Script
  useEffect(() => {
    setLogs([`> Initializing ${agentName}...`]);
    
    const messages = [
      { text: "> Connected to IOI Network (Node #882)", delay: 800, color: "text-green-400" },
      { text: "> Loading strategy 'Vol_Arb_v4.py'", delay: 1500, color: "text-blue-300" },
      { text: "> Verifying manifest signature... OK", delay: 2200, color: "text-slate-300" },
      { text: "> [INFO] Scanning Solana DEXs (Raydium, Orca)", delay: 3000, color: "text-slate-300" },
      { text: "> [DEBUG] Spread detected on SOL/USDC: 0.45%", delay: 4500, color: "text-yellow-400" },
      { text: "> [ACTION] Executing atomic swap...", delay: 5200, color: "text-green-400 font-bold" },
      { text: "> [SUCCESS] Profit: 0.12 SOL ($18.40)", delay: 6500, color: "text-green-400" },
      { text: "> [INFO] Waiting for next block...", delay: 7000, color: "text-slate-400" },
    ];

    const timeouts = [];

    messages.forEach(({ text, delay, color }) => {
      const t = setTimeout(() => {
        setLogs(prev => [...prev, { text, color }]);
      }, delay);
      timeouts.push(t);
    });

    return () => timeouts.forEach(clearTimeout);
  }, [agentName]);

  // Auto-scroll
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  return (
    <div className="fixed inset-0 z-[200] flex items-center justify-center p-4">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/80 backdrop-blur-sm" onClick={onClose}></div>
      
      {/* Terminal Window */}
      <div className="relative bg-slate-950 rounded-xl shadow-2xl w-full max-w-2xl border border-slate-800 overflow-hidden flex flex-col h-[500px] font-mono animate-in zoom-in-95 duration-200">
        
        {/* Header */}
        <div className="bg-slate-900 px-4 py-3 border-b border-slate-800 flex justify-between items-center">
          <div className="flex items-center gap-3">
            <div className="flex gap-1.5">
              <div className="w-3 h-3 rounded-full bg-red-500 cursor-pointer hover:bg-red-400" onClick={onClose}></div>
              <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
              <div className="w-3 h-3 rounded-full bg-green-500"></div>
            </div>
            <span className="text-slate-400 text-xs font-semibold ml-2 flex items-center gap-2">
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 12h14M12 5l7 7-7 7"/></svg>
              root@ioi-node:~/{agentName.replace(/\s+/g, '_').toLowerCase()}
            </span>
          </div>
          <div className="text-[10px] text-green-500 bg-green-900/30 px-2 py-0.5 rounded border border-green-900/50 animate-pulse">
            ● LIVE
          </div>
        </div>

        {/* Output Area */}
        <div className="flex-1 p-6 overflow-y-auto space-y-2">
          {logs.map((log, i) => (
            <div key={i} className={`text-sm ${log.color || 'text-slate-300'}`}>
              <span className="opacity-50 mr-2 text-xs">[{new Date().toLocaleTimeString()}]</span>
              {log.text}
            </div>
          ))}
          <div ref={bottomRef}></div>
          <div className="h-4 w-2 bg-slate-500 animate-pulse mt-2"></div>
        </div>

        {/* Footer Stats */}
        <div className="bg-slate-900 border-t border-slate-800 p-3 flex justify-between text-xs text-slate-500 font-sans">
           <div className="flex gap-4">
             <span>CPU: 12%</span>
             <span>MEM: 480MB</span>
             <span>NET: 450Kb/s</span>
           </div>
           <div>Session ID: 0x8a...9f2</div>
        </div>

      </div>
    </div>
  );
}