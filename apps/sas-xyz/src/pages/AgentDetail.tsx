import { useState } from 'react';
import { motion } from 'motion/react';
import { ArrowLeft, Activity, ShieldCheck, Zap, Server, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { Link } from 'react-router-dom';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import Logo from '../components/Logo';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const mockExecutions = [
  { id: 'tx_99a8f...', type: 'net::fetch', target: 'api.jup.ag/quote', status: 'success', time: '12s ago', gas: '0.002' },
  { id: 'tx_99a8e...', type: 'wallet::sign', target: 'Solana Mainnet', status: 'success', time: '14s ago', gas: '0.015' },
  { id: 'tx_99a8d...', type: 'net::fetch', target: 'api.binance.com', status: 'blocked', time: '5m ago', gas: '0.000' },
];

export default function AgentDetail() {
  const [selectedTx, setSelectedTx] = useState(mockExecutions[0]);

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Back Navigation */}
      <Link to="/app/registry" className="inline-flex items-center text-sm text-gray-400 hover:text-cyan-accent transition-colors">
        <ArrowLeft className="w-4 h-4 mr-2" />
        Back to Registry
      </Link>

      {/* Header & Stats */}
      <div className="bg-surface border border-border rounded-xl p-6">
        <div className="flex justify-between items-start mb-6">
          <div>
            <div className="flex items-center space-x-3 mb-2">
              <h1 className="text-2xl font-bold text-white">DeFi Arbitrage Sentinel</h1>
              <span className="px-2 py-0.5 rounded text-xs font-mono bg-border text-gray-300">v1.2.0</span>
              <span className="px-2 py-0.5 rounded text-xs font-medium bg-emerald-accent/10 text-emerald-accent border border-emerald-accent/20">
                Active
              </span>
            </div>
            <p className="text-sm text-gray-400 font-mono">ai://quantlabs/defi-sentinel</p>
          </div>
          <div className="flex space-x-3">
            <button className="bg-surface border border-border hover:border-gray-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
              Update Policy
            </button>
            <button className="bg-red-500/10 text-red-500 border border-red-500/20 hover:bg-red-500/20 px-4 py-2 rounded-lg text-sm font-medium transition-colors">
              Halt Swarm
            </button>
          </div>
        </div>

        <div className="grid grid-cols-4 gap-6 pt-6 border-t border-border">
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">SLA Bond</p>
            <p className="font-mono text-lg text-amber-accent font-bold flex items-center">
              <ShieldCheck className="w-4 h-4 mr-2" /> 50,000 USDC
            </p>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Labor Gas Earned</p>
            <p className="font-mono text-lg text-emerald-accent font-bold flex items-center">
              <Zap className="w-4 h-4 mr-2" /> 142.5K
            </p>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Success Rate</p>
            <p className="font-mono text-lg text-white font-bold flex items-center">
              <Activity className="w-4 h-4 mr-2" /> 99.98%
            </p>
          </div>
          <div>
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Primary Routing</p>
            <p className="font-mono text-lg text-cyan-accent font-bold flex items-center">
              <Server className="w-4 h-4 mr-2" /> AWS Nitro
            </p>
          </div>
        </div>
      </div>

      {/* Split View: History & Trace */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-[600px]">
        
        {/* Left: Execution Log */}
        <div className="lg:col-span-1 bg-surface border border-border rounded-xl overflow-hidden flex flex-col">
          <div className="p-4 border-b border-border bg-surface-hover">
            <h3 className="font-bold text-white flex items-center text-sm">
              <Logo className="w-4 h-4 mr-2 text-cyan-accent" />
              Live Execution Log
            </h3>
          </div>
          <div className="flex-1 overflow-y-auto p-2 space-y-1">
            {mockExecutions.map((tx) => (
              <div 
                key={tx.id}
                onClick={() => setSelectedTx(tx)}
                className={cn(
                  "p-3 rounded-lg cursor-pointer transition-colors border",
                  selectedTx.id === tx.id 
                    ? "bg-surface-hover border-cyan-accent/50" 
                    : "bg-transparent border-transparent hover:bg-surface-hover"
                )}
              >
                <div className="flex justify-between items-center mb-1">
                  <span className="font-mono text-xs text-gray-300">{tx.id}</span>
                  <span className="text-xs text-gray-500">{tx.time}</span>
                </div>
                <div className="flex items-center space-x-2">
                  {tx.status === 'success' ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-accent" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-amber-accent" />
                  )}
                  <span className="text-sm font-medium text-white">{tx.type}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right: Trace Inspector */}
        <div className="lg:col-span-2 bg-bg border border-border rounded-xl flex flex-col relative overflow-hidden">
          <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyan-accent via-emerald-accent to-transparent"></div>
          
          <div className="p-6 border-b border-border">
            <h3 className="text-lg font-bold text-white mb-1">Execution Trace Inspector</h3>
            <p className="text-sm text-gray-400 font-mono">Receipt: {selectedTx.id}</p>
          </div>

          <div className="flex-1 overflow-y-auto p-6 space-y-8">
            {/* Step 1: Probabilistic Intent */}
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="space-y-2">
              <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider flex items-center">
                <span className="w-5 h-5 rounded-full bg-surface border border-border flex items-center justify-center mr-2 text-white">1</span>
                Probabilistic Intent (LLM Output)
              </h4>
              <div className="bg-surface border border-border rounded-lg p-4 font-mono text-sm text-gray-300">
                <span className="text-purple-400">"action"</span>: <span className="text-emerald-300">"{selectedTx.type}"</span>,<br/>
                <span className="text-purple-400">"target"</span>: <span className="text-emerald-300">"{selectedTx.target}"</span>
              </div>
            </motion.div>

            {/* Step 2: Agency Firewall */}
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="space-y-2">
              <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider flex items-center">
                <span className="w-5 h-5 rounded-full bg-surface border border-border flex items-center justify-center mr-2 text-white">2</span>
                Determinism Boundary (Agency Firewall)
              </h4>
              {selectedTx.status === 'success' ? (
                <div className="bg-emerald-accent/5 border border-emerald-accent/20 rounded-lg p-4 font-mono text-sm text-emerald-accent/80 flex items-start">
                  <CheckCircle2 className="w-5 h-5 mr-3 text-emerald-accent shrink-0" />
                  <div>
                    <p>Policy Match: allow_domains ["*.jup.ag", "*.solana.com"]</p>
                    <p>Spend Limit Check: 0.015 &lt; 50.0 LGAS (PASS)</p>
                  </div>
                </div>
              ) : (
                <div className="bg-amber-accent/5 border border-amber-accent/20 rounded-lg p-4 font-mono text-sm text-amber-accent/80 flex items-start">
                  <AlertTriangle className="w-5 h-5 mr-3 text-amber-accent shrink-0" />
                  <div>
                    <p>Policy Violation: Target 'api.binance.com' not in allow_domains</p>
                    <p>Action: BLOCKED. Execution halted.</p>
                  </div>
                </div>
              )}
            </motion.div>

            {/* Step 3: Cryptographic Receipt */}
            <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }} className="space-y-2">
              <h4 className="text-xs font-bold text-gray-500 uppercase tracking-wider flex items-center">
                <span className="w-5 h-5 rounded-full bg-surface border border-border flex items-center justify-center mr-2 text-white">3</span>
                Cryptographic Receipt
              </h4>
              <div className="bg-[#050505] border border-border rounded-lg p-4 font-mono text-xs text-gray-400 space-y-1">
                <p><span className="text-cyan-accent">policy_hash:</span> 0x8f4b2a9c...</p>
                <p><span className="text-cyan-accent">model_snapshot_id:</span> bafybeigdyr...</p>
                <p><span className="text-cyan-accent">provider_sig:</span> ed25519:5Xp9...</p>
                <div className="mt-4 pt-4 border-t border-gray-800 flex justify-between items-center">
                  <span className="text-gray-500">Committed to LFT Consensus</span>
                  <button className="text-cyan-accent hover:underline">Verify Integrity</button>
                </div>
              </div>
            </motion.div>

          </div>
        </div>

      </div>
    </div>
  );
}


