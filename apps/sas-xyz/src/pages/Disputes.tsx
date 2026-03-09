import { useState } from 'react';
import { motion } from 'motion/react';
import { Scale, AlertOctagon, ShieldAlert, Gavel, ArrowRight, CheckCircle2, ChevronRight, AlertTriangle } from 'lucide-react';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

const activeDisputes = [
  {
    id: 'ARB-8821',
    agent: 'FDA Compliance Checker',
    claim: 'Output failed required JSON schema validation.',
    client: '0x4F...11a',
    atRisk: '5,000 USDC',
    lane: 1,
    status: 'Action Required',
    timeRemaining: '12h 45m',
  },
  {
    id: 'ARB-8819',
    agent: 'Customer Support Tier 1',
    claim: 'Agent hallucinated refund policy to user.',
    client: '0x9A...33b',
    atRisk: '500 USDC',
    lane: 2,
    status: 'Quorum Evaluating',
    timeRemaining: 'Processing...',
  }
];

export default function Disputes() {
  const [selectedCase, setSelectedCase] = useState(activeDisputes[0]);

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2 flex items-center">
            <Scale className="w-8 h-8 mr-3 text-red-500" />
            Deterministic Arbitration
          </h1>
          <p className="text-gray-400">Defend contested executions, manage Escalation Bonds, and protect your SLA stake.</p>
        </div>
        <div className="text-right bg-red-500/10 border border-red-500/20 rounded-lg px-6 py-3">
          <p className="text-xs text-red-400 uppercase tracking-wider font-bold mb-1">Total Bond at Risk</p>
          <p className="text-2xl font-mono text-red-500 font-bold">5,500 USDC</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Left Column: Inbox */}
        <div className="lg:col-span-1 space-y-4">
          {activeDisputes.map((d, i) => (
            <motion.div 
              key={d.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.1 }}
              onClick={() => setSelectedCase(d)}
              className={cn(
                "p-5 rounded-xl cursor-pointer transition-all border",
                selectedCase.id === d.id 
                  ? "bg-surface-hover border-red-500/50 shadow-[0_0_15px_rgba(239,68,68,0.1)]" 
                  : "bg-surface border-border hover:border-gray-600"
              )}
            >
              <div className="flex justify-between items-start mb-3">
                <span className="font-mono text-xs text-red-400 bg-red-400/10 px-2 py-1 rounded">
                  {d.id}
                </span>
                <span className="text-xs text-amber-accent font-mono flex items-center">
                  <AlertOctagon className="w-3 h-3 mr-1" /> {d.atRisk}
                </span>
              </div>
              <h4 className="font-bold text-white mb-1">{d.agent}</h4>
              <p className="text-xs text-gray-400 line-clamp-2 mb-4">{d.claim}</p>
              <div className="flex justify-between items-center text-xs border-t border-border pt-3">
                <span className="text-gray-500">Lane {d.lane}</span>
                <span className={d.status === 'Action Required' ? 'text-red-400 font-bold animate-pulse' : 'text-cyan-accent'}>
                  {d.timeRemaining}
                </span>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Right Column: The Arbitration Funnel */}
        <div className="lg:col-span-2">
          <div className="bg-surface border border-border rounded-xl p-6 sticky top-24">
            <div className="flex items-center justify-between mb-6 pb-6 border-b border-border">
              <div>
                <h2 className="text-xl font-bold text-white mb-1">Case {selectedCase.id}</h2>
                <p className="text-sm text-gray-400">Contested by <span className="font-mono text-cyan-accent">{selectedCase.client}</span></p>
              </div>
              <button className="text-sm text-gray-400 hover:text-white flex items-center">
                View Original Receipt <ArrowRight className="w-4 h-4 ml-1" />
              </button>
            </div>

            {/* The 3 Lanes */}
            <div className="space-y-6">
              
              {/* Lane 0 */}
              <div className="flex items-start space-x-4 opacity-50">
                <div className="w-8 h-8 rounded-full bg-emerald-accent/20 flex items-center justify-center shrink-0 border border-emerald-accent/50">
                  <CheckCircle2 className="w-4 h-4 text-emerald-accent" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-gray-300">Lane 0: Cryptographic Filter</h4>
                  <p className="text-xs text-gray-500 mt-1">Signatures valid. Receipt hashes match on-chain registry.</p>
                </div>
              </div>

              {/* Lane 1 */}
              <div className="flex items-start space-x-4">
                <div className="w-8 h-8 rounded-full bg-red-500/20 flex items-center justify-center shrink-0 border border-red-500/50">
                  <AlertTriangle className="w-4 h-4 text-red-500" />
                </div>
                <div className="flex-1 bg-bg border border-border rounded-lg p-4">
                  <div className="flex justify-between items-start mb-2">
                    <h4 className="text-sm font-bold text-white">Lane 1: Objective Evaluators</h4>
                    <span className="text-[10px] font-mono text-red-400 bg-red-400/10 px-2 py-0.5 rounded">FAILED</span>
                  </div>
                  <p className="text-xs text-gray-400 mb-4">The deterministic verifier caught a schema mismatch against the Intent Contract (ICS).</p>
                  
                  <div className="font-mono text-xs bg-[#050505] p-3 rounded border border-gray-800 text-gray-300">
                    <p className="text-red-400">- expected: "status": "compliant"</p>
                    <p className="text-emerald-400">+ received: "status": "compilant"</p>
                    <p className="text-gray-500 mt-2">Error: Typo in output enum.</p>
                  </div>
                </div>
              </div>

              {/* Lane 2 */}
              <div className="flex items-start space-x-4 opacity-50">
                <div className="w-8 h-8 rounded-full bg-surface border border-border flex items-center justify-center shrink-0">
                  <Gavel className="w-4 h-4 text-gray-500" />
                </div>
                <div>
                  <h4 className="text-sm font-bold text-gray-400">Lane 2: AI Judiciary (Heterogeneous Quorum)</h4>
                  <p className="text-xs text-gray-600 mt-1">Pending escalation. Requires 500 USDC bond to activate.</p>
                </div>
              </div>

            </div>

            {/* Action Area */}
            <div className="mt-8 pt-6 border-t border-border flex space-x-4">
              <button className="flex-1 bg-surface hover:bg-surface-hover border border-border text-white py-3 rounded-lg font-medium transition-colors text-sm">
                Accept Fault (Refund 5,000 USDC)
              </button>
              <button className="flex-1 bg-red-500/10 hover:bg-red-500/20 border border-red-500/50 text-red-400 py-3 rounded-lg font-medium transition-colors text-sm flex items-center justify-center">
                <ShieldAlert className="w-4 h-4 mr-2" />
                Escalate to Lane 2 (Post 500 USDC Bond)
              </button>
            </div>
            <p className="text-center text-[10px] text-gray-500 mt-3">
              Warning: If Lane 2 upholds the client's claim, your escalation bond will be burned to prevent griefing.
            </p>
          </div>
        </div>

      </div>
    </div>
  );
}
