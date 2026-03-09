import { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Search, DollarSign, CheckCircle2, Clock, ChevronRight } from 'lucide-react';
import Logo from '../components/Logo';
import MagneticCard from '../components/ui/MagneticCard';
import { Skeleton } from '../components/ui/Skeleton';

const bounties = [
  {
    id: 'RFA-8842',
    title: 'FDA Compliance Checker',
    description: 'Build an agent that ingests PDF medical device manuals and cross-references them against FDA 21 CFR Part 820. Must output a deterministic JSON report.',
    reward: '5,000 USDC',
    deadline: '2 days',
    status: 'open',
    tests: 42,
  },
  {
    id: 'RFA-8843',
    title: 'DeFi Arbitrage Bot (Solana)',
    description: 'Create a high-frequency trading agent monitoring Raydium and Orca pools. Must execute within 400ms latency. Requires Rust WASM module.',
    reward: '12,500 USDC',
    deadline: '5 days',
    status: 'open',
    tests: 128,
  },
  {
    id: 'RFA-8844',
    title: 'Automated Customer Support Tier 1',
    description: 'Agent to handle Zendesk tickets. Must correctly classify intent and resolve 80% of password resets without human escalation.',
    reward: '2,000 USDC',
    deadline: '12 hours',
    status: 'in_progress',
    tests: 500,
  }
];

export default function Bounties() {
  const [selectedBounty, setSelectedBounty] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => setIsLoading(false), 800);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2">The RFA Terminal</h1>
          <p className="text-gray-400">Fulfill Requests for Agents. Pass the hidden test suite to claim the bounty.</p>
        </div>
        <div className="relative">
          <Search className="w-5 h-5 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input 
            type="text" 
            placeholder="Search bounties..." 
            className="bg-surface border border-border rounded-lg pl-10 pr-4 py-2 text-sm focus:outline-none focus:border-cyan-accent w-64 text-white placeholder-gray-500"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Bounty List */}
        <div className="lg:col-span-2 space-y-4">
          {isLoading ? (
            Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="bg-surface border border-border rounded-xl p-6">
                <div className="flex justify-between items-start mb-4">
                  <div className="space-y-2">
                    <Skeleton className="h-5 w-32" />
                    <Skeleton className="h-6 w-64" />
                  </div>
                  <Skeleton className="h-5 w-20" />
                </div>
                <div className="space-y-2 mb-6">
                  <Skeleton className="h-4 w-full" />
                  <Skeleton className="h-4 w-3/4" />
                </div>
                <div className="flex items-center justify-between border-t border-border pt-4">
                  <div className="flex space-x-4">
                    <Skeleton className="h-4 w-24" />
                    <Skeleton className="h-4 w-32" />
                  </div>
                  <Skeleton className="h-5 w-5" />
                </div>
              </div>
            ))
          ) : (
            bounties.map((bounty, i) => (
              <motion.div 
                key={bounty.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.1 }}
              >
                <MagneticCard
                  onClick={() => setSelectedBounty(bounty.id)}
                  className={`p-6 ${
                    selectedBounty === bounty.id 
                      ? 'border-cyan-accent shadow-[0_0_15px_rgba(0,240,255,0.1)]' 
                      : 'hover:border-gray-600'
                  }`}
                >
                  <div className="flex justify-between items-start mb-4">
                    <div>
                      <div className="flex items-center space-x-3 mb-1">
                        <span className="font-mono text-xs text-cyan-accent bg-cyan-accent/10 px-2 py-1 rounded">
                          {bounty.id}
                        </span>
                        <span className="flex items-center text-amber-accent text-sm font-medium">
                          <DollarSign className="w-4 h-4 mr-1" />
                          {bounty.reward}
                        </span>
                      </div>
                      <h3 className="text-xl font-bold text-white">{bounty.title}</h3>
                    </div>
                    <div className="flex items-center text-gray-500 text-sm">
                      <Clock className="w-4 h-4 mr-1" />
                      {bounty.deadline}
                    </div>
                  </div>
                  <p className="text-gray-400 text-sm mb-6 line-clamp-2">
                    {bounty.description}
                  </p>
                  <div className="flex items-center justify-between border-t border-border pt-4">
                    <div className="flex items-center space-x-4 text-sm">
                      <span className="flex items-center text-emerald-accent">
                        <CheckCircle2 className="w-4 h-4 mr-1" />
                        {bounty.tests} Hidden Tests
                      </span>
                      <span className="text-gray-500">
                        {bounty.status === 'open' ? 'Accepting Submissions' : 'In Progress'}
                      </span>
                    </div>
                    <ChevronRight className="w-5 h-5 text-gray-500" />
                  </div>
                </MagneticCard>
              </motion.div>
            ))
          )}
        </div>

        {/* Validation Panel */}
        <div className="lg:col-span-1">
          <div className="bg-surface border border-border rounded-xl p-6 sticky top-24">
            <h3 className="text-lg font-bold text-white mb-4 flex items-center">
              <Logo className="w-5 h-5 mr-2 text-cyan-accent" />
              Blind Validation
            </h3>
            
            {selectedBounty ? (
              <div className="space-y-6">
                <div className="p-4 bg-bg rounded border border-border font-mono text-sm text-gray-300">
                  <p className="text-gray-500 mb-2"># Submit your Agent Manifest</p>
                  <p><span className="text-cyan-accent">$</span> ioi submit --bounty {selectedBounty}</p>
                </div>
                
                <div className="space-y-3">
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Clean Room Status</span>
                    <span className="text-amber-accent animate-pulse">Awaiting Manifest</span>
                  </div>
                  <div className="w-full bg-bg rounded-full h-2 border border-border overflow-hidden">
                    <div className="bg-cyan-accent h-2 w-0"></div>
                  </div>
                </div>

                <div className="pt-4 border-t border-border">
                  <button className="w-full bg-cyan-accent text-bg py-3 rounded-lg font-bold hover:bg-cyan-accent/90 transition-colors">
                    Upload Manifest (ai://)
                  </button>
                  <p className="text-xs text-gray-500 text-center mt-3">
                    Smart contract will instantly release funds upon passing all {bounties.find(b => b.id === selectedBounty)?.tests} tests.
                  </p>
                </div>
              </div>
            ) : (
              <div className="h-64 flex flex-col items-center justify-center text-gray-500 space-y-4">
                <Logo className="w-12 h-12 opacity-20" />
                <p className="text-sm text-center">Select a bounty to view validation requirements.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
