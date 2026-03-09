import { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Database, Link2, ShieldAlert, Zap, Box, ArrowUpRight } from 'lucide-react';
import { Link } from 'react-router-dom';
import MagneticCard from '../components/ui/MagneticCard';
import { Skeleton } from '../components/ui/Skeleton';

const agents = [
  {
    id: 'ai://builder-xyz/data-analyst',
    name: 'Data Analyst Pro',
    version: 'v1.2.0',
    status: 'Active',
    bond: '5,000 USDC',
    royalty: '$0.02 / run',
    runs: '14,291',
    vram: '16GB',
  },
  {
    id: 'ai://builder-xyz/support-bot',
    name: 'Zendesk Resolver',
    version: 'v0.9.1-beta',
    status: 'Testing',
    bond: '500 USDC',
    royalty: '$0.005 / run',
    runs: '842',
    vram: '8GB',
  }
];

export default function Registry() {
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => setIsLoading(false), 800);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2">Asset Registry</h1>
          <p className="text-gray-400">Manage your minted Service NFTs, set royalty fees, and update manifest versions.</p>
        </div>
        <button className="bg-cyan-accent text-bg px-6 py-2 rounded-lg font-bold hover:bg-cyan-accent/90 transition-colors flex items-center">
          <Box className="w-4 h-4 mr-2" />
          Mint New Agent
        </button>
      </div>

      {/* Bonding Dashboard */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <MagneticCard className="col-span-2 p-6 flex items-center justify-between">
          <div>
            <h3 className="text-lg font-bold text-white mb-1 flex items-center">
              <ShieldAlert className="w-5 h-5 mr-2 text-amber-accent" />
              SLA Bonding Dashboard
            </h3>
            <p className="text-sm text-gray-400">Total Staked Guarantee</p>
          </div>
          <div className="text-right">
            <span className="text-3xl font-bold font-mono text-amber-accent">5,500 USDC</span>
            <p className="text-xs text-gray-500 mt-1">Max parallel instances: 110</p>
          </div>
          <button className="border border-amber-accent/50 text-amber-accent px-4 py-2 rounded hover:bg-amber-accent/10 transition-colors text-sm font-medium">
            Manage Stake
          </button>
        </MagneticCard>
        
        <MagneticCard className="p-6 flex flex-col justify-center">
          <div className="flex items-center justify-between mb-2">
            <span className="text-gray-400 text-sm">Total Royalties</span>
            <Zap className="w-4 h-4 text-emerald-accent" />
          </div>
          <span className="text-2xl font-bold font-mono text-white">$285.82</span>
          <p className="text-xs text-emerald-accent mt-1">+12% this week</p>
        </MagneticCard>
      </div>

      {/* Agent List */}
      <div className="bg-surface border border-border rounded-xl overflow-hidden">
        <div className="px-6 py-4 border-b border-border flex justify-between items-center bg-surface-hover">
          <h3 className="font-bold text-white flex items-center">
            <Database className="w-5 h-5 mr-2 text-cyan-accent" />
            Deployed Manifests
          </h3>
        </div>
        <div className="divide-y divide-border">
          {isLoading ? (
            Array.from({ length: 3 }).map((_, i) => (
              <div key={i} className="p-6 flex flex-col lg:flex-row lg:items-center justify-between">
                <div className="flex-1 mb-4 lg:mb-0 space-y-3">
                  <div className="flex space-x-3">
                    <Skeleton className="h-6 w-48" />
                    <Skeleton className="h-6 w-16" />
                    <Skeleton className="h-6 w-20" />
                  </div>
                  <Skeleton className="h-4 w-64" />
                </div>
                <div className="flex space-x-8">
                  <Skeleton className="h-10 w-16" />
                  <Skeleton className="h-10 w-16" />
                  <Skeleton className="h-10 w-24" />
                  <Skeleton className="h-10 w-24" />
                  <Skeleton className="h-10 w-10" />
                </div>
              </div>
            ))
          ) : (
            agents.map((agent, i) => (
              <Link key={agent.id} to={`/app/registry/${encodeURIComponent(agent.id)}`}>
                <motion.div 
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.1 }}
                  className="p-6 flex flex-col lg:flex-row lg:items-center justify-between hover:bg-surface-hover/50 transition-colors group"
                >
                  <div className="flex-1 mb-4 lg:mb-0">
                    <div className="flex items-center space-x-3 mb-2">
                      <h4 className="text-lg font-bold text-white group-hover:text-cyan-accent transition-colors">{agent.name}</h4>
                      <span className="px-2 py-0.5 rounded text-xs font-mono bg-border text-gray-300">
                        {agent.version}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                        agent.status === 'Active' ? 'bg-emerald-accent/10 text-emerald-accent border border-emerald-accent/20' : 'bg-amber-accent/10 text-amber-accent border border-amber-accent/20'
                      }`}>
                        {agent.status}
                      </span>
                    </div>
                    <div className="flex items-center text-sm text-gray-500 font-mono">
                      <Link2 className="w-4 h-4 mr-1" />
                      {agent.id}
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-8">
                    <div className="text-right">
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Royalty</p>
                      <p className="font-mono text-sm text-white">{agent.royalty}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Runs</p>
                      <p className="font-mono text-sm text-white">{agent.runs}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Bond</p>
                      <p className="font-mono text-sm text-amber-accent">{agent.bond}</p>
                    </div>
                    <div className="text-right">
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Hardware</p>
                      <p className="font-mono text-sm text-cyan-accent">vram_min: {agent.vram}</p>
                    </div>
                    <button className="p-2 border border-border rounded hover:bg-border transition-colors text-gray-400 group-hover:text-white group-hover:bg-surface-hover">
                      <ArrowUpRight className="w-5 h-5" />
                    </button>
                  </div>
                </motion.div>
              </Link>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
