import React, { useState } from 'react';
import { motion } from 'motion/react';
import { Coins, TrendingUp, Zap, Activity } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Economics() {
  const [taskCost, setTaskCost] = useState(0.05);
  const [royalty, setRoyalty] = useState(15);
  const [volume, setVolume] = useState(10000);

  const monthlyRevenue = taskCost * volume * (royalty / 100);

  return (
    <div className="bg-black text-white min-h-screen font-sans pt-32 pb-20">
      <div className="max-w-7xl mx-auto px-6">
        
        {/* Header */}
        <div className="mb-16 text-center max-w-3xl mx-auto">
          <h1 className="text-4xl md:text-6xl font-display font-bold tracking-tighter text-white mb-6">
            The Profit Calculator
          </h1>
          <p className="text-xl text-gray-400 font-light leading-relaxed">
            Service-as-a-Software means zero idle infrastructure costs. You only pay when your agent runs, and you collect royalties on every execution.
          </p>
        </div>

        {/* Calculator Section */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center mb-32">
          
          {/* Sliders */}
          <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-8 shadow-2xl">
            <h3 className="text-2xl font-bold text-white mb-8">Project Your Earnings</h3>
            
            <div className="space-y-8">
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-gray-400">Average Task Cost (Compute + LLM)</span>
                  <span className="text-white font-mono">${taskCost.toFixed(3)}</span>
                </div>
                <input 
                  type="range" min="0.01" max="1.00" step="0.01" 
                  value={taskCost} onChange={(e) => setTaskCost(parseFloat(e.target.value))}
                  className="w-full accent-blue-500"
                />
              </div>

              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-gray-400">Desired Royalty %</span>
                  <span className="text-white font-mono">{royalty}%</span>
                </div>
                <input 
                  type="range" min="1" max="50" step="1" 
                  value={royalty} onChange={(e) => setRoyalty(parseInt(e.target.value))}
                  className="w-full accent-emerald-500"
                />
              </div>

              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-gray-400">Monthly Executions (Volume)</span>
                  <span className="text-white font-mono">{volume.toLocaleString()}</span>
                </div>
                <input 
                  type="range" min="1000" max="1000000" step="1000" 
                  value={volume} onChange={(e) => setVolume(parseInt(e.target.value))}
                  className="w-full accent-purple-500"
                />
              </div>
            </div>
          </div>

          {/* Results */}
          <div className="relative">
            <div className="absolute inset-0 bg-gradient-to-tr from-emerald-500/10 to-transparent blur-3xl rounded-full"></div>
            <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-10 relative overflow-hidden shadow-2xl flex flex-col items-center text-center">
              <Coins className="w-12 h-12 text-emerald-400 mb-6" />
              <p className="text-sm text-gray-400 uppercase tracking-widest font-medium mb-2">Projected Monthly Royalties</p>
              <h2 className="text-6xl font-bold text-white tracking-tighter mb-4">
                ${monthlyRevenue.toLocaleString(undefined, {minimumFractionDigits: 2, maximumFractionDigits: 2})}
              </h2>
              <p className="text-gray-500 text-sm max-w-xs">
                Paid directly to your wallet in USDC or Labor Gas. Zero server costs deducted.
              </p>
              
              <div className="mt-8 w-full bg-white/5 border border-white/10 rounded-xl p-4 flex justify-between items-center">
                <span className="text-sm text-gray-400">Infrastructure Cost</span>
                <span className="text-sm font-bold text-emerald-500">$0.00</span>
              </div>
            </div>
          </div>

        </div>

        {/* Zero-Idle Visualization */}
        <div className="border-t border-white/10 pt-32">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-5xl font-display font-bold tracking-tight text-white mb-6">
              The Zero-Idle Advantage
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto font-light">
              Why pay for servers when your code isn't running?
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-6 flex items-center"><Activity className="w-5 h-5 mr-2 text-red-400"/> Legacy Hosting</h3>
              <div className="h-48 w-full flex items-end space-x-2">
                {/* Fixed cost bars */}
                {[...Array(20)].map((_, i) => (
                  <div key={i} className="flex-1 bg-red-500/20 border-t border-red-500/50 rounded-t" style={{ height: '80%' }}></div>
                ))}
              </div>
              <p className="text-center text-sm text-gray-500 mt-4">High fixed costs, regardless of usage.</p>
            </div>

            <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-8">
              <h3 className="text-xl font-bold text-white mb-6 flex items-center"><Zap className="w-5 h-5 mr-2 text-emerald-400"/> IOI SaS</h3>
              <div className="h-48 w-full flex items-end space-x-2">
                {/* Variable cost bars */}
                {[...Array(20)].map((_, i) => (
                  <div key={i} className={`flex-1 rounded-t ${i % 4 === 0 ? 'bg-emerald-500/80 h-[60%]' : i % 7 === 0 ? 'bg-emerald-500/80 h-[90%]' : 'bg-transparent h-0'}`}></div>
                ))}
              </div>
              <p className="text-center text-sm text-gray-500 mt-4">Costs scale perfectly with revenue.</p>
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
