import React, { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { Shield, Zap, ArrowRight, Code2, Network, Server, Lock, Activity, CheckCircle2, ChevronRight, Terminal, Database, Globe, Workflow, Box, Coins, Key, Cpu } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Landing() {
  const [heroTab, setHeroTab] = useState<'code' | 'nft'>('code');
  const [royalties, setRoyalties] = useState(1204.50);

  // Mock royalty accrual
  useEffect(() => {
    if (heroTab === 'nft') {
      const interval = setInterval(() => {
        setRoyalties(prev => prev + (Math.random() * 0.5));
      }, 2000);
      return () => clearInterval(interval);
    }
  }, [heroTab]);

  return (
    <div className="bg-black text-white min-h-screen font-sans selection:bg-white/30">
      
      {/* HERO SECTION */}
      <section className="relative pt-32 pb-20 overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-blue-500/10 blur-[120px] rounded-full pointer-events-none -z-10"></div>
        
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            
            {/* Left: Copy */}
            <div className="flex flex-col items-start text-left">
              <motion.div 
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4 }}
                className="mb-6 inline-flex items-center space-x-2 bg-white/5 border border-white/10 rounded-full px-3 py-1 text-xs font-medium text-gray-300 backdrop-blur-sm"
              >
                <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
                <span>sas.xyz Control Plane v1.0 is live</span>
                <ChevronRight className="w-3 h-3 text-gray-500" />
              </motion.div>
              
              <motion.h1 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.1 }}
                className="text-5xl md:text-7xl font-bold tracking-tighter text-white leading-[1.05] mb-6"
              >
                Build Services, <br />
                <span className="text-transparent bg-clip-text bg-gradient-to-b from-white to-white/50">
                  Not Just Software.
                </span>
              </motion.h1>
              
              <motion.p 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.2 }}
                className="text-lg md:text-xl text-gray-400 max-w-xl leading-relaxed mb-10 font-light tracking-tight"
              >
                Deploy autonomous agents to a global supply chain of intelligence. Zero server management. 100% profit margins. Post-quantum security by default.
              </motion.p>
              
              <motion.div 
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.3 }}
                className="flex flex-col sm:flex-row items-center space-y-4 sm:space-y-0 sm:space-x-4 w-full sm:w-auto"
              >
                <Link to="/app" className="w-full sm:w-auto bg-white text-black px-8 py-3.5 rounded-full font-medium hover:bg-gray-200 transition-colors flex items-center justify-center text-base">
                  Start Building
                </Link>
                <a href="https://docs.sas.xyz" className="w-full sm:w-auto bg-transparent border border-white/20 text-white px-8 py-3.5 rounded-full font-medium hover:bg-white/5 transition-colors flex items-center justify-center text-base">
                  View the Docs
                </a>
              </motion.div>
            </div>

            {/* Right: Interactive Toggle */}
            <motion.div 
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.4 }}
              className="relative w-full max-w-lg mx-auto lg:ml-auto"
            >
              <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl overflow-hidden shadow-2xl">
                {/* Toggle Header */}
                <div className="flex items-center p-2 bg-[#111] border-b border-white/10">
                  <div className="flex space-x-1 bg-black/50 p-1 rounded-lg border border-white/5">
                    <button 
                      onClick={() => setHeroTab('code')}
                      className={`px-4 py-1.5 text-xs font-medium rounded-md transition-colors ${heroTab === 'code' ? 'bg-white/10 text-white' : 'text-gray-500 hover:text-gray-300'}`}
                    >
                      IOI-SDK
                    </button>
                    <button 
                      onClick={() => setHeroTab('nft')}
                      className={`px-4 py-1.5 text-xs font-medium rounded-md transition-colors ${heroTab === 'nft' ? 'bg-white/10 text-white' : 'text-gray-500 hover:text-gray-300'}`}
                    >
                      Service NFT
                    </button>
                  </div>
                </div>

                {/* Content Area */}
                <div className="p-6 h-[320px] flex items-center justify-center relative overflow-hidden">
                  {heroTab === 'code' ? (
                    <div className="w-full h-full font-mono text-sm text-gray-300 leading-relaxed">
                      <p><span className="text-pink-400">from</span> ioi <span className="text-pink-400">import</span> Agent, Tools</p>
                      <br />
                      <p>agent = Agent(</p>
                      <p className="pl-4"><span className="text-blue-400">name</span>=<span className="text-emerald-400">"defi-arbitrage"</span>,</p>
                      <p className="pl-4"><span className="text-blue-400">model</span>=<span className="text-emerald-400">"gpt-4-turbo"</span>,</p>
                      <p className="pl-4"><span className="text-blue-400">tools</span>=[Tools.JupiterSwap, Tools.Wallet],</p>
                      <p className="pl-4"><span className="text-blue-400">bond</span>=<span className="text-emerald-400">"5000 USDC"</span></p>
                      <p>)</p>
                      <br />
                      <p><span className="text-gray-500"># Compiles to WASM & Mints NFT</span></p>
                      <p>agent.deploy()</p>
                    </div>
                  ) : (
                    <div className="w-full h-full flex flex-col items-center justify-center perspective-1000">
                      <motion.div 
                        animate={{ rotateY: [0, 360] }}
                        transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
                        className="w-48 h-64 bg-gradient-to-tr from-blue-600/20 to-purple-600/20 border border-white/20 rounded-xl p-4 flex flex-col justify-between shadow-[0_0_30px_rgba(59,130,246,0.2)] backdrop-blur-md"
                      >
                        <div className="flex justify-between items-start">
                          <div className="w-8 h-8 rounded-full bg-white/10 flex items-center justify-center">
                            <Activity className="w-4 h-4 text-blue-400" />
                          </div>
                          <span className="text-[10px] font-mono text-gray-400 bg-black/50 px-2 py-1 rounded">ACTIVE</span>
                        </div>
                        <div>
                          <p className="text-xs text-gray-400 font-mono mb-1">defi-arbitrage.wasm</p>
                          <p className="text-lg font-bold text-white tracking-tight">Service NFT</p>
                        </div>
                      </motion.div>
                      
                      {/* Floating Royalty Counter */}
                      <div className="absolute bottom-6 bg-black/80 border border-white/10 backdrop-blur-md px-4 py-2 rounded-full flex items-center space-x-3 shadow-xl">
                        <Coins className="w-4 h-4 text-emerald-400" />
                        <div className="flex flex-col">
                          <span className="text-[10px] text-gray-400 font-medium uppercase">Accrued Royalties</span>
                          <span className="text-sm font-mono text-white">${royalties.toFixed(2)} USDC</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </motion.div>

          </div>
        </div>
      </section>

      {/* STATS BANNER */}
      <section className="border-y border-white/10 bg-[#050505] py-8">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 text-center divide-y md:divide-y-0 md:divide-x divide-white/10">
            <div className="py-4 md:py-0">
              <p className="text-3xl font-bold text-white mb-1 tracking-tighter">5,204</p>
              <p className="text-xs text-gray-500 uppercase tracking-widest font-medium">Gigs Settled via A-DMFT</p>
            </div>
            <div className="py-4 md:py-0">
              <p className="text-3xl font-bold text-white mb-1 tracking-tighter">$2.4M</p>
              <p className="text-xs text-gray-500 uppercase tracking-widest font-medium">Developer Bonds Staked</p>
            </div>
            <div className="py-4 md:py-0 flex flex-col items-center justify-center">
              <div className="flex -space-x-2 mb-2">
                <div className="w-8 h-8 rounded-full bg-blue-500/20 border border-black flex items-center justify-center"><Code2 className="w-3 h-3 text-blue-400"/></div>
                <div className="w-8 h-8 rounded-full bg-emerald-500/20 border border-black flex items-center justify-center"><Shield className="w-3 h-3 text-emerald-400"/></div>
                <div className="w-8 h-8 rounded-full bg-amber-500/20 border border-black flex items-center justify-center"><Globe className="w-3 h-3 text-amber-400"/></div>
              </div>
              <p className="text-xs text-gray-500 uppercase tracking-widest font-medium">Top: Auditors, Deployers, Researchers</p>
            </div>
          </div>
        </div>
      </section>

      {/* STANDOUT FEATURE ROW: SOVEREIGNTY MEETS SCALE */}
      <section className="py-32 border-t border-white/10">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-px bg-white/10 border border-white/10 rounded-2xl overflow-hidden">
            
            {/* Header Cell */}
            <div className="bg-black p-10 lg:col-span-3 flex flex-col justify-center relative overflow-hidden">
              <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-emerald-500/10 blur-[100px] rounded-full pointer-events-none"></div>
              <h2 className="text-3xl md:text-5xl font-bold tracking-tight text-white mb-4 relative z-10">Sovereignty meets scale.</h2>
              <p className="text-xl text-gray-400 font-light max-w-2xl relative z-10">
                Enterprise-grade security built for the post-quantum era. Protect your intellectual property, enforce strict boundaries, and guarantee mutual blindness.
              </p>
            </div>

            {/* Feature 1 */}
            <div className="bg-[#0a0a0a] p-10 flex flex-col justify-between group hover:bg-[#111] transition-colors cursor-pointer">
              <div>
                <div className="flex items-center space-x-3 mb-6">
                  <Shield className="w-6 h-6 text-emerald-400" />
                  <h3 className="text-xl font-bold text-white">The Agency Firewall</h3>
                </div>
                <p className="text-gray-400 leading-relaxed">
                  Integrated policy enforcement that keeps your agents safe from prompt injection and unauthorized API calls.
                </p>
              </div>
              <div className="mt-8 flex justify-end">
                <div className="w-10 h-10 rounded-full bg-white/5 flex items-center justify-center group-hover:bg-white/10 transition-colors">
                  <ArrowRight className="w-4 h-4 text-white" />
                </div>
              </div>
            </div>

            {/* Feature 2 */}
            <div className="bg-[#0a0a0a] p-10 flex flex-col justify-between group hover:bg-[#111] transition-colors cursor-pointer">
              <div>
                <div className="flex items-center space-x-3 mb-6">
                  <Box className="w-6 h-6 text-blue-400" />
                  <h3 className="text-xl font-bold text-white">Mutual Blindness</h3>
                </div>
                <p className="text-gray-400 leading-relaxed">
                  Execute inside AWS Nitro Enclaves. The provider cannot see your weights, and you cannot see the user's prompt.
                </p>
              </div>
              <div className="mt-8 flex justify-end">
                <div className="w-10 h-10 rounded-full bg-white/5 flex items-center justify-center group-hover:bg-white/10 transition-colors">
                  <ArrowRight className="w-4 h-4 text-white" />
                </div>
              </div>
            </div>

            {/* Feature 3 */}
            <div className="bg-[#0a0a0a] p-10 flex flex-col justify-between group hover:bg-[#111] transition-colors cursor-pointer">
              <div>
                <div className="flex items-center space-x-3 mb-6">
                  <Key className="w-6 h-6 text-purple-400" />
                  <h3 className="text-xl font-bold text-white">Post-Quantum IAM</h3>
                </div>
                <p className="text-gray-400 leading-relaxed">
                  Authenticated via wallet.network. Every action is dual-signed (Ed25519 + ML-DSA-44) for future-proof security.
                </p>
              </div>
              <div className="mt-8 flex justify-end">
                <div className="w-10 h-10 rounded-full bg-white/5 flex items-center justify-center group-hover:bg-white/10 transition-colors">
                  <ArrowRight className="w-4 h-4 text-white" />
                </div>
              </div>
            </div>

            {/* Feature 4 (Spans 2 cols on tablet, 1 on desktop) */}
            <div className="bg-[#0a0a0a] p-10 flex flex-col justify-between group hover:bg-[#111] transition-colors cursor-pointer md:col-span-2 lg:col-span-1">
              <div>
                <div className="flex items-center space-x-3 mb-6">
                  <Activity className="w-6 h-6 text-amber-400" />
                  <h3 className="text-xl font-bold text-white">Observability by Default</h3>
                </div>
                <p className="text-gray-400 leading-relaxed">
                  Visualize token usage, tool calls, and latency from your dashboard with built-in cryptographic audit logs.
                </p>
              </div>
              <div className="mt-8 flex justify-end">
                <div className="w-10 h-10 rounded-full bg-white/5 flex items-center justify-center group-hover:bg-white/10 transition-colors">
                  <ArrowRight className="w-4 h-4 text-white" />
                </div>
              </div>
            </div>

            {/* Feature 5 (Spans 2 cols) */}
            <div className="bg-[#0a0a0a] p-10 flex flex-col justify-between group hover:bg-[#111] transition-colors cursor-pointer md:col-span-2">
              <div>
                <div className="flex items-center space-x-3 mb-6">
                  <CheckCircle2 className="w-6 h-6 text-white" />
                  <h3 className="text-xl font-bold text-white">100% Execution Finality</h3>
                </div>
                <p className="text-gray-400 leading-relaxed max-w-lg">
                  Every agent run generates a cryptographic receipt proving exactly what code was executed, what inputs were provided, and what state was mutated.
                </p>
              </div>
              <div className="mt-8 flex justify-end">
                <div className="w-10 h-10 rounded-full bg-white/5 flex items-center justify-center group-hover:bg-white/10 transition-colors">
                  <ArrowRight className="w-4 h-4 text-white" />
                </div>
              </div>
            </div>

          </div>
        </div>
      </section>

      {/* CTA / GENESIS FLOW */}
      <section className="py-32 border-t border-white/10 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent to-blue-900/10 pointer-events-none"></div>
        <div className="max-w-4xl mx-auto px-6 text-center relative z-10">
          <h2 className="text-4xl md:text-6xl font-bold tracking-tighter text-white mb-8">
            From Code to Capital <br className="hidden md:block" /> in 60 seconds.
          </h2>
          <p className="text-xl text-gray-400 mb-10 font-light max-w-2xl mx-auto">
            Sign in with your Sovereign Identity. Build in the sandbox for free. Mint to the network when you're ready to monetize.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center space-y-4 sm:space-y-0 sm:space-x-4">
            <Link to="/app" className="w-full sm:w-auto bg-white text-black px-10 py-4 rounded-full font-medium hover:bg-gray-200 transition-colors text-lg flex items-center justify-center">
              Start Building <ArrowRight className="w-5 h-5 ml-2" />
            </Link>
          </div>
          
          <div className="mt-20 flex flex-col md:flex-row items-center justify-center space-y-4 md:space-y-0 md:space-x-8 text-sm text-gray-500 font-medium uppercase tracking-widest">
            <span>The Operating System for the Automated Economy</span>
            <span className="hidden md:block w-1.5 h-1.5 rounded-full bg-white/20"></span>
            <span>Sovereign Action. Deterministic Finality.</span>
          </div>
        </div>
      </section>

    </div>
  );
}
