import { motion } from 'motion/react';
import { Server, Shield, Activity, Users } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Solutions() {
  return (
    <div className="bg-black text-white min-h-screen font-sans pt-32 pb-20">
      <div className="max-w-7xl mx-auto px-6">
        
        {/* Header */}
        <div className="mb-24 text-center max-w-3xl mx-auto">
          <h1 className="text-4xl md:text-6xl font-display font-bold tracking-tighter text-white mb-6">
            The Enterprise Entryway
          </h1>
          <p className="text-xl text-gray-400 font-light leading-relaxed">
            Automate internal departments without data leaks. Deploy thousands of employee agents securely within your own VPC.
          </p>
        </div>

        {/* Features */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-16 mb-32">
          
          <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-10 hover:border-white/20 transition-colors">
            <Users className="w-10 h-10 text-blue-400 mb-6" />
            <h3 className="text-2xl font-bold text-white mb-4">Mission Control</h3>
            <p className="text-gray-400 leading-relaxed mb-6">
              Manage 1,000+ internal employee agents from a single dashboard. Assign roles, monitor tool usage, and enforce strict spend limits per department.
            </p>
            <div className="h-40 w-full bg-[#111] border border-white/5 rounded-xl flex flex-col justify-end p-4 relative overflow-hidden">
              <div className="absolute top-4 left-4 flex space-x-2">
                <div className="w-2 h-2 rounded-full bg-red-500"></div>
                <div className="w-2 h-2 rounded-full bg-amber-500"></div>
                <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
              </div>
              <div className="h-2 w-1/2 bg-blue-500/50 rounded mb-2"></div>
              <div className="h-2 w-3/4 bg-white/20 rounded mb-2"></div>
              <div className="h-2 w-1/3 bg-white/10 rounded"></div>
            </div>
          </div>

          <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-10 hover:border-white/20 transition-colors">
            <Server className="w-10 h-10 text-emerald-400 mb-6" />
            <h3 className="text-2xl font-bold text-white mb-4">BYO-Infrastructure</h3>
            <p className="text-gray-400 leading-relaxed mb-6">
              Run your own "Private Provider Nodes" inside your VPC. Keep sensitive data completely isolated while still leveraging the IOI network for discovery and settlement.
            </p>
            <div className="h-40 w-full bg-[#111] border border-white/5 rounded-xl flex items-center justify-center relative overflow-hidden">
              <div className="w-16 h-16 border-2 border-emerald-500/50 rounded-full flex items-center justify-center">
                <div className="w-12 h-12 border border-emerald-500/30 rounded-full flex items-center justify-center animate-pulse">
                  <Server className="w-6 h-6 text-emerald-500" />
                </div>
              </div>
            </div>
          </div>

        </div>

        {/* CTA */}
        <div className="text-center">
          <h2 className="text-3xl font-display font-bold text-white mb-6">Ready to secure your AI workforce?</h2>
          <a href="mailto:enterprise@sas.xyz" className="inline-flex items-center justify-center bg-white text-black px-8 py-4 rounded-full font-medium hover:bg-gray-200 transition-colors text-lg">
            Contact Enterprise Sales
          </a>
        </div>

      </div>
    </div>
  );
}
