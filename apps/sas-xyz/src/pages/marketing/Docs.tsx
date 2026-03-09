import { BookOpen, Code2, Shield, Settings } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Docs() {
  return (
    <div className="bg-black text-white min-h-screen font-sans pt-32 pb-20 flex">
      
      {/* Sidebar */}
      <div className="hidden lg:block w-64 border-r border-white/10 h-[calc(100vh-80px)] sticky top-20 overflow-y-auto px-6 py-8">
        <h3 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-4">Getting Started</h3>
        <ul className="space-y-3 mb-8">
          <li><a href="#" className="text-sm text-white font-medium hover:text-blue-400">Quickstart</a></li>
          <li><a href="#" className="text-sm text-gray-400 hover:text-white">Installation</a></li>
          <li><a href="#" className="text-sm text-gray-400 hover:text-white">Your First Agent</a></li>
        </ul>

        <h3 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-4">Core Concepts</h3>
        <ul className="space-y-3 mb-8">
          <li><a href="#" className="text-sm text-gray-400 hover:text-white">The AIIP Spec</a></li>
          <li><a href="#" className="text-sm text-gray-400 hover:text-white">Agency Firewalls</a></li>
          <li><a href="#" className="text-sm text-gray-400 hover:text-white">Service NFTs</a></li>
        </ul>

        <h3 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-4">Resources</h3>
        <ul className="space-y-3">
          <li><a href="#" className="text-sm text-blue-400 hover:text-blue-300 flex items-center">Whitepaper PDF</a></li>
          <li><a href="#" className="text-sm text-emerald-400 hover:text-emerald-300 flex items-center">ioi.network Explorer</a></li>
        </ul>
      </div>

      {/* Main Content */}
      <div className="flex-1 max-w-4xl px-6 py-8 lg:px-16">
        <h1 className="text-4xl md:text-5xl font-display font-bold tracking-tighter text-white mb-6">
          Documentation
        </h1>
        <p className="text-xl text-gray-400 font-light leading-relaxed mb-12">
          Everything you need to build, deploy, and scale autonomous services on the IOI network.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-16">
          <div className="bg-[#0a0a0a] border border-white/10 rounded-xl p-6 hover:border-white/20 transition-colors">
            <Code2 className="w-6 h-6 text-blue-400 mb-4" />
            <h3 className="text-lg font-bold text-white mb-2">The Quickstart</h3>
            <p className="text-sm text-gray-400 mb-4">Deploy your first agent in 60 seconds using the IOI-SDK.</p>
            <a href="#" className="text-sm text-blue-400 hover:text-blue-300 font-medium">Read guide →</a>
          </div>

          <div className="bg-[#0a0a0a] border border-white/10 rounded-xl p-6 hover:border-white/20 transition-colors">
            <BookOpen className="w-6 h-6 text-emerald-400 mb-4" />
            <h3 className="text-lg font-bold text-white mb-2">The AIIP Spec</h3>
            <p className="text-sm text-gray-400 mb-4">Technical details on the Agentic Interoperability Protocol.</p>
            <a href="#" className="text-sm text-emerald-400 hover:text-emerald-300 font-medium">Read spec →</a>
          </div>

          <div className="bg-[#0a0a0a] border border-white/10 rounded-xl p-6 hover:border-white/20 transition-colors">
            <Shield className="w-6 h-6 text-amber-400 mb-4" />
            <h3 className="text-lg font-bold text-white mb-2">The Firewall Guide</h3>
            <p className="text-sm text-gray-400 mb-4">How to write ActionRules to secure your agent's execution.</p>
            <a href="#" className="text-sm text-amber-400 hover:text-amber-300 font-medium">Read guide →</a>
          </div>

          <div className="bg-[#0a0a0a] border border-white/10 rounded-xl p-6 hover:border-white/20 transition-colors">
            <Settings className="w-6 h-6 text-purple-400 mb-4" />
            <h3 className="text-lg font-bold text-white mb-2">Driver SDK</h3>
            <p className="text-sm text-gray-400 mb-4">Build new "Digital Hardware" connections and custom API drivers.</p>
            <a href="#" className="text-sm text-purple-400 hover:text-purple-300 font-medium">Read SDK docs →</a>
          </div>
        </div>

        <div className="prose prose-invert max-w-none">
          <h2>Installation</h2>
          <p>Install the IOI-SDK via pip:</p>
          <pre className="bg-[#111] border border-white/10 rounded-lg p-4 font-mono text-sm text-gray-300">
            <code>pip install ioi-sdk</code>
          </pre>
          <p>Or use the Node.js package:</p>
          <pre className="bg-[#111] border border-white/10 rounded-lg p-4 font-mono text-sm text-gray-300">
            <code>npm install @ioi/sdk</code>
          </pre>
        </div>

      </div>
    </div>
  );
}
