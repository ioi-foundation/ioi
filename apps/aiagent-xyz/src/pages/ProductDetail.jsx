// src/pages/ProductDetail.jsx
import React, { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import Header from '../components/Header';
import DeploymentModal from '../components/DeploymentModal'; 
import NotFound from './NotFound'; // Import 404

// Expanded Mock Data Database
const agents = [
  {
    id: 1,
    name: 'DeFi Arbitrage Sentinel',
    developer: 'QuantLabs_0x',
    verified: true,
    tier: 'Bonded (Tier 2)',
    bondAmount: '$50,000 USDC',
    description: 'An autonomous monitoring agent that scans Solana and Base DEXs for price inefficiencies. Executes atomic arbitrage via Flash Loans. Requires a funded wallet with at least 5 SOL.',
    capabilities: ['net:fetch', 'chain:sign', 'compute:heavy'],
    integrations: ['Jupiter', 'Uniswap', 'Telegram'],
    pricing: { rent: '$0.05 / execution', source: '$4,500 (License)' },
    stats: { users: '1.2k', uptime: '99.9%', avg_latency: '45ms' },
    manifest: { authority: "did:ioi:quantlabs", version: "v2.4.1", runtime: "python:3.11", hardware: "gpu:h100:1" }
  },
  {
    id: 2,
    name: 'Legal Doc Reviewer v4',
    developer: 'LawAI_Corp',
    verified: true,
    tier: 'Verified (Tier 3)',
    bondAmount: '$10,000 USDC',
    description: 'Specialized LLM pipeline for analyzing NDAs, SAFTs, and Service Agreements. Highlights risk clauses and generates redlines automatically.',
    capabilities: ['fs:read', 'compute:mid', 'net:none'],
    integrations: ['Google Drive', 'DocuSign', 'Notion'],
    pricing: { rent: '$29 / month', source: '$12,000 (Enterprise)' },
    stats: { users: '856', uptime: '99.5%', avg_latency: '2.1s' },
    manifest: { authority: "did:ioi:lawai", version: "v4.0.2", runtime: "python:3.10", hardware: "cpu:16core" }
  },
  {
    id: 3,
    name: 'Research Swarm (DeepSeek)',
    developer: 'OpenSci',
    verified: false,
    tier: 'Standard (Tier 1)',
    bondAmount: '$0',
    description: 'A recursive research agent that browses the web, reads academic papers, and synthesizes findings into a markdown report with citations.',
    capabilities: ['net:browse', 'fs:write', 'compute:heavy'],
    integrations: ['Obsidian', 'Zotero', 'Browser'],
    pricing: { rent: 'Free', source: 'Free (MIT)' },
    stats: { users: '2.1k', uptime: '98.0%', avg_latency: '45s' },
    manifest: { authority: "did:ioi:opensci", version: "v1.1.0", runtime: "python:3.11", hardware: "gpu:a100:1" }
  },
  {
    id: 4,
    name: 'Smart Home Orchestrator',
    developer: 'IoT_Native',
    verified: true,
    tier: 'Standard (Tier 1)',
    bondAmount: '$1,000 USDC',
    description: 'Local-first home automation coordinator. Connects Home Assistant to IOI intents. "Turn off lights when I leave" becomes a sovereign policy.',
    capabilities: ['net:local', 'iot:control'],
    integrations: ['Home Assistant', 'Philips Hue', 'Sonos'],
    pricing: { rent: '$15 / license', source: '$15 (Source)' },
    stats: { users: '89', uptime: '100%', avg_latency: '12ms' },
    manifest: { authority: "did:ioi:iotnative", version: "v0.9.5", runtime: "rust:1.75", hardware: "cpu:arm64" }
  },
  {
    id: 9,
    name: 'Accounting Worker v3.2',
    developer: 'LedgerFlow_AI',
    verified: true,
    tier: 'Verified (Tier 3)',
    bondAmount: '$15,000 USDC',
    description: 'Automates invoice intake, coding, routing, and follow-up for finance teams processing up to 10,000 invoices per month. Learns your approval policy in under two hours and keeps exception handling active around the clock.',
    capabilities: ['fs:read', 'compute:mid', 'net:fetch'],
    integrations: ['QuickBooks', 'NetSuite', 'Slack'],
    pricing: { rent: '$49 / month', source: 'Custom Quote' },
    stats: { users: '218', uptime: '99.97%', avg_latency: '1.3s' },
    manifest: { authority: "did:ioi:ledgerflow", version: "v3.2.0", runtime: "python:3.11", hardware: "cpu:8core" }
  }
];

export default function ProductDetail() {
  const { id } = useParams();
  const [activeTab, setActiveTab] = useState('overview');
  const [isDeployOpen, setIsDeployOpen] = useState(false);

  // Data Lookup
  const agentData = agents.find(a => a.id.toString() === id);

  // 404 Handling
  if (!agentData) {
    return <NotFound />;
  }

  return (
    <div className="min-h-screen bg-slate-50">
      <Header />
      
      <DeploymentModal 
        isOpen={isDeployOpen} 
        onClose={() => setIsDeployOpen(false)} 
        agent={agentData} 
      />

      <main className="container mx-auto px-4 py-8 max-w-6xl">
        
        {/* Breadcrumbs */}
        <div className="text-sm text-slate-500 mb-6">
          <Link to="/" className="hover:text-blue-600">Marketplace</Link> 
          <span className="mx-2">/</span>
          <span>Agents</span>
          <span className="mx-2">/</span>
          <span className="text-slate-900 font-medium">{agentData.name}</span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          
          {/* LEFT COLUMN: Main Info */}
          <div className="lg:col-span-8 space-y-6">
            {/* Header Card */}
            <div className="bg-white border border-gray-200 rounded-xl p-6 shadow-sm">
              <div className="flex items-start justify-between">
                <div className="flex gap-4">
                  <div className="w-16 h-16 rounded-lg bg-gradient-to-br from-slate-800 to-slate-900 flex items-center justify-center text-white text-2xl font-bold shadow-inner">
                    {agentData.name[0]}
                  </div>
                  <div>
                    <h1 className="text-2xl font-bold text-slate-900">{agentData.name}</h1>
                    <div className="flex items-center gap-2 mt-1 text-sm">
                      <span className="text-slate-500">by</span>
                      <Link to={`/profile/${agentData.developer}`} className="text-blue-600 font-medium hover:underline flex items-center gap-1">
                        {agentData.developer}
                        {agentData.verified && (
                          <svg className="w-3 h-3 text-blue-500" viewBox="0 0 24 24" fill="currentColor"><path d="M9 16.17L4.83 12l-1.42 1.41L9 19 21 7l-1.41-1.41z"/></svg>
                        )}
                      </Link>
                    </div>
                  </div>
                </div>
                
                {/* KYA Badge (Trust Score) */}
                <div className="flex flex-col items-end">
                   <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-xs font-bold border ${agentData.bondAmount !== '$0' ? 'bg-green-50 text-green-700 border-green-100' : 'bg-slate-100 text-slate-600 border-slate-200'}`}>
                     {agentData.bondAmount !== '$0' && <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>}
                     {agentData.tier}
                   </div>
                   {agentData.bondAmount !== '$0' && (
                      <span className="text-xs text-slate-400 mt-1">Bonded: {agentData.bondAmount}</span>
                   )}
                </div>
              </div>

              <div className="mt-6 flex gap-6 border-t border-gray-100 pt-6">
                <div className="text-center">
                  <div className="text-lg font-bold text-slate-900">{agentData.stats.users}</div>
                  <div className="text-xs text-slate-500 uppercase tracking-wide">Active Users</div>
                </div>
                <div className="text-center border-l border-gray-100 pl-6">
                  <div className="text-lg font-bold text-green-600">{agentData.stats.uptime}</div>
                  <div className="text-xs text-slate-500 uppercase tracking-wide">Reliability</div>
                </div>
                <div className="text-center border-l border-gray-100 pl-6">
                  <div className="text-lg font-bold text-slate-900">{agentData.stats.avg_latency}</div>
                  <div className="text-xs text-slate-500 uppercase tracking-wide">Latency</div>
                </div>
              </div>
            </div>

            {/* Tabs & Content */}
            <div className="bg-white border border-gray-200 rounded-xl min-h-[400px]">
              <div className="flex border-b border-gray-200">
                <button 
                  onClick={() => setActiveTab('overview')}
                  className={`px-6 py-4 text-sm font-medium border-b-2 transition-colors ${activeTab === 'overview' ? 'border-blue-600 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-800'}`}
                >
                  Overview
                </button>
                <button 
                  onClick={() => setActiveTab('manifest')}
                  className={`px-6 py-4 text-sm font-medium border-b-2 transition-colors ${activeTab === 'manifest' ? 'border-blue-600 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-800'}`}
                >
                  Manifest (Code)
                </button>
                <button 
                  onClick={() => setActiveTab('reviews')}
                  className={`px-6 py-4 text-sm font-medium border-b-2 transition-colors ${activeTab === 'reviews' ? 'border-blue-600 text-blue-600' : 'border-transparent text-slate-500 hover:text-slate-800'}`}
                >
                  Reviews (12)
                </button>
              </div>

              <div className="p-6">
                {activeTab === 'overview' && (
                  <div className="space-y-8">
                    <div>
                      <h3 className="text-lg font-bold text-slate-900 mb-3">About this Agent</h3>
                      <p className="text-slate-600 leading-relaxed">
                        {agentData.description}
                      </p>
                    </div>

                    <div>
                      <h3 className="text-sm font-bold text-slate-900 mb-3 uppercase tracking-wide">Capabilities</h3>
                      <div className="flex flex-wrap gap-2">
                        {agentData.capabilities.map(cap => (
                          <span key={cap} className="px-3 py-1 bg-slate-100 text-slate-600 text-xs font-mono rounded border border-slate-200">
                            {cap}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h3 className="text-sm font-bold text-slate-900 mb-3 uppercase tracking-wide">Integrations</h3>
                      <div className="flex gap-4">
                        {agentData.integrations.map(int => (
                          <div key={int} className="flex items-center gap-2 text-sm text-slate-700 bg-white border border-gray-200 px-3 py-2 rounded shadow-sm">
                            <div className="w-2 h-2 rounded-full bg-blue-500"></div>
                            {int}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'manifest' && (
                  <div className="relative group">
                    <pre className="bg-slate-900 text-slate-300 p-4 rounded-lg overflow-x-auto font-mono text-xs leading-relaxed">
                      {JSON.stringify(agentData.manifest, null, 2)}
                    </pre>
                    <button className="absolute top-3 right-3 bg-white/10 hover:bg-white/20 text-white px-2 py-1 rounded text-xs opacity-0 group-hover:opacity-100 transition-opacity">
                      Copy
                    </button>
                  </div>
                )}
                
                {activeTab === 'reviews' && (
                   <div className="text-center py-12 text-slate-500">
                     <p>Reviews coming soon to the IOI Protocol.</p>
                   </div>
                )}
              </div>
            </div>
          </div>

          {/* RIGHT COLUMN: Action Card */}
          <div className="lg:col-span-4 space-y-6">
            <div className="bg-white border border-gray-200 rounded-xl p-6 shadow-lg sticky top-24">
              <h3 className="text-lg font-bold text-slate-900 mb-4">Acquisition Options</h3>
              
              <div 
                className="mb-4 p-4 border-2 border-blue-600 bg-blue-50/30 rounded-lg cursor-pointer relative hover:shadow-md transition-shadow"
                onClick={() => setIsDeployOpen(true)}
              >
                <div className="absolute top-3 right-3 w-4 h-4 bg-blue-600 rounded-full flex items-center justify-center">
                  <div className="w-2 h-2 bg-white rounded-full"></div>
                </div>
                <div className="font-bold text-slate-900 mb-1">Rent Instance</div>
                <div className="text-2xl font-black text-slate-900 mb-2">{agentData.pricing.rent}</div>
                <div className="text-xs text-slate-500">Runs on IOI Provider Network. Zero setup.</div>
              </div>

              <div className="mb-6 p-4 border border-gray-200 rounded-lg hover:border-gray-300 cursor-pointer transition-colors">
                <div className="font-bold text-slate-700 mb-1">Source License</div>
                <div className="text-xl font-bold text-slate-900 mb-2">{agentData.pricing.source}</div>
                <div className="text-xs text-slate-500 leading-relaxed">
                  Full Source + <span className="font-semibold text-blue-600">Network License</span>. 
                  <span className="block mt-1 text-slate-400">Note: Liability Bond applies only to verified provider execution.</span>
                </div>
              </div>

              <button 
                onClick={() => setIsDeployOpen(true)}
                className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3 px-4 rounded-lg shadow-md transition-transform active:scale-[0.98]"
              >
                Hire Agent Now
              </button>
              
              <div className="mt-4 text-center">
                <span className="text-xs text-slate-400 flex items-center justify-center gap-1">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg>
                  Escrow Secured via Smart Contract
                </span>
              </div>
            </div>

            <div className="bg-white border border-gray-200 rounded-xl p-6">
              <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4">About the Developer</h4>
              <div className="flex items-center gap-3 mb-4">
                <div className="w-10 h-10 rounded-full bg-slate-200"></div>
                <div>
                  <div className="font-bold text-slate-900">{agentData.developer}</div>
                  <div className="text-xs text-slate-500">Member since 2024</div>
                </div>
              </div>
              <div className="flex gap-2">
                <button className="flex-1 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-bold py-2 rounded border border-slate-200">
                  Contact
                </button>
                <Link to={`/profile/${agentData.developer}`} className="flex-1 bg-slate-50 hover:bg-slate-100 text-slate-700 text-xs font-bold py-2 rounded border border-slate-200 text-center flex items-center justify-center">
                  View Portfolio
                </Link>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
