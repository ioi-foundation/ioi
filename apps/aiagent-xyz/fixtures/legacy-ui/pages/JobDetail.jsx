// src/pages/JobDetail.jsx
import React, { useState } from 'react';
import Header from '../components/Header';
import { useParams, Link } from 'react-router-dom';
import NotFound from './NotFound';

// Mock Jobs DB
const jobs = [
  {
    id: 1,
    title: 'Arbitrage Bot for Solana/Serum (High Frequency)',
    budget: '$3,500 USDC',
    status: 'Open',
    posted: '2h ago',
    client: 'AlphaCapital_DAO',
    clientRep: 4.9,
    description: `We need a high-performance MEV-resistant arbitrage bot for the Solana ecosystem.\n\nRequirements:\n- Monitor Raydium and Orca pools in real-time.\n- Execute atomic swaps within same block.\n- Must handle RPC congestion gracefully.\n- Latency < 50ms.\n\nThe agent must be packaged as a WASM module compliant with the IOI Runtime v1.2 standards.`,
    validation: {
      type: 'Test-Driven (Tier B)',
      suite: 'solana-arb-test-v1.json',
      tests: [
        { name: 'Quote Accuracy', status: 'Required' },
        { name: 'Slippage Tolerance < 0.5%', status: 'Required' },
        { name: 'Transaction Simulation (Success)', status: 'Required' },
        { name: 'Memory Leak Check', status: 'Required' }
      ]
    },
    bids: [
      { dev: 'Solana_Dev_99', amount: '$3,200', time: '1h ago', rep: 4.8 },
      { dev: 'Rust_Ninja', amount: '$3,500', time: '30m ago', rep: 5.0 },
      { dev: 'DeFi_Wizard', amount: '$3,400', time: '5m ago', rep: 4.6 }
    ]
  },
  {
    id: 2,
    title: 'Medical Research Summarizer (PubMed API)',
    budget: '$500 USDC',
    status: 'Open',
    posted: '5h ago',
    client: 'BioSynth_Labs',
    clientRep: 4.5,
    description: 'Need an agent to query PubMed, retrieve abstracts related to "CRISPR off-target effects", and summarize them into a JSON report.',
    validation: {
      type: 'Golden Output Match',
      suite: 'pubmed-golden-set.json',
      tests: [{ name: 'JSON Schema Validation', status: 'Required' }]
    },
    bids: []
  },
  {
    id: 3,
    title: 'Convert Python Scraper to IOI Manifest',
    budget: '$150 USDC',
    status: 'Open',
    posted: '1d ago',
    client: 'DataVortex',
    clientRep: 5.0,
    description: 'I have a working python script. I need it wrapped in an IOI Manifest with correct permission scopes.',
    validation: { type: 'Lint Check', suite: 'manifest-lint', tests: [] },
    bids: []
  }
];

export default function JobDetail() {
  const { id } = useParams();
  const [isBidding, setIsBidding] = useState(false);

  const jobData = jobs.find(j => j.id.toString() === id);

  if (!jobData) {
    return <NotFound />;
  }

  return (
    <div className="min-h-screen bg-slate-50">
      <Header />

      <main className="container mx-auto px-4 py-8 max-w-6xl">
        
        {/* Breadcrumb */}
        <div className="text-sm text-slate-500 mb-6">
          <Link to="/freelance" className="hover:text-blue-600">Freelance</Link> 
          <span className="mx-2">/</span>
          <span>Jobs</span>
          <span className="mx-2">/</span>
          <span className="text-slate-900 font-medium">#{id}</span>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          
          {/* MAIN CONTENT */}
          <div className="lg:col-span-8 space-y-6">
            
            {/* Header Card */}
            <div className="bg-white border border-gray-200 rounded-xl p-8 shadow-sm">
              <div className="flex justify-between items-start mb-4">
                <span className="bg-green-100 text-green-700 text-xs font-bold px-2 py-1 rounded-full uppercase tracking-wide flex items-center gap-1">
                  <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
                  {jobData.status} for Bids
                </span>
                <span className="text-slate-400 text-sm">{jobData.posted}</span>
              </div>
              
              <h1 className="text-3xl font-black text-slate-900 mb-4 tracking-tight leading-tight">
                {jobData.title}
              </h1>

              <div className="flex items-center gap-4 text-sm text-slate-500 pb-6 border-b border-gray-100">
                <span className="flex items-center gap-1">
                  <span className="font-semibold text-slate-900">{jobData.client}</span>
                  <span className="text-yellow-400">★ {jobData.clientRep}</span>
                </span>
                <span>•</span>
                <span>Payment Verified</span>
                <span>•</span>
                <span>Escrow Secured</span>
              </div>

              <div className="py-6 prose prose-slate max-w-none">
                <h3 className="text-sm font-bold text-slate-900 uppercase tracking-wide mb-2">Scope of Work</h3>
                <p className="text-slate-600 whitespace-pre-wrap leading-relaxed">{jobData.description}</p>
              </div>
            </div>

            {/* Validation Strategy Card */}
            <div className="bg-white border border-gray-200 rounded-xl p-6 shadow-sm overflow-hidden relative">
              <div className="absolute top-0 left-0 w-1 h-full bg-blue-600"></div>
              
              <div className="flex justify-between items-center mb-6">
                <div>
                  <h3 className="text-lg font-bold text-slate-900">Validation Strategy</h3>
                  <p className="text-xs text-slate-500 mt-1">Payment is released automatically upon passing these tests.</p>
                </div>
                <span className="bg-blue-50 text-blue-700 text-xs font-bold px-3 py-1.5 rounded-lg border border-blue-100">
                  {jobData.validation.type}
                </span>
              </div>

              <div className="bg-slate-900 rounded-lg p-4 font-mono text-sm">
                 <div className="flex justify-between items-center text-slate-400 border-b border-slate-700 pb-2 mb-2 text-xs uppercase font-bold">
                    <span>Test Suite: {jobData.validation.suite}</span>
                    <span>{jobData.validation.tests.length} Tests</span>
                 </div>
                 <div className="space-y-2">
                    {jobData.validation.tests.map((test, i) => (
                      <div key={i} className="flex justify-between items-center text-slate-300">
                        <div className="flex items-center gap-2">
                          <span className="text-slate-600">{i+1}.</span>
                          <span>{test.name}</span>
                        </div>
                        <span className="text-green-400 text-xs">[REQUIRED]</span>
                      </div>
                    ))}
                 </div>
              </div>
              
              <div className="mt-4 flex gap-2">
                 <button className="text-xs font-bold text-blue-600 hover:text-blue-700 flex items-center gap-1">
                   <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"/></svg>
                   Download Test Vectors
                 </button>
              </div>
            </div>

          </div>

          {/* RIGHT SIDEBAR */}
          <div className="lg:col-span-4 space-y-6">
            
            {/* Action Card */}
            <div className="bg-white border border-gray-200 rounded-xl p-6 shadow-lg sticky top-24">
              <div className="text-center mb-6">
                <span className="text-sm text-slate-500 font-medium">Bounty Amount</span>
                <div className="text-3xl font-black text-slate-900 mt-1">{jobData.budget}</div>
              </div>

              <button 
                onClick={() => setIsBidding(true)}
                className="w-full bg-slate-900 hover:bg-slate-800 text-white font-bold py-3 px-4 rounded-lg shadow-md transition-transform active:scale-[0.98] mb-4"
              >
                Submit Proposal
              </button>
              
              {isBidding && (
                <div className="bg-slate-50 border border-slate-200 rounded-lg p-4 mb-4 animate-in fade-in slide-in-from-top-2">
                  <label className="block text-xs font-bold text-slate-500 uppercase mb-1">Your Bid Amount</label>
                  <input type="text" className="w-full bg-white border border-gray-300 rounded p-2 text-sm mb-3" placeholder={jobData.budget} />
                  
                  <label className="block text-xs font-bold text-slate-500 uppercase mb-1">Time to Deliver</label>
                  <input type="text" className="w-full bg-white border border-gray-300 rounded p-2 text-sm mb-3" placeholder="7 Days" />
                  
                  <button className="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 rounded text-sm">
                    Confirm Bid
                  </button>
                </div>
              )}

              <div className="text-xs text-slate-400 text-center">
                Includes <span className="font-semibold text-slate-600">Atomic Settlement</span> protection.
              </div>
            </div>

            {/* Current Bids */}
            <div className="bg-white border border-gray-200 rounded-xl p-6">
              <h3 className="font-bold text-slate-900 mb-4 text-sm uppercase tracking-wide">Current Proposals</h3>
              <div className="space-y-4">
                {jobData.bids.length > 0 ? jobData.bids.map((bid, i) => (
                  <div key={i} className="flex justify-between items-center pb-3 border-b border-gray-50 last:border-0 last:pb-0">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-full bg-slate-100 flex items-center justify-center text-xs font-bold text-slate-500">
                        {bid.dev[0]}
                      </div>
                      <div>
                        <div className="text-sm font-semibold text-slate-800">{bid.dev}</div>
                        <div className="text-[10px] text-slate-400">{bid.time}</div>
                      </div>
                    </div>
                    <div className="text-right">
                       <div className="text-sm font-bold text-slate-900">{bid.amount}</div>
                       <div className="text-[10px] text-yellow-500">★ {bid.rep}</div>
                    </div>
                  </div>
                )) : (
                  <div className="text-center text-sm text-slate-500 py-4 italic">No bids yet. Be the first!</div>
                )}
              </div>
            </div>

          </div>
        </div>
      </main>
    </div>
  );
}