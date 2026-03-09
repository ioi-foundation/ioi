// src/pages/PostJob.jsx
import React, { useState } from 'react';
import Header from '../components/Header';
import { Link } from 'react-router-dom';

export default function PostJob() {
  const [validationType, setValidationType] = useState('manual');
  const [budget, setBudget] = useState('');

  return (
    <div className="min-h-screen bg-slate-50">
      <Header />

      <main className="container mx-auto px-4 py-12 max-w-3xl">
        
        <div className="mb-8">
          <Link to="/freelance" className="text-sm text-slate-500 hover:text-blue-600 mb-4 inline-block">← Back to Freelance</Link>
          <h1 className="text-3xl font-black text-slate-900 tracking-tight">Post a Request for Agent (RFA)</h1>
          <p className="text-slate-600 mt-2">Define your requirements and lock a bounty. Developers compete to build it.</p>
        </div>

        <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden">
          
          {/* Step 1: Basics */}
          <div className="p-8 border-b border-gray-100">
            <h2 className="text-lg font-bold text-slate-900 mb-4">1. The Basics</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-1">Job Title</label>
                <input type="text" className="w-full bg-slate-50 border border-gray-300 rounded-lg p-3 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none" placeholder="e.g. Arbitrage Bot for Solana" />
              </div>
              
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-1">Description</label>
                <textarea className="w-full bg-slate-50 border border-gray-300 rounded-lg p-3 text-sm h-32 focus:ring-2 focus:ring-blue-500 focus:outline-none" placeholder="Describe the agent's goal, inputs, and expected outputs..."></textarea>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-semibold text-slate-700 mb-1">Category</label>
                  <select className="w-full bg-slate-50 border border-gray-300 rounded-lg p-3 text-sm">
                    <option>DeFi & Trading</option>
                    <option>Data Extraction</option>
                    <option>Content Generation</option>
                    <option>Infrastructure</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-semibold text-slate-700 mb-1">Budget (USDC)</label>
                  <input 
                    type="number" 
                    className="w-full bg-slate-50 border border-gray-300 rounded-lg p-3 text-sm" 
                    placeholder="500"
                    value={budget}
                    onChange={(e) => setBudget(e.target.value)}
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Step 2: Validation Strategy */}
          <div className="p-8 border-b border-gray-100 bg-slate-50/50">
            <h2 className="text-lg font-bold text-slate-900 mb-4 flex items-center gap-2">
              2. Settlement Strategy
              <span className="text-xs bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full uppercase">Crucial</span>
            </h2>
            <p className="text-sm text-slate-500 mb-6">How will the protocol know when to release the funds?</p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Option A: Manual */}
              <div 
                onClick={() => setValidationType('manual')}
                className={`relative p-5 border-2 rounded-xl cursor-pointer transition-all ${validationType === 'manual' ? 'border-blue-600 bg-blue-50' : 'border-gray-200 bg-white hover:border-gray-300'}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-slate-900">Manual Review</span>
                  {validationType === 'manual' && <div className="w-4 h-4 bg-blue-600 rounded-full"></div>}
                </div>
                <p className="text-xs text-slate-500 leading-relaxed">
                  You review the code manually. Good for creative tasks or vague requirements.
                </p>
                <div className="mt-3 text-xs font-semibold text-slate-400 uppercase tracking-wider">Dispute: Arbitration</div>
              </div>

              {/* Option B: Test-Driven */}
              <div 
                onClick={() => setValidationType('test')}
                className={`relative p-5 border-2 rounded-xl cursor-pointer transition-all ${validationType === 'test' ? 'border-green-600 bg-green-50' : 'border-gray-200 bg-white hover:border-gray-300'}`}
              >
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-slate-900">Test-Driven</span>
                  {validationType === 'test' && <div className="w-4 h-4 bg-green-600 rounded-full"></div>}
                </div>
                <p className="text-xs text-slate-500 leading-relaxed">
                  You upload a test suite. Funds release automatically if code passes.
                </p>
                <div className="mt-3 text-xs font-semibold text-green-600 uppercase tracking-wider flex items-center gap-1">
                  <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                  Trustless
                </div>
              </div>
            </div>

            {/* Conditional Upload for Test-Driven */}
            {validationType === 'test' && (
              <div className="mt-6 p-4 border border-dashed border-green-300 rounded-lg bg-white text-center animate-fadeIn">
                <div className="text-green-600 mb-2">
                  <svg className="w-8 h-8 mx-auto" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/></svg>
                </div>
                <div className="text-sm font-medium text-slate-900">Upload Test Suite (.json / .zip)</div>
                <div className="text-xs text-slate-500 mt-1">Inputs + Expected Outputs</div>
                <button className="mt-3 text-xs bg-slate-100 hover:bg-slate-200 text-slate-700 px-3 py-1.5 rounded transition-colors">Choose File</button>
              </div>
            )}
          </div>

          {/* Footer Actions */}
          <div className="p-8 bg-gray-50 flex items-center justify-between">
            <div className="text-sm text-slate-500">
              Contract Deposit: <span className="font-bold text-slate-900">${budget || '0'} USDC</span>
            </div>
            <button className="bg-slate-900 hover:bg-slate-800 text-white font-bold py-3 px-8 rounded-lg shadow-lg transition-transform active:scale-95">
              Lock Bounty & Post
            </button>
          </div>

        </div>
      </main>
    </div>
  );
}