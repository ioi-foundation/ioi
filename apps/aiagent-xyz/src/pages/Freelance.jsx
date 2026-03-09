// src/pages/Freelance.jsx
import React, { useState } from 'react';
import Header from '../components/Header';
import { Link } from 'react-router-dom';
import MobileFilterDrawer from '../components/MobileFilterDrawer';

// Mock Data
const jobs = [
  { id: 1, title: 'Arbitrage Bot for Solana/Serum', budget: '$3,500', type: 'Fixed Price', client: 'AlphaCapital_DAO', clientRating: 4.9, bids: 12, time: '2h ago', tags: ['DeFi', 'Rust', 'Solana'], verification: 'Test Suite Provided' },
  { id: 2, title: 'Medical Research Summarizer', budget: '$500', type: 'Fixed Price', client: 'BioSynth_Labs', clientRating: 4.5, bids: 4, time: '5h ago', tags: ['Research', 'Python', 'LLM'], verification: 'Golden Output Match' },
  { id: 3, title: 'Convert Python Scraper to IOI Manifest', budget: '$150', type: 'Fixed Price', client: 'DataVortex', clientRating: 5.0, bids: 28, time: '1d ago', tags: ['Migration', 'Python'], verification: 'Lint Check' },
  { id: 4, title: 'Custom "Personality" for Discord Bot', budget: '$25 - $50 / hr', type: 'Hourly', client: 'NFT_Whales', clientRating: 4.2, bids: 8, time: '1d ago', tags: ['Creative', 'Prompt Engineering'], verification: 'Subjective (Review)' }
];

export default function Freelance() {
  const [isMobileFiltersOpen, setIsMobileFiltersOpen] = useState(false);

  const FilterContent = () => (
    <div className="space-y-6">
      <div className="bg-white border border-gray-200 rounded-lg p-5">
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4">Verification Type</h3>
        <div className="space-y-3">
          <label className="flex items-center gap-2 text-sm text-slate-700 cursor-pointer">
            <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" defaultChecked />
            <span>Test-Driven (Automated)</span>
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-700 cursor-pointer">
            <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" />
            <span>Subjective (Review)</span>
          </label>
        </div>
      </div>

      <div className="bg-white border border-gray-200 rounded-lg p-5">
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-4">Category</h3>
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm group cursor-pointer">
            <span className="text-slate-700 font-medium group-hover:text-blue-600">DeFi & Trading</span>
            <span className="bg-slate-100 text-slate-500 px-2 py-0.5 rounded-full text-xs">124</span>
          </div>
          <div className="flex items-center justify-between text-sm group cursor-pointer">
            <span className="text-slate-700 font-medium group-hover:text-blue-600">Data Extraction</span>
            <span className="bg-slate-100 text-slate-500 px-2 py-0.5 rounded-full text-xs">85</span>
          </div>
          {/* ... more categories ... */}
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-50">
      <Header />
      
      <MobileFilterDrawer isOpen={isMobileFiltersOpen} onClose={() => setIsMobileFiltersOpen(false)}>
        <FilterContent />
      </MobileFilterDrawer>

      <main className="container mx-auto px-4 py-8 max-w-6xl">
        
        {/* Page Header */}
        <div className="flex flex-col md:flex-row justify-between items-start md:items-center mb-8 gap-4">
          <div>
            <h1 className="text-3xl font-black text-slate-900 tracking-tight mb-1">Freelance</h1>
            <p className="text-slate-500">Hire developers to build verified agents. Payment is released only when tests pass.</p>
          </div>
          <Link to="/post-job" className="bg-slate-900 hover:bg-slate-800 text-white font-bold py-3 px-6 rounded-lg shadow-md transition-all flex items-center gap-2 w-full md:w-auto justify-center">
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M12 4v16m8-8H4"/></svg>
            Post a Job
          </Link>
        </div>

        {/* Mobile Filter Button */}
        <div className="lg:hidden mb-6">
          <button 
            onClick={() => setIsMobileFiltersOpen(true)}
            className="w-full flex items-center justify-center gap-2 bg-white border border-gray-300 py-3 rounded-lg text-sm font-bold text-slate-700 shadow-sm"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" /></svg>
            Filter Jobs
          </button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
          
          {/* LEFT SIDEBAR (Desktop) */}
          <aside className="hidden lg:block lg:col-span-3 space-y-6">
             <FilterContent />
          </aside>

          {/* MAIN CONTENT: Job Feed */}
          <div className="lg:col-span-9 space-y-4">
            
            {/* Search/Sort Bar */}
            <div className="flex items-center gap-4 bg-white border border-gray-200 p-2 rounded-lg mb-2">
              <div className="relative flex-grow">
                <svg className="w-4 h-4 absolute left-3 top-3 text-slate-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
                <input 
                  type="text" 
                  placeholder="Search jobs..." 
                  className="w-full pl-9 pr-4 py-2 text-sm border-none focus:ring-0 text-slate-700 placeholder-slate-400"
                />
              </div>
              <div className="h-6 w-px bg-gray-200 hidden sm:block"></div>
              <select className="text-sm border-none focus:ring-0 text-slate-600 font-medium bg-transparent pr-8 cursor-pointer hidden sm:block">
                <option>Newest First</option>
                <option>Highest Budget</option>
              </select>
            </div>

            {/* Job List */}
            {jobs.map(job => (
              <Link to={`/freelance/${job.id}`} key={job.id} className="block">
                <div className="bg-white border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow cursor-pointer group">
                  <div className="flex justify-between items-start mb-2">
                    <h3 className="text-lg font-bold text-slate-900 group-hover:text-blue-600 transition-colors">
                      {job.title}
                    </h3>
                    <div className="text-right">
                      <div className="text-lg font-black text-slate-900">{job.budget}</div>
                      <div className="text-xs text-slate-500 font-medium">{job.type}</div>
                    </div>
                  </div>

                  <div className="flex flex-wrap gap-2 mb-4">
                    {/* Verification Badge */}
                    <span className={`inline-flex items-center gap-1 px-2 py-1 rounded text-xs font-semibold border ${
                      job.verification.includes('Test') ? 'bg-green-50 text-green-700 border-green-100' : 'bg-slate-100 text-slate-600 border-slate-200'
                    }`}>
                      {job.verification.includes('Test') && (
                        <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                      )}
                      {job.verification}
                    </span>

                    {job.tags.map(tag => (
                      <span key={tag} className="px-2 py-1 bg-slate-50 text-slate-600 text-xs rounded border border-slate-100">
                        {tag}
                      </span>
                    ))}
                  </div>

                  <div className="flex items-center justify-between text-xs text-slate-500 border-t border-gray-50 pt-4 mt-2">
                    <div className="flex items-center gap-4">
                      <span className="flex items-center gap-1">
                        <span className="font-semibold text-slate-700">{job.client}</span>
                        <span className="flex text-yellow-400">★ {job.clientRating}</span>
                      </span>
                      <span>{job.time}</span>
                    </div>
                    <div className="font-medium text-slate-600">
                      {job.bids} Bids
                    </div>
                  </div>
                </div>
              </Link>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}