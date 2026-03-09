// src/components/FreelanceFeed.jsx
import React from 'react';
import { Link } from 'react-router-dom';

const jobs = [
  { id: 1, title: 'Need Arbitrage Bot for Solana/Serum', budget: '$3,500', bids: 12, time: '2h ago' },
  { id: 2, title: 'Convert Python Scraper to IOI Agent Manifest', budget: '$150', bids: 4, time: '5h ago' },
  { id: 3, title: 'Medical Research Agent (PubMed Integration)', budget: '$5,000+', bids: 28, time: '1d ago' },
];

export default function FreelanceFeed() {
  return (
    <div className="bg-white border border-gray-200 rounded-xl p-6 shadow-sm sticky top-24">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-lg font-bold text-slate-900">Recent Bounties</h2>
        <Link to="/freelance" className="text-xs text-blue-600 hover:text-blue-700 font-semibold hover:underline">
          View All →
        </Link>
      </div>
      
      <div className="space-y-3 mb-6">
        {jobs.map(job => (
          <Link to="/freelance" key={job.id} className="block group">
            <div className="p-3 rounded-lg border border-transparent hover:border-gray-200 hover:bg-slate-50 transition-all cursor-pointer">
              <div className="flex justify-between items-start mb-1">
                <h4 className="font-semibold text-slate-800 text-sm leading-snug group-hover:text-blue-600 line-clamp-2">
                  {job.title}
                </h4>
              </div>
              
              <div className="flex items-center justify-between mt-2">
                <div className="text-xs text-slate-400 flex items-center gap-2">
                   <span>{job.bids} Bids</span>
                   <span className="w-0.5 h-0.5 bg-slate-300 rounded-full"></span>
                   <span>{job.time}</span>
                </div>
                <div className="font-mono font-bold text-green-600 bg-green-50 px-2 py-0.5 rounded text-xs border border-green-100">
                  {job.budget}
                </div>
              </div>
            </div>
          </Link>
        ))}
      </div>
      
      <div className="pt-5 border-t border-gray-100">
        <div className="text-center mb-3">
          <p className="text-xs text-slate-500 mb-3">Can't find the agent you need?</p>
          <Link to="/post-job" className="block w-full bg-slate-900 text-white py-3 rounded-lg font-bold text-sm hover:bg-slate-800 transition-transform active:scale-[0.98] shadow-md">
            Post a Request for Agent (RFA)
          </Link>
        </div>
        <div className="text-[10px] text-center text-slate-400">
          Secure Escrow • Test-Driven Settlement
        </div>
      </div>
    </div>
  );
}