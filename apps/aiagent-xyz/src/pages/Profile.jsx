// src/pages/Profile.jsx
import React from 'react';
import Header from '../components/Header';
import { Link } from 'react-router-dom';

// Mock Data
const profileData = {
  handle: 'QuantLabs_0x',
  joined: 'March 2024',
  bio: 'Specializing in MEV-resistant DeFi agents and high-frequency Solana bots. Former quant dev.',
  badges: ['Github Verified', 'TEE Operator', 'Top 5% Solver'],
  stats: {
    earned: '450k IOI',
    jobs: 34,
    success_rate: '98%',
    uptime: '99.9%'
  },
  portfolio: [
    { id: 1, name: 'DeFi Arbitrage Sentinel', type: 'Finance', rating: 4.8, users: '1.2k', image: 'linear-gradient(135deg, #1e293b 0%, #0f172a 100%)' },
    { id: 5, name: 'Solana Liquidity Sniper', type: 'Finance', rating: 4.9, users: '850', image: 'linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%)' },
    { id: 6, name: 'RugCheck Guardian', type: 'Security', rating: 5.0, users: '2.1k', image: 'linear-gradient(135deg, #064e3b 0%, #065f46 100%)' }
  ]
};

export default function Profile() {
  return (
    <div className="min-h-screen bg-slate-50">
      <Header />

      <main className="container mx-auto px-4 py-8 max-w-5xl">
        
        {/* Header Section */}
        <div className="bg-white border border-gray-200 rounded-xl p-8 shadow-sm mb-8">
          <div className="flex flex-col md:flex-row items-start gap-8">
            <div className="w-24 h-24 rounded-full bg-slate-200 border-4 border-white shadow-lg flex-shrink-0"></div>
            
            <div className="flex-grow">
              <div className="flex items-center gap-3 mb-2">
                <h1 className="text-2xl font-black text-slate-900">{profileData.handle}</h1>
                <span className="bg-blue-100 text-blue-700 text-xs font-bold px-2 py-1 rounded-full uppercase tracking-wide">Pro Seller</span>
              </div>
              <p className="text-slate-600 mb-4 max-w-2xl">{profileData.bio}</p>
              
              <div className="flex flex-wrap gap-2">
                {profileData.badges.map(badge => (
                  <span key={badge} className="inline-flex items-center gap-1 px-3 py-1 bg-slate-100 text-slate-600 text-xs font-semibold rounded-full border border-slate-200">
                    <svg className="w-3 h-3 text-blue-500" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd"/></svg>
                    {badge}
                  </span>
                ))}
              </div>
            </div>

            <div className="w-full md:w-auto flex flex-row md:flex-col gap-3">
               <button className="flex-1 bg-slate-900 text-white px-6 py-2 rounded-lg font-bold text-sm hover:bg-slate-800 transition-colors">
                 Contact
               </button>
               <button className="flex-1 bg-white border border-gray-300 text-slate-700 px-6 py-2 rounded-lg font-bold text-sm hover:bg-slate-50 transition-colors">
                 Hire for Job
               </button>
            </div>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 mt-8 pt-8 border-t border-gray-100">
            <div>
              <div className="text-2xl font-black text-slate-900">{profileData.stats.earned}</div>
              <div className="text-xs text-slate-500 font-medium uppercase tracking-wider">Total Earned</div>
            </div>
            <div>
              <div className="text-2xl font-black text-slate-900">{profileData.stats.jobs}</div>
              <div className="text-xs text-slate-500 font-medium uppercase tracking-wider">Jobs Completed</div>
            </div>
            <div>
              <div className="text-2xl font-black text-green-600">{profileData.stats.success_rate}</div>
              <div className="text-xs text-slate-500 font-medium uppercase tracking-wider">Test Pass Rate</div>
            </div>
            <div>
              <div className="text-2xl font-black text-slate-900">{profileData.stats.uptime}</div>
              <div className="text-xs text-slate-500 font-medium uppercase tracking-wider">Node Uptime</div>
            </div>
          </div>
        </div>

        {/* Portfolio Grid */}
        <h2 className="text-lg font-bold text-slate-900 mb-4">Published Agents</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {profileData.portfolio.map(item => (
            <Link to={`/agent/${item.id}`} key={item.id} className="block group">
              <div className="bg-white border border-gray-200 rounded-xl overflow-hidden hover:shadow-lg transition-shadow">
                <div className="h-32 relative" style={{ background: item.image }}>
                   <div className="absolute top-2 right-2 bg-black/40 text-white text-xs px-2 py-1 rounded backdrop-blur-sm">
                    {item.type}
                  </div>
                </div>
                <div className="p-4">
                  <h3 className="font-bold text-slate-800 mb-1 group-hover:text-blue-600">{item.name}</h3>
                  <div className="flex justify-between items-center mt-4">
                    <div className="flex items-center gap-1">
                      <span className="text-yellow-400 text-sm">★</span>
                      <span className="text-sm font-bold text-slate-700">{item.rating}</span>
                    </div>
                    <div className="text-xs text-slate-500">{item.users} users</div>
                  </div>
                </div>
              </div>
            </Link>
          ))}
        </div>

      </main>
    </div>
  );
}
