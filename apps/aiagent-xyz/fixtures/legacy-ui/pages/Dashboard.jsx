// src/pages/Dashboard.jsx
import React, { useState } from 'react';
import Header from '../components/Header';
import { Link } from 'react-router-dom';
import MarketGrid from '../components/MarketGrid';
import ConsoleModal from '../components/ConsoleModal'; // New Import

// Mock Data
const activeFleet = [
  { id: 'inst-1', name: 'DeFi Arbitrage Sentinel', type: 'Finance', provider: 'AWS Nitro (us-east-1)', status: 'Running', uptime: '14d 2h', cost: '$0.45/hr' },
  { id: 'inst-2', name: 'Research Swarm', type: 'Research', provider: 'Akash Network', status: 'Idle', uptime: '2d 5h', cost: '$0.12/hr' },
];

const myJobs = [
  { id: 1, title: 'Arbitrage Bot for Solana/Serum', budget: '$3,500 USDC', bids: 12, status: 'Open', posted: '2d ago' },
  { id: 7, title: 'Custom scraper for specialized gov data', budget: '$200 USDC', bids: 0, status: 'Draft', posted: '—' },
];

const myListings = [
  { id: 1, name: 'Solana Liquidity Sniper', sales: 420, revenue: '18,400 IOI', rating: 4.9, status: 'Active' },
  { id: 6, name: 'RugCheck Guardian', sales: 1250, revenue: '62,500 IOI', rating: 5.0, status: 'Active' },
];

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState('fleet');
  
  // Console Modal State
  const [consoleOpen, setConsoleOpen] = useState(false);
  const [selectedAgent, setSelectedAgent] = useState('');

  const handleManage = (agentName) => {
    setSelectedAgent(agentName);
    setConsoleOpen(true);
  };

  return (
    <div className="min-h-screen bg-slate-50">
      <Header />
      
      <ConsoleModal 
        isOpen={consoleOpen} 
        onClose={() => setConsoleOpen(false)} 
        agentName={selectedAgent} 
      />

      <main className="container mx-auto px-4 py-8 max-w-6xl">
        
        <div className="flex flex-col md:flex-row justify-between items-end mb-8 gap-4">
          <div>
            <h1 className="text-3xl font-black text-slate-900 tracking-tight mb-1">Command Center</h1>
            <p className="text-slate-500">Manage your active agents, open bounties, and earnings.</p>
          </div>
          <div className="flex gap-2">
            <button className="px-4 py-2 bg-white border border-gray-200 rounded-lg text-sm font-semibold text-slate-600 hover:text-slate-900 shadow-sm">
              Wallet Settings
            </button>
            <button className="px-4 py-2 bg-slate-900 text-white rounded-lg text-sm font-bold shadow-sm hover:bg-slate-800">
              Top Up Balance
            </button>
          </div>
        </div>

        {/* Overview Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <StatCard label="Total Balance" value="450 IOI" sub="$3,240.50 USD" icon="💰" />
          <StatCard label="Active Spend" value="$12.40 / day" sub="3 Active Instances" icon="⚡" />
          <StatCard label="Total Earnings" value="80,900 IOI" sub="+450 this week" icon="📈" />
          <StatCard label="Reputation" value="Top 5%" sub="4.9/5.0 Rating" icon="⭐" />
        </div>

        {/* Main Content Area */}
        <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden min-h-[500px]">
          
          {/* Tabs */}
          <div className="flex border-b border-gray-200 overflow-x-auto">
            <TabButton id="fleet" label="My Fleet" active={activeTab} onClick={setActiveTab} />
            <TabButton id="jobs" label="My Bounties" active={activeTab} onClick={setActiveTab} count={2} />
            <TabButton id="listings" label="Creator Hub" active={activeTab} onClick={setActiveTab} />
            <TabButton id="saved" label="Saved" active={activeTab} onClick={setActiveTab} />
            <TabButton id="history" label="History" active={activeTab} onClick={setActiveTab} />
          </div>

          <div className="p-6">
            
            {/* TAB: MY FLEET */}
            {activeTab === 'fleet' && (
              <div className="space-y-6">
                <div className="flex justify-between items-center">
                  <h3 className="font-bold text-slate-900">Active Instances</h3>
                  <Link to="/" className="text-sm text-blue-600 hover:underline font-semibold">+ Deploy New Agent</Link>
                </div>
                
                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-left">
                    <thead className="text-xs text-slate-400 uppercase bg-slate-50 border-b border-slate-100">
                      <tr>
                        <th className="px-4 py-3 font-bold">Agent Name</th>
                        <th className="px-4 py-3 font-bold">Provider</th>
                        <th className="px-4 py-3 font-bold">Status</th>
                        <th className="px-4 py-3 font-bold">Uptime</th>
                        <th className="px-4 py-3 font-bold text-right">Cost</th>
                        <th className="px-4 py-3 font-bold text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-50">
                      {activeFleet.map(inst => (
                        <tr key={inst.id} className="hover:bg-slate-50 transition-colors">
                          <td className="px-4 py-4 font-medium text-slate-900">
                            {inst.name}
                            <div className="text-xs text-slate-400 font-normal">{inst.id}</div>
                          </td>
                          <td className="px-4 py-4 text-slate-600">{inst.provider}</td>
                          <td className="px-4 py-4">
                            <span className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-bold ${
                              inst.status === 'Running' ? 'bg-green-50 text-green-700' : 'bg-slate-100 text-slate-600'
                            }`}>
                              <span className={`w-1.5 h-1.5 rounded-full ${inst.status === 'Running' ? 'bg-green-500 animate-pulse' : 'bg-slate-400'}`}></span>
                              {inst.status}
                            </span>
                          </td>
                          <td className="px-4 py-4 text-slate-600 font-mono">{inst.uptime}</td>
                          <td className="px-4 py-4 text-right font-mono font-medium text-slate-900">{inst.cost}</td>
                          <td className="px-4 py-4 text-right">
                            <button 
                              onClick={() => handleManage(inst.name)}
                              className="text-blue-600 hover:text-blue-800 font-medium text-xs border border-blue-200 hover:bg-blue-50 px-3 py-1.5 rounded-md transition-colors"
                            >
                              Console
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* TAB: MY JOBS */}
            {activeTab === 'jobs' && (
              <div className="space-y-6">
                <div className="flex justify-between items-center">
                  <h3 className="font-bold text-slate-900">Posted Bounties</h3>
                  <Link to="/post-job" className="text-sm text-blue-600 hover:underline font-semibold">+ Post New Job</Link>
                </div>
                
                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-left">
                    <thead className="text-xs text-slate-400 uppercase bg-slate-50 border-b border-slate-100">
                      <tr>
                        <th className="px-4 py-3 font-bold">Job Title</th>
                        <th className="px-4 py-3 font-bold">Posted</th>
                        <th className="px-4 py-3 font-bold">Status</th>
                        <th className="px-4 py-3 font-bold">Bids</th>
                        <th className="px-4 py-3 font-bold text-right">Budget</th>
                        <th className="px-4 py-3 font-bold text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-50">
                      {myJobs.map(job => (
                        <tr key={job.id} className="hover:bg-slate-50 transition-colors">
                          <td className="px-4 py-4 font-medium text-slate-900">
                            <Link to={`/freelance/${job.id}`} className="hover:text-blue-600 hover:underline">
                              {job.title}
                            </Link>
                          </td>
                          <td className="px-4 py-4 text-slate-500">{job.posted}</td>
                          <td className="px-4 py-4">
                            <span className="bg-blue-50 text-blue-700 px-2 py-0.5 rounded text-xs font-bold border border-blue-100">
                              {job.status}
                            </span>
                          </td>
                          <td className="px-4 py-4 text-slate-600">{job.bids}</td>
                          <td className="px-4 py-4 text-right font-mono font-bold text-green-600">{job.budget}</td>
                          <td className="px-4 py-4 text-right">
                            <Link to={`/freelance/${job.id}`} className="text-blue-600 hover:text-blue-800 font-medium text-xs">View</Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* TAB: CREATOR STUDIO */}
            {activeTab === 'listings' && (
              <div className="space-y-6">
                <div className="flex justify-between items-center">
                  <h3 className="font-bold text-slate-900">My Listings</h3>
                  <Link to="/sell" className="text-sm text-blue-600 hover:underline font-semibold">+ Create New Agent</Link>
                </div>
                
                <div className="overflow-x-auto">
                  <table className="w-full text-sm text-left">
                    <thead className="text-xs text-slate-400 uppercase bg-slate-50 border-b border-slate-100">
                      <tr>
                        <th className="px-4 py-3 font-bold">Agent Name</th>
                        <th className="px-4 py-3 font-bold">Sales/Rentals</th>
                        <th className="px-4 py-3 font-bold">Rating</th>
                        <th className="px-4 py-3 font-bold">Status</th>
                        <th className="px-4 py-3 font-bold text-right">Total Revenue</th>
                        <th className="px-4 py-3 font-bold text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-50">
                      {myListings.map(item => (
                        <tr key={item.id} className="hover:bg-slate-50 transition-colors">
                          <td className="px-4 py-4 font-medium text-slate-900">{item.name}</td>
                          <td className="px-4 py-4 text-slate-600">{item.sales}</td>
                          <td className="px-4 py-4 text-yellow-500 font-bold">★ {item.rating}</td>
                          <td className="px-4 py-4">
                            <span className="bg-green-50 text-green-700 px-2 py-0.5 rounded text-xs font-bold border border-green-100">
                              {item.status}
                            </span>
                          </td>
                          <td className="px-4 py-4 text-right font-mono font-bold text-slate-900">{item.revenue}</td>
                          <td className="px-4 py-4 text-right">
                             <button className="text-slate-500 hover:text-slate-800 font-medium text-xs mr-3">Edit</button>
                             <button className="text-blue-600 hover:text-blue-800 font-medium text-xs">Analytics</button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
            
            {/* TAB: SAVED */}
            {activeTab === 'saved' && (
              <div className="space-y-6">
                <div className="flex justify-between items-center">
                  <h3 className="font-bold text-slate-900">Watchlist</h3>
                </div>
                <MarketGrid /> 
              </div>
            )}

            {/* TAB: HISTORY */}
            {activeTab === 'history' && (
                <div className="text-center py-12 text-slate-400">
                    <p>Transaction history requires wallet signature.</p>
                </div>
            )}

          </div>
        </div>
      </main>
    </div>
  );
}

function StatCard({ label, value, sub, icon }) {
  return (
    <div className="bg-white border border-gray-200 rounded-xl p-4 shadow-sm flex items-start justify-between">
      <div>
        <div className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-1">{label}</div>
        <div className="text-2xl font-black text-slate-900 mb-1">{value}</div>
        <div className="text-xs text-green-600 font-medium">{sub}</div>
      </div>
      <div className="text-2xl opacity-80">{icon}</div>
    </div>
  )
}

function TabButton({ id, label, active, onClick, count }) {
  const isActive = active === id;
  return (
    <button
      onClick={() => onClick(id)}
      className={`
        px-6 py-4 text-sm font-medium border-b-2 transition-colors whitespace-nowrap flex items-center gap-2
        ${isActive 
          ? 'border-blue-600 text-blue-600' 
          : 'border-transparent text-slate-500 hover:text-slate-800 hover:bg-slate-50'}
      `}
    >
      {label}
      {count !== undefined && (
        <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${isActive ? 'bg-blue-100 text-blue-700' : 'bg-slate-200 text-slate-600'}`}>
            {count}
        </span>
      )}
    </button>
  )
}