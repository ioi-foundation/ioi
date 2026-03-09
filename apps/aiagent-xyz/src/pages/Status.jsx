// src/pages/Status.jsx
import React from 'react';
import Header from '../components/Header';

export default function Status() {
  return (
    <div className="min-h-screen bg-slate-50">
      <Header />

      <main className="container mx-auto px-4 py-12 max-w-4xl">
        
        {/* Overall Status Banner */}
        <div className="bg-green-600 rounded-xl p-6 text-white shadow-lg mb-8 flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="p-3 bg-white/20 rounded-full backdrop-blur-sm">
              <svg className="w-8 h-8" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M5 13l4 4L19 7"/></svg>
            </div>
            <div>
              <h1 className="text-2xl font-bold">All Systems Operational</h1>
              <p className="text-green-100 opacity-90">Network performance is nominal.</p>
            </div>
          </div>
          <div className="text-right hidden sm:block">
            <div className="text-xs font-mono opacity-75 uppercase tracking-wider">Last Updated</div>
            <div className="font-mono font-bold">Just now</div>
          </div>
        </div>

        {/* System Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-12">
          <StatusCard 
            title="Mainnet Settlement" 
            status="Operational" 
            uptime="99.99%"
            latency="450ms"
            graphColor="bg-green-500"
          />
          <StatusCard 
            title="Compute Grid (DePIN)" 
            status="Operational" 
            uptime="99.95%"
            latency="1.2s" // Slower because it's p2p negotiation
            graphColor="bg-blue-500"
            extra="2,402 Active Nodes"
          />
          <StatusCard 
            title="Marketplace API" 
            status="Operational" 
            uptime="100%"
            latency="24ms"
            graphColor="bg-green-500"
          />
          <StatusCard 
            title="Freelance Escrow" 
            status="Operational" 
            uptime="99.99%"
            latency="N/A"
            graphColor="bg-purple-500"
          />
        </div>

        {/* Live Metrics */}
        <h2 className="text-xl font-bold text-slate-900 mb-6">Live Network Telemetry</h2>
        <div className="bg-white border border-gray-200 rounded-xl shadow-sm p-6 mb-12 overflow-hidden">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8 text-center divide-x divide-gray-100">
            <div>
              <div className="text-xs text-slate-400 font-bold uppercase tracking-wider mb-1">Avg Gas Price</div>
              <div className="text-2xl font-mono font-black text-slate-900">12 <span className="text-sm text-slate-500 font-normal">Gwei</span></div>
            </div>
            <div>
              <div className="text-xs text-slate-400 font-bold uppercase tracking-wider mb-1">Block Time</div>
              <div className="text-2xl font-mono font-black text-slate-900">1.4 <span className="text-sm text-slate-500 font-normal">sec</span></div>
            </div>
            <div>
              <div className="text-xs text-slate-400 font-bold uppercase tracking-wider mb-1">Compute Capacity</div>
              <div className="text-2xl font-mono font-black text-slate-900">84 <span className="text-sm text-slate-500 font-normal">PH/s</span></div>
            </div>
            <div>
              <div className="text-xs text-slate-400 font-bold uppercase tracking-wider mb-1">24h Transactions</div>
              <div className="text-2xl font-mono font-black text-slate-900">1.2M</div>
            </div>
          </div>
        </div>

        {/* Incident History */}
        <h2 className="text-xl font-bold text-slate-900 mb-6">Past Incidents</h2>
        <div className="space-y-4">
          <IncidentRow 
            date="Oct 24, 2025" 
            title="Solver Network Latency" 
            desc="A subset of solvers experienced delayed block inclusion due to high L1 congestion."
            status="Resolved"
          />
           <IncidentRow 
            date="Sep 12, 2025" 
            title="Mainnet Upgrade v2.4" 
            desc="Scheduled maintenance for A-DMFT consensus upgrade. No downtime observed."
            status="Completed"
          />
           <IncidentRow 
            date="Aug 05, 2025" 
            title="API Rate Limiting" 
            desc="Transient errors on read-heavy marketplace endpoints."
            status="Resolved"
          />
        </div>

      </main>
    </div>
  );
}

function StatusCard({ title, status, uptime, latency, graphColor, extra }) {
  return (
    <div className="bg-white border border-gray-200 rounded-lg p-5 shadow-sm">
      <div className="flex justify-between items-start mb-4">
        <h3 className="font-bold text-slate-900">{title}</h3>
        <span className="flex items-center gap-1.5 text-xs font-bold text-green-700 bg-green-50 px-2 py-1 rounded-full border border-green-100">
           <span className="w-1.5 h-1.5 bg-green-500 rounded-full animate-pulse"></span>
           {status}
        </span>
      </div>
      
      {/* Mock Uptime Bar */}
      <div className="flex gap-0.5 h-6 mb-4 items-end">
         {[...Array(30)].map((_, i) => (
            <div 
              key={i} 
              className={`flex-1 rounded-sm opacity-80 hover:opacity-100 transition-opacity ${graphColor}`} 
              style={{ height: `${30 + Math.random() * 70}%` }}
            ></div>
         ))}
      </div>

      <div className="flex justify-between items-center text-xs text-slate-500 border-t border-gray-50 pt-3">
         <div className="flex gap-4">
            <span>{uptime} uptime</span>
            <span>{latency}</span>
         </div>
         {extra && <span className="font-medium text-blue-600">{extra}</span>}
      </div>
    </div>
  )
}

function IncidentRow({ date, title, desc, status }) {
  return (
    <div className="bg-white border border-gray-200 rounded-lg p-4 flex flex-col md:flex-row gap-4">
      <div className="md:w-32 flex-shrink-0 text-sm font-mono text-slate-500 pt-0.5">{date}</div>
      <div className="flex-grow">
        <h4 className="font-bold text-slate-800 text-sm mb-1">{title}</h4>
        <p className="text-xs text-slate-500 leading-relaxed">{desc}</p>
      </div>
      <div className="flex-shrink-0">
        <span className="text-xs font-medium text-slate-600 bg-slate-100 px-2 py-1 rounded">{status}</span>
      </div>
    </div>
  )
}