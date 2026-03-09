import { Activity, Terminal, Zap, ShieldCheck, AlertCircle, Clock, CheckCircle2, ArrowRight } from 'lucide-react';
import { motion } from 'motion/react';
import { Link } from 'react-router-dom';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const usageData = [
  { time: '00:00', requests: 1200, latency: 45 },
  { time: '04:00', requests: 900, latency: 42 },
  { time: '08:00', requests: 2400, latency: 55 },
  { time: '12:00', requests: 3800, latency: 65 },
  { time: '16:00', requests: 3100, latency: 58 },
  { time: '20:00', requests: 1800, latency: 48 },
  { time: '24:00', requests: 1400, latency: 46 },
];

export default function Dashboard() {
  return (
    <div className="max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Overview</h1>
          <p className="text-gray-400 text-sm">QuantLabs Organization</p>
        </div>
        <div className="flex space-x-3">
          <Link to="/app/canvas" className="bg-white text-bg px-4 py-2 rounded-md font-medium text-sm hover:bg-gray-200 transition-colors shadow-sm shadow-white/10">
            New Service
          </Link>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[
          { label: 'Active Services', value: '12', icon: Activity, color: 'text-cyan-accent' },
          { label: 'Monthly Spend', value: '$1,240.50', icon: Zap, color: 'text-amber-accent' },
          { label: 'Pending Approvals', value: '3', icon: ShieldCheck, color: 'text-emerald-accent' },
          { label: 'Risk Alerts', value: '0', icon: AlertCircle, color: 'text-gray-400' },
        ].map((stat, i) => (
          <motion.div 
            key={i}
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, delay: i * 0.05 }}
            className="bg-surface border border-border rounded-xl p-5 flex flex-col relative overflow-hidden group hover:border-gray-600 transition-colors cursor-default"
          >
            <div className="absolute inset-0 bg-gradient-to-br from-white/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
            <div className="flex items-center justify-between mb-3 relative z-10">
              <span className="text-gray-400 text-sm font-medium">{stat.label}</span>
              <stat.icon className={`w-4 h-4 ${stat.color}`} />
            </div>
            <span className="text-2xl font-bold tracking-tight text-white relative z-10">{stat.value}</span>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Main Left Column */}
        <div className="lg:col-span-2 space-y-8">
          
          {/* Chart Section */}
          <div className="bg-surface border border-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h2 className="text-lg font-semibold text-white">Network Traffic</h2>
                <p className="text-sm text-gray-400">Global API requests across all enclaves</p>
              </div>
              <div className="flex space-x-2 bg-bg p-1 rounded-lg border border-border">
                <button className="px-3 py-1 text-xs font-medium bg-surface rounded text-white shadow-sm">24h</button>
                <button className="px-3 py-1 text-xs font-medium text-gray-400 hover:text-white transition-colors">7d</button>
                <button className="px-3 py-1 text-xs font-medium text-gray-400 hover:text-white transition-colors">30d</button>
              </div>
            </div>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={usageData} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00F0FF" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#00F0FF" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#232730" vertical={false} />
                  <XAxis dataKey="time" stroke="#6b7280" fontSize={12} tickLine={false} axisLine={false} />
                  <YAxis stroke="#6b7280" fontSize={12} tickLine={false} axisLine={false} tickFormatter={(value) => `${value / 1000}k`} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#14161A', borderColor: '#232730', borderRadius: '8px', color: '#fff' }}
                    itemStyle={{ color: '#00F0FF' }}
                    cursor={{ stroke: '#232730', strokeWidth: 1, strokeDasharray: '3 3' }}
                  />
                  <Area type="monotone" dataKey="requests" stroke="#00F0FF" strokeWidth={2} fillOpacity={1} fill="url(#colorRequests)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Recent Deployments */}
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-white">Recent Deployments</h2>
              <Link to="/app/deployments" className="text-sm text-gray-400 hover:text-white transition-colors">View All</Link>
            </div>
            
            <div className="bg-surface border border-border rounded-xl overflow-hidden">
              {[
                { name: 'defi-arbitrage-sentinel', env: 'Production', status: 'Ready', time: '2m ago', version: 'v1.2.0', target: 'AWS Nitro' },
                { name: 'customer-support-agent', env: 'Staging', status: 'Ready', time: '1h ago', version: 'v2.0.1-rc', target: 'Managed Cloud' },
                { name: 'data-pipeline-worker', env: 'Production', status: 'Failed', time: '3h ago', version: 'v1.0.5', target: 'Customer VPC' },
                { name: 'sales-outreach-bot', env: 'Production', status: 'Ready', time: '1d ago', version: 'v3.4.0', target: 'Managed Cloud' },
              ].map((dep, i) => (
                <div key={i} className="flex items-center justify-between p-4 border-b border-border last:border-0 hover:bg-surface-hover transition-colors group cursor-pointer">
                  <div className="flex items-center space-x-4">
                    <div className="relative flex h-2.5 w-2.5">
                      {dep.status === 'Ready' && (
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-accent opacity-75"></span>
                      )}
                      <span className={`relative inline-flex rounded-full h-2.5 w-2.5 ${dep.status === 'Ready' ? 'bg-emerald-accent' : 'bg-red-500'}`}></span>
                    </div>
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-medium text-white group-hover:text-cyan-accent transition-colors">{dep.name}</span>
                        <span className="text-xs px-2 py-0.5 rounded-full bg-bg border border-border text-gray-400">{dep.env}</span>
                      </div>
                      <div className="flex items-center space-x-3 text-sm text-gray-500 mt-1">
                        <span className="font-mono text-xs">{dep.version}</span>
                        <span>•</span>
                        <span>{dep.target}</span>
                        <span>•</span>
                        <span>{dep.time}</span>
                      </div>
                    </div>
                  </div>
                  <button className="p-2 text-gray-400 opacity-0 group-hover:opacity-100 group-hover:text-white transition-all transform translate-x-2 group-hover:translate-x-0">
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Action Center */}
        <div className="space-y-4">
          <h2 className="text-lg font-semibold text-white">Action Center</h2>
          
          <div className="bg-surface border border-border rounded-xl p-4 space-y-4">
            <div className="flex items-start space-x-3 p-3 bg-amber-500/10 border border-amber-500/20 rounded-lg hover:bg-amber-500/15 transition-colors cursor-pointer">
              <AlertCircle className="w-5 h-5 text-amber-500 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-sm font-medium text-amber-500">Approval Required</h4>
                <p className="text-xs text-amber-500/80 mt-1">
                  "defi-arbitrage-sentinel" is requesting to execute a transaction exceeding the $500 automated limit.
                </p>
                <div className="flex space-x-2 mt-3">
                  <button className="text-xs bg-amber-500 text-bg px-3 py-1.5 rounded font-medium hover:bg-amber-400 transition-colors shadow-sm shadow-amber-500/20">Review</button>
                </div>
              </div>
            </div>

            <div className="flex items-start space-x-3 p-3 bg-bg border border-border rounded-lg hover:border-gray-600 transition-colors cursor-pointer">
              <Clock className="w-5 h-5 text-gray-400 shrink-0 mt-0.5" />
              <div>
                <h4 className="text-sm font-medium text-gray-300">Policy Update Pending</h4>
                <p className="text-xs text-gray-500 mt-1">
                  New data residency rules for EU region need to be applied to "customer-support-agent".
                </p>
                <div className="flex space-x-2 mt-3">
                  <button className="text-xs bg-surface-hover border border-border text-white px-3 py-1.5 rounded font-medium hover:bg-border transition-colors">Apply Policy</button>
                </div>
              </div>
            </div>
          </div>

          {/* System Health */}
          <div className="bg-surface border border-border rounded-xl p-5 mt-4 group hover:border-gray-600 transition-colors">
             <h3 className="text-sm font-medium text-gray-400 mb-4 flex items-center justify-between">
               System Health
               <span className="flex h-2 w-2 relative">
                 <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-accent opacity-75"></span>
                 <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-accent"></span>
               </span>
             </h3>
             <div className="space-y-4">
               <div className="flex items-center justify-between text-sm">
                 <span className="text-gray-300">API Latency</span>
                 <span className="text-emerald-400 font-mono bg-emerald-400/10 px-2 py-0.5 rounded text-xs">24ms</span>
               </div>
               <div className="flex items-center justify-between text-sm">
                 <span className="text-gray-300">Tool Call Success Rate</span>
                 <span className="text-emerald-400 font-mono bg-emerald-400/10 px-2 py-0.5 rounded text-xs">99.98%</span>
               </div>
               <div className="flex items-center justify-between text-sm">
                 <span className="text-gray-300">Active Enclaves</span>
                 <span className="text-white font-mono bg-white/10 px-2 py-0.5 rounded text-xs">12/12</span>
               </div>
             </div>
          </div>
        </div>
      </div>
    </div>
  );
}
