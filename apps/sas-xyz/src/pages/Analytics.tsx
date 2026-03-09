import { useState, useEffect } from 'react';
import { motion } from 'motion/react';
import { BarChart3, Globe, Cpu, Activity, ArrowUpRight, ArrowDownRight, Server } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Skeleton } from '../components/ui/Skeleton';

const data = [
  { time: '00:00', lgas: 4000, cost: 2400 },
  { time: '02:00', lgas: 3000, cost: 1398 },
  { time: '04:00', lgas: 2000, cost: 9800 },
  { time: '06:00', lgas: 2780, cost: 3908 },
  { time: '08:00', lgas: 1890, cost: 4800 },
  { time: '10:00', lgas: 2390, cost: 3800 },
  { time: '12:00', lgas: 3490, cost: 4300 },
  { time: '14:00', lgas: 4000, cost: 2400 },
  { time: '16:00', lgas: 3000, cost: 1398 },
  { time: '18:00', lgas: 2000, cost: 9800 },
  { time: '20:00', lgas: 2780, cost: 3908 },
  { time: '22:00', lgas: 1890, cost: 4800 },
  { time: '24:00', lgas: 3490, cost: 4300 },
];

export default function Analytics() {
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => setIsLoading(false), 800);
    return () => clearTimeout(timer);
  }, []);

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2 flex items-center">
            <BarChart3 className="w-8 h-8 mr-3 text-cyan-accent" />
            Fleet Observability
          </h1>
          <p className="text-gray-400">Zero-idle telemetry. Monitor global agent routing, latency, and Labor Gas yields.</p>
        </div>
        <div className="flex space-x-2 bg-surface border border-border rounded-lg p-1">
          <button className="px-4 py-1.5 bg-bg rounded text-sm font-medium text-white shadow">24h</button>
          <button className="px-4 py-1.5 text-sm font-medium text-gray-500 hover:text-white transition-colors">7d</button>
          <button className="px-4 py-1.5 text-sm font-medium text-gray-500 hover:text-white transition-colors">30d</button>
        </div>
      </div>

      {/* Top Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {[
          { label: 'Total Invocations', value: '1.24M', change: '+12.5%', isUp: true },
          { label: 'Avg. Inference Latency', value: '42ms', change: '-4.2%', isUp: true }, // Down is good for latency
          { label: 'Labor Gas Yield', value: '84,291', change: '+22.1%', isUp: true },
          { label: 'Firewall Blocks', value: '4,102', change: '+1.2%', isUp: false },
        ].map((stat, i) => (
          <motion.div 
            key={i}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.1 }}
            className="bg-surface border border-border rounded-xl p-6"
          >
            <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">{stat.label}</p>
            <div className="flex items-end justify-between">
              <span className="text-2xl font-bold font-mono text-white">{stat.value}</span>
              <span className={`flex items-center text-xs font-bold ${stat.isUp ? 'text-emerald-accent' : 'text-amber-accent'}`}>
                {stat.isUp ? <ArrowUpRight className="w-3 h-3 mr-1" /> : <ArrowDownRight className="w-3 h-3 mr-1" />}
                {stat.change}
              </span>
            </div>
          </motion.div>
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Chart: Labor Gas Velocity */}
        <div className="lg:col-span-2 bg-surface border border-border rounded-xl p-6 flex flex-col">
          <div className="flex justify-between items-center mb-8">
            <h3 className="font-bold text-white flex items-center">
              <Activity className="w-5 h-5 mr-2 text-emerald-accent" />
              Labor Gas Velocity (Yield)
            </h3>
            <span className="text-xs text-gray-500 font-mono">LGAS / Hour</span>
          </div>
          
          {/* Main Chart: Labor Gas Velocity */}
          <div className="flex-1 min-h-[300px] mt-4">
            {isLoading ? (
              <Skeleton className="w-full h-full" />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorLgas" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00F0FF" stopOpacity={0.3}/>
                      <stop offset="95%" stopColor="#00F0FF" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" vertical={false} />
                  <XAxis 
                    dataKey="time" 
                    stroke="#666" 
                    tick={{ fill: '#666', fontSize: 12 }}
                    tickLine={false}
                    axisLine={false}
                  />
                  <YAxis 
                    stroke="#666" 
                    tick={{ fill: '#666', fontSize: 12 }}
                    tickLine={false}
                    axisLine={false}
                    tickFormatter={(value) => `${value / 1000}k`}
                  />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#111', borderColor: '#333', borderRadius: '8px' }}
                    itemStyle={{ color: '#00F0FF' }}
                    labelStyle={{ color: '#888' }}
                  />
                  <Area 
                    type="monotone" 
                    dataKey="lgas" 
                    stroke="#00F0FF" 
                    strokeWidth={2}
                    fillOpacity={1} 
                    fill="url(#colorLgas)" 
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Right Column: Hardware & Routing */}
        <div className="space-y-6">
          {/* Hardware Distribution */}
          <div className="bg-surface border border-border rounded-xl p-6">
            <h3 className="font-bold text-white mb-6 flex items-center">
              <Cpu className="w-5 h-5 mr-2 text-cyan-accent" />
              Hardware Routing
            </h3>
            
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-300">Profile 3 (Hardware TEE)</span>
                  <span className="font-mono text-cyan-accent">68%</span>
                </div>
                <div className="w-full bg-bg rounded-full h-1.5 border border-border">
                  <div className="bg-cyan-accent h-1.5 rounded-full" style={{ width: '68%' }}></div>
                </div>
              </div>
              
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-300">Profile 2 (Software TEE)</span>
                  <span className="font-mono text-amber-accent">24%</span>
                </div>
                <div className="w-full bg-bg rounded-full h-1.5 border border-border">
                  <div className="bg-amber-accent h-1.5 rounded-full" style={{ width: '24%' }}></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-300">Profile 1 (Standard GPU)</span>
                  <span className="font-mono text-gray-500">8%</span>
                </div>
                <div className="w-full bg-bg rounded-full h-1.5 border border-border">
                  <div className="bg-gray-500 h-1.5 rounded-full" style={{ width: '8%' }}></div>
                </div>
              </div>
            </div>
          </div>

          {/* Network Providers */}
          <div className="bg-surface border border-border rounded-xl p-6">
            <h3 className="font-bold text-white mb-4 flex items-center">
              <Globe className="w-5 h-5 mr-2 text-emerald-accent" />
              Top Clean Room Providers
            </h3>
            <div className="space-y-3">
              {[
                { name: 'AWS Nitro (us-east-1)', loads: '45.2K', status: 'optimal' },
                { name: 'Akash Network (DePIN)', loads: '28.4K', status: 'optimal' },
                { name: 'GCP Confidential', loads: '12.1K', status: 'warning' },
              ].map((p, i) => (
                <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border bg-bg">
                  <div className="flex items-center">
                    <Server className="w-4 h-4 mr-3 text-gray-500" />
                    <span className="text-sm text-gray-300">{p.name}</span>
                  </div>
                  <div className="flex items-center space-x-3">
                    <span className="font-mono text-xs text-white">{p.loads}</span>
                    <span className={`w-2 h-2 rounded-full ${p.status === 'optimal' ? 'bg-emerald-accent' : 'bg-amber-accent animate-pulse'}`}></span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
