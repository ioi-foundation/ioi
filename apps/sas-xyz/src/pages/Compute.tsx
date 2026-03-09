import { motion } from 'motion/react';
import { Cpu, Server, Activity, ArrowRightLeft, Clock, Zap } from 'lucide-react';

const markets = [
  { pair: 'H100/LGAS', price: '0.0042', change: '+2.4%', volume: '1.2M', status: 'Spot' },
  { pair: 'A100/LGAS', price: '0.0018', change: '-0.8%', volume: '840K', status: 'Spot' },
  { pair: 'H100-DEC26/LGAS', price: '0.0045', change: '+0.1%', volume: '250K', status: 'Futures' },
];

export default function Compute() {
  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2">Compute DEX</h1>
          <p className="text-gray-400">Spot and Futures market for DePIN hardware routing.</p>
        </div>
        <button className="bg-cyan-accent text-bg px-6 py-2 rounded-lg font-bold hover:bg-cyan-accent/90 transition-colors flex items-center">
          <Server className="w-4 h-4 mr-2" />
          Onboard Hardware
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Market Overview */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-surface border border-border rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-border flex justify-between items-center bg-surface-hover">
              <h3 className="font-bold text-white flex items-center">
                <Activity className="w-5 h-5 mr-2 text-cyan-accent" />
                Live Markets
              </h3>
              <div className="flex space-x-2">
                <button className="px-3 py-1 bg-surface border border-border rounded text-xs text-white">All</button>
                <button className="px-3 py-1 bg-transparent border border-transparent rounded text-xs text-gray-500 hover:text-white">Spot</button>
                <button className="px-3 py-1 bg-transparent border border-transparent rounded text-xs text-gray-500 hover:text-white">Futures</button>
              </div>
            </div>
            <div className="divide-y divide-border">
              <div className="grid grid-cols-5 gap-4 px-6 py-3 text-xs text-gray-500 uppercase tracking-wider font-mono">
                <div className="col-span-2">Pair</div>
                <div className="text-right">Price (LGAS)</div>
                <div className="text-right">24h Change</div>
                <div className="text-right">Volume</div>
              </div>
              {markets.map((market, i) => (
                <motion.div 
                  key={market.pair}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.1 }}
                  className="grid grid-cols-5 gap-4 px-6 py-4 items-center hover:bg-surface-hover/50 transition-colors cursor-pointer group"
                >
                  <div className="col-span-2 flex items-center space-x-3">
                    <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                      market.status === 'Spot' ? 'bg-cyan-accent/10 text-cyan-accent' : 'bg-amber-accent/10 text-amber-accent'
                    }`}>
                      {market.status === 'Spot' ? <Zap className="w-4 h-4" /> : <Clock className="w-4 h-4" />}
                    </div>
                    <div>
                      <span className="font-bold text-white font-mono">{market.pair}</span>
                      <span className="block text-xs text-gray-500">{market.status}</span>
                    </div>
                  </div>
                  <div className="text-right font-mono text-white">{market.price}</div>
                  <div className={`text-right font-mono ${market.change.startsWith('+') ? 'text-emerald-accent' : 'text-red-500'}`}>
                    {market.change}
                  </div>
                  <div className="text-right font-mono text-gray-400">{market.volume}</div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>

        {/* Trade Panel */}
        <div className="lg:col-span-1">
          <div className="bg-surface border border-border rounded-xl p-6 sticky top-24">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-lg font-bold text-white flex items-center">
                <ArrowRightLeft className="w-5 h-5 mr-2 text-cyan-accent" />
                Trade Compute
              </h3>
              <span className="text-xs font-mono text-gray-500">H100/LGAS</span>
            </div>
            
            <div className="space-y-4">
              <div className="flex bg-bg rounded-lg p-1 border border-border">
                <button className="flex-1 py-1.5 bg-surface rounded text-sm font-medium text-white shadow">Buy</button>
                <button className="flex-1 py-1.5 text-sm font-medium text-gray-500 hover:text-white">Sell</button>
              </div>

              <div className="space-y-2">
                <label className="text-xs text-gray-500 uppercase tracking-wider">Order Type</label>
                <select className="w-full bg-bg border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-accent">
                  <option>Limit</option>
                  <option>Market</option>
                  <option>Stop Limit</option>
                </select>
              </div>

              <div className="space-y-2">
                <label className="text-xs text-gray-500 uppercase tracking-wider">Price (LGAS)</label>
                <div className="relative">
                  <input type="text" defaultValue="0.0042" className="w-full bg-bg border border-border rounded-lg pl-3 pr-12 py-2 text-sm text-white focus:outline-none focus:border-cyan-accent font-mono" />
                  <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-gray-500 font-mono">LGAS</span>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-xs text-gray-500 uppercase tracking-wider">Amount (Hours)</label>
                <div className="relative">
                  <input type="text" placeholder="0.00" className="w-full bg-bg border border-border rounded-lg pl-3 pr-12 py-2 text-sm text-white focus:outline-none focus:border-cyan-accent font-mono" />
                  <span className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-gray-500 font-mono">H100</span>
                </div>
              </div>

              <div className="pt-4">
                <div className="flex justify-between text-sm mb-4">
                  <span className="text-gray-400">Total</span>
                  <span className="text-white font-mono">0.00 LGAS</span>
                </div>
                <button className="w-full bg-emerald-accent/20 text-emerald-accent border border-emerald-accent/50 py-3 rounded-lg font-bold hover:bg-emerald-accent/30 transition-colors">
                  Buy H100 Compute
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
