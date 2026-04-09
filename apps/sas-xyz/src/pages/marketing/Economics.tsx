import React, { useState } from 'react';
import { Coins, TrendingUp, Workflow } from 'lucide-react';

export default function Economics() {
  const [baseFee, setBaseFee] = useState(12000);
  const [perOutcome, setPerOutcome] = useState(14);
  const [volume, setVolume] = useState(2500);
  const [gainshare, setGainshare] = useState(8);

  const monthlyContractValue = baseFee + perOutcome * volume;
  const gainshareUpside = monthlyContractValue * (gainshare / 100);
  const effectiveOutcomePrice = monthlyContractValue / volume;

  return (
    <div className="bg-black text-white min-h-screen font-sans pt-32 pb-20">
      <div className="max-w-7xl mx-auto px-6">
        <div className="mb-16 text-center max-w-3xl mx-auto">
          <h1 className="text-4xl md:text-6xl font-display font-bold tracking-tighter text-white mb-6">
            Outcome Pricing
          </h1>
          <p className="text-xl text-gray-400 font-light leading-relaxed">
            Keep the pricing split aligned to abstraction. aiagent.xyz monetizes supply-side
            components. sas.xyz monetizes governed service delivery and finished outcomes.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center mb-32">
          <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-8 shadow-2xl">
            <h3 className="text-2xl font-bold text-white mb-8">Model a Hybrid Service Contract</h3>

            <div className="space-y-8">
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-gray-400">Managed Base Fee</span>
                  <span className="text-white font-mono">${baseFee.toLocaleString()}</span>
                </div>
                <input
                  type="range"
                  min="2000"
                  max="50000"
                  step="500"
                  value={baseFee}
                  onChange={(event) => setBaseFee(parseInt(event.target.value, 10))}
                  className="w-full accent-blue-500"
                />
              </div>

              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-gray-400">Per Outcome Fee</span>
                  <span className="text-white font-mono">${perOutcome}</span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="100"
                  step="1"
                  value={perOutcome}
                  onChange={(event) => setPerOutcome(parseInt(event.target.value, 10))}
                  className="w-full accent-emerald-500"
                />
              </div>

              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-gray-400">Monthly Outcomes</span>
                  <span className="text-white font-mono">{volume.toLocaleString()}</span>
                </div>
                <input
                  type="range"
                  min="250"
                  max="10000"
                  step="250"
                  value={volume}
                  onChange={(event) => setVolume(parseInt(event.target.value, 10))}
                  className="w-full accent-purple-500"
                />
              </div>

              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="text-gray-400">Gainshare Kicker</span>
                  <span className="text-white font-mono">{gainshare}%</span>
                </div>
                <input
                  type="range"
                  min="0"
                  max="20"
                  step="1"
                  value={gainshare}
                  onChange={(event) => setGainshare(parseInt(event.target.value, 10))}
                  className="w-full accent-amber-500"
                />
              </div>
            </div>
          </div>

          <div className="relative">
            <div className="absolute inset-0 bg-gradient-to-tr from-emerald-500/10 to-transparent blur-3xl rounded-full"></div>
            <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-10 relative overflow-hidden shadow-2xl flex flex-col items-center text-center">
              <Coins className="w-12 h-12 text-emerald-400 mb-6" />
              <p className="text-sm text-gray-400 uppercase tracking-widest font-medium mb-2">
                Projected Monthly Contract Value
              </p>
              <h2 className="text-6xl font-bold text-white tracking-tighter mb-4">
                ${monthlyContractValue.toLocaleString()}
              </h2>
              <p className="text-gray-500 text-sm max-w-xs">
                Example of a hybrid sas.xyz service agreement with a managed base, per-outcome
                fee, and performance upside.
              </p>

              <div className="mt-8 w-full space-y-3">
                <div className="w-full bg-white/5 border border-white/10 rounded-xl p-4 flex justify-between items-center">
                  <span className="text-sm text-gray-400">Effective Price Per Outcome</span>
                  <span className="text-sm font-bold text-white">${effectiveOutcomePrice.toFixed(2)}</span>
                </div>
                <div className="w-full bg-white/5 border border-white/10 rounded-xl p-4 flex justify-between items-center">
                  <span className="text-sm text-gray-400">Potential Gainshare Upside</span>
                  <span className="text-sm font-bold text-emerald-500">${gainshareUpside.toLocaleString(undefined, { maximumFractionDigits: 0 })}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="border-t border-white/10 pt-32">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-5xl font-display font-bold tracking-tight text-white mb-6">
              Price by abstraction, not by habit.
            </h2>
            <p className="text-xl text-gray-400 max-w-2xl mx-auto font-light">
              The cleanest commercial model keeps supply-side monetization separate from
              buyer-facing outcome contracts.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            <PricingCard
              icon={<Workflow className="w-5 h-5 mr-2 text-blue-400" />}
              title="aiagent.xyz pricing"
              items={[
                'metered execution',
                'license',
                'rev share',
                'lease',
                'settlement-based compensation',
              ]}
            />
            <PricingCard
              icon={<TrendingUp className="w-5 h-5 mr-2 text-emerald-400" />}
              title="sas.xyz pricing"
              items={[
                'per outcome',
                'managed SLA',
                'gainshare',
                'hybrid base fee + outcome kicker',
              ]}
            />
          </div>
        </div>
      </div>
    </div>
  );
}

function PricingCard({
  icon,
  title,
  items,
}: {
  icon: React.ReactNode;
  title: string;
  items: string[];
}) {
  return (
    <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-8">
      <h3 className="text-xl font-bold text-white mb-6 flex items-center">{icon}{title}</h3>
      <div className="space-y-3">
        {items.map((item) => (
          <div key={item} className="border border-white/10 rounded-lg px-4 py-3 text-sm text-gray-300 bg-black/30">
            {item}
          </div>
        ))}
      </div>
    </div>
  );
}
