// src/pages/SellAgent.jsx
import React, { useState } from 'react';
import Header from '../components/Header';

export default function SellAgent() {
  const [step, setStep] = useState(1);

  const nextStep = () => setStep(step + 1);
  const prevStep = () => setStep(step - 1);

  return (
    <div className="min-h-screen bg-slate-50">
      <Header />

      <main className="container mx-auto px-4 py-12 max-w-3xl">
        
        {/* Progress Bar */}
        <div className="mb-8">
          <h1 className="text-3xl font-black text-slate-900 tracking-tight mb-6">Publish New Capability</h1>
          <div className="flex items-center justify-between relative">
            <div className="absolute top-1/2 left-0 w-full h-0.5 bg-gray-200 -z-10"></div>
            <StepIndicator number={1} label="Manifest" current={step} />
            <StepIndicator number={2} label="Source" current={step} />
            <StepIndicator number={3} label="Verification" current={step} />
            <StepIndicator number={4} label="Pricing" current={step} />
          </div>
        </div>

        <div className="bg-white border border-gray-200 rounded-xl shadow-sm overflow-hidden p-8">
          
          {/* STEP 1: Manifest */}
          {step === 1 && (
            <div className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">
              <h2 className="text-xl font-bold text-slate-900">Define Your Capability</h2>
              <p className="text-slate-500 text-sm">The manifest tells the network what your agent, workflow, or service module does, how it composes, and what resources it needs.</p>
              
              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-1">Capability Name</label>
                <input type="text" className="w-full bg-slate-50 border border-gray-300 rounded-lg p-3 text-sm focus:ring-2 focus:ring-blue-500 focus:outline-none" placeholder="e.g. Claims Resolution Service Module" />
              </div>

              <div>
                <label className="block text-sm font-semibold text-slate-700 mb-1">Description</label>
                <textarea className="w-full bg-slate-50 border border-gray-300 rounded-lg p-3 text-sm h-32 focus:ring-2 focus:ring-blue-500 focus:outline-none" placeholder="What problem does it solve? What inputs, policies, and receipts does it expose?"></textarea>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-semibold text-slate-700 mb-1">Execution Shape</label>
                  <select className="w-full bg-slate-50 border border-gray-300 rounded-lg p-3 text-sm">
                    <option>Agent</option>
                    <option>Workflow</option>
                    <option>Swarm</option>
                    <option>Operator Pack</option>
                    <option>Service Module</option>
                    <option>Embodied Runtime</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-semibold text-slate-700 mb-1">Hardware Req.</label>
                  <select className="w-full bg-slate-50 border border-gray-300 rounded-lg p-3 text-sm">
                    <option>CPU Only (Cheap)</option>
                    <option>Standard GPU (8GB)</option>
                    <option>High Performance (24GB+)</option>
                    <option>H100 Cluster</option>
                  </select>
                </div>
              </div>
            </div>
          )}

          {/* STEP 2: Source */}
          {step === 2 && (
            <div className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">
              <h2 className="text-xl font-bold text-slate-900">Connect Code</h2>
              <p className="text-slate-500 text-sm">Point to a repository or upload a packaged container.</p>
              
              <div className="p-4 border-2 border-dashed border-gray-300 rounded-lg text-center hover:bg-slate-50 transition-colors cursor-pointer">
                <div className="text-4xl mb-2">📦</div>
                <div className="font-semibold text-slate-700">Upload OCI / WASM Bundle</div>
                <div className="text-xs text-slate-400 mt-1">Max 500MB. Encrypted on client-side.</div>
              </div>

              <div className="relative">
                <div className="absolute inset-0 flex items-center"><div className="w-full border-t border-gray-200"></div></div>
                <div className="relative flex justify-center text-sm"><span className="px-2 bg-white text-gray-500">Or connect repo</span></div>
              </div>

              <div className="flex gap-4">
                <input type="text" className="flex-grow bg-slate-50 border border-gray-300 rounded-lg p-3 text-sm" placeholder="https://github.com/username/repo" />
                <button className="bg-slate-900 text-white px-6 rounded-lg font-bold text-sm">Connect</button>
              </div>
            </div>
          )}

          {/* STEP 3: Verification */}
          {step === 3 && (
            <div className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">
              <h2 className="text-xl font-bold text-slate-900">Verification Audit</h2>
              <p className="text-slate-500 text-sm">The network is running a dry run of your package in a sandbox to verify capability boundaries, policies, and deployability.</p>
              
              <div className="bg-slate-900 rounded-lg p-4 font-mono text-xs text-slate-300 h-48 overflow-y-auto">
                <div className="text-green-400">&gt; Initializing sandbox environment...</div>
                <div className="text-green-400">&gt; Pulling container... Done (1.2s)</div>
                <div className="text-white">&gt; Analyzing capability manifest...</div>
                <div className="text-white">&gt; Detected network access: api.coingecko.com</div>
                <div className="text-white">&gt; Detected filesystem access: /tmp/output</div>
                <div className="text-yellow-400">&gt; WARNING: Capability requests unrestricted outbound traffic.</div>
                <div className="text-green-400">&gt; Policy check passed. (Score: 92/100)</div>
                <div className="mt-2 animate-pulse">_</div>
              </div>

              <div className="flex items-center gap-2 p-3 bg-green-50 border border-green-200 rounded-lg text-green-800 text-sm">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
                <span>Audit Passed. Ready for signing.</span>
              </div>
            </div>
          )}

          {/* STEP 4: Pricing */}
          {step === 4 && (
            <div className="space-y-6 animate-in fade-in slide-in-from-right-4 duration-300">
              <h2 className="text-xl font-bold text-slate-900">Monetization</h2>
              <p className="text-slate-500 text-sm">Choose the pricing model that fits a composable capability. Full managed SLA and hybrid outcome contracts live on SAS.xyz.</p>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="p-4 border-2 border-blue-600 bg-blue-50 rounded-lg cursor-pointer">
                  <div className="font-bold text-slate-900">Metered Execution</div>
                  <div className="text-xs text-slate-500 mt-1">Charge per execution, document, or compute burst.</div>
                  <div className="mt-3 flex items-center gap-2">
                    <span className="text-sm font-bold">$</span>
                    <input type="number" className="w-24 p-1 rounded border border-blue-200 text-sm" placeholder="0.05" />
                    <span className="text-xs text-slate-500">/ run</span>
                  </div>
                </div>

                <div className="p-4 border border-gray-200 hover:border-gray-300 rounded-lg cursor-pointer">
                  <div className="font-bold text-slate-900">License</div>
                  <div className="text-xs text-slate-500 mt-1">One-time payment for private deployment or packaging rights.</div>
                  <div className="mt-3 flex items-center gap-2">
                    <span className="text-sm font-bold">$</span>
                    <input type="number" className="w-24 p-1 rounded border border-gray-300 text-sm" placeholder="5000" />
                  </div>
                </div>

                <div className="p-4 border border-gray-200 hover:border-gray-300 rounded-lg cursor-pointer opacity-70">
                  <div className="font-bold text-slate-900">Revenue Share</div>
                  <div className="text-xs text-slate-500 mt-1">Take a percentage of the revenue generated downstream.</div>
                </div>

                <div className="p-4 border border-gray-200 hover:border-gray-300 rounded-lg cursor-pointer opacity-70">
                  <div className="font-bold text-slate-900">Settlement-Based</div>
                  <div className="text-xs text-slate-500 mt-1">Attach compensation to verified completion events and receipts.</div>
                </div>
              </div>
              
              <div className="pt-4 border-t border-gray-100">
                 <div className="flex justify-between items-center text-sm font-bold text-slate-900 mb-2">
                   <span>Developer Royalty</span>
                   <span>90%</span>
                 </div>
                 <div className="flex justify-between items-center text-sm font-bold text-slate-900">
                   <span>Protocol Fee</span>
                   <span>10%</span>
                 </div>
                 <p className="text-xs text-slate-500 mt-4">
                   Enterprise-grade managed services can be promoted into SAS.xyz once the package clears governance, reporting, and SLA thresholds.
                 </p>
              </div>
            </div>
          )}

          {/* Navigation */}
          <div className="mt-8 pt-6 border-t border-gray-100 flex justify-between">
            {step > 1 ? (
              <button onClick={prevStep} className="px-6 py-2 text-sm font-semibold text-slate-600 hover:text-slate-900">Back</button>
            ) : (
              <div></div>
            )}
            
            {step < 4 ? (
              <button onClick={nextStep} className="bg-slate-900 hover:bg-slate-800 text-white font-bold py-2 px-6 rounded-lg transition-colors">
                Continue
              </button>
            ) : (
              <button className="bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-6 rounded-lg shadow-lg transition-colors">
                Sign & Publish
              </button>
            )}
          </div>

        </div>
      </main>
    </div>
  );
}

function StepIndicator({ number, label, current }) {
  const active = current >= number;
  return (
    <div className="flex flex-col items-center gap-2 z-10 bg-slate-50 px-2">
      <div className={`w-8 h-8 rounded-full flex items-center justify-center font-bold text-sm transition-colors ${active ? 'bg-slate-900 text-white' : 'bg-gray-200 text-gray-500'}`}>
        {current > number ? '✓' : number}
      </div>
      <span className={`text-xs font-semibold ${active ? 'text-slate-900' : 'text-gray-400'}`}>{label}</span>
    </div>
  );
}
