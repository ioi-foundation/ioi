import { useState } from 'react';
import { motion } from 'motion/react';
import { ShieldAlert, Key, Lock, Eye, EyeOff, Plus, Settings2, AlertTriangle, Power, Server } from 'lucide-react';

const secrets = [
  {
    id: 'sec_aws_prod',
    name: 'AWS Production Credentials',
    type: 'Cloud Provider',
    agents: ['ai://builder-xyz/data-analyst', 'ai://builder-xyz/infra-manager'],
    lastUsed: '2 mins ago',
    budget: '$50/day',
  },
  {
    id: 'sec_sf_crm',
    name: 'Salesforce API Key',
    type: 'SaaS Integration',
    agents: ['ai://builder-xyz/support-bot'],
    lastUsed: '1 hour ago',
    budget: '$10/day',
  },
  {
    id: 'sec_stripe_live',
    name: 'Stripe Restricted Key',
    type: 'Payment Gateway',
    agents: [],
    lastUsed: 'Never',
    budget: '$0/day',
  }
];

export default function Vault() {
  const [showSecret, setShowSecret] = useState<string | null>(null);

  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white mb-2 flex items-center">
            <ShieldAlert className="w-8 h-8 mr-3 text-amber-accent" />
            Sovereign Vault
          </h1>
          <p className="text-gray-400">Enterprise-grade KYA (Know Your Agent) dashboard for scoping API keys.</p>
        </div>
        <button className="bg-amber-accent text-bg px-6 py-2 rounded-lg font-bold hover:bg-amber-accent/90 transition-colors flex items-center">
          <Plus className="w-4 h-4 mr-2" />
          Add Secret
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Secrets List */}
        <div className="lg:col-span-2 space-y-6">
          <div className="bg-surface border border-border rounded-xl overflow-hidden">
            <div className="px-6 py-4 border-b border-border flex justify-between items-center bg-surface-hover">
              <h3 className="font-bold text-white flex items-center">
                <Key className="w-5 h-5 mr-2 text-amber-accent" />
                Encrypted Credentials
              </h3>
              <span className="text-xs text-gray-500 font-mono">Keys are never exposed to LLMs</span>
            </div>
            <div className="divide-y divide-border">
              {secrets.map((secret, i) => (
                <motion.div 
                  key={secret.id}
                  initial={{ opacity: 0, x: -20 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.1 }}
                  className="p-6 hover:bg-surface-hover/50 transition-colors group"
                >
                  <div className="flex justify-between items-start mb-4">
                    <div className="flex items-center space-x-3">
                      <div className="w-10 h-10 rounded-lg bg-surface border border-border flex items-center justify-center text-amber-accent">
                        <Lock className="w-5 h-5" />
                      </div>
                      <div>
                        <h4 className="text-lg font-bold text-white">{secret.name}</h4>
                        <span className="text-xs text-gray-500 font-mono">{secret.type}</span>
                      </div>
                    </div>
                    <div className="flex space-x-2">
                      <button 
                        onClick={() => setShowSecret(showSecret === secret.id ? null : secret.id)}
                        className="p-2 border border-border rounded hover:bg-border transition-colors text-gray-400 group-hover:text-white"
                      >
                        {showSecret === secret.id ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                      </button>
                      <button className="p-2 border border-border rounded hover:bg-border transition-colors text-gray-400 group-hover:text-white">
                        <Settings2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  {showSecret === secret.id && (
                    <div className="mb-4 p-3 bg-bg border border-border rounded font-mono text-sm text-gray-300 flex items-center justify-between">
                      <span>************************</span>
                      <button className="text-cyan-accent hover:underline text-xs">Copy</button>
                    </div>
                  )}

                  <div className="grid grid-cols-3 gap-4 pt-4 border-t border-border">
                    <div>
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Whitelisted Agents</p>
                      {secret.agents.length > 0 ? (
                        <div className="space-y-1">
                          {secret.agents.map(agent => (
                            <div key={agent} className="text-xs font-mono text-cyan-accent bg-cyan-accent/10 px-2 py-1 rounded inline-block mr-2 mb-1">
                              {agent}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <span className="text-xs text-gray-500 italic">None configured</span>
                      )}
                    </div>
                    <div>
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Labor Gas Budget</p>
                      <p className="font-mono text-sm text-amber-accent">{secret.budget}</p>
                    </div>
                    <div>
                      <p className="text-xs text-gray-500 uppercase tracking-wider mb-1">Last Used</p>
                      <p className="font-mono text-sm text-gray-300">{secret.lastUsed}</p>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </div>

        {/* Security Policy Panel */}
        <div className="lg:col-span-1 space-y-6">
          {/* Global Kill Switch */}
          <div className="bg-surface border border-red-500/30 rounded-xl p-6 relative overflow-hidden">
            <div className="absolute top-0 left-0 w-full h-1 bg-red-500"></div>
            <h3 className="text-lg font-bold text-white mb-2 flex items-center">
              <Power className="w-5 h-5 mr-2 text-red-500" />
              Global Kill Switch
            </h3>
            <p className="text-xs text-gray-400 mb-4">
              Instantly revoke all master API keys and invalidate active Session Keys currently executing in DePIN clean rooms globally.
            </p>
            <button className="w-full bg-red-500/10 border border-red-500 text-red-500 py-3 rounded-lg font-bold hover:bg-red-500 hover:text-white transition-colors">
              REVOKE ALL ACCESS
            </button>
          </div>

          <div className="bg-surface border border-border rounded-xl p-6">
            <h3 className="text-lg font-bold text-white mb-4 flex items-center">
              <AlertTriangle className="w-5 h-5 mr-2 text-amber-accent" />
              Enterprise Root Policy
            </h3>
            
            <div className="space-y-6">
              <div className="p-4 bg-amber-accent/10 border border-amber-accent/20 rounded-lg">
                <h4 className="text-amber-accent font-bold text-sm mb-2">Zero-Knowledge Execution</h4>
                <p className="text-xs text-gray-400 leading-relaxed">
                  Secrets are injected directly into the secure enclave at runtime. The LLM cognition nodes never see the raw API keys, only the deterministic tool outputs.
                </p>
              </div>

              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-white flex items-center">
                      <Server className="w-4 h-4 mr-2 text-cyan-accent" />
                      Hardware Tier Enforcement
                    </p>
                    <p className="text-xs text-gray-500 mt-1 max-w-[200px]">Only allow proprietary models to decrypt on Profile 3 (Hardware TEEs).</p>
                  </div>
                  <div className="w-10 h-6 bg-emerald-accent/20 rounded-full relative cursor-pointer border border-emerald-accent/50">
                    <div className="w-4 h-4 bg-emerald-accent rounded-full absolute right-1 top-1"></div>
                  </div>
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-white">Require 2FA for Egress</p>
                    <p className="text-xs text-gray-500">Prompt for approval on high-value API calls.</p>
                  </div>
                  <div className="w-10 h-6 bg-emerald-accent/20 rounded-full relative cursor-pointer border border-emerald-accent/50">
                    <div className="w-4 h-4 bg-emerald-accent rounded-full absolute right-1 top-1"></div>
                  </div>
                </div>

                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-white">Strict IP Whitelisting</p>
                    <p className="text-xs text-gray-500">Only allow requests from verified DePIN nodes.</p>
                  </div>
                  <div className="w-10 h-6 bg-emerald-accent/20 rounded-full relative cursor-pointer border border-emerald-accent/50">
                    <div className="w-4 h-4 bg-emerald-accent rounded-full absolute right-1 top-1"></div>
                  </div>
                </div>
              </div>

              <div className="pt-4 border-t border-border">
                <button className="w-full bg-surface border border-border text-white py-2 rounded-lg font-medium hover:bg-surface-hover transition-colors text-sm">
                  View Audit Logs
                </button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
