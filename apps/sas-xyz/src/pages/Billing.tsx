import React from 'react';
import { CreditCard, Download, ExternalLink, Zap, ShieldCheck, Activity, AlertCircle } from 'lucide-react';
import { motion } from 'motion/react';

const mockInvoices = [
  { id: 'INV-2026-003', date: 'Mar 01, 2026', amount: '$1,240.50', status: 'Paid' },
  { id: 'INV-2026-002', date: 'Feb 01, 2026', amount: '$1,105.20', status: 'Paid' },
  { id: 'INV-2026-001', date: 'Jan 01, 2026', amount: '$980.00', status: 'Paid' },
];

export default function Billing() {
  return (
    <div className="max-w-7xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Billing & Metering</h1>
          <p className="text-gray-400 text-sm">Manage your subscription, track usage, and view invoices.</p>
        </div>
        <div className="flex space-x-3">
          <button className="bg-surface border border-border text-white px-4 py-2 rounded-md font-medium text-sm hover:bg-surface-hover transition-colors shadow-sm">
            Manage Payment Methods
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        
        {/* Left Column: Plan & Payment */}
        <div className="space-y-8">
          
          {/* Current Plan */}
          <div className="bg-surface border border-border rounded-xl overflow-hidden">
            <div className="p-6 border-b border-border">
              <div className="flex justify-between items-start mb-4">
                <div>
                  <h2 className="text-lg font-bold text-white mb-1">Scale Plan</h2>
                  <p className="text-sm text-gray-400">For high-velocity agentic workflows.</p>
                </div>
                <span className="bg-cyan-accent/10 text-cyan-accent border border-cyan-accent/20 px-3 py-1 rounded-full text-xs font-bold tracking-wide uppercase">
                  Active
                </span>
              </div>
              <div className="flex items-baseline space-x-1">
                <span className="text-3xl font-bold text-white">$499</span>
                <span className="text-gray-500 text-sm">/ month</span>
              </div>
            </div>
            <div className="bg-surface-hover p-6">
              <ul className="space-y-3 text-sm text-gray-300">
                <li className="flex items-center"><ShieldCheck className="w-4 h-4 mr-3 text-emerald-accent" /> Up to 50 Active Enclaves</li>
                <li className="flex items-center"><Zap className="w-4 h-4 mr-3 text-emerald-accent" /> 1M Labor Gas (LGAS) included</li>
                <li className="flex items-center"><Activity className="w-4 h-4 mr-3 text-emerald-accent" /> Advanced TEE Hardware Routing</li>
              </ul>
              <button className="w-full mt-6 bg-white text-bg py-2 rounded-lg font-medium text-sm hover:bg-gray-200 transition-colors">
                Upgrade to Enterprise
              </button>
            </div>
          </div>

          {/* Payment Method */}
          <div className="bg-surface border border-border rounded-xl p-6">
            <h3 className="text-lg font-bold text-white mb-4">Payment Method</h3>
            <div className="flex items-center justify-between p-4 border border-border rounded-lg bg-bg">
              <div className="flex items-center space-x-4">
                <div className="w-12 h-8 bg-surface-hover rounded border border-border flex items-center justify-center">
                  <CreditCard className="w-5 h-5 text-gray-400" />
                </div>
                <div>
                  <p className="text-sm font-medium text-white">Mastercard ending in 4242</p>
                  <p className="text-xs text-gray-500">Expires 12/2028</p>
                </div>
              </div>
              <button className="text-sm text-cyan-accent hover:text-cyan-accent/80 transition-colors font-medium">
                Edit
              </button>
            </div>
          </div>

        </div>

        {/* Right Column: Usage & Invoices */}
        <div className="lg:col-span-2 space-y-8">
          
          {/* Current Usage */}
          <div className="bg-surface border border-border rounded-xl p-6">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-lg font-bold text-white">Current Usage</h2>
              <span className="text-sm text-gray-400">Mar 1 - Mar 31, 2026</span>
            </div>

            <div className="space-y-8">
              {/* Labor Gas */}
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="font-medium text-white">Labor Gas (LGAS)</span>
                  <span className="text-gray-400"><span className="text-white">842,910</span> / 1,000,000</span>
                </div>
                <div className="w-full bg-bg rounded-full h-2.5 border border-border overflow-hidden">
                  <motion.div 
                    initial={{ width: 0 }}
                    animate={{ width: '84%' }}
                    transition={{ duration: 1, ease: "easeOut" }}
                    className="bg-cyan-accent h-full rounded-full" 
                  />
                </div>
                <p className="text-xs text-gray-500 mt-2 flex items-center">
                  <AlertCircle className="w-3 h-3 mr-1 text-amber-500" />
                  Approaching limit. Overage billed at $0.001 / LGAS.
                </p>
              </div>

              {/* Active Enclaves */}
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="font-medium text-white">Active Enclaves</span>
                  <span className="text-gray-400"><span className="text-white">12</span> / 50</span>
                </div>
                <div className="w-full bg-bg rounded-full h-2.5 border border-border overflow-hidden">
                  <motion.div 
                    initial={{ width: 0 }}
                    animate={{ width: '24%' }}
                    transition={{ duration: 1, ease: "easeOut", delay: 0.2 }}
                    className="bg-emerald-accent h-full rounded-full" 
                  />
                </div>
              </div>

              {/* Bandwidth */}
              <div>
                <div className="flex justify-between text-sm mb-2">
                  <span className="font-medium text-white">Egress Bandwidth</span>
                  <span className="text-gray-400"><span className="text-white">42.5 GB</span> / 100 GB</span>
                </div>
                <div className="w-full bg-bg rounded-full h-2.5 border border-border overflow-hidden">
                  <motion.div 
                    initial={{ width: 0 }}
                    animate={{ width: '42.5%' }}
                    transition={{ duration: 1, ease: "easeOut", delay: 0.4 }}
                    className="bg-purple-500 h-full rounded-full" 
                  />
                </div>
              </div>
            </div>
          </div>

          {/* Invoices */}
          <div className="bg-surface border border-border rounded-xl overflow-hidden">
            <div className="p-6 border-b border-border flex justify-between items-center">
              <h2 className="text-lg font-bold text-white">Invoices</h2>
              <button className="text-sm text-gray-400 hover:text-white transition-colors flex items-center">
                View All <ExternalLink className="w-3 h-3 ml-1" />
              </button>
            </div>
            <div className="divide-y divide-border">
              {mockInvoices.map((invoice, i) => (
                <div key={i} className="p-4 flex items-center justify-between hover:bg-surface-hover transition-colors group">
                  <div className="flex items-center space-x-4">
                    <div className="w-10 h-10 rounded-lg bg-bg border border-border flex items-center justify-center text-gray-400 group-hover:text-white transition-colors">
                      <Download className="w-4 h-4" />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-white">{invoice.date}</p>
                      <p className="text-xs text-gray-500 font-mono">{invoice.id}</p>
                    </div>
                  </div>
                  <div className="flex items-center space-x-4">
                    <span className="text-sm font-medium text-white">{invoice.amount}</span>
                    <span className="bg-emerald-accent/10 text-emerald-accent border border-emerald-accent/20 px-2 py-0.5 rounded text-xs font-medium">
                      {invoice.status}
                    </span>
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
