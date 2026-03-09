import React from 'react';

export default function Customers() {
  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Customers & Tenants</h1>
          <p className="text-gray-400 text-sm">Manage per-customer policy overrides and data residency.</p>
        </div>
        <button className="bg-white text-bg px-4 py-2 rounded-md font-medium text-sm hover:bg-gray-200 transition-colors">
          Add Tenant
        </button>
      </div>
      <div className="bg-surface border border-border rounded-xl p-8 text-center">
        <p className="text-gray-400">Tenant list will appear here.</p>
      </div>
    </div>
  );
}
