import React from 'react';

export default function Marketplace() {
  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Catalog Promotion</h1>
          <p className="text-gray-400 text-sm">Manage which verified components from aiagent.xyz are promoted into buyer-facing service offerings.</p>
        </div>
        <button className="bg-white text-bg px-4 py-2 rounded-md font-medium text-sm hover:bg-gray-200 transition-colors">
          Publish Listing
        </button>
      </div>
      <div className="bg-surface border border-border rounded-xl p-8 text-center">
        <p className="text-gray-400">Marketplace listings and compliance checklists will appear here.</p>
      </div>
    </div>
  );
}
