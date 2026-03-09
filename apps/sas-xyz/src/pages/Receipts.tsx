import React from 'react';

export default function Receipts() {
  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Receipts & Evidence</h1>
          <p className="text-gray-400 text-sm">Search and export cryptographic execution receipts.</p>
        </div>
        <button className="border border-border text-white px-4 py-2 rounded-md font-medium text-sm hover:bg-surface transition-colors">
          Export Bundle
        </button>
      </div>
      <div className="bg-surface border border-border rounded-xl p-8 text-center">
        <p className="text-gray-400">Searchable receipt log will appear here.</p>
      </div>
    </div>
  );
}
