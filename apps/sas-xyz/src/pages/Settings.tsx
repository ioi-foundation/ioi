import React from 'react';

export default function Settings() {
  return (
    <div className="max-w-7xl mx-auto space-y-8">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">IAM & Settings</h1>
          <p className="text-gray-400 text-sm">Manage organization, RBAC, SSO, and API keys.</p>
        </div>
      </div>
      <div className="bg-surface border border-border rounded-xl p-8 text-center">
        <p className="text-gray-400">Settings panels will appear here.</p>
      </div>
    </div>
  );
}
