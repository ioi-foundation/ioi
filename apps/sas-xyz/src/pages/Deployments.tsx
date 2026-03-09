import React, { useState } from 'react';
import { Search, Filter, MoreVertical, CheckCircle2, XCircle, Loader2, Clock, GitBranch, Globe, ArrowRight, Terminal } from 'lucide-react';
import { motion } from 'motion/react';
import { Link } from 'react-router-dom';

const mockDeployments = [
  {
    id: 'dep_1a2b3c4d',
    service: 'defi-arbitrage-sentinel',
    status: 'Ready',
    env: 'Production',
    version: 'v1.2.0',
    commitMsg: 'Update slippage tolerance for DEX aggregator',
    target: 'AWS Nitro',
    duration: '45s',
    time: '2m ago',
    url: 'defi-arb.sas.xyz',
    creator: 'josmanlevi'
  },
  {
    id: 'dep_5e6f7g8h',
    service: 'customer-support-agent',
    status: 'Building',
    env: 'Preview',
    version: 'v2.0.1-rc',
    commitMsg: 'Integrate new Zendesk MCP tool',
    target: 'Managed Cloud',
    duration: '-',
    time: '1h ago',
    url: 'cs-agent-pr-42.sas.xyz',
    creator: 'auto-deploy'
  },
  {
    id: 'dep_9i0j1k2l',
    service: 'data-pipeline-worker',
    status: 'Failed',
    env: 'Production',
    version: 'v1.0.5',
    commitMsg: 'Migrate to Postgres 15',
    target: 'Customer VPC',
    duration: '12s',
    time: '3h ago',
    url: '-',
    creator: 'josmanlevi'
  },
  {
    id: 'dep_3m4n5o6p',
    service: 'sales-outreach-bot',
    status: 'Ready',
    env: 'Production',
    version: 'v3.4.0',
    commitMsg: 'Add LinkedIn scraping capability',
    target: 'Managed Cloud',
    duration: '1m 12s',
    time: '1d ago',
    url: 'sales-bot.sas.xyz',
    creator: 'josmanlevi'
  },
  {
    id: 'dep_7q8r9s0t',
    service: 'defi-arbitrage-sentinel',
    status: 'Ready',
    env: 'Preview',
    version: 'v1.1.9',
    commitMsg: 'Test new flash loan logic',
    target: 'AWS Nitro',
    duration: '42s',
    time: '2d ago',
    url: 'defi-arb-pr-12.sas.xyz',
    creator: 'josmanlevi'
  }
];

const StatusIcon = ({ status }: { status: string }) => {
  switch (status) {
    case 'Ready':
      return (
        <div className="relative flex h-4 w-4 items-center justify-center">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-accent opacity-20"></span>
          <CheckCircle2 className="w-4 h-4 text-emerald-accent relative z-10" />
        </div>
      );
    case 'Building':
      return <Loader2 className="w-4 h-4 text-cyan-accent animate-spin" />;
    case 'Failed':
      return <XCircle className="w-4 h-4 text-red-500" />;
    default:
      return <Clock className="w-4 h-4 text-gray-500" />;
  }
};

export default function Deployments() {
  const [searchQuery, setSearchQuery] = useState('');
  const [envFilter, setEnvFilter] = useState('All');

  const filteredDeployments = mockDeployments.filter(dep => {
    const matchesSearch = dep.service.toLowerCase().includes(searchQuery.toLowerCase()) || 
                          dep.commitMsg.toLowerCase().includes(searchQuery.toLowerCase());
    const matchesEnv = envFilter === 'All' || dep.env === envFilter;
    return matchesSearch && matchesEnv;
  });

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Deployments</h1>
          <p className="text-gray-400 text-sm">Monitor and manage your agent deployments across all environments.</p>
        </div>
        <div className="flex space-x-3">
          <Link to="/app/canvas" className="bg-white text-bg px-4 py-2 rounded-md font-medium text-sm hover:bg-gray-200 transition-colors shadow-sm shadow-white/10">
            New Deployment
          </Link>
        </div>
      </div>

      {/* Filters & Search */}
      <div className="flex flex-col sm:flex-row gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input 
            type="text" 
            placeholder="Search deployments, commits, or services..." 
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-surface border border-border rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:outline-none focus:border-cyan-accent transition-colors"
          />
        </div>
        <div className="flex space-x-2">
          <select 
            value={envFilter}
            onChange={(e) => setEnvFilter(e.target.value)}
            className="bg-surface border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-cyan-accent transition-colors appearance-none pr-8 relative"
          >
            <option value="All">All Environments</option>
            <option value="Production">Production</option>
            <option value="Preview">Preview</option>
          </select>
          <button className="bg-surface border border-border rounded-lg p-2 text-gray-400 hover:text-white hover:border-gray-500 transition-colors">
            <Filter className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Deployments List */}
      <div className="bg-surface border border-border rounded-xl overflow-hidden shadow-sm">
        {filteredDeployments.length > 0 ? (
          <div className="divide-y divide-border">
            {filteredDeployments.map((dep, i) => (
              <motion.div 
                key={dep.id}
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.2, delay: i * 0.05 }}
                className="p-4 hover:bg-surface-hover transition-colors group flex flex-col sm:flex-row sm:items-center justify-between gap-4"
              >
                {/* Left Side: Status & Main Info */}
                <div className="flex items-start space-x-4">
                  <div className="mt-1">
                    <StatusIcon status={dep.status} />
                  </div>
                  <div>
                    <div className="flex items-center space-x-2 mb-1">
                      <Link to={`/app/services/${dep.service}`} className="font-semibold text-white hover:text-cyan-accent transition-colors">
                        {dep.service}
                      </Link>
                      <span className={`text-[10px] uppercase tracking-wider px-2 py-0.5 rounded-full font-medium border ${
                        dep.env === 'Production' ? 'bg-cyan-accent/10 text-cyan-accent border-cyan-accent/20' : 'bg-purple-500/10 text-purple-400 border-purple-500/20'
                      }`}>
                        {dep.env}
                      </span>
                    </div>
                    
                    <div className="flex items-center text-sm text-gray-400 space-x-2">
                      <span className="font-mono text-xs text-gray-300 bg-bg px-1.5 py-0.5 rounded border border-white/5">{dep.version}</span>
                      <span>•</span>
                      <span className="truncate max-w-[200px] sm:max-w-md" title={dep.commitMsg}>{dep.commitMsg}</span>
                    </div>
                  </div>
                </div>

                {/* Right Side: Meta & Actions */}
                <div className="flex items-center justify-between sm:justify-end space-x-6 sm:w-auto w-full pl-8 sm:pl-0">
                  
                  {/* Meta Details */}
                  <div className="flex flex-col sm:items-end text-xs text-gray-500 space-y-1">
                    <div className="flex items-center space-x-3">
                      <span className="flex items-center"><Clock className="w-3 h-3 mr-1" /> {dep.time}</span>
                      <span className="hidden sm:inline">•</span>
                      <span className="hidden sm:flex items-center"><Terminal className="w-3 h-3 mr-1" /> {dep.duration}</span>
                    </div>
                    <div className="flex items-center space-x-3">
                      <span className="flex items-center"><GitBranch className="w-3 h-3 mr-1" /> {dep.creator}</span>
                      <span className="hidden sm:inline">•</span>
                      <span className="hidden sm:flex items-center"><Globe className="w-3 h-3 mr-1" /> {dep.target}</span>
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center space-x-2">
                    <a 
                      href={`https://${dep.url}`} 
                      target="_blank" 
                      rel="noopener noreferrer"
                      className={`p-2 rounded-md transition-colors ${dep.url !== '-' ? 'text-gray-400 hover:text-white hover:bg-white/10' : 'text-gray-600 cursor-not-allowed'}`}
                      title={dep.url !== '-' ? `Visit ${dep.url}` : 'No URL available'}
                    >
                      <ArrowRight className="w-4 h-4 -rotate-45" />
                    </a>
                    <button className="p-2 text-gray-400 hover:text-white hover:bg-white/10 rounded-md transition-colors opacity-0 group-hover:opacity-100 focus:opacity-100">
                      <MoreVertical className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        ) : (
          <div className="p-12 text-center flex flex-col items-center justify-center">
            <div className="w-12 h-12 rounded-full bg-surface-hover flex items-center justify-center mb-4 border border-border">
              <Search className="w-5 h-5 text-gray-500" />
            </div>
            <h3 className="text-white font-medium mb-1">No deployments found</h3>
            <p className="text-sm text-gray-400">Try adjusting your search or filters.</p>
          </div>
        )}
      </div>
      
      {/* Pagination / Load More */}
      {filteredDeployments.length > 0 && (
        <div className="flex justify-center pt-4">
          <button className="text-sm text-gray-400 hover:text-white transition-colors border border-border bg-surface px-4 py-2 rounded-lg hover:border-gray-500">
            Load More
          </button>
        </div>
      )}
    </div>
  );
}
