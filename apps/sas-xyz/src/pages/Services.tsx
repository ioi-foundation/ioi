import React, { useState } from 'react';
import { Search, Plus, Globe, Github, Activity, MoreVertical, ArrowRight, ShieldCheck } from 'lucide-react';
import { motion } from 'motion/react';
import { Link } from 'react-router-dom';

const mockServices = [
  {
    id: 'srv_1',
    name: 'defi-arbitrage-sentinel',
    framework: 'Node.js',
    status: 'Ready',
    lastDeploy: '2m ago',
    domain: 'defi-arb.sas.xyz',
    repo: 'quantlabs/defi-sentinel',
    enclaves: 3,
    health: 100
  },
  {
    id: 'srv_2',
    name: 'customer-support-agent',
    framework: 'Python',
    status: 'Building',
    lastDeploy: '1h ago',
    domain: 'cs-agent.sas.xyz',
    repo: 'quantlabs/cs-agent',
    enclaves: 1,
    health: 98
  },
  {
    id: 'srv_3',
    name: 'data-pipeline-worker',
    framework: 'Go',
    status: 'Failed',
    lastDeploy: '3h ago',
    domain: 'data-pipe.sas.xyz',
    repo: 'quantlabs/data-pipeline',
    enclaves: 0,
    health: 0
  },
  {
    id: 'srv_4',
    name: 'sales-outreach-bot',
    framework: 'Node.js',
    status: 'Ready',
    lastDeploy: '1d ago',
    domain: 'sales-bot.sas.xyz',
    repo: 'quantlabs/sales-bot',
    enclaves: 2,
    health: 100
  }
];

export default function Services() {
  const [searchQuery, setSearchQuery] = useState('');

  const filteredServices = mockServices.filter(srv => 
    srv.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    srv.repo.toLowerCase().includes(searchQuery.toLowerCase())
  );

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white tracking-tight">Services</h1>
          <p className="text-gray-400 text-sm">Manage your agent service packages and active enclaves.</p>
        </div>
        <div className="flex space-x-3">
          <Link to="/app/canvas" className="flex items-center bg-white text-bg px-4 py-2 rounded-md font-medium text-sm hover:bg-gray-200 transition-colors shadow-sm shadow-white/10">
            <Plus className="w-4 h-4 mr-2" />
            Create Service
          </Link>
        </div>
      </div>

      {/* Search Bar */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
        <input 
          type="text" 
          placeholder="Search services or repositories..." 
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="w-full bg-surface border border-border rounded-lg pl-9 pr-4 py-2 text-sm text-white focus:outline-none focus:border-cyan-accent transition-colors"
        />
      </div>

      {/* Services Grid */}
      {filteredServices.length > 0 ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filteredServices.map((srv, i) => (
            <motion.div 
              key={srv.id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.2, delay: i * 0.05 }}
              className="bg-surface border border-border rounded-xl overflow-hidden hover:border-gray-600 transition-colors group flex flex-col"
            >
              {/* Card Header */}
              <div className="p-5 border-b border-border flex-1">
                <div className="flex items-start justify-between mb-4">
                  <div className="flex items-center space-x-3">
                    <div className="w-10 h-10 rounded-lg bg-bg border border-border flex items-center justify-center">
                      <Activity className={`w-5 h-5 ${
                        srv.status === 'Ready' ? 'text-emerald-accent' : 
                        srv.status === 'Building' ? 'text-cyan-accent animate-pulse' : 'text-red-500'
                      }`} />
                    </div>
                    <div>
                      <Link to={`/app/services/${srv.name}`} className="font-semibold text-white hover:text-cyan-accent transition-colors text-lg">
                        {srv.name}
                      </Link>
                      <div className="flex items-center text-xs text-gray-500 mt-0.5 space-x-2">
                        <span>{srv.framework}</span>
                        <span>•</span>
                        <span className="flex items-center">
                          <ShieldCheck className="w-3 h-3 mr-1" />
                          {srv.enclaves} Enclaves
                        </span>
                      </div>
                    </div>
                  </div>
                  <button className="text-gray-500 hover:text-white transition-colors p-1 rounded hover:bg-white/10">
                    <MoreVertical className="w-4 h-4" />
                  </button>
                </div>

                <div className="space-y-2 mt-4">
                  <div className="flex items-center text-sm text-gray-400">
                    <Globe className="w-4 h-4 mr-2 text-gray-500" />
                    <a href={`https://${srv.domain}`} target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors truncate">
                      {srv.domain}
                    </a>
                  </div>
                  <div className="flex items-center text-sm text-gray-400">
                    <Github className="w-4 h-4 mr-2 text-gray-500" />
                    <a href={`https://github.com/${srv.repo}`} target="_blank" rel="noopener noreferrer" className="hover:text-white transition-colors truncate">
                      {srv.repo}
                    </a>
                  </div>
                </div>
              </div>

              {/* Card Footer */}
              <div className="bg-surface-hover px-5 py-3 flex items-center justify-between text-xs">
                <div className="flex items-center space-x-2">
                  <span className="text-gray-500">{srv.lastDeploy}</span>
                  <span className="text-gray-600">•</span>
                  <span className={`font-medium ${
                    srv.status === 'Ready' ? 'text-emerald-accent' : 
                    srv.status === 'Building' ? 'text-cyan-accent' : 'text-red-500'
                  }`}>
                    {srv.status}
                  </span>
                </div>
                <Link to={`/app/services/${srv.name}`} className="text-gray-400 hover:text-white transition-colors flex items-center">
                  Manage <ArrowRight className="w-3 h-3 ml-1" />
                </Link>
              </div>
            </motion.div>
          ))}
        </div>
      ) : (
        <div className="bg-surface border border-border rounded-xl p-12 text-center flex flex-col items-center justify-center">
          <div className="w-12 h-12 rounded-full bg-surface-hover flex items-center justify-center mb-4 border border-border">
            <Search className="w-5 h-5 text-gray-500" />
          </div>
          <h3 className="text-white font-medium mb-1">No services found</h3>
          <p className="text-sm text-gray-400">Try adjusting your search or create a new service.</p>
        </div>
      )}
    </div>
  );
}
