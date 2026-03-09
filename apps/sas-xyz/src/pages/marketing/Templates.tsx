import { motion } from 'motion/react';
import { ArrowRight, Code2, Shield, Activity, Search, Filter, GitBranch } from 'lucide-react';
import { Link } from 'react-router-dom';

const TEMPLATES = [
  {
    id: 1,
    title: "Multi-Agent Coder",
    description: "A swarm of agents that write, review, and deploy code securely.",
    icon: <Code2 className="w-6 h-6 text-blue-400" />,
    tags: ["Development", "Swarm", "GitHub MCP"],
    color: "from-blue-500/20 to-transparent"
  },
  {
    id: 2,
    title: "Financial Analyst Swarm",
    description: "Real-time market analysis with automated trading execution and strict spend limits.",
    icon: <Activity className="w-6 h-6 text-emerald-400" />,
    tags: ["DeFi", "Trading", "High-Risk"],
    color: "from-emerald-500/20 to-transparent"
  },
  {
    id: 3,
    title: "Personal Health Auditor",
    description: "Analyzes health data locally in a TEE. Zero data exfiltration guaranteed.",
    icon: <Shield className="w-6 h-6 text-purple-400" />,
    tags: ["Healthcare", "Privacy", "Local LLM"],
    color: "from-purple-500/20 to-transparent"
  },
  {
    id: 4,
    title: "Customer Support Router",
    description: "Triage incoming tickets, solve common issues, and escalate to humans.",
    icon: <GitBranch className="w-6 h-6 text-amber-400" />,
    tags: ["Support", "Zendesk MCP", "Routing"],
    color: "from-amber-500/20 to-transparent"
  }
];

export default function Templates() {
  return (
    <div className="bg-black text-white min-h-screen font-sans pt-32 pb-20">
      <div className="max-w-7xl mx-auto px-6">
        
        {/* Header */}
        <div className="mb-16">
          <h1 className="text-4xl md:text-6xl font-display font-bold tracking-tighter text-white mb-6">
            The Genesis Gallery
          </h1>
          <p className="text-xl text-gray-400 max-w-2xl font-light leading-relaxed">
            Don't start with a blank text file. Deploy production-ready agent architectures in one click.
          </p>
        </div>

        {/* Search & Filter */}
        <div className="flex flex-col md:flex-row gap-4 mb-12">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
            <input 
              type="text" 
              placeholder="Search templates..." 
              className="w-full bg-[#0a0a0a] border border-white/10 rounded-xl py-3 pl-12 pr-4 text-white focus:outline-none focus:border-white/30 transition-colors"
            />
          </div>
          <button className="bg-[#0a0a0a] border border-white/10 rounded-xl px-6 py-3 flex items-center justify-center text-gray-300 hover:text-white hover:bg-white/5 transition-colors">
            <Filter className="w-4 h-4 mr-2" />
            Filters
          </button>
        </div>

        {/* Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {TEMPLATES.map((template) => (
            <motion.div 
              key={template.id}
              whileHover={{ y: -4 }}
              className="bg-[#0a0a0a] border border-white/10 rounded-2xl overflow-hidden group relative flex flex-col"
            >
              <div className={`absolute top-0 left-0 w-full h-32 bg-gradient-to-b ${template.color} opacity-50 pointer-events-none`}></div>
              
              <div className="p-8 flex-1 relative z-10">
                <div className="w-12 h-12 rounded-xl bg-black border border-white/10 flex items-center justify-center mb-6 shadow-xl">
                  {template.icon}
                </div>
                <h3 className="text-xl font-bold text-white mb-3">{template.title}</h3>
                <p className="text-gray-400 text-sm leading-relaxed mb-6">
                  {template.description}
                </p>
                <div className="flex flex-wrap gap-2">
                  {template.tags.map(tag => (
                    <span key={tag} className="text-[10px] font-mono text-gray-500 bg-white/5 border border-white/10 px-2 py-1 rounded">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>

              <div className="p-4 border-t border-white/10 bg-black/50 flex items-center justify-between relative z-10">
                <button className="text-sm font-medium text-gray-400 hover:text-white transition-colors flex items-center">
                  View DAG
                </button>
                <Link to="/login" className="bg-white text-black px-4 py-2 rounded-full text-xs font-bold hover:bg-gray-200 transition-colors flex items-center">
                  Deploy <ArrowRight className="w-3 h-3 ml-1" />
                </Link>
              </div>
            </motion.div>
          ))}
        </div>

      </div>
    </div>
  );
}
