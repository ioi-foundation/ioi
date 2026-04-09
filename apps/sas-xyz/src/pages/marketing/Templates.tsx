import { motion } from 'motion/react';
import { ArrowRight, Briefcase, Filter, Search, Shield, Workflow, Activity, Cpu } from 'lucide-react';
import { Link } from 'react-router-dom';

const SERVICES = [
  {
    id: 1,
    title: 'Customer Support Resolution as a Service',
    description: 'Resolve tier-1 and tier-2 tickets with policy-aware automation, approval routes, and measurable CSAT impact.',
    icon: <Workflow className="w-6 h-6 text-blue-400" />,
    tags: ['Customer Operations', 'SLA-backed', 'Zendesk + Salesforce'],
    color: 'from-blue-500/20 to-transparent',
  },
  {
    id: 2,
    title: 'Compliance Screening as a Service',
    description: 'Run document collection, screening, evidence generation, and escalation workflows with audit-ready delivery.',
    icon: <Shield className="w-6 h-6 text-emerald-400" />,
    tags: ['Compliance', 'Governed', 'KYC + Policy'],
    color: 'from-emerald-500/20 to-transparent',
  },
  {
    id: 3,
    title: 'Claims Intake and Resolution Service',
    description: 'Triage intake, extract documents, apply policy rules, and route edge cases to human reviewers without exposing agent topology.',
    icon: <Activity className="w-6 h-6 text-amber-400" />,
    tags: ['Insurance', 'Per Outcome', 'Private Deploy'],
    color: 'from-amber-500/20 to-transparent',
  },
  {
    id: 4,
    title: 'AI Software Maintenance Service',
    description: 'Turn backlog triage, regression review, release checks, and remediation into a managed engineering service lane.',
    icon: <Cpu className="w-6 h-6 text-purple-400" />,
    tags: ['Engineering', 'Hybrid Pricing', 'Evidence'],
    color: 'from-purple-500/20 to-transparent',
  },
  {
    id: 5,
    title: 'Revenue Operations Outreach Service',
    description: 'Run prospect research, sequencing, qualification, and exception handling with governance and reporting built in.',
    icon: <Briefcase className="w-6 h-6 text-cyan-400" />,
    tags: ['Sales', 'Managed Lane', 'CRM Connected'],
    color: 'from-cyan-500/20 to-transparent',
  },
];

export default function Templates() {
  return (
    <div className="bg-black text-white min-h-screen font-sans pt-32 pb-20">
      <div className="max-w-7xl mx-auto px-6">
        <div className="mb-16">
          <h1 className="text-4xl md:text-6xl font-display font-bold tracking-tighter text-white mb-6">
            The Service Catalog
          </h1>
          <p className="text-xl text-gray-400 max-w-2xl font-light leading-relaxed">
            Finished outcome-based AI services powered by verified autonomous supply from aiagent.xyz.
            Browse by business result instead of agent topology.
          </p>
        </div>

        <div className="flex flex-col md:flex-row gap-4 mb-12">
          <div className="relative flex-1">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-gray-500" />
            <input
              type="text"
              placeholder="Search services, industries, or outcomes..."
              className="w-full bg-[#0a0a0a] border border-white/10 rounded-xl py-3 pl-12 pr-4 text-white focus:outline-none focus:border-white/30 transition-colors"
            />
          </div>
          <button className="bg-[#0a0a0a] border border-white/10 rounded-xl px-6 py-3 flex items-center justify-center text-gray-300 hover:text-white hover:bg-white/5 transition-colors">
            <Filter className="w-4 h-4 mr-2" />
            Outcome Filters
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {SERVICES.map((service) => (
            <motion.div
              key={service.id}
              whileHover={{ y: -4 }}
              className="bg-[#0a0a0a] border border-white/10 rounded-2xl overflow-hidden group relative flex flex-col"
            >
              <div className={`absolute top-0 left-0 w-full h-32 bg-gradient-to-b ${service.color} opacity-50 pointer-events-none`}></div>

              <div className="p-8 flex-1 relative z-10">
                <div className="w-12 h-12 rounded-xl bg-black border border-white/10 flex items-center justify-center mb-6 shadow-xl">
                  {service.icon}
                </div>
                <h3 className="text-xl font-bold text-white mb-3">{service.title}</h3>
                <p className="text-gray-400 text-sm leading-relaxed mb-6">
                  {service.description}
                </p>
                <div className="flex flex-wrap gap-2">
                  {service.tags.map((tag) => (
                    <span key={tag} className="text-[10px] font-mono text-gray-500 bg-white/5 border border-white/10 px-2 py-1 rounded">
                      {tag}
                    </span>
                  ))}
                </div>
              </div>

              <div className="p-4 border-t border-white/10 bg-black/50 flex items-center justify-between relative z-10">
                <Link to="/docs" className="text-sm font-medium text-gray-400 hover:text-white transition-colors flex items-center">
                  View brief
                </Link>
                <Link to="/solutions" className="bg-white text-black px-4 py-2 rounded-full text-xs font-bold hover:bg-gray-200 transition-colors flex items-center">
                  Request rollout <ArrowRight className="w-3 h-3 ml-1" />
                </Link>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  );
}
