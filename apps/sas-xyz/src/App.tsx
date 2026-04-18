import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
import ServiceCard from './components/ServiceCard';
import { Service, RuntimePosture, PricingModel } from './types';
import { 
  X, 
  ChevronRight, 
  Terminal, 
  FileCheck, 
  ExternalLink, 
  ShieldAlert,
  Zap,
  Clock,
  Database,
  Scale,
  CreditCard,
  Settings
} from 'lucide-react';

const MOCK_SERVICES: Service[] = [
  {
    id: 'inv-ops-001',
    name: 'Invoice Operations Service',
    provider: 'FinFlow Autonomous',
    description: 'Vetted outcome service for reconciliation between bookkeeping and incoming vendor communications. Matches line items to receipts with autonomous fallback.',
    outcome: 'Reconciled Books & Tax-Ready Exports',
    connects: ['QuickBooks', 'Gmail', 'Google Drive'],
    execution: RuntimePosture.APPROVAL_GATED,
    evidence: 'Verifiable Receipts + Audit Trace',
    settlement: 'Subscription + $0.50 per outcome',
    policy: 'Budget capped at $500/mo. Vendor allowlist only.',
    recourse: '24h Challenge Window / Bonded Service',
    pricing: PricingModel.USAGE_BASED,
    privacy: 'SOC2 Type II / Zero-knowledge processing',
    status: 'available',
    tags: ['Finance', 'Automated']
  },
  {
    id: 'ent-proc-002',
    name: 'Enterprise Procurement Handler',
    provider: 'Sager Systems',
    description: 'Manages incoming RFPs and compares them against procurement policy envelopes. Automatically flags compliance drifts and suggested vendor pivots.',
    outcome: 'Decision-Ready Procurement Briefs',
    connects: ['Workday', 'Slack', 'SharePoint'],
    execution: RuntimePosture.LOCAL_FIRST,
    evidence: 'Policy Compliance Report',
    settlement: 'Monthly Seat License',
    policy: 'Strict adherence to ISO 27001 procurement protocols.',
    recourse: 'Arbitration Gated / Insurance Backed',
    pricing: PricingModel.SUBSCRIPTION,
    privacy: 'Local VPC execution only',
    status: 'monitoring',
    tags: ['Legal', 'Procurement']
  },
  {
    id: 'it-patch-003',
    name: 'Vulnerability Remediation Engine',
    provider: 'Sentinel Core',
    description: 'Autonomous patch orchestration for multi-cloud staging environments. Identifies CVEs, spins up shadow environments for testing, and requests deployment approval.',
    outcome: 'Validated Patch Deployments',
    connects: ['AWS', 'GitHub', 'Datadog'],
    execution: RuntimePosture.AUTONOMOUS,
    evidence: 'Red/Green Test Summaries',
    settlement: 'Per Remediation Action',
    policy: 'Staging environment only. Production requires human MFA.',
    recourse: 'Full Rollback Liability',
    pricing: PricingModel.PER_OUTCOME,
    privacy: 'Encrypted Runtime Environment',
    status: 'provisioned',
    tags: ['DevOps', 'Security']
  },
  {
    id: 'mkt-extract-004',
    name: 'Competitive Intel Extractor',
    provider: 'Insight Labs',
    description: 'Monitors competitor pricing updates and quarterly filings. Extracts specific structured data points relevant to strategic positioning.',
    outcome: 'Structured Market Intel Feed',
    connects: ['SEC EDGAR', 'Crunchbase', 'Public Web'],
    execution: RuntimePosture.ISOLATED,
    evidence: 'Source-linked Intelligence Cards',
    settlement: 'Daily Flat Rate',
    policy: 'No direct crawling of competitor internal APIs.',
    recourse: 'Data Correction Window',
    pricing: PricingModel.FLAT_FEE,
    privacy: 'Anonymous Proxy Execution',
    status: 'available',
    tags: ['Marketing', 'Data']
  }
];

export default function App() {
  const [activeTab, setActiveTab] = useState('catalog');
  const [selectedService, setSelectedService] = useState<Service | null>(null);
  const [services, setServices] = useState<Service[]>(MOCK_SERVICES);

  const activateService = (serviceId: string) => {
    setServices(prev => prev.map(s => 
      s.id === serviceId ? { ...s, status: 'provisioned' } : s
    ));
    setSelectedService(null);
    setActiveTab('instances');
  };

  const activeInstances = services.filter(s => s.status === 'provisioned' || s.status === 'monitoring');

  const stats = [
    { label: 'Active Services', value: '12', icon: Zap },
    { label: 'Pending Approvals', value: '4', icon: Clock },
    { label: 'Data Ingress', value: '2.4 GB', icon: Database },
  ];

  return (
    <div className="flex min-h-screen bg-[#F8FAFC] font-sans text-[#1E293B] selection:bg-[#2563EB] selection:text-white overflow-hidden">
      <Sidebar activeTab={activeTab} setActiveTab={setActiveTab} />
      
      <main className="flex-1 flex flex-col min-w-0">
        <Header />
        
        <div className="flex-1 overflow-y-auto w-full">
          <AnimatePresence mode="wait">
            {activeTab === 'catalog' && (
              <motion.div 
                key="catalog"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="p-8 max-w-7xl mx-auto w-full"
              >
                {/* Private Banner */}
                <div className="bg-[#FFFBEB] border border-[#FEF3C7] text-[#92400E] px-4 py-2 rounded-lg text-[12px] flex items-center mb-10 shadow-sm leading-none">
                  <ShieldAlert className="w-4 h-4 mr-2" />
                  <span><strong>Private Catalog:</strong> You are viewing vetted services approved by Legal and Infosec for Acme Corp Global.</span>
                </div>

                <div className="flex justify-between items-end mb-8">
                  <div className="catalog-title">
                    <h1 className="text-[24px] font-bold text-[#1E293B]">Approved Service Catalog</h1>
                    <p className="text-[14px] text-[#64748B] mt-1 font-medium italic">Deployable machine labor and bounded outcomes</p>
                  </div>
                  <div className="flex gap-2">
                    <div className="bg-[#EEF2FF] text-[#2563EB] px-3 py-1.5 rounded-md text-[12px] font-semibold border border-[#E0E7FF]">Compliance: 100%</div>
                    <div className="bg-[#F0FDFA] text-[#0D9488] px-3 py-1.5 rounded-md text-[12px] font-semibold border border-[#CCFBF1]">Budget: $12.4k remaining</div>
                  </div>
                </div>

                {/* Catalog Filter Bar */}
                <div className="flex items-center gap-8 mb-8 border-b border-[#E2E8F0]">
                  {['All Services', 'Finance', 'Legal', 'DevOps', 'Security'].map((filter, i) => (
                    <button 
                      key={filter} 
                      className={`text-sm font-semibold transition-all pb-4 relative ${i === 0 ? 'text-[#1E293B]' : 'text-[#64748B] hover:text-[#1E293B]'}`}
                    >
                      {filter}
                      {i === 0 && <motion.div layoutId="filterActive" className="absolute bottom-0 left-0 right-0 h-[2px] bg-[#2563EB]" />}
                    </button>
                  ))}
                </div>

                {/* Grid */}
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5 pb-12">
                  {services.filter(s => s.status === 'available').map((service) => (
                    <ServiceCard 
                      key={service.id} 
                      service={service} 
                      onClick={() => setSelectedService(service)} 
                    />
                  ))}
                  
                  <motion.div 
                    whileHover={{ y: -4 }}
                    className="border border-dashed border-[#CBD5E1] rounded-xl flex flex-col items-center justify-center p-8 text-center bg-white/50 group cursor-pointer hover:border-[#2563EB] hover:bg-white transition-all h-full min-h-[420px]"
                  >
                    <div className="w-10 h-10 rounded-full bg-white border border-[#E2E8F0] flex items-center justify-center mb-3 group-hover:bg-[#2563EB] group-hover:border-[#2563EB] transition-all">
                      <span className="text-xl text-[#94A3B8] group-hover:text-white leading-none">+</span>
                    </div>
                    <p className="text-sm font-bold text-[#1E293B]">Request New Service</p>
                    <p className="text-xs text-[#64748B] mt-1 px-4">Submit outcome specification for vendor matching</p>
                  </motion.div>
                </div>
              </motion.div>
            )}

            {activeTab === 'instances' && (
              <motion.div 
                key="instances"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="p-8 max-w-7xl mx-auto w-full"
              >
                <div className="mb-10">
                  <h1 className="text-[24px] font-bold text-[#1E293B]">Active Instances</h1>
                  <p className="text-[14px] text-[#64748B] mt-1 font-medium italic">Operational services currently processing governed outcomes</p>
                </div>

                <div className="grid grid-cols-1 gap-4">
                  {activeInstances.length === 0 ? (
                    <div className="p-20 text-center border border-dashed border-[#E2E8F0] rounded-2xl bg-white/50">
                      <Zap className="w-12 h-12 text-[#E2E8F0] mx-auto mb-4" />
                      <p className="text-[#64748B] font-medium">No active service instances in this environment.</p>
                      <button onClick={() => setActiveTab('catalog')} className="mt-4 text-[#2563EB] font-bold text-sm hover:underline">Go to Service Catalog</button>
                    </div>
                  ) : (
                    activeInstances.map(instance => (
                      <div key={instance.id} className="bg-white border border-[#E2E8F0] rounded-xl p-6 flex items-center justify-between hover:border-[#2563EB] transition-all group">
                        <div className="flex items-center gap-6">
                           <div className="w-12 h-12 bg-[#F1F5F9] rounded-xl flex items-center justify-center text-[#475569] font-bold text-lg group-hover:bg-[#EEF2FF] group-hover:text-[#2563EB] transition-colors">
                             {instance.name[0]}
                           </div>
                           <div>
                             <h4 className="font-bold text-[#1E293B] text-lg">{instance.name}</h4>
                             <p className="text-sm text-[#64748B] mt-1 flex items-center gap-2">
                               {instance.provider} · <span className="font-mono text-xs">ID: {instance.id}</span>
                             </p>
                           </div>
                        </div>
                        
                        <div className="flex items-center gap-12 text-right">
                          <div className="hidden md:block">
                            <p className="text-[10px] uppercase font-bold text-[#94A3B8] mb-1">Runtime Status</p>
                            <div className="flex items-center gap-1.5 justify-end">
                              <div className="w-2 h-2 rounded-full bg-[#10B981] animate-pulse" />
                              <span className="text-xs font-bold text-[#1E293B]">Operational</span>
                            </div>
                          </div>
                          <div className="hidden lg:block">
                            <p className="text-[10px] uppercase font-bold text-[#94A3B8] mb-1">Last Sync</p>
                            <span className="text-xs font-medium text-[#475569]">Just now</span>
                          </div>
                          <div>
                            <p className="text-[10px] uppercase font-bold text-[#94A3B8] mb-1">Health Index</p>
                            <span className="text-xs font-bold text-[#10B981]">100% stable</span>
                          </div>
                          <button className="p-2 hover:bg-[#F8FAFC] rounded-lg border border-[#E2E8F0] transition-all">
                             <ChevronRight className="w-4 h-4 text-[#94A3B8]" />
                          </button>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </motion.div>
            )}

            {activeTab === 'audit' && (
              <motion.div 
                key="audit"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="p-8 max-w-7xl mx-auto w-full"
              >
                <div className="mb-10">
                  <h1 className="text-[24px] font-bold text-[#1E293B]">Audit Trails</h1>
                  <p className="text-[14px] text-[#64748B] mt-1 font-medium italic">Immutable ledger of service evidence and outcome proofs</p>
                </div>

                <div className="bg-white border border-[#E2E8F0] rounded-xl overflow-hidden shadow-sm">
                  <table className="w-full text-left border-collapse">
                    <thead>
                      <tr className="bg-[#F8FAFC] border-b border-[#E2E8F0]">
                        <th className="p-5 text-[10px] font-bold uppercase text-[#64748B] tracking-wider">Timestamp</th>
                        <th className="p-5 text-[10px] font-bold uppercase text-[#64748B] tracking-wider">Service Instance</th>
                        <th className="p-5 text-[10px] font-bold uppercase text-[#64748B] tracking-wider">Outcome Proof</th>
                        <th className="p-5 text-[10px] font-bold uppercase text-[#64748B] tracking-wider">Evidence Hash</th>
                        <th className="p-5 text-[10px] font-bold uppercase text-[#64748B] tracking-wider">State</th>
                      </tr>
                    </thead>
                    <tbody>
                      {[
                        { time: '12:44:05 UTC', name: 'Invoice Ops Service', proof: 'recon_trace_v1.pdf', hash: '0x7a2...df82' },
                        { time: '12:42:12 UTC', name: 'Invoice Ops Service', proof: 'recon_trace_v0.pdf', hash: '0x4b1...e921' },
                        { time: '11:15:30 UTC', name: 'Procurement Handler', proof: 'rfp_eval_brief.pdf', hash: '0x9c3...a834' }
                      ].map((audit, i) => (
                        <tr key={i} className="border-b border-[#F1F5F9] last:border-0 hover:bg-[#F8FAFC] transition-colors cursor-pointer group">
                          <td className="p-5">
                            <p className="text-xs font-bold text-[#1E293B]">Apr 18, 2026</p>
                            <p className="text-[10px] text-[#64748B] mt-1 font-mono">{audit.time}</p>
                          </td>
                          <td className="p-5">
                            <p className="text-xs font-bold text-[#1E293B]">{audit.name}</p>
                            <p className="text-[10px] text-[#64748B] mt-1 italic">Verified Provider</p>
                          </td>
                          <td className="p-5">
                            <div className="flex items-center gap-2">
                              <FileCheck className="w-3.5 h-3.5 text-[#2563EB]" />
                              <span className="text-xs font-medium text-[#475569]">{audit.proof}</span>
                            </div>
                          </td>
                          <td className="p-5">
                            <p className="font-mono text-[10px] text-[#94A3B8]">{audit.hash}</p>
                          </td>
                          <td className="p-5">
                            <span className="text-[10px] font-bold text-[#10B981] bg-[#ECFDF5] px-2.5 py-1 rounded-md border border-[#D1FAE5]">VERIFIED</span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </motion.div>
            )}

            {activeTab === 'settlement' && (
              <motion.div 
                key="settlement"
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
                className="p-8 max-w-7xl mx-auto w-full"
              >
                <div className="mb-10">
                  <h1 className="text-[24px] font-bold text-[#1E293B]">Settlement & Billing</h1>
                  <p className="text-[14px] text-[#64748B] mt-1 font-medium italic">Automated financial settlement for delivered outcomes</p>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                   <div className="bg-[#0F172A] p-10 rounded-2xl text-white shadow-xl relative overflow-hidden">
                      <div className="absolute top-0 right-0 p-8 opacity-10">
                        <CreditCard className="w-32 h-32" />
                      </div>
                      <p className="text-[#94A3B8] text-[11px] uppercase font-bold tracking-[0.2em] mb-3">Total Accrued Spend (MTD)</p>
                      <p className="text-5xl font-bold mb-10 italic serif tracking-tight">$1,420.50</p>
                      
                      <div className="space-y-4 relative z-10">
                        <div className="flex justify-between text-sm py-2 border-b border-white/5">
                          <span className="text-[#94A3B8]">Fixed Subscriptions</span>
                          <span className="font-bold">$900.00</span>
                        </div>
                        <div className="flex justify-between text-sm py-2 border-b border-white/5">
                          <span className="text-[#94A3B8]">Outcome-based Fees</span>
                          <span className="font-bold">$520.50</span>
                        </div>
                        <div className="pt-4 flex justify-between items-center">
                          <span className="text-[#94A3B8] text-xs">Next Automation Date</span>
                          <span className="font-bold text-[#2563EB]">May 01, 2026</span>
                        </div>
                      </div>
                   </div>

                   <div className="bg-white border border-[#E2E8F0] p-8 rounded-2xl shadow-sm">
                      <h3 className="font-bold text-lg mb-8 text-[#1E293B]">Settlement Breakdown</h3>
                      <div className="space-y-6">
                        {[
                          { label: 'FinFlow Invoice Processing', count: 1041, cost: '$520.50', trend: '+12%' },
                          { label: 'Sager Procurement Handle', count: 1, cost: '$450.00', trend: 'Flat' },
                          { label: 'Sentinel Vulnerability Scan', count: 0, cost: '$450.00', trend: 'N/A' }
                        ].map(item => (
                          <div key={item.label} className="flex justify-between items-start border-b border-[#F1F5F9] pb-5 last:border-0 last:pb-0">
                             <div>
                               <p className="text-sm font-bold text-[#1E293B]">{item.label}</p>
                               <p className="text-[11px] text-[#64748B] mt-1 font-mono uppercase tracking-wide">{item.count} Outcomes Delivered</p>
                             </div>
                             <div className="text-right">
                               <p className="font-bold text-[#1E293B]">{item.cost}</p>
                               <p className="text-[10px] text-[#10B981] font-bold mt-1 uppercase">{item.trend}</p>
                             </div>
                          </div>
                        ))}
                      </div>
                   </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
      </main>

      {/* Service Detail Drawer */}
      <AnimatePresence>
        {selectedService && (
          <>
            <motion.div 
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={() => setSelectedService(null)}
              className="fixed inset-0 bg-black/40 z-50 backdrop-blur-[2px]"
            />
            <motion.div 
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ type: 'spring', damping: 25, stiffness: 200 }}
              className="fixed top-0 right-0 h-full w-full max-w-xl bg-white z-[60] shadow-2xl flex flex-col"
            >
              <div className="p-8 border-b border-gray-100 flex items-center justify-between">
                <div>
                   <div className="flex items-center gap-2 mb-2">
                    <span className="text-[10px] font-mono px-1.5 py-0.5 border border-gray-200 rounded uppercase text-gray-500">Service ID: {selectedService.id}</span>
                    <span className="w-1.5 h-1.5 rounded-full bg-green-500" title="Vetted" />
                  </div>
                  <h2 className="text-3xl font-bold tracking-tight italic serif">{selectedService.name}</h2>
                </div>
                <button 
                  onClick={() => setSelectedService(null)}
                  className="p-2 hover:bg-gray-100 rounded-full transition-colors"
                >
                  <X className="w-6 h-6" />
                </button>
              </div>

              <div className="flex-1 overflow-y-auto p-10 space-y-10 custom-scrollbar">
                <section>
                  <h4 className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-[0.2em] mb-4">Core Outcome Output</h4>
                  <div className="p-6 bg-[#F8FAFC] border border-[#E2E8F0] rounded-2xl">
                    <p className="text-2xl font-bold leading-tight text-[#0F172A] italic serif group-hover:text-[#2563EB] transition-colors">
                      {selectedService.outcome}
                    </p>
                    <p className="text-sm text-[#64748B] mt-4 leading-relaxed font-medium">
                      {selectedService.description}
                    </p>
                  </div>
                </section>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-10">
                  <section>
                    <h4 className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-[0.2em] mb-4">Governance Policy</h4>
                    <div className="flex items-start gap-4 p-5 bg-[#F0FDFA] border border-[#CCFBF1] rounded-2xl">
                      <ShieldAlert className="w-5 h-5 text-[#0D9488] shrink-0 mt-0.5" />
                      <div>
                        <p className="text-[13px] text-[#134E48] font-bold leading-none mb-1">POLICY ENVELOPE ALPHA</p>
                        <p className="text-[13px] text-[#0D9488] italic leading-relaxed">"{selectedService.policy}"</p>
                      </div>
                    </div>
                  </section>
                  <section>
                    <h4 className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-[0.2em] mb-4">Recourse & SLAs</h4>
                    <div className="flex items-start gap-4 p-5 bg-[#EFF6FF] border border-[#DBEAFE] rounded-2xl">
                      <Scale className="w-5 h-5 text-[#2563EB] shrink-0 mt-0.5" />
                      <div>
                        <p className="text-[13px] text-[#1E3A8A] font-bold leading-none mb-1">RECOURSE CLASS IV</p>
                        <p className="text-[13px] text-[#2563EB] leading-relaxed italic">{selectedService.recourse}</p>
                      </div>
                    </div>
                  </section>
                </div>

                <div className="grid grid-cols-2 gap-10">
                  <section>
                    <h4 className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-[0.2em] mb-4">Operational Anatomy</h4>
                    <div className="space-y-4">
                      <div className="flex justify-between items-center py-2 border-b border-[#F1F5F9]">
                        <span className="text-[11px] font-bold text-[#64748B] tracking-wider uppercase">Runtime Posture</span>
                        <span className="text-sm font-bold text-[#0F172A]">{selectedService.execution}</span>
                      </div>
                      <div className="flex justify-between items-center py-2 border-b border-[#F1F5F9]">
                        <span className="text-[11px] font-bold text-[#64748B] tracking-wider uppercase">Privacy Class</span>
                        <span className="text-sm font-bold text-[#0F172A]">{selectedService.privacy}</span>
                      </div>
                      <div className="flex justify-between items-center py-2 border-b border-[#F1F5F9]">
                        <span className="text-[11px] font-bold text-[#64748B] tracking-wider uppercase">Settlement Logic</span>
                        <span className="text-sm font-bold text-[#0F172A]">{selectedService.settlement}</span>
                      </div>
                    </div>
                  </section>
                  <section>
                    <h4 className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-[0.2em] mb-4">Deployed Evidence</h4>
                    <div className="flex items-center gap-4 p-5 bg-white border border-[#E2E8F0] rounded-2xl shadow-sm">
                      <div className="p-2 bg-[#F1F5F9] rounded-lg">
                        <FileCheck className="w-6 h-6 text-[#2563EB]" />
                      </div>
                      <div>
                        <p className="text-sm font-bold text-[#0F172A]">{selectedService.evidence}</p>
                        <p className="text-[10px] text-[#94A3B8] font-bold uppercase tracking-widest mt-1">Verifiable Audit Chain</p>
                      </div>
                    </div>
                  </section>
                </div>

                <div className="mt-auto pt-10">
                  <div className="bg-[#0F172A] p-10 rounded-[32px] text-white shadow-2xl relative overflow-hidden group">
                    <div className="absolute top-0 right-0 p-8 opacity-5 group-hover:scale-110 transition-transform duration-700">
                      <Zap className="w-40 h-40" />
                    </div>
                    <div className="flex justify-between items-end mb-8 relative z-10">
                      <div>
                        <p className="text-[#94A3B8] text-[10px] font-bold uppercase tracking-[0.3em] mb-2">Outcome Pricing Model</p>
                        <p className="text-4xl font-bold tracking-tight italic serif">
                          {selectedService.pricing === PricingModel.SUBSCRIPTION ? '$450/mo' : selectedService.pricing === PricingModel.USAGE_BASED ? '$1.20' : '$0.00'}
                          <span className="text-lg opacity-40 ml-2 font-normal">flat rate</span>
                        </p>
                      </div>
                      <div className="text-right">
                        <p className="text-[#94A3B8] text-[10px] font-bold uppercase tracking-[0.3em] mb-2">Availability Status</p>
                        <span className="text-sm font-bold text-[#2563EB] bg-[#2563EB]/10 px-3 py-1 rounded-full border border-[#2563EB]/20">DORMANT / READY</span>
                      </div>
                    </div>
                    <button 
                      onClick={() => activateService(selectedService.id)}
                      className="w-full bg-[#2563EB] text-white font-bold py-5 rounded-2xl hover:bg-[#1D4ED8] transition-all transform hover:scale-[1.02] active:scale-95 shadow-xl flex items-center justify-center gap-4 text-lg border border-[#3B82F6]"
                    >
                      <Zap className="w-5 h-5 fill-white" />
                      Procure & Connect Service
                    </button>
                    <p className="text-[11px] text-[#64748B] text-center mt-6 px-10 leading-relaxed font-medium">
                      Activating this service initiates an autonomous deployment target handshake. Approval via Corporate Policy 2026.4 is pre-verified.
                    </p>
                  </div>
                </div>
              </div>
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </div>
  );
}
