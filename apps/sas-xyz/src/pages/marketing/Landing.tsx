import React, { useEffect, useState } from 'react';
import { motion } from 'motion/react';
import { Activity, ArrowRight, Box, CheckCircle2, ChevronRight, Cpu, Shield, Workflow } from 'lucide-react';
import { Link } from 'react-router-dom';

export default function Landing() {
  const [heroTab, setHeroTab] = useState<'brief' | 'provenance'>('brief');
  const [outcomesDelivered, setOutcomesDelivered] = useState(12840);

  useEffect(() => {
    if (heroTab !== 'provenance') {
      return undefined;
    }

    const interval = setInterval(() => {
      setOutcomesDelivered((previous) => previous + Math.floor(Math.random() * 3 + 1));
    }, 2200);

    return () => clearInterval(interval);
  }, [heroTab]);

  return (
    <div className="bg-black text-white min-h-screen font-sans selection:bg-white/30">
      <section className="relative pt-32 pb-20 overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[400px] bg-blue-500/10 blur-[120px] rounded-full pointer-events-none -z-10"></div>

        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center">
            <div className="flex flex-col items-start text-left">
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.4 }}
                className="mb-6 inline-flex items-center space-x-2 bg-white/5 border border-white/10 rounded-full px-3 py-1 text-xs font-medium text-gray-300 backdrop-blur-sm"
              >
                <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse"></span>
                <span>sas.xyz service catalog is live</span>
                <ChevronRight className="w-3 h-3 text-gray-500" />
              </motion.div>

              <motion.h1
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.1 }}
                className="text-5xl md:text-7xl font-bold tracking-tighter text-white leading-[1.05] mb-6"
              >
                Buy outcomes,
                <br />
                <span className="text-transparent bg-clip-text bg-gradient-to-b from-white to-white/50">
                  not seats.
                </span>
              </motion.h1>

              <motion.p
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.2 }}
                className="text-lg md:text-xl text-gray-400 max-w-xl leading-relaxed mb-10 font-light tracking-tight"
              >
                Deploy AI-native services that execute work end-to-end with policy, evidence,
                measurable results, and enterprise governance. Verified components from aiagent.xyz
                power the service under the hood, but buyers stay focused on the result.
              </motion.p>

              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.5, delay: 0.3 }}
                className="flex flex-col sm:flex-row items-center space-y-4 sm:space-y-0 sm:space-x-4 w-full sm:w-auto"
              >
                <Link
                  to="/solutions"
                  className="w-full sm:w-auto bg-white text-black px-8 py-3.5 rounded-full font-medium hover:bg-gray-200 transition-colors flex items-center justify-center text-base"
                >
                  Explore Services
                </Link>
                <Link
                  to="/docs"
                  className="w-full sm:w-auto bg-transparent border border-white/20 text-white px-8 py-3.5 rounded-full font-medium hover:bg-white/5 transition-colors flex items-center justify-center text-base"
                >
                  View the Docs
                </Link>
              </motion.div>
            </div>

            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ duration: 0.5, delay: 0.4 }}
              className="relative w-full max-w-lg mx-auto lg:ml-auto"
            >
              <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl overflow-hidden shadow-2xl">
                <div className="flex items-center p-2 bg-[#111] border-b border-white/10">
                  <div className="flex space-x-1 bg-black/50 p-1 rounded-lg border border-white/5">
                    <button
                      onClick={() => setHeroTab('brief')}
                      className={`px-4 py-1.5 text-xs font-medium rounded-md transition-colors ${heroTab === 'brief' ? 'bg-white/10 text-white' : 'text-gray-500 hover:text-gray-300'}`}
                    >
                      Service Brief
                    </button>
                    <button
                      onClick={() => setHeroTab('provenance')}
                      className={`px-4 py-1.5 text-xs font-medium rounded-md transition-colors ${heroTab === 'provenance' ? 'bg-white/10 text-white' : 'text-gray-500 hover:text-gray-300'}`}
                    >
                      Provenance
                    </button>
                  </div>
                </div>

                <div className="p-6 h-[320px] flex items-center justify-center relative overflow-hidden">
                  {heroTab === 'brief' ? (
                    <div className="w-full h-full font-mono text-sm text-gray-300 leading-relaxed">
                      <p className="text-white font-semibold mb-4">Claims Intake & Resolution Service</p>
                      <p><span className="text-gray-500">Outcome</span> = Resolve first-touch claims intake</p>
                      <p><span className="text-gray-500">SLA</span> = 97% same-day routing</p>
                      <p><span className="text-gray-500">Governance</span> = approval gate for exception handling</p>
                      <p><span className="text-gray-500">Pricing</span> = base fee + per resolved claim</p>
                      <p><span className="text-gray-500">Deployment</span> = private VPC or managed lane</p>
                      <br />
                      <p className="text-gray-500"># Powered by verified supply from aiagent.xyz</p>
                      <p>components = ["claims-triage-operator", "kyc-extraction-pipeline", "policy-review-workflow"]</p>
                    </div>
                  ) : (
                    <div className="w-full h-full flex flex-col items-center justify-center">
                      <motion.div
                        animate={{ rotateY: [0, 360] }}
                        transition={{ duration: 20, repeat: Infinity, ease: 'linear' }}
                        className="w-56 h-64 bg-gradient-to-tr from-blue-600/20 to-emerald-600/20 border border-white/20 rounded-xl p-5 flex flex-col justify-between shadow-[0_0_30px_rgba(59,130,246,0.2)] backdrop-blur-md"
                      >
                        <div className="flex justify-between items-start">
                          <div className="w-8 h-8 rounded-full bg-white/10 flex items-center justify-center">
                            <Workflow className="w-4 h-4 text-blue-400" />
                          </div>
                          <span className="text-[10px] font-mono text-gray-400 bg-black/50 px-2 py-1 rounded">VERIFIED</span>
                        </div>
                        <div>
                          <p className="text-xs text-gray-400 font-mono mb-1">service-lane.claims-resolution</p>
                          <p className="text-lg font-bold text-white tracking-tight">Governed Outcome Contract</p>
                        </div>
                      </motion.div>

                      <div className="absolute bottom-6 bg-black/80 border border-white/10 backdrop-blur-md px-4 py-2 rounded-full flex items-center space-x-3 shadow-xl">
                        <Activity className="w-4 h-4 text-emerald-400" />
                        <div className="flex flex-col">
                          <span className="text-[10px] text-gray-400 font-medium uppercase">Outcomes Delivered</span>
                          <span className="text-sm font-mono text-white">{outcomesDelivered.toLocaleString()}</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </motion.div>
          </div>
        </div>
      </section>

      <section className="border-y border-white/10 bg-[#050505] py-8">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 text-center divide-y md:divide-y-0 md:divide-x divide-white/10">
            <div className="py-4 md:py-0">
              <p className="text-3xl font-bold text-white mb-1 tracking-tighter">12,480</p>
              <p className="text-xs text-gray-500 uppercase tracking-widest font-medium">Outcomes Completed This Week</p>
            </div>
            <div className="py-4 md:py-0">
              <p className="text-3xl font-bold text-white mb-1 tracking-tighter">99.94%</p>
              <p className="text-xs text-gray-500 uppercase tracking-widest font-medium">SLA Attainment Across Managed Lanes</p>
            </div>
            <div className="py-4 md:py-0 flex flex-col items-center justify-center">
              <div className="flex -space-x-2 mb-2">
                <div className="w-8 h-8 rounded-full bg-blue-500/20 border border-black flex items-center justify-center"><Workflow className="w-3 h-3 text-blue-400" /></div>
                <div className="w-8 h-8 rounded-full bg-emerald-500/20 border border-black flex items-center justify-center"><Shield className="w-3 h-3 text-emerald-400" /></div>
                <div className="w-8 h-8 rounded-full bg-amber-500/20 border border-black flex items-center justify-center"><Cpu className="w-3 h-3 text-amber-400" /></div>
              </div>
              <p className="text-xs text-gray-500 uppercase tracking-widest font-medium">Claims, Support, Compliance, Revenue Ops</p>
            </div>
          </div>
        </div>
      </section>

      <section className="py-32 border-t border-white/10">
        <div className="max-w-7xl mx-auto px-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-px bg-white/10 border border-white/10 rounded-2xl overflow-hidden">
            <div className="bg-black p-10 lg:col-span-3 flex flex-col justify-center relative overflow-hidden">
              <div className="absolute top-0 right-0 w-[500px] h-[500px] bg-emerald-500/10 blur-[100px] rounded-full pointer-events-none"></div>
              <h2 className="text-3xl md:text-5xl font-bold tracking-tight text-white mb-4 relative z-10">
                Governed outcomes, not black-box automation.
              </h2>
              <p className="text-xl text-gray-400 font-light max-w-2xl relative z-10">
                SAS.xyz wraps verified autonomous components in contracts, controls, reporting,
                approvals, and escalation paths so enterprises can buy a service instead of
                assembling an agent graph.
              </p>
            </div>

            <FeatureCard
              icon={<Workflow className="w-6 h-6 text-emerald-400" />}
              title="Outcome Contracts"
              description="Buy finished business services with defined scope, service levels, deployment models, and measurable deliverables."
            />
            <FeatureCard
              icon={<Shield className="w-6 h-6 text-blue-400" />}
              title="Governance & Approvals"
              description="Sensitive actions route through policy-backed approvals, exception queues, and human escalation lanes."
            />
            <FeatureCard
              icon={<Box className="w-6 h-6 text-purple-400" />}
              title="Liability Boundaries"
              description="Every service lane declares ownership, escalation paths, trust posture, and evidence expectations before production rollout."
            />
            <FeatureCard
              icon={<Activity className="w-6 h-6 text-amber-400" />}
              title="Service Analytics"
              description="Measure outcomes, exceptions, turnaround time, and compliance posture from a delivery dashboard built for operators and buyers."
            />
            <FeatureCard
              icon={<CheckCircle2 className="w-6 h-6 text-white" />}
              title="Provenance from aiagent.xyz"
              description="Finished services can disclose the verified agents, workflows, and operator packs that power them without forcing the buyer to manage components."
              wide
            />
          </div>
        </div>
      </section>

      <section className="py-32 border-t border-white/10 relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-transparent to-blue-900/10 pointer-events-none"></div>
        <div className="max-w-4xl mx-auto px-6 text-center relative z-10">
          <h2 className="text-4xl md:text-6xl font-bold tracking-tighter text-white mb-8">
            Launch a governed service lane,
            <br className="hidden md:block" /> not another SaaS seat.
          </h2>
          <p className="text-xl text-gray-400 mb-10 font-light max-w-2xl mx-auto">
            Choose the result, pricing model, deployment posture, and trust requirements. SAS.xyz
            handles the packaging, governance, and measurement while aiagent.xyz supplies the
            verified autonomous substrate underneath.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center space-y-4 sm:space-y-0 sm:space-x-4">
            <Link
              to="/solutions"
              className="w-full sm:w-auto bg-white text-black px-10 py-4 rounded-full font-medium hover:bg-gray-200 transition-colors text-lg flex items-center justify-center"
            >
              Explore Solutions <ArrowRight className="w-5 h-5 ml-2" />
            </Link>
            <a
              href="mailto:enterprise@sas.xyz"
              className="w-full sm:w-auto border border-white/20 text-white px-10 py-4 rounded-full font-medium hover:bg-white/5 transition-colors text-lg flex items-center justify-center"
            >
              Contact Sales
            </a>
          </div>

          <div className="mt-20 flex flex-col md:flex-row items-center justify-center space-y-4 md:space-y-0 md:space-x-8 text-sm text-gray-500 font-medium uppercase tracking-widest">
            <span>Components on aiagent.xyz</span>
            <span className="hidden md:block w-1.5 h-1.5 rounded-full bg-white/20"></span>
            <span>Outcomes on sas.xyz</span>
          </div>
        </div>
      </section>
    </div>
  );
}

function FeatureCard({
  icon,
  title,
  description,
  wide = false,
}: {
  icon: React.ReactNode;
  title: string;
  description: string;
  wide?: boolean;
}) {
  return (
    <div className={`bg-[#0a0a0a] p-10 flex flex-col justify-between group hover:bg-[#111] transition-colors cursor-pointer ${wide ? 'md:col-span-2' : ''}`}>
      <div>
        <div className="flex items-center space-x-3 mb-6">
          {icon}
          <h3 className="text-xl font-bold text-white">{title}</h3>
        </div>
        <p className="text-gray-400 leading-relaxed max-w-lg">{description}</p>
      </div>
      <div className="mt-8 flex justify-end">
        <div className="w-10 h-10 rounded-full bg-white/5 flex items-center justify-center group-hover:bg-white/10 transition-colors">
          <ArrowRight className="w-4 h-4 text-white" />
        </div>
      </div>
    </div>
  );
}
