import { Activity, Briefcase, Shield, Users } from 'lucide-react';

const solutions = [
  {
    title: 'Customer Operations',
    body: 'Resolve support tickets, routing, escalations, and follow-up as a governed service lane with measurable outcomes and human fallback.',
    icon: <Users className="w-10 h-10 text-blue-400 mb-6" />,
  },
  {
    title: 'Compliance',
    body: 'Screen documents, collect evidence, enforce policy, and surface exceptions with audit-ready reporting and approval controls.',
    icon: <Shield className="w-10 h-10 text-emerald-400 mb-6" />,
  },
  {
    title: 'Revenue Operations',
    body: 'Handle prospect research, qualification, sequencing, and CRM hygiene as an end-to-end managed outreach service.',
    icon: <Briefcase className="w-10 h-10 text-amber-400 mb-6" />,
  },
  {
    title: 'Finance Operations',
    body: 'Automate invoice intake, coding, approvals, and exception handling with policy-backed workflows and measurable turnaround time.',
    icon: <Activity className="w-10 h-10 text-purple-400 mb-6" />,
  },
];

const controls = [
  'Approval controls for sensitive steps',
  'Liability boundaries and escalation paths',
  'Audit trails, receipts, and measurable reporting',
];

export default function Solutions() {
  return (
    <div className="bg-black text-white min-h-screen font-sans pt-32 pb-20">
      <div className="max-w-7xl mx-auto px-6">
        <div className="mb-24 text-center max-w-3xl mx-auto">
          <h1 className="text-4xl md:text-6xl font-display font-bold tracking-tighter text-white mb-6">
            Solutions by Outcome
          </h1>
          <p className="text-xl text-gray-400 font-light leading-relaxed">
            SAS.xyz is where enterprises buy finished AI services with SLAs, controls, reporting,
            and trust posture already wrapped around the underlying autonomous supply.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-10 mb-24">
          {solutions.map((solution) => (
            <div key={solution.title} className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-10 hover:border-white/20 transition-colors">
              {solution.icon}
              <h3 className="text-2xl font-bold text-white mb-4">{solution.title}</h3>
              <p className="text-gray-400 leading-relaxed">{solution.body}</p>
            </div>
          ))}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center mb-24">
          <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-10">
            <h2 className="text-3xl font-display font-bold text-white mb-6">Enterprise delivery controls</h2>
            <div className="space-y-4">
              {controls.map((control) => (
                <div key={control} className="border border-white/10 rounded-xl px-5 py-4 text-gray-300 bg-black/30">
                  {control}
                </div>
              ))}
            </div>
          </div>

          <div className="space-y-6">
            <h2 className="text-3xl md:text-5xl font-display font-bold tracking-tight text-white">
              Services delivered by software.
            </h2>
            <p className="text-lg text-gray-400 leading-relaxed">
              Buyers should not have to reason about worker topology, agent graphs, or tool bundles.
              They should be able to buy claims handling, compliance review, support resolution,
              and revenue operations as clear, governed service products.
            </p>
            <p className="text-lg text-gray-400 leading-relaxed">
              The best components still originate on aiagent.xyz. SAS.xyz packages them into
              business-facing offerings with contracts, reporting, and operating boundaries.
            </p>
          </div>
        </div>

        <div className="text-center">
          <h2 className="text-3xl font-display font-bold text-white mb-6">
            Ready to deploy a governed AI service line?
          </h2>
          <a
            href="mailto:enterprise@sas.xyz"
            className="inline-flex items-center justify-center bg-white text-black px-8 py-4 rounded-full font-medium hover:bg-gray-200 transition-colors text-lg"
          >
            Contact Enterprise Sales
          </a>
        </div>
      </div>
    </div>
  );
}
