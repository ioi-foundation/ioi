import { ArrowRight, Boxes, BriefcaseBusiness, CircleDollarSign, Shield, TrendingUp } from 'lucide-react';
import { Link } from 'react-router-dom';

const promotionStages = [
  'Agent',
  'Workflow',
  'Operator Pack',
  'Service Module',
  'Managed Service',
  'Enterprise SaS Offering',
];

const pricingSplit = {
  supply: ['Metered execution', 'License', 'Rev share', 'Lease', 'Settlement-based compensation'],
  demand: ['Per outcome', 'Managed SLA', 'Gainshare', 'Hybrid base fee + outcome kicker'],
};

const trustSplit = {
  supply: ['Verifiable execution', 'Bounded autonomy', 'Programmable policy', 'Signed receipts', 'Sovereign deployment'],
  demand: ['Governed outcomes', 'Approval controls', 'Audit trails', 'Measurable service delivery', 'Policy-backed automation'],
};

export default function Docs() {
  return (
    <div className="bg-black text-white min-h-screen font-sans pt-32 pb-20 flex">
      <div className="hidden lg:block w-72 border-r border-white/10 h-[calc(100vh-80px)] sticky top-20 overflow-y-auto px-6 py-8">
        <h3 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-4">Architecture</h3>
        <ul className="space-y-3 mb-8">
          <li><a href="#decision" className="text-sm text-white font-medium hover:text-blue-400">Core Decision</a></li>
          <li><a href="#rule" className="text-sm text-gray-400 hover:text-white">Rule of Abstraction</a></li>
          <li><a href="#where" className="text-sm text-gray-400 hover:text-white">What Lives Where</a></li>
          <li><a href="#promotion" className="text-sm text-gray-400 hover:text-white">Promotion Path</a></li>
        </ul>

        <h3 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-4">Commercials</h3>
        <ul className="space-y-3 mb-8">
          <li><a href="#pricing" className="text-sm text-gray-400 hover:text-white">Pricing Split</a></li>
          <li><a href="#trust" className="text-sm text-gray-400 hover:text-white">Trust Language</a></li>
        </ul>

        <h3 className="text-xs font-bold text-gray-500 uppercase tracking-widest mb-4">Related</h3>
        <ul className="space-y-3">
          <li><Link to="/templates" className="text-sm text-blue-400 hover:text-blue-300">Service Catalog</Link></li>
          <li><a href="https://aiagent.xyz" className="text-sm text-emerald-400 hover:text-emerald-300">Browse aiagent.xyz</a></li>
        </ul>
      </div>

      <div className="flex-1 max-w-5xl px-6 py-8 lg:px-16">
        <h1 className="text-4xl md:text-5xl font-display font-bold tracking-tighter text-white mb-6">
          Brand Architecture
        </h1>
        <p className="text-xl text-gray-400 font-light leading-relaxed mb-12 max-w-3xl">
          Keep the hierarchy, but define it by abstraction level, not size. Components and
          composables live on aiagent.xyz. Outcomes and contracts live on sas.xyz.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-6 mb-16">
          <GuideCard
            icon={<Boxes className="w-6 h-6 text-blue-400" />}
            title="Core Decision"
            body="aiagent.xyz is the substrate marketplace. sas.xyz is the productized service layer built on top."
          />
          <GuideCard
            icon={<BriefcaseBusiness className="w-6 h-6 text-emerald-400" />}
            title="Rule of Abstraction"
            body="If the buyer chooses how it works, it belongs closer to aiagent.xyz. If they choose the result, it belongs closer to sas.xyz."
          />
          <GuideCard
            icon={<TrendingUp className="w-6 h-6 text-amber-400" />}
            title="Promotion Ladder"
            body="Listings can mature from agent to enterprise service without breaking the architecture."
          />
          <GuideCard
            icon={<CircleDollarSign className="w-6 h-6 text-purple-400" />}
            title="Pricing Split"
            body="Supply-side metering belongs on aiagent.xyz. Outcome contracts and SLA pricing belong on sas.xyz."
          />
        </div>

        <section id="decision" className="mb-16">
          <h2 className="text-2xl font-bold text-white mb-4">Core Decision</h2>
          <p className="text-gray-400 leading-relaxed mb-6 max-w-3xl">
            The durable split is not “small agents on aiagent.xyz, big services on sas.xyz.”
            The durable split is “composable autonomous supply on aiagent.xyz, outcome-based
            service delivery on sas.xyz.”
          </p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <SplitCard
              title="aiagent.xyz"
              subtitle="Supply side"
              description="Discover, publish, compose, license, and run agents, workflows, swarms, operator packs, service modules, and embodied runtimes."
            />
            <SplitCard
              title="sas.xyz"
              subtitle="Demand side"
              description="Buy, deploy, govern, and measure finished services with SLAs, pricing by result, policy controls, evidence, and escalation paths."
            />
          </div>
        </section>

        <section id="rule" className="mb-16">
          <h2 className="text-2xl font-bold text-white mb-4">Rule of Abstraction</h2>
          <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-8">
            <p className="text-lg text-gray-300 leading-relaxed">
              If the buyer is choosing <span className="text-white font-semibold">how it works</span>,
              it belongs closer to <span className="text-white font-semibold">aiagent.xyz</span>.
              If the buyer is choosing <span className="text-white font-semibold">what result they want</span>,
              it belongs closer to <span className="text-white font-semibold">sas.xyz</span>.
            </p>
          </div>
        </section>

        <section id="where" className="mb-16">
          <h2 className="text-2xl font-bold text-white mb-4">What Lives Where</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <ListCard
              title="aiagent.xyz listings"
              items={[
                'Customer Support Resolver Agent',
                'Browser QA Swarm',
                'Compliance Review Workflow',
                'Vehicle Prep Robotics Runtime',
                'Claims Triage Operator',
                'KYC Document Extraction Pipeline',
              ]}
            />
            <ListCard
              title="sas.xyz offerings"
              items={[
                'Customer Support Resolution as a Service',
                'Compliance Screening as a Service',
                'AI SDR Outreach Ops',
                'Autonomous Logistics Coordination',
                'Policy Review & Escalation Service',
                'Claims Intake and Resolution Service',
              ]}
            />
          </div>
        </section>

        <section id="promotion" className="mb-16">
          <h2 className="text-2xl font-bold text-white mb-4">Promotion Path</h2>
          <p className="text-gray-400 leading-relaxed mb-6 max-w-3xl">
            Strong objects on aiagent.xyz should be promotable into sas.xyz once they meet
            governance, reporting, and commercial thresholds.
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {promotionStages.map((stage, index) => (
              <div key={stage} className="bg-[#0a0a0a] border border-white/10 rounded-xl p-5">
                <p className="text-xs text-gray-500 uppercase tracking-widest mb-2">Stage {index + 1}</p>
                <p className="text-white font-semibold">{stage}</p>
              </div>
            ))}
          </div>
        </section>

        <section id="pricing" className="mb-16">
          <h2 className="text-2xl font-bold text-white mb-4">Pricing Split</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <BulletCard title="aiagent.xyz pricing" items={pricingSplit.supply} />
            <BulletCard title="sas.xyz pricing" items={pricingSplit.demand} />
          </div>
        </section>

        <section id="trust" className="mb-12">
          <h2 className="text-2xl font-bold text-white mb-4">Trust Language</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <BulletCard title="Supply-side trust" items={trustSplit.supply} />
            <BulletCard title="Outcome-side trust" items={trustSplit.demand} />
          </div>
        </section>

        <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-8 flex flex-col md:flex-row md:items-center md:justify-between gap-6">
          <div>
            <h3 className="text-xl font-bold text-white mb-2">Standard internal sentence</h3>
            <p className="text-gray-400 max-w-2xl">
              aiagent.xyz is where autonomous capabilities are packaged and traded. sas.xyz is
              where those capabilities are assembled into outcome-based services.
            </p>
          </div>
          <Link to="/templates" className="inline-flex items-center text-sm font-medium text-white hover:text-blue-300 transition-colors">
            Explore the service catalog <ArrowRight className="w-4 h-4 ml-2" />
          </Link>
        </div>
      </div>
    </div>
  );
}

function GuideCard({ icon, title, body }: { icon: React.ReactNode; title: string; body: string }) {
  return (
    <div className="bg-[#0a0a0a] border border-white/10 rounded-xl p-6">
      <div className="mb-4">{icon}</div>
      <h3 className="text-lg font-bold text-white mb-2">{title}</h3>
      <p className="text-sm text-gray-400 leading-relaxed">{body}</p>
    </div>
  );
}

function SplitCard({ title, subtitle, description }: { title: string; subtitle: string; description: string }) {
  return (
    <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-8">
      <p className="text-xs uppercase tracking-widest text-gray-500 mb-3">{subtitle}</p>
      <h3 className="text-2xl font-bold text-white mb-4">{title}</h3>
      <p className="text-gray-400 leading-relaxed">{description}</p>
    </div>
  );
}

function ListCard({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-8">
      <h3 className="text-lg font-bold text-white mb-4">{title}</h3>
      <div className="space-y-3">
        {items.map((item) => (
          <div key={item} className="text-sm text-gray-300 border border-white/5 rounded-lg px-4 py-3 bg-black/40">
            {item}
          </div>
        ))}
      </div>
    </div>
  );
}

function BulletCard({ title, items }: { title: string; items: string[] }) {
  return (
    <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-8">
      <div className="flex items-center gap-3 mb-5">
        <Shield className="w-5 h-5 text-white" />
        <h3 className="text-lg font-bold text-white">{title}</h3>
      </div>
      <div className="space-y-3">
        {items.map((item) => (
          <div key={item} className="text-sm text-gray-300 border border-white/5 rounded-lg px-4 py-3 bg-black/40">
            {item}
          </div>
        ))}
      </div>
    </div>
  );
}
