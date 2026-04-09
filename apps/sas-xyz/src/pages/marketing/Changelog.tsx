import { Calendar, GitCommit, Zap } from 'lucide-react';

export default function Changelog() {
  return (
    <div className="bg-black text-white min-h-screen font-sans pt-32 pb-20">
      <div className="max-w-3xl mx-auto px-6">
        <div className="mb-24 text-center">
          <h1 className="text-4xl md:text-6xl font-display font-bold tracking-tighter text-white mb-6">
            The Pulse
          </h1>
          <p className="text-xl text-gray-400 font-light leading-relaxed">
            Weekly updates on new service lanes, governance primitives, and promotions from
            verified supply on aiagent.xyz into finished offerings on sas.xyz.
          </p>
        </div>

        <div className="space-y-16 relative before:absolute before:inset-0 before:ml-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-white/10 before:to-transparent">
          <TimelineEntry
            tone="text-blue-400"
            label="Catalog Update"
            date="Apr 08, 2026"
            title="Claims Intake and Resolution Service launched"
            body="A new governed outcome offering is live with private deployment, approval controls, and hybrid pricing for carrier teams."
            icon={<Zap className="w-4 h-4" />}
          />
          <TimelineEntry
            tone="text-emerald-400"
            label="Promotion Path"
            date="Apr 03, 2026"
            title="Service modules can now graduate into sas.xyz"
            body="Verified service modules on aiagent.xyz can be promoted into enterprise catalog entries once they pass SLA, governance, and reporting thresholds."
            icon={<GitCommit className="w-4 h-4" />}
          />
          <TimelineEntry
            tone="text-amber-400"
            label="Trust Update"
            date="Mar 27, 2026"
            title="Approval bundles and audit exports added"
            body="Buyer-facing evidence packs now include approvals, exception histories, and signed delivery receipts for every managed lane."
            icon={<GitCommit className="w-4 h-4" />}
          />
        </div>
      </div>
    </div>
  );
}

function TimelineEntry({
  tone,
  label,
  date,
  title,
  body,
  icon,
}: {
  tone: string;
  label: string;
  date: string;
  title: string;
  body: string;
  icon: React.ReactNode;
}) {
  return (
    <div className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group">
      <div className={`flex items-center justify-center w-10 h-10 rounded-full border border-white/20 bg-black ${tone} shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2`}>
        {icon}
      </div>
      <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] bg-[#0a0a0a] border border-white/10 p-6 rounded-2xl shadow-xl">
        <div className="flex items-center justify-between mb-4">
          <span className={`text-xs font-bold uppercase tracking-widest ${tone}`}>{label}</span>
          <span className="text-xs text-gray-500 font-mono flex items-center"><Calendar className="w-3 h-3 mr-1" /> {date}</span>
        </div>
        <h3 className="text-xl font-bold text-white mb-2">{title}</h3>
        <p className="text-gray-400 text-sm leading-relaxed">{body}</p>
      </div>
    </div>
  );
}
