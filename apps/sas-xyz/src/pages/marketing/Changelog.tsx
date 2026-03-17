import { Calendar, GitCommit, Zap } from 'lucide-react';

export default function Changelog() {
  return (
    <div className="bg-black text-white min-h-screen font-sans pt-32 pb-20">
      <div className="max-w-3xl mx-auto px-6">
        
        {/* Header */}
        <div className="mb-24 text-center">
          <h1 className="text-4xl md:text-6xl font-display font-bold tracking-tighter text-white mb-6">
            The Pulse
          </h1>
          <p className="text-xl text-gray-400 font-light leading-relaxed">
            Weekly updates on new Kernel versions, MCP tool integrations, and Mainnet milestones.
          </p>
        </div>

        {/* Timeline */}
        <div className="space-y-16 relative before:absolute before:inset-0 before:ml-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-white/10 before:to-transparent">
          
          {/* Entry 1 */}
          <div className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
            <div className="flex items-center justify-center w-10 h-10 rounded-full border border-white/20 bg-black text-blue-400 shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2">
              <Zap className="w-4 h-4" />
            </div>
            <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] bg-[#0a0a0a] border border-white/10 p-6 rounded-2xl shadow-xl">
              <div className="flex items-center justify-between mb-4">
                <span className="text-xs font-bold text-blue-400 uppercase tracking-widest">Mainnet Launch</span>
                <span className="text-xs text-gray-500 font-mono flex items-center"><Calendar className="w-3 h-3 mr-1"/> Oct 24, 2026</span>
              </div>
              <h3 className="text-xl font-bold text-white mb-2">sas.xyz Control Plane v1.0 is Live</h3>
              <p className="text-gray-400 text-sm leading-relaxed">
                The Provider Control Plane is officially generally available. Deploy your first agent using the IOI-SDK and start collecting royalties.
              </p>
            </div>
          </div>

          {/* Entry 2 */}
          <div className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group">
            <div className="flex items-center justify-center w-10 h-10 rounded-full border border-white/20 bg-black text-emerald-400 shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2">
              <GitCommit className="w-4 h-4" />
            </div>
            <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] bg-[#0a0a0a] border border-white/10 p-6 rounded-2xl shadow-xl">
              <div className="flex items-center justify-between mb-4">
                <span className="text-xs font-bold text-emerald-400 uppercase tracking-widest">Kernel Update</span>
                <span className="text-xs text-gray-500 font-mono flex items-center"><Calendar className="w-3 h-3 mr-1"/> Oct 15, 2026</span>
              </div>
              <h3 className="text-xl font-bold text-white mb-2">Aft Fault Tolerance v2</h3>
              <p className="text-gray-400 text-sm leading-relaxed">
                Improved hardware attestation speeds by 40%. Agents now boot significantly faster in AWS Nitro enclaves.
              </p>
            </div>
          </div>

          {/* Entry 3 */}
          <div className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group">
            <div className="flex items-center justify-center w-10 h-10 rounded-full border border-white/20 bg-black text-amber-400 shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2">
              <GitCommit className="w-4 h-4" />
            </div>
            <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] bg-[#0a0a0a] border border-white/10 p-6 rounded-2xl shadow-xl">
              <div className="flex items-center justify-between mb-4">
                <span className="text-xs font-bold text-amber-400 uppercase tracking-widest">MCP Integration</span>
                <span className="text-xs text-gray-500 font-mono flex items-center"><Calendar className="w-3 h-3 mr-1"/> Oct 02, 2026</span>
              </div>
              <h3 className="text-xl font-bold text-white mb-2">Stripe & GitHub Drivers</h3>
              <p className="text-gray-400 text-sm leading-relaxed">
                Added official MCP drivers for Stripe and GitHub. You can now build agents that manage subscriptions and review pull requests securely.
              </p>
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
