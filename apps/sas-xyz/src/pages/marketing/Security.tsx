import { Box, CheckCircle2, Key, Shield } from 'lucide-react';

export default function Security() {
  return (
    <div className="bg-black text-white min-h-screen font-sans pt-32 pb-20">
      <div className="max-w-7xl mx-auto px-6">
        <div className="mb-24 text-center max-w-3xl mx-auto">
          <h1 className="text-4xl md:text-6xl font-display font-bold tracking-tighter text-white mb-6">
            The Trust Plane
          </h1>
          <p className="text-xl text-gray-400 font-light leading-relaxed">
            Governed outcomes need more than clever automation. SAS.xyz layers approvals, audit
            trails, confidential execution, and signed receipts around every managed service lane.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center mb-32">
          <div className="space-y-6">
            <div className="w-12 h-12 rounded-full bg-white/5 border border-white/10 flex items-center justify-center mb-6">
              <Box className="w-6 h-6 text-white" />
            </div>
            <h2 className="text-3xl md:text-5xl font-display font-bold tracking-tight text-white mb-4">
              Policy-backed execution
            </h2>
            <p className="text-lg text-gray-400 leading-relaxed">
              Confidential execution and programmable controls keep the service lane bounded even
              when the underlying autonomous components are dynamic.
            </p>
            <ul className="space-y-4 pt-4">
              <li className="flex items-start">
                <CheckCircle2 className="w-5 h-5 text-emerald-500 mr-3 shrink-0" />
                <span className="text-gray-300">Sensitive actions can require approvals before a service completes.</span>
              </li>
              <li className="flex items-start">
                <CheckCircle2 className="w-5 h-5 text-emerald-500 mr-3 shrink-0" />
                <span className="text-gray-300">Every step emits receipts, audit trails, and measurable delivery evidence.</span>
              </li>
              <li className="flex items-start">
                <CheckCircle2 className="w-5 h-5 text-emerald-500 mr-3 shrink-0" />
                <span className="text-gray-300">Private deployments can keep buyer data inside controlled environments.</span>
              </li>
            </ul>
          </div>
          <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-8 shadow-2xl">
            <div className="h-64 w-full border border-white/5 rounded-xl bg-[#111] flex items-center justify-center relative overflow-hidden">
              <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGNpcmNsZSBjeD0iMSIgY3k9IjEiIHI9IjEiIGZpbGw9InJnYmEoMjU1LCAyNTUsIDI1NSwgMC4wNSkiLz48L3N2Zz4=')] opacity-50"></div>
              <div className="z-10 text-center">
                <Shield className="w-12 h-12 text-blue-500 mx-auto mb-4" />
                <p className="font-mono text-sm text-gray-400">Governed Service Lane</p>
                <p className="text-xs text-emerald-500 mt-2">Attested • Auditable • Policy-bound</p>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center mb-32">
          <div className="order-2 lg:order-1 bg-[#0a0a0a] border border-white/10 rounded-2xl p-8 shadow-2xl">
            <div className="space-y-4 font-mono text-sm">
              <div className="bg-black border border-white/10 p-4 rounded-lg">
                <p className="text-gray-500 mb-1">// Approval event</p>
                <p className="text-white">approve(exception.claims.review)</p>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/20 p-4 rounded-lg">
                <p className="text-blue-400 mb-1">// Signed receipt</p>
                <p className="text-white break-all">did:ioi:receipt:z6MkhaXgBZDvotDkL5257faiztiCEsJNDsVKv46L</p>
              </div>
            </div>
          </div>
          <div className="order-1 lg:order-2 space-y-6">
            <div className="w-12 h-12 rounded-full bg-white/5 border border-white/10 flex items-center justify-center mb-6">
              <Key className="w-6 h-6 text-white" />
            </div>
            <h2 className="text-3xl md:text-5xl font-display font-bold tracking-tight text-white mb-4">
              Post-quantum audit chain
            </h2>
            <p className="text-lg text-gray-400 leading-relaxed">
              Every approval, deployment, policy update, and evidence export can be signed and
              traced. SAS.xyz inherits IOI’s verifiable substrate but frames it for buyers as
              governed outcomes, not just secure compute.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
