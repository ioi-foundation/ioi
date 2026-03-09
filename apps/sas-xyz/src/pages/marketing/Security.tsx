import { Shield, Key, Box, CheckCircle2 } from 'lucide-react';

export default function Security() {
  return (
    <div className="bg-black text-white min-h-screen font-sans pt-32 pb-20">
      <div className="max-w-7xl mx-auto px-6">
        
        {/* Header */}
        <div className="mb-24 text-center max-w-3xl mx-auto">
          <h1 className="text-4xl md:text-6xl font-display font-bold tracking-tighter text-white mb-6">
            The Sovereign Wall
          </h1>
          <p className="text-xl text-gray-400 font-light leading-relaxed">
            Enterprise-grade security built for the post-quantum era. Protect your intellectual property, enforce strict boundaries, and guarantee mutual blindness.
          </p>
        </div>

        {/* Mutual Blindness */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center mb-32">
          <div className="space-y-6">
            <div className="w-12 h-12 rounded-full bg-white/5 border border-white/10 flex items-center justify-center mb-6">
              <Box className="w-6 h-6 text-white" />
            </div>
            <h2 className="text-3xl md:text-5xl font-display font-bold tracking-tight text-white mb-4">
              Mutual Blindness
            </h2>
            <p className="text-lg text-gray-400 leading-relaxed">
              In traditional cloud environments, the provider can see your code, and you can see the user's data. IOI introduces Mutual Blindness via Hardware Trusted Execution Environments (TEEs).
            </p>
            <ul className="space-y-4 pt-4">
              <li className="flex items-start">
                <CheckCircle2 className="w-5 h-5 text-emerald-500 mr-3 shrink-0" />
                <span className="text-gray-300">The Provider cannot access your proprietary model weights.</span>
              </li>
              <li className="flex items-start">
                <CheckCircle2 className="w-5 h-5 text-emerald-500 mr-3 shrink-0" />
                <span className="text-gray-300">The User's prompt data is encrypted in memory.</span>
              </li>
              <li className="flex items-start">
                <CheckCircle2 className="w-5 h-5 text-emerald-500 mr-3 shrink-0" />
                <span className="text-gray-300">Cryptographic attestation proves the enclave is secure.</span>
              </li>
            </ul>
          </div>
          <div className="bg-[#0a0a0a] border border-white/10 rounded-2xl p-8 shadow-2xl">
            {/* Diagram placeholder */}
            <div className="h-64 w-full border border-white/5 rounded-xl bg-[#111] flex items-center justify-center relative overflow-hidden">
              <div className="absolute inset-0 bg-[url('data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjAiIGhlaWdodD0iMjAiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+PGNpcmNsZSBjeD0iMSIgY3k9IjEiIHI9IjEiIGZpbGw9InJnYmEoMjU1LCAyNTUsIDI1NSwgMC4wNSkiLz48L3N2Zz4=')] opacity-50"></div>
              <div className="z-10 text-center">
                <Shield className="w-12 h-12 text-blue-500 mx-auto mb-4" />
                <p className="font-mono text-sm text-gray-400">AWS Nitro Enclave</p>
                <p className="text-xs text-emerald-500 mt-2">Attestation Verified</p>
              </div>
            </div>
          </div>
        </div>

        {/* Post-Quantum Identity */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-16 items-center mb-32">
          <div className="order-2 lg:order-1 bg-[#0a0a0a] border border-white/10 rounded-2xl p-8 shadow-2xl">
            <div className="space-y-4 font-mono text-sm">
              <div className="bg-black border border-white/10 p-4 rounded-lg">
                <p className="text-gray-500 mb-1">// Legacy ECDSA (Vulnerable)</p>
                <p className="text-red-400 line-through">0x71C...49b</p>
              </div>
              <div className="bg-blue-500/10 border border-blue-500/20 p-4 rounded-lg">
                <p className="text-blue-400 mb-1">// ML-DSA-44 (Quantum Resistant)</p>
                <p className="text-white break-all">did:ioi:z6MkhaXgBZDvotDkL5257faiztiCEsJNDsVKv46L</p>
              </div>
            </div>
          </div>
          <div className="order-1 lg:order-2 space-y-6">
            <div className="w-12 h-12 rounded-full bg-white/5 border border-white/10 flex items-center justify-center mb-6">
              <Key className="w-6 h-6 text-white" />
            </div>
            <h2 className="text-3xl md:text-5xl font-display font-bold tracking-tight text-white mb-4">
              Post-Quantum Identity
            </h2>
            <p className="text-lg text-gray-400 leading-relaxed">
              ECDSA is a ticking time bomb. sas.xyz integrates natively with <span className="text-white font-mono text-sm">wallet.network</span> to provide ML-DSA-44 post-quantum signatures for every deployment, policy update, and execution receipt.
            </p>
          </div>
        </div>

      </div>
    </div>
  );
}
