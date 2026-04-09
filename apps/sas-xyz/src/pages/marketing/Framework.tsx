import { motion, useScroll, useTransform } from 'motion/react';
import { useRef } from 'react';
import { Boxes, BriefcaseBusiness, Cpu, ShieldCheck } from 'lucide-react';

export default function Framework() {
  const containerRef = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ['start end', 'end start'],
  });

  const y1 = useTransform(scrollYProgress, [0, 1], [0, -100]);
  const y2 = useTransform(scrollYProgress, [0, 1], [0, -200]);
  const y3 = useTransform(scrollYProgress, [0, 1], [0, -300]);
  const y4 = useTransform(scrollYProgress, [0, 1], [0, -400]);

  return (
    <div className="pt-24 pb-32">
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-24">
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-5xl md:text-7xl font-bold text-white mb-6 tracking-tight"
          >
            The Service <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-accent to-emerald-accent">Delivery Stack</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="text-xl text-gray-400 max-w-3xl mx-auto"
          >
            Buyers purchase results on sas.xyz, but those results are assembled from verified
            components, governed workflows, and sovereign execution underneath.
          </motion.p>
        </div>

        <div ref={containerRef} className="relative h-[800px] flex justify-center items-center">
          <div className="absolute inset-0 flex flex-col items-center justify-center space-y-8">
            <motion.div
              style={{ y: y4 }}
              className="w-full max-w-2xl bg-surface border border-border rounded-2xl p-8 relative overflow-hidden shadow-2xl z-40"
            >
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-purple-500 to-pink-500"></div>
              <div className="flex items-center space-x-4 mb-4">
                <BriefcaseBusiness className="w-8 h-8 text-purple-400" />
                <h3 className="text-2xl font-bold text-white">4. Outcome Contract</h3>
              </div>
              <p className="text-gray-400">
                The buyer-facing layer. Defines the business result, SLA, reporting, escalation
                path, deployment model, and commercial terms.
              </p>
            </motion.div>

            <motion.div
              style={{ y: y3 }}
              className="w-full max-w-2xl bg-surface border border-border rounded-2xl p-8 relative overflow-hidden shadow-2xl z-30"
            >
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyan-accent to-blue-500"></div>
              <div className="flex items-center space-x-4 mb-4">
                <ShieldCheck className="w-8 h-8 text-cyan-accent" />
                <h3 className="text-2xl font-bold text-white">3. Governed Workflow</h3>
              </div>
              <p className="text-gray-400">
                The orchestration layer for approvals, exception handling, evidence exports,
                liability boundaries, and measurable service delivery.
              </p>
            </motion.div>

            <motion.div
              style={{ y: y2 }}
              className="w-full max-w-2xl bg-surface border border-border rounded-2xl p-8 relative overflow-hidden shadow-2xl z-20"
            >
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-emerald-accent to-green-500"></div>
              <div className="flex items-center space-x-4 mb-4">
                <Boxes className="w-8 h-8 text-emerald-accent" />
                <h3 className="text-2xl font-bold text-white">2. Verified Supply from aiagent.xyz</h3>
              </div>
              <p className="text-gray-400">
                Agents, workflows, swarms, operator packs, service modules, and embodied runtimes
                are discovered, licensed, and promoted from the lower marketplace layer.
              </p>
            </motion.div>

            <motion.div
              style={{ y: y1 }}
              className="w-full max-w-2xl bg-[#050505] border border-gray-800 rounded-2xl p-8 relative overflow-hidden shadow-2xl z-10"
            >
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-amber-accent to-orange-500"></div>
              <div className="flex items-center space-x-4 mb-4">
                <Cpu className="w-8 h-8 text-amber-accent" />
                <h3 className="text-2xl font-bold text-white">1. Sovereign Execution</h3>
              </div>
              <p className="text-gray-400">
                The IOI substrate provides confidential execution, programmable policy, signed
                receipts, and attested compute as the root of trust for the whole stack.
              </p>
            </motion.div>
          </div>
        </div>
      </div>
    </div>
  );
}
