import { motion, useScroll, useTransform } from 'motion/react';
import { useRef } from 'react';
import { ShieldCheck, Cpu, Database, TerminalSquare } from 'lucide-react';

export default function Framework() {
  const containerRef = useRef<HTMLDivElement>(null);
  const { scrollYProgress } = useScroll({
    target: containerRef,
    offset: ["start end", "end start"]
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
            The IOI <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-accent to-emerald-accent">Kernel</span>
          </motion.h1>
          
          <motion.p 
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="text-xl text-gray-400 max-w-3xl mx-auto"
          >
            A deterministic execution environment for probabilistic models.
            We turn fuzzy LLM outputs into hard, verifiable actions.
          </motion.p>
        </div>

        <div ref={containerRef} className="relative h-[800px] flex justify-center items-center">
          {/* Stack Layers */}
          <div className="absolute inset-0 flex flex-col items-center justify-center space-y-8">
            
            {/* Layer 4: Agent Logic */}
            <motion.div 
              style={{ y: y4 }}
              className="w-full max-w-2xl bg-surface border border-border rounded-2xl p-8 relative overflow-hidden shadow-2xl z-40"
            >
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-purple-500 to-pink-500"></div>
              <div className="flex items-center space-x-4 mb-4">
                <TerminalSquare className="w-8 h-8 text-purple-400" />
                <h3 className="text-2xl font-bold text-white">4. Agent Logic (WASM)</h3>
              </div>
              <p className="text-gray-400">
                The developer's code. Written in Rust, TS, or Python, compiled to WebAssembly. 
                This layer contains the prompt chains, memory management, and tool definitions.
              </p>
            </motion.div>

            {/* Layer 3: Agency Firewall */}
            <motion.div 
              style={{ y: y3 }}
              className="w-full max-w-2xl bg-surface border border-border rounded-2xl p-8 relative overflow-hidden shadow-2xl z-30"
            >
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-cyan-accent to-blue-500"></div>
              <div className="flex items-center space-x-4 mb-4">
                <ShieldCheck className="w-8 h-8 text-cyan-accent" />
                <h3 className="text-2xl font-bold text-white">3. Agency Firewall</h3>
              </div>
              <p className="text-gray-400">
                The determinism boundary. Intercepts all outgoing RPC calls and API requests from the agent, 
                evaluating them against the strict `policy.json` defined by the developer.
              </p>
            </motion.div>

            {/* Layer 2: MicroVM */}
            <motion.div 
              style={{ y: y2 }}
              className="w-full max-w-2xl bg-surface border border-border rounded-2xl p-8 relative overflow-hidden shadow-2xl z-20"
            >
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-emerald-accent to-green-500"></div>
              <div className="flex items-center space-x-4 mb-4">
                <Database className="w-8 h-8 text-emerald-accent" />
                <h3 className="text-2xl font-bold text-white">2. IOI MicroVM</h3>
              </div>
              <p className="text-gray-400">
                A lightweight, isolated virtual machine (Firecracker) that boots in milliseconds. 
                Provides a pristine, ephemeral environment for every single agent invocation.
              </p>
            </motion.div>

            {/* Layer 1: Hardware Enclave */}
            <motion.div 
              style={{ y: y1 }}
              className="w-full max-w-2xl bg-[#050505] border border-gray-800 rounded-2xl p-8 relative overflow-hidden shadow-2xl z-10"
            >
              <div className="absolute top-0 left-0 w-full h-1 bg-gradient-to-r from-amber-accent to-orange-500"></div>
              <div className="flex items-center space-x-4 mb-4">
                <Cpu className="w-8 h-8 text-amber-accent" />
                <h3 className="text-2xl font-bold text-white">1. Hardware Enclave (TEE)</h3>
              </div>
              <p className="text-gray-400">
                The physical root of trust. AWS Nitro Enclaves or Google Cloud Confidential Space. 
                Ensures that not even the host provider can inspect or tamper with the agent's memory.
              </p>
            </motion.div>

          </div>
        </div>

      </div>
    </div>
  );
}
