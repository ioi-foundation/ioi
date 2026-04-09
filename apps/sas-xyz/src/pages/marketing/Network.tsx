import { useEffect, useRef } from 'react';
import createGlobe from 'cobe';
import { motion } from 'motion/react';
import { Activity, Server, Zap } from 'lucide-react';

function Globe() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    let phi = 0;
    let width = 0;

    const onResize = () => canvasRef.current && (width = canvasRef.current.offsetWidth);
    window.addEventListener('resize', onResize);
    onResize();

    if (!canvasRef.current) return undefined;

    const globe = createGlobe(canvasRef.current, {
      devicePixelRatio: 2,
      width: width * 2,
      height: width * 2,
      phi: 0,
      theta: 0.3,
      dark: 1,
      diffuse: 1.2,
      mapSamples: 16000,
      mapBrightness: 6,
      baseColor: [0.05, 0.05, 0.1],
      markerColor: [0, 0.94, 1],
      glowColor: [0, 0.94, 1],
      markers: [
        { location: [37.7595, -122.4367], size: 0.05 },
        { location: [40.7128, -74.006], size: 0.05 },
        { location: [51.5074, -0.1278], size: 0.05 },
        { location: [35.6762, 139.6503], size: 0.05 },
        { location: [1.3521, 103.8198], size: 0.05 },
        { location: [-33.8688, 151.2093], size: 0.05 },
      ],
      onRender: (state) => {
        state.phi = phi;
        phi += 0.005;
        state.width = width * 2;
        state.height = width * 2;
      },
    });

    return () => {
      globe.destroy();
      window.removeEventListener('resize', onResize);
    };
  }, []);

  return (
    <div style={{ width: '100%', maxWidth: 600, aspectRatio: 1, margin: 'auto', position: 'relative' }}>
      <canvas
        ref={canvasRef}
        style={{ width: '100%', height: '100%', contain: 'layout paint size', opacity: 0, transition: 'opacity 1s ease' }}
        onRender={(event) => {
          (event.target as HTMLCanvasElement).style.opacity = '1';
        }}
      />
    </div>
  );
}

export default function Network() {
  return (
    <div className="pt-24 pb-16">
      <div className="max-w-7xl mx-auto px-6">
        <div className="text-center mb-16">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="inline-flex items-center space-x-2 bg-cyan-accent/10 border border-cyan-accent/20 text-cyan-accent px-4 py-1.5 rounded-full text-sm font-medium mb-6"
          >
            <span className="w-2 h-2 rounded-full bg-cyan-accent animate-pulse"></span>
            <span>IOI service delivery mesh is live</span>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="text-5xl md:text-7xl font-bold text-white mb-6 tracking-tight"
          >
            The Global <span className="text-transparent bg-clip-text bg-gradient-to-r from-cyan-accent to-emerald-accent">Delivery Mesh</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="text-xl text-gray-400 max-w-3xl mx-auto"
          >
            Outcome-based services route work across confidential execution zones and governed
            operators. Buyers see delivery posture, trust, and performance rather than worker topology.
          </motion.p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-12 items-center mb-24">
          <motion.div
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.3 }}
            className="space-y-8"
          >
            <NetworkCard
              icon={<Activity className="w-5 h-5 mr-2 text-cyan-accent" />}
              title="Active Service Lanes"
              value="186"
              detail="Across customer operations, compliance, finance, and revenue teams"
              glow="bg-cyan-accent/5"
              detailTone="text-emerald-accent"
            />
            <NetworkCard
              icon={<Server className="w-5 h-5 mr-2 text-emerald-accent" />}
              title="Confidential Delivery Zones"
              value="8,492"
              detail="Attested clean rooms across 42 regions"
              glow="bg-emerald-accent/5"
              detailTone="text-gray-400"
            />
            <NetworkCard
              icon={<Zap className="w-5 h-5 mr-2 text-amber-accent" />}
              title="Evidence Exports"
              value="1.2M / day"
              detail="Receipts, approvals, and audit bundles emitted to buyers and operators"
              glow="bg-amber-accent/5"
              detailTone="text-gray-400"
            />
          </motion.div>

          <motion.div
            initial={{ opacity: 0, scale: 0.9 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ delay: 0.4 }}
            className="relative"
          >
            <div className="absolute inset-0 bg-gradient-to-b from-transparent via-cyan-accent/5 to-transparent blur-3xl rounded-full"></div>
            <Globe />
          </motion.div>
        </div>
      </div>
    </div>
  );
}

function NetworkCard({
  icon,
  title,
  value,
  detail,
  glow,
  detailTone,
}: {
  icon: React.ReactNode;
  title: string;
  value: string;
  detail: string;
  glow: string;
  detailTone: string;
}) {
  return (
    <div className="bg-surface border border-border rounded-xl p-6 relative overflow-hidden">
      <div className={`absolute top-0 right-0 w-32 h-32 ${glow} rounded-full blur-3xl`}></div>
      <h3 className="text-lg font-bold text-white mb-2 flex items-center">
        {icon}
        {title}
      </h3>
      <p className="text-4xl font-mono font-bold text-white mb-1">{value}</p>
      <p className={`text-sm ${detailTone}`}>{detail}</p>
    </div>
  );
}
