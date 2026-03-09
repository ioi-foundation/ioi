import { Link, useNavigate } from 'react-router-dom';
import { motion } from 'motion/react';
import { Github, Wallet, ArrowRight } from 'lucide-react';
import Logo from '../../components/Logo';

export default function Login() {
  const navigate = useNavigate();

  const handleLogin = () => {
    // For demo purposes, redirect directly to the app dashboard
    navigate('/app');
  };

  return (
    <div 
      className="min-h-screen bg-black flex flex-col items-center justify-center p-4 relative overflow-hidden font-sans cursor-pointer"
      onClick={() => navigate('/')}
    >
      {/* Background Effects */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-blue-500/5 rounded-full blur-[120px] pointer-events-none"></div>

      <motion.div 
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="w-full max-w-md bg-[#0a0a0a] border border-white/10 rounded-2xl p-8 shadow-2xl relative z-10 cursor-default"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex flex-col items-center mb-8">
          <Link to="/" className="flex items-center space-x-2 mb-6">
            <Logo className="w-8 h-8" />
            <span className="font-bold tracking-tighter text-2xl text-white">sas.xyz</span>
          </Link>
          <h1 className="text-2xl font-bold text-white mb-2">Welcome back</h1>
          <p className="text-gray-400 text-sm text-center">
            Sign in to manage your agents, view telemetry, and claim bounties.
          </p>
        </div>

        <div className="space-y-4">
          {/* Web2 Auth */}
          <button 
            onClick={handleLogin}
            className="w-full flex items-center justify-center space-x-3 bg-white text-black py-3 px-4 rounded-xl font-bold hover:bg-gray-200 transition-colors"
          >
            <Github className="w-5 h-5" />
            <span>Continue with GitHub</span>
          </button>
          
          <button 
            onClick={handleLogin}
            className="w-full flex items-center justify-center space-x-3 bg-[#111] border border-white/10 text-white py-3 px-4 rounded-xl font-bold hover:bg-white/5 transition-colors"
          >
            <svg className="w-5 h-5" viewBox="0 0 24 24">
              <path fill="currentColor" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
              <path fill="currentColor" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
              <path fill="currentColor" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
              <path fill="currentColor" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
            </svg>
            <span>Continue with Google</span>
          </button>

          <div className="relative py-4">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-white/10"></div>
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="px-2 bg-[#0a0a0a] text-gray-500 font-mono">OR</span>
            </div>
          </div>

          {/* Web3 Auth */}
          <button 
            onClick={handleLogin}
            className="w-full flex items-center justify-between bg-blue-500/10 border border-blue-500/30 text-blue-400 py-3 px-4 rounded-xl font-bold hover:bg-blue-500/20 transition-colors group"
          >
            <div className="flex items-center space-x-3">
              <Wallet className="w-5 h-5" />
              <span>Connect wallet.network</span>
            </div>
            <ArrowRight className="w-4 h-4 opacity-0 group-hover:opacity-100 group-hover:translate-x-1 transition-all" />
          </button>
        </div>

        <p className="text-center text-xs text-gray-500 mt-8">
          By continuing, you agree to our <a href="#" className="text-gray-400 hover:text-white underline">Terms of Service</a> and <a href="#" className="text-gray-400 hover:text-white underline">Privacy Policy</a>.
        </p>
      </motion.div>
    </div>
  );
}
