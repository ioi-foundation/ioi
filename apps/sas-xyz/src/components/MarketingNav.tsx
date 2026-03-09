import { Link, useNavigate } from 'react-router-dom';
import { ChevronDown, ArrowRight, Activity } from 'lucide-react';
import Logo from './Logo';

export default function MarketingNav() {
  const navigate = useNavigate();

  return (
    <nav className="fixed top-0 left-0 w-full z-50 border-b border-white/10 bg-black/60 backdrop-blur-md">
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        
        {/* Left: Logo & Status */}
        <div className="flex items-center space-x-6">
          <Link to="/" className="flex items-center space-x-2">
            <Logo className="w-6 h-6" />
            <span className="font-mono font-bold tracking-wider text-lg text-white">sas.xyz</span>
          </Link>
          
          <div className="hidden lg:flex items-center space-x-2 bg-white/5 border border-white/10 rounded-full px-3 py-1">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span className="text-[10px] font-mono text-gray-400 uppercase tracking-widest">Mainnet: Active | 1,402 Nodes Online</span>
          </div>
        </div>

        {/* Center: Navigation Links */}
        <div className="hidden md:flex items-center space-x-6 text-sm font-medium text-gray-400">
          <Link to="/templates" className="hover:text-white transition-colors">Templates</Link>
          <Link to="/docs" className="hover:text-white transition-colors">Docs</Link>
          <Link to="/economics" className="hover:text-white transition-colors">Economics</Link>
          <Link to="/security" className="hover:text-white transition-colors">Security</Link>
          <Link to="/solutions" className="hover:text-white transition-colors">Solutions</Link>
          <Link to="/changelog" className="hover:text-white transition-colors">Changelog</Link>
        </div>

        {/* Right: CTAs */}
        <div className="flex items-center space-x-4">
          <a href="https://aiagent.xyz" target="_blank" rel="noreferrer" className="hidden sm:flex text-sm font-medium text-gray-400 hover:text-white transition-colors items-center">
            Go to aiagent.xyz <ArrowRight className="w-3 h-3 ml-1" />
          </a>
          <div className="hidden sm:block w-px h-5 bg-white/10 mx-2"></div>
          <button className="connect-button bg-white text-black px-4 py-2 rounded-full text-sm font-medium hover:bg-gray-200 transition-colors flex items-center" onClick={() => navigate('/login')}>
            Sign In
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 64 64"
              fill="none"
              width="24"
              height="24"
              style={{ marginLeft: '6px' }}
            >
              <path d="M 55.9 42.2 A 26 26 0 1 0 42.2 55.9" stroke="currentColor" strokeWidth="1.9" fill="none" />
              <circle cx="32" cy="26" r="7.7" stroke="currentColor" strokeWidth="2.1" fill="none" />
              <path d="M19.9 45.7A12.1 12.1 0 0 1 44.1 45.7" stroke="currentColor" strokeWidth="2.1" fill="none" />
              <path d="M49 41L51.5 46.5L57 49L51.5 51.5L49 57L46.5 51.5L41 49L46.5 46.5Z" fill="currentColor" />
            </svg>
          </button>
        </div>
        
      </div>
    </nav>
  );
}
