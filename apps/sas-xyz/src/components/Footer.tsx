import { Shield } from 'lucide-react';
import Logo from './Logo';

export default function Footer() {
  return (
    <footer className="border-t border-white/10 bg-black py-12">
      <div className="max-w-7xl mx-auto px-6 flex flex-col md:flex-row justify-between items-center">
        <div className="flex items-center space-x-4 mb-6 md:mb-0">
          <div className="flex items-center space-x-2">
            <Logo className="w-5 h-5" />
            <span className="font-display font-bold tracking-tighter text-lg text-white">sas.xyz</span>
          </div>
          <div className="hidden md:block w-px h-4 bg-white/20"></div>
          <div className="flex items-center space-x-1.5 text-xs text-gray-400 font-mono bg-white/5 border border-white/10 px-2 py-1 rounded">
            <Shield className="w-3 h-3 text-emerald-500" />
            <span>Security: ML-DSA-44 Certified</span>
          </div>
        </div>
        <div className="text-sm text-gray-500">
          © {new Date().getFullYear()} IOI Network. All rights reserved.
        </div>
      </div>
    </footer>
  );
}
