// src/components/Footer.jsx
import React from 'react';
import { Link } from 'react-router-dom';

export default function Footer() {
  return (
    <footer className="bg-slate-900 border-t border-slate-800 text-slate-400 text-sm mt-auto">
      
      {/* Top Utility Bar */}
      <div className="border-b border-slate-800 bg-slate-950/50">
        <div className="container mx-auto px-4 py-2 flex flex-wrap justify-between items-center gap-4 text-xs font-mono">
          <div className="flex gap-6">
            <span className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-green-500 animate-pulse"></span>
              Network: Operational
            </span>
            <span>Gas: <span className="text-slate-200">12 Gwei</span></span>
            <span>Block: <span className="text-slate-200">#18,492,011</span></span>
          </div>
          <div className="flex gap-4">
            <a href="#" className="hover:text-white transition-colors">Brand Guide</a>
            {/* UPDATED LINK */}
            <Link to="/status" className="hover:text-white transition-colors">Status</Link>
            <a href="#" className="hover:text-white transition-colors">Support</a>
          </div>
        </div>
      </div>

      {/* Main Footer Content */}
      <div className="container mx-auto px-4 py-12">
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-8 mb-12">
          
          <div className="col-span-2 lg:col-span-2">
            <Link to="/" className="text-xl font-black tracking-tighter text-white mb-4 block">
              aiagent<span className="text-blue-500">.xyz</span>
            </Link>
            <p className="mb-6 max-w-sm text-slate-500">
              Composable autonomous supply for the IOI network. Discover, publish, and license verifiable agents, workflows, operator packs, service modules, and embodied runtimes.
            </p>
            <div className="flex gap-4">
              <SocialIcon path="M23 3a10.9 10.9 0 0 1-3.14 1.53 4.48 4.48 0 0 0-7.86 3v1A10.66 10.66 0 0 1 3 4s-4 9 5 13a11.64 11.64 0 0 1-7 2c9 5 20 0 20-11.5a4.5 4.5 0 0 0-.08-.83A7.72 7.72 0 0 0 23 3z" />
              <SocialIcon path="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22" />
              <SocialIcon path="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z" />
            </div>
          </div>

          <div>
            <h4 className="font-bold text-white mb-4">Explore</h4>
            <ul className="space-y-2">
              <li><Link to="/" className="hover:text-blue-400 transition-colors">Browse Listings</Link></li>
              <li><Link to="/?format=Workflow" className="hover:text-blue-400 transition-colors">Workflows</Link></li>
              <li><Link to="/?format=Service+Module" className="hover:text-blue-400 transition-colors">Service Modules</Link></li>
            </ul>
          </div>

          <div>
            <h4 className="font-bold text-white mb-4">Publish</h4>
            <ul className="space-y-2">
              <li><Link to="/sell" className="hover:text-blue-400 transition-colors">Publish Capability</Link></li>
              <li><a href="#" className="hover:text-blue-400 transition-colors">Pricing Models</a></li>
              <li><a href="#" className="hover:text-blue-400 transition-colors">Promotion to SAS.xyz</a></li>
            </ul>
          </div>

          <div>
            <h4 className="font-bold text-white mb-4">Developers</h4>
            <ul className="space-y-2">
              <li><a href="#" className="hover:text-blue-400 transition-colors">IOI SDK</a></li>
              <li><a href="#" className="hover:text-blue-400 transition-colors">Manifest Schema</a></li>
              <li><a href="#" className="hover:text-blue-400 transition-colors">Signed Receipts</a></li>
            </ul>
          </div>

        </div>

        <div className="border-t border-slate-800 pt-8 flex flex-col md:flex-row justify-between items-center gap-4 text-xs text-slate-600">
          <p>© 2026 IOI Foundation. All rights reserved.</p>
          <div className="flex gap-6">
            <a href="#" className="hover:text-slate-400 transition-colors">Privacy Policy</a>
            <a href="#" className="hover:text-slate-400 transition-colors">Terms of Service</a>
            <a href="#" className="hover:text-slate-400 transition-colors">Cookies</a>
          </div>
        </div>
      </div>
    </footer>
  );
}

function SocialIcon({ path }) {
  return (
    <a href="#" className="w-8 h-8 rounded bg-slate-800 flex items-center justify-center hover:bg-slate-700 hover:text-white transition-all">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d={path} />
      </svg>
    </a>
  );
}
