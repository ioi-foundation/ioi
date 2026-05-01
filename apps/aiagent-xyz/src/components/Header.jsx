// src/components/Header.jsx
import React, { useState } from 'react';
import { Link, useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import WalletModal from './WalletModal';

export default function Header() {
  const [user, setUser] = useState(null); 
  const [menuOpen, setMenuOpen] = useState(false);
  const [isWalletModalOpen, setIsWalletModalOpen] = useState(false);
  
  const location = useLocation();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [searchQuery, setSearchQuery] = useState(searchParams.get('q') || '');
  const activeFormat = searchParams.get('format') || 'All Listings';

  const tickerItems = [
    { label: 'LABOR_GAS', val: '0.0042', delta: '+1.2%' },
    { label: 'H100_SPOT', val: '$2.45/hr', delta: '-0.5%' },
    { label: 'LLAMA3_TOK', val: '$0.15/M', delta: '0.0%' },
    { label: 'ZKP_VERIFY', val: '$0.08', delta: '+2.1%' },
  ];

  const handleSearch = (e) => {
    if (e.key === 'Enter' || e.type === 'click') {
      // Navigate to Home with search param if not already there, or update param
      const targetPath = location.pathname === '/' ? '/' : '/';
      const params = new URLSearchParams(searchParams);
      if (searchQuery) {
        params.set('q', searchQuery);
      } else {
        params.delete('q');
      }
      navigate(`${targetPath}?${params.toString()}`);
    }
  };

  const handleLoginClick = () => {
    setIsWalletModalOpen(true);
  };

  const handleWalletConnect = (walletType) => {
    setIsWalletModalOpen(false);
    setUser({
      name: 'QuantLabs_0x',
      avatar: 'https://api.dicebear.com/7.x/avataaars/svg?seed=QuantLabs',
      balance: '450 IOI',
      walletType: walletType 
    });
  };

  const handleLogout = () => {
    setUser(null);
    setMenuOpen(false);
    navigate('/');
  };

  return (
    <>
      <WalletModal 
        isOpen={isWalletModalOpen} 
        onClose={() => setIsWalletModalOpen(false)}
        onConnect={handleWalletConnect}
      />

      <header className="bg-white border-b border-gray-200 sticky top-0 z-50">
        
        {/* 1. Ticker Bar */}
        <div className="bg-slate-50 border-b border-gray-200 py-1 overflow-hidden">
          <div className="flex gap-8 text-xs font-mono animate-marquee whitespace-nowrap px-4">
            {tickerItems.map((item, i) => (
              <span key={i} className="flex gap-2">
                <span className="font-bold text-slate-600">{item.label}</span>
                <span>{item.val}</span>
                <span className={item.delta.startsWith('+') ? 'text-green-600' : 'text-red-600'}>
                  {item.delta}
                </span>
              </span>
            ))}
          </div>
        </div>

        {/* 2. Main Nav */}
        <div className="container mx-auto px-4 h-16 flex items-center justify-between">
          <div className="flex items-center gap-8">
            <Link to="/" className="text-xl font-black tracking-tighter text-slate-900">
              aiagent<span className="text-blue-500">.xyz</span>
            </Link>
            
            <div className="relative w-96 hidden md:block">
              <input 
                type="text" 
                placeholder="Search agents, workflows, operators, or developers..." 
                className="w-full bg-slate-100 border border-slate-200 rounded-md py-2 pl-9 pr-4 text-sm focus:outline-none focus:border-blue-500 transition-colors"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={handleSearch}
              />
              <button 
                onClick={handleSearch}
                className="absolute left-0 top-0 bottom-0 px-3 flex items-center justify-center text-slate-400 hover:text-blue-500 transition-colors"
              >
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
              </button>
            </div>
          </div>

          <div className="flex items-center gap-4 text-sm font-medium text-slate-600">
            {user ? (
              <div className="relative">
                <div 
                  className="flex items-center gap-3 cursor-pointer p-1 rounded hover:bg-slate-50 transition-colors" 
                  onClick={() => setMenuOpen(!menuOpen)}
                >
                  <div className="hidden sm:flex flex-col items-end">
                     <span className="text-slate-900 font-bold text-xs">{user.name}</span>
                     <span className="text-slate-500 font-mono text-[10px] bg-slate-100 px-1.5 rounded border border-slate-200 flex items-center gap-1">
                        {user.walletType === 'passport' && <span>🆔</span>}
                        {user.balance}
                     </span>
                  </div>
                  <img src={user.avatar} className="w-8 h-8 rounded-full border border-slate-200" alt="" />
                </div>
                
                {/* User Dropdown */}
                {menuOpen && (
                  <div className="absolute right-0 mt-2 w-56 bg-white border border-gray-200 rounded-lg shadow-xl py-1 z-50 animate-in fade-in slide-in-from-top-2 duration-200">
                    <div className="px-4 py-3 border-b border-gray-100 bg-slate-50">
                      <p className="font-bold text-slate-900 text-sm">{user.name}</p>
                      <p className="text-xs text-slate-500 font-mono truncate">0x71C...9A23</p>
                    </div>
                    
                    <Link 
                      to="/dashboard" 
                      className="block px-4 py-2 text-sm text-slate-700 hover:bg-slate-50 hover:text-blue-600 font-medium"
                      onClick={() => setMenuOpen(false)}
                    >
                      Command Center
                    </Link>

                    <Link 
                      to="/dashboard" 
                      className="flex items-center justify-between px-4 py-2 text-sm text-slate-700 hover:bg-slate-50 hover:text-blue-600"
                      onClick={() => setMenuOpen(false)}
                    >
                      <span>Saved Listings</span>
                      <span className="text-xs bg-slate-100 text-slate-500 px-1.5 rounded">2</span>
                    </Link>

                    <Link 
                      to={`/profile/${user.name}`} 
                      className="block px-4 py-2 text-sm text-slate-700 hover:bg-slate-50 hover:text-blue-600"
                      onClick={() => setMenuOpen(false)}
                    >
                      Public Profile
                    </Link>
                    <Link 
                      to="/sell" 
                      className="block px-4 py-2 text-sm text-slate-700 hover:bg-slate-50 hover:text-blue-600 font-medium"
                      onClick={() => setMenuOpen(false)}
                    >
                      Publish Capability
                    </Link>
                    <div className="border-t border-gray-100 my-1"></div>
                    <button 
                      onClick={handleLogout} 
                      className="block w-full text-left px-4 py-2 text-sm text-red-600 hover:bg-red-50"
                    >
                      Sign Out
                    </button>
                  </div>
                )}
              </div>
            ) : (
              <button onClick={handleLoginClick} className="hover:text-blue-600 transition-colors font-semibold">
                Log In
              </button>
            )}
          </div>
        </div>

        {/* 3. Tab Bar */}
        <div className="container mx-auto px-4 overflow-x-auto">
          <nav className="flex gap-1 min-w-max">
            <NavLink to="/" active={(location.pathname === '/' && activeFormat === 'All Listings') || location.pathname.startsWith('/agent/')}>Explore</NavLink>
            <NavLink to="/?format=Workflow" active={location.pathname === '/' && activeFormat === 'Workflow'}>Workflows</NavLink>
            <NavLink to="/?format=Service+Module" active={location.pathname === '/' && activeFormat === 'Service Module'}>Services</NavLink>
            <NavLink to="/sell" active={location.pathname === '/sell'}>Publish</NavLink>
            <NavLink to="/freelance" active={location.pathname === '/freelance' || location.pathname === '/post-job' || location.pathname.startsWith('/freelance/')} highlight>Freelance</NavLink>
          </nav>
        </div>
      </header>
    </>
  );
}

function NavLink({ to, children, active, highlight }) {
  const base = "px-4 py-3 text-sm border-b-2 transition-colors whitespace-nowrap";
  const state = active ? "border-blue-600 text-blue-600 font-semibold bg-blue-50/50" 
              : highlight ? "border-transparent text-amber-600 font-semibold hover:bg-amber-50"
              : "border-transparent text-slate-600 hover:text-slate-900 hover:border-slate-300";
  
  return <Link to={to} className={`${base} ${state}`}>{children}</Link>;
}
