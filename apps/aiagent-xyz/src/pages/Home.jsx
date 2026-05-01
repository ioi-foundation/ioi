// src/pages/Home.jsx
import React, { useState } from 'react';
import Header from '../components/Header';
import MarketGrid from '../components/MarketGrid';
import FreelanceFeed from '../components/FreelanceFeed';
import MobileFilterDrawer from '../components/MobileFilterDrawer';
import { Link, useSearchParams } from 'react-router-dom';

const formatOptions = [
  { label: 'All Listings', value: 'All Listings' },
  { label: 'Agents', value: 'Agent' },
  { label: 'Workflows', value: 'Workflow' },
  { label: 'Swarms', value: 'Swarm' },
  { label: 'Operator Packs', value: 'Operator Pack' },
  { label: 'Service Modules', value: 'Service Module' },
  { label: 'Embodied Runtimes', value: 'Embodied Runtime' },
];

// Expanded Mock Data
const allProducts = [
  { 
    id: 1, name: 'Claims Triage Operator', dev: 'AssureOps', 
    price: '$0.18 / execution', format: 'Agent', market: 'Insurance', pricingModel: 'Metered Execution',
    rating: 4.8, reviews: 124,
    image: 'linear-gradient(135deg, #1e293b 0%, #0f172a 100%)' 
  },
  { 
    id: 2, name: 'Compliance Review Workflow', dev: 'LawAI_Corp', 
    price: '$29 / seatless lane', format: 'Workflow', market: 'Compliance', pricingModel: 'License',
    rating: 4.5, reviews: 856,
    image: 'linear-gradient(135deg, #475569 0%, #334155 100%)' 
  },
  { 
    id: 3, name: 'Research Swarm (DeepSeek)', dev: 'OpenSci', 
    price: 'Free', format: 'Swarm', market: 'Research', pricingModel: 'Open Source',
    rating: 4.9, reviews: 2100,
    image: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)' 
  },
  { 
    id: 4, name: 'Vehicle Prep Robotics Runtime', dev: 'EmbodyWorks', 
    price: '$2,400 / month', format: 'Embodied Runtime', market: 'Operations', pricingModel: 'Lease',
    rating: 4.2, reviews: 89,
    image: 'linear-gradient(135deg, #059669 0%, #047857 100%)' 
  },
  { 
    id: 5, name: 'Browser QA Swarm', dev: 'QualityForge', 
    price: '$0.07 / run', format: 'Swarm', market: 'Software', pricingModel: 'Metered Execution',
    rating: 4.9, reviews: 420,
    image: 'linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%)' 
  },
  { 
    id: 6, name: 'KYC Extraction Pipeline', dev: 'SecurityDAO', 
    price: '$0.03 / document', format: 'Service Module', market: 'Risk', pricingModel: 'Settlement-Based',
    rating: 5.0, reviews: 2100,
    image: 'linear-gradient(135deg, #064e3b 0%, #065f46 100%)' 
  },
  { 
    id: 7, name: 'GUI Automation Worker', dev: 'DevTools_Inc', 
    price: '$10 / session', format: 'Agent', market: 'Operations', pricingModel: 'Metered Execution',
    rating: 4.6, reviews: 150,
    image: 'linear-gradient(135deg, #374151 0%, #111827 100%)' 
  },
  { 
    id: 8, name: 'Research + Drafting Pack', dev: 'GrowthHacker', 
    price: '$45 / month', format: 'Operator Pack', market: 'Knowledge Work', pricingModel: 'License',
    rating: 4.3, reviews: 320,
    image: 'linear-gradient(135deg, #7c3aed 0%, #5b21b6 100%)' 
  },
  {
    id: 9, name: 'Accounting Close Service Module', dev: 'LedgerFlow_AI',
    tagline: 'Invoice intake, coding, routing, and exceptions packaged for finance teams that need a composable lane before full managed service rollout.',
    price: '$49 / month', format: 'Service Module', market: 'Finance', pricingModel: 'Revenue Share',
    rating: 4.7, reviews: 218,
    image: 'linear-gradient(135deg, #0f766e 0%, #155e75 100%)'
  },
];

export default function Home() {
  const [isMobileFiltersOpen, setIsMobileFiltersOpen] = useState(false);
  const [searchParams, setSearchParams] = useSearchParams();
  
  const currentFormat = searchParams.get('format') || 'All Listings';
  const searchQuery = searchParams.get('q') || '';
  const currentFormatLabel =
    formatOptions.find((option) => option.value === currentFormat)?.label || currentFormat;

  const setFormat = (format) => {
    const params = new URLSearchParams(searchParams);
    if (format === 'All Listings') {
      params.delete('format');
    } else {
      params.set('format', format);
    }
    setSearchParams(params);
  };

  const clearFilters = () => {
    const params = new URLSearchParams(searchParams);
    params.delete('format');
    params.delete('q');
    setSearchParams(params);
  };

  // Filter Logic
  const filteredProducts = allProducts.filter(p => {
    const matchesFormat = currentFormat === 'All Listings' || p.format === currentFormat;
    
    const matchesSearch =
      p.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.dev.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.format.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.market.toLowerCase().includes(searchQuery.toLowerCase()) ||
      p.pricingModel.toLowerCase().includes(searchQuery.toLowerCase());
                          
    return matchesFormat && matchesSearch;
  });

  // Reusable filter content
  const renderFilterContent = () => (
    <div className="space-y-8">
      <div>
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Execution Shape</h3>
        <ul className="space-y-2 text-sm text-slate-600">
          {formatOptions.map(option => (
             <li 
               key={option.value}
               onClick={() => setFormat(option.value)}
               className={`px-2 cursor-pointer rounded transition-colors ${currentFormat === option.value ? 'font-medium text-blue-600 bg-blue-50 py-1 -ml-2' : 'hover:text-slate-900'}`}
             >
               {option.label}
             </li>
          ))}
        </ul>
      </div>
      
      <div>
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Platform</h3>
        <div className="space-y-2">
          <label className="flex items-center gap-2 text-sm text-slate-600 cursor-pointer hover:text-slate-900">
            <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-0" defaultChecked />
            <span>Autopilot (Desktop)</span>
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-600 cursor-pointer hover:text-slate-900">
            <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-0" />
            <span>Private Deploy</span>
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-600 cursor-pointer hover:text-slate-900">
            <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-0" />
            <span>Cloud / API</span>
          </label>
        </div>
      </div>

      <div>
        <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Price Model</h3>
        <div className="space-y-2">
          <label className="flex items-center gap-2 text-sm text-slate-600 cursor-pointer hover:text-slate-900">
            <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-0" />
            <span>Metered Execution</span>
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-600 cursor-pointer hover:text-slate-900">
            <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-0" />
            <span>License</span>
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-600 cursor-pointer hover:text-slate-900">
            <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-0" />
            <span>Revenue Share</span>
          </label>
          <label className="flex items-center gap-2 text-sm text-slate-600 cursor-pointer hover:text-slate-900">
            <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-0" />
            <span>Settlement-Based</span>
          </label>
        </div>
      </div>
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-50">
      <Header />
      
      {/* Mobile Filter Drawer */}
      <MobileFilterDrawer 
        isOpen={isMobileFiltersOpen} 
        onClose={() => setIsMobileFiltersOpen(false)}
      >
        {renderFilterContent()}
      </MobileFilterDrawer>
      
      <main className="container mx-auto px-4 py-8">
        
        {/* FEATURED HERO (Only show on the broad explore view to save space when filtering) */}
        {currentFormat === 'All Listings' && !searchQuery && (
          <div className="mb-10 rounded-2xl overflow-hidden bg-white border border-gray-200 shadow-sm relative group cursor-pointer hover:shadow-md transition-all">
            <div className="absolute inset-0 bg-gradient-to-r from-slate-900 to-blue-900 opacity-95"></div>
            <div className="absolute inset-0 opacity-10" style={{ backgroundImage: 'radial-gradient(circle at 20% 50%, rgba(255,255,255,0.3) 0%, transparent 20%), radial-gradient(circle at 80% 50%, rgba(255,255,255,0.3) 0%, transparent 20%)', backgroundSize: '20px 20px' }}></div>
            
            <div className="relative z-10 p-8 md:p-12 flex flex-col md:flex-row items-center justify-between gap-8">
              <div className="text-left max-w-xl">
                <span className="inline-block bg-blue-500/20 text-blue-100 text-xs font-bold px-2 py-1 rounded mb-3 border border-blue-400/30">
                  FEATURED SERVICE MODULE
                </span>
                <h1 className="text-3xl md:text-4xl font-black text-white mb-4 tracking-tight">
                  Claims Resolution Service Module
                </h1>
                <p className="text-blue-100 text-lg mb-6 leading-relaxed">
                  Package intake, document extraction, routing, and escalation as a governed autonomous component. Enterprise-ready service wrappers can graduate into SAS.xyz without changing the underlying substrate.
                </p>
                <div className="flex gap-4">
                  <button
                    onClick={() => setFormat('Service Module')}
                    className="bg-white text-slate-900 px-6 py-3 rounded-lg font-bold hover:bg-blue-50 transition-colors shadow-lg"
                  >
                    Explore Service Modules
                  </button>
                  <Link
                    to="/sell"
                    className="flex items-center gap-2 text-white/80 text-sm font-medium px-4 py-3"
                  >
                    <span className="w-2 h-2 bg-green-400 rounded-full animate-pulse"></span>
                    Publish Capability
                  </Link>
                </div>
              </div>
              
              <div className="hidden md:block w-full max-w-xs bg-slate-800/50 backdrop-blur-md rounded-xl border border-white/10 p-4 shadow-2xl transform group-hover:scale-105 transition-transform duration-500">
                <div className="space-y-3">
                   <div className="h-2 w-1/3 bg-slate-600 rounded animate-pulse"></div>
                   <div className="h-2 w-2/3 bg-slate-700 rounded"></div>
                   <div className="h-2 w-3/4 bg-slate-700 rounded"></div>
                   <div className="h-32 bg-slate-900/50 rounded border border-white/5 mt-4 flex items-center justify-center text-xs text-slate-500 font-mono">
                     &gt; Promotion track: Agent → Workflow → Operator Pack → Service Module
                   </div>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* CATEGORY CHIPS */}
        <div className="mb-8 overflow-x-auto pb-2 -mx-4 px-4 md:mx-0 md:px-0 scrollbar-hide">
          <div className="flex gap-3 min-w-max">
            {formatOptions.map(chip => (
               <CategoryChip 
                 key={chip.value} 
                 active={currentFormat === chip.value}
                 onClick={() => setFormat(chip.value)}
               >
                 {chip.label}
               </CategoryChip>
            ))}
          </div>
        </div>

        {/* Mobile Filter Button */}
        <div className="lg:hidden mb-6">
          <button 
            onClick={() => setIsMobileFiltersOpen(true)}
            className="w-full flex items-center justify-center gap-2 bg-white border border-gray-300 py-3 rounded-lg text-sm font-bold text-slate-700 shadow-sm"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M3 4a1 1 0 011-1h16a1 1 0 011 1v2.586a1 1 0 01-.293.707l-6.414 6.414a1 1 0 00-.293.707V17l-4 4v-6.586a1 1 0 00-.293-.707L3.293 7.293A1 1 0 013 6.586V4z" /></svg>
            Filter Agents
          </button>
        </div>

        <div className="grid grid-cols-12 gap-8">
          
          {/* LEFT SIDEBAR (Desktop) */}
          <aside className="hidden lg:block col-span-2">
             <div className="sticky top-24">
               {/* Sort Select */}
               <div className="mb-8">
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-3">Sort By</h3>
                  <select className="w-full bg-white border border-gray-200 rounded-md text-sm p-2.5 focus:outline-none focus:border-blue-500 cursor-pointer">
                    <option>Most Popular</option>
                    <option>Newest Arrivals</option>
                    <option>Highest Rated</option>
                    <option>Price: Low to High</option>
                  </select>
               </div>
               
               {renderFilterContent()}
             </div>
          </aside>
          
          {/* CENTER CONTENT */}
          <div className="col-span-12 lg:col-span-7">
            <div className="flex items-center justify-between mb-4">
               <h2 className="font-bold text-slate-900 text-lg">
                 {searchQuery ? `Results for "${searchQuery}"` : currentFormatLabel}
               </h2>
               <span className="text-xs text-slate-500">{filteredProducts.length} results</span>
            </div>
            
            {filteredProducts.length > 0 ? (
               <MarketGrid products={filteredProducts} />
            ) : (
               <div className="text-center py-20 bg-white border border-gray-200 rounded-xl">
                 <div className="text-4xl mb-4">🔭</div>
                 <h3 className="font-bold text-slate-900 mb-2">No capabilities found</h3>
                 <p className="text-slate-500 text-sm">Try adjusting your search or switching execution shapes.</p>
                 <button 
                    onClick={clearFilters}
                    className="mt-4 text-blue-600 hover:underline text-sm font-medium"
                 >
                   Clear all filters
                 </button>
               </div>
            )}
            
            {filteredProducts.length > 8 && (
              <div className="mt-12 text-center">
                <button className="text-sm font-semibold text-slate-500 hover:text-blue-600 transition-colors">
                  Load More Listings ↓
                </button>
              </div>
            )}
          </div>
          
          {/* RIGHT SIDEBAR */}
          <aside className="hidden xl:block col-span-3 space-y-6">
            <FreelanceFeed />
          </aside>
          
        </div>
      </main>
    </div>
  );
}

function CategoryChip({ children, active, onClick }) {
  return (
    <button 
      onClick={onClick}
      className={`
      px-4 py-2 rounded-full text-sm font-medium transition-all whitespace-nowrap border
      ${active 
        ? 'bg-slate-900 text-white border-slate-900' 
        : 'bg-white text-slate-600 border-gray-200 hover:border-blue-400 hover:text-blue-600'}
    `}>
      {children}
    </button>
  )
}
