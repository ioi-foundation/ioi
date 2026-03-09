import React, { useState, useRef, useEffect } from 'react';
import { Link, Outlet, useLocation } from 'react-router-dom';
import { 
  LayoutDashboard, 
  Workflow, 
  Briefcase, 
  Database, 
  Cpu, 
  ShieldAlert,
  BarChart3,
  Scale,
  Menu,
  Search,
  Bell,
  ChevronDown,
  Terminal,
  X,
  Maximize2,
  Minus,
  FileText,
  Activity,
  CreditCard,
  Users,
  Store,
  Settings
} from 'lucide-react';
import { cn } from '../lib/utils';
import Logo from './Logo';

const navItems = [
  { name: 'Overview', path: '/app', icon: LayoutDashboard },
  { name: 'Services', path: '/app/services', icon: Workflow },
  { name: 'Agent IDE', path: '/app/canvas', icon: Terminal },
  { name: 'Deployments', path: '/app/deployments', icon: Cpu },
  { name: 'Policies & Approvals', path: '/app/policies', icon: ShieldAlert },
  { name: 'Receipts / Evidence', path: '/app/receipts', icon: FileText },
  { name: 'Observability', path: '/app/observability', icon: Activity },
  { name: 'Billing & Metering', path: '/app/billing', icon: CreditCard },
  { name: 'Customers / Tenants', path: '/app/customers', icon: Users },
  { name: 'Marketplace Publishing', path: '/app/marketplace', icon: Store },
  { name: 'Dispute Center', path: '/app/disputes', icon: Scale },
  { name: 'IAM / Settings', path: '/app/settings', icon: Settings },
];

export default function Layout() {
  const location = useLocation();
  const [isSidebarOpen, setIsSidebarOpen] = useState(false);
  const [isShellOpen, setIsShellOpen] = useState(false); // NEW: Cloud Shell State

  // Shell State
  const [shellHistory, setShellHistory] = useState([
    { type: 'system', text: 'Welcome to IOI Cloud Shell. Authenticated as did:ioi:quantlabs.' },
    { type: 'success', text: 'System ready.' }
  ]);
  const [shellInput, setShellInput] = useState('');
  const shellEndRef = useRef<HTMLDivElement>(null);

  const handleShellCommand = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && shellInput.trim()) {
      const command = shellInput.trim();
      setShellHistory(prev => [...prev, { type: 'command', text: `quantlabs@ioi:~$ ${command}` }]);
      
      // Mock Responses
      setTimeout(() => {
        let response = { type: 'info', text: `Command not found: ${command}` };
        if (command === 'clear') {
          setShellHistory([]);
          setShellInput('');
          return;
        } else if (command === 'ioi status') {
          response = { type: 'success', text: 'All systems operational. 4 agents active.' };
        } else if (command.startsWith('ioi logs')) {
          response = { type: 'info', text: 'Tailing logs for active swarm...\n[INFO] Agent RFA-8842 connected to node-7a9b\n[WARN] High latency on RPC endpoint' };
        } else if (command === 'help') {
          response = { type: 'info', text: 'Available commands: ioi status, ioi logs --tail, clear' };
        }
        
        setShellHistory(prev => [...prev, response]);
      }, 300);

      setShellInput('');
    }
  };

  useEffect(() => {
    if (shellEndRef.current) {
      shellEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [shellHistory, isShellOpen]);

  return (
    <div className="flex flex-col h-screen w-full bg-bg text-white overflow-hidden font-sans">
      {/* Top Console Bar (OCB) */}
      <header className="h-14 bg-surface border-b border-border flex items-center justify-between px-4 shrink-0 z-20">
        {/* Left: Hamburger, Logo, Context */}
        <div className="flex items-center space-x-4">
          <button 
            onClick={() => setIsSidebarOpen(!isSidebarOpen)}
            className="p-1.5 text-gray-400 hover:text-white hover:bg-surface-hover rounded transition-colors"
          >
            <Menu className="w-5 h-5" />
          </button>
          
          <Link to="/" className="flex items-center space-x-2 hover:opacity-80 transition-opacity">
            <Logo className="w-5 h-5" />
            <span className="font-mono font-bold tracking-wider text-base">sas.xyz</span>
          </Link>

          <div className="h-6 w-px bg-border mx-2 hidden sm:block"></div>

          <button className="hidden sm:flex items-center space-x-2 text-sm font-medium text-gray-300 hover:text-white transition-colors">
            <div className="w-5 h-5 rounded bg-amber-accent/20 border border-amber-accent/50 flex items-center justify-center">
              <span className="text-amber-accent text-[10px] font-bold">Q</span>
            </div>
            <span>QuantLabs</span>
            <ChevronDown className="w-4 h-4 text-gray-500" />
          </button>
        </div>

        {/* Center: Global Search */}
        <div className="flex-1 max-w-2xl px-8 hidden md:block">
          <div className="relative group">
            <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-gray-500 group-focus-within:text-cyan-accent transition-colors" />
            <input 
              type="text" 
              placeholder="Search for agents, policies, or docs..." 
              className="w-full bg-bg border border-border rounded-md pl-10 pr-12 py-1.5 text-sm text-white focus:outline-none focus:border-cyan-accent transition-colors placeholder-gray-500"
            />
            <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center space-x-1">
              <kbd className="bg-surface border border-border rounded px-1.5 py-0.5 text-[10px] font-mono text-gray-500">⌘</kbd>
              <kbd className="bg-surface border border-border rounded px-1.5 py-0.5 text-[10px] font-mono text-gray-500">K</kbd>
            </div>
          </div>
        </div>

        {/* Right: Shell, Notifications, Profile */}
        <div className="flex items-center space-x-3">
          <div className="flex items-center text-xs font-mono text-gray-400 bg-bg px-2.5 py-1 rounded border border-border hidden lg:flex">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-accent mr-2 animate-pulse"></span>
            IOI Mainnet
          </div>
          
          <div className="h-6 w-px bg-border mx-1 hidden sm:block"></div>

          {/* TOGGLE SHELL BUTTON */}
          <button 
            onClick={() => setIsShellOpen(!isShellOpen)}
            className={cn(
              "p-1.5 rounded transition-colors",
              isShellOpen ? "text-cyan-accent bg-cyan-accent/10" : "text-gray-400 hover:text-white hover:bg-surface-hover"
            )} 
            title="Activate IOI Cloud Shell"
          >
            <Terminal className="w-5 h-5" />
          </button>
          
          <button className="p-1.5 text-gray-400 hover:text-white hover:bg-surface-hover rounded transition-colors relative">
            <Bell className="w-5 h-5" />
            <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-amber-accent rounded-full border-2 border-surface"></span>
          </button>

          <button className="w-7 h-7 rounded-full bg-emerald-accent/20 flex items-center justify-center border border-emerald-accent/50 ml-2 hover:bg-emerald-accent/30 transition-colors">
            <span className="text-emerald-accent text-[10px] font-mono">0x</span>
          </button>
        </div>
      </header>

      {/* Main Layout Area */}
      <div className="flex flex-1 overflow-hidden relative">
        {/* Left Navigation (Collapsible) */}
        <aside 
          className={cn(
            "bg-surface border-r border-border flex flex-col transition-all duration-300 ease-in-out z-10",
            isSidebarOpen ? "w-64 absolute md:relative h-full" : "w-0 md:w-[60px]" // Hides completely on mobile when closed
          )}
        >
          <nav className="flex-1 py-4 flex flex-col space-y-1 px-2 overflow-y-auto overflow-x-hidden">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path || (item.path !== '/app' && location.pathname.startsWith(item.path));
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  onClick={() => window.innerWidth < 768 && setIsSidebarOpen(false)} // Auto-close on mobile
                  className={cn(
                    "flex items-center rounded-md transition-colors group relative",
                    isSidebarOpen ? "px-3 py-2" : "justify-center py-3",
                    isActive 
                      ? "bg-surface-hover text-white" 
                      : "text-gray-400 hover:bg-surface-hover hover:text-white"
                  )}
                  title={!isSidebarOpen ? item.name : undefined}
                >
                  <Icon className={cn(
                    "flex-shrink-0 transition-colors",
                    isSidebarOpen ? "w-5 h-5 mr-3" : "w-5 h-5",
                    isActive ? "text-cyan-accent" : "text-gray-500 group-hover:text-gray-300"
                  )} />
                  
                  {isSidebarOpen && (
                    <span className="text-sm font-medium whitespace-nowrap">{item.name}</span>
                  )}

                  {/* Active Indicator for collapsed state */}
                  {!isSidebarOpen && isActive && (
                    <div className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-5 bg-cyan-accent rounded-r-full"></div>
                  )}
                </Link>
              );
            })}
          </nav>
        </aside>

        {/* Main Content Area (Stack of Canvas + Shell) */}
        <div className="flex-1 flex flex-col min-w-0 overflow-hidden relative bg-bg">
          
          {/* Active Page Content */}
          <main className="flex-1 overflow-auto p-6 md:p-8 relative">
            <Outlet />
          </main>

          {/* IOI Cloud Shell (Bottom Drawer) */}
          <div 
            className={cn(
              "bg-[#050505] border-t border-border flex flex-col transition-transform duration-300 ease-in-out z-50 absolute bottom-0 left-0 w-full shadow-[0_-10px_40px_rgba(0,0,0,0.5)]",
              isShellOpen ? "h-64 translate-y-0" : "h-64 translate-y-full"
            )}
          >
            {/* Shell Header */}
            <div className="h-10 bg-surface border-b border-border flex items-center justify-between px-4 shrink-0">
              <div className="flex items-center space-x-3 text-xs font-mono text-gray-400">
                <span className="text-cyan-accent">Terminal</span>
                <span>Output</span>
                <span>Traces</span>
              </div>
              <div className="flex items-center space-x-2 text-gray-500">
                <button onClick={() => setIsShellOpen(false)} className="hover:text-white p-1 rounded hover:bg-white/10 transition-colors"><Minus className="w-4 h-4" /></button>
                <button className="hover:text-white p-1 rounded hover:bg-white/10 transition-colors"><Maximize2 className="w-4 h-4" /></button>
                <button onClick={() => setIsShellOpen(false)} className="hover:text-white p-1 rounded hover:bg-white/10 transition-colors"><X className="w-4 h-4" /></button>
              </div>
            </div>
            
            {/* Shell Output */}
            <div className="flex-1 overflow-auto p-4 font-mono text-sm space-y-1" onClick={() => document.getElementById('shell-input')?.focus()}>
              {shellHistory.map((item, i) => (
                <div key={i} className={cn(
                  "whitespace-pre-wrap",
                  item.type === 'system' && "text-gray-500",
                  item.type === 'success' && "text-emerald-accent",
                  item.type === 'command' && "text-white",
                  item.type === 'info' && "text-gray-300"
                )}>
                  {item.text}
                </div>
              ))}
              <div className="flex mt-2 items-center">
                <span className="text-cyan-accent mr-2 shrink-0">quantlabs@ioi:~$</span>
                <input
                  id="shell-input"
                  type="text"
                  value={shellInput}
                  onChange={(e) => setShellInput(e.target.value)}
                  onKeyDown={handleShellCommand}
                  className="bg-transparent border-none outline-none text-white flex-1 min-w-0"
                  autoComplete="off"
                  spellCheck="false"
                  autoFocus={isShellOpen}
                />
              </div>
              <div ref={shellEndRef} />
            </div>
          </div>

        </div>
      </div>

      {/* Mobile Sidebar Overlay */}
      {isSidebarOpen && (
        <div 
          className="fixed inset-0 bg-black/50 z-0 md:hidden"
          onClick={() => setIsSidebarOpen(false)}
        />
      )}
    </div>
  );
}
