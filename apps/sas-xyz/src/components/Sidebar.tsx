import { 
  LayoutDashboard, 
  Package, 
  Activity, 
  ShieldCheck, 
  CreditCard, 
  Settings, 
  Box,
  ChevronRight,
  ExternalLink,
  History
} from 'lucide-react';
import { motion } from 'motion/react';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export default function Sidebar({ activeTab, setActiveTab }: SidebarProps) {
  const groups = [
    {
      label: 'Procurement',
      items: [
        { id: 'catalog', label: 'Service Catalog', icon: Package },
        { id: 'requests', label: 'New Requests', icon: Box },
        { id: 'governance', label: 'Governance', icon: ShieldCheck },
      ]
    },
    {
      label: 'Operations',
      items: [
        { id: 'instances', label: 'Active Instances', icon: Activity },
        { id: 'audit', label: 'Audit Trails', icon: History },
        { id: 'settlement', label: 'Settlement', icon: CreditCard },
      ]
    }
  ];

  return (
    <aside className="w-[240px] bg-[#0F172A] text-white h-screen flex flex-col p-6 sticky top-0 shrink-0 shadow-xl overflow-y-auto">
      <div className="text-[22px] font-[800] tracking-[-1px] mb-10 select-none">
        sas<span className="text-[#2563EB]">.xyz</span>
      </div>

      <nav className="flex-grow">
        {groups.map((group) => (
          <div key={group.label} className="mb-8">
            <h3 className="text-[10px] uppercase tracking-[1px] text-[#64748B] font-bold mb-3">{group.label}</h3>
            <div className="space-y-1">
              {group.items.map((item) => (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center gap-3 py-2.5 text-sm transition-all relative ${
                    activeTab === item.id 
                      ? 'text-white opacity-100 font-semibold' 
                      : 'text-white opacity-70 hover:opacity-100'
                  }`}
                >
                  {activeTab === item.id && (
                    <motion.div 
                      layoutId="sidebarActive" 
                      className="absolute left-[-24px] w-[2px] h-5 bg-[#2563EB]" 
                    />
                  )}
                  <item.icon className="w-4 h-4 shrink-0" />
                  <span>{item.label}</span>
                </button>
              ))}
            </div>
          </div>
        ))}
      </nav>

      <div className="mt-auto">
        <div className="mb-8">
          <h3 className="text-[10px] uppercase tracking-[1px] text-[#64748B] font-bold mb-3">Organization</h3>
          <div className="flex items-center gap-3 py-2.5 text-sm opacity-70">
            <Settings className="w-4 h-4" />
            <span>Acme Corp Global</span>
          </div>
        </div>
      </div>
    </aside>
  );
}
