import { Search, Bell, User, LayoutGrid, List } from 'lucide-react';

export default function Header() {
  return (
    <header className="h-[64px] bg-white border-b border-[#E2E8F0] flex items-center justify-between px-8 sticky top-0 z-40 shrink-0">
      <div className="flex items-center gap-4 flex-1">
        <div className="relative w-[400px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#64748B]" />
          <input 
            type="text" 
            placeholder="Search approved services, outcomes, or policy envelopes..."
            className="w-full bg-[#F8FAFC] border border-[#E2E8F0] rounded-md py-2 pl-10 pr-4 text-sm text-[#64748B] focus:outline-none focus:border-[#2563EB] transition-all placeholder:text-[#64748B]/50"
          />
        </div>
      </div>

      <div className="flex items-center gap-5">
        <span className="text-[13px] text-[#64748B] font-medium">v2.4.0 Stable</span>
        <div className="h-8 w-[1px] bg-[#E2E8F0]" />
        
        <button className="relative p-2 text-[#64748B] hover:text-[#1E293B] transition-colors">
          <Bell className="w-5 h-5" />
          <span className="absolute top-2.5 right-2.5 w-1.5 h-1.5 bg-[#10B981] rounded-full border-2 border-white" />
        </button>

        <div className="w-8 h-8 rounded-full bg-[#E2E8F0] border border-[#CBD5E1] flex items-center justify-center overflow-hidden cursor-pointer hover:border-[#2563EB] transition-all">
          <User className="w-4 h-4 text-[#64748B]" />
        </div>
      </div>
    </header>
  );
}
