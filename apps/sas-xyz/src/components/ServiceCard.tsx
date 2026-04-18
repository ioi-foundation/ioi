import { 
  Shield, 
  Cpu, 
  Link2, 
  CheckCircle2, 
  ArrowUpRight,
  Lock,
  History,
  Scale
} from 'lucide-react';
import { Service, RuntimePosture, PricingModel } from '../types';
import { motion } from 'motion/react';

interface ServiceCardProps {
  service: Service;
  onClick: () => void;
  key?: string;
}

export default function ServiceCard({ service, onClick }: ServiceCardProps) {
  const getIconColor = (tags: string[]) => {
    if (tags.includes('Finance')) return 'bg-[#DBEAFE] text-[#1E40AF]';
    if (tags.includes('Security')) return 'bg-[#FEE2E2] text-[#991B1B]';
    if (tags.includes('DevOps')) return 'bg-[#DCFCE7] text-[#166534]';
    if (tags.includes('Marketing')) return 'bg-[#F3E8FF] text-[#6B21A8]';
    return 'bg-[#F1F5F9] text-[#475569]';
  };

  const getInitials = (name: string) => {
    return name.split(' ').map(n => n[0]).join('').substring(0, 2).toUpperCase();
  };

  return (
    <motion.div 
      whileHover={{ y: -4 }}
      onClick={onClick}
      className="bg-white border border-[#E2E8F0] rounded-xl p-6 flex flex-col justify-between h-full min-h-[420px] cursor-pointer hover:shadow-lg transition-all"
    >
      <div>
        <div className="flex justify-between items-start mb-4">
          <div className={`w-12 h-12 rounded-xl flex items-center justify-center font-bold text-lg ${getIconColor(service.tags)}`}>
            {getInitials(service.name)}
          </div>
          <div className="flex items-center gap-1.5 text-[11px] font-bold text-[#10B981] bg-[#ECFDF5] px-2 py-1 rounded-md border border-[#D1FAE5]">
            <div className="w-1.5 h-1.5 bg-[#10B981] rounded-full" />
            <span>POLICY COMPLIANT</span>
          </div>
        </div>

        <div className="mb-6">
          <h3 className="text-[18px] font-bold text-[#1E293B] mb-2 leading-tight">
            {service.name}
          </h3>
          <p className="text-[13px] text-[#64748B] line-clamp-2 leading-[1.5]">
            {service.description}
          </p>
        </div>

        <div className="space-y-4 pt-4 border-t border-[#F1F5F9]">
          <div className="grid grid-cols-1 gap-4">
            <div className="flex flex-col">
              <span className="text-[10px] uppercase font-bold text-[#94A3B8] leading-none mb-1.5">Expected Outcome</span>
              <span className="text-[13px] font-semibold text-[#1E293B]">{service.outcome}</span>
            </div>
            
            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col">
                <span className="text-[10px] uppercase font-bold text-[#94A3B8] leading-none mb-1.5">Runtime</span>
                <span className="text-[12px] font-medium text-[#475569]">{service.execution}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[10px] uppercase font-bold text-[#94A3B8] leading-none mb-1.5">Privacy Class</span>
                <span className="text-[12px] font-medium text-[#475569] truncate" title={service.privacy}>{service.privacy.split(' / ')[0]}</span>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="flex flex-col">
                <span className="text-[10px] uppercase font-bold text-[#94A3B8] leading-none mb-1.5">Evidence Chain</span>
                <span className="text-[12px] font-medium text-[#475569] truncate italic">{service.evidence}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[10px] uppercase font-bold text-[#94A3B8] leading-none mb-1.5">Settlement</span>
                <span className="text-[12px] font-medium text-[#475569] truncate">{service.settlement.split(' + ')[0]}</span>
              </div>
            </div>

            <div className="flex flex-col">
              <span className="text-[10px] uppercase font-bold text-[#94A3B8] leading-none mb-1.5">Policy Envelope</span>
              <span className="text-[12px] font-medium text-[#64748B] line-clamp-1 italic">"{service.policy}"</span>
            </div>
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between mt-8 pt-4 border-t border-[#F1F5F9]">
        <div className="text-[15px] font-bold text-[#1E293B]">
          {service.pricing === PricingModel.SUBSCRIPTION ? '$450' : service.pricing === PricingModel.USAGE_BASED ? '$1.20' : '$0.00'} 
          <span className="font-normal text-[11px] text-[#64748B] ml-1">
            {service.pricing === PricingModel.SUBSCRIPTION ? '/ month' : service.pricing === PricingModel.USAGE_BASED ? '/ unit' : ''}
          </span>
        </div>
        <button className="bg-[#0F172A] text-white px-5 py-2 rounded-lg font-bold text-xs transition-all hover:bg-black active:scale-95">
          View Details
        </button>
      </div>
    </motion.div>
  );
}
