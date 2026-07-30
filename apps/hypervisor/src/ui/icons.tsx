// Source-neutral icon set — original geometric SVG strokes (currentColor), nothing harvested.
// Tiny, consistent 16px line icons for the rail/shell + a Hypervisor brand mark.
import type { SVGProps } from "react";

const S = ({ children, size = 16, ...p }: SVGProps<SVGSVGElement> & { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" aria-hidden {...p}>{children}</svg>
);

export const IconHome = (p: { size?: number }) => <S {...p}><path d="M4 11l8-6 8 6" /><path d="M6 10v9h12v-9" /></S>;
export const IconProjects = (p: { size?: number }) => <S {...p}><rect x="4" y="4" width="7" height="7" rx="1" /><rect x="13" y="4" width="7" height="7" rx="1" /><rect x="4" y="13" width="7" height="7" rx="1" /><rect x="13" y="13" width="7" height="7" rx="1" /></S>;
export const IconAutomations = (p: { size?: number }) => <S {...p}><path d="M13 3L5 14h6l-1 7 8-11h-6z" /></S>;
export const IconApplications = (p: { size?: number }) => <S {...p}><circle cx="7" cy="7" r="3" /><circle cx="17" cy="7" r="3" /><circle cx="7" cy="17" r="3" /><circle cx="17" cy="17" r="3" /></S>;
export const IconSessions = (p: { size?: number }) => <S {...p}><path d="M4 6h16" /><path d="M4 12h16" /><path d="M4 18h10" /></S>;
export const IconSettings = (p: { size?: number }) => <S {...p}><circle cx="12" cy="12" r="3" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2" /></S>;
export const IconPlus = (p: { size?: number }) => <S {...p}><path d="M12 5v14M5 12h14" /></S>;
export const IconSend = (p: { size?: number }) => <S {...p}><path d="M12 19V5M5 12l7-7 7 7" /></S>;
export const IconChevronDown = (p: { size?: number }) => <S {...p}><path d="M6 9l6 6 6-6" /></S>;
export const IconSearch = (p: { size?: number }) => <S {...p}><circle cx="11" cy="11" r="7" /><path d="M21 21l-4-4" /></S>;
export const IconSpark = (p: { size?: number }) => <S {...p}><path d="M12 3v4M12 17v4M3 12h4M17 12h4M6 6l2.5 2.5M15.5 15.5L18 18M18 6l-2.5 2.5M8.5 15.5L6 18" /></S>;
export const IconBug = (p: { size?: number }) => <S {...p}><rect x="8" y="8" width="8" height="10" rx="4" /><path d="M9 4l1.5 2M15 4l-1.5 2M4 11h3M17 11h3M4 16h3M17 16h3" /></S>;
export const IconShield = (p: { size?: number }) => <S {...p}><path d="M12 3l7 3v6c0 4-3 7-7 9-4-2-7-5-7-9V6z" /></S>;

/** Hypervisor brand mark — concentric triangular glyph (original). */
export const BrandMark = ({ size = 18 }: { size?: number }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" aria-label="Hypervisor">
    <path d="M12 3l8 14H4z" />
    <path d="M12 9l4 7H8z" />
  </svg>
);
