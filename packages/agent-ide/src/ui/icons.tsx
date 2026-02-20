// packages/agent-ide/src/ui/icons.tsx
import React from "react";

type IconProps = React.SVGProps<SVGSVGElement>;

// Helper for consistent Lucide-style rendering
// Default to 1em to allow CSS scaling
const IconBase = ({ children, ...props }: IconProps) => (
  <svg 
    xmlns="http://www.w3.org/2000/svg" 
    width="1em" 
    height="1em" 
    viewBox="0 0 24 24" 
    fill="none" 
    stroke="currentColor" 
    strokeWidth="2" 
    strokeLinecap="round" 
    strokeLinejoin="round" 
    {...props}
  >
    {children}
  </svg>
);

// Helper for the Full Color Logo (Custom ViewBox)
const BrandLogo = (props: IconProps) => (
  <svg 
    xmlns="http://www.w3.org/2000/svg" 
    role="img" 
    viewBox="108.97 89.47 781.56 706.06" 
    width="1em" 
    height="1em"
    {...props}
  >
    <defs>
        <linearGradient id="linear-gradient" x1="295.299" x2="485.379" y1="544.373" y2="544.373" gradientUnits="userSpaceOnUse"><stop offset="0" stopColor="#3650c0"/><stop offset="1" stopColor="#346acf"/></linearGradient>
        <linearGradient id="linear-gradient1" x1="302.61" x2="697.39" y1="421.968" y2="421.968" gradientUnits="userSpaceOnUse"><stop offset="0" stopColor="#f7f8f7"/><stop offset="1" stopColor="#b0c6f4"/></linearGradient>
        <linearGradient id="linear-gradient2" x1="797.683" x2="797.683" y1="740.594" y2="425.085" gradientUnits="userSpaceOnUse"><stop offset=".201" stopColor="#3b5eda"/><stop offset="1" stopColor="#2740a8"/></linearGradient>
        <linearGradient id="linear-gradient3" x1="609.661" x2="609.661" y1="654.115" y2="434.631" gradientUnits="userSpaceOnUse"><stop offset="0" stopColor="#c8dcfd"/><stop offset="1" stopColor="#93bef8"/></linearGradient>
        <linearGradient id="linear-gradient4" x1="223.747" x2="392.673" y1="846.122" y2="694.02" gradientUnits="userSpaceOnUse"><stop offset="0" stopColor="#83a0e0"/><stop offset="1" stopColor="#5b86de"/></linearGradient>
        <linearGradient id="linear-gradient5" x1="518.726" x2="622.437" y1="314.342" y2="252.027" gradientUnits="userSpaceOnUse"><stop offset="0" stopColor="#759ce8"/><stop offset=".289" stopColor="#7198e5"/><stop offset=".548" stopColor="#688dde"/><stop offset=".795" stopColor="#587bd2"/><stop offset="1" stopColor="#4666c4"/></linearGradient>
        <linearGradient id="linear-gradient6" x1="202.317" x2="202.317" y1="740.594" y2="425.086" gradientUnits="userSpaceOnUse"><stop offset="0" stopColor="#d3d3df"/><stop offset=".531" stopColor="#e8e9ed"/><stop offset="1" stopColor="#f7f8f7"/></linearGradient>
        <linearGradient id="linear-gradient7" x1="688.68" x2="688.68" y1="780.741" y2="675.219" gradientUnits="userSpaceOnUse"><stop offset="0" stopColor="#5a8cec"/><stop offset="1" stopColor="#3b67d3"/></linearGradient>
        <linearGradient id="linear-gradient8" x1="389.872" x2="389.872" y1="414.066" y2="104.779" gradientUnits="userSpaceOnUse"><stop offset="0" stopColor="#f7f8f7"/><stop offset="1" stopColor="#b2c8f4"/></linearGradient>
        <linearGradient id="linear-gradient9" x1="401.305" x2="401.305" y1="780.741" y2="552.815" gradientUnits="userSpaceOnUse"><stop offset="0" stopColor="#75abf0"/><stop offset=".316" stopColor="#699aeb"/><stop offset=".936" stopColor="#4d6fe0"/><stop offset="1" stopColor="#4a6bdf"/></linearGradient>
        <linearGradient id="linear-gradient10" x1="598.695" x2="598.695" y1="780.741" y2="552.815" gradientUnits="userSpaceOnUse"><stop offset="0" stopColor="#bbd8f2"/><stop offset=".164" stopColor="#b3d3f1"/><stop offset=".413" stopColor="#9ec6ef"/><stop offset=".714" stopColor="#7cb0ed"/><stop offset="1" stopColor="#5698ea"/></linearGradient>
    </defs>
    <g>
        <path fill="url(#linear-gradient)" d="M295.299 434.631L295.299 654.116 485.379 544.373 295.299 434.631z"/>
        <path fill="url(#linear-gradient1)" d="M500 535.931L697.39 421.968 500 308.005 302.61 421.968 500 535.931z"/>
        <path fill="url(#linear-gradient2)" d="M719.322 662.557L854.487 740.594 876.043 695.903 719.322 425.085 719.322 662.557z"/>
        <path fill="url(#linear-gradient3)" d="M514.621 544.373L704.701 654.115 704.701 434.631 514.621 544.373z"/>
        <path fill="url(#linear-gradient4)" d="M287.988 675.22L151.883 753.8 164.878 780.741 470.757 780.741 287.988 675.22z"/>
        <path fill="url(#linear-gradient5)" d="M507.31 295.342L712.945 414.066 533.962 104.779 507.31 104.779 507.31 295.342z"/>
        <path fill="url(#linear-gradient6)" d="M280.678 662.557L280.678 425.086 123.957 695.903 145.513 740.594 280.678 662.557z"/>
        <path fill="url(#linear-gradient7)" d="M712.012 675.219L529.242 780.741 835.122 780.741 848.117 753.8 712.012 675.219z"/>
        <path fill="url(#linear-gradient8)" d="M492.689 295.343L492.689 104.779 466.038 104.779 287.055 414.066 492.689 295.343z"/>
        <g>
            <path fill="url(#linear-gradient9)" d="M302.61 666.778L500 780.741 500 780.741 500 552.815 302.61 666.778z"/>
            <path fill="url(#linear-gradient10)" d="M500 552.815L500 780.741 697.39 666.778 500 552.815z"/>
        </g>
    </g>
  </svg>
);

export const Icons = {
  // --- Brand ---
  Logo: BrandLogo,

  // --- Activity Bar Icons ---
  Brain: (props: IconProps) => (
    <IconBase {...props}>
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z" />
    </IconBase>
  ),

  Action: (props: IconProps) => (
    <IconBase {...props}>
      <circle cx="18" cy="18" r="3" />
      <circle cx="6" cy="6" r="3" />
      <path d="M6 21V9a9 9 0 0 0 9 9" />
    </IconBase>
  ),

  Folder: (props: IconProps) => (
    <IconBase {...props}>
      <path d="M6 2 3 6v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V6l-3-4Z" />
      <path d="M3 6h18" />
      <path d="M16 10a4 4 0 0 1-8 0" />
    </IconBase>
  ),

  Trigger: (props: IconProps) => (
    <IconBase {...props}>
      <rect width="20" height="8" x="2" y="2" rx="2" ry="2" />
      <rect width="20" height="8" x="2" y="14" rx="2" ry="2" />
      <line x1="6" x2="6.01" y1="6" y2="6" />
      <line x1="6" x2="6.01" y1="18" y2="18" />
    </IconBase>
  ),

  Plug: (props: IconProps) => (
    <IconBase {...props}>
      <path d="M12 3v6" />
      <path d="M16 3v6" />
      <path d="M9 9h10a1 1 0 0 1 1 1v1a6 6 0 0 1-6 6h-1v4" />
      <path d="M6 12h3" />
    </IconBase>
  ),

  Mail: (props: IconProps) => (
    <IconBase {...props}>
      <rect x="3" y="5" width="18" height="14" rx="2" />
      <path d="m3 7 9 6 9-6" />
    </IconBase>
  ),

  Cards: (props: IconProps) => (
    <IconBase {...props}>
      <rect x="3" y="11" width="18" height="10" rx="2" />
      <circle cx="12" cy="5" r="2" />
      <path d="M12 7v4" />
    </IconBase>
  ),

  Settings: (props: IconProps) => (
    <IconBase {...props}>
      <path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" />
      <circle cx="12" cy="12" r="3" />
    </IconBase>
  ),

  Record: (props: IconProps) => (
    <IconBase {...props} fill={props.fill || "none"}>
      <circle cx="12" cy="12" r="6" />
    </IconBase>
  ),

  // --- UI Utilities ---
  Play: (props: IconProps) => <IconBase {...props} style={{fill: 'currentColor', stroke: 'none'}}><polygon points="5 3 19 12 5 21 5 3"/></IconBase>,
  Pause: (props: IconProps) => <IconBase {...props} style={{fill: 'currentColor', stroke: 'none'}}><rect x="6" y="4" width="4" height="16"/><rect x="14" y="4" width="4" height="16"/></IconBase>,
  Stop: (props: IconProps) => <IconBase {...props} style={{fill: 'currentColor', stroke: 'none'}}><rect x="4" y="4" width="16" height="16"/></IconBase>,
  
  Plus: (props: IconProps) => <IconBase {...props}><path d="M5 12h14"/><path d="M12 5v14"/></IconBase>,
  Trash: (props: IconProps) => <IconBase {...props}><path d="M3 6h18"/><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6"/><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2"/></IconBase>,
  ChevronDown: (props: IconProps) => <IconBase {...props}><path d="m6 9 6 6 6-6"/></IconBase>,
  
  // Gate (Shield)
  Gate: (props: IconProps) => <IconBase {...props}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></IconBase>,
  
  // File System
  File: (props: IconProps) => <IconBase {...props}><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/></IconBase>,
};
