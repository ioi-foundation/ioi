import React from "react";

export function Logo({ className, style }: { className?: string; style?: React.CSSProperties }) {
  // Using a prefix for IDs to avoid collisions if multiple logos are rendered
  const idPrefix = React.useId ? React.useId().replace(/:/g, "") : "logo-" + Math.random().toString(36).substr(2, 9);

  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 1000 1000"
      className={className}
      style={style}
    >
      <defs>
        <linearGradient id={`${idPrefix}-lg1`} x1="295.3" y1="544.4" x2="485.4" y2="544.4" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#3650c0" />
          <stop offset="1" stopColor="#5a8cec" />
        </linearGradient>
        <linearGradient id={`${idPrefix}-lg2`} x1="302.6" y1="422" x2="697.4" y2="422" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#edf2fd" />
          <stop offset="1" stopColor="#93bef8" />
        </linearGradient>
        <linearGradient id={`${idPrefix}-lg3`} x1="797.7" y1="740.6" x2="797.7" y2="425.1" gradientUnits="userSpaceOnUse">
          <stop offset=".2" stopColor="#2740a8" />
          <stop offset="1" stopColor="#3b5eda" />
        </linearGradient>
        <linearGradient id={`${idPrefix}-lg4`} x1="609.7" y1="654.1" x2="609.7" y2="434.6" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#93bef8" />
          <stop offset="1" stopColor="#759ce8" />
        </linearGradient>
        <linearGradient id={`${idPrefix}-lg5`} x1="223.7" y1="846.1" x2="392.7" y2="694" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#5a8cec" />
          <stop offset="1" stopColor="#93bef8" />
        </linearGradient>
        <linearGradient id={`${idPrefix}-lg6`} x1="518.7" y1="314.3" x2="622.4" y2="252" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#759ce8" />
          <stop offset=".29" stopColor="#93bef8" />
          <stop offset=".55" stopColor="#5a8cec" />
          <stop offset=".8" stopColor="#3650c0" />
          <stop offset="1" stopColor="#2740a8" />
        </linearGradient>
        <linearGradient id={`${idPrefix}-lg7`} x1="202.3" y1="740.6" x2="202.3" y2="425.1" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#c8dcfd" />
          <stop offset=".53" stopColor="#e8e9ed" />
          <stop offset="1" stopColor="#edf2fd" />
        </linearGradient>
        <linearGradient id={`${idPrefix}-lg8`} x1="688.7" y1="780.7" x2="688.7" y2="675.2" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#5a8cec" />
          <stop offset="1" stopColor="#3b5eda" />
        </linearGradient>
        <linearGradient id={`${idPrefix}-lg9`} x1="389.9" y1="414.1" x2="389.9" y2="104.8" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#edf2fd" />
          <stop offset="1" stopColor="#c8dcfd" />
        </linearGradient>
        <linearGradient id={`${idPrefix}-lg10`} x1="401.3" y1="780.7" x2="401.3" y2="552.8" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#3b5eda" />
          <stop offset=".32" stopColor="#5a8cec" />
          <stop offset=".94" stopColor="#93bef8" />
          <stop offset="1" stopColor="#c8dcfd" />
        </linearGradient>
        <linearGradient id={`${idPrefix}-lg11`} x1="598.7" y1="780.7" x2="598.7" y2="552.8" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#3650c0" />
          <stop offset=".16" stopColor="#5a8cec" />
          <stop offset=".41" stopColor="#93bef8" />
          <stop offset=".71" stopColor="#c8dcfd" />
          <stop offset="1" stopColor="#edf2fd" />
        </linearGradient>
      </defs>
      <g>
        <polygon fill={`url(#${idPrefix}-lg1)`} points="295.3 434.6 295.3 654.1 485.4 544.4 295.3 434.6"/>
        <polygon fill={`url(#${idPrefix}-lg2)`} points="500 535.9 697.4 422 500 308 302.6 422 500 535.9"/>
        <polygon fill={`url(#${idPrefix}-lg3)`} points="719.3 662.6 854.5 740.6 876 695.9 719.3 425.1 719.3 662.6"/>
        <polygon fill={`url(#${idPrefix}-lg4)`} points="514.6 544.4 704.7 654.1 704.7 434.6 514.6 544.4"/>
        <polygon fill={`url(#${idPrefix}-lg5)`} points="288 675.2 151.9 753.8 164.9 780.7 470.8 780.7 288 675.2"/>
        <polygon fill={`url(#${idPrefix}-lg6)`} points="507.3 295.3 712.9 414.1 534 104.8 507.3 104.8 507.3 295.3"/>
        <polygon fill={`url(#${idPrefix}-lg7)`} points="280.7 662.6 280.7 425.1 124 695.9 145.5 740.6 280.7 662.6"/>
        <polygon fill={`url(#${idPrefix}-lg8)`} points="712 675.2 529.2 780.7 835.1 780.7 848.1 753.8 712 675.2"/>
        <polygon fill={`url(#${idPrefix}-lg9)`} points="492.7 295.3 492.7 104.8 466 104.8 287.1 414.1 492.7 295.3"/>
        <g>
          <polygon fill={`url(#${idPrefix}-lg10)`} points="302.6 666.8 500 780.7 500 780.7 500 552.8 302.6 666.8"/>
          <polygon fill={`url(#${idPrefix}-lg11)`} points="500 552.8 500 780.7 697.4 666.8 500 552.8"/>
        </g>
      </g>
    </svg>
  );
}
