export default function Logo({ className = "w-6 h-6" }: { className?: string }) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" className={className} viewBox="0 0 223.5778 227.83333">
      <defs>
        <linearGradient id="linear-gradient" x1="155.29379" y1="167.26686" x2="197.85381" y2="246.05421" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#5252be" />
          <stop offset="1" stopColor="#383892" />
        </linearGradient>
        <linearGradient id="linear-gradient1" x1="263.76199" y1="111.29733" x2="188.44299" y2="204.09308" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#787cff" />
          <stop offset="1" stopColor="#6c74f1" />
        </linearGradient>
        <linearGradient id="linear-gradient2" x1="141.93443" y1="52.544533" x2="239.77016" y2="132.4828" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#6c74f1" />
          <stop offset="1" stopColor="#3b3b96" />
        </linearGradient>
        <linearGradient id="linear-gradient3" x1="66.016029" y1="97.781639" x2="128.51045" y2="279.68903" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#4845b8" />
          <stop offset=".49" stopColor="#302e8c" />
          <stop offset="1" stopColor="#14124e" />
        </linearGradient>
        <linearGradient id="linear-gradient4" x1="36.166676" y1="89.93013" x2="147.95557" y2="89.93013" gradientUnits="userSpaceOnUse">
          <stop offset="0" stopColor="#0a0a3a" />
          <stop offset=".49" stopColor="#0c0c4a" />
          <stop offset="1" stopColor="#0a0a3a" />
        </linearGradient>
      </defs>
      <g transform="translate(-36.166659,-45.175329)">
        <polygon fill="url(#linear-gradient)" points="246.02223,215.89755 147.95556,171.23088 147.95556,273.00866 " />
        <polygon fill="url(#linear-gradient1)" points="256.80001,160.60125 249.02223,164.97162 246.02223,215.89755 147.95556,171.23088 259.74445,108.03644 " />
        <polygon fill="url(#linear-gradient2)" points="259.74445,108.03644 212.60415,134.68493 147.95556,98.230884 147.95556,45.175329 " />
      </g>
      <g transform="translate(-36.166659,-45.175329)">
        <polygon fill="url(#linear-gradient3)" points="46.888888,164.97165 49.888888,215.89756 147.95554,273.00864 147.95554,171.23087 36.166659,108.03641 39.111117,160.60123 " />
        <polygon fill="url(#linear-gradient4)" points="36.166674,108.03644 83.306976,134.68493 147.95556,98.230884 147.95556,45.175329 " />
      </g>
    </svg>
  );
}
