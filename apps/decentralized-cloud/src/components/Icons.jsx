// THE CONSOLE'S GLYPHS — drawn here, in currentColor, at one weight.
//
// A console's chrome is read by its glyphs before its words: the nine-dot services
// grid, the search lens, the terminal, the bell, the question mark, the gear, the
// hamburger, the info ring, the chevron. These are the product's own strokes, not a
// vendor's set; each is a 16-unit box, 1.6 stroke, round caps, so they sit on one
// baseline in the bar. Every one is aria-hidden: the button that carries it has the
// accessible name.
const base = { width: 16, height: 16, viewBox: "0 0 16 16", fill: "none", stroke: "currentColor",
  strokeWidth: 1.6, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": "true", focusable: "false" };

export const IconGrid = (p) => (
  <svg {...base} {...p} fill="currentColor" stroke="none">
    {[2, 8, 14].flatMap((y) => [2, 8, 14].map((x) => <circle key={`${x}${y}`} cx={x} cy={y} r="1.6" />))}
  </svg>
);
export const IconSearch = (p) => (
  <svg {...base} {...p}><circle cx="7" cy="7" r="4.5" /><path d="M 10.5 10.5 L 14 14" /></svg>
);
export const IconTerminal = (p) => (
  <svg {...base} {...p}><rect x="1.5" y="2.5" width="13" height="11" rx="1.5" /><path d="M4.5 6l2.5 2-2.5 2M8.5 10h3" /></svg>
);
export const IconBell = (p) => (
  <svg {...base} {...p}><path d="M4 11V7.5a4 4 0 0 1 8 0V11l1 1.5H3L4 11z" /><path d="M6.5 14a1.5 1.5 0 0 0 3 0" /></svg>
);
export const IconHelp = (p) => (
  <svg {...base} {...p}><circle cx="8" cy="8" r="6.5" /><path d="M6.2 6.3a1.9 1.9 0 1 1 2.7 1.7c-.6.3-.9.7-.9 1.3" /><circle cx="8" cy="11.6" r=".7" fill="currentColor" stroke="none" /></svg>
);
export const IconGear = (p) => (
  <svg {...base} {...p}><circle cx="8" cy="8" r="2.2" /><path d="M8 1.8v1.6M8 12.6v1.6M1.8 8h1.6M12.6 8h1.6M3.6 3.6l1.1 1.1M11.3 11.3l1.1 1.1M3.6 12.4l1.1-1.1M11.3 4.7l1.1-1.1" /></svg>
);
export const IconMenu = (p) => (
  <svg {...base} {...p}><path d="M2 4h12M2 8h12M2 12h12" /></svg>
);
export const IconInfo = (p) => (
  <svg {...base} {...p}><circle cx="8" cy="8" r="6.5" /><path d="M8 7.2v4" /><circle cx="8" cy="4.9" r=".7" fill="currentColor" stroke="none" /></svg>
);
export const IconChevron = (p) => (
  <svg {...base} {...p} width="12" height="12"><path d="M4 6l4 4 4-4" /></svg>
);
export const IconArrow = (p) => (
  <svg {...base} {...p} width="12" height="12"><path d="M3 8h10M9 4l4 4-4 4" /></svg>
);
export const IconClose = (p) => (
  <svg {...base} {...p}><path d="M4 4l8 8M12 4l-8 8" /></svg>
);

// ONE GLYPH PER SURFACE, for the navigation panel and the services grid. Same box,
// same stroke, so fifteen of them read as one set. Keyed by surface id.
const S = {
  home: <path d="M2.5 7.5L8 2.5l5.5 5v6h-4v-4h-3v4h-4z" />,
  job: <><path d="M8 13.5V4" /><path d="M4.5 7.5L8 4l3.5 3.5" /><path d="M3 13.5h10" /></>,
  receipts: <><path d="M4 2.5h8v11l-2-1.2-2 1.2-2-1.2-2 1.2z" /><path d="M6 6h4M6 8.5h4" /></>,
  redundancy: <><rect x="2" y="2" width="7" height="7" rx="1.2" /><rect x="7" y="7" width="7" height="7" rx="1.2" /></>,
  catalog: <><rect x="2" y="2" width="5" height="5" rx="1" /><rect x="9" y="2" width="5" height="5" rx="1" /><rect x="2" y="9" width="5" height="5" rx="1" /><rect x="9" y="9" width="5" height="5" rx="1" /></>,
  candidates: <><path d="M2.5 8.5l6-6h5v5l-6 6z" /><circle cx="10.5" cy="5.5" r=".9" fill="currentColor" stroke="none" /></>,
  placement: <><circle cx="8" cy="8" r="5.5" /><circle cx="8" cy="8" r="2" /><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2" /></>,
  storage: <><ellipse cx="8" cy="4" rx="5.5" ry="2" /><path d="M2.5 4v8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2V4" /><path d="M2.5 8c0 1.1 2.5 2 5.5 2s5.5-.9 5.5-2" /></>,
  network: <><circle cx="8" cy="8" r="6" /><path d="M2 8h12M8 2c2 2 2 10 0 12M8 2c-2 2-2 10 0 12" /></>,
  supply: <><path d="M2.5 6.5L4 3h8l1.5 3.5" /><path d="M2.5 6.5h11v7h-11z" /><path d="M6.5 13.5v-4h3v4" /></>,
  sources: <><path d="M1.5 8h3l1.5-4 2.5 8 1.5-4h4.5" /></>,
  spend: <><rect x="1.5" y="3.5" width="13" height="9" rx="1.5" /><path d="M1.5 6.5h13" /><path d="M4 10h3" /></>,
  iam: <><circle cx="6" cy="6" r="3.5" /><path d="M8.5 8.5L14 14M12 12l1.5-1.5M 10.5 10.5 L 12 9" /></>,
  api: <><path d="M5.5 3.5L2 8l3.5 4.5M 10.5 3.5 L 14 8l-3.5 4.5" /></>,
  settings: <><circle cx="8" cy="8" r="2.2" /><path d="M8 1.8v1.6M8 12.6v1.6M1.8 8h1.6M12.6 8h1.6M3.6 3.6l1.1 1.1M11.3 11.3l1.1 1.1M3.6 12.4l1.1-1.1M11.3 4.7l1.1-1.1" /></>,
};
export const SurfaceIcon = ({ id, ...p }) => <svg {...base} {...p}>{S[id] || <circle cx="8" cy="8" r="5" />}</svg>;
