import { useLayoutEffect, useRef } from "react";
import integrationsSvgRaw from "../../../assets/icons/integrations.svg?raw";

const integrationsSvgMarkup = integrationsSvgRaw.replace(
  "<svg ",
  '<svg width="34" height="34" aria-hidden="true" focusable="false" ',
).replace(
  /fill="#363236"/g,
  'fill="currentColor"',
);

export const HypervisorIcon = () => (
  <svg width="24" height="24" viewBox="0 0 64 64" fill="none">
    <path
      d="M10 50V42C10 40.9 9.1 40 8 40H7C5.34 40 4 38.66 4 37V13.5C4 11.84 5.34 10.5 7 10.5H31"
      stroke="currentColor"
      strokeWidth="4.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <path
      d="M47 25.5V37C47 38.66 45.66 40 44 40H20L10 50"
      stroke="currentColor"
      strokeWidth="4.5"
      strokeLinecap="round"
      strokeLinejoin="round"
    />
    <path d="M43 -1L45.25 5.75L52 8L45.25 10.25L43 17L40.75 10.25L34 8L40.75 5.75Z" fill="currentColor" />
    <path d="M53 11.5L54.8 15.7L59 17.5L54.8 19.3L53 23.5L51.2 19.3L47 17.5L51.2 15.7Z" fill="currentColor" />
  </svg>
);

export const SparklesIcon = () => (
  <svg
    width="20"
    height="20"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    aria-hidden="true"
  >
    <path d="M3.75 3.75H20.25V18.25H15.0155L11.9979 20.75L9.0155 18.25H3.75V3.75Z" />
    <path
      d="M8.00195 11.5714C9.32109 11.5714 10.1405 11.8633 10.6396 12.3624C11.1386 12.8615 11.4305 13.6809 11.4305 15H12.5734C12.5734 13.6809 12.8653 12.8615 13.3643 12.3624C13.8634 11.8633 14.6828 11.5714 16.002 11.5714V10.4286C14.6828 10.4286 13.8634 10.1367 13.3643 9.63761C12.8653 9.13853 12.5734 8.31913 12.5734 7H11.4305C11.4305 8.31913 11.1386 9.13853 10.6396 9.63761C10.1405 10.1367 9.32109 10.4286 8.00195 10.4286V11.5714Z"
      fill="currentColor"
      stroke="none"
    />
  </svg>
);

export const HomeIcon = () => (
  <svg
    width="20"
    height="20"
    viewBox="0 0 24 24"
    fill="none"
    aria-hidden="true"
  >
    <path
      d="M3.75 9L3.27507 8.41953L3 8.64459V9H3.75ZM20.25 9H21V8.64459L20.7249 8.41953L20.25 9ZM20.25 20.25V21H21V20.25H20.25ZM3.75 20.25H3V21H3.75V20.25ZM12 2.25L12.4749 1.66953L12 1.28095L11.5251 1.66953L12 2.25ZM9.75 14.75V14H9V14.75H9.75ZM14.25 14.75H15V14H14.25V14.75ZM14.25 20.25H13.5V21H14.25V20.25ZM9.75 20.25V21H10.5V20.25H9.75ZM19.5 9V20.25H21V9H19.5ZM4.5 20.25V9H3V20.25H4.5ZM4.22493 9.58047L12.4749 2.83047L11.5251 1.66953L3.27507 8.41953L4.22493 9.58047ZM11.5251 2.83047L19.7751 9.58047L20.7249 8.41953L12.4749 1.66953ZM9.75 15.5H14.25V14H9.75V15.5ZM13.5 14.75V20.25H15V14.75H13.5ZM10.5 20.25V14.75H9V20.25H10.5ZM9.75 19.5H3.75V21H9.75V19.5ZM14.25 21H20.25V19.5H14.25V21Z"
      fill="currentColor"
    />
  </svg>
);

export const SearchIcon = () => (
  <svg
    width="18"
    height="18"
    viewBox="0 0 20 20"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.7"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <circle cx="8.5" cy="8.5" r="5.5" />
    <path d="m12.6 12.6 4 4" />
  </svg>
);

export const AtlasIcon = () => (
  <svg
    width="22"
    height="22"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <circle cx="12" cy="12" r="1.9" />
    <circle cx="6" cy="6" r="1.6" />
    <circle cx="18" cy="6" r="1.6" />
    <circle cx="6" cy="18" r="1.6" />
    <circle cx="18" cy="18" r="1.6" />
    <path d="M12 10.2L6.9 7.1M13.8 10.1L17 7.7M10.2 13.8L7.2 17M13.8 13.8L16.8 17" />
    <path d="M7.6 6h8.8M7.6 18h8.8" />
  </svg>
);

export const ComposeIcon = () => (
  <svg
    width="20"
    height="20"
    viewBox="0 0 16 16"
    fill="none"
    stroke="currentColor"
    strokeWidth="1"
    strokeLinecap="round"
    strokeLinejoin="round"
    aria-hidden="true"
  >
    <path d="M5.02832 5.99854L5.77832 6.49854L7.02608 4.83487M9.03831 5.66671H11.0383M5.02832 10.4993L5.77832 10.9993L7.02608 9.33562M13.6663 7.33337V2.33337H2.33301V13.6667H8.1649" />
    <path d="M11.333 7.81653L10.333 9.81653L8.33301 10.8165L10.333 11.8165L11.333 13.8165L12.333 11.8165L14.333 10.8165L12.333 9.81653L11.333 7.81653Z" />
  </svg>
);

export const ChatLogoIcon = () => (
  <svg
    width="24"
    height="24"
    viewBox="108.97 89.47 781.56 706.06"
    fill="none"
    aria-hidden="true"
  >
    <g
      stroke="currentColor"
      strokeWidth="12"
      strokeLinejoin="round"
      strokeLinecap="round"
    >
      <path d="M295.299 434.631L295.299 654.116 485.379 544.373z" />
      <path d="M500 535.931L697.39 421.968 500 308.005 302.61 421.968z" />
      <path d="M514.621 544.373L704.701 654.115 704.701 434.631z" />
      <path d="M280.678 662.557L280.678 425.086 123.957 695.903 145.513 740.594z" />
      <path d="M719.322 662.557L854.487 740.594 876.043 695.903 719.322 425.085z" />
      <path d="M287.988 675.22L151.883 753.8 164.878 780.741 470.757 780.741 287.988 675.22z" />
      <path d="M712.012 675.219L529.242 780.741 835.122 780.741 848.117 753.8 712.012 675.219z" />
      <path d="M492.689 295.343L492.689 104.779 466.038 104.779 287.055 414.066z" />
      <path d="M507.31 295.342L712.945 414.066 533.962 104.779 507.31 104.779z" />
      <path d="M302.61 666.778L500 780.741 500 552.815z" />
      <path d="M500 552.815L500 780.741 697.39 666.778z" />
    </g>
  </svg>
);


export const ExplorerIcon = () => (
  <svg
    width="18"
    height="22"
    viewBox="0 0 26 34"
    fill="none"
  >
    <path
      d="m0.29 5.38v27.22c0 0.44 0.38 0.75 0.74 0.75h19.15c0.47 0 0.7-0.46 0.7-0.75v-1.59h-16.92c-0.6 0-1.03-0.73-1.03-1.17v-25.03h-2.01c-0.4 0-0.63 0.4-0.63 0.57z"
      fill="currentColor"
      opacity="0.5"
    />
    <path
      d="m19.39 7.88c-0.66 0-0.98-0.52-0.98-1.09v-6.03h-13.1c-0.47 0-0.84 0.46-0.84 0.82v27.18c0 0.62 0.48 0.95 0.97 0.95h19.41c0.59 0 0.94-0.45 0.94-0.89v-20.94h-6.4zm-2.38 16.73h-9.44c-0.41 0-0.65-0.35-0.65-0.7 0-0.36 0.24-0.65 0.65-0.65h12.88c0.41 0 0.66 0.32 0.66 0.67 0 0.34-0.23 0.68-0.66 0.68h-3.44zm0-4.95h-9.32c-0.41 0-0.65-0.35-0.65-0.67 0-0.35 0.24-0.65 0.65-0.65h12.76c0.41 0 0.66 0.32 0.66 0.66 0 0.35-0.23 0.66-0.66 0.66h-3.44zm0-4.65h-9.38c-0.41 0-0.65-0.35-0.65-0.67 0-0.36 0.24-0.62 0.65-0.62h12.82c0.41 0 0.6 0.29 0.6 0.64 0 0.34-0.23 0.65-0.6 0.65h-3.44zm0-4.89h-9.52c-0.41 0-0.68-0.34-0.68-0.66 0-0.35 0.3-0.65 0.68-0.65h9.45c0.41 0 0.68 0.3 0.68 0.62 0 0.35-0.24 0.69-0.61 0.69z"
      fill="currentColor"
    />
    <path
      d="m20.01 1.61v4.68h4.69l-4.69-4.68z"
      fill="currentColor"
      opacity="0.7"
    />
  </svg>
);

export const AgentsIcon = () => (
  <svg
    width="22"
    height="22"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <rect x="4" y="4" width="16" height="12" rx="2" />
    <path d="M9 9h0M15 9h0" strokeWidth="2.5" />
    <path d="M9 20l3-4 3 4" />
  </svg>
);

export const EnvironmentIcon = () => (
  <svg
    width="20"
    height="20"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    aria-hidden="true"
  >
    <path d="M12 12.75H19.2463C19.2488 12.833 19.25 12.9164 19.25 13C19.25 17.5563 15.5563 21.25 11 21.25C6.44365 21.25 2.75 17.5563 2.75 13C2.75 8.44365 6.44365 4.75 11 4.75C11.0836 4.75 11.167 4.75124 11.25 4.75371V12V12.75H12ZM14.75 2.7889C15.4447 2.86115 16.1267 3.03357 16.7745 3.30187C17.6541 3.66622 18.4533 4.20025 19.1265 4.87348C19.7997 5.5467 20.3338 6.34594 20.6981 7.22555C20.9664 7.87328 21.1388 8.55527 21.2111 9.25L14.75 9.25V2.7889Z" />
  </svg>
);

export const ProjectsIcon = () => (
  <svg
    width="20"
    height="20"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    strokeLinecap="round"
    aria-hidden="true"
  >
    <path d="M3.75 3.75H10.25V10.25H3.75V3.75Z" />
    <path d="M13.75 3.75H20.25V10.25H13.75V3.75Z" />
    <path d="M3.75 13.75H10.25V20.25H3.75V13.75Z" />
    <path d="M13.75 13.75H20.25V20.25H13.75V13.75Z" />
  </svg>
);

export const SessionsFilterIcon = () => (
  <svg
    width="18"
    height="18"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.5"
    strokeLinecap="square"
    aria-hidden="true"
  >
    <rect x="3.75" y="3.75" width="6.5" height="6.5" />
    <rect x="3.75" y="13.75" width="6.5" height="6.5" />
    <path d="M14.75 7.5L18 4L21.25 7.5" />
    <path d="M21.25 16.5L18 20L14.75 16.5" />
    <path d="M18 4.5V19.5" />
  </svg>
);

export const MountsIcon = () => (
  <svg
    width="22"
    height="22"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M12 4.5 7.5 10h9L12 4.5Z" />
    <path d="M7 13h10" />
    <path d="M5 16.5h14" />
    <path d="M6.5 19.5h11" />
    <path d="M5 16.5 3.8 20.3a1 1 0 0 0 1 1.2h14.4a1 1 0 0 0 1-1.2L19 16.5" />
  </svg>
);

export const WorkspaceIcon = () => (
  <svg
    width="22"
    height="22"
    viewBox="0 0 20 20"
    aria-hidden="true"
  >
    <defs>
      <linearGradient id="workspace-panel" x1="78%" y1="115%" x2="19%" y2="-3%">
        <stop offset="0%" stopColor="#E1E8ED" />
        <stop offset="56.8%" stopColor="#EAF0F3" />
        <stop offset="100%" stopColor="#F5F8FA" />
      </linearGradient>
      <linearGradient id="workspace-border" x1="0%" y1="0%" x2="0%" y2="100%">
        <stop offset="0%" stopColor="#BFCCD6" />
        <stop offset="100%" stopColor="#A7B6C2" />
      </linearGradient>
      <linearGradient id="workspace-glyph" x1="0%" y1="0%" x2="0%" y2="100%">
        <stop offset="0%" stopColor="#5C7080" />
        <stop offset="100%" stopColor="#394B59" />
      </linearGradient>
    </defs>
    <rect x="2" y="3.25" width="16" height="13.5" rx="1.6" fill="url(#workspace-panel)" />
    <rect x="2.5" y="3.75" width="15" height="0.5" fill="#FFFFFF" opacity="0.6" />
    <rect
      x="2"
      y="3.25"
      width="16"
      height="13.5"
      rx="1.6"
      fill="none"
      stroke="url(#workspace-border)"
      strokeWidth="0.6"
    />
    <path
      fill="url(#workspace-glyph)"
      d="M7.653 7.575a.665.665 0 0 0-1.14.684L7.557 10l-1.044 1.741a.666.666 0 0 0 1.14.685l1.25-2.083a.67.67 0 0 0 0-.685z"
    />
    <path
      fill="url(#workspace-glyph)"
      d="M10.833 11.418a.665.665 0 0 0 0 1.33h2.5a.665.665 0 0 0 0-1.33z"
    />
  </svg>
);

export const CatalogIcon = () => (
  <svg
    width="22"
    height="22"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <circle cx="12" cy="12" r="10" />
    <path d="M2 12h20" />
    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10A15.3 15.3 0 0 1 12 2z" />
  </svg>
);

export const NotificationsIcon = () => (
  <svg
    width="22"
    height="22"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M6 9a6 6 0 1 1 12 0c0 6 2.5 7 2.5 7h-17S6 15 6 9" />
    <path d="M10 19a2 2 0 0 0 4 0" />
  </svg>
);

interface IntegrationsIconProps {
  disableHoverAnimation?: boolean;
}

export const IntegrationsIcon = ({ disableHoverAnimation = false }: IntegrationsIconProps) => (
  <IntegrationsAnimatedIcon disableHoverAnimation={disableHoverAnimation} />
);

function parseSmilDurationSeconds(raw: string | null): number | null {
  if (!raw) return null;
  const trimmed = raw.trim();
  if (trimmed.endsWith("ms")) {
    const ms = Number.parseFloat(trimmed.slice(0, -2));
    return Number.isFinite(ms) && ms > 0 ? ms / 1000 : null;
  }
  if (trimmed.endsWith("s")) {
    const seconds = Number.parseFloat(trimmed.slice(0, -1));
    return Number.isFinite(seconds) && seconds > 0 ? seconds : null;
  }
  const numeric = Number.parseFloat(trimmed);
  return Number.isFinite(numeric) && numeric > 0 ? numeric : null;
}

function splitSmilList(raw: string | null): string[] {
  if (!raw) return [];
  return raw.split(";").map((part) => part.trim()).filter(Boolean);
}

function formatSmilSeconds(seconds: number): string {
  return `${Number(seconds.toFixed(3))}s`;
}

function reduceAnimationToSingleQuarterStep(animation: SVGAnimationElement): void {
  const type = animation.getAttribute("type");
  const pointsPerQuarter = type === "rotate" ? 3 : type === "translate" ? 4 : null;
  if (!pointsPerQuarter) return;

  const keyTimes = splitSmilList(animation.getAttribute("keyTimes"));
  const values = splitSmilList(animation.getAttribute("values"));
  const keySplines = splitSmilList(animation.getAttribute("keySplines"));

  if (keyTimes.length < pointsPerQuarter || values.length < pointsPerQuarter) return;

  const quarterTimes = keyTimes.slice(0, pointsPerQuarter).map((value) => Number.parseFloat(value));
  const quarterEnd = quarterTimes[quarterTimes.length - 1];
  if (!Number.isFinite(quarterEnd) || quarterEnd <= 0) return;

  const normalizedTimes = quarterTimes.map((time, index) => {
    if (index === 0) return "0";
    if (index === quarterTimes.length - 1) return "1";
    return `${Number((time / quarterEnd).toFixed(6))}`;
  });

  animation.setAttribute("keyTimes", normalizedTimes.join("; "));
  animation.setAttribute("values", values.slice(0, pointsPerQuarter).join("; "));

  const segmentCount = pointsPerQuarter - 1;
  if (keySplines.length >= segmentCount) {
    animation.setAttribute("keySplines", keySplines.slice(0, segmentCount).join("; "));
  }

  const duration = parseSmilDurationSeconds(animation.getAttribute("dur"));
  if (duration) {
    animation.setAttribute("dur", formatSmilSeconds(duration * quarterEnd));
  }

}

function IntegrationsAnimatedIcon({ disableHoverAnimation }: { disableHoverAnimation: boolean }) {
  const ref = useRef<HTMLSpanElement | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const pauseTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const cycleDurationSecondsRef = useRef(7);
  const hoverAnimationArmedRef = useRef(true);

  const clearPendingPause = () => {
    if (!pauseTimerRef.current) return;
    clearTimeout(pauseTimerRef.current);
    pauseTimerRef.current = null;
  };

  const supportsSmilAnimationControl = (
    svg: SVGSVGElement,
  ): svg is SVGSVGElement & {
    pauseAnimations: () => void;
    unpauseAnimations: () => void;
    animationsPaused: () => boolean;
    getCurrentTime: () => number;
    setCurrentTime: (seconds: number) => void;
  } => {
    return (
      typeof (svg as { pauseAnimations?: unknown }).pauseAnimations === "function" &&
      typeof (svg as { unpauseAnimations?: unknown }).unpauseAnimations === "function" &&
      typeof (svg as { animationsPaused?: unknown }).animationsPaused === "function" &&
      typeof (svg as { getCurrentTime?: unknown }).getCurrentTime === "function" &&
      typeof (svg as { setCurrentTime?: unknown }).setCurrentTime === "function"
    );
  };

  useLayoutEffect(() => {
    const svg = ref.current?.querySelector("svg");
    if (!svg) return;
    svgRef.current = svg as SVGSVGElement;
    hoverAnimationArmedRef.current = !(ref.current?.matches(":hover") ?? false);

    const animations = svg.querySelectorAll<SVGAnimationElement>(
      'animateTransform[type="rotate"], animateTransform[type="translate"]',
    );
    animations.forEach(reduceAnimationToSingleQuarterStep);

    const firstAnimatedNode = svg.querySelector<SVGAnimationElement>("[dur]");
    const parsedDuration = parseSmilDurationSeconds(firstAnimatedNode?.getAttribute("dur") ?? null);
    cycleDurationSecondsRef.current = parsedDuration ?? 7;
    if (supportsSmilAnimationControl(svg)) {
      svg.pauseAnimations();
      svg.setCurrentTime(0);
    }
    return () => {
      clearPendingPause();
      svgRef.current = null;
    };
  }, []);

  useLayoutEffect(() => {
    if (!disableHoverAnimation) return;
    const svg = svgRef.current;
    if (!svg || !supportsSmilAnimationControl(svg)) return;
    if (svg.animationsPaused()) {
      clearPendingPause();
      return;
    }
    schedulePauseAtCycleBoundary();
  }, [disableHoverAnimation]);

  const schedulePauseAtCycleBoundary = () => {
    const svg = svgRef.current;
    if (!svg || !supportsSmilAnimationControl(svg)) return;
    clearPendingPause();

    const cycle = cycleDurationSecondsRef.current;
    const now = svg.getCurrentTime();
    const phase = ((now % cycle) + cycle) % cycle;
    const remainingSeconds = cycle - phase || cycle;
    const remainingMs = Math.max(0, Math.round(remainingSeconds * 1000));
    const targetTime = now + remainingSeconds;

    pauseTimerRef.current = setTimeout(() => {
      svg.pauseAnimations();
      svg.setCurrentTime(targetTime);
      pauseTimerRef.current = null;
    }, remainingMs);
  };

  const handleEnter = () => {
    if (disableHoverAnimation) return;
    if (!hoverAnimationArmedRef.current) return;
    const svg = svgRef.current;
    if (!svg || !supportsSmilAnimationControl(svg)) return;
    svg.unpauseAnimations();
    schedulePauseAtCycleBoundary();
  };

  const handleLeave = () => {
    hoverAnimationArmedRef.current = true;
    // One step per hover: let the enter-scheduled pause finish this cycle.
  };

  return (
    <span
      ref={ref}
      aria-hidden="true"
      onMouseEnter={handleEnter}
      onMouseLeave={handleLeave}
      style={{
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        width: "100%",
        height: "100%",
      }}
      dangerouslySetInnerHTML={{ __html: integrationsSvgMarkup }}
    />
  );
}

export const ShieldIcon = () => (
  <svg
    width="22"
    height="22"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M12 21s7-3.5 7-8.8V5.8L12 3 5 5.8v6.4C5 17.5 12 21 12 21z" />
    <path d="m9.5 11.5 1.8 1.8 3.4-3.8" />
  </svg>
);

export const SettingsIcon = () => (
  <svg
    width="20"
    height="20"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="1.8"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
  </svg>
);
