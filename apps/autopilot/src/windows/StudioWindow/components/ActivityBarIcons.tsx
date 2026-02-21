import { useLayoutEffect, useRef } from "react";
import integrationsSvgRaw from "../../../assets/icons/integrations.svg?raw";

const integrationsSvgMarkup = integrationsSvgRaw.replace(
  "<svg ",
  '<svg width="34" height="34" aria-hidden="true" focusable="false" ',
).replace(
  /fill="#363236"/g,
  'fill="currentColor"',
);

export const AutopilotIcon = () => (
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

export const ComposeIcon = () => (
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
    <circle cx="12" cy="12" r="2.5" />
    <circle cx="6" cy="6" r="1.8" />
    <circle cx="18" cy="6" r="1.8" />
    <circle cx="6" cy="18" r="1.8" />
    <circle cx="18" cy="18" r="1.8" />
    <path d="M12 9.5V7.8M12 14.5V16.2M9.5 12H7.8M14.5 12H16.2M10 10L7.8 7.8M14 10L16.2 7.8M10 14L7.8 16.2M14 14L16.2 16.2" />
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

export const FleetIcon = () => (
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
    <rect x="3" y="3" width="7" height="7" rx="1.5" />
    <rect x="14" y="3" width="7" height="7" rx="1.5" />
    <rect x="3" y="14" width="7" height="7" rx="1.5" />
    <rect x="14" y="14" width="7" height="7" rx="1.5" />
  </svg>
);

export const MarketplaceIcon = () => (
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
    svg.pauseAnimations();
    svg.setCurrentTime(0);
    return () => {
      clearPendingPause();
      svgRef.current = null;
    };
  }, []);

  useLayoutEffect(() => {
    if (!disableHoverAnimation) return;
    const svg = svgRef.current;
    if (!svg) return;
    if (svg.animationsPaused()) {
      clearPendingPause();
      return;
    }
    schedulePauseAtCycleBoundary();
  }, [disableHoverAnimation]);

  const schedulePauseAtCycleBoundary = () => {
    const svg = svgRef.current;
    if (!svg) return;
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
    if (!svg) return;
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

export const GhostIcon = () => (
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
    <circle cx="12" cy="12" r="4" fill="currentColor" stroke="none" />
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
