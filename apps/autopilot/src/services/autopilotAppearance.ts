export type AutopilotThemeId =
  | "dark-modern"
  | "light-modern"
  | "dark-high-contrast"
  | "light-high-contrast";

export type AutopilotDensity = "default" | "compact";

export interface AutopilotAppearanceState {
  themeId: AutopilotThemeId;
  density: AutopilotDensity;
  updatedAtMs: number;
}

export interface AutopilotThemeOption {
  id: AutopilotThemeId;
  label: string;
  description: string;
  openVsCodeColorTheme: string;
  sourceMedia: string;
}

const STORAGE_KEY = "autopilot.appearance.v1";
const APPEARANCE_EVENT = "autopilot-appearance-updated";

export const AUTOPILOT_THEME_OPTIONS: AutopilotThemeOption[] = [
  {
    id: "dark-modern",
    label: "Dark Modern",
    description: "Quiet dark surfaces with workbench-grade contrast.",
    openVsCodeColorTheme: "Default Dark Modern",
    sourceMedia: "dark.png",
  },
  {
    id: "light-modern",
    label: "Light Modern",
    description: "The light OpenVSCode setup baseline, adapted for Autopilot.",
    openVsCodeColorTheme: "Default Light Modern",
    sourceMedia: "light.png",
  },
  {
    id: "dark-high-contrast",
    label: "Dark High Contrast",
    description: "High contrast dark mode for stronger boundaries.",
    openVsCodeColorTheme: "Default High Contrast",
    sourceMedia: "dark-hc.png",
  },
  {
    id: "light-high-contrast",
    label: "Light High Contrast",
    description: "High contrast light mode for accessible review work.",
    openVsCodeColorTheme: "Default High Contrast Light",
    sourceMedia: "light-hc.png",
  },
];

const DEFAULT_APPEARANCE: AutopilotAppearanceState = {
  themeId: "light-modern",
  density: "default",
  updatedAtMs: 0,
};

function hasBrowserStorage(): boolean {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
}

function isThemeId(value: unknown): value is AutopilotThemeId {
  return AUTOPILOT_THEME_OPTIONS.some((option) => option.id === value);
}

function isDensity(value: unknown): value is AutopilotDensity {
  return value === "default" || value === "compact";
}

export function getAutopilotThemeOption(
  themeId: AutopilotThemeId,
): AutopilotThemeOption {
  return (
    AUTOPILOT_THEME_OPTIONS.find((option) => option.id === themeId) ??
    AUTOPILOT_THEME_OPTIONS[0]
  );
}

export function loadAutopilotAppearance(): AutopilotAppearanceState {
  if (!hasBrowserStorage()) {
    return { ...DEFAULT_APPEARANCE };
  }

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return { ...DEFAULT_APPEARANCE };
    }
    const parsed = JSON.parse(raw) as Partial<AutopilotAppearanceState>;
    return {
      themeId: isThemeId(parsed.themeId)
        ? parsed.themeId
        : DEFAULT_APPEARANCE.themeId,
      density: isDensity(parsed.density)
        ? parsed.density
        : DEFAULT_APPEARANCE.density,
      updatedAtMs:
        typeof parsed.updatedAtMs === "number"
          ? parsed.updatedAtMs
          : DEFAULT_APPEARANCE.updatedAtMs,
    };
  } catch {
    return { ...DEFAULT_APPEARANCE };
  }
}

export function applyAutopilotAppearance(
  appearance: AutopilotAppearanceState = loadAutopilotAppearance(),
): void {
  if (typeof document === "undefined") {
    return;
  }

  document.documentElement.dataset.autopilotTheme = appearance.themeId;
  document.documentElement.dataset.autopilotDensity = appearance.density;
  document.documentElement.style.colorScheme = appearance.themeId.includes("light")
    ? "light"
    : "dark";
}

export function saveAutopilotAppearance(
  patch: Partial<Omit<AutopilotAppearanceState, "updatedAtMs">>,
): AutopilotAppearanceState {
  const next: AutopilotAppearanceState = {
    ...loadAutopilotAppearance(),
    ...patch,
    updatedAtMs: Date.now(),
  };

  if (hasBrowserStorage()) {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    window.dispatchEvent(new CustomEvent(APPEARANCE_EVENT, { detail: next }));
  }
  applyAutopilotAppearance(next);
  return next;
}

export function subscribeAutopilotAppearance(
  callback: (appearance: AutopilotAppearanceState) => void,
): () => void {
  if (typeof window === "undefined") {
    return () => undefined;
  }

  const handler = (event: Event) => {
    callback(
      event instanceof CustomEvent
        ? (event.detail as AutopilotAppearanceState)
        : loadAutopilotAppearance(),
    );
  };
  window.addEventListener(APPEARANCE_EVENT, handler);
  window.addEventListener("storage", handler);
  return () => {
    window.removeEventListener(APPEARANCE_EVENT, handler);
    window.removeEventListener("storage", handler);
  };
}

export function buildAutopilotAppearanceBridgeState() {
  const appearance = loadAutopilotAppearance();
  const theme = getAutopilotThemeOption(appearance.themeId);
  return {
    themeId: appearance.themeId,
    themeLabel: theme.label,
    density: appearance.density,
    openVsCodeColorTheme: theme.openVsCodeColorTheme,
    source: "autopilot-home-onboarding",
    updatedAtMs: appearance.updatedAtMs,
  };
}
