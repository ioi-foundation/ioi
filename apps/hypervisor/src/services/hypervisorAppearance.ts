export type HypervisorThemeId =
  | "dark-modern"
  | "light-modern"
  | "dark-high-contrast"
  | "light-high-contrast";

export type HypervisorDensity = "default" | "compact";

export interface HypervisorAppearanceState {
  themeId: HypervisorThemeId;
  density: HypervisorDensity;
  updatedAtMs: number;
}

export interface HypervisorThemeOption {
  id: HypervisorThemeId;
  label: string;
  description: string;
  openVsCodeColorTheme: string;
  sourceMedia: string;
}

const STORAGE_KEY = "hypervisor.appearance.v1";
const APPEARANCE_EVENT = "hypervisor-appearance-updated";

export const HYPERVISOR_THEME_OPTIONS: HypervisorThemeOption[] = [
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
    description: "The light Workbench adapter setup baseline, adapted for Hypervisor.",
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

const DEFAULT_APPEARANCE: HypervisorAppearanceState = {
  themeId: "light-modern",
  density: "default",
  updatedAtMs: 0,
};

function hasBrowserStorage(): boolean {
  return typeof window !== "undefined" && typeof window.localStorage !== "undefined";
}

function isThemeId(value: unknown): value is HypervisorThemeId {
  return HYPERVISOR_THEME_OPTIONS.some((option) => option.id === value);
}

function isDensity(value: unknown): value is HypervisorDensity {
  return value === "default" || value === "compact";
}

export function getHypervisorThemeOption(
  themeId: HypervisorThemeId,
): HypervisorThemeOption {
  return (
    HYPERVISOR_THEME_OPTIONS.find((option) => option.id === themeId) ??
    HYPERVISOR_THEME_OPTIONS[0]
  );
}

export function loadHypervisorAppearance(): HypervisorAppearanceState {
  if (!hasBrowserStorage()) {
    return { ...DEFAULT_APPEARANCE };
  }

  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return { ...DEFAULT_APPEARANCE };
    }
    const parsed = JSON.parse(raw) as Partial<HypervisorAppearanceState>;
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

export function applyHypervisorAppearance(
  appearance: HypervisorAppearanceState = loadHypervisorAppearance(),
): void {
  if (typeof document === "undefined") {
    return;
  }

  document.documentElement.dataset.hypervisorTheme = appearance.themeId;
  document.documentElement.dataset.hypervisorDensity = appearance.density;
  document.documentElement.style.colorScheme = appearance.themeId.includes("light")
    ? "light"
    : "dark";
}

export function saveHypervisorAppearance(
  patch: Partial<Omit<HypervisorAppearanceState, "updatedAtMs">>,
): HypervisorAppearanceState {
  const next: HypervisorAppearanceState = {
    ...loadHypervisorAppearance(),
    ...patch,
    updatedAtMs: Date.now(),
  };

  if (hasBrowserStorage()) {
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    window.dispatchEvent(new CustomEvent(APPEARANCE_EVENT, { detail: next }));
  }
  applyHypervisorAppearance(next);
  return next;
}

export function subscribeHypervisorAppearance(
  callback: (appearance: HypervisorAppearanceState) => void,
): () => void {
  if (typeof window === "undefined") {
    return () => undefined;
  }

  const handler = (event: Event) => {
    callback(
      event instanceof CustomEvent
        ? (event.detail as HypervisorAppearanceState)
        : loadHypervisorAppearance(),
    );
  };
  window.addEventListener(APPEARANCE_EVENT, handler);
  window.addEventListener("storage", handler);
  return () => {
    window.removeEventListener(APPEARANCE_EVENT, handler);
    window.removeEventListener("storage", handler);
  };
}

export function buildHypervisorAppearanceBridgeState() {
  const appearance = loadHypervisorAppearance();
  const theme = getHypervisorThemeOption(appearance.themeId);
  return {
    themeId: appearance.themeId,
    themeLabel: theme.label,
    density: appearance.density,
    openVsCodeColorTheme: theme.openVsCodeColorTheme,
    source: "hypervisor-home-onboarding",
    updatedAtMs: appearance.updatedAtMs,
  };
}
