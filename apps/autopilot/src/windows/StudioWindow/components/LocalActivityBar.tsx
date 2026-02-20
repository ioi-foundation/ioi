import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";

const AutopilotIcon = () => (
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

const ComposeIcon = () => (
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

const AgentsIcon = () => (
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

const FleetIcon = () => (
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

const MarketplaceIcon = () => (
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

const IntegrationsIcon = () => (
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
    <path d="M12 3v6" />
    <path d="M16 3v6" />
    <path d="M9 9h10a1 1 0 0 1 1 1v1a6 6 0 0 1-6 6h-1v4" />
    <path d="M6 12h3" />
  </svg>
);

const GhostIcon = () => (
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

const SettingsIcon = () => (
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

interface ActivityBarProps {
  activeView: string;
  onViewChange: (view: string) => void;
  ghostMode: boolean;
  onToggleGhost: () => void;
}

interface NavItem {
  id: string;
  label: string;
  icon: ReactNode;
  shortcut?: string;
}

function Tooltip({ label, shortcut, rect }: { label: string; shortcut?: string; rect: DOMRect }) {
  return (
    <div
      role="tooltip"
      style={{
        position: "fixed",
        left: rect.right + 8,
        top: rect.top + rect.height / 2,
        transform: "translateY(-50%)",
        display: "flex",
        alignItems: "center",
        gap: 8,
        background: "#252526",
        border: "1px solid #454545",
        borderRadius: 4,
        padding: "4px 8px",
        fontSize: 12,
        color: "#cccccc",
        whiteSpace: "nowrap",
        pointerEvents: "none",
        zIndex: 9999,
        boxShadow: "0 2px 8px rgba(0,0,0,0.5)",
        fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif",
      }}
    >
      {label}
      {shortcut && <span style={{ color: "#666", fontSize: 11 }}>{shortcut}</span>}
    </div>
  );
}

function RailButton({
  item,
  isActive,
  onClick,
  variant = "nav",
}: {
  item: NavItem;
  isActive: boolean;
  onClick: () => void;
  variant?: "nav" | "ghost" | "utility";
}) {
  const ref = useRef<HTMLButtonElement | null>(null);
  const [hovered, setHovered] = useState(false);
  const [tooltipRect, setTooltipRect] = useState<DOMRect | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const show = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => {
      if (ref.current) setTooltipRect(ref.current.getBoundingClientRect());
    }, 350);
  }, []);

  const hide = useCallback(() => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = null;
    setTooltipRect(null);
  }, []);

  useEffect(() => () => {
    if (timer.current) clearTimeout(timer.current);
  }, []);

  const activeColor = variant === "ghost" ? "#f59e0b" : "#e4e4e7";
  const inactiveColor = "#6e6e78";
  const hoverColor = variant === "ghost" ? "#f59e0b" : "#b4b4bc";
  const iconColor = isActive ? activeColor : hovered ? hoverColor : inactiveColor;

  return (
    <>
      <button
        ref={ref}
        type="button"
        onClick={onClick}
        onMouseEnter={() => {
          setHovered(true);
          show();
        }}
        onMouseLeave={() => {
          setHovered(false);
          hide();
        }}
        onFocus={show}
        onBlur={hide}
        aria-label={item.label}
        aria-current={isActive ? "page" : undefined}
        style={{
          position: "relative",
          width: "100%",
          height: 48,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          background: "transparent",
          border: "none",
          padding: 0,
          cursor: "pointer",
          color: iconColor,
          transition: "color 0.15s ease",
        }}
      >
        <span
          style={{
            position: "absolute",
            left: 0,
            top: "50%",
            width: 4,
            height: isActive ? 20 : hovered ? 8 : 0,
            background: activeColor,
            borderRadius: "999px",
            transform: `translateY(-50%) translateX(${isActive || hovered ? "0px" : "-4px"})`,
            transition:
              "height 0.3s cubic-bezier(0.2, 0.8, 0.2, 1), transform 0.3s cubic-bezier(0.2, 0.8, 0.2, 1), opacity 0.15s ease",
            opacity: isActive || hovered ? 1 : 0,
          }}
        />
        {item.icon}
      </button>

      {tooltipRect && <Tooltip label={item.label} shortcut={item.shortcut} rect={tooltipRect} />}
    </>
  );
}

const NAV_ITEMS: NavItem[] = [
  { id: "autopilot", label: "Autopilot", icon: <AutopilotIcon />, shortcut: "⌘1" },
  { id: "compose", label: "Compose", icon: <ComposeIcon />, shortcut: "⌘2" },
  { id: "agents", label: "Agents", icon: <AgentsIcon />, shortcut: "⌘3" },
  { id: "fleet", label: "Fleet", icon: <FleetIcon />, shortcut: "⌘4" },
  { id: "marketplace", label: "Marketplace", icon: <MarketplaceIcon />, shortcut: "⌘5" },
  { id: "integrations", label: "Integrations", icon: <IntegrationsIcon />, shortcut: "⌘6" },
];

const GHOST_ITEM: NavItem = { id: "ghost", label: "Ghost Mode", icon: <GhostIcon />, shortcut: "⌘G" };
const SETTINGS_ITEM: NavItem = { id: "settings", label: "Settings", icon: <SettingsIcon /> };

function isEditableElement(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName.toLowerCase();
  return (
    target.isContentEditable ||
    tag === "input" ||
    tag === "textarea" ||
    tag === "select"
  );
}

export function LocalActivityBar({
  activeView,
  onViewChange,
  ghostMode,
  onToggleGhost,
}: ActivityBarProps) {
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if (isEditableElement(event.target)) return;
      if (!event.metaKey && !event.ctrlKey) return;

      const num = Number.parseInt(event.key, 10);
      if (num >= 1 && num <= NAV_ITEMS.length) {
        event.preventDefault();
        onViewChange(NAV_ITEMS[num - 1].id);
        return;
      }

      if (event.key.toLowerCase() === "g") {
        event.preventDefault();
        onToggleGhost();
      }
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [onViewChange, onToggleGhost]);

  return (
    <aside
      role="navigation"
      aria-label="Studio navigation"
      style={{
        width: 48,
        display: "flex",
        flexDirection: "column",
        alignItems: "stretch",
        background: "#181818",
        borderRight: "1px solid #2a2a2a",
        flexShrink: 0,
        userSelect: "none",
      }}
    >
      <div style={{ display: "flex", flexDirection: "column", paddingTop: 4 }}>
        {NAV_ITEMS.map((item) => (
          <RailButton
            key={item.id}
            item={item}
            isActive={activeView === item.id}
            onClick={() => onViewChange(item.id)}
          />
        ))}
      </div>

      <div style={{ flex: 1 }} />

      <div style={{ display: "flex", flexDirection: "column", paddingBottom: 4 }}>
        <RailButton
          item={GHOST_ITEM}
          isActive={ghostMode}
          onClick={onToggleGhost}
          variant="ghost"
        />
        <RailButton
          item={SETTINGS_ITEM}
          isActive={activeView === "settings"}
          onClick={() => onViewChange("settings")}
          variant="utility"
        />
      </div>
    </aside>
  );
}
