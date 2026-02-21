import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import {
  AgentsIcon,
  AutopilotIcon,
  ComposeIcon,
  FleetIcon,
  GhostIcon,
  IntegrationsIcon,
  MarketplaceIcon,
  SettingsIcon,
} from "./ActivityBarIcons";

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
        {NAV_ITEMS.map((item) => {
          const isIntegrationsItem = item.id === "integrations";
          const resolvedItem = isIntegrationsItem
            ? {
              ...item,
              icon: <IntegrationsIcon disableHoverAnimation={activeView === "integrations"} />,
            }
            : item;

          return (
            <RailButton
              key={item.id}
              item={resolvedItem}
              isActive={activeView === item.id}
              onClick={() => onViewChange(item.id)}
            />
          );
        })}
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
