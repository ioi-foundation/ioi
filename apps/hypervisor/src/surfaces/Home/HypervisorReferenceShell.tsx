// Parity Phase B — reference shell (left sidebar) ported bit-for-bit from the IOI
// demo reference's LIVE rendered DOM (http://localhost:9228/, captured via the
// parity dump harness). Emits the exact element tree, classes, SVG paths, copy and
// data-* hooks the reference renders — including the server-injected hypervisor-*
// brand mark and Applications section (CSS vendored in styles/reference/hypervisor-brand.css).
// HypervisorReferenceSidebar stays a prop-compatible drop-in for the activity rail
// (activeView/onViewChange/onOpenNewSession): when onViewChange is provided it routes
// via the controller; otherwise the reference hrefs navigate.
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { CSSProperties, MouseEventHandler, ReactNode, RefObject } from "react";
import { createPortal } from "react-dom";
import { useNavigate } from "react-router-dom";
import type { PrimaryView } from "../parityShellTypes";
import { HypervisorReferenceApplicationsModal } from "../Applications/HypervisorReferenceApplicationsModal";
import { APPLICATION_CATALOG } from "../Applications/applicationsCatalog";
import { useSelectedApplicationId } from "../Applications/selectedApplication";
import {
  OrgSwitcherMenu,
  SessionsFilterMenu,
  WhatsNewDialog,
  IoiEnvironmentsGrid,
} from "./HypervisorReferenceSidebarMenus";
import { CollapsibleContent, useExitDelay } from "../parityOverlays";

// Close an open popover/menu on Escape (outside-click is handled by a transparent
// backdrop rendered alongside the menu, mirroring the launcher modal pattern).
function useEscapeToClose(open: boolean, onClose: () => void) {
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);
}

// Lightweight popover: renders its menu/dialog in a portal positioned from the
// trigger's rect (so the sidebar's overflow-hidden never clips it), with a
// transparent backdrop for outside-click dismissal. We don't depend on Radix.
function SidebarPopover({
  open,
  onClose,
  anchorRef,
  side = "bottom",
  align = "start",
  children,
}: {
  open: boolean;
  onClose: () => void;
  anchorRef: RefObject<HTMLElement | null>;
  side?: "top" | "bottom";
  align?: "start" | "end";
  children: ReactNode;
}) {
  const { mounted, closing } = useExitDelay(open);
  const [rect, setRect] = useState<DOMRect | null>(null);
  useLayoutEffect(() => {
    if (open && anchorRef.current) setRect(anchorRef.current.getBoundingClientRect());
  }, [open, anchorRef]);
  useEscapeToClose(open, onClose);
  if (!mounted || !rect) return null;
  const gap = 4;
  const style: CSSProperties = {
    position: "fixed",
    zIndex: 50,
    ...(align === "end" ? { right: window.innerWidth - rect.right } : { left: rect.left }),
    ...(side === "top" ? { bottom: window.innerHeight - rect.top + gap } : { top: rect.bottom + gap }),
  };
  // Enter plays from the captured menu's own data-[state=open]:animate-in; on close we
  // run an animate-out on the wrapper before unmounting (matching the reference's Radix
  // exit). The backdrop only intercepts clicks while genuinely open.
  const exitAnim = closing
    ? `animate-out fade-out-0 zoom-out-95 duration-150 ${side === "top" ? "slide-out-to-bottom-2" : "slide-out-to-top-2"}`
    : "";
  return createPortal(
    <>
      {!closing && <div className="fixed inset-0 z-40" onClick={onClose} aria-hidden="true" />}
      <div style={style} data-state={closing ? "closed" : "open"} className={exitAnim}>
        {children}
      </div>
    </>,
    document.body,
  );
}

// ---- exact reference SVGs (verbatim paths from :9228) ----
const HomeGlyph = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M3.75 9L3.27507 8.41953L3 8.64459V9H3.75ZM20.25 9H21V8.64459L20.7249 8.41953L20.25 9ZM20.25 20.25V21H21V20.25H20.25ZM3.75 20.25H3V21H3.75V20.25ZM12 2.25L12.4749 1.66953L12 1.28095L11.5251 1.66953L12 2.25ZM9.75 14.75V14H9V14.75H9.75ZM14.25 14.75H15V14H14.25V14.75ZM14.25 20.25H13.5V21H14.25V20.25ZM9.75 20.25V21H10.5V20.25H9.75ZM19.5 9V20.25H21V9H19.5ZM4.5 20.25V9H3V20.25H4.5ZM4.22493 9.58047L12.4749 2.83047L11.5251 1.66953L3.27507 8.41953L4.22493 9.58047ZM11.5251 2.83047L19.7751 9.58047L20.7249 8.41953L12.4749 1.66953L11.5251 2.83047ZM9.75 15.5H14.25V14H9.75V15.5ZM13.5 14.75V20.25H15V14.75H13.5ZM10.5 20.25V14.75H9V20.25H10.5ZM9.75 19.5H3.75V21H9.75V19.5ZM14.25 21H20.25V19.5H14.25V21Z" fill="currentColor" /></svg>
);
const ProjectsGlyph = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M3.75 3.75H10.25V10.25H3.75V3.75Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /><path d="M13.75 3.75H20.25V10.25H13.75V3.75Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /><path d="M3.75 13.75H10.25V20.25H3.75V13.75Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /><path d="M13.75 13.75H20.25V20.25H13.75V13.75Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
);
const AutomationsGlyph = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M5.02832 5.99854L5.77832 6.49854L7.02608 4.83487M9.03831 5.66671H11.0383M5.02832 10.4993L5.77832 10.9993L7.02608 9.33562M13.6663 7.33337V2.33337H2.33301V13.6667H8.1649" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M11.333 7.81653L10.333 9.81653L8.33301 10.8165L10.333 11.8165L11.333 13.8165L12.333 11.8165L14.333 10.8165L12.333 9.81653L11.333 7.81653Z" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /></svg>
);
const ApplicationsGlyph = ({ size = "20px", cls = "hypervisor-sidebar-applications-icon" }: { size?: string; cls?: string }) => (
  <svg className={cls} width={size} height={size} viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M4.75 4.75H9.25V9.25H4.75V4.75Z M14.75 4.75H19.25V9.25H14.75V4.75Z M4.75 14.75H9.25V19.25H4.75V14.75Z M14.75 14.75H19.25V19.25H14.75V14.75Z" stroke="currentColor" strokeWidth="1.5" strokeLinejoin="round" /></svg>
);
const PlusSquareGlyph = () => (
  <svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 3.75V12M12 12V20.25M12 12H3.75M12 12H20.25" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const CollapseGlyph = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M22 4H2V20H22V4ZM20.5 5.5V18.5H8.5V5.5H20.5Z" fill="currentColor" /></svg>
);
const SessionsGlyph = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M3.75 3.75H20.25V18.25H15.0155L11.9979 20.75L9.0155 18.25H3.75V3.75Z" stroke="currentColor" strokeWidth="1.5" /><path d="M8.00195 11.5714C9.32109 11.5714 10.1405 11.8633 10.6396 12.3624C11.1386 12.8615 11.4305 13.6809 11.4305 15H12.5734C12.5734 13.6809 12.8653 12.8615 13.3643 12.3624C13.8634 11.8633 14.6828 11.5714 16.002 11.5714V10.4286C14.6828 10.4286 13.8634 10.1367 13.3643 9.63761C12.8653 9.13853 12.5734 8.31913 12.5734 7H11.4305C11.4305 8.31913 11.1386 9.13853 10.6396 9.63761C10.1405 10.1367 9.32109 10.4286 8.00195 10.4286V11.5714Z" fill="currentColor" /></svg>
);
const FilterGlyph = () => (
  <svg className="text-content-strong" aria-hidden="true" width="18px" height="18px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><rect x="3.75" y="3.75" width="6.5" height="6.5" stroke="currentColor" strokeWidth="1.5" /><rect x="3.75" y="13.75" width="6.5" height="6.5" stroke="currentColor" strokeWidth="1.5" /><path d="M14.75 7.5L18 4L21.25 7.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /><path d="M21.25 16.5L18 20L14.75 16.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /><path d="M18 4.5V19.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const ChevronGroupGlyph = () => (
  <svg className="text-content-muted" width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg"><g transform="translate(4,4)"><path d="M4.33329 2.66667L7.6666 6L4.33329 9.3333" stroke="currentColor" strokeLinecap="square" /></g></svg>
);
const GearGlyph = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M9.225 5.525L6.21875 4.83125L4.83125 6.21875L5.525 9.225L2.75 11.075V12.925L5.525 14.775L4.83125 17.7812L6.21875 19.1687L9.225 18.475L11.075 21.25H12.925L14.775 18.475L17.7812 19.1687L19.1687 17.7812L18.475 14.775L21.25 12.925V11.075L18.475 9.225L19.1687 6.21875L17.7812 4.83125L14.775 5.525L12.925 2.75H11.075L9.225 5.525Z" stroke="currentColor" strokeWidth="1.5" /><path d="M14.75 12C14.75 13.5188 13.5188 14.75 12 14.75C10.4812 14.75 9.25 13.5188 9.25 12C9.25 10.4812 10.4812 9.25 12 9.25C13.5188 9.25 14.75 10.4812 14.75 12Z" stroke="currentColor" strokeWidth="1.5" /></svg>
);
const OrgChevronGlyph = () => (
  <svg className="flex-shrink-0 text-content-primary" aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8 9L12 5L16 9M16 15L12 19L8 15" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const BrandMark = () => (
  <svg className="hypervisor-activity-brand-mark" width="24" height="24" viewBox="108.97 89.47 781.56 706.06" fill="none" xmlns="http://www.w3.org/2000/svg"><g stroke="currentColor" strokeWidth="12" strokeLinejoin="round" strokeLinecap="round"><path d="M295.299 434.631L295.299 654.116 485.379 544.373z" /><path d="M500 535.931L697.39 421.968 500 308.005 302.61 421.968z" /><path d="M514.621 544.373L704.701 654.115 704.701 434.631z" /><path d="M280.678 662.557L280.678 425.086 123.957 695.903 145.513 740.594z" /><path d="M719.322 662.557L854.487 740.594 876.043 695.903 719.322 425.085z" /><path d="M287.988 675.22L151.883 753.8 164.878 780.741 470.757 780.741 287.988 675.22z" /><path d="M712.012 675.219L529.242 780.741 835.122 780.741 848.117 753.8 712.012 675.219z" /><path d="M492.689 295.343L492.689 104.779 466.038 104.779 287.055 414.066z" /><path d="M507.31 295.342L712.945 414.066 533.962 104.779 507.31 104.779z" /><path d="M302.61 666.778L500 780.741 500 552.815z" /><path d="M500 552.815L500 780.741 697.39 666.778z" /></g></svg>
);
const SHIP_KEYFRAMES = `
@keyframes ship-bob { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-1px); } }
.ship-hull-animated { animation: ship-bob 1.6s ease-in-out 3; }
`;
const WhatsNewGlyph = () => (
  <svg width="20" height="20" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><style>{SHIP_KEYFRAMES}</style><g><path d="M3.66663 7.66663V4.33329H12.3333V7.66663M6.33329 4.33329V1.66663H9.66663V4.33329" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M4.07229 13.1602C3.11359 11.9139 2.68871 10.3628 2.45732 8.92924C2.40281 8.59154 2.62356 8.27332 2.95643 8.19448L7.84632 7.03635C7.94735 7.01242 8.05257 7.01242 8.1536 7.03635L13.0435 8.19448C13.3764 8.27332 13.5971 8.59154 13.5426 8.92924C13.3112 10.3628 12.8863 11.9139 11.9276 13.1602" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /></g><path fill="none" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" d="M1.66663 13.6666 L4.07229 13.1602 L4.69595 13.0289 C4.78652 13.0098 4.88007 13.0098 4.97063 13.0289 L7.86262 13.6377 C7.95319 13.6568 8.04673 13.6568 8.1373 13.6377 L11.0293 13.0289 C11.1199 13.0098 11.2134 13.0098 11.304 13.0289 L11.9276 13.1602 L14.3333 13.6666" /></svg>
);

const KBD =
  "rounded shadow-none inline-flex items-center justify-center my-0.5 text-center font-sans capitalize group-data-[component=tooltip]:bg-surface-accent-always-dark group-data-[component=tooltip]:text-content-always-white bg-surface-muted text-content-muted h-5 px-1.5 text-[12px] leading-5";

interface NavLinkProps {
  href: string;
  label: string;
  icon: ReactNode;
  active?: boolean;
  onActivate?: MouseEventHandler;
  extra?: Record<string, string>;
}
function NavLink({ href, label, icon, active, onActivate, extra }: NavLinkProps) {
  return (
    <a
      className={`flex flex-row items-center rounded-lg h-8 min-w-0 ${active ? "bg-surface-hover" : "hover:bg-surface-hover"}`}
      href={href}
      onClick={onActivate}
      {...(active ? { "aria-current": "page" } : {})}
      {...extra}
    >
      <div className="relative flex w-full flex-row items-center">
        <div className="relative h-8 w-8 shrink-0" data-state="default">
          <span className="transform-gpu transition-transform duration-200 ease-out flex size-full items-center justify-center" aria-hidden="true">{icon}</span>
        </div>
        <div className="flex-grow text-start text-base min-w-0 overflow-hidden whitespace-nowrap transform-gpu transition-opacity duration-200 ease-out opacity-100 px-0">{label}</div>
      </div>
    </a>
  );
}

function SessionGroup({ label, withCreate, children }: { label: string; withCreate?: boolean; children?: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div data-state={open ? "open" : "closed"} className="flex flex-col">
      <div className="group flex h-9 w-full flex-row content-center items-center justify-between rounded-lg hover:bg-surface-hover has-[>button:focus-visible]:outline has-[>button:focus-visible]:outline-1 has-[>button:focus-visible]:outline-offset-0 has-[>button:focus-visible]:outline-content-primary">
        <button aria-expanded={open} className="mr-2 flex min-w-0 grow flex-row content-center items-center focus:ring-0" aria-label="Toggle Environment Group" title={label} data-tracking-id-none="true" type="button" onClick={() => setOpen((o) => !o)}>
          <div className="flex shrink-0 pl-1">
            <div className={`flex size-6 items-center justify-center transition-transform duration-150 ease-in-out ${open ? "rotate-90" : "rotate-0"}`}><ChevronGroupGlyph /></div>
          </div>
          <div className="flex min-w-0 pl-1 text-sm font-medium text-content-muted" translate="no">
            <span className="inline-block max-w-full truncate text-content-muted">{label}</span>
          </div>
        </button>
        {withCreate ? (
          <div className="mr-2 flex items-center transition-opacity duration-300 opacity-0 group-focus-within:opacity-100 group-hover:opacity-100">
            <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 h-6 text-sm aspect-square p-0 border-0 text-content-muted" aria-busy="false" type="button" aria-label="Create environment" data-tracking-id="create-environment-button" data-state="closed">
              <div className="relative size-4">
                <div className="pointer-events-none absolute inset-0 flex items-center justify-center transition-all duration-300 scale-100 opacity-100 blur-none" aria-hidden="false"><PlusSquareGlyph /></div>
              </div>
            </button>
          </div>
        ) : null}
      </div>
      <CollapsibleContent open={open}>{children}</CollapsibleContent>
    </div>
  );
}

type SessionFilter = "project" | "recently-active" | "archived";
const SESSION_FILTER_LABELS: Record<SessionFilter, string> = {
  project: "Project",
  "recently-active": "Recently active",
  archived: "Archived",
};

interface ReferenceSidebarProps {
  activeView?: PrimaryView;
  onViewChange?: (view: PrimaryView) => void;
  onOpenNewSession?: () => void;
}

export function HypervisorReferenceSidebar({ activeView = "home", onViewChange, onOpenNewSession }: ReferenceSidebarProps) {
  const navigate = useNavigate();
  const selectedAppId = useSelectedApplicationId();
  const selectedApp = selectedAppId ? APPLICATION_CATALOG.find((a) => a.id === selectedAppId) : undefined;
  const [collapsed, setCollapsed] = useState(false);
  // Only one sidebar popover is open at a time (org switcher, sessions filter, what's new).
  const [menu, setMenu] = useState<null | "org" | "filter" | "whatsnew">(null);
  const [sessionFilter, setSessionFilter] = useState<SessionFilter>("project");
  const orgRef = useRef<HTMLButtonElement>(null);
  const filterRef = useRef<HTMLButtonElement>(null);
  const whatsNewRef = useRef<HTMLButtonElement>(null);
  const closeMenu = () => setMenu(null);
  const toggleMenu = (which: "org" | "filter" | "whatsnew") => () =>
    setMenu((current) => (current === which ? null : which));
  // Menus close when an item is chosen; anchor items keep their own navigation. The
  // sessions filter additionally updates the visible filter label.
  const onMenuItemClick: MouseEventHandler = (e) => {
    if ((e.target as HTMLElement).closest('[role="menuitem"], a, button')) closeMenu();
  };
  const onFilterItemClick: MouseEventHandler = (e) => {
    const item = (e.target as HTMLElement).closest<HTMLElement>(
      '[data-testid="sessions-filter-project"], [data-testid="sessions-filter-recently-active"], [data-testid="sessions-filter-archived"]',
    );
    if (!item) return;
    setSessionFilter(item.getAttribute("data-testid")!.replace("sessions-filter-", "") as SessionFilter);
    closeMenu();
  };
  const onDialogDismissClick: MouseEventHandler = (e) => {
    if ((e.target as HTMLElement).closest('[aria-label="Dismiss"]')) closeMenu();
  };
  const go = (view: PrimaryView): MouseEventHandler => (e) => {
    if (onViewChange) {
      e.preventDefault();
      onViewChange(view);
    }
  };
  // New Session opens the home composer (the reference's "what do you want to get
  // done today?" surface), matching :9228.
  const onNewSession: MouseEventHandler = (e) => {
    e.preventDefault();
    onOpenNewSession?.();
    navigate("/");
  };

  return (
    <div data-sidebar-container="true" className="relative flex-shrink-0 overflow-hidden">
      <div className="h-full overflow-hidden pt-2" data-track-location="sidebar">
        <div className="relative h-full" style={{ width: collapsed ? "48px" : "300px", transition: "width 200ms ease-in-out" }}>
          <div data-testid="sidebar" className="flex size-full flex-col pb-[6px]">
            {/* header: brand + collapse */}
            <div className="flex items-center justify-between px-2 pb-0 pt-1">
              <div className="relative h-8 w-8" role="group" aria-label="Sidebar logo and expand control">
                <div className="absolute top-0 flex h-8 w-auto items-center gap-2 left-2">
                  <a className="flex h-8 cursor-pointer items-center hypervisor-logo-home-link" aria-label="Go to Hypervisor home" data-tracking-id="logo-home-link" href="/ai" onClick={go("home")}>
                    <span className="hypervisor-activity-brand" aria-hidden="true">
                      <span className="hypervisor-activity-brand-tick" />
                      <BrandMark />
                      <span className="hypervisor-activity-brand-tick" />
                    </span>
                  </a>
                </div>
              </div>
              <div className="flex items-center gap-1">
                <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear text-content-primary hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 text-base size-8 rounded-[4px] border-0 p-0 transition-opacity duration-200 ease-out opacity-100" aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} aria-expanded={!collapsed} data-tracking-id="toggle-sidebar-collapse" data-state="closed" type="button" onClick={() => setCollapsed((c) => !c)}>
                  <CollapseGlyph />
                </button>
              </div>
            </div>

            {/* scroll region */}
            <div className="relative [scrollbar-gutter:stable] overflow-y-auto overflow-x-hidden mr-0.5 flex-grow pr-[1px]" data-orientation="vertical">
              <div className="flex flex-col gap-1 pl-2 pt-2">
                <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg disabled:text-content-tertiary disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear hover:bg-surface-button-clear-accent data-[state=open]:bg-surface-button-clear-accent border border-border-base text-content-primary hover:text-content-accent data-[state=open]:text-content-accent disabled:border-opacity-1 focus-visible:outline-border-brand text-base relative gap-0 px-0 py-0 h-8 w-full" data-testid="create-session-button" aria-label="New Session" data-tracking-id="new-environment" type="button" onClick={onNewSession}>
                  <div data-testid="create-session-icon" className="absolute -left-px flex h-8 w-8 shrink-0 items-center justify-center"><PlusSquareGlyph /></div>
                  <div className="absolute right-0 flex items-center justify-between overflow-hidden pr-2 left-8 opacity-100">
                    <span data-testid="session-text" className="whitespace-nowrap">New Session</span>
                    <div data-testid="keyboard-shortcut"><kbd className="flex items-center gap-1"><kbd className={KBD}>Ctrl</kbd><kbd className={KBD}>O</kbd></kbd></div>
                  </div>
                </button>
                <NavLink href="/ai" label="Home" icon={<HomeGlyph />} active={activeView === "home"} onActivate={go("home")} />
                <NavLink href="/projects" label="Projects" icon={<ProjectsGlyph />} active={activeView === "projects"} onActivate={go("projects")} />
                <NavLink href="/automations" label="Automations" icon={<AutomationsGlyph />} active={activeView === "automations"} onActivate={go("automations")} />
                <NavLink href="#applications" label="Applications" icon={<ApplicationsGlyph />} active={activeView === "applications"} onActivate={go("applications")} extra={{ "aria-label": "Applications", "data-hypervisor-applications-launcher": "true", "data-hypervisor-applications-bound": "true" }} />
              </div>

              <div className="my-2 border-t border-border-subtle" aria-hidden="true" />

              {/* Applications section — zero pinned applications by default (matches the
                  reference): the heading plus a quiet empty hint. Once the operator opens
                  an app from the launcher it becomes the selected/pinned app here and
                  opens its surface on /insights. */}
              <section data-hypervisor-applications-section="true" className="hypervisor-applications-sidebar-section" data-rendered-application-id={selectedApp ? selectedApp.id : "__none__"}>
                <div className="hypervisor-applications-sidebar-heading text-content-secondary">
                  <span className="hypervisor-applications-sidebar-heading-main">
                    <span className="hypervisor-applications-sidebar-heading-icon" aria-hidden="true"><ApplicationsGlyph size="18px" cls="" /></span>
                    <span>Applications</span>
                  </span>
                </div>
                {selectedApp ? (
                  <a className="hypervisor-selected-application" data-hypervisor-selected-application="" aria-label={`Open selected application: ${selectedApp.name}`} href="/insights">
                    <span className="hypervisor-application-icon " aria-hidden="true" style={{ background: selectedApp.color, color: "#f5f7fb", display: "inline-flex", alignItems: "center", justifyContent: "center", fontSize: "11px", fontWeight: 750 }}>{selectedApp.glyph}</span>
                    <span className="hypervisor-selected-application-copy"><span className="hypervisor-selected-application-title">{selectedApp.name}</span></span>
                  </a>
                ) : (
                  <p className="hypervisor-applications-sidebar-empty">Your favorite apps will appear here</p>
                )}
              </section>

              {/* sessions */}
              <div className="flex min-h-0 flex-1 flex-col gap-0.5" data-testid="sidebar-activity-tabs" role="tablist" aria-label="Sidebar">
                <div className="flex items-center justify-between gap-1 pr-2">
                  <div className="flex items-center gap-1">
                    <span className="inline-flex h-8 items-center gap-2 rounded-lg px-1.5 text-base font-normal text-content-secondary" data-testid="sidebar-tab-sessions"><SessionsGlyph /><span>Sessions</span></span>
                  </div>
                  <div className="flex items-center gap-1">
                    <span className="truncate text-sm text-content-secondary" data-testid="sessions-filter-label">{SESSION_FILTER_LABELS[sessionFilter]}</span>
                    <button ref={filterRef} className="select-none font-medium whitespace-nowrap transition-colors border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear text-content-primary hover:text-content-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 text-base flex h-8 w-8 items-center justify-center rounded-md p-0 hover:bg-surface-button-clear-accent data-[state=open]:bg-surface-button-clear-accent" aria-label="Filter sessions" data-testid="sessions-filter-button" data-tracking-id="sessions-filter-button" type="button" aria-haspopup="menu" aria-expanded={menu === "filter"} data-state={menu === "filter" ? "open" : "closed"} onClick={toggleMenu("filter")}><FilterGlyph /></button>
                  </div>
                </div>
                <div role="tabpanel" aria-label="Sessions" className="min-h-0 flex-1 flex-col flex">
                  <div className="contents" data-testid="environments-list" data-track-location="sidebar_environment_list">
                    <SessionGroup label="ioi" withCreate><IoiEnvironmentsGrid /></SessionGroup>
                    <SessionGroup label="From scratch" />
                  </div>
                </div>
              </div>
            </div>

            {/* footer */}
            <div className="p-2 pb-2 pt-4">
              <div className="flex flex-col w-full gap-2">
                <div className="flex flex-col gap-1">
                  <NavLink href="/settings" label="Organization settings" icon={<GearGlyph />} active={activeView === "settings"} onActivate={go("settings")} />
                </div>
                <div className="flex w-full items-center gap-1">
                  <div className="min-w-0 flex-1">
                    <button className="select-none items-center font-medium whitespace-nowrap transition-colors disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 text-content-primary hover:text-content-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand text-base h-[48px] w-full flex gap-2 border-0 p-2 bg-transparent rounded-lg group focus-visible:!outline-none focus-visible:!ring-1 focus-visible:!ring-content-primary focus-visible:!ring-offset-0 justify-between hover:bg-surface-hover data-[state=open]:bg-surface-hover" ref={orgRef} aria-label="Switch organization. Currently in Levi Josman's Workspace 320" aria-expanded={menu === "org"} aria-haspopup="menu" data-testid="org-switcher" type="button" data-state={menu === "org" ? "open" : "closed"} onClick={toggleMenu("org")}>
                      <div className="flex w-full min-w-0 items-center gap-2 transform-gpu transition-all duration-200 ease-out translate-x-0">
                        <div className="relative flex-shrink-0 rounded-lg" data-testid="org-switcher-icon">
                          <span data-slot="avatar" className="relative flex shrink-0 overflow-hidden size-8 rounded-lg">
                            <div className="inline-flex size-full select-none items-center justify-center font-medium text-xs leading-8 bg-surface-brand-accent-09 text-content-brand-accent-07" role="img" aria-label="Levi Josman's Workspace 320's avatar"><span className="inline-block text-center">LJ</span></div>
                          </span>
                        </div>
                        <div className="flex min-w-0 flex-1 flex-col items-start justify-start overflow-hidden transform-gpu transition-all duration-200 ease-out max-w-full opacity-100" data-testid="org-switcher-text">
                          <div className="min-w-0 max-w-full truncate whitespace-nowrap text-left text-base font-bold leading-tight">Levi Josman's Workspace 320</div>
                          <div className="min-w-0 max-w-full truncate whitespace-nowrap text-left text-base font-normal leading-tight">Levi Josman</div>
                        </div>
                        <div className="flex flex-shrink-0 items-center overflow-hidden transform-gpu transition-all duration-200 ease-out max-w-full opacity-100" data-testid="org-switcher-chevron"><OrgChevronGlyph /></div>
                      </div>
                    </button>
                  </div>
                  <div>
                    <button ref={whatsNewRef} type="button" className="flex flex-row items-center rounded-lg h-8 min-w-0 hover:bg-surface-hover shrink-0" aria-label="What's new" data-tracking-id="open-changelog-expanded" data-testid="changelog-button" aria-haspopup="dialog" aria-expanded={menu === "whatsnew"} data-state={menu === "whatsnew" ? "open" : "closed"} onClick={toggleMenu("whatsnew")}>
                      <div className="relative h-8 w-8 shrink-0">
                        <span className="transform-gpu transition-transform duration-200 ease-out flex size-full items-center justify-center" aria-hidden="true"><WhatsNewGlyph /></span>
                      </div>
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <button className="absolute right-0 w-1 cursor-ew-resize rounded-full transition-colors duration-150 hover:bg-surface-03 active:bg-surface-04 top-4 mr-[1px] h-[calc(100%-32px)]" data-tracking-id-none="true" type="button" aria-hidden="true" />
      <SidebarPopover open={menu === "org"} onClose={closeMenu} anchorRef={orgRef} side="top" align="start"><div onClick={onMenuItemClick}><OrgSwitcherMenu /></div></SidebarPopover>
      <SidebarPopover open={menu === "filter"} onClose={closeMenu} anchorRef={filterRef} side="bottom" align="end"><div onClick={onFilterItemClick}><SessionsFilterMenu /></div></SidebarPopover>
      <SidebarPopover open={menu === "whatsnew"} onClose={closeMenu} anchorRef={whatsNewRef} side="top" align="end"><div onClick={onDialogDismissClick}><WhatsNewDialog /></div></SidebarPopover>
    </div>
  );
}

// Mirror the reference's theme contract: `<html class="ona ... light">` with
// `--chat-color-scheme: light`. This activates the `:root[class~=ona]` token layer
// (e.g. neutral --app-background instead of the bare-:root warm gradient) and the
// `.ona`-scoped parity preflight. Applied only while a parity surface is mounted so
// the live app's own theme is untouched on other routes.
export function useReferenceTheme() {
  useEffect(() => {
    const root = document.documentElement;
    const added = ["ona", "light"].filter((c) => !root.classList.contains(c));
    root.classList.add(...added);
    const hadScheme = root.style.getPropertyValue("--chat-color-scheme");
    root.style.setProperty("--chat-color-scheme", "light");
    return () => {
      root.classList.remove(...added);
      if (hadScheme) root.style.setProperty("--chat-color-scheme", hadScheme);
      else root.style.removeProperty("--chat-color-scheme");
    };
  }, []);
}

export function HypervisorReferenceShell({
  children,
  activeView = "home",
  onViewChange,
  onOpenNewSession,
}: {
  children: ReactNode;
  activeView?: PrimaryView;
  onViewChange?: (view: PrimaryView) => void;
  onOpenNewSession?: () => void;
}) {
  useReferenceTheme();
  const [appsOpen, setAppsOpen] = useState(false);
  // The reference Applications nav item opens the catalog launcher modal; all other
  // views delegate to the route navigator. (Pipeline Builder's open-app behavior is
  // a separate surface, deferred.)
  const handleViewChange = (view: PrimaryView) => {
    if (view === "applications") {
      setAppsOpen(true);
      return;
    }
    onViewChange?.(view);
  };
  return (
    <div className="app-background flex size-full flex-col overflow-hidden">
      <div className="flex w-full grow flex-row overflow-hidden">
        <HypervisorReferenceSidebar activeView={activeView} onViewChange={handleViewChange} onOpenNewSession={onOpenNewSession} />
        {children}
      </div>
      <HypervisorReferenceApplicationsModal open={appsOpen} onClose={() => setAppsOpen(false)} />
    </div>
  );
}

export default HypervisorReferenceShell;
