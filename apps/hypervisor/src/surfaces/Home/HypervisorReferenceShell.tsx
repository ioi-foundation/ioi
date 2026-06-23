// Parity Phase B — reference shell (left sidebar column) ported from the IOI demo
// reference's harvested sidebar DOM, using the vendored reference utility classes.
// Additive: wraps the parity surfaces on /parity-home; the live app shell is
// untouched. Validate the whole page against http://localhost:9228/ via
// scripts/internal/parity-shot.mjs, then iterate.
import type { ReactNode } from "react";

const ICON = {
  width: 18, height: 18, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor",
  strokeWidth: 2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, "aria-hidden": true,
};
const HomeIcon = () => (<svg {...ICON}><path d="m3 9 9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" /><path d="M9 22V12h6v10" /></svg>);
const GridIcon = () => (<svg {...ICON}><rect width="7" height="7" x="3" y="3" rx="1" /><rect width="7" height="7" x="14" y="3" rx="1" /><rect width="7" height="7" x="14" y="14" rx="1" /><rect width="7" height="7" x="3" y="14" rx="1" /></svg>);
const FlowIcon = () => (<svg {...ICON}><rect width="8" height="8" x="3" y="3" rx="2" /><path d="M7 11v4a2 2 0 0 0 2 2h4" /><rect width="8" height="8" x="13" y="13" rx="2" /></svg>);
const PlusIcon = () => (<svg {...ICON} width="16" height="16"><path d="M5 12h14" /><path d="M12 5v14" /></svg>);
const GearIcon = () => (<svg {...ICON}><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z" /><circle cx="12" cy="12" r="3" /></svg>);
const ChevronRight = () => (<svg {...ICON} width="16" height="16"><path d="m9 18 6-6-6-6" /></svg>);
const PanelIcon = () => (<svg {...ICON} width="16" height="16"><rect width="18" height="18" x="3" y="3" rx="2" /><path d="M9 3v18" /></svg>);
const FilterIcon = () => (<svg {...ICON} width="16" height="16"><path d="M3 6h18" /><path d="M7 12h10" /><path d="M10 18h4" /></svg>);

function NavItem({ icon, label, active }: { icon: ReactNode; label: string; active?: boolean }) {
  return (
    <a className={`flex flex-row items-center rounded-lg h-8 min-w-0 ${active ? "bg-surface-hover" : "hover:bg-surface-hover"}`}>
      <div className="relative flex w-full flex-row items-center">
        <div className="relative h-8 w-8 shrink-0">
          <span className="flex size-full items-center justify-center text-content-secondary">{icon}</span>
        </div>
        <div className="flex-grow text-start text-base min-w-0 overflow-hidden whitespace-nowrap text-content-primary">{label}</div>
      </div>
    </a>
  );
}

function SessionGroup({ label }: { label: string }) {
  return (
    <div className="flex flex-col">
      <div className="group flex h-9 w-full flex-row content-center items-center justify-between rounded-lg hover:bg-surface-hover">
        <button type="button" aria-label="Toggle Environment Group" className="mr-2 flex min-w-0 grow flex-row content-center items-center focus:ring-0">
          <div className="flex shrink-0 pl-1">
            <div className="flex size-6 items-center justify-center text-content-muted"><ChevronRight /></div>
          </div>
          <div className="flex min-w-0 pl-1 text-sm font-medium text-content-muted">
            <span className="inline-block max-w-full truncate text-content-muted">{label}</span>
          </div>
        </button>
        <div className="mr-2 flex items-center opacity-0 group-hover:opacity-100">
          <button type="button" aria-label="Create environment" className="inline-flex size-6 items-center justify-center rounded text-content-muted hover:bg-surface-hover"><PlusIcon /></button>
        </div>
      </div>
    </div>
  );
}

export function HypervisorReferenceShell({ children }: { children: ReactNode }) {
  return (
    <div className="app-background flex size-full">
      <div className="flex w-[15.5rem] shrink-0 flex-col pb-[6px] border-r border-border-base bg-surface-primary">
        {/* header: brand + collapse */}
        <div className="flex items-center justify-between px-2 pb-0 pt-1">
          <a aria-label="Go to home" className="flex h-8 cursor-pointer items-center px-1.5">
            <span className="text-sm font-semibold tracking-tight text-content-primary">Hypervisor</span>
          </a>
          <button type="button" aria-label="Collapse sidebar" className="inline-flex items-center justify-center size-8 rounded-[4px] text-content-secondary hover:bg-surface-button-clear-accent">
            <PanelIcon />
          </button>
        </div>

        <div className="relative overflow-y-auto overflow-x-hidden mr-0.5 flex-grow pr-0.5">
          {/* top nav */}
          <div className="flex flex-col gap-1 pl-2 pt-2 pr-2">
            <button type="button" aria-label="New Session" className="flex h-8 items-center gap-2 rounded-lg border border-border-base px-2 text-base text-content-primary hover:bg-surface-hover">
              <span className="flex size-6 items-center justify-center"><PlusIcon /></span>
              <span className="flex-grow whitespace-nowrap text-start">New Session</span>
              <kbd className="flex items-center gap-1 text-xs text-content-muted">
                <kbd className="rounded px-1 font-sans">Ctrl</kbd>
                <kbd className="rounded px-1 font-sans">O</kbd>
              </kbd>
            </button>
            <NavItem icon={<HomeIcon />} label="Home" active />
            <NavItem icon={<GridIcon />} label="Projects" />
            <NavItem icon={<FlowIcon />} label="Automations" />
            <NavItem icon={<GridIcon />} label="Applications" />
          </div>

          {/* Applications section + singular Open Application */}
          <div className="flex flex-col gap-0.5 pl-2 pt-3 pr-2">
            <span className="inline-flex h-8 items-center gap-2 rounded-lg px-1.5 text-base font-normal text-content-secondary">
              <span className="flex size-6 items-center justify-center text-content-secondary"><GridIcon /></span>
              Applications
            </span>
            <a className="flex flex-row items-center rounded-lg h-8 min-w-0 hover:bg-surface-hover">
              <div className="relative flex w-full flex-row items-center">
                <div className="relative h-8 w-8 shrink-0">
                  <span className="flex size-full items-center justify-center">
                    <span className="flex size-5 items-center justify-center rounded bg-surface-accent text-[10px] font-semibold text-content-primary">P</span>
                  </span>
                </div>
                <div className="flex-grow text-start text-base min-w-0 overflow-hidden whitespace-nowrap font-medium text-content-primary">Pipeline Builder</div>
              </div>
            </a>
          </div>

          <div className="my-2 mx-2 border-t border-border-subtle" />

          {/* sessions */}
          <div className="flex min-h-0 flex-1 flex-col gap-0.5 pl-2 pr-2">
            <div className="flex items-center justify-between gap-1 pr-2">
              <div className="flex items-center gap-1">
                <span className="inline-flex h-8 items-center gap-2 rounded-lg px-1.5 text-base font-normal text-content-secondary">Sessions</span>
              </div>
              <div className="flex items-center gap-1">
                <span className="truncate text-sm text-content-secondary">Project</span>
                <button type="button" aria-label="Filter sessions" className="inline-flex size-6 items-center justify-center rounded text-content-strong hover:bg-surface-hover"><FilterIcon /></button>
              </div>
            </div>
            <SessionGroup label="ioi" />
            <SessionGroup label="From scratch" />
          </div>
        </div>

        {/* footer */}
        <div className="flex flex-col w-full gap-2 p-2 pb-2 pt-4">
          <NavItem icon={<GearIcon />} label="Organization settings" />
          <button type="button" aria-label="Switch organization" className="flex w-full items-center gap-2 rounded-lg p-1 hover:bg-surface-hover">
            <span className="flex size-8 shrink-0 items-center justify-center rounded-lg bg-surface-accent text-xs font-medium text-content-primary">LJ</span>
            <span className="flex min-w-0 flex-col text-start">
              <span className="truncate text-sm text-content-primary">Levi Josman's Workspace</span>
              <span className="truncate text-xs text-content-muted">Levi Josman</span>
            </span>
          </button>
        </div>
      </div>

      {/* main surface slot */}
      {children}
    </div>
  );
}

export default HypervisorReferenceShell;
