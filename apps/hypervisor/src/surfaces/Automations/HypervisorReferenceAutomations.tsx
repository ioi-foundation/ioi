// Parity Phase C — Automations surface ported bit-for-bit from the reference's LIVE
// /automations <main> DOM (:9228): sticky header (title + New), stat cards (Total
// with avatar + sparkline, Successful, Failed), toolbar (search + Status/Sort filter
// triggers + Yours/All tabs), the 5-row automations list (grid-subgrid rows), the
// mobile Suggested section (xl:hidden), and the Suggested-templates sidebar (xl:block,
// 16 cards from automationsTemplates). Closed-state dropdown contents (status/sort
// listboxes, row more-actions menus) are omitted — they are not visibly rendered.
// Note: the reference renders the row as a <button> containing Run/More <button>s
// (nested-button DOM) — reproduced verbatim for parity; React logs a dev warning.
import { useRef, useState } from "react";
import type { MouseEventHandler } from "react";
import { useNavigate } from "react-router-dom";
import { SUGGESTED_TEMPLATES } from "./automationsTemplates";
import { AnchoredPopover } from "../parityOverlays";
import {
  StatusFilterMenu,
  SortMenu,
  AutomationRowMenu,
} from "./HypervisorReferenceAutomationMenus";

const PlusGlyph = () => (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><path d="M10.25 5V10.25M10.25 10.25V15.5M10.25 10.25H5M10.25 10.25H15.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
);
const SearchGlyph = () => (
  <svg className="size-4" aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M20 20L16.1265 16.1265M16.1265 16.1265C17.4385 14.8145 18.25 13.002 18.25 11C18.25 6.99594 15.0041 3.75 11 3.75C6.99594 3.75 3.75 6.99594 3.75 11C3.75 15.0041 6.99594 18.25 11 18.25C13.002 18.25 14.8145 17.4385 16.1265 16.1265Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const SelectChevron = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8 10L12 14L16 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const CardChevron = () => (
  <svg className="shrink-0 text-content-muted" aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M9 4L17 12L9 20" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const DotsGlyph = () => (
  <svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M4.5 8C4.5 8.72488 3.91238 9.3125 3.1875 9.3125C2.46262 9.3125 1.875 8.72488 1.875 8C1.875 7.27512 2.46262 6.6875 3.1875 6.6875C3.91238 6.6875 4.5 7.27512 4.5 8ZM9.3125 8C9.3125 8.72488 8.72488 9.3125 8 9.3125C7.27512 9.3125 6.6875 8.72488 6.6875 8C6.6875 7.27512 7.27512 6.6875 8 6.6875C8.72488 6.6875 9.3125 7.27512 9.3125 8ZM12.8125 9.3125C13.5373 9.3125 14.125 8.72488 14.125 8C14.125 7.27512 13.5373 6.6875 12.8125 6.6875C12.0877 6.6875 11.5 7.27512 11.5 8C11.5 8.72488 12.0877 9.3125 12.8125 9.3125Z" fill="currentColor" /></svg>
);
const RunGlyph = () => (
  <svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M5 4.948C5 3.9986 6.0503 3.42519 6.84891 3.93858L11.5965 6.99058C12.3313 7.46295 12.3313 8.53705 11.5965 9.00941L6.84891 12.0614C6.0503 12.5748 5 12.0014 5 11.052V4.948Z" fill="currentColor" /></svg>
);
const ManualTriggerGlyph = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10 15.75V8.25L15.5 12L10 15.75Z" fill="currentColor" /><path fillRule="evenodd" clipRule="evenodd" d="M12 3.5C7.30558 3.5 3.5 7.30558 3.5 12C3.5 16.6944 7.30558 20.5 12 20.5C16.6944 20.5 20.5 16.6944 20.5 12C20.5 7.30558 16.6944 3.5 12 3.5ZM2 12C2 6.47715 6.47715 2 12 2C17.5228 2 22 6.47715 22 12C22 17.5228 17.5228 22 12 22C6.47715 22 2 17.5228 2 12Z" fill="currentColor" /></svg>
);
const ScheduledGlyph = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M3.75 4.75V4H3V4.75H3.75ZM20.25 4.75H21V4H20.25V4.75ZM3.75 20.25H3V21H3.75V20.25ZM8.5 2.75V2H7V2.75H8.5ZM17 2.75V2H15.5V2.75H17ZM19.5 8.75V9.5H21V8.75H19.5ZM8.75 21H9.5V19.5H8.75V21ZM3.75 5.5H7.75V4H3.75V5.5ZM7.75 5.5H16.25V4H7.75V5.5ZM16.25 5.5H20.25V4H16.25V5.5ZM4.5 20.25V4.75H3V20.25H4.5ZM8.5 4.75V2.75H7V4.75H8.5ZM17 4.75V2.75H15.5V4.75H17ZM19.5 4.75V8.75H21V4.75H19.5ZM8.75 19.5H3.75V21H8.75V19.5Z" fill="currentColor" /><circle cx="17" cy="17" r="5.25" stroke="currentColor" strokeWidth="1.5" /><path d="M17 14.75V16.9996L18.75 18.75" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);

const AVATAR_SRC = "https://lh3.googleusercontent.com/a/ACg8ocIBE-yWc_g6QMTLx_fI4gV6NkJ6Q1ERKa4YxbkEy2U9RsS3DCHb=s96-c";
const BTN_SECONDARY = "select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-secondary text-content-primary hover:bg-surface-button-secondary-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 px-3 py-2 h-8 text-base";
const BTN_CLEAR_SQUARE = "select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear text-content-primary hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 h-8 text-base aspect-square p-0";
const SELECT_TRIGGER = "flex w-full items-center justify-between gap-2 text-base text-content-primary outline-none disabled:cursor-not-allowed disabled:opacity-50 h-9 px-3 rounded-lg border border-border-input-default bg-surface-input transition-all duration-150 ease-out focus:border-border-input-active focus:ring-4 focus:ring-ring-default focus:ring-offset-0 aria-expanded:border-border-input-active aria-expanded:ring-4 aria-expanded:ring-ring-default aria-expanded:ring-offset-0";
const TAB = "inline-flex flex-row h-7 items-center @md:justify-center gap-2 overflow-hidden rounded-md border-transparent py-1 text-content-strong text-left @md:text-center flex-shrink flex-grow hover:text-content-primary data-[state=active]:bg-surface-button-tab-primary data-[state=active]:border-transparent data-[state=active]:text-content-primary disabled:opacity-50 disabled:hover:text-content-strong min-w-0 flex-1 px-3 text-sm @[700px]:flex-initial";

const AUTOMATIONS = [
  { id: "019ed112-cbe6-7bee-a494-0c13389d783a", name: "10x engineer", trigger: "scheduled" as const, label: "Scheduled every weekday at 9:00 AM UTC", run: false },
  { id: "019ed13f-9429-711d-8bf1-814cbdea19e6", name: "Add optimized AGENTS.md", trigger: "manual" as const, label: "Manual trigger", run: true },
  { id: "019ed140-0000-7000-8000-000000000001", name: "Automated dev environment setup", trigger: "manual" as const, label: "Manual trigger", run: true },
  { id: "019ed141-0000-7000-8000-000000000002", name: "Draft weekly release notes", trigger: "scheduled" as const, label: "Scheduled", run: false },
  { id: "019ed142-0000-7000-8000-000000000003", name: "Scan recent commits for bugs", trigger: "scheduled" as const, label: "Scheduled", run: false },
];

const RunButton = () => (
  <button type="button" className={BTN_SECONDARY} data-testid="workflow-row-run" data-tracking-id="run-workflow-row"><RunGlyph /><span className="truncate">Run</span></button>
);

function AutomationRow({ a }: { a: (typeof AUTOMATIONS)[number] }) {
  const [open, setOpen] = useState(false);
  const moreRef = useRef<HTMLButtonElement>(null);
  return (
    <li tabIndex={-1} role="row" aria-label={a.id} data-list-item={a.id} className="col-span-full grid grid-cols-subgrid">
      <div style={{ display: "none" }} />
      <div role="gridcell" aria-colindex={1} className="col-span-full grid grid-cols-subgrid">
        <button type="button" aria-controls={`automation-${a.id}-recent-executions`} aria-expanded="false" className="select-none hover:bg-surface-button-clear-accent duration-75 data-[active=true]:bg-surface-button-clear-accent focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-border-brand group/item col-span-full grid grid-cols-subgrid items-center gap-2 p-4 cursor-pointer text-left" data-active="false" data-list-interactive="" data-tracking-id="list-item">
          <div className="hidden items-center justify-center @xl:flex">
            <div data-list-slot="icon" className="flex shrink-0 items-center justify-center rounded-full bg-surface-muted" style={{ width: "40px", height: "40px" }}>
              <div className="flex shrink-0 items-center justify-center rounded-full border border-border-subtle bg-surface-base text-content-secondary" aria-label={a.label} data-state="closed" style={{ width: "40px", height: "40px" }}>
                {a.trigger === "manual" ? <ManualTriggerGlyph /> : <ScheduledGlyph />}
              </div>
            </div>
          </div>
          <div className="flex min-w-0 flex-col gap-0.5">
            <p className="text-base font-medium leading-tight text-content-primary" data-list-slot="title"><span className="flex items-center gap-2">{a.name}</span></p>
            <p className="text-base leading-tight text-content-strong" data-list-slot="description"><span className="text-content-inactive">Never ran</span></p>
            <div className="mt-1 @xl:hidden"><div className="flex items-center gap-2">{a.run ? <RunButton /> : null}</div></div>
          </div>
          <div className="hidden items-center @xl:flex">
            <div data-list-slot="content" className="flex grow items-center justify-end"><div className="flex items-center gap-2">{a.run ? <RunButton /> : null}</div></div>
          </div>
          <div className="flex items-center justify-end" data-tracking-id-none="true">
            <button ref={moreRef} type="button" className={BTN_CLEAR_SQUARE} aria-label="More actions" aria-haspopup="menu" aria-expanded={open} data-state={open ? "open" : "closed"} onClick={(e) => { e.preventDefault(); e.stopPropagation(); setOpen((o) => !o); }}><DotsGlyph /></button>
          </div>
        </button>
      </div>
      <AnchoredPopover open={open} onClose={() => setOpen(false)} anchorRef={moreRef} side="bottom" align="end">
        <div onClick={(e) => { if ((e.target as HTMLElement).closest('[role="menuitem"], a, button')) setOpen(false); }}><AutomationRowMenu /></div>
      </AnchoredPopover>
    </li>
  );
}

function TemplateCard({ t }: { t: (typeof SUGGESTED_TEMPLATES)[number] }) {
  return (
    <button type="button" className="flex flex-col gap-1.5 rounded-xl border border-border-base bg-surface-secondary p-4 text-left transition-colors hover:border-border-strong hover:shadow-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-border-brand focus-visible:ring-offset-1" data-testid={t.testid} data-tracking-id={t.tracking}>
      <div className="flex items-center gap-2">
        <div className={t.iconBoxClass} dangerouslySetInnerHTML={{ __html: t.iconSvg }} />
        <p className="grow truncate text-sm font-semibold text-content-primary">{t.title}</p>
        <CardChevron />
      </div>
      <p className="line-clamp-3 text-sm text-content-muted">{t.desc}</p>
    </button>
  );
}

export function HypervisorReferenceAutomations() {
  const navigate = useNavigate();
  const [query, setQuery] = useState("");
  const [ownerTab, setOwnerTab] = useState<"mine" | "all">("mine");
  const [menu, setMenu] = useState<null | "status" | "sort">(null);
  const statusRef = useRef<HTMLButtonElement>(null);
  const sortRef = useRef<HTMLButtonElement>(null);
  const closeMenu = () => setMenu(null);
  const toggleMenu = (which: "status" | "sort") => () => setMenu((m) => (m === which ? null : which));
  const onMenuItemClick: MouseEventHandler = (e) => {
    if ((e.target as HTMLElement).closest('[role="option"], [role="menuitem"], a, button')) closeMenu();
  };
  const q = query.trim().toLowerCase();
  const filtered = AUTOMATIONS.filter((a) => !q || a.name.toLowerCase().includes(q));
  return (
    <main id="main-content" className="size-full overflow-hidden bg-surface-01 p-0 border-l border-border-base">
      <div className="size-full max-w-full flex min-h-0 flex-col p-0">
        <div data-testid="workflows-page" className="relative flex h-full min-w-0 grow flex-col overflow-y-auto">
          {/* sticky header */}
          <div className="sticky top-0 z-20 min-w-0 px-6 pb-6 pt-6 transition-[background-color,backdrop-filter] duration-200 bg-surface-01">
            <div className="flex min-w-0 items-center justify-between">
              <h1 className="truncate text-2xl font-semibold tracking-[-0.2px] text-content-primary">Automations</h1>
              <div className="flex items-center gap-2">
                <button type="button" className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-primary text-content-primary-inverted hover:bg-surface-button-primary-accent disabled:opacity-50 disabled:bg-surface-primary-inverted disabled:text-content-primary-inverted focus-visible:outline-border-brand gap-2 px-4 py-2 h-9 text-base" data-testid="new-automation-button" data-tracking-id="new-automation-automations-page" onClick={() => navigate("/automations/new")}>
                  <PlusGlyph /><span className="truncate">New</span>
                </button>
              </div>
            </div>
          </div>

          {/* body: main column + suggested sidebar */}
          <div className="flex min-w-0 flex-1 items-start gap-6 px-6 pb-6">
            <div className="flex min-w-0 flex-1 flex-col gap-6">
              {/* stat cards */}
              <div className="grid min-w-0 grid-cols-2 gap-2 sm:grid-cols-3">
                <button type="button" aria-pressed="true" data-tracking-id="stat-card-total" className="flex flex-col justify-between overflow-hidden rounded-xl border p-4 text-left transition-colors focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-border-brand border-border-brand bg-surface-brand-subtle ring-1 ring-inset ring-border-brand order-3 col-span-2 sm:order-1 sm:col-span-1">
                  <p className="text-sm font-medium text-content-brand">Total Automations</p>
                  <div className="flex items-end justify-between gap-2">
                    <div className="flex min-w-0 items-end gap-2">
                      <p className="text-2xl font-semibold text-content-brand">5</p>
                      <div className="flex items-center -space-x-1.5 pb-0.5">
                        <span data-slot="avatar" className="relative flex shrink-0 overflow-hidden rounded-full size-4 border border-surface-secondary transition-transform duration-200 hover:-translate-y-0.5" data-state="closed">
                          <img data-slot="avatar-image" data-testid="avatar-image" className="aspect-square size-full object-cover pointer-events-none" referrerPolicy="no-referrer" loading="lazy" alt="Levi Josman's avatar" src={AVATAR_SRC} />
                        </span>
                      </div>
                    </div>
                    <svg viewBox="0 0 120 36" className="max-w-full shrink text-content-brand" style={{ width: "120px", height: "36px" }}>
                      <defs><linearGradient id="parity_spark" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="currentColor" stopOpacity="0.2" /><stop offset="100%" stopColor="currentColor" stopOpacity="0" /></linearGradient></defs>
                      <path d="M2,2 L21.333333333333332,34 L40.666666666666664,34 L60,34 L79.33333333333333,34 L98.66666666666666,34 L118,26 L118,36 L2,36 Z" fill="url(#parity_spark)" className="animate-sparkline-area-in" />
                      <path d="M2,2 L21.333333333333332,34 L40.666666666666664,34 L60,34 L79.33333333333333,34 L98.66666666666666,34 L118,26" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" opacity="0.6" />
                    </svg>
                  </div>
                </button>
                <button type="button" aria-pressed="false" data-tracking-id="stat-card-successful" className="flex flex-col justify-between rounded-xl border p-4 text-left transition-colors focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-border-brand border-border-base bg-surface-secondary hover:border-content-tertiary hover:bg-surface-hover order-1 sm:order-2">
                  <p className="text-sm text-content-muted">Successful · 7d</p>
                  <div className="flex items-end justify-between gap-2"><p className="text-2xl font-semibold text-content-primary">0</p></div>
                </button>
                <button type="button" aria-pressed="false" data-tracking-id="stat-card-failed" className="flex flex-col justify-between rounded-xl border p-4 text-left transition-colors focus:outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-border-brand border-border-base bg-surface-secondary hover:border-content-tertiary hover:bg-surface-hover order-2 sm:order-3">
                  <p className="text-sm text-content-muted">Failed · 7d</p>
                  <div className="flex items-end justify-between gap-2"><p className="text-2xl font-semibold text-content-primary">0</p></div>
                </button>
              </div>

              {/* toolbar + list */}
              <div className="flex min-w-0 flex-col gap-3 @container" data-testid="workflows-list">
                <div className="flex min-w-0 flex-col gap-3 @[700px]:flex-row @[700px]:items-center">
                  <div className="relative [&>div]:max-w-none min-w-0 flex-1">
                    <div className="flex items-center gap-2 h-9 w-full max-w-[600px] px-3 py-2 rounded-lg border border-border-light text-base disabled:cursor-text focus-within:ring-4 focus-within:ring-ring-default focus-visible:ring-4 focus-visible:ring-ring-default group-data-[state=error]:border-border-error group-data-[state=error]:ring-ring-destructive disabled:bg-inherit bg-surface-input [&[readonly]]:border-border-subtle [&[readonly]]:bg-transparent data-[readonly]:border-border-subtle data-[readonly]:bg-transparent">
                      <span className="flex-shrink-0 text-content-secondary"><SearchGlyph /></span>
                      <input className="flex h-full w-full focus-visible:ring-0 text-base p-0 border-0 outline-none file:border-0 file:bg-transparent file:text-sm file:font-medium disabled:cursor-text placeholder:text-content-muted border-border-base disabled:bg-surface-input text-content-primary bg-transparent [&[readonly]]:bg-transparent transition-all duration-150 ease-out max-w-none" type="text" placeholder="Search..." data-testid="automation-search-input" value={query} onChange={(e) => setQuery(e.target.value)} />
                    </div>
                  </div>
                  <div className="grid min-w-0 grid-cols-2 gap-3 @[700px]:flex @[700px]:shrink-0">
                    <div className="relative w-full">
                      <span className="sr-only">Select</span>
                      <button ref={statusRef} type="button" aria-label="Select" aria-haspopup="listbox" aria-expanded={menu === "status"} data-state={menu === "status" ? "open" : "closed"} data-testid="workflow-status-filter-trigger" className={SELECT_TRIGGER} onClick={toggleMenu("status")}>
                        <span className="truncate"><span>Status: All</span></span><SelectChevron />
                      </button>
                    </div>
                    <div className="relative w-full min-w-0 @[512px]:min-w-[210px]">
                      <span className="sr-only">Sort by</span>
                      <button ref={sortRef} type="button" aria-label="Sort by" aria-haspopup="listbox" aria-expanded={menu === "sort"} data-state={menu === "sort" ? "open" : "closed"} data-testid="automation-sort-trigger" className={SELECT_TRIGGER} onClick={toggleMenu("sort")}>
                        <span className="truncate"><span>Sort: Recently completed</span></span><SelectChevron />
                      </button>
                    </div>
                    <div dir="ltr" data-orientation="horizontal" className="@container col-span-2 [container-type:normal] @[700px]:col-span-1">
                      <div role="tablist" aria-orientation="horizontal" className="scrollbar-hide flex gap-0.5 overflow-x-auto rounded-lg border border-transparent bg-surface-button-tab-base p-[3px] @md:flex-row @md:justify-between dark:border-border-subtle min-h-9 w-full flex-row justify-start @[700px]:w-auto" tabIndex={0}>
                        <button type="button" role="tab" aria-selected={ownerTab === "mine"} data-state={ownerTab === "mine" ? "active" : "inactive"} className={TAB} data-testid="owner-filter-mine" data-tracking-id="owner-filter-mine" onClick={() => setOwnerTab("mine")}><span className="truncate">Yours</span></button>
                        <button type="button" role="tab" aria-selected={ownerTab === "all"} data-state={ownerTab === "all" ? "active" : "inactive"} className={TAB} data-testid="owner-filter-all" data-tracking-id="owner-filter-all" onClick={() => setOwnerTab("all")}><span className="truncate">All (5)</span></button>
                      </div>
                    </div>
                  </div>
                </div>
                <ul className="grid grid-cols-[auto_1fr_0fr_auto] @xl:grid-cols-[auto_minmax(120px,1fr)_1fr_auto] divide-y divide-border-base overflow-clip rounded-xl border border-border-base bg-surface-primary [&>*:first-child]:rounded-t-xl [&>*:last-child]:rounded-b-xl [&>li:first-child>*]:rounded-t-xl [&>li:last-child>*]:rounded-b-xl shadow-none">
                  {filtered.map((a) => <AutomationRow key={a.id} a={a} />)}
                  {filtered.length === 0 ? (
                    <li className="col-span-full p-4 text-sm text-content-secondary">No automations match your search.</li>
                  ) : null}
                </ul>
              </div>

              {/* mobile suggested (hidden at xl) */}
              <div className="xl:hidden">
                <div className="flex flex-col gap-3">
                  <p className="text-sm font-medium text-content-muted">Suggested</p>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                    {SUGGESTED_TEMPLATES.slice(0, 6).map((t) => <TemplateCard key={`m-${t.testid}`} t={t} />)}
                  </div>
                  <button type="button" className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear text-content-primary hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 px-3 py-2 h-8 text-base self-start" data-testid="view-more-templates" data-tracking-id="view-more-suggested-templates"><span className="truncate">View more</span></button>
                </div>
              </div>
            </div>

            {/* suggested templates sidebar */}
            <div className="sticky top-[5.25rem] hidden max-h-[calc(100vh-8rem)] w-[clamp(20rem,30%,28rem)] shrink-0 overflow-y-auto rounded-xl border border-border-subtle xl:block">
              <div className="flex h-full flex-col" data-testid="suggested-templates-sidebar">
                <div className="flex flex-col gap-1 px-4 pb-2 pt-4">
                  <p className="text-base font-medium text-content-primary">Suggested templates</p>
                  <p className="text-sm text-content-secondary">Try these automations for common engineering workflows.</p>
                </div>
                <div className="flex-1 overflow-y-auto px-4 pb-4">
                  <div className="flex flex-col gap-2">
                    {SUGGESTED_TEMPLATES.map((t) => <TemplateCard key={t.testid} t={t} />)}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <AnchoredPopover open={menu === "status"} onClose={closeMenu} anchorRef={statusRef} side="bottom" align="start"><div onClick={onMenuItemClick}><StatusFilterMenu /></div></AnchoredPopover>
      <AnchoredPopover open={menu === "sort"} onClose={closeMenu} anchorRef={sortRef} side="bottom" align="start"><div onClick={onMenuItemClick}><SortMenu /></div></AnchoredPopover>
    </main>
  );
}

export default HypervisorReferenceAutomations;
