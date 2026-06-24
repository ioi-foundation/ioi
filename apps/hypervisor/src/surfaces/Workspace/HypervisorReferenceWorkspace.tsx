// Parity Phase D — environment detail / workspace surface, ported from the reference
// live /details/<id> DOM (:9228). Reproduces the 3-pane IDE: a resizable horizontal
// panel-group with the conversation pane (70) + a right panel (30); the conversation
// pane has the Environment-actions header + Open-VS-Code split button, the Code/session
// tab bar, the agent thread (user message + TODOs + "Environment stopped" code panel)
// and the chat input; the right panel has Changes/All Files/Comments + Review/Create PR,
// the Search + Uncommitted file tree, and the Ports/Tasks/Terminal panel. Static panel
// sizes (no live resizing); editor iframe is the reference's stopped-state placeholder.
// The big VS Code logo SVG is injected verbatim (dangerouslySetInnerHTML, stable ids).
import { useRef, useState } from "react";
import type { MouseEventHandler, ReactNode } from "react";
import { AnchoredPopover } from "../parityOverlays";
import { AgentModeMenu } from "../Home/HypervisorReferenceHomeMenus";
import {
  AllFilesPanel,
  CommentsPanel,
  TasksPanel,
  TerminalPanel,
  ChangesScopeMenu,
  EnvironmentActionsMenu,
} from "./HypervisorReferenceWorkspacePanels";
import { DesignEditor } from "./HypervisorReferenceWorkspaceEditor";

const VSCODE_LOGO = `<svg class="shrink-0 size-[16px]" width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><mask id="mask0_vsc" maskUnits="userSpaceOnUse" x="0" y="0" width="24" height="24"><path fill-rule="evenodd" clip-rule="evenodd" d="M17.0189 23.8361C17.3969 23.9834 17.8279 23.9739 18.2094 23.7903L23.1506 21.4127C23.6698 21.1629 24 20.6374 24 20.0609V3.93919C24 3.36271 23.6698 2.83723 23.1506 2.58739L18.2094 0.209701C17.7087 -0.0312311 17.1227 0.0277823 16.6832 0.347268C16.6205 0.392906 16.5607 0.443863 16.5046 0.500018L7.04522 9.12996L2.92493 6.0023C2.54136 5.71116 2.00487 5.73502 1.64864 6.05906L0.327127 7.26118C-0.108612 7.65754 -0.109112 8.34305 0.326047 8.74008L3.8993 12L0.326047 15.26C-0.109112 15.657 -0.108612 16.3425 0.327127 16.7389L1.64864 17.941C2.00487 18.265 2.54136 18.2889 2.92493 17.9977L7.04522 14.8701L16.5046 23.5C16.6542 23.6497 16.8299 23.7625 17.0189 23.8361ZM18.0036 6.55174L10.8262 12L18.0036 17.4483V6.55174Z" fill="white"></path></mask><g mask="url(#mask0_vsc)"><path d="M23.1507 2.59101L18.2057 0.210054C17.6333 -0.0655412 16.9492 0.050711 16.5 0.499924L0.311659 15.2599C-0.123766 15.6569 -0.123266 16.3424 0.312739 16.7388L1.63505 17.9409C1.9915 18.2649 2.52833 18.2888 2.91211 17.9976L22.4066 3.2087C23.0606 2.71255 24 3.17901 24 3.99993V3.94252C24 3.36628 23.6699 2.841 23.1507 2.59101Z" fill="#0065A9"></path><g filter="url(#filter0_d_vsc)"><path d="M23.1507 21.4089L18.2057 23.7899C17.6333 24.0655 16.9492 23.9492 16.5 23.5L0.311659 8.74003C-0.123766 8.34302 -0.123266 7.65749 0.312739 7.26113L1.63505 6.05902C1.9915 5.73497 2.52833 5.71111 2.91211 6.00226L22.4066 20.7912C23.0606 21.2874 24 20.8209 24 20V20.0574C24 20.6336 23.6699 21.1589 23.1507 21.4089Z" fill="#007ACC"></path></g><g filter="url(#filter1_d_vsc)"><path d="M18.2059 23.7903C17.6333 24.0658 16.9493 23.9493 16.5 23.5C17.0535 24.0535 18 23.6615 18 22.8787V1.12134C18 0.338523 17.0535 -0.053516 16.5 0.500019C16.9493 0.0507659 17.6333 -0.0656504 18.2059 0.209701L23.1501 2.5874C23.6696 2.83724 24 3.36272 24 3.9392V20.0609C24 20.6374 23.6696 21.1629 23.1501 21.4127L18.2059 23.7903Z" fill="#1F9CF0"></path></g><g opacity="0.25"><path fill-rule="evenodd" clip-rule="evenodd" d="M17.0043 23.8362C17.3823 23.9835 17.8133 23.974 18.1948 23.7905L23.136 21.4129C23.6552 21.163 23.9854 20.6375 23.9854 20.061V3.93933C23.9854 3.36282 23.6552 2.83734 23.136 2.5875L18.1948 0.209824C17.6941 -0.0311089 17.1081 0.0279045 16.6686 0.347388C16.6059 0.393029 16.5461 0.443985 16.49 0.500141L7.03063 9.13007L2.91034 6.00244C2.52679 5.71127 1.99028 5.73515 1.63405 6.05918L0.31254 7.26129C-0.1232 7.65767 -0.123699 8.34318 0.31146 8.74019L3.88471 12.0001L0.31146 15.2601C-0.123699 15.6571 -0.1232 16.3426 0.31254 16.739L1.63405 17.9411C1.99028 18.2651 2.52679 18.289 2.91034 17.9979L7.03063 14.8702L16.49 23.5001C16.6396 23.6499 16.8153 23.7626 17.0043 23.8362ZM17.9891 6.55187L10.8116 12.0001L17.9891 17.4484V6.55187Z" fill="url(#paint0_linear_vsc)"></path></g></g><defs><filter id="filter0_d_vsc" x="-8.34793" y="-2.53439" width="40.6813" height="34.8056" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"></feFlood><feColorMatrix in="SourceAlpha" type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 127 0" result="hardAlpha"></feColorMatrix><feOffset></feOffset><feGaussianBlur stdDeviation="4.16667"></feGaussianBlur><feColorMatrix type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0.25 0"></feColorMatrix><feBlend mode="overlay" in2="BackgroundImageFix" result="effect1_dropShadow"></feBlend><feBlend mode="normal" in="SourceGraphic" in2="effect1_dropShadow" result="shape"></feBlend></filter><filter id="filter1_d_vsc" x="8.16666" y="-8.27145" width="24.1667" height="40.543" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB"><feFlood flood-opacity="0" result="BackgroundImageFix"></feFlood><feColorMatrix in="SourceAlpha" type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 127 0" result="hardAlpha"></feColorMatrix><feOffset></feOffset><feGaussianBlur stdDeviation="4.16667"></feGaussianBlur><feColorMatrix type="matrix" values="0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0.25 0"></feColorMatrix><feBlend mode="overlay" in2="BackgroundImageFix" result="effect1_dropShadow"></feBlend><feBlend mode="normal" in="SourceGraphic" in2="effect1_dropShadow" result="shape"></feBlend></filter><linearGradient id="paint0_linear_vsc" x1="11.9854" y1="0.0620116" x2="11.9854" y2="23.9383" gradientUnits="userSpaceOnUse"><stop stop-color="white"></stop><stop offset="1" stop-color="white" stop-opacity="0"></stop></linearGradient></defs></svg>`;

const ChevronDownSmall = ({ cls = "size-4" }: { cls?: string }) => (
  <svg className={cls} width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6 7.1554L7.46965 8.62505C7.76255 8.91795 8.23745 8.91795 8.53035 8.62505L10 7.1554" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
);
const SelectChevron = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8 10L12 14L16 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const SearchGlyph = () => (
  <svg className="size-4" aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M20 20L16.1265 16.1265M16.1265 16.1265C17.4385 14.8145 18.25 13.002 18.25 11C18.25 6.99594 15.0041 3.75 11 3.75C6.99594 3.75 3.75 6.99594 3.75 11C3.75 15.0041 6.99594 18.25 11 18.25C13.002 18.25 14.8145 17.4385 16.1265 16.1265Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const FileGlyph = () => (
  <svg className="shrink-0 text-content-tertiary" aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10.5 9L7.5 12L10.5 15M13.5 9L16.5 12L13.5 15M3.75 3.75H20.25V20.25H3.75V3.75Z" stroke="currentColor" strokeWidth="1.5" /></svg>
);
const FolderGlyph = () => (
  <svg className="shrink-0 text-content-tertiary" aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M5.5 19.25L8 10.75H20.25M5.5 19.25H19.5L22 10.75H20.25M5.5 19.25H2.75V3.75H10L12 6.75H20.25V10.75" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
);
const Check = () => (
  <svg className="size-5 text-content-success" width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="10" cy="10" r="9" fill="currentColor" /><path d="M6 10L8.5 12.5L14 7" stroke="white" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" fill="none" /></svg>
);
const TAB = "group/tab relative flex h-full max-w-60 shrink-0 items-center font-medium transition-colors text-base focus-visible:outline-none focus-visible:ring-0 text-content-strong hover:text-content-primary data-[state=active]:text-content-primary after:absolute after:bottom-0 after:left-0 after:right-0 after:z-10 after:h-0.5 after:scale-x-0 after:bg-content-primary data-[state=active]:after:scale-x-100 disabled:pointer-events-none disabled:opacity-50";
const TAB_INNER = "relative flex min-w-0 items-center overflow-hidden rounded-md transition-colors gap-1.5 px-2 py-1.5 group-hover/tab:bg-surface-02";
const BTN_CLEAR_SQUARE = "select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:pointer-events-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 active:outline-0 focus:ring-0 bg-surface-button-clear text-content-primary hover:bg-surface-button-clear-accent hover:text-content-accent disabled:opacity-50 gap-2 h-8 text-base aspect-square p-0";

function Tab({ label, active, icon, onSelect }: { label: string; active?: boolean; icon?: ReactNode; onSelect?: () => void }) {
  return (
    <button type="button" role="tab" aria-selected={active ? "true" : "false"} data-state={active ? "active" : "inactive"} className={TAB} tabIndex={active ? 0 : -1} onClick={onSelect}>
      <span className={TAB_INNER}>{icon}<span className="truncate">{label}</span></span>
    </button>
  );
}

const FILES = [
  { name: ".devcontainer/", folder: true, depth: 0, count: 2 },
  { name: "devcontainer.json", depth: 1 },
  { name: "Dockerfile", depth: 1 },
  { name: "index.html", depth: 0 },
  { name: "script.js", depth: 0 },
  { name: "styles.css", depth: 0 },
];
const TODOS = ["Inspect project structure", "Implement website UI and content", "Run or validate locally", "Report files and preview path"];

function FileRow({ f, expanded, selected, onActivate }: { f: (typeof FILES)[number]; expanded?: boolean; selected?: boolean; onActivate?: () => void }) {
  const pad = f.depth === 0 ? 8 : 28;
  const inner = (
    <div className="flex items-center" style={{ height: "30px", paddingLeft: `${pad}px` }}>
      <button type="button" onClick={onActivate} className={`flex h-7 w-full items-center gap-1.5 rounded-md px-2 text-left font-mono text-sm cursor-pointer hover:bg-surface-02 ${f.folder ? "text-content-secondary" : ""} ${selected ? "bg-surface-02" : ""}`} tabIndex={-1} role="treeitem" {...(f.folder ? { "aria-expanded": expanded ? "true" : "false", "data-tree-folder": "true" } : { "aria-selected": selected ? "true" : "false" })} data-tree-path={f.name} data-tree-depth={f.depth}>
        {f.folder ? <FolderGlyph /> : <FileGlyph />}
        <span className={f.folder ? "truncate" : "min-w-0 flex-1 truncate text-left text-content-primary"}>{f.name}</span>
        {f.folder ? (
          <span className="ml-auto shrink-0 rounded border border-border-subtle px-1 py-0.5 text-xs leading-none text-content-tertiary">{f.count}</span>
        ) : (
          <div className="ml-2 flex shrink-0 items-center gap-2"><div className="flex items-center gap-1.5 text-xs"><span className="flex size-4 select-none items-center justify-center rounded-full text-xs font-medium bg-surface-warning-subtle text-content-warning">U</span></div></div>
        )}
      </button>
    </div>
  );
  if (f.depth === 0) return inner;
  return (
    <div className="group/row relative">
      <div className="absolute bottom-0 top-0 border-l border-border-subtle group-hover/row:border-border-base" aria-hidden="true" style={{ left: "24px" }} />
      {inner}
    </div>
  );
}

export function HypervisorReferenceWorkspace() {
  const [codeTab, setCodeTab] = useState<"code" | "design">("code");
  const [rightTab, setRightTab] = useState<"changes" | "allfiles" | "comments">("changes");
  const [bottomTab, setBottomTab] = useState<"ports" | "tasks" | "terminal">("ports");
  const [rightHidden, setRightHidden] = useState(false);
  const [bottomCollapsed, setBottomCollapsed] = useState(false);
  const [treeOpen, setTreeOpen] = useState(true);
  const [selectedFile, setSelectedFile] = useState<string | null>(null);
  const [fileQuery, setFileQuery] = useState("");
  const [prompt, setPrompt] = useState("");
  const [menu, setMenu] = useState<null | "scope" | "env" | "agent">(null);
  const scopeRef = useRef<HTMLButtonElement>(null);
  const envRef = useRef<HTMLButtonElement>(null);
  const agentRef = useRef<HTMLButtonElement>(null);
  const closeMenu = () => setMenu(null);
  const onMenuItemClick: MouseEventHandler = (e) => {
    if ((e.target as HTMLElement).closest('[role="menuitem"], [role="option"], a, button')) closeMenu();
  };
  const q = fileQuery.trim().toLowerCase();
  const visibleFiles = FILES.filter((f) => (q ? f.name.toLowerCase().includes(q) : f.depth === 0 || treeOpen));
  return (
    <main id="main-content" className="size-full overflow-hidden bg-surface-01 p-0 border-l border-border-base">
      <div className="size-full max-w-full flex min-h-0 flex-col p-0">
        <div className="relative flex min-h-0 flex-1">
          <div className="absolute right-4 top-2 z-20">
            <button type="button" onClick={() => setRightHidden((h) => !h)} className="select-none inline-flex items-center justify-center text-content-primary hover:bg-surface-button-clear-accent gap-2 h-8 text-base rounded-[4px] border-0 bg-surface-01 p-2" aria-label={rightHidden ? "Show right panel" : "Hide right panel"} aria-pressed={!rightHidden}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="currentColor" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M22 4H2V20H22V4ZM15.5 5.5V18.5H3.5V5.5H15.5Z" fill="currentColor" /></svg>
            </button>
          </div>

          <div className="flex h-full w-full min-h-0 flex-1" data-panel-group data-panel-group-direction="horizontal" style={{ flexDirection: "row", height: "100%", overflow: "hidden", width: "100%" }}>
            {/* conversation panel (70) */}
            <div id="conversation-panel" data-panel data-panel-size="70.0" style={{ flex: "70 1 0px", overflow: "hidden" }}>
              {codeTab === "code" ? (
              <div data-testid="environment-agent-execution-conversation" className="flex h-full min-w-[100px] flex-col rounded-l-lg border-border-base bg-surface-01">
                <div className="flex flex-col">
                  {/* header */}
                  <div className="flex h-12 w-full items-center justify-between gap-2 border-b border-border-subtle px-4 py-2">
                    <div className="flex h-6 min-w-0 flex-1 items-center gap-0.5">
                      <button ref={envRef} type="button" aria-haspopup="menu" aria-expanded={menu === "env"} data-state={menu === "env" ? "open" : "closed"} onClick={() => setMenu((m) => (m === "env" ? null : "env"))} data-testid="environment-header-dropdown-trigger" className="group flex min-w-0 cursor-pointer items-center focus:outline-none" aria-label="Environment actions">
                        <div className="flex min-w-0 items-center gap-1 self-stretch rounded-l-md p-1 transition-colors group-hover:bg-surface-hover">
                          <span className="inline-flex align-middle"><svg className="block text-content-tertiary shrink-0" aria-label="Idle" data-testid="status-dot" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="8" cy="8" r="3" fill="currentColor" /></svg></span>
                          <span className="min-w-0 truncate text-left text-content-primary font-bold text-base">main</span>
                        </div>
                        <div className="flex flex-shrink-0 items-center self-stretch rounded-r-md px-1 transition-colors group-hover:bg-surface-hover"><ChevronDownSmall /></div>
                      </button>
                    </div>
                    <div className="flex items-center justify-end gap-1">
                      <div data-testid="open-in-default-editor">
                        <div className="inline-flex rounded-lg border border-border-subtle hover:border-border-base" role="group">
                          <button className="min-h-8 select-none inline-flex items-center gap-2 text-sm font-medium justify-center whitespace-nowrap rounded-none first:rounded-l-lg last:rounded-r-lg text-content-primary hover:text-content-accent bg-surface-button-clear hover:bg-surface-button-clear-accent p-0 aspect-auto w-8 pl-2.5 pr-1" aria-label="Open VS Code" data-tracking-id="open-in-selected-editor">
                            <span aria-hidden="true" dangerouslySetInnerHTML={{ __html: VSCODE_LOGO }} />
                          </button>
                          <button className="min-h-8 select-none inline-flex items-center justify-center rounded-none last:rounded-r-lg text-content-primary hover:text-content-accent bg-surface-button-clear hover:bg-surface-button-clear-accent w-6 p-0" aria-label="Select editor"><ChevronDownSmall cls="size-4" /></button>
                        </div>
                      </div>
                    </div>
                  </div>
                  {/* tab bar */}
                  <div className="relative flex shrink-0 items-center gap-1 border-b border-border-subtle px-2 h-10">
                    <div role="tablist" className="flex h-full items-center gap-1">
                      <Tab label="Code" active={codeTab === "code"} onSelect={() => setCodeTab("code")} icon={<svg className="shrink-0" aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M13.6906 3.19491L11.1705 1.98254C10.8773 1.8409 10.5285 1.90062 10.2992 2.12992L5.47235 6.53418L3.36879 4.939C3.17356 4.78932 2.89832 4.80157 2.71686 4.96695L2.04311 5.58098C1.81993 5.78234 1.81993 6.13338 2.0412 6.33474L3.86568 7.99959L2.0412 9.66444C1.81993 9.8658 1.81993 10.2168 2.04311 10.4182L2.71686 11.0322C2.90023 11.1976 3.17356 11.2099 3.36879 11.0602L5.47235 9.46308L10.3015 13.8693C10.5289 14.0986 10.8777 14.1583 11.1709 14.0166L13.6932 12.8024C13.9585 12.6749 14.1258 12.4077 14.1258 12.1125V3.88397C14.1258 3.59074 13.9562 3.32162 13.6913 3.19414L13.6906 3.19491ZM11.0645 10.7815L7.39981 7.99997L11.0645 5.21845V10.7815Z" fill="currentColor" /></svg>} />
                      <Tab label="Design Post-Quantum Co…" onSelect={() => setCodeTab("design")} icon={<svg className="hypervisor-activity-brand-mark size-4" width="24" height="24" viewBox="108.97 89.47 781.56 706.06" fill="none" xmlns="http://www.w3.org/2000/svg"><g stroke="currentColor" strokeWidth="12" strokeLinejoin="round" strokeLinecap="round"><path d="M295.299 434.631L295.299 654.116 485.379 544.373z" /><path d="M500 535.931L697.39 421.968 500 308.005 302.61 421.968z" /><path d="M514.621 544.373L704.701 654.115 704.701 434.631z" /><path d="M280.678 662.557L280.678 425.086 123.957 695.903 145.513 740.594z" /><path d="M719.322 662.557L854.487 740.594 876.043 695.903 719.322 425.085z" /><path d="M287.988 675.22L151.883 753.8 164.878 780.741 470.757 780.741 287.988 675.22z" /><path d="M712.012 675.219L529.242 780.741 835.122 780.741 848.117 753.8 712.012 675.219z" /><path d="M492.689 295.343L492.689 104.779 466.038 104.779 287.055 414.066z" /><path d="M507.31 295.342L712.945 414.066 533.962 104.779 507.31 104.779z" /><path d="M302.61 666.778L500 780.741 500 552.815z" /><path d="M500 552.815L500 780.741 697.39 666.778z" /></g></svg>} />
                    </div>
                  </div>
                </div>

                {/* thread */}
                <div className="flex min-h-0 flex-1 flex-col">
                  <div className="flex flex-col gap-1"><p className="w-full text-center text-sm text-content-secondary">Retrying in 1s...</p></div>
                  <div className="relative flex h-full min-h-0 flex-1 flex-col">
                    <div id="conversation-content" className="relative overflow-y-auto overflow-x-hidden flex-1 pb-8" data-orientation="vertical">
                      <div className="mx-auto flex h-full w-full max-w-[700px] flex-col items-start gap-4 p-4 sm:p-6">
                        {/* user message */}
                        <div className="pb-4 w-full">
                          <div className="flex w-full justify-end">
                            <div className="group/row flex w-fit max-w-[90%] flex-col items-end gap-1 self-end">
                              <div className="min-w-0 max-w-full flex-1 rounded-xl rounded-br-sm border border-border-subtle bg-surface-muted px-3 py-2 text-base text-content-primary dark:bg-surface-secondary">
                                <p className="mb-0">Design a standalone static website about post-quantum computers. Use a polished educational style and create a small static site if the repo is empty.</p>
                              </div>
                            </div>
                          </div>
                        </div>
                        {/* TODOs */}
                        <div className="pb-4 w-full">
                          <div className="flex w-full flex-col gap-2">
                            <div className="flex items-center gap-2">
                              <div className="rounded bg-surface-muted px-1.5 py-0.5 text-xs font-medium uppercase tracking-[0.5px] text-content-muted">TODOs</div>
                              <span className="text-sm font-medium text-content-muted">4/4</span>
                            </div>
                            <div className="flex flex-col overflow-clip rounded-lg border border-border-base bg-surface-pure dark:bg-surface-base">
                              {TODOS.map((t) => (
                                <div key={t} className="border-b border-border-base transition-colors last:border-b-0">
                                  <button type="button" className="flex w-full items-center justify-between gap-4 px-4 py-3 text-left cursor-default" aria-label={`Completed: ${t}`} disabled>
                                    <div className="flex min-w-0 flex-1 items-center gap-2">
                                      <div className="flex h-5 w-5 flex-shrink-0 items-center justify-center"><Check /></div>
                                      <div className="flex min-w-0 flex-1 flex-col gap-0">
                                        <div className="flex min-w-0 items-center gap-2"><h2 className="min-w-0 flex-1 truncate text-base text-content-muted">{t}</h2></div>
                                      </div>
                                    </div>
                                  </button>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                        {/* Summary (assistant) */}
                        <div className="pb-4 w-full">
                          <div className="flex w-full flex-col gap-2">
                            <span className="text-sm font-medium text-content-muted">Summary</span>
                            <div className="markdown-container text-base text-content-primary">
                              <p className="mb-4">Created a standalone static website about post-quantum computers:</p>
                              <ul className="mb-4 list-disc pl-5">
                                <li>index.html</li>
                                <li>styles.css</li>
                                <li>script.js</li>
                              </ul>
                              <p className="mb-4">It includes a responsive educational layout, animated quantum-network canvas visual, cards explaining the impact, an interactive risk explorer, and a migration checklist.</p>
                              <p className="mb-0">Validation: checked file links, ASCII cleanliness, and JavaScript brace/parenthesis balance. Runtime browser/server validation was blocked because this container does not have node, python3, or another local server runtime installed. You can open index.html directly in a browser.</p>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                    {/* chat input */}
                    <div className="px-4 pb-4">
                      <div className="flex flex-col gap-0.5 rounded-xl bg-surface-muted p-1.5">
                        <div className="flex flex-col overflow-clip rounded-lg border border-border-base bg-surface-secondary">
                          <div className="p-2">
                            <textarea placeholder="Describe your task or type / for commands" rows={2} value={prompt} onChange={(e) => setPrompt(e.target.value)} className="placeholder:text-content-muted text-content-primary text-base h-auto resize-none overflow-y-auto leading-[18px] w-full rounded-none border-0 bg-transparent outline-none focus-within:ring-0 max-w-full p-2" />
                            <div className="flex h-full min-w-0 flex-row items-center justify-between gap-2 p-2 pt-0">
                              <button type="button" aria-label="Add to prompt" className="inline-flex size-8 items-center justify-center rounded-lg text-content-secondary hover:bg-surface-hover"><svg className="size-4" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M5 12h14" /><path d="M12 5v14" /></svg></button>
                              <div className="ml-auto flex flex-row items-center gap-2">
                                <button ref={agentRef} type="button" aria-label="Change agent mode" aria-expanded={menu === "agent"} data-state={menu === "agent" ? "open" : "closed"} onClick={() => setMenu((m) => (m === "agent" ? null : "agent"))} className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border-base px-2 text-sm font-normal text-content-primary hover:opacity-80"><span className="truncate">5.5 Medium</span><ChevronDownSmall /></button>
                                <button type="button" aria-label="Submit" disabled={!prompt.trim()} className="select-none inline-flex items-center justify-center rounded-lg bg-surface-button-primary text-content-always-white size-8 shrink-0 disabled:opacity-50"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="m5 12 7-7 7 7" /><path d="M12 19V5" /></svg></button>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
              ) : (
              <div className="contents" onClick={(e) => { const t = (e.target as HTMLElement).closest('[role="tab"]'); if (t && (t.textContent || "").trim() === "Code") setCodeTab("code"); }}>
                <DesignEditor />
              </div>
              )}
            </div>

            <div role="separator" className="relative flex w-0 border-l border-border-base" style={{ display: rightHidden ? "none" : undefined }} />

            {/* right panel (30) */}
            <div id="environment-details" data-panel data-panel-size="30.0" style={{ flex: "30 1 0px", overflow: "hidden", display: rightHidden ? "none" : undefined }}>
              <div className="relative flex h-full max-h-full flex-col">
                {/* right header */}
                <div className="flex flex-col">
                  <div role="tablist" className="relative flex items-center gap-1 after:absolute after:bottom-0 after:left-0 after:right-0 after:h-px h-12 justify-between px-4 @container after:bg-border-subtle">
                    <div className="flex h-full items-center">
                      <Tab label="Changes" active={rightTab === "changes"} onSelect={() => setRightTab("changes")} />
                      <Tab label="All Files" active={rightTab === "allfiles"} onSelect={() => setRightTab("allfiles")} />
                      <Tab label="Comments" active={rightTab === "comments"} onSelect={() => setRightTab("comments")} />
                    </div>
                    <div className="flex items-center gap-1" data-testid="right-panel-header-actions">
                      <button type="button" className="aspect-square p-0 min-h-8 select-none inline-flex items-center justify-center rounded-lg text-content-primary bg-surface-button-secondary hover:bg-surface-button-secondary-accent" aria-label="Review"><svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M2.84265 11.9999C5.16302 16.4127 8.63937 18.4999 11.9999 18.4999C15.3605 18.4999 18.8369 16.4128 21.1572 12C18.8369 7.58725 15.3605 5.50003 11.9999 5.5C8.63936 5.49997 5.16301 7.58714 2.84265 11.9999ZM11.9999 4C16.1417 4.00003 20.1618 6.64058 22.6709 11.6649L22.8383 12L22.6709 12.3351C20.1618 17.3595 16.1417 20 11.9999 19.9999C7.8582 19.9999 3.83809 17.3593 1.32896 12.335L1.16162 11.9999L1.32896 11.6648C3.8381 6.64046 7.85821 3.99997 11.9999 4Z" fill="currentColor" /><path d="M10.6666 10.6666L11.9999 7.99997L13.3333 10.6666L15.9999 12L13.3333 13.3333L11.9999 16L10.6666 13.3333L7.99994 12L10.6666 10.6666Z" fill="currentColor" /></svg></button>
                      <button type="button" className="aspect-square p-0 min-h-8 select-none inline-flex items-center justify-center rounded-lg text-content-primary-inverted bg-surface-button-primary hover:bg-surface-button-primary-accent" aria-label="Create PR"><svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="1.66667" cy="1.66667" r="1.66667" transform="matrix(1 0 0 -1 2.6665 13.6667)" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><circle cx="1.66667" cy="1.66667" r="1.66667" transform="matrix(1 0 0 -1 2.6665 5.66675)" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M4.3335 10.3333V5.66659" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M11.6665 7V5.665C11.6665 4.56043 10.7711 3.665 9.66655 3.665H8.5" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M11.6665 13.5V9.25736M13.7878 11.3787H9.54518" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /></svg></button>
                    </div>
                  </div>
                </div>
                {/* vertical split: file tree (70) + ports (30) */}
                <div className="flex min-h-0 flex-1 flex-col">
                  <div className="flex h-full w-full min-h-0 flex-1 flex-col" data-panel-group data-panel-group-direction="vertical" style={{ flexDirection: "column", height: "100%", overflow: "hidden", width: "100%" }}>
                    <div data-panel data-panel-size="70.0" style={{ flex: "70 1 0px", overflow: "hidden" }}>
                      <div className="flex h-full flex-col"><div className="flex min-h-0 flex-1 flex-col">
                        {rightTab === "allfiles" ? (<AllFilesPanel />) : rightTab === "comments" ? (<CommentsPanel />) : (<>
                        <div className="flex items-center gap-2 px-4 py-2">
                          <div className="relative min-w-0 flex-1">
                            <div className="flex items-center gap-2 h-9 w-full max-w-[600px] px-3 py-2 rounded-lg border border-border-light text-base bg-surface-input">
                              <span className="flex-shrink-0 text-content-secondary"><SearchGlyph /></span>
                              <input className="flex h-full w-full text-base p-0 border-0 outline-none placeholder:text-content-muted text-content-primary bg-transparent max-w-none" type="text" placeholder="Search files..." value={fileQuery} onChange={(e) => setFileQuery(e.target.value)} />
                            </div>
                          </div>
                          <div className="relative w-fit">
                            <button ref={scopeRef} type="button" aria-label="Select" aria-haspopup="listbox" aria-expanded={menu === "scope"} data-state={menu === "scope" ? "open" : "closed"} onClick={() => setMenu((m) => (m === "scope" ? null : "scope"))} data-testid="changes-scope-select" className="flex w-full items-center justify-between gap-2 text-base text-content-primary outline-none h-9 px-3 rounded-lg border border-border-input-default bg-surface-input"><span className="truncate">Uncommitted</span><SelectChevron /></button>
                          </div>
                        </div>
                        <div role="tree" tabIndex={0} className="overflow-auto py-2 outline-none min-h-0 flex-1">
                          {visibleFiles.map((f) => (
                            <FileRow
                              key={f.name}
                              f={f}
                              expanded={f.folder ? treeOpen : undefined}
                              selected={selectedFile === f.name}
                              onActivate={() => (f.folder ? setTreeOpen((o) => !o) : setSelectedFile(f.name))}
                            />
                          ))}
                        </div>
                        </>)}
                      </div></div>
                    </div>
                    <div role="separator" className="relative flex h-0 border-t border-border-base" />
                    <div data-panel data-panel-size="30.0" style={{ flex: "30 1 0px", overflow: "hidden" }}>
                      <div className="flex min-h-0 flex-1 flex-col overflow-hidden h-full">
                        <div className="relative flex shrink-0 items-center after:absolute after:bottom-0 after:left-0 after:right-0 after:h-px after:bg-border-base">
                          <button type="button" onClick={() => setBottomCollapsed((c) => !c)} className={`${BTN_CLEAR_SQUARE} ml-2 h-6 w-6 shrink-0`} aria-label={bottomCollapsed ? "Expand panel" : "Collapse panel"}><svg className="text-content-secondary" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M13.3031 5.81248L12.839 6.27652L8.61871 10.4968C8.27701 10.8386 7.72298 10.8386 7.38128 10.4968L3.16095 6.27652L2.69691 5.81248L3.62499 4.8844L4.08903 5.34844L7.99999 9.2594L11.911 5.34844L12.375 4.8844L13.3031 5.81248Z" fill="currentColor" /></svg></button>
                          <div role="tablist" className="flex items-center gap-1 overflow-x-auto h-10 flex-1">
                            <Tab label="Ports & Services" active={bottomTab === "ports"} onSelect={() => setBottomTab("ports")} />
                            <Tab label="Tasks" active={bottomTab === "tasks"} onSelect={() => setBottomTab("tasks")} />
                            <Tab label="Terminal" active={bottomTab === "terminal"} onSelect={() => setBottomTab("terminal")} />
                          </div>
                        </div>
                        <div className="flex min-h-0 flex-1 flex-col" hidden={bottomCollapsed}>
                          {bottomTab === "tasks" ? (<TasksPanel />) : bottomTab === "terminal" ? (<TerminalPanel />) : (<>
                          <div className="flex items-center justify-between px-4 py-3">
                            <h3 className="text-base font-medium text-content-primary">Ports</h3>
                            <button type="button" className="select-none inline-flex items-center gap-2 text-sm font-medium rounded-lg px-3 py-2 h-8 text-content-primary hover:bg-surface-hover"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M5 12h14" /><path d="M12 5v14" /></svg><span>Add port</span></button>
                          </div>
                          <div className="flex flex-1 flex-col items-center justify-center gap-2 px-4 pb-6 text-content-muted">
                            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d="M5 12.55a11 11 0 0 1 14.08 0" /><path d="M1.42 9a16 16 0 0 1 21.16 0" /><path d="M8.53 16.11a6 6 0 0 1 6.95 0" /><path d="M12 20h.01" /></svg>
                            <span className="text-base">No open ports</span>
                          </div>
                          </>)}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <AnchoredPopover open={menu === "env"} onClose={closeMenu} anchorRef={envRef} side="bottom" align="start"><div onClick={onMenuItemClick}><EnvironmentActionsMenu /></div></AnchoredPopover>
      <AnchoredPopover open={menu === "scope"} onClose={closeMenu} anchorRef={scopeRef} side="bottom" align="end"><div onClick={onMenuItemClick}><ChangesScopeMenu /></div></AnchoredPopover>
      <AnchoredPopover open={menu === "agent"} onClose={closeMenu} anchorRef={agentRef} side="top" align="end"><div onClick={onMenuItemClick}><AgentModeMenu /></div></AnchoredPopover>
    </main>
  );
}

export default HypervisorReferenceWorkspace;
