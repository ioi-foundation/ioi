// Parity Phase C — Home cockpit ported bit-for-bit from the IOI demo reference's
// LIVE <main> DOM (http://localhost:9228/, captured via the parity dump harness):
// exact element tree, classes, verbatim SVG paths and copy. Additive on /parity-home.
// Off-screen measurement-only nodes (codex-picker-*-measure, fixed at -10000px,
// opacity 0) are omitted — they never render; everything visible is reproduced.
// The mobile waiting lottie (md:hidden) is kept as its container only (hidden at
// the reference's desktop viewport). Validate vs :9228 with .ioi/tmp/compare.mjs.
import { useRef, useState } from "react";
import type { MouseEventHandler } from "react";
import { AnchoredPopover } from "../parityOverlays";
import {
  AgentModeMenu,
  WorkInProjectMenu,
  AddToPromptMenu,
} from "./HypervisorReferenceHomeMenus";

const BrandMark = ({ cls }: { cls: string }) => (
  <svg className={cls} width="24" height="24" viewBox="108.97 89.47 781.56 706.06" fill="none" xmlns="http://www.w3.org/2000/svg"><g stroke="currentColor" strokeWidth="12" strokeLinejoin="round" strokeLinecap="round"><path d="M295.299 434.631L295.299 654.116 485.379 544.373z" /><path d="M500 535.931L697.39 421.968 500 308.005 302.61 421.968z" /><path d="M514.621 544.373L704.701 654.115 704.701 434.631z" /><path d="M280.678 662.557L280.678 425.086 123.957 695.903 145.513 740.594z" /><path d="M719.322 662.557L854.487 740.594 876.043 695.903 719.322 425.085z" /><path d="M287.988 675.22L151.883 753.8 164.878 780.741 470.757 780.741 287.988 675.22z" /><path d="M712.012 675.219L529.242 780.741 835.122 780.741 848.117 753.8 712.012 675.219z" /><path d="M492.689 295.343L492.689 104.779 466.038 104.779 287.055 414.066z" /><path d="M507.31 295.342L712.945 414.066 533.962 104.779 507.31 104.779z" /><path d="M302.61 666.778L500 780.741 500 552.815z" /><path d="M500 552.815L500 780.741 697.39 666.778z" /></g></svg>
);
const FocusGlyph = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-focus shrink-0"><circle cx="12" cy="12" r="3" /><path d="M3 7V5a2 2 0 0 1 2-2h2" /><path d="M17 3h2a2 2 0 0 1 2 2v2" /><path d="M21 17v2a2 2 0 0 1-2 2h-2" /><path d="M7 21H5a2 2 0 0 1-2-2v-2" /></svg>
);
const ProjectChevronGlyph = () => (
  <svg className="hidden md:block" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M13.3031 5.81248L12.839 6.27652L8.61871 10.4968C8.27701 10.8386 7.72298 10.8386 7.38128 10.4968L3.16095 6.27652L2.69691 5.81248L3.62499 4.8844L4.08903 5.34844L7.99999 9.2594L11.911 5.34844L12.375 4.8844L13.3031 5.81248Z" fill="currentColor" /></svg>
);
const ProjectPlusGlyph = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" className="md:hidden"><path d="M8 3.75V8M8 8V12.25M8 8H3.75M8 8H12.25" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
);
const AddPlusGlyph = () => (
  <svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 3.75V12M12 12V20.25M12 12H3.75M12 12H20.25" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const AgentChevronGlyph = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6 7.1554L7.46965 8.62505C7.76255 8.91795 8.23745 8.91795 8.53035 8.62505L10 7.1554" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
);
const SubmitGlyph = () => (
  <svg width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><g clipPath="url(#parity_submit_clip)"><path d="M4.16667 9.99999L10 4.16666L15.8333 9.99999" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /><path d="M10 15.8333L10 4.16666" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></g><defs><clipPath id="parity_submit_clip"><rect width="20" height="20" fill="white" /></clipPath></defs></svg>
);
const StatusDotGlyph = () => (
  <svg aria-label="Environment auto-stopped" width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" className="text-content-tertiary inline-block align-middle" data-testid="status-dot"><circle cx="12" cy="12" r="2" fill="currentColor" /></svg>
);
const EnvGlyph = () => (
  <svg className="size-4" aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 2.76027V2.75M12 21.2397V21.25M15.5359 3.4636L15.5398 3.45411M8.46411 20.5364L8.46018 20.5459M18.5335 5.46661L18.5407 5.45935M5.46651 18.5336L5.45924 18.5408M20.5363 8.46431L20.5458 8.46038M3.46354 15.5361L3.45405 15.54M2.76027 12H2.75M21.2397 12H21.25M5.46675 5.46647L5.45949 5.4592M18.5337 18.5334L18.541 18.5407M3.46392 8.4638L3.45443 8.45987M20.5367 15.5356L20.5462 15.5395M8.46409 3.46357L8.46016 3.45408M15.5359 20.5364L15.5398 20.5459" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
);
const BugGlyph = () => (
  <svg className="size-4" aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M5.37036 9.80627L3 9M5.37036 13.75H2.75M5.37036 17.4437L3 18.25M18.63 9.80627L21 9M18.63 13.75H21.2504M18.63 17.4437L21 18.25M12 13.75V20.75M7.75 7.5V7C7.75 4.65279 9.65279 2.75 12 2.75C14.3472 2.75 16.25 4.65279 16.25 7V7.5M18.25 7.75H5.75V15C5.75 18.4518 8.54822 21.25 12 21.25C15.4518 21.25 18.25 18.4518 18.25 15V7.75Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const CoverageGlyph = () => (
  <svg className="size-4" aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10.9998 9.44736L9.7497 1.75H14.2497L12.9998 9.5M8.92211 20.7244C9.88471 21.0648 10.9206 21.25 11.9997 21.25C13.0788 21.25 14.1146 21.0648 15.0772 20.7244M5.99784 4.99117C5.2219 5.65499 4.54364 6.45987 4.00409 7.39482C3.46454 8.32977 3.10694 9.31986 2.92029 10.3241M21.079 10.3239C20.8924 9.31975 20.5348 8.32966 19.9952 7.39471C19.4557 6.45976 18.7774 5.65488 18.0015 4.99106M10.2891 14.1425L4.24805 19.0737L1.99805 15.1766L9.33471 12.3841M14.7103 12.4102L22.0015 15.1763L19.7515 19.0734L13.6647 14.1159M14.2497 12C14.2497 13.2426 13.2423 14.25 11.9997 14.25C10.7571 14.25 9.7497 13.2426 9.7497 12C9.7497 10.7574 10.7571 9.75 11.9997 9.75C13.2423 9.75 14.2497 10.7574 14.2497 12Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);

const EXAMPLE_PROMPTS = [
  { id: "parity-ex-env", testid: "example-prompt-automate-env-setup", tracking: "example-prompt-automate-env-setup-ona-ai-page", iconColor: "text-content-brand", icon: <EnvGlyph />, title: "Automate env setup", sr: "Create a fully working dev environment as code configuration." },
  { id: "parity-ex-bug", testid: "example-prompt-fix-bug", tracking: "example-prompt-fix-bug-ona-ai-page", iconColor: "text-content-destructive", icon: <BugGlyph />, title: "Fix a bug", sr: "Find a bug in the codebase that looks important and fix it." },
  { id: "parity-ex-cov", testid: "example-prompt-boost-test-coverage", tracking: "example-prompt-boost-test-coverage-ona-ai-page", iconColor: "text-content-brand-accent-01", icon: <CoverageGlyph />, title: "Boost your test coverage", sr: "Find key areas to cover with new and smarter tests." },
];
const PROMPT_LABEL_CLASS =
  "relative box-border flex h-full justify-start bg-surface-button-clear font-medium peer-checked:border-content-brand peer-focus-visible:animate-focus-pulse peer-focus-visible:outline peer-focus-visible:outline-1 peer-focus-visible:outline-offset-1 peer-focus-visible:outline-border-brand motion-reduce:animate-none border border-border-base shadow-prompt-template dark:shadow-prompt-template-dark flex-row items-center gap-1.5 rounded-lg p-2 transition-[border-color,box-shadow,transform] duration-100 hover:border-border-strong hover:shadow-prompt-template-hover dark:hover:shadow-prompt-template-hover-dark cursor-pointer active:scale-[99%] active:shadow-inner";

const RECENT_SESSIONS = [
  { href: "/details/019ee1b5-0cdd-72af-81e4-327345446648", name: "Design Post-Quantum Computing Website", when: "4d ago" },
  { href: "/details/019ed139-ddf8-7c5d-a655-2a2a04a0eee6", name: "Write Parent Harness Evidence Boundary Doc", when: "7d ago" },
];

export function HypervisorReferenceHome() {
  const [prompt, setPrompt] = useState("");
  const [menu, setMenu] = useState<null | "agent" | "project" | "addprompt">(null);
  const agentRef = useRef<HTMLButtonElement>(null);
  const projectRef = useRef<HTMLButtonElement>(null);
  const addPromptRef = useRef<HTMLButtonElement>(null);
  const closeMenu = () => setMenu(null);
  const toggleMenu = (which: "agent" | "project" | "addprompt") => () =>
    setMenu((m) => (m === which ? null : which));
  // Menus close when an item is chosen; anchor items keep their navigation.
  const onMenuItemClick: MouseEventHandler = (e) => {
    if ((e.target as HTMLElement).closest('[role="menuitem"], [role="option"], a, button')) closeMenu();
  };
  return (
    <main id="main-content" className="size-full overflow-hidden bg-surface-01 p-0 border-l border-border-base">
      <div className="size-full max-w-full flex min-h-0 flex-col p-0">
        <div data-testid="ona-ai-page" className="flex size-full">
          <div className="relative flex size-full flex-col overflow-y-auto">
            <div data-testid="ona-ai-page-contents" className="mx-auto flex min-h-[calc(100dvh-4rem)] w-full max-w-[46rem] flex-col overflow-x-hidden pb-[calc(0.5rem+env(safe-area-inset-bottom,0px))] pl-[env(safe-area-inset-left,0px)] pr-[env(safe-area-inset-right,0px)] md:min-h-0 md:gap-12 md:px-1 md:pb-0">

              {/* heading */}
              <div className="flex flex-1 flex-col items-center justify-center gap-2 pb-2 md:flex-none md:gap-4 md:pb-0 md:pt-20">
                <div className="relative size-12 md:hidden" role="img" aria-label="Hypervisor waiting" style={{ filter: "var(--lottie-color-filter)" }}>
                  <div className="size-full" />
                </div>
                <h1 className="truncate text-2xl font-semibold tracking-[-0.2px] text-content-primary hidden md:block">
                  <div className="relative h-8 hypervisor-wordmark-brand-host" style={{ aspectRatio: "283 / 96" }}>
                    <span className="hypervisor-activity-brand" aria-hidden="true">
                      <span className="hypervisor-activity-brand-tick" />
                      <BrandMark cls="hypervisor-activity-brand-mark" />
                      <span className="hypervisor-activity-brand-tick" />
                    </span>
                  </div>
                </h1>
                <p className="text-center text-xl text-content-primary md:text-2xl">What do you want to get done today?</p>
              </div>

              {/* prompt input */}
              <div className="w-full">
                <div className="flex flex-col gap-1 md:gap-0">
                  <div className="flex flex-col gap-0.5 rounded-xl bg-surface-muted p-1.5 transition-opacity">
                    <div className="flex flex-col overflow-clip rounded-lg border border-border-base bg-surface-secondary">
                      <div>
                        <div className="p-2">
                          <div className="relative">
                            <div role="combobox" aria-expanded="false" aria-haspopup="listbox" className="mx-[1px]">
                              <textarea
                                aria-autocomplete="list"
                                placeholder="Describe your task or type / for commands"
                                data-testid="prompt-input-textarea"
                                rows={5}
                                data-tracking-id="suggestion-selected-textarea-with-suggestions"
                                className="outline-none file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-content-muted text-content-primary flex items-center gap-2 border-border-light text-base disabled:cursor-text focus-within:ring-ring-default focus-visible:ring-ring-default group-data-[state=error]:border-border-error group-data-[state=error]:ring-ring-destructive disabled:bg-inherit [&[readonly]]:border-border-subtle [&[readonly]]:bg-transparent h-auto resize-none overflow-y-auto leading-[18px] w-full rounded-none border-0 bg-transparent focus-within:ring-0 focus-visible:ring-0 max-w-full p-2"
                                style={{ minHeight: "118px", maxHeight: "400px", height: "120px" }}
                                value={prompt}
                                onChange={(e) => setPrompt(e.target.value)}
                              />
                            </div>
                            <div className="sr-only" role="status" aria-live="assertive" aria-atomic="true" />
                          </div>
                          <div className="flex h-full min-w-0 flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
                            <div className="hidden min-w-0 flex-1 flex-col gap-2 md:flex md:flex-none md:flex-row md:items-center">
                              <button ref={projectRef} type="button" className="h-10 rounded-lg border border-border-base px-3 py-1.5 text-base opacity-80 outline-none ring-0 hover:bg-surface-hover focus:border-border-brand active:border-border-brand md:h-8 md:py-1 flex flex-1 items-center space-x-2" data-tracking-id="add-context-prompt-input" onClick={toggleMenu("project")}>
                                <FocusGlyph />
                                <span className="flex-1 text-start">Work in a project</span>
                                <ProjectPlusGlyph />
                                <ProjectChevronGlyph />
                              </button>
                            </div>
                            <div className="ml-auto flex min-w-0 flex-row flex-wrap items-center gap-2">
                              <input type="file" accept="image/png,image/jpeg" multiple className="hidden" />
                              <div className="relative inline-flex w-fit items-center" data-tracking-id="prompt-actions-area" aria-haspopup="menu" aria-expanded="false" data-state="closed">
                                <button type="button" className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 h-8 text-base aspect-square p-0 text-content-secondary" aria-label="Add to prompt" data-tracking-id="prompt-actions-menu-button" ref={addPromptRef} onClick={toggleMenu("addprompt")}>
                                  <AddPlusGlyph />
                                </button>
                              </div>
                              <span className="inline-flex" data-state="closed">
                                <button ref={agentRef} type="button" aria-haspopup="menu" aria-expanded={menu === "agent"} data-state={menu === "agent" ? "open" : "closed"} aria-label="Change agent mode" onClick={toggleMenu("agent")} className="inline-flex h-8 items-center gap-1.5 rounded-md border border-border-base px-2 text-sm font-normal text-content-primary hover:opacity-80 focus:outline-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:outline-border-brand data-[state=open]:opacity-80">
                                  <div className="flex min-w-0 items-center gap-1.5">
                                    <BrandMark cls="hypervisor-activity-brand-mark size-4" />
                                    <span className="truncate">5.5 Medium</span>
                                  </div>
                                  <AgentChevronGlyph />
                                </button>
                              </span>
                              <div data-state="closed">
                                <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-primary text-content-primary-inverted hover:bg-surface-button-primary-accent disabled:opacity-50 disabled:bg-surface-primary-inverted disabled:text-content-primary-inverted focus-visible:outline-border-brand gap-2 text-base aspect-square m-0 h-8 flex-1 p-2 sm:aspect-square sm:flex-none" disabled={!prompt.trim()} aria-busy="false" type="button" data-testid="prompt-input-submit-button" aria-label="Submit" data-tracking-id="submit-prompt-prompt-input">
                                  <div className="relative size-5">
                                    <div className="pointer-events-none absolute inset-0 flex items-center justify-center transition-all duration-300 scale-100 opacity-100 blur-none" aria-hidden="false"><SubmitGlyph /></div>
                                  </div>
                                </button>
                              </div>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              </div>

              {/* example prompts */}
              <div className="mt-2 hidden w-full flex-row flex-wrap justify-center gap-4 md:flex" data-testid="example-prompts">
                <div className="flex w-full flex-wrap justify-center gap-4 text-sm text-content-secondary">
                  {EXAMPLE_PROMPTS.map((p) => (
                    <div className="select-none w-fit" key={p.id}>
                      <input id={p.id} type="checkbox" className="peer sr-only" />
                      <label data-testid={p.testid} data-tracking-id={p.tracking} className={PROMPT_LABEL_CLASS} htmlFor={p.id} onClick={() => setPrompt(p.sr)}>
                        <span className={`flex size-5 flex-shrink-0 items-center justify-center ${p.iconColor}`}>{p.icon}</span>
                        <span className="text-base text-content-primary">{p.title}</span>
                        <span className="text-base text-content-muted sr-only">{p.sr}</span>
                      </label>
                    </div>
                  ))}
                </div>
              </div>

              {/* recent sessions */}
              <div className="hidden md:block">
                <div data-testid="recent-agent-executions" className="duration-300 animate-in fade-in block">
                  <div className="mb-4 flex justify-between">
                    <h2 className="tracking-[-0.2px] text-base font-medium text-content-muted">Recent Sessions</h2>
                  </div>
                  <ul data-testid="recent-agent-executions-list">
                    {RECENT_SESSIONS.map((s) => (
                      <li key={s.href} className="group flex list-none items-center justify-between border-b border-border-subtle last:border-b-0">
                        <a className="mr-2 flex flex-1 items-center p-2 hover:bg-surface-muted focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring-default focus-visible:ring-0" href={s.href}>
                          <span data-testid="environment-status-dot" className="align-middle m-auto size-auto pr-2">
                            <span className="inline-flex align-middle" data-state="closed"><StatusDotGlyph /></span>
                          </span>
                          <div className="flex min-w-0 flex-1 flex-col gap-0.5 pt-0.5">
                            <p className="min-w-0 flex-shrink truncate text-base text-content-primary" data-testid="agent-execution-name">{s.name}</p>
                            <div className="flex flex-row"><p className="truncate text-sm text-content-muted" data-testid="agent-execution-details-started-at">{s.when}</p></div>
                          </div>
                        </a>
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <AnchoredPopover open={menu === "agent"} onClose={closeMenu} anchorRef={agentRef} side="top" align="end"><div onClick={onMenuItemClick}><AgentModeMenu /></div></AnchoredPopover>
      <AnchoredPopover open={menu === "project"} onClose={closeMenu} anchorRef={projectRef} side="top" align="start"><div onClick={onMenuItemClick}><WorkInProjectMenu /></div></AnchoredPopover>
      <AnchoredPopover open={menu === "addprompt"} onClose={closeMenu} anchorRef={addPromptRef} side="top" align="start"><div onClick={onMenuItemClick}><AddToPromptMenu /></div></AnchoredPopover>
    </main>
  );
}

export default HypervisorReferenceHome;
