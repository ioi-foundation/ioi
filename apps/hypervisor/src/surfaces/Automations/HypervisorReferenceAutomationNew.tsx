// Parity — "New automation" editor ported bit-for-bit from the IOI demo
// reference's LIVE <main> DOM for /automations/new (the "Start from scratch"
// workflow editor: breadcrumb, Cancel/Create, name/description + agent-mode
// picker, manual-trigger node, Prompt + Shell Script steps, and Add-step).
// Exact element tree, classes, verbatim SVG paths and copy.
// Off-screen measurement-only nodes (codex-picker-root-measure /
// codex-picker-submenu-measure, fixed at -10000px, opacity 0, inside the
// aria-hidden measurement wrapper) are omitted — they never render; everything
// visible is reproduced, exactly as the sibling Home surface does.
import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { AnchoredPopover } from "../parityOverlays";
import { AgentModeMenu } from "../Home/HypervisorReferenceHomeMenus";
import { AutomationEditNodeMenu } from "../parityCapturedMenus";

const BreadcrumbChevronGlyph = ({ cls }: { cls: string }) => (
  <svg className={cls} width="20" height="20" viewBox="0 0 20 20" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8.733 13L10.9375 10.7955C11.3768 10.3562 11.3768 9.64382 10.9375 9.20447L8.733 7" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
);
const BrandMark = ({ cls }: { cls: string }) => (
  <svg className={cls} width="24" height="24" viewBox="108.97 89.47 781.56 706.06" fill="none" xmlns="http://www.w3.org/2000/svg"><g stroke="currentColor" strokeWidth="12" strokeLinejoin="round" strokeLinecap="round"><path d="M295.299 434.631L295.299 654.116 485.379 544.373z" /><path d="M500 535.931L697.39 421.968 500 308.005 302.61 421.968z" /><path d="M514.621 544.373L704.701 654.115 704.701 434.631z" /><path d="M280.678 662.557L280.678 425.086 123.957 695.903 145.513 740.594z" /><path d="M719.322 662.557L854.487 740.594 876.043 695.903 719.322 425.085z" /><path d="M287.988 675.22L151.883 753.8 164.878 780.741 470.757 780.741 287.988 675.22z" /><path d="M712.012 675.219L529.242 780.741 835.122 780.741 848.117 753.8 712.012 675.219z" /><path d="M492.689 295.343L492.689 104.779 466.038 104.779 287.055 414.066z" /><path d="M507.31 295.342L712.945 414.066 533.962 104.779 507.31 104.779z" /><path d="M302.61 666.778L500 780.741 500 552.815z" /><path d="M500 552.815L500 780.741 697.39 666.778z" /></g></svg>
);
const AgentChevronGlyph = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6 7.1554L7.46965 8.62505C7.76255 8.91795 8.23745 8.91795 8.53035 8.62505L10 7.1554" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
);
const ManualTriggerGlyph = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10 15.75V8.25L15.5 12L10 15.75Z" fill="currentColor" /><path fillRule="evenodd" clipRule="evenodd" d="M12 3.5C7.30558 3.5 3.5 7.30558 3.5 12C3.5 16.6944 7.30558 20.5 12 20.5C16.6944 20.5 20.5 16.6944 20.5 12C20.5 7.30558 16.6944 3.5 12 3.5ZM2 12C2 6.47715 6.47715 2 12 2C17.5228 2 22 6.47715 22 12C22 17.5228 17.5228 22 12 22C6.47715 22 2 17.5228 2 12Z" fill="currentColor" /></svg>
);
const DragHandleGlyph = () => (
  <svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg" className="shrink-0 cursor-grab text-content-tertiary transition-colors group-hover:text-content-primary"><circle cx="4.5" cy="3" r="0.8" fill="currentColor" /><circle cx="9.5" cy="3" r="0.8" fill="currentColor" /><circle cx="4.5" cy="7" r="0.8" fill="currentColor" /><circle cx="9.5" cy="7" r="0.8" fill="currentColor" /><circle cx="4.5" cy="11" r="0.8" fill="currentColor" /><circle cx="9.5" cy="11" r="0.8" fill="currentColor" /></svg>
);
const PromptGlyph = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M15.25 9.75H8.75M12.25 14.25H8.75M2.75 20.25H16.25C19.0114 20.25 21.25 18.0114 21.25 15.25V8.75C21.25 5.98858 19.0114 3.75 16.25 3.75H7.75C4.98858 3.75 2.75 5.98858 2.75 8.75V20.25Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const ShellScriptGlyph = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M4.75 6.75L10 12L4.75 17.25M12.75 17.25H19.25" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const EditNodeGlyph = () => (
  <svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M4.5 8C4.5 8.72488 3.91238 9.3125 3.1875 9.3125C2.46262 9.3125 1.875 8.72488 1.875 8C1.875 7.27512 2.46262 6.6875 3.1875 6.6875C3.91238 6.6875 4.5 7.27512 4.5 8ZM9.3125 8C9.3125 8.72488 8.72488 9.3125 8 9.3125C7.27512 9.3125 6.6875 8.72488 6.6875 8C6.6875 7.27512 7.27512 6.6875 8 6.6875C8.72488 6.6875 9.3125 7.27512 9.3125 8ZM12.8125 9.3125C13.5373 9.3125 14.125 8.72488 14.125 8C14.125 7.27512 13.5373 6.6875 12.8125 6.6875C12.0877 6.6875 11.5 7.27512 11.5 8C11.5 8.72488 12.0877 9.3125 12.8125 9.3125Z" fill="currentColor" /></svg>
);
const AddStepGlyph = () => (
  <svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8 3.75V8M8 8V12.25M8 8H3.75M8 8H12.25" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>
);

export function HypervisorReferenceAutomationNew() {
  const navigate = useNavigate();
  const [agentOpen, setAgentOpen] = useState(false);
  const agentRef = useRef<HTMLButtonElement>(null);
  const [editNodeOpen, setEditNodeOpen] = useState(false);
  const editNodeRef = useRef<HTMLElement | null>(null);
  const onEditorClick = (e: React.MouseEvent<HTMLElement>) => {
    const t = (e.target as HTMLElement).closest<HTMLElement>('[aria-label="Edit node"]');
    if (t) { editNodeRef.current = t; setEditNodeOpen(true); }
  };
  return (
    <main id="main-content" className="size-full overflow-hidden bg-surface-01 p-0 border-l border-border-base" onClick={onEditorClick}>
      <div {...{ orientation: "both" }} className="size-full max-w-full flex min-h-0 flex-col p-0">
        <div data-testid="workflow-edit-page" className="flex min-h-0 max-h-full grow flex-col overflow-hidden relative size-full">
          <header className="@container/page-header flex items-center justify-between gap-4 bg-surface-primary border-b border-border-base px-6 py-3 min-h-[57px]">
            <div className="min-w-[min(67%,200px)]">
              <div className="relative min-w-0">
                <ol className="flex min-w-0 flex-row items-center h-6 gap-0.5 text-base invisible absolute inset-0 overflow-hidden" aria-hidden="true">
                  <li className="flex shrink-0 flex-row items-center whitespace-nowrap">
                    <span className="max-w-[200px] truncate">Automations</span>
                    <BreadcrumbChevronGlyph cls="shrink-0 mx-0.5" />
                  </li>
                  <li className="flex shrink-0 flex-row items-center whitespace-nowrap">
                    <span>Start from scratch</span>
                  </li>
                </ol>
                <ol className="flex min-w-0 flex-row items-center h-6 gap-0.5 text-base">
                  <li className="flex min-w-0 shrink-0 flex-row items-center text-content-strong gap-0.5 text-base font-normal">
                    <a className="max-w-[200px] truncate hover:text-content-primary" title="Automations" data-tracking-id="breadcrumb-link" href="/automations/">Automations</a>
                    <BreadcrumbChevronGlyph cls="shrink-0 text-content-inactive" />
                  </li>
                  <li className="flex min-w-0 shrink items-center text-content-primary gap-1.5 text-base font-medium">
                    <span className="truncate" title="Start from scratch">Start from scratch</span>
                  </li>
                </ol>
              </div>
            </div>
            <div className="flex shrink-0 items-center gap-2">
              <div className="flex grow items-center justify-between gap-2">
                <div></div>
                <div className="flex items-center gap-2">
                  <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-secondary text-content-primary hover:bg-surface-button-secondary-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 px-3 py-2 h-8 text-base" data-tracking-id="cancel" type="button" onClick={() => navigate("/automations")}><span className="truncate">Cancel</span></button>
                  <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-primary text-content-primary-inverted hover:bg-surface-button-primary-accent disabled:opacity-50 disabled:bg-surface-primary-inverted disabled:text-content-primary-inverted focus-visible:outline-border-brand gap-2 px-3 py-2 h-8 text-base" aria-busy="false" data-tracking-id="create-automation-from-template"><span className="truncate">Create</span></button>
                </div>
              </div>
            </div>
          </header>
          <div className="flex min-h-0 grow flex-col overflow-hidden">
            <div className="ease-[cubic-bezier(0.4,0,0.2,1)] grid grow grid-rows-1 overflow-hidden transition-[grid-template-columns] duration-500 grid-cols-[1fr_0px]">
              <div id="step-list-container-scrollarea" className="relative [scrollbar-gutter:stable] overflow-y-auto overflow-x-hidden pr-[3px] flex flex-col border-border-subtle bg-surface-primary bg-[image:radial-gradient(circle,rgb(var(--border-subtle)/var(--border-subtle-opacity))_1.5px,transparent_1.5px)] bg-[length:15px_15px] flex-[3] grow rounded-none border-0" data-orientation="vertical">
                <div data-automation-edit-container="true" className="relative flex grow items-start justify-center px-6 py-6">
                  <div className="flex w-full max-w-screen-xl grow flex-row items-start justify-center gap-4">
                    <ol className="flex min-h-full w-full max-w-[720px] flex-1 flex-col items-center">
                      <li className="w-full">
                        <div className="mb-6 w-full">
                          <div className="group flex flex-row items-center gap-1 rounded-lg border bg-surface-popover py-3.5 pr-4 transition-all dark:bg-surface-base border-border-subtle pl-4 cursor-default flex-col items-stretch gap-2 py-4">
                            <div className="group flex w-full flex-col gap-1">
                              <input className="p-0 outline-none file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-content-muted text-content-primary flex items-center gap-2 h-9 w-full px-3 py-2 rounded-lg border border-border-light disabled:cursor-text focus-within:ring-4 focus-within:ring-ring-default focus-visible:ring-4 focus-visible:ring-ring-default group-data-[state=error]:border-border-error group-data-[state=error]:ring-ring-destructive disabled:bg-inherit bg-surface-input [&amp;[readonly]]:border-border-subtle [&amp;[readonly]]:bg-transparent data-[readonly]:border-border-subtle data-[readonly]:bg-transparent max-w-none text-md" type="text" name="automation_name" aria-label="Automation name" placeholder="Automation name" data-tracking-id="automation-name-input" data-1p-ignore="true" data-lpignore="true" defaultValue="Start from scratch" />
                            </div>
                            <div className="group flex w-full flex-col">
                              <textarea name="automation_description" aria-label="Automation description" placeholder="Describe what this automation does (optional)" data-tracking-id="automation-description-input" className="p-0 outline-none file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-content-muted text-content-primary flex items-center gap-2 w-full px-3 py-2 rounded-lg border border-border-light text-base disabled:cursor-text focus-within:ring-4 focus-within:ring-ring-default focus-visible:ring-4 focus-visible:ring-ring-default group-data-[state=error]:border-border-error group-data-[state=error]:ring-ring-destructive disabled:bg-inherit bg-surface-input [&amp;[readonly]]:border-border-subtle [&amp;[readonly]]:bg-transparent h-auto max-w-full resize-none overflow-y-auto leading-[18px]" style={{ minHeight: "74px", maxHeight: "9.0072e+15px", transition: "none !important", height: "74px" }} defaultValue="Create a custom automation workflow from scratch." />
                            </div>
                            <div className="flex w-full">
                              <span className="inline-flex" data-state="closed">
                                <button ref={agentRef} type="button" id="radix-:r2v:" aria-haspopup="menu" aria-expanded={agentOpen} data-state={agentOpen ? "open" : "closed"} onClick={() => setAgentOpen((o) => !o)} aria-label="Change agent mode" className="inline-flex h-8 items-center gap-1.5 rounded-md border px-2 text-sm font-normal text-content-primary hover:opacity-80 focus:outline-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:outline-border-brand data-[state=open]:opacity-80 border-border-light">
                                  <div className="flex min-w-0 items-center gap-1.5">
                                    <BrandMark cls="hypervisor-activity-brand-mark size-4" />
                                    <span className="truncate">5.5 Medium</span>
                                  </div>
                                  <AgentChevronGlyph />
                                </button>
                              </span>
                            </div>
                          </div>
                        </div>
                      </li>
                      <li className="w-full" data-tracking-id="select-automation-trigger-node-automation-step-list">
                        <div className="group flex flex-row items-center gap-1 rounded-lg border bg-surface-popover py-3.5 pr-4 transition-all dark:bg-surface-base shadow-sm border-border-base hover:border-border-brand-subtle hover:shadow pl-2 py-3.5 pl-4 pr-4 cursor-pointer">
                          <div className="flex flex-1 flex-col items-start gap-2">
                            <span className="inline-flex items-center gap-1 rounded-[20px] border-0 bg-surface-muted text-content-strong text-sm select-none px-2 py-1 font-medium" data-variant="default">
                              <ManualTriggerGlyph />
                              <span className="">Manual trigger</span>
                            </span>
                            <p className="text-content-primary text-base"><span>Runs across </span><span className="inline-flex items-center gap-1 rounded-[20px] border-0 font-normal bg-surface-muted text-content-strong px-2 py-1 text-sm" data-variant="default"><span className="">0 projects</span></span></p>
                            <p className="text-content-primary text-base"><span className="font-medium">5 concurrent</span><span> and </span><span className="font-medium"><span>Max </span>10 actions</span><span> per batch</span></p>
                            <p className="flex items-center gap-1.5 text-base text-content-strong pt-1"><span>Runs as</span><span><span data-slot="avatar" className="relative flex shrink-0 overflow-hidden rounded-full size-4"><img data-slot="avatar-image" data-testid="avatar-image" className="aspect-square size-full object-cover" referrerPolicy="no-referrer" loading="lazy" alt="Levi Josman" src="https://lh3.googleusercontent.com/a/ACg8ocIBE-yWc_g6QMTLx_fI4gV6NkJ6Q1ERKa4YxbkEy2U9RsS3DCHb=s96-c" /></span></span><span>Levi Josman</span></p>
                          </div>
                        </div>
                      </li>
                      <li className="w-full">
                        <div className="-mt-px flex w-full flex-row items-start pl-6 transition-all duration-300 ease-in-out">
                          <svg width="24" height="36" viewBox="0 0 24 36" fill="none" xmlns="http://www.w3.org/2000/svg" className="mr-3 text-content-secondary"><title>Next step</title><defs><linearGradient id=":r2k:-g" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stopColor="currentColor" stopOpacity="0" /><stop offset="0.3" stopColor="currentColor" stopOpacity="0.25" /><stop offset="0.5" stopColor="currentColor" stopOpacity="0.65" /><stop offset="0.7" stopColor="currentColor" stopOpacity="0.25" /><stop offset="1" stopColor="currentColor" stopOpacity="0" /></linearGradient></defs><rect x="0" y="0" width="24" height="1" fill="url(#:r2k:-g)" /><path d="M11.5 0L11.5 35L12.5 35L12.5 0L11.5 0ZM11.6464 35.3536C11.8417 35.5488 12.1583 35.5488 12.3536 35.3536L15.5355 32.1716C15.7308 31.9763 15.7308 31.6597 15.5355 31.4645C15.3403 31.2692 15.0237 31.2692 14.8284 31.4645L12 34.2929L9.17157 31.4645C8.97631 31.2692 8.65973 31.2692 8.46447 31.4645C8.2692 31.6597 8.2692 31.9763 8.46447 32.1716L11.6464 35.3536Z" fill="currentColor" /></svg>
                          <hr className="h-[1.5px] flex-1 self-center rounded-full border-0 bg-content-brand opacity-0" />
                        </div>
                      </li>
                      <li className="w-full">
                        <div className="w-full rounded-lg transition-transform duration-150 outline-none focus-visible:ring-2 focus-visible:ring-border-brand select-none touch-none" role="button" tabIndex={0} aria-disabled="false" aria-roledescription="draggable" aria-describedby="DndDescribedBy-0" aria-label="Reorder step 1: agent prompt">
                          <div className="group flex flex-row items-center gap-1 rounded-lg border bg-surface-popover py-3.5 pr-4 transition-all dark:bg-surface-base shadow-sm border-border-base hover:border-border-brand-subtle hover:shadow pl-2 w-full cursor-pointer" data-tracking-id="automation-step-node">
                            <DragHandleGlyph />
                            <div className="flex min-w-0 flex-1 flex-col items-start gap-1.5">
                              <div className="flex w-full items-center justify-between">
                                <span className="inline-flex items-center gap-1 rounded-[20px] border-0 bg-surface-brand-subtle text-content-brand text-sm select-none px-2 py-1 font-medium" data-variant="brand">
                                  <PromptGlyph />
                                  <span className="">Prompt</span>
                                </span>
                                <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear text-content-primary hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 h-6 text-sm aspect-square p-0" aria-label="Edit node" type="button" id="radix-:r2l:" aria-haspopup="menu" aria-expanded="false" data-state="closed">
                                  <EditNodeGlyph />
                                </button>
                              </div>
                              <div className="flex w-full flex-col rounded-lg border border-border-subtle touch-none">
                                <div className="relative [scrollbar-gutter:stable] overflow-x-auto overflow-y-auto pb-[3px] pr-[3px] flex max-h-[300px] flex-col max-h-none pointer-events-none" data-orientation="both">
                                  <p className="text-content-primary whitespace-pre-wrap break-words px-3 py-2 text-base font-normal">With prompts you can send messages to Hypervisor Agent</p>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                        <div className="-mt-px flex w-full flex-row items-start pl-6 transition-all duration-300 ease-in-out">
                          <svg width="24" height="36" viewBox="0 0 24 36" fill="none" xmlns="http://www.w3.org/2000/svg" className="mr-3 text-content-secondary"><title>Next step</title><defs><linearGradient id=":r2n:-g" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stopColor="currentColor" stopOpacity="0" /><stop offset="0.3" stopColor="currentColor" stopOpacity="0.25" /><stop offset="0.5" stopColor="currentColor" stopOpacity="0.65" /><stop offset="0.7" stopColor="currentColor" stopOpacity="0.25" /><stop offset="1" stopColor="currentColor" stopOpacity="0" /></linearGradient></defs><rect x="0" y="0" width="24" height="1" fill="url(#:r2n:-g)" /><path d="M11.5 0L11.5 35L12.5 35L12.5 0L11.5 0ZM11.6464 35.3536C11.8417 35.5488 12.1583 35.5488 12.3536 35.3536L15.5355 32.1716C15.7308 31.9763 15.7308 31.6597 15.5355 31.4645C15.3403 31.2692 15.0237 31.2692 14.8284 31.4645L12 34.2929L9.17157 31.4645C8.97631 31.2692 8.65973 31.2692 8.46447 31.4645C8.2692 31.6597 8.2692 31.9763 8.46447 32.1716L11.6464 35.3536Z" fill="currentColor" /></svg>
                          <hr className="h-[1.5px] flex-1 self-center rounded-full border-0 bg-content-brand opacity-0" />
                        </div>
                      </li>
                      <li className="w-full">
                        <div className="w-full rounded-lg transition-transform duration-150 outline-none focus-visible:ring-2 focus-visible:ring-border-brand select-none touch-none" role="button" tabIndex={0} aria-disabled="false" aria-roledescription="draggable" aria-describedby="DndDescribedBy-0" aria-label="Reorder step 2: command">
                          <div className="group flex flex-row items-center gap-1 rounded-lg border bg-surface-popover py-3.5 pr-4 transition-all dark:bg-surface-base shadow-sm border-border-base hover:border-border-brand-subtle hover:shadow pl-2 w-full cursor-pointer" data-tracking-id="automation-step-node">
                            <DragHandleGlyph />
                            <div className="flex min-w-0 flex-1 flex-col items-start gap-1.5">
                              <div className="flex w-full items-center justify-between">
                                <span className="inline-flex items-center gap-1 rounded-[20px] border-0 bg-surface-warning-subtle text-content-warning dark:text-content-warning-subtle text-sm select-none px-2 py-1 font-medium" data-variant="warning">
                                  <ShellScriptGlyph />
                                  <span className="">Shell Script</span>
                                </span>
                                <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear text-content-primary hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 h-6 text-sm aspect-square p-0" aria-label="Edit node" type="button" id="radix-:r2o:" aria-haspopup="menu" aria-expanded="false" data-state="closed">
                                  <EditNodeGlyph />
                                </button>
                              </div>
                              <div className="flex w-full flex-col rounded-lg border border-border-subtle touch-none">
                                <div className="relative [scrollbar-gutter:stable] overflow-x-auto overflow-y-auto pb-[3px] pr-[3px] flex max-h-[300px] flex-col max-h-none pointer-events-none" data-orientation="both">
                                  <p className="text-content-primary whitespace-pre-wrap break-words px-3 py-2 text-base font-normal font-mono">echo 'with commands you can run shell commands'</p>
                                </div>
                              </div>
                            </div>
                          </div>
                        </div>
                      </li>
                      <li className="relative w-full" aria-hidden="true">
                        <div className="absolute inset-x-0 top-0 flex h-4 items-center pl-6">
                          <div className="mr-3 w-6 shrink-0"></div>
                          <hr className="h-[1.5px] flex-1 rounded-full border-0 bg-content-brand opacity-0" />
                        </div>
                      </li>
                      <li className="-mt-px flex w-full pl-6">
                        <div className="group/add flex flex-col items-center">
                          <svg width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" className="text-content-secondary group-hover/add:text-border-brand"><defs><linearGradient id=":r2q:-sg" x1="0" y1="0" x2="1" y2="0"><stop offset="0" stopColor="currentColor" stopOpacity="0" /><stop offset="0.3" stopColor="currentColor" stopOpacity="0.25" /><stop offset="0.5" stopColor="currentColor" stopOpacity="0.65" /><stop offset="0.7" stopColor="currentColor" stopOpacity="0.25" /><stop offset="1" stopColor="currentColor" stopOpacity="0" /></linearGradient></defs><rect x="0" y="0" width="24" height="1" fill="url(#:r2q:-sg)" /><rect x="11.5" y="0" width="1" height="24" fill="currentColor" /></svg>
                          <button type="button" aria-label="Add step" data-tracking-id="step" className="flex size-8 items-center justify-center rounded-lg bg-content-primary text-content-invert transition-all hover:bg-content-secondary focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-border-brand">
                            <AddStepGlyph />
                          </button>
                        </div>
                      </li>
                    </ol>
                    <div id="DndDescribedBy-0" style={{ display: "none" }}>
                      To pick up a draggable item, press the space bar.
                      While dragging, use the arrow keys to move the item.
                      Press space again to drop the item in its new position, or press escape to cancel.
                    </div>
                    <div id="DndLiveRegion-0" role="status" aria-live="assertive" aria-atomic="true" style={{ position: "fixed", top: "0px", left: "0px", width: "1px", height: "1px", margin: "-1px", border: "0px", padding: "0px", overflow: "hidden", clip: "rect(0px, 0px, 0px, 0px)", clipPath: "inset(100%)", whiteSpace: "nowrap" }}></div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <AnchoredPopover open={agentOpen} onClose={() => setAgentOpen(false)} anchorRef={agentRef} side="top" align="start"><div onClick={(e) => { if ((e.target as HTMLElement).closest('[role="menuitem"], [role="option"], a, button')) setAgentOpen(false); }}><AgentModeMenu /></div></AnchoredPopover>
      <AnchoredPopover open={editNodeOpen} onClose={() => setEditNodeOpen(false)} anchorRef={editNodeRef} side="bottom" align="end"><div onClick={(e) => { if ((e.target as HTMLElement).closest('[role="menuitem"], a, button')) setEditNodeOpen(false); }}><AutomationEditNodeMenu /></div></AnchoredPopover>
    </main>
  );
}

export default HypervisorReferenceAutomationNew;
