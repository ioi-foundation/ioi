// Parity — opened states of the Home composer pickers, ported bit-for-bit from the
// IOI demo reference's LIVE DOM captures: exact element tree, classes, verbatim
// SVG paths and copy. Each export returns the converted role="menu"/role="dialog"
// element (content-only, data-state="open" — we position these ourselves).

import type { CSSProperties } from "react";

const BrandMarkGlyph = ({ className }: { className: string }) => (
  <svg className={className} width="24" height="24" viewBox="108.97 89.47 781.56 706.06" fill="none" xmlns="http://www.w3.org/2000/svg"><g stroke="currentColor" strokeWidth="12" strokeLinejoin="round" strokeLinecap="round"><path d="M295.299 434.631L295.299 654.116 485.379 544.373z" /><path d="M500 535.931L697.39 421.968 500 308.005 302.61 421.968z" /><path d="M514.621 544.373L704.701 654.115 704.701 434.631z" /><path d="M280.678 662.557L280.678 425.086 123.957 695.903 145.513 740.594z" /><path d="M719.322 662.557L854.487 740.594 876.043 695.903 719.322 425.085z" /><path d="M287.988 675.22L151.883 753.8 164.878 780.741 470.757 780.741 287.988 675.22z" /><path d="M712.012 675.219L529.242 780.741 835.122 780.741 848.117 753.8 712.012 675.219z" /><path d="M492.689 295.343L492.689 104.779 466.038 104.779 287.055 414.066z" /><path d="M507.31 295.342L712.945 414.066 533.962 104.779 507.31 104.779z" /><path d="M302.61 666.778L500 780.741 500 552.815z" /><path d="M500 552.815L500 780.741 697.39 666.778z" /></g></svg>
);

const ChevronGlyph = () => (
  <svg className="ml-auto size-4 shrink-0" aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10 16L14 12L10 8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);

export function AgentModeMenu() {
  return (
    <div data-side="top" data-align="end" role="menu" aria-orientation="vertical" data-state="open" data-radix-menu-content="" dir="ltr" id="radix-:r37:" aria-labelledby="radix-:r36:" className="z-50 overflow-hidden border w-64 rounded-lg border-border-base bg-surface-popover p-0 shadow first:pt-1 last:pb-1 outline-none focus:outline-none focus-visible:ring-0 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 min-w-72 max-w-[calc(100vw-16px)]" tabIndex={-1} data-orientation="vertical" style={{ outline: "none", "--radix-dropdown-menu-content-transform-origin": "var(--radix-popper-transform-origin)", "--radix-dropdown-menu-content-available-width": "var(--radix-popper-available-width)", "--radix-dropdown-menu-content-available-height": "var(--radix-popper-available-height)", "--radix-dropdown-menu-trigger-width": "var(--radix-popper-anchor-width)", "--radix-dropdown-menu-trigger-height": "var(--radix-popper-anchor-height)", pointerEvents: "auto" } as CSSProperties}>
      <div className="overflow-hidden transition-[height] duration-200 ease-out motion-reduce:transition-none" style={{ height: "303px" }}>
        <div>
          <div className="mx-1 px-2 py-1.5 text-sm font-medium text-content-muted">Agent</div>
          <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
            <BrandMarkGlyph className="hypervisor-activity-brand-mark size-4" />
            <span className="ml-2 min-w-0 flex-1 truncate">Codex</span>
            <BrandMarkGlyph className="hypervisor-activity-brand-mark lucide lucide-check ml-auto shrink-0" />
          </div>
          <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
            <BrandMarkGlyph className="hypervisor-activity-brand-mark text-content-strong" />
            <span className="ml-2 min-w-0 flex-1 truncate">Hypervisor Agent</span>
          </div>
          <div role="separator" aria-orientation="horizontal" className="my-1 h-px bg-content-tertiary/20"></div>
          <div role="menuitem" id="radix-:r45:" aria-haspopup="menu" aria-expanded="false" aria-controls="radix-:r44:" data-state="closed" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 data-[state=open]:bg-surface-hover" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
            <span className="min-w-0 shrink-0">Mode</span>
            <kbd className="flex items-center gap-1 ml-2">
              <kbd className="rounded shadow-none inline-flex items-center justify-center my-0.5 text-center font-sans capitalize group-data-[component=tooltip]:bg-surface-accent-always-dark group-data-[component=tooltip]:text-content-always-white bg-surface-muted text-content-muted h-4 px-1 text-[12px] leading-4">Ctrl</kbd>
              <kbd className="rounded shadow-none inline-flex items-center justify-center my-0.5 text-center font-sans capitalize group-data-[component=tooltip]:bg-surface-accent-always-dark group-data-[component=tooltip]:text-content-always-white bg-surface-muted text-content-muted h-4 px-1 text-[12px] leading-4">Shift</kbd>
              <kbd className="rounded shadow-none inline-flex items-center justify-center my-0.5 text-center font-sans capitalize group-data-[component=tooltip]:bg-surface-accent-always-dark group-data-[component=tooltip]:text-content-always-white bg-surface-muted text-content-muted h-4 px-1 text-[12px] leading-4">M</kbd>
            </kbd>
            <span className="flex-1"></span>
            <span className="mr-2 truncate text-content-secondary">Agent</span>
            <ChevronGlyph />
          </div>
          <div role="menuitem" id="radix-:r48:" aria-haspopup="menu" aria-expanded="false" aria-controls="radix-:r47:" data-state="closed" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 data-[state=open]:bg-surface-hover" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
            <span className="min-w-0 shrink-0">Model</span>
            <span className="flex-1"></span>
            <span className="mr-2 truncate text-content-secondary">GPT-5.5</span>
            <ChevronGlyph />
          </div>
          <div role="menuitem" id="radix-:r4b:" aria-haspopup="menu" aria-expanded="false" aria-controls="radix-:r4a:" data-state="closed" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 data-[state=open]:bg-surface-hover" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
            <span className="min-w-0 shrink-0">Reasoning</span>
            <span className="flex-1"></span>
            <span className="mr-2 truncate text-content-secondary">Medium</span>
            <ChevronGlyph />
          </div>
          <div role="menuitem" id="radix-:r4e:" aria-haspopup="menu" aria-expanded="false" aria-controls="radix-:r4d:" data-state="closed" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 data-[state=open]:bg-surface-hover" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
            <span className="min-w-0 shrink-0">Speed</span>
            <span className="flex-1"></span>
            <span className="mr-2 truncate text-content-secondary">Standard</span>
            <ChevronGlyph />
          </div>
          <div role="menuitem" className="relative flex select-none cursor-pointer focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 mx-1 mt-2 h-auto min-h-0 flex-col items-start gap-0.5 rounded-lg bg-surface-button-secondary px-3 py-2 text-left text-sm text-content-secondary hover:bg-surface-button-secondary-accent focus:bg-surface-button-secondary-accent disabled:opacity-50" data-tracking-id="agent-mode-codex-login-offer" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
            <span className="font-medium text-content-primary">Already have ChatGPT or Codex?</span>
            <span className="font-normal text-content-secondary">Use your ChatGPT plan for Codex and save your Hypervisor credits.</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export function WorkInProjectMenu() {
  return (
    <div data-side="bottom" data-align="center" data-state="open" role="dialog" id="radix-:r2l:" tabIndex={-1} style={{ "--radix-popover-content-transform-origin": "var(--radix-popper-transform-origin)", "--radix-popover-content-available-width": "var(--radix-popper-available-width)", "--radix-popover-content-available-height": "var(--radix-popper-available-height)", "--radix-popover-trigger-width": "var(--radix-popper-anchor-width)", "--radix-popover-trigger-height": "var(--radix-popper-anchor-height)" } as CSSProperties}>
      <div className="mt-1" style={{ width: "714px" }}>
        <div tabIndex={-1} className="flex size-full flex-col overflow-hidden rounded-lg border border-border-base bg-surface-popover p-0 shadow" cmdk-root="">
          <label cmdk-label="" htmlFor="radix-:r4k:" id="radix-:r4j:" style={{ position: "absolute", width: "1px", height: "1px", padding: "0px", margin: "-1px", overflow: "hidden", clip: "rect(0px, 0px, 0px, 0px)", whiteSpace: "nowrap", borderWidth: "0px" }}></label>
          <div className="flex w-full items-center border-b border-border-base">
            <div className="relative flex w-full items-center">
              <div className="border-border-base w-full border-b-0">
                <div className="flex h-10 w-full items-center gap-2 px-3 py-2" cmdk-input-wrapper="">
                  <div className="flex aspect-square size-6 items-center justify-center">
                    <svg className="size-4 shrink-0 text-content-muted" aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M20 20L16.1265 16.1265M16.1265 16.1265C17.4385 14.8145 18.25 13.002 18.25 11C18.25 6.99594 15.0041 3.75 11 3.75C6.99594 3.75 3.75 6.99594 3.75 11C3.75 15.0041 6.99594 18.25 11 18.25C13.002 18.25 14.8145 17.4385 16.1265 16.1265Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
                  </div>
                  <input placeholder="Type to search…" className="flex w-full focus-visible:ring-0 text-base p-0 border-0 outline-none file:border-0 file:bg-transparent file:text-sm file:font-medium disabled:cursor-text placeholder:text-content-muted border-border-base disabled:bg-surface-input text-content-primary [&amp;[readonly]]:bg-transparent h-5 max-w-none rounded-none bg-transparent py-0" cmdk-input="" autoComplete="off" autoCorrect="off" spellCheck="false" aria-autocomplete="list" role="combobox" aria-expanded="true" aria-controls="radix-:r4i:" aria-labelledby="radix-:r4j:" id="radix-:r4k:" type="text" defaultValue="" />
                </div>
              </div>
            </div>
          </div>
          <div className="w-full overflow-y-auto overflow-x-hidden" cmdk-list="" role="listbox" tabIndex={-1} aria-label="Suggestions" id="radix-:r4i:" style={{ "--cmdk-list-height": "132.0px" } as CSSProperties}>
            <div cmdk-list-sizer="">
              <div className="overflow-hidden p-1 text-content-primary [&amp;_[cmdk-group-heading]]:px-2 [&amp;_[cmdk-group-heading]]:py-1.5 [&amp;_[cmdk-group-heading]]:text-sm [&amp;_[cmdk-group-heading]]:font-normal [&amp;_[cmdk-group-heading]]:text-content-muted" cmdk-group="" role="presentation" data-value="Select an option">
                <div cmdk-group-heading="" aria-hidden="true" id="radix-:r4n:">Select an option</div>
                <div cmdk-group-items="" role="group" aria-labelledby="radix-:r4n:">
                  <div className="relative flex w-full cursor-default select-none items-center gap-2 rounded-md px-2 py-1.5 text-base outline-none data-[disabled=true]:pointer-events-none data-[selected=true]:bg-surface-hover data-[disabled=true]:opacity-50 [&amp;_svg]:pointer-events-none [&amp;_svg]:size-4 [&amp;_svg]:shrink-0" id="radix-:r4o:" cmdk-item="" role="option" aria-disabled="false" aria-selected="true" data-disabled="false" data-selected="true" data-value="Start from project">
                    <svg className="size-4 shrink-0" aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M3.75 3.75H10.25V10.25H3.75V3.75Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /><path d="M13.75 3.75H20.25V10.25H13.75V3.75Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /><path d="M3.75 13.75H10.25V20.25H3.75V13.75Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /><path d="M13.75 13.75H20.25V20.25H13.75V13.75Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" /></svg>Start from project
                  </div>
                  <div className="relative flex w-full cursor-default select-none items-center gap-2 rounded-md px-2 py-1.5 text-base outline-none data-[disabled=true]:pointer-events-none data-[selected=true]:bg-surface-hover data-[disabled=true]:opacity-50 [&amp;_svg]:pointer-events-none [&amp;_svg]:size-4 [&amp;_svg]:shrink-0" id="radix-:r4p:" cmdk-item="" role="option" aria-disabled="false" aria-selected="false" data-disabled="false" data-selected="false" data-value="Start from URL">
                    <svg className="size-4 shrink-0" aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M19.7781 4.22184L4.22173 19.7782M21.25 12C21.25 17.1086 17.1086 21.25 12 21.25C6.89137 21.25 2.75 17.1086 2.75 12C2.75 6.89137 6.89137 2.75 12 2.75C17.1086 2.75 21.25 6.89137 21.25 12ZM18.5161 18.516C17.3165 19.7156 13.4267 17.7707 9.82802 14.172C6.22931 10.5733 4.28442 6.68352 5.48399 5.48395C6.68356 4.28438 10.5733 6.22927 14.172 9.82798C17.7708 13.4267 19.7156 17.3165 18.5161 18.516Z" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>Start from URL
                  </div>
                  <div className="relative flex w-full cursor-default select-none items-center gap-2 rounded-md px-2 py-1.5 text-base outline-none data-[disabled=true]:pointer-events-none data-[selected=true]:bg-surface-hover data-[disabled=true]:opacity-50 [&amp;_svg]:pointer-events-none [&amp;_svg]:size-4 [&amp;_svg]:shrink-0" id="radix-:r4q:" cmdk-item="" role="option" aria-disabled="false" aria-selected="false" data-disabled="false" data-selected="false" data-value="Start from scratch">
                    <svg className="size-4 shrink-0" aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M19.25 15.5972V2.75H4.75V21.25H5.69717M19.25 15.5972V15.9643C19.25 16.7267 19.0019 17.4686 18.5429 18.0786C17.0405 20.075 14.6826 21.25 12.1786 21.25H5.69717M19.25 15.5972C19.25 18.1667 15.6406 18.1667 14.0938 17.1389L12.9892 18.2397C11.0552 20.1672 8.43222 21.25 5.69717 21.25" stroke="currentColor" strokeWidth="1.5" /></svg>Start from scratch
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export function AddToPromptMenu() {
  return (
    <div data-side="top" data-align="start" role="menu" aria-orientation="vertical" data-state="open" data-radix-menu-content="" dir="ltr" id="radix-:r33:" aria-labelledby="radix-:r32:" className="z-50 min-w-[8rem] overflow-hidden border rounded-lg border-border-base bg-surface-popover p-0 shadow first:pt-1 last:pb-1 outline-none focus:outline-none focus-visible:ring-0 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 w-64" tabIndex={-1} data-orientation="vertical" style={{ outline: "none", "--radix-dropdown-menu-content-transform-origin": "var(--radix-popper-transform-origin)", "--radix-dropdown-menu-content-available-width": "var(--radix-popper-available-width)", "--radix-dropdown-menu-content-available-height": "var(--radix-popper-available-height)", "--radix-dropdown-menu-trigger-width": "var(--radix-popper-anchor-width)", "--radix-dropdown-menu-trigger-height": "var(--radix-popper-anchor-height)", pointerEvents: "auto" } as CSSProperties}>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-tracking-id="add-image-prompt-input" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
        <span className="mr-2"><svg width="14" height="14" viewBox="0 0 14 14" fill="none" xmlns="http://www.w3.org/2000/svg" overflow="visible"><path d="M7.71985 12.8137L12.25 8.17499" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M9.3333 4.50001L4.42516 9.50851C4.20644 9.72729 4.08357 10.024 4.08357 10.3333C4.08357 10.6427 4.20644 10.9394 4.42516 11.1582C4.64394 11.3769 4.94063 11.4998 5.24999 11.4998C5.55935 11.4998 5.85604 11.3769 6.07482 11.1582L10.983 6.14968C11.4204 5.71211 11.6662 5.11873 11.6662 4.50001C11.6662 3.88129 11.4204 3.28791 10.983 2.85034C10.5454 2.41291 9.952 2.16718 9.3333 2.16718C8.71461 2.16718 8.12122 2.41291 7.68366 2.85034L2.77491 7.85826C2.11847 8.51469 1.74969 9.40501 1.74969 10.3333C1.74969 11.2617 2.11847 12.152 2.77491 12.8084C3.43134 13.4649 4.32166 13.8336 5.24999 13.8336C6.17833 13.8336 7.06864 13.4649 7.72508 12.8084" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /></svg></span>Attach file or image
      </div>
      <div role="menuitem" id="radix-:r4t:" aria-haspopup="menu" aria-expanded="false" aria-controls="radix-:r4s:" data-state="closed" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 data-[state=open]:bg-surface-hover" data-tracking-id="mcp-integrations-button" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
        <span className="mr-2"><svg width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M2.5 2.5H6.83333V6.83333H2.5V2.5Z" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M2.5 9.16666H6.83333V13.5H2.5V9.16666Z" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M9.1665 11.3333C9.1665 10.1367 10.1366 9.16666 11.3332 9.16666C12.5298 9.16666 13.4998 10.1367 13.4998 11.3333C13.4998 12.5299 12.5298 13.5 11.3332 13.5C10.1366 13.5 9.1665 12.5299 9.1665 11.3333Z" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /><path d="M9.1665 2.5H13.4998V6.83333H9.1665V2.5Z" stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" /></svg></span>Integrations<svg className="ml-auto size-4 shrink-0" aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M10 16L14 12L10 8" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
      </div>
    </div>
  );
}
