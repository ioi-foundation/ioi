// Parity — opened states of sidebar shell controls, ported bit-for-bit from the
// IOI demo reference's LIVE DOM captures: exact element tree, classes, verbatim
// SVG paths and copy. Each export returns the converted role="menu"/role="dialog"/
// role="grid" element (Radix popper positioning wrappers stripped — we position
// these ourselves).

import type { CSSProperties } from "react";

const SettingsGlyph = () => (
  <svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M9.225 5.525L6.21875 4.83125L4.83125 6.21875L5.525 9.225L2.75 11.075V12.925L5.525 14.775L4.83125 17.7812L6.21875 19.1687L9.225 18.475L11.075 21.25H12.925L14.775 18.475L17.7812 19.1687L19.1687 17.7812L18.475 14.775L21.25 12.925V11.075L18.475 9.225L19.1687 6.21875L17.7812 4.83125L14.775 5.525L12.925 2.75H11.075L9.225 5.525Z" stroke="currentColor" strokeWidth="1.5" /><path d="M14.75 12C14.75 13.5188 13.5188 14.75 12 14.75C10.4812 14.75 9.25 13.5188 9.25 12C9.25 10.4812 10.4812 9.25 12 9.25C13.5188 9.25 14.75 10.4812 14.75 12Z" stroke="currentColor" strokeWidth="1.5" /></svg>
);
const CheckGlyph = () => (
  <svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6.75 13.0625L9.9 16.25L17.25 7.75" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const PlusBrandGlyph = () => (
  <svg className="text-content-brand" aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M12 6.75V12M12 12V17.25M12 12H6.75M12 12H17.25" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const ExternalLinkGlyph = () => (
  <svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M9.25 3.75H3.75V20.25H20.25V14.75M13.75 3.75H20.25V10.25M11 13L19.7451 4.25492" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const SupportGlyph = () => (
  <svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M3.75 3.75H20.25V18.25H15.0155L11.9979 20.75L9.0155 18.25H3.75V3.75Z" stroke="currentColor" strokeWidth="1.5" /><path d="M7.25 11.25C7.25 11.6642 7.58579 12 8 12C8.41421 12 8.75 11.6642 8.75 11.25C8.75 10.8358 8.41421 10.5 8 10.5C7.58579 10.5 7.25 10.8358 7.25 11.25ZM11.25 11.25C11.25 11.6642 11.5858 12 12 12C12.4142 12 12.75 11.6642 12.75 11.25C12.75 10.8358 12.4142 10.5 12 10.5C11.5858 10.5 11.25 10.8358 11.25 11.25ZM15.25 11.25C15.25 11.6642 15.5858 12 16 12C16.4142 12 16.75 11.6642 16.75 11.25C16.75 10.8358 16.4142 10.5 16 10.5C15.5858 10.5 15.25 10.8358 15.25 11.25Z" fill="currentColor" stroke="currentColor" strokeWidth="0.5" strokeLinecap="square" /></svg>
);
const LogoutGlyph = () => (
  <svg aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M11.25 20.25H3.75L3.75 3.75L11.25 3.75M9 12L19.5 12M15.75 16.5L20.25 12L15.75 7.5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);

export function OrgSwitcherMenu() {
  return (
    <div data-side="top" data-align="start" role="menu" aria-orientation="vertical" data-state="open" data-radix-menu-content="" dir="ltr" id="radix-:rv:" aria-labelledby="radix-:ru:" className="min-w-[8rem] overflow-hidden bg-surface-popover p-0 first:pt-1 last:pb-1 outline-none focus:outline-none data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 z-50 max-h-[min(80vh,600px)] w-full max-w-md select-none overflow-y-auto rounded-lg border border-border-light shadow-sm focus-visible:ring-0" translate="no" tabIndex={-1} data-orientation="vertical" style={{ outline: "none", width: "var(--radix-dropdown-menu-trigger-width)", "--radix-dropdown-menu-content-transform-origin": "var(--radix-popper-transform-origin)", "--radix-dropdown-menu-content-available-width": "var(--radix-popper-available-width)", "--radix-dropdown-menu-content-available-height": "var(--radix-popper-available-height)", "--radix-dropdown-menu-trigger-width": "var(--radix-popper-anchor-width)", "--radix-dropdown-menu-trigger-height": "var(--radix-popper-anchor-height)", pointerEvents: "auto" } as CSSProperties}>
      <div className="flex items-center justify-between px-3 py-2">
        <div className="flex flex-col">
          <div className="text-base text-content-primary">Levi Josman</div>
          <div className="text-sm text-content-secondary">josmanlevi@gmail.com</div>
        </div>
        <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg disabled:text-content-tertiary disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear hover:bg-surface-button-clear-accent data-[state=open]:bg-surface-button-clear-accent border border-border-base text-content-primary hover:text-content-accent data-[state=open]:text-content-accent disabled:border-opacity-1 focus-visible:outline-border-brand gap-2 text-base size-8 flex-shrink-0 p-0" aria-label="Open user settings" data-tracking-id="org-switcher-user-settings" data-state="closed">
          <SettingsGlyph />
        </button>
      </div>
      <div role="separator" aria-orientation="horizontal" className="my-1 h-px bg-content-tertiary/20 -mx-3"></div>
      <div className="px-3 py-1.5 text-sm text-content-secondary">Organizations</div>
      <div role="menuitem" className="relative flex select-none items-center rounded py-1.5 cursor-pointer text-base mx-1 h-8 focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 px-3 hover:bg-surface-hover focus:bg-surface-hover" aria-label="Switch to Levi Josman's Workspace 320 organization" aria-current="true" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
        <div className="flex w-full items-center justify-between gap-2">
          <div className="flex min-w-0 flex-1 items-center gap-2">
            <span data-slot="avatar" className="relative flex shrink-0 overflow-hidden size-6 flex-shrink-0 rounded-md">
              <div className="inline-flex size-full select-none items-center justify-center font-medium text-xs leading-6 bg-surface-brand-accent-09 text-content-brand-accent-07" role="img" aria-label="Levi Josman's Workspace 320's avatar"><span className="inline-block text-center">LJ</span></div>
            </span>
            <span className="min-w-0 truncate text-base" title="Levi Josman's Workspace 320">Levi Josman's Workspace 320</span>
            <span className="inline-flex items-center gap-1 rounded-[20px] border-0 font-normal px-1.5 py-0.5 text-xs bg-[rgb(var(--ona-brown-600)/0.15)] text-[rgb(var(--ona-brown-600))] dark:bg-[rgb(var(--ona-brown-100)/0.2)] dark:text-[rgb(var(--ona-brown-100))] flex-shrink-0" data-variant="neutral"><span className="">Core</span></span>
          </div>
          <div className="flex flex-shrink-0 items-center gap-1.5 pl-2">
            <CheckGlyph />
          </div>
        </div>
      </div>
      <a className="relative flex select-none items-center rounded py-1.5 cursor-pointer mx-1 focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 h-9 px-3 text-base hover:bg-surface-hover focus:bg-surface-hover text-content-brand" aria-label="Join an existing organization or create a new one" role="menuitem" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="" href="/join-organization">
        <div className="flex min-w-0 flex-1 items-center justify-start gap-2">
          <div className="flex size-6 flex-shrink-0 items-center justify-center rounded-full bg-surface-muted">
            <PlusBrandGlyph />
          </div>
          <span className="min-w-0 truncate text-content-brand">Join or create an organization</span>
        </div>
      </a>
      <div role="separator" aria-orientation="horizontal" className="my-1 h-px bg-content-tertiary/20 -mx-3"></div>
      <a href="https://ona.com/docs" target="_blank" rel="noopener noreferrer" role="menuitem" className="relative select-none rounded py-1.5 cursor-pointer mx-1 h-8 focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 flex items-center justify-between px-3 text-base hover:bg-surface-hover focus:bg-surface-hover" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
        <span>Docs</span>
        <div className="p-0.5 pl-2">
          <ExternalLinkGlyph />
        </div>
      </a>
      <div role="menuitem" className="relative select-none rounded py-1.5 cursor-pointer mx-1 h-8 focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 flex items-center justify-between px-3 text-base hover:bg-surface-hover focus:bg-surface-hover" aria-label="Open support chat" data-tracking-id="org-switcher-support" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
        <span>Support</span>
        <div className="p-0.5 pl-2">
          <SupportGlyph />
        </div>
      </div>
      <div role="menuitem" className="relative select-none rounded py-1.5 cursor-pointer mx-1 h-8 focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 flex items-center justify-between px-3 text-base hover:bg-surface-hover focus:bg-surface-hover" aria-label="Show keyboard shortcuts" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
        <span>Keyboard shortcuts</span>
        <div className="p-0.5 pl-2">
          <kbd className="flex items-center gap-1">
            <kbd className="rounded shadow-none inline-flex items-center justify-center my-0.5 text-center font-sans capitalize group-data-[component=tooltip]:bg-surface-accent-always-dark group-data-[component=tooltip]:text-content-always-white bg-surface-accent text-content-accent h-5 px-1.5 text-[12px] leading-5">Ctrl</kbd>
            <kbd className="rounded shadow-none inline-flex items-center justify-center my-0.5 text-center font-sans capitalize group-data-[component=tooltip]:bg-surface-accent-always-dark group-data-[component=tooltip]:text-content-always-white bg-surface-accent text-content-accent h-5 px-1.5 text-[12px] leading-5">/</kbd>
          </kbd>
        </div>
      </div>
      <div role="menuitem" className="relative select-none rounded py-1.5 cursor-pointer mx-1 h-8 focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 flex items-center justify-between px-3 text-base hover:bg-surface-hover focus:bg-surface-hover" aria-label="Log out of your account" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
        <span>Log out</span>
        <div className="p-0.5 pl-2">
          <LogoutGlyph />
        </div>
      </div>
    </div>
  );
}

export function SessionsFilterMenu() {
  return (
    <div data-side="bottom" data-align="end" role="menu" aria-orientation="vertical" data-state="open" data-radix-menu-content="" dir="ltr" id="radix-:rs:" aria-labelledby="radix-:rr:" className="z-50 min-w-[8rem] overflow-hidden border rounded-lg border-border-base bg-surface-popover p-0 shadow first:pt-1 last:pb-1 outline-none focus:outline-none focus-visible:ring-0 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 w-48" tabIndex={-1} data-orientation="vertical" style={{ outline: "none", "--radix-dropdown-menu-content-transform-origin": "var(--radix-popper-transform-origin)", "--radix-dropdown-menu-content-available-width": "var(--radix-popper-available-width)", "--radix-dropdown-menu-content-available-height": "var(--radix-popper-available-height)", "--radix-dropdown-menu-trigger-width": "var(--radix-popper-anchor-width)", "--radix-dropdown-menu-trigger-height": "var(--radix-popper-anchor-height)" } as CSSProperties}>
      <div className="mx-1 px-2 py-1.5 text-sm font-medium text-content-muted">Sort by</div>
      <div>
        <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-testid="sessions-filter-project" data-tracking-id="sessions-filter-project" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
          <span className="flex-1">Project</span>
          <svg className="ml-2 shrink-0 text-content-primary" aria-hidden="true" width="16px" height="16px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6.75 13.0625L9.9 16.25L17.25 7.75" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
        </div>
      </div>
      <div>
        <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-testid="sessions-filter-recently-active" data-tracking-id="sessions-filter-recently-active" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
          <span className="flex-1">Recently active</span>
        </div>
      </div>
      <div>
        <div role="separator" aria-orientation="horizontal" className="my-1 h-px bg-content-tertiary/20"></div>
        <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-testid="sessions-filter-archived" data-tracking-id="sessions-filter-archived" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">
          <span className="flex-1">Archived<span className="ml-1.5 rounded-full bg-surface-tertiary px-1.5 text-xs tabular-nums text-content-secondary">5</span></span>
        </div>
      </div>
    </div>
  );
}

export function WhatsNewDialog() {
  return (
    <div data-side="top" data-align="end" data-state="open" role="dialog" id="radix-:r1k:" className="z-50 flex select-none flex-col rounded-lg border border-border-base bg-surface-primary shadow-md" data-testid="changelog-preview" tabIndex={-1} style={{ width: "340px", "--radix-popover-content-transform-origin": "var(--radix-popper-transform-origin)", "--radix-popover-content-available-width": "var(--radix-popper-available-width)", "--radix-popover-content-available-height": "var(--radix-popper-available-height)", "--radix-popover-trigger-width": "var(--radix-popper-anchor-width)", "--radix-popover-trigger-height": "var(--radix-popper-anchor-height)" } as CSSProperties}>
      <div className="flex items-center justify-between border-b border-border-subtle px-5 py-3">
        <p className="text-sm font-semibold text-content-primary">What's new</p>
        <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear text-content-primary hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 h-6 text-sm -mr-1 p-1" aria-label="Dismiss" data-tracking-id="dismiss-changelog-preview" type="button">
          <svg aria-hidden="true" width="10px" height="10px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M4.75 4.75L19.25 19.25M19.25 4.75L4.75 19.25" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
        </button>
      </div>
      <div className="flex flex-col px-5 pb-4 pt-3">
        <p className="text-md font-semibold text-content-primary">User budgets for AI usage</p>
        <p className="mt-0.5 text-sm text-content-quaternary">June 10, 2026</p>
        <div className="relative mt-3 aspect-video w-full overflow-hidden rounded-md border border-border-base">
          <img src="https://docs.ona.com/images/changelog/user-budgets.webp" alt="User budgets for AI usage" className="absolute inset-0 size-full rounded-md object-cover" decoding="sync" />
        </div>
        <div className="mt-3 line-clamp-3 text-base text-content-secondary"><span className="inline"><span>Enterprise admins can now set monthly AI usage budgets for every member of their organization. Set one default budget for all users, then override it for individual users where needed.</span>
          <span>Budgets cover credit-billed AI usage and model spend through your own provider keys (BYOK), and each user sees their own utilization in the chat input as they work.</span>
          <span>Budgets are soft limits for visibility: nobody is blocked when they exceed one. Over-budget users are highlighted on Settings &gt; Usage, and budgets are included in CSV exports.</span>
          <span><a href="https://ona.com/docs/ona/billing/user-budgets" className="font-medium text-content-brand hover:underline" target="_blank" rel="noopener noreferrer">Learn more</a></span></span></div>
        <div className="mt-4 flex flex-col gap-2">
          <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-secondary text-content-primary hover:bg-surface-button-secondary-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 px-4 py-2 h-9 text-base w-full" data-tracking-id="changelog-learn-more"><span className="truncate">Learn more</span></button>
        </div>
      </div>
    </div>
  );
}

export function IoiEnvironmentsGrid() {
  return (
    <ul aria-label="Environments List for ioi" role="grid" id="react-aria327278260-:r43:" tabIndex={0} data-collection="react-aria327278260-:r42:" className="mx-[1px] my-1 flex flex-col gap-1">
      <li tabIndex={-1} data-collection="react-aria327278260-:r42:" data-key="019ee101-d37f-7537-bd92-2eeca49b6532" id="react-aria327278260-:r43:-019ee101-d37f-7537-bd92-2eeca49b6532" role="row" aria-label="019ee101-d37f-7537-bd92-2eeca49b6532">
        <div role="gridcell" aria-colindex={1} className="">
          <span data-state="closed">
            <div className="relative">
              <div>
                <div className="group w-full select-none rounded-lg p-1 pr-2 flex items-center justify-between gap-1 group-hover:gap-1 group-focus-within:gap-1 hover:bg-surface-hover sidebar-session-shortcut-row relative" data-testid="environment-entry-019ee101-d37f-7537-bd92-2eeca49b6532" data-sidebar-session-shortcut-url="/details/019ee101-d37f-7537-bd92-2eeca49b6532">
                  <a className="absolute inset-0 z-0 rounded-lg focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-ring-default focus-visible:ring-0" aria-label="master" href="/details/019ee101-d37f-7537-bd92-2eeca49b6532"></a>
                  <div className="pointer-events-none relative z-10 flex h-9 min-w-0 items-center gap-1">
                    <div className="relative size-6">
                      <span className="inline-flex align-middle" data-state="closed">
                        <svg aria-label="Stopped" width="24" height="24" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg" className="block text-content-tertiary group-focus-within:invisible group-hover:invisible" data-testid="status-dot"><circle cx="12" cy="12" r="2" fill="currentColor" /></svg>
                      </span>
                      <div className="absolute inset-0 hidden size-6 group-data-[state=open]/actions-context-menu:block group-focus-within:block group-hover:block">
                        <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 text-sm aspect-square p-0 size-6 border-0 text-content-secondary" aria-busy="false" aria-label="Start Environment" tabIndex={-1} data-tracking-id="start-environment-environment-status-indicator" data-state="closed">
                          <div className="relative size-4">
                            <div className="pointer-events-none absolute inset-0 flex items-center justify-center transition-all duration-300 scale-100 opacity-100 blur-none" aria-hidden="false">
                              <svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M5 4.948C5 3.9986 6.0503 3.42519 6.84891 3.93858L11.5965 6.99058C12.3313 7.46295 12.3313 8.53705 11.5965 9.00941L6.84891 12.0614C6.0503 12.5748 5 12.0014 5 11.052V4.948Z" fill="currentColor" /></svg>
                            </div>
                            <div className="pointer-events-none absolute inset-0 flex items-center justify-center transition-all duration-300 scale-50 opacity-0 blur-sm" aria-hidden="true">
                              <svg className="animate-spin" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true"><g clipPath="url(#clip0_599_1241)"><path d="M13.3594 8C13.3594 10.9599 10.9599 13.3594 8 13.3594V14.8906C11.8056 14.8906 14.8906 11.8056 14.8906 8H13.3594ZM8 13.3594C5.0401 13.3594 2.64063 10.9599 2.64063 8H1.10937C1.10937 11.8056 4.19441 14.8906 8 14.8906V13.3594ZM8 2.64063C10.9599 2.64063 13.3594 5.0401 13.3594 8H14.8906C14.8906 4.19441 11.8056 1.10937 8 1.10937V2.64063Z" fill="currentColor" /></g></svg>
                            </div>
                          </div>
                        </button>
                      </div>
                    </div>
                    <div className="flex min-w-0 flex-1 flex-col truncate">
                      <span className="inline-block truncate text-base" translate="no">master</span>
                      <span className="block truncate text-sm text-content-muted"><span><span>Stopped</span></span></span>
                    </div>
                  </div>
                  <div className="pointer-events-auto relative z-20 mr-0.5 flex items-center gap-0.5" data-tracking-id="open-environment-actions-sidebar-environment-list">
                    <span className="sr-only group-focus-within:not-sr-only group-hover:not-sr-only flex gap-0.5">
                      <span className="flex items-center" {...{ type: "button" }} id="radix-:r4b:" aria-haspopup="menu" aria-expanded="false" data-state="closed">
                        <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 h-6 text-sm aspect-square p-0 border-0 text-content-secondary" type="button" aria-label="Open, logs, and more" data-state="closed" data-open="closed" tabIndex={-1} data-tracking-id="open-logs-and-more">
                          <svg aria-hidden="true" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path fillRule="evenodd" clipRule="evenodd" d="M4.5 8C4.5 8.72488 3.91238 9.3125 3.1875 9.3125C2.46262 9.3125 1.875 8.72488 1.875 8C1.875 7.27512 2.46262 6.6875 3.1875 6.6875C3.91238 6.6875 4.5 7.27512 4.5 8ZM9.3125 8C9.3125 8.72488 8.72488 9.3125 8 9.3125C7.27512 9.3125 6.6875 8.72488 6.6875 8C6.6875 7.27512 7.27512 6.6875 8 6.6875C8.72488 6.6875 9.3125 7.27512 9.3125 8ZM12.8125 9.3125C13.5373 9.3125 14.125 8.72488 14.125 8C14.125 7.27512 13.5373 6.6875 12.8125 6.6875C12.0877 6.6875 11.5 7.27512 11.5 8C11.5 8.72488 12.0877 9.3125 12.8125 9.3125Z" fill="currentColor" /></svg>
                        </button>
                      </span>
                      <div></div>
                    </span>
                    <span className="sidebar-session-shortcut-hidden-when-active">
                      <button type="button" aria-label="Git changes" aria-haspopup="dialog" aria-expanded="false" aria-controls="radix-:r4h:" data-state="closed">
                        <span className="min-w-[20px] rounded-[10px] px-[6px] py-[2px] font-bold font-mono text-sm text-center bg-surface-brand text-content-brand dark:bg-content-brand/25 dark:text-surface-brand/80 inline-flex items-center gap-0.5">2<svg className="size-3" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6 7.1554L7.46965 8.62505C7.76255 8.91795 8.23745 8.91795 8.53035 8.62505L10 7.1554" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg></span>
                      </button>
                    </span>
                    <span className="min-w-[20px] rounded-[10px] px-[6px] py-[2px] font-bold font-mono text-sm text-center bg-surface-accent text-content-strong sidebar-session-shortcut-hint items-center gap-0.5 tabular-nums" aria-hidden="true"><span className="sidebar-session-shortcut-prefix"></span><span className="sidebar-session-shortcut-index" data-sidebar-session-shortcut-index="1"></span></span>
                  </div>
                </div>
              </div>
            </div>
          </span>
        </div>
      </li>
    </ul>
  );
}
