// Parity — opened states of the Automations page menus, ported bit-for-bit from
// the IOI demo reference's LIVE DOM captures: exact element tree, classes,
// verbatim SVG paths and copy. Each export returns the converted
// role="listbox"/role="menu" element (Radix/react-aria popper positioning
// wrappers stripped — we position these ourselves).

import type { CSSProperties } from "react";

const CheckGlyph = () => (
  <svg className="size-4" aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6.75 13.0625L9.9 16.25L17.25 7.75" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);

export function StatusFilterMenu() {
  return (
    <ul id="react-aria2529388104-:r2g:" aria-labelledby="react-aria2529388104-:r2h:" role="listbox" tabIndex={-1} data-collection="react-aria2529388104-:r7o:" className="m-0 min-h-0 flex-1 list-none overflow-auto p-0" style={{ outline: "none" }}>
      <li role="option" aria-selected="true" tabIndex={0} data-collection="react-aria2529388104-:r7o:" data-react-aria-pressable="true" data-key="all" id="react-aria2529388104-:r2g:-option-all" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50 bg-surface-hover aria-disabled:bg-transparent">
        <div className="min-w-0 flex-1">All</div>
        <span className="flex-none"><CheckGlyph /></span>
      </li>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria2529388104-:r7o:" data-react-aria-pressable="true" data-key="running" id="react-aria2529388104-:r2g:-option-running" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">Running</div>
      </li>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria2529388104-:r7o:" data-react-aria-pressable="true" data-key="completed" id="react-aria2529388104-:r2g:-option-completed" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">Completed</div>
      </li>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria2529388104-:r7o:" data-react-aria-pressable="true" data-key="failed" id="react-aria2529388104-:r2g:-option-failed" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">Failed</div>
      </li>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria2529388104-:r7o:" data-react-aria-pressable="true" data-key="enabled" id="react-aria2529388104-:r2g:-option-enabled" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">Enabled</div>
      </li>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria2529388104-:r7o:" data-react-aria-pressable="true" data-key="disabled" id="react-aria2529388104-:r2g:-option-disabled" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">Disabled</div>
      </li>
    </ul>
  );
}

export function SortMenu() {
  return (
    <ul id="react-aria2529388104-:r2o:" aria-labelledby="react-aria2529388104-:r2p:" role="listbox" tabIndex={-1} data-collection="react-aria2529388104-:r8h:" className="m-0 min-h-0 flex-1 list-none overflow-auto p-0" style={{ outline: "none" }}>
      <li role="option" aria-selected="true" tabIndex={0} data-collection="react-aria2529388104-:r8h:" data-react-aria-pressable="true" data-key="recent-run" id="react-aria2529388104-:r2o:-option-recent-run" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50 bg-surface-hover aria-disabled:bg-transparent">
        <div className="min-w-0 flex-1">Recently completed</div>
        <span className="flex-none"><CheckGlyph /></span>
      </li>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria2529388104-:r8h:" data-react-aria-pressable="true" data-key="name" id="react-aria2529388104-:r2o:-option-name" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">Name</div>
      </li>
    </ul>
  );
}

export function AutomationRowMenu() {
  return (
    <div data-side="bottom" data-align="end" role="menu" aria-orientation="vertical" data-state="open" data-radix-menu-content="" dir="ltr" id="radix-:r7a:" aria-labelledby="radix-:r79:" className="z-50 min-w-[8rem] overflow-hidden border rounded-lg border-border-base bg-surface-popover p-0 shadow first:pt-1 last:pb-1 outline-none focus:outline-none data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 focus-visible:ring-0 w-48" tabIndex={-1} data-orientation="vertical" style={{ outline: "none", "--radix-dropdown-menu-content-transform-origin": "var(--radix-popper-transform-origin)", "--radix-dropdown-menu-content-available-width": "var(--radix-popper-available-width)", "--radix-dropdown-menu-content-available-height": "var(--radix-popper-available-height)", "--radix-dropdown-menu-trigger-width": "var(--radix-popper-anchor-width)", "--radix-dropdown-menu-trigger-height": "var(--radix-popper-anchor-height)", pointerEvents: "auto" } as CSSProperties}>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-testid="workflow-actions-dropdown-copy-id" data-tracking-id="copy-id-workflow-actions-dropdown" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">Copy Automation ID</div>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-testid="workflow-actions-dropdown-duplicate" data-tracking-id="duplicate-workflow-actions-dropdown" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">Duplicate</div>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-testid="workflow-actions-dropdown-share" data-tracking-id="share-workflow-actions-dropdown" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">Share</div>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-testid="workflow-actions-dropdown-edit" data-tracking-id="edit-workflow-actions-dropdown" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">Edit</div>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-testid="workflow-actions-dropdown-toggle-disabled" data-tracking-id="toggle-disabled-workflow-actions-dropdown" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">Disable</div>
      <div role="separator" aria-orientation="horizontal" className="my-1 h-px bg-content-tertiary/20"></div>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 text-content-destructive hover:text-content-destructive focus:text-content-destructive data-[search-highlighted]:text-content-destructive" data-testid="workflow-actions-dropdown-delete" data-tracking-id="delete-workflow-actions-dropdown" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">Delete</div>
    </div>
  );
}
