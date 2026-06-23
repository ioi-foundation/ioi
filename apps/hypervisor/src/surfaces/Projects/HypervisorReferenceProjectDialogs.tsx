// Parity — opened states of project surface dialogs/menus, ported bit-for-bit
// from the IOI demo reference's LIVE DOM captures: exact element tree, classes,
// verbatim SVG paths and copy. Each export returns the converted role="dialog"/
// role="menu" element (content-only, data-state="open"; no outer positioning).

import type { CSSProperties } from "react";

const PlusGlyph = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="lucide lucide-plus"><path d="M5 12h14" /><path d="M12 5v14" /></svg>
);
const ChevronDownGlyph = () => (
  <svg aria-hidden="true" width="20px" height="20px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M8 10L12 14L16 10" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const CloseGlyph = () => (
  <svg aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M7.75 7.75L16.25 16.25M16.25 7.75L7.75 16.25" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);
const SpinnerGlyph = () => (
  <svg className="animate-spin" width="16" height="16" viewBox="0 0 16 16" fill="none" xmlns="http://www.w3.org/2000/svg"><g clipPath="url(#clip0_599_1241)"><path d="M13.3594 8C13.3594 10.9599 10.9599 13.3594 8 13.3594V14.8906C11.8056 14.8906 14.8906 11.8056 14.8906 8H13.3594ZM8 13.3594C5.0401 13.3594 2.64063 10.9599 2.64063 8H1.10937C1.10937 11.8056 4.19441 14.8906 8 14.8906V13.3594ZM8 2.64063C10.9599 2.64063 13.3594 5.0401 13.3594 8H14.8906C14.8906 4.19441 11.8056 1.10937 8 1.10937V2.64063Z" fill="currentColor" /></g></svg>
);

const hiddenSelectStyle: CSSProperties = { border: "0px", clip: "rect(0px, 0px, 0px, 0px)", clipPath: "inset(50%)", height: "1px", margin: "-1px", overflow: "hidden", padding: "0px", position: "absolute", width: "1px", whiteSpace: "nowrap" };

export function NewProjectDialog() {
  return (
    <div role="dialog" id="radix-:r36:" aria-describedby="radix-:r38:" aria-labelledby="radix-:r37:" data-state="open" className="relative flex max-h-[90%] flex-col overflow-x-auto p-6 rounded-xl border border-border-base bg-surface-secondary shadow-modal duration-200 @container data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 w-[600px] max-w-[600px]" data-track-location="create_project_modal" tabIndex={-1} style={{ pointerEvents: "auto" }}>
      <header className="mb-6 flex flex-col gap-1.5 text-left">
        <h2 id="radix-:r37:" className="text-lg font-semibold leading-none tracking-tight text-content-primary">New Project</h2>
        <p id="radix-:r38:" className="m-0 p-0 text-base text-content-secondary">A project links your repository to Hypervisor so you can launch dev environments, run agent sessions to build features or fix issues, and trigger Automations. Instantly, anywhere.</p>
      </header>
      <div className="overflow-x-visible px-1 text-base py-1.5 text-content-muted">
        <form id="create-project-form" className="flex flex-col gap-4">
          <div className="flex flex-col gap-4">
            <div className="flex flex-col gap-0">
              <div className="flex w-full flex-col gap-1">
                <div className="flex gap-2">
                  <div className="flex-1">
                    <div data-track-location="context_url_input">
                      <div className="flex items-center gap-2 h-9 w-full max-w-[600px] px-3 py-2 rounded-lg border border-border-light text-base disabled:cursor-text focus-within:ring-4 focus-within:ring-ring-default focus-visible:ring-4 focus-visible:ring-ring-default group-data-[state=error]:border-border-error group-data-[state=error]:ring-ring-destructive disabled:bg-inherit bg-surface-input [&amp;[readonly]]:border-border-subtle [&amp;[readonly]]:bg-transparent data-[readonly]:border-border-subtle data-[readonly]:bg-transparent">
                        <input id=":r40:" aria-label="" type="text" aria-autocomplete="list" autoComplete="off" placeholder="https://github.com/microsoft/vscode-remote-try-go" autoCorrect="off" spellCheck="false" tabIndex={0} role="combobox" aria-expanded="false" data-testid="context-url-input" className="flex h-full w-full max-w-[600px] focus-visible:ring-0 text-base p-0 border-0 outline-none file:border-0 file:bg-transparent file:text-sm file:font-medium disabled:cursor-text placeholder:text-content-muted border-border-base disabled:bg-surface-input text-content-primary bg-transparent [&amp;[readonly]]:bg-transparent" defaultValue="" />
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          <div className="flex flex-col gap-2">
            <label className="text-base text-content-primary peer-disabled:cursor-text peer-disabled:opacity-70 font-medium" htmlFor="project-name">Project name</label>
            <input className="p-0 outline-none file:border-0 file:bg-transparent file:text-sm file:font-medium placeholder:text-content-muted text-content-primary flex items-center gap-2 h-9 w-full max-w-[600px] px-3 py-2 rounded-lg border border-border-light text-base disabled:cursor-text focus-within:ring-4 focus-within:ring-ring-default focus-visible:ring-4 focus-visible:ring-ring-default group-data-[state=error]:border-border-error group-data-[state=error]:ring-ring-destructive disabled:bg-inherit bg-surface-input [&amp;[readonly]]:border-border-subtle [&amp;[readonly]]:bg-transparent data-[readonly]:border-border-subtle data-[readonly]:bg-transparent" id="project-name" data-testid="project-name-input" name="projectName" placeholder="My Project" required defaultValue="" />
          </div>
          <div className="flex w-full flex-col gap-2">
            <div className="flex items-center">
              <label className="text-base text-content-primary peer-disabled:cursor-text peer-disabled:opacity-70 font-medium" htmlFor=":r3l:">Environment Classes</label>
            </div>
            <div className="flex w-full flex-col gap-2">
              <div className="group flex flex-col gap-1" data-testid="environment-class-select-trigger">
                <div aria-hidden="true" data-react-aria-prevent-focus="true" data-a11y-ignore="aria-hidden-focus" data-testid="hidden-select-container" style={hiddenSelectStyle}>
                  <label><select tabIndex={-1} disabled><option></option><option value="019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7dd9-a299-6d9e2b8af49e">019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7dd9-a299-6d9e2b8af49e</option><option value="019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7de3-8375-713bff6e8b0d">019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7de3-8375-713bff6e8b0d</option><option value="019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7de6-9c30-c9025d1b9513">019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7de6-9c30-c9025d1b9513</option><option value="019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7dea-afe4-cf9725e05fcf">019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7dea-afe4-cf9725e05fcf</option><option value="019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7ded-95aa-28416abc02ce">019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7ded-95aa-28416abc02ce</option></select></label>
                </div>
                <button type="button" disabled data-react-aria-pressable="true" aria-label="Environment class" id="react-aria3471161965-:r3p:" aria-labelledby="react-aria3471161965-:r3u: react-aria3471161965-:r3p:" aria-haspopup="listbox" aria-expanded="false" className="flex h-9 min-w-40 items-center justify-between gap-2 rounded-lg border border-border-input-default bg-surface-input px-3 transition-all duration-150 ease-out outline-none focus:border-border-input-active focus:ring-1 focus:ring-border-brand focus:ring-offset-1 aria-expanded:border-border-input-active aria-expanded:ring-4 aria-expanded:ring-ring-default aria-expanded:ring-offset-0 cursor-not-allowed opacity-50 w-full">
                  <span className="truncate"><span className="truncate text-base text-content-primary"><span className="flex items-center gap-2"><PlusGlyph /><span>Add environment class</span></span></span></span>
                  <ChevronDownGlyph />
                </button>
              </div>
            </div>
          </div>
          <div className="flex min-h-4 flex-col items-center justify-center gap-2 text-sm" data-testid="errors"></div>
        </form>
      </div>
      <footer className="flex gap-2 sm:flex-row mt-6 flex-row justify-between">
        <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg disabled:text-content-tertiary disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear hover:bg-surface-button-clear-accent data-[state=open]:bg-surface-button-clear-accent border border-border-base text-content-primary hover:text-content-accent data-[state=open]:text-content-accent disabled:border-opacity-1 focus-visible:outline-border-brand gap-2 px-4 py-2 h-9 text-base" type="button" data-tracking-id="cancel-create-project-modal"><span className="truncate">Cancel</span></button>
        <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-primary text-content-primary-inverted hover:bg-surface-button-primary-accent disabled:opacity-50 disabled:bg-surface-primary-inverted disabled:text-content-primary-inverted focus-visible:outline-border-brand gap-2 px-4 py-2 h-9 text-base" disabled aria-busy="false" type="submit" form="create-project-form" data-tracking-id="create-project-create-project-modal"><span className="truncate">Create</span></button>
      </footer>
      <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 h-8 text-base absolute right-4 top-4 aspect-square p-0 text-content-muted" aria-label="Close" type="button">
        <CloseGlyph />
      </button>
    </div>
  );
}

export function ShareProjectDialog() {
  return (
    <div role="dialog" id="radix-:r3o:" aria-describedby="radix-:r3q:" aria-labelledby="radix-:r3p:" data-state="open" className="relative flex max-h-[90%] w-full flex-col overflow-x-auto p-6 rounded-xl border border-border-base bg-surface-secondary shadow-modal duration-200 @container data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 max-w-xl" data-testid="share-resource-modal" data-track-location="share_resource_modal" tabIndex={-1} style={{ pointerEvents: "auto" }}>
      <header className="mb-6 flex flex-col gap-1.5 text-left">
        <h2 id="radix-:r3p:" className="text-lg font-semibold leading-none tracking-tight text-content-primary">Share ioi project</h2>
      </header>
      <div className="flex flex-col gap-4" data-testid="3-sharing-content">
        <div className="flex flex-col gap-2">
          <h4 className="text-base text-content-primary font-medium">General access</h4>
          <div className="relative w-full">
            <span className="sr-only">Select</span>
            <div aria-hidden="true" data-react-aria-prevent-focus="true" data-a11y-ignore="aria-hidden-focus" data-testid="hidden-select-container" style={hiddenSelectStyle}>
              <label>Select<select tabIndex={-1}><option></option><option value="shared">shared</option><option value="unshared">unshared</option></select></label>
            </div>
            <button type="button" tabIndex={0} data-react-aria-pressable="true" id="react-aria3862923233-:r3v:" aria-label="Select" aria-labelledby="react-aria3862923233-:r44: react-aria3862923233-:r3v:" aria-haspopup="listbox" data-testid="general-access-select" className="flex w-full items-center justify-between gap-2 text-base text-content-primary outline-none disabled:cursor-not-allowed disabled:opacity-50 h-9 px-3 rounded-lg border border-border-input-default bg-surface-input transition-all duration-150 ease-out focus:border-border-input-active focus:ring-4 focus:ring-ring-default focus:ring-offset-0 aria-expanded:border-border-input-active aria-expanded:ring-4 aria-expanded:ring-ring-default aria-expanded:ring-offset-0">
              <span id="react-aria3862923233-:r44:" className="truncate"><div className="ml-2 flex items-center gap-2 text-base"><span data-slot="avatar" className="relative flex shrink-0 overflow-hidden rounded-full size-5"><div className="inline-flex size-full select-none items-center justify-center font-medium text-[10px] leading-4 bg-surface-brand-accent-09 text-content-brand-accent-07" role="img" aria-label="Levi Josman's Workspace 320's avatar"><span className="inline-block text-center">LJ</span></div></span><span>Everyone in Levi Josman's Workspace 320</span></div></span>
              <ChevronDownGlyph />
            </button>
          </div>
        </div>
      </div>
      <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 h-8 text-base absolute right-4 top-4 aspect-square p-0 text-content-muted" aria-label="Close" type="button">
        <CloseGlyph />
      </button>
    </div>
  );
}

export function CreateEnvironmentDialog() {
  return (
    <div role="dialog" id="radix-:r3m:" aria-describedby="radix-:r3o:" aria-labelledby="radix-:r3n:" data-state="open" className="relative flex max-h-[90%] w-full flex-col overflow-x-auto rounded-xl border border-border-base shadow-modal duration-200 @container data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 min-h-0 max-w-lg self-center bg-surface-glass p-8" data-track-location="create_environment_scm_authentication_modal" tabIndex={-1} style={{ pointerEvents: "auto" }}>
      <h2 id="radix-:r3n:" className="text-lg font-semibold leading-none tracking-tight text-content-primary sr-only">Authentication for </h2>
      <p id="radix-:r3o:" className="m-0 p-0 text-base text-content-secondary sr-only">Configure authentication for  repository access</p>
      <div className="flex flex-col items-center gap-4 px-4 pt-4">
        <div className="flex items-center justify-center py-8">
          <SpinnerGlyph />
        </div>
      </div>
      <button className="select-none inline-flex items-center font-medium justify-center whitespace-nowrap transition-colors rounded-lg border-0 disabled:border-opacity-0 disabled:pointer-events-none disabled:shadow-none focus-visible:outline focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:animate-focus-pulse motion-reduce:animate-none active:outline-0 focus:ring-0 bg-surface-button-clear hover:bg-surface-button-clear-accent hover:text-content-accent data-[state=open]:bg-surface-button-clear-accent data-[state=open]:text-content-accent disabled:opacity-50 disabled:text-content-primary focus-visible:outline-border-brand gap-2 h-8 text-base absolute right-4 top-4 aspect-square p-0 text-content-muted" aria-label="Close" type="button">
        <CloseGlyph />
      </button>
    </div>
  );
}

export function ProjectActionsMenu() {
  return (
    <div data-side="bottom" data-align="end" role="menu" aria-orientation="vertical" data-state="open" data-radix-menu-content="" dir="ltr" id="radix-:r2i:" aria-labelledby="radix-:r2h:" className="z-50 min-w-[8rem] overflow-hidden border rounded-lg border-border-base bg-surface-popover p-0 shadow first:pt-1 last:pb-1 outline-none focus:outline-none data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 focus-visible:ring-0 w-48" tabIndex={-1} data-orientation="vertical" style={{ outline: "none", "--radix-dropdown-menu-content-transform-origin": "var(--radix-popper-transform-origin)", "--radix-dropdown-menu-content-available-width": "var(--radix-popper-available-width)", "--radix-dropdown-menu-content-available-height": "var(--radix-popper-available-height)", "--radix-dropdown-menu-trigger-width": "var(--radix-popper-anchor-width)", "--radix-dropdown-menu-trigger-height": "var(--radix-popper-anchor-height)", pointerEvents: "auto" } as CSSProperties}>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-tracking-id="copy-id-project-actions" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">Copy ID</div>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-tracking-id="copy-url-project-actions" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">Copy URL</div>
      <div role="separator" aria-orientation="horizontal" className="my-1 h-px bg-content-tertiary/20"></div>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-testid="project-actions-dropdown-share" data-tracking-id="share-project-actions" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">Share project</div>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-testid="project-actions-dropdown-edit" data-tracking-id="edit-project-actions" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">Edit</div>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 text-content-red" data-tracking-id="delete-project-actions" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">Delete</div>
    </div>
  );
}
