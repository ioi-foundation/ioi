// Parity — opened states of Settings/Project/Automation dropdown/listbox/menu
// controls, ported bit-for-bit from the IOI demo reference's LIVE DOM captures:
// exact element tree, classes, verbatim SVG paths and copy. Each export returns
// the converted role="listbox" <ul> / role="menu" <div> element as-is
// (content-only, data-state="open"; Radix popper positioning wrappers stripped).

import type { CSSProperties } from "react";

const CheckGlyph = () => (
  <svg className="size-4" aria-hidden="true" width="24px" height="24px" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M6.75 13.0625L9.9 16.25L17.25 7.75" stroke="currentColor" strokeWidth="1.5" strokeLinecap="square" /></svg>
);

export function SettingsCreditUsageSelect() {
  return (
    <ul id="react-aria1234935341-:r1l:" aria-labelledby="react-aria1234935341-:r1m:" role="listbox" tabIndex={-1} data-collection="react-aria1234935341-:r20:" className="m-0 min-h-0 flex-1 list-none overflow-auto p-0" style={{ outline: "none" }}>
      <li role="option" aria-selected="true" tabIndex={0} data-collection="react-aria1234935341-:r20:" data-key="7" data-react-aria-pressable="true" id="react-aria1234935341-:r1l:-option-7" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50 bg-surface-hover aria-disabled:bg-transparent">
        <div className="min-w-0 flex-1"><span>7 days</span></div>
        <span className="flex-none"><CheckGlyph /></span>
      </li>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria1234935341-:r20:" data-key="30" data-react-aria-pressable="true" id="react-aria1234935341-:r1l:-option-30" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1"><span>30 days</span></div>
      </li>
    </ul>
  );
}

export function SettingsMembersSelect0() {
  return (
    <ul id="react-aria7570567438-:r32:" aria-labelledby="react-aria7570567438-:r33:" role="listbox" tabIndex={-1} data-collection="react-aria7570567438-:r4b:" className="m-0 min-h-0 flex-1 list-none overflow-auto p-0" style={{ outline: "none" }}>
      <li role="option" aria-selected="true" tabIndex={0} data-collection="react-aria7570567438-:r4b:" data-key="all" data-react-aria-pressable="true" id="react-aria7570567438-:r32:-option-all" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50 bg-surface-hover aria-disabled:bg-transparent">
        <div className="min-w-0 flex-1">All roles</div>
        <span className="flex-none"><CheckGlyph /></span>
      </li>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria7570567438-:r4b:" data-key="admin" data-react-aria-pressable="true" id="react-aria7570567438-:r32:-option-admin" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">Admin</div>
      </li>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria7570567438-:r4b:" data-key="member" data-react-aria-pressable="true" id="react-aria7570567438-:r32:-option-member" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">Member</div>
      </li>
    </ul>
  );
}

export function SettingsMembersSelect1() {
  return (
    <ul id="react-aria7570567438-:r3a:" aria-labelledby="react-aria7570567438-:r3b:" role="listbox" tabIndex={-1} data-collection="react-aria7570567438-:r4r:" className="m-0 min-h-0 flex-1 list-none overflow-auto p-0" style={{ outline: "none" }}>
      <li role="option" aria-selected="true" tabIndex={0} data-collection="react-aria7570567438-:r4r:" data-key="all" data-react-aria-pressable="true" id="react-aria7570567438-:r3a:-option-all" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50 bg-surface-hover aria-disabled:bg-transparent">
        <div className="min-w-0 flex-1">All (0)</div>
        <span className="flex-none"><CheckGlyph /></span>
      </li>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria7570567438-:r4r:" data-key="active" data-react-aria-pressable="true" id="react-aria7570567438-:r3a:-option-active" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">Active (0)</div>
      </li>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria7570567438-:r4r:" data-key="suspended" data-react-aria-pressable="true" id="react-aria7570567438-:r3a:-option-suspended" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">Suspended (0)</div>
      </li>
    </ul>
  );
}

export function SettingsAgentPolicySelect0() {
  return (
    <ul id="react-aria3520505560-:r23:" aria-labelledby="codex-reasoning-ceiling" role="listbox" tabIndex={-1} data-collection="react-aria3520505560-:r2k:" className="m-0 min-h-0 flex-1 list-none overflow-auto p-0" style={{ outline: "none" }}>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria3520505560-:r2k:" data-key="1" data-react-aria-pressable="true" id="react-aria3520505560-:r23:-option-1" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">Low</div>
      </li>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria3520505560-:r2k:" data-key="2" data-react-aria-pressable="true" id="react-aria3520505560-:r23:-option-2" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">Medium</div>
      </li>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria3520505560-:r2k:" data-key="3" data-react-aria-pressable="true" id="react-aria3520505560-:r23:-option-3" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">High</div>
      </li>
      <li role="option" aria-selected="true" tabIndex={0} data-collection="react-aria3520505560-:r2k:" data-key="4" data-react-aria-pressable="true" id="react-aria3520505560-:r23:-option-4" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50 bg-surface-hover aria-disabled:bg-transparent">
        <div className="min-w-0 flex-1">Extra high</div>
        <span className="flex-none"><CheckGlyph /></span>
      </li>
    </ul>
  );
}

export function SettingsAgentPolicySelect1() {
  return (
    <ul id="react-aria3520505560-:r2c:" aria-labelledby="codex-service-tier" role="listbox" tabIndex={-1} data-collection="react-aria3520505560-:r37:" className="m-0 min-h-0 flex-1 list-none overflow-auto p-0" style={{ outline: "none" }}>
      <li role="option" aria-selected="false" tabIndex={-1} data-collection="react-aria3520505560-:r37:" data-key="standard" data-react-aria-pressable="true" id="react-aria3520505560-:r2c:-option-standard" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50">
        <div className="min-w-0 flex-1">Standard</div>
      </li>
      <li role="option" aria-selected="true" tabIndex={0} data-collection="react-aria3520505560-:r37:" data-key="fast" data-react-aria-pressable="true" id="react-aria3520505560-:r2c:-option-fast" className="flex w-full cursor-pointer select-none items-center justify-between gap-2 rounded px-2 py-1.5 text-base text-content-primary focus:outline-none focus:ring-0 aria-disabled:cursor-default aria-disabled:opacity-50 bg-surface-hover aria-disabled:bg-transparent">
        <div className="min-w-0 flex-1">Fast</div>
        <span className="flex-none"><CheckGlyph /></span>
      </li>
    </ul>
  );
}

export function SettingsAgentPolicySelect2() {
  return (
    <ul id="react-aria3520505560-:r1p:" aria-labelledby="react-aria3520505560-:r1q:" role="listbox" data-collection="react-aria3520505560-:r3k:" className="h-auto max-h-[320px] overflow-auto p-1">
      <li role="option" aria-selected="true" data-collection="react-aria3520505560-:r3k:" data-key="__all__" data-react-aria-pressable="true" id="react-aria3520505560-:r1p:-option-__all__" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1" data-active-item="true">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 bg-surface-hover group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1">
            <div className="flex min-w-0 items-center gap-1.5">
              <span className="mr-2"><span className="flex size-5 items-center justify-center rounded bg-surface-tertiary text-xs">∞</span></span>
              <div className="min-w-0 flex-1"><p className="truncate text-content-primary">All</p></div>
            </div>
          </div>
          <span className="flex-none"><CheckGlyph /></span>
        </div>
      </li>
      <li role="option" aria-selected="false" data-collection="react-aria3520505560-:r3k:" data-key="019ed02a-f982-7408-8503-520b665a0e5b" data-react-aria-pressable="true" id="react-aria3520505560-:r1p:-option-019ed02a-f982-7408-8503-520b665a0e5b" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1">
            <div className="flex min-w-0 items-center gap-1.5">
              <span className="mr-2"><span data-slot="avatar" className="relative flex shrink-0 overflow-hidden size-5 rounded"><div className="inline-flex size-full select-none items-center justify-center font-medium text-xs leading-6 bg-surface-brand-accent-07 text-content-brand-accent-05" role="img" aria-label="org-members's avatar"><span className="inline-block text-center">O</span></div></span></span>
              <div className="min-w-0 flex-1"><p className="truncate text-content-primary">org-members</p></div>
            </div>
          </div>
        </div>
      </li>
    </ul>
  );
}

export function SettingsIntegrationsSelect() {
  return (
    <ul id="react-aria6341102433-:r1q:" aria-labelledby="react-aria6341102433-:r1r:" role="listbox" data-collection="react-aria6341102433-:r2v:" className="h-auto max-h-[320px] overflow-auto p-1">
      <li role="option" aria-selected="true" data-collection="react-aria6341102433-:r2v:" data-key="all" data-react-aria-pressable="true" id="react-aria6341102433-:r1q:-option-all" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1" data-active-item="true">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 bg-surface-hover group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1"><p className="truncate text-content-primary">All</p></div>
          <span className="flex-none"><CheckGlyph /></span>
        </div>
      </li>
      <li role="option" aria-selected="false" data-collection="react-aria6341102433-:r2v:" data-key="source-control" data-react-aria-pressable="true" id="react-aria6341102433-:r1q:-option-source-control" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1"><p className="truncate text-content-primary">Source control</p></div>
        </div>
      </li>
      <li role="option" aria-selected="false" data-collection="react-aria6341102433-:r2v:" data-key="project-management" data-react-aria-pressable="true" id="react-aria6341102433-:r1q:-option-project-management" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1"><p className="truncate text-content-primary">Project management</p></div>
        </div>
      </li>
      <li role="option" aria-selected="false" data-collection="react-aria6341102433-:r2v:" data-key="observability" data-react-aria-pressable="true" id="react-aria6341102433-:r1q:-option-observability" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1"><p className="truncate text-content-primary">Observability</p></div>
        </div>
      </li>
      <li role="option" aria-selected="false" data-collection="react-aria6341102433-:r2v:" data-key="knowledge" data-react-aria-pressable="true" id="react-aria6341102433-:r1q:-option-knowledge" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1"><p className="truncate text-content-primary">Knowledge</p></div>
        </div>
      </li>
      <li role="option" aria-selected="false" data-collection="react-aria6341102433-:r2v:" data-key="mcp" data-react-aria-pressable="true" id="react-aria6341102433-:r1q:-option-mcp" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1"><p className="truncate text-content-primary">MCP</p></div>
        </div>
      </li>
    </ul>
  );
}

export function SettingsEnvSelect0() {
  return (
    <ul id="react-aria8782451475-:r1s:" aria-labelledby="react-aria8782451475-:r1t:" role="listbox" data-collection="react-aria8782451475-:r59:" className="h-auto max-h-[320px] overflow-auto p-1">
      <li role="option" aria-selected="true" data-collection="react-aria8782451475-:r59:" data-key="all" data-react-aria-pressable="true" id="react-aria8782451475-:r1s:-option-all" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1" data-active-item="true">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 bg-surface-hover group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1"><p className="truncate text-content-primary">All Projects</p></div>
          <span className="flex-none"><CheckGlyph /></span>
        </div>
      </li>
      <li role="option" aria-selected="false" data-collection="react-aria8782451475-:r59:" data-key="019ee100-f64f-7554-946f-405f46528c91" data-react-aria-pressable="true" id="react-aria8782451475-:r1s:-option-019ee100-f64f-7554-946f-405f46528c91" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1"><p className="truncate text-content-primary">ioi</p></div>
        </div>
      </li>
    </ul>
  );
}

export function SettingsEnvSelect1() {
  return (
    <ul id="react-aria8782451475-:r25:" aria-labelledby="react-aria8782451475-:r26:" role="listbox" data-collection="react-aria8782451475-:r5m:" className="h-auto max-h-[320px] overflow-auto p-1">
      <li role="option" aria-selected="true" data-collection="react-aria8782451475-:r5m:" data-key="all" data-react-aria-pressable="true" id="react-aria8782451475-:r25:-option-all" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1" data-active-item="true">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 bg-surface-hover group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1">
            <div className="flex items-center">
              <div className="flex flex-col">
                <p className="truncate text-content-primary">All members</p>
                <p className="text-sm text-content-secondary">Member</p>
              </div>
            </div>
          </div>
          <span className="flex-none"><CheckGlyph /></span>
        </div>
      </li>
      <li role="option" aria-selected="false" data-collection="react-aria8782451475-:r5m:" data-key="019ed111-8694-75fc-ae39-66da8a6c08e8" data-react-aria-pressable="true" id="react-aria8782451475-:r25:-option-019ed111-8694-75fc-ae39-66da8a6c08e8" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1">
            <div className="flex items-center">
              <span className="mr-2"><span data-slot="avatar" className="relative flex shrink-0 overflow-hidden rounded-full size-6"><img data-slot="avatar-image" data-testid="avatar-image" className="aspect-square size-full object-cover" referrerPolicy="no-referrer" loading="lazy" alt="Hypervisor" src="https://app.gitpod.io/static/assets/ona-service-account-avatar-C04VslwU.jpg" /></span></span>
              <div className="flex flex-col">
                <p className="truncate text-content-primary">Hypervisor</p>
                <p className="text-sm text-content-secondary">Built-in agent</p>
              </div>
            </div>
          </div>
        </div>
      </li>
      <li role="option" aria-selected="false" data-collection="react-aria8782451475-:r5m:" data-key="019ed02a-f98f-7b13-8517-79305e5788e8" data-react-aria-pressable="true" id="react-aria8782451475-:r25:-option-019ed02a-f98f-7b13-8517-79305e5788e8" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1">
            <div className="flex items-center">
              <span className="mr-2"><span data-slot="avatar" className="relative flex shrink-0 overflow-hidden rounded-full size-6"><img data-slot="avatar-image" data-testid="avatar-image" className="aspect-square size-full object-cover" referrerPolicy="no-referrer" loading="lazy" src="https://lh3.googleusercontent.com/a/ACg8ocIBE-yWc_g6QMTLx_fI4gV6NkJ6Q1ERKa4YxbkEy2U9RsS3DCHb=s96-c" /></span></span>
              <div className="flex flex-col">
                <p className="truncate text-content-primary">Levi Josman</p>
                <p className="text-sm text-content-secondary">Signed in with Google</p>
              </div>
            </div>
          </div>
        </div>
      </li>
    </ul>
  );
}

export function ProjectEnvClassMenu() {
  return (
    <ul id="react-aria2165904409-:r3p:" aria-labelledby="react-aria2165904409-:r3q:" role="listbox" data-collection="react-aria2165904409-:r41:" className="h-auto max-h-[320px] overflow-auto p-1">
      <li role="option" aria-selected="false" data-collection="react-aria2165904409-:r41:" data-key="019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7de3-8375-713bff6e8b0d" data-react-aria-pressable="true" id="react-aria2165904409-:r3p:-option-019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7de3-8375-713bff6e8b0d" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1" data-active-item="true">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 bg-surface-hover group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1">
            <div className="flex items-center">
              <div className="flex flex-col">
                <p className="truncate text-content-primary"><span className="font-medium">Regular</span><span className="ml-1 font-normal text-content-tertiary">Hypervisor Cloud (US01)</span></p>
                <p className="text-sm text-content-secondary">4 vCPU / 16 GiB / 80 GiB disk • m6i.xlarge</p>
              </div>
            </div>
          </div>
        </div>
      </li>
      <li role="option" aria-selected="false" data-collection="react-aria2165904409-:r41:" data-key="019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7de6-9c30-c9025d1b9513" data-react-aria-pressable="true" id="react-aria2165904409-:r3p:-option-019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7de6-9c30-c9025d1b9513" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1">
            <div className="flex items-center">
              <div className="flex flex-col">
                <p className="truncate text-content-primary"><span className="font-medium">Large</span><span className="ml-1 font-normal text-content-tertiary">Hypervisor Cloud (US01)</span></p>
                <p className="text-sm text-content-secondary">8 vCPU / 32 GiB / 100 GiB disk • m6i.2xlarge</p>
              </div>
            </div>
          </div>
        </div>
      </li>
      <li role="option" aria-selected="false" data-collection="react-aria2165904409-:r41:" data-key="019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7dea-afe4-cf9725e05fcf" data-react-aria-pressable="true" id="react-aria2165904409-:r3p:-option-019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7dea-afe4-cf9725e05fcf" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1">
            <div className="flex items-center">
              <div className="flex flex-col">
                <p className="truncate text-content-primary"><span className="font-medium">GPU Large</span><span className="ml-1 font-normal text-content-tertiary">Hypervisor Cloud (US01)</span></p>
                <p className="text-sm text-content-secondary">16 vCPU / 64 GiB / 300 GiB disk • g5.4xlarge</p>
              </div>
            </div>
          </div>
        </div>
      </li>
      <li role="option" aria-selected="false" data-collection="react-aria2165904409-:r41:" data-key="019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7ded-95aa-28416abc02ce" data-react-aria-pressable="true" id="react-aria2165904409-:r3p:-option-019ed02a-fe51-766f-8663-1c478f189fde:019ed02a-ffd8-7ded-95aa-28416abc02ce" className="group/combobox-item flex cursor-pointer select-none items-center justify-between pb-1 text-base text-content-primary first:pt-0 last:pb-0 scroll-mt-1 last:scroll-mb-1">
        <div className="flex w-full items-center justify-between gap-2 rounded px-2 py-1.5 group-hover/combobox-item:bg-surface-hover">
          <div className="min-w-0 flex-1">
            <div className="flex items-center">
              <div className="flex flex-col">
                <p className="truncate text-content-primary"><span className="font-medium">Extra Large</span><span className="ml-1 font-normal text-content-tertiary">Hypervisor Cloud (US01)</span></p>
                <p className="text-sm text-content-secondary">32 vCPU / 128 GiB / 200 GiB disk • m6i.8xlarge</p>
              </div>
            </div>
          </div>
        </div>
      </li>
    </ul>
  );
}

export function AutomationEditNodeMenu() {
  return (
    <div data-side="bottom" data-align="end" role="menu" aria-orientation="vertical" data-state="open" data-radix-menu-content="" dir="ltr" id="radix-:r2m:" aria-labelledby="radix-:r2l:" className="z-50 min-w-[8rem] overflow-hidden border w-64 rounded-lg border-border-base bg-surface-popover p-0 shadow first:pt-1 last:pb-1 outline-none focus:outline-none focus-visible:ring-0 data-[state=open]:animate-in data-[state=closed]:animate-out data-[state=closed]:fade-out-0 data-[state=open]:fade-in-0 data-[state=closed]:zoom-out-95 data-[state=open]:zoom-in-95 data-[side=bottom]:slide-in-from-top-2 data-[side=left]:slide-in-from-right-2 data-[side=right]:slide-in-from-left-2 data-[side=top]:slide-in-from-bottom-2 max-w-40" tabIndex={-1} data-orientation="vertical" style={{ outline: "none", "--radix-dropdown-menu-content-transform-origin": "var(--radix-popper-transform-origin)", "--radix-dropdown-menu-content-available-width": "var(--radix-popper-available-width)", "--radix-dropdown-menu-content-available-height": "var(--radix-popper-available-height)", "--radix-dropdown-menu-trigger-width": "var(--radix-popper-anchor-width)", "--radix-dropdown-menu-trigger-height": "var(--radix-popper-anchor-height)", pointerEvents: "auto" } as CSSProperties}>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus:text-content-primary focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50" data-tracking-id="edit" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">Edit</div>
      <div role="menuitem" className="relative flex select-none items-center rounded px-2 py-1.5 cursor-pointer hover:bg-surface-hover text-base mx-1 h-8 focus:bg-surface-hover focus-visible:ring-0 data-[search-highlighted]:bg-surface-hover data-[disabled]:pointer-events-none data-[disabled]:opacity-50 text-content-destructive hover:text-content-destructive focus:text-content-destructive data-[search-highlighted]:text-content-destructive" data-tracking-id="remove-step" tabIndex={-1} data-orientation="vertical" data-radix-collection-item="">Remove step</div>
    </div>
  );
}
