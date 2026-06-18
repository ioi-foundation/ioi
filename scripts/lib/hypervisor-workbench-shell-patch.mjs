import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

import { HYPERVISOR_WORKBENCH_ADAPTER_HOST } from "./hypervisor-workbench-adapter-host-paths.mjs";

const JS_START = "// IOI_HYPERVISOR_WORKBENCH_SHELL_PATCH_START";
const JS_END = "// IOI_HYPERVISOR_WORKBENCH_SHELL_PATCH_END";
const CSS_START = "/* IOI_HYPERVISOR_WORKBENCH_SHELL_PATCH_START */";
const CSS_END = "/* IOI_HYPERVISOR_WORKBENCH_SHELL_PATCH_END */";
const ELECTRON_MAIN_MENU_VISIBILITY_PATCH =
  "        if (process.env.IOI_WORKBENCH_NATIVE_SHELL === '1') {\n            return 'hidden';\n        }\n";
const ELECTRON_MAIN_APPLICATION_MENU_PATCH =
  "            if (process.env.IOI_WORKBENCH_NATIVE_SHELL === '1') {\n                menu = null;\n            }\n";
const ELECTRON_MAIN_CUSTOM_TITLEBAR_PATCH_LEGACY =
  "        if (process.env.IOI_WORKBENCH_NATIVE_SHELL === '1') {\n            return TitlebarStyle.CUSTOM;\n        }\n";
const ELECTRON_MAIN_CUSTOM_TITLEBAR_PATCH =
  "        return TitlebarStyle.CUSTOM; // Hypervisor shell uses VS Code's custom titlebar/menubar substrate.\n";

function upsertMarkedBlock(filePath, startMarker, endMarker, block) {
  const existing = existsSync(filePath) ? readFileSync(filePath, "utf8") : "";
  const start = existing.indexOf(startMarker);
  const end = existing.indexOf(endMarker);
  let next;

  if (start >= 0 && end > start) {
    next = `${existing.slice(0, start)}${block}${existing.slice(end + endMarker.length)}`;
  } else {
    next = `${existing.replace(/\s*$/, "")}\n\n${block}\n`;
  }

  if (next !== existing) {
    writeFileSync(filePath, next);
  }
}

function workbenchShellCss() {
  return `${CSS_START}
.monaco-workbench.ioi-hypervisor-native-shell {
  --ioi-shell-header-height: 0px;
  --ioi-shell-code-menu-height: 30px;
  --ioi-shell-rail-width: 48px;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-primary-rail {
  position: fixed;
  top: var(--ioi-shell-header-top, 35px);
  left: 0;
  bottom: 22px;
  width: var(--ioi-shell-rail-width);
  z-index: 100002;
  box-sizing: border-box;
  display: flex;
  flex-direction: column;
  align-items: stretch;
  padding: 8px 0;
  border-right: 1px solid var(--vscode-activityBar-border, rgba(255,255,255,.08));
  background: var(--vscode-activityBar-background, #181818);
  color: var(--vscode-activityBar-inactiveForeground, #858585);
  pointer-events: auto;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-primary-rail .ioi-native-rail-button {
  width: 48px;
  height: 46px;
  flex: 0 0 46px;
  display: grid;
  place-items: center;
  border: 0;
  border-left: 2px solid transparent;
  background: transparent;
  color: inherit;
  cursor: pointer;
  font: inherit;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-primary-rail .ioi-native-rail-button .codicon {
  font-size: 22px;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-primary-rail .ioi-native-rail-svg {
  width: 24px;
  height: 24px;
  display: block;
  background: currentColor;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-primary-rail .ioi-native-rail-workflows {
  mask: url("data:image/svg+xml,%3Csvg width='24' height='24' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M5 4.5a2 2 0 1 1 0 4 2 2 0 0 1 0-4Zm14 0a2 2 0 1 1 0 4 2 2 0 0 1 0-4ZM5 15.5a2 2 0 1 1 0 4 2 2 0 0 1 0-4Zm14 0a2 2 0 1 1 0 4 2 2 0 0 1 0-4ZM7.2 6.5h9.6v1.5H7.2V6.5Zm10.4 2.1 1.2.8-3.8 5.7-1.2-.8 3.8-5.7Zm-11.2 0 3.8 5.7-1.2.8-3.8-5.7 1.2-.8Zm1 8.2h9.2v1.5H7.4v-1.5Z' fill='currentColor'/%3E%3C/svg%3E") center / 24px 24px no-repeat;
  -webkit-mask: url("data:image/svg+xml,%3Csvg width='24' height='24' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M5 4.5a2 2 0 1 1 0 4 2 2 0 0 1 0-4Zm14 0a2 2 0 1 1 0 4 2 2 0 0 1 0-4ZM5 15.5a2 2 0 1 1 0 4 2 2 0 0 1 0-4Zm14 0a2 2 0 1 1 0 4 2 2 0 0 1 0-4ZM7.2 6.5h9.6v1.5H7.2V6.5Zm10.4 2.1 1.2.8-3.8 5.7-1.2-.8 3.8-5.7Zm-11.2 0 3.8 5.7-1.2.8-3.8-5.7 1.2-.8Zm1 8.2h9.2v1.5H7.4v-1.5Z' fill='currentColor'/%3E%3C/svg%3E") center / 24px 24px no-repeat;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-primary-rail .ioi-native-rail-button:hover,
.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-primary-rail .ioi-native-rail-button.is-active {
  color: var(--vscode-activityBar-foreground, #fff);
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-primary-rail .ioi-native-rail-button.is-active {
  border-left-color: var(--vscode-activityBar-activeBorder, var(--vscode-focusBorder, #0078d4));
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode #ioi-hypervisor-primary-rail {
  display: none;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-workbench-native-header {
  display: none !important;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-workbench-code-menu {
  position: fixed;
  top: calc(var(--ioi-shell-header-top, 35px) + var(--ioi-shell-header-height));
  left: var(--ioi-shell-header-left, 48px);
  right: 0;
  height: var(--ioi-shell-code-menu-height);
  z-index: 100000;
  box-sizing: border-box;
  display: none;
  align-items: center;
  gap: 2px;
  padding: 0 14px;
  border-bottom: 1px solid var(--vscode-panel-border, rgba(255,255,255,.12));
  background: var(--vscode-titleBar-activeBackground, var(--vscode-editor-background, #1f1f1f));
  color: var(--vscode-titleBar-activeForeground, var(--vscode-foreground, #d4d4d4));
  pointer-events: auto;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode #ioi-hypervisor-workbench-code-menu {
  display: none !important;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-workbench-code-menu .ioi-code-menu-button {
  height: 24px;
  min-width: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 0;
  border-radius: 4px;
  padding: 0 8px;
  background: transparent;
  color: inherit;
  font: inherit;
  font-size: 12px;
  white-space: nowrap;
  cursor: pointer;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-workbench-code-menu .ioi-code-menu-button:hover,
.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-workbench-code-menu .ioi-code-menu-button:focus-visible,
.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-workbench-code-menu .ioi-code-menu-button.is-open {
  background: var(--vscode-toolbar-hoverBackground, rgba(255,255,255,.10));
  outline: none;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-workbench-code-menu-dropdown {
  position: fixed;
  top: calc(var(--ioi-shell-header-top, 35px) + var(--ioi-shell-header-height) + var(--ioi-shell-code-menu-height));
  left: var(--ioi-code-menu-dropdown-left, var(--ioi-shell-header-left, 48px));
  z-index: 100003;
  display: none;
  min-width: 236px;
  max-width: 340px;
  box-sizing: border-box;
  padding: 5px;
  border: 1px solid var(--vscode-menu-border, var(--vscode-panel-border, rgba(255,255,255,.18)));
  border-radius: 6px;
  background: var(--vscode-menu-background, #252526);
  color: var(--vscode-menu-foreground, var(--vscode-foreground, #d4d4d4));
  box-shadow: 0 16px 36px rgba(0,0,0,.38);
  pointer-events: auto;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode #ioi-hypervisor-workbench-code-menu-dropdown.is-open {
  display: grid;
  gap: 1px;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-workbench-code-menu-dropdown .ioi-code-menu-item {
  width: 100%;
  min-height: 28px;
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto;
  align-items: center;
  gap: 18px;
  border: 0;
  border-radius: 4px;
  padding: 4px 10px;
  background: transparent;
  color: inherit;
  font: inherit;
  font-size: 12px;
  text-align: left;
  cursor: pointer;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-workbench-code-menu-dropdown .ioi-code-menu-item:hover,
.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-workbench-code-menu-dropdown .ioi-code-menu-item:focus-visible {
  background: var(--vscode-menu-selectionBackground, #094771);
  color: var(--vscode-menu-selectionForeground, #fff);
  outline: none;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-workbench-code-menu-dropdown .ioi-code-menu-shortcut {
  color: var(--vscode-descriptionForeground, #a8a8a8);
  font-size: 11px;
  white-space: nowrap;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-workbench-code-menu-dropdown .ioi-code-menu-separator {
  height: 1px;
  margin: 4px 8px;
  background: var(--vscode-menu-separatorBackground, var(--vscode-panel-border, rgba(255,255,255,.14)));
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-hypervisor-mode .part.titlebar .menubar {
  opacity: 0 !important;
  width: 0 !important;
  min-width: 0 !important;
  overflow: hidden !important;
  pointer-events: none !important;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode .part.titlebar .menubar {
  opacity: 1 !important;
  width: auto !important;
  min-width: revert !important;
  overflow: visible !important;
  pointer-events: auto !important;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode #ioi-hypervisor-workbench-native-header,
.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode #ioi-hypervisor-workbench-code-menu,
.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode #ioi-hypervisor-workbench-code-menu-dropdown {
  display: none !important;
}

.monaco-workbench.ioi-hypervisor-native-shell .part.editor > .content {
  padding-top: 0 !important;
  box-sizing: border-box !important;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode .part.editor > .content {
  padding-top: 0 !important;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-hypervisor-mode .part.editor .editor-group-container > .title,
.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-hypervisor-mode .part.editor .tabs-and-actions-container {
  display: none !important;
  height: 0 !important;
  min-height: 0 !important;
  overflow: hidden !important;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode .part.editor .editor-group-container > .title,
.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode .part.editor .tabs-and-actions-container {
  display: flex !important;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-hypervisor-mode .part.sidebar {
  display: none !important;
  width: 0 !important;
  min-width: 0 !important;
  visibility: hidden !important;
  pointer-events: none !important;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-hypervisor-mode .part.activitybar .action-item {
  visibility: hidden !important;
  pointer-events: none !important;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-hypervisor-mode .part.activitybar .action-item.ioi-vscode-substrate-action,
.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-hypervisor-mode .part.activitybar .action-item.ioi-vscode-global-action {
  display: none !important;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode .part.activitybar .action-item.ioi-hypervisor-mode-action:not(.ioi-code-action) {
  display: none !important;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode .part.activitybar .action-item.ioi-code-action {
  display: none !important;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode .part.activitybar .action-item.ioi-vscode-substrate-action,
.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode .part.activitybar .action-item.ioi-vscode-global-action {
  visibility: visible !important;
  pointer-events: auto !important;
}

#ioi-hypervisor-back-rail {
  display: none;
  width: 48px;
  height: 48px;
  flex: 0 0 48px;
  align-items: center;
  justify-content: center;
  border: 0;
  border-left: 2px solid transparent;
  background: transparent;
  color: var(--vscode-activityBar-inactiveForeground, #858585);
  cursor: pointer;
  font-size: 20px;
}

#ioi-hypervisor-back-rail:hover {
  color: var(--vscode-activityBar-foreground, #fff);
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-code-mode #ioi-hypervisor-back-rail {
  display: flex;
}

.monaco-workbench.ioi-hypervisor-native-shell.ioi-shell-hypervisor-mode #ioi-hypervisor-back-rail {
  display: none;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-backdrop {
  position: fixed;
  inset: 0;
  z-index: 100019;
  background: transparent;
  pointer-events: auto;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host {
  position: fixed;
  z-index: 100020;
  width: min(620px, calc(100vw - 64px));
  color: var(--vscode-quickInput-foreground, var(--vscode-foreground, #cccccc));
  font-family: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif);
  font-size: 13px;
  line-height: 1.35;
  pointer-events: auto;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host.ioi-quickinput--tools {
  top: calc(var(--ioi-shell-header-top, 35px) + 7px);
  left: 50%;
  transform: translateX(-50%);
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host.ioi-quickinput--context {
  left: 50%;
  bottom: 126px;
  transform: translateX(-50%);
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host.ioi-quickinput--target,
.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host.ioi-quickinput--agentmode,
.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host.ioi-quickinput--modelroute {
  width: min(260px, calc(100vw - 32px));
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-widget {
  overflow: hidden;
  border: 1px solid var(--vscode-quickInput-border, var(--vscode-widget-border, rgba(255,255,255,.16)));
  border-radius: 6px;
  background: var(--vscode-quickInput-background, #252526);
  color: inherit;
  box-shadow: 0 18px 42px rgba(0,0,0,.48);
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-titlebar {
  min-height: 26px;
  display: grid;
  grid-template-columns: 1fr auto 1fr;
  align-items: center;
  gap: 8px;
  padding: 0 8px;
  border-bottom: 1px solid var(--vscode-widget-border, rgba(255,255,255,.12));
  background: var(--vscode-titleBar-activeBackground, #3c3c3c);
  color: var(--vscode-titleBar-activeForeground, #d4d4d4);
  text-align: center;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-titlebar strong {
  font-weight: 500;
  justify-self: center;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-titlebar-actions {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-icon-action,
.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-ok {
  min-width: 0;
  border: 0;
  border-radius: 4px;
  background: transparent;
  color: inherit;
  font: inherit;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-icon-action {
  width: 18px;
  height: 18px;
  display: grid;
  place-items: center;
  padding: 0;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-icon-action .codicon {
  font-size: 14px;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-ok {
  height: 24px;
  padding: 0 9px;
  background: var(--vscode-button-background, #0e639c);
  color: var(--vscode-button-foreground, #fff);
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-search-row {
  display: grid;
  grid-template-columns: minmax(0, 1fr) auto auto;
  align-items: center;
  gap: 6px;
  padding: 6px 6px 4px;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-input {
  height: 28px;
  width: 100%;
  box-sizing: border-box;
  border: 1px solid var(--vscode-input-border, var(--vscode-focusBorder, #007fd4));
  border-radius: 3px;
  padding: 3px 7px;
  outline: none;
  background: var(--vscode-input-background, #3c3c3c);
  color: var(--vscode-input-foreground, #cccccc);
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-input:focus {
  border-color: var(--vscode-focusBorder, #007fd4);
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-selected-count {
  height: 22px;
  min-width: 68px;
  display: inline-grid;
  place-items: center;
  padding: 0 6px;
  border-radius: 3px;
  background: var(--vscode-badge-background, #4d4d4d);
  color: var(--vscode-badge-foreground, #fff);
  font-size: 12px;
  white-space: nowrap;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-description {
  padding: 8px 12px 6px;
  color: var(--vscode-foreground, #d4d4d4);
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-list {
  max-height: min(520px, calc(100vh - 140px));
  overflow: auto;
  padding: 2px 0 8px;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host.ioi-quickinput--context .ioi-quickinput-list {
  max-height: 210px;
  padding: 3px 7px 7px;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-compact-list {
  max-height: min(260px, calc(100vh - 96px));
  overflow: auto;
  padding: 4px;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-row {
  min-height: 24px;
  display: grid;
  grid-template-columns: 20px minmax(0, auto) minmax(0, 1fr) auto;
  align-items: center;
  gap: 4px;
  padding: 0 10px;
  border: 0;
  background: transparent;
  color: inherit;
  font: inherit;
  text-align: left;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-row.is-active,
.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-row:hover,
.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-row:focus-visible {
  background: var(--vscode-quickInputList-focusBackground, var(--vscode-list-activeSelectionBackground, #04395e));
  color: var(--vscode-quickInputList-focusForeground, var(--vscode-list-activeSelectionForeground, #fff));
  outline: none;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-row-label {
  font-weight: 600;
  color: inherit;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-row.is-disabled {
  opacity: 0.58;
  cursor: default;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-row.is-disabled.is-active,
.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-row.is-disabled:hover,
.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-row.is-disabled:focus-visible {
  background: transparent;
  color: inherit;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-row-detail {
  overflow: hidden;
  color: var(--vscode-descriptionForeground, #a8a8a8);
  text-overflow: ellipsis;
  white-space: nowrap;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-row-meta {
  color: var(--vscode-descriptionForeground, #a8a8a8);
  font-size: 12px;
  white-space: nowrap;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-twistie {
  width: 18px;
  height: 18px;
  display: grid;
  place-items: center;
  border: 0;
  background: transparent;
  color: inherit;
  padding: 0;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-twistie .codicon {
  font-size: 14px;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-checkbox {
  width: 14px;
  height: 14px;
  margin: 0;
  accent-color: var(--vscode-checkbox-selectBackground, var(--vscode-focusBorder, #007fd4));
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-children {
  display: grid;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-children[hidden] {
  display: none;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-child {
  padding-left: 30px;
}

.monaco-workbench.ioi-hypervisor-native-shell #ioi-hypervisor-quickinput-host .ioi-quickinput-compact-list .ioi-quickinput-row {
  grid-template-columns: 20px minmax(0, 1fr) auto;
  gap: 5px;
  padding: 0 7px;
}
${CSS_END}`;
}

function workbenchShellJs() {
  return `${JS_START}
;(function ioiHypervisorWorkbenchShellPatch() {
  if (globalThis.__ioiHypervisorWorkbenchShellPatchLoaded) {
    return;
  }
  globalThis.__ioiHypervisorWorkbenchShellPatchLoaded = true;

  const substratePatterns = [
    /explorer/i,
    /search/i,
    /source control/i,
    /run and debug/i,
    /extensions/i,
  ];
  const globalPatterns = [
    /accounts/i,
    /manage/i,
    /settings/i,
  ];
  const hypervisorModes = [
    { id: "home", title: "Home", codicon: "home", patterns: [/hypervisor overview/i, /home/i] },
    { id: "studio", title: "Studio", codicon: "sparkle", patterns: [/agent studio/i, /studio/i] },
    { id: "workflows", title: "Workflows", customIcon: "workflows", patterns: [/hypervisor workflows/i, /workflow/i] },
    { id: "models", title: "Models", codicon: "server", patterns: [/hypervisor models/i, /models/i] },
    { id: "runs", title: "Runs", codicon: "pulse", patterns: [/hypervisor runs/i, /runs/i] },
    { id: "policy", title: "Policy", codicon: "shield", patterns: [/hypervisor policy/i, /policy/i] },
    { id: "connectors", title: "Connectors", codicon: "plug", patterns: [/hypervisor connectors/i, /connectors/i] },
    { id: "code", title: "Code", codicon: "code", patterns: [/hypervisor code/i, /code/i] },
  ];
  const codeMenuModel = [
    {
      label: "File",
      items: [
        { label: "New File", shortcut: "Ctrl+N" },
        { label: "Open File...", shortcut: "Ctrl+O" },
        { label: "Open Folder..." },
        { separator: true },
        { label: "Save", shortcut: "Ctrl+S" },
        { label: "Save All" },
        { separator: true },
        { label: "Close Folder" },
      ],
    },
    {
      label: "Edit",
      items: [
        { label: "Undo", shortcut: "Ctrl+Z" },
        { label: "Redo", shortcut: "Ctrl+Y" },
        { separator: true },
        { label: "Cut", shortcut: "Ctrl+X" },
        { label: "Copy", shortcut: "Ctrl+C" },
        { label: "Paste", shortcut: "Ctrl+V" },
        { separator: true },
        { label: "Find", shortcut: "Ctrl+F" },
        { label: "Replace", shortcut: "Ctrl+H" },
      ],
    },
    {
      label: "Selection",
      items: [
        { label: "Select All", shortcut: "Ctrl+A" },
        { label: "Expand Selection" },
        { label: "Shrink Selection" },
        { separator: true },
        { label: "Add Cursor Above" },
        { label: "Add Cursor Below" },
      ],
    },
    {
      label: "View",
      items: [
        { label: "Command Palette...", shortcut: "Ctrl+Shift+P" },
        { separator: true },
        { label: "Explorer", shortcut: "Ctrl+Shift+E" },
        { label: "Search", shortcut: "Ctrl+Shift+F" },
        { label: "Source Control", shortcut: "Ctrl+Shift+G" },
        { label: "Extensions", shortcut: "Ctrl+Shift+X" },
      ],
    },
    {
      label: "Go",
      items: [
        { label: "Go to File...", shortcut: "Ctrl+P" },
        { label: "Go to Symbol..." },
        { separator: true },
        { label: "Back" },
        { label: "Forward" },
      ],
    },
    {
      label: "Run",
      items: [
        { label: "Start Debugging", shortcut: "F5" },
        { label: "Run Without Debugging", shortcut: "Ctrl+F5" },
        { label: "Stop Debugging" },
      ],
    },
    {
      label: "Terminal",
      items: [
        { label: "New Terminal" },
        { label: "Toggle Terminal" },
        { label: "Run Task..." },
      ],
    },
    {
      label: "Help",
      items: [
        { label: "Welcome" },
        { label: "Documentation" },
        { label: "Keyboard Shortcuts" },
        { label: "About Hypervisor" },
      ],
    },
  ];
  const codeMenuLabels = codeMenuModel.map((menu) => menu.label);
  const quickContextRows = [
    {
      id: "files-folders",
      label: "Files & Folders...",
      detail: "Add files and folders from the current workspace.",
      codicon: "folder-opened",
      requestType: "chat.attachFilesAndFolders",
    },
    {
      id: "instructions",
      label: "Instructions...",
      detail: "Attach reusable agent instructions.",
      codicon: "bookmark",
      requestType: "chat.generateAgentInstructions",
    },
    {
      id: "problems",
      label: "Problems...",
      detail: "Attach diagnostics and problems from the workspace.",
      codicon: "error",
      requestType: "chat.attachProblems",
    },
    {
      id: "symbols",
      label: "Symbols...",
      detail: "Attach workspace or editor symbols.",
      codicon: "symbol-field",
      requestType: "chat.attachSymbols",
    },
    {
      id: "tools",
      label: "Tools...",
      detail: "Configure the tools available to chat.",
      codicon: "tools",
      requestType: "chat.contextTools.open",
      openTools: true,
    },
  ];
  const quickTargetRows = [
    {
      id: "local",
      label: "Local",
      detail: "",
      meta: "",
      codicon: "device-desktop",
      selected: true,
      requestType: "chat.target.select",
    },
    {
      id: "learn-agent-types",
      label: "Learn about agent types...",
      detail: "",
      meta: "",
      codicon: "book",
      requestType: "chat.agentTypes.learn",
    },
  ];
  const quickAgentModeRows = [
    {
      id: "agent",
      label: "Agent",
      detail: "",
      meta: "Ctrl+Shift+Alt+I",
      codicon: "sparkle",
      selected: true,
      requestType: "chat.agentMode.select",
    },
    {
      id: "ask",
      label: "Ask",
      detail: "",
      meta: "",
      codicon: "question",
      requestType: "chat.agentMode.select",
    },
    {
      id: "edit",
      label: "Edit",
      detail: "",
      meta: "",
      codicon: "edit",
      requestType: "chat.agentMode.select",
    },
    {
      id: "configure-custom-agents",
      label: "Configure Custom Agents...",
      detail: "",
      meta: "",
      codicon: "settings-gear",
      requestType: "chat.agentMode.configure",
    },
  ];
  const quickPermissionModeRows = [
    {
      id: "suggest",
      label: "Default permissions",
      detail: "Ask before consequential, external, or destructive actions.",
      meta: "",
      codicon: "shield",
      selected: true,
      requestType: "chat.permissionMode.select",
    },
    {
      id: "auto_local",
      label: "Auto-review",
      detail: "Allow low-risk local actions; still gate destructive or external actions.",
      meta: "",
      codicon: "eye",
      requestType: "chat.permissionMode.select",
    },
    {
      id: "never_prompt",
      label: "Full access",
      detail: "Run without approval prompts for this daemon session.",
      meta: "",
      codicon: "shield",
      requestType: "chat.permissionMode.select",
    },
  ];
  const quickToolGroups = [
    {
      id: "built-in",
      label: "Built-In",
      selected: true,
      expanded: true,
      children: [
        { id: "agent", label: "agent", detail: "Delegate tasks to other agents", codicon: "code", selected: true },
        {
          id: "execute",
          label: "execute",
          detail: "Execute code and applications on your machine",
          codicon: "terminal",
          selected: true,
          expanded: true,
          children: [
            { id: "awaitTerminal", label: "awaitTerminal", detail: "Wait for a background terminal command to complete. Returns the output, exit code, and runtime state.", codicon: "terminal", selected: true },
            { id: "createAndRunTask", label: "createAndRunTask", detail: "Create and run a task in the workspace", codicon: "git-pull-request-create", selected: true },
            { id: "getTerminalOutput", label: "getTerminalOutput", detail: "Get the output of a terminal command previously started with run_in_terminal", codicon: "terminal", selected: true },
            { id: "killTerminal", label: "killTerminal", detail: "Kill a terminal by its ID. Use this to clean up terminals that are no longer needed.", codicon: "terminal", selected: true },
            { id: "runInTerminal", label: "runInTerminal", detail: "Run commands in the terminal", codicon: "terminal", selected: true },
          ],
        },
        { id: "new", label: "new", detail: "Scaffold a new workspace in VS Code", codicon: "new-folder", selected: true },
        {
          id: "read",
          label: "read",
          detail: "Read files in your workspace",
          codicon: "book",
          selected: true,
          expanded: true,
          children: [
            { id: "terminalLastCommand", label: "terminalLastCommand", detail: "Get the last command run in the active terminal.", codicon: "terminal", selected: true },
            { id: "terminalSelection", label: "terminalSelection", detail: "Get the current selection in the active terminal.", codicon: "terminal", selected: true },
          ],
        },
        { id: "todo", label: "todo", detail: "Manage and track todo items for task planning", codicon: "list-unordered", selected: true },
        {
          id: "vscode",
          label: "vscode",
          detail: "Use VS Code features",
          codicon: "vscode",
          selected: true,
          expanded: true,
          children: [
            { id: "extensions", label: "extensions", detail: "Search for VS Code extensions", codicon: "extensions", selected: true },
          ],
        },
        {
          id: "mermaid-chat-features",
          label: "Mermaid Chat Features",
          detail: "",
          codicon: "type-hierarchy",
          selected: true,
          expanded: true,
          children: [
            { id: "renderMermaidDiagram", label: "renderMermaidDiagram", detail: "Render a Mermaid.js diagram from markup.", codicon: "type-hierarchy", selected: true },
          ],
        },
      ],
    },
    {
      id: "live-tools",
      label: "Live Tools",
      selected: false,
      expanded: false,
      children: [
        { id: "loading-live-tools", label: "Loading Live Tools", detail: "Querying connector-backed tool affordances.", codicon: "sync", disabled: true },
      ],
    },
    {
      id: "runtime-catalog",
      label: "Runtime Catalog",
      selected: false,
      expanded: false,
      children: [
        { id: "kernel-backend-gallery", label: "Kernel backend gallery", detail: "Primary daemon-backed local backend catalog.", codicon: "server", selected: false },
        { id: "kernel-model-gallery", label: "Kernel model gallery", detail: "Daemon-projected local model inventory.", codicon: "database", selected: false },
        { id: "browser-playbook", label: "Browser playbook", detail: "Parent playbook for browser and GUI work.", codicon: "globe", selected: false },
        { id: "artifact-generator", label: "Artifact Generator", detail: "Parent playbook for artifact work.", codicon: "package", selected: false },
      ],
    },
  ];

  let shellMode = localStorage.getItem("ioi.hypervisor.shell.mode") || "hypervisor";
  let activeHypervisorMode = localStorage.getItem("ioi.hypervisor.active.mode") || "home";
  let scheduled = false;
  let lastHeaderMarkup = "";
  let lastCodeMenuMarkup = "";
  let lastRailMarkup = "";
  let navigationLockUntilMs = 0;
  let openCodeMenuLabel = "";
  let closeCodeMenuTimer = 0;
  let quickInputBackdrop = null;
  let quickInputHost = null;
  let quickInputKind = "";
  let quickInputRows = [];
  let quickInputActiveIndex = 0;
  let quickInputTargetWindow = null;
  let quickInputTargetOrigin = "*";
  let quickInputBridgeUrl = "";
  let quickInputAnchorRect = null;
  const quickExpandedGroups = new Set(["built-in", "execute", "read", "vscode", "mermaid-chat-features"]);
  const quickSelectedTools = new Set();

  function workbench() {
    return document.querySelector(".monaco-workbench");
  }

  function visible(element) {
    if (!element) return false;
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    return style.display !== "none" && style.visibility !== "hidden" && rect.width > 1 && rect.height > 1;
  }

  function labelFor(element) {
    const values = [
      element.getAttribute("aria-label"),
      element.getAttribute("title"),
      element.textContent,
      element.querySelector(".action-label")?.getAttribute("aria-label"),
      element.querySelector(".action-label")?.getAttribute("title"),
      element.querySelector(".action-label")?.className,
    ];
    return values.filter(Boolean).join(" ");
  }

  function classifyHypervisorAction(label) {
    return hypervisorModes.find((mode) => mode.patterns.some((pattern) => pattern.test(label)));
  }

  function inferModeFromLabel(label) {
    return /hypervisor code|code repository|code mode/i.test(label) ? "code"
      : /workflow composer|hypervisor workflow/i.test(label) ? "workflows"
      : /hypervisor models/i.test(label) ? "models"
      : /agent studio/i.test(label) ? "studio"
      : /hypervisor runs/i.test(label) ? "runs"
      : /hypervisor policy/i.test(label) ? "policy"
      : /hypervisor connectors/i.test(label) ? "connectors"
      : /hypervisor overview|hypervisor home/i.test(label) ? "home"
      : null;
  }

  function setShellMode(nextMode, nextActiveMode) {
    shellMode = nextMode === "code" ? "code" : "hypervisor";
    if (nextActiveMode && nextActiveMode !== "code") {
      activeHypervisorMode = nextActiveMode;
      localStorage.setItem("ioi.hypervisor.active.mode", activeHypervisorMode);
    }
    localStorage.setItem("ioi.hypervisor.shell.mode", shellMode);
    applyClasses();
    renderHeader();
    renderCodeMenu();
    renderPrimaryRail();
    decorateActivityBar();
  }

  function openMode(modeId) {
    navigationLockUntilMs = Date.now() + 650;
    if (modeId === "code") {
      setShellMode("code");
    } else {
      setShellMode("hypervisor", modeId || "home");
    }
    const targetMode = modeId || "home";
    const editorSelection = selectExistingEditor(targetMode);
    if (editorSelection === "active") {
      navigationLockUntilMs = Date.now() + 1800;
      clickActivity(targetMode);
    } else if (editorSelection === "selected") {
      setTimeout(() => {
        if (inferModeFromLabel(activeWorkbenchLabel()) !== targetMode) {
          navigationLockUntilMs = Date.now() + 1800;
          clickActivity(targetMode);
        }
      }, 180);
    } else {
      navigationLockUntilMs = Date.now() + 1800;
      clickActivity(targetMode);
    }
    scheduleTick();
  }

  function modeTitle() {
    if (shellMode === "code") return "Code";
    return hypervisorModes.find((mode) => mode.id === activeHypervisorMode)?.title || "Home";
  }

  function activeWorkbenchLabel() {
    const selectors = [
      ".part.editor .editor-group-container.active .tabs-container .tab.active",
      ".part.editor .tabs-container .tab.active",
      ".part.editor .title-label .label-name",
      ".part.editor [aria-selected='true']",
    ];
    const values = [document.title];
    for (const selector of selectors) {
      for (const element of document.querySelectorAll(selector)) {
        values.push(labelFor(element));
      }
    }
    return values.filter(Boolean).join(" ");
  }

  function synchronizeModeFromWorkbench() {
    if (Date.now() < navigationLockUntilMs) return;
    const label = activeWorkbenchLabel();
    const inferred = inferModeFromLabel(label);
    if (!inferred) return;
    shellMode = inferred === "code" ? "code" : "hypervisor";
    if (inferred !== "code") {
      activeHypervisorMode = inferred;
      localStorage.setItem("ioi.hypervisor.active.mode", activeHypervisorMode);
    }
    localStorage.setItem("ioi.hypervisor.shell.mode", shellMode);
  }

  function workspaceLabel() {
    const title = document.title || "ioi - Hypervisor";
    const match = title.match(/-\\s*([^-]+)\\s*-\\s*Hypervisor/i);
    return match?.[1]?.trim() || "ioi";
  }

  function applyClasses() {
    const wb = workbench();
    if (!wb) return;
    updateClass(wb, "ioi-hypervisor-native-shell", true);
    updateClass(wb, "ioi-shell-code-mode", shellMode === "code");
    updateClass(wb, "ioi-shell-hypervisor-mode", shellMode !== "code");
    setDataset(wb, "ioiShellMode", shellMode);
    setDataset(wb, "ioiActiveMode", shellMode === "code" ? "code" : activeHypervisorMode);

    const titlebar = document.querySelector(".part.titlebar");
    const activitybar = document.querySelector(".part.activitybar");
    const top = titlebar?.getBoundingClientRect().bottom || 35;
    const left = activitybar?.getBoundingClientRect().right || 48;
    setStyleProperty(document.documentElement, "--ioi-shell-header-top", top + "px");
    setStyleProperty(document.documentElement, "--ioi-shell-header-left", left + "px");
  }

  function selectExistingEditor(modeId) {
    const activeLabel = activeWorkbenchLabel();
    if (inferModeFromLabel(activeLabel) === modeId) {
      return "active";
    }

    const tabs = Array.from(document.querySelectorAll(".part.editor .tabs-container .tab"));
    const match = tabs.find((tab) => inferModeFromLabel(labelFor(tab)) === modeId);
    if (!match) {
      return "missing";
    }
    match.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true, view: window }));
    match.dispatchEvent(new MouseEvent("mouseup", { bubbles: true, cancelable: true, view: window }));
    match.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, view: window }));
    return "selected";
  }

  function clickActivity(modeId) {
    const actions = Array.from(document.querySelectorAll(".part.activitybar .action-item"));
    const match = actions.find((action) => {
      const label = labelFor(action);
      const mode = classifyHypervisorAction(label);
      return mode?.id === modeId;
    });
    match?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, view: window }));
  }

  function renderHeader() {
    document.getElementById("ioi-hypervisor-workbench-native-header")?.remove();
    lastHeaderMarkup = "";
  }

  function activateNativeMenubar(label) {
    const normalized = String(label || "").trim().toLowerCase();
    if (!normalized) return false;
    const candidates = Array.from(document.querySelectorAll([
      ".part.titlebar .menubar [role='menuitem']",
      ".part.titlebar .menubar .menubar-menu-button",
      ".part.titlebar .menubar .menubar-menu-title",
      ".part.titlebar .menubar .action-menu-item",
    ].join(",")));
    const match = candidates.find((candidate) => {
      const value = labelFor(candidate).trim().toLowerCase();
      return value === normalized || value.startsWith(normalized + " ");
    });
    if (!match) return false;
    match.dispatchEvent(new MouseEvent("mousedown", { bubbles: true, cancelable: true, view: window }));
    match.dispatchEvent(new MouseEvent("mouseup", { bubbles: true, cancelable: true, view: window }));
    match.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, view: window }));
    return true;
  }

  function codeMenuByLabel(label) {
    return codeMenuModel.find((menu) => menu.label === label);
  }

  function closeCodeMenu() {
    openCodeMenuLabel = "";
    const dropdown = document.getElementById("ioi-hypervisor-workbench-code-menu-dropdown");
    dropdown?.classList.remove("is-open");
    dropdown?.replaceChildren();
    for (const button of document.querySelectorAll("[data-ioi-code-menu-label]")) {
      button.classList.remove("is-open");
      button.setAttribute("aria-expanded", "false");
    }
  }

  function cancelCloseCodeMenu() {
    if (!closeCodeMenuTimer) return;
    clearTimeout(closeCodeMenuTimer);
    closeCodeMenuTimer = 0;
  }

  function scheduleCloseCodeMenu() {
    cancelCloseCodeMenu();
    closeCodeMenuTimer = setTimeout(() => {
      closeCodeMenuTimer = 0;
      closeCodeMenu();
    }, 220);
  }

  function ensureCodeMenuDropdown(wb) {
    let dropdown = document.getElementById("ioi-hypervisor-workbench-code-menu-dropdown");
    if (!dropdown) {
      dropdown = document.createElement("div");
      dropdown.id = "ioi-hypervisor-workbench-code-menu-dropdown";
      dropdown.dataset.testid = "code-mode-local-menu-dropdown";
      dropdown.dataset.workbenchOwned = "true";
      dropdown.setAttribute("role", "menu");
      dropdown.setAttribute("aria-label", "Code mode local menu dropdown");
      dropdown.addEventListener("mouseenter", cancelCloseCodeMenu);
      dropdown.addEventListener("mouseleave", scheduleCloseCodeMenu);
      dropdown.addEventListener("click", (event) => {
        const item = event.target.closest("[data-ioi-code-menu-item]");
        if (!item) return;
        event.preventDefault();
        event.stopPropagation();
        closeCodeMenu();
      }, true);
    }
    if (dropdown.parentElement !== wb) {
      wb.appendChild(dropdown);
    }
    return dropdown;
  }

  function openCodeMenu(label, anchor) {
    if (shellMode !== "code") {
      closeCodeMenu();
      return;
    }
    const wb = workbench();
    const menu = codeMenuByLabel(label);
    if (!wb || !menu) return;
    cancelCloseCodeMenu();
    const dropdown = ensureCodeMenuDropdown(wb);
    openCodeMenuLabel = label;
    dropdown.dataset.menu = label;
    dropdown.replaceChildren(
      ...menu.items.map((item, index) => {
        if (item.separator) {
          const separator = element("div", { className: "ioi-code-menu-separator" });
          separator.setAttribute("role", "separator");
          return separator;
        }
        const button = element("button", {
          className: "ioi-code-menu-item",
          type: "button",
          testId: "code-menu-item-" + label.toLowerCase().replace(/\\s+/g, "-") + "-" + index,
        }, [
          element("span", {}, [item.label]),
          element("span", { className: "ioi-code-menu-shortcut" }, [item.shortcut || ""]),
        ]);
        button.dataset.ioiCodeMenuItem = item.label;
        button.dataset.ioiCodeMenuParent = label;
        button.setAttribute("role", "menuitem");
        return button;
      }),
    );
    const rect = anchor?.getBoundingClientRect?.();
    if (rect) {
      const width = 250;
      const left = Math.max(
        4,
        Math.min(rect.left, Math.max(4, window.innerWidth - width - 8)),
      );
      setStyleProperty(document.documentElement, "--ioi-code-menu-dropdown-left", left + "px");
    }
    dropdown.classList.add("is-open");
    for (const button of document.querySelectorAll("[data-ioi-code-menu-label]")) {
      const selected = button.dataset.ioiCodeMenuLabel === label;
      updateClass(button, "is-open", selected);
      button.setAttribute("aria-expanded", selected ? "true" : "false");
    }
  }

  function renderCodeMenu() {
    closeCodeMenu();
    document.getElementById("ioi-hypervisor-workbench-code-menu")?.remove();
    document.getElementById("ioi-hypervisor-workbench-code-menu-dropdown")?.remove();
    lastCodeMenuMarkup = "";
  }

  function renderPrimaryRail() {
    const wb = workbench();
    if (!wb) return;
    let rail = document.getElementById("ioi-hypervisor-primary-rail");
    if (!rail) {
      rail = document.createElement("nav");
      rail.id = "ioi-hypervisor-primary-rail";
      rail.dataset.testid = "hypervisor-primary-rail";
      rail.setAttribute("aria-label", "Hypervisor primary modes");
      rail.addEventListener("click", (event) => {
        const button = event.target.closest("[data-ioi-native-mode]");
        if (!button) return;
        event.preventDefault();
        event.stopPropagation();
        openMode(button.getAttribute("data-ioi-native-mode") || "home");
      }, true);
    }
    if (rail.parentElement !== wb) {
      wb.appendChild(rail);
    }
    const signature = [shellMode, activeHypervisorMode].join("\\n");
    if (signature === lastRailMarkup) return;
    rail.replaceChildren(
      ...hypervisorModes.map((mode) => {
        const button = element("button", {
          className: "ioi-native-rail-button" + (
            (shellMode === "code" && mode.id === "code") ||
            (shellMode !== "code" && mode.id === activeHypervisorMode)
              ? " is-active"
              : ""
          ),
          type: "button",
          testId: "native-rail-" + mode.id,
        }, [
          element("span", {
            className: mode.customIcon
              ? "ioi-native-rail-svg ioi-native-rail-" + mode.customIcon
              : "codicon codicon-" + mode.codicon,
          }),
        ]);
        button.dataset.ioiNativeMode = mode.id;
        button.title = mode.id === "code" ? "Code" : "Hypervisor " + mode.title;
        button.setAttribute("aria-label", button.title);
        return button;
      }),
    );
    lastRailMarkup = signature;
  }

  function element(tagName, options = {}, children = []) {
    const node = document.createElement(tagName);
    if (options.id) node.id = options.id;
    if (options.className) node.className = options.className;
    if (options.type) node.type = options.type;
    if (options.testId) node.dataset.testid = options.testId;
    if (options.shellAction) node.dataset.ioiShellAction = options.shellAction;
    if (options.role) node.setAttribute("role", options.role);
    if (options.title) node.title = options.title;
    if (options.ariaLabel) node.setAttribute("aria-label", options.ariaLabel);
    if (Object.prototype.hasOwnProperty.call(options, "tabIndex")) node.tabIndex = options.tabIndex;
    if (Object.prototype.hasOwnProperty.call(options, "value")) node.value = options.value;
    if (Object.prototype.hasOwnProperty.call(options, "checked")) node.checked = Boolean(options.checked);
    if (Object.prototype.hasOwnProperty.call(options, "disabled")) node.disabled = Boolean(options.disabled);
    if (options.dataset) {
      for (const [key, value] of Object.entries(options.dataset)) {
        if (value !== undefined && value !== null) node.dataset[key] = String(value);
      }
    }
    if (options.attrs) {
      for (const [key, value] of Object.entries(options.attrs)) {
        if (value !== undefined && value !== null) node.setAttribute(key, String(value));
      }
    }
    for (const child of children) {
      node.append(child instanceof Node ? child : document.createTextNode(String(child ?? "")));
    }
    return node;
  }

  function walkQuickTools(rows, visitor, parent = null) {
    for (const row of rows || []) {
      visitor(row, parent);
      if (Array.isArray(row.children)) walkQuickTools(row.children, visitor, row);
    }
  }

  function ensureQuickToolSelection() {
    if (quickSelectedTools.size > 0) return;
    walkQuickTools(quickToolGroups, (row) => {
      if (row.selected && !row.disabled) quickSelectedTools.add(row.id);
    });
  }

  function quickToolSelectedCount() {
    ensureQuickToolSelection();
    let count = 0;
    walkQuickTools(quickToolGroups, (row) => {
      if (!row.disabled && quickSelectedTools.has(row.id)) count += 1;
    });
    return count;
  }

  function findQuickToolRow(toolId) {
    let match = null;
    walkQuickTools(quickToolGroups, (row, parent) => {
      if (row.id === toolId) match = { row, parent };
    });
    return match;
  }

  function closeForkQuickInput({ restoreComposer = true } = {}) {
    if (quickInputHost) {
      quickInputHost.remove();
      quickInputHost = null;
    }
    if (quickInputBackdrop) {
      quickInputBackdrop.remove();
      quickInputBackdrop = null;
    }
    quickInputKind = "";
    quickInputRows = [];
    quickInputActiveIndex = 0;
    quickInputAnchorRect = null;
    if (restoreComposer) {
      restoreForkComposerFocus();
    }
  }

  function restoreForkComposerFocus() {
    void writeForkQuickInputBridgeRequest("chat.focusComposer", {
      action: "restoreComposerFocus",
      source: "fork-native-quickinput",
      restoreComposer: true,
    });
    const send = () => {
      postForkQuickInputResult({
        kind: "focusComposer",
        command: "ioi.quickInput.focusComposer",
        restoreComposer: true,
      });
    };
    send();
    for (const delay of [80, 220, 500, 900]) {
      setTimeout(send, delay);
    }
  }

  function postForkQuickInputResult(result) {
    const message = {
      source: "ioi-hypervisor-workbench-quickinput",
      type: "ioi.quickInput.result",
      result: {
        nativeForkContributionUsed: true,
        extensionQuickPickFallbackUsed: false,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "hypervisor-workbench-quickinput",
        ...result,
      },
    };
    try {
      quickInputTargetWindow?.postMessage(message, quickInputTargetOrigin || "*");
    } catch {
      // The webview may have been swapped by VS Code; durable picker focus still stays in the workbench.
    }
    for (const frame of document.querySelectorAll("iframe, webview")) {
      try {
        frame.contentWindow?.postMessage(message, "*");
      } catch {
        // Cross-origin webviews still accept postMessage when contentWindow is available.
      }
    }
  }

  async function writeForkQuickInputBridgeRequest(requestType, payload = {}) {
    let base = String(quickInputBridgeUrl || "");
    while (base.endsWith("/")) {
      base = base.slice(0, -1);
    }
    if (!base || !requestType) return false;
    const requestId = globalThis.crypto?.randomUUID?.() || ("quickinput-" + Date.now() + "-" + Math.random().toString(16).slice(2));
    const request = {
      requestId,
      requestType,
      context: {
        source: "fork-quickinput-workbench",
        runtimeAuthority: "daemon-owned",
        projectionOwner: "hypervisor-workbench-quickinput",
      },
      payload: {
        nativeForkContributionUsed: true,
        extensionQuickPickFallbackUsed: false,
        runtimeAuthority: "daemon-owned",
        projectionOwner: "hypervisor-workbench-quickinput",
        ...payload,
      },
      timestampMs: Date.now(),
    };
    try {
      const response = await fetch(base + "/requests", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
      });
      return response.ok;
    } catch {
      return false;
    }
  }

  function quickVisibleRows() {
    if (!quickInputHost) return [];
    return Array.from(quickInputHost.querySelectorAll("[data-ioi-quick-row]")).filter((row) => {
      return row instanceof HTMLElement && row.offsetParent !== null;
    });
  }

  function setQuickActiveIndex(nextIndex) {
    const rows = quickVisibleRows();
    if (rows.length === 0) {
      quickInputActiveIndex = 0;
      return;
    }
    quickInputActiveIndex = Math.max(0, Math.min(nextIndex, rows.length - 1));
    rows.forEach((row, index) => {
      updateClass(row, "is-active", index === quickInputActiveIndex);
      row.setAttribute("aria-selected", index === quickInputActiveIndex ? "true" : "false");
      row.tabIndex = index === quickInputActiveIndex ? 0 : -1;
    });
    rows[quickInputActiveIndex]?.scrollIntoView?.({ block: "nearest" });
  }

  function makeCodicon(name) {
    return element("span", { className: "codicon codicon-" + name, attrs: { "aria-hidden": "true" } });
  }

  function clampNumber(value, min, max) {
    return Math.max(min, Math.min(max, value));
  }

  function resolveForkQuickInputAnchorRect(anchorRect, sourceWindow) {
    if (!anchorRect || typeof anchorRect !== "object") {
      return null;
    }
    const numeric = (key) => Number.isFinite(Number(anchorRect[key])) ? Number(anchorRect[key]) : 0;
    let frameLeft = 0;
    let frameTop = 0;
    for (const frame of document.querySelectorAll("iframe, webview")) {
      try {
        if (frame.contentWindow && frame.contentWindow === sourceWindow) {
          const frameRect = frame.getBoundingClientRect();
          frameLeft = frameRect.left;
          frameTop = frameRect.top;
          break;
        }
      } catch {
        // Cross-origin frames are ignored; raw coordinates still keep the picker usable.
      }
    }
    return {
      left: frameLeft + numeric("left"),
      top: frameTop + numeric("top"),
      right: frameLeft + numeric("right"),
      bottom: frameTop + numeric("bottom"),
      width: numeric("width"),
      height: numeric("height"),
    };
  }

  function positionAnchoredQuickInputHost() {
    if (!quickInputHost || !quickInputAnchorRect) return;
    if (!["target", "agentmode", "modelroute", "permissionmode"].includes(quickInputKind)) return;
    requestAnimationFrame(() => {
      if (!quickInputHost || !quickInputAnchorRect) return;
      const rect = quickInputHost.getBoundingClientRect();
      const left = clampNumber(
        quickInputAnchorRect.left,
        12,
        Math.max(12, window.innerWidth - rect.width - 12),
      );
      const top = clampNumber(
        quickInputAnchorRect.top - rect.height - 7,
        12,
        Math.max(12, window.innerHeight - rect.height - 12),
      );
      quickInputHost.style.left = left + "px";
      quickInputHost.style.top = top + "px";
      quickInputHost.style.bottom = "auto";
      quickInputHost.style.transform = "none";
    });
  }

  function makeQuickInputHost(kind, testId) {
    const anchorBeforeClose = quickInputAnchorRect;
    closeForkQuickInput({ restoreComposer: false });
    quickInputAnchorRect = anchorBeforeClose;
    const wb = workbench();
    if (!wb) return null;
    const backdrop = element("div", {
      id: "ioi-hypervisor-quickinput-backdrop",
      testId: "fork-quickinput-backdrop",
      attrs: {
        "aria-hidden": "true",
      },
      dataset: {
        nativeForkContribution: "true",
        quickInputDismissLayer: kind,
      },
    });
    backdrop.addEventListener("pointerdown", (event) => {
      event.preventDefault();
      event.stopPropagation();
      closeForkQuickInput();
    }, true);
    backdrop.addEventListener("contextmenu", (event) => {
      event.preventDefault();
      event.stopPropagation();
      closeForkQuickInput();
    }, true);
    const host = element("div", {
      id: "ioi-hypervisor-quickinput-host",
      className: "ioi-quickinput--" + kind,
      testId,
      role: "dialog",
      ariaLabel: kind === "tools" ? "Configure Tools"
        : kind === "target" ? "Select Target"
        : kind === "agentmode" ? "Select Agent Mode"
        : kind === "modelroute" ? "Select Model Route"
        : "Add Context",
      tabIndex: -1,
      dataset: {
        nativeForkContribution: "true",
        extensionQuickPickFallback: "false",
      },
    });
    quickInputBackdrop = backdrop;
    quickInputHost = host;
    quickInputKind = kind;
    wb.appendChild(backdrop);
    wb.appendChild(host);
    return host;
  }

  function focusForkQuickInputControl(control) {
    const focus = () => {
      try {
        window.focus();
      } catch {
        // Best-effort only; the workbench may already own focus.
      }
      control?.focus?.({ preventScroll: true });
    };
    focus();
    requestAnimationFrame(focus);
    for (const delay of [50, 120, 250, 500]) {
      setTimeout(focus, delay);
    }
  }

  function renderForkContextQuickInput() {
    const host = makeQuickInputHost("context", "fork-add-context-quickinput");
    if (!host) return;
    const input = element("input", {
      className: "ioi-quickinput-input",
      type: "text",
      value: "",
      testId: "fork-add-context-input",
      attrs: {
        placeholder: "Search for files and context to add to your request",
        autocomplete: "off",
        spellcheck: "false",
      },
    });
    const list = element("div", { className: "ioi-quickinput-list", role: "listbox" });
    const rows = quickContextRows.map((row) => {
      const button = element("button", {
        className: "ioi-quickinput-row",
        type: "button",
        role: "option",
        testId: "fork-context-row-" + row.id,
        dataset: {
          ioiQuickRow: row.id,
          rowId: row.id,
        },
      }, [
        makeCodicon(row.codicon),
        element("span", { className: "ioi-quickinput-row-label" }, [row.label]),
        element("span", { className: "ioi-quickinput-row-detail" }, [row.detail]),
        element("span", { className: "ioi-quickinput-row-meta" }, [row.openTools ? "Tools" : "Context"]),
      ]);
      button.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (row.openTools) {
          renderForkToolsQuickInput();
          return;
        }
        const bridgeRequestAlreadyWritten = await writeForkQuickInputBridgeRequest(row.requestType, {
          contextId: row.id,
          label: row.label,
          source: "fork-native-quickinput",
          selectedCount: 1,
        });
        postForkQuickInputResult({
          kind: "context",
          command: "ioi.quickInput.context.open",
          contextId: row.id,
          label: row.label,
          requestType: row.requestType,
          selectedCount: 1,
          bridgeRequestAlreadyWritten,
        });
        closeForkQuickInput();
      }, true);
      return button;
    });
    list.replaceChildren(...rows);
    const panel = element("div", { className: "ioi-quickinput-widget", dataset: { nativeQuickInput: "context" } }, [
      element("div", { className: "ioi-quickinput-search-row" }, [input]),
      list,
    ]);
    host.replaceChildren(panel);
    quickInputRows = rows;
    input.addEventListener("input", () => {
      const query = input.value.trim().toLowerCase();
      rows.forEach((button) => {
        const row = quickContextRows.find((candidate) => candidate.id === button.dataset.rowId);
        const text = [row?.label, row?.detail].filter(Boolean).join(" ").toLowerCase();
        button.hidden = query && !text.includes(query);
      });
      setQuickActiveIndex(0);
    });
    installForkQuickInputKeyboard(host);
    setQuickActiveIndex(0);
    focusForkQuickInputControl(input);
  }

  function renderForkSimpleQuickInput(kind, testId, rows, command) {
    const host = makeQuickInputHost(kind, testId);
    if (!host) return;
    const list = element("div", {
      className: "ioi-quickinput-compact-list",
      role: "listbox",
      testId: testId + "-list",
    });
    const rowButtons = rows.map((row) => {
      const button = element("button", {
        className: "ioi-quickinput-row" + (row.selected ? " is-selected" : "") + (row.disabled ? " is-disabled" : ""),
        type: "button",
        role: "option",
        testId: testId + "-row-" + row.id,
        tabIndex: -1,
        disabled: !!row.disabled,
        title: row.detail || row.label,
        attrs: row.disabled ? { "aria-disabled": "true" } : {},
        dataset: {
          ioiQuickRow: row.id,
          rowId: row.id,
        },
      }, [
        makeCodicon(row.codicon),
        element("span", { className: "ioi-quickinput-row-label" }, [row.label]),
        element("span", { className: "ioi-quickinput-row-meta" }, [row.meta || ""]),
      ]);
      button.addEventListener("click", async (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (row.disabled) {
          return;
        }
        const normalizedMode = String(row.id || row.label || "agent").toLowerCase().replace(/[\\s-]+/g, "_");
        const executionMode = kind === "agentmode" && row.requestType === "chat.agentMode.select"
          ? (["ask", "chat", "chat_only", "chatonly", "direct_chat", "direct_model"].includes(normalizedMode) ? "ask" : "agent")
          : undefined;
        const approvalMode = kind === "permissionmode" && row.requestType === "chat.permissionMode.select"
          ? (["auto_review", "auto_local", "autolocal"].includes(normalizedMode)
            ? "auto_local"
            : ["full_access", "fullaccess", "never_prompt", "neverprompt", "yolo"].includes(normalizedMode)
              ? "never_prompt"
              : "suggest")
          : undefined;
        const threadMode = approvalMode === "never_prompt" ? "yolo" : approvalMode ? "agent" : undefined;
        const selectionPayload = {
          selectionId: row.id,
          label: row.label,
          detail: row.detail || "",
          source: "fork-native-quickinput",
          selectedCount: 1,
          ...(executionMode ? { executionMode } : {}),
          ...(approvalMode ? { approvalMode, approval_mode: approvalMode, threadMode, thread_mode: threadMode } : {}),
        };
        const bridgeRequestAlreadyWritten = await writeForkQuickInputBridgeRequest(row.requestType, selectionPayload);
        postForkQuickInputResult({
          kind: kind === "agentmode" ? "agentMode" : kind === "permissionmode" ? "permissionMode" : kind === "modelroute" ? "modelRoute" : kind,
          command,
          selectionId: row.id,
          executionMode,
          approvalMode,
          approval_mode: approvalMode,
          threadMode,
          thread_mode: threadMode,
          label: row.label,
          detail: row.detail || "",
          requestType: row.requestType,
          selectedCount: 1,
          bridgeRequestAlreadyWritten,
        });
        closeForkQuickInput();
      }, true);
      return button;
    });
    list.replaceChildren(...rowButtons);
    const panel = element("div", { className: "ioi-quickinput-widget", dataset: { nativeQuickInput: kind } }, [
      list,
    ]);
    host.replaceChildren(panel);
    quickInputRows = rowButtons;
    installForkQuickInputKeyboard(host);
    setQuickActiveIndex(0);
    positionAnchoredQuickInputHost();
    focusForkQuickInputControl(rowButtons[quickInputActiveIndex] || host);
  }

  function renderForkToolsQuickInput() {
    ensureQuickToolSelection();
    const host = makeQuickInputHost("tools", "fork-configure-tools-quickinput");
    if (!host) return;
    const input = element("input", {
      className: "ioi-quickinput-input",
      type: "text",
      testId: "fork-tools-filter-input",
      attrs: {
        placeholder: "Select tools that are available to chat.",
        autocomplete: "off",
        spellcheck: "false",
      },
    });
    const selectedCount = element("span", {
      className: "ioi-quickinput-selected-count",
      testId: "fork-tools-selected-count",
    }, [String(quickToolSelectedCount()) + " Selected"]);
    const okButton = element("button", {
      className: "ioi-quickinput-ok",
      type: "button",
      testId: "fork-tools-ok",
    }, ["OK"]);
    const list = element("div", { className: "ioi-quickinput-list", role: "tree", testId: "fork-tools-tree" });

    function refreshSelectedCount() {
      selectedCount.textContent = String(quickToolSelectedCount()) + " Selected";
    }

    function setChildrenChecked(row, checked) {
      if (checked) {
        quickSelectedTools.add(row.id);
      } else {
        quickSelectedTools.delete(row.id);
      }
      for (const child of row.children || []) {
        if (child.disabled) continue;
        setChildrenChecked(child, checked);
      }
    }

    function renderToolRow(row, depth = 0, parentId = "") {
      const hasChildren = Array.isArray(row.children) && row.children.length > 0;
      const expanded = quickExpandedGroups.has(row.id);
      const rowEl = element("div", {
        className: "ioi-quickinput-row" + (depth > 0 ? " ioi-quickinput-child" : ""),
        role: "treeitem",
        testId: "fork-tool-" + (hasChildren ? "group-" : "child-") + row.id,
        attrs: hasChildren
          ? { "aria-expanded": expanded ? "true" : "false", "aria-level": String(depth + 1) }
          : { "aria-level": String(depth + 1) },
        dataset: {
          ioiQuickRow: row.id,
          toolId: row.id,
          parentId,
          hasChildren: hasChildren ? "true" : "false",
        },
      });
      const twistie = element("button", {
        className: "ioi-quickinput-twistie",
        type: "button",
        tabIndex: -1,
        ariaLabel: hasChildren ? (expanded ? "Collapse " + row.label : "Expand " + row.label) : "",
      }, [
        hasChildren ? makeCodicon(expanded ? "chevron-down" : "chevron-right") : element("span"),
      ]);
      const checkbox = element("input", {
        className: "ioi-quickinput-checkbox",
        type: "checkbox",
        checked: !row.disabled && quickSelectedTools.has(row.id),
        disabled: row.disabled,
        testId: "fork-tool-checkbox-" + row.id,
        attrs: {
          "aria-label": row.label,
        },
      });
      const label = element("span", { className: "ioi-quickinput-row-label" }, [row.label]);
      const detail = element("span", { className: "ioi-quickinput-row-detail" }, [row.detail || ""]);
      const meta = element("span", { className: "ioi-quickinput-row-meta" }, [row.disabled ? "disabled" : row.meta || ""]);
      rowEl.replaceChildren(twistie, checkbox, label, detail, meta);
      twistie.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        if (!hasChildren) return;
        if (quickExpandedGroups.has(row.id)) {
          quickExpandedGroups.delete(row.id);
        } else {
          quickExpandedGroups.add(row.id);
        }
        renderForkToolsQuickInput();
      }, true);
      rowEl.addEventListener("click", (event) => {
        const target = event.target;
        if (
          target?.closest?.(".ioi-quickinput-twistie") ||
          target?.closest?.(".ioi-quickinput-checkbox")
        ) {
          return;
        }
        event.preventDefault();
        event.stopPropagation();
        if (row.disabled) return;
        const checked = !quickSelectedTools.has(row.id);
        setChildrenChecked(row, checked);
        renderForkToolsQuickInput();
      }, true);
      checkbox.addEventListener("click", (event) => {
        event.stopPropagation();
        if (row.disabled) return;
        setChildrenChecked(row, checkbox.checked);
        refreshSelectedCount();
        renderForkToolsQuickInput();
      }, true);
      const nodes = [rowEl];
      if (hasChildren) {
        const children = element("div", {
          className: "ioi-quickinput-children",
          attrs: expanded ? {} : { hidden: "hidden" },
        }, row.children.flatMap((child) => renderToolRow(child, depth + 1, row.id)));
        nodes.push(children);
      }
      return nodes;
    }

    list.replaceChildren(...quickToolGroups.flatMap((group) => renderToolRow(group, 0, "")));
    const titlebar = element("div", { className: "ioi-quickinput-titlebar" }, [
      element("span"),
      element("strong", {}, ["Configure Tools"]),
      element("div", { className: "ioi-quickinput-titlebar-actions" }, [
        element("button", { className: "ioi-quickinput-icon-action", type: "button", title: "Add Context" }, [makeCodicon("paperclip")]),
        element("button", { className: "ioi-quickinput-icon-action", type: "button", title: "Manage Tools" }, [makeCodicon("extensions")]),
        element("button", { className: "ioi-quickinput-icon-action", type: "button", title: "Tool Settings" }, [makeCodicon("settings-gear")]),
      ]),
    ]);
    const panel = element("div", { className: "ioi-quickinput-widget", dataset: { nativeQuickInput: "tools" } }, [
      titlebar,
      element("div", { className: "ioi-quickinput-search-row" }, [input, selectedCount, okButton]),
      element("div", { className: "ioi-quickinput-description" }, ["The selected tools will be applied globally for all chat sessions that use the default agent."]),
      list,
    ]);
    host.replaceChildren(panel);

    input.addEventListener("input", () => {
      const query = input.value.trim().toLowerCase();
      for (const row of list.querySelectorAll("[data-ioi-quick-row]")) {
        const toolId = row.getAttribute("data-tool-id");
        const match = findQuickToolRow(toolId);
        const text = [match?.row?.label, match?.row?.detail].filter(Boolean).join(" ").toLowerCase();
        row.hidden = query && !text.includes(query);
      }
      setQuickActiveIndex(0);
    });
    okButton.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();
      const selectedTools = [];
      walkQuickTools(quickToolGroups, (row, parent) => {
        if (!row.disabled && quickSelectedTools.has(row.id)) {
          selectedTools.push({
            toolId: row.id,
            label: row.label,
            detail: row.detail || "",
            parentId: parent?.id || "",
          });
        }
      });
      const bridgeRequestAlreadyWritten = await writeForkQuickInputBridgeRequest("chat.toolControls", {
        action: "configureTools",
        selectedTools,
        selectedCount: selectedTools.length,
        source: "fork-native-quickinput",
      });
      postForkQuickInputResult({
        kind: "tools",
        command: "ioi.quickInput.tools.configure",
        action: "configureTools",
        selectedTools,
        selectedCount: selectedTools.length,
        bridgeRequestAlreadyWritten,
      });
      closeForkQuickInput();
    }, true);
    installForkQuickInputKeyboard(host);
    setQuickActiveIndex(0);
    focusForkQuickInputControl(input);
  }

  function toggleActiveToolRow() {
    const row = quickVisibleRows()[quickInputActiveIndex];
    if (!row) return;
    const toolId = row.getAttribute("data-tool-id");
    const match = findQuickToolRow(toolId);
    if (!match?.row || match.row.disabled) return;
    if (quickSelectedTools.has(toolId)) {
      quickSelectedTools.delete(toolId);
    } else {
      quickSelectedTools.add(toolId);
    }
    renderForkToolsQuickInput();
  }

  function expandOrCollapseActiveToolRow(expand) {
    const row = quickVisibleRows()[quickInputActiveIndex];
    const toolId = row?.getAttribute("data-tool-id");
    if (!toolId || row?.dataset.hasChildren !== "true") return;
    if (expand) {
      quickExpandedGroups.add(toolId);
    } else {
      quickExpandedGroups.delete(toolId);
    }
    renderForkToolsQuickInput();
  }

  function installForkQuickInputKeyboard(host) {
    host.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        closeForkQuickInput();
        return;
      }
      if (event.key === "ArrowDown") {
        event.preventDefault();
        event.stopPropagation();
        setQuickActiveIndex(quickInputActiveIndex + 1);
        return;
      }
      if (event.key === "ArrowUp") {
        event.preventDefault();
        event.stopPropagation();
        setQuickActiveIndex(quickInputActiveIndex - 1);
        return;
      }
      if (quickInputKind === "tools" && event.key === "ArrowRight") {
        event.preventDefault();
        event.stopPropagation();
        expandOrCollapseActiveToolRow(true);
        return;
      }
      if (quickInputKind === "tools" && event.key === "ArrowLeft") {
        event.preventDefault();
        event.stopPropagation();
        expandOrCollapseActiveToolRow(false);
        return;
      }
      if (quickInputKind === "tools" && event.key === " ") {
        event.preventDefault();
        event.stopPropagation();
        toggleActiveToolRow();
        return;
      }
      if (event.key === "Enter") {
        event.preventDefault();
        event.stopPropagation();
        const row = quickVisibleRows()[quickInputActiveIndex];
        row?.dispatchEvent(new MouseEvent("click", { bubbles: true, cancelable: true, view: window }));
      }
    }, true);
  }

  function handleForkQuickInputMessage(event) {
    const message = event.data || {};
    if (message.source !== "ioi-workbench-agent-studio") {
      return;
    }
    if (message.type === "ioi.quickInput.dismiss") {
      closeForkQuickInput();
      return;
    }
    if (message.type !== "ioi.quickInput.open") {
      return;
    }
    quickInputTargetWindow = event.source || null;
    quickInputTargetOrigin = event.origin && event.origin !== "null" ? event.origin : "*";
    quickInputBridgeUrl = String(message.payload?.bridgeUrl || "");
    quickInputAnchorRect = resolveForkQuickInputAnchorRect(message.payload?.anchorRect, event.source);
    const command = String(message.command || "");
    if (command === "ioi.quickInput.tools.configure") {
      if (quickInputHost && quickInputKind === "tools") {
        closeForkQuickInput();
        return;
      }
      renderForkToolsQuickInput();
      return;
    }
    if (command === "ioi.quickInput.context.open") {
      if (quickInputHost && quickInputKind === "context") {
        closeForkQuickInput();
        return;
      }
      renderForkContextQuickInput();
      return;
    }
    if (command === "ioi.quickInput.workflowTarget.pick") {
      if (quickInputHost && quickInputKind === "target") {
        closeForkQuickInput();
        return;
      }
      renderForkSimpleQuickInput("target", "fork-workflow-target-quickinput", quickTargetRows, command);
      return;
    }
    if (command === "ioi.quickInput.agentMode.pick") {
      if (quickInputHost && quickInputKind === "agentmode") {
        closeForkQuickInput();
        return;
      }
      renderForkSimpleQuickInput("agentmode", "fork-agent-mode-quickinput", quickAgentModeRows, command);
      return;
    }
    if (command === "ioi.quickInput.permissionMode.pick") {
      if (quickInputHost && quickInputKind === "permissionmode") {
        closeForkQuickInput();
        return;
      }
      renderForkSimpleQuickInput("permissionmode", "fork-permission-mode-quickinput", quickPermissionModeRows, command);
      return;
    }
    if (command === "ioi.quickInput.modelRoute.pick") {
      if (quickInputHost && quickInputKind === "modelroute") {
        closeForkQuickInput();
        return;
      }
      const mountedRows = Array.isArray(message.payload?.mountedModels)
        ? message.payload.mountedModels
        : [];
      const modelRows = mountedRows.length
        ? mountedRows.map((row, index) => ({
          id: String(row.routeId || row.id || row.modelId || "mounted-model-" + index),
          label: String(row.label || row.modelId || row.routeId || "Mounted model"),
          detail: String(row.detail || row.modelId || row.routeId || ""),
          meta: String(row.meta || "mounted"),
          codicon: "package",
          selected: index === 0,
          requestType: "chat.modelRoute.select",
        }))
        : [
          {
            id: "setup-recommended-models",
            label: "Set up recommended models",
            detail: "Open Models to download a hardware-appropriate chat model, plus optional story and embedding models.",
            meta: "setup",
            codicon: "cloud-download",
            requestType: "models.open",
          },
        ];
      renderForkSimpleQuickInput("modelroute", "fork-model-route-quickinput", modelRows, command);
      return;
    }
    postForkQuickInputResult({
      kind: "unsupported",
      command,
      requestType: "quickInput.unsupported",
      label: command || "unsupported",
    });
  }

  function installBackRail() {
    const content = document.querySelector(".part.activitybar .content");
    if (!content) return;
    let back = document.getElementById("ioi-hypervisor-back-rail");
    if (!back) {
      back = document.createElement("button");
      back.id = "ioi-hypervisor-back-rail";
      back.type = "button";
      back.title = "Back to Hypervisor";
      back.setAttribute("aria-label", "Back to Hypervisor");
      back.dataset.testid = "code-rail-back-to-hypervisor";
      back.textContent = "‹";
      back.addEventListener("click", () => {
        openMode(activeHypervisorMode || "home");
      });
      content.prepend(back);
    }
  }

  function decorateActivityBar() {
    renderPrimaryRail();
    installBackRail();
    for (const action of document.querySelectorAll(".part.activitybar .action-item")) {
      const label = labelFor(action);
      const hypervisorMode = classifyHypervisorAction(label);
      const isHypervisor = Boolean(hypervisorMode);
      const isSubstrate = !isHypervisor && substratePatterns.some((pattern) => pattern.test(label));
      const isGlobal = !isHypervisor && !isSubstrate && globalPatterns.some((pattern) => pattern.test(label));
      updateClass(action, "ioi-hypervisor-mode-action", isHypervisor);
      updateClass(action, "ioi-code-action", hypervisorMode?.id === "code");
      updateClass(action, "ioi-vscode-substrate-action", isSubstrate);
      updateClass(action, "ioi-vscode-global-action", isGlobal);
      if (hypervisorMode) {
        setDataset(action, "ioiRailKind", "hypervisor");
        setDataset(action, "ioiMode", hypervisorMode.id);
        continue;
      }
      if (isSubstrate) {
        setDataset(action, "ioiRailKind", "substrate");
        setDataset(action, "ioiMode", "");
        continue;
      }
      setDataset(action, "ioiRailKind", isGlobal ? "global" : "");
      setDataset(action, "ioiMode", "");
    }
  }

  function updateClass(element, className, enabled) {
    if (!element) return;
    if (enabled && !element.classList.contains(className)) {
      element.classList.add(className);
    } else if (!enabled && element.classList.contains(className)) {
      element.classList.remove(className);
    }
  }

  function setDataset(element, key, value) {
    if (!element) return;
    if (!value) {
      if (element.dataset[key] !== undefined) delete element.dataset[key];
      return;
    }
    if (element.dataset[key] !== value) element.dataset[key] = value;
  }

  function setStyleProperty(element, name, value) {
    if (!element) return;
    if (element.style.getPropertyValue(name) !== value) {
      element.style.setProperty(name, value);
    }
  }

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeCodeMenu();
      closeForkQuickInput();
    }
  }, true);
  window.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && quickInputHost) {
      event.preventDefault();
      event.stopPropagation();
      closeForkQuickInput();
    }
  }, true);

  window.addEventListener("message", handleForkQuickInputMessage, true);

  document.addEventListener("click", (event) => {
    if (!openCodeMenuLabel) return;
    const target = event.target;
    if (!(target instanceof Element)) return;
    if (
      target.closest("#ioi-hypervisor-workbench-code-menu") ||
      target.closest("#ioi-hypervisor-workbench-code-menu-dropdown")
    ) {
      return;
    }
    closeCodeMenu();
  }, true);

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const action = target.closest(".part.activitybar .action-item");
    if (!action) return;
    const label = labelFor(action);
    const hypervisorMode = classifyHypervisorAction(label);
    if (hypervisorMode?.id === "code") {
      setShellMode("code");
    } else if (hypervisorMode) {
      setShellMode("hypervisor", hypervisorMode.id);
    }
  }, true);

  function tick() {
    synchronizeModeFromWorkbench();
    applyClasses();
    renderHeader();
    renderCodeMenu();
    renderPrimaryRail();
    decorateActivityBar();
  }

  function scheduleTick() {
    if (scheduled) return;
    scheduled = true;
    requestAnimationFrame(() => {
      scheduled = false;
      tick();
    });
  }

  const observer = new MutationObserver(scheduleTick);
  function start() {
    tick();
    observer.observe(document.body, { childList: true, subtree: true });
    setInterval(tick, 1000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
})();
${JS_END}`;
}

function patchElectronMainMenuVisibility(mainJsPath) {
  let existing = readFileSync(mainJsPath, "utf8");
  let patched = false;

  if (existing.includes(ELECTRON_MAIN_MENU_VISIBILITY_PATCH)) {
    existing = existing.replace(ELECTRON_MAIN_MENU_VISIBILITY_PATCH, "");
    patched = true;
  }

  if (existing.includes(ELECTRON_MAIN_APPLICATION_MENU_PATCH)) {
    existing = existing.replace(ELECTRON_MAIN_APPLICATION_MENU_PATCH, "");
    patched = true;
  }

  if (existing.includes(ELECTRON_MAIN_CUSTOM_TITLEBAR_PATCH_LEGACY)) {
    existing = existing.replace(ELECTRON_MAIN_CUSTOM_TITLEBAR_PATCH_LEGACY, "");
    patched = true;
  }

  const titlebarNeedle = "function $TD(configurationService) {\n        if (platform_1.$o) {";
  const titlebarReplacement =
    "function $TD(configurationService) {\n" +
    ELECTRON_MAIN_CUSTOM_TITLEBAR_PATCH +
    "        if (platform_1.$o) {";
  if (!existing.includes(ELECTRON_MAIN_CUSTOM_TITLEBAR_PATCH)) {
    if (!existing.includes(titlebarNeedle)) {
      console.warn(
        `[hypervisor-workbench-shell-patch] Electron main titlebar style function shape not found in ${mainJsPath}; continuing without titlebar override.`,
      );
      return false;
    }
    existing = existing.replace(titlebarNeedle, titlebarReplacement);
    patched = true;
  }

  if (patched) {
    writeFileSync(mainJsPath, existing);
  }
  return patched;
}

function patchWorkbenchTitlebarStyle(workbenchJsPath) {
  let existing = readFileSync(workbenchJsPath, "utf8");
  let patched = false;

  if (existing.includes(ELECTRON_MAIN_CUSTOM_TITLEBAR_PATCH_LEGACY)) {
    existing = existing.replace(ELECTRON_MAIN_CUSTOM_TITLEBAR_PATCH_LEGACY, "");
    patched = true;
  }

  const titlebarNeedle = "function $TD(configurationService) {\n        if (platform_1.$o) {";
  const titlebarReplacement =
    "function $TD(configurationService) {\n" +
    ELECTRON_MAIN_CUSTOM_TITLEBAR_PATCH +
    "        if (platform_1.$o) {";
  if (!existing.includes(ELECTRON_MAIN_CUSTOM_TITLEBAR_PATCH)) {
    if (!existing.includes(titlebarNeedle)) {
      console.warn(
        `[hypervisor-workbench-shell-patch] Workbench titlebar style function shape not found in ${workbenchJsPath}; continuing without titlebar override.`,
      );
      return false;
    }
    existing = existing.replace(titlebarNeedle, titlebarReplacement);
    patched = true;
  }

  if (patched) {
    writeFileSync(workbenchJsPath, existing);
  }
  return patched;
}

function patchWorkbenchIntegrityWarning(workbenchJsPath) {
  let existing = readFileSync(workbenchJsPath, "utf8");
  const safeGuard = "typeof process === 'undefined' || process.env.IOI_WORKBENCH_NATIVE_SHELL === '1'";
  const safeMarker = safeGuard + ") {\n                return; // Hypervisor shell intentionally patches the packaged workbench.";
  const unsafeMarker = "process.env.IOI_WORKBENCH_NATIVE_SHELL === '1') {\n                return; // Hypervisor shell intentionally patches the packaged workbench.";
  if (existing.includes(safeMarker)) {
    return false;
  }
  if (existing.includes(unsafeMarker)) {
    existing = existing.replace(unsafeMarker, safeMarker);
    writeFileSync(workbenchJsPath, existing);
    return true;
  }
  const needle = "        async k() {\n            const { isPure } = await this.isPure();";
  const replacement =
    "        async k() {\n            if (" +
    safeGuard +
    ") {\n                return; // Hypervisor shell intentionally patches the packaged workbench.\n            }\n            const { isPure } = await this.isPure();";
  if (!existing.includes(needle)) {
    console.warn(
      `[hypervisor-workbench-shell-patch] Workbench integrity service shape not found in ${workbenchJsPath}; continuing without integrity-warning suppression.`,
    );
    return false;
  }
  existing = existing.replace(needle, replacement);
  writeFileSync(workbenchJsPath, existing);
  return true;
}

function patchWorkbenchCspForLocalBridge(workbenchHtmlPath) {
  let existing = readFileSync(workbenchHtmlPath, "utf8");
  if (
    existing.includes("http://127.0.0.1:*") &&
    existing.includes("http://localhost:*")
  ) {
    return false;
  }

  const needle =
    "\t\t\t\tconnect-src\n" +
    "\t\t\t\t\t'self'\n" +
    "\t\t\t\t\thttps:\n" +
    "\t\t\t\t\tws:\n" +
    "\t\t\t\t;";
  const replacement =
    "\t\t\t\tconnect-src\n" +
    "\t\t\t\t\t'self'\n" +
    "\t\t\t\t\thttps:\n" +
    "\t\t\t\t\tws:\n" +
    "\t\t\t\t\thttp://127.0.0.1:*\n" +
    "\t\t\t\t\thttp://localhost:*\n" +
    "\t\t\t\t;";
  if (!existing.includes(needle)) {
    throw new Error(`Workbench CSP shape not found in ${workbenchHtmlPath}`);
  }
  existing = existing.replace(needle, replacement);
  writeFileSync(workbenchHtmlPath, existing);
  return true;
}

export function applyHypervisorWorkbenchShellPatch({
  packagedRoot = HYPERVISOR_WORKBENCH_ADAPTER_HOST.packagedRoot,
} = {}) {
  const workbenchDir = resolve(packagedRoot, "resources/app/out/vs/workbench");
  const electronMainDir = resolve(packagedRoot, "resources/app/out/vs/code/electron-main");
  const electronWorkbenchDir = resolve(
    packagedRoot,
    "resources/app/out/vs/code/electron-sandbox/workbench",
  );
  const cssPath = join(workbenchDir, "workbench.desktop.main.css");
  const jsPath = join(workbenchDir, "workbench.desktop.main.js");
  const electronMainPath = join(electronMainDir, "main.js");
  const workbenchHtmlPath = join(electronWorkbenchDir, "workbench.html");
  if (
    !existsSync(cssPath) ||
    !existsSync(jsPath) ||
    !existsSync(electronMainPath) ||
    !existsSync(workbenchHtmlPath)
  ) {
    throw new Error(`Workbench/Electron bundle not found under ${packagedRoot}`);
  }

  upsertMarkedBlock(cssPath, CSS_START, CSS_END, workbenchShellCss());
  upsertMarkedBlock(jsPath, JS_START, JS_END, workbenchShellJs());
  const workbenchIntegrityPatched = patchWorkbenchIntegrityWarning(jsPath);
  const workbenchCspPatched = patchWorkbenchCspForLocalBridge(workbenchHtmlPath);
  const workbenchTitlebarPatched = patchWorkbenchTitlebarStyle(jsPath);
  const electronMainMenuPatched = patchElectronMainMenuVisibility(electronMainPath);

  const metadataPath = resolve(
    packagedRoot,
    "resources/app/out/ioi/hypervisor-workbench-shell-patch.json",
  );
  mkdirSync(dirname(metadataPath), { recursive: true });
  const metadata = {
    schemaVersion: "ioi.hypervisor-workbench-shell-patch.v1",
    packagedRoot,
    cssPath,
    jsPath,
    electronMainPath,
    workbenchHtmlPath,
    installedAt: new Date().toISOString(),
	    capabilities: {
	      forkNativeRailShim: true,
	      forkNativeHeaderShim: false,
	      secondaryHypervisorHeaderRemoved: true,
	      vscodeCommandCenterOwnsTopShell: true,
	      forkNativeModeHostShim: true,
      originalVscodeMenuRestoredInElectronMain: true,
      originalVscodeCustomTitlebarForcedInElectronMain: true,
      codeModeUsesOriginalVscodeMenubar: true,
      hypervisorModeMenuHiddenByCssAndSettings: true,
      workbenchIntegrityWarningSuppressed: true,
      workbenchIntegrityPatched,
      workbenchCspPatched,
      forkQuickInputBridgeConnectSrcPatched: true,
      workbenchTitlebarPatched,
      electronMainMenuPatched,
      codeDrilldownRail: true,
      forkNativeQuickInputShim: true,
      nativeQuickInputCommands: [
        "ioi.quickInput.context.open",
        "ioi.quickInput.tools.configure",
        "ioi.quickInput.modelRoute.pick",
        "ioi.quickInput.workflowTarget.pick",
        "ioi.quickInput.agentMode.pick",
        "ioi.quickInput.permissionMode.pick",
      ],
      extensionQuickPickFallbackUsedInTestedPath: false,
      quickInputContextRows: [
        "Files & Folders",
        "Instructions",
        "Problems",
        "Symbols",
        "Tools",
      ],
      quickInputToolsTreePicker: true,
      quickInputToolsCheckboxSemantics: true,
      quickInputAgentModePicker: true,
      quickInputWorkflowTargetPicker: true,
      webviewRuntimeAuthority: false,
      tauriUsed: false,
    },
  };
  writeFileSync(metadataPath, `${JSON.stringify(metadata, null, 2)}\n`);
  return metadata;
}
