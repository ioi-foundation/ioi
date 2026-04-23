declare module "@xterm/xterm/css/xterm.css";

interface ImportMetaEnv {
  readonly VITE_AUTOPILOT_WORKSPACE_DEBUG_FOOTER?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
