type HostEventCallback<T> = (event: { payload: T }) => void;
type HostUnlisten = () => void | Promise<void>;

type HostWindow = {
  label: string;
  setTitle: (title: string) => Promise<void>;
  setDecorations: (decorated: boolean) => Promise<void>;
  isMaximized: () => Promise<boolean>;
  onMoved: (handler: () => void) => Promise<HostUnlisten>;
  onResized: (handler: () => void) => Promise<HostUnlisten>;
  toggleMaximize: () => Promise<void>;
  minimize: () => Promise<void>;
  close: () => Promise<void>;
  outerPosition: () => Promise<{ x: number; y: number }>;
  setPosition: (position: { x: number; y: number }) => Promise<void>;
};

type HostWindowBridge = Partial<HostWindow>;

type HypervisorHostBridge = {
  core?: {
    invoke?: <T>(command: string, args?: unknown) => Promise<T>;
  };
  event?: {
    listen?: <T>(
      eventName: string,
      handler: HostEventCallback<T>,
    ) => Promise<HostUnlisten>;
    emit?: <T>(eventName: string, payload?: T) => Promise<void>;
  };
  window?: {
    getCurrentWindow?: () => HostWindowBridge;
  };
  dialog?: {
    save?: (options?: unknown) => Promise<string | null>;
  };
  opener?: {
    openUrl?: (url: string) => Promise<void>;
    openPath?: (path: string) => Promise<void>;
    revealItemInDir?: (path: string) => Promise<void>;
  };
  notification?: {
    isPermissionGranted?: () => Promise<boolean>;
    requestPermission?: () => Promise<"granted" | "denied" | "default">;
    sendNotification?: (options: { title: string; body?: string }) => Promise<void>;
  };
  deepLink?: {
    getCurrent?: () => Promise<string[]>;
    onOpenUrl?: (handler: (urls: string[]) => void) => Promise<HostUnlisten>;
  };
};

declare global {
  interface Window {
    __HYPERVISOR_HOST_BRIDGE__?: HypervisorHostBridge;
  }
}

export class PhysicalPosition {
  constructor(
    public readonly x: number,
    public readonly y: number,
  ) {}
}

function activeBridge(): HypervisorHostBridge | null {
  if (typeof window === "undefined") {
    return null;
  }
  return window.__HYPERVISOR_HOST_BRIDGE__ ?? null;
}

export function isHypervisorHostBridgeRuntime(): boolean {
  return Boolean(activeBridge());
}

export async function invoke<T>(command: string, args?: unknown): Promise<T> {
  const hostInvoke = activeBridge()?.core?.invoke;
  if (!hostInvoke) {
    throw new Error(
      `${command} requires a Hypervisor host bridge or daemon-backed client route.`,
    );
  }
  return hostInvoke<T>(command, args);
}

export async function emit<T>(eventName: string, payload?: T): Promise<void> {
  const hostEmit = activeBridge()?.event?.emit;
  if (!hostEmit) {
    return;
  }
  await hostEmit(eventName, payload);
}

export function listen<T>(
  eventName: string,
  handler: HostEventCallback<T>,
): Promise<HostUnlisten> {
  const hostListen = activeBridge()?.event?.listen;
  if (!hostListen) {
    return Promise.resolve(() => {});
  }
  return hostListen(eventName, handler);
}

function fallbackWindow(): HostWindow {
  return {
    label: "hypervisor-app",
    setTitle: async (title) => {
      document.title = title;
    },
    isMaximized: async () => false,
    setDecorations: async () => {},
    onMoved: async (handler) => {
      window.addEventListener("move", handler);
      return () => window.removeEventListener("move", handler);
    },
    onResized: async (handler) => {
      window.addEventListener("resize", handler);
      return () => window.removeEventListener("resize", handler);
    },
    toggleMaximize: async () => {},
    minimize: async () => {},
    close: async () => {},
    outerPosition: async () => ({ x: window.screenX, y: window.screenY }),
    setPosition: async () => {},
  };
}

export function getCurrentWindow(): HostWindow {
  const fallback = fallbackWindow();
  const hostWindow = activeBridge()?.window?.getCurrentWindow?.() ?? {};
  return {
    ...fallback,
    ...hostWindow,
  };
}

export async function save(options?: unknown): Promise<string | null> {
  const hostSave = activeBridge()?.dialog?.save;
  if (!hostSave) {
    return null;
  }
  return hostSave(options);
}

export async function openUrl(url: string): Promise<void> {
  const hostOpenUrl = activeBridge()?.opener?.openUrl;
  if (hostOpenUrl) {
    await hostOpenUrl(url);
    return;
  }
  window.open(url, "_blank", "noopener,noreferrer");
}

export async function openPath(path: string): Promise<void> {
  const hostOpenPath = activeBridge()?.opener?.openPath;
  if (!hostOpenPath) {
    throw new Error(`openPath requires a Hypervisor host bridge: ${path}`);
  }
  await hostOpenPath(path);
}

export async function revealItemInDir(path: string): Promise<void> {
  const hostReveal = activeBridge()?.opener?.revealItemInDir;
  if (!hostReveal) {
    throw new Error(`revealItemInDir requires a Hypervisor host bridge: ${path}`);
  }
  await hostReveal(path);
}

export async function isPermissionGranted(): Promise<boolean> {
  return activeBridge()?.notification?.isPermissionGranted?.() ?? false;
}

export async function requestPermission(): Promise<"granted" | "denied" | "default"> {
  return activeBridge()?.notification?.requestPermission?.() ?? "denied";
}

export async function sendNotification(options: {
  title: string;
  body?: string;
}): Promise<void> {
  const hostSend = activeBridge()?.notification?.sendNotification;
  if (!hostSend) {
    return;
  }
  await hostSend(options);
}

export async function getCurrent(): Promise<string[]> {
  return activeBridge()?.deepLink?.getCurrent?.() ?? [];
}

export function onOpenUrl(
  handler: (urls: string[]) => void,
): Promise<HostUnlisten> {
  const hostOnOpenUrl = activeBridge()?.deepLink?.onOpenUrl;
  if (!hostOnOpenUrl) {
    return Promise.resolve(() => {});
  }
  return hostOnOpenUrl(handler);
}
