import type { HypervisorHostBridge } from "../services/hypervisorHostBridge";
import { HYPERVISOR_DEV_REPLAY_BRIDGE_INVOKE_PATH } from "./replayContracts";

interface InstallHypervisorDevHostBridgeOptions {
  endpoint: string;
}

function endpointUrl(endpoint: string, path: string): string {
  return `${endpoint.replace(/\/+$/, "")}${path}`;
}

async function invokeReplayCommand<T>(
  endpoint: string,
  command: string,
  args?: unknown,
): Promise<T> {
  const response = await fetch(endpointUrl(endpoint, HYPERVISOR_DEV_REPLAY_BRIDGE_INVOKE_PATH), {
    body: JSON.stringify({ command, args }),
    headers: {
      accept: "application/json",
      "content-type": "application/json",
    },
    method: "POST",
  });
  const text = await response.text();
  const value = text ? JSON.parse(text) : null;
  if (!response.ok) {
    throw new Error(
      `Hypervisor dev replay host bridge command ${command} failed with ${response.status}`,
    );
  }
  return value as T;
}

export function installHypervisorDevHostBridge({
  endpoint,
}: InstallHypervisorDevHostBridgeOptions): boolean {
  if (typeof window === "undefined") {
    return false;
  }
  if (window.__HYPERVISOR_HOST_BRIDGE__) {
    return false;
  }

  const listeners = new Map<string, Set<(event: { payload: unknown }) => void>>();

  const bridge: HypervisorHostBridge = {
    core: {
      invoke: (command, args) => invokeReplayCommand(endpoint, command, args),
    },
    event: {
      listen: async (eventName, handler) => {
        const handlers = listeners.get(eventName) ?? new Set();
        handlers.add(handler as (event: { payload: unknown }) => void);
        listeners.set(eventName, handlers);
        return () => {
          handlers.delete(handler as (event: { payload: unknown }) => void);
        };
      },
      emit: async (eventName, payload) => {
        listeners.get(eventName)?.forEach((handler) => {
          handler({ payload });
        });
      },
    },
    window: {
      getCurrentWindow: () => ({
        label: "hypervisor-dev-replay",
        setTitle: async (title) => {
          document.title = title;
        },
        setDecorations: async () => {},
        isMaximized: async () => false,
        onMoved: async () => () => {},
        onResized: async () => () => {},
        toggleMaximize: async () => {},
        minimize: async () => {},
        close: async () => {},
        outerPosition: async () => ({ x: window.screenX, y: window.screenY }),
        setPosition: async () => {},
      }),
    },
    dialog: {
      save: async () => null,
    },
    opener: {
      openUrl: async (url) => {
        window.open(url, "_blank", "noopener,noreferrer");
      },
      openPath: async () => {},
      revealItemInDir: async () => {},
    },
    notification: {
      isPermissionGranted: async () => false,
      requestPermission: async () => "denied",
      sendNotification: async () => {},
    },
    deepLink: {
      getCurrent: async () => [],
      onOpenUrl: async () => () => {},
    },
  };

  window.__HYPERVISOR_HOST_BRIDGE__ = bridge;
  window.dispatchEvent(
    new CustomEvent("hypervisor-dev-replay-host-bridge-installed", {
      detail: { endpoint },
    }),
  );
  return true;
}
