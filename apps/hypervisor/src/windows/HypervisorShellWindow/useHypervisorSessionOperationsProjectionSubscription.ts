import { useEffect } from "react";

import {
  hypervisorSessionEventsPath,
  loadHypervisorSessionOperationsProjection,
  readHypervisorSessionOperationsDaemonEndpoint,
  type HypervisorChangedFileGroupProjection,
  type HypervisorEnvironmentStatus,
  type HypervisorSessionOperationsProjection,
  type HypervisorTerminalEventProjection,
} from "../../domain/hypervisorSessionOperationsModel";

interface SubscriptionOptions {
  enabled: boolean;
  sessionRef: string;
  onProjection: (projection: HypervisorSessionOperationsProjection) => void;
  // Injected for the gate + testability; defaults to the one-shot loader.
  load?: () => Promise<HypervisorSessionOperationsProjection>;
}

function toTerminalEvent(
  data: unknown,
  index: number,
): HypervisorTerminalEventProjection | null {
  if (data && typeof data === "object" && "command_summary" in data) {
    const record = data as Record<string, unknown>;
    const status = record.status;
    return {
      event_ref:
        typeof record.event_ref === "string"
          ? record.event_ref
          : `terminal-event:${index}`,
      command_summary: String(record.command_summary ?? ""),
      status:
        status === "proposed" || status === "blocked" ? status : "executed",
      receipt_ref:
        typeof record.receipt_ref === "string" ? record.receipt_ref : "",
    };
  }
  // dev-replay terminal_chunk shapes: a raw string, or { text }/{ chunk }.
  const text =
    typeof data === "string"
      ? data
      : data && typeof data === "object"
        ? String(
            (data as Record<string, unknown>).text ??
              (data as Record<string, unknown>).chunk ??
              "",
          )
        : "";
  if (!text.trim()) return null;
  return {
    event_ref: `terminal-event:${index}`,
    command_summary: text.slice(0, 400),
    status: "executed",
    receipt_ref: "",
  };
}

// Fold one canonical session event into the projection. Targeted field merges
// (not a full re-normalize) so live deltas never clobber unrelated fields.
function applySessionEvent(
  current: HypervisorSessionOperationsProjection,
  event: string,
  data: unknown,
): HypervisorSessionOperationsProjection {
  const record = (data ?? {}) as Record<string, unknown>;
  switch (event) {
    case "environment_status":
      return data && typeof data === "object"
        ? { ...current, environment_status: data as HypervisorEnvironmentStatus }
        : current;
    case "workspace_change":
      return Array.isArray(record.changed_file_groups)
        ? {
            ...current,
            changed_file_groups:
              record.changed_file_groups as HypervisorChangedFileGroupProjection[],
          }
        : current;
    case "terminal_chunk": {
      const next = toTerminalEvent(data, current.terminal_events.length);
      return next
        ? { ...current, terminal_events: [...current.terminal_events, next] }
        : current;
    }
    case "receipt_projection":
      return Array.isArray(record.latest_receipt_refs)
        ? {
            ...current,
            latest_receipt_refs: (record.latest_receipt_refs as unknown[]).map(
              String,
            ),
          }
        : current;
    default:
      // session_state | readiness and unknown events carry no projection delta.
      return current;
  }
}

/**
 * Subscribe a session's operations projection to the daemon's live session
 * events. Does a baseline one-shot load (so the cockpit paints immediately),
 * then opens the canonical `/v1/hypervisor/sessions/:id/events` SSE stream and
 * folds environment_status / workspace_change / terminal_chunk /
 * receipt_projection deltas into the projection. Degrades silently offline
 * (keeps the baseline/fixture) — no console noise.
 */
export function useHypervisorSessionOperationsProjectionSubscription(
  options: SubscriptionOptions,
): void {
  const { enabled, sessionRef, onProjection } = options;
  const load = options.load ?? loadHypervisorSessionOperationsProjection;
  useEffect(() => {
    if (!enabled) return;
    let cancelled = false;
    const controller = new AbortController();
    const endpoint = readHypervisorSessionOperationsDaemonEndpoint().replace(
      /\/+$/,
      "",
    );
    let current: HypervisorSessionOperationsProjection | null = null;

    const publish = () => {
      if (current && !cancelled) onProjection(current);
    };

    const subscribe = async () => {
      let response: Response;
      try {
        response = await fetch(
          `${endpoint}${hypervisorSessionEventsPath(sessionRef)}`,
          {
            headers: { accept: "text/event-stream" },
            signal: controller.signal,
          },
        );
      } catch {
        return;
      }
      if (!response.ok || !response.body) return;
      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (!cancelled) {
        let chunk: ReadableStreamReadResult<Uint8Array>;
        try {
          chunk = await reader.read();
        } catch {
          break;
        }
        if (chunk.done) break;
        buffer += decoder.decode(chunk.value, { stream: true });
        const blocks = buffer.split("\n\n");
        buffer = blocks.pop() ?? "";
        for (const block of blocks) {
          const lines = block.split("\n");
          const event =
            lines.find((line) => line.startsWith("event: "))?.slice(7) ??
            "message";
          const dataLine = lines
            .find((line) => line.startsWith("data: "))
            ?.slice(6);
          if (!dataLine) continue;
          let data: unknown;
          try {
            data = JSON.parse(dataLine);
          } catch {
            continue;
          }
          if (current) {
            current = applySessionEvent(current, event, data);
            publish();
          }
        }
      }
    };

    void load()
      .then((baseline) => {
        if (cancelled) return undefined;
        current = baseline;
        publish();
        return subscribe();
      })
      .catch(() => {
        // Offline / no daemon: keep whatever baseline the caller already has.
      });

    return () => {
      cancelled = true;
      controller.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, sessionRef]);
}
