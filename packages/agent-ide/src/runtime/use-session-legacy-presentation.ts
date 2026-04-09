import { useMemo } from "react";
import type { SessionGateChatEvent } from "./use-session-gate-state";

export interface SessionLegacyPresentationMessageLike {
  role: string;
  text: string;
  timestamp: number;
}

export interface SessionLegacyPresentationEventLike {
  step_index: number;
}

export interface SessionLegacyPresentationEntry<
  TGateData,
> extends SessionLegacyPresentationMessageLike {
  isGate?: boolean;
  gateData?: TGateData | null;
}

export type SessionLegacyPresentationGroup<TGateData> =
  | {
      type: "message";
      content: SessionLegacyPresentationEntry<TGateData>;
    }
  | {
      type: "chain";
      content: SessionLegacyPresentationEntry<TGateData>[];
    }
  | {
      type: "gate";
      content: TGateData | null | undefined;
    };

export interface SessionLegacyTimelineStep<TEvent> {
  stepIndex: number;
  events: TEvent[];
}

export interface UseSessionLegacyPresentationOptions<
  THistoryMessage extends SessionLegacyPresentationMessageLike,
  TChatEvent extends SessionGateChatEvent,
  TEvent extends SessionLegacyPresentationEventLike,
> {
  activeHistory: THistoryMessage[];
  chatEvents: TChatEvent[];
  activeEvents: TEvent[];
}

export function useSessionLegacyPresentation<
  THistoryMessage extends SessionLegacyPresentationMessageLike,
  TChatEvent extends SessionGateChatEvent,
  TEvent extends SessionLegacyPresentationEventLike,
>({
  activeHistory,
  chatEvents,
  activeEvents,
}: UseSessionLegacyPresentationOptions<THistoryMessage, TChatEvent, TEvent>) {
  return useMemo(() => {
    type GateData = TChatEvent["gateData"];
    type Entry = SessionLegacyPresentationEntry<GateData>;

    const combined: Entry[] = [
      ...activeHistory.map(
        (message) =>
          ({
            ...message,
            isGate: false,
            gateData: null,
          }) as Entry,
      ),
      ...chatEvents.map((event) => event as Entry),
    ];

    const groups: SessionLegacyPresentationGroup<GateData>[] = [];
    const timelineSteps: SessionLegacyTimelineStep<TEvent>[] = [];

    let currentChain: Entry[] = [];
    let foundChain = false;

    for (const message of combined) {
      if (message.role === "tool" || (message.role === "system" && !message.isGate)) {
        currentChain.push(message);
        continue;
      }

      if (currentChain.length > 0) {
        groups.push({ type: "chain", content: [...currentChain] });
        foundChain = true;
        currentChain = [];
      }

      if (message.isGate) {
        groups.push({ type: "gate", content: message.gateData });
      } else {
        groups.push({ type: "message", content: message });
      }
    }

    if (currentChain.length > 0) {
      groups.push({ type: "chain", content: currentChain });
      foundChain = true;
    }

    const byStep = new Map<number, TEvent[]>();
    for (const event of activeEvents) {
      const stepIndex = event.step_index;
      const existing = byStep.get(stepIndex) || [];
      existing.push(event);
      byStep.set(stepIndex, existing);
    }

    for (const stepIndex of Array.from(byStep.keys()).sort((a, b) => a - b)) {
      timelineSteps.push({
        stepIndex,
        events: byStep.get(stepIndex) || [],
      });
    }

    return {
      groups,
      timelineSteps,
      hasLegacyChainContent: foundChain || timelineSteps.length > 0,
    };
  }, [activeEvents, activeHistory, chatEvents]);
}
