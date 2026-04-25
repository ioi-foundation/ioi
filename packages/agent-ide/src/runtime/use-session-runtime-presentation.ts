import { useMemo } from "react";
import type { SessionGateChatEvent } from "./use-session-gate-state";

export interface SessionRuntimePresentationMessageLike {
  role: string;
  text: string;
  timestamp: number;
}

export interface SessionRuntimePresentationEventLike {
  step_index: number;
}

export interface SessionRuntimePresentationEntry<
  TGateData,
> extends SessionRuntimePresentationMessageLike {
  isGate?: boolean;
  gateData?: TGateData | null;
}

export type SessionRuntimePresentationGroup<TGateData> =
  | {
      type: "message";
      content: SessionRuntimePresentationEntry<TGateData>;
    }
  | {
      type: "chain";
      content: SessionRuntimePresentationEntry<TGateData>[];
    }
  | {
      type: "gate";
      content: TGateData | null | undefined;
    };

export interface SessionRuntimeTimelineStep<TEvent> {
  stepIndex: number;
  events: TEvent[];
}

export interface UseSessionRuntimePresentationOptions<
  THistoryMessage extends SessionRuntimePresentationMessageLike,
  TChatEvent extends SessionGateChatEvent,
  TEvent extends SessionRuntimePresentationEventLike,
> {
  activeHistory: THistoryMessage[];
  chatEvents: TChatEvent[];
  activeEvents: TEvent[];
}

export function useSessionRuntimePresentation<
  THistoryMessage extends SessionRuntimePresentationMessageLike,
  TChatEvent extends SessionGateChatEvent,
  TEvent extends SessionRuntimePresentationEventLike,
>({
  activeHistory,
  chatEvents,
  activeEvents,
}: UseSessionRuntimePresentationOptions<THistoryMessage, TChatEvent, TEvent>) {
  return useMemo(() => {
    type GateData = TChatEvent["gateData"];
    type Entry = SessionRuntimePresentationEntry<GateData>;

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

    const groups: SessionRuntimePresentationGroup<GateData>[] = [];
    const timelineSteps: SessionRuntimeTimelineStep<TEvent>[] = [];

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
      hasRuntimeTimelineContent: foundChain || timelineSteps.length > 0,
    };
  }, [activeEvents, activeHistory, chatEvents]);
}
