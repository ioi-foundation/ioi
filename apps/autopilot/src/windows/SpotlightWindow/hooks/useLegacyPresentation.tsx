import React, { useMemo } from "react";
import type { AgentEvent, ChatMessage } from "../../../types";
import { MarkdownMessage } from "../components/MarkdownMessage";
import { MessageActions } from "../components/MessageActions";
import { ThoughtChain } from "../components/ThoughtChain";
import type { ChatEvent } from "./useGateState";

type LegacyChatEvent = ChatEvent;

type LegacyPresentationGroup =
  | { type: "message"; content: LegacyChatEvent }
  | { type: "chain"; content: ChatMessage[] }
  | { type: "gate"; content: unknown };

interface LegacyPresentationOptions {
  activeHistory: ChatMessage[];
  chatEvents: ChatEvent[];
  activeEvents: AgentEvent[];
  isRunning: boolean;
  taskMeta: {
    currentStep: string | undefined;
    agent: string | undefined;
    generation: number | undefined;
    progress: number | undefined;
    totalSteps: number | undefined;
  };
  onOpenArtifact: (artifactId: string) => void;
}

export function useLegacyPresentation({
  activeHistory,
  chatEvents,
  activeEvents,
  isRunning,
  taskMeta,
  onOpenArtifact,
}: LegacyPresentationOptions) {
  return useMemo(() => {
    const combined = [
      ...activeHistory.map((message) => ({ ...message, isGate: false, gateData: null })),
      ...chatEvents,
    ];

    const groups: LegacyPresentationGroup[] = [];

    let currentChain: ChatMessage[] = [];
    let foundChain = false;

    combined.forEach((message) => {
      if (message.role === "tool" || (message.role === "system" && !message.isGate)) {
        currentChain.push(message);
      } else if (message.isGate) {
        if (currentChain.length > 0) {
          groups.push({ type: "chain", content: [...currentChain] });
          foundChain = true;
          currentChain = [];
        }
        groups.push({ type: "gate", content: message.gateData });
      } else {
        if (currentChain.length > 0) {
          groups.push({ type: "chain", content: [...currentChain] });
          foundChain = true;
          currentChain = [];
        }
        groups.push({ type: "message", content: message });
      }
    });

    if (currentChain.length > 0) {
      groups.push({ type: "chain", content: currentChain });
      foundChain = true;
    }

    const historyElements = groups.map((group, index) => (
      <React.Fragment key={index}>
        {group.type === "message" && (
          <div className={`spot-message ${group.content.role === "user" ? "user" : "agent"}`}>
            {group.content.role === "agent" ? (
              <MarkdownMessage text={group.content.text} />
            ) : (
              <div className="message-content-text">{group.content.text}</div>
            )}
            {group.content.role !== "user" && (
              <MessageActions text={group.content.text} showRetry={true} onRetry={() => {}} />
            )}
          </div>
        )}

        {group.type === "chain" && (
          <ThoughtChain
            messages={group.content}
            activeStep={isRunning && index === groups.length - 1 ? taskMeta.currentStep : null}
            agentName={taskMeta.agent}
            generation={taskMeta.generation}
            progress={taskMeta.progress}
            totalSteps={taskMeta.totalSteps}
            onOpenArtifact={onOpenArtifact}
          />
        )}

        {group.type === "gate" && null}
      </React.Fragment>
    ));

    const timelineElements: React.ReactNode[] = [];
    if (activeEvents.length > 0) {
      const byStep = new Map<number, AgentEvent[]>();
      for (const event of activeEvents) {
        const list = byStep.get(event.step_index) || [];
        list.push(event);
        byStep.set(event.step_index, list);
      }
      const orderedSteps = Array.from(byStep.keys()).sort((a, b) => a - b);
      const latestStep = orderedSteps[orderedSteps.length - 1];
      for (const stepIndex of orderedSteps) {
        timelineElements.push(
          <ThoughtChain
            key={`thinking-${stepIndex}`}
            messages={[]}
            events={byStep.get(stepIndex) || []}
            onOpenArtifact={onOpenArtifact}
            activeStep={isRunning && stepIndex === latestStep ? taskMeta.currentStep : null}
            agentName={taskMeta.agent}
            generation={taskMeta.generation}
            progress={taskMeta.progress}
            totalSteps={taskMeta.totalSteps}
          />,
        );
      }
    }

    return {
      legacyChatElements: [...historyElements, ...timelineElements],
      hasLegacyChainContent: foundChain || timelineElements.length > 0,
    };
  }, [activeEvents, activeHistory, chatEvents, isRunning, onOpenArtifact, taskMeta]);
}
