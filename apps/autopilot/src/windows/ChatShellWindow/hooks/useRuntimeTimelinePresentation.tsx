import React, { useMemo } from "react";
import {
  useSessionRuntimePresentation,
  type SessionGateChatEvent as ChatEvent,
} from "@ioi/agent-ide";
import type { AgentEvent, ChatMessage } from "../../../types";
import { MarkdownMessage } from "../../ChatShellWindow/components/MarkdownMessage";
import { MessageActions } from "../../ChatShellWindow/components/MessageActions";
import { ThoughtChain } from "../../ChatShellWindow/components/ThoughtChain";

interface RuntimePresentationOptions {
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

export function useRuntimeTimelinePresentation({
  activeHistory,
  chatEvents,
  activeEvents,
  isRunning,
  taskMeta,
  onOpenArtifact,
}: RuntimePresentationOptions) {
  const { groups, timelineSteps, hasRuntimeTimelineContent } =
    useSessionRuntimePresentation({
      activeHistory,
      chatEvents,
      activeEvents,
    });

  return useMemo(() => {
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
            messages={group.content as ChatMessage[]}
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

    const latestStep = timelineSteps[timelineSteps.length - 1]?.stepIndex;
    const timelineElements = timelineSteps.map((step) => (
      <ThoughtChain
        key={`thinking-${step.stepIndex}`}
        messages={[]}
        events={step.events as AgentEvent[]}
        onOpenArtifact={onOpenArtifact}
        activeStep={isRunning && step.stepIndex === latestStep ? taskMeta.currentStep : null}
        agentName={taskMeta.agent}
        generation={taskMeta.generation}
        progress={taskMeta.progress}
        totalSteps={taskMeta.totalSteps}
      />
    ));

    return {
      runtimeTimelineElements: [...historyElements, ...timelineElements],
      hasRuntimeTimelineContent,
    };
  }, [groups, hasRuntimeTimelineContent, isRunning, onOpenArtifact, taskMeta, timelineSteps]);
}
