import type {
  AgentEvent,
  Artifact,
  ArtifactHubViewKey,
  ContextAtlasFocusRequest,
  SourceSummary,
  ThoughtSummary,
} from "../../../types";
import { ArtifactHubSidebar } from "./ArtifactHubSidebar";
import { ArtifactSidebar } from "./ArtifactSidebar";

interface SpotlightArtifactPanelProps {
  visible: boolean;
  threadId?: string | null;
  artifactHubView: ArtifactHubViewKey | null;
  artifactHubTurnId: string | null;
  events: AgentEvent[];
  artifacts: Artifact[];
  selectedArtifact: Artifact | null;
  sourceSummary: SourceSummary | null;
  thoughtSummary: ThoughtSummary | null;
  onOpenArtifact: (artifactId: string) => void;
  onOpenAtlasFocus?: (request: ContextAtlasFocusRequest) => void;
  onClose: () => void;
}

export function SpotlightArtifactPanel({
  visible,
  threadId,
  artifactHubView,
  artifactHubTurnId,
  events,
  artifacts,
  selectedArtifact,
  sourceSummary,
  thoughtSummary,
  onOpenArtifact,
  onOpenAtlasFocus,
  onClose,
}: SpotlightArtifactPanelProps) {
  if (!visible) {
    return null;
  }

  if (artifactHubView) {
    return (
      <ArtifactHubSidebar
        threadId={threadId}
        initialView={artifactHubView}
        initialTurnId={artifactHubTurnId}
        events={events}
        artifacts={artifacts}
        sourceSummary={sourceSummary}
        thoughtSummary={thoughtSummary}
        onOpenArtifact={onOpenArtifact}
        onOpenAtlasFocus={onOpenAtlasFocus}
        onClose={onClose}
      />
    );
  }

  if (selectedArtifact) {
    return <ArtifactSidebar artifact={selectedArtifact} onClose={onClose} />;
  }

  return null;
}
