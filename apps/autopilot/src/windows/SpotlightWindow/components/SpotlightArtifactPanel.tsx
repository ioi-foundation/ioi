import type {
  AgentEvent,
  Artifact,
  ArtifactHubViewKey,
  SourceSummary,
  ThoughtSummary,
} from "../../../types";
import { ArtifactHubSidebar } from "./ArtifactHubSidebar";
import { ArtifactSidebar } from "./ArtifactSidebar";

interface SpotlightArtifactPanelProps {
  visible: boolean;
  artifactHubView: ArtifactHubViewKey | null;
  artifactHubTurnId: string | null;
  events: AgentEvent[];
  artifacts: Artifact[];
  selectedArtifact: Artifact | null;
  sourceSummary: SourceSummary | null;
  thoughtSummary: ThoughtSummary | null;
  onOpenArtifact: (artifactId: string) => void;
  onClose: () => void;
}

export function SpotlightArtifactPanel({
  visible,
  artifactHubView,
  artifactHubTurnId,
  events,
  artifacts,
  selectedArtifact,
  sourceSummary,
  thoughtSummary,
  onOpenArtifact,
  onClose,
}: SpotlightArtifactPanelProps) {
  if (!visible) {
    return null;
  }

  if (selectedArtifact) {
    return <ArtifactSidebar artifact={selectedArtifact} onClose={onClose} />;
  }

  return (
    <ArtifactHubSidebar
      initialView={artifactHubView || undefined}
      initialTurnId={artifactHubTurnId}
      events={events}
      artifacts={artifacts}
      sourceSummary={sourceSummary}
      thoughtSummary={thoughtSummary}
      onOpenArtifact={onOpenArtifact}
      onClose={onClose}
    />
  );
}
