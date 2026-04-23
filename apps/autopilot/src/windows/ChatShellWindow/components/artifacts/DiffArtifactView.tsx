interface DiffArtifactViewProps {
  content: string;
}

export function DiffArtifactView({ content }: DiffArtifactViewProps) {
  return (
    <div className="artifact-view artifact-view-diff">
      <pre>{content || "No diff content available."}</pre>
    </div>
  );
}
