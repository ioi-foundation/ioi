interface WebArtifactViewProps {
  content: string;
}

export function WebArtifactView({ content }: WebArtifactViewProps) {
  return (
    <div className="artifact-view artifact-view-web">
      <pre>{content || "No captured web content available."}</pre>
    </div>
  );
}
