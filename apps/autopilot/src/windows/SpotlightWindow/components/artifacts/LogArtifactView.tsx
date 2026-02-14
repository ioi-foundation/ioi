interface LogArtifactViewProps {
  content: string;
}

export function LogArtifactView({ content }: LogArtifactViewProps) {
  return (
    <div className="artifact-view artifact-view-log">
      <pre>{content || "No log output available."}</pre>
    </div>
  );
}
