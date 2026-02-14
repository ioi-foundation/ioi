interface FileArtifactViewProps {
  content: string;
}

export function FileArtifactView({ content }: FileArtifactViewProps) {
  return (
    <div className="artifact-view artifact-view-file">
      <pre>{content || "No file content available."}</pre>
    </div>
  );
}
