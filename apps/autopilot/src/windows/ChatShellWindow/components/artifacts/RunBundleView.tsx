interface RunBundleViewProps {
  content: string;
}

export function RunBundleView({ content }: RunBundleViewProps) {
  return (
    <div className="artifact-view artifact-view-run-bundle">
      <pre>{content || "No run bundle payload available."}</pre>
    </div>
  );
}
