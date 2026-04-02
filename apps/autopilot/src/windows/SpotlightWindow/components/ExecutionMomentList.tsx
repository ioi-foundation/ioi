import type { ExecutionMoment } from "../../../types";

type ExecutionMomentListProps = {
  moments: ExecutionMoment[];
};

function momentLabel(kind: ExecutionMoment["kind"]): string {
  switch (kind) {
    case "branch":
      return "Branch";
    case "approval":
      return "Approval";
    case "pause":
      return "Pause";
    case "verification":
      return "Verifier";
    default:
      return "Execution";
  }
}

export function ExecutionMomentList({
  moments,
}: ExecutionMomentListProps) {
  if (moments.length === 0) {
    return null;
  }

  return (
    <div className="spot-execution-moments" aria-label="Execution history moments">
      {moments.map((moment) => (
        <article
          className={`spot-execution-moment is-${moment.status}`}
          key={`${moment.key}-${moment.stepIndex}`}
        >
          <div className="spot-execution-moment-header">
            <span className="spot-execution-moment-kicker">
              {momentLabel(moment.kind)}
            </span>
            <span className="spot-execution-moment-step">step {moment.stepIndex}</span>
          </div>
          <strong>{moment.title}</strong>
          <p>{moment.summary}</p>
        </article>
      ))}
    </div>
  );
}
