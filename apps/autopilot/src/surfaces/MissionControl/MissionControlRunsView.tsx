import { FleetView } from "@ioi/agent-ide";
import { TauriRuntime } from "../../services/TauriRuntime";

interface MissionControlRunsViewProps {
  runtime: TauriRuntime;
}

export function MissionControlRunsView({ runtime }: MissionControlRunsViewProps) {
  return (
    <div className="mission-control-view">
      <header className="mission-control-header">
        <div className="mission-control-header-copy">
          <span className="mission-control-kicker">Execute And Supervise</span>
          <h2>Observe work in motion</h2>
          <p>
            Runs stays focused on live execution health, blocked work, and runtime outcomes without
            mixing in a separate context browser.
          </p>
        </div>
      </header>

      <div className="mission-control-stage">
        <div className="mission-control-stage-frame">
          <FleetView runtime={runtime} />
        </div>
      </div>
    </div>
  );
}
