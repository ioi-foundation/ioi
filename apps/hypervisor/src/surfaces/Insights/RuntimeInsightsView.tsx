import { HypervisorClientRuntime } from "../../services/HypervisorClientRuntime";
import { EnvironmentEstateView } from "../Environments/EnvironmentEstateView";

interface RuntimeInsightsViewProps {
  runtime: HypervisorClientRuntime;
}

export function RuntimeInsightsView({ runtime }: RuntimeInsightsViewProps) {
  return (
    <div className="hypervisor-surface-view">
      <header className="hypervisor-surface-header">
        <div className="hypervisor-surface-header-copy">
          <span className="hypervisor-surface-kicker">Execute And Supervise</span>
          <h2>Observe work in motion</h2>
          <p>
            Runs stays focused on live execution health, blocked work, and runtime outcomes without
            mixing in a separate context browser.
          </p>
        </div>
      </header>

      <div className="hypervisor-surface-stage">
        <div className="hypervisor-surface-stage-frame">
          <EnvironmentEstateView runtime={runtime} />
        </div>
      </div>
    </div>
  );
}
