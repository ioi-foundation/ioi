export const COMPUTER_USE_CONTRACT_SCHEMA_VERSION = "ioi.computer-use.harness.v1";

export function isComputerUseRunEventType(type) {
  return String(type ?? "").startsWith("computer_use_");
}

export function computerUseSourceEventKind(type) {
  switch (type) {
    case "computer_use_environment_selected":
      return "ComputerUse.EnvironmentSelected";
    case "computer_use_lease_acquired":
      return "ComputerUse.LeaseAcquired";
    case "computer_use_run_state":
      return "ComputerUse.RunState";
    case "computer_use_observation":
      return "ComputerUse.Observation";
    case "computer_use_affordance_graph":
      return "ComputerUse.AffordanceGraph";
    case "computer_use_browser_discovery":
      return "ComputerUse.BrowserDiscovery";
    case "computer_use_action_proposed":
      return "ComputerUse.ActionProposed";
    case "computer_use_action_executed":
      return "ComputerUse.ActionExecuted";
    case "computer_use_verification":
      return "ComputerUse.Verification";
    case "computer_use_commit_gate":
      return "ComputerUse.CommitGate";
    case "computer_use_trajectory_written":
      return "ComputerUse.TrajectoryWritten";
    case "computer_use_cleanup":
      return "ComputerUse.Cleanup";
    default:
      return "ComputerUse.Event";
  }
}
