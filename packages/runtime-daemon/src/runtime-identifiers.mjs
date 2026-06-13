import { isRuntimeServiceProfile } from "./runtime-api-bridge.mjs";
import { DAEMON_FIXTURE_PROFILE } from "./runtime-contract-constants.mjs";

export function threadIdForAgent(agentId) {
  return agentId.startsWith("agent_") ? `thread_${agentId.slice("agent_".length)}` : `thread_${agentId}`;
}

export function agentIdForThread(threadId) {
  return threadId.startsWith("thread_") ? `agent_${threadId.slice("thread_".length)}` : threadId;
}

export function runtimeSessionIdForAgent(agent = {}) {
  return agent.runtimeSessionId ?? agent.id;
}

export function isRuntimeBackedAgent(agent = {}) {
  return isRuntimeServiceProfile(agent.runtimeProfile ?? agent.runtime_profile);
}

export function fixtureProfileForAgent(agent = {}) {
  return Object.hasOwn(agent, "fixtureProfile") ? agent.fixtureProfile : DAEMON_FIXTURE_PROFILE;
}

export function turnIdForRun(runId) {
  return runId.startsWith("run_") ? `turn_${runId.slice("run_".length)}` : `turn_${runId}`;
}

export function runtimeTurnIdForRun(run = {}) {
  const turnId = optionalString(run.runtimeTurnId ?? run.runtime_turn_id);
  return turnId ?? turnIdForRun(run.id);
}

export function runIdForTurn(turnId) {
  return turnId.startsWith("turn_") ? `run_${turnId.slice("turn_".length)}` : `run_${turnId}`;
}

export function eventStreamIdForThread(threadId) {
  return `${threadId}:events`;
}

export function threadStatusForAgent(status) {
  switch (status) {
    case "archived":
    case "closed":
      return "archived";
    case "failed":
    case "error":
      return "failed";
    default:
      return "active";
  }
}

export function lifecycleStatusForRun(status) {
  switch (status) {
    case "queued":
      return "queued";
    case "running":
      return "running";
    case "canceled":
      return "canceled";
    case "failed":
    case "error":
      return "failed";
    case "blocked":
      return "waiting_for_input";
    case "completed":
    default:
      return "completed";
  }
}

function optionalString(value) {
  if (value === undefined || value === null) return undefined;
  const text = String(value).trim();
  return text ? text : undefined;
}
