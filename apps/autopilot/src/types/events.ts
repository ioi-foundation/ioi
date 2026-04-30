import type { AgentEvent as GeneratedAgentEvent } from "../generated/autopilot-contracts";
import type { JsonRecord } from "./base";
import type { EventType } from "./generated";

export type AgentEvent = Omit<
  GeneratedAgentEvent,
  "event_type" | "digest" | "details"
> & {
  event_type: EventType;
  digest: JsonRecord;
  details: JsonRecord;
};
