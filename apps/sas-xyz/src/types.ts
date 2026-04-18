export enum RuntimePosture {
  LOCAL_FIRST = "Local-first",
  APPROVAL_GATED = "Approval-gated",
  AUTONOMOUS = "Autonomous",
  ISOLATED = "Isolated"
}

export enum PricingModel {
  SUBSCRIPTION = "Subscription",
  PER_OUTCOME = "Per Outcome",
  USAGE_BASED = "Usage-based",
  FLAT_FEE = "Flat Fee"
}

export interface Service {
  id: string;
  name: string;
  provider: string;
  description: string;
  outcome: string;
  connects: string[];
  execution: RuntimePosture;
  evidence: string;
  settlement: string;
  policy: string;
  recourse: string;
  pricing: PricingModel;
  privacy: string;
  status: 'available' | 'provisioned' | 'monitoring';
  tags: string[];
}
