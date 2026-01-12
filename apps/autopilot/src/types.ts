export interface Node {
  id: string;
  type: string;
  name: string;
  x: number;
  y: number;
  status?: "idle" | "running" | "success" | "error";
  inputs?: string[];
  outputs?: string[];
  ioTypes?: { in: string; out: string };
  metrics?: { records: number; time: string };
  isGhost?: boolean;
  attested?: boolean;
}

export interface Edge {
  id: string;
  from: string;
  to: string;
  fromPort: string;
  toPort: string;
  type: "data" | "control";
  active?: boolean;
  volume?: number;
}

export type ExecutionMode = "local" | "session" | "settlement";
export type LiabilityMode = "none" | "optional" | "required";