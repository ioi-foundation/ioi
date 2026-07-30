import type { ReactNode } from "react";
import type { SurfaceState } from "../data/productSurface";

const COPY: Record<SurfaceState, string> = {
  loading: "Loading current owner records…",
  empty: "No policy-visible records match this context.",
  missing_prerequisite: "A required owner record or runtime binding is missing.",
  degraded: "Current data is incomplete. Available owner records remain inspectable.",
  blocked: "A runtime prerequisite is blocked.",
  approval_pending: "A governed mutation is waiting for approval.",
  denied: "Policy denied this operation for the current principal and organization.",
  failed: "The operation failed before a durable result was admitted.",
  recovery: "A durable recovery or reconciliation obligation remains open.",
  completed: "The governed operation completed with a durable receipt.",
};

export function SurfaceStateFrame({ state, detail, children }: { state: SurfaceState; detail?: string; children?: ReactNode }) {
  return <section className={`hv-state hv-state--${state}`} data-surface-state={state} role={state === "failed" || state === "denied" ? "alert" : "status"}>
    <strong>{state.replace(/_/g, " ")}</strong>
    <span>{detail ?? COPY[state]}</span>
    {children}
  </section>;
}
