// Standalone view-id union for the reference-parity shell (formerly re-exported from
// the removed legacy windows/HypervisorShellWindow/hypervisorShellModel). The parity UX
// owns this independently — it has no dependency on the legacy shell.
export type PrimaryView =
  | "home"
  | "sessions"
  | "projects"
  | "applications"
  | "missions"
  | "workbench"
  | "automations"
  | "insights"
  | "agents"
  | "models"
  | "privacy"
  | "providers"
  | "environments"
  | "foundry"
  | "authority"
  | "receipts"
  | "settings";
