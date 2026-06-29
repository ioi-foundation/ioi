// Account + organization data — source-owned, native daemon boundary (/v1/hypervisor/auth/whoami).
import { daemon } from "./daemon";

export type Account = { name: string; email: string; role?: string; source?: string };
export type Org = { name: string; tier: string; current: boolean };

export async function fetchAccount(): Promise<Account | null> {
  const r = await daemon
    .get<{ principal?: { name?: string; email?: string; role?: string; source?: string } }>("/hypervisor/auth/whoami")
    .catch((): null => null);
  const p = r?.principal;
  if (!p) return null;
  return { name: p.name || "Operator", email: p.email || "", role: p.role, source: p.source };
}

// The workspace/org. A single local operator org today; modelled so multi-org slots in later.
export async function fetchOrgs(): Promise<Org[]> {
  return [{ name: "IOI Workspace", tier: "Core", current: true }];
}

export function initials(name: string): string {
  return (name || "?")
    .split(/\s+/)
    .map((w) => w[0])
    .filter(Boolean)
    .slice(0, 2)
    .join("")
    .toUpperCase();
}
