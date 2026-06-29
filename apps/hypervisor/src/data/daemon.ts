// Typed Hypervisor daemon client — the IOI-native data boundary for source-owned surfaces.
//
// Source-owned React surfaces call the daemon's own /v1/hypervisor/* REST contracts directly
// (proxied to the hypervisor-daemon by vite.config). No gitpod.v1 wire, no namespace bridge —
// this is the "protocol-native" layer (cut 3): a surface that uses this never speaks the
// upstream namespace, so the request-entry bridge does not exist for it.

export class DaemonError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.name = "DaemonError";
    this.status = status;
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(`/v1/hypervisor${path}`, {
    method,
    headers: body !== undefined ? { "content-type": "application/json" } : undefined,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json: unknown = undefined;
  try {
    json = text ? JSON.parse(text) : undefined;
  } catch {
    /* non-JSON body */
  }
  if (!res.ok) {
    const msg = (json as { error?: string })?.error || text || `HTTP ${res.status}`;
    throw new DaemonError(res.status, msg);
  }
  return json as T;
}

export const daemon = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown) => request<T>("POST", path, body),
  del: <T>(path: string) => request<T>("DELETE", path),
};
