// M05.8 — the SDK thin client for PolicyBoundDataView.
//
// A PASS-THROUGH, NOT A CHECKER. `PolicyBoundDataViewClient` serializes a body, adds the caller's own
// bearer token, hits ONE of the two native owner routes, and returns the daemon's JSON verbatim.
// Every admission and materialization decision is made in the daemon's owner route; this file
// resolves no policy, reinterprets no refusal code, and grants no authority. It carries a TOKEN, not
// a principal, so it cannot name a tenant or author a server-resolved field — the daemon refuses
// those regardless of which client sent them.
//
// WHY IT DOES NOT REUSE `DaemonRuntimeSubstrateClient`: that client maps a daemon error through
// `normalizeDaemonErrorCode`, collapsing a typed refusal (for example a cross-tenant-source refusal)
// into a small enum. This client's whole reason to exist is to surface the refusal `code` LOSSLESSLY,
// so it throws `PolicyBoundDataViewRefusal` carrying the daemon body unchanged. It reuses the same
// transport conventions — endpoint from options or `IOI_DAEMON_ENDPOINT`, api key from options or
// `IOI_DAEMON_TOKEN`, `Bearer` auth, `accept: application/json` — so there is one wire contract, not
// two. It names no refusal code of its own, because a client that hardcodes one has started to
// decide.

export interface PolicyBoundDataViewClientOptions {
  /** Daemon endpoint. Defaults to `IOI_DAEMON_ENDPOINT`. */
  endpoint?: string;
  /** A session token or a `pat_*` API token. Defaults to `IOI_DAEMON_TOKEN`. The token IS the
   *  principal binding; this client never names a principal or tenant itself. */
  apiKey?: string;
  /** Extra headers, merged under the SDK defaults. A caller cannot override `authorization` here to
   *  smuggle a second credential: it is set last, from `apiKey`. */
  headers?: Record<string, string>;
}

export interface PolicyBoundDataViewQueryInput {
  /** A family token; omit to list the caller's authorized inventory. */
  family?: string;
  /** An exact revision ordinal within `family`. */
  revision?: number;
}

/** A non-2xx daemon response, carrying the typed refusal body UNCHANGED. `refusalCode` is the exact
 *  code the owner route wrote — never a normalized SDK enum. */
export class PolicyBoundDataViewRefusal extends Error {
  readonly status: number;
  readonly body: unknown;
  readonly refusalCode: string | undefined;

  constructor(status: number, body: unknown) {
    const code =
      body && typeof body === "object" && "error" in body && (body as Record<string, unknown>).error &&
      typeof (body as Record<string, { code?: unknown }>).error === "object"
        ? ((body as Record<string, { code?: unknown }>).error.code as string | undefined)
        : body && typeof body === "object" && typeof (body as Record<string, unknown>).code === "string"
          ? ((body as Record<string, string>).code)
          : undefined;
    super(`policy-bound-data-view daemon request refused (${status})${code ? `: ${code}` : ""}`);
    this.name = "PolicyBoundDataViewRefusal";
    this.status = status;
    this.body = body;
    this.refusalCode = code;
  }
}

const VIEWS = "/v1/hypervisor/policy-bound-data-views";
const MATERIALIZATIONS = "/v1/hypervisor/policy-bound-data-view-materializations";

export class PolicyBoundDataViewClient {
  private readonly endpoint?: string;
  private readonly apiKey?: string;
  private readonly headers: Record<string, string>;

  constructor(options: PolicyBoundDataViewClientOptions = {}) {
    this.endpoint = options.endpoint ?? process.env.IOI_DAEMON_ENDPOINT;
    this.apiKey = options.apiKey ?? process.env.IOI_DAEMON_TOKEN;
    this.headers = options.headers ?? {};
  }

  /** Admit one immutable view revision. Returns the daemon's admitted record verbatim, or throws
   *  `PolicyBoundDataViewRefusal` carrying the typed refusal. The body IS the admission request the
   *  native route expects; every binding is resolved server-side through its owner seam. */
  async admit(body: unknown): Promise<unknown> {
    return this.request("POST", VIEWS, body);
  }

  /** Read the caller's own view inventory, one family, or one exact revision. */
  async query(input: PolicyBoundDataViewQueryInput = {}): Promise<unknown> {
    const params = new URLSearchParams();
    if (input.family !== undefined) params.set("family", input.family);
    if (input.revision !== undefined) params.set("revision", String(input.revision));
    const suffix = params.toString();
    return this.request("GET", suffix ? `${VIEWS}?${suffix}` : VIEWS);
  }

  /** Ask for a bounded projection. THE DAEMON decides whether a descriptor is granted; a refused
   *  decision is still admitted to the chain as evidence and returned here unchanged. */
  async materialize(body: unknown): Promise<unknown> {
    return this.request("POST", MATERIALIZATIONS, body);
  }

  private requireEndpoint(): string {
    const endpoint = this.endpoint;
    if (!endpoint) {
      throw new Error(
        "policy-bound-data-view: no daemon endpoint configured (pass `endpoint` or set IOI_DAEMON_ENDPOINT).",
      );
    }
    return endpoint;
  }

  private async request(method: "GET" | "POST", route: string, body?: unknown): Promise<unknown> {
    const url = new URL(route.replace(/^\/+/, ""), this.requireEndpoint());
    const headers: Record<string, string> = {
      accept: "application/json",
      ...this.headers,
    };
    if (body !== undefined) {
      headers["content-type"] = "application/json";
    }
    // Set LAST, so a caller-supplied `headers.authorization` cannot smuggle a second credential.
    if (this.apiKey) {
      headers.authorization = `Bearer ${this.apiKey}`;
    }

    const response = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await response.text();
    let parsed: unknown;
    try {
      parsed = text.length ? JSON.parse(text) : null;
    } catch {
      // The daemon returned non-JSON; surface the raw bytes rather than swallow them.
      parsed = text;
    }
    if (!response.ok) {
      throw new PolicyBoundDataViewRefusal(response.status, parsed);
    }
    return parsed;
  }
}

/** Convenience constructor mirroring `createRuntimeSubstrateClient`. */
export function createPolicyBoundDataViewClient(
  options: PolicyBoundDataViewClientOptions = {},
): PolicyBoundDataViewClient {
  return new PolicyBoundDataViewClient(options);
}
