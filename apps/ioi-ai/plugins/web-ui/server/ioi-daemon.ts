import type { IncomingMessage } from "node:http";
import {
  mintPortalDaemonExchangeAssertion,
  PORTAL_DAEMON_EXCHANGE_PATH,
  validatePortalDaemonExchangeConfig,
  type PortalDaemonExchangeConfig,
} from "./portal-daemon-exchange.ts";

export interface IoiDaemonResponse {
  status: number;
  text: string;
}

export interface IoiDaemonGateway {
  request(
    req: IncomingMessage,
    expectedPrincipal: string,
    method: string,
    path: string,
    body?: string,
  ): Promise<IoiDaemonResponse>;
}

export interface IoiDaemonGatewayOptions {
  timeoutMs?: number;
  allowLoopbackTrust?: boolean;
  allowInsecureRemoteHttp?: boolean;
  portalExchange?: PortalDaemonExchangeConfig;
  requirePortalExchange?: boolean;
}

interface CachedDaemonSession {
  token: string;
  expiresAtMs: number;
}

function isDaemonResponse(value: Record<string, string> | IoiDaemonResponse): value is IoiDaemonResponse {
  return typeof (value as IoiDaemonResponse).status === "number";
}

function loopback(hostname: string): boolean {
  return hostname === "localhost" || hostname === "127.0.0.1" || hostname === "::1" || hostname === "[::1]";
}

function cookieValue(raw: string | undefined, name: string): string | null {
  if (!raw) return null;
  for (const part of raw.split(";")) {
    const [key, ...value] = part.trim().split("=");
    if (key === name) return value.join("=") || null;
  }
  return null;
}

export function createIoiDaemonGateway(
  baseUrl: string,
  fetcher: typeof fetch = fetch,
  options: IoiDaemonGatewayOptions = {},
): IoiDaemonGateway {
  const base = new URL(baseUrl);
  if (base.protocol !== "http:" && base.protocol !== "https:") throw new Error("IOI daemon URL must use HTTP or HTTPS");
  if (base.protocol === "http:" && !loopback(base.hostname) && !options.allowInsecureRemoteHttp) {
    throw new Error("A non-loopback IOI daemon must use HTTPS");
  }
  const prefix = base.href.replace(/\/$/, "");
  const trustedLocal = options.allowLoopbackTrust === true && loopback(base.hostname);
  const timeoutMs = options.timeoutMs ?? 10_000;
  const exchange = options.portalExchange;
  if (exchange) validatePortalDaemonExchangeConfig(exchange);
  const daemonSessions = new Map<string, CachedDaemonSession>();

  function identityHeaders(req: IncomingMessage): Record<string, string> {
    const headers: Record<string, string> = { accept: "application/json" };
    const session = cookieValue(req.headers.cookie, "ioi_session");
    if (session) headers.cookie = `ioi_session=${session}`;
    const authorization = req.headers.authorization;
    if (authorization?.startsWith("Bearer ")) headers.authorization = authorization;
    if (!trustedLocal) headers["x-ioi-forwarded"] = "ioi-ai";
    return headers;
  }

  function refusal(status: number, code: string, message: string): IoiDaemonResponse {
    return { status, text: JSON.stringify({ error: { code, message } }) };
  }

  async function send(
    path: string,
    method: string,
    headers: Record<string, string>,
    body?: string,
  ): Promise<IoiDaemonResponse> {
    const response = await fetcher(`${prefix}${path}`, {
      method,
      headers,
      body,
      redirect: "manual",
      signal: AbortSignal.timeout(timeoutMs),
    });
    return { status: response.status, text: await response.text() };
  }

  function mismatch(): IoiDaemonResponse {
    return refusal(
      403,
      "ioi_daemon_principal_mismatch",
      "The authenticated IOI daemon principal does not match the signed-in ioi.ai principal and tenant.",
    );
  }

  function portalIdentity(req: IncomingMessage): string | null {
    const value = req.headers["x-portal-identity"];
    return (Array.isArray(value) ? value[0] : value)?.trim() || null;
  }

  function rememberSession(principal: string, session: CachedDaemonSession): void {
    if (daemonSessions.size >= 1_024 && !daemonSessions.has(principal)) {
      const oldest = daemonSessions.keys().next().value;
      if (oldest !== undefined) daemonSessions.delete(oldest);
    }
    daemonSessions.set(principal, session);
  }

  async function exchangeHeaders(
    req: IncomingMessage,
    expectedPrincipal: string,
    force = false,
  ): Promise<Record<string, string> | IoiDaemonResponse> {
    if (!exchange) {
      if (options.requirePortalExchange) {
        return refusal(
          503,
          "ioi_daemon_portal_exchange_not_configured",
          "Production ioi.ai daemon access requires an explicitly configured portal session exchange.",
        );
      }
      return identityHeaders(req);
    }
    if (force) daemonSessions.delete(expectedPrincipal);
    const cached = daemonSessions.get(expectedPrincipal);
    if (cached && cached.expiresAtMs - Date.now() > 15_000) {
      return {
        accept: "application/json",
        authorization: `Bearer ${cached.token}`,
        "x-ioi-forwarded": "ioi-ai",
      };
    }
    const sourceIdentity = portalIdentity(req);
    if (!sourceIdentity) {
      return refusal(
        401,
        "ioi_daemon_portal_identity_required",
        "A verified portal identity is required before ioi.ai can obtain a daemon session.",
      );
    }
    let assertion: string;
    try {
      assertion = mintPortalDaemonExchangeAssertion(exchange, expectedPrincipal, sourceIdentity).assertion;
    } catch {
      return refusal(
        401,
        "ioi_daemon_portal_identity_invalid",
        "The signed-in portal identity cannot be exchanged for a daemon session.",
      );
    }
    const exchanged = await send(
      PORTAL_DAEMON_EXCHANGE_PATH,
      "POST",
      {
        accept: "application/json",
        "content-type": "application/json",
        "x-ioi-forwarded": "ioi-ai-exchange",
      },
      JSON.stringify({ assertion }),
    );
    if (exchanged.status !== 200) return exchanged;
    let result: {
      session_token?: unknown;
      expires_at?: unknown;
      principal?: { principal_id?: unknown; tenant_refs?: unknown };
    };
    try {
      result = JSON.parse(exchanged.text) as typeof result;
    } catch {
      return refusal(502, "ioi_daemon_exchange_response_invalid", "The daemon returned an invalid exchange response.");
    }
    const expiresAtMs = typeof result.expires_at === "string" ? Date.parse(result.expires_at) : Number.NaN;
    const nowMs = Date.now();
    const tenantRefs = result.principal?.tenant_refs;
    if (
      typeof result.session_token !== "string" ||
      !result.session_token.startsWith("ioi_sess_") ||
      result.session_token.length > 512 ||
      !Number.isFinite(expiresAtMs) ||
      expiresAtMs <= nowMs ||
      expiresAtMs > nowMs + 5 * 60_000 + 5_000 ||
      result.principal?.principal_id !== expectedPrincipal ||
      !Array.isArray(tenantRefs) ||
      !tenantRefs.includes(exchange.tenantRef)
    ) {
      return mismatch();
    }
    rememberSession(expectedPrincipal, { token: result.session_token, expiresAtMs });
    return {
      accept: "application/json",
      authorization: `Bearer ${result.session_token}`,
      "x-ioi-forwarded": "ioi-ai",
    };
  }

  return {
    async request(req, expectedPrincipal, method, path, body) {
      if (!expectedPrincipal) return mismatch();
      let resolved = await exchangeHeaders(req, expectedPrincipal);
      if (isDaemonResponse(resolved)) return resolved;
      let headers = resolved;
      let whoami = await send("/v1/hypervisor/auth/whoami", "GET", headers);
      if (exchange && whoami.status === 401) {
        resolved = await exchangeHeaders(req, expectedPrincipal, true);
        if (isDaemonResponse(resolved)) return resolved;
        headers = resolved;
        whoami = await send("/v1/hypervisor/auth/whoami", "GET", headers);
      }
      if (whoami.status !== 200) return whoami;
      let identity: unknown;
      try {
        identity = JSON.parse(whoami.text);
      } catch {
        return mismatch();
      }
      const response = identity as {
        authenticated?: unknown;
        principal?: { principal_id?: unknown; tenant_refs?: unknown };
      };
      if (
        ((exchange || !trustedLocal) && response.authenticated !== true) ||
        response.principal?.principal_id !== expectedPrincipal ||
        (exchange &&
          (!Array.isArray(response.principal?.tenant_refs) ||
            !response.principal.tenant_refs.includes(exchange.tenantRef)))
      ) {
        if (exchange) daemonSessions.delete(expectedPrincipal);
        return mismatch();
      }
      if (body !== undefined) headers["content-type"] = "application/json";
      const result = await send(path, method, headers, body);
      if (exchange && method === "POST" && path === "/v1/hypervisor/auth/logout") {
        daemonSessions.delete(expectedPrincipal);
      }
      return result;
    },
  };
}

export function boundedIoiId(value: string, prefix: string): string | null {
  let decoded: string;
  try {
    decoded = decodeURIComponent(value);
  } catch {
    return null;
  }
  if (!decoded.startsWith(prefix) || decoded.length > 160 || !/^[A-Za-z0-9_-]+$/.test(decoded)) return null;
  return decoded;
}
