import { createHash, createHmac, randomBytes } from "node:crypto";

export const PORTAL_DAEMON_EXCHANGE_TYPE = "ioi-portal-daemon-exchange+jwt";
export const PORTAL_DAEMON_EXCHANGE_PATH = "/v1/hypervisor/auth/portal-session-exchange";

export interface PortalDaemonExchangeConfig {
  secret: string;
  issuer: string;
  audience: string;
  tenantRef: string;
  assertionTtlSeconds?: number;
}

export interface PortalDaemonExchangeClaims {
  iss: string;
  aud: string;
  sub: string;
  tenant_ref: string;
  source_identity_hash: string;
  iat: number;
  nbf: number;
  exp: number;
  jti: string;
}

function base64url(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function bounded(value: string, maximum: number): boolean {
  return Boolean(value) && value.length <= maximum && !/[\u0000-\u001f\u007f]/u.test(value);
}

export function validatePortalDaemonExchangeConfig(config: PortalDaemonExchangeConfig): void {
  if (Buffer.byteLength(config.secret, "utf8") < 32) {
    throw new Error("IOI portal-daemon exchange secret must be at least 32 bytes");
  }
  if (!bounded(config.issuer, 300) || !bounded(config.audience, 300)) {
    throw new Error("IOI portal-daemon exchange issuer and audience must be explicit bounded values");
  }
  if (!/^(?:org|project):\/\/[^\s?#\\]{1,480}$/u.test(config.tenantRef)) {
    throw new Error("IOI portal-daemon exchange tenant must be one canonical org:// or project:// ref");
  }
  const ttl = config.assertionTtlSeconds ?? 30;
  if (!Number.isSafeInteger(ttl) || ttl < 10 || ttl > 60) {
    throw new Error("IOI portal-daemon exchange assertions must live for 10..60 seconds");
  }
}

export function portalIdentityHash(token: string): string {
  return `sha256:${createHash("sha256").update(token, "utf8").digest("hex")}`;
}

export function mintPortalDaemonExchangeAssertion(
  config: PortalDaemonExchangeConfig,
  principalId: string,
  sourceIdentityToken: string,
  options: { nowMs?: number; nonce?: string } = {},
): { assertion: string; claims: PortalDaemonExchangeClaims } {
  validatePortalDaemonExchangeConfig(config);
  if (!bounded(principalId, 480) || /[\s/?#\\]/u.test(principalId)) {
    throw new Error("portal principal cannot be represented as one deployment-local daemon principal");
  }
  if (!sourceIdentityToken) throw new Error("a verified portal identity is required for daemon exchange");
  const now = Math.floor((options.nowMs ?? Date.now()) / 1_000);
  const ttl = config.assertionTtlSeconds ?? 30;
  const nonce = options.nonce ?? randomBytes(24).toString("base64url");
  if (!/^[A-Za-z0-9_-]{32,128}$/u.test(nonce)) throw new Error("exchange nonce is not canonical");
  const claims: PortalDaemonExchangeClaims = {
    iss: config.issuer,
    aud: config.audience,
    sub: principalId,
    tenant_ref: config.tenantRef,
    source_identity_hash: portalIdentityHash(sourceIdentityToken),
    iat: now,
    nbf: now,
    exp: now + ttl,
    jti: nonce,
  };
  const encodedHeader = base64url(JSON.stringify({ alg: "HS256", typ: PORTAL_DAEMON_EXCHANGE_TYPE }));
  const encodedClaims = base64url(JSON.stringify(claims));
  const signingInput = `${encodedHeader}.${encodedClaims}`;
  const signature = createHmac("sha256", config.secret).update(signingInput, "utf8").digest("base64url");
  return { assertion: `${signingInput}.${signature}`, claims };
}

export function portalDaemonExchangeConfigFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): PortalDaemonExchangeConfig | undefined {
  const secret = env.IOI_PORTAL_DAEMON_EXCHANGE_SECRET?.trim() ?? "";
  const issuer = env.IOI_PORTAL_DAEMON_EXCHANGE_ISSUER?.trim() ?? "";
  const audience = env.IOI_PORTAL_DAEMON_EXCHANGE_AUDIENCE?.trim() ?? "";
  const tenantRef = env.IOI_PORTAL_DAEMON_EXCHANGE_TENANT_REF?.trim() ?? "";
  if (![secret, issuer, audience, tenantRef].some(Boolean)) return undefined;
  const config = { secret, issuer, audience, tenantRef };
  validatePortalDaemonExchangeConfig(config);
  return config;
}
