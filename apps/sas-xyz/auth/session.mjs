import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

export class SessionError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}

const encoded = (value) => Buffer.from(value).toString('base64url');
const decoded = (value) => Buffer.from(value, 'base64url').toString('utf8');
const sign = (secret, value) => createHmac('sha256', secret).update(value).digest('base64url');
const safeEqual = (left, right) => {
  const leftBytes = Buffer.from(left); const rightBytes = Buffer.from(right);
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
};
const cookies = (request) => Object.fromEntries(String(request.headers.cookie || '').split(';').map((part) => part.trim()).filter(Boolean).map((part) => {
  const separator = part.indexOf('='); return separator === -1 ? [part, ''] : [part.slice(0, separator), part.slice(separator + 1)];
}));
const validPrincipal = (value) => typeof value === 'string' && /^(principal|wallet|org):\/\/[A-Za-z0-9._~:/-]+$/.test(value);
const validTenant = (value) => typeof value === 'string' && /^(tenant|org):\/\/[A-Za-z0-9._~:/-]+$/.test(value);

export const isLoopbackHost = (host) => ['127.0.0.1', '::1', 'localhost'].includes(String(host || '').replace(/^\[|\]$/g, '').toLowerCase());

export function createSessionAuthority({ secret, issuer = 'sas.xyz', developmentAuthority = false, cookieName, ttlSeconds = 3600 } = {}) {
  if (typeof secret !== 'string' || secret.length < 32) throw new Error('IOI session signing secret must contain at least 32 characters');
  const name = cookieName || (developmentAuthority ? 'ioi_sas_dev_session' : '__Host-ioi_sas_session');
  const issueSession = ({ principalRef, tenantRef, lifetimeSeconds = ttlSeconds } = {}) => {
    if (!validPrincipal(principalRef) || !validTenant(tenantRef)) throw new SessionError(422, 'invalid_session_subject', 'Session principal and tenant refs are invalid');
    const issuedAt = Math.floor(Date.now() / 1000);
    const payload = { schema_version: 'ioi.product-session.v1', issuer, principal_ref: principalRef, tenant_ref: tenantRef, csrf_token: randomBytes(24).toString('base64url'), session_id: randomBytes(18).toString('base64url'), issued_at: issuedAt, expires_at: issuedAt + lifetimeSeconds };
    const body = encoded(JSON.stringify(payload)); const token = `${body}.${sign(secret, body)}`;
    const attributes = [`${name}=${token}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${lifetimeSeconds}`];
    if (!developmentAuthority) attributes.push('Secure');
    return { payload, cookie: attributes.join('; ') };
  };
  const authenticate = (request) => {
    if (request.headers['x-ioi-principal'] || request.headers['x-ioi-tenant']) throw new SessionError(400, 'browser_authority_headers_forbidden', 'Browser requests cannot supply principal or tenant authority headers');
    const token = cookies(request)[name]; if (!token) throw new SessionError(401, 'session_required', 'An authenticated product session is required');
    const [body, signature, extra] = token.split('.');
    if (!body || !signature || extra || !safeEqual(sign(secret, body), signature)) throw new SessionError(401, 'invalid_session', 'Product session signature is invalid');
    let payload; try { payload = JSON.parse(decoded(body)); } catch { throw new SessionError(401, 'invalid_session', 'Product session payload is invalid'); }
    const now = Math.floor(Date.now() / 1000);
    if (payload.schema_version !== 'ioi.product-session.v1' || payload.issuer !== issuer || !validPrincipal(payload.principal_ref) || !validTenant(payload.tenant_ref) || !payload.csrf_token || !Number.isSafeInteger(payload.expires_at) || payload.expires_at <= now) throw new SessionError(401, 'invalid_session', 'Product session is expired or malformed');
    return payload;
  };
  const assertMutation = (request, payload, publicOrigin) => {
    const origin = request.headers.origin; const expectedOrigin = publicOrigin || `${request.socket.encrypted ? 'https' : 'http'}://${request.headers.host}`;
    if (!origin || origin !== expectedOrigin || (request.headers['sec-fetch-site'] && request.headers['sec-fetch-site'] !== 'same-origin')) throw new SessionError(403, 'cross_origin_mutation_forbidden', 'Mutation origin does not match the product origin');
    const csrf = request.headers['x-ioi-csrf']; if (typeof csrf !== 'string' || !safeEqual(csrf, payload.csrf_token)) throw new SessionError(403, 'csrf_invalid', 'CSRF token is missing or invalid');
  };
  return {
    cookieName: name, issueSession, authenticate, assertMutation,
    developmentSession: () => {
      if (!developmentAuthority) throw new SessionError(401, 'session_required', 'An authenticated product session is required');
      return issueSession({ principalRef: 'principal://development/operator', tenantRef: 'tenant://development/local' });
    },
  };
}
