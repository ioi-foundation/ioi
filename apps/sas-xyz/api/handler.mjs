import { DomainError } from '../domain/service.mjs';
import { OwnerDependencyError } from '../domain/adapters.mjs';
import { SessionError } from '../auth/session.mjs';

const send = (response, status, payload, extraHeaders = {}) => {
  response.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extraHeaders });
  response.end(`${JSON.stringify(payload)}\n`);
};

const bodyOf = async (request) => {
  let source = '';
  for await (const chunk of request) { source += chunk; if (source.length > 1_000_000) throw new DomainError(413, 'body_too_large', 'Request body exceeds one megabyte'); }
  if (!source) return {};
  try { return JSON.parse(source); } catch { throw new DomainError(400, 'invalid_json', 'Request body must be valid JSON'); }
};

const match = (pathname, pattern) => {
  const keys = [];
  const expression = pattern.replace(/:[A-Za-z_]+/g, (token) => { keys.push(token.slice(1)); return '([^/]+)'; });
  const found = pathname.match(new RegExp(`^${expression}/?$`));
  return found ? Object.fromEntries(keys.map((key, index) => [key, decodeURIComponent(found[index + 1])])) : null;
};

const contextOf = (request, session) => ({ principalRef: session.principal_ref, tenantRef: session.tenant_ref, sessionId: session.session_id, idempotencyKey: request.headers['idempotency-key'] });

export function createApiHandler(service, { developmentAuthority = false, sessionAuthority, publicOrigin } = {}) {
  if (!sessionAuthority) throw new Error('sessionAuthority is required');
  return async (request, response) => {
    if (!request.url?.startsWith('/v1/')) return false;
    const url = new URL(request.url, 'http://localhost'); const pathname = url.pathname;
    try {
      if (request.method === 'GET' && pathname === '/v1/session') {
        let session; let cookie;
        try { session = sessionAuthority.authenticate(request); }
        catch (error) {
          if (!(error instanceof SessionError) || error.code !== 'session_required' || !developmentAuthority) throw error;
          const issued = sessionAuthority.developmentSession(); session = issued.payload; cookie = issued.cookie;
        }
        return send(response, 200, { authenticated: true, principal_ref: session.principal_ref, tenant_ref: session.tenant_ref, csrf_token: session.csrf_token, expires_at: session.expires_at, authority_mode: developmentAuthority ? 'development' : 'network' }, cookie ? { 'set-cookie': cookie } : {}), true;
      }
      const session = sessionAuthority.authenticate(request);
      if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method)) sessionAuthority.assertMutation(request, session, publicOrigin);
      const context = contextOf(request, session); const body = ['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method) ? await bodyOf(request) : {};
      let params;
      if (request.method === 'GET' && pathname === '/v1/status') return send(response, 200, await service.status()), true;
      if (request.method === 'GET' && pathname === '/v1/services') return send(response, 200, { items: await service.listServices() }), true;
      if (request.method === 'POST' && pathname === '/v1/provider/services') return send(response, 201, await service.createService(body, context)), true;
      if ((params = match(pathname, '/v1/services/:serviceId')) && request.method === 'GET') return send(response, 200, await service.getService(params.serviceId)), true;

      if (request.method === 'POST' && pathname === '/v1/orders') return send(response, 201, await service.createOrder(body, context)), true;
      if (request.method === 'GET' && pathname === '/v1/orders') return send(response, 200, { items: await service.listOrders(context) }), true;
      if ((params = match(pathname, '/v1/orders/:orderId')) && request.method === 'GET') return send(response, 200, await service.getOrder(params.orderId, context)), true;
      if ((params = match(pathname, '/v1/provider/orders/:orderId/claim')) && request.method === 'POST') return send(response, 200, await service.claimOrder(params.orderId, body, context)), true;
      if ((params = match(pathname, '/v1/provider/orders/:orderId/submit-delivery')) && request.method === 'POST') return send(response, 201, await service.submitDelivery(params.orderId, body, context)), true;

      if ((params = match(pathname, '/v1/deliveries/:deliveryId/accept')) && request.method === 'POST') return send(response, 200, await service.acceptDelivery(params.deliveryId, body, context)), true;
      if ((params = match(pathname, '/v1/deliveries/:deliveryId/request-revision')) && request.method === 'POST') return send(response, 200, await service.requestRevision(params.deliveryId, body, context)), true;
      if ((params = match(pathname, '/v1/deliveries/:deliveryId/open-dispute')) && request.method === 'POST') return send(response, 201, await service.openDispute(params.deliveryId, body, context)), true;

      if ((params = match(pathname, '/v1/disputes/:disputeId/submit-evidence')) && request.method === 'POST') return send(response, 201, await service.addDisputeEvidence(params.disputeId, body, context)), true;
      if ((params = match(pathname, '/v1/disputes/:disputeId/resolve')) && request.method === 'POST') return send(response, 200, await service.resolveDispute(params.disputeId, body, context)), true;

      if ((params = match(pathname, '/v1/orders/:orderId/provider-substitutions')) && request.method === 'POST') return send(response, 201, await service.proposeSubstitution(params.orderId, body, context)), true;
      if ((params = match(pathname, '/v1/orders/:orderId/provider-substitutions/:proposalId/:decision')) && request.method === 'POST' && ['accept', 'reject'].includes(params.decision)) return send(response, 200, await service.decideSubstitution(params.orderId, params.proposalId, params.decision, body, context)), true;
      if ((params = match(pathname, '/v1/orders/:orderId/provider-substitutions/:proposalId/apply')) && request.method === 'POST') return send(response, 200, await service.applySubstitution(params.orderId, params.proposalId, body, context)), true;

      if ((params = match(pathname, '/v1/artifact-licenses/:licenseRef')) && request.method === 'GET') return send(response, 200, await service.getLicense(params.licenseRef, context)), true;
      if ((params = match(pathname, '/v1/production-entitlements/:entitlementRef')) && request.method === 'GET') return send(response, 200, await service.getEntitlement(params.entitlementRef, context)), true;
      if ((params = match(pathname, '/v1/production-entitlements/:entitlementRef/reservations')) && request.method === 'POST') return send(response, 201, await service.reserveProduction(params.entitlementRef, body, context)), true;
      if ((params = match(pathname, '/v1/production-entitlements/:entitlementRef/usage-receipts')) && request.method === 'POST') return send(response, 201, await service.consumeProduction(params.entitlementRef, body, context)), true;
      if ((params = match(pathname, '/v1/artifacts/:artifactRef/download-authorizations')) && request.method === 'POST') return send(response, 201, await service.authorizeDownload(params.artifactRef, body, context)), true;

      if (request.method === 'GET' && pathname === '/v1/receipts') return send(response, 200, { items: await service.receipts(context, url.searchParams.get('object_ref')) }), true;
      return send(response, 404, { error: { code: 'route_not_found', message: `No ${request.method} route for ${pathname}` } }), true;
    } catch (error) {
      const status = error instanceof DomainError || error instanceof OwnerDependencyError || error instanceof SessionError ? error.status : 500;
      if (status === 500) console.error(error);
      send(response, status, { error: { code: error.code || (error instanceof OwnerDependencyError ? 'owner_unavailable' : 'internal_error'), message: status === 500 ? 'Internal server error' : error.message, owner: error.owner, details: error.details } });
      return true;
    }
  };
}
