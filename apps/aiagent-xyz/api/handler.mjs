import { DomainError } from '../domain/service.mjs';
import { OwnerDependencyError } from '../domain/adapters.mjs';
import { SessionError } from '../auth/session.mjs';

const json = (response, status, payload, extraHeaders = {}) => {
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    ...extraHeaders,
  });
  response.end(`${JSON.stringify(payload)}\n`);
};

const readBody = async (request) => {
  let body = '';
  for await (const chunk of request) {
    body += chunk;
    if (body.length > 1_000_000) throw new DomainError(413, 'body_too_large', 'Request body exceeds one megabyte');
  }
  if (!body) return {};
  try { return JSON.parse(body); } catch { throw new DomainError(400, 'invalid_json', 'Request body must be valid JSON'); }
};

const match = (pathname, pattern) => {
  const names = [];
  const expression = pattern.replace(/:[A-Za-z_]+/g, (token) => {
    names.push(token.slice(1));
    return '([^/]+)';
  });
  const result = pathname.match(new RegExp(`^${expression}/?$`));
  if (!result) return null;
  return Object.fromEntries(names.map((name, index) => [name, decodeURIComponent(result[index + 1])]));
};

const contextFor = (request, session) => ({
  principalRef: session.principal_ref,
  tenantRef: session.tenant_ref,
  sessionId: session.session_id,
  idempotencyKey: request.headers['idempotency-key'],
});

export function createApiHandler(service, { developmentAuthority = false, sessionAuthority, publicOrigin } = {}) {
  if (!sessionAuthority) throw new Error('sessionAuthority is required');
  return async function apiHandler(request, response) {
    if (!request.url?.startsWith('/v1/')) return false;
    const url = new URL(request.url, 'http://localhost');
    const { pathname } = url;
    try {
      if (request.method === 'GET' && pathname === '/v1/session') {
        let session;
        let cookie;
        try { session = sessionAuthority.authenticate(request); }
        catch (error) {
          if (!(error instanceof SessionError) || error.code !== 'session_required' || !developmentAuthority) throw error;
          const issued = sessionAuthority.developmentSession();
          session = issued.payload;
          cookie = issued.cookie;
        }
        return json(response, 200, {
          authenticated: true,
          principal_ref: session.principal_ref,
          tenant_ref: session.tenant_ref,
          csrf_token: session.csrf_token,
          expires_at: session.expires_at,
          authority_mode: developmentAuthority ? 'development' : 'network',
        }, cookie ? { 'set-cookie': cookie } : {}), true;
      }
      const session = sessionAuthority.authenticate(request);
      if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method)) sessionAuthority.assertMutation(request, session, publicOrigin);
      const context = contextFor(request, session);
      const body = ['POST', 'PATCH', 'PUT', 'DELETE'].includes(request.method) ? await readBody(request) : {};
      let params;

      if (request.method === 'GET' && pathname === '/v1/status') return json(response, 200, await service.status()), true;
      if (request.method === 'GET' && pathname === '/v1/worker-templates') return json(response, 200, { items: await service.templates() }), true;
      if (request.method === 'GET' && pathname === '/v1/worker-package-drafts') return json(response, 200, { items: await service.listDrafts(context) }), true;
      if (request.method === 'GET' && pathname === '/v1/creator/supply') return json(response, 200, await service.creatorState(context)), true;
      if (request.method === 'POST' && pathname === '/v1/worker-package-drafts') return json(response, 201, await service.createDraft(body, context)), true;
      if ((params = match(pathname, '/v1/worker-package-drafts/:draftRef'))) {
        if (request.method === 'PATCH') return json(response, 200, await service.updateDraft(params.draftRef, body, context)), true;
      }
      if ((params = match(pathname, '/v1/worker-package-drafts/:draftRef/validate')) && request.method === 'POST') return json(response, 200, await service.validateDraft(params.draftRef, body, context)), true;
      if ((params = match(pathname, '/v1/worker-package-drafts/:draftRef/package-candidates')) && request.method === 'POST') return json(response, 201, await service.releaseDraft(params.draftRef, body, context)), true;

      if (request.method === 'GET' && pathname === '/v1/worker-registrations') return json(response, 200, { items: await service.listRegistrations(context) }), true;
      if (request.method === 'POST' && pathname === '/v1/worker-registrations') return json(response, 201, await service.registerWorker(body, context)), true;
      if ((params = match(pathname, '/v1/worker-registrations/:registrationRef/promotion-proposals')) && request.method === 'POST') return json(response, 201, await service.createPromotion(params.registrationRef, body, context)), true;
      if ((params = match(pathname, '/v1/worker-registrations/:registrationRef/promotion-proposals/:promotionRef/submit')) && request.method === 'POST') return json(response, 201, await service.submitPromotion(params.registrationRef, params.promotionRef, body, context)), true;
      if ((params = match(pathname, '/v1/marketplace/submissions/:submissionId/benchmark')) && request.method === 'POST') return json(response, 200, await service.benchmarkSubmission(params.submissionId, body, context)), true;
      if ((params = match(pathname, '/v1/marketplace/submissions/:submissionId/publish')) && request.method === 'POST') return json(response, 201, await service.publishSubmission(params.submissionId, body, context)), true;

      if (request.method === 'GET' && pathname === '/v1/marketplace/workers') return json(response, 200, { items: await service.listWorkers() }), true;
      if ((params = match(pathname, '/v1/marketplace/workers/:workerId'))) {
        if (request.method === 'GET') return json(response, 200, await service.getWorker(params.workerId)), true;
      }
      if ((params = match(pathname, '/v1/marketplace/workers/:workerId/quote')) && request.method === 'POST') return json(response, 201, await service.quoteWorker(params.workerId, body, context)), true;
      if ((params = match(pathname, '/v1/marketplace/workers/:workerId/instances')) && request.method === 'POST') return json(response, 201, await service.hireWorker(params.workerId, body, context)), true;

      if (request.method === 'GET' && pathname === '/v1/marketplace/instances') return json(response, 200, { items: await service.listInstances(context) }), true;
      if ((params = match(pathname, '/v1/marketplace/instances/:instanceId'))) {
        if (request.method === 'GET') return json(response, 200, await service.getInstance(params.instanceId, context)), true;
      }
      if ((params = match(pathname, '/v1/marketplace/instances/:instanceId/:transition')) && request.method === 'POST' && ['suspend', 'resume', 'archive', 'restore'].includes(params.transition)) return json(response, 202, await service.transitionInstance(params.instanceId, params.transition, body, context)), true;
      if ((params = match(pathname, '/v1/marketplace/instances/:instanceId/integrations')) && request.method === 'POST') return json(response, 201, await service.addIntegration(params.instanceId, body, context)), true;
      if ((params = match(pathname, '/v1/marketplace/instances/:instanceId/integrations/:bindingId/test')) && request.method === 'POST') return json(response, 200, await service.testIntegration(params.instanceId, params.bindingId, body, context)), true;
      if ((params = match(pathname, '/v1/marketplace/instances/:instanceId/integrations')) && request.method === 'GET') return json(response, 200, { items: (await service.getInstance(params.instanceId, context)).integrations }), true;

      if (request.method === 'GET' && pathname === '/v1/receipts') return json(response, 200, { items: await service.receipts(context, url.searchParams.get('object_ref')) }), true;
      return json(response, 404, { error: { code: 'route_not_found', message: `No ${request.method} route for ${pathname}` } }), true;
    } catch (error) {
      const status = error instanceof DomainError || error instanceof OwnerDependencyError || error instanceof SessionError ? error.status : 500;
      if (status === 500) console.error(error);
      json(response, status, {
        error: {
          code: error.code || (error instanceof OwnerDependencyError ? 'owner_unavailable' : 'internal_error'),
          message: status === 500 ? 'Internal server error' : error.message,
          owner: error.owner,
          details: error.details,
        },
      });
      return true;
    }
  };
}
