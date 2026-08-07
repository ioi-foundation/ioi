import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createApiHandler } from '../api/handler.mjs';
import { createSessionAuthority } from '../auth/session.mjs';
import { createOwnerAdapters } from '../domain/adapters.mjs';
import { AiagentService, seedState } from '../domain/service.mjs';
import { JsonStore } from '../domain/store.mjs';

async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'aiagent-http-'));
  const service = new AiagentService(await new JsonStore(path.join(directory, 'state.json'), seedState).init(), createOwnerAdapters({ developmentAuthority: true }));
  const sessionAuthority = createSessionAuthority({ secret: 'aiagent-http-test-session-secret-000000000', developmentAuthority: true });
  const api = createApiHandler(service, { developmentAuthority: true, sessionAuthority });
  const server = createServer(async (request, response) => { if (!await api(request, response)) { response.writeHead(404); response.end(); } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  return { origin };
}

const json = async (response) => ({ status: response.status, body: await response.json() });

test('HttpOnly product session is required and browser authority headers are rejected', async (t) => {
  const { origin } = await fixture(t);
  const sessionResponse = await fetch(`${origin}/v1/session`);
  assert.equal(sessionResponse.status, 200);
  const session = await sessionResponse.json();
  const setCookie = sessionResponse.headers.get('set-cookie');
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Strict/);
  const cookie = setCookie.split(';')[0];

  const missingCsrf = await json(await fetch(`${origin}/v1/worker-package-drafts`, { method: 'POST', headers: { cookie, origin, 'content-type': 'application/json', 'idempotency-key': 'missing-csrf' }, body: '{}' }));
  assert.equal(missingCsrf.status, 403);
  assert.equal(missingCsrf.body.error.code, 'csrf_invalid');

  const forged = await json(await fetch(`${origin}/v1/worker-templates`, { headers: { cookie, 'x-ioi-principal': 'principal://attacker', 'x-ioi-tenant': 'tenant://victim' } }));
  assert.equal(forged.status, 400);
  assert.equal(forged.body.error.code, 'browser_authority_headers_forbidden');

  const crossOrigin = await json(await fetch(`${origin}/v1/worker-package-drafts`, { method: 'POST', headers: { cookie, origin: 'https://attacker.invalid', 'x-ioi-csrf': session.csrf_token, 'content-type': 'application/json', 'idempotency-key': 'cross-origin' }, body: '{}' }));
  assert.equal(crossOrigin.status, 403);
  assert.equal(crossOrigin.body.error.code, 'cross_origin_mutation_forbidden');

  const created = await json(await fetch(`${origin}/v1/worker-package-drafts`, { method: 'POST', headers: { cookie, origin, 'x-ioi-csrf': session.csrf_token, 'content-type': 'application/json', 'idempotency-key': 'valid' }, body: JSON.stringify({ template_ref: 'worker-template://blank/v1', name: 'HTTP worker', description: 'Authenticated request', model_route_ref: 'model-route://one', harness_ref: 'harness://one', runtime_profile_ref: 'runtime-profile://one' }) }));
  assert.equal(created.status, 201);
  assert.equal(created.body.owner_ref, 'principal://development/operator');

  const tampered = await json(await fetch(`${origin}/v1/worker-templates`, { headers: { cookie: `${cookie}x` } }));
  assert.equal(tampered.status, 401);
  assert.equal(tampered.body.error.code, 'invalid_session');
});
