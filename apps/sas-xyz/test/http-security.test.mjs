import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { mkdtemp, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { createApiHandler } from '../api/handler.mjs';
import { createSessionAuthority } from '../auth/session.mjs';
import { createOwnerAdapters } from '../domain/adapters.mjs';
import { SasService, seedState } from '../domain/service.mjs';
import { JsonStore } from '../domain/store.mjs';

async function fixture(t) {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'sas-http-'));
  const service = new SasService(await new JsonStore(path.join(directory, 'state.json'), seedState).init(), createOwnerAdapters({ developmentAuthority: true }));
  const sessionAuthority = createSessionAuthority({ secret: 'sas-http-test-session-secret-00000000000000', developmentAuthority: true });
  const api = createApiHandler(service, { developmentAuthority: true, sessionAuthority });
  const server = createServer(async (request, response) => { if (!await api(request, response)) { response.writeHead(404); response.end(); } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => { await new Promise((resolve) => server.close(resolve)); await rm(directory, { recursive: true, force: true }); });
  return { origin };
}

const json = async (response) => ({ status: response.status, body: await response.json() });

test('sas BFF derives identity from signed HttpOnly session and enforces CSRF', async (t) => {
  const { origin } = await fixture(t);
  const sessionResponse = await fetch(`${origin}/v1/session`); const session = await sessionResponse.json(); const setCookie = sessionResponse.headers.get('set-cookie'); const cookie = setCookie.split(';')[0];
  assert.match(setCookie, /HttpOnly/);
  assert.match(setCookie, /SameSite=Strict/);

  const forged = await json(await fetch(`${origin}/v1/services`, { headers: { cookie, 'x-ioi-principal': 'principal://attacker', 'x-ioi-tenant': 'tenant://victim' } }));
  assert.equal(forged.status, 400);
  assert.equal(forged.body.error.code, 'browser_authority_headers_forbidden');

  const noOrigin = await json(await fetch(`${origin}/v1/provider/services`, { method: 'POST', headers: { cookie, 'x-ioi-csrf': session.csrf_token, 'content-type': 'application/json', 'idempotency-key': 'no-origin' }, body: '{}' }));
  assert.equal(noOrigin.status, 403);
  assert.equal(noOrigin.body.error.code, 'cross_origin_mutation_forbidden');

  const created = await json(await fetch(`${origin}/v1/provider/services`, { method: 'POST', headers: { cookie, origin, 'x-ioi-csrf': session.csrf_token, 'content-type': 'application/json', 'idempotency-key': 'valid' }, body: JSON.stringify({ name: 'HTTP outcome', version: '1.0.0', summary: 'Authenticated provider release', outcome_contract: { output: 'report' }, deliverable_kind: 'general', price: { asset: 'USD', amount_minor: 100 }, sla: 'one day' }) }));
  assert.equal(created.status, 201);
  assert.equal(created.body.provider_ref, 'principal://development/operator');

  const tampered = await json(await fetch(`${origin}/v1/services`, { headers: { cookie: `${cookie}x` } }));
  assert.equal(tampered.status, 401);
  assert.equal(tampered.body.error.code, 'invalid_session');
});
