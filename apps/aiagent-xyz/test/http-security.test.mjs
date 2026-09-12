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

// THE STATIC RESPONSE'S SECURITY POSTURE WAS UNGUARDED (2026-09-12). Nothing in this repository
// asserted the content-security-policy this server sends — it could be widened, or deleted
// outright, and every gate would stay green. That was found while ADDING a directive to it
// (`worker-src 'self' blob:`, which the landing hero's Draco decoder needs), and a posture that
// can be edited without anything noticing is exactly what should not be edited quietly.
//
// The directives are compared as a SET rather than as one string, so reordering them is not a
// failure and adding, removing or altering one is. Each is named here with what it is for, so a
// future change is a visible edit to a list with reasons on it rather than a diff in a header.
test('the static response declares exactly the security directives it means to', async () => {
  const { readFile } = await import('node:fs/promises');
  const { fileURLToPath } = await import('node:url');
  const source = await readFile(
    path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'server.mjs'),
    'utf8',
  );
  const declared = /'content-security-policy':\s*"([^"]+)"/u.exec(source);
  assert.ok(declared, 'server.mjs declares a content-security-policy header');
  const directives = Object.fromEntries(
    declared[1].split(';').map((part) => part.trim()).filter(Boolean)
      .map((part) => { const [name, ...values] = part.split(/\s+/u); return [name, values.join(' ')]; }),
  );
  assert.deepEqual(directives, {
    // Nothing loads from anywhere but this origin unless a directive below says otherwise.
    'default-src': "'self'",
    // No remote script and no inline script. This is the directive that must not widen.
    'script-src': "'self'",
    // Workers from this origin and from blob URLs: three.js's DRACOLoader inlines its decoder and
    // starts it from a Blob. Without this it falls back to script-src and the decoder is blocked.
    'worker-src': "'self' blob:",
    'style-src': "'self'",
    // data: is for the inlined icons the build emits; it is not a script source.
    'img-src': "'self' data:",
    'connect-src': "'self'",
    'object-src': "'none'",
    'base-uri': "'none'",
    'frame-ancestors': "'none'",
  });
});
