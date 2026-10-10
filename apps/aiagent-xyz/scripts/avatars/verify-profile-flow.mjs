import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { chromium } from 'playwright';
import { avatarEditorPath } from '../../shared/avatar-catalog.mjs';

const root = fileURLToPath(new URL('../../', import.meta.url));
const directory = await mkdtemp(path.join(tmpdir(), 'aiagent-avatar-browser-'));
const reserve = createServer();
await new Promise((resolve) => reserve.listen(0, '127.0.0.1', resolve));
const port = reserve.address().port;
await new Promise((resolve) => reserve.close(resolve));
const origin = `http://127.0.0.1:${port}`;
const server = spawn(process.execPath, ['server.mjs'], { cwd: root, env: { ...process.env, PORT: String(port),
  IOI_ENABLE_DEVELOPMENT_AUTHORITY: '1', IOI_SERVE_BUILT_UI: '1', IOI_AIAGENT_STORE_PATH: path.join(directory, 'state.json') }, stdio: 'pipe' });
let logs = ''; server.stderr.on('data', (value) => { logs += value; });
let browser;
try {
  for (let tries = 0; ; tries++) {
    try { if ((await fetch(`${origin}/v1/session`)).ok) break; } catch { /* Server starting. */ }
    assert.ok(tries < 100, `Server failed to start: ${logs}`); await delay(100);
  }
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  await page.addInitScript(() => {
    let session;
    window.profileTestApi = async (path, options = {}) => {
      session ||= fetch('/v1/session').then((response) => response.json());
      const current = await session;
      const method = options.method || 'GET';
      const response = await fetch(path, { method, credentials: 'same-origin', headers: {
        'content-type': 'application/json', ...(method !== 'GET' ? { 'x-ioi-csrf': current.csrf_token, 'idempotency-key': crypto.randomUUID() } : {}),
      }, body: options.body === undefined ? undefined : JSON.stringify(options.body) });
      const result = await response.json();
      if (!response.ok) throw new Error(result.error?.message || `HTTP ${response.status}`);
      return result;
    };
  });
  const errors = []; page.on('pageerror', (error) => errors.push(error.message));
  // GLTFLoader catches image failures and can leave a white untextured model
  // without a pageerror. Treat those console failures as a broken avatar too.
  page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()); });
  await page.goto(`${origin}/avatar-studio`);
  const fixtures = await page.evaluate(async () => {
    const api = window.profileTestApi;
    const create = (name) => api('/v1/worker-package-drafts', { method: 'POST', body: {
      template_ref: 'worker-template://blank/v1', name, description: 'A worker profile used for isolated appearance verification.',
      task_contract: { input: 'Input', output: 'Output' }, model_route_ref: 'model-route://one', harness_ref: 'harness://one', runtime_profile_ref: 'runtime-profile://one',
    } });
    const first = await create('Atlas'), second = await create('Mira');
    return { first, second };
  });
  const edit = (kind, ref) => page.goto(origin + avatarEditorPath(kind, ref));
  const ready = () => page.locator('.avatar-stage[data-status="ready"]').waitFor();
  await edit('draft_ref', fixtures.first.draft_ref); await ready();
  await page.getByRole('button', { name: /^Human / }).click(); await ready();
  await page.getByRole('button', { name: 'Ocean palette' }).click();
  await page.getByRole('button', { name: 'Warm', exact: true }).click();
  await page.getByRole('button', { name: 'Charcoal', exact: true }).click();
  await page.getByRole('button', { name: 'Save appearance', exact: true }).click();
  await page.getByText('Appearance saved privately.', { exact: true }).waitFor();
  await page.reload(); await ready();
  assert.equal(await page.getByRole('button', { name: /^Human / }).getAttribute('aria-pressed'), 'true');
  assert.equal(await page.getByRole('button', { name: 'Ocean palette' }).getAttribute('aria-pressed'), 'true');
  assert.equal(await page.getByRole('button', { name: 'Warm', exact: true }).getAttribute('aria-pressed'), 'true');
  assert.equal(await page.getByRole('button', { name: 'Charcoal', exact: true }).getAttribute('aria-pressed'), 'true');
  await edit('draft_ref', fixtures.second.draft_ref); await ready();
  assert.equal(await page.getByRole('button', { name: /^Cyborg / }).getAttribute('aria-pressed'), 'true');
  await page.getByRole('button', { name: /^Anime / }).click(); await ready();
  await page.getByRole('button', { name: 'Plain coat', exact: true }).click();
  await page.getByRole('button', { name: 'Loose hair', exact: true }).click();
  assert.equal(await page.getByRole('button', { name: 'Composed', exact: true }).getAttribute('aria-pressed'), 'true');
  await page.getByRole('button', { name: 'Save appearance', exact: true }).click();
  await page.getByText('Appearance saved privately.', { exact: true }).waitFor();
  await page.reload(); await ready();
  assert.equal(await page.getByRole('button', { name: 'Plain coat', exact: true }).getAttribute('aria-pressed'), 'true');
  assert.equal(await page.getByRole('button', { name: 'Loose hair', exact: true }).getAttribute('aria-pressed'), 'true');
  const listing = await page.evaluate(async (draft) => {
    const api = window.profileTestApi;
    const base = `/v1/worker-package-drafts/${encodeURIComponent(draft.draft_ref)}`;
    await api(`${base}/validate`, { method: 'POST', body: { expected_revision: draft.revision } });
    await api(`${base}/package-candidates`, { method: 'POST', body: { version: '1.0.0', sbom_ref: 'sbom://one', provenance_ref: 'provenance://one' } });
    const registration = await api('/v1/worker-registrations', { method: 'POST', body: { draft_ref: draft.draft_ref } });
    const reg = `/v1/worker-registrations/${encodeURIComponent(registration.registration_ref)}`;
    const promotion = await api(`${reg}/promotion-proposals`, { method: 'POST', body: { disclosure_allowlist: ['name'], license: 'commercial', pricing: { asset: 'USD', amount_minor: 100 } } });
    const submission = await api(`${reg}/promotion-proposals/${encodeURIComponent(promotion.promotion_ref)}/submit`, { method: 'POST', body: {} });
    await api(`/v1/marketplace/submissions/${submission.submission_id}/benchmark`, { method: 'POST', body: { evaluation_plan_ref: 'evaluation-plan://one' } });
    return api(`/v1/marketplace/submissions/${submission.submission_id}/publish`, { method: 'POST', body: {} });
  }, fixtures.first);
  assert.equal(listing.avatar.appearance.body, 'robot');
  await edit('worker_id', listing.worker_id); await ready();
  assert.equal(await page.getByRole('button', { name: /^Human / }).getAttribute('aria-pressed'), 'true');
  assert.equal(await page.getByRole('button', { name: 'Charcoal', exact: true }).getAttribute('aria-pressed'), 'true');
  await page.getByRole('button', { name: 'Use saved appearance publicly' }).click();
  await page.getByText('Public appearance updated.', { exact: true }).waitFor();
  await page.goto(`${origin}/agents/${listing.worker_id}`); await ready();
  assert.equal(await page.locator('canvas').count(), 1);
  assert.equal(await page.getByRole('heading', { name: 'Atlas', exact: true }).count(), 1);
  await page.getByRole('button', { name: 'Pause avatar animation' }).click();
  await page.screenshot({ path: '/tmp/avatar-worker-desktop.png', fullPage: false });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForFunction(() => {
    const canvas = document.querySelector('.avatar-stage-canvas canvas');
    return Math.abs(canvas.width / canvas.height - canvas.clientWidth / canvas.clientHeight) < .005;
  });
  await page.screenshot({ path: '/tmp/avatar-worker-mobile.png', fullPage: false });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  assert.ok(await page.locator('.avatar-profile-header').evaluate((header) => header.getBoundingClientRect().bottom <= innerHeight), 'The mobile fixture must show the complete full-body stage in the first viewport');
  await page.goto(`${origin}/agents`);
  await page.getByRole('heading', { name: 'Atlas', level: 3, exact: true }).waitFor();
  assert.equal(await page.locator('canvas').count(), 0);
  await page.waitForFunction(() => [...document.querySelectorAll('img[alt="Atlas avatar"]')].some((image) => image.complete && image.naturalWidth > 0));
  assert.deepEqual(errors, []);
  console.log('PASS: independent save/reload, lifecycle transfer, explicit public revision, one detail canvas, static list portraits, mobile overflow, no browser errors.');
} finally {
  await browser?.close();
  server.kill('SIGTERM');
  await new Promise((resolve) => server.exitCode !== null ? resolve() : server.once('exit', resolve));
  await rm(directory, { recursive: true, force: true });
}
