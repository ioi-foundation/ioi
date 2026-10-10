import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { chromium } from 'playwright';

const origin = process.env.AVATAR_AUTHORING_ORIGIN || 'http://127.0.0.1:5173';
const browser = await chromium.launch({ headless: false, args: ['--no-sandbox', '--enable-gpu'] });
const results = {};
try {
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, reducedMotion: 'reduce' });
  const page = await context.newPage();
  const errors = []; page.on('pageerror', (error) => errors.push(error.message));
  await page.addInitScript(() => {
    window.avatarContexts = [];
    const original = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function (kind, ...args) {
      const context = original.call(this, kind, ...args);
      if (kind.startsWith('webgl') && context && !window.avatarContexts.includes(context)) window.avatarContexts.push(context);
      return context;
    };
  });
  await page.goto(origin + '/avatar-studio');
  const stage = page.locator('.avatar-stage'), canvas = page.locator('.avatar-stage-canvas');
  const ready = () => page.locator('.avatar-stage[data-status="ready"]').waitFor();
  const time = async () => Number(await canvas.getAttribute('data-animation-time'));
  await ready(); await page.waitForTimeout(350);
  assert.equal(await time(), 0);
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.waitForFunction(() => Number(document.querySelector('.avatar-stage-canvas')?.dataset.animationTime) > .1);
  await page.emulateMedia({ reducedMotion: 'reduce' }); await page.waitForTimeout(250);
  assert.equal(await time(), 0); results.reducedMotionChange = true;
  await page.emulateMedia({ reducedMotion: 'no-preference' });
  await page.getByRole('button', { name: 'Pause animation' }).click();
  await page.getByRole('slider', { name: 'Animation position' }).fill('1.28'); await page.waitForTimeout(250);
  assert.equal(await time(), 1.28); await page.waitForTimeout(200); assert.equal(await time(), 1.28);
  results.pausedSeek = true;
  await page.getByRole('button', { name: 'Play animation' }).click();
  await page.waitForTimeout(150);
  // This runner keeps each browser target visible even with focus emulation
  // disabled. Exercise the Page Visibility event contract explicitly; this
  // is not reported as an operating-system tab-occlusion measurement.
  await page.evaluate(() => { Object.defineProperty(document, 'hidden', { configurable: true, value: true }); document.dispatchEvent(new Event('visibilitychange')); });
  const hidden = await time(); await page.waitForTimeout(400); assert.equal(await time(), hidden);
  await page.evaluate(() => { delete document.hidden; document.dispatchEvent(new Event('visibilitychange')); });
  await page.waitForFunction((previous) => Number(document.querySelector('.avatar-stage-canvas').dataset.animationTime) !== previous, hidden);
  results.visibilityEventPause = true;
  await page.evaluate(() => { const spacer = document.createElement('div'); spacer.id = 'visibility-test-spacer'; spacer.style.height = '2000px'; document.body.append(spacer); window.scrollTo(0, document.body.scrollHeight); }); await page.waitForTimeout(250);
  const offscreen = await time(); await page.waitForTimeout(300); assert.equal(await time(), offscreen);
  await stage.scrollIntoViewIfNeeded(); await page.waitForTimeout(200); assert.notEqual(await time(), offscreen);
  await page.evaluate(() => document.getElementById('visibility-test-spacer').remove());
  results.offscreenPause = true;
  await page.evaluate(() => {
    const gl = document.querySelector('.avatar-stage-canvas canvas').getContext('webgl2');
    window.avatarLoss = gl.getExtension('WEBGL_lose_context'); window.avatarLoss.loseContext();
  });
  await page.locator('.avatar-stage[data-status="unavailable"]').waitFor();
  assert.equal(await page.locator('.avatar-stage-poster').evaluate((img) => img.complete && img.naturalWidth > 0), true);
  await page.waitForTimeout(300); await page.evaluate(() => window.avatarLoss.restoreContext()); await ready();
  results.contextLossPosterAndRecovery = true;
  for (let index = 0; index < 5; index++) {
    await page.getByRole('link', { name: 'My workers ↗', exact: true }).click();
    await page.waitForTimeout(200);
    const cleanup = await page.evaluate(async () => {
      const { avatarCacheState } = await import('/src/product/avatar/asset-cache.js');
      return { cached: avatarCacheState().length, liveContexts: window.avatarContexts.filter((gl) => !gl.isContextLost()).length };
    });
    assert.deepEqual(cleanup, { cached: 0, liveContexts: 0 });
    await page.goBack(); await ready();
  }
  results.repeatedMountsReleased = 5;
  await page.route('**/models/avatars/human-performance-v1.glb', (route) => route.fulfill({ status: 503, body: 'Unavailable' }));
  await page.getByRole('button', { name: /^Human / }).click();
  await page.locator('.avatar-stage[data-status="error"]').waitFor();
  assert.equal(await page.locator('.avatar-stage-poster').evaluate((img) => img.complete && img.naturalWidth > 0), true);
  await page.unroute('**/models/avatars/human-performance-v1.glb');
  await page.getByRole('button', { name: 'Try again', exact: true }).click(); await ready();
  results.assetFailurePosterAndRetry = true;
  const unavailable = await browser.newPage();
  await unavailable.addInitScript(() => {
    const get = HTMLCanvasElement.prototype.getContext;
    HTMLCanvasElement.prototype.getContext = function (kind, ...args) { return kind.startsWith('webgl') ? null : get.call(this, kind, ...args); };
  });
  await unavailable.goto(origin + '/avatar-studio');
  await unavailable.locator('.avatar-stage[data-status="unavailable"]').waitFor();
  await unavailable.waitForFunction(() => { const img = document.querySelector('.avatar-stage-poster'); return img?.complete && img.naturalWidth > 0; });
  assert.equal(await unavailable.getByRole('button', { name: /^Human / }).isEnabled(), true);
  results.noWebglFallback = true;
  assert.deepEqual(errors, []);
  await writeFile('/tmp/avatar-lifecycle-validation.json', JSON.stringify(results, null, 2) + '\n');
  console.log(results);
} finally { await browser.close(); }
