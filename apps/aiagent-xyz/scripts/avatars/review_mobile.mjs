import assert from 'node:assert/strict';
import { chromium } from 'playwright';
const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--enable-gpu', '--use-gl=angle', '--use-angle=gl'] });
try {
  const page = await browser.newPage({ viewport: { width: 390, height: 844 }, deviceScaleFactor: 2, reducedMotion: 'reduce' });
  const models = [], errors = [];
  page.on('response', (response) => { if (/\.(glb|vrm)$/.test(response.url())) models.push(response.url()); });
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('console', (message) => { if (message.type() === 'error') errors.push(message.text()); });
  await page.goto((process.env.AVATAR_AUTHORING_ORIGIN || 'http://127.0.0.1:5173') + '/avatar-studio');
  for (const body of ['Cyborg', 'Human', 'Anime']) {
    await page.getByRole('button', { name: new RegExp('^' + body + ' ') }).click();
    await page.locator('.avatar-stage[data-status="ready"]').waitFor();
    for (const [motion, time, label] of [['Cup & kick', 0, 'standing'], ['Cup & kick', 1.28, 'kick'], ['Entrance', .45, 'takeoff'], ['Entrance', .8, 'entrance'], ['Entrance', 1, 'recovery']]) {
      await page.getByRole('button', { name: motion, exact: true }).click();
      await page.getByRole('slider', { name: 'Animation position' }).fill(time === 0 ? '0.01' : String(time));
      if (time === 0) await page.getByRole('slider', { name: 'Animation position' }).fill('0');
      await page.locator('.avatar-stage').evaluate((stage) => stage.scrollIntoView({ block: 'center' }));
      await page.waitForTimeout(200);
      await page.locator('.avatar-stage').screenshot({ path: `/tmp/avatar-mobile-${body.toLowerCase()}-${label}.png` });
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
    }
  }
  // Development StrictMode may request an aborted first mount twice. Verify
  // the three selected assets, rather than treating repeated requests as LODs.
  assert.equal(new Set(models.filter((url) => url.includes('-mobile-v1'))).size, 3);
  assert.equal(models.some((url) => !url.includes('-mobile-v1')), false);
  assert.deepEqual(errors, []);
  console.log('Mobile models loaded, all three pose sequences captured, no horizontal overflow or browser errors.');
} finally { await browser.close(); }
