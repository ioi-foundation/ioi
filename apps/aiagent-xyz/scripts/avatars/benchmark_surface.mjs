import { writeFile } from 'node:fs/promises';
import { cpus } from 'node:os';
import { chromium } from 'playwright';

// Hardware browser measurement. Mobile dimensions below are explicitly a
// layout/quality emulation on this GPU, not evidence from a mobile device.
const browser = await chromium.launch({ headless: false, args: ['--no-sandbox', '--enable-gpu'] });
const report = { cpu: cpus()[0].model, browser: browser.version(), measuredAt: new Date().toISOString(), cases: [] };
try {
  for (const surface of [
    { name: 'desktop', viewport: { width: 1440, height: 1000 }, deviceScaleFactor: 2 },
    { name: 'mobile-layout-on-desktop-gpu', viewport: { width: 390, height: 844 }, deviceScaleFactor: 3 },
  ]) {
    const context = await browser.newContext(surface);
    const page = await context.newPage();
    await page.goto((process.env.AVATAR_AUTHORING_ORIGIN || 'http://127.0.0.1:5173') + '/avatar-studio');
    for (const body of ['Cyborg', 'Human', 'Anime']) {
      const started = performance.now();
      await page.getByRole('button', { name: new RegExp('^' + body + ' ') }).click();
      await page.locator('.avatar-stage[data-status="ready"]').waitFor();
      const localReadyMs = performance.now() - started;
      await page.locator('.avatar-stage').scrollIntoViewIfNeeded();
      await page.waitForTimeout(2000);
      const measured = await page.evaluate(() => new Promise((resolve) => {
        const canvas = document.querySelector('.avatar-stage-canvas canvas');
        const gl = canvas.getContext('webgl2'), debug = gl.getExtension('WEBGL_debug_renderer_info');
        const gpu = gl.getParameter(debug.UNMASKED_RENDERER_WEBGL);
        const frames = []; let first = null, previous = null;
        function frame(now) {
          if (first === null) first = now;
          if (previous !== null) frames.push(now - previous);
          previous = now;
          if (now - first < 10000) { requestAnimationFrame(frame); return; }
          const sorted = [...frames].sort((a, b) => a - b);
          resolve({ gpu, canvas: [canvas.width, canvas.height], averageFps: frames.length * 1000 / (now - first),
            medianFrameMs: sorted[Math.floor(sorted.length * .5)], p95FrameMs: sorted[Math.floor(sorted.length * .95)],
            p99FrameMs: sorted[Math.floor(sorted.length * .99)], frames: frames.length,
            renderStats: document.querySelector('.avatar-inspection')?.textContent });
        }
        requestAnimationFrame(frame);
      }));
      const result = { surface: surface.name, body, localReadyMs, ...measured };
      report.cases.push(result); console.log(JSON.stringify(result));
    }
    await context.close();
  }
  await writeFile('/tmp/avatar-performance-validation.json', JSON.stringify(report, null, 2) + '\n');
} finally { await browser.close(); }
