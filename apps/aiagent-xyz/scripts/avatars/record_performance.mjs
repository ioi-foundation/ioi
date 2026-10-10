import { chromium } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execute = promisify(execFile);

const destination = resolve(process.env.AVATAR_REVIEW_DIR || '/tmp/avatar-performance-review');
await mkdir(destination, { recursive: true });
// A headful window can be resized by the tiling window manager independently
// of the emulated viewport, silently cropping Playwright's video surface.
// These are visual records, not GPU benchmarks; use the fixed headless surface.
const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--enable-gpu', '--use-gl=angle', '--use-angle=gl'] });
try {
  for (const body of process.argv.slice(2).length ? process.argv.slice(2) : ['Cyborg', 'Human', 'Anime']) {
    const context = await browser.newContext({ viewport: { width: 1280, height: 720 }, reducedMotion: 'reduce',
      recordVideo: { dir: destination, size: { width: 1280, height: 720 } } });
    const page = await context.newPage();
    await page.goto((process.env.AVATAR_AUTHORING_ORIGIN || 'http://127.0.0.1:5173') + '/avatar-studio');
    await page.getByRole('button', { name: new RegExp('^' + body + ' ') }).click();
    await page.locator('.avatar-stage[data-status="ready"]').waitFor();
    if (process.env.AVATAR_REVIEW_VIEW) await page.getByRole('button', { name: { quarter: '¾ view', side: 'Side', front: 'Front' }[process.env.AVATAR_REVIEW_VIEW], exact: true }).click();
    await page.getByRole('button', { name: 'Entrance', exact: true }).click();
    // The recording uses the real product stage and animation player. This
    // page-local stylesheet only removes surrounding editor chrome.
    await page.addStyleTag({ content: 'body{overflow:hidden}body *{visibility:hidden}.avatar-stage,.avatar-stage *{visibility:visible}.avatar-stage{position:fixed!important;inset:0!important;width:100vw!important;height:100vh!important;z-index:99999;border-radius:0}.avatar-stage-toolbar{display:none}' });
    await page.waitForTimeout(300);
    // A short slate makes the first performance frame identifiable in the
    // actual recording. Trimming the last ten seconds included encoder tail
    // frames and could remove part of the entrance.
    await page.evaluate(() => {
      const marker = document.createElement('div'); marker.id = 'avatar-record-marker';
      marker.style.cssText = 'position:fixed;inset:0;z-index:100000;background:rgb(129,9,209);visibility:visible';
      document.body.append(marker);
    });
    await page.waitForTimeout(400);
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await page.locator('.avatar-replay').evaluate((button) => { document.getElementById('avatar-record-marker').remove(); button.click(); });
    const samplesPromise = page.evaluate(() => new Promise((resolve) => {
      const values = [], start = performance.now();
      const timer = setInterval(() => {
        const stage = document.querySelector('.avatar-stage-canvas');
        values.push({ elapsed: performance.now() - start, motion: stage.dataset.motion, time: Number(stage.dataset.animationTime) });
        if (performance.now() - start >= 10000) { clearInterval(timer); resolve(values); }
      }, 100);
    }));
    await page.waitForTimeout(800);
    await page.screenshot({ path: `${destination}/${body.toLowerCase()}-entrance.png` });
    const samples = await samplesPromise;
    const transition = samples.find((sample) => sample.motion === 'cup-kick');
    if (!transition || Math.abs(transition.elapsed - 2000) > 250) throw new Error('Recording could not sustain the authored timing');
    await page.screenshot({ path: `${destination}/${body.toLowerCase()}-stage.png` });
    await page.waitForTimeout(250);
    const video = page.video(); await context.close();
    const raw = `${destination}/${body.toLowerCase()}-raw.webm`;
    await video.saveAs(raw);
    const probe = JSON.parse((await execute('ffprobe', ['-v', 'error', '-select_streams', 'v:0', '-show_entries', 'stream=r_frame_rate,width,height', '-of', 'json', raw])).stdout).streams[0];
    if (probe.width !== 1280 || probe.height !== 720) throw new Error('Unexpected video dimensions');
    const [numerator, denominator] = probe.r_frame_rate.split('/').map(Number), fps = numerator / denominator;
    const pixels = (await execute('ffmpeg', ['-v', 'error', '-i', raw, '-vf', 'crop=2:2:0:0,scale=1:1,format=rgb24', '-f', 'rawvideo', 'pipe:1'], { encoding: 'buffer' })).stdout;
    let lastSlate = -1;
    for (let i = 0; i < pixels.length; i += 3) {
      if (Math.abs(pixels[i] - 129) < 15 && Math.abs(pixels[i + 1] - 9) < 15 && Math.abs(pixels[i + 2] - 209) < 15) lastSlate = i / 3;
    }
    if (lastSlate < 0) throw new Error('Recording start slate was not captured');
    const offset = (lastSlate + 1) / fps;
    await execute('ffmpeg', ['-v', 'error', '-y', '-ss', String(offset), '-i', raw, '-t', '10', '-c:v', 'libx264', '-crf', '18', '-pix_fmt', 'yuv420p', '-movflags', '+faststart', `${destination}/${body.toLowerCase()}-performance.mp4`]);
    await writeFile(`${destination}/${body.toLowerCase()}-timing.json`, JSON.stringify(samples, null, 2) + '\n');
    console.log(`Recorded ${body}: entrance and two loops; ${samples.length} timing samples; recording starts at ${offset.toFixed(2)}s.`);
  }
} finally { await browser.close(); }
