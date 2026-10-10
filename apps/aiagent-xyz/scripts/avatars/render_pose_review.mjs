import { chromium } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';

// Native 3D renders, sampled at the demanding points of the authored clips.
// Keep this contact sheet separate from product surfaces and portrait assets.
const destination = resolve(process.env.AVATAR_REVIEW_DIR || '/tmp/avatar-pose-review');
await mkdir(destination, { recursive: true });
const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--enable-gpu', '--use-gl=angle', '--use-angle=gl'] });
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 1000 } });
  await page.goto((process.env.AVATAR_AUTHORING_ORIGIN || 'http://127.0.0.1:5173') + '/avatar-verification');
  for (const body of process.argv.slice(2).length ? process.argv.slice(2) : ['robot', 'human', 'anime']) {
    const renders = await page.evaluate(async ({ body, source }) => {
      const T = await import('/node_modules/three/build/three.module.js');
      const { acquireAvatar } = await import('/src/product/avatar/asset-cache.js');
      const { applyPalette } = await import('/src/product/avatar/appearance-materials.js');
      const { acquireVrmAvatar } = await import('/src/product/avatar/vrm-adapter.js');
      const { AVATAR_BODIES, DEFAULT_APPEARANCE } = await import('/shared/avatar-catalog.mjs');
      const { applyAppearanceParts } = await import('/src/product/avatar/appearance-parts.js');
      const definition = AVATAR_BODIES.find((item) => item.id === body);
      const handle = source && body !== 'robot' ? acquireVrmAvatar({ ...definition, asset: definition.sourceAsset }) : acquireAvatar(body), avatar = await handle.ready;
      const scene = new T.Scene(); scene.add(avatar.root);
      const toon = body === 'anime';
      scene.add(new T.HemisphereLight(0xffffff, 0xc6ae97, toon ? .95 : 1.5));
      const key = new T.DirectionalLight(toon ? 0xffffff : 0xfff2dc, toon ? 1.6 : 2.8);
      key.position.set(-2, 4, 5); scene.add(key);
      const rim = new T.DirectionalLight(0xd7edff, toon ? .15 : .8); rim.position.set(3, 2, -3); scene.add(rim);
      applyPalette(avatar.materials, 'original');
      applyAppearanceParts(avatar, { ...DEFAULT_APPEARANCE, body });
      const renderer = new T.WebGLRenderer({ antialias: true, preserveDrawingBuffer: true });
      renderer.setSize(320, 430); renderer.setPixelRatio(2); renderer.setClearColor(0xffdf00);
      renderer.toneMapping = toon ? T.NoToneMapping : T.ACESFilmicToneMapping;
      renderer.toneMappingExposure = body === 'human' ? 1.15 : 1;
      const camera = new T.PerspectiveCamera(48, 320 / 430, .05, 30), mixer = new T.AnimationMixer(avatar.root);
      const result = [];
      try {
        for (const [motion, time, label, side] of [
          ['cup-kick', 0, 'Ready'], ['cup-kick', .856, 'Knee lift'],
          ['cup-kick', 1.28, 'Forward kick'], ['cup-kick', 1.28, 'Kick · side', true],
          ['cup-kick', 3.28, 'Opposite kick'], ['entrance', .8, 'Airborne'],
          ['entrance', .8, 'Airborne · side', true], ['entrance', 1.5, 'Landing'],
          ['entrance', .45, 'Takeoff'], ['entrance', .6, 'Opening split'],
          ['entrance', 1.0, 'Split recovery'], ['entrance', 1.25, 'Closing split'],
        ]) {
          mixer.stopAllAction(); const action = mixer.clipAction(avatar.clips.find((clip) => clip.name === motion));
          action.reset().setLoop(T.LoopOnce, 1); action.clampWhenFinished = true; action.play(); action.time = time;
          mixer.update(0); avatar.update?.(0, time, true);
          const entrance = motion === 'entrance';
          camera.position.set(side ? (entrance ? 4.7 : 3.4) : 0, entrance ? 1.3 : 1, side ? 0 : entrance ? 4.7 : 3.05);
          camera.lookAt(0, entrance ? 1.12 : .97, 0); camera.updateMatrixWorld(true);
          renderer.render(scene, camera);
          result.push({ label, motion, time, image: renderer.domElement.toDataURL('image/png') });
        }
      } finally { mixer.stopAllAction(); mixer.uncacheRoot(avatar.root); renderer.dispose(); renderer.forceContextLoss(); handle.release(); }
      return result;
    }, { body, source: process.env.AVATAR_SOURCE === '1' });
    for (let i = 0; i < renders.length; i++) await writeFile(`${destination}/${body}-${i}.png`, Buffer.from(renders[i].image.split(',')[1], 'base64'));
    const html = `<title>${body} pose review</title><style>body{margin:0;background:#1c2021;color:white;font:15px system-ui}main{display:grid;grid-template-columns:repeat(4,320px)}figure{margin:0}img{display:block;width:320px;height:430px}figcaption{padding:10px 14px}h1{font-size:22px;margin:16px}</style><h1>${body} · authored performance</h1><main>${renders.map((render) => `<figure><img src="${render.image}"><figcaption>${render.label} · ${render.time.toFixed(2)}s</figcaption></figure>`).join('')}</main>`;
    await writeFile(`${destination}/${body}.html`, html);
    await page.setContent(html); await page.screenshot({ path: `${destination}/${body}-sheet.png`, fullPage: true });
    console.log(`Rendered ${body}: ${destination}/${body}-sheet.png`);
    await page.goto((process.env.AVATAR_AUTHORING_ORIGIN || 'http://127.0.0.1:5173') + '/avatar-verification');
  }
} finally { await browser.close(); }
