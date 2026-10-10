import { chromium } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { AVATAR_BODIES, AVATAR_PALETTES, DEFAULT_APPEARANCE, avatarPortrait, avatarPoster, validateAppearance } from '../../shared/avatar-catalog.mjs';
import { appearanceVariants } from '../../shared/avatar-parts.mjs';

const root = fileURLToPath(new URL('../../public/', import.meta.url));
const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--enable-gpu', '--use-gl=angle', '--use-angle=gl'] });
try {
  const page = await browser.newPage();
  await page.goto(process.env.AVATAR_AUTHORING_ORIGIN || 'http://127.0.0.1:5173/avatar-verification');
  for (const body of AVATAR_BODIES) {
    if (process.argv.length > 2 && !process.argv.slice(2).includes(body.id)) continue;
    for (const parts of appearanceVariants(body.id)) for (const palette of AVATAR_PALETTES) for (const finish of body.finishes) {
      let appearance;
      try { appearance = validateAppearance({ ...DEFAULT_APPEARANCE, body: body.id, asset_revision: body.revision, palette: palette.id, finish: finish.id, parts }); }
      catch { continue; }
      const rendered = await page.evaluate(async (appearance) => {
        const T = await import('/node_modules/three/build/three.module.js');
        const { acquireAvatar } = await import('/src/product/avatar/asset-cache.js');
        const { applyPalette } = await import('/src/product/avatar/appearance-materials.js');
        const { applyAppearanceParts } = await import('/src/product/avatar/appearance-parts.js');
        if (!window.avatarPortraitBatch) {
          const handle = acquireAvatar(appearance.body);
          const avatar = await handle.ready;
          const renderer = new T.WebGLRenderer({ alpha: true, antialias: true, preserveDrawingBuffer: true });
          renderer.outputColorSpace = T.SRGBColorSpace;
          const toon = appearance.body === 'anime';
          renderer.toneMapping = toon ? T.NoToneMapping : T.ACESFilmicToneMapping;
          renderer.toneMappingExposure = toon || appearance.body === 'robot' ? 1 : 1.15;
          const scene = new T.Scene(); scene.add(avatar.root);
          scene.add(new T.HemisphereLight(0xffffff, 0xc6ae97, toon ? .95 : 1.5));
          const key = new T.DirectionalLight(toon ? 0xffffff : 0xfff2dc, toon ? 1.6 : 2.8); key.position.set(-2, 4, 5); scene.add(key);
          const rim = new T.DirectionalLight(0xd7edff, toon ? .15 : .8); rim.position.set(3, 2, -3); scene.add(rim);
          window.avatarPortraitBatch = { handle, avatar, renderer, scene, mixer: new T.AnimationMixer(avatar.root), camera: new T.PerspectiveCamera(38, 1, .05, 30) };
        }
        const { avatar, renderer, scene, mixer, camera } = window.avatarPortraitBatch;
          applyPalette(avatar.materials, appearance.palette); avatar.setFinish?.(appearance.finish);
          applyAppearanceParts(avatar, appearance);
          mixer.stopAllAction(); mixer.clipAction(avatar.clips.find((clip) => clip.name === 'idle')).reset().play(); mixer.update(0); avatar.update?.(0, 0, true);
          camera.fov = 38; camera.aspect = 1; camera.updateProjectionMatrix();
          camera.position.set(0, 1.49, 1.05); camera.lookAt(0, 1.49, 0);
          renderer.setSize(512, 512); renderer.setClearColor(0xeee7dd, 1);
          renderer.render(scene, camera);
          const portrait = renderer.domElement.toDataURL('image/webp', .94).split(',')[1];
          mixer.stopAllAction(); mixer.clipAction(avatar.clips.find((clip) => clip.name === 'cup-kick')).reset().play(); mixer.update(0); avatar.update?.(0, 0, true);
          camera.fov = 48; camera.aspect = 600 / 740; camera.position.set(0, 1, 2.65); camera.lookAt(0, .96, 0); camera.updateProjectionMatrix();
          renderer.setSize(600, 740); renderer.setClearColor(0x000000, 0);
          renderer.render(scene, camera);
          const poster = renderer.domElement.toDataURL('image/webp', .94).split(',')[1];
          return { portrait, poster };
      }, appearance);
      for (const [kind, path] of [['portrait', avatarPortrait(appearance)], ['poster', avatarPoster(appearance)]]) {
        const file = root + path.slice(1);
        await mkdir(file.slice(0, file.lastIndexOf('/')), { recursive: true });
        await writeFile(file, Buffer.from(rendered[kind], 'base64'));
      }
      console.log(`Rendered ${body.id} / ${palette.id} / ${finish.id}`);
    }
    await page.evaluate(() => {
      const batch = window.avatarPortraitBatch;
      if (!batch) return;
      batch.mixer.stopAllAction(); batch.mixer.uncacheRoot(batch.avatar.root);
      batch.renderer.dispose(); batch.renderer.forceContextLoss(); batch.handle.release();
      delete window.avatarPortraitBatch;
    });
  }
} finally { await browser.close(); }
