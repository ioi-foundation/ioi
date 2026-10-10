import { chromium } from 'playwright';
import { mkdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

// Capture the retargeted control motion in the model's original coordinates.
// bake_motion.py transfers these world deltas onto the editable Blender rig.
const destination = fileURLToPath(new URL('../../assets/avatars/motion/', import.meta.url));
await mkdir(destination, { recursive: true });
const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
try {
  const page = await browser.newPage();
  await page.goto(process.env.AVATAR_AUTHORING_ORIGIN || 'http://127.0.0.1:5173/avatar-studio');
  for (const bodyId of ['human', 'anime']) {
    const data = await page.evaluate(async (id) => {
      const { acquireVrmAvatar } = await import('/src/product/avatar/vrm-adapter.js');
      const { AVATAR_BODIES } = await import('/shared/avatar-catalog.mjs');
      const { AnimationMixer, Matrix4, LoopOnce } = await import('/node_modules/three/build/three.module.js');
      const body = AVATAR_BODIES.find((item) => item.id === id);
      const handle = acquireVrmAvatar({ ...body, asset: body.sourceAsset });
      try {
        const { root, clips, update, authoring } = await handle.ready;
        const result = { body: id, fps: 30, sourceRest: authoring.sourceRest, clips: [] };
        const inverse = new Matrix4();
        const mixer = new AnimationMixer(root);
        for (const clip of clips) {
          mixer.stopAllAction();
          const action = mixer.clipAction(clip);
          action.reset().setLoop(LoopOnce, 1); action.clampWhenFinished = true; action.play();
          const frames = [];
          for (let frame = 0; frame <= clip.duration * 30; frame++) {
            const time = frame / 30;
            action.time = time;
            mixer.update(0);
            update(0, time, true);
            root.updateMatrixWorld(true);
            inverse.copy(root.matrixWorld).invert();
            frames.push(Object.fromEntries(authoring.rawBones.map((bone) => [bone.name, inverse.clone().multiply(bone.matrixWorld).toArray()])));
          }
          result.clips.push({ name: clip.name, duration: clip.duration, frames });
        }
        mixer.stopAllAction(); mixer.uncacheRoot(root);
        return result;
      } finally { handle.release(); }
    }, bodyId);
    await writeFile(`${destination}/${bodyId}-controls.json`, JSON.stringify(data));
    console.log(`${bodyId}: ${Object.keys(data.sourceRest).length} source joints, ${data.clips.map((clip) => `${clip.name} ${clip.frames.length} frames`).join(', ')}`);
  }
} finally {
  await browser.close();
}
