import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { chromium } from 'playwright';

const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
try {
  const page = await browser.newPage();
  await page.goto((process.env.AVATAR_AUTHORING_ORIGIN || 'http://127.0.0.1:5173') + '/avatar-verification');
  const result = await page.evaluate(async () => {
    const T = await import('/node_modules/three/build/three.module.js');
    const { acquireAvatar, avatarCacheState } = await import('/src/product/avatar/asset-cache.js');
    const { createMotionPlayer } = await import('/src/product/avatar/motion-player.js');
    const { createAppearanceAssembly } = await import('/src/product/avatar/appearance-assembly.js');
    const { applyPalette } = await import('/src/product/avatar/appearance-materials.js');
    const { applyAppearanceParts } = await import('/src/product/avatar/appearance-parts.js');
    const expect = (value, message) => { if (!value) throw new Error(message); };
    const pose = (root) => { root.updateMatrixWorld(true); const values = []; root.traverse((node) => { if (node.isBone) values.push(...node.matrixWorld.elements); }); return values; };
    const difference = (a, b) => Math.max(...a.map((value, i) => Math.abs(value - b[i])));
    const reports = [];
    for (const quality of ['desktop', 'mobile']) for (const body of ['robot', 'human', 'anime']) {
      const firstHandle = acquireAvatar(body, { quality }), secondHandle = acquireAvatar(body, { quality });
      const [first, second] = await Promise.all([firstHandle.ready, secondHandle.ready]);
      const firstPlayer = createMotionPlayer(first.root, first.clips), secondPlayer = createMotionPlayer(second.root, second.clips);
      const assembly = createAppearanceAssembly(first.root);
      const rootBones = (root) => { const bones = []; root.traverse((node) => { if (node.isBone) bones.push(node); }); return bones; };
      expect(first.root !== second.root && rootBones(first.root).every((bone) => !rootBones(second.root).includes(bone)), `${body}: shared skeleton`);
      expect([...first.materials].every((material) => !second.materials.has(material)), `${body}: shared material`);
      const unchanged = pose(second.root);
      firstPlayer.seek(1.28); first.update?.(0, 1.28, true);
      expect(difference(unchanged, pose(second.root)) < 1e-9 && secondPlayer.getState().time === 0, `${body}: pose leaked to second instance`);
      const secondColors = [...second.materials].map((material) => material.color?.getHex());
      applyPalette(first.materials, 'ocean');
      expect([...second.materials].every((material, index) => material.color?.getHex() === secondColors[index]), `${body}: palette leaked`);
      applyAppearanceParts(second, { body });
      const secondVisibility = []; second.root.traverse((node) => secondVisibility.push(node.visible));
      const secondMaterialVisibility = [...second.materials].map((material) => material.visible);
      applyAppearanceParts(first, { body, parts: { hair: body === 'robot' ? 'headset-v1' : body === 'human' ? 'shaved-v1' : 'unadorned-v1', prop: 'charcoal-v1', face: 'warm-v1' } });
      const currentVisibility = []; second.root.traverse((node) => currentVisibility.push(node.visible));
      expect(JSON.stringify(secondVisibility) === JSON.stringify(currentVisibility) && [...second.materials].every((material, i) => material.visible === secondMaterialVisibility[i]), `${body}: part visibility leaked`);
      const once = pose(first.root);
      firstPlayer.seek(2.8); first.update?.(0, 2.8, true);
      firstPlayer.seek(1.28); first.update?.(0, 1.28, true);
      const seekError = difference(once, pose(first.root));
      expect(seekError < 1e-6, `${body}: nondeterministic seek ${seekError}`);
      firstPlayer.seek(0); first.update?.(0, 0, true); const seam = pose(first.root);
      for (let frame = 0; frame < 4000; frame++) firstPlayer.update(.01);
      first.update?.(0, firstPlayer.getState().time, true);
      const loopError = difference(seam, pose(first.root));
      expect(loopError < .0001, `${body}: accumulated loop drift ${loopError}`);
      const jointPositions = (time) => {
        firstPlayer.seek(time); first.update?.(0, time, true); first.root.updateMatrixWorld(true);
        return rootBones(first.root).flatMap((bone) => bone.getWorldPosition(new T.Vector3()).toArray());
      };
      const start = jointPositions(0), next = jointPositions(1 / 30), next2 = jointPositions(2 / 30);
      const before = jointPositions(4 - 1 / 30), before2 = jointPositions(4 - 2 / 30);
      const velocityError = Math.max(...start.map((x, i) => Math.abs((-3*x + 4*next[i] - next2[i] - (3*x - 4*before[i] + before2[i])) * 15)));
      expect(velocityError < .03, `${body}: loop velocity discontinuity ${velocityError} m/s`);
      const grip = first.root.getObjectByName('rightGrip');
      assembly.apply({ proportion: 'balanced' });
      const cupScale = grip.getWorldScale(new T.Vector3());
      let scaleError = 0;
      for (const proportion of ['compact', 'tall', 'balanced']) {
        firstPlayer.seek(.8); first.update?.(0, .8, true); assembly.apply({ proportion });
        scaleError = Math.max(scaleError, cupScale.distanceTo(grip.getWorldScale(new T.Vector3())));
      }
      expect(scaleError < .00001, `${body}: cup changes physical size ${scaleError}`);
      let secondDisposals = 0;
      const geometries = new Set(); second.root.traverse((node) => { if (node.geometry) geometries.add(node.geometry); });
      for (const geometry of geometries) geometry.addEventListener('dispose', () => secondDisposals++);
      firstPlayer.dispose(); firstHandle.release();
      expect(secondDisposals === 0, `${body}: releasing one avatar destroyed its neighbor`);
      secondPlayer.update(.04); second.update?.(.04, .04); pose(second.root);
      secondPlayer.dispose(); secondHandle.release();
      expect(secondDisposals === geometries.size, `${body}: geometry was not disposed exactly once (${secondDisposals}/${geometries.size})`);
      expect(avatarCacheState().length === 0, `${body}: cache retained a released avatar`);
      reports.push({ body, quality, seekError, loopError, velocityError, scaleError, independentSkeletons: true, independentMaterials: true, independentParts: true, disposedGeometries: secondDisposals });
    }
    const cancelled = acquireAvatar('anime'); cancelled.release();
    await cancelled.ready.then(() => { throw new Error('Cancelled load unexpectedly completed'); }, (error) => { expect(error.name === 'AbortError', `Unexpected cancellation: ${error.message}`); });
    expect(avatarCacheState().length === 0, 'Cancelled load retained cache state');
    return { reports, cancelledLoad: true };
  });
  assert.equal(result.reports.length, 6);
  await writeFile('/tmp/avatar-runtime-validation.json', JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify(result, null, 2));
} finally { await browser.close(); }
