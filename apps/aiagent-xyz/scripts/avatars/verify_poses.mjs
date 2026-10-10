import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import { chromium } from 'playwright';

const browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
try {
  const page = await browser.newPage();
  await page.goto((process.env.AVATAR_AUTHORING_ORIGIN || 'http://127.0.0.1:5173') + '/avatar-verification');
  const report = await page.evaluate(async () => {
    const T = await import('/node_modules/three/build/three.module.js');
    const { acquireAvatar } = await import('/src/product/avatar/asset-cache.js');
    const { createMotionPlayer } = await import('/src/product/avatar/motion-player.js');
    const { createAppearanceAssembly } = await import('/src/product/avatar/appearance-assembly.js');
    const { avatarFraming, interpolateCameraPosition } = await import('/src/product/avatar/scene-framing.js');
    const cases = [], failures = [], contacts = [], strut = [];
    const camera = new T.PerspectiveCamera(48, 1, .05, 30), point = new T.Vector3();
    for (const quality of ['desktop', 'mobile']) for (const body of ['robot', 'human', 'anime']) {
      const handle = acquireAvatar(body, { quality }); const avatar = await handle.ready;
      const player = createMotionPlayer(avatar.root, avatar.clips), assembly = createAppearanceAssembly(avatar.root);
      const bone = (name) => avatar.authoring?.vrm.humanoid.getRawBoneNode(name) || avatar.root.getObjectByName(name);
      const foot = (side) => bone(`${side}Foot`);
      for (const proportion of ['compact', 'tall']) {
        player.select('cup-kick', { blend: 0 }); player.seek(0); avatar.update?.(0, 0, true); assembly.apply({ proportion });
        // Sliding backward is authored choreography, not a contact defect.
        // Check the delivered bones: substantial monotonic travel, constant
        // contact height/lateral position, level orientation and outward knees.
        for (const [support, offset] of [['right', 0], ['left', 2]]) {
          const samples = [];
          for (let frame = 0; frame <= 24; frame++) {
            const time = offset + .4 + frame * 1.52 / 24;
            player.seek(time); avatar.update?.(0, time, true); assembly.apply({ proportion });
            samples.push({ position: foot(support).getWorldPosition(new T.Vector3()), rotation: foot(support).getWorldQuaternion(new T.Quaternion()) });
          }
          const initial = samples[0], final = samples.at(-1);
          const contactHeightError = Math.max(...samples.map((s) => Math.abs(s.position.y - initial.position.y)));
          const lateralError = Math.max(...samples.map((s) => Math.abs(s.position.x - initial.position.x)));
          const rotationError = Math.max(...samples.map((s) => s.rotation.angleTo(initial.rotation)));
          const backwardTravel = initial.position.z - final.position.z;
          const reversal = Math.max(0, ...samples.slice(1).map((s, i) => s.position.z - samples[i].position.z));
          const swing = support === 'right' ? 'left' : 'right', sign = swing === 'left' ? 1 : -1;
          const time = offset + .856;
          player.seek(time); avatar.update?.(0, time, true); assembly.apply({ proportion });
          const kneeOpening = sign * (bone(`${swing}LowerLeg`).getWorldPosition(new T.Vector3()).x - bone(`${swing}UpperLeg`).getWorldPosition(new T.Vector3()).x);
          const item = { body, quality, proportion, support, backwardTravel, contactHeightError, lateralError, rotationError, reversal, kneeOpening };
          contacts.push(item);
          if (backwardTravel < .10 || backwardTravel > .25 || contactHeightError > .002 || lateralError > .002 || rotationError > .01 || reversal > .001 || kneeOpening < .14) failures.push(item);
        }
        const turns = [1, 3].map((time) => {
          player.seek(time); avatar.update?.(0, time, true); assembly.apply({ proportion });
          const line = (joint) => bone(`left${joint}`).getWorldPosition(new T.Vector3()).sub(bone(`right${joint}`).getWorldPosition(new T.Vector3()));
          const shoulder = line('UpperArm'), hips = line('UpperLeg');
          return { shoulder: Math.atan2(shoulder.z, shoulder.x), hips: Math.atan2(hips.z, hips.x) };
        });
        const shoulderTurn = turns[1].shoulder - turns[0].shoulder, hipTurn = turns[1].hips - turns[0].hips;
        const upperBody = { body, quality, proportion, shoulderTurn, hipTurn };
        strut.push(upperBody);
        if (Math.abs(shoulderTurn) < .20 || Math.abs(shoulderTurn) > .40 || shoulderTurn * hipTurn >= 0) failures.push(upperBody);
        for (const [motion, time] of [['cup-kick', 0], ['cup-kick', .856], ['cup-kick', 1.28], ['cup-kick', 3.28], ['entrance', 0], ['entrance', .45], ['entrance', .6], ['entrance', .8], ['entrance', 1], ['entrance', 1.25], ['entrance', 1.5], ['entrance', 2], ['idle', 0]]) {
          player.select(motion, { blend: 0 }); player.seek(time); avatar.update?.(0, time, true); assembly.apply({ proportion });
          const vertices = [];
          avatar.root.traverseVisible((node) => {
            if (!node.isMesh) return;
            for (let i = 0; i < node.geometry.attributes.position.count; i++) {
              node.getVertexPosition(i, point); point.applyMatrix4(node.matrixWorld); vertices.push(point.x, point.y, point.z);
            }
          });
          for (const view of ['front', 'quarter', 'side', 'orbit-25', 'orbit-50', 'orbit-75']) for (const aspect of [1080 / 570, 358 / 440]) {
            const framing = avatarFraming(view.startsWith('orbit-') ? 'front' : view, motion, aspect);
            if (view.startsWith('orbit-')) {
              const side = avatarFraming('side', motion, aspect);
              const weight = Number(view.split('-')[1]) / 100;
              framing.position = interpolateCameraPosition(framing.position, side.position, weight, motion, aspect);
              framing.target = framing.target.map((value, i) => value * (1 - weight) + side.target[i] * weight);
            }
            camera.aspect = aspect; camera.position.fromArray(framing.position); camera.lookAt(...framing.target); camera.updateProjectionMatrix(); camera.updateMatrixWorld(true);
            let maximum = 0;
            for (let i = 0; i < vertices.length; i += 3) {
              point.fromArray(vertices, i).project(camera); maximum = Math.max(maximum, Math.abs(point.x), Math.abs(point.y));
            }
            const item = { body, quality, proportion, motion, time, view, aspect, maximumNdc: maximum };
            cases.push(item); if (maximum > .98) failures.push(item);
          }
        }
      }
      player.dispose(); handle.release();
    }
    return { cases, contacts, strut, failures };
  });
  await writeFile('/tmp/avatar-pose-validation.json', JSON.stringify(report, null, 2) + '\n');
  console.log(JSON.stringify({ cases: report.cases.length, contacts: report.contacts, strut: report.strut, failures: report.failures }, null, 2));
  assert.equal(report.failures.length, 0, 'Pose qualification found framing or ground-contact failures');
} finally { await browser.close(); }
