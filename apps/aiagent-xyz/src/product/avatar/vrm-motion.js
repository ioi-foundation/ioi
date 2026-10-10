import { AnimationClip, Quaternion, QuaternionKeyframeTrack, Vector3, VectorKeyframeTrack } from 'three';
import { choreography, sampleFootwork } from './choreography.js';

const v = (x, y, z) => new Vector3(x, y, z);
const clamp = (n) => Math.max(0, Math.min(1, n));
const ease = (n) => { const t = clamp(n); return t * t * (3 - 2 * t); };

function solve(a, target, pole, upper, lower) {
  const direction = target.clone().sub(a);
  const distance = Math.max(Math.abs(upper - lower) + .00001, Math.min(direction.length(), upper + lower - .00001));
  direction.normalize();
  const along = (upper * upper - lower * lower + distance * distance) / (2 * distance);
  const bend = pole.clone().sub(a);
  bend.addScaledVector(direction, -bend.dot(direction)).normalize();
  return [a.clone().addScaledVector(direction, along).addScaledVector(bend, Math.sqrt(Math.max(0, upper * upper - along * along))), a.clone().addScaledVector(direction, distance)];
}

// Bake against the imported avatar's actual limb lengths and normalized rest
// transforms. The runtime then uses ordinary independent AnimationMixer clips.
export function bakeVrmMotion(vrm, profile) {
  const names = Object.keys(vrm.humanoid.normalizedHumanBones);
  const bones = Object.fromEntries(names.map((name) => [name, vrm.humanoid.getNormalizedBoneNode(name)]));
  vrm.scene.updateMatrixWorld(true);
  const rest = Object.fromEntries(names.map((name) => [name, {
    position: bones[name].getWorldPosition(new Vector3()),
    rotation: bones[name].getWorldQuaternion(new Quaternion()),
    localPosition: bones[name].position.clone(),
    localRotation: bones[name].quaternion.clone(),
  }]));
  const end = { hips: 'spine', spine: 'chest', chest: 'upperChest', upperChest: 'neck', neck: 'head' };
  for (const side of ['left', 'right']) {
    Object.assign(end, { [`${side}Shoulder`]: `${side}UpperArm`, [`${side}UpperArm`]: `${side}LowerArm`, [`${side}LowerArm`]: `${side}Hand`, [`${side}Hand`]: `${side}MiddleProximal`, [`${side}UpperLeg`]: `${side}LowerLeg`, [`${side}LowerLeg`]: `${side}Foot`, [`${side}Foot`]: `${side}Toes` });
    for (const finger of ['Index', 'Middle', 'Ring', 'Little']) {
      end[`${side}${finger}Proximal`] = `${side}${finger}Intermediate`;
      end[`${side}${finger}Intermediate`] = `${side}${finger}Distal`;
    }
    end[`${side}ThumbMetacarpal`] = `${side}ThumbProximal`;
    end[`${side}ThumbProximal`] = `${side}ThumbDistal`;
  }
  const aim = (name, direction) => {
    const bone = bones[name];
    if (!bone || !end[name] || !rest[end[name]]) return;
    const initial = rest[end[name]].position.clone().sub(rest[name].position).normalize();
    const world = new Quaternion().setFromUnitVectors(initial, direction.clone().normalize()).multiply(rest[name].rotation);
    bone.quaternion.copy(bone.parent.getWorldQuaternion(new Quaternion()).invert().multiply(world));
    bone.updateWorldMatrix(false, true);
  };
  const origin = (name) => bones[name].getWorldPosition(new Vector3());
  const length = (name) => rest[name].position.distanceTo(rest[end[name]].position);
  const height = rest.head.position.y;
  const scale = height / 1.58;
  const clips = [];
  const palms = {};
  for (const [side, sign] of [['left', 1], ['right', -1]]) {
    const index = rest[`${side}IndexProximal`].position.clone().sub(rest[`${side}Hand`].position);
    const little = rest[`${side}LittleProximal`].position.clone().sub(rest[`${side}Hand`].position);
    palms[side] = index.cross(little).normalize().multiplyScalar(-sign);
  }
  const coat = [];
  const hair = [];
  vrm.scene.traverse((node) => {
    const match = /^coat_(\d+)_(upper|lower)$/.exec(node.name);
    if (match) coat.push({ node, panel: Number(match[1]), lower: match[2] === 'lower', rotation: node.quaternion.clone(), world: node.getWorldQuaternion(new Quaternion()) });
    const strand = /^J_Sec_Hair(\d+)_(\d+)$/.exec(node.name);
    if (strand) hair.push({ node, depth: Number(strand[1]), strand: Number(strand[2]), rotation: node.quaternion.clone(), world: node.getWorldQuaternion(new Quaternion()) });
  });
  const feet = ['left', 'right'].map((side) => ({ side, node: vrm.humanoid.getRawBoneNode(`${side}Foot`) }));
  for (const foot of feet) foot.scale = foot.node.scale.clone();

  const pose = (time, mode) => {
    for (const name of names) {
      bones[name].position.copy(rest[name].localPosition);
      bones[name].quaternion.copy(rest[name].localRotation);
    }
    const duration = mode === 'entrance' ? 2 : 4;
    const restPose = mode === 'idle' || mode === 'settle';
    const relaxation = mode === 'idle' ? 1 : mode === 'settle' ? ease(time / 1.2) : 0;
    const phase = restPose ? 0 : time / duration;
    const air = mode === 'entrance' && time < 1.6 ? Math.sin(Math.PI * time / 1.6) ** 2 : 0;
    const root = v(-Math.sin(phase * Math.PI * 2) * .045, -.050 + (1 - Math.cos(phase * Math.PI * 4)) * .01 + air * .30, -(1 - Math.cos(phase * Math.PI * 4)) * .025).multiplyScalar(scale);
    if (mode === 'idle') root.y += Math.sin(time * Math.PI / 2) * .003 * scale;
    if (mode === 'entrance') root.x -= .8 * (1 - clamp(time / 2)) ** 2;
    const hipsWorld = rest.hips.position.clone().add(root);
    bones.hips.position.copy(bones.hips.parent.worldToLocal(hipsWorld));
    const strut = Math.sin(phase * Math.PI * 2 - choreography.strutLag) * (1 - relaxation) * (1 - air);
    const torsoYaw = strut * choreography.torsoTwist, hipYaw = -strut * choreography.hipTwist;
    bones.hips.quaternion.multiply(new Quaternion().setFromAxisAngle(v(0, 1, 0), hipYaw));
    bones.spine.quaternion.multiply(new Quaternion().setFromAxisAngle(v(0, 0, 1), Math.sin(phase * Math.PI * 2) * .045 - air * .25));
    bones.spine.quaternion.multiply(new Quaternion().setFromAxisAngle(v(0, 1, 0), torsoYaw * .5 - hipYaw));
    bones.chest.quaternion.multiply(new Quaternion().setFromAxisAngle(v(0, 1, 0), torsoYaw * .5));
    // Keep the gaze/cup stable while the shoulder line turns through the step.
    bones.neck.quaternion.multiply(new Quaternion().setFromAxisAngle(v(0, 1, 0), -torsoYaw * .8));
    bones.hips.updateWorldMatrix(false, true);
    const kicks = {};
    for (const [side, sign] of [['left', 1], ['right', -1]]) {
      const upper = `${side}UpperLeg`, lower = `${side}LowerLeg`, foot = `${side}Foot`;
      const local = (phase + (side === 'left' ? 0 : .5)) % 1;
      const { forward, lift, kick, outward } = sampleFootwork(local, restPose);
      kicks[side] = { lift, kick };
      const a = origin(upper);
      const target = rest[foot].position.clone().add(v(sign * (choreography.stanceWidth + outward), lift, forward).multiplyScalar(scale));
      if (air) target.lerp(v(sign * (side === 'left' ? .74 : .83), (side === 'left' ? .47 : .96), .14).multiplyScalar(scale).add(root), air);
      const [knee, ankle] = solve(a, target, a.clone().add(v(sign * choreography.kneeOut, .12, choreography.kneeForward)), length(upper), length(lower));
      aim(upper, knee.clone().sub(a));
      aim(lower, ankle.clone().sub(knee));
      const footDirection = rest[end[foot]].position.clone().sub(rest[foot].position);
      footDirection.applyAxisAngle(v(1, 0, 0), -(kick * 1.35 + air * .2));
      aim(foot, footDirection);
      // Apply turnout as a world-space yaw after pitch so a grounded sole
      // remains level instead of rolling onto its outside edge.
      const footWorld = bones[foot].getWorldQuaternion(new Quaternion());
      footWorld.premultiply(new Quaternion().setFromAxisAngle(v(0, 1, 0), sign * choreography.turnout * (1 - kick * .7) * (1 - air)));
      bones[foot].quaternion.copy(bones[foot].parent.getWorldQuaternion(new Quaternion()).invert().multiply(footWorld));
      bones[foot].updateWorldMatrix(false, true);
      const arm = `${side}UpperArm`, forearm = `${side}LowerArm`, hand = `${side}Hand`;
      const shoulder = origin(arm);
      const mouth = origin('head').add(v(...profile.mouth).multiplyScalar(scale));
      const pump = restPose ? 0 : Math.max(0, Math.sin(phase * Math.PI * 2)) ** 2;
      const wristTarget = side === 'right'
        ? mouth.clone().add(v(...profile.wrist).multiplyScalar(scale)).lerp(origin('head').add(v(-.15, .36, .04).multiplyScalar(scale)), air)
        : rest.hips.position.clone().add(root).add(v(.25, .13 + pump * .62, .10).multiplyScalar(scale)).lerp(rest.hips.position.clone().add(root).add(v(-.32, -.05, .34).multiplyScalar(scale)), air);
      wristTarget.add(v(side === 'right' ? 0 : -.04, side === 'right' ? -.22 : -.10, side === 'right' ? .06 : 0).multiplyScalar(relaxation * scale));
      const [elbow, wrist] = solve(shoulder, wristTarget, shoulder.clone().add(v(sign * .7, -.12, .15)), length(arm), length(forearm));
      aim(arm, elbow.clone().sub(shoulder));
      aim(forearm, wrist.clone().sub(elbow));
      aim(hand, side === 'right' ? v(1, 0, .08) : v(0, .8, .6).lerp(v(-.8, -.35, .3), air));
      if (side === 'right') {
        const world = bones[hand].getWorldQuaternion(new Quaternion());
        world.premultiply(new Quaternion().setFromAxisAngle(v(1, 0, .08).normalize(), profile.wristRoll ?? Math.PI / 2));
        bones[hand].quaternion.copy(bones[hand].parent.getWorldQuaternion(new Quaternion()).invert().multiply(world));
        bones[hand].updateWorldMatrix(false, true);
      }
      for (const finger of ['Index', 'Middle', 'Ring', 'Little']) {
        for (const [segment, curl] of [['Proximal', 1.05], ['Intermediate', 1.4], ['Distal', .95]]) {
          const node = bones[`${side}${finger}${segment}`];
          if (node) {
            const key = `${side}${finger}${segment}`;
            const initial = rest[end[key] || `${side}${finger}Distal`].position.clone().sub(rest[key].position);
            if (initial.lengthSq() < .000001) initial.copy(rest[`${side}${finger}Distal`].position).sub(rest[`${side}${finger}Intermediate`].position);
            const restAxis = initial.normalize().cross(palms[side]).normalize().applyQuaternion(rest[key].rotation.clone().invert());
            node.quaternion.multiply(new Quaternion().setFromAxisAngle(restAxis, curl * (side === 'left' ? 1 - air * .85 : 1)));
          }
        }
      }
      bones[hand].updateWorldMatrix(false, true);
      const palm = palms[side].clone().applyQuaternion(rest[hand].rotation.clone().invert()).applyQuaternion(bones[hand].getWorldQuaternion(new Quaternion()));
      aim(`${side}ThumbMetacarpal`, origin(`${side}IndexProximal`).addScaledVector(palm, .021).sub(origin(`${side}ThumbMetacarpal`)));
      aim(`${side}ThumbProximal`, origin(`${side}IndexIntermediate`).addScaledVector(palm, .012).sub(origin(`${side}ThumbProximal`)));
    }
    for (const control of coat) {
      const angle = (control.panel + .5) * Math.PI * 2 / profile.coatPanels;
      const side = Math.sin(angle) > 0 ? 'left' : 'right';
      const { lift } = kicks[side];
      const front = Math.max(0, Math.cos(angle));
      const raise = lift / .7;
      const sway = Math.sin(phase * Math.PI * 2 - .5) * .09 * (1 - relaxation);
      // During the split, open the garment radially around the hips. Sending
      // every panel forward folded the back lining through the underdress,
      // and left the front panels across the abducted thighs at takeoff.
      const forward = (front * raise * 1.8 * (1 - air) + air * Math.cos(angle) * profile.entranceCoatSpread) * (control.lower ? -.42 : 1) * profile.coatAmplitude;
      const sideways = (Math.sign(Math.sin(angle)) * raise * .55 * (1 - air) + air * Math.sin(angle) * profile.entranceCoatSpread + sway * (1 - air)) * (control.lower ? -.25 : 1);
      const x = v(1, 0, 0).applyQuaternion(control.world.clone().invert());
      const z = v(0, 0, 1).applyQuaternion(control.world.clone().invert());
      control.node.quaternion.copy(control.rotation)
        .multiply(new Quaternion().setFromAxisAngle(x, -forward))
        .multiply(new Quaternion().setFromAxisAngle(z, sideways));
    }
    for (const foot of feet) {
      const exaggeration = kicks[foot.side].kick;
      foot.node.scale.copy(foot.scale).multiply(v(1 + exaggeration * profile.kickScale, 1 + exaggeration * .25, 1 + exaggeration * profile.kickScale));
    }
    for (const control of hair) {
      const amplitude = control.strand > 4 ? .065 : .015;
      const wave = Math.sin((mode === 'idle' ? time / 4 : phase) * Math.PI * 2 - .65 - control.depth * .30);
      const axis = v(0, 0, 1).applyQuaternion(control.world.clone().invert());
      control.node.quaternion.copy(control.rotation).multiply(new Quaternion().setFromAxisAngle(axis, wave * amplitude * (1 - relaxation * .75)));
    }
    vrm.scene.updateMatrixWorld(true);
  };

  for (const [mode, duration] of [['cup-kick', 4], ['entrance', 2], ['settle', 1.2], ['idle', 4]]) {
    const times = [], values = Object.fromEntries(names.map((name) => [name, []])), positions = [];
    const coatValues = coat.map(() => []), footValues = feet.map(() => []), hairValues = hair.map(() => []);
    for (let frame = 0; frame <= duration * 30; frame++) {
      times.push(frame / 30);
      pose(frame / 30, mode);
      for (const name of names) bones[name].quaternion.toArray(values[name], values[name].length);
      bones.hips.position.toArray(positions, positions.length);
      coat.forEach((control, i) => control.node.quaternion.toArray(coatValues[i], coatValues[i].length));
      feet.forEach((foot, i) => foot.node.scale.toArray(footValues[i], footValues[i].length));
      hair.forEach((control, i) => control.node.quaternion.toArray(hairValues[i], hairValues[i].length));
    }
    const tracks = names.map((name) => new QuaternionKeyframeTrack(`${bones[name].uuid}.quaternion`, times, values[name]));
    tracks.push(new VectorKeyframeTrack(`${bones.hips.uuid}.position`, times, positions));
    coat.forEach((control, i) => tracks.push(new QuaternionKeyframeTrack(`${control.node.uuid}.quaternion`, times, coatValues[i])));
    feet.forEach((foot, i) => tracks.push(new VectorKeyframeTrack(`${foot.node.uuid}.scale`, times, footValues[i])));
    hair.forEach((control, i) => tracks.push(new QuaternionKeyframeTrack(`${control.node.uuid}.quaternion`, times, hairValues[i])));
    clips.push(new AnimationClip(mode, duration, tracks));
  }
  pose(0, 'cup-kick');
  vrm.update(0);
  return { clips, scale };
}
