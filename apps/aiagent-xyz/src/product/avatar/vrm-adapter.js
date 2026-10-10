import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { VRMHumanoid, VRMLoaderPlugin, VRMUtils } from '@pixiv/three-vrm';
import { AnimationMixer, Group, LatheGeometry, Mesh, MeshToonMaterial, Quaternion, TorusGeometry, Vector2, Vector3 } from 'three';
import { bakeVrmMotion } from './vrm-motion';
import { MOTION_PROFILES } from './motion-profiles';
import { verifiedModel } from './model-integrity.js';

const buffers = new Map();

export function vrmCacheState() {
  return [...buffers.entries()].map(([asset, entry]) => ({ asset, references: entry.references }));
}

function addCup(vrm, scale, profile) {
  const material = new MeshToonMaterial({ color: 0xfff7e2 });
  material.name = 'porcelain';
  const cup = new Group();
  cup.name = 'rightGrip';
  cup.add(new Mesh(new LatheGeometry([[.025, 0], [.028, .008], [.043, .056], [.041, .062], [.037, .057], [.023, .012]].map(([x, y]) => new Vector2(x, y)), 32), material));
  const handle = new Mesh(new TorusGeometry(.021, .0045, 8, 24), material);
  handle.position.set(-.048, .033, 0);
  cup.add(handle);
  const hand = vrm.humanoid.getRawBoneNode('rightHand');
  const head = vrm.humanoid.getRawBoneNode('head');
  const mouth = head.getWorldPosition(new Vector3()).add(new Vector3(...profile.mouth).add(new Vector3(0, -.062, .035)).multiplyScalar(scale));
  hand.add(cup);
  cup.position.copy(hand.worldToLocal(mouth));
  cup.quaternion.copy(hand.getWorldQuaternion(new Quaternion()).invert());
  // The porcelain has a physical size independent of the head/body preset.
  const worldScale = hand.getWorldScale(new Vector3());
  cup.scale.set(1 / worldScale.x, 1 / worldScale.y, 1 / worldScale.z);
}

export function acquireVrmAvatar(body) {
  let entry = buffers.get(body.asset);
  if (!entry) {
    const controller = new AbortController();
    entry = { references: 0, controller, promise: fetch(body.asset, { signal: controller.signal }).then((response) => {
      if (!response.ok) throw new Error('The avatar model could not be loaded.');
      return response.arrayBuffer();
    }).then((buffer) => verifiedModel(body.asset, buffer)) };
    buffers.set(body.asset, entry);
  }
  entry.references++;
  let released = false;
  let vrm = null;
  const release = () => {
    if (released) return;
    released = true;
    if (vrm) {
      // Palette choices temporarily detach the original clothing atlas. Put
      // it back before disposal so it remains part of the owned texture graph.
      vrm.scene.traverse((node) => {
        for (const material of node.material ? (Array.isArray(node.material) ? node.material : [node.material]) : []) {
          if (Object.hasOwn(material.userData, 'originalMap')) material.map = material.userData.originalMap;
        }
      });
      VRMUtils.deepDispose(vrm.scene);
    }
    entry.references--;
    if (!entry.references) {
      entry.controller.abort();
      if (buffers.get(body.asset) === entry) buffers.delete(body.asset);
    }
  };
  const ready = entry.promise.then(async (buffer) => {
    if (released) throw new DOMException('Avatar load cancelled', 'AbortError');
    // Parse per instance: VRM expression, spring, constraint and humanoid
    // managers retain object references and cannot share a cloned manager.
    const loader = new GLTFLoader();
    if (body.format === 'vrm1') loader.register((parser) => new VRMLoaderPlugin(parser));
    const gltf = await loader.parseAsync(buffer, '/models/avatars/');
    vrm = gltf.userData.vrm;
    if (body.format === 'humanoid-glb') {
      let mapping;
      gltf.scene.traverse((node) => {
        if (node.userData.humanoidBones) mapping = JSON.parse(node.userData.humanoidBones);
      });
      if (!mapping) {
        VRMUtils.deepDispose(gltf.scene);
        throw new Error('The body is missing its humanoid mapping.');
      }
      const bones = Object.fromEntries(Object.entries(mapping).map(([name, nodeName]) => [name, { node: gltf.scene.getObjectByName(nodeName) }]));
      if (Object.values(bones).some(({ node }) => !node)) {
        VRMUtils.deepDispose(gltf.scene);
        throw new Error('The body has an incomplete humanoid mapping.');
      }
      gltf.scene.updateMatrixWorld(true);
      const humanoid = new VRMHumanoid(bones);
      gltf.scene.add(humanoid.normalizedHumanBonesRoot);
      const expressions = [];
      gltf.scene.traverse((node) => {
        if (node.morphTargetDictionary) expressions.push(node);
      });
      const setExpression = (name, weight) => {
        const targets = name === 'blink' ? ['eyeBlinkLeft', 'eyeBlinkRight']
          : name === 'relaxed' ? ['mouthSmileLeft', 'mouthSmileRight'] : [];
        for (const node of expressions) for (const target of targets) {
          const index = node.morphTargetDictionary[target];
          if (index !== undefined) node.morphTargetInfluences[index] = weight;
        }
      };
      vrm = { scene: gltf.scene, humanoid, setExpression, update: () => { if (humanoid.autoUpdateHumanBones) humanoid.update(); } };
    }
    if (!vrm || (body.format === 'vrm1' && vrm.meta.metaVersion !== '1')) {
      VRMUtils.deepDispose(gltf.scene);
      vrm = null;
      throw new Error('Only verified VRM 1.0 avatars are supported.');
    }
    if (released) {
      VRMUtils.deepDispose(vrm.scene);
      vrm = null;
      throw new DOMException('Avatar load cancelled', 'AbortError');
    }
    VRMUtils.combineSkeletons(vrm.scene);
    if (vrm.expressionManager) VRMUtils.combineMorphs(vrm);
    const head = vrm.humanoid.getNormalizedBoneNode('head');
    vrm.scene.updateMatrixWorld(true);
    const normalized = new Set(Object.values(vrm.humanoid.normalizedHumanBones).map(({ node }) => node));
    const rawBones = [];
    vrm.scene.traverse((node) => { if (node.isBone && !normalized.has(node)) rawBones.push(node); });
    const sourceRest = Object.fromEntries(rawBones.map((node) => [node.name, node.matrixWorld.toArray()]));
    // The authored reference clips carry deterministic hair tracks. General
    // real-time spring behavior is intentionally separate from these clips.
    vrm.springBoneManager = undefined;
    const height = head.getWorldPosition(new Vector3()).y;
    vrm.scene.scale.setScalar(1.58 / height);
    vrm.scene.updateMatrixWorld(true);
    const profile = MOTION_PROFILES[body.id];
    let clips, scale, setup;
    if (gltf.animations.length) {
      clips = gltf.animations;
      scale = 1;
      vrm.humanoid.autoUpdateHumanBones = false;
      setup = new AnimationMixer(vrm.scene);
      const action = setup.clipAction(clips.find((clip) => clip.name === 'cup-kick'));
      action.play(); setup.update(0);
      vrm.scene.updateMatrixWorld(true);
    } else ({ clips, scale } = bakeVrmMotion(vrm, profile));
    vrm.scene.position.y += profile.groundOffset;
    vrm.scene.updateMatrixWorld(true);
    addCup(vrm, scale, profile);
    setup?.stopAllAction();
    setup?.uncacheRoot(vrm.scene);
    const materials = new Set();
    vrm.scene.traverse((node) => {
      if (!node.isMesh) return;
      node.frustumCulled = false;
      node.castShadow = true;
      for (const material of Array.isArray(node.material) ? node.material : [node.material]) {
        material.userData.originalColor = material.color?.clone();
        materials.add(material);
      }
    });
    let expression = 'composed';
    const setExpression = (value) => { expression = value; };
    const update = (delta, time, reset = false) => {
      if (reset) {
        if (vrm.humanoid.autoUpdateHumanBones) vrm.humanoid.update();
        vrm.scene.updateMatrixWorld(true);
        vrm.springBoneManager?.reset();
      }
      // Repeatable facial timing also works while seeking a paused clip.
      const blinkPhase = time % 4;
      const blink = Math.max(0, 1 - Math.abs(blinkPhase - 2.8) / .085);
      vrm.expressionManager?.setValue('blink', blink);
      vrm.expressionManager?.setValue('relaxed', expression === 'warm' ? .45 : .10);
      vrm.expressionManager?.setValue('happy', expression === 'warm' ? .15 : 0);
      vrm.setExpression?.('blink', blink);
      vrm.setExpression?.('relaxed', expression === 'warm' ? .60 : .08);
      vrm.update(Math.min(Math.max(delta, 0), .033));
    };
    return { root: vrm.scene, clips, materials, update, setExpression, authoring: { vrm, rawBones, sourceRest } };
  });
  return { ready, release };
}
