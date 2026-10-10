import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { DRACOLoader } from 'three/addons/loaders/DRACOLoader.js';
import { clone } from 'three/addons/utils/SkeletonUtils.js';
import { FrontSide } from 'three';
import { AVATAR_BODIES, AVATAR_RIG } from '../../../shared/avatar-catalog.mjs';
import { acquireVrmAvatar, vrmCacheState } from './vrm-adapter';
import { createHologramMaterial } from './hologram-material';

const entries = new Map();

function disposeOriginal(root) {
  const geometries = new Set();
  const materials = new Set();
  const textures = new Set();
  root.traverse((node) => {
    if (node.geometry) geometries.add(node.geometry);
    for (const material of node.material ? (Array.isArray(node.material) ? node.material : [node.material]) : []) {
      materials.add(material);
      for (const value of Object.values(material)) if (value?.isTexture) textures.add(value);
    }
    node.skeleton?.dispose();
  });
  geometries.forEach((item) => item.dispose());
  materials.forEach((item) => item.dispose());
  textures.forEach((item) => item.dispose());
}

export function acquireAvatar(bodyId, { quality = 'desktop' } = {}) {
  const selected = AVATAR_BODIES.find((item) => item.id === bodyId);
  if (!selected) throw new Error('Unknown avatar body.');
  const body = quality === 'mobile' && selected.mobileAsset ? { ...selected, asset: selected.mobileAsset } : selected;
  if (body.format === 'vrm1' || body.format === 'humanoid-glb') return acquireVrmAvatar(body);
  let entry = entries.get(body.asset);
  if (!entry) {
    const controller = new AbortController();
    const draco = new DRACOLoader();
    draco.setDecoderPath('/draco/');
    draco.setDecoderConfig({ type: 'js' });
    draco.setWorkerLimit(1);
    const loader = new GLTFLoader().setDRACOLoader(draco);
    entry = { references: 0, controller, original: null, draco };
    const created = entry;
    created.promise = fetch(body.asset, { signal: controller.signal })
      .then((response) => {
        if (!response.ok) throw new Error('The avatar model could not be loaded.');
        return response.arrayBuffer();
      })
      .then((buffer) => loader.parseAsync(buffer, '/models/avatars/'))
      .then((gltf) => {
        const rigs = [];
        gltf.scene.traverse((node) => { if (node.userData.rigVersion) rigs.push(node); });
        if (!rigs.some((node) => node.userData.rigVersion === AVATAR_RIG)) {
          disposeOriginal(gltf.scene);
          throw new Error('This avatar has an unsupported rig.');
        }
        created.original = gltf;
        if (created.references === 0) {
          disposeOriginal(gltf.scene);
          created.original = null;
          draco.dispose();
          throw new DOMException('Avatar load cancelled', 'AbortError');
        }
        return gltf;
      });
    entries.set(body.asset, created);
  }
  entry.references += 1;
  let released = false;
  let instance = null;
  const instanceMaterials = new Set();
  const finishes = [];

  const release = () => {
    if (released) return;
    released = true;
    instanceMaterials.forEach((material) => material.dispose());
    instance?.traverse((node) => node.skeleton?.dispose());
    entry.references -= 1;
    if (entry.references === 0) {
      if (entries.get(body.asset) === entry) entries.delete(body.asset);
      entry.controller.abort();
      if (entry.original) disposeOriginal(entry.original.scene);
      // A worker that is still decoding must finish before it can be disposed.
      entry.promise.finally(() => entry.draco.dispose()).catch(() => {});
    }
  };

  const ready = entry.promise.then((gltf) => {
    if (released) throw new DOMException('Avatar load cancelled', 'AbortError');
    instance = clone(gltf.scene);
    instance.traverse((node) => {
      if (!node.isMesh) return;
      const copy = (material) => {
        const result = material.clone();
        if (body.id === 'robot' && ['shell', 'mechanism'].includes(material.name)) {
          const shell = material.name === 'shell';
          result.color.set(shell ? 0xe9e3d7 : 0x34414b);
          result.metalness = shell ? .12 : .65;
          result.roughness = shell ? .34 : .46;
          result.side = FrontSide;
          const etched = createHologramMaterial(material.name);
          etched.userData.originalColor = etched.color.clone();
          instanceMaterials.add(etched);
          result.userData.etched = etched;
        }
        result.userData.originalColor = result.color?.clone();
        instanceMaterials.add(result);
        return result;
      };
      node.material = Array.isArray(node.material) ? node.material.map(copy) : copy(node.material);
      finishes.push({ node, material: node.material });
      node.castShadow = true;
      // The shell contains closely layered panels. Receiving a coarse shadow
      // map on those surfaces produces false black seams and finger speckles.
      // Keep their authored shading; the studio floor still receives shadows.
      node.receiveShadow = false;
      // Bounds vary dramatically during the kick; the stage frames the whole
      // authored motion envelope, so a stale bind-pose bound must not cull it.
      node.frustumCulled = false;
    });
    let expression = 'composed';
    const setExpression = (value) => { expression = value; };
    const update = (_delta, time) => {
      const blink = Math.max(0, 1 - Math.abs(time % 4 - 2.8) / .085);
      for (const material of instanceMaterials) {
        if (material.uniforms?.time) material.uniforms.time.value = time;
        if (material.name === 'eyes') material.emissiveIntensity = (expression === 'warm' ? 1.8 : .7) * (1 - blink);
      }
    };
    const setFinish = (finish) => {
      const choose = (material) => finish === 'etched' ? material.userData.etched || material : material;
      for (const entry of finishes) entry.node.material = Array.isArray(entry.material) ? entry.material.map(choose) : choose(entry.material);
    };
    return { root: instance, clips: gltf.animations, materials: instanceMaterials, update, setFinish, setExpression };
  });
  return { ready, release };
}

export function avatarCacheState() {
  return [...entries.entries()].map(([asset, entry]) => ({ asset, references: entry.references, loaded: Boolean(entry.original) })).concat(vrmCacheState());
}
