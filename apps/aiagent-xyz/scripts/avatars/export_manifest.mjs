import { readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { AVATAR_BODIES, AVATAR_RIG, AVATAR_PROPORTIONS } from '../../shared/avatar-catalog.mjs';
import { AVATAR_PARTS, DEFAULT_PARTS } from '../../shared/avatar-parts.mjs';
import { MOTION_PROFILES } from '../../src/product/avatar/motion-profiles.js';

const root = new URL('../../', import.meta.url);
const provenance = JSON.parse(await readFile(new URL('assets/avatars/third-party.json', root), 'utf8'));
const bodies = [];
for (const body of AVATAR_BODIES) {
  const levels = [];
  for (const [quality, asset] of [['desktop', body.asset], ['mobile', body.mobileAsset || body.asset]]) {
    const bytes = await readFile(new URL('public' + asset, root));
    const document = JSON.parse(bytes.subarray(20, 20 + bytes.readUInt32LE(12)).toString());
    const triangles = document.meshes.reduce((sum, mesh) => sum + mesh.primitives.reduce((count, primitive) => count + (document.accessors[primitive.indices ?? primitive.attributes.POSITION].count / 3), 0), 0);
    levels.push({ quality, asset, bytes: bytes.length, sha256: createHash('sha256').update(bytes).digest('hex'), baseTriangles: triangles,
      materials: document.materials.map((material) => material.name), meshes: document.nodes.filter((node) => node.mesh !== undefined).map((node) => node.name),
      animations: document.animations.map((clip) => ({ name: clip.name, duration: Math.max(...clip.samplers.map((sampler) => document.accessors[sampler.input].max[0])) })),
      joints: Math.max(...document.skins.map((skin) => skin.joints.length)) });
  }
  bodies.push({ id: body.id, revision: body.revision, rig: AVATAR_RIG, format: body.format || 'gltf2', fitFamily: `${body.id}-${body.revision}`,
    coordinates: { units: 'metres', up: '+Y', forward: '+Z', normalizedHeadPivotHeight: 1.58 },
    attachments: { rightGrip: { semanticParent: 'rightHand', physicalCupSizeIndependentOfProportion: true, calibration: MOTION_PROFILES[body.id] || 'baked robot grip bone' } },
    capabilities: ['humanoid', 'finger-grip', 'blink', 'expression', 'baked-secondary-motion', 'entrance', 'cup-kick', 'settle', 'idle'],
    proportions: AVATAR_PROPORTIONS, parts: AVATAR_PARTS[body.id], defaultParts: DEFAULT_PARTS,
    fitRules: ['Body-specific slot revisions only', 'Long coat retains its dress and stocking underlayer', 'Cup physical dimensions are independent of height', 'Pinstripe suit uses its original fabric'],
    source: { robot: 'assets/avatars/source/robot-study.blend', human: 'assets/avatars/source/human-motion.blend', anime: 'assets/avatars/source/anime-motion.blend' }[body.id], levels });
}
await writeFile(new URL('public/models/avatars/catalog-v1.json', root), JSON.stringify({ schema: 'aiagent.avatar-assets.v1', bodies, provenance }, null, 2) + '\n');
console.log(bodies.map(({ id, levels }) => ({ id, desktopBytes: levels[0].bytes, desktopTriangles: levels[0].baseTriangles, mobileTriangles: levels[1].baseTriangles })));
