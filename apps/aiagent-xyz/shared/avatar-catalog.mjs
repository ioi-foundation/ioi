import { DEFAULT_PARTS, validateParts, partSignature } from './avatar-parts.mjs';

// Product presentation only. These choices do not change worker identity,
// package admission, capabilities, runtime placement, or authority.
export const AVATAR_SCHEMA = 'aiagent.appearance.v1';
export const AVATAR_RIG = 'humanoid-v1';

export const AVATAR_BODIES = Object.freeze([
  { id: 'robot', label: 'Cyborg', asset: '/models/avatars/robot-study-v1.glb', mobileAsset: '/models/avatars/robot-study-mobile-v1.glb', revision: 'study-v1', description: 'Articulated mechanical body', paletteSlots: ['shell', 'mechanism'], finishes: [{ id: 'ceramic', label: 'Porcelain' }, { id: 'etched', label: 'Etched glass' }] },
  { id: 'human', label: 'Human', asset: '/models/avatars/human-performance-v1.glb', mobileAsset: '/models/avatars/human-performance-mobile-v1.glb', sourceAsset: '/__avatar-authoring/human-authored-v1.glb', format: 'humanoid-glb', revision: 'performance-v1', description: 'Tailored jacket and trousers', paletteSlots: ['jacket', 'trousers', 'skin', 'hair'], finishes: [{ id: 'natural', label: 'Natural' }] },
  { id: 'anime', label: 'Anime', asset: '/models/avatars/anime-performance-baked-v1.vrm', mobileAsset: '/models/avatars/anime-performance-baked-mobile-v1.vrm', sourceAsset: '/__avatar-authoring/anime-performance-v1.vrm', format: 'vrm1', revision: 'performance-v1', description: 'Lined performance coat and boots', paletteSlots: ['coat', 'trousers', 'skin', 'hair'], finishes: [{ id: 'cel', label: 'Cel' }] },
]);

export const AVATAR_MOTIONS = Object.freeze([
  { id: 'cup-kick', label: 'Cup & kick', duration: 4, loop: true },
  { id: 'entrance', label: 'Entrance', duration: 2, loop: false },
  { id: 'settle', label: 'Settle', duration: 1.2, loop: false },
  { id: 'idle', label: 'At ease', duration: 4, loop: true },
]);

export const AVATAR_SCENES = Object.freeze([
  { id: 'dots', label: 'Spotlight' },
  { id: 'studio', label: 'Studio' },
]);

export const AVATAR_PROPORTIONS = Object.freeze([
  { id: 'compact', label: 'Compact', scale: .94 },
  { id: 'balanced', label: 'Balanced', scale: 1 },
  { id: 'tall', label: 'Tall', scale: 1.06 },
]);

export const AVATAR_PALETTES = Object.freeze([
  { id: 'original', label: 'Original', swatches: ['#f5cbb3', '#99867b', '#802f37'], materials: { jacket: '#99867b', trousers: '#99867b' } },
  { id: 'ocean', label: 'Ocean', swatches: ['#126d78', '#b9e7de', '#142f43'], materials: { shell: '#b9e7de', mechanism: '#126d78', jacket: '#14384a', coat: '#126d78', trousers: '#142f43' } },
  { id: 'ember', label: 'Ember', swatches: ['#c45937', '#ecd1b0', '#43323a'], materials: { shell: '#ecd1b0', mechanism: '#633e33', jacket: '#9c4b36', coat: '#c45937', trousers: '#43323a' } },
  { id: 'ink', label: 'Ink', swatches: ['#313d53', '#dddde2', '#181d2e'], materials: { shell: '#dddde2', mechanism: '#313d53', jacket: '#313d53', coat: '#313d53', trousers: '#181d2e' } },
]);

export const DEFAULT_APPEARANCE = Object.freeze({
  schema: AVATAR_SCHEMA,
  body: 'robot',
  asset_revision: 'study-v1',
  palette: 'original',
  finish: 'ceramic',
  motion: 'cup-kick',
  scene: 'dots',
  proportion: 'balanced',
  parts: DEFAULT_PARTS,
});

export function validateAppearance(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Appearance must be an object.');
  const allowed = new Set(Object.keys(DEFAULT_APPEARANCE));
  if (Object.keys(input).some((key) => !allowed.has(key))) throw new Error('Appearance contains an unsupported field.');
  if (input.schema !== AVATAR_SCHEMA) throw new Error('Unsupported appearance version.');
  const body = AVATAR_BODIES.find((item) => item.id === input.body);
  if (!body || input.asset_revision !== body.revision) throw new Error('Unsupported body revision.');
  if (!body.finishes.some((item) => item.id === input.finish)) throw new Error('Unsupported surface finish.');
  if (!AVATAR_PALETTES.some((item) => item.id === input.palette)) throw new Error('Unsupported palette.');
  if (!AVATAR_MOTIONS.some((item) => item.id === input.motion)) throw new Error('Unsupported movement.');
  if (!AVATAR_SCENES.some((item) => item.id === input.scene)) throw new Error('Unsupported scene.');
  const proportion = input.proportion === undefined ? 'balanced' : input.proportion;
  if (!AVATAR_PROPORTIONS.some((item) => item.id === proportion)) throw new Error('Unsupported proportion preset.');
  const parts = validateParts(body.id, input.parts, input.palette);
  return Object.fromEntries(Object.keys(DEFAULT_APPEARANCE).map((key) => [key, key === 'proportion' ? proportion : key === 'parts' ? parts : input[key]]));
}

export function avatarPortrait(input) {
  const appearance = validateAppearance(input);
  return `/models/avatars/portraits/${appearance.asset_revision}/${appearance.body}-${appearance.palette}-${appearance.finish}${partSignature(appearance.parts)}.webp`;
}

export function avatarPoster(input) {
  return avatarPortrait(input).replace(/\.webp$/, '-poster.webp');
}

export function avatarEditorPath(kind, ref) {
  return `/avatar-studio?${new URLSearchParams({ target_kind: kind, target_ref: ref })}`;
}
