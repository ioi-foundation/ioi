// Part identifiers are scoped by body + slot + revision. Asset paths and fit
// rules are server-owned; appearance records never carry arbitrary model URLs.
const standard = (label) => [{ id: 'standard-v1', label }];
export const AVATAR_PART_SLOTS = Object.freeze([
  { id: 'face', label: 'Expression' }, { id: 'hair', label: 'Hair & headwear' },
  { id: 'outerwear', label: 'Clothing' }, { id: 'hands', label: 'Hands' },
  { id: 'lower_body', label: 'Lower body' }, { id: 'footwear', label: 'Footwear' },
  { id: 'prop', label: 'Cup' },
]);
export const DEFAULT_PARTS = Object.freeze(Object.fromEntries(AVATAR_PART_SLOTS.map(({ id }) => [id, 'standard-v1'])));
export const AVATAR_PARTS = Object.freeze({
  robot: {
    face: [...standard('Composed'), { id: 'warm-v1', label: 'Bright' }],
    hair: [...standard('Bare head'), { id: 'headset-v1', label: 'Headset' }],
    outerwear: standard('Articulated shell'), hands: standard('Mechanical grip'),
    lower_body: standard('Leg armor'), footwear: standard('Articulated feet'),
    prop: [...standard('Ivory'), { id: 'charcoal-v1', label: 'Charcoal' }],
  },
  human: {
    face: [...standard('Composed'), { id: 'warm-v1', label: 'Warm' }],
    hair: [...standard('Short waves'), { id: 'shaved-v1', label: 'Shaved' }],
    outerwear: [...standard('Tailored suit'), { id: 'pinstripe-v1', label: 'Pinstripe suit', palettes: ['original'] }],
    hands: standard('Fitted grip'), lower_body: standard('Tailored trousers'),
    footwear: standard('Oxford shoes'), prop: [...standard('Ivory'), { id: 'charcoal-v1', label: 'Charcoal' }],
  },
  anime: {
    face: [...standard('Composed'), { id: 'warm-v1', label: 'Warm' }],
    hair: [...standard('Hairband'), { id: 'unadorned-v1', label: 'Loose hair' }],
    outerwear: [...standard('Piped coat'), { id: 'clean-v1', label: 'Plain coat' }],
    hands: standard('Fitted grip'), lower_body: standard('Dress & stockings'),
    footwear: standard('Tall boots'), prop: [...standard('Ivory'), { id: 'charcoal-v1', label: 'Charcoal' }],
  },
});

export function validateParts(body, input = DEFAULT_PARTS, palette = 'original') {
  if (!input || typeof input !== 'object' || Array.isArray(input)
    || Object.keys(input).some((slot) => !Object.hasOwn(DEFAULT_PARTS, slot))) throw new Error('Unsupported part slot.');
  const result = {};
  for (const { id: slot } of AVATAR_PART_SLOTS) {
    const id = input[slot] === undefined ? DEFAULT_PARTS[slot] : input[slot];
    const part = AVATAR_PARTS[body]?.[slot].find((item) => item.id === id);
    if (!part) throw new Error(`This ${slot.replace('_', ' ')} does not fit the selected body.`);
    if (part.palettes && !part.palettes.includes(palette)) throw new Error('The pinstripe suit uses its original fabric palette.');
    result[slot] = id;
  }
  return result;
}

export function partSignature(parts) {
  const changed = AVATAR_PART_SLOTS.filter(({ id }) => parts[id] !== DEFAULT_PARTS[id]);
  return changed.length ? '--' + changed.map(({ id }) => `${id}-${parts[id]}`).join('_') : '';
}

export function appearanceVariants(body) {
  return AVATAR_PART_SLOTS.reduce((variants, { id }) => variants.flatMap((parts) =>
    AVATAR_PARTS[body][id].map((part) => ({ ...parts, [id]: part.id }))), [{}]);
}
