import { AVATAR_PALETTES } from '../../../shared/avatar-catalog.mjs';

export function applyPalette(materials, paletteId) {
  const palette = AVATAR_PALETTES.find((item) => item.id === paletteId) || AVATAR_PALETTES[0];
  for (const material of materials) {
    // The original suit uses a neutral fabric; the anime hosiery keeps its
    // authored burgundy even though both occupy the lower-body color slot.
    const override = paletteId === 'original' && material.isMToonMaterial ? undefined : palette.materials[material.name];
    if (override && material.color) material.color.set(override);
    else if (material.userData.originalColor) material.color.copy(material.userData.originalColor);
    if (material.shadeColorFactor?.isColor) {
      material.userData.originalShade ||= material.shadeColorFactor.clone();
      if (override) material.shadeColorFactor.copy(material.color).multiplyScalar(.64);
      else material.shadeColorFactor.copy(material.userData.originalShade);
    }
    if (['jacket', 'trousers'].includes(material.name) && !material.isMToonMaterial) {
      if (!Object.hasOwn(material.userData, 'originalMap')) material.userData.originalMap = material.map;
      const map = override ? null : material.userData.originalMap;
      if (material.map !== map) { material.map = map; material.needsUpdate = true; }
    }
  }
}
