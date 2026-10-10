import { DEFAULT_PARTS } from '../../../shared/avatar-parts.mjs';

export function applyAppearanceParts(avatar, appearance) {
  const parts = { ...DEFAULT_PARTS, ...appearance.parts };
  avatar.root.traverse((node) => {
    if (node.name.includes('short02')) node.visible = parts.hair !== 'shaved-v1';
    if (node.name === 'Hairband') node.visible = parts.hair !== 'unadorned-v1';
  });
  for (const material of avatar.materials) {
    if (material.name === 'headset') material.visible = parts.hair === 'headset-v1';
    if (material.name === 'coat-piping') material.visible = parts.outerwear !== 'clean-v1';
    if (material.name === 'porcelain') {
      if (parts.prop === 'charcoal-v1') material.color.set('#263946');
      else material.color.copy(material.userData.originalColor);
    }
    if (appearance.body === 'human' && ['jacket', 'trousers'].includes(material.name) && parts.outerwear === 'pinstripe-v1') {
      material.color.copy(material.userData.originalColor);
      if (material.map !== material.userData.originalMap) {
        material.map = material.userData.originalMap; material.needsUpdate = true;
      }
    }
  }
  avatar.setExpression?.(parts.face === 'warm-v1' ? 'warm' : 'composed');
}
