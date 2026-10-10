import { AVATAR_PROPORTIONS } from '../../../shared/avatar-catalog.mjs';

// Capture once per independently loaded avatar. Animation runs first, then
// assembly reapplies the selected body scale and physical prop correction.
export function createAppearanceAssembly(root) {
  const baseScale = root.scale.clone(), basePosition = root.position.clone();
  const grip = root.getObjectByName('rightGrip');
  const gripScale = grip?.scale.clone();
  return {
    apply(appearance) {
      const scale = AVATAR_PROPORTIONS.find((item) => item.id === appearance.proportion)?.scale || 1;
      root.scale.copy(baseScale).multiplyScalar(scale);
      root.position.copy(basePosition).multiplyScalar(scale);
      if (grip) grip.scale.copy(gripScale).divideScalar(scale);
      root.updateMatrixWorld(true);
    },
  };
}
