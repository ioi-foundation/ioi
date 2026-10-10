// Offsets are meters in the normalized, 1.58 m head-pivot frame. The mouth
// landmark is calibrated per authored body, not inferred from a bone name.
export const MOTION_PROFILES = {
  human: { mouth: [0, -.040, .112], wrist: [-.160, -.007, .030], wristRoll: -Math.PI / 2, coatAmplitude: .45, coatPanels: 8, entranceCoatSpread: .7, groundOffset: .029, kickScale: 1.15 },
  anime: { mouth: [0, .020, .125], wrist: [-.122, -.010, .025], coatAmplitude: 1, coatPanels: 16, entranceCoatSpread: 1.4, groundOffset: 0, kickScale: 1.05 },
};
