const VIEWS = {
  front: [0, 1, 2.65],
  quarter: [1.325, 1.06, 2.295],
  side: [2.65, 1, 0],
};

function orbitRadius(angle, motion, aspect) {
  const entrance = motion === 'entrance';
  const distance = entrance ? (aspect < 1 ? 1.45 : 1.20) : 1;
  // A forward kick spans more of a narrow viewport at oblique angles. This
  // continuous envelope covers the turns between the named inspection views.
  const minimumAspect = .85 + .25 * Math.abs(Math.sin(angle)) + .05 * Math.abs(Math.sin(2 * angle));
  return 2.65 * distance * Math.max(1, minimumAspect / aspect);
}

// Fixed envelopes cover the supported height range and the complete clip.
// Side and quarter views reserve more horizontal space for the forward kick.
export function avatarFraming(view, motion, aspect) {
  const position = VIEWS[view] || VIEWS.front;
  const entrance = motion === 'entrance';
  const angle = Math.atan2(position[0], position[2]), radius = orbitRadius(angle, motion, aspect);
  return { position: [Math.sin(angle) * radius, entrance ? 1.22 : position[1], Math.cos(angle) * radius], target: [0, entrance ? 1.20 : .96, 0] };
}
// The target stays on the vertical scene axis. Interpolate azimuth and radius
// independently so front/side transitions cannot cut through the orbit.
export function interpolateCameraPosition(from, to, weight, motion = 'cup-kick', aspect = 1) {
  const start = Math.atan2(from[0], from[2]), end = Math.atan2(to[0], to[2]);
  const turn = Math.atan2(Math.sin(end - start), Math.cos(end - start));
  const angle = start + turn * weight;
  const interpolated = Math.hypot(from[0], from[2]) * (1 - weight) + Math.hypot(to[0], to[2]) * weight;
  const radius = Math.max(interpolated, Math.abs(turn) > .000001 ? orbitRadius(angle, motion, aspect) : 0);
  return [Math.sin(angle) * radius, from[1] * (1 - weight) + to[1] * weight, Math.cos(angle) * radius];
}
