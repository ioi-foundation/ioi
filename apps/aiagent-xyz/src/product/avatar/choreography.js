import score from '../../../shared/avatar-choreography.json';

const ease = (value) => { const t = Math.max(0, Math.min(1, value)); return t * t * (3 - 2 * t); };

// Coordinates are lateral, up, forward. Support deliberately shuffles back;
// recovery happens in the air, so neither foot teleports at the loop boundary.
export function sampleFootwork(local, resting = false) {
  if (resting) return { forward: 0, lift: 0, kick: 0, outward: 0 };
  if (local > score.swingStart && local < score.swingEnd) {
    const t = (local - score.swingStart) / (score.swingEnd - score.swingStart);
    for (let i = 0; i < score.beats.length - 1; i++) {
      const a = score.beats[i], b = score.beats[i + 1];
      if (t >= a[0] && t <= b[0]) {
        const f = ease((t - a[0]) / (b[0] - a[0]));
        const [forward, lift, kick, outward] = [1, 2, 3, 4].map((j) => a[j] + (b[j] - a[j]) * f);
        return { forward, lift, kick, outward };
      }
    }
  }
  const supportPhase = local <= score.swingStart ? local + 1 : local;
  const travel = ease((supportPhase - score.shuffleStart) / (score.shuffleEnd - score.shuffleStart));
  return { forward: score.supportFront + (score.supportBack - score.supportFront) * travel, lift: 0, kick: 0, outward: 0 };
}

export { score as choreography };
