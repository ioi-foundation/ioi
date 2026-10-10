import { AnimationMixer, LoopOnce, LoopRepeat } from 'three';
import { AVATAR_MOTIONS } from '../../../shared/avatar-catalog.mjs';

export function createMotionPlayer(root, clips, onMotionChange = () => {}) {
  const mixer = new AnimationMixer(root);
  const byName = new Map(clips.map((clip) => [clip.name, clip]));
  let current = null;
  let motion = 'cup-kick';
  let duration = 4;
  let stopped = false;

  function select(name, { blend = .22, time = 0 } = {}) {
    const definition = AVATAR_MOTIONS.find((item) => item.id === name);
    const clip = byName.get(name);
    if (!clip || !definition) throw new Error(`Avatar movement is missing: ${name}`);
    const next = mixer.clipAction(clip);
    if (next !== current) {
      next.reset().setEffectiveWeight(1).setEffectiveTimeScale(1);
      next.setLoop(definition.loop ? LoopRepeat : LoopOnce, definition.loop ? Infinity : 1);
      next.clampWhenFinished = !definition.loop;
      next.play();
      if (current && blend > 0) current.crossFadeTo(next, blend, false);
      else current?.stop();
      current = next;
    }
    motion = name;
    duration = clip.duration;
    current.time = Math.min(Math.max(time, 0), duration);
    mixer.update(0);
  }

  const finished = (event) => {
    if (event.action === current && (motion === 'entrance' || motion === 'settle')) {
      const next = motion === 'entrance' ? 'cup-kick' : 'idle';
      select(next);
      onMotionChange(next);
    }
  };
  mixer.addEventListener('finished', finished);
  select(motion, { blend: 0 });

  return {
    select,
    update(delta) { if (!stopped) mixer.update(Math.min(Math.max(delta, 0), .05)); },
    seek(time) {
      mixer.stopAllAction();
      current = null;
      select(motion, { blend: 0, time });
    },
    getState() { return { motion, time: current?.time ?? 0, duration }; },
    dispose() {
      stopped = true;
      mixer.removeEventListener('finished', finished);
      mixer.stopAllAction();
      mixer.uncacheRoot(root);
    },
  };
}
