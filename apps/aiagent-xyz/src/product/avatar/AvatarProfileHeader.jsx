import { useMemo, useState } from 'react';
import AvatarStage from './AvatarStage';
import { DEFAULT_APPEARANCE } from '../../../shared/avatar-catalog.mjs';

export default function AvatarProfileHeader({ worker, handle }) {
  const selected = worker.avatar?.appearance || DEFAULT_APPEARANCE;
  const [motion, setMotion] = useState(selected.motion);
  const [playing, setPlaying] = useState(true);
  const [seekRequest, setSeekRequest] = useState(null);
  const appearance = useMemo(() => ({ ...selected, motion }), [selected, motion]);
  return <section className={`avatar-profile-header avatar-profile-header--${appearance.scene}`} aria-label="Worker profile">
    <div className="avatar-profile-copy">
      <p className="avatar-eyebrow">Agent profile</p>
      <h1>{worker.name}</h1>
      <div className="avatar-profile-tags"><span>{worker.license}</span><span title={`Derived shorthand. Composition root ${worker.composition_root}`}>{handle}</span></div>
      <p>{worker.description}</p>
      <div className="avatar-profile-controls"><button type="button" onClick={() => setPlaying((value) => !value)} aria-label={playing ? 'Pause avatar animation' : 'Play avatar animation'}>{playing ? 'Pause Ⅱ' : 'Play ▶'}</button>
        <button type="button" onClick={() => { setMotion(selected.motion); setSeekRequest({ time: 0 }); setPlaying(true); }}>Replay ↻</button></div>
    </div>
    <AvatarStage key={selected.body} className="avatar-profile-performance" appearance={appearance} playing={playing} seekRequest={seekRequest} onMotionChange={setMotion} />
  </section>;
}
