import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import { api } from '../api';
import AvatarStage from './AvatarStage';
import { AVATAR_BODIES, AVATAR_MOTIONS, AVATAR_PALETTES, AVATAR_SCENES, AVATAR_PROPORTIONS, DEFAULT_APPEARANCE, avatarPortrait } from '../../../shared/avatar-catalog.mjs';
import { AVATAR_PARTS, AVATAR_PART_SLOTS, DEFAULT_PARTS } from '../../../shared/avatar-parts.mjs';

function Choice({ selected, children, onClick, ...props }) {
  return <button type="button" className={`avatar-choice ${selected ? 'is-selected' : ''}`} aria-pressed={selected} onClick={onClick} {...props}>{children}</button>;
}

export default function AvatarStudio() {
  const [params, setParams] = useSearchParams();
  const kind = params.get('target_kind'), ref = params.get('target_ref');
  const target = useMemo(() => kind || ref ? { kind, ref } : null, [kind, ref]);
  const [load, setLoad] = useState({ key: '', record: null, error: null });
  const [profiles, setProfiles] = useState(null);
  const [profileError, setProfileError] = useState(null);
  const [attempt, setAttempt] = useState(0);
  const key = JSON.stringify(target);
  useEffect(() => {
    let current = true;
    api('/v1/creator/supply').then((value) => {
      if (current) setProfiles([['drafts', 'draft_ref', 'Draft'], ['registrations', 'registration_ref', 'Private worker'], ['listings', 'worker_id', 'Public listing']]
        .flatMap(([collection, kind, label]) => value[collection].map((item) => ({ target: { kind, ref: item[kind] }, label: `${item.name} · ${label}` }))));
    }).catch((error) => { if (current) setProfileError(error); });
    return () => { current = false; };
  }, [attempt]);
  useEffect(() => {
    if (!target) return undefined;
    let current = true;
    const query = new URLSearchParams({ target_kind: target.kind || '', target_ref: target.ref || '' });
    api(`/v1/profile-appearance?${query}`).then((record) => {
      if (current) setLoad({ key, record, error: null });
    }).catch((error) => { if (current) setLoad({ key, record: null, error }); });
    return () => { current = false; };
  }, [target, key, attempt]);
  const picker = <div className="avatar-profile-picker"><label htmlFor="avatar-profile">Worker profile</label>
    <select id="avatar-profile" value={target ? key : ''} onChange={(event) => {
      const selected = event.target.value ? JSON.parse(event.target.value) : null;
      setParams(selected ? { target_kind: selected.kind, target_ref: selected.ref } : {});
    }}>
      <option value="">Try an appearance</option>
      {target && !profiles?.some((item) => JSON.stringify(item.target) === key) && <option value={key}>{load.record?.profile_name || 'Selected worker'}</option>}
      {profiles?.map((item) => <option key={JSON.stringify(item.target)} value={JSON.stringify(item.target)}>{item.label}</option>)}
    </select>
    {profileError && <p role="status">{profileError.message} <button type="button" onClick={() => { setProfileError(null); setAttempt((value) => value + 1); }}>Retry</button></p>}
    {profiles?.length === 0 && <Link to="/builder">Create a worker to save an appearance →</Link>}
  </div>;
  if (target && (load.key !== key || load.error)) return <main className="avatar-studio">{picker}
    {load.key !== key ? <p role="status">Loading worker appearance…</p> : <div role="alert"><p>{load.error.message}</p><button type="button" onClick={() => { setLoad({ key: '', record: null, error: null }); setAttempt((value) => value + 1); }}>Retry</button></div>}
  </main>;
  return <StudioEditor key={`${key}:${attempt}`} target={target} initialRecord={target ? load.record : null} picker={picker} />;
}

function StudioEditor({ target, initialRecord, picker }) {
  const [record, setRecord] = useState(initialRecord);
  const [appearance, setAppearance] = useState(initialRecord?.appearance || { ...DEFAULT_APPEARANCE });
  const [previewMotion, setPreviewMotion] = useState(initialRecord?.appearance.motion || DEFAULT_APPEARANCE.motion);
  const [saving, setSaving] = useState(false);
  const [notice, setNotice] = useState('');
  const [error, setError] = useState(null);
  const [playing, setPlaying] = useState(true);
  const [view, setView] = useState('front');
  const [showRig, setShowRig] = useState(false);
  const [seekRequest, setSeekRequest] = useState(null);
  const [progress, setProgress] = useState({ time: 0, duration: 4, calls: 0, triangles: 0 });
  const stageAppearance = useMemo(() => ({ ...appearance, motion: previewMotion }), [appearance, previewMotion]);
  const dirty = JSON.stringify(appearance) !== JSON.stringify(record?.appearance || DEFAULT_APPEARANCE);
  const change = (key, value) => {
    if (key === 'body') setSeekRequest({ time: progress.time });
    if (key === 'motion') { setSeekRequest({ time: 0 }); setPreviewMotion(value); }
    setNotice('');
    setAppearance((current) => ({ ...current, [key]: value,
      ...(key === 'body' ? { asset_revision: AVATAR_BODIES.find((body) => body.id === value).revision,
        finish: AVATAR_BODIES.find((body) => body.id === value).finishes[0].id, parts: { ...DEFAULT_PARTS } } : {}) }));
  };
  const changePart = (slot, id) => {
    setNotice('');
    const part = AVATAR_PARTS[appearance.body][slot].find((item) => item.id === id);
    setAppearance((current) => ({ ...current, parts: { ...DEFAULT_PARTS, ...current.parts, [slot]: id },
      ...(part.palettes ? { palette: part.palettes[0] } : {}) }));
  };
  const fabricPalettes = AVATAR_PARTS[appearance.body].outerwear.find((item) => item.id === (appearance.parts?.outerwear || 'standard-v1')).palettes;
  const motionChange = useCallback((motion) => setPreviewMotion(motion), []);
  const seek = (time) => {
    setPlaying(false);
    setProgress((current) => ({ ...current, time }));
    setSeekRequest({ time });
  };
  const reset = () => {
    setAppearance({ ...DEFAULT_APPEARANCE });
    setPreviewMotion(DEFAULT_APPEARANCE.motion);
    setPlaying(true);
    setView('front');
    setShowRig(false);
    setSeekRequest({ time: 0 });
  };
  const save = async (publish = false) => {
    setSaving(true); setError(null); setNotice('');
    try {
      const result = await api(publish ? '/v1/profile-appearance/publish' : '/v1/profile-appearance', {
        method: publish ? 'POST' : 'PUT', body: { target, expected_revision: record.revision,
          ...(publish ? { appearance_revision: record.appearance_revision } : { appearance }) },
      });
      setRecord(result);
      setNotice(publish ? 'Public appearance updated.' : 'Appearance saved privately.');
    } catch (failure) { setError(failure); }
    finally { setSaving(false); }
  };
  const reloadSaved = async () => {
    setSaving(true); setError(null);
    try {
      const query = new URLSearchParams({ target_kind: target.kind, target_ref: target.ref });
      const result = await api(`/v1/profile-appearance?${query}`);
      setRecord(result); setAppearance(result.appearance); setPreviewMotion(result.appearance.motion); setSeekRequest({ time: 0 });
      setNotice('Saved appearance restored.');
    } catch (failure) { setError(failure); }
    finally { setSaving(false); }
  };

  return (
    <main className="avatar-studio">
      <div className="avatar-studio-heading">
        <div><p className="avatar-eyebrow">Agent appearance</p><h1>{initialRecord?.profile_name || 'Avatar studio'}</h1><p>Choose an appearance and performance for your worker.</p></div>
        <Link className="avatar-back-link" to="/my-workers">My workers ↗</Link>
      </div>
      {picker}
      <div className="avatar-workspace">
        <section className="avatar-preview" aria-label="Avatar preview">
          <div className="avatar-stage-toolbar">
            <span>{AVATAR_BODIES.find((item) => item.id === appearance.body)?.label}</span>
            <div className="avatar-view-options" aria-label="Camera view">
              {[['front', 'Front'], ['quarter', '¾ view'], ['side', 'Side']].map(([id, label]) => <Choice key={id} selected={view === id} onClick={() => setView(id)}>{label}</Choice>)}
            </div>
          </div>
          <AvatarStage key={appearance.body} appearance={stageAppearance} playing={playing} view={view} showRig={showRig}
            seekRequest={seekRequest} onProgress={setProgress} onMotionChange={motionChange} />
          <div className="avatar-playback">
            <button className="avatar-play-button" type="button" onClick={() => setPlaying((value) => !value)} aria-label={playing ? 'Pause animation' : 'Play animation'}>{playing ? 'Ⅱ' : '▶'}</button>
            <input aria-label="Animation position" type="range" min="0" max={progress.duration || 4} step="0.01" value={Math.min(progress.time, progress.duration || 4)} onInput={(event) => seek(Number(event.target.value))} onChange={(event) => seek(Number(event.target.value))} />
            <output>{progress.time.toFixed(1)} / {progress.duration.toFixed(1)}s</output>
            <button className="avatar-replay" type="button" onClick={() => { setPreviewMotion(appearance.motion); setSeekRequest({ time: 0 }); setPlaying(true); }}>Replay ↻</button>
          </div>
        </section>

        <aside className="avatar-options" aria-label="Avatar options">
          <fieldset><legend>Body</legend><div className="avatar-body-options">
            {AVATAR_BODIES.map((body) => <Choice key={body.id} selected={appearance.body === body.id} onClick={() => change('body', body.id)}><strong>{body.label}</strong><span>{body.description}</span></Choice>)}
          </div></fieldset>
          <fieldset><legend>Height</legend><div className="avatar-movement-options">
            {AVATAR_PROPORTIONS.map((preset) => <Choice key={preset.id} selected={(appearance.proportion || 'balanced') === preset.id} onClick={() => change('proportion', preset.id)}>{preset.label}</Choice>)}
          </div></fieldset>
          {AVATAR_BODIES.find((body) => body.id === appearance.body).finishes.length > 1 && <fieldset><legend>Surface</legend><div className="avatar-movement-options">
            {AVATAR_BODIES.find((body) => body.id === appearance.body).finishes.map((finish) => <Choice key={finish.id} selected={appearance.finish === finish.id} onClick={() => change('finish', finish.id)}>{finish.label}</Choice>)}
          </div></fieldset>}
          {AVATAR_PART_SLOTS.filter(({ id }) => AVATAR_PARTS[appearance.body][id].length > 1).map(({ id, label }) => <fieldset key={id}><legend>{label}</legend><div className="avatar-movement-options">
            {AVATAR_PARTS[appearance.body][id].map((part) => <Choice key={part.id} selected={(appearance.parts?.[id] || DEFAULT_PARTS[id]) === part.id} onClick={() => changePart(id, part.id)}>{part.label}</Choice>)}
          </div></fieldset>)}
          <fieldset><legend>Palette</legend><div className="avatar-palette-options">
            {AVATAR_PALETTES.map((palette) => <Choice key={palette.id} selected={appearance.palette === palette.id} disabled={Boolean(fabricPalettes && !fabricPalettes.includes(palette.id))} onClick={() => change('palette', palette.id)} aria-label={`${palette.label} palette`}>
              <span className="avatar-swatches" aria-hidden="true">{palette.swatches.map((color) => <i key={color} style={{ backgroundColor: color }} />)}</span><span>{palette.label}</span>
            </Choice>)}
          </div>{fabricPalettes && <p className="avatar-choice-note">This fabric uses its original palette.</p>}</fieldset>
          <fieldset><legend>Movement</legend><div className="avatar-movement-options">
            {AVATAR_MOTIONS.map((motion) => <Choice key={motion.id} selected={appearance.motion === motion.id} onClick={() => { change('motion', motion.id); setPlaying(true); }}>{motion.label}</Choice>)}
          </div></fieldset>
          <fieldset><legend>Scene</legend><div className="avatar-movement-options">
            {AVATAR_SCENES.map((scene) => <Choice key={scene.id} selected={appearance.scene === scene.id} onClick={() => change('scene', scene.id)}>{scene.label}</Choice>)}
          </div></fieldset>
          <div className="avatar-portrait-preview"><img src={avatarPortrait(appearance)} alt="Worker portrait preview" width="72" height="72" /><div><strong>Profile portrait</strong><span>Used in worker lists</span></div></div>
          <div className="avatar-options-footer"><button type="button" onClick={reset} disabled={saving}>Reset to default</button>
            {target ? <>
              <button className="avatar-save-button" type="button" disabled={saving || (!dirty && record.appearance_revision > 0)} onClick={() => save()}>{saving ? 'Saving…' : 'Save appearance'}</button>
              <button type="button" disabled={saving} onClick={reloadSaved}>Restore saved appearance</button>
              {target.kind === 'worker_id' && <button className="avatar-publish-button" type="button" onClick={() => save(true)} disabled={saving || dirty || !record.appearance_revision || record.public_revision === record.appearance_revision}>Use saved appearance publicly</button>}
              <span>{dirty ? 'Unsaved changes' : record.appearance_revision ? `Saved appearance ${record.appearance_revision}` : 'Default appearance'}{record.public_revision ? ` · Public appearance ${record.public_revision}` : ''}</span>
            </> : <span>Choose a worker above to save this appearance.</span>}
            {notice && <p role="status">{notice}</p>}
            {error && <p role="alert">{error.message}{error.code === 'appearance_revision_conflict' && ' Use Restore saved appearance to load the latest version.'}</p>}
          </div>
        </aside>
      </div>
      <details className="avatar-inspection"><summary>Motion inspection</summary><div><label><input type="checkbox" checked={showRig} onChange={(event) => setShowRig(event.target.checked)} /> Show joints</label><span>{progress.triangles.toLocaleString()} rendered triangles · {progress.calls} draw calls</span><span>Pause and change views to inspect the pose and garment clearance.</span></div></details>
    </main>
  );
}
