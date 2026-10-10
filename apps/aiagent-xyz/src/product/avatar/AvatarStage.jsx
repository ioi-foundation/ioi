import { useEffect, useRef, useState } from 'react';
import * as THREE from 'three';
import { acquireAvatar } from './asset-cache';
import { createMotionPlayer } from './motion-player';
import { applyPalette } from './appearance-materials';
import { applyAppearanceParts } from './appearance-parts';
import { avatarPoster } from '../../../shared/avatar-catalog.mjs';
import { createAppearanceAssembly } from './appearance-assembly';
import { avatarFraming, interpolateCameraPosition } from './scene-framing';
import './avatar.css';

export default function AvatarStage({ appearance, playing = true, view = 'front', showRig = false,
  seekRequest = null, onProgress, onMotionChange, onReady, className = '' }) {
  const mount = useRef(null);
  const runtime = useRef(null);
  const settings = useRef({ appearance, playing, view, showRig, seekRequest, onProgress, onMotionChange, onReady });
  const [status, setStatus] = useState('loading');
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    settings.current = { appearance, playing, view, showRig, seekRequest, onProgress, onMotionChange, onReady };
    const active = runtime.current;
    if (!active) return;
    applyPalette(active.materials, appearance.palette);
    active.setFinish?.(appearance.finish);
    applyAppearanceParts(active, appearance);
    active.update?.(0, active.player.getState().time);
    active.applyProportion();
    if (active.player.getState().motion !== appearance.motion) active.player.select(appearance.motion);
    active.skeleton.visible = showRig;
    active.setScene(appearance.scene);
    active.setCamera(view);
    active.draw();
  }, [appearance, playing, view, showRig, seekRequest, onProgress, onMotionChange, onReady]);

  useEffect(() => {
    if (seekRequest && runtime.current) {
      runtime.current.player.seek(seekRequest.time);
      runtime.current.update?.(0, seekRequest.time, true);
      runtime.current.draw();
    }
  }, [seekRequest]);

  useEffect(() => {
    const host = mount.current;
    if (!host) return undefined;
    let renderer;
    try {
      renderer = new THREE.WebGLRenderer({ alpha: true, antialias: true, powerPreference: 'low-power' });
    } catch {
      // Failure is a supported stage state; the surrounding editor remains usable.
      queueMicrotask(() => setStatus('unavailable'));
      return undefined;
    }
    let disposed = false;
    let contextLost = false;
    queueMicrotask(() => { if (!disposed) setStatus('loading'); });
    let visible = true;
    let raf = 0;
    let previous = 0;
    let reportAt = 0;
    let active = null;
    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
    let reduced = reduceMotion.matches;
    // Fine facial lines and garment seams need more than a 1.25 DPR canvas.
    // Geometry LOD handles the mobile cost while this cap keeps edges legible.
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 1.75));
    renderer.setClearColor(0x000000, 0);
    renderer.outputColorSpace = THREE.SRGBColorSpace;
    const toon = appearance.body === 'anime';
    renderer.toneMapping = toon ? THREE.NoToneMapping : THREE.ACESFilmicToneMapping;
    renderer.toneMappingExposure = toon || appearance.body === 'robot' ? 1 : 1.15;
    renderer.shadowMap.enabled = settings.current.appearance.scene === 'studio';
    renderer.shadowMap.type = THREE.PCFShadowMap;
    renderer.domElement.setAttribute('aria-label', 'Animated agent avatar');
    renderer.domElement.setAttribute('role', 'img');
    host.appendChild(renderer.domElement);
    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(48, 1, .05, 30);
    const cameraGoal = new THREE.Vector3(), aimGoal = new THREE.Vector3(), cameraAim = new THREE.Vector3();
    let cameraInitialized = false;
    let cameraMoving = false;
    scene.add(new THREE.HemisphereLight(0xffffff, 0xc6ae97, toon ? .95 : 1.5));
    const key = new THREE.DirectionalLight(toon ? 0xffffff : 0xfff2dc, toon ? 1.6 : 2.8);
    key.position.set(-2, 4, 5);
    key.castShadow = true;
    key.shadow.mapSize.set(1024, 1024);
    Object.assign(key.shadow.camera, { left: -2, right: 2, top: 3, bottom: -2, near: .1, far: 12 });
    key.shadow.bias = -.0005;
    key.shadow.normalBias = .015;
    scene.add(key);
    const rim = new THREE.DirectionalLight(0xd7edff, toon ? .15 : .8);
    rim.position.set(3, 2, -3);
    scene.add(rim);
    const floorGeometry = new THREE.PlaneGeometry(20, 20);
    const floorMaterial = new THREE.ShadowMaterial({ color: 0x47331b, opacity: .12 });
    const floor = new THREE.Mesh(floorGeometry, floorMaterial);
    floor.rotation.x = -Math.PI / 2;
    floor.position.y = -.012;
    floor.receiveShadow = true;
    floor.visible = settings.current.appearance.scene === 'studio';
    scene.add(floor);
    const setScene = (name) => {
      floor.visible = name === 'studio';
      renderer.shadowMap.enabled = floor.visible;
    };
    const asset = acquireAvatar(appearance.body, { quality: window.innerWidth < 768 ? 'mobile' : 'desktop' });

    const setCamera = (name, instant = false) => {
      const framing = avatarFraming(name, settings.current.appearance.motion, camera.aspect);
      cameraGoal.fromArray(framing.position);
      aimGoal.fromArray(framing.target);
      if (!cameraInitialized || instant || reduceMotion.matches) {
        camera.position.copy(cameraGoal); cameraAim.copy(aimGoal); cameraInitialized = true;
      }
      cameraMoving = camera.position.distanceToSquared(cameraGoal) + cameraAim.distanceToSquared(aimGoal) > .000001;
      camera.lookAt(cameraAim);
      camera.updateProjectionMatrix();
    };
    const draw = () => {
      if (disposed || contextLost) return;
      renderer.render(scene, camera);
      if (active) {
        const state = active.player.getState();
        host.dataset.motion = state.motion;
        host.dataset.animationTime = state.time.toFixed(3);
      }
    };
    const resize = () => {
      const { width, height } = host.getBoundingClientRect();
      if (width <= 0 || height <= 0) return;
      renderer.setSize(width, height, false);
      camera.aspect = width / height;
      setCamera(settings.current.view, true);
      draw();
    };
    const resizeObserver = new ResizeObserver(resize);
    resizeObserver.observe(host);
    resize();
    const intersection = new IntersectionObserver(([entry]) => {
      visible = entry.isIntersecting;
      previous = 0;
    });
    intersection.observe(host);
    const visibility = () => { previous = 0; };
    document.addEventListener('visibilitychange', visibility);
    const motionPreference = () => {
      reduced = reduceMotion.matches;
      if (reduceMotion.matches && active) {
        active.player.seek(0);
        active.update?.(0, 0, true);
        draw();
      }
    };
    reduceMotion.addEventListener('change', motionPreference);
    const loseContext = (event) => { event.preventDefault(); contextLost = true; setStatus('unavailable'); };
    const restoreContext = () => { if (!disposed) { setStatus('loading'); setAttempt((value) => value + 1); } };
    renderer.domElement.addEventListener('webglcontextlost', loseContext);
    renderer.domElement.addEventListener('webglcontextrestored', restoreContext);

    asset.ready.then(({ root, clips, materials, update, setFinish, setExpression }) => {
      if (disposed) return;
      scene.add(root);
      const skeleton = new THREE.SkeletonHelper(root);
      skeleton.visible = settings.current.showRig;
      scene.add(skeleton);
      const player = createMotionPlayer(root, clips, (name) => settings.current.onMotionChange?.(name));
      const assembly = createAppearanceAssembly(root);
      const applyProportion = () => assembly.apply(settings.current.appearance);
      const updateAvatar = (delta, time, reset) => { update?.(delta, time, reset); applyProportion(); };
      active = { root, skeleton, player, materials, draw, setCamera, update: updateAvatar, setFinish, setExpression, floor, setScene, applyProportion };
      runtime.current = active;
      applyPalette(materials, settings.current.appearance.palette);
      setFinish?.(settings.current.appearance.finish);
      applyAppearanceParts(active, settings.current.appearance);
      player.select(settings.current.appearance.motion, { blend: 0 });
      player.seek(reduceMotion.matches ? 0 : settings.current.seekRequest?.time || 0);
      updateAvatar(0, player.getState().time, true);
      draw();
      setStatus(contextLost ? 'unavailable' : 'ready');
      settings.current.onReady?.({ body: appearance.body, clips: clips.map((clip) => clip.name) });
    }).catch((error) => {
      if (!disposed && error.name !== 'AbortError') setStatus('error');
    });

    const tick = (now) => {
      if (disposed) return;
      // Some browsers update the query before dispatching its change event.
      // Observe the transition here too so playback always settles promptly.
      if (reduceMotion.matches !== reduced) motionPreference();
      const motionActive = String(Boolean(active && visible && !document.hidden && !contextLost && settings.current.playing && !reduceMotion.matches));
      if (host.parentElement.dataset.motionActive !== motionActive) host.parentElement.dataset.motionActive = motionActive;
      const delta = previous ? (now - previous) / 1000 : 0;
      previous = now;
      let changed = false;
      if (visible && !document.hidden && cameraMoving && !contextLost) {
        const weight = reduceMotion.matches ? 1 : 1 - Math.exp(-Math.min(delta, .05) * 10);
        camera.position.fromArray(interpolateCameraPosition(camera.position.toArray(), cameraGoal.toArray(), weight, settings.current.appearance.motion, camera.aspect));
        cameraAim.lerp(aimGoal, weight); camera.lookAt(cameraAim);
        cameraMoving = camera.position.distanceToSquared(cameraGoal) + cameraAim.distanceToSquared(aimGoal) > .000001;
        changed = true;
      }
      if (active && visible && !document.hidden && !contextLost && settings.current.playing && !reduceMotion.matches) {
        active.player.update(delta);
        active.update?.(delta, active.player.getState().time);
        changed = true;
      }
      if (changed) draw();
      if (active && visible && !document.hidden && now - reportAt > 100) {
        settings.current.onProgress?.({ ...active.player.getState(), calls: renderer.info.render.calls, triangles: renderer.info.render.triangles });
        reportAt = now;
      }
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);

    return () => {
      disposed = true;
      cancelAnimationFrame(raf);
      resizeObserver.disconnect();
      intersection.disconnect();
      document.removeEventListener('visibilitychange', visibility);
      reduceMotion.removeEventListener('change', motionPreference);
      renderer.domElement.removeEventListener('webglcontextlost', loseContext);
      renderer.domElement.removeEventListener('webglcontextrestored', restoreContext);
      active?.player.dispose();
      active?.skeleton.geometry.dispose();
      active?.skeleton.material.dispose();
      if (runtime.current === active) runtime.current = null;
      asset.release();
      floorGeometry.dispose();
      floorMaterial.dispose();
      renderer.dispose();
      renderer.forceContextLoss();
      renderer.domElement.remove();
    };
  }, [appearance.body, attempt]);

  return (
    <div className={`avatar-stage avatar-stage--${appearance.scene} ${className}`} data-status={status}>
      <div className="avatar-stage-pattern" aria-hidden="true"><div className="avatar-stage-large-dots" /><div className="avatar-stage-small-dots"><div /></div></div>
      {status !== 'ready' && <img className="avatar-stage-poster" src={avatarPoster(appearance)} alt="Worker avatar" />}
      <div ref={mount} className="avatar-stage-canvas" />
      {status === 'loading' && <div className="avatar-stage-message" role="status">Preparing avatar…</div>}
      {(status === 'error' || status === 'unavailable') && (
        <div className="avatar-stage-message" role="status">
          <p>{status === 'unavailable' ? '3D preview is unavailable on this device.' : 'The avatar could not be loaded.'}</p>
          <button type="button" onClick={() => { setStatus('loading'); setAttempt((value) => value + 1); }}>Try again</button>
        </div>
      )}
    </div>
  );
}
