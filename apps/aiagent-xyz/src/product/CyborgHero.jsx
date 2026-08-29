// The lander hero's figure: the estate's own cyborg (public/models/cyborg/,
// shared with internetofintelligence-com's Web4 page), rendered with the
// hologram treatment from that page's robot rig (createCyborgRobotRig.js) —
// materials AND behavior, at lander volume: a soft scanline raster and gentle
// flicker say "digital being"; the rig's glitch tick stays on web4, where a
// hologram materializing is the story — on a storefront selling dependable
// agents a glitch reads as malfunction. Still the lean subset — no glass
// system, no joint puppetry, no scroll choreography: idle presence, waist-up.
//
// Loaded lazily from CategoryHome so three.js and the 2.4MB GLB are paid for
// only by the lander, and only after the storefront's own facts are on screen.
import { useEffect, useRef } from 'react';
import * as THREE from 'three';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';
import { DRACOLoader } from 'three/addons/loaders/DRACOLoader.js';

const VERTEX = /* glsl */ `
  varying vec3 vNormal;
  varying vec3 vViewDir;
  varying float vWorldY;

  void main() {
    vec4 worldPos = modelMatrix * vec4(position, 1.0);
    vWorldY = worldPos.y;
    vec4 mvPosition = viewMatrix * worldPos;
    vNormal = normalize(normalMatrix * normal);
    vViewDir = normalize(-mvPosition.xyz);
    gl_Position = projectionMatrix * mvPosition;
  }
`;

const FRAGMENT = /* glsl */ `
  uniform vec3 uFillColor;
  uniform vec3 uRimColor;
  uniform float uFillOpacity;
  uniform float uRimOpacity;
  uniform float uRimPower;
  uniform float uTopLight;
  uniform float uTime;
  uniform float uScanlineFreq;
  uniform float uScanlineStrength;
  uniform float uFlicker;

  varying vec3 vNormal;
  varying vec3 vViewDir;
  varying float vWorldY;

  void main() {
    vec3 normal = normalize(vNormal);
    vec3 viewDir = normalize(vViewDir);
    // abs() keeps back faces rim-lit so interior mechanics stay legible
    float facing = abs(dot(normal, viewDir));
    float fresnel = pow(1.0 - facing, uRimPower);
    float top = clamp(normal.y, 0.0, 1.0) * uTopLight;
    // Hologram raster: world-space lines drifting slowly upward
    float scan = 0.5 + 0.5 * sin(vWorldY * uScanlineFreq - uTime * 2.0);
    float scanShade = mix(1.0, 0.5 + 0.5 * scan, uScanlineStrength);
    vec3 color = mix(uFillColor, uRimColor, fresnel) + vec3(top);
    float alpha = clamp(uFillOpacity + fresnel * uRimOpacity, 0.0, 1.0);
    alpha = clamp(alpha * scanShade * uFlicker, 0.0, 1.0);
    gl_FragColor = vec4(color, alpha);
  }
`;

const fresnelMaterial = ({ fillColor, rimColor, fillOpacity, rimOpacity, rimPower, topLight }) =>
  new THREE.ShaderMaterial({
    vertexShader: VERTEX,
    fragmentShader: FRAGMENT,
    uniforms: {
      uFillColor: { value: new THREE.Color(fillColor) },
      uRimColor: { value: new THREE.Color(rimColor) },
      uFillOpacity: { value: fillOpacity },
      uRimOpacity: { value: rimOpacity },
      uRimPower: { value: rimPower },
      uTopLight: { value: topLight },
      uTime: { value: 0 },
      uScanlineFreq: { value: 80 },
      uScanlineStrength: { value: 0 },
      uFlicker: { value: 1 },
    },
    transparent: true,
    side: THREE.DoubleSide,
    depthWrite: false,
  });

// The rig's light-mode palette, verbatim — this site is a light surface, and
// the estate already answered "hologram on a light ground": dark rims over
// pale fills, etched glass rather than neon.
// Light = the PIXEL INVERSE of dark, in structure and luminance: fills are
// dark's fills inverted (near-white on white, as dark's are near-black on
// black — nearly invisible either way), rims are dark's rims inverted, and
// the opacities match exactly. The information is carried by rims alone;
// any fill far from the ground shades the surface and eats definition —
// first as 0.8-opacity solid shells, then as a 0x222222 face tint.
const makeMaterials = () => ({
  body: fresnelMaterial({ fillColor: 0xf2f2f0, rimColor: 0x000000, fillOpacity: 0.05, rimOpacity: 0.58, rimPower: 2.2, topLight: 0.05 }),
  skeleton: fresnelMaterial({ fillColor: 0xe5e5e3, rimColor: 0x111111, fillOpacity: 0.16, rimOpacity: 0.7, rimPower: 1.8, topLight: 0.05 }),
  accent: fresnelMaterial({ fillColor: 0xd5d5d1, rimColor: 0x000000, fillOpacity: 0.32, rimOpacity: 0.85, rimPower: 1.6, topLight: 0.05 }),
});

const chooseMaterial = (name, materials) => {
  if (/head|hand|foot|shoulder|pelvis/i.test(name)) return materials.accent;
  if (/skeleton/i.test(name)) return materials.skeleton;
  return materials.body;
};

const FIGURE_HEIGHT = 1.9;

// The rig's flicker/scan formulas at lander volume: scanlines at 0.25 (the
// rig idles at 0.6 — "transmission artifact"; this reads "glass instrument"),
// flicker depth halved. No glitch here by ruling — see header.
const driveHologram = (materials, elapsed) => {
  const flickerDepth = (0.045 + 0.045 * Math.sin(elapsed * 2.1)) * (0.5 + 0.5 * Math.sin(elapsed * 13.7));

  Object.values(materials).forEach((material) => {
    const u = material.uniforms;
    u.uTime.value = elapsed;
    u.uScanlineStrength.value = 0.25;
    u.uFlicker.value = 1 - flickerDepth * 0.5;
  });
};

export default function CyborgHero({ className }) {
  const mount = useRef(null);

  useEffect(() => {
    const host = mount.current;
    if (!host) return undefined;

    const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    renderer.domElement.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;display:block;';
    host.appendChild(renderer.domElement);

    const scene = new THREE.Scene();
    const camera = new THREE.PerspectiveCamera(34, 1, 0.1, 30);
    // Waist-up: the framing that earns the figure's facial and torso
    // line-work — full-body rendered the face at a few pixels.
    camera.position.set(0.15, 1.35, 2.0);
    camera.lookAt(0, 1.3, 0);

    const materials = makeMaterials();
    const figure = new THREE.Group();
    scene.add(figure);

    let disposed = false;
    let raf = 0;

    // The GLB is Draco-compressed; decoder binaries live in public/draco/,
    // copied from this three version's examples/jsm/libs (same layout the
    // web4 page uses).
    const dracoLoader = new DRACOLoader();
    dracoLoader.setDecoderPath('/draco/');
    const gltfLoader = new GLTFLoader();
    gltfLoader.setDRACOLoader(dracoLoader);
    gltfLoader.load('/models/cyborg/cyborg_female_separated.glb', (gltf) => {
      if (disposed) return;
      const model = gltf.scene;
      model.traverse((node) => {
        if (node.isMesh) node.material = chooseMaterial(node.name, materials);
      });
      // Normalise: feet at y=0, figure ~1.9 units tall, centred.
      const box = new THREE.Box3().setFromObject(model);
      const size = box.getSize(new THREE.Vector3());
      const scale = FIGURE_HEIGHT / size.y;
      model.scale.setScalar(scale);
      box.setFromObject(model);
      const center = box.getCenter(new THREE.Vector3());
      model.position.x -= center.x;
      model.position.z -= center.z;
      model.position.y -= box.min.y;
      // Rig formula: scanline density is fixed in the model's own units, so
      // the raster survives any display scale.
      Object.values(materials).forEach((m) => { m.uniforms.uScanlineFreq.value = 140 / scale; });
      figure.add(model);
      if (reduceMotion) renderer.render(scene, camera);
    });

    const resize = () => {
      const { clientWidth: w, clientHeight: h } = host;
      if (!w || !h) return;
      renderer.setSize(w, h, false);
      camera.aspect = w / h;
      camera.updateProjectionMatrix();
      if (reduceMotion) renderer.render(scene, camera);
    };
    const observer = new ResizeObserver(resize);
    observer.observe(host);
    resize();

    if (!reduceMotion) {
      const tick = (ms) => {
        const t = ms / 1000;
        figure.rotation.y = 0.28 * Math.sin(t * 0.22) - 0.12;
        driveHologram(materials, t);
        renderer.render(scene, camera);
        raf = requestAnimationFrame(tick);
      };
      raf = requestAnimationFrame(tick);
    }
    // Reduced motion: uniforms stay at their defaults — no scanlines, no
    // flicker, no glitch — a static etched-glass figure, matching the rig's
    // own reducedMotion behavior.

    return () => {
      disposed = true;
      cancelAnimationFrame(raf);
      observer.disconnect();
      scene.traverse((node) => {
        if (node.isMesh) node.geometry?.dispose();
      });
      Object.values(materials).forEach((m) => m.dispose());
      dracoLoader.dispose();
      renderer.dispose();
      renderer.domElement.remove();
    };
  }, []);

  return <div ref={mount} aria-hidden="true" className={className} />;
}
