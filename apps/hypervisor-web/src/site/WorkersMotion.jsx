const React = window.React;
// Workers-section motion — count-up stats + a native octahedron-facet field.
// The facet field is the on-brand echo of the IOI mark (a triangulated
// octahedron), used in place of a borrowed round-dot grid.
const { useState, useEffect, useRef, useReducer, useMemo } = React;

/* tiny shared store so the Tweaks panel can drive both pieces */
const _store = (window.__hvMotion = window.__hvMotion || { statCount: true, triField: true, subs: new Set() });
function setMotion(patch) { Object.assign(_store, patch); _store.subs.forEach((f) => f()); }
function useMotion() {
  const [, force] = useReducer((x) => x + 1, 0);
  useEffect(() => { _store.subs.add(force); return () => { _store.subs.delete(force); }; }, []);
  return _store;
}

const REDUCED = typeof window !== "undefined" && window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function useInView(threshold) {
  const ref = useRef(null);
  const [seen, setSeen] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el || seen) return;
    let done = false;
    const check = () => {
      if (done) return;
      const r = el.getBoundingClientRect();
      const vh = window.innerHeight || document.documentElement.clientHeight;
      if (r.top < vh * 0.9 && r.bottom > vh * 0.06) { done = true; setSeen(true); cleanup(); }
    };
    const cleanup = () => {
      window.removeEventListener("scroll", check, true);
      window.removeEventListener("resize", check);
    };
    window.addEventListener("scroll", check, true);
    window.addEventListener("resize", check);
    check();
    const t1 = setTimeout(check, 300);
    const t2 = setTimeout(check, 1200);
    return () => { cleanup(); clearTimeout(t1); clearTimeout(t2); };
  }, [seen]);
  return [ref, seen];
}

/* ---- odometer-style count up ---- */
function CountStat({ to, decimals = 0, prefix = "", suffix = "", style }) {
  const motion = useMotion();
  const [ref, seen] = useInView(0.45);
  const [val, setVal] = useState(motion.statCount && !REDUCED ? 0 : to);
  useEffect(() => {
    if (!motion.statCount || REDUCED) { setVal(to); return; }
    if (!seen) { setVal(0); return; }
    let raf;
    const t0 = performance.now();
    const dur = 1500;
    const tick = (now) => {
      const p = Math.min(1, (now - t0) / dur);
      const e = 1 - Math.pow(1 - p, 3);
      setVal(to * e);
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [seen, motion.statCount, to]);
  const num = val.toLocaleString("en-US", { minimumFractionDigits: decimals, maximumFractionDigits: decimals });
  return <div ref={ref} style={style}>{prefix}{num}{suffix}</div>;
}

/* ---- triangulated facet field ---- */
function buildFacets(W, H, g, t) {
  const out = [];
  for (let r = 0; r * g <= H; r++) {
    const cy = r * g;
    for (let c = 0; c * g <= W; c++) {
      const cx = c * g + (r % 2 ? g / 2 : 0);
      if (cx > W) continue;
      const up = (r + c) % 2 === 0;
      const pts = up
        ? `${cx},${(cy - t).toFixed(1)} ${(cx + t * 0.87).toFixed(1)},${(cy + t * 0.5).toFixed(1)} ${(cx - t * 0.87).toFixed(1)},${(cy + t * 0.5).toFixed(1)}`
        : `${cx},${(cy + t).toFixed(1)} ${(cx + t * 0.87).toFixed(1)},${(cy - t * 0.5).toFixed(1)} ${(cx - t * 0.87).toFixed(1)},${(cy - t * 0.5).toFixed(1)}`;
      // vertical falloff (fade top/bottom) + organic jitter
      const vf = Math.sin(Math.PI * (cy / H));
      const op = Math.max(0, 0.6 * vf * (0.55 + 0.45 * ((Math.sin(cx * 12.9 + cy * 78.2) + 1) / 2)));
      out.push({ pts, cx, op });
    }
  }
  return out;
}

function TriField({ side }) {
  const motion = useMotion();
  const [ref, seen] = useInView(0.25);
  const W = 168, H = 256, g = 18, t = 4.4;
  const facets = useMemo(() => buildFacets(W, H, g, t), []);
  if (!motion.triField) return null;
  const outer = side === "left" ? "left" : "right";
  const fade = side === "left"
    ? "linear-gradient(to right, transparent 4%, #000 78%)"
    : "linear-gradient(to left, transparent 4%, #000 78%)";
  const pos = side === "left" ? { right: "100%", marginRight: "1.75rem" } : { left: "100%", marginLeft: "1.75rem" };
  return (
    <div
      ref={ref}
      className="hv-trifield"
      data-in={seen ? 1 : 0}
      aria-hidden="true"
      style={{ position: "absolute", top: "50%", transform: "translateY(-50%)", width: W, height: H, zIndex: 0, pointerEvents: "none", WebkitMaskImage: fade, maskImage: fade, ...pos }}
    >
      <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} fill="none">
        {facets.map((f, i) => {
          const dnorm = side === "left" ? (W - f.cx) / W : f.cx / W; // inner edge first
          const delay = (dnorm * 0.4 + (i % 6) * 0.015).toFixed(3);
          return <polygon key={i} className="tri" points={f.pts} fill="var(--color-link-green)" style={{ fillOpacity: f.op, animationDelay: `${delay}s` }} />;
        })}
      </svg>
    </div>
  );
}

window.WorkersMotion = { CountStat, TriField, setMotion, useMotion };
