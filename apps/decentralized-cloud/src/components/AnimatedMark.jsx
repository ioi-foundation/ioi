import { useEffect, useRef, useState } from "react";
import {
  MARK_BOX, MARK_PATHS, MARK_GRADIENT, MARK_WIDTH, MARK_HEIGHT, CUT_NODES, CUT_EDGES,
  CUT_EDGE_WIDTH, CUT_NODE_RADIUS, ANIM, inCloud,
} from "../../brand/mark/mark.mjs";

// THE ANIMATED MARK — the owner's "cloud to network", as pure SVG DOM.
//
// Ported from the owner's SVG animation with its geometry and timing taken from
// brand/mark/mark.mjs (ANIM) rather than copied: the cloud is the same five paths the
// static mark and the gate carry, clipped at a seam; right of the seam a pixel field
// and a network of squares build, pulses ride the network while it is live, the seam
// sweeps right as the cloud reabsorbs it, and it recedes. One loop is ANIM.duration
// seconds. The owner ruled (2026-09-07) that the header carries this animated lockup.
//
// HONEST MOTION. This is brand motion, not a claim about data: it is the one
// animation on the face that is not bound to a daemon timestamp, and it is confined
// to the lockup. It stops entirely under prefers-reduced-motion — the static cut mark
// stands instead — and it pauses while the tab is hidden.

const clamp01 = (x) => Math.max(0, Math.min(1, x));
const lerp = (a, b, t) => a + (b - a) * t;
const easeOut = (x) => 1 - Math.pow(1 - x, 3);
const easeInOut = (x) => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2);

// The field and the fibres are built once, from ANIM's seed, so the drawing is the
// same on every load.
function buildScene() {
  let seed = ANIM.seed;
  const rnd = () => (seed = (seed * 9301 + 49297) % 233280) / 233280;
  const nodes = ANIM.nodes.map((n) => ({ ...n, d: clamp01((n.x - ANIM.buildFrom) / ANIM.buildSpan) }));
  const pixels = [];
  const P = ANIM.pixels;
  for (let gx = P.x0; gx <= P.x1; gx += P.step) {
    const u = (gx - P.x0) / P.span;
    const keep = 1 - u * u * 0.98 - u * 0.15;
    for (let gy = P.y0; gy <= P.y1; gy += P.step) {
      if (rnd() > keep) continue;
      const s = Math.max(3, Math.round(lerp(8, 3.5, u) + (rnd() - 0.5) * 3));
      const x = gx + (rnd() - 0.5) * 3, y = gy + (rnd() - 0.5) * 3;
      if (!inCloud(x + s / 2, y + s / 2)) continue;
      pixels.push({ x, y, s, d: u * 0.7 + rnd() * 0.3 });
    }
  }
  const F = ANIM.fibres;
  const fibres = [];
  nodes.slice(7).forEach((n, i) => {
    for (let k = 0; k < 3; k++) {
      const ex = F.x0 + rnd() * F.xSpread, ey = n.y + (k - 1) * F.dy + (rnd() - 0.5) * F.jitter;
      if (!inCloud(ex, ey)) continue;
      fibres.push({ sat: 7 + i, ex, ey, c1x: n.x - F.c1, c1y: n.y, c2x: ex + F.c2, c2y: ey });
    }
  });
  return { nodes, pixels, fibres };
}

const reducedMotion = () =>
  typeof window !== "undefined" && window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

export default function AnimatedMark({ id = "dc-mark-g" }) {
  const [reduce, setReduce] = useState(reducedMotion);
  const ref = useRef(null);
  const scene = useRef(null);
  if (!scene.current) scene.current = buildScene();

  useEffect(() => {
    if (!window.matchMedia) return undefined;
    const mq = window.matchMedia("(prefers-reduced-motion: reduce)");
    const on = () => setReduce(mq.matches);
    mq.addEventListener?.("change", on);
    return () => mq.removeEventListener?.("change", on);
  }, []);

  useEffect(() => {
    if (reduce) return undefined;
    const svg = ref.current;
    if (!svg) return undefined;
    const { nodes, pixels, fibres } = scene.current;
    const T = ANIM.times, D = ANIM.duration;
    const cut = svg.querySelector("[data-cut]");
    const nodeEls = [...svg.querySelectorAll("[data-node]")];
    const edgeEls = [...svg.querySelectorAll("[data-edge]")];
    const pxEls = [...svg.querySelectorAll("[data-px]")];
    const fibreEls = [...svg.querySelectorAll("[data-fibre]")];
    const signals = svg.querySelector("[data-signals]");

    const front = (t) => {
      if (t < T.sweep) return ANIM.seam;
      if (t < T.sweepEnd) return lerp(ANIM.seam, ANIM.full, easeInOut((t - T.sweep) / (T.sweepEnd - T.sweep)));
      if (t < T.recede) return ANIM.full;
      if (t < T.recedeEnd) return lerp(ANIM.full, ANIM.seam, easeInOut((t - T.recede) / (T.recedeEnd - T.recede)));
      return ANIM.seam;
    };
    const nodeState = (n, t, fx) => {
      const t0 = T.build + 0.35 + n.d * T.buildDur;
      let k = 0, x = n.x;
      if (t >= t0 && t < T.sweep) {
        const q = clamp01((t - t0) / 0.45);
        k = q < 0.6 ? easeOut(q / 0.6) * 1.2 : lerp(1.2, 1, (q - 0.6) / 0.4);
      } else if (t >= T.sweep && t < T.sweepEnd) {
        const p = (fx - ANIM.seam) / (ANIM.full - ANIM.seam);
        x = n.x - p * (n.x - ANIM.seam) * 0.45;
        k = clamp01((x - fx) / 28);
      }
      return { x, y: n.y, k };
    };
    const settledSince = (n, t) => t - (T.build + 0.35 + n.d * T.buildDur + 0.25);

    let raf = 0;
    const frame = (now) => {
      const t = (((now / 1000) % D) + D) % D;
      const fx = front(t);
      cut.setAttribute("width", fx);

      pixels.forEach((p, i) => {
        let k = 0, dx = 0;
        if (t < T.sweep) { const q = clamp01((t - T.build - p.d * 0.9) / 0.35); k = easeOut(q); dx = lerp(-10, 0, k); }
        else if (t < T.sweepEnd) k = clamp01((p.x + p.s / 2 - fx) / 14);
        else if (t >= T.recede) { const q = clamp01((t - T.recede - 0.25 - p.d * 0.8) / 0.35); k = easeOut(q); dx = lerp(-10, 0, k); k = Math.min(k, clamp01((p.x + p.s / 2 - fx) / 14)); }
        const s = p.s * k, el = pxEls[i];
        el.setAttribute("x", p.x + dx + (p.s - s) / 2); el.setAttribute("y", p.y + (p.s - s) / 2);
        el.setAttribute("width", s); el.setAttribute("height", s);
      });

      const st = nodes.map((n) => nodeState(n, t, fx));
      nodes.forEach((n, i) => {
        const { x, y, k } = st[i], s = n.s * k, el = nodeEls[i];
        el.setAttribute("x", x - s / 2); el.setAttribute("y", y - s / 2);
        el.setAttribute("width", s); el.setAttribute("height", s);
      });

      fibres.forEach((f, i) => {
        const S = st[f.sat], el = fibreEls[i];
        let k = 0;
        if (t < T.sweep) k = easeOut(clamp01(settledSince(nodes[f.sat], t) / 0.5));
        else if (t < T.sweepEnd) k = S.k > 0 && f.ex > fx ? 1 : 0;
        const dxs = S.x - nodes[f.sat].x;
        el.setAttribute("d", `M ${S.x} ${S.y} C ${f.c1x + dxs} ${f.c1y} ${f.c2x} ${f.c2y} ${f.ex} ${f.ey}`);
        const len = el.getTotalLength();
        el.setAttribute("stroke-dasharray", len); el.setAttribute("stroke-dashoffset", len * (1 - k));
        el.style.opacity = k > 0 ? 0.75 * Math.min(S.k, 1) : 0;
      });

      ANIM.edges.forEach(([a, b], i) => {
        const A = st[a], B = st[b], el = edgeEls[i];
        let k = 0;
        if (t < T.sweep) k = easeOut(clamp01(Math.min(settledSince(nodes[a], t), settledSince(nodes[b], t)) / 0.5));
        else if (t < T.sweepEnd) k = Math.min(A.k, B.k) > 0 ? 1 : 0;
        const len = Math.hypot(B.x - A.x, B.y - A.y);
        el.setAttribute("x1", A.x); el.setAttribute("y1", A.y); el.setAttribute("x2", B.x); el.setAttribute("y2", B.y);
        el.setAttribute("stroke-dasharray", len); el.setAttribute("stroke-dashoffset", len * (1 - k));
        el.style.opacity = k > 0 ? Math.min(A.k, B.k, 1) : 0;
      });

      signals.style.opacity = t >= T.live && t < T.sweep ? clamp01(Math.min((t - T.live) / 0.4, (T.sweep - t) / 0.3)) : 0;
      raf = requestAnimationFrame(frame);
    };
    // Paused while the tab is hidden: a brand loop nobody is looking at is cost.
    const onVis = () => {
      cancelAnimationFrame(raf);
      if (document.visibilityState === "visible") raf = requestAnimationFrame(frame);
    };
    document.addEventListener("visibilitychange", onVis);
    raf = requestAnimationFrame(frame);
    return () => { cancelAnimationFrame(raf); document.removeEventListener("visibilitychange", onVis); };
  }, [reduce]);

  const gradient = (
    <linearGradient id={id} gradientUnits="userSpaceOnUse"
      x1={MARK_GRADIENT.x1} y1={MARK_GRADIENT.y1} x2={MARK_GRADIENT.x2} y2={MARK_GRADIENT.y2}>
      <stop offset="0" stopColor={MARK_GRADIENT.from} />
      <stop offset="1" stopColor={MARK_GRADIENT.to} />
    </linearGradient>
  );

  // REDUCED MOTION: the static mark, the cloud with the network knocked out.
  if (reduce) {
    return (
      <svg className="mark" viewBox={MARK_BOX} role="img" aria-label="decentralized.cloud">
        <defs>
          {gradient}
          <mask id={`${id}-cut`} maskUnits="userSpaceOnUse" x="0" y="0" width={MARK_WIDTH} height={MARK_HEIGHT}>
            <rect width={MARK_WIDTH} height={MARK_HEIGHT} fill="#fff" />
            {CUT_EDGES.map(([a, b]) => (
              <line key={`${a}-${b}`} x1={CUT_NODES[a].x} y1={CUT_NODES[a].y} x2={CUT_NODES[b].x} y2={CUT_NODES[b].y}
                stroke="#000" strokeWidth={CUT_EDGE_WIDTH} />
            ))}
            {CUT_NODES.map((n, i) => (
              <rect key={i} x={n.x - n.s / 2} y={n.y - n.s / 2} width={n.s} height={n.s} rx={CUT_NODE_RADIUS} fill="#000" />
            ))}
          </mask>
        </defs>
        <g fill={`url(#${id})`} mask={`url(#${id}-cut)`}>
          {MARK_PATHS.map((d, i) => <path key={i} d={d} />)}
        </g>
      </svg>
    );
  }

  const { nodes, pixels, fibres } = scene.current;
  const paint = `url(#${id})`;
  return (
    <svg ref={ref} className="mark mark-live" viewBox={MARK_BOX} role="img"
      aria-label="decentralized.cloud — a cloud dissolving into a network of connected squares, then reabsorbing it">
      <defs>
        {gradient}
        <clipPath id={`${id}-seam`}><rect data-cut x="0" y="0" width={ANIM.seam} height={MARK_HEIGHT} /></clipPath>
      </defs>
      <g fill={paint} clipPath={`url(#${id}-seam)`}>
        {MARK_PATHS.map((d, i) => <path key={i} d={d} />)}
      </g>
      <g fill={paint}>
        {pixels.map((p, i) => <rect key={i} data-px="" rx="1" width="0" height="0" />)}
      </g>
      <g stroke={paint} fill="none" strokeWidth="1.3" strokeLinecap="round" className="mark-fibres">
        {fibres.map((f, i) => <path key={i} data-fibre="" d="" />)}
      </g>
      <g stroke={paint} fill="none" strokeLinecap="round">
        {ANIM.edges.map(([a, b, thin], i) => <line key={i} data-edge="" strokeWidth={thin ? 1.8 : 2.6} />)}
      </g>
      <g fill={paint}>
        {nodes.map((n, i) => <rect key={i} data-node="" rx="4" width="0" height="0" />)}
      </g>
      <g data-signals="" fill={ANIM.pulse} className="mark-signals">
        {ANIM.signals.map((s, i) => (
          <circle key={i} r="2.8">
            <animateMotion dur={`${s.dur}s`} begin={`${s.begin}s`} repeatCount="indefinite" path={s.path} />
          </circle>
        ))}
      </g>
    </svg>
  );
}
