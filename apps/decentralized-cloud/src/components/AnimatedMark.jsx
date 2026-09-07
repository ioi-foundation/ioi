import { useEffect, useRef, useState } from "react";
import { ANIM, INTERIOR_INDIGO, MARK_CYAN } from "../../brand/mark/mark.mjs";
import markSvg from "../../brand/mark/source/mark-dark.svg?raw";

// THE ANIMATED MARK — the owner's "replica engine", pure SVG DOM, in the header.
//
// Ported from brand/mark/source/mark-animated.html with its constants taken from
// mark.mjs (ANIM) and its arithmetic kept: a cloud extruded 0.34 deep is projected
// through a 45° camera in slices; a grid of blocks across its face sinks where the
// cut is, revealing the interior walls; a network of eight cyan nodes builds inside
// the cut and one node pulses at a time. The cut opens on load at the owner's default
// position and follows the pointer across the cloud. Two adaptations only: the stage
// is the mark's own box rather than the window, and the wordmark is not drawn here —
// the header sets it as live text beside this.
//
// HONEST MOTION. Brand motion, not a claim about data; confined to the lockup; paused
// while the tab is hidden; and under prefers-reduced-motion the owner's static mark
// (mark-dark.svg, verbatim) stands instead.

const W = 420, H = 250;
const clamp01 = (x) => Math.max(0, Math.min(1, x));
const lerp = (a, b, t) => a + (b - a) * t;
const easeOut = (x) => 1 - Math.pow(1 - x, 3);

const reducedMotion = () =>
  typeof window !== "undefined" && window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

export default function AnimatedMark() {
  const [reduce, setReduce] = useState(reducedMotion);
  const ref = useRef(null);

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
    const NS = "http://www.w3.org/2000/svg";
    const A = ANIM;
    const CIRCLES = A.circles, FLAT_Y = A.flatY, XMIN = A.xMin, XMAX = A.xMax;
    const DEPTH = A.depth, FRONT_Z = DEPTH / 2, BACK_Z = -DEPTH / 2;
    const BLOCK_FRONT = FRONT_Z + 0.0012, BLOCK_D = A.blockDepth, SINK = A.sink;
    const PITCH = A.pitch, X0 = A.x0, Y0 = A.y0;
    const CAMZ = A.camZ, CAMY = A.camY, FOV = A.fov;
    const U = A.u, HW = A.halfWidth, DEF = A.defaultCut, NZ = FRONT_Z + A.nodeZOffset;
    const NODES = A.nodes, EDGES = A.edges;
    const WALL = INTERIOR_INDIGO, NODE_C = MARK_CYAN;

    const topAt = (x) => { let y = -1e9; for (const [cx, cy, r] of CIRCLES) { const d = r * r - (x - cx) * (x - cx); if (d > 0) y = Math.max(y, cy + Math.sqrt(d)); } return y; };
    const bottomAt = (x) => { let y = 1e9; for (const [cx, cy, r] of CIRCLES) { const d = r * r - (x - cx) * (x - cx); if (d > 0) y = Math.min(y, cy - Math.sqrt(d)); } return Math.max(y, FLAT_Y); };
    const insideInset = (x, y, m) => { if (y < FLAT_Y + m) return false; for (const [cx, cy, r] of CIRCLES) { if (Math.hypot(x - cx, y - cy) <= r - m) return true; } return false; };

    // Cells and the union hole, the owner's exact port.
    const cells = [];
    for (let iy = 0; Y0 + iy * PITCH <= 0.66; iy++) for (let ix = 0; X0 + ix * PITCH <= 0.90; ix++) {
      const x = X0 + ix * PITCH, y = Y0 + iy * PITCH;
      if (insideInset(x, y, A.inset)) cells.push({ ix, iy, x, y });
    }
    const occ = {}; cells.forEach((c) => { occ[c.ix + "," + c.iy] = 1; });
    const adj = {};
    const lk = (a, b) => { (adj[a] = adj[a] || []).push(b); (adj[b] = adj[b] || []).push(a); };
    cells.forEach((c) => {
      if (!occ[c.ix + "," + (c.iy - 1)]) lk(c.ix + "," + c.iy, (c.ix + 1) + "," + c.iy);
      if (!occ[c.ix + "," + (c.iy + 1)]) lk(c.ix + "," + (c.iy + 1), (c.ix + 1) + "," + (c.iy + 1));
      if (!occ[(c.ix - 1) + "," + c.iy]) lk(c.ix + "," + c.iy, c.ix + "," + (c.iy + 1));
      if (!occ[(c.ix + 1) + "," + c.iy]) lk((c.ix + 1) + "," + c.iy, (c.ix + 1) + "," + (c.iy + 1));
    });
    const startK = Object.keys(adj)[0], loop = [startK];
    let prevK = null, curK = startK;
    do {
      const nb = adj[curK]; let nx = null;
      for (let i = 0; i < nb.length; i++) if (nb[i] !== prevK) { nx = nb[i]; break; }
      if (nx === null) nx = nb[0];
      prevK = curK; curK = nx; loop.push(curK);
    } while (curK !== startK && loop.length < 500);
    const rim = loop.slice(0, -1).map((k) => { const p = k.split(","); return [X0 + (p[0] - 0.5) * PITCH, Y0 + (p[1] - 0.5) * PITCH]; });
    const N = A.samples;
    const pts = [];
    for (let i = 0; i <= N; i++) { const x = XMIN + (XMAX - XMIN) * (i / N); pts.push([x, topAt(x)]); }
    for (let i = N; i >= 0; i--) { const x = XMIN + (XMAX - XMIN) * (i / N); pts.push([x, bottomAt(x)]); }
    let facePathD = "M " + pts.map((p) => p[0].toFixed(4) + " " + p[1].toFixed(4)).join(" L ") + " Z";
    facePathD += " M " + rim.map((p) => p[0].toFixed(4) + " " + p[1].toFixed(4)).join(" L ") + " Z";

    const g = [0.45 / 2.01, 0.55 / 1.06], g2 = g[0] * g[0] + g[1] * g[1];
    const GP0 = [-1.055, -0.30], GP1 = [-1.055 + g[0] / g2, -0.30 + g[1] / g2];

    svg.textContent = "";
    const el = (name, attrs, parent) => { const e = document.createElementNS(NS, name); for (const k in attrs) e.setAttribute(k, attrs[k]); (parent || svg).appendChild(e); return e; };
    const defs = el("defs", {});
    const grad = el("linearGradient", { id: "dc-anim-gg", gradientUnits: "userSpaceOnUse", x1: GP0[0], y1: GP0[1], x2: GP1[0], y2: GP1[1] }, defs);
    A.gradientStops.forEach((s) => { el("stop", { offset: s[0], "stop-color": s[1] }, grad); });
    const SLICES = A.slices;
    const sweepG = el("g", {});
    const sweepEls = [];
    for (let s1 = 0; s1 < SLICES; s1++) sweepEls.push(el("path", { d: facePathD, fill: WALL, "fill-rule": "evenodd" }, sweepG));
    const blockSidesG = el("g", {});
    const blockFrontsG = el("g", {});
    const faceG = el("g", {});
    el("path", { d: facePathD, fill: "url(#dc-anim-gg)", "fill-rule": "evenodd" }, faceG);
    const netG = el("g", {});
    const SIDE_SLICES = A.sideSlices;
    const blockEls = cells.map((c) => {
      const sides = [];
      for (let i = 0; i < SIDE_SLICES; i++) sides.push(el("rect", { x: c.x - PITCH / 2, y: c.y - PITCH / 2, width: PITCH, height: PITCH, fill: WALL }, blockSidesG));
      const fr = el("rect", { x: c.x - PITCH / 2 - 0.004, y: c.y - PITCH / 2 - 0.004, width: PITCH + 0.008, height: PITCH + 0.008, fill: "url(#dc-anim-gg)" }, blockFrontsG);
      return { c, sides, fr, k: 0 };
    });
    const nEls = NODES.map(() => el("rect", { rx: 0.012, fill: NODE_C, opacity: 0 }, netG));
    const eEls = EDGES.map(() => el("line", { stroke: NODE_C, "stroke-width": 1, "vector-effect": "non-scaling-stroke", opacity: 0 }, netG));
    const tmpl = NODES.map((n) => ({ u: n[0], v: n[1], t0: 0.15 + n[1] * 0.35 + Math.abs(n[0]) * 0.08 }));

    // Layout: the owner's projection, with the stage being this box and no wordmark
    // beside the cloud (the header sets it separately).
    let ppw = 1, targetX = 0, axisX = 0, axisY = 0, camz = CAMZ;
    const planeK = (z) => ppw * camz / (camz - z);
    const planeTransform = (z) => { const k = planeK(z); return "translate(" + (axisX - targetX * k) + "," + (axisY + CAMY * k) + ") scale(" + k + "," + (-k) + ")"; };
    const layout = () => {
      svg.setAttribute("viewBox", "0 0 " + W + " " + H);
      const t2 = 2 * Math.tan(FOV * Math.PI / 360);
      ppw = Math.min(H / (t2 * CAMZ), (0.98 * W) / (XMAX - XMIN));
      camz = H / (t2 * ppw);
      const cloudW = (XMAX - XMIN) * ppw;
      const leftPx = (W - cloudW) / 2;
      targetX = XMIN - (leftPx - W / 2) / ppw;
      axisX = W / 2; axisY = H / 2;
      faceG.setAttribute("transform", planeTransform(FRONT_Z));
      netG.setAttribute("transform", planeTransform(NZ));
      for (let i = 0; i < SLICES; i++) sweepEls[i].setAttribute("transform", planeTransform(lerp(BACK_Z, FRONT_Z, i / (SLICES - 1))));
    };
    layout();

    // Interaction: pointer positions mapped from the element's box into the stage.
    let hovering = false, tx = DEF, o = 0, cx = DEF, last = 0;
    const onMove = (e) => {
      const b = svg.getBoundingClientRect();
      const px = (e.clientX - b.left) / b.width * W, py = (e.clientY - b.top) / b.height * H;
      const kf = planeK(FRONT_Z);
      const wx = (px - axisX) / kf + targetX, wy = CAMY - (py - axisY) / kf;
      hovering = insideInset(wx, wy, -0.15);
      tx = hovering ? Math.max(-0.52, Math.min(0.55, wx)) : DEF;
    };
    const onLeave = () => { hovering = false; tx = DEF; };
    svg.addEventListener("pointermove", onMove);
    svg.addEventListener("pointerleave", onLeave);

    let raf = 0;
    const frame = (now) => {
      const dt = Math.min(0.05, (now - last) / 1000) || 0; last = now;
      o += (1 - o) * Math.min(1, dt * (hovering ? 5 : 2));
      cx += (tx - cx) * Math.min(1, dt * 9);
      const ch = HW * easeOut(clamp01(o / 0.7));
      for (const b of blockEls) {
        const target = o < 0.01 ? 0 : clamp01((ch - Math.abs(b.c.x - cx)) / 0.06);
        const rate = 7 + (b.c.y + 0.30) * 9;
        b.k += (target - b.k) * Math.min(1, dt * rate);
        const k = b.k, s = k * k * (3 - 2 * k);
        const zf = BLOCK_FRONT - s * SINK;
        const fade = 1 - clamp01((k - 0.5) / 0.35);
        b.fr.setAttribute("transform", planeTransform(zf));
        b.fr.setAttribute("opacity", fade.toFixed(3));
        b.fr.style.display = fade > 0.005 ? "" : "none";
        for (let j = 0; j < SIDE_SLICES; j++) {
          const zs = zf - BLOCK_D * (j + 1) / SIDE_SLICES;
          b.sides[j].setAttribute("transform", planeTransform(zs));
          b.sides[j].setAttribute("opacity", fade.toFixed(3));
          b.sides[j].style.display = fade > 0.005 ? "" : "none";
        }
      }
      const tNow = now / 1000;
      const gi = Math.floor(tNow / A.pulsePeriod) % tmpl.length, gph = (tNow % A.pulsePeriod) / A.pulsePeriod;
      const st = tmpl.map((n) => {
        const x = cx + n.u * U, top = topAt(x), bot = bottomAt(x);
        if (top < -1e8) return { x: 0, y: 0, k: 0, settle: 0 };
        const y = lerp(top - 0.08, bot + 0.07, n.v);
        const q = clamp01((o - n.t0) / 0.3);
        let kk = q < 0.6 ? easeOut(q / 0.6) * 1.2 : lerp(1.2, 1, (q - 0.6) / 0.4);
        kk *= clamp01((ch - Math.abs(n.u * U) - 0.027) / 0.072);
        return { x, y, k: kk, settle: clamp01((o - n.t0 - 0.2) / 0.3) };
      });
      st.forEach((s2, i) => {
        const elN = nEls[i];
        const pulse = i === gi ? Math.exp(-Math.pow((gph - 0.5) * 5, 2)) : 0;
        const sz = A.nodeSize * Math.max(0.0001, s2.k) * (1 + 0.22 * pulse);
        elN.setAttribute("x", s2.x - sz / 2); elN.setAttribute("y", s2.y - sz / 2);
        elN.setAttribute("width", sz); elN.setAttribute("height", sz);
        elN.setAttribute("rx", sz * 0.1667);
        elN.setAttribute("opacity", s2.k > 0 ? 1 : 0);
      });
      EDGES.forEach((e2, i) => {
        const P = st[e2[0]], Q = st[e2[1]], k3 = Math.min(P.settle, Q.settle);
        const on = P.k > 0 && Q.k > 0 && k3 > 0;
        const elE = eEls[i];
        elE.setAttribute("opacity", on ? (Math.min(P.k, Q.k, 1) * 0.85).toFixed(3) : 0);
        if (on) { elE.setAttribute("x1", P.x); elE.setAttribute("y1", P.y); elE.setAttribute("x2", lerp(P.x, Q.x, easeOut(k3))); elE.setAttribute("y2", lerp(P.y, Q.y, easeOut(k3))); }
      });
      raf = requestAnimationFrame(frame);
    };
    const onVis = () => { cancelAnimationFrame(raf); if (document.visibilityState === "visible") { last = 0; raf = requestAnimationFrame(frame); } };
    document.addEventListener("visibilitychange", onVis);
    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      document.removeEventListener("visibilitychange", onVis);
      svg.removeEventListener("pointermove", onMove);
      svg.removeEventListener("pointerleave", onLeave);
    };
  }, [reduce]);

  // REDUCED MOTION: the owner's static mark, the file verbatim.
  if (reduce) {
    return <span className="mark mark-static" role="img" aria-label="decentralized.cloud" dangerouslySetInnerHTML={{ __html: markSvg }} />;
  }
  return (
    <svg ref={ref} className="mark mark-live" viewBox={`0 0 ${W} ${H}`} role="img"
      aria-label="decentralized.cloud — a cloud whose face opens into a network of connected nodes" />
  );
}
