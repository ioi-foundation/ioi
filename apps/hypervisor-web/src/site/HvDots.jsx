const React = window.React;
// Faceted-polygon illustration (site-scoped) — a low-poly triangular lattice
// inspired by the facets of the ioi octahedron mark. Outlined triangles with a
// sparse scatter of lit/accent facets. Greyscale on light; luminous on dark
// (inverse). Pass `interactive` for cursor-proximity lighting + a subtle ambient
// shimmer (reduced-motion aware) — reserve it for large hero/doctrine panels.
function hvBuildFacets(cols, rows, gap, seed, inverse) {
  const fills = inverse
    ? ["transparent", "rgba(255,255,255,0.05)", "rgba(255,255,255,0.13)", "var(--color-pistachio-green)"]
    : ["transparent", "#ECECEC", "#D4D4D4", "var(--color-link-green)"];
  const stroke = inverse ? "rgba(255,255,255,0.15)" : "rgba(0,0,0,0.12)";
  const sw = Math.max(0.6, gap * 0.04);
  const hash = (x, y) => { const v = Math.sin(x * 127.1 + y * 311.7 + seed * 13.17) * 43758.5453; return v - Math.floor(v); };
  const pt = (c, r) => {
    const edge = c === 0 || r === 0 || c === cols || r === rows;
    const j = edge ? 0 : gap * 0.42;
    return [c * gap + (hash(c, r) - 0.5) * j, r * gap + (hash(c + 7.3, r + 4.1) - 0.5) * j];
  };
  const shade = (c, r, h) => { const v = hash(c * 2 + h * 0.5 + 0.3, r * 2 + 0.7); return v < 0.05 ? 3 : v < 0.15 ? 2 : v < 0.4 ? 1 : 0; };
  const tris = [];
  for (let r = 0; r < rows; r++) {
    for (let c = 0; c < cols; c++) {
      const a = pt(c, r), b = pt(c + 1, r), d = pt(c, r + 1), e = pt(c + 1, r + 1);
      [[[a, b, e], shade(c, r, 0)], [[a, e, d], shade(c, r, 1)]].forEach(([tp, si]) => {
        tris.push({
          points: tp.map((p) => `${p[0]},${p[1]}`).join(" "),
          fill: fills[si], cx: (tp[0][0] + tp[1][0] + tp[2][0]) / 3, cy: (tp[0][1] + tp[1][1] + tp[2][1]) / 3,
        });
      });
    }
  }
  return { tris, stroke, sw, accent: inverse ? "var(--color-pistachio-green)" : "var(--color-link-green)" };
}

function HvDots({ cols = 11, rows = 11, gap = 22, dot = 7, seed = 0, inverse = false, interactive = false, cover = false }) {
  const svgRef = React.useRef(null);
  const elsRef = React.useRef([]);
  const geom = React.useMemo(() => hvBuildFacets(cols, rows, gap, seed, inverse), [cols, rows, gap, seed, inverse]);

  React.useEffect(() => {
    if (!interactive) return;
    const svg = svgRef.current;
    if (!svg) return;
    const tris = geom.tris, els = elsRef.current, accent = geom.accent;
    const R = gap * 2.6;
    const state = new Float32Array(tris.length);
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    let mx = null, my = null, raf = 0;
    const t0 = performance.now();

    function frame(now) {
      raf = requestAnimationFrame(frame);
      let ux = null, uy = null;
      if (mx != null) {
        const ctm = svg.getScreenCTM();
        if (ctm) { const p = svg.createSVGPoint(); p.x = mx; p.y = my; const u = p.matrixTransform(ctm.inverse()); ux = u.x; uy = u.y; }
      }
      const ph = (now - t0) / 1000;
      for (let i = 0; i < tris.length; i++) {
        const t = tris[i];
        let inf = 0;
        if (ux != null) { const dd = Math.hypot(ux - t.cx, uy - t.cy); inf = Math.max(0, 1 - dd / R); inf *= inf; }
        if (!reduce) { const w = Math.sin((t.cx + t.cy) * 0.012 - ph * 0.9); inf = Math.max(inf, Math.max(0, w) * 0.13); }
        if (Math.abs(inf - state[i]) < 0.01) continue;
        state[i] = inf;
        const el = els[i];
        if (!el) continue;
        if (inf <= 0.01) { el.style.fill = ""; el.style.fillOpacity = ""; el.style.stroke = ""; el.style.strokeOpacity = ""; }
        else { el.style.fill = accent; el.style.fillOpacity = (0.08 + inf * 0.62).toFixed(3); el.style.stroke = accent; el.style.strokeOpacity = (0.18 + inf * 0.55).toFixed(3); }
      }
    }
    const onMove = (e) => { mx = e.clientX; my = e.clientY; };
    const onLeave = () => { mx = null; my = null; };
    window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("blur", onLeave);
    raf = requestAnimationFrame(frame);
    return () => { cancelAnimationFrame(raf); window.removeEventListener("pointermove", onMove); window.removeEventListener("blur", onLeave); };
  }, [interactive, geom, gap]);

  return (
    <svg ref={svgRef} viewBox={`0 0 ${cols * gap} ${rows * gap}`} width="100%" height="100%" preserveAspectRatio={cover ? "xMidYMid slice" : "xMidYMid meet"} aria-hidden="true" style={{ display: "block" }}>
      <g strokeLinejoin="round">
        {geom.tris.map((t, i) => (
          <polygon key={i} ref={(el) => { elsRef.current[i] = el; }} points={t.points} fill={t.fill} stroke={geom.stroke} strokeWidth={geom.sw} />
        ))}
      </g>
    </svg>
  );
}
window.HvDots = HvDots;
