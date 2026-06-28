const React = window.React;
// hypervisor.com — volumetric octahedron (the brand mark, made solid).
// A hand-rolled 3D render of the ioi octahedron: 6 vertices, 8 lit faces,
// painter-sorted, edge-lit, with a faint green core glow. Greyscale-luminous
// for dark surfaces by default. Slow auto-rotation; drag to orbit.
//
// Driver note: requestAnimationFrame is paused in some embedded/preview
// contexts, so we start on rAF and fall back to setInterval if it never ticks.
function HvOcta({ size = 130, interactive = true, glow = true, speed = 0.5, theme = "dark" }) {
  const ref = React.useRef(null);
  const ang = React.useRef({ x: 0.62, y: 0.5 });
  const drag = React.useRef({ active: false, lx: 0, ly: 0 });

  React.useEffect(function () {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const dark = theme !== "light";

    function fit() {
      const w = canvas.clientWidth || size, h = canvas.clientHeight || size;
      canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    fit();
    const ro = new ResizeObserver(fit); ro.observe(canvas);

    // geometry
    const OV = [[1, 0, 0], [-1, 0, 0], [0, 1, 0], [0, -1, 0], [0, 0, 1], [0, 0, -1]];
    const OF = [];
    [0, 1].forEach(function (sx) { [2, 3].forEach(function (sy) { [4, 5].forEach(function (sz) { OF.push([sx, sy, sz]); }); }); });
    const L = (function () { const a = [0.45, 0.7, 0.75], m = Math.hypot(a[0], a[1], a[2]); return [a[0] / m, a[1] / m, a[2] / m]; })();
    const EDGE = dark ? "255,255,255" : "10,14,25";
    const GREEN = "219,239,219";

    function rotate(p, ax, ay) {
      const x = p[0], y = p[1], z = p[2];
      const cy = Math.cos(ay), sy = Math.sin(ay);
      const x1 = x * cy + z * sy, z1 = -x * sy + z * cy;
      const cx = Math.cos(ax), sx = Math.sin(ax);
      const y1 = y * cx - z1 * sx, z2 = y * sx + z1 * cx;
      return [x1, y1, z2];
    }
    function proj(p, cx, cy, s, camZ) { const k = camZ / (camZ - p[2]); return [cx + p[0] * s * k, cy - p[1] * s * k]; }
    function nrm(a) { const m = Math.hypot(a[0], a[1], a[2]) || 1; return [a[0] / m, a[1] / m, a[2] / m]; }
    function dot(a, b) { return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]; }

    let lastT = performance.now();
    function draw() {
      const now = performance.now();
      const dt = Math.min((now - lastT) / 1000, 0.05); lastT = now;
      if (!drag.current.active && !reduce) ang.current.y += dt * speed;

      const W = canvas.clientWidth || size, H = canvas.clientHeight || size;
      ctx.clearRect(0, 0, W, H);
      const cx = W / 2, cy = H / 2, s = Math.min(W, H) * 0.34;
      const ax = ang.current.x, ay = ang.current.y;
      const rv = OV.map(function (v) { return rotate(v, ax, ay); });

      if (glow) {
        const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, s * 1.15);
        g.addColorStop(0, "rgba(" + GREEN + ",0.16)"); g.addColorStop(1, "rgba(" + GREEN + ",0)");
        ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);
      }

      const faces = OF.map(function (f) {
        const a = rv[f[0]], b = rv[f[1]], c = rv[f[2]];
        const cen = [(a[0] + b[0] + c[0]) / 3, (a[1] + b[1] + c[1]) / 3, (a[2] + b[2] + c[2]) / 3];
        const bright = Math.max(0, dot(nrm(cen), L));
        return { pts: [a, b, c], cz: cen[2], bright: bright, front: cen[2] > -0.02 };
      });
      faces.sort(function (p, q) { return p.cz - q.cz; });

      for (let i = 0; i < faces.length; i++) {
        const fc = faces[i];
        const P = fc.pts.map(function (v) { return proj(v, cx, cy, s, 3.4); });
        ctx.beginPath(); ctx.moveTo(P[0][0], P[0][1]); ctx.lineTo(P[1][0], P[1][1]); ctx.lineTo(P[2][0], P[2][1]); ctx.closePath();
        const fa = (fc.front ? 0.07 : 0.02) + fc.bright * (dark ? 0.5 : 0.34);
        ctx.fillStyle = (dark ? "rgba(255,255,255," : "rgba(10,14,25,") + fa.toFixed(3) + ")";
        ctx.fill();
        ctx.strokeStyle = "rgba(" + EDGE + "," + ((dark ? 0.22 : 0.3) + fc.bright * 0.55).toFixed(3) + ")";
        ctx.lineWidth = 1.1; ctx.lineJoin = "round"; ctx.stroke();
      }
    }

    // hybrid driver
    let ticked = false, rafId = 0, intId = 0;
    function rafLoop() { draw(); ticked = true; rafId = requestAnimationFrame(rafLoop); }
    rafId = requestAnimationFrame(rafLoop);
    const watchdog = setTimeout(function () { if (!ticked) { intId = setInterval(draw, 1000 / 40); } }, 450);

    // drag to orbit
    function onDown(e) { if (!interactive) return; drag.current.active = true; drag.current.lx = e.clientX; drag.current.ly = e.clientY; try { canvas.setPointerCapture(e.pointerId); } catch (x) {} }
    function onMove(e) {
      if (!drag.current.active) return;
      ang.current.y += (e.clientX - drag.current.lx) * 0.01;
      ang.current.x += (e.clientY - drag.current.ly) * 0.01;
      ang.current.x = Math.max(-1.2, Math.min(1.2, ang.current.x));
      drag.current.lx = e.clientX; drag.current.ly = e.clientY;
    }
    function onUp() { drag.current.active = false; }
    if (interactive) {
      canvas.addEventListener("pointerdown", onDown);
      canvas.addEventListener("pointermove", onMove);
      window.addEventListener("pointerup", onUp);
    }

    return function () {
      ro.disconnect(); clearTimeout(watchdog);
      if (rafId) cancelAnimationFrame(rafId); if (intId) clearInterval(intId);
      if (interactive) { canvas.removeEventListener("pointerdown", onDown); canvas.removeEventListener("pointermove", onMove); window.removeEventListener("pointerup", onUp); }
    };
  }, [size, interactive, glow, speed, theme]);

  return <canvas ref={ref} style={{ width: size, height: size, display: "block", cursor: interactive ? "grab" : "default", touchAction: "none" }} />;
}
window.HvOcta = HvOcta;
