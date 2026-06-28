const React = window.React;
// hypervisor.com — atmospheric depth field for faceted (triangle-accent) panels.
// Layered parallax lattice + depth-of-field blur + fog. The "Whisper" preset:
// it adds immersive depth BEHIND content without reading as a graphic. Drop it
// in place of an inverse `HvDots cover` background — same family, more dimension.
//
// Scope: only for dark containers that already use the triangle accent. Fills
// its parent (give the parent position + the radial mask, as before).
function HvDepthField({ seed = 0, intensity = 1, interactive = true }) {
  const ref = React.useRef(null);
  const cur = React.useRef({ mx: 0.5, my: 0.5, cx: 0.5, cy: 0.5 });

  React.useEffect(function () {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const GREEN = "219,239,219";

    // baked "Whisper" preset
    const CFG = { layers: 4, parallax: 14, blur: 3, fog: 82, edge: 7 * intensity, drift: reduce ? 0 : 22, accent: 2 };

    function fit() {
      const w = canvas.clientWidth || 1, h = canvas.clientHeight || 1;
      canvas.width = Math.round(w * dpr); canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    fit();
    const ro = new ResizeObserver(fit); ro.observe(canvas);

    function hash(x, y) { const v = Math.sin(x * 127.1 + y * 311.7) * 43758.5453; return v - Math.floor(v); }
    function buildLayer(cols, rows, sd) {
      function pt(c, r) {
        const edge = c === 0 || r === 0 || c === cols || r === rows;
        const j = edge ? 0 : 0.42 / cols;
        return [c / cols + (hash(c + sd, r) - 0.5) * j, r / rows + (hash(c + 7.3, r + 4.1 + sd) - 0.5) * j];
      }
      const tris = [];
      for (let r = 0; r < rows; r++) for (let c = 0; c < cols; c++) {
        const a = pt(c, r), b = pt(c + 1, r), d = pt(c, r + 1), e = pt(c + 1, r + 1);
        tris.push({ p: [a, b, e], f: hash(c + sd, r) });
        tris.push({ p: [a, e, d], f: hash(c + sd + 0.5, r + 0.3) });
      }
      return tris;
    }
    const POOL = [
      buildLayer(7, 5, 1 + seed), buildLayer(8, 6, 4 + seed),
      buildLayer(9, 6, 8 + seed), buildLayer(10, 7, 12 + seed), buildLayer(11, 8, 16 + seed)
    ];

    function onMove(e) {
      const r = canvas.getBoundingClientRect();
      let x = (e.clientX - r.left) / r.width, y = (e.clientY - r.top) / r.height;
      if (x < -0.6 || x > 1.6 || y < -0.6 || y > 1.6) { x = 0.5; y = 0.5; }
      cur.current.mx = x; cur.current.my = y;
    }
    if (interactive) window.addEventListener("pointermove", onMove, { passive: true });

    function draw(t) {
      const W = canvas.clientWidth, H = canvas.clientHeight;
      if (!W || !H) return;
      ctx.clearRect(0, 0, W, H);
      const cc = cur.current;
      cc.cx += (cc.mx - cc.cx) * 0.05; cc.cy += (cc.my - cc.cy) * 0.05;
      const N = CFG.layers;
      const cover = Math.max(W, H) * 1.5;
      const ox0 = W / 2 - cover / 2, oy0 = H / 2 - cover / 2;

      for (let i = 0; i < N; i++) {
        const tris = POOL[i];
        const near = N > 1 ? i / (N - 1) : 1;
        const pw = 0.35 + near * 0.65;
        const drift = CFG.drift * (1 - near * 0.5);
        const px = (cc.cx - 0.5) * -CFG.parallax * pw + Math.sin(t * 0.00012 + i) * drift;
        const py = (cc.cy - 0.5) * -CFG.parallax * pw + Math.cos(t * 0.00010 + i * 1.7) * drift * 0.6;
        const sc = cover * (0.92 + near * 0.16);
        const ox = ox0 + (cover - sc) / 2 + px, oy = oy0 + (cover - sc) / 2 + py;
        const blur = CFG.blur * (1 - near);
        const aMul = 0.45 + near * 0.55;
        const edgeA = (CFG.edge / 100) * aMul;
        const fillA = edgeA * 0.9;

        ctx.save();
        if (blur > 0.05) ctx.filter = "blur(" + blur.toFixed(2) + "px)";
        ctx.lineWidth = 0.7; ctx.lineJoin = "round";
        ctx.strokeStyle = "rgba(255,255,255," + edgeA.toFixed(3) + ")";
        ctx.beginPath();
        for (let k = 0; k < tris.length; k++) {
          const tp = tris[k].p;
          ctx.moveTo(ox + tp[0][0] * sc, oy + tp[0][1] * sc);
          ctx.lineTo(ox + tp[1][0] * sc, oy + tp[1][1] * sc);
          ctx.lineTo(ox + tp[2][0] * sc, oy + tp[2][1] * sc);
          ctx.closePath();
        }
        ctx.stroke();
        const accentThresh = CFG.accent / 100;
        for (let j = 0; j < tris.length; j++) {
          const tf = tris[j].f, tpp = tris[j].p;
          const isAcc = tf < accentThresh, isWhite = !isAcc && tf < accentThresh + 0.12;
          if (!isAcc && !isWhite) continue;
          ctx.beginPath();
          ctx.moveTo(ox + tpp[0][0] * sc, oy + tpp[0][1] * sc);
          ctx.lineTo(ox + tpp[1][0] * sc, oy + tpp[1][1] * sc);
          ctx.lineTo(ox + tpp[2][0] * sc, oy + tpp[2][1] * sc);
          ctx.closePath();
          ctx.fillStyle = isAcc ? "rgba(" + GREEN + "," + (fillA * 1.7).toFixed(3) + ")" : "rgba(255,255,255," + (fillA * 0.7).toFixed(3) + ")";
          ctx.fill();
        }
        ctx.restore();
      }

      const f = CFG.fog / 100;
      if (f > 0) {
        const g = ctx.createRadialGradient(W * 0.5, H * 0.42, Math.min(W, H) * 0.12, W * 0.5, H * 0.5, Math.max(W, H) * 0.72);
        g.addColorStop(0, "rgba(10,12,20," + (0.55 * f).toFixed(3) + ")");
        g.addColorStop(0.55, "rgba(9,10,16," + (0.2 * f).toFixed(3) + ")");
        g.addColorStop(1, "rgba(8,9,15," + (0.95 * f).toFixed(3) + ")");
        ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);
      }
    }

    // driver: rAF, falling back to interval where rAF is paused
    let ticked = false, rafId = 0, intId = 0;
    function loop() { draw(performance.now()); ticked = true; rafId = requestAnimationFrame(loop); }
    rafId = requestAnimationFrame(loop);
    const wd = setTimeout(function () { if (!ticked) intId = setInterval(function () { draw(performance.now()); }, 1000 / 40); }, 450);

    return function () {
      ro.disconnect(); clearTimeout(wd);
      if (rafId) cancelAnimationFrame(rafId); if (intId) clearInterval(intId);
      if (interactive) window.removeEventListener("pointermove", onMove);
    };
  }, [seed, intensity, interactive]);

  return <canvas ref={ref} aria-hidden="true" style={{ position: "absolute", inset: 0, width: "100%", height: "100%", display: "block", pointerEvents: "none" }} />;
}
window.HvDepthField = HvDepthField;
