const React = window.React;
// Scroll-into-view reveal for the hypervisor.com line-art diagrams.
// Generic: it reads the shared visual grammar of HvDiagrams —
//   · decorative SVG (dotted orbits, dashed VPC boundary, labels) → fade in
//   · solid SVG connectors (<line>/<path> with no dash) → stroke-draw
//   · HTML chips (nodes, cards, pills) → fade + lift, radiating out from center
// End-state is the base style; we animate *from* hidden, gated on inbound
// viewport entry (once) and disabled under prefers-reduced-motion.

const easeOutCubic = (t) => 1 - Math.pow(1 - t, 3);
const clamp01 = (t) => (t < 0 ? 0 : t > 1 ? 1 : t);

// Inject the (once) keyframes for the post-reveal marching VPC boundary.
// Seamless: each cycle shifts the dash pattern by exactly one period (2+7=9u),
// so an infinite repeat reads as a calm continuous drift, not a march.
// Meaningful (a live, sealed perimeter), low-contrast, single. It begins the
// instant the boundary has faded in and keeps drifting through the rest of the
// reveal — off entirely under reduced-motion.
(function injectRevealStyle() {
  if (typeof document === "undefined") return;
  let s = document.getElementById("rv-style");
  if (!s) { s = document.createElement("style"); s.id = "rv-style"; document.head.appendChild(s); }
  s.textContent =
    "@keyframes rvVpcMarch { to { stroke-dashoffset: -6.5; } }" +
    "@keyframes rvOrbit { to { transform: rotate(360deg); } }" +
    "[data-orbit] { transform-box: fill-box; transform-origin: center; }" +
    "@media (prefers-reduced-motion: no-preference) {" +
    "  .rv-march [data-vpc-border] { animation: rvVpcMarch var(--vpc-period, 2.6s) linear infinite; }" +
    "  .rv-march [data-orbit] { animation: rvOrbit var(--orbit-period, 42s) linear infinite; }" +
    "}" +
    "body.vpc-march-off [data-vpc-border] { animation: none !important; }" +
    "body.orbit-spin-off [data-orbit] { animation: none !important; }";
  document.head.appendChild(s);
})();

function buildController(root, opts = {}) {
  const svg = root.querySelector("svg");
  const items = [];
  const order = opts.order || "radial";

  // ---- bespoke: code-editor diagram (DiagToolStack) ----
  // chrome settles → tool logos drop in from above → code types line-by-line →
  // cursor lands on the active (highlighted) line.
  if (order === "code") {
    const editor = root.querySelector('[data-rv="editor"]');
    const lines = Array.from(root.querySelectorAll('[data-rv="codeline"]'));
    const cursor = root.querySelector('[data-rv="cursor"]');
    const tools = Array.from(root.querySelectorAll('[data-rv="tools"] > *'));

    if (editor) {
      const base = editor.style.transform || "";
      editor.style.opacity = "0";
      editor.style.willChange = "transform, opacity";
      items.push({ el: editor, kind: "rise", base, dy: 8, sc: 0.04, start: 0, dur: 0.32 });
    }
    tools.forEach((el, i) => {
      const base = el.style.transform || "";
      el.style.opacity = "0";
      el.style.willChange = "transform, opacity";
      items.push({ el, kind: "drop", base, dy: -10, start: 0.16 + i * 0.06, dur: 0.34 });
    });
    const lineStart = 0.34, lineStep = 0.052;
    lines.forEach((el, i) => {
      el.style.opacity = "0";
      el.style.willChange = "opacity";
      items.push({ el, kind: "type", start: lineStart + i * lineStep, dur: 0.22 });
    });
    const typedEnd = lineStart + lines.length * lineStep; // ~0.76
    // active row (7 → index 6) gets the persistent highlight; row below (8 → index 7)
    // gets a transient highlight as the cursor sweeps up past it from below.
    const activeRow = lines[6], passRow = lines[7];
    if (activeRow) activeRow.style.background = "transparent"; // override static; the glow drives it
    const cStart = typedEnd + 0.02, cDur = 0.5;
    if (cursor) {
      const base = cursor.style.transform || "";
      cursor.style.opacity = "0";
      cursor.style.willChange = "transform, opacity";
      // enters from bottom-right, holds over row 8, then settles on row 7 (linear: honest travel)
      items.push({ el: cursor, kind: "cursorPath", base, ease: "linear", start: cStart, dur: cDur });
    }
    if (passRow) {
      passRow.style.background = "transparent";
      // transient flash while the cursor holds over row 8 (mid-sweep)
      items.push({ el: passRow, kind: "pulse", peak: 7.5, ease: "linear", start: cStart + 0.45 * cDur - 0.05, dur: 0.2 });
    }
    if (activeRow) {
      // settles on row 7 as the cursor arrives
      items.push({ el: activeRow, kind: "glow", peak: 9, ease: "linear", start: cStart + 0.84 * cDur, dur: 0.16 });
    }
  } else

  // ---- bespoke: depth-stack diagram (DiagPrivacy) ----
  // deal the cascade of windows back-to-front (z-order), then draw the accent
  // connector as the private-model card seats, then fill the front card's lines.
  if (order === "stack") {
    const frame = svg ? svg.parentElement : root.querySelector("div");
    const cards = Array.from(frame.children).filter((c) => c.tagName === "DIV"); // WinCards, DOM = back→front
    const dealStep = 0.11;
    cards.forEach((el, i) => {
      const base = el.style.transform || "";
      el.style.opacity = "0";
      el.style.willChange = "transform, opacity";
      // dealt in from up-and-right (the fan's origin), settling into the slot
      items.push({ el, kind: "deal", base, dx: 34, dy: -26, start: i * dealStep, dur: 0.42 });
    });
    // accent card is the one with an accent border (next-to-last in DOM)
    const accentIdx = Math.max(0, cards.length - 2);
    const accentSeated = accentIdx * dealStep + 0.42;
    if (svg) {
      svg.querySelectorAll("path").forEach((p) => {
        let len = 0; try { len = p.getTotalLength(); } catch (e) {}
        if (!len) return;
        p.style.strokeDasharray = len; p.style.strokeDashoffset = len;
        items.push({ el: p, kind: "draw", len, start: accentSeated - 0.06, dur: 0.34 });
      });
      svg.querySelectorAll("circle").forEach((c) => {
        const target = parseFloat(getComputedStyle(c).opacity) || 1;
        c.style.opacity = "0";
        items.push({ el: c, kind: "fade", target, start: accentSeated - 0.08, dur: 0.2 });
      });
    }
    // front card's numbered code lines fill in last
    const winLines = Array.from(root.querySelectorAll('[data-rv="wincode"]'));
    const frontSeated = (cards.length - 1) * dealStep + 0.3;
    winLines.forEach((el, i) => {
      el.style.opacity = "0";
      el.style.willChange = "opacity";
      items.push({ el, kind: "type", start: frontSeated + i * 0.06, dur: 0.22 });
    });
  } else

  // ---- bespoke: agent capability tree (DiagAgentTree) ----
  // agent pill drops in → branch connector draws down → capability pills
  // ripple in row-by-row, center-out within each row.
  if (order === "tree") {
    const agent = root.querySelector('[data-rv="agent"]');
    const branchSvg = root.querySelector('[data-rv="branch"]');
    const rows = Array.from(root.querySelectorAll('[data-rv="caprow"]'));

    if (agent) {
      const base = agent.style.transform || "";
      agent.style.opacity = "0";
      agent.style.willChange = "transform, opacity";
      items.push({ el: agent, kind: "drop", base, dy: -9, start: 0, dur: 0.34 });
    }
    if (branchSvg) {
      branchSvg.querySelectorAll("path").forEach((p) => {
        let len = 0; try { len = p.getTotalLength(); } catch (e) {}
        if (!len) return;
        p.style.strokeDasharray = len; p.style.strokeDashoffset = len;
        items.push({ el: p, kind: "draw", len, start: 0.22, dur: 0.3 });
      });
    }
    const rowStart = 0.44, rowStep = 0.16;
    rows.forEach((rowEl, ri) => {
      const pills = Array.from(rowEl.querySelectorAll('[data-rv="cap"]'));
      // center-out ordering within the row
      const mid = (pills.length - 1) / 2;
      const ranked = pills
        .map((el, idx) => ({ el, d: Math.abs(idx - mid) }))
        .sort((a, b) => a.d - b.d);
      ranked.forEach(({ el }, rank) => {
        const base = el.style.transform || "";
        el.style.display = el.style.display || "inline-block";
        el.style.opacity = "0";
        el.style.willChange = "transform, opacity";
        items.push({ el, kind: "chip", base, start: rowStart + ri * rowStep + rank * 0.03, dur: 0.32 });
      });
    });
  } else

  // ---- classify SVG layer ----
  if (svg) {
    const frame = svg.parentElement;

    // decorative: anything dashed, plus text + circles (orbits)
    const decor = Array.from(
      svg.querySelectorAll("[stroke-dasharray], text, circle")
    );
    decor.forEach((el, i) => {
      const target = parseFloat(getComputedStyle(el).opacity) || 1;
      el.style.opacity = "0";
      items.push({
        el, kind: "fade", target,
        start: Math.min(i * 0.035, 0.16), dur: 0.32,
      });
    });

    // solid connectors: lines / paths with no dash pattern
    const conns = Array.from(svg.querySelectorAll("line, path")).filter(
      (el) => !el.getAttribute("stroke-dasharray") && !el.closest("[stroke-dasharray]")
    );
    conns.forEach((el, i) => {
      let len = 0;
      try { len = el.getTotalLength(); } catch (e) { len = 0; }
      if (!len) return;
      el.style.strokeDasharray = len;
      el.style.strokeDashoffset = len;
      items.push({
        el, kind: "draw", len,
        start: 0.30 + i * 0.028, dur: 0.34,
      });
    });

    // chips: frame children that aren't the svg.
    // order "radial"  → build from the geometric center outward (a hub diagram)
    // order "topdown" → build from the top down (a hierarchy whose source is up top)
    if (frame) {
      const rootRect = root.getBoundingClientRect();
      const cx = rootRect.left + rootRect.width / 2;
      const cy = rootRect.top + rootRect.height / 2;
      const chips = Array.from(frame.children).filter((c) => c !== svg);
      const ranked = chips
        .map((el) => {
          const r = el.getBoundingClientRect();
          const mx = r.left + r.width / 2;
          const my = r.top + r.height / 2;
          // radial: distance from center. topdown: vertical first, then
          // distance-from-center as the within-row tiebreak (center-out per row).
          const key = order === "topdown"
            ? (my - rootRect.top) * 1000 + Math.abs(mx - cx)
            : Math.hypot(mx - cx, my - cy);
          return { el, key };
        })
        .sort((a, b) => a.key - b.key);
      ranked.forEach(({ el }, rank) => {
        // the joined AI-agent + Developer pill gets a gooey metaball merge
        const joined = el.querySelector && el.querySelector('[data-rv="joined"]');
        if (joined) {
          const L = joined.querySelector('[data-rv="goo-left"]');
          const R = joined.querySelector('[data-rv="goo-right"]');
          const B = joined.querySelector('[data-rv="goo-bridge"]');
          const TL = joined.querySelector('[data-rv="goo-tl"]');
          const TR = joined.querySelector('[data-rv="goo-tr"]');
          if (L) { L.style.opacity = "0"; L.style.willChange = "transform, opacity"; items.push({ el: L, kind: "gooSlide", dx: -24, start: 0.04, dur: 0.42 }); }
          if (R) { R.style.opacity = "0"; R.style.willChange = "transform, opacity"; items.push({ el: R, kind: "gooSlide", dx: 24, start: 0.04, dur: 0.42 }); }
          if (B) { B.style.opacity = "0"; B.style.transformOrigin = "center"; B.style.willChange = "transform, opacity"; items.push({ el: B, kind: "gooBridge", start: 0.2, dur: 0.24 }); }
          if (TL) { TL.style.opacity = "0"; items.push({ el: TL, kind: "gooText", start: 0.36, dur: 0.24 }); }
          if (TR) { TR.style.opacity = "0"; items.push({ el: TR, kind: "gooText", start: 0.38, dur: 0.24 }); }
          return; // not a generic chip
        }
        const base = el.style.transform || "";
        el.style.opacity = "0";
        el.style.willChange = "transform, opacity";
        // source (first) leads; the rest follow once connectors are drawing
        const start = rank === 0 ? 0.14 : 0.42 + (rank - 1) * 0.058;
        items.push({ el, kind: "chip", base, start, dur: 0.36 });
      });
    }
  }

  const MAXEND = items.reduce((m, it) => Math.max(m, it.start + it.dur), 1);

  function apply(it, e) {
    if (it.kind === "fade") it.el.style.opacity = String(e * it.target);
    else if (it.kind === "draw") it.el.style.strokeDashoffset = String(it.len * (1 - e));
    else if (it.kind === "chip") {
      it.el.style.opacity = String(e);
      it.el.style.transform = `${it.base} translateY(${(1 - e) * 9}px) scale(${0.93 + 0.07 * e})`;
    }
    else if (it.kind === "gooSlide") {
      it.el.style.opacity = String(Math.min(1, e / 0.25));
      it.el.style.transform = `translateX(${(1 - e) * it.dx}px)`;
    }
    else if (it.kind === "gooBridge") {
      it.el.style.opacity = String(Math.min(1, e * 1.4));
      it.el.style.transform = `scaleX(${e})`;
    }
    else if (it.kind === "gooText") {
      it.el.style.opacity = String(e);
    }
    else if (it.kind === "rise") {
      it.el.style.opacity = String(e);
      it.el.style.transform = `${it.base} translateY(${(1 - e) * it.dy}px) scale(${(1 - it.sc) + it.sc * e})`;
    }
    else if (it.kind === "drop") {
      it.el.style.opacity = String(e);
      it.el.style.transform = `${it.base} translateY(${(1 - e) * it.dy}px)`;
    }
    else if (it.kind === "deal") {
      it.el.style.opacity = String(e);
      it.el.style.transform = `${it.base} translate(${(1 - e) * it.dx}px, ${(1 - e) * it.dy}px) scale(${0.96 + 0.04 * e})`;
    }
    else if (it.kind === "type") {
      it.el.style.opacity = String(e);
      it.el.style.transform = `translateX(${(1 - e) * -4}px)`;
    }
    else if (it.kind === "land") {
      it.el.style.opacity = String(e);
      it.el.style.transform = `${it.base} translate(${(1 - e) * -5}px, ${(1 - e) * -6}px) scale(${0.55 + 0.45 * e})`;
    }
    else if (it.kind === "cursorPath") {
      // bottom-right → hold over row 8 → settles on row 7 (offsets in px from rest)
      const lerp = (a, b, k) => a + (b - a) * k;
      const startPt = [22, 40], midPt = [6, 23]; // midPt ≈ one row below rest (over row 8)
      let dx, dy;
      if (e < 0.45) { const k = e / 0.45; dx = lerp(startPt[0], midPt[0], k); dy = lerp(startPt[1], midPt[1], k); }
      else if (e < 0.6) { dx = midPt[0]; dy = midPt[1]; }            // hold over row 8
      else { const k = (e - 0.6) / 0.4; dx = lerp(midPt[0], 0, k); dy = lerp(midPt[1], 0, k); }
      it.el.style.opacity = String(Math.min(1, e / 0.12));
      it.el.style.transform = `${it.base} translate(${dx}px, ${dy}px) scale(${0.62 + 0.38 * Math.min(1, e / 0.25)})`;
    }
    else if (it.kind === "glow") {
      it.el.style.background = `color-mix(in srgb, var(--color-link-green) ${(it.peak * e).toFixed(2)}%, transparent)`;
    }
    else if (it.kind === "pulse") {
      const a = Math.sin(Math.PI * e); // 0 → 1 → 0
      it.el.style.background = `color-mix(in srgb, var(--color-link-green) ${(it.peak * a).toFixed(2)}%, transparent)`;
    }
  }

  function seek(tn) {
    const t = clamp01(tn) * MAXEND;
    for (const it of items) {
      const raw = clamp01((t - it.start) / it.dur);
      apply(it, it.ease === "linear" ? raw : easeOutCubic(raw));
    }
  }

  // Start the boundary's marching drift the moment it finishes fading in —
  // so it comes alive while the rest of the diagram is still revealing.
  const borderEl = root.querySelector("[data-vpc-border]");
  const borderItem = borderEl && items.find((it) => it.el === borderEl);
  const marchAtTn = borderItem ? (borderItem.start + borderItem.dur) / MAXEND : 0.35;

  let raf = null, done = false, marched = false;
  function pause() { if (raf) { cancelAnimationFrame(raf); raf = null; } }
  function play(ms = 1550) {
    if (raf || done) return;
    const t0 = performance.now();
    const tick = (now) => {
      const tn = (now - t0) / ms;
      seek(tn);
      if (!marched && tn >= marchAtTn) { marched = true; root.classList.add("rv-march"); }
      if (tn < 1) raf = requestAnimationFrame(tick);
      else { raf = null; done = true; seek(1); root.classList.add("rv-march"); }
    };
    raf = requestAnimationFrame(tick);
  }

  function reset() {
    // restore the pre-reveal hidden state so the next entrance plays fresh
    pause();
    done = false; marched = false;
    root.classList.remove("rv-march");
    seek(0); // internal seek — does not latch `done`
  }

  seek(0);
  return { seek: (t) => { pause(); done = true; seek(t); }, play, pause, reset, _raw: seek, _items: items };
}

function Reveal({ children, enter = 0.82, order = "radial" }) {
  const ref = React.useRef(null);
  React.useEffect(() => {
    const root = ref.current;
    if (!root) return;
    const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;

    let ctrl, ticking = false, cleaned = false, shown = false;
    const cleanup = () => {
      if (cleaned) return; cleaned = true;
      window.removeEventListener("scroll", onScroll, { passive: true });
      window.removeEventListener("resize", onScroll);
    };
    const inView = () => {
      const r = root.getBoundingClientRect();
      const vh = window.innerHeight || document.documentElement.clientHeight;
      return r.top < vh * enter && r.bottom > vh * (1 - enter);
    };
    // fully past the top or below the bottom — nothing of it is visible
    const fullyOut = () => {
      const r = root.getBoundingClientRect();
      const vh = window.innerHeight || document.documentElement.clientHeight;
      return r.bottom <= 0 || r.top >= vh;
    };
    const onScroll = () => {
      if (ticking || !ctrl) return;
      ticking = true;
      requestAnimationFrame(() => {
        ticking = false;
        if (!shown && inView()) { shown = true; ctrl.play(); }
        // re-arm only once it has fully left the viewport, so it never
        // dismantles while any part is still on screen
        else if (shown && fullyOut()) { shown = false; ctrl.reset(); }
      });
    };

    const id = requestAnimationFrame(() => {
      try {
        ctrl = buildController(root, { order });
      } catch (err) {
        // never leave the graphic stuck hidden — reveal it as-is
        root.querySelectorAll("[style]").forEach((el) => {
          if (el.style.opacity === "0") el.style.opacity = "1";
          if (el.style.strokeDashoffset) el.style.strokeDashoffset = "0";
        });
        console.warn("RevealDiagram: build failed, shown statically", err);
        return;
      }
      (window.__reveals = window.__reveals || []).push(ctrl);
      if (reduce) { ctrl.seek(1); return; }
      window.addEventListener("scroll", onScroll, { passive: true });
      window.addEventListener("resize", onScroll);
      // fire immediately if already on-screen at mount
      if (inView()) { shown = true; ctrl.play(); }
    });
    return () => { cancelAnimationFrame(id); cleanup(); };
  }, []);
  return <div ref={ref} style={{ width: "100%", display: "flex", justifyContent: "center" }}>{children}</div>;
}

window.RevealDiagram = { Reveal };
