// Subtle ASCII animations — ambient texture for the outcome-first design.
// Every component is intentionally low-contrast: muted color, mono font, small.
// Runs via a single shared rAF tick so many can render cheaply.

(function() {
  // ── Shared tick ──────────────────────────────────────────────────
  const listeners = new Set();
  let running = false;
  let frameStart = performance.now();
  const tick = (t) => {
    const elapsed = (t - frameStart) / 1000;
    listeners.forEach(fn => { try { fn(elapsed); } catch (_) {} });
    if (listeners.size) requestAnimationFrame(tick);
    else running = false;
  };
  const useTick = (fn, fps = 12) => {
    const lastRef = React.useRef(0);
    React.useEffect(() => {
      const interval = 1 / fps;
      const wrapped = (t) => {
        if (t - lastRef.current < interval) return;
        lastRef.current = t;
        fn(t);
      };
      listeners.add(wrapped);
      if (!running) { running = true; frameStart = performance.now(); requestAnimationFrame(tick); }
      return () => { listeners.delete(wrapped); };
    }, []);
  };

  // Respect reduced motion: freeze to a static frame.
  const prefersReduced = typeof window !== 'undefined'
    && window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ── <AsciiWave> ─ horizontal sine band. Use as a seam / divider. ──
  // Cols characters wide, 2 rows tall. Two-tone muted palette.
  const AsciiWave = ({ cols = 80, speed = 0.7, amp = 1.4, density = 0.55, className = '', style = {} }) => {
    const [frame, setFrame] = React.useState(0);
    useTick(() => { if (!prefersReduced) setFrame(f => f + 1); }, 10);
    const t = frame * 0.12 * speed;
    const chars = ['·','·',' ',' ','˙','·',' ',' '];
    const rows = [];
    for (let r = 0; r < 2; r++) {
      let line = '';
      for (let c = 0; c < cols; c++) {
        const y = Math.sin((c / cols) * Math.PI * 4 + t + r * 0.6) * amp;
        const yi = Math.round(y) + r;
        if (yi === 0) {
          line += Math.random() < density ? chars[(c + frame) & 7] : ' ';
        } else line += ' ';
      }
      rows.push(line);
    }
    return (
      <pre aria-hidden="true" className={`ascii-wave ${className}`} style={{
        margin: 0, padding: 0, fontFamily: 'var(--mono)',
        fontSize: 10, lineHeight: 1.05, letterSpacing: '0.08em',
        color: 'var(--muted-2)', opacity: 0.5,
        whiteSpace: 'pre', userSelect: 'none', pointerEvents: 'none',
        ...style,
      }}>{rows.join('\n')}</pre>
    );
  };

  // ── <AsciiRain> ─ vertical drift of dots + occasional glyphs.
  // For hero corners and close section.
  const AsciiRain = ({ cols = 24, rows = 8, className = '', style = {} }) => {
    const [frame, setFrame] = React.useState(0);
    useTick(() => { if (!prefersReduced) setFrame(f => f + 1); }, 6);
    const seedRef = React.useRef(
      Array(cols).fill(0).map(() => ({
        offset: Math.random() * rows,
        speed: 0.3 + Math.random() * 0.7,
        density: 0.2 + Math.random() * 0.6,
      }))
    );
    const lines = [];
    for (let r = 0; r < rows; r++) {
      let line = '';
      for (let c = 0; c < cols; c++) {
        const seed = seedRef.current[c];
        const pos = ((r - seed.offset - frame * seed.speed * 0.4) % rows + rows) % rows;
        const head = pos < 0.8;
        const tail = pos < 2.5;
        if (head && Math.random() < 0.7) line += (c & 1) ? '│' : '·';
        else if (tail && Math.random() < seed.density * 0.4) line += '·';
        else line += ' ';
      }
      lines.push(line);
    }
    return (
      <pre aria-hidden="true" className={`ascii-rain ${className}`} style={{
        margin: 0, padding: 0, fontFamily: 'var(--mono)',
        fontSize: 10, lineHeight: 1.05, letterSpacing: '0.12em',
        color: 'var(--muted-2)', opacity: 0.35,
        whiteSpace: 'pre', userSelect: 'none', pointerEvents: 'none',
        ...style,
      }}>{lines.join('\n')}</pre>
    );
  };

  // ── <AsciiFlow> ─ horizontal streaming line: shuttles left→right.
  // For "substrate handoff" / "boundary sealed" seams.
  const AsciiFlow = ({ cols = 40, speed = 0.8, className = '', style = {} }) => {
    const [frame, setFrame] = React.useState(0);
    useTick(() => { if (!prefersReduced) setFrame(f => f + 1); }, 14);
    const glyphs = ['─','─','─','─','·','─','─','╌','─','─'];
    const t = Math.floor(frame * speed);
    let line = '';
    for (let c = 0; c < cols; c++) {
      const idx = (c + t) % glyphs.length;
      line += glyphs[idx];
    }
    // inject a single moving beacon
    const beaconPos = (frame * Math.max(1, Math.floor(speed))) % cols;
    line = line.substring(0, beaconPos) + '›' + line.substring(beaconPos + 1);
    return (
      <pre aria-hidden="true" className={`ascii-flow ${className}`} style={{
        margin: 0, padding: 0, fontFamily: 'var(--mono)',
        fontSize: 11, lineHeight: 1, letterSpacing: '0.04em',
        color: 'var(--muted)', opacity: 0.55,
        whiteSpace: 'pre', userSelect: 'none', pointerEvents: 'none',
        ...style,
      }}>{line}</pre>
    );
  };

  // ── <AsciiBars> ─ animated pulse-bar meter. For stat tiles.
  const AsciiBars = ({ cols = 18, className = '', style = {} }) => {
    const [frame, setFrame] = React.useState(0);
    useTick(() => { if (!prefersReduced) setFrame(f => f + 1); }, 8);
    const t = frame * 0.18;
    const glyphs = [' ','▁','▂','▃','▄','▅','▆','▇'];
    let line = '';
    for (let c = 0; c < cols; c++) {
      const v = (Math.sin(c * 0.6 + t) + Math.sin(c * 0.2 + t * 1.6) + 2) / 4;
      const idx = Math.min(glyphs.length - 1, Math.max(0, Math.floor(v * (glyphs.length - 1))));
      line += glyphs[idx];
    }
    return (
      <pre aria-hidden="true" className={`ascii-bars ${className}`} style={{
        margin: 0, padding: 0, fontFamily: 'var(--mono)',
        fontSize: 11, lineHeight: 1, letterSpacing: 0,
        color: 'var(--accent-ink)', opacity: 0.55,
        whiteSpace: 'pre', userSelect: 'none', pointerEvents: 'none',
        ...style,
      }}>{line}</pre>
    );
  };

  // ── <AsciiLattice> ─ quiet dotted lattice that ripples slowly.
  // For boundary-sealed visualization between "data" and "model".
  const AsciiLattice = ({ cols = 10, rows = 6, className = '', style = {} }) => {
    const [frame, setFrame] = React.useState(0);
    useTick(() => { if (!prefersReduced) setFrame(f => f + 1); }, 6);
    const t = frame * 0.15;
    const lines = [];
    for (let r = 0; r < rows; r++) {
      let line = '';
      for (let c = 0; c < cols; c++) {
        const v = Math.sin((c + r) * 0.8 + t) * 0.5 + 0.5;
        line += v > 0.7 ? '·' : v > 0.4 ? '˙' : ' ';
        line += ' ';
      }
      lines.push(line);
    }
    return (
      <pre aria-hidden="true" className={`ascii-lattice ${className}`} style={{
        margin: 0, padding: 0, fontFamily: 'var(--mono)',
        fontSize: 10, lineHeight: 1.1, letterSpacing: 0,
        color: 'var(--sage-ink)', opacity: 0.5,
        whiteSpace: 'pre', userSelect: 'none', pointerEvents: 'none',
        ...style,
      }}>{lines.join('\n')}</pre>
    );
  };

  // ── <AsciiCaret> ─ a tiny blinking receipt-line cursor.
  const AsciiCaret = ({ style = {} }) => {
    const [on, setOn] = React.useState(true);
    useTick(() => { if (!prefersReduced) setOn(v => !v); }, 1.2);
    return (
      <span aria-hidden="true" style={{
        fontFamily: 'var(--mono)', fontSize: 11,
        color: 'var(--accent-ink)', opacity: on ? 0.9 : 0.15,
        transition: 'opacity 120ms linear', marginLeft: 4,
        ...style,
      }}>▍</span>
    );
  };

  // ── <AsciiTicker> ─ horizontal scroll of receipt-like events.
  // Reads from window.STREAMS (contractId → [receipt]) if present;
  // falls back to a synthetic loop so it never feels dead.
  const AsciiTicker = ({ speed = 1.4, className = '', style = {} }) => {
    const [frame, setFrame] = React.useState(0);
    useTick(() => { if (!prefersReduced) setFrame(f => f + 1); }, 18);

    // Build a long ticker string from current streams.
    const tickerText = React.useMemo(() => {
      const streams = (typeof window !== 'undefined' && window.STREAMS) || {};
      const contracts = (typeof window !== 'undefined' && window.CONTRACTS) || [];
      const codeById = Object.fromEntries(contracts.map(c => [c.id, c.code || c.id]));
      const rows = [];
      Object.entries(streams).forEach(([cid, items]) => {
        (items || []).slice(0, 3).forEach(r => {
          const hash = (r.sub || '').match(/0x[0-9a-f]{2,}[…·]?[0-9a-f]*/i);
          const amt = r.amt != null ? `$${r.amt.toFixed(r.amt % 1 ? 2 : 0)}` : '—';
          const state = (r.state || 'ok').toUpperCase();
          rows.push(`${codeById[cid] || cid} · ${hash ? hash[0] : 'sealed'} · ${amt} · ${state}`);
        });
      });
      if (!rows.length) {
        rows.push(
          'CT-0001 · 0x7a2c9f…df82 · $14.20 · LIVE',
          'CT-0002 · 0x4b1a3e…e921 · $9.84  · LIVE',
          'CT-0003 · 0x9c3d77…a834 · $4.00  · SEALED',
        );
      }
      return rows.join('   ›   ') + '   ›   ';
    }, []);

    const tick = Math.floor(frame * speed);
    const len = tickerText.length;
    const offset = ((tick % len) + len) % len;
    const windowed = tickerText.slice(offset) + tickerText.slice(0, offset);

    return (
      <div aria-hidden="true" className={`ascii-ticker ${className}`} style={{
        position: 'relative',
        overflow: 'hidden',
        whiteSpace: 'nowrap',
        fontFamily: 'var(--mono)',
        fontSize: 10, letterSpacing: '0.08em',
        color: 'var(--muted)',
        opacity: 0.7,
        userSelect: 'none', pointerEvents: 'none',
        maskImage: 'linear-gradient(90deg, transparent 0, #000 48px, #000 calc(100% - 48px), transparent 100%)',
        WebkitMaskImage: 'linear-gradient(90deg, transparent 0, #000 48px, #000 calc(100% - 48px), transparent 100%)',
        ...style,
      }}>
        <span>{windowed}</span>
      </div>
    );
  };

  Object.assign(window, { AsciiWave, AsciiRain, AsciiFlow, AsciiBars, AsciiLattice, AsciiCaret, AsciiTicker });
})();
