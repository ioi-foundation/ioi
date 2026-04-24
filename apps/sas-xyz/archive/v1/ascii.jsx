// Subtle ASCII animations — low-chroma, monospace, reduced-motion friendly.
// All animations use requestAnimationFrame, throttled to ~8-10 fps for a
// mechanical, printer-like cadence rather than smooth 60fps motion.

// Tick hook — returns an integer that increments at `hz` frames/sec.
// Uses rAF but coalesces frames so we don't trigger hot renders.
const useTick = (hz = 8, enabled = true) => {
  const [tick, setTick] = React.useState(0);
  React.useEffect(() => {
    if (!enabled) return;
    const period = 1000 / hz;
    let raf, last = 0;
    const loop = (t) => {
      if (t - last >= period) { last = t; setTick(x => x + 1); }
      raf = requestAnimationFrame(loop);
    };
    raf = requestAnimationFrame(loop);
    return () => cancelAnimationFrame(raf);
  }, [hz, enabled]);
  return tick;
};

// 1. Heartbeat sparkline — a tiny 12-char line that breathes.
// Used under the brand ("Service-as-Software" line).
const AsciiPulse = ({ width = 14, hz = 9 }) => {
  const tick = useTick(hz);
  // glyph ramp from flat to peak
  const ramp = ['·', '·', '·', '–', '–', '=', '∿', '*', '∿', '=', '–', '·', '·', '·'];
  const out = [];
  for (let i = 0; i < width; i++) {
    const phase = (tick + i) % ramp.length;
    out.push(ramp[phase]);
  }
  return <span className="ascii-pulse mono">{out.join('')}</span>;
};

// 2. Ticker — streams a slow horizontal scroll of fake audit events.
// Used in the topbar beside the release tag.
const AUDIT_SNIPPETS = [
  'SVC-0142 settled',
  'policy 2026.4 verified',
  'SVC-0199 gated → approved',
  'receipt 0x4f2a sealed',
  'SVC-0207 running',
  'envelope diff +0',
  'SVC-0188 retired',
  'budget −$142.00',
];
const AsciiTicker = ({ width = 34 }) => {
  const tick = useTick(2);
  const stream = AUDIT_SNIPPETS.join('   ·   ') + '   ·   ';
  const offset = tick % stream.length;
  const doubled = stream + stream;
  const slice = doubled.slice(offset, offset + width);
  return <span className="ascii-ticker mono">{slice}</span>;
};

// 3. Posture glyph — 5 chars, animated differently per posture.
// Static by default; only animates when `animated` prop is true (hover).
const AsciiPosture = ({ postureKey, animated = false }) => {
  const tick = useTick(6, animated);
  let frames;
  switch (postureKey) {
    case 'autonomous': // flowing dots — data in motion
      frames = ['·──→', '─·─→', '──·→', '───⇢', '·──→'];
      break;
    case 'gated': // bar rising and falling — a gate
      frames = ['[   ]', '[ · ]', '[ | ]', '[ · ]', '[   ]'];
      break;
    case 'local': // oscillating — bounded motion
      frames = ['⟨·  ⟩', '⟨ · ⟩', '⟨  ·⟩', '⟨ · ⟩', '⟨·  ⟩'];
      break;
    case 'isolated': // static, caged
      frames = ['▪ ▪ ▪', '▪ ▫ ▪', '▪ ▪ ▪', '▫ ▪ ▫', '▪ ▪ ▪'];
      break;
    default:
      frames = ['·····'];
  }
  return <span className="ascii-posture mono">{frames[animated ? tick % frames.length : 0]}</span>;
};

// 4. Banner rule — a slowly shifting dashed pattern that sits below the
// banner text. Very low contrast, just a hint of motion.
const AsciiRule = ({ width = 80, hz = 4 }) => {
  const tick = useTick(hz);
  const pattern = '─ ─ ─── · ─── ─ ─ ──── · ── ';
  const doubled = pattern + pattern + pattern;
  const offset = tick % pattern.length;
  return <span className="ascii-rule mono">{doubled.slice(offset, offset + width)}</span>;
};

// 5. Cursor — a blinking prompt glyph, used in the "Request a service" card.
const AsciiCursor = () => {
  const tick = useTick(2);
  return <span className="ascii-cursor mono">{tick % 2 === 0 ? '▍' : ' '}</span>;
};

// 6. Boot progress — a 10-slot progress bar that fills and empties.
// Used on the live instance pulse indicator and drawer status pill.
const AsciiBar = ({ slots = 10, hz = 8 }) => {
  const tick = useTick(hz);
  const pos = tick % (slots * 2);
  const head = pos < slots ? pos : (slots * 2 - pos - 1);
  const cells = [];
  for (let i = 0; i < slots; i++) {
    cells.push(i === head ? '█' : i < head ? '▓' : '░');
  }
  return <span className="ascii-bar mono">{cells.join('')}</span>;
};

window.AsciiPulse = AsciiPulse;
window.AsciiTicker = AsciiTicker;
window.AsciiPosture = AsciiPosture;
window.AsciiRule = AsciiRule;
window.AsciiCursor = AsciiCursor;
window.AsciiBar = AsciiBar;

// 7. Activity bar — per-row live indicator keyed off (seed, health).
// 'Nominal' pushes the wave forward; 'Monitoring' stalls with sporadic gaps;
// 'Degraded' introduces a clear hole in the bar.
const AsciiActivity = ({ seed = 0, health = 'Nominal', width = 14 }) => {
  const tick = useTick(health === 'Monitoring' ? 4 : 8);
  const cells = [];
  const state = health.toLowerCase();
  for (let i = 0; i < width; i++) {
    const phase = (tick + i * 2 + seed * 3) % (width * 2);
    const norm = phase < width ? phase : width * 2 - phase - 1;
    const intensity = norm / width; // 0..1
    let glyph;
    if (state === 'degraded') {
      glyph = (i + tick) % 5 === 0 ? ' ' : intensity > 0.6 ? '▒' : '░';
    } else if (state === 'monitoring') {
      glyph = intensity > 0.8 ? '▓' : intensity > 0.4 ? '▒' : '░';
    } else {
      glyph = intensity > 0.85 ? '█' : intensity > 0.55 ? '▓' : intensity > 0.25 ? '▒' : '░';
    }
    cells.push(glyph);
  }
  return <span className={`ascii-activity mono ${state}`}>{cells.join('')}</span>;
};

// 8. Throughput ticker — shows fake "outcomes/min" ticking up; small + muted.
const AsciiThroughput = ({ base = 12, seed = 0 }) => {
  const tick = useTick(2);
  // Jitter around the base rate so it feels alive
  const jitter = ((tick * 7 + seed * 13) % 11) - 5;
  const rate = Math.max(0, base + jitter);
  return <span className="ascii-throughput mono">{String(rate).padStart(2, '0')}/min ↻</span>;
};

window.AsciiActivity = AsciiActivity;
window.AsciiThroughput = AsciiThroughput;

// 9. Chain — a row of ◆ nodes linked by ─, with a verification wave that
// sweeps left-to-right. Every ~nodeCount frames, one node flashes bright.
const AsciiChain = ({ nodes = 12, hz = 6 }) => {
  const tick = useTick(hz);
  const head = tick % (nodes + 4); // +4 gives a pause between passes
  const parts = [];
  for (let i = 0; i < nodes; i++) {
    const isHead = i === head;
    const isRecent = i === head - 1 || i === head - 2;
    let cls = 'dim';
    if (isHead) cls = 'hot';
    else if (isRecent) cls = 'warm';
    parts.push(<span key={i} className={`chain-node ${cls}`}>◆</span>);
    if (i < nodes - 1) parts.push(<span key={`l${i}`} className="chain-link">─</span>);
  }
  return <span className="ascii-chain mono">{parts}</span>;
};

// 10. Re-verifying hash — shows the stored hash normally, but when `active`
// is true, scrambles the middle characters for a beat then settles back.
const SCRAMBLE_GLYPHS = '0123456789abcdef';
const AsciiHash = ({ value, active = false }) => {
  const tick = useTick(12, active);
  if (!active) return <span className="audit-hash">{value}</span>;
  // value looks like "0x7a2c9f…df82" — scramble the first group
  const m = value.match(/^(0x)([0-9a-f]+)(…)([0-9a-f]+)$/i);
  if (!m) return <span className="audit-hash">{value}</span>;
  const [, prefix, left, ell, right] = m;
  const scrambled = left.split('').map((c, i) => {
    const idx = (tick + i * 3) % SCRAMBLE_GLYPHS.length;
    return SCRAMBLE_GLYPHS[idx];
  }).join('');
  return <span className="audit-hash verifying">{prefix}{scrambled}{ell}{right}</span>;
};

// Coordinator: walks through audit rows — each row verifies for ~1.2s,
// then there's an ~800ms pause before advancing. Returns index or -1.
const useAuditVerifier = (rowCount) => {
  const [active, setActive] = React.useState(-1);
  React.useEffect(() => {
    if (rowCount <= 0) return;
    let idx = 0;
    let timer;
    const step = () => {
      setActive(idx);
      timer = setTimeout(() => {
        setActive(-1);
        timer = setTimeout(() => {
          idx = (idx + 1) % rowCount;
          step();
        }, 800);
      }, 1200);
    };
    step();
    return () => clearTimeout(timer);
  }, [rowCount]);
  return active;
};

window.AsciiChain = AsciiChain;
window.AsciiHash = AsciiHash;
window.useAuditVerifier = useAuditVerifier;

// 11. Fill meter — N-char bar filling proportionally with percent; warms
// from sage toward coral as utilization crosses 75%.
const AsciiMeter = ({ value = 0, max = 100, width = 40 }) => {
  const pct = Math.max(0, Math.min(1, value / max));
  const filled = Math.round(pct * width);
  const cells = [];
  for (let i = 0; i < width; i++) {
    cells.push(i < filled ? '█' : i === filled ? '▌' : '░');
  }
  const tone = pct > 0.85 ? 'hot' : pct > 0.6 ? 'warm' : 'cool';
  return (
    <div className={`ascii-meter mono ${tone}`}>
      <div className="meter-bar">{cells.join('')}</div>
      <div className="meter-label">
        <span>{Math.round(pct * 100)}% of ${max.toLocaleString()} soft cap</span>
        <span className="meter-remaining">${(max - value).toLocaleString(undefined,{minimumFractionDigits:2,maximumFractionDigits:2})} remaining</span>
      </div>
    </div>
  );
};

// 12. Countdown — live ticker to a target date, 1hz.
const AsciiCountdown = ({ target }) => {
  const [now, setNow] = React.useState(() => Date.now());
  React.useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  const targetMs = new Date(target).getTime();
  let diff = Math.max(0, targetMs - now);
  const d = Math.floor(diff / 86400000); diff -= d * 86400000;
  const h = Math.floor(diff / 3600000); diff -= h * 3600000;
  const m = Math.floor(diff / 60000); diff -= m * 60000;
  const s = Math.floor(diff / 1000);
  const pad = (n) => String(n).padStart(2, '0');
  return (
    <span className="ascii-countdown mono">
      {pad(d)}d <span className="sep">:</span> {pad(h)}h <span className="sep">:</span> {pad(m)}m <span className="sep blink">:</span> {pad(s)}s
    </span>
  );
};

window.AsciiMeter = AsciiMeter;
window.AsciiCountdown = AsciiCountdown;
