// Receipt stream component
const Stream = ({ items, onPick }) => {
  return (
    <div className="stream">
      {items.map((r, i) => (
        <div key={i} className={`stream-item ${r.flag ? 'flag' : ''} ${i === 0 ? 'fresh' : ''}`} onClick={() => onPick && onPick(i)}>
          <div className="stream-ts mono">{r.ts}</div>
          <div className="stream-body">
            <div className="stream-head-line serif" dangerouslySetInnerHTML={{__html: r.title}} />
            <div className="stream-sub mono">
              <span className="hash">{r.sub}</span>
            </div>
          </div>
          <div style={{display:'flex', flexDirection:'column', alignItems:'flex-end', gap:6}}>
            {r.amt !== null && r.amt !== undefined && (
              <div className="stream-amt serif">
                <em>${r.amt.toFixed(r.amt % 1 ? 2 : 0)}</em>
                {r.unit && <span className="unit">{r.unit}</span>}
              </div>
            )}
            <div className="stream-state mono">{r.state}</div>
          </div>
        </div>
      ))}
      <div className="stream-more mono">
        <Icon name="history" size={12} /> load older receipts
      </div>
    </div>
  );
};

// Pulse row — 40 tiny cells showing recent receipt rhythm.
// Below the bars: a quiet ASCII band that ticks when the contract is live.
const Pulse = ({ data }) => {
  const okCount = data.filter(v => v === 1).length;
  const live = okCount > 0;
  const intensity = Math.min(1, okCount / Math.max(1, data.length));
  const [frame, setFrame] = React.useState(0);
  React.useEffect(() => {
    if (!live) return;
    const prefersReduced = window.matchMedia
      && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReduced) return;
    // Gentle cadence: ~6fps, slower when the contract is quieter.
    const ms = 110 + (1 - intensity) * 260;
    const id = setInterval(() => setFrame(f => f + 1), ms);
    return () => clearInterval(id);
  }, [live, intensity]);

  const cols = data.length;
  const glyphs = ['·',' ',' ','˙',' ',' ','·',' '];
  let band = '';
  for (let c = 0; c < cols; c++) {
    const v = data[c];
    if (v === -1) band += '×';
    else if (v === 0) band += ' ';
    else band += glyphs[(c + frame) & 7];
  }
  return (
    <div>
      <div className="pulse">
        {data.map((v, i) => {
          const h = v === 0 ? 4 : v === -1 ? 10 + ((i * 7) % 14) : 8 + ((i * 11) % 18);
          const cls = v === 0 ? 'empty' : v === -1 ? 'flag' : 'ok';
          return (
            <div
              key={i}
              className={`pulse-cell ${cls}`}
              style={{ height: h + 'px', opacity: v === 0 ? 0.3 : 0.88 - (data.length - 1 - i) * 0.012 }}
            />
          );
        })}
      </div>
      <pre aria-hidden="true" style={{
        margin: '2px 0 0', padding: 0,
        fontFamily: 'var(--mono)', fontSize: 9,
        lineHeight: 1, letterSpacing: '0.14em',
        color: 'var(--muted-2)', opacity: live ? 0.55 : 0.25,
        whiteSpace: 'pre', userSelect: 'none', pointerEvents: 'none',
        height: 10,
      }}>{band}</pre>
    </div>
  );
};

// PulseScrubber — interactive version used inside the contract detail.
// Each cell maps to a receipt index in the stream (newest at the RIGHT).
// Clicking or dragging highlights the cell and calls onPickReceipt(index).
const PulseScrubber = ({ data, streamLength, onPickReceipt }) => {
  const [hover, setHover] = React.useState(null);
  const wrapRef = React.useRef(null);

  // Map pulse index (left→right, index 0 = oldest) to stream index (0 = newest).
  // We overlay the last min(data.length, streamLength) cells onto the stream.
  const cellCount = data.length;
  const activeCount = Math.min(cellCount, streamLength);
  const firstActive = cellCount - activeCount; // pulse indexes < this are "older than stream"

  const cellToStreamIdx = (cellIdx) => {
    if (cellIdx < firstActive) return null;
    // cellIdx = cellCount - 1 (rightmost, newest)   → stream 0
    // cellIdx = firstActive    (leftmost active)    → stream activeCount - 1
    return (cellCount - 1) - cellIdx;
  };

  const onCellClick = (cellIdx) => {
    const streamIdx = cellToStreamIdx(cellIdx);
    if (streamIdx != null && onPickReceipt) onPickReceipt(streamIdx);
  };

  const onMouseMoveWrap = (e) => {
    if (!wrapRef.current) return;
    const rect = wrapRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const pct = Math.max(0, Math.min(1, x / rect.width));
    const idx = Math.min(cellCount - 1, Math.floor(pct * cellCount));
    setHover(idx);
  };

  return (
    <div style={{position:'relative', padding:'14px 0 8px'}}>
      <div
        ref={wrapRef}
        onMouseMove={onMouseMoveWrap}
        onMouseLeave={() => setHover(null)}
        style={{display:'flex', alignItems:'flex-end', gap:3, height:44, cursor:'pointer'}}
      >
        {data.map((v, i) => {
          const h = v === 0 ? 6 : v === -1 ? 26 + ((i * 7) % 8) : 18 + ((i * 11) % 18);
          const isActive = i >= firstActive;
          const isHover = hover === i;
          const color = v === -1 ? 'var(--coral)' : v === 0 ? 'var(--rule)' : 'var(--ink)';
          return (
            <div
              key={i}
              onClick={() => onCellClick(i)}
              title={isActive ? `Receipt ${cellToStreamIdx(i) + 1}` : 'no receipt'}
              style={{
                flex:1,
                minWidth:4,
                height: h + 'px',
                background: isActive ? color : 'var(--rule-soft)',
                opacity: isActive ? (isHover ? 1 : 0.8) : 0.4,
                borderRadius: 2,
                transform: isHover ? 'scaleY(1.12) translateY(-1px)' : 'none',
                transformOrigin: 'bottom',
                transition: 'transform .12s, opacity .12s',
              }}
            />
          );
        })}
      </div>

      {/* Axis */}
      <div style={{display:'flex', justifyContent:'space-between', marginTop:8}}>
        <span className="mono" style={{fontSize:9.5, color:'var(--muted-2)', letterSpacing:'0.12em', textTransform:'uppercase'}}>
          older {cellCount} events →
        </span>
        <span className="mono" style={{fontSize:9.5, color:'var(--muted)', letterSpacing:'0.12em', textTransform:'uppercase'}}>
          {hover !== null && cellToStreamIdx(hover) != null
            ? <>receipt #{cellToStreamIdx(hover) + 1} · click to open</>
            : <>newest →</>}
        </span>
      </div>
    </div>
  );
};

window.Stream = Stream;
window.Pulse = Pulse;
window.PulseScrubber = PulseScrubber;
