const React = window.React;
// hypervisor.com — line-art product diagrams (site-scoped).
// On-brand: hairline strokes, IOI mark as the recurring node, green accent
// reserved for the single "live / verified" highlight. Chips are HTML (crisp
// type, directly editable); connectors are an SVG layer in matching aspect.
const DGS = window.IoiDesignSystem;
const MarkLogo = DGS.Logo;

const INK = "var(--color-onyx-black)";
const LINE = "var(--color-grey-600)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";
const RED = "var(--color-red-500)";
// One dotted identity across every diagram: fine round dots, 0.5pt tick / 6pt gap.
// Period = 6.5 — the marching/orbit keyframes step by this for a seamless loop.
const DOT_DASH = "0.5 6";

/* ---- shared frame: SVG connector layer (meet, matching aspect) + HTML chips ---- */
function Frame({ W, H, svg, children }) {
  return (
    <div style={{ position: "relative", width: "100%", maxWidth: W, aspectRatio: `${W} / ${H}`, margin: "0 auto" }}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height="100%" preserveAspectRatio="xMidYMid meet" style={{ position: "absolute", inset: 0, overflow: "visible" }} aria-hidden="true">
        {svg}
      </svg>
      {children}
    </div>
  );
}

// position helper → percentage so HTML chips track the SVG viewBox exactly
const at = (x, y, W, H) => ({ position: "absolute", left: `${(x / W) * 100}%`, top: `${(y / H) * 100}%`, transform: "translate(-50%, -50%)" });

function Box({ size = 46, accent = false, style, children }) {
  return (
    <div style={{ width: size, height: size, borderRadius: 13, background: "var(--color-white)", border: `0.5px solid ${accent ? ACC : HAIR}`, boxShadow: "var(--shadow-sm)", display: "grid", placeItems: "center", ...style }}>
      {children}
    </div>
  );
}

/* ---------- glyphs (simple geometric marks — no third-party logos) ---------- */
const g = (paths, { s = 22, sw = 1.5, fill = "none", stroke = INK } = {}) => (
  <svg width={s} height={s} viewBox="0 0 24 24" fill={fill} stroke={stroke} strokeWidth={sw} strokeLinecap="round" strokeLinejoin="round">{paths}</svg>
);
const Sparkle = ({ s, c = INK } = {}) => g(<path d="M12 3 L13.6 9.6 L20 12 L13.6 14.4 L12 21 L10.4 14.4 L4 12 L10.4 9.6 Z" fill={c} stroke="none" />, { s });
const Burst = ({ s } = {}) => g(<g><line x1="12" y1="3" x2="12" y2="21" /><line x1="3" y1="12" x2="21" y2="12" /><line x1="5.5" y1="5.5" x2="18.5" y2="18.5" /><line x1="18.5" y1="5.5" x2="5.5" y2="18.5" /></g>, { s, stroke: ACC });
const Rings = ({ s } = {}) => g(<g><circle cx="12" cy="12" r="3" /><circle cx="12" cy="12" r="7" /><circle cx="12" cy="12" r="10.5" /></g>, { s });
const Graph = ({ s } = {}) => g(<g><circle cx="6" cy="7" r="2.2" /><circle cx="18" cy="7" r="2.2" /><circle cx="12" cy="17" r="2.2" /><line x1="7.6" y1="8.4" x2="11" y2="15" /><line x1="16.4" y1="8.4" x2="13" y2="15" /><line x1="8" y1="7" x2="16" y2="7" /></g>, { s });
const Brackets = ({ s } = {}) => g(<g><path d="M9 6 L4 12 L9 18" /><path d="M15 6 L20 12 L15 18" /></g>, { s });
const Shield = ({ s } = {}) => g(<path d="M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z" />, { s });
const Lock = ({ s = 22 } = {}) => (
  <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={INK} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <rect x="5" y="10.5" width="14" height="9.5" rx="2.2" /><path d="M8 10.5 V7.5 a4 4 0 0 1 8 0 V10.5" /><circle cx="12" cy="15" r="1.4" fill={INK} stroke="none" />
  </svg>
);
const Person = ({ s = 20, c = INK } = {}) => (
  <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
    <circle cx="12" cy="8" r="3.4" /><path d="M5.5 19 a6.5 6.5 0 0 1 13 0" />
  </svg>
);
const Badge = ({ ok }) => (
  <span style={{ position: "absolute", top: -4, right: -4, width: 16, height: 16, borderRadius: "50%", background: ok ? ACC : RED, display: "grid", placeItems: "center", boxShadow: "0 0 0 2px var(--color-white)" }}>
    {ok
      ? <svg width="10" height="10" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
      : <svg width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M3 3 L9 9 M9 3 L3 9" stroke="#fff" strokeWidth="1.6" strokeLinecap="round" /></svg>}
  </span>
);

/* ============================================================= *
 * DiagHub — deployed in your cloud: IOI mark at center, pluggable
 * model marks below, your stack / policy nodes to the sides.
 * ============================================================= */
function DiagHub() {
  const W = 460, H = 338, cx = 230, cy = 150;
  const dotted = { stroke: HAIR, strokeWidth: 1, fill: "none", strokeDasharray: DOT_DASH, strokeLinecap: "round" };
  const mx = [122, 192, 262, 332];
  const models = [
    ["claude", <img src="assets/logos/models/claude.png" alt="" width="26" height="26" style={{ objectFit: "contain" }} />],
    ["openai", <img src="assets/logos/models/openai.png" alt="" width="28" height="28" style={{ objectFit: "contain", borderRadius: "50%" }} />],
    ["bedrock", <img src="assets/logos/models/bedrock.png" alt="" width="28" height="28" style={{ objectFit: "contain", borderRadius: "50%" }} />],
    ["custom", <Rings s={20} />],
  ];
  return (
    <Frame W={W} H={H} svg={
      <g>
        <rect data-vpc-border x="46" y="20" width="368" height="200" rx="22" stroke={HAIR} strokeWidth="1" fill="none" strokeDasharray={DOT_DASH} strokeLinecap="round" />
        <text x="66" y="40" fontFamily="var(--font-mono)" fontSize="11" letterSpacing="0.12em" fill="var(--color-grey-600)">your VPC</text>
        <circle cx={cx} cy={cy} r="50" {...dotted} />
        <circle cx={cx} cy={cy} r="66" {...dotted} opacity="0.6" />
        <circle cx="100" cy={cy} r="33" {...dotted} />
        <circle cx="360" cy={cy} r="33" {...dotted} />
        <g stroke={LINE} strokeWidth="1.25" fill="none" strokeLinecap="round">
          <line x1={cx} y1="120" x2={cx} y2="82" />
          <line x1="200" y1={cy} x2="126" y2={cy} />
          <line x1="260" y1={cy} x2="334" y2={cy} />
          <line x1={cx} y1="184" x2={cx} y2="232" />
          <line x1={mx[0]} y1="232" x2={mx[3]} y2="232" />
          {mx.map((x) => <line key={x} x1={x} y1="232" x2={x} y2="266" />)}
        </g>
      </g>
    }>
      <Box size={64} accent style={{ ...at(cx, cy, W, H), borderRadius: 17 }}><img src="assets/brand/ioi-logo.svg" alt="IOI" width="34" height="34" /></Box>
      <Box size={46} style={at(cx, 56, W, H)}><Sparkle s={22} /></Box>
      <Box size={50} style={at(100, cy, W, H)}><Brackets s={22} /></Box>
      <Box size={50} style={at(360, cy, W, H)}><Shield s={22} /></Box>
      {models.map(([label, gl], i) => (
        <div key={label} style={{ ...at(mx[i], 296, W, H), display: "flex", flexDirection: "column", alignItems: "center", gap: 6 }}>
          <Box size={44}>{gl}</Box>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-grey-700)", whiteSpace: "nowrap" }}>{label}</span>
        </div>
      ))}
    </Frame>
  );
}

/* ============================================================= *
 * DiagCollab — work together, not in turns.
 * ============================================================= */
function pill(label, glyph) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 7, background: INK, color: "#fff", borderRadius: 999, padding: "9px 15px 9px 12px", fontFamily: "var(--font-sans)", fontSize: 14, whiteSpace: "nowrap", boxShadow: "var(--shadow-md)" }}>
      {glyph}{label}
    </span>
  );
}
const ChatBubble = ({ s = 13, c = "var(--color-grey-600)" } = {}) => (
  <svg width={s} height={s} viewBox="0 0 16 16" fill={c} aria-hidden="true"><path d="M3 2.5 H13 a2 2 0 0 1 2 2 V9 a2 2 0 0 1 -2 2 H7 L4 13.5 V11 H3 a2 2 0 0 1 -2 -2 V4.5 a2 2 0 0 1 2 -2 Z" /></svg>
);
// AI agent + Developer fused into one pinched shape — "together, not in turns".
// Gooey metaball: two INK blobs (filtered) merge with a liquid bridge; crisp
// text rides on top. Base style = merged end-state; the reveal animates from apart.
function JoinedPills() {
  const W = 214, Hh = 40, leftW = 116, rightW = 122, rightX = W - rightW; // 92
  const blob = { position: "absolute", top: 0, height: Hh, background: INK };
  const text = { position: "absolute", top: 0, height: Hh, display: "inline-flex", alignItems: "center", justifyContent: "center", gap: 7, color: "#fff", fontFamily: "var(--font-sans)", fontSize: 14, whiteSpace: "nowrap" };
  return (
    <div data-rv="joined" style={{ position: "relative", width: W, height: Hh }}>
      <svg width="0" height="0" style={{ position: "absolute" }} aria-hidden="true">
        <filter id="collabGoo">
          <feGaussianBlur in="SourceGraphic" stdDeviation="6" result="b" />
          <feColorMatrix in="b" type="matrix" values="1 0 0 0 0  0 1 0 0 0  0 0 1 0 0  0 0 0 20 -9" />
        </filter>
      </svg>
      {/* filtered blob layer — the metaball merge */}
      <div data-rv="goo-layer" style={{ position: "absolute", inset: 0, filter: "url(#collabGoo) drop-shadow(0 2px 6px rgba(0,0,0,0.18))" }}>
        <span data-rv="goo-left" style={{ ...blob, left: 0, width: leftW, borderRadius: 999 }} />
        <span data-rv="goo-bridge" style={{ ...blob, left: 84, width: 46, top: 9, height: 22 }} />
        <span data-rv="goo-right" style={{ ...blob, left: rightX, width: rightW, borderRadius: 999 }} />
      </div>
      {/* crisp text overlay — never blurred */}
      <span data-rv="goo-tl" style={{ ...text, left: 0, width: leftW }}><Sparkle s={15} c="#fff" />AI agent</span>
      <span data-rv="goo-tr" style={{ ...text, left: rightX, width: rightW }}><Person s={14} c="#fff" />Developer</span>
    </div>
  );
}
function TaskCard({ rows }) {
  return (
    <div style={{ width: 116, background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 12, boxShadow: "var(--shadow-sm)", padding: "11px 12px" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 5, marginBottom: 9 }}>
        <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--color-grey-600)" }} />
        <span style={{ height: 4, width: 34, borderRadius: 2, background: "var(--color-grey-500)" }} />
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {rows.map((r, i) => (
          <div key={i} style={{ display: "flex", alignItems: "center", gap: 7 }}>
            <span style={{ height: 4, width: r.w, borderRadius: 2, background: "var(--color-grey-450)", flex: "none" }} />
            {r.s === "chat"
              ? <span style={{ marginLeft: "auto", display: "grid", placeItems: "center", flex: "none" }}><ChatBubble s={13} /></span>
              : <span style={{ marginLeft: "auto", width: 13, height: 13, borderRadius: "50%", background: r.s === "ok" ? ACC : r.s === "no" ? RED : "var(--color-grey-600)", display: "grid", placeItems: "center", flex: "none" }}>
                  {r.s === "ok" && <svg width="8" height="8" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>}
                  {r.s === "no" && <svg width="7" height="7" viewBox="0 0 12 12" fill="none"><path d="M3 3 L9 9 M9 3 L3 9" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" /></svg>}
                </span>}
          </div>
        ))}
      </div>
    </div>
  );
}
function DiagCollab() {
  const W = 460, H = 300;
  const cardX = [102, 230, 358];
  return (
    <Frame W={W} H={H} svg={
      <g stroke={LINE} strokeWidth="1.25" fill="none" strokeLinecap="round">
        <line x1="230" y1="70" x2="230" y2="104" />
        <path d="M102 132 V116 H358 V132" />
        <line x1="230" y1="104" x2="230" y2="116" />
      </g>
    }>
      <div style={at(230, 46, W, H)}><JoinedPills /></div>
      <div style={at(cardX[0], 196, W, H)}><TaskCard rows={[{ w: 40, s: "ok" }, { w: 30, s: "chat" }, { w: 46, s: "ok" }, { w: 26, s: "no" }]} /></div>
      <div style={at(cardX[1], 196, W, H)}><TaskCard rows={[{ w: 34, s: "ok" }, { w: 44, s: "chat" }, { w: 28, s: "ok" }, { w: 38, s: "no" }]} /></div>
      <div style={at(cardX[2], 196, W, H)}><TaskCard rows={[{ w: 44, s: "ok" }, { w: 30, s: "ok" }, { w: 40, s: "chat" }, { w: 26, s: "ok" }]} /></div>
    </Frame>
  );
}

/* ============================================================= *
 * DiagToolStack — works in the tools you already use.
 * ============================================================= */
function DiagToolStack() {
  const code = [
    [<span style={{ color: "var(--color-grey-700)" }}>import</span>, " { useIOI } ", <span style={{ color: "var(--color-grey-700)" }}>from</span>, <span style={{ color: ACC }}> "@ioi/sdk"</span>],
    [],
    [<span style={{ color: "var(--color-grey-700)" }}>const</span>, " { stepIn, review } = ", <span style={{ color: INK }}>useIOI</span>, "();"],
    [],
    [<span style={{ color: "var(--color-grey-700)" }}>async</span>, " () => {"],
    ["  ", <span style={{ color: "var(--color-grey-700)" }}>await</span>, " review(", <span style={{ color: ACC }}>"scoped"</span>, ");"],
    ["  ", <span style={{ color: "var(--color-grey-700)" }}>await</span>, " stepIn();", <span style={{ color: "var(--color-grey-600)" }}>  // full context</span>],
    ["}"],
  ];
  return (
    <div style={{ position: "relative", width: "100%", maxWidth: 440, margin: "0 auto" }}>
      <div data-rv="editor" style={{ border: `0.5px solid ${HAIR}`, borderRadius: 14, overflow: "hidden", boxShadow: "var(--shadow-md)", background: "var(--color-white)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "11px 14px", borderBottom: `0.5px solid ${HAIR}` }}>
          {["#e1e1e1", "#e1e1e1", "#e1e1e1"].map((c, i) => <span key={i} style={{ width: 9, height: 9, borderRadius: "50%", background: c }} />)}
          <span style={{ marginLeft: 8, fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--color-grey-700)" }}>session.ts</span>
        </div>
        <div style={{ padding: "14px 16px", fontFamily: "var(--font-mono)", fontSize: 12.5, lineHeight: 1.85 }}>
          {code.map((ln, i) => (
            <div key={i} data-rv="codeline" style={{ display: "flex", gap: 14, background: i === 6 ? "color-mix(in srgb, var(--color-link-green) 9%, transparent)" : "transparent", margin: "0 -16px", padding: "0 16px" }}>
              <span style={{ color: "var(--color-grey-600)", width: 14, textAlign: "right", flex: "none", userSelect: "none" }}>{i + 1}</span>
              <span style={{ color: INK, whiteSpace: "pre" }}>{ln.length ? ln.map((seg, j) => <React.Fragment key={j}>{seg}</React.Fragment>) : "\u00a0"}</span>
            </div>
          ))}
        </div>
      </div>
      <svg data-rv="cursor" width="17" height="17" viewBox="0 0 24 24" aria-hidden="true" style={{ position: "absolute", top: 196, left: 188, filter: "drop-shadow(0 1.5px 1.5px rgba(0,0,0,0.25))" }}>
        <path d="M5 3 L19 12 L12.2 13.2 L15.8 20.4 L12.9 21.7 L9.3 14.4 L5 18.2 Z" fill="#fff" stroke={INK} strokeWidth="1.3" strokeLinejoin="round" />
      </svg>
      <div data-rv="tools" style={{ position: "absolute", top: -16, right: 18, display: "flex" }}>
        {[<img src="assets/logos/tools/vscode.svg" alt="" width="20" height="20" />, <img src="assets/logos/tools/cursor.svg" alt="" width="20" height="20" />, <img src="assets/logos/tools/jetbrains.svg" alt="" width="20" height="20" />, <MarkLogo size={20} />].map((gl, i) => (
          <Box key={i} size={40} style={{ marginLeft: i ? -10 : 0, borderRadius: 11, zIndex: 4 - i, boxShadow: "var(--shadow-md)" }}>{gl}</Box>
        ))}
      </div>
    </div>
  );
}

/* ============================================================= *
 * DiagPrivacy — your data is never training data (stacked windows,
 * front one verified / accent).
 * ============================================================= */
function WinCard({ accent, lines, code, style }) {
  return (
    <div style={{ position: "absolute", width: 250, height: 158, background: "var(--color-white)", border: `${accent ? "1px" : "0.5px"} solid ${accent ? ACC : HAIR}`, borderRadius: 12, boxShadow: accent ? "var(--shadow-md)" : "var(--shadow-xs)", padding: "12px 14px", ...style }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 13 }}>
        <span style={{ width: 7, height: 7, borderRadius: "50%", background: accent ? ACC : "var(--color-grey-600)" }} />
        <span style={{ height: 4, width: 56, borderRadius: 2, background: "var(--color-grey-500)" }} />
      </div>
      {code && (
        <div style={{ display: "flex", flexDirection: "column", gap: 11 }}>
          {code.map((w, i) => (
            <div key={i} data-rv="wincode" style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-grey-600)", width: 8 }}>{i + 1}</span>
              <span style={{ height: 4, width: w, borderRadius: 2, background: "var(--color-grey-450)" }} />
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
function DiagPrivacy() {
  return (
    <div style={{ position: "relative", width: "100%", maxWidth: 380, aspectRatio: "380 / 300", margin: "0 auto" }}>
      {/* deep cascade — neutral windows fanning up-right */}
      <WinCard style={{ right: 0, top: 4 }} />
      <WinCard style={{ right: 30, top: 30 }} />
      <WinCard style={{ right: 60, top: 56 }} />
      {/* highlighted private model — peeks mid-stack with an accent connector */}
      <svg viewBox="0 0 380 300" width="100%" height="100%" preserveAspectRatio="none" style={{ position: "absolute", inset: 0, overflow: "visible", pointerEvents: "none" }} aria-hidden="true">
        <path d="M96 116 H64 a8 8 0 0 0 -8 8 V176" fill="none" stroke={ACC} strokeWidth="1.5" strokeLinecap="round" />
        <circle cx="96" cy="116" r="3.5" fill={ACC} />
      </svg>
      <WinCard accent style={{ left: 40, top: 86 }} />
      {/* front readable window with numbered code lines */}
      <WinCard code={[120, 96, 134, 78]} style={{ left: 0, bottom: 0 }} />
    </div>
  );
}

/* ============================================================= *
 * DiagAccess — enterprise access & auditability: users (RBAC,
 * verified/denied) AND agents (governed actors) around a shield.
 * ============================================================= */
function ShieldLock({ size = 66 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 64 64" aria-hidden="true" style={{ filter: "drop-shadow(0 5px 12px rgba(0,0,0,0.14))" }}>
      <path d="M32 5 L54 13 V30 C54 44.5 44 53.5 32 59 C20 53.5 10 44.5 10 30 V13 Z" fill={INK} />
      <circle cx="32" cy="27.5" r="4.6" fill="#fff" />
      <path d="M30 30.5 L34 30.5 L35.4 42 L28.6 42 Z" fill="#fff" />
    </svg>
  );
}
function DiagAccess() {
  const W = 460, H = 340, cx = 230, cy = 182;
  const dotted = { stroke: HAIR, strokeWidth: 1, fill: "none", strokeDasharray: DOT_DASH, strokeLinecap: "round" };
  // [x, y, kind, ok] — kind: "user" | "agent"
  const nodes = [
    [230, 54, "user", true],
    [104, 104, "user", true],
    [352, 96, "user", false],
    [120, 274, "agent"],
    [232, 296, "agent"],
    [340, 256, "agent"],
  ];
  return (
    <Frame W={W} H={H} svg={
      <g>
        <g data-orbit style={{ transformBox: "fill-box", transformOrigin: "center" }}>
          <circle cx={cx} cy={cy} r="48" {...dotted} />
          <circle cx={cx} cy={cy} r="64" {...dotted} opacity="0.55" />
        </g>
        <circle cx="120" cy="274" r="28" {...dotted} opacity="0.7" />
        <circle cx="120" cy="274" r="38" {...dotted} opacity="0.4" />
        <circle cx="340" cy="256" r="28" {...dotted} opacity="0.7" />
        <circle cx="340" cy="256" r="38" {...dotted} opacity="0.4" />
        <g stroke={LINE} strokeWidth="1.25" fill="none" strokeLinecap="round">
          <line x1={cx} y1="150" x2={cx} y2="78" />
          <line x1="204" y1="170" x2="124" y2="116" />
          <line x1="256" y1="168" x2="334" y2="110" />
          <line x1="208" y1="202" x2="140" y2="264" />
          <line x1={cx} y1="214" x2={cx} y2="280" />
          <line x1="254" y1="200" x2="322" y2="244" />
        </g>
      </g>
    }>
      <div style={at(cx, cy, W, H)}><ShieldLock size={66} /></div>
      {nodes.map(([x, y, kind, ok], i) => (
        <Box key={i} size={kind === "user" ? 46 : 44} style={{ ...at(x, y, W, H), position: "absolute" }}>
          {kind === "user" ? <><Person s={20} /><Badge ok={ok} /></> : <Sparkle s={20} />}
        </Box>
      ))}
    </Frame>
  );
}

/* ============================================================= *
 * DiagAgentTree — run any agent at scale (composable workers).
 * ============================================================= */
// meaningful per-capability line icons (13px, fine stroke)
const gi13 = (paths) => g(paths, { s: 13, sw: 1.35 });
const TREE_ICON = {
  git: gi13(<g><circle cx="6" cy="6" r="2.3" /><circle cx="6" cy="18" r="2.3" /><circle cx="17" cy="10" r="2.3" /><path d="M6 8.3 V15.7 M7.8 7.4 a7 7 0 0 1 7.4 3.4" /></g>),
  memory: gi13(<g><ellipse cx="12" cy="6" rx="7" ry="2.6" /><path d="M5 6 V18 c0 1.4 3.1 2.6 7 2.6 s7 -1.2 7 -2.6 V6 M5 12 c0 1.4 3.1 2.6 7 2.6 s7 -1.2 7 -2.6" /></g>),
  code_parse: gi13(<g><rect x="6.5" y="6.5" width="11" height="11" rx="2" /><path d="M9.5 2 V4.5 M14.5 2 V4.5 M9.5 19.5 V22 M14.5 19.5 V22 M2 9.5 H4.5 M2 14.5 H4.5 M19.5 9.5 H22 M19.5 14.5 H22" /></g>),
  testing: gi13(<g><path d="M9.5 3 H14.5 M10.5 3 V9 L5.5 18.5 c-0.6 1.1 0.2 2.5 1.5 2.5 H17 c1.3 0 2.1 -1.4 1.5 -2.5 L13.5 9 V3" /></g>),
  sdk: gi13(<g><path d="M12 3 L20 7.5 V16.5 L12 21 L4 16.5 V7.5 Z" /><path d="M4 7.5 L12 12 L20 7.5 M12 12 V21" /></g>),
  context: gi13(<g><path d="M4 5.5 H20 M9 12 H20 M9 18.5 H20" /><path d="M4.5 11 L6 12 L4.5 13 M4.5 17.5 L6 18.5 L4.5 19.5" /></g>),
  version_control: gi13(<g><circle cx="6" cy="5" r="1.9" /><circle cx="6" cy="12" r="1.9" /><circle cx="6" cy="19" r="1.9" /><circle cx="17" cy="6" r="1.9" /><path d="M6 6.9 V10.1 M6 13.9 V17.1 M8 12 H13 c2.2 0 4 -1.8 4 -4 V7.9" /></g>),
  reasoning: gi13(<g><circle cx="6" cy="7" r="2.1" /><circle cx="18" cy="7" r="2.1" /><circle cx="12" cy="17" r="2.1" /><path d="M7.7 8.3 L10.6 15 M16.3 8.3 L13.4 15 M8.1 7 H15.9" /></g>),
  guardrails: gi13(<path d="M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z" />),
  debugging: gi13(<g><ellipse cx="12" cy="13.5" rx="4.6" ry="5.6" /><path d="M12 7.9 V4 M9.4 5.2 L10.8 7.6 M14.6 5.2 L13.2 7.6 M7.4 10.6 L3.8 9.4 M16.6 10.6 L20.2 9.4 M7 13.5 H3.3 M17 13.5 H20.7 M7.4 16.6 L3.8 18 M16.6 16.6 L20.2 18" /></g>),
  code_synthesis: gi13(<g><path d="M9 6 L4 12 L9 18 M15 6 L20 12 L15 18" /></g>),
  data_analysis: gi13(<g><path d="M4 3.5 V20.5 H21" /><path d="M8 17 V12 M12.5 17 V8 M17 17 V5" /></g>),
  doc_gen: gi13(<g><path d="M7 3 H13.5 L18 7.5 V20 c0 0.6 -0.4 1 -1 1 H7 c-0.6 0 -1 -0.4 -1 -1 V4 c0 -0.6 0.4 -1 1 -1 Z M13.5 3 V7.5 H18 M9 12.5 H15 M9 16.5 H15" /></g>),
  fm_endpoint: gi13(<g><circle cx="12" cy="12" r="3" /><path d="M12 4 V9 M12 15 V20 M4 12 H9 M15 12 H20 M6.3 6.3 L9.5 9.5 M14.5 14.5 L17.7 17.7 M17.7 6.3 L14.5 9.5 M9.5 14.5 L6.3 17.7" /></g>),
  project_mgmt: gi13(<g><rect x="3.5" y="4" width="17" height="16" rx="2" /><path d="M8 4 V20 M14 4 V20 M8 9 H14 M8 14 H14" /></g>),
};
function CapPill({ label }) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 7, background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 999, padding: "7px 13px", fontFamily: "var(--font-mono)", fontSize: 12.5, color: "var(--color-grey-900)", boxShadow: "var(--shadow-xs)", whiteSpace: "nowrap" }}>
      <span style={{ display: "grid", placeItems: "center", opacity: 0.85 }}>{TREE_ICON[label] || <Rings s={13} />}</span>{label}
    </span>
  );
}
function DiagAgentTree({ compact }) {
  const rows = compact ? [
    ["git", "memory"],
    ["testing", "reasoning"],
    ["sdk", "context"],
  ] : [
    ["git", "fm_endpoint", "memory", "code_parse", "doc_gen", "testing"],
    ["context", "version_control", "sdk", "project_mgmt", "reasoning"],
    ["guardrails", "debugging", "code_synthesis", "data_analysis"],
  ];
  return (
    <div style={{ width: "100%", maxWidth: 460, margin: "0 auto", display: "flex", flexDirection: "column", alignItems: "center" }}>
      <span data-rv="agent" style={{ display: "inline-flex", alignItems: "center", gap: 8, background: INK, color: "#fff", borderRadius: 999, padding: "9px 16px", fontFamily: "var(--font-mono)", fontSize: 13, boxShadow: "var(--shadow-md)" }}>
        <Sparkle s={15} c="#fff" />your_agent
      </span>
      <svg data-rv="branch" width="160" height="26" viewBox="0 0 160 26" aria-hidden="true" style={{ display: "block" }}><path d="M80 0 V8 M14 26 V18 a4 4 0 0 1 4 -4 H142 a4 4 0 0 1 4 4 V26 M80 8 H80" fill="none" stroke={LINE} strokeWidth="1.25" strokeLinecap="round" /><path d="M14 26 V20 M80 26 V14 M146 26 V20" fill="none" stroke={LINE} strokeWidth="1.25" strokeLinecap="round" /></svg>
      <div style={{ display: "flex", flexDirection: "column", gap: 11, alignItems: "center" }}>
        {rows.map((row, ri) => (
          <div key={ri} data-rv="caprow" style={{ display: "flex", flexWrap: "wrap", gap: 9, justifyContent: "center" }}>
            {row.map((c) => <span key={c} data-rv="cap"><CapPill label={c} /></span>)}
          </div>
        ))}
      </div>
    </div>
  );
}

window.HvDiagrams = { DiagHub, DiagCollab, DiagToolStack, DiagPrivacy, DiagAccess, DiagAgentTree };
