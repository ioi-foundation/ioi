const React = window.React;
// hypervisor.com — Background Work solution (under Solutions).
const BNS = window.IoiDesignSystem;
const { Button: BgButton, Badge: BgBadge, TextLink: BgLink, Eyebrow: BgEyebrow, Wordmark: BgWordmark, Logo: BgLogo } = BNS;
const bawrap = { maxWidth: "75rem", margin: "0 auto", padding: "0 2.5rem" };

const INK = "var(--color-onyx-black)";
const HAIR = "var(--color-grey-500)";
const ACC = "var(--color-link-green)";

/* ---- tiny tab glyphs ---- */
const tg = (paths) => (
  <svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">{paths}</svg>
);
const ICONS = {
  parallel: tg(<g><rect x="3" y="4" width="7" height="7" rx="1.5" /><rect x="14" y="4" width="7" height="7" rx="1.5" /><rect x="3" y="13" width="7" height="7" rx="1.5" /><rect x="14" y="13" width="7" height="7" rx="1.5" /></g>),
  decoupled: tg(<g><rect x="3" y="5" width="18" height="11" rx="1.5" /><path d="M2 20 H22" /></g>),
  sandbox: tg(<g><rect x="4" y="4" width="16" height="16" rx="2.5" /><path d="M9 12 L11 14 L15 9.5" /></g>),
  edit: tg(<g><path d="M4 20 H20" /><path d="M14.5 5.5 L18.5 9.5 L9 19 L5 20 L6 16 Z" /></g>),
  trigger: tg(<g><path d="M13 2 L4 14 H11 L10 22 L20 9 H13 Z" /></g>),
};

const TABS = [
  {
    icon: "parallel", label: "Runs in parallel", demo: "parallel",
    heading: "One intent, every repo.",
    body: [
      "One repo is a coding agent task. Five hundred is a fleet task.",
      "Hypervisor spins up the same sandbox across every repo that needs the change. Parallel runs, tracked progress, merged results. One person's productivity becomes the whole org's throughput.",
    ],
  },
  {
    icon: "decoupled", label: "Decoupled from your laptop", demo: "decoupled",
    heading: "Your laptop stays fast. Hypervisor does the work.",
    body: [
      "A coding agent needs your machine and your attention. A background agent needs neither.",
      "Start one from your laptop. Check the result from your phone. Close the lid, join a meeting, go offline. Hypervisor compiles, tests, and fixes failures without you.",
    ],
  },
  {
    icon: "sandbox", label: "Sandboxed execution", demo: "sandbox",
    heading: "Every agent gets its own computer.",
    body: [
      "Each agent runs in its own short-lived environment: full toolchain, test suite, scoped credentials.",
      "No shared state. No leaked secrets. No cascade when one fails. The environment is destroyed after use.",
    ],
  },
  {
    icon: "edit", label: "Edit alongside Hypervisor", demo: "edit",
    heading: "On the loop, not in the loop.",
    body: [
      "You don't steer it. You don't watch it. But you can.",
      "Open the same environment Hypervisor used. Edit its work, change direction, or take over — VS Code in the browser or your desktop editor. Pick up where Hypervisor left off.",
    ],
  },
  {
    icon: "trigger", label: "Triggered automatically", demo: "trigger",
    heading: "Take the human out of the trigger.",
    body: [
      "If every run starts with someone typing a prompt, you automated the work but not the workflow.",
      "Hypervisor fires from PRs, webhooks, schedules, or Slack. A vulnerability lands. A PR opens. A ticket stalls. Hypervisor is already on it.",
    ],
  },
];

/* ========================= demos ========================= */
const PANEL = { background: "var(--color-porcelain-grey)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", height: 480, padding: "2rem", position: "relative", overflow: "hidden" };
const card = { background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 14, boxShadow: "var(--shadow-sm)" };

function PromptCard({ title }) {
  return (
    <div style={{ ...card, padding: "18px 18px 14px" }}>
      <div style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: INK }}>{title}</div>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 28, paddingTop: 12, borderTop: `0.5px solid ${HAIR}` }}>
        <span style={{ width: 26, height: 26, borderRadius: 7, border: `0.5px solid ${HAIR}`, display: "grid", placeItems: "center", color: "var(--color-grey-700)" }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M21 12.5 L12.5 21 a5 5 0 0 1 -7 -7 L14 5.5 a3.2 3.2 0 0 1 4.5 4.5 L10 18.5 a1.4 1.4 0 0 1 -2 -2 L16 8.5" /></svg>
        </span>
        <span style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: "var(--color-grey-800)" }}>Intercom</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--color-grey-700)" strokeWidth="2" strokeLinecap="round"><path d="M6 9 L12 15 L18 9" /></svg>
        <span style={{ marginLeft: "auto", width: 30, height: 30, borderRadius: 8, background: INK, display: "grid", placeItems: "center" }}>
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 5 L4 5 L4 14 a3 3 0 0 0 3 3 H17" /><path d="M13 12 L17 16 L13 20" /></svg>
        </span>
      </div>
    </div>
  );
}

function ParallelDemo() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setT(0.85); return; }
    let raf, start = null;
    const PERIOD = 7200;
    const tick = (ts) => {
      if (start == null) start = ts;
      setT((((ts - start) % PERIOD) / PERIOD));
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const fullTitle = "Fix Pending State Issue";
  const typeStart = 0.05, typeEnd = 0.24;
  const typed = t < typeStart ? "" : fullTitle.slice(0, Math.round(Math.min(1, (t - typeStart) / (typeEnd - typeStart)) * fullTitle.length));
  const caretOn = Math.sin(t * Math.PI * 2 * 7) > 0;
  const composerOpacity = t < 0.30 ? 1 : Math.max(0, 1 - (t - 0.30) / 0.05);
  const tasks = [
    { title: "Fix Pending State Issue", meta: "7 seconds ago \u00b7 Intercom", tone: "run", at: 0.33 },
    { title: "Refactor blog item page", meta: "17 seconds ago \u00b7 Intercom", tone: "run", at: 0.46 },
    { title: "Check code and suggest improvements", meta: "40 seconds ago \u00b7 Netflix", tone: "done", at: 0.57 },
  ];
  const fade = t > 0.94 ? (1 - (t - 0.94) / 0.06) : 1;
  return (
    <div style={{ ...PANEL, display: "flex", alignItems: "center", justifyContent: "center", position: "relative" }}>
      {t < 0.37 && (
        <div style={{ position: "absolute", left: "7%", right: "7%", opacity: composerOpacity, transition: "opacity 0.15s" }}>
          <div style={{ ...card, minHeight: 124, padding: "18px 18px 14px", display: "flex", flexDirection: "column" }}>
            <div style={{ fontFamily: "var(--font-sans)", fontSize: "1.25rem", color: INK, flex: 1, lineHeight: 1.3 }}>
              {typed}<span style={{ opacity: caretOn && typed.length < fullTitle.length ? 0.7 : 0, color: INK }}>|</span>
            </div>
            <div style={{ display: "flex", alignItems: "center", gap: 10, marginTop: 16 }}>
              <span style={{ width: 28, height: 28, borderRadius: 8, border: `0.5px solid ${HAIR}`, display: "grid", placeItems: "center", color: "var(--color-grey-700)" }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M21 12.5 L12.5 21 a5 5 0 0 1 -7 -7 L14 5.5 a3.2 3.2 0 0 1 4.5 4.5 L10 18.5 a1.4 1.4 0 0 1 -2 -2 L16 8.5" /></svg>
              </span>
              <span style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: "var(--color-grey-700)" }}>Intercom</span>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--color-grey-600)" strokeWidth="2" strokeLinecap="round"><path d="M6 9 L12 15 L18 9" /></svg>
              <span style={{ marginLeft: "auto", width: 32, height: 32, borderRadius: 9, background: INK, display: "grid", placeItems: "center" }}>
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#fff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9 5 L4 5 L4 14 a3 3 0 0 0 3 3 H17" /><path d="M13 12 L17 16 L13 20" /></svg>
              </span>
            </div>
          </div>
        </div>
      )}
      <div style={{ width: "88%", display: "flex", flexDirection: "column", gap: 12, opacity: fade }}>
        {tasks.map((task, i) => {
          const vis = t >= task.at;
          const op = vis ? Math.min(1, (t - task.at) / 0.06) : 0;
          const tone = task.tone === "done" ? ACC : "var(--color-red-500)";
          const tint = task.tone === "done" ? "color-mix(in srgb, var(--color-pistachio-green) 45%, var(--color-white))" : "color-mix(in srgb, var(--color-red-500) 15%, var(--color-white))";
          return (
            <div key={i} style={{ ...card, padding: "15px 18px", display: "flex", alignItems: "center", gap: 15, opacity: op, transform: vis ? "translateY(0)" : "translateY(12px)", transition: "opacity 0.35s, transform 0.35s" }}>
              <span style={{ width: 52, height: 52, borderRadius: 14, flex: "none", background: tint, display: "grid", placeItems: "center" }}>
                <span style={{ width: 9, height: 9, borderRadius: "50%", background: tone }} />
              </span>
              <div style={{ minWidth: 0 }}>
                <div style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: INK, lineHeight: 1.25 }}>{task.title}</div>
                <div style={{ fontFamily: "var(--font-sans)", fontSize: "0.875rem", color: "var(--color-grey-600)", marginTop: 3 }}>{task.meta}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function DecoupledDemo() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setT(0.9); return; }
    let raf, start = null;
    const PERIOD = 8200;
    const tick = (ts) => { if (start == null) start = ts; setT((((ts - start) % PERIOD) / PERIOD)); raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const todos = [
    "Check recent merged PRs and commits",
    "Analyze closed issues and PRs",
    "Identify files with most churn",
    "Check for any releases or tags",
    "Draft the weekly digest",
  ];
  const done = Math.max(0, Math.min(todos.length, Math.floor((t - 0.42) / 0.09)));
  const enter = Math.max(0, Math.min(1, t / 0.12));
  const exit = t > 0.95 ? (1 - (t - 0.95) / 0.05) : 1;
  const reveal = (s, d) => { const p = Math.max(0, Math.min(1, (t - s) / (d || 0.06))); return { opacity: p, transform: `translateY(${(1 - p) * 10}px)` }; };
  return (
    <div style={{ ...PANEL, background: "color-mix(in srgb, var(--color-pistachio-green) 45%, var(--color-porcelain-grey))", padding: 0, display: "flex", justifyContent: "center", alignItems: "flex-start" }}>
      <div style={{ width: 300, marginTop: 34, background: "var(--color-white)", border: "6px solid var(--color-onyx-black)", borderBottom: "none", borderRadius: "34px 34px 0 0", overflow: "hidden", boxShadow: "var(--shadow-lg)", opacity: enter * exit, transform: `translateY(${(1 - enter) * 70}px)` }}>
        <div style={{ display: "flex", alignItems: "center", padding: "16px 18px 12px" }}>
          <span style={{ display: "flex", color: INK }}><BgWordmark height={16} /></span>
          <span style={{ marginLeft: "auto", display: "flex", flexDirection: "column", gap: 3 }}>
            {[0, 1, 2].map((i) => <span key={i} style={{ width: 16, height: 1.6, background: INK, borderRadius: 1 }} />)}
          </span>
        </div>
        <div style={{ margin: "0 14px", padding: "8px 12px", border: `0.5px solid ${HAIR}`, borderRadius: 9, display: "flex", alignItems: "center", gap: 7, fontFamily: "var(--font-sans)", fontSize: 12.5, color: "var(--color-grey-700)" }}>
          <span style={{ color: ACC }}>+</span>Add command pallets
          <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" style={{ marginLeft: "auto" }}><path d="M6 9 L12 15 L18 9" /></svg>
        </div>
        <div style={{ padding: "14px 14px 0" }}>
          <div style={{ marginLeft: "auto", width: "86%", background: "var(--color-porcelain-grey)", border: `0.5px solid ${HAIR}`, borderRadius: 12, padding: "10px 12px", fontFamily: "var(--font-sans)", fontSize: 12.5, lineHeight: 1.45, color: INK, ...reveal(0.16) }}>
            Good morning — give me a weekly digest of everything merged, closed, or released since yesterday, including the files with the most churn.
          </div>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, lineHeight: 1.5, color: "var(--color-grey-900)", margin: "14px 0 0", ...reveal(0.26) }}>
            I'll analyze the recent activity in the repository to produce a comprehensive weekly digest.
          </p>
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--color-grey-700)", margin: "8px 0 12px", ...reveal(0.30) }}>› Adding {todos.length} todo items</div>
        </div>
        <div style={{ margin: "0 14px 0", borderTop: `0.5px solid ${HAIR}`, paddingTop: 11, ...reveal(0.36) }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
            <span style={{ width: 7, height: 7, borderRadius: "50%", background: ACC }} />
            <span style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: INK }}>Processing todos…</span>
            <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-grey-700)" }}>{Math.min(done + (done < todos.length ? 1 : 0), todos.length)}/{todos.length}</span>
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--color-grey-700)", border: `0.5px solid ${HAIR}`, borderRadius: 5, padding: "2px 6px" }}>Stop</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: 9, paddingBottom: 18 }}>
            {todos.map((todo, i) => {
              const isDone = i < done;
              const active = i === done;
              return (
                <div key={todo} style={{ display: "flex", alignItems: "center", gap: 9, opacity: i <= done ? 1 : 0.45 }}>
                  <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-grey-600)", width: 10, flex: "none" }}>{i + 1}.</span>
                  <span style={{ fontFamily: "var(--font-sans)", fontSize: 12, color: INK, flex: 1, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{todo}</span>
                  <span style={{ width: 15, height: 15, borderRadius: "50%", flex: "none", display: "grid", placeItems: "center", background: isDone ? ACC : "transparent", border: isDone ? "none" : `1.5px solid ${active ? ACC : "var(--color-grey-500)"}` }}>
                    {isDone && <svg width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>}
                    {active && <span style={{ width: 5, height: 5, borderRadius: "50%", background: ACC }} />}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

function SandboxDemo() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setT(0.7); return; }
    let raf, start = null;
    const PERIOD = 5200;
    const tick = (ts) => { if (start == null) start = ts; setT((((ts - start) % PERIOD) / PERIOD)); raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const inP = Math.min(1, t / 0.16);
  const outP = t > 0.78 ? Math.min(1, (t - 0.78) / 0.14) : 0;
  const vis = Math.max(0, inP - outP);
  const scale = 0.86 + 0.14 * vis;
  const blur = (1 - vis) * 9;
  const pulse = (Math.sin(t * Math.PI * 2 * 2) + 1) / 2; // 0..1
  const halo = 4 + pulse * 8;
  return (
    <div style={{ ...PANEL, background: "var(--color-porcelain-grey)", padding: 0, position: "relative", overflow: "hidden" }}>
      <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", opacity: vis, filter: `blur(${blur}px)`, transform: `scale(${scale})` }}>
        <div style={{ position: "absolute", inset: 22, borderRadius: 42, background: "color-mix(in srgb, var(--color-pistachio-green) 46%, var(--color-white))" }} />
        <div style={{ ...card, position: "relative", width: "80%", padding: "20px 22px", display: "flex", alignItems: "center", gap: 16 }}>
          <span style={{ width: 50, height: 50, borderRadius: 13, flex: "none", background: "color-mix(in srgb, var(--color-pistachio-green) 55%, var(--color-white))", display: "grid", placeItems: "center" }}>
            <span style={{ width: 14, height: 14, borderRadius: "50%", background: ACC, boxShadow: `0 0 0 ${halo}px color-mix(in srgb, ${ACC} 26%, transparent)` }} />
          </span>
          <div>
            <div style={{ fontFamily: "var(--font-sans)", fontSize: "1.125rem", color: INK }}>Development Environment</div>
            <div style={{ fontFamily: "var(--font-sans)", fontSize: "1rem", color: "var(--color-grey-600)", marginTop: 3 }}>Started</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function EditDemo() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setT(0.6); return; }
    let raf, start = null;
    const PERIOD = 6800;
    const tick = (ts) => { if (start == null) start = ts; setT((((ts - start) % PERIOD) / PERIOD)); raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const caretOn = Math.sin(t * Math.PI * 2 * 5) > 0;
  const ap = Math.max(0, Math.min(1, (t - 0.08) / 0.30));
  const retract = t > 0.85 ? Math.max(0, Math.min(1, (t - 0.85) / 0.12)) : 0;
  const prog = ap * (1 - retract);
  const selOp = Math.max(0, Math.min(1, (prog - 0.55) / 0.3));
  const GREY = "var(--color-grey-700)", RED = "var(--color-red-500)";
  const lineH = 30, humanIdx = 2, agentIdx = 5;
  const ax = 54 + prog * 78;
  const ay = 6 + prog * (humanIdx * lineH + 4);
  const lines = [
    <span><span style={{ color: GREY }}>function</span>{" deleteContext() {"}</span>,
    <span>{"  setSelectedContext("}<span style={{ color: GREY }}>null</span>{")"}</span>,
    <span>{"  setContextAssoc(id)"}</span>,
    <span>{"}"}</span>,
    <span>{"\u00a0"}</span>,
    <span><span style={{ color: RED }}>return</span>{" ("}</span>,
    <span>{"  <"}<span style={{ color: ACC }}>Chip</span>{" icon={Git}>"}</span>,
    <span>{"    {context.owner}"}</span>,
  ];
  return (
    <div style={{ ...PANEL, background: "var(--color-white)", padding: 0, position: "relative", overflow: "hidden", display: "flex", flexDirection: "column" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "0 16px", borderBottom: `0.5px solid ${HAIR}`, height: 44, flex: "none" }}>
        {[0, 1, 2].map((i) => <span key={i} style={{ width: 9, height: 9, borderRadius: "50%", background: "#e1e1e1" }} />)}
        <span style={{ marginLeft: 10, fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-grey-700)" }}>context.tsx</span>
        <span style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 7 }}>
          <span style={{ display: "flex" }}>
            <span style={{ width: 17, height: 17, borderRadius: "50%", background: ACC, border: "1.5px solid var(--color-white)" }} />
            <span style={{ width: 17, height: 17, borderRadius: "50%", background: INK, border: "1.5px solid var(--color-white)", marginLeft: -6 }} />
          </span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-grey-700)" }}>2 editing</span>
        </span>
      </div>
      <div style={{ flex: 1, display: "flex", alignItems: "center" }}>
        <div style={{ position: "relative", width: "100%", fontFamily: "var(--font-mono)", fontSize: 13.5 }}>
          {lines.map((code, i) => {
            const isAgent = i === agentIdx, isHuman = i === humanIdx;
            return (
              <div key={i} style={{ position: "relative", height: lineH, display: "flex", alignItems: "center", padding: "0 22px", whiteSpace: "pre", color: INK, background: isAgent ? `color-mix(in srgb, ${ACC} 13%, transparent)` : isHuman ? `rgba(90,90,90,${0.16 * selOp})` : "transparent", boxShadow: isAgent ? `inset 3px 0 0 ${ACC}` : "none" }}>
                {code}
                {isAgent && <span style={{ display: "inline-block", width: 2, height: 14, marginLeft: 1, background: ACC, opacity: caretOn ? 0.9 : 0, verticalAlign: "middle" }} />}
                {isAgent && <span style={{ position: "absolute", left: 20, top: -8, fontFamily: "var(--font-sans)", fontSize: 10, color: "#fff", background: ACC, borderRadius: 4, padding: "2px 7px", whiteSpace: "nowrap", zIndex: 4 }}>Hypervisor</span>}
              </div>
            );
          })}
          <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" style={{ position: "absolute", left: ax, top: ay, filter: "drop-shadow(0 1.5px 2px rgba(0,0,0,0.28))", zIndex: 5 }}>
            <path d="M5 3 L19 12 L12.2 13.2 L15.8 20.4 L12.9 21.7 L9.3 14.4 L5 18.2 Z" fill="#fff" stroke={INK} strokeWidth="1.3" strokeLinejoin="round" />
          </svg>
          <span style={{ position: "absolute", left: ax + 13, top: ay + 15, fontFamily: "var(--font-sans)", fontSize: 9.5, color: "#fff", background: INK, borderRadius: 4, padding: "2px 6px", opacity: selOp, zIndex: 5, whiteSpace: "nowrap" }}>You</span>
        </div>
      </div>
    </div>
  );
}

function TriggerDemo() {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setT(0.6); return; }
    let raf, start = null;
    const PERIOD = 5600;
    const tick = (ts) => { if (start == null) start = ts; setT((((ts - start) % PERIOD) / PERIOD)); raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  const items = ["Webhooks", "Scheduled", "Pull Requests", "Manual"];
  const active = Math.min(items.length - 1, Math.floor(t * (items.length + 0.4)));
  const spin = (t * 1440) % 360;
  return (
    <div style={{ ...PANEL, background: "color-mix(in srgb, var(--color-pistachio-green) 38%, var(--color-white))", display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center", gap: 14 }}>
      {items.map((label, i) => {
        const fired = i < active;
        const firing = i === active;
        return (
          <div key={label} style={{ ...card, width: "84%", borderRadius: 999, padding: "15px 22px", display: "flex", alignItems: "center", gap: 13, transform: firing ? "scale(1.02)" : "scale(1)", boxShadow: firing ? "var(--shadow-md)" : "var(--shadow-xs)", transition: "transform 0.3s, box-shadow 0.3s" }}>
            <span style={{ width: 20, height: 20, flex: "none", display: "grid", placeItems: "center" }}>
              {fired
                ? <span style={{ width: 18, height: 18, borderRadius: "50%", background: ACC, display: "grid", placeItems: "center" }}><svg width="10" height="10" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg></span>
                : firing
                  ? <svg width="18" height="18" viewBox="0 0 18 18" style={{ transform: `rotate(${spin}deg)` }}><circle cx="9" cy="9" r="7" fill="none" stroke={ACC} strokeWidth="2" strokeDasharray="11 33" strokeLinecap="round" /></svg>
                  : <svg width="18" height="18" viewBox="0 0 18 18"><circle cx="9" cy="9" r="7" fill="none" stroke="var(--color-grey-500)" strokeWidth="1.5" strokeDasharray="0.5 3.5" strokeLinecap="round" /></svg>}
            </span>
            <span style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: INK }}>{label}</span>
          </div>
        );
      })}
    </div>
  );
}

const DEMOS = { parallel: ParallelDemo, decoupled: DecoupledDemo, sandbox: SandboxDemo, edit: EditDemo, trigger: TriggerDemo };

/* ========================= page ========================= */
function BgHero() {
  return (
    <section style={{ ...bawrap, paddingTop: "4rem", textAlign: "center", display: "flex", flexDirection: "column", alignItems: "center" }}>
      <BgEyebrow color="var(--color-link-green)">Solutions · Background work</BgEyebrow>
      <h1 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3.5rem", lineHeight: 1.05, letterSpacing: "-0.02em", margin: "1.25rem 0 0", maxWidth: "20ch", color: INK }}>
        Fleets of agents, working while you don't
      </h1>
      <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.1875rem", color: "var(--color-grey-800)", marginTop: "1.25rem", maxWidth: "54ch", lineHeight: 1.5 }}>
        Task in, pull request out. Delegate work to autonomous agents that run on Hypervisor's infrastructure — sandboxed, governed, and receipted — across one repo or five hundred.
      </p>
    </section>
  );
}

function FeatureBlock() {
  const [active, setActive] = React.useState(0);
  const tab = TABS[active];
  const Demo = DEMOS[tab.demo];
  return (
    <section style={{ ...bawrap, paddingTop: "5rem" }}>
      <div style={{ background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", padding: "2.5rem", display: "grid", gridTemplateColumns: "16rem 1fr", gap: "2.5rem", alignItems: "start" }}>
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 4 }}>
          {TABS.map((t, i) => {
            const on = i === active;
            return (
              <li key={t.label}>
                <button onClick={() => setActive(i)} style={{ width: "100%", textAlign: "left", display: "flex", alignItems: "center", gap: 11, padding: "12px 14px", borderRadius: "var(--radius-lg)", border: "none", cursor: "pointer", background: on ? "var(--color-porcelain-grey)" : "transparent", color: on ? INK : "var(--color-grey-800)", fontFamily: "var(--font-sans)", fontSize: "0.9375rem", fontWeight: on ? 500 : 400 }}>
                  <span style={{ color: on ? ACC : "var(--color-grey-600)", display: "grid", placeItems: "center" }}>{ICONS[t.icon]}</span>
                  {t.label}
                </button>
              </li>
            );
          })}
        </ul>
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1.15fr", gap: "2.5rem", alignItems: "center" }}>
          <div>
            <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.25rem", letterSpacing: "-0.02em", lineHeight: 1.1, margin: 0, color: INK }}>{tab.heading}</h2>
            {tab.body.map((p, i) => (
              <p key={i} style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: i === 0 ? "1.25rem" : "1rem", lineHeight: 1.5, maxWidth: "40ch" }}>{p}</p>
            ))}
          </div>
          <Demo />
        </div>
      </div>
    </section>
  );
}

/* ===================== What teams automate first ===================== */
const AUTO_ICON = {
  cve: (<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M12 3 L19 6 V11 C19 16 15.5 19.5 12 21 C8.5 19.5 5 16 5 11 V6 Z" /><path d="M9 12 L11 14 L15 9.5" /></svg>),
  review: (<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M21 11.5 a8.5 8.5 0 1 1 -4.5 -7.5 L21 4" /><path d="M21 4 V8 H17" /></svg>),
  modernize: (<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round"><path d="M3 8 H15 a4 4 0 0 1 0 8 H9" /><path d="M6 5 L3 8 L6 11" /><path d="M18 19 L21 16 L18 13" /></svg>),
};

function useClock(period) {
  const [t, setT] = React.useState(0);
  React.useEffect(() => {
    const reduce = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduce) { setT(0.7); return; }
    let raf, start = null;
    const tick = (ts) => { if (start == null) start = ts; setT((((ts - start) % period) / period)); raf = requestAnimationFrame(tick); };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);
  return t;
}

function CVEDemo() {
  const t = useClock(7000);
  const steps = [
    ["Scheduled scan", "Run on a schedule or trigger manually for specific repositories.", true],
    ["Scan dependencies", "Run security scanners to identify CVEs and outdated packages."],
    ["Apply updates", "Update vulnerable or outdated dependencies. Handle breaking changes."],
    ["Run tests", "Execute the test suite to validate the updates."],
    ["Open PR with fix", "Create a pull request with dependency updates and CVE details."],
  ];
  const active = Math.min(steps.length - 1, Math.floor(t * (steps.length + 0.6)));
  return (
    <div style={{ ...PANEL, background: "var(--color-porcelain-grey)", display: "flex", alignItems: "center", justifyContent: "center", padding: "0 26px" }}>
      <div style={{ width: "100%", display: "flex", flexDirection: "column", gap: 8 }}>
        {steps.map(([title, desc, trig], i) => {
          const done = i < active;
          const on = i === active;
          return (
            <div key={i} style={{ ...card, padding: "13px 16px", opacity: on || done ? 1 : Math.max(0.45, 0.95 - (i - active) * 0.16), boxShadow: on ? "var(--shadow-md)" : "var(--shadow-xs)", transform: on ? "scale(1.015)" : "scale(1)", transition: "opacity 0.3s, transform 0.3s, box-shadow 0.3s" }}>
              {trig && <span style={{ display: "inline-flex", alignItems: "center", gap: 5, background: "color-mix(in srgb, var(--color-pistachio-green) 55%, var(--color-white))", color: "var(--color-green-700, #1f7a4d)", borderRadius: 6, padding: "2px 8px", fontFamily: "var(--font-mono)", fontSize: 10.5, marginBottom: 7 }}><svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="9" /><path d="M10 8 L16 12 L10 16 Z" fill="currentColor" stroke="none" /></svg>Trigger</span>}
              <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
                <span style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: INK }}>{title}</span>
                {done && <span style={{ marginLeft: "auto", width: 16, height: 16, borderRadius: "50%", background: ACC, display: "grid", placeItems: "center", flex: "none" }}><svg width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg></span>}
                {on && <span style={{ marginLeft: "auto", width: 17, height: 17, viewBox: "0 0 18 18", flex: "none" }}><svg width="17" height="17" viewBox="0 0 18 18" style={{ transform: `rotate(${(t * 1440) % 360}deg)` }}><circle cx="9" cy="9" r="7" fill="none" stroke={ACC} strokeWidth="2" strokeDasharray="11 33" strokeLinecap="round" /></svg></span>}
              </div>
              {on && <div style={{ fontFamily: "var(--font-sans)", fontSize: "0.8125rem", color: "var(--color-grey-700)", marginTop: 5, lineHeight: 1.4 }}>{desc}</div>}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ModernizeDemo() {
  const t = useClock(7000);
  const rows = [
    ["JAVA 8 \u2192 JAVA 17", "Repository 01 \u00b7 1 min ago"],
    ["COBOL \u2192 JAVA", "Repository 02 \u00b7 30 sec ago"],
    ["JAVA 8 \u2192 JAVA 17", "AetherNet \u00b7 started 10s ago"],
    ["JAVA 8 \u2192 JAVA 17", "Project Phoenix \u00b7 started 9s ago"],
    ["JAVA 8 \u2192 JAVA 17", "InfernoCore \u00b7 started 8s ago"],
    ["JAVA 8 \u2192 JAVA 17", "PyroLink \u00b7 started 7s ago"],
  ];
  const done = Math.max(0, Math.min(rows.length, Math.floor((t - 0.12) / 0.12)));
  const count = 1 + done + Math.floor(t * 9);
  const spin = (t * 1440) % 360;
  return (
    <div style={{ ...PANEL, background: "color-mix(in srgb, var(--color-pistachio-green) 30%, var(--color-porcelain-grey))", padding: 0, overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 9, padding: "16px 18px", borderBottom: `0.5px solid ${HAIR}` }}>
        <span style={{ width: 8, height: 8, borderRadius: "50%", background: ACC, flex: "none" }} />
        <span style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: INK }}>Migration in progress…</span>
        <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--color-grey-700)", background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: 999, padding: "3px 10px" }}>{count}/210</span>
      </div>
      <div style={{ padding: "6px 0", WebkitMaskImage: "linear-gradient(180deg, #000 60%, transparent)", maskImage: "linear-gradient(180deg, #000 60%, transparent)" }}>
        {rows.map(([title, meta], i) => {
          const ok = i < done; const active = i === done;
          return (
            <div key={i} style={{ display: "flex", alignItems: "center", gap: 12, padding: "11px 18px", opacity: i <= done ? 1 : Math.max(0.2, 0.85 - (i - done) * 0.22) }}>
              <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, color: "var(--color-grey-600)", width: 16, flex: "none" }}>{i + 1}.</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: INK, whiteSpace: "nowrap" }}>{title}</div>
                <div style={{ fontFamily: "var(--font-sans)", fontSize: "0.75rem", color: "var(--color-grey-600)", marginTop: 2, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>{meta}</div>
              </div>
              <span style={{ width: 18, height: 18, flex: "none", display: "grid", placeItems: "center" }}>
                {ok
                  ? <span style={{ width: 18, height: 18, borderRadius: "50%", background: ACC, display: "grid", placeItems: "center" }}><svg width="10" height="10" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg></span>
                  : active
                    ? <svg width="17" height="17" viewBox="0 0 18 18" style={{ transform: `rotate(${spin}deg)` }}><circle cx="9" cy="9" r="7" fill="none" stroke={ACC} strokeWidth="2" strokeDasharray="11 33" strokeLinecap="round" /></svg>
                    : <svg width="17" height="17" viewBox="0 0 18 18"><circle cx="9" cy="9" r="7" fill="none" stroke="var(--color-grey-500)" strokeWidth="1.5" strokeDasharray="0.5 3.5" strokeLinecap="round" /></svg>}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ReviewDemo() {
  const t = useClock(6500);
  const rv = (s, d) => Math.max(0, Math.min(1, (t - s) / (d || 0.08)));
  const diff = [
    "export async function up(knex: Knex) {",
    "  await knex.schema.alterTable('users', t => {",
    "    t.index(['org_id', 'last_active']);\u2026",
    "  });\u2026",
  ];
  return (
    <div style={{ ...PANEL, background: "color-mix(in srgb, var(--color-pistachio-green) 26%, var(--color-white))", padding: 0, display: "flex", flexDirection: "column", overflow: "hidden" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 6, padding: "0 16px", height: 40, flex: "none", borderBottom: `0.5px solid ${HAIR}`, background: "var(--color-white)" }}>
        {[0, 1, 2].map((i) => <span key={i} style={{ width: 9, height: 9, borderRadius: "50%", background: "#dcdcdc" }} />)}
        <span style={{ margin: "0 auto", fontFamily: "var(--font-mono)", fontSize: 11.5, color: "var(--color-grey-700)" }}>Hypervisor Code Review</span>
      </div>
      <div style={{ flex: 1, background: "var(--color-white)", margin: "14px", borderRadius: 12, border: `0.5px solid ${HAIR}`, padding: "16px 18px", display: "flex", flexDirection: "column", opacity: rv(0.05) }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span style={{ width: 28, height: 28, borderRadius: 8, background: INK, display: "grid", placeItems: "center", flex: "none", color: "#fff" }}><BgLogo size={16} /></span>
          <span style={{ fontFamily: "var(--font-sans)", fontSize: 13.5, color: INK, fontWeight: 600 }}>Hypervisor Automations</span>
          <span style={{ fontFamily: "var(--font-sans)", fontSize: 12.5, color: "var(--color-grey-600)" }}>commented 30 min ago</span>
        </div>
        <div style={{ display: "flex", alignItems: "center", marginTop: 14, opacity: rv(0.18) }}>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: INK }}>db/migrations/add_users_org_id_index.ts</span>
          <span style={{ marginLeft: "auto", fontFamily: "var(--font-mono)", fontSize: 11.5, color: ACC }}>+4</span>
        </div>
        <div style={{ marginTop: 8, borderRadius: 8, overflow: "hidden", border: `0.5px solid ${HAIR}`, opacity: rv(0.28) }}>
          {diff.map((c, i) => (
            <div key={i} style={{ display: "flex", gap: 8, padding: "3px 10px", background: "color-mix(in srgb, var(--color-pistachio-green) 16%, var(--color-white))", fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-green-700, #1f7a4d)", whiteSpace: "nowrap", overflow: "hidden" }}><span>+</span>{c}</div>
          ))}
          <div style={{ padding: "4px 10px", fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--color-grey-600)", background: "var(--color-white)" }}>-- migrate: add index for user lookup</div>
        </div>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: "var(--color-grey-900)", lineHeight: 1.5, marginTop: 14, opacity: rv(0.42) }}>
          This query runs without an index on <span style={{ background: "var(--color-porcelain-grey)", borderRadius: 4, padding: "1px 5px", fontFamily: "var(--font-mono)", fontSize: 12 }}>user_id</span> — causes full table scans in production. Added index and updated the migration.
        </p>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: 13, color: INK, marginTop: 10, opacity: rv(0.55), display: "flex", alignItems: "center", gap: 7 }}><span style={{ width: 15, height: 15, borderRadius: "50%", background: ACC, display: "grid", placeItems: "center" }}><svg width="9" height="9" viewBox="0 0 12 12" fill="none"><path d="M2.5 6.3 L5 8.5 L9.5 3.7" stroke="#fff" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg></span>Tests pass.</p>
      </div>
    </div>
  );
}

const AUTO_TABS = [
  { icon: "cve", label: "CVE remediation", demo: CVEDemo, heading: "CVE remediation", body: ["Scanners find vulnerabilities. Hypervisor patches them across your codebase, in parallel.", "Scan, apply updates, run tests, and open a PR with the fix — every step scoped and receipted."] },
  { icon: "review", label: "Code review on every PR", demo: ReviewDemo, heading: "Code review on every PR", body: ["Hypervisor clones, compiles, runs tests, and fixes issues before your team opens the diff.", "It comments with evidence and a working change — not just a flag."] },
  { icon: "modernize", label: "Code modernization", demo: ModernizeDemo, heading: "Code modernization", body: ["Migrations that sat in backlogs for years — done in days across hundreds of repos.", "One intent fans out into a tracked fleet: JAVA 8 to 17, COBOL to JAVA, framework upgrades."] },
];

function WhatTeamsAutomate() {
  const [active, setActive] = React.useState(0);
  const tab = AUTO_TABS[active];
  const Demo = tab.demo;
  return (
    <section style={{ ...bawrap, paddingTop: "8rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", flexWrap: "wrap", gap: "1rem", marginBottom: "2.5rem" }}>
        <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.5rem", letterSpacing: "-0.02em", lineHeight: 1.08, margin: 0, color: INK }}>What teams automate first</h2>
        <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-700)", margin: 0, maxWidth: "30ch", textAlign: "right" }}>Start with repetitive, well-scoped tasks where the blast radius is small.</p>
      </div>
      <div style={{ background: "var(--color-white)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", padding: "2.5rem", display: "grid", gridTemplateColumns: "16rem 1fr", gap: "2.5rem", alignItems: "start" }}>
        <ul style={{ listStyle: "none", margin: 0, padding: 0, display: "flex", flexDirection: "column", gap: 4 }}>
          {AUTO_TABS.map((tb, i) => {
            const on = i === active;
            return (
              <li key={tb.label}>
                <button onClick={() => setActive(i)} style={{ width: "100%", textAlign: "left", display: "flex", alignItems: "flex-start", gap: 11, padding: "14px", borderRadius: "var(--radius-lg)", border: "none", cursor: "pointer", background: on ? "var(--color-porcelain-grey)" : "transparent" }}>
                  <span style={{ color: on ? ACC : "var(--color-grey-600)", display: "grid", placeItems: "center", marginTop: 1 }}>{AUTO_ICON[tb.icon]}</span>
                  <span>
                    <span style={{ display: "block", fontFamily: "var(--font-sans)", fontSize: "0.9375rem", fontWeight: on ? 600 : 500, color: INK }}>{tb.heading}</span>
                    <span style={{ display: "block", fontFamily: "var(--font-sans)", fontSize: "0.8125rem", color: "var(--color-grey-700)", marginTop: 3, lineHeight: 1.4 }}>{tb.body[0]}</span>
                    {on && <span style={{ display: "inline-block", marginTop: 8 }}><BgLink href="#">Learn more</BgLink></span>}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
        <Demo />
      </div>
    </section>
  );
}

function HandoffOutro() {
  const t = useClock(6000);
  const lidP = Math.max(0, Math.min(1, (Math.sin(t * Math.PI * 2 - Math.PI / 2) + 1) / 2)); // 0 open → 1 closed
  const closed = lidP > 0.55;
  const pulse = (Math.sin(t * Math.PI * 2 * 2) + 1) / 2;
  const stats = [
    ["10x", "More tasks in parallel"],
    ["0%", "Local compute used"],
    ["24/7", "Runs while you sleep"],
  ];
  return (
    <section style={{ ...bawrap, paddingTop: "8rem" }}>
      <div style={{ display: "grid", gridTemplateColumns: "0.85fr 1.15fr", gap: "4rem", alignItems: "center" }}>
        <div>
          <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "2.5rem", letterSpacing: "-0.02em", lineHeight: 1.08, margin: 0, color: INK }}>Hand off work, walk away</h2>
          <p style={{ fontFamily: "var(--font-sans)", fontSize: "1.0625rem", color: "var(--color-grey-800)", marginTop: "1.25rem", lineHeight: 1.55, maxWidth: "42ch" }}>
            Hand off a task and close your laptop as Hypervisor runs in its own cloud environment with the full toolchain, test suite, and dependencies. You can even pick up the work from your phone.
          </p>
          <div style={{ marginTop: "1.75rem" }}><BgLink href="#">Browse automation templates</BgLink></div>
        </div>
        <div style={{ background: "color-mix(in srgb, var(--color-pistachio-green) 22%, var(--color-porcelain-grey))", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", height: 320, display: "flex", alignItems: "center", justifyContent: "center", gap: 46, overflow: "hidden" }}>
          {/* laptop closing */}
          <div style={{ width: 150, display: "flex", flexDirection: "column", alignItems: "center" }}>
            <div style={{ width: 132, height: 84, position: "relative", perspective: 460 }}>
              <div style={{ position: "absolute", inset: 0, ...card, borderRadius: 8, display: "grid", placeItems: "center", overflow: "hidden" }}>
                <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--color-grey-600)", opacity: 1 - lidP }}>handing off…</span>
              </div>
              <div style={{ position: "absolute", inset: 0, background: "var(--color-onyx-black)", borderRadius: 8, transformOrigin: "bottom", transform: `rotateX(${-90 + lidP * 90}deg)`, opacity: 0.96 }} />
            </div>
            <div style={{ width: 150, height: 7, borderRadius: "0 0 6px 6px", background: "var(--color-grey-400)" }} />
            <span style={{ fontFamily: "var(--font-mono)", fontSize: 10.5, color: "var(--color-grey-700)", marginTop: 10 }}>{closed ? "lid closed" : "you, leaving"}</span>
          </div>
          {/* handoff arc */}
          <svg width="64" height="40" viewBox="0 0 64 40" fill="none" aria-hidden="true">
            <path d="M2 30 Q32 2 62 30" stroke={ACC} strokeWidth="1.5" strokeDasharray="3 5" strokeLinecap="round" opacity={closed ? 1 : 0.4} />
            <circle cx={2 + 60 * lidP} cy={30 - Math.sin(lidP * Math.PI) * 28} r="3.5" fill={ACC} opacity={closed ? 1 : 0} />
          </svg>
          {/* cloud env keeps running */}
          <div style={{ ...card, padding: "16px 18px", display: "flex", alignItems: "center", gap: 13 }}>
            <span style={{ width: 40, height: 40, borderRadius: 11, flex: "none", background: "color-mix(in srgb, var(--color-pistachio-green) 55%, var(--color-white))", display: "grid", placeItems: "center" }}>
              <span style={{ width: 11, height: 11, borderRadius: "50%", background: ACC, boxShadow: `0 0 0 ${4 + pulse * 6}px color-mix(in srgb, ${ACC} 24%, transparent)` }} />
            </span>
            <div>
              <div style={{ fontFamily: "var(--font-sans)", fontSize: 14, color: INK }}>Running on Hypervisor</div>
              <div style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--color-grey-700)", marginTop: 2 }}>3 sessions · cloud</div>
            </div>
          </div>
        </div>
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: "1.25rem", marginTop: "2.5rem" }}>
        {stats.map(([value, label]) => (
          <div key={label} style={{ background: "var(--color-porcelain-grey)", border: `0.5px solid ${HAIR}`, borderRadius: "var(--radius-card)", padding: "2.25rem 2rem", display: "flex", flexDirection: "column", gap: "0.625rem" }}>
            <div style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", lineHeight: 1, letterSpacing: "-0.02em", color: INK }}>{value}</div>
            <div style={{ fontFamily: "var(--font-sans)", fontSize: "0.9375rem", color: "var(--color-grey-700)" }}>{label}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

function BgCTA() {
  return (
    <section style={{ ...bawrap, paddingTop: "8rem", textAlign: "center" }}>
      <h2 style={{ fontFamily: "var(--font-serif)", fontWeight: 300, fontSize: "3rem", letterSpacing: "-0.02em", margin: 0, color: INK }}>Put a fleet to work</h2>
      <div style={{ display: "flex", gap: "0.5rem", justifyContent: "center", marginTop: "1.75rem" }}>
        <BgButton iconRight={<span>→</span>}>Get started</BgButton>
        <BgLink href="solutions.html">Back to solutions</BgLink>
      </div>
    </section>
  );
}

function HvPage() {
  return (
    <main>
      <BgHero />
      <FeatureBlock />
      <WhatTeamsAutomate />
      <HandoffOutro />
      <BgCTA />
    </main>
  );
}
window.HvPage = HvPage;
window.HvPageActive = "Solutions";
